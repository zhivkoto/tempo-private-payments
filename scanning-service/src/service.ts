import {
  type Address,
  type Hex,
  type PublicClient,
  type WatchBlockNumberReturnType,
  parseAbiItem,
  decodeEventLog,
} from "viem";
import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";
import { Hono } from "hono";
import { serve, type ServerType } from "@hono/node-server";
import * as fs from "node:fs";
import * as path from "node:path";

// ── Types ────────────────────────────────────────────────────────────────────

type CompressedPubKey = Hex;

export interface DetectedPayment {
  stealthAddress: Address;
  stealthPrivateKey: Hex;
  ephemeralPubKey: CompressedPubKey;
  blockNumber: bigint;
  txHash: Hex;
  metadata: Hex;
  detectedAt: Date;
}

export interface ScanningServiceConfig {
  publicClient: PublicClient;
  announcerAddress: Address;
  viewingPrivateKey: Hex;
  spendingPubKey: CompressedPubKey;
  schemeId?: bigint;
  pollIntervalMs?: number;
  batchSize?: number;
  /** Path to persist scanner state (lastScannedBlock) */
  statePath?: string;
  /** HTTP port for health endpoint */
  healthPort?: number;
  /** MPP challenge timeout in seconds (default: 30) */
  challengeTimeoutSec?: number;
  /** Use WebSocket for new block subscriptions */
  useWebSocket?: boolean;
}

export interface ScannerMetrics {
  scanLatencyMs: number[];
  matchesFound: number;
  eventsProcessed: number;
  viewTagFilteredOut: number;
  lastScanDurationMs: number;
}

interface PersistedState {
  lastScannedBlock: string; // bigint serialized as string
}

// ── Announcement event ABI ───────────────────────────────────────────────────

const ANNOUNCEMENT_EVENT = parseAbiItem(
  "event Announcement(uint256 indexed schemeId, address indexed stealthAddress, address indexed caller, bytes ephemeralPubKey, uint8 viewTag, bytes metadata)"
);

// ── Helpers ──────────────────────────────────────────────────────────────────

function hexToBytes(hex: Hex): Uint8Array {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): Hex {
  return `0x${Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")}` as Hex;
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let result = 0n;
  for (const byte of bytes) {
    result = (result << 8n) | BigInt(byte);
  }
  return result;
}

function pubKeyToAddress(uncompressedPubKey: Uint8Array): Address {
  const pubKeyNoPrefix = uncompressedPubKey.slice(1);
  const hash = keccak_256(pubKeyNoPrefix);
  const addressBytes = hash.slice(12);
  return `0x${Array.from(addressBytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")}` as Address;
}

function checkAnnouncement(
  stealthAddress: Address,
  ephemeralPubKeyHex: Hex,
  viewTag: number,
  viewingPrivateKey: Hex,
  spendingPubKey: CompressedPubKey
): { stealthPrivateKey: Hex; viewTagMatched: boolean } | null {
  const viewingPrivBytes = hexToBytes(viewingPrivateKey);
  const ephemeralPubBytes = hexToBytes(ephemeralPubKeyHex);

  let ephemeralPoint;
  try {
    ephemeralPoint = secp256k1.ProjectivePoint.fromHex(ephemeralPubBytes);
  } catch {
    return null;
  }

  const viewingPrivScalar = bytesToBigInt(viewingPrivBytes);
  const sharedPoint = ephemeralPoint.multiply(viewingPrivScalar);
  const sharedCompressed = sharedPoint.toRawBytes(true);
  const sharedHash = keccak_256(sharedCompressed);

  // View tag filter
  if (sharedHash[0] !== viewTag) {
    return null;
  }

  const s = bytesToBigInt(sharedHash) % secp256k1.CURVE.n;
  const spendingPubBytes = hexToBytes(spendingPubKey);
  const spendingPoint = secp256k1.ProjectivePoint.fromHex(spendingPubBytes);
  const sTimesG = secp256k1.ProjectivePoint.BASE.multiply(s);
  const stealthPoint = spendingPoint.add(sTimesG);

  const stealthPubUncompressed = stealthPoint.toRawBytes(false);
  const computedAddress = pubKeyToAddress(stealthPubUncompressed);

  if (computedAddress.toLowerCase() !== stealthAddress.toLowerCase()) {
    return null;
  }

  const sHex = `0x${s.toString(16).padStart(64, "0")}` as Hex;
  return { stealthPrivateKey: sHex, viewTagMatched: true };
}

// ── ScanningService ──────────────────────────────────────────────────────────

export class ScanningService {
  private config: Required<ScanningServiceConfig>;
  private lastScannedBlock: bigint = 0n;
  private pollTimer: ReturnType<typeof setInterval> | null = null;
  private wsUnsubscribe: WatchBlockNumberReturnType | null = null;
  private isRunning = false;
  private httpServer: ServerType | null = null;
  private detectedPayments: DetectedPayment[] = [];
  private onPaymentCallback: ((payment: DetectedPayment) => void | Promise<void>) | null = null;
  private chainTip: bigint = 0n;
  private shutdownHandlersRegistered = false;

  metrics: ScannerMetrics = {
    scanLatencyMs: [],
    matchesFound: 0,
    eventsProcessed: 0,
    viewTagFilteredOut: 0,
    lastScanDurationMs: 0,
  };

  constructor(config: ScanningServiceConfig) {
    this.config = {
      ...config,
      schemeId: config.schemeId ?? 1n,
      pollIntervalMs: config.pollIntervalMs ?? 2000,
      batchSize: config.batchSize ?? 100,
      statePath: config.statePath ?? "./scanner-state.json",
      healthPort: config.healthPort ?? 3100,
      challengeTimeoutSec: config.challengeTimeoutSec ?? 30,
      useWebSocket: config.useWebSocket ?? false,
    };

    this.loadState();
  }

  // ── State persistence ────────────────────────────────────────────────────

  private loadState(): void {
    try {
      if (fs.existsSync(this.config.statePath)) {
        const raw = fs.readFileSync(this.config.statePath, "utf-8");
        const state: PersistedState = JSON.parse(raw);
        this.lastScannedBlock = BigInt(state.lastScannedBlock);
      }
    } catch {
      // No persisted state, start from 0
    }
  }

  saveState(): void {
    const state: PersistedState = {
      lastScannedBlock: this.lastScannedBlock.toString(),
    };
    const dir = path.dirname(this.config.statePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(this.config.statePath, JSON.stringify(state, null, 2));
  }

  // ── Health endpoint ──────────────────────────────────────────────────────

  startHealthEndpoint(): ServerType {
    const app = new Hono();

    app.get("/health", (c) => {
      const lag = this.chainTip - this.lastScannedBlock;
      return c.json({
        status: this.isRunning ? "running" : "stopped",
        lastScannedBlock: this.lastScannedBlock.toString(),
        chainTip: this.chainTip.toString(),
        lag: lag.toString(),
        paymentsDetected: this.detectedPayments.length,
        metrics: {
          matchesFound: this.metrics.matchesFound,
          eventsProcessed: this.metrics.eventsProcessed,
          viewTagFilterRate:
            this.metrics.eventsProcessed > 0
              ? (this.metrics.viewTagFilteredOut / this.metrics.eventsProcessed).toFixed(4)
              : "0",
          lastScanDurationMs: this.metrics.lastScanDurationMs,
        },
      });
    });

    this.httpServer = serve({ fetch: app.fetch, port: this.config.healthPort });
    return this.httpServer;
  }

  stopHealthEndpoint(): void {
    if (this.httpServer) {
      this.httpServer.close();
      this.httpServer = null;
    }
  }

  // ── Scanning ─────────────────────────────────────────────────────────────

  async start(
    fromBlock: bigint | "latest",
    onPayment: (payment: DetectedPayment) => void | Promise<void>
  ): Promise<void> {
    if (this.isRunning) return;
    this.isRunning = true;
    this.onPaymentCallback = onPayment;

    // Resolve starting block
    if (fromBlock === "latest") {
      const latest = await this.config.publicClient.getBlockNumber();
      if (this.lastScannedBlock === 0n) {
        this.lastScannedBlock =
          latest - BigInt(this.config.batchSize) > 0n
            ? latest - BigInt(this.config.batchSize)
            : 0n;
      }
    } else if (this.lastScannedBlock === 0n) {
      this.lastScannedBlock = fromBlock;
    }

    // Register shutdown handlers
    if (!this.shutdownHandlersRegistered) {
      const shutdown = () => this.gracefulShutdown();
      process.on("SIGTERM", shutdown);
      process.on("SIGINT", shutdown);
      this.shutdownHandlersRegistered = true;
    }

    // WebSocket subscription for new blocks
    if (this.config.useWebSocket) {
      this.wsUnsubscribe = this.config.publicClient.watchBlockNumber({
        onBlockNumber: async (blockNumber) => {
          this.chainTip = blockNumber;
          if (blockNumber > this.lastScannedBlock) {
            await this.pollOnce();
          }
        },
        onError: (err) => {
          console.error("[ScanningService] WS block subscription error:", err);
        },
      });
    }

    // Polling fallback (or primary if no WS)
    this.pollTimer = setInterval(async () => {
      if (!this.isRunning) return;
      await this.pollOnce();
    }, this.config.pollIntervalMs);

    // Initial poll
    await this.pollOnce();
  }

  private async pollOnce(): Promise<void> {
    try {
      const latest = await this.config.publicClient.getBlockNumber();
      this.chainTip = latest;
      if (latest <= this.lastScannedBlock) return;

      const startTime = Date.now();

      // Batch processing
      let currentFrom = this.lastScannedBlock + 1n;
      const allPayments: DetectedPayment[] = [];

      while (currentFrom <= latest) {
        const batchEnd =
          currentFrom + BigInt(this.config.batchSize) - 1n > latest
            ? latest
            : currentFrom + BigInt(this.config.batchSize) - 1n;

        const payments = await this.scanRange(currentFrom, batchEnd);
        allPayments.push(...payments);
        currentFrom = batchEnd + 1n;
      }

      const scanDuration = Date.now() - startTime;
      this.metrics.lastScanDurationMs = scanDuration;
      this.metrics.scanLatencyMs.push(scanDuration);

      // Check MPP challenge timeout
      if (scanDuration > this.config.challengeTimeoutSec * 1000) {
        console.warn(
          `[ScanningService] Scan took ${scanDuration}ms, exceeding challenge timeout of ${this.config.challengeTimeoutSec}s`
        );
      }

      for (const payment of allPayments) {
        this.detectedPayments.push(payment);
        if (this.onPaymentCallback) {
          await this.onPaymentCallback(payment);
        }
      }

      this.lastScannedBlock = latest;
      this.saveState();
    } catch (err) {
      console.error("[ScanningService] poll error:", err);
    }
  }

  async scanRange(fromBlock: bigint, toBlock: bigint): Promise<DetectedPayment[]> {
    const detected: DetectedPayment[] = [];

    const logs = await this.config.publicClient.getLogs({
      address: this.config.announcerAddress,
      event: ANNOUNCEMENT_EVENT,
      fromBlock,
      toBlock,
      args: {
        schemeId: this.config.schemeId,
      },
    });

    for (const log of logs) {
      const { stealthAddress, ephemeralPubKey, viewTag, metadata } = log.args as {
        schemeId: bigint;
        stealthAddress: Address;
        caller: Address;
        ephemeralPubKey: Hex;
        viewTag: number;
        metadata: Hex;
      };

      this.metrics.eventsProcessed++;

      const result = checkAnnouncement(
        stealthAddress,
        ephemeralPubKey,
        viewTag,
        this.config.viewingPrivateKey,
        this.config.spendingPubKey
      );

      if (result === null) {
        this.metrics.viewTagFilteredOut++;
      } else {
        this.metrics.matchesFound++;
        detected.push({
          stealthAddress,
          stealthPrivateKey: result.stealthPrivateKey,
          ephemeralPubKey,
          blockNumber: log.blockNumber ?? 0n,
          txHash: (log.transactionHash ?? "0x") as Hex,
          metadata: metadata ?? ("0x" as Hex),
          detectedAt: new Date(),
        });
      }
    }

    return detected;
  }

  async verifyPayment(txHash: Hex): Promise<DetectedPayment | null> {
    const receipt = await this.config.publicClient.getTransactionReceipt({
      hash: txHash,
    });

    for (const log of receipt.logs) {
      if (log.address.toLowerCase() !== this.config.announcerAddress.toLowerCase()) {
        continue;
      }

      try {
        const decoded = decodeEventLog({
          abi: [ANNOUNCEMENT_EVENT],
          data: log.data,
          topics: log.topics,
        });

        const args = decoded.args as {
          schemeId: bigint;
          stealthAddress: Address;
          caller: Address;
          ephemeralPubKey: Hex;
          viewTag: number;
          metadata: Hex;
        };

        if (args.schemeId !== this.config.schemeId) continue;

        this.metrics.eventsProcessed++;
        const result = checkAnnouncement(
          args.stealthAddress,
          args.ephemeralPubKey,
          args.viewTag,
          this.config.viewingPrivateKey,
          this.config.spendingPubKey
        );

        if (result) {
          this.metrics.matchesFound++;
          return {
            stealthAddress: args.stealthAddress,
            stealthPrivateKey: result.stealthPrivateKey,
            ephemeralPubKey: args.ephemeralPubKey,
            blockNumber: log.blockNumber ?? 0n,
            txHash,
            metadata: args.metadata ?? ("0x" as Hex),
            detectedAt: new Date(),
          };
        } else {
          this.metrics.viewTagFilteredOut++;
        }
      } catch {
        continue;
      }
    }

    return null;
  }

  // ── Accessors ────────────────────────────────────────────────────────────

  getLastScannedBlock(): bigint {
    return this.lastScannedBlock;
  }

  getChainTip(): bigint {
    return this.chainTip;
  }

  getDetectedPayments(): DetectedPayment[] {
    return [...this.detectedPayments];
  }

  getMetrics(): ScannerMetrics {
    return { ...this.metrics };
  }

  getIsRunning(): boolean {
    return this.isRunning;
  }

  // ── Shutdown ─────────────────────────────────────────────────────────────

  async stop(): Promise<void> {
    this.isRunning = false;
    if (this.pollTimer) {
      clearInterval(this.pollTimer);
      this.pollTimer = null;
    }
    if (this.wsUnsubscribe) {
      this.wsUnsubscribe();
      this.wsUnsubscribe = null;
    }
    this.saveState();
  }

  private async gracefulShutdown(): Promise<void> {
    console.log("[ScanningService] Graceful shutdown initiated...");
    await this.stop();
    this.stopHealthEndpoint();
    console.log("[ScanningService] State saved.");
  }
}
