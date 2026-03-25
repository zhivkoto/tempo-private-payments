import { timingSafeEqual } from "node:crypto";
import {
  type Address,
  type Hex,
  type PublicClient,
  parseAbiItem,
  decodeEventLog,
} from "viem";
import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";

/** Compressed secp256k1 public key (33 bytes, hex-encoded with 0x prefix) */
type CompressedPubKey = Hex;

/** A detected stealth payment with block context */
export interface DetectedPayment {
  /** Detected stealth address that matches */
  stealthAddress: Address;
  /** Shared secret scalar s (needs k_spend added for full stealth private key) */
  sharedSecretScalar: Hex;
  /** Ephemeral public key from the announcement */
  ephemeralPubKey: CompressedPubKey;
  /** Block number where the announcement was emitted */
  blockNumber: bigint;
  /** Transaction hash of the announcement */
  txHash: Hex;
  /** Metadata from the announcement event */
  metadata: Hex;
  /** Timestamp of detection */
  detectedAt: Date;
}

/** Configuration for the scanning service */
export interface ScannerConfig {
  /** viem PublicClient connected to Tempo RPC */
  publicClient: PublicClient;
  /** StealthAnnouncer contract address */
  announcerAddress: Address;
  /** Recipient's viewing private key (for ECDH checks) */
  viewingPrivateKey: Hex;
  /** Recipient's spending public key (for stealth address verification) */
  spendingPubKey: CompressedPubKey;
  /** Scheme ID to filter for (default: 1n) */
  schemeId?: bigint;
  /** Block polling interval in milliseconds (default: 2000) */
  pollIntervalMs?: number;
  /** Number of blocks to scan per batch (default: 100) */
  batchSize?: number;
}

// ── Announcement event ABI ─────────────────────────────────────────────────────

const ANNOUNCEMENT_EVENT = parseAbiItem(
  "event Announcement(uint256 indexed schemeId, address indexed stealthAddress, address indexed caller, bytes ephemeralPubKey, uint8 viewTag, bytes metadata)"
);

// ── Helpers ────────────────────────────────────────────────────────────────────

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

/** Constant-time address comparison to prevent timing side-channels (H-TS-2). */
function addressEquals(a: string, b: string): boolean {
  const aBuf = Buffer.from(a.slice(2).toLowerCase(), "hex");
  const bBuf = Buffer.from(b.slice(2).toLowerCase(), "hex");
  if (aBuf.length !== bBuf.length) return false;
  return timingSafeEqual(aBuf, bBuf);
}

/**
 * Check if an announcement is addressed to us.
 * Returns DetectedPayment if match, null otherwise.
 */
function checkAnnouncement(
  stealthAddress: Address,
  ephemeralPubKeyHex: Hex,
  viewTag: number,
  viewingPrivateKey: Hex,
  spendingPubKey: CompressedPubKey
): { sharedSecretScalar: Hex } | null {
  const viewingPrivBytes = hexToBytes(viewingPrivateKey);
  const ephemeralPubBytes = hexToBytes(ephemeralPubKeyHex);

  // Parse ephemeral public key
  let ephemeralPoint;
  try {
    ephemeralPoint = secp256k1.ProjectivePoint.fromHex(ephemeralPubBytes);
  } catch {
    return null; // Invalid ephemeral key
  }

  // C-TS-3: Validate viewing private key scalar range
  const viewingPrivScalar = bytesToBigInt(viewingPrivBytes);
  if (viewingPrivScalar === 0n || viewingPrivScalar >= secp256k1.CURVE.n) {
    return null;
  }

  // Compute shared secret: S' = k_view * R
  const sharedPoint = ephemeralPoint.multiply(viewingPrivScalar);
  const sharedCompressed = sharedPoint.toRawBytes(true);

  // Hash the shared secret
  const sharedHash = keccak_256(sharedCompressed);

  // Fast filter: check view tag
  if (sharedHash[0] !== viewTag) {
    return null;
  }

  // s' = hash as scalar (mod n)
  const s = bytesToBigInt(sharedHash) % secp256k1.CURVE.n;

  // C-TS-2: Reject degenerate zero scalar
  if (s === 0n) {
    return null;
  }

  // K_stealth' = K_spend + s' * G
  const spendingPubBytes = hexToBytes(spendingPubKey);
  const spendingPoint = secp256k1.ProjectivePoint.fromHex(spendingPubBytes);
  const sTimesG = secp256k1.ProjectivePoint.BASE.multiply(s);
  const stealthPoint = spendingPoint.add(sTimesG);

  // Compute address
  const stealthPubUncompressed = stealthPoint.toRawBytes(false);
  const computedAddress = pubKeyToAddress(stealthPubUncompressed);

  // H-TS-2: Constant-time address comparison
  if (!addressEquals(computedAddress, stealthAddress)) {
    return null;
  }

  const sHex = `0x${s.toString(16).padStart(64, "0")}` as Hex;
  return { sharedSecretScalar: sHex };
}

// ── AnnouncementScanner ────────────────────────────────────────────────────────

export class AnnouncementScanner {
  private config: Required<ScannerConfig>;
  private lastScannedBlock: bigint = 0n;
  private pollTimer: ReturnType<typeof setInterval> | null = null;
  private isRunning = false;

  constructor(config: ScannerConfig) {
    this.config = {
      ...config,
      schemeId: config.schemeId ?? 1n,
      pollIntervalMs: config.pollIntervalMs ?? 2000,
      batchSize: config.batchSize ?? 100,
    };
  }

  /**
   * Start polling for announcements.
   */
  start(
    fromBlock: bigint | "latest",
    onPayment: (payment: DetectedPayment) => void | Promise<void>
  ): void {
    if (this.isRunning) return;
    this.isRunning = true;

    const init = async () => {
      if (fromBlock === "latest") {
        const latest = await this.config.publicClient.getBlockNumber();
        this.lastScannedBlock =
          latest - BigInt(this.config.batchSize) > 0n
            ? latest - BigInt(this.config.batchSize)
            : 0n;
      } else {
        this.lastScannedBlock = fromBlock;
      }

      this.pollTimer = setInterval(async () => {
        if (!this.isRunning) return;
        try {
          const latest = await this.config.publicClient.getBlockNumber();
          if (latest <= this.lastScannedBlock) return;

          const payments = await this.scanRange(
            this.lastScannedBlock + 1n,
            latest
          );
          for (const payment of payments) {
            await onPayment(payment);
          }
          this.lastScannedBlock = latest;
        } catch (err) {
          // Log and continue polling
          console.error("[AnnouncementScanner] poll error:", err);
        }
      }, this.config.pollIntervalMs);
    };

    init().catch(console.error);
  }

  /** Stop polling. */
  stop(): void {
    this.isRunning = false;
    if (this.pollTimer) {
      clearInterval(this.pollTimer);
      this.pollTimer = null;
    }
  }

  /** Get the last scanned block number. */
  getLastScannedBlock(): bigint {
    return this.lastScannedBlock;
  }

  /** Get the underlying public client (used by method.ts for transfer verification). */
  getPublicClient(): PublicClient {
    return this.config.publicClient;
  }

  /**
   * Scan a specific block range (one-shot, no polling).
   */
  async scanRange(
    fromBlock: bigint,
    toBlock: bigint
  ): Promise<DetectedPayment[]> {
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
      const { stealthAddress, ephemeralPubKey, viewTag, metadata } =
        log.args as {
          schemeId: bigint;
          stealthAddress: Address;
          caller: Address;
          ephemeralPubKey: Hex;
          viewTag: number;
          metadata: Hex;
        };

      const result = checkAnnouncement(
        stealthAddress,
        ephemeralPubKey,
        viewTag,
        this.config.viewingPrivateKey,
        this.config.spendingPubKey
      );

      if (result) {
        detected.push({
          stealthAddress,
          sharedSecretScalar: result.sharedSecretScalar,
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

  /**
   * Verify that a specific transaction hash corresponds to a payment to us.
   */
  async verifyPayment(txHash: Hex): Promise<DetectedPayment | null> {
    const receipt = await this.config.publicClient.getTransactionReceipt({
      hash: txHash,
    });

    for (const log of receipt.logs) {
      // Check if this log is from our announcer contract
      if (
        log.address.toLowerCase() !==
        this.config.announcerAddress.toLowerCase()
      ) {
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

        const result = checkAnnouncement(
          args.stealthAddress,
          args.ephemeralPubKey,
          args.viewTag,
          this.config.viewingPrivateKey,
          this.config.spendingPubKey
        );

        if (result) {
          return {
            stealthAddress: args.stealthAddress,
            sharedSecretScalar: result.sharedSecretScalar,
            ephemeralPubKey: args.ephemeralPubKey,
            blockNumber: log.blockNumber ?? 0n,
            txHash,
            metadata: args.metadata ?? ("0x" as Hex),
            detectedAt: new Date(),
          };
        }
      } catch {
        continue; // Not an Announcement event
      }
    }

    return null;
  }
}
