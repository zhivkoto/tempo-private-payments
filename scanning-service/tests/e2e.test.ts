import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { ScanningService, type DetectedPayment } from "../src/service.js";
import { MCPStealthTransport } from "../src/mcp-transport.js";
import { AccessKeyManager } from "../src/access-key.js";
import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";
import type { Address, Hex, PublicClient } from "viem";
import * as fs from "node:fs";

// ── Helpers ──────────────────────────────────────────────────────────────────

function bytesToHex(bytes: Uint8Array): Hex {
  return `0x${Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")}` as Hex;
}

function hexToBytes(hex: Hex): Uint8Array {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
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

/** Simulate a stealth payment (what the SDK client would do) */
function simulateStealthPayment(viewingPrivKey: Hex, spendingPubKey: Hex) {
  const ephemeralPriv = secp256k1.utils.randomPrivateKey();
  const ephemeralPub = secp256k1.getPublicKey(ephemeralPriv, true);
  const ephemeralPubHex = bytesToHex(ephemeralPub);

  const viewingPrivBytes = hexToBytes(viewingPrivKey);
  const viewingPub = secp256k1.getPublicKey(viewingPrivBytes, true);
  const viewingPoint = secp256k1.ProjectivePoint.fromHex(viewingPub);

  const ephemeralScalar = bytesToBigInt(ephemeralPriv);
  const sharedPoint = viewingPoint.multiply(ephemeralScalar);
  const sharedCompressed = sharedPoint.toRawBytes(true);
  const sharedHash = keccak_256(sharedCompressed);

  const viewTag = sharedHash[0];
  const s = bytesToBigInt(sharedHash) % secp256k1.CURVE.n;

  const spendingPubBytes = hexToBytes(spendingPubKey);
  const spendingPoint = secp256k1.ProjectivePoint.fromHex(spendingPubBytes);
  const sTimesG = secp256k1.ProjectivePoint.BASE.multiply(s);
  const stealthPoint = spendingPoint.add(sTimesG);
  const stealthPubUncompressed = stealthPoint.toRawBytes(false);
  const stealthAddress = pubKeyToAddress(stealthPubUncompressed);

  const txHash = bytesToHex(keccak_256(ephemeralPriv));

  return {
    stealthAddress,
    ephemeralPubKey: ephemeralPubHex,
    viewTag,
    metadata: "0x" as Hex,
    txHash,
  };
}

// ── E2E Test ─────────────────────────────────────────────────────────────────

describe("E2E: Scanning Service + MCP Transport + Access Keys", () => {
  // Generate recipient keys
  const viewingPrivKey = bytesToHex(secp256k1.utils.randomPrivateKey());
  const spendingPriv = secp256k1.utils.randomPrivateKey();
  const spendingPubKey = bytesToHex(secp256k1.getPublicKey(spendingPriv, true));
  const announcerAddress = "0x024a2dEB837e0450dC9eF7Ddc3Ce17af65607E8a" as Address;
  const statePath = "/tmp/e2e-scanner-state.json";

  let service: ScanningService;
  let mcpTransport: MCPStealthTransport;
  let client: Client;
  let accessKeyManager: AccessKeyManager;
  let payment: ReturnType<typeof simulateStealthPayment>;

  beforeAll(async () => {
    // Clean up
    if (fs.existsSync(statePath)) fs.unlinkSync(statePath);

    // Step 1: Simulate a stealth payment
    payment = simulateStealthPayment(viewingPrivKey, spendingPubKey as Hex);

    // Step 2: Create mock RPC that returns our payment as a log
    const mockLog = {
      address: announcerAddress,
      blockNumber: 50n,
      transactionHash: payment.txHash,
      data: "0x",
      topics: [],
      args: {
        schemeId: 1n,
        stealthAddress: payment.stealthAddress,
        caller: "0x0000000000000000000000000000000000000001" as Address,
        ephemeralPubKey: payment.ephemeralPubKey,
        viewTag: payment.viewTag,
        metadata: "0x" as Hex,
      },
    };

    const mockReceipt = {
      logs: [
        {
          address: announcerAddress,
          blockNumber: 50n,
          transactionHash: payment.txHash,
          data: "0x",
          // For verifyPayment we need properly encoded event data
          // So we mock it to go through the scanRange path instead
          topics: [],
        },
      ],
    };

    const mockClient = {
      getBlockNumber: vi.fn().mockResolvedValue(100n),
      getLogs: vi.fn().mockResolvedValue([mockLog]),
      getTransactionReceipt: vi.fn().mockResolvedValue(mockReceipt),
      watchBlockNumber: vi.fn().mockReturnValue(() => {}),
    } as unknown as PublicClient;

    // Step 3: Start scanning service
    service = new ScanningService({
      publicClient: mockClient,
      announcerAddress,
      viewingPrivateKey: viewingPrivKey,
      spendingPubKey: spendingPubKey as Hex,
      statePath,
      healthPort: 3198,
    });

    service.startHealthEndpoint();

    const detectedPayments: DetectedPayment[] = [];
    await service.start(0n, (p) => {
      detectedPayments.push(p);
    });

    // Wait for initial poll
    await new Promise((r) => setTimeout(r, 100));

    // Step 4: Set up MCP transport
    mcpTransport = new MCPStealthTransport(service);
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    client = new Client({ name: "e2e-test-client", version: "0.1.0" });
    await mcpTransport.connect(serverTransport);
    await client.connect(clientTransport);

    // Step 5: Set up access keys
    accessKeyManager = new AccessKeyManager(viewingPrivKey);
  });

  afterAll(async () => {
    await client.close();
    await service.stop();
    service.stopHealthEndpoint();
    if (fs.existsSync(statePath)) fs.unlinkSync(statePath);
  });

  it("should detect the stealth payment via scanning", () => {
    const detected = service.getDetectedPayments();
    expect(detected.length).toBeGreaterThanOrEqual(1);
    expect(detected[0].stealthAddress.toLowerCase()).toBe(
      payment.stealthAddress.toLowerCase()
    );
  });

  it("should report payment via MCP get_scanner_status", async () => {
    const result = await client.callTool({
      name: "get_scanner_status",
      arguments: {},
    });

    const content = result.content as Array<{ type: string; text: string }>;
    const status = JSON.parse(content[0].text);

    expect(Number(status.payments_detected)).toBeGreaterThanOrEqual(1);
    expect(status.is_running).toBe(true);
    expect(Number(status.last_block)).toBeGreaterThan(0);
  });

  it("should scan range via MCP and find payment", async () => {
    const result = await client.callTool({
      name: "scan_range",
      arguments: { from_block: 40, to_block: 60 },
    });

    const content = result.content as Array<{ type: string; text: string }>;
    const payments = JSON.parse(content[0].text);

    expect(payments.length).toBeGreaterThanOrEqual(1);
    expect(payments[0].stealthAddress.toLowerCase()).toBe(
      payment.stealthAddress.toLowerCase()
    );
  });

  it("should track metrics correctly", () => {
    const metrics = service.getMetrics();
    expect(metrics.eventsProcessed).toBeGreaterThan(0);
    expect(metrics.matchesFound).toBeGreaterThan(0);
  });

  it("should serve health endpoint", async () => {
    const res = await fetch("http://localhost:3198/health");
    const data = await res.json();

    expect(data.status).toBe("running");
    expect(Number(data.paymentsDetected)).toBeGreaterThanOrEqual(1);
  });

  it("should manage access keys for service authorization", () => {
    // Generate a scan-only key
    const scanKey = accessKeyManager.generateAccessKey(["scan"], 60_000);
    expect(accessKeyManager.validateAccessKey(scanKey.key, "scan")).toBe(true);
    expect(accessKeyManager.validateAccessKey(scanKey.key, "admin")).toBe(false);

    // Generate an admin key
    const adminKey = accessKeyManager.generateAccessKey(["admin"], 60_000);
    expect(accessKeyManager.validateAccessKey(adminKey.key, "scan")).toBe(true);
    expect(accessKeyManager.validateAccessKey(adminKey.key, "verify")).toBe(true);

    // Rotate keys
    const newAdmin = accessKeyManager.rotateKeys(60_000);
    expect(accessKeyManager.validateAccessKey(scanKey.key, "scan")).toBe(false);
    expect(accessKeyManager.validateAccessKey(adminKey.key, "admin")).toBe(false);
    expect(accessKeyManager.validateAccessKey(newAdmin.key, "admin")).toBe(true);
  });

  it("should persist state to disk", () => {
    service.saveState();
    expect(fs.existsSync(statePath)).toBe(true);

    const raw = fs.readFileSync(statePath, "utf-8");
    const state = JSON.parse(raw);
    expect(Number(state.lastScannedBlock)).toBeGreaterThan(0);
  });
});
