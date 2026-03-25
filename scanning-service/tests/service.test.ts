import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { ScanningService, type DetectedPayment } from "../src/service.js";
import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";
import type { Address, Hex, PublicClient } from "viem";
import * as fs from "node:fs";

// ── Test key generation helpers ──────────────────────────────────────────────

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

/** Generate a mock stealth announcement that matches our keys */
function generateMockAnnouncement(viewingPrivKey: Hex, spendingPubKey: Hex) {
  // Generate ephemeral keypair
  const ephemeralPriv = secp256k1.utils.randomPrivateKey();
  const ephemeralPub = secp256k1.getPublicKey(ephemeralPriv, true);
  const ephemeralPubHex = bytesToHex(ephemeralPub);

  // Compute shared secret: S = r * K_view
  const viewingPubBytes = hexToBytes(spendingPubKey); // just need viewing pub for ECDH
  const viewingPrivBytes = hexToBytes(viewingPrivKey);
  const viewingPrivScalar = bytesToBigInt(viewingPrivBytes);

  // Get viewing public key from private key
  const viewingPub = secp256k1.getPublicKey(viewingPrivBytes, true);
  const viewingPoint = secp256k1.ProjectivePoint.fromHex(viewingPub);

  // Shared secret from ephemeral side: S = r * K_view
  const ephemeralScalar = bytesToBigInt(ephemeralPriv);
  const sharedPoint = viewingPoint.multiply(ephemeralScalar);
  const sharedCompressed = sharedPoint.toRawBytes(true);
  const sharedHash = keccak_256(sharedCompressed);

  const viewTag = sharedHash[0];
  const s = bytesToBigInt(sharedHash) % secp256k1.CURVE.n;

  // Compute stealth address
  const spendingPubBytes = hexToBytes(spendingPubKey);
  const spendingPoint = secp256k1.ProjectivePoint.fromHex(spendingPubBytes);
  const sTimesG = secp256k1.ProjectivePoint.BASE.multiply(s);
  const stealthPoint = spendingPoint.add(sTimesG);
  const stealthPubUncompressed = stealthPoint.toRawBytes(false);
  const stealthAddress = pubKeyToAddress(stealthPubUncompressed);

  return {
    stealthAddress,
    ephemeralPubKey: ephemeralPubHex,
    viewTag,
    metadata: "0x" as Hex,
  };
}

// ── Tests ────────────────────────────────────────────────────────────────────

describe("ScanningService", () => {
  const viewingPrivKey = bytesToHex(secp256k1.utils.randomPrivateKey());
  const viewingPub = secp256k1.getPublicKey(hexToBytes(viewingPrivKey), true);
  const spendingPrivKey = secp256k1.utils.randomPrivateKey();
  const spendingPubKey = bytesToHex(secp256k1.getPublicKey(spendingPrivKey, true));

  const announcerAddress = "0x024a2dEB837e0450dC9eF7Ddc3Ce17af65607E8a" as Address;
  const statePath = "/tmp/test-scanner-state.json";

  let service: ScanningService;

  function createMockClient(overrides: Partial<PublicClient> = {}): PublicClient {
    return {
      getBlockNumber: vi.fn().mockResolvedValue(100n),
      getLogs: vi.fn().mockResolvedValue([]),
      getTransactionReceipt: vi.fn().mockResolvedValue({ logs: [] }),
      watchBlockNumber: vi.fn().mockReturnValue(() => {}),
      ...overrides,
    } as unknown as PublicClient;
  }

  beforeEach(() => {
    // Clean up state file
    if (fs.existsSync(statePath)) {
      fs.unlinkSync(statePath);
    }
  });

  afterEach(async () => {
    if (service) {
      await service.stop();
      service.stopHealthEndpoint();
    }
    if (fs.existsSync(statePath)) {
      fs.unlinkSync(statePath);
    }
  });

  describe("state persistence", () => {
    it("should save and load state from disk", async () => {
      const mockClient = createMockClient();
      service = new ScanningService({
        publicClient: mockClient,
        announcerAddress,
        viewingPrivateKey: viewingPrivKey,
        spendingPubKey: spendingPubKey as Hex,
        statePath,
      });

      // Simulate scanning
      await service.start(50n, () => {});
      // Wait a tick for initial poll
      await new Promise((r) => setTimeout(r, 50));
      await service.stop();

      // Verify state was saved
      expect(fs.existsSync(statePath)).toBe(true);
      const raw = fs.readFileSync(statePath, "utf-8");
      const state = JSON.parse(raw);
      expect(state.lastScannedBlock).toBe("100");
    });

    it("should resume from persisted state", async () => {
      // Write initial state
      fs.writeFileSync(statePath, JSON.stringify({ lastScannedBlock: "42" }));

      const mockClient = createMockClient();
      service = new ScanningService({
        publicClient: mockClient,
        announcerAddress,
        viewingPrivateKey: viewingPrivKey,
        spendingPubKey: spendingPubKey as Hex,
        statePath,
      });

      expect(service.getLastScannedBlock()).toBe(42n);
    });
  });

  describe("batch processing", () => {
    it("should scan in batches", async () => {
      const getLogs = vi.fn().mockResolvedValue([]);
      const mockClient = createMockClient({
        getBlockNumber: vi.fn().mockResolvedValue(250n),
        getLogs,
      } as unknown as Partial<PublicClient>);

      service = new ScanningService({
        publicClient: mockClient,
        announcerAddress,
        viewingPrivateKey: viewingPrivKey,
        spendingPubKey: spendingPubKey as Hex,
        statePath,
        batchSize: 100,
      });

      await service.start(0n, () => {});
      await new Promise((r) => setTimeout(r, 50));
      await service.stop();

      // Should have called getLogs multiple times for batches
      expect(getLogs.mock.calls.length).toBeGreaterThanOrEqual(2);
    });
  });

  describe("scanRange", () => {
    it("should detect matching announcements", async () => {
      const announcement = generateMockAnnouncement(
        viewingPrivKey,
        spendingPubKey as Hex
      );

      const mockLog = {
        address: announcerAddress,
        blockNumber: 50n,
        transactionHash: "0xabc123" as Hex,
        args: {
          schemeId: 1n,
          stealthAddress: announcement.stealthAddress,
          caller: "0x0000000000000000000000000000000000000001" as Address,
          ephemeralPubKey: announcement.ephemeralPubKey,
          viewTag: announcement.viewTag,
          metadata: "0x" as Hex,
        },
      };

      const mockClient = createMockClient({
        getLogs: vi.fn().mockResolvedValue([mockLog]),
      } as unknown as Partial<PublicClient>);

      service = new ScanningService({
        publicClient: mockClient,
        announcerAddress,
        viewingPrivateKey: viewingPrivKey,
        spendingPubKey: spendingPubKey as Hex,
        statePath,
      });

      const payments = await service.scanRange(40n, 60n);
      expect(payments).toHaveLength(1);
      expect(payments[0].stealthAddress.toLowerCase()).toBe(
        announcement.stealthAddress.toLowerCase()
      );
    });

    it("should filter out non-matching announcements", async () => {
      // Use a different spending pub key so the announcement won't match
      const otherSpendingPriv = secp256k1.utils.randomPrivateKey();
      const otherSpendingPub = bytesToHex(
        secp256k1.getPublicKey(otherSpendingPriv, true)
      );
      const announcement = generateMockAnnouncement(viewingPrivKey, otherSpendingPub as Hex);

      const mockLog = {
        address: announcerAddress,
        blockNumber: 50n,
        transactionHash: "0xabc456" as Hex,
        args: {
          schemeId: 1n,
          stealthAddress: announcement.stealthAddress,
          caller: "0x0000000000000000000000000000000000000001" as Address,
          ephemeralPubKey: announcement.ephemeralPubKey,
          viewTag: announcement.viewTag,
          metadata: "0x" as Hex,
        },
      };

      const mockClient = createMockClient({
        getLogs: vi.fn().mockResolvedValue([mockLog]),
      } as unknown as Partial<PublicClient>);

      service = new ScanningService({
        publicClient: mockClient,
        announcerAddress,
        viewingPrivateKey: viewingPrivKey,
        spendingPubKey: spendingPubKey as Hex,
        statePath,
      });

      const payments = await service.scanRange(40n, 60n);
      // View tag might match (1/256 chance) but address won't
      // Either filtered by view tag or by address mismatch
      expect(payments).toHaveLength(0);
    });
  });

  describe("metrics", () => {
    it("should track events processed and matches", async () => {
      const announcement = generateMockAnnouncement(
        viewingPrivKey,
        spendingPubKey as Hex
      );

      const mockLog = {
        address: announcerAddress,
        blockNumber: 50n,
        transactionHash: "0xdef789" as Hex,
        args: {
          schemeId: 1n,
          stealthAddress: announcement.stealthAddress,
          caller: "0x0000000000000000000000000000000000000001" as Address,
          ephemeralPubKey: announcement.ephemeralPubKey,
          viewTag: announcement.viewTag,
          metadata: "0x" as Hex,
        },
      };

      const mockClient = createMockClient({
        getLogs: vi.fn().mockResolvedValue([mockLog]),
      } as unknown as Partial<PublicClient>);

      service = new ScanningService({
        publicClient: mockClient,
        announcerAddress,
        viewingPrivateKey: viewingPrivKey,
        spendingPubKey: spendingPubKey as Hex,
        statePath,
      });

      await service.scanRange(40n, 60n);
      const metrics = service.getMetrics();
      expect(metrics.eventsProcessed).toBe(1);
      expect(metrics.matchesFound).toBe(1);
    });
  });

  describe("health endpoint", () => {
    it("should return scanner status", async () => {
      const mockClient = createMockClient();
      service = new ScanningService({
        publicClient: mockClient,
        announcerAddress,
        viewingPrivateKey: viewingPrivKey,
        spendingPubKey: spendingPubKey as Hex,
        statePath,
        healthPort: 3199,
      });

      service.startHealthEndpoint();

      const res = await fetch("http://localhost:3199/health");
      const data = await res.json();

      expect(data.status).toBe("stopped");
      expect(data).toHaveProperty("lastScannedBlock");
      expect(data).toHaveProperty("metrics");
    });
  });
});
