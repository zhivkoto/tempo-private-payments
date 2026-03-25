import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { MCPStealthTransport } from "../src/mcp-transport.js";
import type { ScanningService, DetectedPayment } from "../src/service.js";
import type { Address, Hex } from "viem";

// ── Mock ScanningService ────────────────────────────────────────────────────

function createMockService(overrides: Partial<ScanningService> = {}): ScanningService {
  return {
    verifyPayment: vi.fn().mockResolvedValue(null),
    getLastScannedBlock: vi.fn().mockReturnValue(100n),
    getChainTip: vi.fn().mockReturnValue(105n),
    getMetrics: vi.fn().mockReturnValue({
      scanLatencyMs: [],
      matchesFound: 3,
      eventsProcessed: 50,
      viewTagFilteredOut: 47,
      lastScanDurationMs: 120,
    }),
    getDetectedPayments: vi.fn().mockReturnValue([]),
    getIsRunning: vi.fn().mockReturnValue(true),
    scanRange: vi.fn().mockResolvedValue([]),
    ...overrides,
  } as unknown as ScanningService;
}

const MOCK_PAYMENT: DetectedPayment = {
  stealthAddress: "0x1234567890abcdef1234567890abcdef12345678" as Address,
  sharedSecretScalar: "0x" + "ab".repeat(32) as Hex,
  ephemeralPubKey: "0x" + "cd".repeat(33) as Hex,
  blockNumber: 50n,
  txHash: "0x" + "ef".repeat(32) as Hex,
  metadata: "0x" as Hex,
  detectedAt: new Date("2026-01-01T00:00:00Z"),
};

// ── Tests ────────────────────────────────────────────────────────────────────

describe("MCPStealthTransport", () => {
  let mcpTransport: MCPStealthTransport;
  let client: Client;
  let mockService: ScanningService;

  beforeEach(async () => {
    mockService = createMockService();
    mcpTransport = new MCPStealthTransport(mockService);

    // Set up in-memory transport pair
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();

    client = new Client({ name: "test-client", version: "0.1.0" });

    // Connect both sides
    await mcpTransport.connect(serverTransport);
    await client.connect(clientTransport);
  });

  afterEach(async () => {
    await client.close();
  });

  describe("tool registration and discovery", () => {
    it("should register all three tools", async () => {
      const result = await client.listTools();
      const toolNames = result.tools.map((t) => t.name);

      expect(toolNames).toContain("verify_stealth_payment");
      expect(toolNames).toContain("get_scanner_status");
      expect(toolNames).toContain("scan_range");
      expect(result.tools).toHaveLength(3);
    });

    it("should have correct schemas for verify_stealth_payment", async () => {
      const result = await client.listTools();
      const verifyTool = result.tools.find((t) => t.name === "verify_stealth_payment");

      expect(verifyTool).toBeDefined();
      expect(verifyTool!.inputSchema.properties).toHaveProperty("tx_hash");
    });
  });

  describe("verify_stealth_payment", () => {
    it("should return valid=true for a matching payment", async () => {
      (mockService.verifyPayment as ReturnType<typeof vi.fn>).mockResolvedValue(MOCK_PAYMENT);

      const result = await client.callTool({
        name: "verify_stealth_payment",
        arguments: { tx_hash: "0x" + "ef".repeat(32) },
      });

      const content = result.content as Array<{ type: string; text: string }>;
      const parsed = JSON.parse(content[0].text);

      expect(parsed.valid).toBe(true);
      expect(parsed.stealth_address).toBe(MOCK_PAYMENT.stealthAddress);
      expect(parsed.metadata).toBeDefined();
    });

    it("should return valid=false for non-matching payment", async () => {
      const result = await client.callTool({
        name: "verify_stealth_payment",
        arguments: { tx_hash: "0x" + "00".repeat(32) },
      });

      const content = result.content as Array<{ type: string; text: string }>;
      const parsed = JSON.parse(content[0].text);

      expect(parsed.valid).toBe(false);
      expect(parsed.stealth_address).toBeNull();
    });

    it("should handle errors gracefully", async () => {
      (mockService.verifyPayment as ReturnType<typeof vi.fn>).mockRejectedValue(
        new Error("Transaction not found")
      );

      const result = await client.callTool({
        name: "verify_stealth_payment",
        arguments: { tx_hash: "0xinvalid" },
      });

      const content = result.content as Array<{ type: string; text: string }>;
      const parsed = JSON.parse(content[0].text);

      expect(parsed.valid).toBe(false);
      expect(parsed.error).toBe("Transaction not found");
      expect(result.isError).toBe(true);
    });
  });

  describe("get_scanner_status", () => {
    it("should return current scanner status", async () => {
      const result = await client.callTool({
        name: "get_scanner_status",
        arguments: {},
      });

      const content = result.content as Array<{ type: string; text: string }>;
      const parsed = JSON.parse(content[0].text);

      expect(parsed.last_block).toBe("100");
      expect(parsed.chain_tip).toBe("105");
      expect(parsed.lag).toBe("5");
      expect(parsed.is_running).toBe(true);
      expect(parsed.metrics.matches_found).toBe(3);
      expect(parsed.metrics.events_processed).toBe(50);
    });
  });

  describe("scan_range", () => {
    it("should return detected payments for a range", async () => {
      (mockService.scanRange as ReturnType<typeof vi.fn>).mockResolvedValue([MOCK_PAYMENT]);

      const result = await client.callTool({
        name: "scan_range",
        arguments: { from_block: 40, to_block: 60 },
      });

      const content = result.content as Array<{ type: string; text: string }>;
      const parsed = JSON.parse(content[0].text);

      expect(parsed).toHaveLength(1);
      expect(parsed[0].stealthAddress).toBe(MOCK_PAYMENT.stealthAddress);
      expect(parsed[0].blockNumber).toBe("50");
    });

    it("should return empty array when no payments found", async () => {
      const result = await client.callTool({
        name: "scan_range",
        arguments: { from_block: 1, to_block: 10 },
      });

      const content = result.content as Array<{ type: string; text: string }>;
      const parsed = JSON.parse(content[0].text);

      expect(parsed).toHaveLength(0);
    });

    it("should handle scan errors", async () => {
      (mockService.scanRange as ReturnType<typeof vi.fn>).mockRejectedValue(
        new Error("RPC timeout")
      );

      const result = await client.callTool({
        name: "scan_range",
        arguments: { from_block: 1, to_block: 1000000 },
      });

      const content = result.content as Array<{ type: string; text: string }>;
      const parsed = JSON.parse(content[0].text);

      expect(parsed.error).toBe("RPC timeout");
      expect(result.isError).toBe(true);
    });
  });

  describe("concurrent tool calls", () => {
    it("should handle multiple concurrent calls", async () => {
      (mockService.verifyPayment as ReturnType<typeof vi.fn>).mockResolvedValue(MOCK_PAYMENT);

      const results = await Promise.all([
        client.callTool({
          name: "get_scanner_status",
          arguments: {},
        }),
        client.callTool({
          name: "verify_stealth_payment",
          arguments: { tx_hash: "0x" + "ef".repeat(32) },
        }),
        client.callTool({
          name: "scan_range",
          arguments: { from_block: 1, to_block: 10 },
        }),
      ]);

      expect(results).toHaveLength(3);

      // All calls should succeed
      for (const result of results) {
        const content = result.content as Array<{ type: string; text: string }>;
        expect(content).toHaveLength(1);
        expect(() => JSON.parse(content[0].text)).not.toThrow();
      }
    });
  });
});
