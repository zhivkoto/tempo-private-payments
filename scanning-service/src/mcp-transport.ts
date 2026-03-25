import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import type { Hex } from "viem";
import type { ScanningService, DetectedPayment } from "./service.js";

/** Serializable payment for MCP responses */
interface SerializedPayment {
  stealthAddress: string;
  ephemeralPubKey: string;
  blockNumber: string;
  txHash: string;
  metadata: string;
  detectedAt: string;
}

function serializePayment(p: DetectedPayment): SerializedPayment {
  return {
    stealthAddress: p.stealthAddress,
    ephemeralPubKey: p.ephemeralPubKey,
    blockNumber: p.blockNumber.toString(),
    txHash: p.txHash,
    metadata: p.metadata,
    detectedAt: p.detectedAt.toISOString(),
  };
}

/**
 * MCP Transport layer wrapping the scanning service.
 * Exposes stealth payment tools via Model Context Protocol.
 */
export class MCPStealthTransport {
  private server: McpServer;
  private scanningService: ScanningService;

  constructor(scanningService: ScanningService) {
    this.scanningService = scanningService;
    this.server = new McpServer({
      name: "stealth-scanner",
      version: "0.1.0",
    });

    this.registerTools();
  }

  private registerTools(): void {
    // Tool: verify_stealth_payment
    this.server.tool(
      "verify_stealth_payment",
      "Verify a stealth payment by transaction hash",
      {
        tx_hash: z.string().describe("Transaction hash (0x-prefixed hex)"),
      },
      async ({ tx_hash }) => {
        try {
          const payment = await this.scanningService.verifyPayment(tx_hash as Hex);

          if (payment) {
            return {
              content: [
                {
                  type: "text" as const,
                  text: JSON.stringify(
                    {
                      valid: true,
                      stealth_address: payment.stealthAddress,
                      metadata: {
                        blockNumber: payment.blockNumber.toString(),
                        ephemeralPubKey: payment.ephemeralPubKey,
                        detectedAt: payment.detectedAt.toISOString(),
                      },
                    },
                    null,
                    2
                  ),
                },
              ],
            };
          }

          return {
            content: [
              {
                type: "text" as const,
                text: JSON.stringify({ valid: false, stealth_address: null, metadata: null }),
              },
            ],
          };
        } catch (err) {
          return {
            content: [
              {
                type: "text" as const,
                text: JSON.stringify({
                  valid: false,
                  error: err instanceof Error ? err.message : "Unknown error",
                }),
              },
            ],
            isError: true,
          };
        }
      }
    );

    // Tool: get_scanner_status
    this.server.tool(
      "get_scanner_status",
      "Get the current status of the stealth payment scanner",
      {},
      async () => {
        const lastBlock = this.scanningService.getLastScannedBlock();
        const chainTip = this.scanningService.getChainTip();
        const metrics = this.scanningService.getMetrics();
        const payments = this.scanningService.getDetectedPayments();

        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(
                {
                  last_block: lastBlock.toString(),
                  chain_tip: chainTip.toString(),
                  lag: (chainTip - lastBlock).toString(),
                  payments_detected: payments.length,
                  is_running: this.scanningService.getIsRunning(),
                  metrics: {
                    matches_found: metrics.matchesFound,
                    events_processed: metrics.eventsProcessed,
                    view_tag_filter_rate:
                      metrics.eventsProcessed > 0
                        ? (metrics.viewTagFilteredOut / metrics.eventsProcessed).toFixed(4)
                        : "0",
                    last_scan_duration_ms: metrics.lastScanDurationMs,
                  },
                },
                null,
                2
              ),
            },
          ],
        };
      }
    );

    // Tool: scan_range
    this.server.tool(
      "scan_range",
      "Scan a specific block range for stealth payments",
      {
        from_block: z.number().describe("Starting block number"),
        to_block: z.number().describe("Ending block number"),
      },
      async ({ from_block, to_block }) => {
        try {
          const payments = await this.scanningService.scanRange(
            BigInt(from_block),
            BigInt(to_block)
          );

          return {
            content: [
              {
                type: "text" as const,
                text: JSON.stringify(payments.map(serializePayment), null, 2),
              },
            ],
          };
        } catch (err) {
          return {
            content: [
              {
                type: "text" as const,
                text: JSON.stringify({
                  error: err instanceof Error ? err.message : "Unknown error",
                }),
              },
            ],
            isError: true,
          };
        }
      }
    );
  }

  /** Get the underlying MCP server for custom transports */
  getServer(): McpServer {
    return this.server;
  }

  /** Start the MCP server with stdio transport */
  async startStdio(): Promise<void> {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
  }

  /** Connect to a custom transport (for testing) */
  async connect(transport: Parameters<McpServer["connect"]>[0]): Promise<void> {
    await this.server.connect(transport);
  }
}
