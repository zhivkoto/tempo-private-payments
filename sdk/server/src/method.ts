import { randomUUID } from "node:crypto";
import type { Address, Hex } from "viem";
import type { AnnouncementScanner, DetectedPayment } from "./scanner.js";

/** The "st:eth:0x..." URI format used in the stealth-meta auth-param */
type StealthMetaURI = `st:eth:${Hex}`;

/** Configuration for the confidential charge method */
export interface ConfidentialChargeConfig {
  /** The service's stealth meta-address URI */
  stealthMetaURI: StealthMetaURI;
  /** The announcement scanner instance */
  scanner: AnnouncementScanner;
  /** TIP-20 token address for payments */
  tokenAddress: Address;
  /** Expected payment amount in base units */
  amount: bigint;
  /** Challenge timeout in milliseconds (default: 30000) */
  challengeTimeoutMs?: number;
}

/** MPP Method implementation for confidential charge payments */
export interface ConfidentialChargeMethod {
  /**
   * Build the WWW-Authenticate challenge header value.
   * Includes stealth-meta auth-param for cMPP clients.
   */
  buildChallenge(paymentId?: string): string;

  /**
   * Verify a credential from the Authorization header.
   */
  verifyCredential(authHeader: string): Promise<{
    valid: boolean;
    paymentId: string;
    payment?: DetectedPayment;
    error?: string;
  }>;

  /**
   * Clean up resources (clear interval timers).
   */
  destroy(): void;
}

// ── Implementation ─────────────────────────────────────────────────────────────

function generatePaymentId(): string {
  return `inv_${randomUUID()}`;
}

function base64urlEncode(data: string): string {
  const buf = Buffer.from(data, "utf-8");
  return buf
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function base64urlDecode(str: string): string {
  let base64 = str.replace(/-/g, "+").replace(/_/g, "/");
  while (base64.length % 4) base64 += "=";
  return Buffer.from(base64, "base64").toString("utf-8");
}

function parseAuthParams(str: string): Record<string, string> {
  const params: Record<string, string> = {};
  const regex = /([a-zA-Z_-]+)\s*=\s*"([^"]*)"/g;
  let match;
  while ((match = regex.exec(str)) !== null) {
    params[match[1]] = match[2];
  }
  return params;
}

/**
 * Create a confidential charge method instance.
 */
export function createConfidentialChargeMethod(
  config: ConfidentialChargeConfig
): ConfidentialChargeMethod {
  const challengeTimeoutMs = config.challengeTimeoutMs ?? 30000;

  // Track active challenges
  const activeChallenges = new Map<
    string,
    { createdAt: number; amount: bigint }
  >();

  // Track consumed transaction hashes to prevent credential replay (C-MW-1)
  const consumedTxHashes = new Set<string>();

  // Clean up expired challenges periodically
  const cleanupTimer = setInterval(
    () => {
      const now = Date.now();
      for (const [id, challenge] of activeChallenges) {
        if (now - challenge.createdAt > challengeTimeoutMs * 2) {
          activeChallenges.delete(id);
        }
      }
    },
    challengeTimeoutMs * 2
  );

  return {
    buildChallenge(paymentId?: string): string {
      const id = paymentId || generatePaymentId();

      // Store challenge
      activeChallenges.set(id, {
        createdAt: Date.now(),
        amount: config.amount,
      });

      // Build payment request (base64url-encoded JSON)
      const paymentRequest = JSON.stringify({
        token: config.tokenAddress,
        amount: config.amount.toString(),
        chainId: 42431,
      });
      const requestEncoded = base64urlEncode(paymentRequest);

      return `Payment id="${id}", method="tempo", intent="charge", request="${requestEncoded}", stealth-meta="${config.stealthMetaURI}"`;
    },

    async verifyCredential(authHeader: string): Promise<{
      valid: boolean;
      paymentId: string;
      payment?: DetectedPayment;
      error?: string;
    }> {
      if (!authHeader.startsWith("Payment")) {
        return { valid: false, paymentId: "", error: "Invalid auth scheme" };
      }

      const params = parseAuthParams(authHeader.slice("Payment".length));
      const paymentId = params["id"] || "";
      const credential = params["credential"] || "";

      if (!paymentId || !credential) {
        return {
          valid: false,
          paymentId,
          error: "Missing id or credential",
        };
      }

      // Check if challenge exists and is not expired
      const challenge = activeChallenges.get(paymentId);
      if (!challenge) {
        return {
          valid: false,
          paymentId,
          error: "Unknown or expired challenge",
        };
      }

      if (Date.now() - challenge.createdAt > challengeTimeoutMs) {
        activeChallenges.delete(paymentId);
        return {
          valid: false,
          paymentId,
          error: "Challenge expired",
        };
      }

      // Decode credential to get tx hash
      let txHash: Hex;
      try {
        txHash = base64urlDecode(credential) as Hex;
        if (!txHash.startsWith("0x") || txHash.length !== 66) {
          return {
            valid: false,
            paymentId,
            error: "Invalid credential format",
          };
        }
      } catch {
        return {
          valid: false,
          paymentId,
          error: "Failed to decode credential",
        };
      }

      // C-MW-1: Reject replayed transaction hashes
      const txHashLower = txHash.toLowerCase();
      if (consumedTxHashes.has(txHashLower)) {
        return {
          valid: false,
          paymentId,
          error: "Transaction already consumed",
        };
      }

      // Verify the payment on-chain via scanner
      try {
        const payment = await config.scanner.verifyPayment(txHash);
        if (!payment) {
          return {
            valid: false,
            paymentId,
            error: "Payment not found or not addressed to us",
          };
        }

        // Mark tx hash as consumed to prevent replay
        consumedTxHashes.add(txHashLower);

        // Clean up used challenge
        activeChallenges.delete(paymentId);

        return {
          valid: true,
          paymentId,
          payment,
        };
      } catch (err) {
        return {
          valid: false,
          paymentId,
          error: "Verification failed",
        };
      }
    },

    destroy(): void {
      clearInterval(cleanupTimer);
    },
  };
}
