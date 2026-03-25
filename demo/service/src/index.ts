import { Hono } from "hono";
import { serve } from "@hono/node-server";
import { createPublicClient, http, type Address, type Hex } from "viem";
import {
  createConfidentialChargeMethod,
  AnnouncementScanner,
} from "@cmpp/server";
import { generateStealthKeys, formatStealthMetaURI } from "@cmpp/client";

// ── Configuration ──────────────────────────────────────────────────────────────

const TEMPO_TESTNET_RPC =
  process.env.TEMPO_TESTNET_RPC || "https://rpc.moderato.tempo.xyz";
const PORT = parseInt(process.env.PORT || "3000");
const ANNOUNCER_ADDRESS = (process.env.ANNOUNCER_ADDRESS ||
  "0x024a2dEB837e0450dC9eF7Ddc3Ce17af65607E8a") as Address;
const REGISTRY_ADDRESS = (process.env.REGISTRY_ADDRESS ||
  "0x145560c016F29d212A385a319930Ecff4A1a62fC") as Address;
// TIP-20 precompile on Tempo
const TOKEN_ADDRESS = (process.env.TOKEN_ADDRESS ||
  "0x0000000000000000000000000000000000000001") as Address;
const PAYMENT_AMOUNT = BigInt(process.env.PAYMENT_AMOUNT || "1000");

// ── Stealth keys ───────────────────────────────────────────────────────────────

const { keys, metaAddress } = (() => {
  if (
    process.env.STEALTH_SPENDING_KEY &&
    process.env.STEALTH_VIEWING_KEY
  ) {
    // Use pre-configured keys
    const { secp256k1 } = require("@noble/curves/secp256k1");
    const spendingPriv = Buffer.from(
      (process.env.STEALTH_SPENDING_KEY as string).replace("0x", ""),
      "hex"
    );
    const viewingPriv = Buffer.from(
      (process.env.STEALTH_VIEWING_KEY as string).replace("0x", ""),
      "hex"
    );
    const spendingPub = secp256k1.getPublicKey(spendingPriv, true);
    const viewingPub = secp256k1.getPublicKey(viewingPriv, true);
    const metaBytes = new Uint8Array(66);
    metaBytes.set(spendingPub, 0);
    metaBytes.set(viewingPub, 33);
    const metaHex =
      `0x${Array.from(metaBytes)
        .map((b: number) => b.toString(16).padStart(2, "0"))
        .join("")}` as Hex;

    return {
      keys: {
        spending: {
          privateKey: process.env.STEALTH_SPENDING_KEY as Hex,
          publicKey: `0x${Buffer.from(spendingPub).toString("hex")}` as Hex,
        },
        viewing: {
          privateKey: process.env.STEALTH_VIEWING_KEY as Hex,
          publicKey: `0x${Buffer.from(viewingPub).toString("hex")}` as Hex,
        },
      },
      metaAddress: metaHex,
    };
  }
  return generateStealthKeys();
})();

const stealthMetaURI = formatStealthMetaURI(metaAddress);

console.log("Service stealth meta-address:", stealthMetaURI);
console.log("Spending pub:", keys.spending.publicKey);
console.log("Viewing pub:", keys.viewing.publicKey);

// ── viem client ────────────────────────────────────────────────────────────────

const publicClient = createPublicClient({
  transport: http(TEMPO_TESTNET_RPC),
});

// ── AnnouncementScanner from @cmpp/server ──────────────────────────────────────

const scanner = new AnnouncementScanner({
  publicClient,
  announcerAddress: ANNOUNCER_ADDRESS,
  viewingPrivateKey: keys.viewing.privateKey,
  spendingPubKey: keys.spending.publicKey,
  schemeId: 1n,
  pollIntervalMs: 2000,
  batchSize: 100,
});

// Start scanning from latest block
scanner.start("latest", (payment) => {
  console.log(
    `[Scanner] Detected payment to ${payment.stealthAddress} in tx ${payment.txHash}`
  );
});

// ── Confidential Charge Method from @cmpp/server ───────────────────────────────

const method = createConfidentialChargeMethod({
  stealthMetaURI,
  scanner,
  tokenAddress: TOKEN_ADDRESS,
  amount: PAYMENT_AMOUNT,
  challengeTimeoutMs: 60000, // 60s for demo
});

// ── Hono App ───────────────────────────────────────────────────────────────────

const app = new Hono();

// Health check
app.get("/health", (c) =>
  c.json({
    status: "ok",
    stealthMetaURI,
    tokenAddress: TOKEN_ADDRESS,
    amount: PAYMENT_AMOUNT.toString(),
    chainId: 42431,
    announcer: ANNOUNCER_ADDRESS,
    registry: REGISTRY_ADDRESS,
  })
);

// Paid endpoint — uses @cmpp/server's createConfidentialChargeMethod
app.get("/api/data", async (c) => {
  const authHeader = c.req.header("Authorization");

  if (!authHeader) {
    // Issue 402 challenge with stealth-meta, token, and amount
    const challenge = method.buildChallenge();
    return c.text("Payment Required", 402, {
      "WWW-Authenticate": challenge,
    });
  }

  // Verify credential using @cmpp/server — checks announcement + TIP-20 transfer
  const result = await method.verifyCredential(authHeader);

  if (!result.valid || !result.payment) {
    const challenge = method.buildChallenge();
    return c.json(
      {
        error: "Payment Required",
        message: result.error || "Invalid or expired credential.",
      },
      402,
      { "WWW-Authenticate": challenge }
    );
  }

  // Payment verified — serve data
  return c.json(
    {
      data: {
        message: "This is confidential-payment-gated data",
        timestamp: new Date().toISOString(),
        paymentId: result.paymentId,
        stealthAddress: result.payment.stealthAddress,
        verifiedTx: result.payment.txHash,
      },
    },
    200,
    {
      "Payment-Receipt": `id="${result.paymentId}", status="settled"`,
    }
  );
});

// ── Start server ───────────────────────────────────────────────────────────────

serve({ fetch: app.fetch, port: PORT });
console.log(`Demo service running on http://localhost:${PORT}`);
console.log(`Paid endpoint: GET /api/data`);
console.log(`Health: GET /health`);
console.log(`Token: ${TOKEN_ADDRESS} | Amount: ${PAYMENT_AMOUNT}`);
console.log(`Chain: Tempo Testnet (42431) | RPC: ${TEMPO_TESTNET_RPC}`);
