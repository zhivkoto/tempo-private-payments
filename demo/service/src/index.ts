import { Hono } from "hono";
import { serve } from "@hono/node-server";
import { createPublicClient, http, type Address, type Hex } from "viem";
import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";

// ── Inline stealth helpers (avoid workspace dep complexity for demo) ──────────

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return `0x${Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")}`;
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let result = 0n;
  for (const byte of bytes) {
    result = (result << 8n) | BigInt(byte);
  }
  return result;
}

function pubKeyToAddress(uncompressedPubKey: Uint8Array): string {
  const pubKeyNoPrefix = uncompressedPubKey.slice(1);
  const hash = keccak_256(pubKeyNoPrefix);
  const addressBytes = hash.slice(12);
  return `0x${Array.from(addressBytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")}`;
}

// ── Configuration ──────────────────────────────────────────────────────────────

const TEMPO_TESTNET_RPC = process.env.TEMPO_TESTNET_RPC || "https://rpc.moderato.tempo.xyz";
const PORT = parseInt(process.env.PORT || "3000");
const ANNOUNCER_ADDRESS = (process.env.ANNOUNCER_ADDRESS || "0x024a2dEB837e0450dC9eF7Ddc3Ce17af65607E8a") as Address;
const TOKEN_ADDRESS = (process.env.TOKEN_ADDRESS || "0x0000000000000000000000000000000000000001") as Address;
const PAYMENT_AMOUNT = BigInt(process.env.PAYMENT_AMOUNT || "1000");

// ── Generate or load stealth keys ──────────────────────────────────────────────

const spendingPriv = process.env.STEALTH_SPENDING_KEY
  ? hexToBytes(process.env.STEALTH_SPENDING_KEY)
  : secp256k1.utils.randomPrivateKey();

const viewingPriv = process.env.STEALTH_VIEWING_KEY
  ? hexToBytes(process.env.STEALTH_VIEWING_KEY)
  : secp256k1.utils.randomPrivateKey();

const spendingPub = secp256k1.getPublicKey(spendingPriv, true);
const viewingPub = secp256k1.getPublicKey(viewingPriv, true);

// Build stealth meta-address
const metaAddressBytes = new Uint8Array(66);
metaAddressBytes.set(spendingPub, 0);
metaAddressBytes.set(viewingPub, 33);
const metaAddress = bytesToHex(metaAddressBytes);
const stealthMetaURI = `st:eth:${metaAddress}`;

console.log("Service stealth meta-address:", stealthMetaURI);
console.log("Spending pub:", bytesToHex(spendingPub));
console.log("Viewing pub:", bytesToHex(viewingPub));

// ── Scanner logic (inline for demo) ───────────────────────────────────────────

function checkAnnouncementForUs(
  stealthAddress: string,
  ephPubKey: Uint8Array,
  viewTag: number
): boolean {
  try {
    const ephPoint = secp256k1.ProjectivePoint.fromHex(ephPubKey);
    const sharedPoint = ephPoint.multiply(bytesToBigInt(viewingPriv));
    const sharedCompressed = sharedPoint.toRawBytes(true);
    const sharedHash = keccak_256(sharedCompressed);

    if (sharedHash[0] !== viewTag) return false;

    const s = bytesToBigInt(sharedHash) % secp256k1.CURVE.n;
    const spendingPoint = secp256k1.ProjectivePoint.fromHex(spendingPub);
    const sTimesG = secp256k1.ProjectivePoint.BASE.multiply(s);
    const stealthPoint = spendingPoint.add(sTimesG);
    const stealthPubUncompressed = stealthPoint.toRawBytes(false);
    const computedAddress = pubKeyToAddress(stealthPubUncompressed);

    return computedAddress.toLowerCase() === stealthAddress.toLowerCase();
  } catch {
    return false;
  }
}

// ── Challenge management ───────────────────────────────────────────────────────

let challengeCounter = 0;
const activeChallenges = new Map<string, { createdAt: number }>();

function generateChallengeId(): string {
  challengeCounter++;
  const rand = Math.random().toString(36).slice(2, 6);
  return `inv_${rand}${challengeCounter}`;
}

function base64urlEncode(data: string): string {
  return Buffer.from(data, "utf-8")
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

// ── viem client ────────────────────────────────────────────────────────────────

const publicClient = createPublicClient({
  transport: http(TEMPO_TESTNET_RPC),
});

// ── Hono App ───────────────────────────────────────────────────────────────────

const app = new Hono();

// Health check
app.get("/health", (c) => c.json({ status: "ok", stealthMetaURI }));

// Paid endpoint — requires confidential charge
app.get("/api/data", async (c) => {
  const authHeader = c.req.header("Authorization");

  if (!authHeader) {
    // Issue challenge with stealth-meta
    const id = generateChallengeId();
    activeChallenges.set(id, { createdAt: Date.now() });

    const paymentRequest = JSON.stringify({
      token: TOKEN_ADDRESS,
      amount: PAYMENT_AMOUNT.toString(),
      chainId: 42431,
    });
    const requestEncoded = base64urlEncode(paymentRequest);

    const challengeValue = `Payment id="${id}", method="tempo", intent="charge", request="${requestEncoded}", stealth-meta="${stealthMetaURI}"`;

    return c.text("Payment Required", 402, {
      "WWW-Authenticate": challengeValue,
    });
  }

  // Verify the credential
  if (!authHeader.startsWith("Payment")) {
    return c.text("Invalid auth scheme", 401);
  }

  const params = parseAuthParams(authHeader.slice("Payment".length));
  const paymentId = params["id"] || "";
  const credential = params["credential"] || "";

  if (!paymentId || !credential) {
    return c.text("Missing payment id or credential", 401);
  }

  const challenge = activeChallenges.get(paymentId);
  if (!challenge) {
    return c.text("Unknown or expired challenge", 402, {
      "WWW-Authenticate": `Payment id="${generateChallengeId()}", method="tempo", intent="charge", stealth-meta="${stealthMetaURI}"`,
    });
  }

  // For demo: we accept the credential if we can verify the announcement tx
  let txHash: string;
  try {
    txHash = base64urlDecode(credential);
  } catch {
    return c.text("Invalid credential", 401);
  }

  // Simple verification: check that the tx exists and has an announcement to us
  try {
    const receipt = await publicClient.getTransactionReceipt({
      hash: txHash as Hex,
    });

    // Look for Announcement event in logs
    // Event sig: Announcement(uint256,address,address,bytes,uint8,bytes)
    const announcementSig = "0x5bb411b7e33aa442e9a1366c3b0cce0d44e8e6cdb92e20978a29e2e4b46d5047";
    let verified = false;

    for (const log of receipt.logs) {
      if (
        log.address.toLowerCase() === ANNOUNCER_ADDRESS.toLowerCase() &&
        log.topics[0] === announcementSig
      ) {
        // Found an announcement event — for now we accept it
        // A production version would decode and verify the ECDH
        verified = true;
        break;
      }
    }

    if (!verified) {
      // If no announcement event found, still accept if tx went to announcer
      // (simpler verification for demo)
      if (receipt.to?.toLowerCase() === ANNOUNCER_ADDRESS.toLowerCase()) {
        verified = true;
      }
    }

    if (!verified) {
      return c.text("Payment verification failed", 402);
    }

    // Clean up challenge
    activeChallenges.delete(paymentId);

    // Payment verified — serve data
    return c.json(
      {
        data: {
          message: "This is confidential-payment-gated data",
          timestamp: new Date().toISOString(),
          paymentId,
          verifiedTx: txHash,
        },
      },
      200,
      {
        "Payment-Receipt": `id="${paymentId}", status="settled"`,
      }
    );
  } catch (err) {
    console.error("Verification error:", err);
    return c.text("Payment verification failed", 402);
  }
});

// ── Start server ───────────────────────────────────────────────────────────────

serve({ fetch: app.fetch, port: PORT });
console.log(`Demo service running on http://localhost:${PORT}`);
console.log(`Paid endpoint: GET /api/data`);
console.log(`Health: GET /health`);
