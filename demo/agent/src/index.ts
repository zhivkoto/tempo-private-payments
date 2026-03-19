import {
  createPublicClient,
  createWalletClient,
  http,
  encodeFunctionData,
  type Address,
  type Hex,
  type Chain,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";

// ── Inline stealth helpers ─────────────────────────────────────────────────────

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

function generateStealthAddress(spendingPubKey: Uint8Array, viewingPubKey: Uint8Array) {
  const ephPriv = secp256k1.utils.randomPrivateKey();
  const ephPub = secp256k1.getPublicKey(ephPriv, true);

  const viewingPoint = secp256k1.ProjectivePoint.fromHex(viewingPubKey);
  const sharedPoint = viewingPoint.multiply(bytesToBigInt(ephPriv));
  const sharedCompressed = sharedPoint.toRawBytes(true);
  const sharedHash = keccak_256(sharedCompressed);

  const viewTag = sharedHash[0];
  const s = bytesToBigInt(sharedHash) % secp256k1.CURVE.n;

  const spendingPoint = secp256k1.ProjectivePoint.fromHex(spendingPubKey);
  const sTimesG = secp256k1.ProjectivePoint.BASE.multiply(s);
  const stealthPoint = spendingPoint.add(sTimesG);
  const stealthPubUncompressed = stealthPoint.toRawBytes(false);
  const stealthAddress = pubKeyToAddress(stealthPubUncompressed);

  return {
    stealthAddress: stealthAddress as Address,
    ephemeralPubKey: ephPub,
    viewTag,
  };
}

// ── Configuration ──────────────────────────────────────────────────────────────

const SERVICE_URL = process.env.SERVICE_URL || "http://localhost:3000";
const TEMPO_TESTNET_RPC = process.env.TEMPO_TESTNET_RPC || "https://rpc.moderato.tempo.xyz";
const AGENT_PRIVATE_KEY = (process.env.AGENT_PRIVATE_KEY || process.env.PRIVATE_KEY) as Hex;
const ANNOUNCER_ADDRESS = (process.env.ANNOUNCER_ADDRESS || "0x024a2dEB837e0450dC9eF7Ddc3Ce17af65607E8a") as Address;
const TOKEN_ADDRESS = (process.env.TOKEN_ADDRESS || "0x0000000000000000000000000000000000000001") as Address;

if (!AGENT_PRIVATE_KEY) {
  console.error("AGENT_PRIVATE_KEY or PRIVATE_KEY environment variable required");
  process.exit(1);
}

// ── Auth param parser ──────────────────────────────────────────────────────────

function parseAuthParams(str: string): Record<string, string> {
  const params: Record<string, string> = {};
  const regex = /([a-zA-Z_-]+)\s*=\s*"([^"]*)"/g;
  let match;
  while ((match = regex.exec(str)) !== null) {
    params[match[1]] = match[2];
  }
  return params;
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

// ── Tempo chain definition ─────────────────────────────────────────────────────

const tempoTestnet: Chain = {
  id: 42431,
  name: "Tempo Testnet",
  nativeCurrency: { name: "PathUSD", symbol: "PUSD", decimals: 18 },
  rpcUrls: {
    default: { http: ["https://rpc.moderato.tempo.xyz"] },
  },
};

// ── Announcer ABI ──────────────────────────────────────────────────────────────

const ANNOUNCER_ABI = [
  {
    name: "announce",
    type: "function",
    inputs: [
      { name: "schemeId", type: "uint256" },
      { name: "stealthAddress", type: "address" },
      { name: "ephemeralPubKey", type: "bytes" },
      { name: "viewTag", type: "uint8" },
      { name: "metadata", type: "bytes" },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    name: "announcementFee",
    type: "function",
    inputs: [],
    outputs: [{ type: "uint256" }],
    stateMutability: "view",
  },
] as const;

// ── Main ───────────────────────────────────────────────────────────────────────

async function main() {
  const account = privateKeyToAccount(AGENT_PRIVATE_KEY);
  console.log("Agent address:", account.address);

  const publicClient = createPublicClient({
    chain: tempoTestnet,
    transport: http(TEMPO_TESTNET_RPC),
  });

  const walletClient = createWalletClient({
    account,
    chain: tempoTestnet,
    transport: http(TEMPO_TESTNET_RPC),
  });

  // 1. Request the paid endpoint
  console.log(`\n📡 Requesting ${SERVICE_URL}/api/data...`);
  const response = await fetch(`${SERVICE_URL}/api/data`);
  console.log("Status:", response.status);

  if (response.status !== 402) {
    console.log("Unexpected status:", response.status);
    const body = await response.text();
    console.log("Body:", body);
    return;
  }

  // 2. Parse the 402 challenge
  const wwwAuth = response.headers.get("WWW-Authenticate");
  if (!wwwAuth) {
    console.log("❌ No WWW-Authenticate header");
    return;
  }
  console.log("WWW-Authenticate:", wwwAuth.substring(0, 100) + "...");

  if (!wwwAuth.startsWith("Payment")) {
    console.log("❌ Not a Payment challenge");
    return;
  }

  const params = parseAuthParams(wwwAuth.slice("Payment".length));
  const challengeId = params["id"];
  const stealthMeta = params["stealth-meta"];
  const requestParam = params["request"];

  if (!stealthMeta) {
    console.log("❌ No stealth-meta in challenge");
    return;
  }

  console.log(`\n🔐 Challenge ID: ${challengeId}`);
  console.log(`Stealth-meta: ${stealthMeta.substring(0, 30)}...`);

  // 3. Parse stealth meta-address
  const metaHex = stealthMeta.slice(7); // Remove "st:eth:"
  const metaBytes = hexToBytes(metaHex);
  const spendingPub = metaBytes.slice(0, 33);
  const viewingPub = metaBytes.slice(33, 66);

  // Parse payment request
  let paymentAmount = 1000n;
  if (requestParam) {
    try {
      const decoded = JSON.parse(base64urlDecode(requestParam));
      paymentAmount = BigInt(decoded.amount || "1000");
      console.log(`Payment amount: ${paymentAmount}`);
    } catch {
      console.log("Could not decode payment request, using default amount");
    }
  }

  // 4. Derive stealth address
  console.log("\n🎲 Deriving stealth address...");
  const stealth = generateStealthAddress(spendingPub, viewingPub);
  console.log(`Stealth address: ${stealth.stealthAddress}`);
  console.log(`Ephemeral pub key: ${bytesToHex(stealth.ephemeralPubKey).substring(0, 20)}...`);
  console.log(`View tag: 0x${stealth.viewTag.toString(16).padStart(2, "0")}`);

  // 5. Call StealthAnnouncer.announce()
  // (In a real flow, we'd also transfer TIP-20 to the stealth address first,
  //  but on testnet with fee=0 we just need the announcement)
  console.log("\n📢 Calling StealthAnnouncer.announce()...");

  const metadataBytes = new TextEncoder().encode(challengeId);
  const metadataHex = bytesToHex(metadataBytes) as Hex;
  const ephPubHex = bytesToHex(stealth.ephemeralPubKey) as Hex;

  const announceData = encodeFunctionData({
    abi: ANNOUNCER_ABI,
    functionName: "announce",
    args: [
      1n, // scheme ID
      stealth.stealthAddress as Address,
      ephPubHex,
      stealth.viewTag,
      metadataHex,
    ],
  });

  const announceTxHash = await walletClient.sendTransaction({
    to: ANNOUNCER_ADDRESS,
    data: announceData,
  });

  console.log(`Announcement tx: ${announceTxHash}`);

  // Wait for confirmation
  console.log("Waiting for confirmation...");
  const receipt = await publicClient.waitForTransactionReceipt({
    hash: announceTxHash,
  });
  console.log(`Confirmed in block ${receipt.blockNumber}, status: ${receipt.status}`);

  // 6. Retry with credential
  console.log("\n🔑 Retrying with credential...");
  const credential = base64urlEncode(announceTxHash);
  const authHeader = `Payment id="${challengeId}", credential="${credential}"`;

  const dataResponse = await fetch(`${SERVICE_URL}/api/data`, {
    headers: {
      Authorization: authHeader,
    },
  });

  console.log(`Response status: ${dataResponse.status}`);

  if (dataResponse.status === 200) {
    const paymentReceipt = dataResponse.headers.get("Payment-Receipt");
    const data = await dataResponse.json();
    console.log("\n✅ Success!");
    console.log("Payment-Receipt:", paymentReceipt);
    console.log("Data:", JSON.stringify(data, null, 2));
  } else {
    const body = await dataResponse.text();
    console.log("\n❌ Payment verification failed");
    console.log("Body:", body);
  }
}

main().catch(console.error);
