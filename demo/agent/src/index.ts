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
import {
  parseConfidentialChallenge,
  executeConfidentialCharge,
  buildAuthorizationHeader,
} from "@cmpp/client";

// ── Configuration ──────────────────────────────────────────────────────────────

const SERVICE_URL = process.env.SERVICE_URL || "http://localhost:3000";
const TEMPO_TESTNET_RPC =
  process.env.TEMPO_TESTNET_RPC || "https://rpc.moderato.tempo.xyz";
const AGENT_PRIVATE_KEY = (process.env.AGENT_PRIVATE_KEY ||
  process.env.PRIVATE_KEY) as Hex;
const ANNOUNCER_ADDRESS = (process.env.ANNOUNCER_ADDRESS ||
  "0x024a2dEB837e0450dC9eF7Ddc3Ce17af65607E8a") as Address;
const REGISTRY_ADDRESS = (process.env.REGISTRY_ADDRESS ||
  "0x145560c016F29d212A385a319930Ecff4A1a62fC") as Address;
// TIP-20 precompile on Tempo
const TOKEN_ADDRESS = (process.env.TOKEN_ADDRESS ||
  "0x0000000000000000000000000000000000000001") as Address;

if (!AGENT_PRIVATE_KEY) {
  console.error(
    "AGENT_PRIVATE_KEY or PRIVATE_KEY environment variable required"
  );
  process.exit(1);
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

// ── TIP-20 approve ABI ─────────────────────────────────────────────────────────

const ERC20_ABI = [
  {
    name: "approve",
    type: "function",
    inputs: [
      { name: "spender", type: "address" },
      { name: "amount", type: "uint256" },
    ],
    outputs: [{ type: "bool" }],
    stateMutability: "nonpayable",
  },
  {
    name: "balanceOf",
    type: "function",
    inputs: [{ name: "account", type: "address" }],
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

  // 1. Request the paid endpoint — expect 402
  console.log(`\nRequesting ${SERVICE_URL}/api/data...`);
  const response = await fetch(`${SERVICE_URL}/api/data`);
  console.log("Status:", response.status);

  if (response.status !== 402) {
    console.log("Unexpected status:", response.status);
    const body = await response.text();
    console.log("Body:", body);
    return;
  }

  // 2. Parse the 402 challenge using @cmpp/client
  const wwwAuth = response.headers.get("WWW-Authenticate");
  if (!wwwAuth) {
    console.log("No WWW-Authenticate header");
    return;
  }
  console.log("WWW-Authenticate:", wwwAuth.substring(0, 100) + "...");

  const challenge = parseConfidentialChallenge(wwwAuth);
  if (!challenge) {
    console.log("Not a confidential payment challenge");
    return;
  }

  console.log(`\nChallenge ID: ${challenge.id}`);
  console.log(`Stealth-meta: ${challenge.stealthMeta.substring(0, 30)}...`);
  console.log(`Nonce: ${challenge.nonce}`);

  // Parse payment request to get amount
  let paymentAmount = 1000n;
  if (challenge.request) {
    try {
      const decoded = JSON.parse(
        Buffer.from(
          challenge.request.replace(/-/g, "+").replace(/_/g, "/") + "==",
          "base64"
        ).toString("utf-8")
      );
      paymentAmount = BigInt(decoded.amount || "1000");
      console.log(`Payment amount: ${paymentAmount}`);
      console.log(`Token: ${decoded.token}`);
    } catch {
      console.log("Could not decode payment request, using default amount");
    }
  }

  // 3. Execute the confidential charge using @cmpp/client
  // This handles: stealth address derivation, TIP-20 transfer, announcement
  console.log("\nExecuting confidential charge...");
  console.log("  Step 1: Deriving stealth address from stealth-meta...");
  console.log("  Step 2: Transferring TIP-20 tokens to stealth address...");
  console.log("  Step 3: Calling StealthAnnouncer.announce()...");

  const paymentResult = await executeConfidentialCharge({
    challenge,
    walletClient,
    publicClient,
    tokenAddress: TOKEN_ADDRESS,
    amount: paymentAmount,
    announcerAddress: ANNOUNCER_ADDRESS,
  });

  console.log(`\nPayment complete:`);
  console.log(`  Stealth address: ${paymentResult.stealthAddress}`);
  console.log(`  Transfer tx: ${paymentResult.txHash}`);
  console.log(`  Announcement tx: ${paymentResult.announcementTxHash}`);

  // 4. Retry with credential using @cmpp/client's buildAuthorizationHeader
  console.log("\nRetrying with credential...");
  const authHeader = buildAuthorizationHeader(
    challenge.id,
    paymentResult.credential,
    challenge.nonce
  );

  const dataResponse = await fetch(`${SERVICE_URL}/api/data`, {
    headers: {
      Authorization: authHeader,
    },
  });

  console.log(`Response status: ${dataResponse.status}`);

  if (dataResponse.status === 200) {
    const paymentReceipt = dataResponse.headers.get("Payment-Receipt");
    const data = await dataResponse.json();
    console.log("\nSuccess!");
    console.log("Payment-Receipt:", paymentReceipt);
    console.log("Data:", JSON.stringify(data, null, 2));
  } else {
    const body = await dataResponse.text();
    console.log("\nPayment verification failed");
    console.log("Body:", body);
  }
}

main().catch(console.error);
