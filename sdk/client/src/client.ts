import {
  type Address,
  type Hex,
  type PublicClient,
  type WalletClient,
  encodeFunctionData,
  type Account,
  type Chain,
  type Transport,
} from "viem";
import {
  type StealthMetaURI,
  type GenerateStealthAddressResult,
  type CompressedPubKey,
  generateStealthAddress,
  parseStealthMetaURI,
} from "./stealth.js";

// ── Types ──────────────────────────────────────────────────────────────────────

/** Parsed WWW-Authenticate: Payment challenge with stealth-meta */
export interface ConfidentialChallenge {
  id: string;
  method: string;
  intent: string;
  request: string; // base64url-encoded payment request
  stealthMeta: StealthMetaURI; // "st:eth:0x..." — the recipient's stealth meta-address
  /** H-TS-3: Server-issued nonce that must be returned with the credential */
  nonce: string;
}

/** Result of a confidential payment */
export interface ConfidentialPaymentResult {
  /** Transaction hash of the TIP-20 transfer to the stealth address */
  txHash: Hex;
  /** Transaction hash of the announcement call */
  announcementTxHash: Hex;
  /** The stealth address that received the payment */
  stealthAddress: Address;
  /** Credential string for the Authorization header */
  credential: string;
}

// ── StealthAnnouncer ABI (minimal) ─────────────────────────────────────────────

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
] as const;

// ── Functions ──────────────────────────────────────────────────────────────────

/**
 * Parse a 402 response's WWW-Authenticate header to extract the confidential challenge.
 *
 * Format: Payment id="inv_7x9k", method="tempo", intent="charge",
 *         request="base64url...", stealth-meta="st:eth:0x..."
 */
export function parseConfidentialChallenge(
  wwwAuthenticate: string
): ConfidentialChallenge | null {
  // Check it starts with "Payment"
  if (!wwwAuthenticate.startsWith("Payment")) {
    return null;
  }

  const params = parseAuthParams(wwwAuthenticate.slice("Payment".length));

  const stealthMeta = params["stealth-meta"];
  if (!stealthMeta) {
    return null; // Not a cMPP challenge
  }

  return {
    id: params["id"] || "",
    method: params["method"] || "tempo",
    intent: params["intent"] || "charge",
    request: params["request"] || "",
    stealthMeta: stealthMeta as StealthMetaURI,
    nonce: params["nonce"] || "",
  };
}

/**
 * Execute a confidential charge payment:
 * 1. Parse stealth-meta → derive stealth address
 * 2. Transfer TIP-20 to stealth address
 * 3. Call StealthAnnouncer.announce() with ephemeral pubkey + view tag
 * 4. Return credential for Authorization header
 */
export async function executeConfidentialCharge(params: {
  challenge: ConfidentialChallenge;
  walletClient: WalletClient<Transport, Chain | undefined, Account>;
  publicClient: PublicClient;
  tokenAddress: Address;
  amount: bigint;
  announcerAddress: Address;
}): Promise<ConfidentialPaymentResult> {
  const {
    challenge,
    walletClient,
    publicClient,
    tokenAddress,
    amount,
    announcerAddress,
  } = params;

  // 1. Parse stealth meta-address and derive stealth address
  const { spendingPubKey, viewingPubKey } = parseStealthMetaURI(
    challenge.stealthMeta
  );
  const stealthResult = generateStealthAddress(spendingPubKey, viewingPubKey);

  // 2. Transfer TIP-20 to stealth address
  const transferData = encodeFunctionData({
    abi: [
      {
        name: "transfer",
        type: "function",
        inputs: [
          { name: "to", type: "address" },
          { name: "amount", type: "uint256" },
        ],
        outputs: [{ type: "bool" }],
        stateMutability: "nonpayable",
      },
    ],
    functionName: "transfer",
    args: [stealthResult.stealthAddress, amount],
  });

  const txHash = await walletClient.sendTransaction({
    chain: walletClient.chain ?? null,
    to: tokenAddress,
    data: transferData,
  } as any);

  // Wait for transfer confirmation
  await publicClient.waitForTransactionReceipt({ hash: txHash });

  // 3. Call StealthAnnouncer.announce()
  const metadata = new TextEncoder().encode(challenge.id);
  const metadataHex = `0x${Array.from(metadata)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")}` as Hex;

  const announceData = encodeFunctionData({
    abi: ANNOUNCER_ABI,
    functionName: "announce",
    args: [
      1n, // scheme ID
      stealthResult.stealthAddress,
      stealthResult.ephemeralPubKey,
      stealthResult.viewTag,
      metadataHex,
    ],
  });

  const announcementTxHash = await walletClient.sendTransaction({
    chain: walletClient.chain ?? null,
    to: announcerAddress,
    data: announceData,
  } as any);

  // Wait for announcement confirmation
  await publicClient.waitForTransactionReceipt({ hash: announcementTxHash });

  // 4. Build credential (base64url of tx hash)
  const credential = base64urlEncode(txHash);

  return {
    txHash,
    announcementTxHash,
    stealthAddress: stealthResult.stealthAddress,
    credential,
  };
}

/**
 * Build the Authorization header value from a confidential payment result.
 * H-TS-3: Includes the challenge nonce for cryptographic binding.
 */
export function buildAuthorizationHeader(
  challengeId: string,
  credential: string,
  nonce?: string
): string {
  let header = `Payment id="${challengeId}", credential="${credential}"`;
  if (nonce) {
    header += `, nonce="${nonce}"`;
  }
  return header;
}

// ── Internal helpers ───────────────────────────────────────────────────────────

function parseAuthParams(str: string): Record<string, string> {
  const params: Record<string, string> = {};
  // Match key="value" or key=value patterns
  const regex = /([a-zA-Z_-]+)\s*=\s*"([^"]*)"/g;
  let match;
  while ((match = regex.exec(str)) !== null) {
    params[match[1]] = match[2];
  }
  return params;
}

function base64urlEncode(str: string): string {
  // For Node.js environments
  const buf = Buffer.from(str, "utf-8");
  return buf
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}
