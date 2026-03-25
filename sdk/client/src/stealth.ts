import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";
import { type Hex, type Address, getAddress } from "viem";

// ── Types ──────────────────────────────────────────────────────────────────────

/** Compressed secp256k1 public key (33 bytes, hex-encoded with 0x prefix) */
export type CompressedPubKey = Hex;

/** Stealth meta-address: spending pubkey + viewing pubkey concatenated (66 bytes) */
export type StealthMetaAddress = Hex;

/** The "st:eth:0x..." URI format used in the stealth-meta auth-param */
export type StealthMetaURI = `st:eth:${Hex}`;

export interface StealthKeyPair {
  /** Private key (32 bytes) */
  privateKey: Hex;
  /** Compressed public key (33 bytes) */
  publicKey: CompressedPubKey;
}

export interface StealthKeys {
  spending: StealthKeyPair;
  viewing: StealthKeyPair;
}

export interface GenerateStealthAddressResult {
  /** The one-time stealth address to send funds to */
  stealthAddress: Address;
  /** Ephemeral public key to include in the Announcement (33 bytes compressed) */
  ephemeralPubKey: CompressedPubKey;
  /** View tag for fast scanning (single byte) */
  viewTag: number;
}

export interface StealthPaymentInfo {
  /** Detected stealth address that matches */
  stealthAddress: Address;
  /** Private key that controls the stealth address */
  stealthPrivateKey: Hex;
  /** Ephemeral public key from the announcement */
  ephemeralPubKey: CompressedPubKey;
}

// ── Helpers ────────────────────────────────────────────────────────────────────

/** Zero out a Uint8Array containing key material (H-TS-1). */
function zeroBytes(arr: Uint8Array): void {
  arr.fill(0);
}

function hexToBytes(hex: Hex): Uint8Array {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): Hex {
  return `0x${Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")}` as Hex;
}

function pubKeyToAddress(uncompressedPubKey: Uint8Array): Address {
  // Remove the 0x04 prefix (uncompressed point indicator)
  const pubKeyNoPrefix = uncompressedPubKey.slice(1);
  const hash = keccak_256(pubKeyNoPrefix);
  // Take last 20 bytes
  const addressBytes = hash.slice(12);
  return getAddress(bytesToHex(addressBytes));
}

// ── Core Functions ─────────────────────────────────────────────────────────────

/**
 * Generate a new stealth key pair (spending + viewing keys).
 * @returns The key pairs and the 66-byte stealth meta-address.
 */
export function generateStealthKeys(): {
  keys: StealthKeys;
  metaAddress: StealthMetaAddress;
} {
  const spendingPriv = secp256k1.utils.randomPrivateKey();
  const viewingPriv = secp256k1.utils.randomPrivateKey();

  const spendingPub = secp256k1.getPublicKey(spendingPriv, true); // compressed
  const viewingPub = secp256k1.getPublicKey(viewingPriv, true); // compressed

  const keys: StealthKeys = {
    spending: {
      privateKey: bytesToHex(spendingPriv),
      publicKey: bytesToHex(spendingPub),
    },
    viewing: {
      privateKey: bytesToHex(viewingPriv),
      publicKey: bytesToHex(viewingPub),
    },
  };

  // Meta-address = spendingPubKey (33) + viewingPubKey (33) = 66 bytes
  const metaBytes = new Uint8Array(66);
  metaBytes.set(spendingPub, 0);
  metaBytes.set(viewingPub, 33);

  const result = {
    keys,
    metaAddress: bytesToHex(metaBytes) as StealthMetaAddress,
  };

  // H-TS-1: Zero intermediate key material
  zeroBytes(spendingPriv);
  zeroBytes(viewingPriv);

  return result;
}

/**
 * Parse a stealth meta-address URI ("st:eth:0x...") into its component public keys.
 */
export function parseStealthMetaURI(uri: StealthMetaURI): {
  spendingPubKey: CompressedPubKey;
  viewingPubKey: CompressedPubKey;
} {
  if (!uri.startsWith("st:eth:0x")) {
    throw new Error(`Invalid stealth meta URI: ${uri}`);
  }
  const hex = uri.slice(7) as Hex; // Remove "st:eth:"
  return parseStealthMetaAddress(hex);
}

/**
 * Parse a raw stealth meta-address hex into its component public keys.
 */
export function parseStealthMetaAddress(metaAddress: StealthMetaAddress): {
  spendingPubKey: CompressedPubKey;
  viewingPubKey: CompressedPubKey;
} {
  const bytes = hexToBytes(metaAddress);
  if (bytes.length !== 66) {
    throw new Error(
      `Invalid stealth meta-address length: ${bytes.length}, expected 66`
    );
  }

  return {
    spendingPubKey: bytesToHex(bytes.slice(0, 33)),
    viewingPubKey: bytesToHex(bytes.slice(33, 66)),
  };
}

/**
 * Format a stealth meta-address as a URI for the stealth-meta auth-param.
 */
export function formatStealthMetaURI(
  metaAddress: StealthMetaAddress
): StealthMetaURI {
  return `st:eth:${metaAddress}` as StealthMetaURI;
}

/**
 * Derive a one-time stealth address from a recipient's stealth meta-address.
 * Called by the PAYER when making a confidential payment.
 *
 * Algorithm:
 * 1. Generate ephemeral key pair (r, R) where R = r * G
 * 2. Compute shared secret S = r * K_view
 * 3. viewTag = first byte of keccak256(S.x in compressed form)
 * 4. s = keccak256(S.x in compressed form) as scalar
 * 5. K_stealth = K_spend + s * G
 * 6. stealthAddr = address from K_stealth
 */
export function generateStealthAddress(
  spendingPubKey: CompressedPubKey,
  viewingPubKey: CompressedPubKey
): GenerateStealthAddressResult {
  // Generate ephemeral key pair
  const ephemeralPriv = secp256k1.utils.randomPrivateKey();
  const ephemeralPub = secp256k1.getPublicKey(ephemeralPriv, true); // compressed

  // Parse recipient's viewing public key
  const viewingPubBytes = hexToBytes(viewingPubKey);
  const viewingPoint = secp256k1.ProjectivePoint.fromHex(viewingPubBytes);

  // Compute shared secret: S = r * K_view
  const sharedPoint = viewingPoint.multiply(
    bytesToBigInt(ephemeralPriv)
  );
  const sharedCompressed = sharedPoint.toRawBytes(true); // compressed

  // Hash the shared secret
  const sharedHash = keccak_256(sharedCompressed);

  // View tag = first byte of hash
  const viewTag = sharedHash[0];

  // s = hash interpreted as scalar (mod n)
  const s = bytesToBigInt(sharedHash) % secp256k1.CURVE.n;

  // C-TS-2: Reject degenerate zero scalar (stealth address would equal spending pubkey)
  if (s === 0n) {
    throw new Error("Degenerate shared secret scalar (zero after reduction)");
  }

  // K_stealth = K_spend + s * G
  const spendingPubBytes = hexToBytes(spendingPubKey);
  const spendingPoint = secp256k1.ProjectivePoint.fromHex(spendingPubBytes);
  const sTimesG = secp256k1.ProjectivePoint.BASE.multiply(s);
  const stealthPoint = spendingPoint.add(sTimesG);

  // Compute address from uncompressed stealth public key
  const stealthPubUncompressed = stealthPoint.toRawBytes(false); // uncompressed (65 bytes)
  const stealthAddress = pubKeyToAddress(stealthPubUncompressed);

  const result = {
    stealthAddress,
    ephemeralPubKey: bytesToHex(ephemeralPub),
    viewTag,
  };

  // H-TS-1: Zero intermediate key material
  zeroBytes(ephemeralPriv);
  zeroBytes(sharedCompressed);
  zeroBytes(sharedHash);

  return result;
}

/**
 * Check if an announcement is addressed to us (fast path: view tag check first).
 * Called by the RECIPIENT's scanning service.
 *
 * Algorithm:
 * 1. Compute S' = k_view * R (where R = ephemeralPubKey from event)
 * 2. Compute viewTag' = first byte of keccak256(S')
 * 3. If viewTag' != event.viewTag, return null (fast filter)
 * 4. s' = keccak256(S') as scalar
 * 5. K_stealth' = K_spend + s' * G
 * 6. If address(K_stealth') == event.stealthAddress, match found
 * 7. stealthPrivKey = k_spend + s'
 */
export function checkStealthAnnouncement(
  announcement: {
    schemeId: bigint;
    stealthAddress: Address;
    ephemeralPubKey: CompressedPubKey;
    viewTag: number;
  },
  viewingPrivateKey: Hex,
  spendingPubKey: CompressedPubKey
): StealthPaymentInfo | null {
  // Only support scheme 1
  if (announcement.schemeId !== 1n) return null;

  const viewingPrivBytes = hexToBytes(viewingPrivateKey);
  const ephemeralPubBytes = hexToBytes(announcement.ephemeralPubKey);

  // Parse ephemeral public key
  const ephemeralPoint = secp256k1.ProjectivePoint.fromHex(ephemeralPubBytes);

  // C-TS-3: Validate viewing private key scalar range
  const viewingPrivScalar = bytesToBigInt(viewingPrivBytes);
  if (viewingPrivScalar === 0n || viewingPrivScalar >= secp256k1.CURVE.n) {
    zeroBytes(viewingPrivBytes);
    return null;
  }

  // Compute shared secret: S' = k_view * R
  const sharedPoint = ephemeralPoint.multiply(viewingPrivScalar);
  const sharedCompressed = sharedPoint.toRawBytes(true);

  // Hash the shared secret
  const sharedHash = keccak_256(sharedCompressed);

  // Fast filter: check view tag
  const computedViewTag = sharedHash[0];
  if (computedViewTag !== announcement.viewTag) {
    zeroBytes(viewingPrivBytes);
    zeroBytes(sharedCompressed);
    zeroBytes(sharedHash);
    return null;
  }

  // s' = hash as scalar (mod n)
  const s = bytesToBigInt(sharedHash) % secp256k1.CURVE.n;

  // C-TS-2: Reject degenerate zero scalar
  if (s === 0n) {
    return null;
  }

  // K_stealth' = K_spend + s' * G
  const spendingPubBytes = hexToBytes(spendingPubKey);
  const spendingPoint = secp256k1.ProjectivePoint.fromHex(spendingPubBytes);
  const sTimesG = secp256k1.ProjectivePoint.BASE.multiply(s);
  const stealthPoint = spendingPoint.add(sTimesG);

  // Compute address
  const stealthPubUncompressed = stealthPoint.toRawBytes(false);
  const computedAddress = pubKeyToAddress(stealthPubUncompressed);

  // Check if it matches the announced stealth address
  if (computedAddress.toLowerCase() !== announcement.stealthAddress.toLowerCase()) {
    return null;
  }

  // Compute stealth private key: k_stealth = k_spend + s' (mod n)
  // NOTE: We don't have spending private key here, so we compute it from
  // the viewing private key and return partial info. The full private key
  // computation needs computeStealthPrivateKey() with spending private key.
  // For now, we return a placeholder — the actual spending requires
  // the spending private key which the scanner may or may not have.
  
  // We compute the stealth private key component s for later use
  const sHex = `0x${s.toString(16).padStart(64, "0")}` as Hex;

  // H-TS-1: Zero intermediate key material
  zeroBytes(viewingPrivBytes);
  zeroBytes(sharedCompressed);
  zeroBytes(sharedHash);

  return {
    stealthAddress: computedAddress,
    stealthPrivateKey: sHex, // This is the shared secret scalar, needs k_spend added
    ephemeralPubKey: announcement.ephemeralPubKey,
  };
}

/**
 * Compute the full stealth private key (requires both viewing and spending private keys).
 * Used when the recipient wants to withdraw/spend from a stealth address.
 *
 * k_stealth = k_spend + keccak256(k_view * R) mod n
 */
export function computeStealthPrivateKey(
  spendingPrivateKey: Hex,
  ephemeralPubKey: CompressedPubKey,
  viewingPrivateKey: Hex
): Hex {
  const viewingPrivBytes = hexToBytes(viewingPrivateKey);
  const ephemeralPubBytes = hexToBytes(ephemeralPubKey);

  // Parse ephemeral public key
  const ephemeralPoint = secp256k1.ProjectivePoint.fromHex(ephemeralPubBytes);

  // C-TS-3: Validate key scalar ranges
  const viewingPrivScalar = bytesToBigInt(viewingPrivBytes);
  if (viewingPrivScalar === 0n || viewingPrivScalar >= secp256k1.CURVE.n) {
    throw new Error("Invalid viewing private key: out of scalar range");
  }

  // Compute shared secret: S = k_view * R
  const sharedPoint = ephemeralPoint.multiply(viewingPrivScalar);
  const sharedCompressed = sharedPoint.toRawBytes(true);

  // s = keccak256(S) mod n
  const sharedHash = keccak_256(sharedCompressed);
  const s = bytesToBigInt(sharedHash) % secp256k1.CURVE.n;

  // C-TS-2: Reject degenerate zero scalar
  if (s === 0n) {
    throw new Error("Degenerate shared secret scalar (zero after reduction)");
  }

  // k_stealth = k_spend + s mod n
  const spendingPrivBytes = hexToBytes(spendingPrivateKey);
  const kSpend = bytesToBigInt(spendingPrivBytes);
  if (kSpend === 0n || kSpend >= secp256k1.CURVE.n) {
    throw new Error("Invalid spending private key: out of scalar range");
  }
  const kStealth = (kSpend + s) % secp256k1.CURVE.n;

  const result = `0x${kStealth.toString(16).padStart(64, "0")}` as Hex;

  // H-TS-1: Zero intermediate key material
  zeroBytes(viewingPrivBytes);
  zeroBytes(spendingPrivBytes);
  zeroBytes(sharedCompressed);
  zeroBytes(sharedHash);

  return result;
}

// ── Utility ────────────────────────────────────────────────────────────────────

function bytesToBigInt(bytes: Uint8Array): bigint {
  let result = 0n;
  for (const byte of bytes) {
    result = (result << 8n) | BigInt(byte);
  }
  return result;
}
