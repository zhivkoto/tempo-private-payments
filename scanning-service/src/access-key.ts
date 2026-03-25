import { keccak_256 } from "@noble/hashes/sha3";
import { secp256k1 } from "@noble/curves/secp256k1";
import type { Hex } from "viem";

export type Permission = "scan" | "verify" | "admin";

export interface AccessKey {
  /** The key itself (hex-encoded) */
  key: Hex;
  /** Hash of the key for storage */
  keyHash: Hex;
  /** Permissions granted */
  permissions: Permission[];
  /** Expiry timestamp (ms since epoch) */
  expiresAt: number;
  /** Creation timestamp */
  createdAt: number;
}

interface StoredKey {
  keyHash: string;
  permissions: Permission[];
  expiresAt: number;
  createdAt: number;
  revoked: boolean;
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

/**
 * Access key delegation system for the scanning service.
 * Keys are signed with the service's viewing key to ensure authenticity.
 */
export class AccessKeyManager {
  private signingKey: Hex;
  private storedKeys: Map<string, StoredKey> = new Map();

  constructor(signingKey: Hex) {
    this.signingKey = signingKey;
  }

  /**
   * Generate a new access key with specific permissions and expiry.
   */
  generateAccessKey(permissions: Permission[], expiryMs: number): AccessKey {
    const now = Date.now();
    const expiresAt = now + expiryMs;

    // Generate random nonce
    const nonce = secp256k1.utils.randomPrivateKey();

    // Create key material: sign(nonce || permissions || expiry) with viewing key
    const payload = new Uint8Array([
      ...nonce,
      ...new TextEncoder().encode(permissions.join(",")),
      ...new TextEncoder().encode(expiresAt.toString()),
    ]);

    const payloadHash = keccak_256(payload);

    // Sign the payload hash with the service's signing key
    const signingKeyBytes = hexToBytes(this.signingKey);
    const signingScalar = BigInt(
      "0x" +
        Array.from(signingKeyBytes)
          .map((b) => b.toString(16).padStart(2, "0"))
          .join("")
    );

    // HMAC-like derivation: key = keccak256(signingKey || payloadHash)
    const keyMaterial = new Uint8Array([...signingKeyBytes, ...payloadHash]);
    const keyBytes = keccak_256(keyMaterial);
    const key = bytesToHex(keyBytes);
    const keyHash = bytesToHex(keccak_256(keyBytes));

    // Store the key metadata
    this.storedKeys.set(keyHash, {
      keyHash,
      permissions,
      expiresAt,
      createdAt: now,
      revoked: false,
    });

    return {
      key,
      keyHash,
      permissions,
      expiresAt,
      createdAt: now,
    };
  }

  /**
   * Validate an access key and check if it has the required permission.
   */
  validateAccessKey(key: Hex, requiredPermission: Permission): boolean {
    const keyBytes = hexToBytes(key);
    const keyHash = bytesToHex(keccak_256(keyBytes));

    const stored = this.storedKeys.get(keyHash);
    if (!stored) return false;
    if (stored.revoked) return false;
    if (Date.now() > stored.expiresAt) return false;

    // Admin permission grants access to everything
    if (stored.permissions.includes("admin")) return true;

    return stored.permissions.includes(requiredPermission);
  }

  /**
   * Revoke an access key by its hash.
   */
  revokeKey(keyHash: Hex): boolean {
    const stored = this.storedKeys.get(keyHash);
    if (!stored) return false;
    stored.revoked = true;
    return true;
  }

  /**
   * Rotate: revoke all existing keys and generate a new admin key.
   */
  rotateKeys(expiryMs: number): AccessKey {
    // Revoke all existing keys
    for (const [, stored] of this.storedKeys) {
      stored.revoked = true;
    }

    return this.generateAccessKey(["admin"], expiryMs);
  }

  /**
   * Get info about all stored keys (without exposing the keys themselves).
   */
  listKeys(): Array<Omit<StoredKey, "keyHash"> & { keyHash: string }> {
    return Array.from(this.storedKeys.values()).map((k) => ({ ...k }));
  }

  /**
   * Get the number of active (non-revoked, non-expired) keys.
   */
  activeKeyCount(): number {
    const now = Date.now();
    let count = 0;
    for (const [, stored] of this.storedKeys) {
      if (!stored.revoked && now <= stored.expiresAt) {
        count++;
      }
    }
    return count;
  }
}
