/**
 * Cross-SDK deterministic test vectors for the ERC-5564 stealth address scheme.
 *
 * Uses known private keys and computes the ECDH math inline (bypassing
 * generateStealthAddress which randomises the ephemeral key).
 */
import { describe, it, expect } from "vitest";
import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";
import {
  checkStealthAnnouncement,
  computeStealthPrivateKey,
  parseStealthMetaAddress,
} from "../src/stealth.js";
import { getAddress, type Hex, type Address } from "viem";
import vectors from "../../../test-vectors/vectors.json";

// ── Helpers ─────────────────────────────────────────────────────────────────

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return "0x" + Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let result = 0n;
  for (const byte of bytes) result = (result << 8n) | BigInt(byte);
  return result;
}

// ── Tests ───────────────────────────────────────────────────────────────────

describe("Cross-SDK Deterministic Test Vectors", () => {
  const { keys, expected, meta_address } = vectors;

  it("should parse the meta-address into correct spending and viewing keys", () => {
    const { spendingPubKey, viewingPubKey } = parseStealthMetaAddress(
      meta_address as Hex
    );
    expect(spendingPubKey).toBe(keys.spending_public_key);
    expect(viewingPubKey).toBe(keys.viewing_public_key);
  });

  it("should derive correct stealth address from known ephemeral key", () => {
    // Reproduce the algorithm with known ephemeral private key
    const ephemeralPrivBytes = hexToBytes(keys.ephemeral_private_key);
    const ephemeralPrivScalar = bytesToBigInt(ephemeralPrivBytes);

    // S = r * K_view (ECDH)
    const viewingPubBytes = hexToBytes(keys.viewing_public_key);
    const viewingPoint = secp256k1.ProjectivePoint.fromHex(viewingPubBytes);
    const sharedPoint = viewingPoint.multiply(ephemeralPrivScalar);
    const sharedCompressed = sharedPoint.toRawBytes(true);

    expect(bytesToHex(sharedCompressed)).toBe(expected.shared_secret_point);

    // H = keccak256(compress(S))
    const sharedHash = keccak_256(sharedCompressed);
    expect(bytesToHex(sharedHash)).toBe(expected.shared_secret_hash);

    // View tag
    expect(sharedHash[0]).toBe(expected.view_tag);

    // s = H mod n
    const s = bytesToBigInt(sharedHash) % secp256k1.CURVE.n;
    expect("0x" + s.toString(16).padStart(64, "0")).toBe(
      expected.shared_secret_scalar
    );

    // K_stealth = K_spend + s*G
    const spendingPubBytes = hexToBytes(keys.spending_public_key);
    const spendingPoint = secp256k1.ProjectivePoint.fromHex(spendingPubBytes);
    const sTimesG = secp256k1.ProjectivePoint.BASE.multiply(s);
    const stealthPoint = spendingPoint.add(sTimesG);

    // Compute address
    const stealthPubUncompressed = stealthPoint.toRawBytes(false);
    const pubNoPrefix = stealthPubUncompressed.slice(1);
    const addrHash = keccak_256(pubNoPrefix);
    const addrBytes = addrHash.slice(12);
    const stealthAddress = bytesToHex(addrBytes);

    expect(stealthAddress).toBe(expected.stealth_address);
  });

  it("should detect announcement via checkStealthAnnouncement", () => {
    const detected = checkStealthAnnouncement(
      {
        schemeId: 1n,
        stealthAddress: getAddress(expected.stealth_address) as Address,
        ephemeralPubKey: keys.ephemeral_public_key as Hex,
        viewTag: expected.view_tag,
      },
      keys.viewing_private_key as Hex,
      keys.spending_public_key as Hex
    );

    expect(detected).not.toBeNull();
    expect(detected!.stealthAddress.toLowerCase()).toBe(
      expected.stealth_address.toLowerCase()
    );
    expect(detected!.sharedSecretScalar).toBe(expected.shared_secret_scalar);
  });

  it("should compute correct stealth private key", () => {
    const stealthPrivKey = computeStealthPrivateKey(
      keys.spending_private_key as Hex,
      keys.ephemeral_public_key as Hex,
      keys.viewing_private_key as Hex
    );

    expect(stealthPrivKey).toBe(expected.stealth_private_key);

    // Verify: derive public key from stealth private key and check address
    const privBytes = hexToBytes(stealthPrivKey);
    const pubUncompressed = secp256k1.getPublicKey(privBytes, false);
    const pubNoPrefix = pubUncompressed.slice(1);
    const addrHash = keccak_256(pubNoPrefix);
    const addrBytes = addrHash.slice(12);
    const derivedAddress = bytesToHex(addrBytes);

    expect(derivedAddress).toBe(expected.stealth_address);
  });
});
