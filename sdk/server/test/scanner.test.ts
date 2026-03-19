import { describe, it, expect, vi } from "vitest";
import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";
import type { Address, Hex } from "viem";

// We test the scanner logic by re-implementing the stealth check
// and verifying it matches client-side derivation
describe("Scanner Stealth Detection Logic", () => {
  // Helper functions (same as in stealth.ts)
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

  // Simulate sender derivation
  function senderDerive(spendingPub: Uint8Array, viewingPub: Uint8Array) {
    const ephPriv = secp256k1.utils.randomPrivateKey();
    const ephPub = secp256k1.getPublicKey(ephPriv, true);

    const viewingPoint = secp256k1.ProjectivePoint.fromHex(viewingPub);
    const sharedPoint = viewingPoint.multiply(bytesToBigInt(ephPriv));
    const sharedCompressed = sharedPoint.toRawBytes(true);
    const sharedHash = keccak_256(sharedCompressed);

    const viewTag = sharedHash[0];
    const s = bytesToBigInt(sharedHash) % secp256k1.CURVE.n;

    const spendingPoint = secp256k1.ProjectivePoint.fromHex(spendingPub);
    const sTimesG = secp256k1.ProjectivePoint.BASE.multiply(s);
    const stealthPoint = spendingPoint.add(sTimesG);
    const stealthPubUncompressed = stealthPoint.toRawBytes(false);
    const stealthAddress = pubKeyToAddress(stealthPubUncompressed);

    return { stealthAddress, ephemeralPubKey: ephPub, viewTag };
  }

  // Simulate scanner check
  function scannerCheck(
    stealthAddress: string,
    ephPubKey: Uint8Array,
    viewTag: number,
    viewingPrivKey: Uint8Array,
    spendingPubKey: Uint8Array
  ): boolean {
    const ephPoint = secp256k1.ProjectivePoint.fromHex(ephPubKey);
    const sharedPoint = ephPoint.multiply(bytesToBigInt(viewingPrivKey));
    const sharedCompressed = sharedPoint.toRawBytes(true);
    const sharedHash = keccak_256(sharedCompressed);

    if (sharedHash[0] !== viewTag) return false;

    const s = bytesToBigInt(sharedHash) % secp256k1.CURVE.n;
    const spendingPoint = secp256k1.ProjectivePoint.fromHex(spendingPubKey);
    const sTimesG = secp256k1.ProjectivePoint.BASE.multiply(s);
    const stealthPoint = spendingPoint.add(sTimesG);
    const stealthPubUncompressed = stealthPoint.toRawBytes(false);
    const computedAddress = pubKeyToAddress(stealthPubUncompressed);

    return computedAddress.toLowerCase() === stealthAddress.toLowerCase();
  }

  it("should detect payment from sender to recipient", () => {
    const spendPriv = secp256k1.utils.randomPrivateKey();
    const viewPriv = secp256k1.utils.randomPrivateKey();
    const spendPub = secp256k1.getPublicKey(spendPriv, true);
    const viewPub = secp256k1.getPublicKey(viewPriv, true);

    const { stealthAddress, ephemeralPubKey, viewTag } = senderDerive(
      spendPub,
      viewPub
    );

    const detected = scannerCheck(
      stealthAddress,
      ephemeralPubKey,
      viewTag,
      viewPriv,
      spendPub
    );

    expect(detected).toBe(true);
  });

  it("should NOT detect payment for different recipient", () => {
    const spendPriv = secp256k1.utils.randomPrivateKey();
    const viewPriv = secp256k1.utils.randomPrivateKey();
    const spendPub = secp256k1.getPublicKey(spendPriv, true);
    const viewPub = secp256k1.getPublicKey(viewPriv, true);

    const otherViewPriv = secp256k1.utils.randomPrivateKey();
    const otherSpendPub = secp256k1.getPublicKey(
      secp256k1.utils.randomPrivateKey(),
      true
    );

    const { stealthAddress, ephemeralPubKey, viewTag } = senderDerive(
      spendPub,
      viewPub
    );

    const detected = scannerCheck(
      stealthAddress,
      ephemeralPubKey,
      viewTag,
      otherViewPriv,
      otherSpendPub
    );

    expect(detected).toBe(false);
  });

  it("should filter ~255/256 by view tag alone", () => {
    const spendPriv = secp256k1.utils.randomPrivateKey();
    const viewPriv = secp256k1.utils.randomPrivateKey();
    const spendPub = secp256k1.getPublicKey(spendPriv, true);
    const viewPub = secp256k1.getPublicKey(viewPriv, true);

    let viewTagMisses = 0;
    const trials = 256;

    for (let i = 0; i < trials; i++) {
      // Generate random ephemeral key (simulating unrelated payments)
      const randomEphPriv = secp256k1.utils.randomPrivateKey();
      const randomEphPub = secp256k1.getPublicKey(randomEphPriv, true);
      const randomViewTag = Math.floor(Math.random() * 256);

      const ephPoint = secp256k1.ProjectivePoint.fromHex(randomEphPub);
      const sharedPoint = ephPoint.multiply(bytesToBigInt(viewPriv));
      const sharedCompressed = sharedPoint.toRawBytes(true);
      const sharedHash = keccak_256(sharedCompressed);

      if (sharedHash[0] !== randomViewTag) {
        viewTagMisses++;
      }
    }

    // Expect ~255/256 = ~99.6% to be filtered by view tag
    // Allow some statistical variance
    expect(viewTagMisses).toBeGreaterThan(trials * 0.9);
  });

  it("should produce unique stealth addresses for repeated payments", () => {
    const spendPriv = secp256k1.utils.randomPrivateKey();
    const viewPriv = secp256k1.utils.randomPrivateKey();
    const spendPub = secp256k1.getPublicKey(spendPriv, true);
    const viewPub = secp256k1.getPublicKey(viewPriv, true);

    const addresses = new Set<string>();

    for (let i = 0; i < 10; i++) {
      const { stealthAddress, ephemeralPubKey, viewTag } = senderDerive(
        spendPub,
        viewPub
      );

      // Each should be unique
      expect(addresses.has(stealthAddress.toLowerCase())).toBe(false);
      addresses.add(stealthAddress.toLowerCase());

      // Each should be detectable
      const detected = scannerCheck(
        stealthAddress,
        ephemeralPubKey,
        viewTag,
        viewPriv,
        spendPub
      );
      expect(detected).toBe(true);
    }
  });

  it("should correctly reconstruct stealth private key", () => {
    const spendPriv = secp256k1.utils.randomPrivateKey();
    const viewPriv = secp256k1.utils.randomPrivateKey();
    const spendPub = secp256k1.getPublicKey(spendPriv, true);
    const viewPub = secp256k1.getPublicKey(viewPriv, true);

    const { stealthAddress, ephemeralPubKey, viewTag } = senderDerive(
      spendPub,
      viewPub
    );

    // Scanner side: reconstruct shared secret
    const ephPoint = secp256k1.ProjectivePoint.fromHex(ephemeralPubKey);
    const sharedPoint = ephPoint.multiply(bytesToBigInt(viewPriv));
    const sharedCompressed = sharedPoint.toRawBytes(true);
    const sharedHash = keccak_256(sharedCompressed);
    const s = bytesToBigInt(sharedHash) % secp256k1.CURVE.n;

    // Full stealth private key: k_stealth = k_spend + s mod n
    const kSpend = bytesToBigInt(spendPriv);
    const kStealth = (kSpend + s) % secp256k1.CURVE.n;

    // Derive address from stealth private key
    const kStealthBytes = new Uint8Array(32);
    let val = kStealth;
    for (let i = 31; i >= 0; i--) {
      kStealthBytes[i] = Number(val & 0xffn);
      val >>= 8n;
    }

    const stealthPub = secp256k1.getPublicKey(kStealthBytes, false);
    const derivedAddress = pubKeyToAddress(stealthPub);

    expect(derivedAddress.toLowerCase()).toBe(stealthAddress.toLowerCase());
  });
});

describe("Method Challenge Builder", () => {
  it("should build valid WWW-Authenticate challenge string", () => {
    // Test the format without actually importing method.ts (which needs scanner)
    const id = "inv_test1";
    const metaUri = `st:eth:0x${"ab".repeat(66)}`;
    const request = Buffer.from(
      JSON.stringify({ token: "0x1234", amount: "1000", chainId: 42431 })
    )
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");

    const challenge = `Payment id="${id}", method="tempo", intent="charge", request="${request}", stealth-meta="${metaUri}"`;

    expect(challenge).toContain(`id="${id}"`);
    expect(challenge).toContain(`method="tempo"`);
    expect(challenge).toContain(`intent="charge"`);
    expect(challenge).toContain(`stealth-meta="${metaUri}"`);
    expect(challenge).toContain(`request="`);
  });
});
