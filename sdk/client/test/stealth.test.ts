import { describe, it, expect } from "vitest";
import { secp256k1 } from "@noble/curves/secp256k1";
import {
  generateStealthKeys,
  generateStealthAddress,
  checkStealthAnnouncement,
  computeStealthPrivateKey,
  parseStealthMetaURI,
  formatStealthMetaURI,
} from "../src/stealth.js";
import { getAddress } from "viem";

describe("Stealth Address Cryptography", () => {
  it("should generate valid stealth keys", () => {
    const { keys, metaAddress } = generateStealthKeys();

    // Meta-address should be 66 bytes (0x prefix + 132 hex chars)
    expect(metaAddress).toMatch(/^0x[0-9a-f]{132}$/i);

    // Spending key should be 33 bytes compressed
    expect(keys.spending.publicKey).toMatch(/^0x(02|03)[0-9a-f]{64}$/i);

    // Viewing key should be 33 bytes compressed
    expect(keys.viewing.publicKey).toMatch(/^0x(02|03)[0-9a-f]{64}$/i);

    // Private keys should be 32 bytes
    expect(keys.spending.privateKey).toMatch(/^0x[0-9a-f]{64}$/i);
    expect(keys.viewing.privateKey).toMatch(/^0x[0-9a-f]{64}$/i);
  });

  it("should derive stealth address and detect it via scanning", () => {
    const { keys } = generateStealthKeys();

    // Sender derives stealth address
    const result = generateStealthAddress(
      keys.spending.publicKey,
      keys.viewing.publicKey
    );

    expect(result.stealthAddress).toMatch(/^0x[0-9a-fA-F]{40}$/);
    expect(result.ephemeralPubKey).toMatch(/^0x(02|03)[0-9a-f]{64}$/i);
    expect(result.viewTag).toBeGreaterThanOrEqual(0);
    expect(result.viewTag).toBeLessThanOrEqual(255);

    // Recipient scans and detects
    const detected = checkStealthAnnouncement(
      {
        schemeId: 1n,
        stealthAddress: result.stealthAddress,
        ephemeralPubKey: result.ephemeralPubKey,
        viewTag: result.viewTag,
      },
      keys.viewing.privateKey,
      keys.spending.publicKey
    );

    expect(detected).not.toBeNull();
    expect(detected!.stealthAddress.toLowerCase()).toBe(
      result.stealthAddress.toLowerCase()
    );
  });

  it("should NOT detect announcements with wrong view tag", () => {
    const { keys } = generateStealthKeys();
    const result = generateStealthAddress(
      keys.spending.publicKey,
      keys.viewing.publicKey
    );

    const wrongViewTag = (result.viewTag + 1) % 256;
    const detected = checkStealthAnnouncement(
      {
        schemeId: 1n,
        stealthAddress: result.stealthAddress,
        ephemeralPubKey: result.ephemeralPubKey,
        viewTag: wrongViewTag,
      },
      keys.viewing.privateKey,
      keys.spending.publicKey
    );

    expect(detected).toBeNull();
  });

  it("should NOT detect announcements for different recipients", () => {
    const recipient = generateStealthKeys();
    const otherRecipient = generateStealthKeys();

    const result = generateStealthAddress(
      recipient.keys.spending.publicKey,
      recipient.keys.viewing.publicKey
    );

    // Other recipient scans — should not detect
    const detected = checkStealthAnnouncement(
      {
        schemeId: 1n,
        stealthAddress: result.stealthAddress,
        ephemeralPubKey: result.ephemeralPubKey,
        viewTag: result.viewTag,
      },
      otherRecipient.keys.viewing.privateKey,
      otherRecipient.keys.spending.publicKey
    );

    expect(detected).toBeNull();
  });

  it("should compute correct stealth private key for spending", () => {
    const { keys } = generateStealthKeys();

    const result = generateStealthAddress(
      keys.spending.publicKey,
      keys.viewing.publicKey
    );

    const stealthPrivKey = computeStealthPrivateKey(
      keys.spending.privateKey,
      result.ephemeralPubKey,
      keys.viewing.privateKey
    );

    // The stealth private key should be a valid 32-byte key
    expect(stealthPrivKey).toMatch(/^0x[0-9a-f]{64}$/i);

    // Verify: derive the public key from stealthPrivKey and check address matches
    const stealthPrivBytes = hexToBytes(stealthPrivKey);
    const stealthPub = secp256k1.getPublicKey(stealthPrivBytes, false); // uncompressed
    const pubKeyNoPrefix = stealthPub.slice(1);
    const { keccak_256 } = require("@noble/hashes/sha3");
    const hash = keccak_256(pubKeyNoPrefix);
    const addressBytes = hash.slice(12);
    const derivedAddress = getAddress(
      `0x${Array.from(addressBytes)
        .map((b: number) => b.toString(16).padStart(2, "0"))
        .join("")}`
    );

    expect(derivedAddress.toLowerCase()).toBe(
      result.stealthAddress.toLowerCase()
    );
  });

  it("should parse and format stealth meta URI", () => {
    const { metaAddress } = generateStealthKeys();
    const uri = formatStealthMetaURI(metaAddress);

    expect(uri).toMatch(/^st:eth:0x[0-9a-f]{132}$/i);

    const parsed = parseStealthMetaURI(uri);
    expect(parsed.spendingPubKey).toMatch(/^0x(02|03)[0-9a-f]{64}$/i);
    expect(parsed.viewingPubKey).toMatch(/^0x(02|03)[0-9a-f]{64}$/i);
  });

  it("should produce different stealth addresses for each payment", () => {
    const { keys } = generateStealthKeys();

    const result1 = generateStealthAddress(
      keys.spending.publicKey,
      keys.viewing.publicKey
    );
    const result2 = generateStealthAddress(
      keys.spending.publicKey,
      keys.viewing.publicKey
    );

    // Each call generates a new ephemeral key → different stealth address
    expect(result1.stealthAddress).not.toBe(result2.stealthAddress);
    expect(result1.ephemeralPubKey).not.toBe(result2.ephemeralPubKey);
  });

  it("should handle multiple sequential payments to same recipient", () => {
    const { keys } = generateStealthKeys();
    const results = [];

    for (let i = 0; i < 5; i++) {
      const result = generateStealthAddress(
        keys.spending.publicKey,
        keys.viewing.publicKey
      );
      results.push(result);

      // Each should be detectable by the recipient
      const detected = checkStealthAnnouncement(
        {
          schemeId: 1n,
          stealthAddress: result.stealthAddress,
          ephemeralPubKey: result.ephemeralPubKey,
          viewTag: result.viewTag,
        },
        keys.viewing.privateKey,
        keys.spending.publicKey
      );

      expect(detected).not.toBeNull();
    }

    // All addresses should be unique
    const addresses = results.map((r) => r.stealthAddress.toLowerCase());
    expect(new Set(addresses).size).toBe(addresses.length);
  });
});

// Helper used in tests
function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}
