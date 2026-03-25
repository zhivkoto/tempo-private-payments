import { describe, it, expect, beforeEach, vi } from "vitest";
import { AccessKeyManager, type Permission } from "../src/access-key.js";
import { secp256k1 } from "@noble/curves/secp256k1";
import type { Hex } from "viem";

function bytesToHex(bytes: Uint8Array): Hex {
  return `0x${Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")}` as Hex;
}

describe("AccessKeyManager", () => {
  const signingKey = bytesToHex(secp256k1.utils.randomPrivateKey());
  let manager: AccessKeyManager;

  beforeEach(() => {
    manager = new AccessKeyManager(signingKey);
  });

  describe("generateAccessKey", () => {
    it("should generate a valid access key", () => {
      const key = manager.generateAccessKey(["scan", "verify"], 60_000);

      expect(key.key).toMatch(/^0x[0-9a-f]{64}$/);
      expect(key.keyHash).toMatch(/^0x[0-9a-f]{64}$/);
      expect(key.permissions).toEqual(["scan", "verify"]);
      expect(key.expiresAt).toBeGreaterThan(Date.now());
      expect(key.createdAt).toBeLessThanOrEqual(Date.now());
    });

    it("should generate unique keys each time", () => {
      const key1 = manager.generateAccessKey(["scan"], 60_000);
      const key2 = manager.generateAccessKey(["scan"], 60_000);

      expect(key1.key).not.toBe(key2.key);
      expect(key1.keyHash).not.toBe(key2.keyHash);
    });
  });

  describe("validateAccessKey", () => {
    it("should validate a key with correct permission", () => {
      const key = manager.generateAccessKey(["scan", "verify"], 60_000);
      expect(manager.validateAccessKey(key.key, "scan")).toBe(true);
      expect(manager.validateAccessKey(key.key, "verify")).toBe(true);
    });

    it("should reject a key without required permission", () => {
      const key = manager.generateAccessKey(["scan"], 60_000);
      expect(manager.validateAccessKey(key.key, "admin")).toBe(false);
    });

    it("should accept admin key for any permission", () => {
      const key = manager.generateAccessKey(["admin"], 60_000);
      expect(manager.validateAccessKey(key.key, "scan")).toBe(true);
      expect(manager.validateAccessKey(key.key, "verify")).toBe(true);
      expect(manager.validateAccessKey(key.key, "admin")).toBe(true);
    });

    it("should reject unknown keys", () => {
      const fakeKey = "0x" + "ab".repeat(32) as Hex;
      expect(manager.validateAccessKey(fakeKey, "scan")).toBe(false);
    });

    it("should reject expired keys", async () => {
      // Generate with 1ms expiry
      const key = manager.generateAccessKey(["scan"], 1);

      // Wait for it to expire
      await new Promise((r) => setTimeout(r, 10));

      expect(manager.validateAccessKey(key.key, "scan")).toBe(false);
    });
  });

  describe("revokeKey", () => {
    it("should revoke an existing key", () => {
      const key = manager.generateAccessKey(["scan"], 60_000);
      expect(manager.validateAccessKey(key.key, "scan")).toBe(true);

      const revoked = manager.revokeKey(key.keyHash);
      expect(revoked).toBe(true);
      expect(manager.validateAccessKey(key.key, "scan")).toBe(false);
    });

    it("should return false for unknown key hash", () => {
      const fakeHash = "0x" + "00".repeat(32) as Hex;
      expect(manager.revokeKey(fakeHash)).toBe(false);
    });
  });

  describe("rotateKeys", () => {
    it("should revoke all existing keys and create new admin key", () => {
      const key1 = manager.generateAccessKey(["scan"], 60_000);
      const key2 = manager.generateAccessKey(["verify"], 60_000);

      const newAdmin = manager.rotateKeys(60_000);

      // Old keys should be revoked
      expect(manager.validateAccessKey(key1.key, "scan")).toBe(false);
      expect(manager.validateAccessKey(key2.key, "verify")).toBe(false);

      // New admin key should work
      expect(manager.validateAccessKey(newAdmin.key, "admin")).toBe(true);
      expect(manager.validateAccessKey(newAdmin.key, "scan")).toBe(true);
    });
  });

  describe("listKeys and activeKeyCount", () => {
    it("should list all stored keys", () => {
      manager.generateAccessKey(["scan"], 60_000);
      manager.generateAccessKey(["verify"], 60_000);

      const keys = manager.listKeys();
      expect(keys).toHaveLength(2);
    });

    it("should count only active keys", () => {
      const key1 = manager.generateAccessKey(["scan"], 60_000);
      manager.generateAccessKey(["verify"], 60_000);

      expect(manager.activeKeyCount()).toBe(2);

      manager.revokeKey(key1.keyHash);
      expect(manager.activeKeyCount()).toBe(1);
    });
  });
});
