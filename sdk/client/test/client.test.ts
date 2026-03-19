import { describe, it, expect } from "vitest";
import {
  parseConfidentialChallenge,
  buildAuthorizationHeader,
} from "../src/client.js";

describe("MPP Client Extension", () => {
  it("should parse a confidential challenge with stealth-meta", () => {
    const wwwAuth = `Payment id="inv_7x9k", method="tempo", intent="charge", request="dGVzdA", stealth-meta="st:eth:0x${"a1".repeat(66)}"`;

    const challenge = parseConfidentialChallenge(wwwAuth);

    expect(challenge).not.toBeNull();
    expect(challenge!.id).toBe("inv_7x9k");
    expect(challenge!.method).toBe("tempo");
    expect(challenge!.intent).toBe("charge");
    expect(challenge!.request).toBe("dGVzdA");
    expect(challenge!.stealthMeta).toContain("st:eth:0x");
  });

  it("should return null for non-stealth challenges", () => {
    const wwwAuth = `Payment id="inv_7x9k", method="tempo", intent="charge", request="dGVzdA"`;

    const challenge = parseConfidentialChallenge(wwwAuth);
    expect(challenge).toBeNull();
  });

  it("should return null for non-Payment auth schemes", () => {
    const wwwAuth = `Bearer realm="example"`;
    const challenge = parseConfidentialChallenge(wwwAuth);
    expect(challenge).toBeNull();
  });

  it("should build correct Authorization header", () => {
    const header = buildAuthorizationHeader("inv_7x9k", "base64url-tx-proof");
    expect(header).toBe(
      `Payment id="inv_7x9k", credential="base64url-tx-proof"`
    );
  });
});
