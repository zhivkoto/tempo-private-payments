import { describe, it, expect, vi, beforeEach } from "vitest";
import { withStealthPayment } from "../src/index.js";
import { createStealthMiddleware } from "../src/middleware.js";
import type { AnnouncementScanner, DetectedPayment } from "@cmpp/server";
import type { Address, Hex } from "viem";

// ── Test helpers ────────────────────────────────────────────────────────────────

const STEALTH_META_URI =
  "st:eth:0x02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa03bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" as const;
const TOKEN_ADDRESS = "0x1234567890abcdef1234567890abcdef12345678" as Address;
const AMOUNT = 1000000n;

const mockPayment: DetectedPayment = {
  stealthAddress: "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef" as Address,
  sharedSecretScalar: "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" as Hex,
  ephemeralPubKey: "0x02cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" as Hex,
  blockNumber: 100n,
  txHash: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" as Hex,
  metadata: "0x" as Hex,
  detectedAt: new Date(),
};

function createMockScanner(
  verifyResult: DetectedPayment | null = mockPayment
): AnnouncementScanner {
  return {
    verifyPayment: vi.fn().mockResolvedValue(verifyResult),
    start: vi.fn(),
    stop: vi.fn(),
    getLastScannedBlock: vi.fn().mockReturnValue(0n),
    scanRange: vi.fn().mockResolvedValue([]),
  } as unknown as AnnouncementScanner;
}

function base64urlEncode(str: string): string {
  return Buffer.from(str, "utf-8")
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function parseChallenge(wwwAuth: string): Record<string, string> {
  const params: Record<string, string> = {};
  const regex = /([a-zA-Z_-]+)\s*=\s*"([^"]*)"/g;
  let match;
  while ((match = regex.exec(wwwAuth)) !== null) {
    params[match[1]] = match[2];
  }
  return params;
}

const baseConfig = {
  stealthMetaURI: STEALTH_META_URI,
  tokenAddress: TOKEN_ADDRESS,
  amount: AMOUNT,
};

// ── withStealthPayment tests ────────────────────────────────────────────────────

describe("withStealthPayment", () => {
  let scanner: AnnouncementScanner;

  beforeEach(() => {
    scanner = createMockScanner();
  });

  it("returns 402 with challenge when no auth header", async () => {
    const handler = withStealthPayment(
      async () => Response.json({ data: "secret" }),
      { ...baseConfig, scanner }
    );

    const req = new Request("http://localhost/api/data");
    const res = await handler(req);

    expect(res.status).toBe(402);
    const wwwAuth = res.headers.get("www-authenticate")!;
    expect(wwwAuth).toBeDefined();

    const challenge = parseChallenge(wwwAuth);
    expect(challenge["method"]).toBe("tempo");
    expect(challenge["stealth-meta"]).toBe(STEALTH_META_URI);
    expect(challenge["id"]).toMatch(/^inv_/);
  });

  it("returns 200 with payment receipt for valid credential", async () => {
    const handler = withStealthPayment(
      async (request) => {
        const paymentId = request.headers.get("X-Payment-Id");
        return Response.json({ data: "secret", paymentId });
      },
      { ...baseConfig, scanner }
    );

    // Get challenge first
    const challengeRes = await handler(new Request("http://localhost/api/data"));
    const challenge = parseChallenge(
      challengeRes.headers.get("www-authenticate")!
    );

    // Build valid credential
    const txHash = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const credential = base64urlEncode(txHash);
    const authHeader = `Payment id="${challenge["id"]}", credential="${credential}"`;

    const req = new Request("http://localhost/api/data", {
      headers: { Authorization: authHeader },
    });
    const res = await handler(req);

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.data).toBe("secret");
    expect(body.paymentId).toBe(challenge["id"]);
    expect(res.headers.get("payment-receipt")).toContain("settled");
  });

  it("returns 402 for unknown challenge ID", async () => {
    const handler = withStealthPayment(
      async () => Response.json({ data: "secret" }),
      { ...baseConfig, scanner }
    );

    const credential = base64urlEncode(
      "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    );
    const authHeader = `Payment id="inv_fake", credential="${credential}"`;

    const req = new Request("http://localhost/api/data", {
      headers: { Authorization: authHeader },
    });
    const res = await handler(req);

    expect(res.status).toBe(402);
    expect(res.headers.get("www-authenticate")).toBeDefined();
  });

  it("returns 402 when scanner rejects payment", async () => {
    const failScanner = createMockScanner(null);
    const handler = withStealthPayment(
      async () => Response.json({ data: "secret" }),
      { ...baseConfig, scanner: failScanner }
    );

    // Get challenge
    const challengeRes = await handler(new Request("http://localhost/api/data"));
    const challenge = parseChallenge(
      challengeRes.headers.get("www-authenticate")!
    );

    const credential = base64urlEncode(
      "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    );
    const authHeader = `Payment id="${challenge["id"]}", credential="${credential}"`;

    const req = new Request("http://localhost/api/data", {
      headers: { Authorization: authHeader },
    });
    const res = await handler(req);

    expect(res.status).toBe(402);
  });
});

// ── createStealthMiddleware tests ───────────────────────────────────────────────

describe("createStealthMiddleware", () => {
  let scanner: AnnouncementScanner;

  beforeEach(() => {
    scanner = createMockScanner();
  });

  it("returns 402 for protected paths without auth", async () => {
    const mw = createStealthMiddleware({
      ...baseConfig,
      scanner,
      protectedPaths: ["/api/premium"],
    });

    const req = new Request("http://localhost/api/premium/data");
    const res = await mw(req);

    expect(res).toBeDefined();
    expect(res!.status).toBe(402);
  });

  it("returns undefined for non-protected paths", async () => {
    const mw = createStealthMiddleware({
      ...baseConfig,
      scanner,
      protectedPaths: ["/api/premium"],
    });

    const req = new Request("http://localhost/api/public/data");
    const res = await mw(req);

    expect(res).toBeUndefined();
  });

  it("returns undefined for valid credential on protected path", async () => {
    const mw = createStealthMiddleware({
      ...baseConfig,
      scanner,
      protectedPaths: ["/api/premium"],
    });

    // Get challenge
    const challengeRes = await mw(
      new Request("http://localhost/api/premium/data")
    );
    const challenge = parseChallenge(
      challengeRes!.headers.get("www-authenticate")!
    );

    const txHash = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const credential = base64urlEncode(txHash);
    const authHeader = `Payment id="${challenge["id"]}", credential="${credential}"`;

    const req = new Request("http://localhost/api/premium/data", {
      headers: { Authorization: authHeader },
    });
    const res = await mw(req);

    expect(res).toBeUndefined();
  });
});
