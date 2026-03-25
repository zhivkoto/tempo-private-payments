import { describe, it, expect, vi, beforeEach } from "vitest";
import express from "express";
import request from "supertest";
import { createStealthPaymentMiddleware } from "../src/index.js";
import type { StealthPaymentRequest } from "../src/index.js";
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

function createApp(scanner: AnnouncementScanner, opts?: { shouldCharge?: (req: any) => boolean }) {
  const app = express();
  const middleware = createStealthPaymentMiddleware({
    stealthMetaURI: STEALTH_META_URI,
    scanner,
    tokenAddress: TOKEN_ADDRESS,
    amount: AMOUNT,
    ...opts,
  });

  app.get("/api/data", middleware, (req, res) => {
    const paymentReq = req as StealthPaymentRequest;
    res.json({
      data: "paid content",
      paymentId: paymentReq.payment.paymentId,
    });
  });

  return app;
}

// ── Tests ───────────────────────────────────────────────────────────────────────

describe("createStealthPaymentMiddleware", () => {
  let scanner: AnnouncementScanner;

  beforeEach(() => {
    scanner = createMockScanner();
  });

  it("returns 402 with WWW-Authenticate challenge when no auth header", async () => {
    const app = createApp(scanner);
    const res = await request(app).get("/api/data");

    expect(res.status).toBe(402);
    expect(res.headers["www-authenticate"]).toBeDefined();

    const challenge = parseChallenge(res.headers["www-authenticate"]);
    expect(challenge["method"]).toBe("tempo");
    expect(challenge["intent"]).toBe("charge");
    expect(challenge["stealth-meta"]).toBe(STEALTH_META_URI);
    expect(challenge["id"]).toMatch(/^inv_/);
    expect(challenge["request"]).toBeDefined();

    // Decode and verify payment request
    const paymentRequest = JSON.parse(
      Buffer.from(
        challenge["request"].replace(/-/g, "+").replace(/_/g, "/"),
        "base64"
      ).toString("utf-8")
    );
    expect(paymentRequest.token).toBe(TOKEN_ADDRESS);
    expect(paymentRequest.amount).toBe(AMOUNT.toString());
    expect(paymentRequest.chainId).toBe(42431);

    expect(res.body.error).toBe("Payment Required");
  });

  it("returns 200 with payment data for valid credential", async () => {
    const app = createApp(scanner);

    // First get a challenge
    const challengeRes = await request(app).get("/api/data");
    const challenge = parseChallenge(challengeRes.headers["www-authenticate"]);
    const paymentId = challenge["id"];

    // Build a valid credential
    const txHash = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const credential = base64urlEncode(txHash);
    const authHeader = `Payment id="${paymentId}", credential="${credential}"`;

    const res = await request(app)
      .get("/api/data")
      .set("Authorization", authHeader);

    expect(res.status).toBe(200);
    expect(res.body.data).toBe("paid content");
    expect(res.body.paymentId).toBe(paymentId);
    expect(res.headers["payment-receipt"]).toContain(paymentId);
    expect(res.headers["payment-receipt"]).toContain("settled");

    // Verify scanner was called
    expect(scanner.verifyPayment).toHaveBeenCalledWith(txHash);
  });

  it("returns 402 for expired/unknown challenge", async () => {
    const app = createApp(scanner);

    // Use a non-existent payment ID
    const credential = base64urlEncode(
      "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    );
    const authHeader = `Payment id="inv_nonexistent", credential="${credential}"`;

    const res = await request(app)
      .get("/api/data")
      .set("Authorization", authHeader);

    expect(res.status).toBe(402);
    expect(res.headers["www-authenticate"]).toBeDefined();
    expect(res.body.error).toBe("Payment Required");
  });

  it("returns 402 when payment verification fails", async () => {
    const failScanner = createMockScanner(null);
    const app = createApp(failScanner);

    // Get challenge first
    const challengeRes = await request(app).get("/api/data");
    const challenge = parseChallenge(challengeRes.headers["www-authenticate"]);

    const credential = base64urlEncode(
      "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    );
    const authHeader = `Payment id="${challenge["id"]}", credential="${credential}"`;

    const res = await request(app)
      .get("/api/data")
      .set("Authorization", authHeader);

    expect(res.status).toBe(402);
    expect(res.headers["www-authenticate"]).toBeDefined();
  });

  it("returns 402 for invalid auth scheme", async () => {
    const app = createApp(scanner);

    const res = await request(app)
      .get("/api/data")
      .set("Authorization", "Bearer some-token");

    expect(res.status).toBe(402);
    expect(res.headers["www-authenticate"]).toBeDefined();
  });

  it("skips payment check when shouldCharge returns false", async () => {
    const app = express();
    const middleware = createStealthPaymentMiddleware({
      stealthMetaURI: STEALTH_META_URI,
      scanner,
      tokenAddress: TOKEN_ADDRESS,
      amount: AMOUNT,
      shouldCharge: () => false,
    });

    app.get("/api/data", middleware, (_req, res) => {
      res.json({ data: "free content" });
    });

    const res = await request(app).get("/api/data");

    expect(res.status).toBe(200);
    expect(res.body.data).toBe("free content");
  });

  it("returns 402 for malformed credential", async () => {
    const app = createApp(scanner);

    // Get a valid challenge
    const challengeRes = await request(app).get("/api/data");
    const challenge = parseChallenge(challengeRes.headers["www-authenticate"]);

    // Send a credential that decodes to something invalid (not 0x + 64 hex chars)
    const credential = base64urlEncode("not-a-tx-hash");
    const authHeader = `Payment id="${challenge["id"]}", credential="${credential}"`;

    const res = await request(app)
      .get("/api/data")
      .set("Authorization", authHeader);

    expect(res.status).toBe(402);
  });
});
