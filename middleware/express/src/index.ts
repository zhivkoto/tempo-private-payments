import type { Request, Response, NextFunction } from "express";
import { createConfidentialChargeMethod } from "@cmpp/server";
import type { StealthPaymentConfig, StealthPaymentRequest } from "./types.js";

export type { StealthPaymentConfig, StealthPaymentRequest } from "./types.js";

/**
 * Create Express middleware that gates routes behind stealth address payments.
 *
 * Implements the full 402 → payment → credential → 200 flow:
 * - No Authorization header: responds 402 with WWW-Authenticate challenge
 * - Valid credential: attaches payment info to `req.payment` and calls `next()`
 * - Invalid/expired credential: responds 402 with a fresh challenge
 *
 * @example
 * ```ts
 * import express from "express";
 * import { createStealthPaymentMiddleware } from "@cmpp/express";
 *
 * const app = express();
 * app.get("/api/data", createStealthPaymentMiddleware({
 *   stealthMetaURI: "st:eth:0x...",
 *   scanner,
 *   tokenAddress: "0x...",
 *   amount: 1000000n,
 * }), (req, res) => {
 *   const { paymentId, details } = (req as StealthPaymentRequest).payment;
 *   res.json({ data: "paid content", paymentId });
 * });
 * ```
 */
export function createStealthPaymentMiddleware(config: StealthPaymentConfig) {
  const method = createConfidentialChargeMethod(config);

  return async (req: Request, res: Response, next: NextFunction) => {
    // Optional route-level gating
    if (config.shouldCharge && !config.shouldCharge(req)) {
      return next();
    }

    const authHeader = req.headers.authorization;

    // No auth → issue 402 challenge
    if (!authHeader) {
      const challenge = method.buildChallenge();
      res.status(402).set("WWW-Authenticate", challenge).json({
        error: "Payment Required",
        message: "This endpoint requires a confidential payment.",
      });
      return;
    }

    // Verify the credential
    const result = await method.verifyCredential(authHeader);

    if (!result.valid || !result.payment) {
      // Invalid/expired → issue fresh 402 challenge
      const challenge = method.buildChallenge();
      res.status(402).set("WWW-Authenticate", challenge).json({
        error: "Payment Required",
        message: result.error || "Invalid or expired credential.",
      });
      return;
    }

    // Valid payment — attach info and continue
    (req as StealthPaymentRequest).payment = {
      paymentId: result.paymentId,
      details: result.payment,
    };

    res.set(
      "Payment-Receipt",
      `id="${result.paymentId}", status="settled"`
    );

    next();
  };
}
