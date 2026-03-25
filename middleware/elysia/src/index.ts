import { Elysia } from "elysia";
import { createConfidentialChargeMethod } from "@cmpp/server";
import type {
  ConfidentialChargeConfig,
  DetectedPayment,
} from "@cmpp/server";

export type { ConfidentialChargeConfig, DetectedPayment };

/** Payment info derived and attached to the request context */
export interface StealthPaymentContext {
  paymentId: string;
  details: DetectedPayment;
}

/**
 * Elysia plugin that gates routes behind stealth address payments.
 *
 * H-MW-1: Uses derive() for per-request payment context instead of shared
 * store, preventing race conditions under concurrent requests.
 *
 * @example
 * ```ts
 * import { Elysia } from "elysia";
 * import { stealthPayment } from "@cmpp/elysia";
 *
 * const app = stealthPayment(new Elysia(), {
 *   stealthMetaURI: "st:eth:0x...",
 *   scanner,
 *   tokenAddress: "0x...",
 *   amount: 1000000n,
 * })
 *   .get("/api/data", ({ payment }) => ({
 *     data: "paid content",
 *     paymentId: payment?.paymentId,
 *   }))
 *   .listen(3000);
 * ```
 */
export function stealthPayment<T extends Elysia<any, any, any, any, any, any, any, any>>(
  app: T,
  config: ConfidentialChargeConfig
) {
  const method = createConfidentialChargeMethod(config);

  return app
    .derive(async ({ headers, set }) => {
      const authHeader = headers["authorization"];

      // No auth → 402 challenge
      if (!authHeader) {
        const challenge = method.buildChallenge();
        set.status = 402;
        set.headers["WWW-Authenticate"] = challenge;
        return {
          payment: null as StealthPaymentContext | null,
          _paymentBlocked: true,
        };
      }

      // Verify credential
      const result = await method.verifyCredential(authHeader);

      if (!result.valid || !result.payment) {
        const challenge = method.buildChallenge();
        set.status = 402;
        set.headers["WWW-Authenticate"] = challenge;
        return {
          payment: null as StealthPaymentContext | null,
          _paymentBlocked: true,
        };
      }

      // Valid — attach per-request payment context
      set.headers["Payment-Receipt"] =
        `id="${result.paymentId}", status="settled"`;
      return {
        payment: {
          paymentId: result.paymentId,
          details: result.payment,
        } as StealthPaymentContext | null,
        _paymentBlocked: false,
      };
    })
    .onBeforeHandle(({ _paymentBlocked, set }) => {
      if (_paymentBlocked) {
        return {
          error: "Payment Required",
          message: "This endpoint requires a confidential payment.",
        };
      }
    });
}
