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
 * Uses `.onBeforeHandle()` to enforce the 402 → payment → credential → 200
 * flow and `.resolve()` to expose payment context to handlers.
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
    .state("_stealthPaymentId", "" as string)
    .state("_stealthPaymentDetails", null as DetectedPayment | null)
    .onBeforeHandle(async ({ set, headers, store }) => {
      const authHeader = headers["authorization"];

      // No auth → 402 challenge
      if (!authHeader) {
        const challenge = method.buildChallenge();
        set.status = 402;
        set.headers["WWW-Authenticate"] = challenge;
        return {
          error: "Payment Required",
          message: "This endpoint requires a confidential payment.",
        };
      }

      // Verify credential
      const result = await method.verifyCredential(authHeader);

      if (!result.valid || !result.payment) {
        const challenge = method.buildChallenge();
        set.status = 402;
        set.headers["WWW-Authenticate"] = challenge;
        return {
          error: "Payment Required",
          message: result.error || "Invalid or expired credential.",
        };
      }

      // Valid — store payment info for resolve
      store._stealthPaymentId = result.paymentId;
      store._stealthPaymentDetails = result.payment;
      set.headers["Payment-Receipt"] =
        `id="${result.paymentId}", status="settled"`;
    })
    .resolve(({ store }) => ({
      payment: store._stealthPaymentId
        ? ({
            paymentId: store._stealthPaymentId,
            details: store._stealthPaymentDetails!,
          } as StealthPaymentContext)
        : (null as StealthPaymentContext | null),
    }));
}
