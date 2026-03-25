import { createConfidentialChargeMethod } from "@cmpp/server";
import type {
  ConfidentialChargeConfig,
  ConfidentialChargeMethod,
  DetectedPayment,
} from "@cmpp/server";

export type { ConfidentialChargeConfig, DetectedPayment };

/** Payment info attached to the request context after successful verification */
export interface StealthPaymentContext {
  paymentId: string;
  details: DetectedPayment;
}

/** Next.js App Router Route Handler signature */
type RouteHandler = (
  request: Request,
  context?: any
) => Response | Promise<Response>;

/**
 * Higher-order function that wraps a Next.js App Router Route Handler
 * with stealth payment gating.
 *
 * Implements the 402 → payment → credential → 200 flow:
 * - No Authorization: returns 402 with WWW-Authenticate challenge
 * - Valid credential: calls handler with payment context in a header
 * - Invalid/expired: returns 402 with fresh challenge
 *
 * @example
 * ```ts
 * // app/api/data/route.ts
 * import { withStealthPayment } from "@cmpp/nextjs";
 *
 * export const GET = withStealthPayment(async (request) => {
 *   const paymentId = request.headers.get("X-Payment-Id");
 *   return Response.json({ data: "paid content", paymentId });
 * }, {
 *   stealthMetaURI: "st:eth:0x...",
 *   scanner,
 *   tokenAddress: "0x...",
 *   amount: 1000000n,
 * });
 * ```
 */
export function withStealthPayment(
  handler: RouteHandler,
  config: ConfidentialChargeConfig
): RouteHandler {
  const method = createConfidentialChargeMethod(config);

  return async (request: Request, context?: any) => {
    const authHeader = request.headers.get("authorization");

    // No auth → 402 challenge
    if (!authHeader) {
      return buildChallengeResponse(method);
    }

    // Verify credential
    const result = await method.verifyCredential(authHeader);

    if (!result.valid || !result.payment) {
      return buildChallengeResponse(method, result.error);
    }

    // Attach payment info via headers on a cloned request
    const enrichedHeaders = new Headers(request.headers);
    enrichedHeaders.set("X-Payment-Id", result.paymentId);
    enrichedHeaders.set("X-Payment-TxHash", result.payment.txHash);
    enrichedHeaders.set(
      "X-Payment-StealthAddress",
      result.payment.stealthAddress
    );

    const enrichedRequest = new Request(request.url, {
      method: request.method,
      headers: enrichedHeaders,
      body: request.body,
      // @ts-expect-error duplex needed for streaming body
      duplex: request.body ? "half" : undefined,
    });

    const response = await handler(enrichedRequest, context);

    // Add receipt header to the response
    const enrichedResponse = new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: new Headers(response.headers),
    });
    enrichedResponse.headers.set(
      "Payment-Receipt",
      `id="${result.paymentId}", status="settled"`
    );

    return enrichedResponse;
  };
}

function buildChallengeResponse(
  method: ConfidentialChargeMethod,
  message?: string
): Response {
  const challenge = method.buildChallenge();
  return Response.json(
    {
      error: "Payment Required",
      message: message || "This endpoint requires a confidential payment.",
    },
    {
      status: 402,
      headers: {
        "WWW-Authenticate": challenge,
      },
    }
  );
}
