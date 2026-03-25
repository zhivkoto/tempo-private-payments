import { NextResponse } from "next/server";
import { createConfidentialChargeMethod } from "@cmpp/server";
import type { ConfidentialChargeConfig } from "@cmpp/server";

export type { ConfidentialChargeConfig };

/** Configuration for the Next.js Edge Middleware */
export interface StealthMiddlewareConfig extends ConfidentialChargeConfig {
  /** Paths that require payment (glob-like matching). Defaults to all paths. */
  protectedPaths?: string[];
}

/**
 * Create a Next.js Edge Middleware function for path-based payment gating.
 *
 * This runs at the edge before your route handlers. Requests to protected
 * paths without valid payment credentials receive a 402 challenge.
 *
 * H-MW-2: When credential is valid, returns NextResponse.next() with
 * X-Payment-Id, X-Payment-Status, and X-Payment-Stealth-Address headers
 * so route handlers can identify paid requests.
 *
 * @example
 * ```ts
 * // middleware.ts (root)
 * import { createStealthMiddleware } from "@cmpp/nextjs/middleware";
 *
 * const middleware = createStealthMiddleware({
 *   stealthMetaURI: "st:eth:0x...",
 *   scanner,
 *   tokenAddress: "0x...",
 *   amount: 1000000n,
 *   protectedPaths: ["/api/premium"],
 * });
 *
 * export default middleware;
 * export const config = { matcher: ["/api/premium/:path*"] };
 * ```
 */
export function createStealthMiddleware(config: StealthMiddlewareConfig) {
  const method = createConfidentialChargeMethod(config);
  const protectedPaths = config.protectedPaths;

  return async (request: Request): Promise<Response | NextResponse> => {
    // Check if this path should be gated
    if (protectedPaths && protectedPaths.length > 0) {
      const url = new URL(request.url);
      const isProtected = protectedPaths.some((p) =>
        url.pathname.startsWith(p)
      );
      if (!isProtected) {
        return NextResponse.next();
      }
    }

    const authHeader = request.headers.get("authorization");

    if (!authHeader) {
      const challenge = method.buildChallenge();
      return Response.json(
        {
          error: "Payment Required",
          message: "This endpoint requires a confidential payment.",
        },
        {
          status: 402,
          headers: { "WWW-Authenticate": challenge },
        }
      );
    }

    const result = await method.verifyCredential(authHeader);

    if (!result.valid || !result.payment) {
      const challenge = method.buildChallenge();
      return Response.json(
        {
          error: "Payment Required",
          message: result.error || "Invalid or expired credential.",
        },
        {
          status: 402,
          headers: { "WWW-Authenticate": challenge },
        }
      );
    }

    // H-MW-2: Propagate payment context to route handlers via request headers.
    // NextResponse.next() forwards the request with modified headers so route
    // handlers can read payment info without needing shared state.
    const response = NextResponse.next({
      request: {
        headers: new Headers({
          ...Object.fromEntries(request.headers.entries()),
          "X-Payment-Id": result.paymentId,
          "X-Payment-Status": "settled",
          "X-Payment-Stealth-Address": result.payment.stealthAddress,
        }),
      },
    });

    response.headers.set(
      "Payment-Receipt",
      `id="${result.paymentId}", status="settled"`
    );

    return response;
  };
}
