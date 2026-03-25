# cMPP Framework Middleware

Drop-in middleware for gating HTTP endpoints behind **confidential stealth-address payments** on Tempo. Each package implements the full `402 → payment → credential → 200` flow.

## Packages

| Package | Framework | Install |
|---------|-----------|---------|
| `@cmpp/express` | Express.js | `pnpm add @cmpp/express` |
| `@cmpp/nextjs` | Next.js App Router | `pnpm add @cmpp/nextjs` |
| `@cmpp/elysia` | Elysia (Bun) | `pnpm add @cmpp/elysia` |

All packages depend on `@cmpp/server` for challenge building and credential verification.

---

## Prerequisites

You need a configured `AnnouncementScanner` instance and your service's stealth meta-address URI:

```ts
import { AnnouncementScanner } from "@cmpp/server";
import { createPublicClient, http } from "viem";

const publicClient = createPublicClient({
  transport: http("https://rpc.moderato.tempo.xyz"),
});

const scanner = new AnnouncementScanner({
  publicClient,
  announcerAddress: "0x024a2dEB837e0450dC9eF7Ddc3Ce17af65607E8a",
  viewingPrivateKey: "0x...",
  spendingPubKey: "0x02...",
});

const paymentConfig = {
  stealthMetaURI: "st:eth:0x..." as const,
  scanner,
  tokenAddress: "0x..." as `0x${string}`,
  amount: 1000000n, // in base units
};
```

---

## Express.js

```ts
import express from "express";
import { createStealthPaymentMiddleware } from "@cmpp/express";
import type { StealthPaymentRequest } from "@cmpp/express";

const app = express();

// Route-level: gate a single endpoint
app.get(
  "/api/data",
  createStealthPaymentMiddleware(paymentConfig),
  (req, res) => {
    const { paymentId, details } = (req as StealthPaymentRequest).payment;
    res.json({ data: "paid content", paymentId });
  }
);

// Global: gate all routes (with opt-out via shouldCharge)
app.use(
  createStealthPaymentMiddleware({
    ...paymentConfig,
    shouldCharge: (req) => req.path.startsWith("/api/premium"),
  })
);

app.listen(3000);
```

---

## Next.js (App Router)

### Route Handler HOC

```ts
// app/api/data/route.ts
import { withStealthPayment } from "@cmpp/nextjs";

export const GET = withStealthPayment(async (request) => {
  const paymentId = request.headers.get("X-Payment-Id");
  return Response.json({ data: "paid content", paymentId });
}, paymentConfig);
```

Payment info is passed to your handler via request headers:
- `X-Payment-Id` — the verified payment ID
- `X-Payment-TxHash` — the on-chain transaction hash
- `X-Payment-StealthAddress` — the stealth address that received payment

### Edge Middleware (path-based gating)

```ts
// middleware.ts (project root)
import { createStealthMiddleware } from "@cmpp/nextjs/middleware";

const middleware = createStealthMiddleware({
  ...paymentConfig,
  protectedPaths: ["/api/premium"],
});

export default middleware;
export const config = { matcher: ["/api/premium/:path*"] };
```

---

## Elysia

```ts
import { Elysia } from "elysia";
import { stealthPayment } from "@cmpp/elysia";

const app = stealthPayment(new Elysia(), paymentConfig)
  .get("/api/data", ({ payment }) => ({
    data: "paid content",
    paymentId: payment?.paymentId,
  }))
  .listen(3000);
```

For route-level application, use Elysia's `.group()`:

```ts
import { Elysia } from "elysia";
import { stealthPayment } from "@cmpp/elysia";

const app = new Elysia()
  .group("/api/premium", (app) =>
    stealthPayment(app, paymentConfig)
      .get("/data", ({ payment }) => ({
        data: "paid content",
        paymentId: payment?.paymentId,
      }))
  )
  .get("/api/public", () => ({ data: "free content" }))
  .listen(3000);
```

---

## Payment Flow

1. Client sends `GET /api/data` with no auth
2. Middleware responds `402` with `WWW-Authenticate: Payment id="inv_...", method="tempo", intent="charge", request="...", stealth-meta="st:eth:0x..."`
3. Client parses challenge, derives stealth address, sends TIP-20 transfer + announcement on Tempo
4. Client retries with `Authorization: Payment id="inv_...", credential="base64url(txHash)"`
5. Middleware verifies credential via `AnnouncementScanner.verifyPayment()`
6. On success: returns `200` with `Payment-Receipt` header and serves content

---

## Testing

```bash
cd middleware/express && pnpm install && pnpm test
cd middleware/nextjs && pnpm install && pnpm test
cd middleware/elysia && pnpm install && pnpm test
```
