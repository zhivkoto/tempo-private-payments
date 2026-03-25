# Usage Guide

## Generate Stealth Keys

<details>
<summary><strong>TypeScript</strong></summary>

```ts
import { generateStealthKeys, formatStealthMetaURI } from "@cmpp/client";

const { keys, metaAddress } = generateStealthKeys();
const uri = formatStealthMetaURI(metaAddress);
// "st:eth:0x02abc...03def..."
```

</details>

<details>
<summary><strong>Python</strong></summary>

```python
from pympp.stealth import generate_stealth_keys, format_stealth_meta_uri

keys, meta_address = generate_stealth_keys()
uri = format_stealth_meta_uri(meta_address)
```

</details>

<details>
<summary><strong>Rust</strong></summary>

```rust
use mpp_rs::stealth::{generate_stealth_keys, format_stealth_meta_uri};

let (keys, meta_bytes) = generate_stealth_keys();
let uri = format_stealth_meta_uri(&meta_bytes);
```

</details>

## Derive a Stealth Address (Payer)

```ts
import { generateStealthAddress, parseStealthMetaAddress } from "@cmpp/client";

const { spendingPubKey, viewingPubKey } = parseStealthMetaAddress(metaAddress);
const { stealthAddress, ephemeralPubKey, viewTag } =
  generateStealthAddress(spendingPubKey, viewingPubKey);

// Send TIP-20 to stealthAddress, then announce ephemeralPubKey + viewTag on-chain
```

## Scan Announcements (Recipient)

```ts
import { AnnouncementScanner } from "@cmpp/server";
import { createPublicClient, http } from "viem";

const scanner = new AnnouncementScanner({
  publicClient: createPublicClient({
    transport: http("https://rpc.moderato.tempo.xyz"),
  }),
  announcerAddress: "0x024a2dEB837e0450dC9eF7Ddc3Ce17af65607E8a",
  viewingPrivateKey: "0x...",
  spendingPubKey: "0x02...",
});

scanner.start("latest", (payment) => {
  console.log(`Payment detected: ${payment.stealthAddress}`);
});
```

## Framework Middleware

### Express.js

```ts
import express from "express";
import { createStealthPaymentMiddleware } from "@cmpp/express";

app.get("/api/data",
  createStealthPaymentMiddleware({ stealthMetaURI, scanner, tokenAddress, amount }),
  (req, res) => {
    res.json({ data: "paid content", paymentId: req.payment.paymentId });
  }
);
```

### Next.js (App Router)

```ts
import { withStealthPayment } from "@cmpp/nextjs";

export const GET = withStealthPayment(async (request) => {
  const paymentId = request.headers.get("X-Payment-Id");
  return Response.json({ data: "paid content", paymentId });
}, config);
```

### Elysia

```ts
import { Elysia } from "elysia";
import { stealthPayment } from "@cmpp/elysia";

const app = stealthPayment(new Elysia(), config)
  .get("/api/data", ({ payment }) => ({ data: "paid content" }))
  .listen(3000);
```

## MCP Tools

The scanning service exposes tools via [Model Context Protocol](https://modelcontextprotocol.io):

| Tool | Description |
|---|---|
| `verify_stealth_payment` | Verify a payment by tx hash |
| `get_scanner_status` | Scanner status, last block, lag, metrics |
| `scan_range` | Scan a block range for payments |

```ts
import { MCPStealthTransport } from "./mcp-transport.js";
const mcp = new MCPStealthTransport(service);
await mcp.startStdio();
```

The service also supports **access-key delegation** — scoped, time-limited keys with `scan`, `verify`, or `admin` permissions.
