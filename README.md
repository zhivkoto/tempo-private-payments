# Confidential Payments on Tempo

![Tests](https://github.com/zhivkoto/tempo-private-payments/actions/workflows/test.yml/badge.svg)

**Privacy-preserving stablecoin transfers using stealth addresses — so on-chain observers can't link who pays whom.**

Every TIP-20 transfer on Tempo is fully visible. When an AI agent pays a service, or a user pays a merchant, the entire payment graph is public. Competitors see your vendors, customers, pricing, and volume. For agents operating autonomously via [MPP](https://github.com/nicktempo/mpp-spec), every `Payment` credential reveals both parties.

This project implements **stealth addresses** (adapted from [ERC-5564](https://eips.ethereum.org/EIPS/eip-5564) / [ERC-6538](https://eips.ethereum.org/EIPS/eip-6538)) for Tempo's TIP-20 tokens. Each payment goes to a unique one-time address derived via ECDH. On-chain, there is no link between payments to the same recipient.

---

## Components

| Component | Package | Description |
|---|---|---|
| **Solidity Contracts** | `contracts/` | `StealthRegistry` + `StealthAnnouncer` (Foundry) |
| **TypeScript Client SDK** | `@cmpp/client` | Stealth ECDH, address derivation, MPP client helpers |
| **TypeScript Server SDK** | `@cmpp/server` | Announcement scanner, payment verification, challenge builder |
| **Python SDK** | `pympp` | Full stealth address implementation (coincurve/libsecp256k1) |
| **Rust SDK** | `mpp-rs` | Full stealth address implementation (k256) |
| **Express Middleware** | `@cmpp/express` | Drop-in payment gating for Express.js |
| **Next.js Middleware** | `@cmpp/nextjs` | Route handler HOC + Edge middleware for Next.js App Router |
| **Elysia Middleware** | `@cmpp/elysia` | Plugin for Elysia (Bun) |
| **Scanning Service** | `scanning-service/` | Long-running scanner with MCP transport + access-key delegation |
| **Demo** | `demo/` | End-to-end Hono service + agent on Tempo Testnet |

---

## Architecture

### Payment Flow

```
  Agent/Payer                                           Service/Payee
  ───────────                                           ─────────────
       │                                                      │
       │  1. GET /api/data                                    │
       │─────────────────────────────────────────────────────►│
       │                                                      │
       │  2. 402 Payment Required                             │
       │     WWW-Authenticate: Payment                        │
       │       amount="1000", token="0x...",                  │
       │       stealth-meta="0x02...03..."                    │
       │◄─────────────────────────────────────────────────────│
       │                                                      │
       │  3. Derive stealth address (ECDH)                    │
       │  4. Transfer TIP-20 to stealth address               │
       │  5. Announce on StealthAnnouncer (ephemeral pubkey)  │
       │                                                      │
       │  6. GET /api/data                                    │
       │     Authorization: Payment tx="0x..."                │
       │─────────────────────────────────────────────────────►│
       │                                                      │
       │                            7. Scan announcements     │
       │                            8. Derive stealth key     │
       │                            9. Verify payment         │
       │                                                      │
       │  10. 200 OK + data                                   │
       │◄─────────────────────────────────────────────────────│
```

Each payment creates a fresh address. An observer sees unrelated transfers to random addresses — no way to link them back to the service.

### Stealth Address Scheme

- **Scheme ID 1:** secp256k1 ECDH (compatible with ERC-5564/6538)
- **Meta-address:** 66 bytes = compressed spending pubkey (33) + viewing pubkey (33)
- **View tags:** single-byte filter eliminates ~255/256 irrelevant events during scanning
- **View tag deviation:** stored as a separate event field (not embedded in metadata) for cleaner parsing

### Cryptographic Algorithm

```
Payer (generate stealth address):
  1. (r, R) ← random ephemeral keypair, R = r·G
  2. S = r · K_view                          (ECDH shared secret)
  3. h = keccak256(compress(S))
  4. viewTag = h[0]
  5. s = h mod n                             (shared secret scalar)
  6. K_stealth = K_spend + s·G
  7. stealthAddr = address(K_stealth)

Recipient (scan announcements):
  1. S' = k_view · R                         (same shared secret)
  2. h' = keccak256(compress(S'))
  3. if h'[0] ≠ viewTag → skip               (fast filter)
  4. s' = h' mod n
  5. K_stealth' = K_spend + s'·G
  6. if address(K_stealth') = stealthAddr → match
  7. k_stealth = k_spend + s'                (spending key)
```

---

## Quick Start

### Prerequisites

- Node.js 20+, pnpm 9+
- [Foundry](https://book.getfoundry.sh/getting-started/installation) (for contracts)
- Python 3.12+ (for Python SDK — coincurve requires 3.12–3.13)
- Rust stable (for Rust SDK)

### Installation

```bash
# TypeScript SDKs (from npm or workspace)
pnpm add @cmpp/client @cmpp/server

# Middleware (pick your framework)
pnpm add @cmpp/express    # Express.js
pnpm add @cmpp/nextjs     # Next.js
pnpm add @cmpp/elysia     # Elysia/Bun

# Python SDK
cd sdk/python && pip install -e '.[dev]'

# Rust SDK
# Add to Cargo.toml:
# [dependencies]
# mpp-rs = { path = "../sdk/rust" }
```

---

## Usage

### Generate Stealth Keys

<details>
<summary><strong>TypeScript</strong></summary>

```ts
import { generateStealthKeys, formatStealthMetaURI } from "@cmpp/client";

const { keys, metaAddress } = generateStealthKeys();
const uri = formatStealthMetaURI(metaAddress);

console.log(uri);
// "st:eth:0x02abc...03def..."
console.log(keys.spending.publicKey);
// "0x02..." (33-byte compressed)
console.log(keys.viewing.privateKey);
// "0x..." (32-byte, keep secret — used for scanning)
```

</details>

<details>
<summary><strong>Python</strong></summary>

```python
from pympp.stealth import generate_stealth_keys, format_stealth_meta_uri

keys, meta_address = generate_stealth_keys()
uri = format_stealth_meta_uri(meta_address)

print(uri)
# "st:eth:0x02abc...03def..."
print(keys.spending.public_key)
print(keys.viewing.private_key)  # keep secret
```

</details>

<details>
<summary><strong>Rust</strong></summary>

```rust
use mpp_rs::stealth::{generate_stealth_keys, format_stealth_meta_uri};

let (keys, meta_bytes) = generate_stealth_keys();
let uri = format_stealth_meta_uri(&meta_bytes);

println!("{}", uri);
// "st:eth:0x02abc...03def..."
```

</details>

### Derive a Stealth Address (Payer)

```ts
import { generateStealthAddress, parseStealthMetaAddress } from "@cmpp/client";

// Parse the recipient's meta-address from a 402 challenge
const { spendingPubKey, viewingPubKey } = parseStealthMetaAddress(metaAddress);

// Derive one-time stealth address
const { stealthAddress, ephemeralPubKey, viewTag } =
  generateStealthAddress(spendingPubKey, viewingPubKey);

// Send TIP-20 to stealthAddress, then announce ephemeralPubKey + viewTag on-chain
```

### Scan Announcements (Recipient)

```ts
import { AnnouncementScanner } from "@cmpp/server";
import { createPublicClient, http } from "viem";

const scanner = new AnnouncementScanner({
  publicClient: createPublicClient({
    transport: http("https://rpc.moderato.tempo.xyz"),
  }),
  announcerAddress: "0x024a2dEB837e0450dC9eF7Ddc3Ce17af65607E8a",
  viewingPrivateKey: "0x...",    // your viewing key
  spendingPubKey: "0x02...",     // your spending pubkey
  pollIntervalMs: 2000,
  batchSize: 100,
});

scanner.start("latest", (payment) => {
  console.log(`Payment detected: ${payment.stealthAddress}`);
  console.log(`  tx: ${payment.txHash}`);
  console.log(`  block: ${payment.blockNumber}`);
});
```

### Middleware — Express.js

```ts
import express from "express";
import { createStealthPaymentMiddleware } from "@cmpp/express";

const app = express();

app.get(
  "/api/data",
  createStealthPaymentMiddleware({
    stealthMetaURI: "st:eth:0x..." as const,
    scanner,
    tokenAddress: "0x0000000000000000000000000000000000000001",
    amount: 1000n,
  }),
  (req, res) => {
    const { paymentId, details } = (req as any).payment;
    res.json({ data: "paid content", paymentId });
  }
);
```

### Middleware — Next.js

```ts
// app/api/data/route.ts
import { withStealthPayment } from "@cmpp/nextjs";

export const GET = withStealthPayment(async (request) => {
  const paymentId = request.headers.get("X-Payment-Id");
  return Response.json({ data: "paid content", paymentId });
}, paymentConfig);
```

Payment info is passed via headers: `X-Payment-Id`, `X-Payment-TxHash`, `X-Payment-StealthAddress`.

### Middleware — Elysia

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

### MCP Tools

The scanning service exposes three tools via [Model Context Protocol](https://modelcontextprotocol.io):

| Tool | Description |
|---|---|
| `verify_stealth_payment` | Verify a stealth payment by transaction hash |
| `get_scanner_status` | Get scanner status: last block, chain tip, lag, metrics |
| `scan_range` | Scan a specific block range for stealth payments |

```ts
import { ScanningService } from "./service.js";
import { MCPStealthTransport } from "./mcp-transport.js";

const service = new ScanningService({ /* config */ });
const mcp = new MCPStealthTransport(service);
await mcp.startStdio(); // stdio transport for Claude Desktop, etc.
```

The scanning service also supports **access-key delegation** — generate scoped, time-limited keys with `scan`, `verify`, or `admin` permissions.

---

## MPP Integration

This extends the [Machine Payment Protocol](https://github.com/nicktempo/mpp-spec) with a `stealth-meta` auth-param in the `WWW-Authenticate: Payment` challenge:

```http
HTTP/1.1 402 Payment Required
WWW-Authenticate: Payment
  id="inv_abc123",
  method="tempo",
  intent="charge",
  request="base64url...",
  stealth-meta="st:eth:0x02abc...03def...",
  nonce="hmac-derived-nonce"
```

When `stealth-meta` is present, the client:
1. Parses the 66-byte stealth meta-address (spending + viewing pubkeys)
2. Generates an ephemeral keypair, derives the stealth address via ECDH
3. Transfers TIP-20 to the stealth address (not the `receiver`)
4. Calls `StealthAnnouncer.announce()` with the ephemeral pubkey and view tag
5. Submits `Authorization: Payment id="...", credential="base64url(txHash)", nonce="..."`

The server verifies the credential by scanning the on-chain announcement and confirming the TIP-20 transfer amount. Consumed transaction hashes are tracked to prevent replay.

Services that don't support stealth can omit the `stealth-meta` param — standard MPP works normally. Fully backward compatible.

---

## Deployed Contracts (Tempo Testnet — Chain ID 42431)

| Contract | Address |
|---|---|
| StealthRegistry | [`0x145560c016F29d212A385a319930Ecff4A1a62fC`](https://explorer.moderato.tempo.xyz/address/0x145560c016F29d212A385a319930Ecff4A1a62fC) |
| StealthAnnouncer | [`0x024a2dEB837e0450dC9eF7Ddc3Ce17af65607E8a`](https://explorer.moderato.tempo.xyz/address/0x024a2dEB837e0450dC9eF7Ddc3Ce17af65607E8a) |

---

## Cross-SDK Compatibility

All three SDK implementations (TypeScript, Python, Rust) follow the identical ECDH algorithm:

| Step | Implementation |
|---|---|
| Shared secret | `S = ephemeral_scalar × K_view` |
| Hash input | Compressed point serialization of `S` |
| Hash function | keccak256 |
| Scalar derivation | `s = keccak256(compress(S)) mod n` |
| Stealth pubkey | `K_stealth = K_spend + s × G` |
| Address | `last_20_bytes(keccak256(uncompressed_K_stealth[1:]))` |
| View tag | `hash[0]` |

**Deterministic test vectors** in [`test-vectors/vectors.json`](./test-vectors/vectors.json) enforce this invariant across all SDKs. Each SDK's test suite imports the same vectors and validates identical outputs for fixed inputs, preventing silent cross-SDK regressions.

---

## Demo

Run the end-to-end demo on Tempo Testnet:

```bash
# Terminal 1 — start the service
cd demo/service && npm install && npm start

# Terminal 2 — run the agent
cd demo/agent && npm install
PRIVATE_KEY=0x<your-testnet-key> npm start
```

The agent will:
1. Hit the service's `/api/data` endpoint, receive a 402 with `stealth-meta`
2. Derive a stealth address, transfer TIP-20, announce on-chain
3. Retry with a payment credential and receive the gated data

---

## Testing

### Solidity Contracts

```bash
cd contracts && forge test -vvv
```

### TypeScript SDKs

```bash
cd sdk/client && npm ci && npm test
cd sdk/server && npm ci && npm test
```

### Python SDK

Requires Python 3.12+ (coincurve does not support 3.14 yet):

```bash
cd sdk/python && pip install -e '.[dev]' && pytest tests/ -v
```

### Rust SDK

```bash
cd sdk/rust && cargo test
```

### Middleware

```bash
pnpm install
pnpm --filter @cmpp/client run build && pnpm --filter @cmpp/server run build
pnpm --filter @cmpp/express test
pnpm --filter @cmpp/nextjs test
pnpm --filter @cmpp/elysia test
```

### Scanning Service

```bash
cd scanning-service && npm ci && npm test
```

---

## Security

The full stack — contracts, SDKs, middleware, and scanning service — has been [audited](./AUDIT.md). Key hardening measures implemented:

- **Contracts:** Two-step ownership transfer, fee collection via TIP-20, metadata size caps
- **TypeScript SDK:** Constant-time address comparison (`timingSafeEqual`), key material zeroization, zero-scalar rejection, HMAC-bound challenge nonces
- **Python SDK:** `coincurve` (libsecp256k1) for constant-time EC operations, scalar range validation
- **Rust SDK:** `zeroize` crate for key material, `OsRng` for cryptographic randomness
- **Middleware:** Consumed tx hash tracking (replay prevention), on-chain transfer amount verification

See the [full audit report](./AUDIT.md) for findings and remediation status.

---

## License

MIT
