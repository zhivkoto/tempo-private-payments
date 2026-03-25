# Confidential Payments on Tempo

![Tests](https://github.com/zhivkoto/tempo-private-payments/actions/workflows/test.yml/badge.svg)

**Privacy-preserving stablecoin transfers using stealth addresses — so on-chain observers can't link who pays whom.**

Every TIP-20 transfer on Tempo is fully visible. When an AI agent pays a service via [MPP](https://github.com/nicktempo/mpp-spec), the entire payment graph is public. This project implements **stealth addresses** ([ERC-5564](https://eips.ethereum.org/EIPS/eip-5564) / [ERC-6538](https://eips.ethereum.org/EIPS/eip-6538)) for Tempo — each payment goes to a unique one-time address derived via ECDH. On-chain, there's no link between payments to the same recipient.

```
  Payer                                                 Payee
  ─────                                                 ─────
    │  1. GET /api/data                                   │
    │────────────────────────────────────────────────────►│
    │  2. 402 + stealth-meta="0x02...03..."               │
    │◄────────────────────────────────────────────────────│
    │  3. Derive stealth address (ECDH)                   │
    │  4. Transfer TIP-20 → stealth address               │
    │  5. Announce ephemeral pubkey on-chain               │
    │  6. Retry with credential                           │
    │────────────────────────────────────────────────────►│
    │                         7. Scan → verify → serve    │
    │  8. 200 OK + data                                   │
    │◄────────────────────────────────────────────────────│
```

## What's Included

| Component | Language | Description |
|---|---|---|
| [`contracts/`](./contracts) | Solidity | `StealthRegistry` + `StealthAnnouncer` (Foundry) |
| [`sdk/client/`](./sdk/client) | TypeScript | Stealth ECDH, address derivation, MPP client |
| [`sdk/server/`](./sdk/server) | TypeScript | Announcement scanner, payment verification |
| [`sdk/python/`](./sdk/python) | Python | Full stealth implementation (coincurve/libsecp256k1) |
| [`sdk/rust/`](./sdk/rust) | Rust | Full stealth implementation (k256, zeroize) |
| [`middleware/`](./middleware) | TypeScript | Drop-in payment gating for Express, Next.js, Elysia |
| [`scanning-service/`](./scanning-service) | TypeScript | Production scanner + MCP transport + access-key delegation |
| [`demo/`](./demo) | TypeScript | E2E demo on Tempo Testnet |

## Quick Start

```bash
# Contracts
cd contracts && forge test -vvv

# TypeScript
cd sdk/client && npm ci && npm test
cd sdk/server && npm ci && npm test

# Python (requires 3.12+)
cd sdk/python && pip install -e '.[dev]' && pytest tests/ -v

# Rust
cd sdk/rust && cargo test

# Middleware (requires pnpm workspace)
pnpm install && pnpm --filter @cmpp/client run build && pnpm --filter @cmpp/server run build
pnpm --filter @cmpp/express test
```

📖 **[Usage guide & code examples →](./docs/usage.md)**

## Deployed Contracts (Tempo Testnet — Chain 42431)

| Contract | Address |
|---|---|
| StealthRegistry | [`0x145560c016F29d212A385a319930Ecff4A1a62fC`](https://explorer.moderato.tempo.xyz/address/0x145560c016F29d212A385a319930Ecff4A1a62fC) |
| StealthAnnouncer | [`0x024a2dEB837e0450dC9eF7Ddc3Ce17af65607E8a`](https://explorer.moderato.tempo.xyz/address/0x024a2dEB837e0450dC9eF7Ddc3Ce17af65607E8a) |

## Cross-SDK Compatibility

All three SDKs implement identical ECDH math. Deterministic [test vectors](./test-vectors/vectors.json) enforce this — each SDK validates the same fixed inputs produce the same outputs, preventing silent cross-SDK regressions.

## Security

Full-stack [security audit](./AUDIT.md) covering contracts, all SDKs, middleware, and scanning service. Key measures: constant-time comparisons, key material zeroization, HMAC-bound challenge nonces, credential replay prevention, on-chain transfer amount verification.

## License

MIT
