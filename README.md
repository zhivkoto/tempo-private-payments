# Confidential Payments on Tempo

**Privacy-preserving stablecoin transfers using stealth addresses — so on-chain observers can't link who pays whom.**

## Problem

Every TIP-20 transfer on Tempo is fully visible. When an AI agent pays a service, or a user pays a merchant, the entire payment graph is public. Competitors can see your vendors, customers, pricing, and volume. For agents operating autonomously via [MPP](https://github.com/nicktempo/mpp-spec), this is a critical intelligence leak — every `Payment` credential reveals both parties.

## Solution

Stealth addresses (adapted from [ERC-5564](https://eips.ethereum.org/EIPS/eip-5564) / [ERC-6538](https://eips.ethereum.org/EIPS/eip-6538)) for Tempo's TIP-20 tokens. Each payment goes to a **unique one-time address** derived via ECDH — on-chain, there's no link between payments to the same recipient. Integrates with MPP's `402 Payment Required` flow via a `stealth-meta` auth-param.

## How It Works

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

**Key insight:** Each payment creates a fresh address. An observer sees unrelated transfers to random addresses — no way to link them back to the service.

## What's Included

| Component | Description |
|---|---|
| `contracts/` | Solidity (Foundry) — `StealthRegistry` + `StealthAnnouncer` |
| `sdk/client/` | TypeScript — stealth ECDH math, address derivation, MPP client extension |
| `sdk/server/` | TypeScript — announcement scanner, stealth key derivation, payment verification |
| `demo/service/` | Hono server with a payment-gated endpoint |
| `demo/agent/` | Node.js agent that pays confidentially and accesses gated data |

## Quick Start

### Prerequisites

- [Foundry](https://book.getfoundry.sh/getting-started/installation) with Solidity 0.8.28+
- Node.js 20+, pnpm

### Build & Test Contracts

```bash
cd contracts
forge build
forge test -vvv
```

### Run the SDK Tests

```bash
cd sdk/client && npm install && npm test
cd ../server && npm install && npm test
```

### Run the Demo (End-to-End on Tempo Testnet)

```bash
# Terminal 1 — start the service
cd demo/service && npm install && npm start

# Terminal 2 — run the agent
cd demo/agent && npm install
PRIVATE_KEY=0x<your-testnet-key> npm start
```

The agent will:
1. Hit the service's gated endpoint, receive a 402 with `stealth-meta`
2. Derive a stealth address, transfer TIP-20, announce on-chain
3. Retry with a payment credential and receive the data

## Architecture

### Stealth Address Scheme

- **Scheme ID 1:** secp256k1 ECDH (compatible with ERC-5564/6538)
- **Meta-address:** 66 bytes = compressed spending pubkey (33) + viewing pubkey (33)
- **View tags:** single-byte filter eliminates ~255/256 irrelevant events during scanning
- **Deviation:** view tag is a separate event field (not embedded in metadata) for cleaner parsing

### Three-Phase Roadmap

| Phase | Description | Status |
|---|---|---|
| **Phase 1** | Stealth addresses — unlinkable payment destinations | ✅ Built |
| **Phase 2** | Confidential amounts — hide transfer values via Pedersen commitments | 🔜 Planned |
| **Phase 3** | Private token swaps — confidential DEX integration | 🔜 Planned |

Only Phase 1 is implemented. Phases 2–3 are architectural extensions described in the design document.

## Deployed Contracts (Tempo Testnet — Chain ID 42431)

| Contract | Address |
|---|---|
| StealthRegistry | [`0x145560c016F29d212A385a319930Ecff4A1a62fC`](https://explorer.moderato.tempo.xyz/address/0x145560c016F29d212A385a319930Ecff4A1a62fC) |
| StealthAnnouncer | [`0x024a2dEB837e0450dC9eF7Ddc3Ce17af65607E8a`](https://explorer.moderato.tempo.xyz/address/0x024a2dEB837e0450dC9eF7Ddc3Ce17af65607E8a) |

## MPP Integration

This extends the [Machine Payment Protocol](https://github.com/nicktempo/mpp-spec) with a `stealth-meta` auth-param in the `WWW-Authenticate: Payment` challenge:

```http
HTTP/1.1 402 Payment Required
WWW-Authenticate: Payment
  realm="api",
  amount="1000",
  token="0x0000000000000000000000000000456E65726779",
  receiver="0x...",
  stealth-meta="0x02abc...03def...",
  announcer="0x024a2dEB837e0450dC9eF7Ddc3Ce17af65607E8a"
```

When `stealth-meta` is present, the client:
1. Parses the 66-byte stealth meta-address (spending + viewing pubkeys)
2. Generates an ephemeral keypair, derives the stealth address via ECDH
3. Transfers TIP-20 to the stealth address (not the `receiver`)
4. Calls `StealthAnnouncer.announce()` with the ephemeral pubkey and view tag
5. Submits `Authorization: Payment tx="0x..."` — the service scans and verifies

Services that don't support stealth can omit the param — MPP works normally. Backward compatible.

## Security

The contracts have been [audited](./AUDIT.md) — all MEDIUM findings (two-step ownership, admin events, metadata size cap) have been addressed. See the audit report for the full assessment.

## License

MIT
