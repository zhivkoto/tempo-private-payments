# Confidential MPP — Phase 1: Stealth Addresses for Tempo

Privacy-preserving payments on Tempo blockchain using stealth addresses (ERC-5564/6538 adapted for TIP-20).

## Architecture

```
┌─────────────┐     402 + stealth-meta     ┌──────────────┐
│  Agent/Payer ├──────────────────────────►│ Service/Payee│
│              │                            │              │
│  1. Derive   │  Authorization: Payment    │  Scanner     │
│     stealth  ├──────────────────────────►│  verifies    │
│     address  │                            │  on-chain    │
│  2. Pay to   │       200 + data           │              │
│     stealth  │◄──────────────────────────┤              │
│  3. Announce │                            │              │
└──────┬───────┘                            └──────────────┘
       │
       │  TIP-20 transfer + Announcement
       ▼
┌──────────────────────────────────────────────────────────┐
│                    Tempo Blockchain                       │
│  StealthRegistry: meta-address storage                   │
│  StealthAnnouncer: announcement events + fee collection  │
└──────────────────────────────────────────────────────────┘
```

## Deployed Contracts (Tempo Testnet — Chain ID 42431)

| Contract | Address |
|---|---|
| StealthRegistry | `0x145560c016F29d212A385a319930Ecff4A1a62fC` |
| StealthAnnouncer | `0x024a2dEB837e0450dC9eF7Ddc3Ce17af65607E8a` |

## Project Structure

```
├── contracts/           # Solidity (Foundry) — StealthRegistry + StealthAnnouncer
├── sdk/
│   ├── client/          # TypeScript — stealth ECDH math + MPP client extension
│   └── server/          # TypeScript — announcement scanner + confidential charge method
├── demo/
│   ├── service/         # Hono server with payment-gated endpoint
│   └── agent/           # Node.js client that pays confidentially
```

## Quick Start

### Prerequisites
- [Foundry (Tempo fork)](https://github.com/AztecProtocol/foundry): `foundryup -n tempo`
- Node.js 20+

### Contracts
```bash
cd contracts
forge build
forge test -vvv
```

### SDK
```bash
cd sdk/client && npm install && npm test
cd ../server && npm install && npm test
```

### Demo (End-to-End)
```bash
# Terminal 1: Start service
cd demo/service && npm install && npm start

# Terminal 2: Run agent
cd demo/agent && npm install
PRIVATE_KEY=0x... npm start
```

## How It Works

1. **Service** registers a stealth meta-address (spending + viewing public keys)
2. **Agent** requests a paid endpoint, receives 402 with `stealth-meta` auth-param
3. **Agent** derives a one-time stealth address via ECDH, pays to it, announces on-chain
4. **Service** scans announcements, verifies payment was addressed to them
5. **Agent** retries with credential, gets the data

Each payment goes to a unique stealth address — on-chain observers cannot link payments to the service.

## Stealth Address Scheme

- **Scheme ID 1**: secp256k1 ECDH (compatible with ERC-5564/6538)
- **View tags**: Single-byte filter eliminates ~255/256 of irrelevant events
- **Meta-address**: 66 bytes = compressed spending pubkey (33) + viewing pubkey (33)

## License

MIT
