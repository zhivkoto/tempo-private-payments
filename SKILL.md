# Confidential Payments on Tempo — Agent Skill

> Stealth address protocol for private TIP-20 transfers on Tempo. Integrates with MPP (Machine Payments Protocol) via `stealth-meta` auth-param.

## What This Does

Lets you send or receive TIP-20 stablecoins on Tempo without revealing the payer-payee link on-chain. Each payment goes to a unique one-time stealth address derived via ECDH (secp256k1, ERC-5564/6538).

## Contracts (Tempo Testnet — Chain ID 42431)

- **StealthRegistry:** `0x145560c016F29d212A385a319930Ecff4A1a62fC` — stores stealth meta-addresses per account
- **StealthAnnouncer:** `0x024a2dEB837e0450dC9eF7Ddc3Ce17af65607E8a` — emits announcement events for payment discovery

RPC: `https://rpc.moderato.tempo.xyz`

## Core Concepts

**Stealth meta-address:** 66 bytes = compressed spending pubkey (33 bytes) + compressed viewing pubkey (33 bytes). Registered on StealthRegistry by the recipient.

**Flow:**
1. Recipient registers stealth meta-address on `StealthRegistry`
2. Sender fetches meta-address, generates ephemeral keypair
3. Sender derives one-time stealth address via ECDH: `stealthAddr = pubToAddress(spendingPub + hash(ephemeralPriv * viewingPub) * G)`
4. Sender transfers TIP-20 to stealth address
5. Sender calls `StealthAnnouncer.announce(schemeId=1, stealthAddr, ephemeralPubKey, viewTag, metadata)`
6. Recipient's scanner polls `Announcement` events, filters by view tag (eliminates 255/256), derives stealth private key for matches

## SDK Usage

### Client (Sending a Confidential Payment)

```typescript
import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";

// Parse stealth meta-address (66 bytes: 33 spending + 33 viewing)
const spendingPub = metaAddress.slice(0, 33);  // compressed
const viewingPub = metaAddress.slice(33, 66);   // compressed

// Generate ephemeral keypair
const ephemeralPriv = secp256k1.utils.randomPrivateKey();
const ephemeralPub = secp256k1.getPublicKey(ephemeralPriv, true); // compressed

// ECDH: shared secret
const sharedPoint = secp256k1.getSharedSecret(ephemeralPriv, viewingPub);
const sharedSecret = keccak_256(sharedPoint.slice(1)); // hash x-coordinate

// Derive stealth address
const stealthScalar = BigInt("0x" + bytesToHex(sharedSecret));
const stealthPoint = secp256k1.ProjectivePoint.fromHex(spendingPub)
  .add(secp256k1.ProjectivePoint.BASE.multiply(stealthScalar));
const stealthPubUncompressed = stealthPoint.toRawBytes(false); // 65 bytes
const stealthAddr = keccak_256(stealthPubUncompressed.slice(1)).slice(-20);

// View tag = first byte of shared secret
const viewTag = sharedSecret[0];

// 1. Transfer TIP-20 to stealthAddr
// 2. Call StealthAnnouncer.announce(1, stealthAddr, ephemeralPub, viewTag, metadata)
```

### Server (Scanning for Payments)

```typescript
// Poll Announcement events from StealthAnnouncer
const logs = await client.getLogs({
  address: "0x024a2dEB837e0450dC9eF7Ddc3Ce17af65607E8a",
  event: parseAbiItem("event Announcement(uint256 indexed schemeId, address indexed stealthAddress, address indexed caller, bytes ephemeralPubKey, uint8 viewTag, bytes metadata)"),
  fromBlock: lastScannedBlock
});

for (const log of logs) {
  // Fast filter: check view tag first (eliminates ~255/256 events)
  const expectedViewTag = deriveViewTag(viewingPrivKey, log.args.ephemeralPubKey);
  if (log.args.viewTag !== expectedViewTag) continue;

  // Derive stealth private key for this announcement
  const sharedPoint = secp256k1.getSharedSecret(viewingPrivKey, log.args.ephemeralPubKey);
  const sharedSecret = keccak_256(sharedPoint.slice(1));
  const stealthPriv = (spendingPrivKey + BigInt("0x" + bytesToHex(sharedSecret))) % secp256k1.CURVE.n;
  
  // Verify: does this private key correspond to the announced stealth address?
  const derivedAddr = privateKeyToAddress(stealthPriv);
  if (derivedAddr === log.args.stealthAddress) {
    // This payment is for us — we can spend from stealthAddr using stealthPriv
  }
}
```

## MPP Integration

When building an MPP service that accepts confidential payments, include `stealth-meta` in the 402 challenge:

```
WWW-Authenticate: Payment id="inv_abc", method="tempo", intent="charge",
    request="<base64url>", stealth-meta="st:eth:0x<66-byte-meta-address-hex>"
```

Non-stealth clients ignore the param (MPP spec: unknown params must be ignored). Stealth-aware clients derive a one-time address and pay there instead of the standard `receiver`.

## Contract ABIs

### StealthRegistry

```solidity
function registerKeys(uint256 schemeId, bytes calldata stealthMetaAddress) external;
function stealthMetaAddressOf(address registrant, uint256 schemeId) external view returns (bytes memory);
```

### StealthAnnouncer

```solidity
function announce(uint256 schemeId, address stealthAddress, bytes calldata ephemeralPubKey, uint8 viewTag, bytes calldata metadata) external;

event Announcement(uint256 indexed schemeId, address indexed stealthAddress, address indexed caller, bytes ephemeralPubKey, uint8 viewTag, bytes metadata);
```

## Dependencies

- `@noble/curves` — secp256k1 ECDH
- `@noble/hashes` — keccak256
- `viem` — Ethereum/Tempo client

## Project Structure

```
contracts/     — Foundry project (StealthRegistry + StealthAnnouncer)
sdk/client/    — TypeScript stealth derivation + MPP client extension
sdk/server/    — TypeScript scanner + confidential charge method
demo/service/  — Hono server with payment-gated endpoint
demo/agent/    — Node.js agent that pays confidentially
```

## Source

https://github.com/zhivkoto/tempo-private-payments
