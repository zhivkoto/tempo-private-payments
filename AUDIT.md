# Security Audit Report — Tempo Stealth Payments

**Auditor:** Moltius Maximus (AI Security Auditor)  
**Date:** 2026-03-19  
**Scope:** StealthAnnouncer.sol, StealthRegistry.sol, interfaces/, Deploy.s.sol  
**Commit:** HEAD (pre-deployment)  
**Severity Scale:** CRITICAL / HIGH / MEDIUM / LOW / INFO

---

## Executive Summary

The contracts implement ERC-5564 (stealth announcements) and ERC-6538 (stealth meta-address registry) adapted for Tempo's TIP-20 precompile ecosystem. Overall, the codebase is **clean, minimal, and well-structured**. No CRITICAL vulnerabilities were found. One MEDIUM issue warrants attention before mainnet deployment. Several LOW and INFO findings are included for hardening.

**Verdict: PASS with recommendations.** Safe for testnet deployment. Address MEDIUM-1 and MEDIUM-2 before mainnet.

---

## Findings

### MEDIUM-1 — Single-Step Ownership Transfer Risks Permanent Loss

**Contract:** `StealthAnnouncer.sol` L75–78  
**Description:** `transferOwnership()` immediately transfers ownership to `newOwner` in a single step. If the owner mistypes the address (e.g., checksummed vs. non-checksummed, wrong paste), ownership is irrecoverably lost. All admin functions (`setAnnouncementFee`, `setTreasury`, `transferOwnership`) become permanently locked.

```solidity
function transferOwnership(address newOwner) external onlyOwner {
    require(newOwner != address(0), "StealthAnnouncer: zero owner");
    owner = newOwner; // ← immediate, no confirmation step
}
```

**Impact:** Permanent loss of admin control over fee parameters and treasury address.

**Recommended Fix:** Implement a two-step transfer pattern:

```solidity
address public pendingOwner;

function transferOwnership(address newOwner) external onlyOwner {
    require(newOwner != address(0), "StealthAnnouncer: zero owner");
    pendingOwner = newOwner;
    emit OwnershipTransferStarted(owner, newOwner);
}

function acceptOwnership() external {
    require(msg.sender == pendingOwner, "StealthAnnouncer: not pending owner");
    emit OwnershipTransferred(owner, pendingOwner);
    owner = pendingOwner;
    pendingOwner = address(0);
}
```

---

### MEDIUM-2 — No Events Emitted for Admin State Changes

**Contract:** `StealthAnnouncer.sol` L64–73  
**Description:** `setAnnouncementFee()`, `setTreasury()`, and `transferOwnership()` modify critical protocol parameters but emit no events. Off-chain monitoring systems, governance dashboards, and indexers cannot detect when:
- The fee is changed (potentially to 0, disabling DoS protection)
- The treasury is redirected to a new address
- Ownership is transferred

**Impact:** Reduced transparency and auditability. A compromised owner key could silently redirect fees or disable protections without any on-chain signal.

**Recommended Fix:** Add events:

```solidity
event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
event AnnouncementFeeUpdated(uint256 oldFee, uint256 newFee);
event TreasuryUpdated(address indexed oldTreasury, address indexed newTreasury);

function setAnnouncementFee(uint256 newFee) external onlyOwner {
    uint256 oldFee = announcementFee;
    announcementFee = newFee;
    emit AnnouncementFeeUpdated(oldFee, newFee);
}

function setTreasury(address newTreasury) external onlyOwner {
    require(newTreasury != address(0), "StealthAnnouncer: zero treasury");
    address oldTreasury = treasury;
    treasury = newTreasury;
    emit TreasuryUpdated(oldTreasury, newTreasury);
}

function transferOwnership(address newOwner) external onlyOwner {
    require(newOwner != address(0), "StealthAnnouncer: zero owner");
    emit OwnershipTransferred(owner, newOwner);
    owner = newOwner;
}
```

---

### MEDIUM-3 — No Metadata Size Limit Enables Event Log Bloat DoS

**Contract:** `StealthAnnouncer.sol` L43  
**Description:** The `announce()` function accepts `bytes calldata metadata` with no upper bound on length. An attacker can pass arbitrarily large metadata (limited only by block gas limit), which is fully emitted in the `Announcement` event. This inflates event log storage and directly increases the cost/time for scanning services to process announcements.

Given the spec requires the scanner to "complete within 10 seconds for a batch of 1000 announcements," a sustained attack with large metadata payloads could degrade scanning performance.

**Impact:** DoS against scanning services; increased RPC node storage costs.

**Recommended Fix:** Cap metadata length:

```solidity
require(metadata.length <= 1024, "StealthAnnouncer: metadata too large");
```

1024 bytes is generous for payment references, token addresses, and amounts. Adjust based on expected use cases.

---

### LOW-1 — No `schemeId` Validation in `announce()`

**Contract:** `StealthAnnouncer.sol` L43  
**Description:** The `announce()` function does not validate `schemeId`. A caller can announce with `schemeId = 0`, which the `StealthRegistry` explicitly rejects (`require(schemeId > 0)`). This creates an inconsistency: announcements with invalid scheme IDs pollute the event log and waste scanning resources on non-existent schemes.

**Recommended Fix:**
```solidity
require(schemeId > 0, "StealthAnnouncer: invalid scheme ID");
```

---

### LOW-2 — String Error Messages Instead of Custom Errors

**Contracts:** Both  
**Description:** All `require` statements use string error messages, which cost more gas than Solidity custom errors (introduced in 0.8.4). On Tempo with 250k gas per storage slot, gas efficiency matters more than usual.

**Example (StealthAnnouncer.sol):**
```solidity
// Current: ~200+ gas per character stored in revert data
require(stealthAddress != address(0), "StealthAnnouncer: zero stealth address");

// Recommended: ~3-4× cheaper
error ZeroStealthAddress();
if (stealthAddress == address(0)) revert ZeroStealthAddress();
```

**Impact:** Increased gas costs, especially relevant on Tempo's expensive storage model.

---

### LOW-3 — `abi.encodeWithSignature` Computes Selector at Runtime

**Contract:** `StealthAnnouncer.sol` L49  
**Description:** `abi.encodeWithSignature("transferFrom(address,address,uint256)", ...)` hashes the signature string at runtime to derive the 4-byte selector. Using a precomputed selector saves ~100 gas per call.

**Recommended Fix:**
```solidity
bytes4 private constant TRANSFER_FROM_SELECTOR = 
    bytes4(keccak256("transferFrom(address,address,uint256)"));

// In announce():
(bool success, bytes memory returnData) = feeToken.call(
    abi.encodeWithSelector(TRANSFER_FROM_SELECTOR, msg.sender, treasury, announcementFee)
);
```

---

### LOW-4 — No Deregistration Function in StealthRegistry

**Contract:** `StealthRegistry.sol`  
**Description:** Once a stealth meta-address is registered, it cannot be deleted—only overwritten. ERC-6538 envisions the ability for users to remove their meta-address. A user wanting to opt out of stealth payments has no clean way to signal this.

**Recommended Fix:** Add a deregistration function:
```solidity
function deregisterStealthMetaAddress(uint256 schemeId) external {
    delete _metaAddresses[msg.sender][schemeId];
    emit StealthMetaAddressSet(msg.sender, schemeId, "");
}
```

---

### LOW-5 — No On-Chain Validation of Public Key Format

**Contracts:** Both  
**Description:** 
- `StealthAnnouncer.sol` validates `ephemeralPubKey.length == 33` but does not check the prefix byte (must be `0x02` or `0x03` for compressed secp256k1).
- `StealthRegistry.sol` validates `stealthMetaAddress.length == 66` for scheme 1 but does not validate that both embedded 33-byte keys have valid prefix bytes.

A malformed public key (e.g., 33 bytes of zeros) would be accepted and stored/announced, but the off-chain ECDH derivation would fail. This wastes gas and creates dead entries.

**Recommended Fix (optional, gas tradeoff):**
```solidity
// In announce():
require(
    ephemeralPubKey[0] == 0x02 || ephemeralPubKey[0] == 0x03,
    "StealthAnnouncer: invalid ephemeral pubkey prefix"
);

// In registerStealthMetaAddress() for schemeId 1:
require(
    stealthMetaAddress[0] == 0x02 || stealthMetaAddress[0] == 0x03,
    "StealthRegistry: invalid spending pubkey prefix"
);
require(
    stealthMetaAddress[33] == 0x02 || stealthMetaAddress[33] == 0x03,
    "StealthRegistry: invalid viewing pubkey prefix"
);
```

**Note:** Full curve-point validation is infeasible on-chain. Prefix validation is a reasonable middle ground.

---

### LOW-6 — ERC-5564 Deviation: viewTag as Separate Event Field

**Contract:** `StealthAnnouncer.sol`, `IStealthAnnouncer.sol`  
**Description:** ERC-5564 specifies the view tag as the **first byte of the metadata** field in the `Announcement` event. This implementation extracts `viewTag` as a separate `uint8` parameter and event field. While the spec header says "Adapted from ERC-5564," clients implementing standard ERC-5564 scanning would not find the view tag where expected.

**Impact:** Incompatibility with generic ERC-5564 scanners. Not a vulnerability, but a portability concern.

**Recommendation:** Document this deviation prominently. If cross-chain interoperability is ever needed, consider conforming to the standard layout.

---

### INFO-1 — `feeToken` is Immutable (No Setter)

**Contract:** `StealthAnnouncer.sol`  
**Description:** There is no `setFeeToken()` function. If the TIP-20 precompile address changes or a migration is needed, the entire `StealthAnnouncer` contract must be redeployed. This is a valid design choice (prevents owner from swapping to a malicious token), but reduces operational flexibility.

**Recommendation:** Consider adding `setFeeToken()` gated by `onlyOwner` if token migration is plausible, or document this as intentional.

---

### INFO-2 — Calling an EOA as `feeToken` Silently Bypasses Fees

**Contract:** `StealthAnnouncer.sol` L49–58  
**Description:** If `feeToken` is an externally owned account (EOA) rather than a contract/precompile, `feeToken.call(...)` succeeds with empty return data. The SafeERC20-style check `(returnData.length == 0 || abi.decode(returnData, (bool)))` passes, and the fee is considered "paid" without any actual transfer.

**Risk:** This is a **deployment-time risk only**, since `feeToken` is immutable. If the deployer provides a valid TIP-20 precompile address, this is not exploitable. On Tempo, TIP-20 precompiles are at well-known addresses and respond to calls, so this is a theoretical concern.

**Mitigation:** The deploy script should validate the `FEE_TOKEN` address against a known list of Tempo TIP-20 precompiles.

---

### INFO-3 — No Pause Mechanism

**Contracts:** Both  
**Description:** Neither contract has an emergency pause function. If a vulnerability is discovered post-deployment, there is no way to halt operations without redeploying.

**Recommendation:** For a Phase 1 / testnet deployment, this is acceptable. For mainnet, consider adding a `paused` modifier to `announce()` and `registerStealthMetaAddress()`, or using a proxy pattern.

---

### INFO-4 — Deploy Script Does Not Use Deterministic Addresses (CREATE2)

**Contract:** `Deploy.s.sol`  
**Description:** Contracts are deployed with `new` (CREATE opcode), producing addresses that depend on the deployer's nonce. This makes addresses non-reproducible across chains or redeployments.

**Recommendation:** For a singleton registry/announcer, consider CREATE2 deployment for deterministic addresses across Tempo testnet and mainnet.

---

### INFO-5 — Tempo 250k Gas Per Slot Impact on StealthRegistry

**Contract:** `StealthRegistry.sol`  
**Description:** Registering a 66-byte stealth meta-address for scheme 1 requires 3 storage slots (32 bytes each, with length prefix). At 250k gas per new slot creation on Tempo, the first registration costs ~750k gas just for storage. Users should be aware of this cost.

**Recommendation:** Document expected gas costs for users. Consider whether a more gas-efficient encoding is possible (e.g., using events instead of storage for meta-address publication, with an off-chain indexer as the source of truth).

---

### INFO-6 — ERC-6538 Naming Deviation

**Contract:** `StealthRegistry.sol`  
**Description:** ERC-6538 defines the registration function as `registerKeys()`. This implementation uses `registerStealthMetaAddress()`. While more descriptive, it deviates from the standard function name.

**Impact:** None functionally; noted for awareness.

---

## Reentrancy Assessment

**StealthAnnouncer.announce():**
The function makes an external call to `feeToken.call(transferFrom(...))` before emitting the `Announcement` event. However:
1. The function modifies **no contract state** — there are no storage writes to exploit via reentrancy.
2. A re-entrant call would re-execute the entire function, including fee collection, so the attacker pays fees for every re-entry.
3. On Tempo, TIP-20 tokens are system precompiles, which do not execute arbitrary Solidity code and cannot re-enter.

**Verdict:** No reentrancy risk in practice. The CEI (Checks-Effects-Interactions) pattern is technically violated (event after external call), but there are no exploitable effects.

---

## Fee Bypass Assessment

Can the announcement fee be circumvented?

| Attack Vector | Possible? | Notes |
|---|---|---|
| Set fee to 0 | Owner only | By design; owner is trusted |
| Call with `announcementFee = 0` | No | Fee is read from storage, not caller input |
| Front-run `setAnnouncementFee` | Technically yes | Attacker could announce at old fee before new fee takes effect; inherent to all admin fee updates |
| Malicious feeToken | No | `feeToken` is immutable; set at deploy time |
| feeToken is EOA | Deploy risk only | See INFO-2 |
| Reentrancy to skip fee | No | Fee is collected before event; re-entry would re-collect |

**Verdict:** Fee mechanism is sound. No bypass possible post-deployment with a valid TIP-20 precompile.

---

## Access Control Matrix

| Function | Caller | Check |
|---|---|---|
| `announce()` | Anyone | Pays fee |
| `setAnnouncementFee()` | Owner | `onlyOwner` modifier |
| `setTreasury()` | Owner | `onlyOwner` + non-zero check |
| `transferOwnership()` | Owner | `onlyOwner` + non-zero check |
| `registerStealthMetaAddress()` | Anyone | Self-only (uses `msg.sender` as key) |
| `stealthMetaAddressOf()` | Anyone | View function, no restriction |

**Verdict:** Access control is correct and minimal. No privilege escalation vectors.

---

## Gas Report (Estimates)

| Operation | Estimated Gas (Ethereum) | Tempo Multiplier Note |
|---|---|---|
| `announce()` (with fee) | ~65k | +250k if first fee transfer to treasury creates storage |
| `registerStealthMetaAddress()` (scheme 1, first time) | ~85k | +750k for 3 new storage slots |
| `registerStealthMetaAddress()` (overwrite) | ~30k | Existing slots, no creation cost |
| `setAnnouncementFee()` | ~28k | Overwrite existing slot |
| `setTreasury()` | ~28k | Overwrite existing slot |

---

## Test Coverage Assessment

The test suite covers:
- ✅ Happy path: announce with fee, register and retrieve
- ✅ Fee collection: balance changes verified
- ✅ Zero fee: announcement works without transfer
- ✅ Input validation: zero address, wrong ephemeral key length, empty meta-address, wrong scheme 1 length
- ✅ Access control: owner-only functions revert for non-owners
- ✅ Ownership transfer: old owner loses access, new owner gains it
- ✅ Multiple announcements: fee accumulation
- ✅ Overwrite: meta-address update
- ✅ Scheme independence: different scheme IDs are separate
- ✅ Unregistered returns empty

**Missing test cases:**
- ❌ `transferOwnership` to address(0) reverts
- ❌ Announce with `schemeId = 0` (currently passes — should it?)
- ❌ Very large metadata in `announce()`
- ❌ Fee token that returns `false` instead of reverting
- ❌ Fee token that returns no data (non-standard ERC-20)
- ❌ Constructor with zero `announcementFee` (edge case)
- ❌ Constructor revert cases (zero feeToken, zero treasury)

---

## Summary of Recommendations

| ID | Severity | Finding | Action |
|---|---|---|---|
| M-1 | MEDIUM | Single-step ownership transfer | Implement two-step pattern |
| M-2 | MEDIUM | No events for admin changes | Add events |
| M-3 | MEDIUM | No metadata size limit | Add `require(metadata.length <= 1024)` |
| L-1 | LOW | No schemeId check in announce | Add `require(schemeId > 0)` |
| L-2 | LOW | String errors vs custom errors | Migrate to custom errors |
| L-3 | LOW | Runtime selector computation | Use constant `bytes4` selector |
| L-4 | LOW | No deregistration function | Add `deregisterStealthMetaAddress()` |
| L-5 | LOW | No pubkey prefix validation | Add 0x02/0x03 prefix checks |
| L-6 | LOW | viewTag deviation from ERC-5564 | Document intentional deviation |
| I-1 | INFO | Immutable feeToken | Document or add setter |
| I-2 | INFO | EOA feeToken bypasses fees | Validate at deploy time |
| I-3 | INFO | No pause mechanism | Consider for mainnet |
| I-4 | INFO | Non-deterministic deployment | Consider CREATE2 |
| I-5 | INFO | 250k gas/slot registry cost | Document for users |
| I-6 | INFO | ERC-6538 function name deviation | Awareness only |

---

## Overall Assessment

**The contracts are well-designed for their purpose.** The attack surface is small — no ETH handling, no complex state machines, no token balances held by the contracts. The main risks are operational (ownership loss, silent parameter changes) rather than exploitable vulnerabilities.

**Recommended priority before mainnet:**
1. Add admin change events (MEDIUM-2) — easy win, high value
2. Implement two-step ownership (MEDIUM-1) — prevents irreversible mistakes
3. Cap metadata length (MEDIUM-3) — prevents DoS on scanning infrastructure
4. Add `schemeId` validation to announcer (LOW-1) — consistency fix

**Not recommended to change:**
- The viewTag separation from metadata (LOW-6) is arguably better UX despite deviating from ERC-5564
- The immutable feeToken (INFO-1) is a reasonable security/flexibility tradeoff
- Full on-chain curve-point validation (LOW-5) — gas cost likely outweighs benefit; prefix check is sufficient

---

*Report generated by automated security analysis. Manual review by a human auditor is recommended before mainnet deployment.*
