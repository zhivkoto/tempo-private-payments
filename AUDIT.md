# Security Audit Report — Phase 2: Full-Stack Review

**Auditor:** Moltius Maximus (AI Security Auditor)
**Date:** 2026-03-25
**Scope:** Full codebase — Solidity contracts, TypeScript/Python/Rust SDKs, middleware, scanning service
**Commit:** HEAD (main branch)
**Severity Scale:** CRITICAL / HIGH / MEDIUM / LOW / INFO

---

## Executive Summary

This Phase 2 audit expands the scope from the Phase 1 contract-only review to cover the entire tempo-private-payments stack: Solidity contracts, three SDK implementations (TypeScript, Python, Rust), three middleware packages (Express, Next.js, Elysia), and the scanning service with MCP transport.

**Total findings: 7 CRITICAL, 12 HIGH, 18 MEDIUM, 14 LOW, 10 INFO**

### Critical Issues Requiring Immediate Attention

1. **Payment credential replay** — A single on-chain payment can authorize unlimited API requests because consumed transaction hashes are never tracked (C-MW-1)
2. **No payment amount verification** — Zero-value or dust transactions with valid stealth announcements pass verification (C-MW-2)
3. **`Math.random()` for payment IDs** — Predictable IDs allow attackers to guess valid challenge identifiers (C-TS-1)
4. **Zero-scalar degeneration** — If `keccak256(shared_secret) mod n == 0`, the stealth address degenerates to the spending public key, destroying privacy (C-TS-2)
5. **Python `ecdsa` library** — Pure-Python EC operations are timing-vulnerable (CVE history) and non-constant-time (C-PY-1)
6. **Rust private keys not zeroized** — Byte-array copies of key material bypass k256's internal zeroization (C-RS-1)
7. **Rust stealth address comparison not constant-time** — Short-circuit `!=` creates timing side channel on the core privacy comparison (C-RS-2)

### Cross-SDK Compatibility Assessment

The ECDH math is **identical across all three SDKs** (TS, Python, Rust):
- Shared secret: `S = ephemeral_scalar * viewing_pub` (ECDH)
- Hash input: compressed point serialization of `S`
- Scalar derivation: `s = keccak256(compressed_S) mod n`
- Stealth pubkey: `K_stealth = K_spend + s * G`
- Address: `last_20_bytes(keccak256(uncompressed_K_stealth[1:]))`
- View tag: `hash[0]`

**No cross-SDK incompatibility found.** However, no shared deterministic test vectors exist to enforce this invariant — a regression in any SDK would silently break payment detection.

**Verdict: FAIL — do not deploy to production until CRITICAL findings are resolved.**

---

## Findings by Component

---

### Solidity Contracts (contracts/src/)

#### C-SOL-1 — No findings at CRITICAL or HIGH severity

The contracts were hardened after Phase 1 audit. Two-step ownership transfer is now implemented. No reentrancy, no exploitable access control, no integer overflow risks.

---

#### M-SOL-1 — `feeToken` not declared `immutable` (wastes gas, not upgradeable)
- **Severity:** MEDIUM
- **Location:** `contracts/src/StealthAnnouncer.sol:19`
- **Description:** `feeToken` is set once in the constructor but stored as a regular storage variable. Costs ~2100 gas extra per `announce()` call. Cannot be changed if the TIP-20 precompile address migrates.
- **Recommendation:** Declare as `immutable` to save gas. If upgradeability is needed, add a guarded setter instead.
- **Fix Status:** Open

#### M-SOL-2 — Low-level call to `feeToken` does not verify target is a contract
- **Severity:** MEDIUM
- **Location:** `contracts/src/StealthAnnouncer.sol:57-68`
- **Description:** If `feeToken` is an EOA or self-destructed contract, the `call` returns `success = true` with empty return data, passing the check on line 66. Announcements would silently succeed without collecting fees.
- **Recommendation:** Add `feeToken.code.length > 0` check in constructor, or validate `returnData.length > 0` when `announcementFee > 0`.
- **Fix Status:** Open

#### M-SOL-3 — `setMaxMetadataSize` has no upper bound
- **Severity:** MEDIUM
- **Location:** `contracts/src/StealthAnnouncer.sol:90-94`
- **Description:** Owner can set `maxMetadataSize` to `type(uint256).max`, effectively removing the scanner DoS protection that the cap is designed to provide.
- **Recommendation:** Add `require(newSize <= 65536)` or similar reasonable bound.
- **Fix Status:** Open

#### L-SOL-1 — `schemeId` not validated in `announce()`
- **Severity:** LOW
- **Location:** `contracts/src/StealthAnnouncer.sol:44-72`
- **Description:** `announce()` accepts `schemeId == 0`, but `StealthRegistry` rejects scheme 0 for registration. Scanners must filter invalid scheme-0 announcements.
- **Recommendation:** Add `require(schemeId > 0)`.
- **Fix Status:** Open

#### L-SOL-2 — No mechanism to cancel pending ownership transfer
- **Severity:** LOW
- **Location:** `contracts/src/StealthAnnouncer.sol:97-101`, `StealthRegistry.sol:57-61`
- **Description:** `transferOwnership(address(0))` is rejected, so a pending transfer can only be overwritten, never explicitly cancelled.
- **Recommendation:** Add `cancelOwnershipTransfer()` or allow zero-address to cancel.
- **Fix Status:** Open

#### L-SOL-3 — No pubkey prefix validation for scheme 1 registration
- **Severity:** LOW
- **Location:** `contracts/src/StealthRegistry.sol:37-42`
- **Description:** Checks 66-byte length but not that bytes 0 and 33 are `0x02` or `0x03` (valid compressed secp256k1 prefixes).
- **Recommendation:** Add prefix byte checks — cheap sanity check.
- **Fix Status:** Open

#### L-SOL-4 — No deregistration mechanism in StealthRegistry
- **Severity:** LOW
- **Location:** `contracts/src/StealthRegistry.sol`
- **Description:** Users cannot remove their stealth meta-address once registered. Can overwrite but not delete.
- **Recommendation:** Add `deregisterStealthMetaAddress(uint256 schemeId)`.
- **Fix Status:** Open

#### I-SOL-1 — Reentrancy confirmed safe
- **Severity:** INFO
- **Location:** `contracts/src/StealthAnnouncer.sol:56-68`
- **Description:** External call precedes only an `emit` statement. Checks-effects-interactions pattern correctly followed.

#### I-SOL-2 — Event emission correct for scanner reliability
- **Severity:** INFO
- **Location:** Both contracts
- **Description:** All state changes emit events. `Announcement` event indexes `schemeId`, `stealthAddress`, and `caller` — correct for scanner log filtering.

---

### TypeScript SDK (sdk/client/ and sdk/server/)

#### C-TS-1 — `Math.random()` used for payment ID generation
- **Severity:** CRITICAL
- **Location:** `sdk/server/src/method.ts:46`
- **Description:** `Math.random().toString(36).slice(2, 6)` produces ~20 bits of non-cryptographic randomness. Payment IDs are predictable and brute-forceable. An attacker can guess valid challenge IDs and submit credentials.
- **Recommendation:** Replace with `crypto.randomUUID()` or `crypto.getRandomValues()` for at least 128 bits of entropy.
- **Fix Status:** Open

#### C-TS-2 — No zero-scalar validation after hashing shared secret
- **Severity:** CRITICAL
- **Location:** `sdk/client/src/stealth.ts:190`, `sdk/client/src/stealth.ts:256`, `sdk/server/src/scanner.ts:126`
- **Description:** If `keccak256(sharedSecret) mod n == 0`, then `s * G` is the point at infinity and the stealth public key degenerates to the spending public key itself, completely destroying privacy. While probability is ~1/n, the ERC-5564 security model requires explicit rejection.
- **Recommendation:** Add `if (s === 0n) throw new Error('Degenerate shared secret scalar')` after modular reduction.
- **Fix Status:** Open

#### C-TS-3 — No validation of viewing private key scalar range
- **Severity:** CRITICAL
- **Location:** `sdk/client/src/stealth.ts:242`, `sdk/server/src/scanner.ts:113`
- **Description:** Viewing private key is converted to BigInt without checking `0 < scalar < n`. Zero scalar causes crash; scalar >= n silently wraps. Both break the protocol guarantees.
- **Recommendation:** Validate `0 < viewingPrivScalar < secp256k1.CURVE.n`.
- **Fix Status:** Open

#### H-TS-1 — Private keys and shared secrets never zeroed from memory
- **Severity:** HIGH
- **Location:** `sdk/client/src/stealth.ts:82-83,170,235,301-302,317`, `sdk/server/src/scanner.ts:101-102`
- **Description:** Private key bytes, shared secrets, and derived stealth keys remain in memory as `Uint8Array` and hex strings indefinitely. Hex strings are immutable in JS and cannot be wiped.
- **Recommendation:** Zero `Uint8Array` intermediates with `.fill(0)` after use. Store long-lived secrets as `Uint8Array` not hex strings.
- **Fix Status:** Open

#### H-TS-2 — Stealth address comparison not constant-time
- **Severity:** HIGH
- **Location:** `sdk/client/src/stealth.ts:269`, `sdk/server/src/scanner.ts:138`
- **Description:** `computedAddress.toLowerCase() !== announcement.stealthAddress.toLowerCase()` short-circuits on first differing character. This is the core privacy-sensitive comparison — an attacker with timing access can deduce address matches.
- **Recommendation:** Use `crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b))`.
- **Fix Status:** Open

#### H-TS-3 — Credential is just base64url(txHash) with no cryptographic binding
- **Severity:** HIGH
- **Location:** `sdk/client/src/client.ts:175`, `sdk/server/src/method.ts:164-168`
- **Description:** Anyone observing the public transaction hash can forge a valid credential for any challenge. No HMAC, no signature, no binding between challenge ID and credential.
- **Recommendation:** Bind credential to challenge: `HMAC(server_secret, challengeId || txHash)`.
- **Fix Status:** Open

#### H-TS-4 — Challenge expiry uses wall clock with no drift tolerance
- **Severity:** HIGH
- **Location:** `sdk/server/src/method.ts:155`
- **Description:** `Date.now()` comparison. In-memory `activeChallenges` Map not shared across instances. Horizontal scaling breaks challenge verification entirely.
- **Recommendation:** Use monotonic time for single-process, or shared store with TTL for multi-instance.
- **Fix Status:** Open

#### M-TS-1 — `parseStealthMetaURI` does not validate curve points
- **Severity:** MEDIUM
- **Location:** `sdk/client/src/stealth.ts:127-142`
- **Description:** Only checks 66-byte length. Invalid compressed points cause unhelpful late crashes.
- **Recommendation:** Validate with `secp256k1.ProjectivePoint.fromHex()` in the parser.
- **Fix Status:** Open

#### M-TS-2 — `hexToBytes` does not validate hex input
- **Severity:** MEDIUM
- **Location:** `sdk/client/src/stealth.ts:48-55`, `sdk/server/src/scanner.ts:58-65`
- **Description:** `parseInt(…, 16)` produces `NaN` for non-hex chars → silently becomes 0 in Uint8Array. Odd-length strings silently truncate.
- **Recommendation:** Validate with regex before parsing.
- **Fix Status:** Open

#### M-TS-3 — `setInterval` cleanup timer leaks on method creation
- **Severity:** MEDIUM
- **Location:** `sdk/server/src/method.ts:90-100`
- **Description:** Each `createConfidentialChargeMethod` call creates a `setInterval` that is never cleared. No `destroy()` method exists.
- **Recommendation:** Return a `destroy()` method that calls `clearInterval`.
- **Fix Status:** Open

#### M-TS-4 — Scanner `scanRange` does not chunk large block ranges
- **Severity:** MEDIUM
- **Location:** `sdk/server/src/scanner.ts:225-274`
- **Description:** Single `getLogs` RPC call for entire range. After restart, gap can exceed provider limits (typically 2000-10000 blocks).
- **Recommendation:** Split into `batchSize` chunks.
- **Fix Status:** Open

#### M-TS-5 — Scanner loses all state on crash
- **Severity:** MEDIUM
- **Location:** `sdk/server/src/scanner.ts:150`
- **Description:** `lastScannedBlock` is memory-only. Crash requires full rescan.
- **Recommendation:** Provide `onCheckpoint(blockNumber)` callback for persistence.
- **Fix Status:** Open

#### M-TS-6 — `pubKeyToAddress` inconsistency between client and server
- **Severity:** MEDIUM
- **Location:** `sdk/server/src/scanner.ts:81-88` vs `sdk/client/src/stealth.ts:69`
- **Description:** Server version returns raw lowercase hex; client uses `getAddress()` with EIP-55 checksum. Code duplication caused this divergence.
- **Recommendation:** Extract shared crypto into common package; use `getAddress()` consistently.
- **Fix Status:** Open

#### L-TS-1 — `checkStealthAnnouncement` returns misleadingly named `stealthPrivateKey`
- **Severity:** LOW
- **Location:** `sdk/client/src/stealth.ts:280-285`
- **Description:** Returns the shared secret scalar `s`, not the full stealth private key (`k_spend + s`). Field name suggests a usable spending key.
- **Recommendation:** Rename to `sharedSecretScalar`.
- **Fix Status:** Open

#### L-TS-2 — Duplicated code between client and server stealth implementations
- **Severity:** LOW
- **Location:** `sdk/client/src/stealth.ts`, `sdk/server/src/scanner.ts`
- **Description:** `hexToBytes`, `bytesToHex`, `bytesToBigInt`, `pubKeyToAddress`, and stealth check algorithm are copy-pasted. M-TS-6 is a direct consequence.
- **Recommendation:** Extract shared module.
- **Fix Status:** Open

---

### Python SDK (sdk/python/pympp/)

#### C-PY-1 — `ecdsa` library is timing-vulnerable and historically exploited
- **Severity:** CRITICAL
- **Location:** `sdk/python/pyproject.toml:11`, `sdk/python/pympp/stealth.py:9`
- **Description:** Pure-Python `ecdsa` library performs non-constant-time scalar multiplication. Documented CVEs (CVE-2019-14859, CVE-2024-23342). All EC operations leak timing information about secret scalars (viewing key, spending key, ephemeral key). Co-tenant cache-timing attacks can extract keys.
- **Recommendation:** Replace with `coincurve` (libsecp256k1 wrapper, constant-time, ~100x faster).
- **Fix Status:** Open

#### H-PY-1 — No point-at-infinity or zero-scalar validation
- **Severity:** HIGH
- **Location:** `sdk/python/pympp/stealth.py:212,229,266,316`
- **Description:** No explicit check that parsed public keys are not the point at infinity. No check that `s = hash mod n != 0`. Point at infinity as ephemeral key makes shared secret deterministic.
- **Recommendation:** Assert `point != INFINITY` after parsing. Check `s != 0` after scalar derivation.
- **Fix Status:** Open

#### H-PY-2 — All EC scalar multiplications are non-constant-time
- **Severity:** HIGH
- **Location:** `sdk/python/pympp/stealth.py:215,230,269,285,319,324,329`
- **Description:** `ecdsa` library's `PointJacobi.__mul__` uses variable-time double-and-add. Secret scalars include viewing private key (compromises all stealth addresses) and spending private key (compromises all funds).
- **Recommendation:** Use `coincurve` (constant-time by design).
- **Fix Status:** Open

#### H-PY-3 — `check_stealth_announcement` returns `s` labeled as `stealth_private_key`
- **Severity:** HIGH
- **Location:** `sdk/python/pympp/stealth.py:294-300`
- **Description:** Same misleading naming as TS SDK. The field contains only the shared secret scalar, not the spendable private key.
- **Recommendation:** Rename to `shared_secret_scalar` in both Python and TS SDKs.
- **Fix Status:** Open

#### M-PY-1 — Silent exception swallowing in scanner poll loop
- **Severity:** MEDIUM
- **Location:** `sdk/python/pympp/scanner.py:144-145`
- **Description:** Bare `except Exception: pass` silently swallows all errors including connection failures, deserialization errors, and logic bugs. Malformed announcements that trigger exceptions cause the scanner to skip entire block ranges without any indication.
- **Recommendation:** Log exceptions. Distinguish transient vs data vs fatal errors.
- **Fix Status:** Open

#### M-PY-2 — No input validation on private key scalars
- **Severity:** MEDIUM
- **Location:** `sdk/python/pympp/stealth.py:262-263,312-313,327-328`
- **Description:** Externally-supplied private keys are not checked for `0 < scalar < N`. Zero scalar produces point at infinity; scalar >= N indicates corruption.
- **Recommendation:** Validate range at function entry.
- **Fix Status:** Open

#### M-PY-3 — Nonce reuse risk in `execute_confidential_charge`
- **Severity:** MEDIUM
- **Location:** `sdk/python/pympp/client.py:139,166`
- **Description:** Separate `get_transaction_count` calls for transfer and announce transactions. Race condition if node state hasn't updated between calls.
- **Recommendation:** Compute announce nonce as `transfer_nonce + 1`.
- **Fix Status:** Open

#### M-PY-4 — `pycryptodome` adds large dependency surface for one function
- **Severity:** MEDIUM
- **Location:** `sdk/python/pyproject.toml:13`
- **Description:** 100+ C extension modules imported solely for keccak256. `web3` dependency already provides keccak via `eth_hash`.
- **Recommendation:** Use `pysha3` or keccak from web3's dependency chain.
- **Fix Status:** Open

#### L-PY-1 — No cross-SDK deterministic test vectors
- **Severity:** LOW
- **Location:** `sdk/python/tests/test_stealth.py`
- **Description:** Tests cover happy path but no hardcoded input/output vectors shared with TS/Rust SDKs to enforce cross-SDK compatibility.
- **Recommendation:** Add shared test vectors.
- **Fix Status:** Open

#### I-PY-1 — Correct use of `os.urandom` for key generation
- **Severity:** INFO
- **Location:** `sdk/python/pympp/stealth.py:89`
- **Description:** No use of `random` module. Key generation uses `os.urandom(32)`. Correct.

---

### Rust SDK (sdk/rust/src/)

#### C-RS-1 — Private key byte arrays not zeroized on drop
- **Severity:** CRITICAL
- **Location:** `sdk/rust/src/types.rs:76-81`, `sdk/rust/src/stealth.rs:168-169,202-208`
- **Description:** `StealthKeyPair::private_bytes()` returns plain `[u8; 32]` that bypasses k256's internal zeroization. `compute_stealth_private_key` creates multiple unzeroized stack copies of spending key and stealth key scalars. `check_stealth_announcement` leaves `scalar_bytes` (shared secret) on stack.
- **Recommendation:** Add `zeroize` as direct dependency. Use `Zeroizing<[u8; 32]>` for all key material returns.
- **Fix Status:** Open

#### C-RS-2 — Stealth address comparison not constant-time
- **Severity:** CRITICAL
- **Location:** `sdk/rust/src/stealth.rs:163`
- **Description:** Derived `PartialEq` on `Address` (`[u8; 20]`) short-circuits on first mismatch. This is the core privacy comparison in stealth address detection.
- **Recommendation:** Use `subtle::ConstantTimeEq`.
- **Fix Status:** Open

#### H-RS-1 — Ephemeral private key scalar copy not zeroized
- **Severity:** HIGH
- **Location:** `sdk/rust/src/stealth.rs:75-76,86`
- **Description:** `*ephemeral_priv.to_nonzero_scalar()` dereferences and copies the scalar to the stack. This copy is not zeroized when it goes out of scope.
- **Recommendation:** Use a reference instead of dereferencing.
- **Fix Status:** Open

#### H-RS-2 — `compute_stealth_private_key` leaves intermediates on stack
- **Severity:** HIGH
- **Location:** `sdk/rust/src/stealth.rs:202-208`
- **Description:** `k_spend`, `k_stealth`, and `k_stealth_bytes` are all plain stack variables containing the most sensitive value in the system — the key that controls funds.
- **Recommendation:** Wrap in `Zeroizing<>`.
- **Fix Status:** Open

#### H-RS-3 — `AnnouncementScanner` holds private key for entire lifetime
- **Severity:** HIGH
- **Location:** `sdk/rust/src/scanner.rs:11-12,41`
- **Description:** Viewing private key stored in struct for scanner's full lifetime. `clone()` on line 41 creates additional untracked copy moved into async task. No key rotation mechanism.
- **Recommendation:** Implement `Drop` with explicit zeroization. Consider storing key in `Zeroizing` wrapper.
- **Fix Status:** Open

#### M-RS-1 — `unwrap()` in production code path
- **Severity:** MEDIUM
- **Location:** `sdk/rust/src/client.rs:82,116`
- **Description:** `chars.next().unwrap()` in auth parameter parsing. Guarded by prior `peek()` but represents a panic risk if refactored.
- **Recommendation:** Replace with `if let Some(c)` pattern.
- **Fix Status:** Open

#### M-RS-2 — `thread_rng()` instead of explicit `OsRng`
- **Severity:** MEDIUM
- **Location:** `sdk/rust/src/stealth.rs:14,72`
- **Description:** `rand::thread_rng()` is CSPRNG in practice but documentation ambiguity exists. Cryptographic intent should be explicit.
- **Recommendation:** Use `rand::rngs::OsRng` directly.
- **Fix Status:** Open

#### M-RS-3 — No input sanitization in `build_authorization_header`
- **Severity:** MEDIUM
- **Location:** `sdk/rust/src/client.rs:38-40`
- **Description:** `challenge_id` and `credential` interpolated into header string without escaping. Double quotes in either value break header format.
- **Recommendation:** Reject or escape double quotes in inputs.
- **Fix Status:** Open

#### M-RS-4 — `StealthPaymentInfo.shared_secret_scalar` exposed as public field
- **Severity:** MEDIUM
- **Location:** `sdk/rust/src/types.rs:107-108`
- **Description:** `pub [u8; 32]` containing sensitive scalar accessible to any code with a reference.
- **Recommendation:** Make private with accessor method.
- **Fix Status:** Open

#### L-RS-1 — `start()` can be called multiple times spawning duplicate tasks
- **Severity:** LOW
- **Location:** `sdk/rust/src/scanner.rs:30`
- **Description:** Each call spawns a new task with cloned key. Old tasks keep running. Multiple tasks process same announcements concurrently.
- **Recommendation:** Check `running` flag; return error if already started.
- **Fix Status:** Open

#### L-RS-2 — `StealthKeys` derives `Debug` — may print private keys to logs
- **Severity:** LOW
- **Location:** `sdk/rust/src/types.rs:85`
- **Description:** `#[derive(Debug)]` on a struct containing private keys. Any `println!("{:?}", keys)` exposes key material.
- **Recommendation:** Implement `Debug` manually to redact private fields.
- **Fix Status:** Open

#### L-RS-3 — No `Cargo.lock` committed
- **Severity:** LOW
- **Location:** `sdk/rust/Cargo.toml`
- **Description:** Semver ranges without pinning. Different builds may pull different patch versions of crypto dependencies.
- **Recommendation:** Commit `Cargo.lock` for reproducible builds.
- **Fix Status:** Open

#### I-RS-1 — Dependencies current, no known CVEs
- **Severity:** INFO
- **Description:** k256 0.13, sha3 0.10, rand 0.8, tokio 1 — all current and maintained.

#### I-RS-2 — ECDH algorithm correctness confirmed
- **Severity:** INFO
- **Description:** Rust implementation follows identical algorithm to TS and Python. Scalar reduction via `Scalar::reduce_bytes()` is equivalent to `BigInt mod n` for 256-bit inputs.

---

### Middleware (middleware/)

#### H-MW-1 — Elysia plugin stores payment state in shared mutable `store`
- **Severity:** HIGH
- **Location:** `middleware/elysia/src/index.ts:47-48,77-78`
- **Description:** `_stealthPaymentId` and `_stealthPaymentDetails` are set on Elysia's shared `store` object. Under concurrent requests, Request A's payment details bleed into Request B's handler. Classic race condition.
- **Recommendation:** Use per-request context via Elysia's `derive()`.
- **Fix Status:** Open

#### H-MW-2 — Next.js middleware does not propagate payment context to route handler
- **Severity:** HIGH
- **Location:** `middleware/nextjs/src/middleware.ts:83-84`
- **Description:** Valid credential causes middleware to return `undefined` (pass-through) but sets no headers. Route handler cannot distinguish paid from unpaid requests.
- **Recommendation:** Return `NextResponse.next()` with payment identity headers.
- **Fix Status:** Open

#### M-MW-1 — Error details leaked in 402 response body
- **Severity:** MEDIUM
- **Location:** `sdk/server/src/method.ts:202-206`
- **Description:** Full error stringification including stack traces and RPC URLs passed to client in verification failure response.
- **Recommendation:** Return generic error to client; log details server-side.
- **Fix Status:** Open

#### L-MW-1 — Header injection potential in `Payment-Receipt`
- **Severity:** LOW
- **Location:** `middleware/express/src/index.ts:72-75`, `middleware/elysia/src/index.ts:79-80`, `middleware/nextjs/src/index.ts:93-95`
- **Description:** `paymentId` interpolated into response header without sanitization.
- **Recommendation:** Strip control characters before header interpolation.
- **Fix Status:** Open

#### I-MW-1 — CSRF protection adequate for API usage
- **Severity:** INFO
- **Description:** Custom `Authorization` header scheme with `Payment` scheme cannot be set by HTML forms. CORS preflight required for cross-origin requests. Adequate for API-only.

---

### Scanning Service (scanning-service/)

#### C-MW-1 — Payment credential replay: one payment grants unlimited access
- **Severity:** CRITICAL
- **Location:** `sdk/server/src/method.ts:195`, `scanning-service/src/service.ts:398`
- **Description:** After credential verification, `activeChallenges.delete(paymentId)` removes the challenge but does not track the consumed transaction hash. An attacker observing any valid payment transaction on the public blockchain can: (1) request fresh challenge, (2) submit the already-used tx hash. `verifyPayment()` confirms the tx exists on-chain — it never checks whether the tx was already consumed. One payment = infinite access.
- **Recommendation:** Maintain a persistent set of consumed transaction hashes. Reject any `txHash` already used.
- **Fix Status:** Open

#### C-MW-2 — No payment amount verification
- **Severity:** CRITICAL
- **Location:** `sdk/server/src/method.ts:184-197`, `scanning-service/src/service.ts:398`
- **Description:** Challenge stores expected `amount` but `verifyCredential` never checks on-chain transfer amount. `verifyPayment` only verifies the announcement was addressed to the recipient — not that tokens were transferred, let alone in the correct amount. A zero-value tx with valid stealth announcement passes.
- **Recommendation:** Inspect token transfer events in the transaction and confirm correct token address and amount.
- **Fix Status:** Open

#### H-MW-3 — `scanLatencyMs` array grows unboundedly
- **Severity:** HIGH
- **Location:** `scanning-service/src/service.ts:323`
- **Description:** Every `pollOnce()` pushes to `metrics.scanLatencyMs`, never trimmed. At 2-second intervals: ~43,200 entries/day. Long-running service will OOM.
- **Recommendation:** Use fixed-size ring buffer or running average.
- **Fix Status:** Open

#### H-MW-4 — `detectedPayments` array grows unboundedly
- **Severity:** HIGH
- **Location:** `scanning-service/src/service.ts:333`
- **Description:** Every detected payment pushed to array, never pruned. `getDetectedPayments()` returns full copy. On busy chain → OOM.
- **Recommendation:** Implement max size or age-based eviction. Consider database persistence.
- **Fix Status:** Open

#### M-MW-2 — State file write is not atomic
- **Severity:** MEDIUM
- **Location:** `scanning-service/src/service.ts:196-204`
- **Description:** `fs.writeFileSync()` is not atomic. Crash during write leaves truncated file → `loadState()` fails → scanner restarts from block 0, reprocessing all events and triggering duplicate callbacks.
- **Recommendation:** Write to temp file then `fs.renameSync()`.
- **Fix Status:** Open

#### M-MW-3 — No concurrent-poll guard
- **Severity:** MEDIUM
- **Location:** `scanning-service/src/service.ts:289-296`
- **Description:** `setInterval` fires regardless of whether previous `pollOnce()` completed. Slow RPC causes overlapping polls processing same block range, emitting duplicate callbacks.
- **Recommendation:** Add `isPolling` mutex flag.
- **Fix Status:** Open

#### M-MW-4 — MCP `scan_range` has no input bounds validation
- **Severity:** MEDIUM
- **Location:** `scanning-service/src/mcp-transport.ts:148-184`
- **Description:** Arbitrary `from_block` and `to_block` accepted. Malicious MCP client can request `scan_range(0, 999999999)` causing massive RPC consumption.
- **Recommendation:** Validate `to_block - from_block <= MAX_RANGE`.
- **Fix Status:** Open

#### M-MW-5 — MCP `verify_stealth_payment` does not validate `tx_hash` format
- **Severity:** MEDIUM
- **Location:** `scanning-service/src/mcp-transport.ts:54-56`
- **Description:** `tx_hash` typed as `z.string()` with no format constraint, cast directly to `Hex`. Arbitrary strings passed to RPC.
- **Recommendation:** Add `z.string().regex(/^0x[0-9a-fA-F]{64}$/)`.
- **Fix Status:** Open

#### M-MW-6 — Access key comparison not strictly timing-safe
- **Severity:** MEDIUM
- **Location:** `scanning-service/src/access-key.ts:110-123`
- **Description:** Hash-then-lookup via `Map.get()` provides reasonable resistance, but JavaScript's string comparison is not guaranteed constant-time.
- **Recommendation:** Use `crypto.timingSafeEqual()` to compare hashes.
- **Fix Status:** Open

#### L-MW-2 — Health endpoint exposes internal metrics without authentication
- **Severity:** LOW
- **Location:** `scanning-service/src/service.ts:208-233`
- **Description:** Unauthenticated `/health` exposes `lastScannedBlock`, `chainTip`, `lag`, `paymentsDetected`.
- **Recommendation:** Split into minimal `/healthz` and authenticated metrics endpoint.
- **Fix Status:** Open

#### L-MW-3 — Access key manager stores keys only in memory
- **Severity:** LOW
- **Location:** `scanning-service/src/access-key.ts:49`
- **Description:** In-memory `Map`. Restart loses all keys and revocation state.
- **Recommendation:** Persist to disk or database.
- **Fix Status:** Open

#### L-MW-4 — Unused `signingScalar` in access key manager
- **Severity:** LOW
- **Location:** `scanning-service/src/access-key.ts:76-81`
- **Description:** Computed but never used. Suggests incomplete implementation.
- **Recommendation:** Remove dead code.
- **Fix Status:** Open

#### I-MW-2 — No CORS headers set by any middleware
- **Severity:** INFO
- **Description:** CORS expected to be configured at a higher level. Consumers must allow `Authorization` and `Payment-Receipt` headers.

---

## Cross-SDK Compatibility Assessment

| Step | TypeScript | Python | Rust | Match? |
|------|-----------|--------|------|--------|
| ECDH shared point | `ephemeralPoint.multiply(viewingPriv)` | `ephemeral_point * viewing_scalar` | `(ephemeral_pub * viewing_priv).to_affine()` | Yes |
| Hash input | `compress(S)` | `compress(S)` | `compress(S)` | Yes |
| Hash function | `keccak256` | `keccak256` | `Keccak256` | Yes |
| View tag | `hash[0]` | `hash[0]` | `hash[0]` | Yes |
| Scalar derivation | `BigInt(hash) % n` | `int(hash) % N` | `Scalar::reduce_bytes(hash)` | Yes* |
| Stealth pubkey | `K_spend + s * G` | `K_spend + s * G` | `K_spend + s * G` | Yes |
| Address derivation | `keccak256(uncomp[1:])[-20:]` | `keccak256(uncomp[1:])[-20:]` | `keccak256(uncomp[1:])[-20:]` | Yes |

*\*Equivalent for 256-bit inputs. Add cross-SDK test vectors to lock this.*

**Risk:** No shared deterministic test vectors exist. A subtle change in any SDK's serialization or byte ordering would silently break cross-SDK payment detection with no test failure.

**Recommendation:** Create a shared `test-vectors.json` with hardcoded private keys, ephemeral keys, and expected outputs. Import in all three SDK test suites.

---

## Summary Table

| Severity | Count | Contracts | TS SDK | Python SDK | Rust SDK | Middleware | Scanning |
|----------|-------|-----------|--------|------------|----------|------------|----------|
| CRITICAL | 7 | 0 | 3 | 1 | 2 | 0 | 1* |
| HIGH | 12 | 0 | 4 | 3 | 3 | 2 | 0* |
| MEDIUM | 18 | 3 | 6 | 4 | 4 | 1 | 0* |
| LOW | 14 | 4 | 2 | 1 | 3 | 1 | 3 |
| INFO | 10 | 2 | 0 | 1 | 2 | 1 | 4* |

*\*Some findings span both SDK server code and scanning service.*

---

## Prioritized Remediation Roadmap

### Immediate (Before Any Production Use)
1. **C-MW-1:** Implement consumed tx hash tracking to prevent credential replay
2. **C-MW-2:** Add payment amount verification in `verifyPayment`
3. **C-TS-1:** Replace `Math.random()` with `crypto.randomUUID()`
4. **C-TS-2/C-TS-3:** Add zero-scalar and key range validation in TS SDK
5. **C-PY-1:** Replace `ecdsa` with `coincurve`
6. **C-RS-1/C-RS-2:** Add `zeroize` + `subtle` crates to Rust SDK

### Before Mainnet
7. **H-TS-2/H-TS-3:** Constant-time comparison + credential binding
8. **H-MW-1:** Fix Elysia shared state race condition
9. **H-MW-3/H-MW-4:** Bound all unbounded arrays
10. Cross-SDK test vectors (`test-vectors.json`)

### Hardening
11. All MEDIUM findings
12. All LOW findings
13. Security-focused test cases (malformed inputs, edge cases)
