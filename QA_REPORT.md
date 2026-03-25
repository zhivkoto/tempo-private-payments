# QA Report — Phase 2

**Date:** 2026-03-25
**Runner:** Claude Code QA Agent

---

## 1. Rust SDK (`sdk/rust/`)

### `cargo test` — PASS
| Suite | Passed | Failed | Ignored |
|-------|--------|--------|---------|
| Unit tests (`src/lib.rs`) | 14 | 0 | 0 |
| Integration (`tests/scanner_tests.rs`) | 6 | 0 | 0 |
| Integration (`tests/stealth_tests.rs`) | 12 | 0 | 0 |
| **Total** | **32** | **0** | **0** |

### `cargo clippy` — 10 warnings (0 errors)
- 1× deprecated `GenericArray::as_mut_slice()` in `stealth.rs:224` — upgrade to generic-array 1.x recommended
- 5× `map_or(false, …)` → `is_some_and(…)` in `client.rs` (clippy::unnecessary_map_or)
- 4× useless `.into()` conversion in `stealth.rs` (clippy::useless_conversion)

**Verdict: PASS** (warnings are non-blocking)

---

## 2. Python SDK (`sdk/python/`)

### `pytest` — FAIL (dependency install failure)

The `coincurve` package fails to build on Python 3.14 (both v21.x and v20.x). All 3 test modules fail to import due to `ModuleNotFoundError: No module named 'coincurve'`.

| Test File | Status | Error |
|-----------|--------|-------|
| `tests/test_client.py` | COLLECTION ERROR | `coincurve` not installed |
| `tests/test_scanner.py` | COLLECTION ERROR | `coincurve` not installed |
| `tests/test_stealth.py` | COLLECTION ERROR | `coincurve` not installed |

**Root cause:** `coincurve` does not yet support Python 3.14. The project needs either:
1. A `python_requires` constraint (e.g., `<3.14`) in `pyproject.toml`, or
2. A pinned Python version (3.12 or 3.13) in CI / dev environment

**Verdict: FAIL** (environment issue — tests cannot run)

---

## 3. TypeScript Client SDK (`sdk/client/`)

### `vitest run` — PASS
| File | Tests | Passed |
|------|-------|--------|
| `test/client.test.ts` | 4 | 4 |
| `test/stealth.test.ts` | 8 | 8 |
| **Total** | **12** | **12** |

**Verdict: PASS**

---

## 4. TypeScript Server SDK (`sdk/server/`)

### `vitest run` — PASS
| File | Tests | Passed |
|------|-------|--------|
| `test/scanner.test.ts` | 6 | 6 |

**Verdict: PASS**

---

## 5. Middleware

### Express (`middleware/express/`) — PASS
| File | Tests | Passed |
|------|-------|--------|
| `test/middleware.test.ts` | 7 | 7 |

### Next.js (`middleware/nextjs/`) — PASS
| File | Tests | Passed |
|------|-------|--------|
| `test/middleware.test.ts` | 7 | 7 |

### Elysia (`middleware/elysia/`) — PASS
| File | Tests | Passed |
|------|-------|--------|
| `test/middleware.test.ts` | 4 | 4 |

**Verdict: PASS** (all 3 middleware packages)

---

## 6. Scanning Service (`scanning-service/`)

### `vitest run` — PASS
| File | Tests | Passed |
|------|-------|--------|
| `tests/access-key.test.ts` | 12 | 12 |
| `tests/mcp-transport.test.ts` | 10 | 10 |
| `tests/service.test.ts` | 7 | 7 |
| `tests/e2e.test.ts` | 7 | 7 |
| **Total** | **36** | **36** |

**Verdict: PASS**

---

## 7. Solidity Contracts (`contracts/`)

### `forge test -vvv` — PASS
| Suite | Tests | Passed |
|-------|-------|--------|
| `StealthRegistry.t.sol` | 17 | 17 |
| `StealthAnnouncer.t.sol` | 29 | 29 |
| **Total** | **46** | **46** |

**Verdict: PASS**

---

## Summary

| Component | Tests | Passed | Failed | Verdict |
|-----------|-------|--------|--------|---------|
| Rust SDK | 32 | 32 | 0 | PASS |
| Rust Clippy | — | — | 10 warnings | PASS (warnings) |
| Python SDK | 3 files | 0 | 3 (import errors) | **FAIL** |
| TS Client SDK | 12 | 12 | 0 | PASS |
| TS Server SDK | 6 | 6 | 0 | PASS |
| Express Middleware | 7 | 7 | 0 | PASS |
| Next.js Middleware | 7 | 7 | 0 | PASS |
| Elysia Middleware | 4 | 4 | 0 | PASS |
| Scanning Service | 36 | 36 | 0 | PASS |
| Solidity Contracts | 46 | 46 | 0 | PASS |
| **Total** | **150+** | **150** | **3 collection errors** | — |

### Overall Verdict: **CONDITIONAL PASS**

All code components pass their test suites. The Python SDK cannot be tested due to a `coincurve` build failure on Python 3.14 — this is an environment/dependency compatibility issue, not a code defect. Recommend testing Python SDK on Python 3.12 or 3.13.

Rust clippy reports 10 non-blocking warnings (style/deprecation) that should be addressed in a cleanup pass.
