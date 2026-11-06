---
name: goose-bug-hunter
description: "Use when auditing any Goose (.goose) codebase, package, or file for bugs, memory/bounds truncation, integer/SWAR wrap-around, state machine flaws, reusable pool leaks, cryptographic/FFI defects, or specification compliance, or when verifying external audit reports against .goose source code."
license: Apache-2.0
metadata:
  author: Lemon4ksan
---

# Goose Bug Hunter (`goose-bug-hunter`)

> Copyright (c) 2026 Lemon4ksan. Licensed under the [Apache-2.0 License](file:///LICENSE).

A project-agnostic bug-hunting, bounds-verification, and specification-compliance skill for any codebase written in the **Goose programming language (`.goose`)**.

It combines a deterministic zero-dependency Python scanner (`scripts/goose_audit_scanner.py`) with Goose's exact language semantics (stack-bounded arrays `T[..N]`, data-stack growable vectors `T[>..]`, `slot_pool<T>` / `slice_pool<T>` and `reusable` pools, `root struct`, `defer` block exits, `checkfree` compile-time BCE, explicit casts `as` / `as!`, saturating arithmetic, and thread-local `thread_fn` globals) and a 6-gate false-positive refutation protocol (`fp-check`).

---

## 1. Progressive Context Loading & Directory Layout

Load companion references from `file:///.agents/skills/goose-bug-hunter/` **only when needed**:

- [`references/goose-bug-classes.md`](file:///.agents/skills/goose-bug-hunter/references/goose-bug-classes.md) — **Always read before hunting**: Detailed mechanics, vulnerable patterns, zero-allocation fixes, and `rg` queries for the 8 Universal Goose Bug Classes (`GOOSE-BUG-1`..`8`).
- [`references/fp-gate-checklist.md`](file:///.agents/skills/goose-bug-hunter/references/fp-gate-checklist.md) — **Always read before verifying/reporting**: The 6 Verification Gates, the 8 Goose False-Positive Traps, and exact JSON schemas (`run-metadata.json`, `coverage-ledger.json`, `findings.json`).
- [`references/crypto-and-protocols.md`](file:///.agents/skills/goose-bug-hunter/references/crypto-and-protocols.md) — **Read only when auditing crypto, auth, or network/wire protocols**: Constant-time `ct_eq_bytes`, early-return secret zeroization, order-of-operations, normalization bypasses, and RFC/spec atomic compliance.
- [`references/subagent-prompts.md`](file:///.agents/skills/goose-bug-hunter/references/subagent-prompts.md) — **Read only in `Full Pipeline Mode`**: Copy-paste prompt contracts for Sliced Hunter and Module-Batched Refuter subagents.
- [`../goose/SKILL.md`](file:///.agents/skills/goose/SKILL.md) and [`../goose/references/`](file:///.agents/skills/goose/references/) — **Read when verifying Goose language semantics, compiler diagnostics, memory placement rules, or standard library signatures** (`language.md`, `memory.md`, `stdlib.md`, `patterns.md`, `tooling.md`, `diagnostics.md`).

---

## 2. Scope & Mode Router

First, run the deterministic scanner on the user's target path:

```bash
python ./.agents/skills/goose-bug-hunter/scripts/goose_audit_scanner.py scan <target_path>
```

Check `recommended_mode` and `total_units` in the JSON output:

1. **`Inline / Verify Mode`** (1–2 `.goose` files, $\le 24$ functions, or verifying an external bug report):
   - Do **not** spawn subagent swarms.
   - Read `references/goose-bug-classes.md` and `references/fp-gate-checklist.md` directly.
   - Audit every function unit in `coverage-ledger.json` (or each claim in the external report) inline, apply all 6 `fp-check` gates, update `coverage-ledger.json` and `findings.json`, and validate with `validate-ledger`.
2. **`Full Pipeline Mode`** (Directory, package, or repository with $>2$ files or $>24$ functions):
   - Read `references/subagent-prompts.md` and execute the 4-Phase Pipeline below.

### Strict Scope Separation (`finding_scope_root` vs. `context_roots`)
- **`finding_scope_root`**: The target file/directory being audited. File bugs **only** in `finding_scope_root`.
- **`context_roots`**: The entire repository (`.`). Always search `context_roots` (via `rg`) to inspect callers, struct definitions, and upstream parsers before claiming a check is missing.
- **Read-Only Default**: Never modify tracked `.goose` files unless the user explicitly asks to fix the bugs.

---

## 3. The 4-Phase Audit Workflow

### Phase 1: Deterministic Recon & Ledger Generation
1. Run `goose_audit_scanner.py scan <target_path> [--out-dir <dir>] [--profile auto|universal|wing]`.
   - Automatically runs `goose-lit crap <target_path> --format json` when `goose-lit` is installed, attaching `gcrap_score`, `eff_cc`, `risk_safety`, and `uncovered_bce_keep` to each function unit.
   - Runs 12 static Goose probes (`BOUNDED_APPEND_NO_GUARD`, `NARROW_OR_FORCE_CAST`, `BCE_OR_CHECKFREE_RISK`, `UNBOUNDED_LOOP_GROWTH_OR_ALIAS`, `IGNORED_RETURN_TUPLE`, `SATURATING_OR_SIGNED_OVERFLOW`, `REUSABLE_POOL_OR_GLOBAL_STATE`, `EARLY_RETURN_RESOURCE_LEAK`, `SWAR_ARITHMETIC`, `EARLY_EXIT_SECRET_CMP`, `SECRET_NO_ZEROIZE`, `EXTERN_FFI_OR_STUB_RETURN`).

### Phase 2: Sliced Coverage-Led Hunting
1. In `Full Pipeline Mode`, dispatch parallel **Hunter subagents** (`invoke_subagent`) using the prompt in `references/subagent-prompts.md`, assigning 1 slice ($\le 12$ functions / $\le 400$ lines) per Hunter.
2. **Single-Writer Rule**: Subagents never write to `coverage-ledger.json`; they return JSON results to the Coordinator, which updates `coverage-ledger.json`.

### Phase 3: Adversarial 6-Gate Refutation (`fp-check`)
1. Deduplicate candidate bugs by `(file, sink_line, bug_class)`.
2. Group candidates by file/module into bounded batches of **3–5 candidates per Refuter subagent** (or verify inline in `Inline Mode`).
3. Every candidate must pass all 6 gates in `references/fp-gate-checklist.md`:
   - **Gate 1 (Source Trace)**: Exact `file:line` from entrypoint to sink (*name is not evidence*).
   - **Gate 2 (Upstream Caller Reachability)**: Check all callers in `context_roots` (`rg -n "<fn_name>\s*\("`).
   - **Gate 3 (Goose Bounds & Cast Math)**: Prove an input satisfies preceding `guard`s yet violates `.cap` / width at the sink.
   - **Gate 4 (8 Goose FP Traps)**: Reject false claims that misstate Goose language rules (`checkfree` is compile-time BCE; `T[>..]` is data-stack allocated; `thread_fn` globals are thread-local copies; `%` is Euclidean).
   - **Gate 5 (Concrete Impact)**: Classify as `confirmed` (exploitable bug/spec violation), `partial` (defense-in-depth hardening gap), or `rejected`.
   - **Gate 6 (Minimal Trigger / LIT Proof)**: Concrete input vector or `goose-lit` test.

### Phase 4: Variant Sweep & Ledger Validation
1. For every `confirmed` finding, sweep the codebase for structural siblings using `rg -n "<pattern>"` or `goose_audit_scanner.py variants "<pattern>"`.
2. Write final verdicts to `findings.json` and `REPORT.md`, update all reviewed units in `coverage-ledger.json` to `"covered"`, and verify completion (must exit with code `0`):
   ```bash
   python ./.agents/skills/goose-bug-hunter/scripts/goose_audit_scanner.py validate-ledger <out_dir>/coverage-ledger.json
   ```

---

## 4. Quick Reference: The 8 Universal Goose Bug Classes

| Class | Summary | Key Goose Mechanism |
| :--- | :--- | :--- |
| `GOOSE-BUG-1` | **Validation/Crypto/FFI Stubs** | `verify_*`/`validate_*` returning `true`, `0`, or `CloseNotify` on unhandled branches or empty slices. |
| `GOOSE-BUG-2` | **Silent `T[..N]` Truncation** | `.append()` / `.push()` on bounded array `T[..N]` without `guard dst.len + src.len <= dst.cap`, or caller/callee buffer cap mismatch. |
| `GOOSE-BUG-3` | **Wrap-Around, `as!` Casts, Overflow, SWAR** | Ring-buffer `write_pos = 0` wrap leaving stale `head`; narrowing `i64` `.len` via `as u16`/`as!`; signed overflow (aborts in debug, wraps in release); `mul_sat_u64` PRNG lockup; SWAR byte carry. |
| `GOOSE-BUG-4` | **Non-Transactional State & `T[>..]` Aliasing** | Mutating `idx: i64&`, `seq += 1`, or evicting table entries before verification succeeds; `let b = a` on `T[>..]` aliasing by reference instead of copying (`copy(a)`). |
| `GOOSE-BUG-5` | **Discarded Tuples & Enum Fallbacks** | `let val, _ = parse_foo(...)` ignoring error flag; parser mapping unknown strings/codes to a valid operational enum variant. |
| `GOOSE-BUG-6` | **Order-Dependent Checks & Normalization** | Cross-field validation inside an unordered loop; checking host/IP/path before normalizing case, trailing `.`, or IPv6 `[::1]`. |
| `GOOSE-BUG-7` | **`slot_pool` / `slice_pool` / `reusable` Pools, Leaks, & Global State** | Stale slot index/ref after `pool.free(idx)` / `free_ref` without generation check; `realloc_slice` invalidating sub-slices; early `guard` return leaking resources when no `defer` is registered (or on `abort`/`exit`); single-thread global re-entrancy or `thread_fn` global copy isolation. |
| `GOOSE-BUG-8` | **Outer-Loop `T[>..]` Growth & BCE Risks** | Growing `var buf: T[>..]` declared outside a loop without `.clear()`; `checkfree` / BCE index masks or `assert`s failing on short slices; $O(N)$ per-frame rebuilds. |

---

## 5. Rationalizations to Reject

| Common Rationalization | Why You Must Reject It |
| :--- | :--- |
| *"The helper is named `validate_token`, so the token is already validated."* | **Name is not evidence.** Read the function body; it may be a stub or check only syntax length. |
| *"This `u8[..512]` buffer is plenty big for normal RFC examples."* | Real bearer tokens, certs, and headers reach 4096–8192 bytes; missing `guard len <= cap` is a confirmed truncation bug (`GOOSE-BUG-2`). |
| *"`checkfree fn` disables bounds checks at runtime, so any indexing inside it is an OOB bug."* | False in Goose (`checkfree` enforces compile-time BCE). You must prove a faulty `as!`, bad bitwise mask, or failing `assert`. |
| *"`var scratch: u8[>..] = []` inside a loop leaks heap memory."* | Goose has no heap; `T[>..]` uses a data stack freed on scope exit. Check whether it is declared *outside* the loop without `.clear()` or if `--profile wing` applies. |
| *"This module-level `var g_count` has a multi-threaded data race across `thread_fn`."* | Goose threads share no memory (`thread_fn` copies globals). Check instead if worker mutations are lost to `main` or if single-thread callbacks re-enter `g_count`. |
| *"I already found 5 bugs in this file; I can mark the remaining functions `covered` by skimming."* | Every unit in `coverage-ledger.json` must be inspected line by line before transitioning from `planned` to `covered`. |
