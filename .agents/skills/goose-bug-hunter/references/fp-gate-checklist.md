# The 6-Gate Adversarial Refutation Protocol (`fp-check`) & Schemas

Every candidate finding—whether discovered by a Hunter subagent in `Full Pipeline Mode` or evaluated from an external report in `Inline / Verify Mode`—must pass all 6 adversarial gates before receiving a `CONFIRMED` verdict.

---

## 1. The 6 Verification Gates

### Gate 1 — Source Trace Completeness (*Name-Is-Not-Evidence*)
- **Requirement**: Cite exact `.goose` file paths and positive line numbers (`file.goose:start-end`) for:
  1. The entrypoint where untrusted data enters (`finding_scope_root` or caller).
  2. Every intermediate helper or state transition along the call chain.
  3. The exact sink line where truncation, wrap-around, state corruption, bypass, or panic occurs.
- **Refutation Rule**: If the candidate infers what a helper function does from its name (`validate_*`, `sanitize_*`, `check_*`) without reading its implementation body, **hold or reject** until the body is read and cited.

### Gate 2 — Upstream Caller & Guard Reachability (`context_roots`)
- **Requirement**: Search all callers of the target function across `context_roots` (`.` across the repository) using `rg -n "<fn_name>\s*\("`.
- **Refutation Rule**:
  - If the function is an internal helper and **every** upstream caller already enforces the missing precondition (e.g., an ingress frame decoder already guaranteed `payload.len <= 128` before calling a helper with a `u8[..256]` buffer), downgrade to `PARTIAL` (if the function is `pub` and lacks defensive boundary checks) or `REJECTED` (if the function is private/internal and the invariant is documented).
  - If the function is dead code (`0` callers in production or tests), classify as dead-code hygiene rather than an exploitable runtime vulnerability.

### Gate 3 — Goose Type, Cast, & Bounds Mathematics
- **Requirement**: Write out the explicit algebraic inequality over `.len` (`i64`), `.cap` (`i64`), and integer widths (`u8`, `u16`, `u32`, `u64`, `i32`, `i64`):
  - Show the exact range of values permitted by all preceding `guard` or `if` statements.
  - Show the exact input length or value $X$ that satisfies every preceding `guard` yet violates the sink invariant (e.g., `prefix.len (22) + token.len (500) > out.cap (512)`).
- **Refutation Rule**: If preceding guards mathematically imply the sink stays in bounds for all reachable inputs, **reject** (`REJECTED`).

### Gate 4 — Goose Language & Architectural Exemptions (The 8 FP Traps)
- **Requirement**: Check the candidate against the **8 Goose False-Positive Traps** below.
- **Refutation Rule**: If the candidate matches any false-positive trap, **reject** (`REJECTED`) or reclassify accurately.

### Gate 5 — Concrete Impact vs. Hardening (`CONFIRMED` vs. `PARTIAL`)
- **Requirement**: Demonstrate a concrete runtime failure mode:
  - Security bypass (authentication/MAC/signature/SSRF/ACL bypass, timing side-channel, unzeroized secret on error).
  - Silent data truncation or wire frame corruption (`T[..N]` overflow without error return).
  - State machine lockup, ring-buffer/arena corruption, PRNG period collapse (`mul_sat_u64`), or `reusable` pool slot leak.
  - Runtime abort (`assert` failure, debug signed overflow vs. release wrap, or slice OOB).
- **Classification Rule**:
  - `confirmed`: All 6 gates pass; reachable and triggers concrete bug or spec violation.
  - `partial`: Valid defense-in-depth hardening gap or edge case only reachable if a caller bypasses normal constructors, or partially mitigated by another layer.
  - `rejected`: Disproved by upstream guards, Goose language semantics, or bounds math.

### Gate 6 — Minimal Reproduction or Concrete Trigger Input
- **Requirement**: Provide either:
  1. A concrete input vector (exact byte slice length, wire hex sequence, or call sequence) that triggers the bug step by step, OR
  2. A runnable `goose-lit` test directive (`// RUN: goose %s`) when `goose-lit` is available.

---

## 2. The 8 Goose False-Positive Traps

| Trap # | False Claim Commonly Made by Naive Auditors | Actual Goose Language / Architecture Truth | Verdict Action |
| :--- | :--- | :--- | :--- |
| **Trap 1** | "`checkfree fn` disables runtime bounds checks like Rust's `get_unchecked`, causing an out-of-bounds memory read." | In Goose, `checkfree fn` makes any surviving runtime bounds check a **compile error** (enforcing compile-time Bounds Check Elimination / BCE). A `checkfree` function only has a bug if it uses a faulty `as!` cast, bad `assert`, or arithmetic wraparound before indexing. | **REJECT** unless an `as!`, bad mask, or `assert` abort is proven. |
| **Trap 2** | "`var buf: u8[>..] = []` declared inside a loop leaks heap memory or allocates on the system heap every iteration." | Goose has **no heap**. `T[>..]` lives on a compiler-sized data stack where scope exit is a single stack-pointer store; a fresh local inside a loop frees at the end of each iteration. It is only a bug in universal Goose if declared **outside** the loop and grown inside without `.clear()`/`.truncate()`, or if it violates a project-specific zero-alloc lint (`--profile wing`). | **REJECT** as a memory leak; only flag unbounded outer-loop growth or `--profile wing` hot-loop policy. |
| **Trap 3** | "Module-level `var g_state` is accessed by multiple `thread_fn` workers without a mutex, causing a shared-memory data race." | Goose has **no shared mutable memory between threads**. Every `thread_fn` receives its own thread-local copy of every global it uses. The real bug with globals in `thread_fn` is assuming mutations in a worker are visible to `main`, or single-thread re-entrancy across sequential requests. | **REJECT** "multi-thread data race" claims; check for worker-to-main visibility bugs or single-thread re-entrancy instead. |
| **Trap 4** | "Growing `T[>..]` as the final field of a long-lived struct (e.g., `TlsSession`, `Arena`) is a bug because all structs must use `T[..N]`." | Goose permits `T[>..]` as the final field of a struct specifically so large long-lived tables do not consume multi-megabyte stack frames on creation. Only wire frame/packet/header structs (`*Frame`, `*Packet`, `*Header`) prohibit `T[>..]`. | **REJECT** on long-lived session/pool structs. |
| **Trap 5** | "Downstream helper `encode_block(s: const u8[:])` uses `u8[..768]` without checking `s.len <= 768`." | If `encode_block` is only called with a struct field `item: u8[..128]` whose `.cap` is `128`, `s.len` can never exceed `128`. | **REJECT** if private; **PARTIAL** if `pub` and callable with arbitrary slices. |
| **Trap 6** | "`a % b` on negative signed integers `i64` returns a negative index and reads out-of-bounds." | In Goose, `%` is **Euclidean modulo** (`-7 % 3 == 2`), which is always non-negative when the divisor `b > 0` (`rem` is the truncating remainder operator). | **REJECT** negative-result claims on `%` when divisor `> 0`. |
| **Trap 7** | "Matching on a fixed-size enum or iterating `for x in arr` mutates the original array elements in place." | In Goose, `for x in xs` on fixed-size elements binds a read-only copy (`for &x in xs` is required to mutate in place). Conversely, `let b = a` on a resizable `T[>..]` binds `b` by reference. | Verify exact Goose value vs. reference binding rules before flagging. |
| **Trap 8** | "Comparing an enum tag, HTTP status code, or public key ID (`kid`) with `==` is a timing side-channel vulnerability." | Constant-time comparison (`ct_eq_bytes`) is required only for secret-derived digests, MACs, HMACs, signatures, passwords, and bearer/session tokens—not public identifiers or wire opcodes. | **REJECT** timing claims on public identifiers. |

---

## 3. Canonical JSON Schemas

### 3.1 `run-metadata.json`
```json
{
  "run_id": "run_20261103_221000",
  "created_at": "2026-11-03T22:10:00+00:00",
  "repo_root": "D:/GooseProjects/goose-wing",
  "finding_scope_root": "auth",
  "context_roots": ["D:/GooseProjects/goose-wing"],
  "profile": "wing",
  "recommended_mode": "full_pipeline",
  "capabilities": {
    "goose_available": true,
    "goose_lit_available": true,
    "rg_available": true,
    "has_agents_md": true,
    "has_wing_lint_invariants": true,
    "has_rfc_corpus": true
  },
  "total_files": 6,
  "total_units": 155,
  "total_slices": 14,
  "signal_summary": {
    "BOUNDED_APPEND_NO_GUARD": 11
  }
}
```

### 3.2 `coverage-ledger.json`
Top-level JSON object containing `slices` and `units`. Each unit must transition from `"planned"` to `"covered"` or `"skipped"` (with non-empty `"skip_reason"`):
```json
{
  "run_id": "run_20261103_221000",
  "finding_scope_root": "auth",
  "total_units": 155,
  "total_slices": 14,
  "slices": [
    {
      "slice_id": "S001",
      "files": ["auth/acme.goose", "auth/digest.goose"],
      "unit_ids": ["U0001", "U0002"],
      "unit_count": 2,
      "line_span": 54
    }
  ],
  "units": [
    {
      "unit_id": "U0001",
      "slice_id": "S001",
      "file": "auth/acme.goose",
      "name": "acme_validate_token",
      "kind": "pub fn",
      "start_line": 29,
      "end_line": 46,
      "signature": "pub fn acme_validate_token(token: const u8[:]) -> bool",
      "gcrap_score": 0.34,
      "eff_cc": 10,
      "risk_safety": 0.0,
      "uncovered_bce_keep": 0,
      "static_signals": [],
      "status": "covered",
      "skip_reason": "",
      "finding_ids": []
    }
  ]
}
```

### 3.3 `findings.json`
Top-level JSON object containing `run_id` and `findings` array (preserving `confirmed`, `partial`, and `rejected` records for full auditability):
```json
{
  "run_id": "run_20261103_221000",
  "findings": [
    {
      "finding_id": "F001",
      "unit_id": "U0022",
      "file": "proxy/load_balancer.goose",
      "lines": "72-78",
      "bug_class": "GOOSE-BUG-3",
      "severity": "P1",
      "confidence": "HIGH",
      "verdict": "confirmed",
      "gates_passed": [1, 2, 3, 4, 5, 6],
      "trigger_trace": "next_prng(state) at proxy/load_balancer.goose:74 calls core::mul_sat_u64(state & 0xFFFFFFFF, 6364136223846793005), which saturates to u64::MAX whenever (state & 0xFFFFFFFF) >= 3",
      "refutation_notes": "Checked all callers in proxy/load_balancer.goose; state is initialized with non-zero seed and saturates permanently on first step.",
      "variants": [
        "proxy/gcra.goose:64"
      ]
    }
  ]
}
```
