---
name: goose-rfc-audit
description: "Use when generating ASD-STE100 state-machine specifications (.sm.md) with goose2rfc or conducting two-phase RFC conformance, wire-framing, and transactional rollback audits across Goose (.goose) protocol packages."
license: Apache-2.0
metadata:
  author: Lemon4ksan
---

# Goose RFC Conformance & State-Machine Audit (`goose-rfc-audit`)

> Copyright (c) 2026 Lemon4ksan. Licensed under the
> [Apache-2.0 License](file:///LICENSE).

Two-phase RFC conformance, wire-framing, and state-machine audit workflow for
`goose-wing` powered by the `goose2rfc` ASD-STE100 specification compiler and
[`scripts/gen_rfc_specs.py`](file:///scripts/gen_rfc_specs.py).

## 1. Specification Generation (`scripts/gen_rfc_specs.py`)

Before auditing a package or after modifying `.goose` protocol files, compile
the target modules into `.agents/rfc_specs/<pkg>/<module>.sm.md`:

```bash
# Compile specific packages or files in parallel and format with goosemarklint
python scripts/gen_rfc_specs.py auth http2
python scripts/gen_rfc_specs.py http2/connection.goose

# Compile all 18 production packages in goose-wing
python scripts/gen_rfc_specs.py --all
```

Each generated `.sm.md` file contains up to 6 deterministic sections per
protocol function:

1. **Signature**: Parameters, types, `in` / `in_out` mode, and Goose size class.
2. **Entry context and wire operations**: Caller preconditions and positional
   `Read#k` / `Write#k` wire operations with bit/byte encodings.
3. **Requirements (`R1..Rn`)**: Inlined guard predicates, bounds (`REQ_MIN`,
   `REQ_MAX`, `REQ_EQ`, `REQ_NE`), and arithmetic wrap annotations
   (`+_u64_wrap`, `-_u64_wrap`, `as_checked`, `as_truncate`).
4. **Unchecked surface**: `UNCONSTRAINED_INPUT`, `DISCARDED_WIRE_FIELD`, and
   `[UNRESOLVED_AST_HAZARD]` items.
5. **Error side effects**: 4-state parameter rollback classification
   (`UNMODIFIED`, `TRANSACTIONAL_SELF`, `DIRTY_SELF_RESTORED_BY_CALLER`,
   `DIRTY_EXPOSED`).
6. **Machine (`## Machine`)**: Extracted FSM transition table (`state`, `event`,
   `guard`, `next`, `req`, `source`).

## 2. Two-Phase Subagent Audit Architecture

To prevent context bias where an agent rationalizes existing code as compliant,
audits of protocol packages run in two isolated phases. Read
[`references/subagent-prompts.md`](file:///.agents/skills/goose-rfc-audit/references/subagent-prompts.md)
for copy-paste subagent prompts.

### Phase 1: Isolated Specification Hunting (Zero `.goose` Source Access)

Spawn parallel `research` Hunter subagents (`2-4` modules per Hunter).

- **Allowed inputs**:
  - `.agents/rfc_specs/<pkg>/<module>.sm.md`
  - Normative RFC text in `.agents/rfc/rfc<NUM>.txt`
- **Strictly forbidden in Phase 1**:
  - Reading any `.goose` source file or `tests/*` file.
- **What Hunters look for**:
  1. **RFC MUST / MUST NOT violations** in `### 3. Requirements` (`<` vs `<=`
     off-by-one bounds, missing crypto key length bounds, missing header syntax
     checks, permissive fallbacks).
  2. **Unchecked wire fields** in `### 4. Unchecked surface`
     (`UNCONSTRAINED_INPUT` or `DISCARDED_WIRE_FIELD` on fields that RFCs
     require receivers to validate).
  3. **Transactional rollback violations** in `### 5. Error side effects`
     (`DIRTY_EXPOSED` on `idx: i64&` cursors or `out: B&` buffers, violating
     Invariants 5 and 18).
  4. **FSM transition gaps** in `## Machine` (accepting frames in invalid
     stream/connection states or emitting wrong RFC error codes).

### Phase 2: Adversarial Source & Caller Refutation

Spawn parallel `research` Refuter subagents (or verify inline for $\le 5$
candidates) with full access to `.goose` source files and `tests/*`. Every
Phase 1 candidate must pass 3 refutation gates before any code is modified:

1. **Gate 1 (Direct Source Verification)**:
   - Read the exact `.goose` function at `file:line`. Verify whether the logic
     is actually missing or whether a helper not inlined by `goose2rfc` already
     enforces the check.
2. **Gate 2 (Caller & Unit-Test Contract Verification)**:
   - Search all callers and tests via `rg -n "<fn_name>\s*\("`.
   - Check whether unit or LIT tests (`tests/*_test.goose`, `tests/lit/*.goose`)
     explicitly lock in a specific return value or policy boundary (e.g., RFC
     8725 16-byte HMAC minimum or intentional partial consumption). Never break
     an explicit test contract without user approval.
3. **Gate 3 (Goose Memory & Invariant Safety)**:
   - Verify that the proposed fix obeys all 19 repository invariants in
     [`scripts/lint_invariants.py`](file:///scripts/lint_invariants.py):
     - Use `defer if !committed { idx = saved_idx; out.resize(saved_len); };`
       for transactional cursor and out-buffer rollback (Invariants 5 and 18).
     - Use `(id & 1)` instead of `(id % 2)` on unsigned integers to avoid adding
       Euclidean modulo `ovf_ops` to G-CRAP.
     - Keep nesting depth $\le 3$ levels (`guard cond else { return ...; }`) and
       loop functions $\le 65$ lines.

## 3. Distinguishing Library Bugs from `goose2rfc` Analyzer Bugs

When a `.sm.md` specification shows an anomaly that contradicts the `.goose`
source code, classify it into one of two categories:

| Symptom in `.sm.md` | Root Cause in `goose2rfc` |
| --- | --- |
| Second `let x = ...` branch shows expression from first branch | `inl_add_binding` in `tools/goose2rfc/src/sema/inliner.goose` must update existing binding `x` in place instead of appending a shadowed duplicate. |
| Stdlib call `json::finish(r)` inlines unrelated `finish` from another file | `inl_try_inline_guard_call` / `inl_try_inline_let_stmt` in `tools/goose2rfc/src/sema/inliner.goose` must not strip `json::` / `std::` prefixes and must check parameter arity in `inl_bind_call_params`. |
| Inliner scans past the end of a function containing `'{'` or `'}'` | `inl_find_matching_rbrace` in `tools/goose2rfc/src/sema/inliner.goose` must ignore braces inside char literals `'...'`, strings `"..."`, and `//` comments. |
| `if a \|\| b { return false; }` becomes `a_neg \|\| b` instead of `!(a \|\| b)` | `inl_negate_fail_cond` in `tools/goose2rfc/src/sema/inliner.goose` must wrap compound `\|\|` / `&&` conditions in `!(...)` per De Morgan's laws. |
| `a >= X && a <= Y` renders as `` `a >= X && a` must be at most `Y` `` | `inl_emit_bound_callee_clause` in `tools/goose2rfc/src/sema/inliner.goose` must split top-level `&&` clauses before matching `<=` / `>=`. |
| `json::each_member` / `json::each_element` flagged as `[UNRESOLVED_AST_HAZARD]` | `parse_assign_or_expr_stmt` in `tools/goose2rfc/src/frontend/parser.goose` must parse trailing-block calls `callee(args) { ... };` as `AstKind.ForStmt`. |
| Dispatcher `if k == "x" { mutate(out); return true; }` marked `DIRTY_EXPOSED` | `scan_param_mutations` in `tools/goose2rfc/src/sema/effects.goose` must skip `IfStmt` blocks that unconditionally end with `return true;` (`if_stmt_returns_only_true_eff`). |

## 4. Mandatory Verification Checklist Before Commit

Every package audit and fix must pass all verification gates with exit code `0`:

```bash
# 1. Run package unit tests and LIT tests
goose run tests/<pkg>_test.goose --cc gcc
goose-lit tests/lit/lit_<pkg>*.goose

# 2. Check formatting, 19 static invariants, and G-CRAP gate (<= 25.0)
goose format --check <modified_files>
python scripts/lint_invariants.py --check-dead-code
python scripts/verify_wing_gate.py <modified_files> --max-gcrap 25

# 3. Regenerate and lint .sm.md specifications
python scripts/gen_rfc_specs.py <pkg>
```
