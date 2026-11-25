---
name: goose-goal-sloc
description: Use when shrinking, simplifying, or optimizing Goose (.goose) codebases to reduce SLOC while preserving or improving CPU cycles and BCE proofs, or when tempted to trade speed, formatting, or safety checks for shorter code.
---

# Goose Goal-SLOC

## Core theorem

Among semantically equivalent Goose implementations, one canonical form wins:
the Pareto minimum of `(cycles, SLOC)` under `goose format`, with zero new
`bce:keep` checks and zero new compiler smells.

Violating the letter of the rules violates the spirit. Never trade CPU cycles,
BCE proofs, or RFC boundary checks for fewer lines.

## Metrics (`goose-lit sloc`)

- Diagnostic radar: `cycles / SLOC` (`HOT_KERNEL >= 1.0`, `BALANCED 0.1..1.0`,
  `COLD_BLOAT < 0.1`). Never optimize `cycles / SLOC` alone (adding lines
  lowers it; slowing code raises it).
- Acceptance gate: `CL = cycles * SLOC` plus Pareto check (`L <= L0`,
  `C <= C0 * (1 + noise)`, zero `GAMING_DETECTED`, zero `bce:keep` increase,
  zero local compiler smell increase).
- Self-Audit: always report `goose-lit sloc` deltas (`delta_sloc`,
  `delta_stmts`, `delta_comments`, `delta_smells`, `delta_bce_kept`). If
  `delta_sloc < 0` while `delta_stmts >= 0`, you packed lines instead of
  removing logic - revert.

## Workflow

1. **Pin baseline**: run `just sloc-ratchet` and `just sloc-profile` (or
   `goose-lit sloc <target> --smells --bce`). Record starting `SLOC`, `Stmts`,
   `Smells`, `bce_kept`, and scope `cycles`.
2. **Identify irreducible floor**: RFC static tables, crypto S-boxes, C shims.
   Report floor separately; never degrade fast lookup tables to slow loops to
   chase a line target.
3. **Cut in honest reduction order**:
   1. Dead code and redundant forwarding wrappers (`new_*()`, 1-line aliases).
   2. Manual field-by-field `reset_*` / `init_*` blocks -> struct default
      assignment `slot = Slot { field: v, .. };` and array fills `[0; N]`.
   3. Repetitive `match` tables -> `const for <N, V> in variants<E>` or dense
      const LUTs (never duplicate enum-to-name tables).
   4. Compiler-hostile loops -> BCE-clean `i64` `for i in n`, `for &x in xs`,
      `u32 in arr`, removing `core::*_sat_*` from BCE-proven loop steps.
   5. Multi-return `inline fn -> T, bool` -> `T?` or `return err from f`
      (`optimize.h` marks multi-return `noinline` in Goose IR).
   6. Built-in bit/array/SIMD ops -> `63 - clz(x)`, `(1 as u64) << n`,
      `a == [0; 4]`, `simd fn`, `stripk`, `sumred`, `Speculatable &&/||`.
   7. Cross-module deduplication into `core/` and clean-room rewrites of
      mega-files using existing tests as spec.
4. **Verify every milestone**:
   `goose format --check .`, `goose-lit check`, unit/LIT tests,
   `python scripts/lint_invariants.py`, and `goose-lit sloc --baseline ...
   --check-packing --check-smells` (plus `--run-profile` on mapped hot paths).

## Anti-gaming rules

| Temptation | Required action |
| --- | --- |
| Pack statements onto 1 line (`a; b; c;`) | Keep canonical `goose format`; `--check-packing` rejects `stmts/SLOC > 1.35` |
| Strip comments/RFC citations for SLOC | `sloc` ignores comment-only lines; keep RFC citations and `// Example:` |
| Skip `--bce` / `--run-profile` because tests pass | Functional tests miss BCE/cycle regressions; measure before committing |
| Spam `inline fn` everywhere | Goose auto-inlines small helpers (`<= 200` nodes); drop redundant `inline` |
| Keep `u64` counters or `*_sat_*` inside hot loops | Use `i64` / `for i in n` / `u32 in arr`; `bce.h` excludes plain `u64` |

## References

- Compiler-verified idioms and quirks:
  [goose-canonical-patterns.md](references/goose-canonical-patterns.md)
- `goose-wing` wave targets and commands:
  [goose-wing-campaign-plan.md](references/goose-wing-campaign-plan.md)
