---
name: goose-evolve
description: Use when optimizing, simplifying, or evolving Goose (.goose) modules for latency, BCE bounds-check elimination, data-stack footprint, or SLOC under strict mechanical verification gates and a Pareto frontier archive.
---

# Goose-Evolve

Closed-loop evolutionary optimization for `goose-wing`. Every candidate edit is
filtered through hard mechanical gates (`goose format`, `goose check`,
`checkfree`, `lint_invariants.py`, `goose-lit` G-CRAP and anti-packing, plus
optional `verify_ct_asm.py`, `goose2rfc`, and differential tests) and ranked on
a multi-objective Pareto frontier (`ns_op`, `target_bce_kept`,
`main_data_stacks`, `sloc`, `max_gcrap`).

## Compiler independence

`scripts/goose_evolve.py` works 100% on an **unpatched** `goose` binary using
stock `goose check --stats --bce-lines --stacks`. If the optional
`--export-facts` compiler flag is present, it automatically switches to
`patched:--export-facts` to expose exact `BCE::KeptWhy` explanations,
`Speculatable` `&&`/`||` blockers, per-function data-stack counts, and BCE
effect summaries. Pass `--force-unpatched` to force stock CLI mode.

## Workflow

1. Inspect bottlenecks and compiler-backed hypotheses:

   ```bash
   python scripts/goose_evolve.py analyze <target.goose> [--entry <entry.goose>]
   ```

2. Lock `gen_0000` baseline before making edits:

   ```bash
   python scripts/goose_evolve.py init <campaign> --target <target.goose> \
     --entry <entry.goose> --test-cmd "<test>" --bench-cmd "<bench>"
   ```

3. Edit `<target.goose>` with a single architectural or kernel hypothesis (never
   stack unrelated speculative edits).

4. Run gates, optional benchmark, and Pareto comparison:

   ```bash
   python scripts/goose_evolve.py eval <campaign> --note "<hypothesis>"
   ```

5. Keep `IMPROVED_PARETO` or `PARETO_TRADEOFF`. On `DOMINATED` or
   `REJECTED_GATE`, roll back immediately to the best frontier snapshot:

   ```bash
   python scripts/goose_evolve.py restore <campaign> <best_gen_id>
   ```

6. Inspect the archive with `python scripts/goose_evolve.py status <campaign>`.

## High-leverage Goose mutations

| Mutation | Goose technique |
| --- | --- |
| BCE boundary transfer | Replace raw `u64` or field indices across API boundaries with `u32 in arr` or `i64 upto slice`, and move `u64` loop counters to `i64` or `for i in n`. |
| SIMD speculation unblock | Split short-circuit `&&` or `\|\|` conditions flagged by `speculation_blocks` or prove inner bounds before the branch so C compilers can if-convert loops. |
| Data-stack compression | Replace local `T[>..]` scratch vectors in hot functions with stack-bounded `T[..N]` or caller-reused buffers to cut `main_data_stacks` and raise `hardware_threads()`. |
| Single-pass parser and stage fusion | Merge adjacent scans over the same `const u8[:]` buffer while preserving `errdefer` rollback hygiene. |
| Compile-time LUTs | Replace repetitive `match` dispatch tables with `const for` or dense static tables. |

## Anti-gaming rules

- Never weaken tests, relax `--max-gcrap`, or bypass `--check-packing`.
- Never drop RFC validation guards, `// Example:` contracts, or `core::ct_eq_*`
  constant-time checks (`--ct-check` rejects branchy crypto codegen).
- Always run `status` before finishing and clean up temporary campaigns under
  `.lit/cache/evolve/` if no longer needed.
