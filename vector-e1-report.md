# Vector E batch 1 - measurement gaps: runtime allocation counter and H2 micro-benchmarks

Branch `feat/measurement-gaps` (base `3ff1fa3`). Scope: the two batch-1 items from
`.gemini/AI_CONTEXT.md` section "Vector E. Пробелы измерений". TLS handshake bench,
sweeps, and soak are explicitly out of scope (other Streams).

## 1. Runtime allocation counter

### What "allocation" means in the Goose memory model

Investigation of the toolchain codegen (probe builds via `goose -o out.c`) established:

- Growable arrays `T[>..]` are bump-allocated on per-thread data stacks. Push/append
  compiles to inline stores against `gs_stack.top`; there is no per-growth runtime call
  and no `malloc`. Growth beyond the reservation hits the guard region
  (`gs_stack_overflow`).
- The runtime's only function-call allocator paths are the slice-pool span primitives:
  `gs_slice_pool_place` / `gs_slice_pool_regrow` / `gs_slice_pool_free` (stdlib
  `slice_pool` / `alloc_slice` family) and `gs_spans_alloc` / `gs_spans_regrow` /
  `gs_spans_free` (`reusable` pool freelist builtins). These are the "core allocator
  paths" a runtime counter can hook.
- Stack stores (`u8[..N]`, large structs like `DecodedH2HeaderList` ~277 KB) are fixed
  data-stack reservations; they remain static-analysis territory
  (`scripts/lint_invariants.py`, `goose-lit crap` bounds radar).

### Deliverables

| File | Role |
| :--- | :--- |
| `tests/lit/alloc_count.c` | C shim: event/byte/free counters, enable flag, counting forwarders (`wing_ac_*`) over the six runtime allocator primitives, and a data-stack growth watermark probe (`wing_alloc_mark` / `wing_alloc_growth`) that reads `gs_stack.top` through the `gs_rref` builder contract (`goose.h`). |
| `tests/lit/alloc_hook.h` | Compile-time interposition: macro-renames the six runtime primitives to the counting forwarders. Splice with `--include` on instrumented builds only. |
| `tests/lit/alloc_kit.goose` | Goose bindings (`namespace alloc_kit`), same pattern as `server/profiler.goose`. |
| `tests/lit/verify_alloc_counter.goose` | LIT self-test and zero-alloc demonstration. |
| `tests/lit/verify_alloc_counter.build` | Program sidecar linking `alloc_count.c` (Goose `docs/packages.md` section 3; no production build files touched). |

### Counter channels and their coverage

1. **Interposed span events (complete for runtime allocator calls).** With
   `alloc_hook.h` spliced in, every `gs_slice_pool_*` / `gs_spans_*` call in the
   generated program - including calls from non-cooperating code such as stdlib
   `slice_pool` - routes through the counting forwarders. The self-test proves this:
   `pool.alloc_slice` / `pool.free_slice` (stdlib, never calls the counter directly)
   are observed (`ALLOC_POOL_INTERPOSE: OK`).
2. **Data-stack growth watermark.** `alloc_mark(probe)` snapshots the bump watermark of
   the data stack owning `probe`; `alloc_growth(probe, mark)` reports surviving
   growable-array growth in bytes. Scratch that rewinds with its scope nets zero and is
   not counted at runtime (see limitations).
3. **Explicit taps.** `alloc_note(bytes)` counts harness-instrumented allocation sites
   (e.g. future tiny production hooks at `OverflowArena` spills or body appends).

### Zero-overhead when disabled

- Production builds do not splice `alloc_hook.h`: the generated C calls the runtime
  primitives directly. The shim object is inert (never called), same as
  `shim/profiler.c` today.
- Instrumented builds gate counting on the enabled flag (`alloc_reset` enables,
  `alloc_disable` stops counting); disabled counting is one predictable branch inside
  the shim, which is the documented counter exception.

### Demonstrated zero-alloc verification

`ZERO_ALLOC_HOT_PATHS: OK`: 1000 iterations of `core::fast_find_crlfcrlf`,
`internal::parse_frame_header`, `internal::decode_hpack_header_block` (RFC 7541
Appendix A block), and `internal::encode_hpack_field` (literal + Huffman) ran with
zero interposed allocation events and zero watermark growth.

### Limitations (documented, not hidden)

- Inline bump churn of `u8[>..]` scratch that dies inside the measured call (grown and
  rewound without a runtime call) is not runtime-observable without compiler
  instrumentation. Static analysis (`scripts/lint_invariants.py` heap-in-loop and
  `u8[>..]` rules, `goose-lit crap` bounds radar) covers that category.
- Watermark probing observes the stack that owns the passed probe buffer; growth on
  other data stacks of the same thread program is only visible if it survives and the
  test holds a probe on that stack.
- `wing_alloc_growth` is net-of-region: surviving growth and scratch churn that never
  rewinds are both counted; purely transient churn is not.

### How to run

```bash
# Self-test + zero-alloc demonstration (build splices the interposition header):
goose-lit tests/lit/verify_alloc_counter.goose

# Or manually:
goose build --cc gcc -O2 --include tests/lit/alloc_hook.h -o ac.exe tests/lit/verify_alloc_counter.goose
./ac.exe
```

To measure another test program: add `verify_alloc_counter.build`-style sidecar next to
it (`c_sources = ["alloc_count.c"];`), add `--include <dir>/alloc_hook.h` to its
`// RUN:` build line, `import alloc_kit from ".";`, then
`alloc_kit::alloc_reset()` -> run the workload -> `alloc_kit::alloc_events()` /
`alloc_growth(probe, mark)`.

## 2. HTTP/2 micro-benchmarks

`tests/lit/verify_h2_microbench.goose`, following the
`tests/lit/verify_wire_benchmarks.goose` pattern (warm-up + timed loop over
`core::monotonic_now()`, latency ceiling assert, FileCheck labels). Benchmarks:

| Benchmark | Budget ceiling | Measured (this machine, gcc -O2) |
| :--- | :--- | :--- |
| `BENCH_H2_FRAME_ROUNDTRIP` (RFC 9113 Section 4.1 header encode + parse) | 500 ns | ~5-6 ns/op |
| `BENCH_H2_HPACK_ENCODE` (literal + Huffman, no indexing, RFC 7541 Section 5) | 800 ns | ~22-36 ns/op |
| `BENCH_H2_HPACK_DECODE` (3-field static-index block, RFC 7541 Appendix A) | 3000 ns | ~580-1300 ns/op |

Notes on methodology:

- Frames/inputs feed forward across iterations (`echo_stream_byte`, `echo_value_byte`)
  and pass an extern-builder opacity barrier (`opaque_barrier`), because gcc -O2
  constant-folds and loop-invariant-hoists the pure frame codecs otherwise; the first
  draft of the bench measured 0 ns/op for that reason.
- The decode cost is dominated by the current decoder API shape: `DecodedH2Header`
  entries are 4.3 KB stack structs copied into `DecodedH2HeaderList` per field. The
  3000 ns ceiling leaves CI headroom; the printed ns/op is the comparable number
  (micro-budgets: CRLFCRLF 18 ns, TLS header 12 ns, LPM 14 ns, chunk FSM 38 ns).
- Per-op averaging uses a 4096-iteration window (`ns_per_op_4k`: shift, not divide) to
  keep every function under the G-CRAP 25 gate.

Run once:

```bash
goose-lit tests/lit/verify_h2_microbench.goose
```

## Verification performed

| Command | Result |
| :--- | :--- |
| `python tools/test_runner.py --check-only -j 2` | 100% valid (core, wing, 11 examples, 36 suites) |
| `python scripts/verify_wing_gate.py <file> --max-gcrap 25` on all three new `.goose` files | all verification checks passed |
| `python scripts/lint_invariants.py --target-file <file> --strict-examples` on all three new `.goose` files | LINT PASSED |
| `goose build --cc gcc -O2 --include tests/lit/alloc_hook.h ... && ./ac.exe` | all 4 counter checks passed |
| `goose build --cc gcc -O2 -o h2bench.exe tests/lit/verify_h2_microbench.goose && ./h2bench.exe` | all 3 budgets passed (6 / 36 / 1300 ns/op) |
| `goose format` on all new `.goose` files | clean |

## G-CRAP gate caveat

The G-CRAP formula penalizes any arithmetic op by roughly 15-30 points per op
(multiply 15, divide 30) plus a depth multiplier. Repo-accepted files do not clear a
per-function 25 ceiling: `tests/lit/verify_wire_benchmarks.goose` scores 105.1 on all
four of its bench functions and `http2/hpack.goose` scores up to 660.2
(`compact_dynamic_arena`); the enforced invariant is the `.lit/baseline` ratchet
("zero regressions"), which passes. The new files were shaped to pass the strict
per-function gate where possible: all functions in the three new `.goose` files are at
G-CRAP <= 25 (leaf arithmetic extracted into `inline fn` singles; per-op average is a
shift).

## Files touched

- `tests/lit/alloc_count.c` (new)
- `tests/lit/alloc_hook.h` (new)
- `tests/lit/alloc_kit.goose` (new)
- `tests/lit/verify_alloc_counter.goose` (new)
- `tests/lit/verify_alloc_counter.build` (new)
- `tests/lit/verify_h2_microbench.goose` (new)
- `vector-e1-report.md` (this file)

No production modules, parsers, or package build files were modified.
