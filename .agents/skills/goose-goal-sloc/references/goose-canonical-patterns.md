# Goose canonical shrink-and-speed patterns

Every pattern below is verified against `d:/GooseProjects/goose/src/` (`bce.h`,
`optimize.h`, `optimize_loops.h`, `optimize_basecase.h`, `optimize_tre.h`,
`optimize_reassoc.h`, `stdlib/base64.goose`) and cuts both SLOC and CPU cycles.

## 1. Bounds-check elimination (`bce.h`)

- **Never use plain `u64` locals as loop indices**: `bce.h` excludes plain
  `u64` variables from BCE bases. Use `for i in xs.len` (`i64`) so `ge0`,
  `lelen`, `mono`, and `ShiftCore` eliminate every check.
- **Never use `core::add_sat_*` / `sub_sat_*` on loop counters**: saturating
  helpers break BCE induction tracking and add branch/select overhead per step.
  Prove the upper bound once at entry with `guard` and use `i++` or `for i in`.
- **Use index types (`u32 in arr`, `u32 upto arr`) + `checkfree fn`**: prove
  bounds once at boundary ingress (`bench/notes.md`: 1.17-1.21x speedup, zero
  repeated `guard idx < arr.len` checks inside callees).
- **Row slices, byte LUTs, and masks**: `src[lo..lo + w]` proves inner loops;
  `u8` indexing `[256]`, `b >> 2` indexing `[64]`, Euclidean `%`, and `a &
  mask` eliminate checks with zero branches.
- **Monotone write cursor**: `w += if keep { 1 } else { 0 }` proves `w <= i`
  for branchless filtering/compaction without bounds checks.

## 2. Inlining, multi-return, and error paths (`optimize.h`)

- **Multi-return blocks Goose IR inlining**: `inline fn foo() -> T, bool` sets
  `info.noinline = true` in `optimize.h` (only C `GS_INLINE` applies), blocking
  BCE and constant propagation across the call boundary. Prefer `T?` or
  `return err from f` on hot helpers so callers drop `let v, ok = ...; guard ok
  else { ... }` (-2 to -3 SLOC per call site) and keep full IR inlining.
- **Stop spamming `inline fn`**: Goose auto-inlines single-use helpers
  (`<= 200` IR nodes) and loop helpers (`LOOPNCU = 4`, up to `480 / uses`), and
  intentionally marks cold `guard ... else` callees `GS_NOINLINE`. Excess
  `inline fn` bloats C output, hits `MAXNEST = 64`, and triggers MinGW OOM.
- **NRVO rule**: return the same single local variable on every return path so
  Goose eliminates struct copies cleanly.

## 3. Loop auto-optimizations (`optimize_loops.h`, `optimize_reassoc.h`)

- **`stripk` auto-strip-mining**: write natural `for x, i in data { lanes[i %
  K] ... }` (`K` in `2..16`) instead of manual K-way unrolled loops.
- **`sumred` 8-way float reduction**: write simple `for x in xs { acc +=
  pure(x); }` on `f32`/`f64` accumulators instead of manual 4x/8x accumulator
  unrolling (integer `for b in buf` gets BCE and C auto-vectorization).
- **Small bounded unrolling**: loops over `T[..8]` (`lenbound <= 8`) auto-unroll
  automatically; do not hand-unroll 4-element loops.
- **Countdown rewrite**: `while v > 0 { v--; ... }` auto-rewrites to optimal
  up-counting; avoid awkward manual index gymnastics.
- **Associative `min`/`max`**: use `std` `min(a, b)` and `max(a, b)` (never
  `if a < b { a } else { b }`); `optimize_reassoc.h` regroups chains off
  loop-carried critical paths and lowers `EffCC`.
- **Self-recursion (`optimize_basecase.h`, `optimize_tre.h`)**: putting the
  base case first (`if c { return e; }`) inlines the base case at call sites;
  associative integer tail recursion (`+ * & | ^`) compiles to a loop.

## 4. Vectorization and low-level idioms (`implementation.md`, `stdlib/base64.goose`)

- **Bit ops over lookup tables and bit loops**:
  - Replace `ZSTD_POW2_U64[64]` (18 SLOC + 512 B `.rodata`) with `(1 as u64) <<
    (n & 63)` (1 `shl` instruction).
  - Replace 7-line bit-scan loops (`while top >= 0 { ... }`) with `63 - clz(x)`
    (1 `lzcnt`/`bsr` instruction; `std::clz(0) == 64`, so `63 - clz(0)` returns
    `-1` without a zero-check branch).
- **Whole-array assignment and comparison**:
  - Replace 4-line zeroing loops/statements with `bf.bits = [0; 4];`.
  - Replace 4-term `&&` zero checks with `(bf.bits[0] | bf.bits[1] | bf.bits[2]
    | bf.bits[3]) == 0` (branchless in registers without `EqFn` or `[0; 4]`
    materialization) or `bf.bits == [0; 4]` for larger arrays.
- **Struct default reset (`..`)**:
  - Replace 40-76 line manual field-by-field `reset_*_slot` functions with
    `slot = Slot { active: true, gen: gen, .. };` (preserve only buffers that
    require `secure_zeroize_slice` before reset).
- **Compile-time enum reflection (`const for`)**:
  - Replace 64-arm sequential `match id { A => 0, B => 1, ... }` functions with
    `const for <N, V> in variants<E>` (collapses to a single register move
    under `-O2`, -60 SLOC).
  - Replace enum-to-variant-name `match` blocks and string LUTs with `match val
    { const for <N, V> in variants<E> { V => N, } }` (`typecheck_expansion.h`
    expands `const for` directly inside `match` arms into a C `switch`).
  - Never duplicate enum-to-name `match` tables when a `const` name LUT array
    already exists; index the LUT by slot id.
- **Branchless SIMD (`simd fn`, `Speculatable &&/||`, `HoistDivisors`)**:
  - Use `simd fn` for hot byte kernels with wrapping range checks
    (`c - 'a' < 26`) and accumulated error flags (`bad |= ...`, no early
    `return`/`break` inside the inner loop) so `&&`/`||` stay `Speculatable`
    and avoid slow SIMD gathers (`stdlib/base64.goose`: ~80 SLOC, 4-6x faster).
  - Prefer `u32` loop-invariant `/` and `%` over signed `i64` (`HoistDivisors`
    converts unsigned division to vectorized libdivide multiplies, 4-7x faster).
  - Keep distinct `T[>..]&` pools as direct parameters (`RefTopsOk` caches
    stack top/len in registers) and iterate structs by reference (`for &x in
    xs`) to eliminate copies.
