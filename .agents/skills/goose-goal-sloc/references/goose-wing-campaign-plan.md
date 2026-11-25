# `goose-wing` simplification campaign plan

Baseline captured via `just sloc-save-profile` (433 shipping files, 163,690
SLOC, 116,137 stmts, Pack 0.71, 1,853 local compiler smells, 9 RDTSC scopes).

## Commands

- Static check (< 0.5s): `just sloc-ratchet`
- Full smell breakdown: `just sloc`
- Live RDTSC Pareto check: `just sloc-profile`
- Save static baseline (preserves RDTSC cycles): `just sloc-save`
- Save full baseline with live RDTSC: `just sloc-save-profile`

## Waves

1. **Wave 0 (benchmark coverage)**: convert remaining `bench/*.goose` files
   (codecs, TLS, QUIC, HTTP/2, HTTP/3, URL, auth) to `lit::bench` and add rows
   to `.lit/sloc-map` with 4th column `bench_file` so every major subsystem has
   RDTSC Pareto protection before deep rewrites.
2. **Wave 1 (high-leverage structural bloat & enum/reset collapse)**:
   - `http/headers.goose` (1,897 SLOC) + `http/headers/wire_internal.goose`:
     collapse 64-arm `well_known_to_slot` + duplicate `well_known_header_name`
     (-124 SLOC), `HeaderBloomFilter` (`[0; 4]`), 13 + 12 compiler smells.
   - `grpc/constants.goose`: collapse three 18-arm status `match` blocks via
     `const for` + LUT (-50 SLOC).
   - Manual 40-76 line `reset_*_slot` functions in `quic/server_endpoint.goose`,
     `http3/server_session.goose`, `proxy/h2_upstream.goose`, and
     `server/h2_mux_types_internal.goose` -> struct default resets (`..`).
   - Collapsible 3-line `guard ... else` blocks (479 instances, ~958 SLOC) and
     redundant `new_*()` / 1-line pass-through wrappers (111 `new_*`, 278 short
     wrappers, respecting public API stability).
3. **Wave 2 (codec mega-files & top smell clusters)**:
   - `core/compress/zstd.goose` (3,631 SLOC, 29 smells): delete `ZSTD_POW2_U64`,
     use `zstd_high_bit` (`clz`), unify fast/generic decode paths, remove `u64`
     loop counters and `*_sat_*` in loops.
   - `core/compress/deflate.goose` (2,742 SLOC, 70 smells - #1 in repo):
     delete custom `comp_try_*` duplicating `core` UFCS, unify twin
     `step_lz77_nodict`/`step_lz77_dict`, clean 63 `sat_loop` smells.
   - `core/compress/brotli.goose` (2,178 SLOC, 26 smells),
     `core/url/idna.goose` (54 smells), `http/sfv_sig_internal.goose` (35
     smells), `h1/wire.goose` (30 smells), `core/url/ip.goose` (28 smells).
4. **Wave 3 (protocol session mega-files)**:
   - `quic/server_endpoint.goose` (2,903 SLOC, 43 smells),
     `http3/server_session.goose` (2,440 SLOC, 25 smells),
     `proxy/h2_upstream.goose` (1,820 SLOC, 21 smells),
     `net/goose_io.goose` (1,660 SLOC, 20 smells),
     `http2/server_session.goose` (1,566 SLOC, 21 smells).
5. **Wave 4 (SIMD hot kernels & floor report)**:
   - Vectorize `HOT_KERNEL` loops with `simd fn` / `stripk` / `sumred`, lock
     `.lit/sloc-baseline` at each wave exit, and document irreducible data floor
     (RFC 7541 Huffman tables, Brotli dictionary, crypto S-boxes, C shims).

## Wave exit gate (no shortcuts)

Every wave passes all five before saving `.lit/sloc-baseline`:

1. `goose format --check .`
2. `python scripts/lint_invariants.py --strict-examples`
3. `just check` and relevant `goose-lit` test suites
4. `just sloc-ratchet` (SLOC down, smells down, 0 packing violations)
5. `just sloc-profile` (`PARETO_WIN` or `UNCHANGED` on all mapped scopes)
