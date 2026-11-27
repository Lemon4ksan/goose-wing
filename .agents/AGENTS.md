# Agent rules: workflow, static invariants, and geometry (Part 2 of 2)

This file (`.agents/AGENTS.md`) and root [`AGENTS.md`](file:///AGENTS.md) form
the two-part rulebook for `goose-wing`. Both are loaded into `<user_rules>`;
keep each under 13.5 KB so neither is truncated. See
[`AGENTS.md`](file:///AGENTS.md) for Part 1 (module map, canonical `core::` and
UFCS primitives catalog, Goose memory model, and compiler idioms).

## Commit conventions and releases

Releases are automated via Google's `release-please` workflow on `main`.

- Follow Conventional Commits (`feat:`, `fix:`, `refactor:`, `perf:`, `style:`,
  `test:`, `chore:`).
- Mark breaking changes with `!` (`feat!: ...`, `refactor(client)!: ...`) or a
  `BREAKING CHANGE:` footer.
- Do not bump `version.txt` or `CHANGELOG.md` by hand during feature branches.

## Continuous integration, testing, and `goose-lit`

- **CI policy**: Test suites in `.github/workflows/ci.yml` run on
  `pull_request`. Docker suites (`tools/grpc.py`, `tools/tls.py`,
  `tools/http3.py`, `tools/toxiproxy.py`) run when `**/*.goose` files change.
- **Local verification (Zero unverified assertions)**: Always run verification
  commands and observe exit code `0` before claiming completion:
  ```bash
  python tools/test_runner.py --check-only   # or: just check
  goose format --check .                     # or: just fmt-check
  python scripts/verify_wing_gate.py "<path/to/file.goose>" --max-gcrap 25
  goose-lit gate auth/jwks.goose 25
  goose-lit crap http/headers.goose --threshold 25.0
  goose-lit tests/lit/verify_wire_framing.goose
  python scripts/test_lit.py                 # or: just lit
  ```
- **LIT test directives**: `// RUN: goose %s | %FileCheck %s`,
  `// RUN: goose check %s`, `// CHECK:`, `// CHECK-NEXT:`, `// CHECK-NOT:`.

## Pragmatic systems engineering principles

- **Boundary discipline (parse once at boundary)**: Validate raw wire bytes
  into typed, bounded structures immediately at ingress. Internal state
  machines trust validated types without redundant checks.
- **Minimal diffs**: Implement the smallest self-contained change that solves
  the issue. Do not refactor adjacent modules unless required.
- **Specification-first testing**: Test wire-level conformance against RFC
  vectors rather than private helpers or mock harnesses.
- **Idempotent lifecycle operations**: Connection teardowns, socket closures,
  FSM resets, and timer cancellations must be safe when repeated or called
  after mid-flight errors.
- **Prohibited anti-patterns**: Never split performance-critical FSMs, SWAR
  loops, or protocol decoders into artificial micro-functions just to game
  cyclomatic complexity metrics. If a cohesive function causes a legitimate
  G-CRAP ratchet delta, update `.lit/baseline` rather than bloating the module.

## Strict code clarity and anti-bloat invariants (Rules 1-19)

Enforced statically via [`scripts/lint_invariants.py`](file:///scripts/lint_invariants.py)
and [`.githooks/pre-commit`](file:///.githooks/pre-commit):

1. **Zero meaningless function or type aliases (No pass-through wrappers)**:
   - **No pass-through function aliases**: Never declare `fn foo(a, b) { return bar(a, b); }`
     forwarding identical arguments without adding validation, constants, or
     state transitions.
   - **No primitive or slice `type` aliases**: Never hide memory layout behind
     `type ByteSlice = u8[:]` or `type UserId = u64`. Write `const u8[:]`,
     `u8[..256]`, `u64` directly at every call site.
   - **No `import ... as ...` namespace renaming**: Use canonical module names.
   - **No local variable re-aliasing**: Do not chain synonymous locals
     (`let a = buf.len; let n = a;`).
   - **No redundant 0-arg struct constructor wrappers**: Never declare
     `fn new_foo() -> Foo { return Foo { .. }; }`. Instantiate `Foo { .. }`
     directly at call sites.
   - **No trivial single-line struct field getters, setters, or raw arithmetic
     wrappers (Anti G-CRAP gaming)**: Never write 1-line getters (`return x.f;`),
     setters (`claims.exp = v;`), or mechanical arithmetic helpers (`val + 1`)
     to artificially lower G-CRAP. Access and mutate fields directly at call
     sites. *Exception*: 1-line functions encapsulating reusable domain rules
     or bitmasks (`is_supported_digest_algo`, `calc_amplification_limit`) are
     encouraged.
   - **Zero dead code**: Every function in production source files must be
     called by protocol engines, dispatchers, or test suites.
   - **Domain-named leaf primitives**: Name arithmetic helpers after the
     protocol domain rule (`calc_amplification_limit`), never after raw
     operators (`add_one`, `mul_by_three`).
2. **Input/output examples (`// Example:`) on wire parsers and transformers**:
   - **Compulsory archetypes**:
     - *Cursor mutators*: Functions advancing an in-out cursor (`idx: i64&`,
       `pos: i64&`, `offset: u64&`, `cursor: i64&`).
     - *Stream/slice-consuming parsers*: Functions returning consumed byte
       length or slices (`-> (i64|u64|i32), bool` or `-> const u8[:], bool`).
     - *Prefix-assumption parsers*: Routines assuming a leading delimiter (`"`
       or `[`).
     - *RFC grammar parsers and decoders*: Functions named `parse_*`,
       `decode_*`, `extract_*`, or `scan_*`.
     - *Wire bitmask builders and transformers*: Functions named
       `build_*_type`, `pack_*`, `unpack_*`, `escape_*`, `unescape_*`, or
       `sanitize_*`.
   - **Required contract format**:
     ```goose
     // Extracts a parameter key up to '=', space, or tab (RFC 7616 Section 3.4).
     // Advances `idx` to the delimiter without consuming it.
     //
     // Example:
     //   raw = "realm=\"api\", nonce=\"xyz\"", idx = 0
     //   returns: "realm", ok = true, idx = 5 (points to '=')
     ```
   - **Omit on trivial functions**: Do not add `// Example:` to getters,
     setters, constructors, state resets, 1-line predicates, or I/O handlers.
3. **No boolean trap signatures**:
   - Never declare functions with consecutive `bool` parameters
     (`fn configure(a: bool, b: bool)`). Use `enum` types or config structs.
4. **Zero dynamic allocation in hot loops**:
   - Never declare `var buf: u8[>..] = []` inside `for` or `while` loops. Use
     stack-bounded `u8[..N]` or hoist and `.clear()` a single reusable buffer.
5. **Transactional cursor contract on error**:
   - Functions taking `idx: i64&` and returning `(..., bool)` must document or
     guarantee whether `idx` is unchanged on `false` or stops at the bad byte.
6. **Named RFC constants over magic numbers**:
   - Define wire frame types (`0x08`), close codes (`1002`), and bitmasks as
     module-level `const` declarations citing the RFC section.
7. **Silence on the obvious and zero placeholder code**:
   - Never write comments restating the function name (`// Parses header`),
     `// Does not panic`, `TODO`, `FIXME`, `HACK`, or `simplified for now`.
8. **Linear Git commit history**:
   - Merge commits (`git merge` without `--ff-only`) are blocked by pre-commit.
9. **Value returns over intermediate out-parameters**:
   - Functions computing hashes, digests, token slices, or single-result
     transformations must return values directly (`-> u8[..64]`, `-> u8[32]`,
     `-> (T, bool)`) via RVO/sret, never C-style `out_hex: u8[..64]&`.
     Out-parameters (`out: B&`) are reserved for cumulative streaming sinks.
10. **Byte slice (`const u8[:]`) as lingua franca vs `core::ByteCursor`**:
    - HTTP, header, URL, and text tokenizers (`parse_*`, `decode_*`, `demux_*`)
      must accept `const u8[:]` (and `idx: i64&`), never custom `SliceReader`
      or `ByteCursor` wrappers.
    - Binary length-prefixed protocols (`tls/*`, `quic/frames.goose`,
      `core/io/*`) must use `core::ByteCursor` and `core::ByteBuilder` instead
      of manual multi-shift index arithmetic.
11. **Constant-time cryptographic comparisons and secret zeroization**:
    - Always compare MACs, digests, HMACs, and auth tags with
      `core::ct_eq_bytes` (`ct_eq_tag16`, `ct_eq_tag32`), never `==` or `!=`.
    - Wipe stack keys, PRKs, nonces, and seeds with
      `core::secure_zeroize_16/32/64` before return (including early errors).
12. **Zero dynamic vectors (`u8[>..]`) in wire frame structs**:
    - `*Frame`, `*Packet`, and `*WireHeader` structs must use `const u8[:]`
      slices or bounded `u8[..N]` arrays, never `u8[>..]`.
13. **Zero silent buffer drops (Strict capacity overflow propagation)**:
    - Never write `if buf.len < buf.cap { buf.push(x); }` without an `else`
      error branch. Use `guard buf.try_push(x) else { return ..., false; }` or
      `guard buf.try_append(s) else { return ..., false; }`.
14. **Prohibition of naive substring searching on structured wire formats**:
    - Never use `find`, `contains`, or `index_of_slice` to extract fields from
      JSON, JWTs, HTTP headers, URLs, or cookies. Use `json::Reader`,
      `core::read_json_string_into`, `core::parse_url`, and `HeaderMap`.
15. **Zero fallback to valid enum variants in parsers**:
    - String-to-enum parsers (`parse_*`, `str_to_*`) must return `(Enum, bool)`
      or an explicit `Enum.Unknown` / `Enum.Invalid` variant, never defaulting
      unrecognized input to an operational variant.
16. **Stateful entropy in PRNG and ID generators**:
    - Never initialize a constant seed (`var state: u64 = 0x...`) inside a
      nonce, JTI, or ID generator. Accept `rng: WyRand&` or mix `clock_ns()`.
17. **Enterprise-scale buffer capacities**:
    - Size JWT, Bearer, DPoP, and OAuth token buffers to `>= 2048..4096` bytes
      (`MAX_AUTH_TOKEN_LEN: u64 = 4096`), never `< 1024` bytes.
18. **Transactional out-buffer hygiene (Zero dirty state on error)**:
    - Functions taking `out: B&` and returning `bool` must validate all
      preconditions before mutating `out`, or call `out.clear()` /
      `out.resize(mark)` on every failure path (`return false`).
19. **`HeaderMap` Bloom filter synchronization**:
    - Never call `req.headers.push(...)` directly without updating
      `bloom_filter` or routing through `add_header` / `append_header`.

## Protocol specification fidelity and RFC citation contract

1. **RFC Appendix vector conformance & negative fuzzing**:
   - Verify intermediate cryptographic values and wire frames byte-for-byte
     against RFC Appendix vectors.
   - Include negative tests for oversize inputs (`len > cap`), unknown enum
     variants, escaped quotes (`\"`), CRLF injection, and OWS variations.
2. **Canonical RFC citation comment format**:
   - Verified by [`scripts/audit_rfc_citations.py`](file:///scripts/audit_rfc_citations.py)
     against `.agents/rfc/rfc<NUM>.txt`. Cite current RFCs (RFC 9110/9112/9113/
     9114 over obsolete RFC 2616/7230) using this exact format:
     ```goose
     // RFC <NUM> Section <X.Y>: <VERBATIM_SECTION_TITLE> - <SPECIFIC_REQUIREMENT>
     ```
   - `<VERBATIM_SECTION_TITLE>` must match the official heading in
     `rfc<NUM>.txt` character-for-character. Never guess section numbers.

## Code formatting, geometry, and G-CRAP harmony

Enforced by `goose format --check .`, `scripts/lint_invariants.py`, and
`goose-lit gate <file> 25` ($\text{G-CRAP} \le 25.0$, $\text{EffCC} \le 15$):

1. **Line length (Soft 100 / Hard 120 columns)**:
   - Target 100 columns; hard limit is **120 columns** (excluding RFC test
     vectors, URLs, and `// CHECK:` lines).
   - Functions with $\ge 5$ parameters exceeding 100 columns must place each
     parameter on its own 4-space indented line with a trailing comma `,`.
2. **Whitespace and vertical rhythm**:
   - Strictly **4 spaces** per indent level (no tabs, no trailing spaces).
   - No consecutive blank lines (`\n\n\n`) and no blank lines immediately after
     `{` or before `}`.
3. **Nesting depth ceiling ($\le 3$ levels inside a function)**:
   - Control-flow nesting (`for`/`while`/`if`/`match`) must not exceed **3
     levels** (16 spaces from column 0; $\ge 20$ spaces is rejected).
   - Invert preconditions into top-level `guard cond else { return ...; }`
     statements so the main path stays at indent level 1 (4 spaces).
4. **Adaptive function length**:
   - **Loop functions (`while` / `for`)**: Maximum **65 lines**. Extract inner
     loop steps into domain-named `inline fn` helpers when needed.
   - **Flat dispatch tables / classifiers (depth $\le 2$, no loops)**: Up to
     **100 lines**. Do not split flat `match` tables into `part1`/`part2`.

## Documentation, `goosemarklint`, and communication style

- **File naming**: `docs/*.md` files use `snake_case`; root meta-files and
  per-module `README.md` files use `UPPERCASE`.
- **80-column Markdown and `goosemarklint`**:
  - Hard-wrap prose, blockquotes, and list items at **80 columns** (tables,
    code blocks, headings, and long links exempt).
  - Run `just md-fmt` and `just md-lint` after editing `.md` files.
- **Communication & anti-AI tone**:
  - Start directly with the technical answer; never use sycophantic openers or
    closing platitudes.
  - Do not use AI buzzwords (`crucial`, `robust`, `comprehensive`,
    `seamlessly`, `vital`, `testament`, `delve`, `meticulously`, `pivotal`,
    `game-changer`, `plethora`, `tapestry`, `leverage`).
  - Use sentence case for headings, straight quotes (`'` and `"`), and hyphens
    or parentheses instead of em dashes in prose.
  - Link all files and symbols with clickable `file:///` markdown links.
