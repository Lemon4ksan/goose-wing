# Agent rules

Guidelines and invariants for agents working in the `goose-wing` repository.

## Commit conventions and releases

Releases are automated via Google's `release-please` workflow on `main`.

- Follow the Conventional Commits specification for all commit messages:
  - `feat:` for new capabilities.
  - `fix:` for bug fixes.
  - `refactor:` for code restructuring without behavioral changes.
  - `perf:` for performance optimizations.
  - `style:` for formatting or whitespace changes.
  - `test:` for adding or adjusting test suites.
  - `chore:` for toolchain, workflow, or build adjustments.
- **Breaking changes**:
  - `release-please` detects breaking changes purely from commit metadata.
  - Mark breaking changes with an exclamation mark after type or scope:
    ```git
    feat!: change signature of new_session
    refactor(client)!: drop deprecated transport options
    ```
  - Or include a dedicated footer in the commit body:
    ```git
    BREAKING CHANGE: HeaderMap.get now returns a Result instead of an Option.
    ```
- Version tracking resides in `version.txt`. Do not bump `version.txt` by hand during feature branches; let `release-please` manage version bumps and `CHANGELOG.md` updates through its Release PR.

## Continuous integration and testing

- **Trigger policy**:
  - Test suites in `.github/workflows/ci.yml` run only on pull requests (`pull_request`), not on direct pushes to `main`.
  - On `push` to `main`, only the `release-please` workflow executes.
- **Path filtering**:
  - Docker-based protocol suites (`tools/grpc.py`, `tools/tls.py`, `tools/http3.py`, `tools/toxiproxy.py`) are gated by `dorny/paths-filter`.
  - These suites only run in a PR if `.goose` files (`**/*.goose`) have been modified.
- **Local verification**:
  - Always run the full typecheck validation before opening a PR or finalizing a commit:
    ```bash
    python tools/test_runner.py --check-only
    # or: just check
    ```
  - Core libraries (`core.goose`, `wing.goose`) and all test suites must pass without errors or warnings.
  - **Zero unverified assertions (Empirical evidence over declarations)**: Never declare that code
    compiles, passes tests, or satisfies invariants without having executed the corresponding command
    in the session and observing exit code 0.
- **Hardware enforcement gate (`goose-lit`)**:
  - Every modified or refactored `.goose` file must pass the hardware complexity gate before finalizing changes:
    ```bash
    python scripts/verify_wing_gate.py "<path/to/file.goose>" --max-gcrap 25
    # or: just gate "<path/to/file.goose>" 25
    ```
  - Pass `--lit-script "<path/to/test.goose>"` and `--test-suite "<path/to/test.goose>"` to combine static complexity gating with native LIT assertions and unit tests in a single run.
  - If the script exits with code 1 (`GATE REJECTED`), functions must be flattened with `guard` clauses, bounds checks proved, and cyclomatic depth reduced until all functions pass.

## Goose LIT and native wire verification workflow

Use `goose-lit` (available in PATH) to run LLVM-style `// RUN:` test directives, FileCheck output matching, and static G-CRAP complexity analysis without Wasm virtualization:

```bash
# Execute a single native LIT test suite
goose-lit tests/lit/verify_wire_framing.goose

# Run all native LIT verification suites in parallel
python scripts/test_lit.py
# or: just lit

# Hardware complexity gate analysis
goose-lit gate auth/jwks.goose 25 --cov 0.85

# Risk radar table output
goose-lit crap http/headers.goose --threshold 25.0
```

### Goose LIT CLI commands and options

| Subcommand / Option | Arguments | Purpose in `goose-wing` workflows |
| :--- | :--- | :--- |
| `<path>` | `<file.goose\|dir>` | Discovers and executes all `// RUN:` directives under target. |
| `filecheck` | `<file.goose>` | Verifies standard input against `// CHECK:` patterns in target file. |
| `gate` | `<path> [ceiling]` | Enforces G-CRAP risk gate ceiling (default 25.0, exits with 1 on violation). |
| `crap` | `<path>` | Runs static G-CRAP complexity and bounds risk analysis radar. |
| `inspect` | `<file\|hex>` | Dumps byte buffers in hex/ASCII or 128-bit SIMD lanes (`--simd`). |
| `--prefix` | `<PREFIX>` | Configures FileCheck pattern prefix (default `CHECK`). |
| `--cov` | `<0.0..1.0>` | Sets simulated branch coverage for crap and gate analysis (default 0.85). |
| `--threshold` | `<val>` | Sets G-CRAP warning threshold for radar reporting (default 25.0). |
| `--format` | `table\|md\|json` | Sets output format for report formatting. |

### LIT test directives and FileCheck patterns

| Directive | Purpose in test files (`tests/lit/*.goose`) |
| :--- | :--- |
| `// RUN: goose %s \| %FileCheck %s` | Compiles and executes test via native Goose and pipes stdout to FileCheck. |
| `// RUN: goose check %s` | Typechecks test file statically. |
| `// CHECK: <pattern>` | Asserts that `<pattern>` appears in output stream. |
| `// CHECK-NEXT: <pattern>` | Asserts that `<pattern>` appears on the immediate next line. |
| `// CHECK-NOT: <pattern>` | Asserts that `<pattern>` does not appear before next match. |

## Pragmatic systems engineering principles

Adapted engineering invariants to preserve zero-allocation networking performance:

- **Boundary discipline (parse once at boundary)**:
  - Validate and parse raw network wire bytes into typed, bounded structures immediately upon ingress (L4 driver, TLS record layer, HTTP framer).
  - Internal routines and hot-path state machines must trust validated types without redundant defensive assertions.
  - Keep domain protocol logic in pure, deterministic functions without side effects where possible.
- **Minimal diffs and laziness**:
  - Implement the smallest self-contained change that solves the issue.
  - Do not refactor adjacent code or reorganize modules unless directly required by the task.
  - If code is already clear, local, and performs without dynamic allocations, leave it alone.
- **Specification-first testing**:
  - Test protocol behavior and wire-level conformance against RFC vectors and specifications, not internal private helper implementations.
  - Write failing behavioral test vectors before fixing protocol bugs when reproducible.
  - Do not introduce mock harnesses that obscure real transport dynamics.
- **Idempotent lifecycle operations**:
  - Connection teardowns, socket closures, FSM resets, and timer cancellations must produce identical safe states whether called once, repeated, or executed after a mid-flight failure.
- **Prohibited anti-patterns**:
  - Never split performance-critical FSMs, SWAR loops, or protocol decoders into micro-functions solely to satisfy arbitrary cyclomatic complexity metrics. Locality and compiler inlining take priority over shallow function counts.
  - Avoid premature deduplication (DRY) across independent protocol boundaries where structural similarities exist but specifications differ.
  - Never initiate a radical rewrite of working subsystems from first principles without explicit user instruction.

## Goose language rules

- **Data-stack memory model and size classes**:
  - Goose has no heap allocator, no garbage collector, no reference counting, no destructors (RAII), and no lifetime annotations. Memory consists of the native call stack, static data, and a fixed compile-time count of **data stacks** (virtual-memory reservations with bump pointers that pop en masse on scope exit).
  - Every type belongs to one of three size classes:
    - **Fixed** (compile-time size): scalars, `T[k]`, `T[..k]`, structs of fixed fields, references (`T&`), slices (`T[:]`), fixed-mode enums (`Shape`). Allowed anywhere.
    - **Variable** (construction-time size, then frozen): `T[]`, `T[varint]`, `T[..]`, variable-mode enums (`Shape..`). Allowed in locals, globals, parameters, results, and any struct field position; arrays of variable-size elements (`u8[][>..]`, `Shape..[>..]`) are **sequential** (iterable only, not indexable; keep a side array `(T&)[>..]` for random access).
    - **Resizable** (growable on a data stack): `T[>..]` (grow-only; references into it remain valid across pushes because it sits at the top of its data stack and never reallocates/moves) and `T[>..<]` (grow-shrink; references into it may live only in local variables, never in storage). At most one resizable value is live per data stack, and an ordinary struct may contain at most one resizable field as its **final field**.
  - **Root owners (`root struct`)**: When a container needs multiple independently growing fields (such as `slot_pool<T>` and `slice_pool<T>`), declare it as a `root struct`. A root owner may only be declared as a local or global variable (never as a field, array element, or return value) and is passed by reference (`Pool&`).
- **References, inferred roots, and copy semantics**:
  - References (`T&`) and nullable references (`T?`, narrowed via `if x`, `guard x`, `while x`, or `assert(x)`) are transparent (no `*` or `->`). Use `.=` to bind or retarget a reference (`let r .= xs[0]; r .= xs[1];`) and `.==` / `.!=` to compare reference identity.
  - Every reference and slice carries a static **root** (the variable owning its target) and may not outlive it. Liveness is tracked to the **last use** of the view, not the end of its lexical block.
  - **Fixed-size values copy implicitly** on `=` and in `for x in xs`. To mutate fixed-size array elements in place or take a slice that outlives a loop iteration (such as a `dictionary<const u8[:], V>` key viewing an inline `u8[..k]` field), iterate by reference: `for &x in xs`.
  - **Non-fixed values never copy implicitly**: `var b = a;` on a `T[>..]` binds `b` by reference to `a`. Write `copy(a)` for an explicit $O(n)$ copy.
  - **Relative references**: `T&<u32>` stores a position-independent 4-byte self-relative offset within the same enclosing array (enabling zero-copy `to_bytes` / `from_bytes` serialization); `T&<u32 in pool>` stores an offset relative to a global array. Self-relative nodes cannot be copied—construct them in place via `push` or `alloc_with() { ... self ... }` and bind with `.=`.
- **Arithmetic, casts, and control-flow semantics**:
  - Arithmetic runs at the operands' width with no implicit cross-width promotion (`u8 + u8` is `u8`; `u32 + i32` is a type error).
  - Unsigned overflow wraps in all builds. **Signed overflow aborts in `--debug` builds and wraps in release builds.**
  - **`%` is Euclidean** (`-7 % 3 == 2`, always in `[0, |b|)`). Integer `/` truncates toward zero; `std` provides `rem(a, b)` (truncating remainder) and `div_euclid(a, b)`.
  - Narrowing and sign changes require `as` (range-checked in `--debug`, wraps/truncates in release) or `as!` (unchecked).
  - Statement-form `defer cleanup();` runs at every lexical block exit (latest-first), including `return`, `break`, `continue`, and `return E from f`, but does **not** run on `abort`, `exit`, or failed runtime checks.
  - `checkfree fn` does not disable bounds checks; it makes any bounds check that the compiler cannot statically eliminate via Bounds Check Elimination (BCE) a **compile error** (inspect with `goose check --stats` or `--bce-lines`).
  - Threads (`thread_fn`) share no memory: each worker has its own data stacks and its own copies of globals, communicating flat values (no references or slices) over typed queues (`qput`, `qget<T>`, `qpoll<T>`) and requiring `goose build`.
- **Extern declarations (Goose §7.10)**:
  - Write extern symbol names after the signature:
    ```goose
    extern fn native_fast_u64toa(val: u64, dst: u8[:]) -> i32 = "wing_fast_u64toa";
    extern fn native_tcp_cleanup() = "wing_tcp_cleanup";
    ```
  - Never use the deprecated prefix syntax `extern "symbol" fn`.
- **Formatting**:
  - Run `goose format` on any modified `.goose` files before committing:
    ```bash
    goose format <file.goose|dir...>
    ```
  - Check formatting compliance with:
    ```bash
    goose format --check .
    ```
- **Hot path performance**:
  - Maintain zero dynamic memory allocation on wire parsing and serialization paths.
  - Use bounded inline buffers, slices (`u8[:]`), SWAR word scanners, and SIMD primitives.
- **Goose language hallucination traps**:
  - **Zero integer literal type suffixes**: Goose does not support type suffixes on literals (`1u64`,
    `0xFFu32`, `0i64` fail to parse). Write bare numbers (`1`, `0xFF`) or cast explicitly when required:
    `(0xFF as u64)`. Hex literals in `0x8000000000000000..0xFFFFFFFFFFFFFFFF` receive type `u64`; cast
    explicitly `(lit as! i64)` if assigning to `i64`.
  - **Zero heap allocators or object graphs**: Goose has no `malloc`, `free`, `new`, `make`, `Box`, `Vec`,
    `String`, `HashMap`, `Option`, or `Result`. Never invent heap allocation calls. Memory lives on the stack
    or compiler-sized data stacks (`slot_pool<T>`, `slice_pool<T>`, or `reusable var pool: T[>..] = []`).
  - **Zero OOP traits, interfaces, or virtual dispatch**: Goose has no `trait`, `impl`, `interface`,
    virtual methods, closures stored in structs, or dynamic dispatch. Dynamic polymorphism is algebraic
    (`enum` + `match` or exhaustive variant case functions `fn area(s: Shape.Circle)`).
  - **Zero imaginary standard library imports**: Goose standard library is compact (`std`, `dictionary`,
    `slot_pool`, `slice_pool`, `vec`, `math`, `os`, `ffi`, `binary`, `base64`, `csv`, `json`, `regex`,
    `exception`). Never import Go (`strings`, `bytes`, `io`), Rust (`std::collections`, `anyhow`), or
    nonexistent packages.
  - **Zero dynamic arrays (`u8[>..]`) in mid-struct definitions**: Struct fields of growable array type
    (`u8[>..]`) may only appear as the final field of an ordinary struct, never followed by other fields.
    Prefer bounded arrays (`u8[..N]`), or `root struct` when multiple growable pools are required at top level.
  - **Zero `usize` or `isize` types (No pointer-sized integer keywords)**: Goose does not have `usize`
    or `isize` (attempting `let x: usize` produces `unknown type: usize`; casting `x as usize` fails with
    `as can only convert between numeric types, not to usize`). Slice and buffer `.len` is strictly `i64`,
    and indexing uses `i64` or `u64`. Always use canonical fixed-width types: `u64`, `i64`, `u32`, `i32`.
  - **Built-in `min(a, b)`, `max(a, b)`, and UFCS `.try_set(src)`**: Goose provides built-in `min` and
    `max` in `std`. Never write ternary clamping (`if x > 96 { 96 } else { x }`); write `min(x, 96)` or
    `max(0, x)` directly (which also avoids adding branch nodes to `EffCC` / `G-CRAP`). Similarly, use
    `dst.try_set(src)` from `core/ufcs.goose` instead of repeating `guard src.len <= dst.cap ... dst.clear(); dst.append(src);`.
  - **Canonical `core` character classes, unquoted scanners, and URI normalizers**: Never re-declare
    per-module lookup tables (`PKCE_UNRESERVED_LUT`, `is_cookie_token_char`, `is_dpop_token_char`, `is_sf_tchar`),
    ad-hoc quote-aware delimiter loops (`find_altsvc_entry_end`, `find_forwarded_param_end`), or private
    Base64/UTF-8 decoders. Use canonical `core` primitives (`core::is_tchar`, `core::is_uri_unreserved`,
    `core::is_ascii_vchar`, `core::is_ascii_printable`, `core::is_ascii_hexdigit`, `find_unquoted_byte`,
    `split_once_unquoted_byte`, `core::normalize_http_target_uri`, `core::base64_decode`, `core::validate_utf8`).

## Strict code clarity and anti-bloat invariants

Enforced statically via `scripts/lint_invariants.py` and `.githooks/pre-commit`:

1. **Zero meaningless function aliases (No pass-through wrappers)**:
   - **No pass-through function aliases**: Never declare a function `fn foo(a, b) { return bar(a, b); }` that merely forwards its identical argument list to another function under a different name without adding validation, constants, or state transitions. Call the canonical function directly.
   - **No primitive or slice `type` aliases**: Never hide memory layout behind aliases like `type ByteSlice = u8[:]` or `type UserId = u64`. Write canonical Goose types (`const u8[:]`, `u8[..256]`, `u64`) directly at every call site so bounds and ownership are immediately visible.
   - **No `import ... as ...` namespace renaming**: Use canonical module names unless resolving a hard symbol collision.
   - **No local variable re-aliasing**: Do not create chains of synonymous local bindings (`let a = buf.len; let n = a;`).
   - **No redundant 0-arg struct constructor wrappers**: Never declare `fn new_foo() -> Foo { return Foo { .. }; }` (or `Foo {}`). Instantiate structs with native literal syntax `Foo { .. }` (or `wing::Foo { .. }`, `core::Foo { .. }`) directly at every call site.
   - **No trivial single-line struct field getters**: Never write wrapper functions whose sole purpose is returning an attribute or field of an argument (`fn foo(x: const Bar&) -> Baz { return x.field; }`). Access struct attributes directly at call sites or document invariants directly on struct fields.
   - **No trivial single-line struct field setters, raw arithmetic wrappers, or mutators (Anti G-CRAP gaming)**: Never declare functions or `inline fn` helpers whose sole purpose is assigning a single field (`claims.exp = exp_unix_sec;`) or performing trivial mechanical arithmetic (`val1 + val2`, `val1 + 1`, `val1 - 1`) without domain validation or state machine transitions:
     ```goose
     // PROHIBITED ANTI-PATTERN:
     fn set_expiry(claims: JwtClaims&, exp_unix_sec: i64) {
         claims.exp = exp_unix_sec;
     }
     fn set_not_before(claims: JwtClaims&, nbf_unix_sec: i64) {
         claims.nbf = nbf_unix_sec;
     }
     fn set_issued_at(claims: JwtClaims&, iat_unix_sec: i64) {
         claims.iat = iat_unix_sec;
     }
     inline fn inc_one(val: i64) -> i64 {
         return val + 1;
     }
     ```
     Mutate struct fields directly at call sites (`claims.exp = exp_unix_sec;`). AI models often invent trivial setter wrappers, mechanical arithmetic helpers (`val + 1`), or micro-functions to artificially decrease cyclomatic complexity and cheat the G-CRAP complexity gate.
     *Exception / Permitted pattern*: 1-line functions are entirely valid and encouraged when they encapsulate non-trivial logic (e.g. bitmasks, complex predicate expressions, domain rules), are reused across multiple call sites, and their descriptive name brings genuine architectural clarity to the algorithm (e.g. `is_supported_digest_algo`, `is_valid_dpop_nonce`, `calc_amplification_limit`).
     Never slice cohesive protocol routines into trivial artificial micro-helpers solely to satisfy G-CRAP. If a cohesive protocol function has legitimate linear guards or assignments that cause a G-CRAP ratchet delta, fix/update the baseline entry (`.lit/baseline`) rather than introducing artificial function bloat.
   - **Zero dead code (Mandatory call-site or test integration)**: Every function declared in production source files must be actively integrated and called by protocol engines, dispatchers, or test suites. Unreferenced functions are rejected by pre-commit.
   - **Domain-named leaf primitives over mechanical names**: When isolating a depth-0 arithmetic invariant for G-CRAP proof (`inline fn calc_amplification_limit`), name the function after the protocol domain rule, never after the raw operator (`add_one`, `sub_one`, `mul_by_three`).
2. **Input/output examples (`// Example:`) where genuinely useful**:
   - **Compulsory function archetypes**:
     - *Cursor mutators*: Any function advancing an in-out wire cursor (`idx: i64&`, `pos: i64&`, `offset: u64&`, `cursor: i64&`).
     - *Stream/slice-consuming parsers*: Any function consuming wire bytes and returning consumed byte length or parsed tokens (`-> (i64|u64|i32), bool` or `-> const u8[:], bool`), e.g. `fn parse_quoted_param<B>(s: const u8[:], out_val: B&) -> i64, bool`.
     - *Prefix-assumption parsers*: Any routine assuming a non-zero start or expecting leading delimiters (`"` or `[`).
     - *RFC grammar parsers and decoders*: Functions named `parse_*`, `decode_*`, `extract_*`, or `scan_*` handling wire frames or header tokens.
     - *Wire bitmask builders and transformers*: Functions named `build_*_type`, `pack_*`, `unpack_*`, `escape_*`, `unescape_*`, or `sanitize_*`.
   - **Required contract format**: A compact 2-4 line `// Example:` block documenting:
     - Input wire bytes and initial cursor/slice position.
     - Returned values/slices, final consumed length, and cursor index.
     ```goose
     // Extracts a parameter key up to '=', space, or tab (RFC 7616 §3.4).
     // Advances `idx` to the delimiter without consuming it.
     //
     // Example:
     //   raw = "realm=\"api\", nonce=\"xyz\"", idx = 0
     //   returns: "realm", ok = true, idx = 5 (points to '=')
     ```
     ```goose
     // Parses a quoted string parameter up to unescaped closing quote (RFC 7616 §3.4).
     // Assumes s[0] == '"'.
     //
     // Example:
     //   s = "\"hello \\\"world\\\"\", next=1"
     //   returns: consumed = 17, ok = true, out_val = "hello \"world\""
     ```
   - **Omit on trivial functions (Anti-noise)**: Do not add examples to simple getters, setters, constructors (`new_*`), state resets, pure 1-line arithmetic leaves, self-evident boolean predicates, block memory/buffer I/O operations (`read`, `write`, `copy`, `drain`), or server/protocol event handlers.
3. **No boolean trap signatures**:
   - Do not declare functions with consecutive raw `bool` parameters (`fn configure(a: bool, b: bool)`). Use explicit `enum` types (`QuicRole.Server`, `VerifyMode.Strict`) or configuration structs with named fields.
4. **Zero heap allocation in hot loops**:
   - Never declare dynamic buffers (`var buf: u8[>..] = []`) inside `for` or `while` loops. Use stack-bounded arrays (`u8[..N]`) or hoist and `.clear()` a single reusable buffer outside the loop.
5. **Transactional cursor contract on error**:
   - Functions taking a mutable cursor (`idx: i64&`) and returning `(..., bool)` must document or guarantee whether `idx` remains unchanged on `false` or stops at the offending byte.
6. **Named RFC constants over magic numbers**:
   - Protocol frame types (`0x08`), close codes (`1002`, `1007`), and wire bitmasks must be defined as module-level `const` declarations referencing the RFC section (`const WS_CLOSE_PROTOCOL_ERROR: u16 = 1002; // RFC 6455 §7.4.1`), never hardcoded inside branch conditions.
7. **Silence on the obvious & no placeholder code**:
   - Never write comments that merely restate the function name (`// Parses header` above `fn parse_header`).
   - Never write `// Does not panic` or `// Memory safe` (zero-panic safety is the baseline expectation; document only failure conditions and invariants).
   - Never commit `TODO`, `FIXME`, `HACK`, or `simplified for now` markers in production modules.
8. **Linear Git commit history**:
   - Merge commits are strictly prohibited (`git merge` without `--ff-only` is blocked). The commit graph on `main` must remain 100% linear via fast-forward, rebase, or cherry-pick.
9. **Value returns over intermediate out-parameters (No C-style out-buffers for pure computations)**:
   - Functions computing intermediate cryptographic hashes, message digests, token slices, or single-result data transformations must return their values directly (`-> u8[..64]`, `-> u8[32]`, `-> const u8[:]`, `-> (T, bool)`) relying on compiler RVO / structural return (`sret`).
   - Never define functions taking C-style out-parameters (`out_hex: u8[..64]&`, `out_ha1: u8[..64]&`, `out_response: u8[..64]&`) that force the caller to declare uninitialized temporary stack buffers (`var buf: u8[..64] = [];`) before invocation.
   - Out-parameters (`out: B&`, `dst: u8[:]&`) are permitted exclusively for cumulative streaming sinks (e.g. `HeaderWriter`, `serialize_digest_auth`, `encode_quic_frame`) that append directly into caller-owned transport buffers without intermediate copies.
10. **Byte slice (`const u8[:]`) as universal lingua franca and canonical `core::ByteCursor` / `core::ByteBuilder`**:
   - The byte slice (`const u8[:]` or `u8[:]`) is the universal primitive for all memory, wire packets, and protocol payloads across Goose.
   - **No ad-hoc cursor wrappers in text/HTTP parsers**: HTTP, header, URL, and RFC text tokenizers must never invent custom cursor wrapper structs (`struct SliceReader`, `struct WireReader`). Accept canonical slices (`raw: const u8[:]`) with an explicit cursor offset (`idx: i64&`), or return `(consumed_len, bool)` / `(Frame, bool)`. Direct slices preserve bounds visibility for compiler Bounds Check Elimination (BCE) and maintain minimal G-CRAP branch depth.
   - **Canonical `core::ByteCursor` and `core::ByteBuilder` (`core/io/cursor.goose`)**: For binary length-prefixed wire protocols (TLS 1.3 records/handshakes, ASN.1 DER/X.509, QUIC frames), use `core::ByteCursor` (`read_u8`, `read_u16`, `read_u24`, `read_u16_prefixed`, `read_u24_prefixed`) and `core::ByteBuilder` (`start_u16_prefix`, `finish_u16_prefix`) instead of manual index arithmetic.
   - **Zero-copy socket streaming via ring-buffer views**: Sockets and transports must not implement Go-style virtual `io.Reader.Read(p: u8[:])` (which forces callers to allocate receiving buffers and copy bytes from the kernel). Transports manage an internal ring buffer (`core::PageRingBuffer`, `core::PipeBuffer`) or scratch arena and vend unread slices directly, advancing state after parsing.
11. **Constant-time cryptographic comparisons and stack secret zeroization (No side-channels or key leaks)**:
   - Never compare cryptographic digests, MAC tags, HMAC outputs, or verification tokens using `==` or `!=`. Always use `core::ct_eq_bytes` to prevent timing side-channel leaks.
   - Ephemeral private keys, AEAD keys, HKDF PRKs/secrets, and signing seeds copied onto the stack must be wiped with `core::secure_zeroize_16` / `core::secure_zeroize_32` before function return (including on early error paths).
12. **Zero dynamic vectors (`u8[>..]`) in wire frame structs**:
   - Protocol frame, packet, and header structs (`*Frame`, `*Packet`, `*Header`) must store payload views as zero-copy slices (`const u8[:]`) or stack-bounded arrays (`u8[..N]`), never heap-allocated `u8[>..]` vectors.
13. **Zero silent buffer drops (Strict capacity overflow error propagation)**:
   - Never write `if len <= cap { push(); }` or `if len < cap { ... }` without an explicit rejection or error-handling branch (`else { return ..., false; }` or emitting a protocol error).
   - Silently ignoring input when a buffer's capacity is exceeded masks protocol violations, corrupts security invariants, and creates silent state de-synchronization.
   - Invert checks into top-level guards at function ingress: `guard buf.len + item.len <= buf.cap else { return ..., false; }`.
14. **Prohibition of naive substring searching on structured wire formats**:
   - Never use `index_of_slice`, `contains`, `index_of_byte`, or manual slice splitting to extract fields from JSON, URLs, HTTP headers, query strings, or cookies in security-critical parsers.
   - Always use canonical streaming readers (`json::reader`, `url::`, `HeaderMap`) to defend against escaped quote bugs, duplicate key smuggling, and injection attacks.
15. **Zero fallback to valid enum variants in parsers (Exhaustive enum parsing)**:
   - Parsers converting wire strings to enums (`parse_*_type`, `str_to_*`, `parse_alg`) must return `(Enum, bool)` or define an explicit `Enum.Unknown` or `Enum.Invalid` variant.
   - Never map unrecognized values, unsupported algorithms, or wildcard `_` to an operational default (such as returning `OKP` for unknown key types like `"RSA"`, or defaulting unknown hash algorithms to `SHA-256`).
16. **Stateful entropy in pseudo-random and identifier generators**:
   - Never declare fixed initial states (`var state: u64 = 0x...`) inside functions generating unique tokens (`jti`, `nonce`, `uuid`).
   - Generators must either accept a mutable RNG state by reference (`rng: Rng&`), take an external entropy buffer, or mix high-resolution hardware/OS clocks (`clock_ns()`).
17. **Enterprise-scale buffer limits over toy RFC examples**:
   - Never allocate miniature stack buffers (`u8[..384]`, `u8[..512]`) for external bearer tokens, access tokens, certificates, or authorization headers based on brief RFC examples.
   - Use canonical enterprise constants: `const MAX_AUTH_TOKEN_LEN: u64 = 4096;`, `const MAX_HEADER_FIELD_LEN: u64 = 8192;`.
18. **Transactional out-buffer hygiene (Zero dirty state on error)**:
   - Functions taking a mutable output buffer (`out: B&`, `dst: u8[..N]&`) and returning `bool` must validate all preconditions before mutating `out`, or call `out.clear()` on every failure branch (`return false`) so callers never observe partial or corrupted data.
19. **HeaderMap Bloom filter synchronization**:
   - Never push directly to `req.headers.push(...)` without updating the corresponding `bloom_filter` or routing through `add_header` / `append_header`.

## Protocol specification fidelity and adversarial testing

Engineering rules ensuring protocol compliance and resilience against real-world edge cases:

1. **RFC Appendix vector conformance**:
   - Implementations of RFC protocols must verify behavior against official test vectors in the RFC's Appendix.
   - Intermediate cryptographic digests (such as `HA1`, `HA2`, `response` in RFC 7616 §5, or `ath` in RFC 9449) must match RFC vector values byte-for-byte before a module is approved.
2. **Mandatory negative and edge fuzzing test vectors**:
   - Every parser must include explicit negative tests verifying:
     - *Oversize inputs*: strings exceeding buffer capacity must return explicit errors (`ok == false`), never silent truncation.
     - *Unknown enum variants*: unrecognized algorithms or key types must fail parsing.
     - *Injection payloads*: escaped quotes (`\"`), CRLF, and duplicate keys must not confuse parsers.
     - *Delimiter variations*: comma-separated lists (`qop="auth, auth-int"`) must be tested with varying whitespace, order, and extra tokens.
3. **Pre-commit adversarial self-audit checklist**:
   - Before opening a PR or finalizing any feature branch, verify the 6 cardinal LLM bug patterns:
     1. Check every `len < cap` and `len <= cap`: does every branch reject on overflow?
     2. Check every PRNG / unique ID generator: does it preserve entropy across invocations?
     3. Check every string search: is a structured reader used for JSON, headers, and URLs?
     4. Check enum dispatchers: do unknown strings return `Unknown` / `false` instead of defaulting to a valid variant?
     5. Check buffer sizing: are enterprise-sized tokens (up to 4096 bytes) supported?
     6. Check stack secrets and out-buffers: are ephemeral keys wiped via `core::secure_zeroize_*` and out-buffers cleared on error?
4. **Anti-hallucination RFC citation contract**:
   - Always cite the active authoritative RFC specification (e.g. RFC 9110 / RFC 9112 over obsolete
     RFC 7230 / RFC 7231 / RFC 2616).
   - **Canonical RFC citation comment format**:
     To enable automated word-for-word verification against the RFC corpus via `scripts/audit_rfc_citations.py`, all protocol comments must follow this exact structure:
     ```goose
     // RFC <NUM> Section <X.Y>: <VERBATIM_SECTION_TITLE> - <SPECIFIC_REQUIREMENT>
     ```
     *Examples:*
     ```goose
     // RFC 9113 Section 4.3: Header Compression and Decompression - An endpoint receiving HEADERS must decompress the block.
     // RFC 7616 Section 3.4.2.2: Calculation of the "response" Directive - qop=auth calculation of HA2.
     ```
   - **Verbatim section title matching**: The `<VERBATIM_SECTION_TITLE>` immediately after `Section <X.Y>:` must match the official section heading in `rfc<NUM>.txt` character-for-character so static scanners can verify section authenticity without false positives.
   - **Normative keyword quotes**: When citing constraints, quote RFC keywords (`MUST`, `MUST NOT`, `SHOULD`, `REQUIRED`) verbatim:
     ```goose
     // RFC 8446 Section 4.2.10: Early Data Indication - A client MUST NOT send early_data if max_early_data_size is 0.
     ```
   - **Never invent or extrapolate section numbers**: Do not guess section numbers (such as `RFC 9112 §3.1.2`
     or `RFC 7692 §8.1`). Validate section numbers against the local RFC corpus in `.gemini/rfc/` or execute
     `python scripts/audit_rfc_citations.py`. If a specific section number cannot be verified, cite the
     RFC title or top-level RFC number only.

## Code formatting, geometry, and G-CRAP harmony

Structural formatting rules designed to work in mathematical synergy with `goose format` and the `goose-lit` G-CRAP complexity gate ($\text{G-CRAP} \le 25.0$, $\text{EffCC} \le 15$):

1. **Line length (Soft 100 / Hard 120 columns)**:
   - Target **100 columns** for standard code and comments; enforce a hard ceiling of **120 columns** (excluding long RFC test vector strings, URLs, and `// CHECK:` directives).
   - Why 120 columns harmonizes with G-CRAP: It allows single-line early exits (`guard idx < buf.len else { return 0, false; }`) to stay on one line instead of expanding into 3 lines each.
   - Multi-line signatures: Functions with $\ge 4$ parameters or signatures exceeding 100 columns must place each parameter on its own 4-space indented line with a trailing comma `,`.
2. **Whitespace and vertical rhythm**:
   - **Indentation**: Strictly **4 spaces** per indent level. Tab characters (`\t`) and trailing end-of-line spaces are prohibited.
   - **Single blank line grouping**: Separate distinct phases inside a function (1: precondition `guard` block, 2: core loop/computation, 3: final serialization/return) with at most 1 blank line. Consecutive blank lines (`\n\n\n`) and blank lines immediately after `{` or before `}` are prohibited.
   - **Operator spacing**: Exactly 1 space around binary operators (`+`, `-`, `==`, `!=`, `&&`, `||`, `=`, `->`) and after commas; enforced via `goose format --check .`.
3. **Nesting depth ceiling ($\le 3$ levels inside a function)**:
   - Control-flow nesting inside a function body (`for`/`while`/`if`/`match`) must not exceed **3 levels** (16 spaces of indentation from column 0).
   - **Synergy with G-CRAP**: In G-CRAP, branch depth $d \ge 4$ adds $+4$ to Cognitive Complexity (`EffCC`) per branch and multiplies any arithmetic operation by $d \times \beta_{\text{ovf}} \ge 60.0$ (instantly violating the 25.0 gate).
   - **Guard-first flattening**: Always invert preconditions into top-level `guard cond else { return ...; }` statements so the happy path remains at indent level 1 (4 spaces).
4. **Adaptive function length (By structural archetype)**:
   - **Stateful / loop functions (containing `while` or `for`)**: Maximum **65 lines** (ideal 15-45 lines). If a loop function exceeds 65 lines, extract the inner loop body into a named domain helper (`decode_stream_frame_reader`, `should_forward_header`), simultaneously lowering `EffCC` and `G-CRAP`.
   - **Flat dispatch tables and RFC classifiers (depth $\le 2$, no loops)**: Up to **100 lines**. Flat `match` or `if` dispatchers at depth 1 have near-zero `G-CRAP` ($\le 1.0$) and must **not** be artificially split into `part1`/`part2` micro-functions, preserving cache locality and readability.

## Documentation and style

- **File naming**:
  - Documentation files inside `docs/` must use lowercase `snake_case` matching upstream `goose` conventions (`docs/architecture.md`, `docs/caller_reference.md`, `docs/features_and_nuances.md`, `docs/security_defenses.md`, `docs/rfc_conformance.md`, `docs/benchmarks.md`).
  - Root repository meta-files (`README.md`, `CONTRIBUTING.md`, `SECURITY.md`, `CHANGELOG.md`, `LICENSE`) and per-module `README.md` files use standard `UPPERCASE`.
- **80-column hard-wrap and `goosemarklint` enforcement**:
  - Prose paragraphs, blockquotes, and list items in Markdown files must hard-wrap at **80 columns** (enforced via `MD013` and formatted automatically by `goosemarklint fmt .`). Tables, code blocks, headings, and unbreakable single-token code spans or URLs are exempt from `MD013`.
  - Run `goosemarklint fmt .` and `goosemarklint check .` (or `just md-fmt` and `just md-lint`) after editing any `.md` file.
- Write documentation, comments, and commit messages concisely and factually without AI buzzwords, corporate fluff, or melodrama.
- Headings must use sentence case (`Commit conventions and releases`, not `Commit Conventions And Releases`).
- Use straight quotes (`'` and `"`) instead of curly quotes.

## Communication and anti-AI tone

When communicating with users, drafting pull request descriptions, or writing reviews:

- **Zero sycophancy**: Never open with conversational pleasantries, validation, or filler (`Certainly!`, `Great idea!`, `I'd be glad to help`). Start directly with the factual answer or action taken.
- **No concluding platitudes**: Do not add polite sign-offs (`Let me know if you need anything else!`, `Hope this helps!`). Conclude when the technical point is made.
- **Banned AI vocabulary**: Avoid inflated adjectives and AI hallmarks:
  - Do not use: `crucial`, `robust`, `comprehensive`, `seamlessly`, `vital`, `testament`, `delve`, `meticulously`, `pivotal`, `game-changer`, `plethora`, `tapestry`, `leverage`.
- **Formatting and punctuation**:
  - Headings must use sentence case, not Title Case.
  - Do not use em dashes (`—`) as decorative pauses or conversational asides; use hyphens, commas, or parentheses.
  - Avoid repetitive bold-colon list structures (`- **Item**: explanation`) when normal sentences or tables are cleaner.
- **File and symbol references**: Link all file paths with clickable `file:///` markdown links and use backticks for types, functions, and identifiers.
