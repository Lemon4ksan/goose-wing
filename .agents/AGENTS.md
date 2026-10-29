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
    ```powershell
    powershell -ExecutionPolicy Bypass -File .\scripts\test_all.ps1 -CheckOnly
    ```
  - Core libraries (`core.goose`, `wing.goose`) and all test suites must pass without errors or warnings.
- **Hardware enforcement gate (`goose-lit`)**:
  - Every modified or refactored `.goose` file must pass the hardware complexity gate before finalizing changes:
    ```powershell
    powershell -ExecutionPolicy Bypass -File .\scripts\verify_wing_gate.ps1 -TargetFile "<path\to\file.goose>" -MaxGCrap 25
    ```
  - Pass `-LitScript "<path\to\test.goose>"` and `-TestSuite "<path\to\test.goose>"` to combine static complexity gating with native LIT assertions and unit tests in a single run.
  - If the script exits with code 1 (`GATE REJECTED`), functions must be flattened with `guard` clauses, bounds checks proved, and cyclomatic depth reduced until all functions pass.

## Goose LIT and native wire verification workflow

Use `..\goose-lit\bin\goose-lit.exe` to run LLVM-style `// RUN:` test directives, FileCheck output matching, and static G-CRAP complexity analysis without Wasm virtualization:

```powershell
# Execute a single native LIT test suite
..\goose-lit\bin\goose-lit.exe tests\lit\verify_wire_framing.goose

# Run all native LIT verification suites in parallel
powershell -ExecutionPolicy Bypass -File .\scripts\test_lit.ps1

# Hardware complexity gate analysis
..\goose-lit\bin\goose-lit.exe gate auth/jwks.goose 25 --cov 0.85

# Risk radar table output
..\goose-lit\bin\goose-lit.exe crap http/headers.goose --threshold 25.0
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

## Strict code clarity and anti-bloat invariants

Enforced statically via `scripts/lint_invariants.ps1` and `.githooks/pre-commit`:

1. **Zero meaningless function aliases (No pass-through wrappers)**:
   - **No pass-through function aliases**: Never declare a function `fn foo(a, b) { return bar(a, b); }` that merely forwards its identical argument list to another function under a different name without adding validation, constants, or state transitions. Call the canonical function directly.
   - **No primitive or slice `type` aliases**: Never hide memory layout behind aliases like `type ByteSlice = u8[:]` or `type UserId = u64`. Write canonical Goose types (`const u8[:]`, `u8[..256]`, `u64`) directly at every call site so bounds and ownership are immediately visible.
   - **No `import ... as ...` namespace renaming**: Use canonical module names unless resolving a hard symbol collision.
   - **No local variable re-aliasing**: Do not create chains of synonymous local bindings (`let a = buf.len; let n = a;`).
   - **Domain-named leaf primitives over mechanical names**: When isolating a depth-0 arithmetic invariant for G-CRAP proof (`inline fn calc_amplification_limit`), name the function after the protocol domain rule, never after the raw operator (`add_one`, `sub_one`, `mul_by_three`).
2. **Input/output examples (`// Example:`) where genuinely useful**:
   - **Compulsory function archetypes**:
     - *Cursor mutators*: Any function advancing an in-out wire cursor (`idx: i64&`, `pos: i64&`, `offset: u64&`, `r: SliceReader&`, `rd: WireReader&`).
     - *Stream/slice-consuming parsers*: Any function consuming wire bytes and returning consumed byte length or parsed tokens (`-> (i64|u64|usize|i32), bool` or `-> const u8[:], bool`), e.g. `fn parse_quoted_param<B>(s: const u8[:], out_val: B&) -> i64, bool`.
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
   - **Omit on trivial functions (Anti-noise)**: Do not add examples to simple getters, setters, constructors (`new_*`), state resets, pure 1-line arithmetic leaves, or self-evident boolean predicates.
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
10. **Byte slice (`const u8[:]`) as universal lingua franca (Prohibition of `io.Reader` and cursor wrappers in parsers)**:
   - The byte slice (`const u8[:]` or `u8[:]`) is the universal primitive for all memory, wire packets, and protocol payloads across Goose.
   - **No artificial cursor wrappers**: Protocol parsers, frame decoders, and RFC tokenizers must never wrap in-memory slices in artificial cursor objects (`struct SliceReader`, `struct ByteCursor`, `struct WireReader`). Parsers must accept canonical slices (`raw: const u8[:]`) and an explicit cursor offset (`idx: i64&`), or return `(consumed_len, bool)` / `(Frame, bool)`. Direct slices preserve bounds visibility for compiler Bounds Check Elimination (BCE) and maintain minimal G-CRAP branch depth.
   - **Zero-copy socket streaming via ring-buffer views**: Sockets and transports must not implement Go-style virtual `io.Reader.Read(p: u8[:])` (which forces callers to allocate receiving buffers and copy bytes from the kernel). Transports manage an internal ring buffer or scratch arena and vend unread slices directly (`incoming_slice() -> const u8[:]`), advancing state after parsing (`advance_read(consumed)`).
11. **Constant-time cryptographic comparisons (No timing side-channels)**:
   - Never compare cryptographic digests, MAC tags, HMAC outputs, or verification tokens using `==` or `!=`. Always use `core::ct_eq_bytes` to prevent timing side-channel leaks.
12. **Zero dynamic vectors (`u8[>..]`) in wire frame structs**:
   - Protocol frame, packet, and header structs (`*Frame`, `*Packet`, `*Header`) must store payload views as zero-copy slices (`const u8[:]`) or stack-bounded arrays (`u8[..N]`), never heap-allocated `u8[>..]` vectors.

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
