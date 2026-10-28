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
- **Hardware enforcement gate (`goose-crap` + `gosling`)**:
  - Every modified or refactored `.goose` file must pass the hardware complexity gate before finalizing changes:
    ```powershell
    powershell -ExecutionPolicy Bypass -File .\scripts\verify_wing_gate.ps1 -TargetFile "<path\to\file.goose>" -MaxGCrap 25
    ```
  - Pass `-ReplScript "<path\to\checks.repl>"` and `-TestSuite "<path\to\test.goose>"` to combine static complexity gating with in-memory packet assertions and unit tests in a single run.
  - If the script exits with code 1 (`GATE REJECTED`), functions must be flattened with `guard` clauses, bounds checks proved, and cyclomatic depth reduced until all functions pass.

## Gosling REPL and wire verification workflow

Use `..\gosling\bin\gosling-repl.exe` (`..\gosling\compiler\repl.goose`) to compile, fuzz, and benchmark `goose-wing` protocol parsers, SIMD scanners, and L4 socket state machines in memory without starting external network servers:

```powershell
# Composable one-liner: load, inject packet, inspect SIMD, and assert without string escaping or `n
..\gosling\bin\gosling-repl.exe -q -l http\parser.goose `
  --pkt '2048:"GET /index.html HTTP/1.1\r\n\r\n"' `
  --simd 2048:47 `
  -a "scan_uri(2048, 28) == 1"

# Hardware complexity gate with JSON/TSV structured reporting
..\gosling\bin\gosling-repl.exe -l auth\jwks.goose --gate 25 --cov 0.85 --format json

# Execute a batch .repl verification script
..\gosling\bin\gosling-repl.exe "<path\to\verify_parser.repl>"

# Execute all in-memory protocol verification suites (< 300ms)
powershell -ExecutionPolicy Bypass -File .\scripts\test_repl.ps1
```

### Composable CLI flags

| CLI flag | Arguments | Purpose in `goose-wing` workflows |
| :--- | :--- | :--- |
| `-l`, `--load` | `<file.goose>` | Loads declarations into session (can be repeated for dependencies). |
| `--set` | `<name>=<val>` | Pre-sets session variable before execution. |
| `-e`, `--eval` | `<expr\|:cmd>` | Evaluates expression, statement, or REPL command. |
| `-a`, `--assert` | `<lhs> == <rhs>` | Evaluates assertion; exits with code 2 on mismatch or trap. |
| `--pkt` | `<addr>:<hex\|"str">` | Injects raw wire bytes or escaped HTTP/TLS/gRPC payload into linear memory. |
| `--pkt-file` | `<addr>:<path>` | Injects binary test vector file directly into linear memory. |
| `--mem` | `[addr][:len]` | Dumps linear memory in hex and ASCII (default 2048:64). |
| `--simd` | `[addr][:byte]` | Inspects 16-byte `v128` window and match mask (default 2048:'/'). |
| `--crap` | `[fn]` | Computes `G-CRAP`, `CC`, `EffCC`, `BCE`, and archetype. |
| `--gate` | `[file.goose\|max] [cov]` | Enforces hardware gate thresholds (exits with code 3 on violation). |
| `--cov` | `<0.0..1.0>` | Sets simulated branch coverage for crap and gate analysis (default 0.85). |
| `--format` | `text\|json\|tsv` | Sets output format for crap and gate reporting. |
| `--wasm` | `<fn\|expr>` | Disassembles generated Wasm bytecode. |
| `--dump-wasm` | `<path>` | Saves compiled Wasm bytecode to file. |
| `--jit` | `<fn(args)\|expr>` | Compiles to x86_64, executes on CPU, and verifies VM parity (code 4 on mismatch). |
| `--bench` | `<fn(args)\|expr>[:iters]` | Benchmarks execution time between Wasm VM and native JIT. |
| `-q`, `--quiet` | - | Suppresses banners and non-error status messages. |
| `--keep-going` | - | Continues execution across multiple assertions instead of aborting on first failure. |
| `-i`, `--interactive` | - | Enters interactive REPL terminal after batch steps. |

Exit codes: `0` = Success, `1` = Syntax/Compile/CLI error, `2` = Assertion/Trap failure, `3` = Gate ceiling breach, `4` = JIT parity mismatch.

### Interactive and script meta-commands

| REPL command | Purpose in `goose-wing` workflows |
| :--- | :--- |
| `:load <file.goose>` | Strips `namespace`/`import` headers, hot-reloads declarations into the session, and compiles them to Wasm in memory. |
| `:decls` / `:undef <sym>` | Lists active session functions/types or removes a symbol before redefining it. |
| `:pkt <addr> <hex\|"str">` | Injects raw wire bytes or escaped HTTP/TLS/gRPC payloads directly into persistent linear memory (`2048..65535`). |
| `:pkt_file <addr> <path>` | Injects binary test vector file into persistent linear memory. |
| `:simd <addr> [byte]` | Displays a 16-byte `v128` memory window at `<addr>`, lane-by-lane matches against `[byte]` (default `'/'`, `47`), and the computed `i8x16.bitmask`. |
| `:mem [addr] [len]` | Dumps linear memory in hex and ASCII to inspect zero-copy parser state or serialized frames. |
| `:sockets` | Inspects the 8 virtual in-memory L4 socket slots (`wing_tcp_listen`, `wing_tcp_connect`, `wing_tcp_accept`, `wing_tcp_send`, `wing_tcp_recv`, `wing_tcp_close`) pre-bound in every session. |
| `:assert <lhs> == <rhs>` | Evaluates both expressions in the Wasm VM and fails with exit code 1 on trap (`OutOfBoundsMemoryAccess`, `IntegerOverflow`) or value mismatch. |
| `:crap [fn] [cov]` | Computes cyclomatic complexity (`CC`), nesting-weighted `EffCC`, unproven bounds checks (`BCE`), overflow ops (`OVF`), and `G-CRAP` archetype (`SAFE_PRIMITIVE`, `VERIFIED_DISPATCH`, `FUZZ_PRIORITY`, `PANIC_HAZARD`). |
| `:gate [max_gcrap] [cov]` | Rejects the session (exit code 1) if any function exceeds `max_gcrap`, `EffCC > 15`, or contains unproven `BCE` at `< 80%` simulated coverage. |
| `:wasm <fn\|expr>` | Disassembles generated W3C WebAssembly bytecode, including `0xFC` bulk memory and `0xFD` 128-bit SIMD opcodes. |
| `:dump_wasm <path>` | Saves compiled Wasm bytecode to file. |
| `:jit <fn(args)>` | Compiles Wasm bytecode to native x86_64 machine code, executes it on the CPU, and verifies `BIT-EXACT MATCH` against the Wasm VM. |
| `:bench <fn(args)> [iters]` | Benchmarks execution time (`ns/op`) and speedup between the Wasm interpreter and native x86_64 JIT. |

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
