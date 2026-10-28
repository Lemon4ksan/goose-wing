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
  - If the script exits with code 1 (`GATE REJECTED`), functions must be flattened with `guard` clauses, bounds checks proved, and cyclomatic depth reduced until all functions pass.

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
