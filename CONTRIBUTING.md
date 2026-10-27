# Contributing to goose-wing

Thank you for your interest in contributing to **goose-wing**! This document provides guidelines, architectural invariants, and workflows for contributing to the library.

## 1. Architectural Philosophy & Core Invariants

`goose-wing` is a high-performance, zero-allocation systems networking engine built in pure [Goose](https://github.com/lemon4ksan/goose). Every contribution must respect these invariants:

1. **Zero Dynamic Allocation on Wire Paths**:
   - Never perform dynamic heap allocations (`[>..]`) on request, response, framing, or wire serialization hot paths.
   - Use bounded stack-allocated arrays (`u8[..N]`, `HeaderItem[..32]`, `QueryItem[..16]`) with compile-time capacities.
   - Wire parsing methods must work with borrowed slices (`const u8[:]`) without copying payload bytes.

2. **Systems Identity (No Browser Impersonation)**:
   - `goose-wing` is an authentic systems networking engine for cloud microservices, brokers, and high-performance clients—**not** a web scraper or browser impersonation tool.
   - The canonical client profile is `Profile.Wing`. Do not add browser persona mocks (`Chrome`, `Firefox`, `Safari`) or fake browser TLS fingerprints.

3. **Defensive RFC Conformance**:
   - Parsers must be resilient against HTTP request smuggling (RFC 9112 §6.1, §7.1), desynchronization attacks, CRLF injection, and SSRF (RFC 6797, RFC 6265bis).
   - Any external wire input must return error status enums or `(result, bool)` tuples—never panic on untrusted wire bytes.

4. **Uniform Function Call Syntax (UFCS)**:
   - Prefer free functions where the mutated struct is passed as the first parameter by reference (`fn set_header(req: Request&, name: const u8[:], val: const u8[:])`).
   - This enables clean chaining (`req.set_header(...).bearer(...)`).

## 2. Prerequisites

- **Goose Compiler**: `goose v2026.3+` on `PATH`.
- **C Toolchain**: GCC 14+ (MinGW-w64 on Windows, native GCC on Linux) or Clang 18+.
- **Python**: Python 3.10+ (used for the parallel test runner, licensing validation, and E2E harnesses).

## 3. Repository Layout

```text
goose-wing/
├── core/             # Primitives, SIMD search, bytes manipulation, system clock
│   ├── bytes/        # Zero-copy slice searching, string folding, parsing
│   ├── compress/     # Zstandard, Brotli, Gzip streaming decompressors
│   └── time/         # High-resolution monotonic timers & RFC HTTP dates
├── net/              # TCP, UDP, TLS 1.3, Happy Eyeballs v2, Socket options
├── http/             # HTTP/1.1 chunked framing, HTTP/2 HPACK, HTTP/3 QPACK
│   ├── cache/        # RFC 9111 HTTP Cache Engine
│   └── headers/      # Lexical analyzers, case-insensitive folding, bloom filters
├── client/           # Resilient Client, Sessions, Interceptors, Tracing
├── server/           # Zero-allocation HTTP/1.1 & HTTP/2 Server & Router
├── websocket/        # RFC 6455 WebSocket framing & TopicTree OASIS pub/sub
├── grpc/             # gRPC Unary & Streaming microservice dispatcher, LPM framing
├── shim/             # Native C acceleration shims (RIO, io_uring, kqueue, SIMD)
├── examples/         # Self-contained showcase programs
├── tests/            # 81 comprehensive verification test suites
├── tools/            # Python test runner, licensing check, E2E verification
└── .github/          # CI workflows, issue & pull request templates
```

## 4. Development & Testing Workflow

### Step 1: Parallel Fast Typechecking
To verify that all 81 test suites, core library, and examples pass typechecking without compiling native binaries:

```bash
python tools/test_runner.py --check-only
```
*(Runs in parallel across all CPU cores in ~14 seconds).*

### Step 2: Running Specific Suites
To compile and execute a specific test suite or pattern:

```bash
python tools/test_runner.py --pattern "*grpc*"
python tools/test_runner.py --pattern "http1_chunked_test.goose"
```

Or using PowerShell on Windows:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\test_all.ps1 -Pattern "*grpc*"
```

### Step 3: End-to-End (E2E) Verification Suites
Before submitting a PR, run the automated integration harnesses:

```bash
python tools/grpc.py       # gRPC cross-language unary & streaming verification
python tools/tls.py        # TLS 1.3 cryptographic handshake & 0-RTT resumption
python tools/http3.py      # HTTP/3 & QUIC stream multiplexing verification
python tools/chaos.py      # Toxiproxy network latency & partition chaos suite
```

### Step 4: Formatting Code
Format all Goose source files according to the official style:

```bash
goose format .
goose format --check .
```

### Step 5: License & Header Verification
Ensure all files include the official Apache-2.0 SPDX header:

```bash
python tools/licensing.py --check
```
*(If headers are missing, run `python tools/licensing.py --fix`).*

## 5. Coding Standards

### Memory Management & Bounded Arrays
Always define clear capacity bounds for collections:

```goose
// Good: Zero-allocation, stack-allocated bounded array
var headers: HeaderItem[..32] = [];
var buffer: u8[..4096] = [];

// Avoid on hot paths: Dynamic heap growth
var dynamic_list: u8[>..] = [];
```

### C Shims & Dynamic Externs
C acceleration shims reside in `shim/`. When adding or modifying C shims:
- Must compile cleanly under `-Wall -Wextra -Werror` with zero compiler warnings on both GCC and Clang.
- Expose symbols to Goose using the standard extern syntax:
  ```goose
  extern fn native_fast_find_crlfcrlf(s: const u8[:]) -> i64 = "wing_fast_find_crlfcrlf";
  ```
- Always configure Windows, Linux, and macOS sources in `wing.build` and `core.build`.

## 6. Pull Request Checklist

When opening a pull request, ensure:

- [ ] All 81 test suites pass `python tools/test_runner.py --check-only`.
- [ ] Code is formatted with `goose format`.
- [ ] No heap allocations are added on wire parsing hot paths.
- [ ] C shims compile with zero warnings under `-Wall -Wextra -Werror`.
- [ ] Licensing check passes (`python tools/licensing.py --check`).
- [ ] Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/):
  - `feat: add RFC 9110 Retry-After parser`
  - `fix: prevent double masking in websocket frame encoder`
  - `perf: optimize SIMD CRLF scan for AVX2`
  - `docs: update caller reference guide`
