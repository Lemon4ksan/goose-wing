# goose-wing

An HTTP client stack, zero-allocation time primitives, and Chromium-grade CookieMonster implementation for the [Goose](https://github.com/goose-lang/goose) programming language.

`goose-wing` provides application-layer networking components designed around Goose's memory model: bounded inline storage, explicit growth vectors, UFCS ergonomics, and zero unexpected runtime allocations.

## Overview

The library is organized into four architectural layers:

1. **`core/time.goose`**: Nanosecond-precision calendar and monotonic time engine based on Howard Hinnant's civil calendar algorithms. Includes RFC 3339, RFC 9110 HTTP-Date codecs, Go-compatible `parse_duration`, monotonic `Stopwatch`, and anti-overflow `Deadline`.
2. **`cookie/`**: Clean-room implementation of Chromium's `net::CookieMonster` adhering to RFC 6265, RFC 6265bis, the Layered Cookies draft, CHIPS (partitioned cookies), and Public Suffix List rules.
3. **`core/url.goose` & `app/redirect.goose`**: WHATWG URL parser with continuous memory buffer, RFC 5952 IPv6 zero-run compression, Swift Foundation-grade File URL and path manipulation API (cross-platform Windows/POSIX path normalization, component inspection, and fluent UFCS chaining), `Origin` model (`Tuple` vs `Opaque`), and a deterministic HTTP Redirect State Machine (`net::RedirectInfo`) defending against CVE-2023-45143, CVE-2024-1968, CVE-2026-55553, and CVE-2026-64684.
4. **`app/`**: Client session coordinator (`ClientSession`) orchestrating a 6-phase pipeline over `CanonicalCookieJar`, with `BodyRewind` (Request.GetBody), 3-tier SSRF/DNS Rebinding guards, browser profiles (Chrome 131, Firefox 133, Safari 18), and resilience policies.
5. **`core/test.goose`**: Zero-allocation testing framework featuring compile-time structural diffing, table-driven runners, high-resolution `MockClock`, and a deterministic Xorshift64* property fuzzer.

## Key Modules

### 1. Canonical Cookie Engine (`cookie/`)

Implements the complete semantics of Chromium's `CookieMonster`:

- **Quotas & Parsing**: 4096-byte payload cap (`name + value`), 1024-byte per-attribute limit, 33-byte ASCII CTL character rejection, and nameless cookie support (`=value` and value-only strings per WPT).
- **Domain & PSL Logic**: eTLD+1 boundary extraction, localhost/IPv4/IPv6 address normalization, and protection against public suffix cookie injection.
- **Layered Prefixes**: Strict enforcement for `__Secure-`, `__Host-`, `__Http-`, and `__Host-Http-`.
- **SameSite & Incrementalism**: `Strict`, `Lax`, `None`, and default `Lax` with the 120-second Lax-allowing-unsafe window for top-level `POST` requests.
- **CHIPS (Partitioning)**: Partition-keyed isolation with 10 KB per-partition byte budget enforcement.
- **6-Round Garbage Collection**: Matches Chromium's asymmetric eviction policy (Round 4 domain cookies before host cookies, Round 5 host cookies, Round 6 global eviction) and respects the 30-day purge immunity window.
- **Persistence Store**: SQLite-compatible schema (v24), write-back batching with coalescing, 60-second access time throttling, and constant-time comparison against timing attacks.

### 2. Time & Calendar (`core/time.goose`)

Zero-heap timekeeping and date calculations:

- **Calendar Math**: Hinnant algorithms for conversion between proleptic Gregorian calendar dates and Unix epoch timestamps without lookup tables.
- **Durations**: Full arithmetic (`+`, `-`, `*`, `/`), comparisons, signs (`zero`, `positive`, `negative`), truncation, and rounding.
- **Parsing**: Go-compatible `parse_duration` supporting composite units (`1h30m45s`), decimal fractions (`-2.5s`), and overflow protection.
- **Formatting**: RFC 3339 (with sub-second fractional precision), IMF-fixdate / RFC 1123, RFC 850, and asctime formats per RFC 9110 §5.6.7.
- **Resilience**: Monotonic `Stopwatch`, deadline checking with `deadline_after(dur)`, token-bucket `RateLimiter`, and exponential `Backoff` with jitter.

### 3. WHATWG URL, PSL, File URLs & Redirect FSM (`core/url.goose`, `app/redirect.goose`)

Browser-grade URL parsing, Swift-like path manipulation, origin isolation, and redirect state machine:

- **WHATWG URL Parser**: Single continuous byte buffer with compact offset indices (ada-url / sorug pattern), default port stripping, dot-segment collapsing (`/a/b/../c` -> `/a/c`), and relative base resolution.
- **Swift-Style File URLs & Paths**: First-class support for file paths with bidirectional normalization:
  - `new_file_url(path)`: Normalizes Windows drive letters (`C:\...` -> `file:///C:/...`, spaces -> `%20`), POSIX paths (`/var/log/...`), and Windows UNC shares (`\\nas\share` -> `file://nas/share`).
  - `file_path(url, out)`: Decodes `%20`, drops leading slashes before drive letters, and maps separators back to native OS backslashes (`C:\...`).
  - **Component Inspection**: `last_path_component(url)` (ignoring trailing slashes) and `path_extension(url)` (correctly identifying extensions like `.tar.gz` while ignoring hidden files like `.gitignore`).
  - **Mutations & Navigation**: `deleting_last_path_component` (parent directory), `deleting_path_extension`, `appending_path_component`, `appending_path` (multi-segment subpaths), and `appending_path_extension`.
  - **Fluent UFCS Chaining**: `base.appending("build").appending("bin").appending_path_extension("exe")`.
- **IPv6 RFC 5952 Compression**: Deterministic zero-run compression finding the longest leftmost run of zeros (`[2001:db8::ff00:42:8329]`, `[::1]`) and IPv4-mapped IPv6 normalization.
- **Origin Model**: Strict differentiation between `Tuple` (`scheme://host:port`) and `Opaque` (monotonic random nonces), with cross-origin serialization to `"null"`.
- **Mozilla PSL Scoping**: Full rule matching (Normal, Wildcard `*.`, Exception `!`) with ICANN vs Private tenant isolation (e.g. `foo.github.io` cannot share state with `bar.github.io`).
- **Redirect State Machine (`RedirectInfo`)**: Deterministic pure function transitions per RFC 9110 and WHATWG Fetch §4.5:
  - Method mutation: `POST` -> `GET` on 301/302, non-GET/HEAD -> `GET` on 303 (with payload header stripping: `Content-Type`, `Content-Length`, `Transfer-Encoding`).
  - Method preservation: `POST` stays `POST` on 307/308 with body preservation.
  - Sensitive header stripping: Purges `Authorization`, `X-API-Key`, `X-Auth-Token`, `X-Access-Token` on cross-origin hops or HTTPS -> HTTP downgrades (defending against CVE-2024-1968, CVE-2026-55553, CVE-2026-64684).
  - Cookie stripping: Outgoing `Cookie` header is unconditionally stripped before every redirect hop to prevent session hijacking across domains (CVE-2023-45143).
  - Monotonic chain tainting: Any cross-site hop permanently marks `had_cross_site_hop` to prevent SameSite bypasses.

### 4. Client Session & Security Orchestration (`app/`)

Unified HTTP client ergonomics and defense-in-depth pipeline:

- **6-Phase Execution Pipeline**: Executes requests over `CanonicalCookieJar` with automatic SameSite context evaluation, fresh cookie header synthesis, response Set-Cookie ingestion before 3xx handling, and hop sanitization.
- **BodyRewind Engine**: Implements the Go `Request.GetBody` pattern: rewindable buffered bodies are seamlessly resent on 307/308 redirects, while unrewindable streams fail cleanly with `RedirectError.UnrewindableBodyStream`.
- **3-Tier SSRF & DNS Rebinding Guard**:
  - Tier 1: Hostname validation against loopback (`127.0.0.1`, `[::1]`, `localhost`).
  - Tier 2: IP subnet blacklisting against RFC 1918 private addresses (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local, and cloud metadata services (`169.254.169.254`).
  - Tier 3: DNS Rebinding sweep over all resolved socket IPs before network connection.
  - Dangerous service port filtering (SSH, Redis, SMTP, etc.).
- **Browser Profiles**: Preconfigured header baselines (`User-Agent`, `Accept`, `Sec-CH-UA`, `Sec-Fetch-*`) simulating Chrome 131, Firefox 133, Safari 18, and cURL.

### 5. Testing Framework (`core/test.goose`)

A standalone test library designed for Goose:

- **Assertions**: `assert_eq`, `assert_bytes_eq`, `assert_struct_eq`, `assert_true`, `assert_in_delta`, `assert_contains`, plus terminating `require_*` variants.
- **Virtual Mock Clock**: `new_mock_clock(initial_us)` for time-travel testing with `advance_sec`, `advance_ms`, and `advance_days`.
- **Property Fuzzer**: Zero-allocation Xorshift64* PRNG (`new_fuzz_rng`) for randomized invariant testing.

## Usage Examples

### Unified HTTP Client Session

```goose
import std;
import wing from "..";

struct OrderPayload {
    symbol: const u8[:] = "BTC-USDT",
    amount: f64 = 0.5,
}

struct OrderResponse {
    order_id: i64 = 0,
    status: u8[..32] = [],
}

fn main() {
    var session = wing::new_session("https://api.exchange.io") { sess =>
        sess.set_profile(wing::Profile.Chrome131);
        sess.set_proxy("socks5://127.0.0.1:1080");
        sess.set_timeout_ms(5000);
        sess.default_header("Accept", "application/json");
    };

    let order = OrderPayload { symbol: "BTC-USDT", amount: 1.25 };

    let res, err = session.post("/v1/orders") { req =>
        req.bearer("jwt-auth-token-xyz");
        req.query("dry_run", "false");
        req.json(order);
    };

    guard err.ok() && res.is_success() else {
        print("Order failed: ", err.message);
        return;
    }

    var resp = OrderResponse { .. };
    if res.json(resp).ok() {
        print("Order created: id=", resp.order_id, " status=", resp.status);
    }
}
```

### Canonical Cookie Engine

```goose
import wing;

fn handle_incoming_cookies() {
    var jar = wing::new_canonical_cookie_jar();
    let clock = wing::new_mock_clock();

    // Ingest Set-Cookie headers with security context
    jar.set_cookie_header(
        "https://api.crypto-dex.io/v1",
        "auth_token=secret; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600",
        clock.now_us
    );

    // Build standalone cookies via builder pattern
    var custom = wing::new_canonical_cookie("theme", "dark");
    custom.with_domain("crypto-dex.io")
          .with_path("/")
          .with_secure();
    jar.set(custom, clock.now_us);

    // Generate RFC 6265 §5.4 Cookie header for an outbound request
    var header_buf: u8[>..] = [];
    jar.get_canonical_cookies_for_request(
        "https://api.crypto-dex.io/v1/orders",
        clock.now_us,
        header_buf,
        true,  // is_same_site
        true,  // is_top_level_navigation
        true   // is_safe_method (GET/HEAD)
    );

    print("Outbound Cookie: ", header_buf);
}
```

### Calendar Math & Deadlines

```goose
import wing;

fn run_time_example() {
    // Parse ISO 8601 / RFC 3339 timestamps
    let parsed_time, ok = wing::parse_rfc3339("2026-10-23T14:30:00Z");
    guard ok else { return; }

    // Civil calendar projections
    let year = parsed_time.year();       // 2026
    let month = parsed_time.month();     // October
    let is_leap = parsed_time.leap_year(); // false

    // Go-compatible duration parsing
    let dur, dur_ok = wing::parse_duration("2h45m30s");

    // Monotonic deadlines with anti-overflow protection
    let deadline = wing::deadline_after(wing::secs(10));
    if !deadline.is_expired() {
        let remaining_dur = deadline.remaining();
        print("Remaining seconds: ", remaining_dur.seconds());
    }
}
```

### File URLs & Fluent Path Chaining

```goose
import wing;

fn run_file_url_example() {
    // Construct normalized file URL from native Windows path (spaces -> %20)
    let project_dir = wing::new_file_url("C:\\Users\\senya\\My Projects");

    // Fluent UFCS method chaining for subpaths and extensions
    let binary_url = project_dir.appending("build")
                                .appending("release")
                                .appending("goose-server")
                                .appending_path_extension("exe");

    // Path component inspection (Swift Foundation style)
    let filename = binary_url.last_path_component(); // "goose-server.exe"
    let file_ext = binary_url.path_extension();      // "exe"

    // Navigate to parent directory
    let parent_dir = binary_url.deleting_last_path_component(); // file:///C:/Users/senya/My%20Projects/build/release/

    // Extract native OS path for system calls (replaces / with \, decodes %20)
    var native_path: u8[..256] = [];
    if binary_url.file_path(native_path) {
        print("Ready for OS exec: ", native_path); // "C:\Users\user\My Projects\build\release\goose-server.exe"
    }
}
```

## Verification & Test Suite

The test suite covers full RFC specifications, Chromium edge cases, audit regressions, and property-based randomized testing across **2,150+ checks**:

### Test Taxonomy

All verification suites live in `tests/` and adhere to a strict, scalable `<subsystem>_<topic>_test.goose` convention:

| Subsystem Prefix | Scope & Responsibilities | Example Files |
|---|---|---|
| `core_*` | Core runtime primitives (time, calendar, URL, sync, concurrency, actors) | `core_time_test.goose`, `core_url_test.goose`, `core_sync_test.goose` |
| `cookie_*` | RFC 6265bis engine, WPT clean-room compliance, and 1..16 edge vectors | `cookie_engine_test.goose`, `cookie_vectors_test.goose` |
| `app_*` | Client session pipelines, redirect FSM, profiles, request/response | `app_session_test.goose` |
| `sec_*` | Security regressions, CVE validations, threat model assertions | `sec_cve_test.goose`, `sec_protocol_test.goose`, `sec_cookie_test.goose`, `sec_concurrency_test.goose` |
| *Future: `proto_*`* | Wire protocols (HTTP/1.1, HTTP/2, HTTP/3, QUIC, WebSocket) | `proto_h1_test.goose`, `proto_h2_test.goose`, `proto_quic_test.goose` |
| *Future: `compress_*`* | Compression codecs (Deflate/zlib, Brotli, Zstandard) | `compress_zstd_test.goose`, `compress_brotli_test.goose` |
| *Future: `cache_*`* | RFC 9111 HTTP caching engine & revalidation | `cache_engine_test.goose` |

### Suite Breakdown

| Test Suite | File | Focus Areas | Checks |
|---|---|---|---|
| **Core Time & Calendar** | `tests/core_time_test.goose` | Hinnant calendar math, leap years, ReDoS protection, RFC 3339, RFC 9110 HTTP-date | 334 checks |
| **Core WHATWG URL** | `tests/core_url_test.goose` | WHATWG URL, IPv6 RFC 5952, Swift File URLs & Path API, dual-mode resolution, UrlView zero-copy | 357 checks |
| **Core Concurrency** | `tests/core_sync_test.goose` | BatonMutex, Semaphore, CyclicBarrier, CSP patterns, Actors, OTP supervision trees | 68 checks |
| **Clean Room Cookie Jar** | `tests/cookie_engine_test.goose` | WPT compliance, domain quotas, eviction ordering, persistence keys | 78 checks |
| **Cookie Edge Matrices** | `tests/cookie_vectors_test.goose` | Matrices 1..16 (Lexer limits, CTL sweep, PSL, prefixes, SameSite, CHIPS, 6-round GC, SQLite v24, clock skew, PRNG fuzzer) | 1,113 checks |
| **App Client Session** | `tests/app_session_test.goose` | PSL tenant isolation, SiteForCookies, Redirect FSM, 6-Phase ClientSession, BodyRewind, SSRF Guard | 80 checks |
| **CVE Security Regression** | `tests/sec_cve_test.goose` | CVE-2021-28918/29922 (octal/hex IP SSRF), CVE-2024-24790 (RFC 6761 localhost), CVE-2023-26159 (CRLF headers), CVE-2022-27776 (port leaks), CVE-2023-27534 (URL/query ambiguity), CVE-2016-8616 (PSL import) | 35 checks |
| **Protocol Security** | `tests/sec_protocol_test.goose` | IPv4-mapped IPv6 SSRF defense, HTTPS->HTTP scheme downgrade header stripping, file URL drive normalization | 36 checks |
| **Cookie Chaos Defense** | `tests/sec_cookie_test.goose` | RFC 6265bis §5.6 cookie shadowing, case-insensitive prefixes (`__Host-`, `__Secure-`), Max-Age 400-day capping | 38 checks |
| **Concurrency Hardening** | `tests/sec_concurrency_test.goose` | WaitGroup capacity limits, bounded channel timeouts, worker crash containment & supervisor restarts | 18 checks |
| **Total** | **10 verification suites** | | **2,157 checks** |

### Running the Tests

To typecheck the entire library and run verification suites:

```powershell
# Typecheck and compilation validation
goose check wing.goose

# Run individual test suites via compilation (supports threads & JIT)
goose build -o tests/core_time_test.exe tests/core_time_test.goose; .\tests\core_time_test.exe
goose build -o tests/core_url_test.exe tests/core_url_test.goose; .\tests\core_url_test.exe
goose build -o tests/cookie_engine_test.exe tests/cookie_engine_test.goose; .\tests\cookie_engine_test.exe
goose build -o tests/cookie_vectors_test.exe tests/cookie_vectors_test.goose; .\tests\cookie_vectors_test.exe
goose build -o tests/app_session_test.exe tests/app_session_test.goose; .\tests\app_session_test.exe
goose build -o tests/sec_cve_test.exe tests/sec_cve_test.goose; .\tests\sec_cve_test.exe

# Or run all 10 suites via automated script
.\scripts\test_all.ps1

# Run end-to-end demonstrations
goose run examples/unified_demo.goose
goose run examples/cookie_demo.goose
goose run examples/time_demo.goose
```

## Design Principles

- **Zero Hidden Allocations**: Core structs use bounded fixed-capacity byte arrays (`u8[..N]`) for common headers, paths, and URLs, falling back to explicit dynamic vectors (`u8[>..]`) only for long-lived payload bodies.
- **Deterministic Clocks**: Time-dependent logic accepts an explicit microsecond timestamp (`now_us`), allowing comprehensive time-travel testing via `MockClock` without real system sleep calls.
- **Standard Conformance**: Strict alignment with RFC 6265bis, RFC 9110, and Chromium CookieMonster implementation details rather than loose interpretations.
- **Idiomatic Goose DX**: Uniform Function Call Syntax (UFCS) support throughout, allowing both `jar.get(...)` and `wing::get(jar, ...)`.

## License

Apache License, Version 2.0. See `LICENSE` for details.
