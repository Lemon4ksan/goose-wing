# goose-wing

An HTTP client stack, zero-allocation time primitives, and Chromium-grade CookieMonster implementation for the [Goose](https://github.com/goose-lang/goose) programming language.

`goose-wing` provides application-layer networking components designed around Goose's memory model: bounded inline storage, explicit growth vectors, UFCS ergonomics, and zero unexpected runtime allocations.

## Overview

The library is organized into four architectural layers:

1. **`core/time.goose`**: Nanosecond-precision calendar and monotonic time engine based on Howard Hinnant's civil calendar algorithms. Includes RFC 3339, RFC 9110 HTTP-Date codecs, Go-compatible `parse_duration`, monotonic `Stopwatch`, and anti-overflow `Deadline`.
2. **`cookie/`**: Clean-room implementation of Chromium's `net::CookieMonster` adhering to RFC 6265, RFC 6265bis, the Layered Cookies draft, CHIPS (partitioned cookies), and Public Suffix List rules.
3. **`core/url.goose` & `app/redirect.goose`**: WHATWG URL parser with continuous memory buffer, RFC 5952 IPv6 zero-run compression, `Origin` model (`Tuple` vs `Opaque`), and a deterministic HTTP Redirect State Machine (`net::RedirectInfo`) defending against CVE-2023-45143, CVE-2024-1968, CVE-2026-55553, and CVE-2026-64684.
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

### 3. WHATWG URL, PSL & Redirect FSM (`core/url.goose`, `app/redirect.goose`)

Browser-grade URL parsing, origin isolation, and redirect state machine:

- **WHATWG URL Parser**: Single continuous byte buffer with compact offset indices (ada-url / sorug pattern), default port stripping, dot-segment collapsing (`/a/b/../c` -> `/a/c`), and relative base resolution.
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

## Verification & Test Suite

The test suite covers full RFC specifications, Chromium edge cases, and property-based randomized testing:

| Test Suite | File | Focus Areas | Checks |
|---|---|---|---|
| **Session & URL Suite** | `tests/session_suite.goose` | WHATWG URL, IPv6 RFC 5952, PSL tenant isolation, SiteForCookies, Redirect FSM, 6-Phase ClientSession, BodyRewind, 3-tier SSRF | 117 checks |
| **Cookie Vectors** | `tests/max_cookie_vectors.goose` | Matrices 1..16 (Lexer limits, CTL sweep, PSL, prefixes, SameSite, CHIPS, 6-round GC, SQLite v24, clock skew, PRNG fuzzer) | 1,126 checks |
| **Clean Room Suite** | `tests/cookie_suite.goose` | WPT compliance, domain quotas, eviction ordering, persistence keys | 78 checks |
| **Time & Calendar** | `tests/time_suite.goose` | Hinnant calendar math, leap years, ReDoS protection, RFC 3339, RFC 9110 | 334 checks |

### Running the Tests

To verify syntax and run the verification suites:

```powershell
# Typecheck and compilation validation
goose check wing.goose

# Run Client Session verification suite (URL, Redirect FSM, SiteForCookies, SSRF Guard)
goose run tests/session_suite.goose

# Run core cookie verification matrices (14 test modules, 1,126 checks)
goose run tests/max_cookie_vectors.goose

# Run Clean Room CookieMonster test suite
goose run tests/cookie_suite.goose

# Run standard time & calendar test suite
goose run tests/time_suite.goose

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
