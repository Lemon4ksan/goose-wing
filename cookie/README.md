# Cookie Engine & Storage Subsystem (cookie)

## Overview
RFC 6265bis and CHIPS (Cookies Having Independent Partitioned State) compliant cookie engine. Provides zero-copy cookie parsing, Mozilla Public Suffix List (PSL) domain scoping, Schemeful Same-Site policy evaluation, 6-round priority-based garbage collection, and persistent store serialization.

## Public API

### Canonical Cookie Model (RFC 6265bis)
- **`struct CanonicalCookie`**: Fully normalized cookie record (`name`, `value`, `encrypted_value`, `domain`, `path`, `creation_utc`, `last_access_utc`, `last_update_utc`, `expires_utc`, `partition_key`, `source_port`, `host_only`, `has_domain_attr`, `has_path_attr`, `persistent`, `secure`, `httponly`, `partitioned`, `same_site`, `priority`, `source_scheme`, `creation_seq`).
- **`enum CookieSameSite`**: SameSite enforcement tiers (`Default`, `Lax`, `Strict`, `None`, `Unknown`).
- **`enum CookiePriority`**: Eviction priority tiers (`Low`, `Medium`, `High`, `Unknown`).
- **`enum CookieSourceScheme`**: Scheme provenance tracking (`Unset`, `NonSecure`, `Secure`).
- **`fn matches_domain(cookie: const CanonicalCookie&, host: const u8[:]) -> bool`**: Domain-matching per RFC 6265 §5.1.3 and IP exact-matching per RFC 6055.
- **`fn matches_path(cookie: const CanonicalCookie&, req_path: const u8[:]) -> bool`**: Path-matching per RFC 6265 §5.1.4.
- **`fn is_expired(cookie: const CanonicalCookie&, now_us: i64) -> bool`**: Verifies expiry against microsecond epoch timestamp.

### Cookie Jar Engine (RFC 6265)
- **`struct CanonicalCookieJar`**: In-memory cookie jar managing storage, eviction, and query sorting.
- **`fn set_canonical_cookie(jar: CanonicalCookieJar&, new_cookie: CanonicalCookie&, opts: CookieSourceOptions, now_us: i64) -> bool`**: Ingests and stores a cookie, enforcing domain quotas and collision rules.
- **`fn set_cookie_header(jar: CanonicalCookieJar&, req_url: const u8[:], set_cookie_raw: const u8[:], now_us: i64, is_http_api: bool = true, partition_key: const u8[:] = "") -> bool`**: High-level helper parsing and storing an incoming `Set-Cookie` header.
- **`fn get_canonical_cookies_for_request(jar: CanonicalCookieJar&, req_url: const u8[:], is_http_api: bool, partition_key: const u8[:], now_us: i64, out: CanonicalCookie[>..]&, access: CookieAccessOptions = CookieAccessOptions { .. })`**: Queries cookies matching the request, sorted per RFC 6265 §5.4 (longest path first, then earliest creation time).
- **`fn build_cookie_header<B>(jar: CanonicalCookieJar&, out: B&, host: const u8[:], path: const u8[:], is_secure: bool, now_us: i64)`**: Formats an outgoing `Cookie: name=value; ...` header.
- **`fn delete_session_cookies(jar: CanonicalCookieJar&, purge_non_secure: bool = false) -> i64`**: Evicts non-persistent session cookies.
- **`fn purge_expired(jar: CanonicalCookieJar&, now_us: i64) -> i64`**: Sweeps and removes all expired cookies.

### Set-Cookie Parser (RFC 6265bis §5.5)
- **`fn parse_canonical_set_cookie(header_val: const u8[:], default_domain: const u8[:], default_path: const u8[:], now_us: i64) -> CanonicalCookie, CookieDeleteCause, bool`**: Zero-allocation parser validating name-value tokens, attribute syntax, and control characters (CTL).
- **`fn parse_canonical_cookie_url(raw_url: const u8[:]) -> CookieUrl`**: Deconstructs target URL into canonical components for domain and path scoping.

### Policy & SameSite Evaluation (RFC 6265bis)
- **`enum SameSiteContextType`**: Request context rating (`CrossSite`, `SameSiteLaxMethodUnsafe`, `SameSiteLax`, `SameSiteStrict`).
- **`struct SameSiteCookieContext`**: Context metadata (`context_type`, `schemefully_same`, `is_reload`, `had_cross_site_hop`).
- **`struct SiteForCookies`**: First-party site context for ancestor frame hierarchy validation.
- **`fn site_for_cookies_from_url(url: const u8[:]) -> SiteForCookies`**: Computes site-for-cookies from URL string.
- **`fn compute_site_for_cookies_with_ancestors(top_url: const u8[:], ancestor_urls: const u8[:][:], is_sandboxed: bool = false) -> SiteForCookies`**: Computes site-for-cookies context evaluating ancestor frame chain.
- **`fn validate_security_cookie_prefixes(cookie_val: const CanonicalCookie&, cookie_name: const u8[:], opts: CookieSourceOptions) -> bool`**: Enforces strict prefix invariants:
  - `__Secure-`: Requires `Secure` flag and secure URL.
  - `__Host-`: Requires `Secure` flag, secure URL, `host_only = true` (no Domain attribute), and `path = "/"`.
  - `__Http-`: Requires `is_http_api`, `Secure` flag, secure URL, and `HttpOnly`.
  - `__Host-Http-`: Combines `__Host-` and `__Http-` requirements.

### Mozilla Public Suffix List (PSL)
- **`struct PslDatabase`**: Public Suffix List rule database and DAFSA graph evaluator.
- **`fn find_public_suffix<B>(db: const PslDatabase&, domain: const u8[:], out: B&) -> bool, bool`**: Finds effective public suffix (eTLD) and returns `(found, is_exception)`.
- **`fn extract_etld_plus_one<B>(db: const PslDatabase&, host: const u8[:], out: B&)`**: Computes registrable domain (eTLD+1).
- **`fn is_public_suffix(db: const PslDatabase&, domain: const u8[:], is_icann_only: bool = false) -> bool`**: Checks if domain is a public suffix.
- **`fn cookie_domain_match(host: const u8[:], cookie_domain: const u8[:]) -> bool`**: Domain-matching per RFC 6265 §5.1.3 and IP exact-matching per RFC 6055.
- **`fn cookie_path_match(req_path: const u8[:], cookie_path: const u8[:]) -> bool`**: Path-matching per RFC 6265 §5.1.4.

### Persistence & Storage
- **`fn import_netscape(jar: CanonicalCookieJar&, content: const u8[:], now_us: i64) -> i64`**: Imports cookies from standard Netscape/cURL `cookies.txt` format.
- **`fn export_netscape<B>(jar: const CanonicalCookieJar&, now_us: i64, out: B&)`**: Serializes active cookies to Netscape format.
- **`fn import_json(jar: CanonicalCookieJar&, json_bytes: const u8[:]) -> i64`**: Deserializes cookies from JSON format.
- **`fn export_json<B>(jar: const CanonicalCookieJar&, out: B&)`**: Serializes cookies to JSON format.

## Invariants
- **RFC 6265 §5.4 Sorting**: Query results are ordered by longest path length descending, then earliest `creation_utc` ascending.
- **400-day Max-Age cap**: Cookie lifetimes are capped at 400 days (34,560,000 seconds) per RFC 6265bis Section 5.5.
- **Control character rejection**: Header values containing any of the 33 ASCII control characters (`0x00..0x1F`, `0x7F`) are strictly rejected.
- **CHIPS memory quota**: Partitioned cookies are bounded by a 10 KB quota per partition-key/domain pair.
- **Prefix enforcement**: `__Secure-`, `__Host-`, `__Http-`, and `__Host-Http-` prefixes are enforced case-insensitively.

## Verification
- Cookie engine test suite: `python tools/test_runner.py -p "*cookie*"`
- Full typecheck: `python tools/test_runner.py --check-only`
- Invariant audit: `python scripts/lint_invariants.py --target-file cookie/engine.goose --strict-examples`
