# `http/cache`

Zero-allocation RFC 9111 HTTP caching engine, freshness evaluation model, and storage coordinator.

## Public API

### Cache-Control Directives (`cache_control.goose`)

- **`struct CacheControl`**: Parsed representation of RFC 9111 §5.2 and RFC 5861 Cache-Control directives with 32-bit bitmask flags and delta-seconds clamping.
- **`fn parse_cache_control(val: const u8[:], out: CacheControl&) -> bool`**: Parses a raw Cache-Control header value into a typed struct.
- **`fn parse_cache_control_headers(headers: const HeaderMap&, out: CacheControl&) -> bool`**: Aggregates all Cache-Control headers from a `HeaderMap`.
- **`fn has_flag(cc: const CacheControl&, flag: u32) -> bool`**: Checks if a specific bitmask flag is set.
- **`fn is_no_store(cc: const CacheControl&) -> bool`**: Returns true if `no-store` is active.
- **`fn is_no_cache(cc: const CacheControl&) -> bool`**: Returns true if `no-cache` is active.
- **`fn is_must_revalidate(cc: const CacheControl&) -> bool`**: Returns true if `must-revalidate` is active.
- **`fn is_proxy_revalidate(cc: const CacheControl&) -> bool`**: Returns true if `proxy-revalidate` is active.
- **`fn is_must_understand(cc: const CacheControl&) -> bool`**: Returns true if `must-understand` (RFC 9111 §5.2.2.3) is active.
- **`fn is_private(cc: const CacheControl&) -> bool`**: Returns true if `private` is active.
- **`fn is_public(cc: const CacheControl&) -> bool`**: Returns true if `public` is active.
- **`fn is_immutable(cc: const CacheControl&) -> bool`**: Returns true if `immutable` (RFC 8246) is active.
- **`fn is_only_if_cached(cc: const CacheControl&) -> bool`**: Returns true if `only-if-cached` is active.
- **`fn is_no_transform(cc: const CacheControl&) -> bool`**: Returns true if `no-transform` is active.

### Freshness & Clock Skew Model (`freshness.goose`)

- **`struct CacheTimestamps`**: Monotonic and wall-clock timestamps captured across the request/response lifecycle.
- **`fn new_cache_timestamps(req_time: core::Time, resp_time: core::Time, cur_now: core::Time) -> CacheTimestamps`**: Constructs timestamps with wall-clock times.
- **`fn with_monotonic(ts: CacheTimestamps, req_mono: core::MonotonicInstant, resp_mono: core::MonotonicInstant, cur_mono: core::MonotonicInstant) -> CacheTimestamps`**: Attaches monotonic clock checkpoints.
- **`struct FreshnessMetrics`**: Evaluated age, freshness lifetime, and stale-while-revalidate/stale-if-error margins.
- **`fn compute_apparent_age(resp_date: core::Time, resp_time: core::Time) -> i64`**: Calculates RFC 9111 §4.2.1 apparent age.
- **`fn compute_response_delay(req_time: core::Time, resp_time: core::Time) -> i64`**: Calculates round-trip response delay.
- **`fn compute_corrected_initial_age(apparent_age: i64, age_val_sec: i64, delay_sec: i64) -> i64`**: Computes corrected initial age.
- **`fn compute_resident_time(resp_time: core::Time, now: core::Time) -> i64`**: Calculates time resident in cache.
- **`fn compute_current_age(initial_age: i64, resident_time: i64) -> i64`**: Calculates RFC 9111 current age.
- **`fn compute_freshness_lifetime(resp_cc: const CacheControl&, req_cc: const CacheControl&, date_time: core::Time, expires_time: core::Time, is_shared: bool) -> i64`**: Resolves freshness lifetime across hierarchical directives.
- **`fn evaluate_freshness(resp_headers: const HeaderMap&, resp_cc: const CacheControl&, req_cc: const CacheControl&, ts: const CacheTimestamps&, is_shared: bool) -> FreshnessMetrics`**: Executes complete RFC 9111 freshness evaluation.

### Validators & Vary Engine (`validators.goose`)

- **`struct EntityTag`**: Parsed ETag with weak/strong flag and opaque ASCII token (RFC 9110 §8.8.3).
- **`fn parse_etag(raw: const u8[:]) -> EntityTag`**: Parses raw ETag header value into typed `EntityTag`.
- **`fn weak_eq(a: EntityTag, b: EntityTag) -> bool`**: Performs weak comparison (RFC 9110 §8.8.3.2).
- **`fn strong_eq(a: EntityTag, b: EntityTag) -> bool`**: Performs strong comparison (RFC 9110 §8.8.3.2).
- **`fn matches_if_none_match(header_val: const u8[:], current_etag: EntityTag) -> bool`**: Evaluates If-None-Match condition.
- **`fn matches_if_match(header_val: const u8[:], current_etag: EntityTag) -> bool`**: Evaluates If-Match condition.
- **`fn matches_if_modified_since(ims_raw: const u8[:], last_modified: core::Time) -> bool`**: Evaluates If-Modified-Since timestamp condition.
- **`struct VarySnapshot`**: Recorded Vary request header snapshot defending against CVE-2026-93750.
- **`fn record_vary_snapshot(cached_vary_raw: const u8[:], req_headers: const HeaderMap&) -> VarySnapshot`**: Captures original request headers specified by Vary.
- **`fn matches_vary(snap: const VarySnapshot&, incoming_req_headers: const HeaderMap&) -> bool`**: Verifies incoming request against recorded Vary invariants.
- **`fn update_cached_headers_on_304(cached_headers: HeaderMap&, fresh_304_headers: const HeaderMap&)`**: Merges 304 response headers into cached entry.

### Cache Engine & Storage Coordinator (`engine.goose`)

- **`struct CacheOptions`**: Configuration options governing storage limits, heuristic TTL, and shared vs private mode.
- **`struct CachedEntry`**: Cached HTTP representation with headers, body, Vary snapshot, and LRU eviction links.
- **`enum CacheLookupResult`**: Lookup classification (`FreshHit`, `StaleRevalidate`, `StaleWhileRevalidate`, `StaleIfError`, `Miss`, `Bypass`).
- **`struct HttpCache`**: Fixed-capacity, zero-allocation LRU cache store.
- **`fn new_http_cache(opts: CacheOptions = CacheOptions { .. }) -> HttpCache`**: Constructs a new cache store.
- **`fn lookup_cache(cache: HttpCache&, req: const Request&, now: core::Time, out_entry: CachedEntry&, out_metrics: FreshnessMetrics&) -> CacheLookupResult`**: Looks up and evaluates cached representation.
- **`fn store_response(cache: HttpCache&, req: const Request&, res: const Response&, timestamps: const CacheTimestamps&) -> bool`**: Sanitizes and stores response in cache.
- **`fn handle_revalidation_response(cache: HttpCache&, req: const Request&, res: const Response&, timestamps: const CacheTimestamps&, entry_idx: i64) -> bool`**: Updates cached entry on 304 Not Modified.
- **`fn invalidate_url(cache: HttpCache&, url: const u8[:])`**: Explicitly invalidates a URL from the cache.
- **`fn invalidate_for_unsafe_method(cache: HttpCache&, req: const Request&, res: const Response&)`**: Cascade-invalidates cache on unsafe HTTP methods (POST, PUT, DELETE, PATCH).
