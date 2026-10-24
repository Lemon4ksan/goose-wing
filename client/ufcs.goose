// Global UFCS bridges for method-call syntax across namespaces.
namespace wing;

// ---- session ufcs bridges --------------------------------------------------

fn ::set_base_url(session: wing::Session&, url: const u8[:]) { wing::set_base_url(session, url); }
fn ::set_profile(session: wing::Session&, profile: wing::Profile) { wing::set_profile(session, profile); }
fn ::set_profile(session: wing::Session&, profile: const wing::BrowserProfile&) { wing::set_profile(session, profile); }
fn ::set_user_agent(session: wing::Session&, ua: const u8[:]) { wing::set_user_agent(session, ua); }
fn ::set_user_agent(profile: wing::BrowserProfile&, ua: const u8[:]) { wing::set_user_agent(profile, ua); }
fn ::set_accept(profile: wing::BrowserProfile&, accept_str: const u8[:]) { wing::set_accept(profile, accept_str); }
fn ::set_accept_encoding(profile: wing::BrowserProfile&, enc: const u8[:]) { wing::set_accept_encoding(profile, enc); }
fn ::set_accept_language(profile: wing::BrowserProfile&, lang: const u8[:]) { wing::set_accept_language(profile, lang); }
fn ::set_header(profile: wing::BrowserProfile&, name: const u8[:], value: const u8[:]) { wing::set_header(profile, name, value); }
fn ::user_agent(session: const wing::Session&) -> const u8[:] { return wing::user_agent(session); }
fn ::ja4(session: const wing::Session&, is_quic: bool = false, sni: bool = true) -> u8[..64] { return wing::session_ja4(session, is_quic, sni); }
fn ::set_proxy(session: wing::Session&, proxy_url: const u8[:]) { wing::set_proxy(session, proxy_url); }
fn ::set_timeout_ms(session: wing::Session&, timeout_millis: i64) { wing::set_timeout_ms(session, timeout_millis); }
fn ::set_cookie(session: wing::Session&, name: const u8[:], value: const u8[:]) { wing::set_cookie(session, name, value); }
fn ::cookie(session: const wing::Session&, name: const u8[:]) -> const u8[:] { return wing::cookie(session, name); }
fn ::default_header(session: wing::Session&, name: const u8[:], value: const u8[:]) { wing::default_header(session, name, value); }

fn ::do(session: wing::Session&, req: const wing::Request&) -> wing::Response, wing::Error {
    return wing::do(session, req);
}

fn ::do<BuilderFn: fn(wing::Request&)>(session: wing::Session&, req: const wing::Request&) -> wing::Response, wing::Error {
    return wing::do(session, req, BuilderFn);
}

fn ::get(session: wing::Session&, url: const u8[:]) -> wing::Response, wing::Error {
    return wing::get(session, url);
}

fn ::get<BuilderFn: fn(wing::Request&)>(session: wing::Session&, url: const u8[:]) -> wing::Response, wing::Error {
    return wing::get(session, url, BuilderFn);
}

fn ::post<BuilderFn: fn(wing::Request&)>(session: wing::Session&, url: const u8[:]) -> wing::Response, wing::Error {
    return wing::post(session, url, BuilderFn);
}

fn ::post_json<T>(session: wing::Session&, url: const u8[:], payload: const T&) -> wing::Response, wing::Error {
    return wing::post_json(session, url, payload);
}

fn ::put<BuilderFn: fn(wing::Request&)>(session: wing::Session&, url: const u8[:]) -> wing::Response, wing::Error {
    return wing::put(session, url, BuilderFn);
}

fn ::put_json<T>(session: wing::Session&, url: const u8[:], payload: const T&) -> wing::Response, wing::Error {
    return wing::put_json(session, url, payload);
}

fn ::delete(session: wing::Session&, url: const u8[:]) -> wing::Response, wing::Error {
    return wing::delete(session, url);
}

fn ::delete<BuilderFn: fn(wing::Request&)>(session: wing::Session&, url: const u8[:]) -> wing::Response, wing::Error {
    return wing::delete(session, url, BuilderFn);
}

// ---- request ufcs bridges --------------------------------------------------

fn ::header(req: wing::Request&, name: const u8[:], value: const u8[:]) { wing::header(req, name, value); }
fn ::set_header(req: wing::Request&, name: const u8[:], value: const u8[:]) { wing::set_header(req, name, value); }
fn ::bearer(req: wing::Request&, token: const u8[:]) { wing::bearer(req, token); }
fn ::set_bearer(req: wing::Request&, token: const u8[:]) { wing::set_bearer(req, token); }
fn ::query(req: wing::Request&, key: const u8[:], value: const u8[:]) { wing::query(req, key, value); }
fn ::set_query(req: wing::Request&, key: const u8[:], value: const u8[:]) { wing::set_query(req, key, value); }
fn ::timeout_ms(req: wing::Request&, timeout_millis: i64) { wing::timeout_ms(req, timeout_millis); }
fn ::set_timeout_ms(req: wing::Request&, timeout_millis: i64) { wing::set_timeout_ms(req, timeout_millis); }
fn ::text(req: wing::Request&, body_str: const u8[:]) { wing::text(req, body_str); }
fn ::raw_json(req: wing::Request&, json_str: const u8[:]) { wing::raw_json(req, json_str); }
fn ::json<T>(req: wing::Request&, payload: const T&) { wing::json(req, payload); }
fn ::set_json<T>(req: wing::Request&, payload: const T&) { wing::set_json(req, payload); }

// ---- response & error ufcs bridges -----------------------------------------

fn ::ok(err: const wing::Error&) -> bool { return wing::ok(err); }
fn ::is_success(res: const wing::Response&) -> bool { return wing::is_success(res); }
fn ::is_redirect(res: const wing::Response&) -> bool { return wing::is_redirect(res); }
fn ::header(res: const wing::Response&, name: const u8[:]) -> const u8[:] { return wing::header(res, name); }
fn ::text(res: const wing::Response&) -> const u8[:] { return wing::text(res); }
fn ::decode_body(res: wing::Response&) -> bool { return wing::decode_body(res); }
fn ::json<T>(res: const wing::Response&, out: T&) -> wing::Error { return wing::json(res, out); }
fn ::decode_json<T>(res: const wing::Response&) -> T, wing::Error { return wing::decode_json<T>(res); }

// Policy Bridges (Backoff & RateLimiter)

fn ::delay(backoff: const wing::Backoff&, attempt: i64) -> core::Duration { return wing::delay(backoff, attempt); }
fn ::allow(limiter: wing::RateLimiter&) -> bool { return wing::allow(limiter); }

// ---- cookie & cookie jar ufcs bridges --------------------------------------

fn ::add(jar: wing::CanonicalCookieJar&, name: const u8[:], val: const u8[:]) -> wing::CanonicalCookie& {
    return wing::add(jar, name, val);
}

fn ::with_domain(cookie_val: wing::CanonicalCookie&, domain_val: const u8[:], host_only: bool = false) -> wing::CanonicalCookie& {
    return wing::with_domain(cookie_val, domain_val, host_only);
}

fn ::with_host(cookie_val: wing::CanonicalCookie&, host_val: const u8[:]) -> wing::CanonicalCookie& {
    return wing::with_host(cookie_val, host_val);
}

fn ::with_path(cookie_val: wing::CanonicalCookie&, path_val: const u8[:]) -> wing::CanonicalCookie& {
    return wing::with_path(cookie_val, path_val);
}

fn ::with_secure(cookie_val: wing::CanonicalCookie&, secure_flag: bool = true) -> wing::CanonicalCookie& {
    return wing::with_secure(cookie_val, secure_flag);
}

fn ::with_http_only(cookie_val: wing::CanonicalCookie&, http_only_flag: bool = true) -> wing::CanonicalCookie& {
    return wing::with_http_only(cookie_val, http_only_flag);
}

fn ::with_same_site(cookie_val: wing::CanonicalCookie&, same_site_mode: wing::CookieSameSite) -> wing::CanonicalCookie& {
    return wing::with_same_site(cookie_val, same_site_mode);
}

fn ::with_priority(cookie_val: wing::CanonicalCookie&, priority_level: wing::CookiePriority) -> wing::CanonicalCookie& {
    return wing::with_priority(cookie_val, priority_level);
}

fn ::with_max_age_seconds(cookie_val: wing::CanonicalCookie&, seconds: i64, now_us: i64) -> wing::CanonicalCookie& {
    return wing::with_max_age_seconds(cookie_val, seconds, now_us);
}

fn ::with_expires_utc(cookie_val: wing::CanonicalCookie&, expires_us: i64) -> wing::CanonicalCookie& {
    return wing::with_expires_utc(cookie_val, expires_us);
}

fn ::purge_expired(jar: wing::CanonicalCookieJar&, now_us: i64) -> i64 {
    return wing::purge_expired(jar, now_us);
}

fn ::build_cookie_header<B>(
    jar: wing::CanonicalCookieJar&,
    out: B&,
    host: const u8[:],
    path: const u8[:],
    is_secure: bool,
    now_us: i64
) {
    wing::build_cookie_header(jar, out, host, path, is_secure, now_us);
}

fn ::build_cookie_header<B>(
    jar: wing::CanonicalCookieJar&,
    req_url: const u8[:],
    out: B&,
    now_us: i64,
    partition_key: const u8[:] = ""
) {
    wing::build_cookie_header(jar, req_url, out, now_us, partition_key);
}

fn ::set_cookie_header(
    jar: wing::CanonicalCookieJar&,
    req_url: const u8[:],
    set_cookie_raw: const u8[:],
    now_us: i64,
    is_http_api: bool = true,
    partition_key: const u8[:] = ""
) -> bool {
    return wing::set_cookie_header(jar, req_url, set_cookie_raw, now_us, is_http_api, partition_key);
}

fn ::set(jar: wing::CanonicalCookieJar&, cookie_val: wing::CanonicalCookie, now_us: i64) -> bool {
    return wing::set(jar, cookie_val, now_us);
}

fn ::get(
    jar: wing::CanonicalCookieJar&,
    req_url: const u8[:],
    name: const u8[:],
    now_us: i64,
    is_same_site: bool = true,
    is_top_level_navigation: bool = true,
    is_safe_method: bool = true,
    partition_key: const u8[:] = ""
) -> const u8[:] {
    return wing::get(jar, req_url, name, now_us, is_same_site, is_top_level_navigation, is_safe_method, partition_key);
}

fn ::get(jar: const wing::CanonicalCookieJar&, name: const u8[:]) -> const u8[:] {
    return wing::get(jar, name);
}

fn ::export_netscape<B>(jar: const wing::CanonicalCookieJar&, out: B&) {
    wing::export_canonical_netscape(jar, out);
}

fn ::import_netscape(jar: wing::CanonicalCookieJar&, content: const u8[:], now_us: i64) -> i64 {
    return wing::import_canonical_netscape(jar, content, now_us);
}

fn ::export_json<B>(jar: const wing::CanonicalCookieJar&, out: B&) {
    wing::export_canonical_json(jar, out);
}

fn ::import_json(jar: wing::CanonicalCookieJar&, json_text: const u8[:], now_us: i64) -> i64 {
    return wing::import_canonical_json(jar, json_text, now_us);
}

// ---- http headers, mime, and multipart ufcs bridges -----------------------

fn ::has_header(map: const wing::HeaderMap&, name: const u8[:]) -> bool { return wing::has_header(map, name); }
fn ::get_header(map: const wing::HeaderMap&, name: const u8[:]) -> const u8[:] { return wing::get_header(map, name); }
fn ::header(map: const wing::HeaderMap&, name: const u8[:]) -> const u8[:] { return wing::get_header(map, name); }
fn ::get_inline(map: const wing::HeaderMap&, id: wing::WellKnownHeader) -> const u8[:] { return wing::get_inline(map, id); }
fn ::set_inline(map: wing::HeaderMap&, id: wing::WellKnownHeader, value: const u8[:]) -> bool { return wing::set_inline(map, id, value); }
fn ::insert_header(map: wing::HeaderMap&, name: const u8[:], value: const u8[:]) -> bool { return wing::insert_header(map, name, value); }
fn ::append_header(map: wing::HeaderMap&, name: const u8[:], value: const u8[:]) -> bool { return wing::append_header(map, name, value); }
fn ::remove_header(map: wing::HeaderMap&, name: const u8[:]) -> bool { return wing::remove_header(map, name); }
fn ::reset_for_keep_alive(map: wing::HeaderMap&) { wing::reset_for_keep_alive(map); }
fn ::get_combined(map: const wing::HeaderMap&, name: const u8[:], out: u8[>..]&) -> bool { return wing::get_combined(map, name, out); }
fn ::get_all_values(map: const wing::HeaderMap&, name: const u8[:], out_values: u8[..256][>..]&) { wing::get_all_values(map, name, out_values); }
fn ::get_set_cookie(map: const wing::HeaderMap&, out_cookies: u8[..1024][>..]&) { wing::get_set_cookie(map, out_cookies); }
fn ::raw_headers(map: const wing::HeaderMap&, out: u8[>..]&) { wing::raw_headers(map, out); }
fn ::serialize_headers(map: const wing::HeaderMap&, out: u8[>..]&) { wing::serialize_headers(map, out); }
fn ::merge_with_headers_304(cached: wing::HeaderMap&, response_304: const wing::HeaderMap&) { wing::merge_with_headers_304(cached, response_304); }
fn ::persist_headers(src: const wing::HeaderMap&, dst: wing::HeaderMap&, flags: u32) { wing::persist_headers(src, dst, flags); }

fn ::param(mt: const wing::MediaType&, key: const u8[:]) -> const u8[:] { return wing::param(mt, key); }
fn ::has_param(mt: const wing::MediaType&, key: const u8[:]) -> bool { return wing::has_param(mt, key); }
fn ::is_multipart(mt: const wing::MediaType&) -> bool { return wing::is_multipart(mt); }
fn ::boundary(mt: const wing::MediaType&) -> const u8[:] { return wing::boundary(mt); }
fn ::charset(mt: const wing::MediaType&) -> const u8[:] { return wing::charset(mt); }
fn ::parse_content_disposition(raw: const u8[:]) -> wing::MediaType, bool { return wing::parse_content_disposition(raw); }

// ---- security & server ufcs bridges ----------------------------------------

fn ::add_key(store: wing::KeyStore&, slot: wing::KeySlot) -> bool { return wing::add_key(store, slot); }
fn ::active_key(store: const wing::KeyStore&) -> wing::KeySlot, bool { return wing::active_key(store); }
fn ::find_key(store: const wing::KeyStore&, key_id: u32) -> wing::KeySlot, bool { return wing::find_key(store, key_id); }
fn ::revoke_key(store: wing::KeyStore&, key_id: u32) -> bool { return wing::revoke_key(store, key_id); }

fn ::add_trusted_origin(guard_cfg: wing::CrossOriginGuard&, origin_str: const u8[:]) -> bool { return wing::add_trusted_origin(guard_cfg, origin_str); }
fn ::add_exempt_path(guard_cfg: wing::CrossOriginGuard&, path_str: const u8[:]) -> bool { return wing::add_exempt_path(guard_cfg, path_str); }

fn ::add_allowed_origin(policy: wing::CorsPolicy&, origin_pattern: const u8[:]) -> bool { return wing::add_allowed_origin(policy, origin_pattern); }

fn ::add_route(router: wing::RadixRouter&, method: const u8[:], path: const u8[:], handler_id: i32, entries_mask: u32 = 0) -> bool {
    return wing::add_route(router, method, path, handler_id, entries_mask);
}
fn ::match_route(router: const wing::RadixRouter&, method: const u8[:], path: const u8[:], params: wing::ZeroAllocParams&) -> wing::RouteMatchResult {
    return wing::match_route(router, method, path, params);
}

fn ::acquire_header_map(pool: wing::HeaderMapPool&) -> i32 { return wing::acquire_header_map(pool); }
fn ::release_header_map(pool: wing::HeaderMapPool&, idx: i32) { wing::release_header_map(pool, idx); }
fn ::acquire_extensions(pool: wing::ExtensionsPool&) -> i32 { return wing::acquire_extensions(pool); }
fn ::release_extensions(pool: wing::ExtensionsPool&, idx: i32) { wing::release_extensions(pool, idx); }
fn ::check_connection_tick(timer: wing::ConnectionTimer&, now_ns: u64) -> bool { return wing::check_connection_tick(timer, now_ns); }

// ---- http cache ufcs bridges -----------------------------------------------

fn ::is_no_store(cc: const wing::CacheControl&) -> bool { return wing::is_no_store(cc); }
fn ::is_no_cache(cc: const wing::CacheControl&) -> bool { return wing::is_no_cache(cc); }
fn ::is_must_revalidate(cc: const wing::CacheControl&) -> bool { return wing::is_must_revalidate(cc); }
fn ::is_proxy_revalidate(cc: const wing::CacheControl&) -> bool { return wing::is_proxy_revalidate(cc); }
fn ::is_must_understand(cc: const wing::CacheControl&) -> bool { return wing::is_must_understand(cc); }
fn ::is_private(cc: const wing::CacheControl&) -> bool { return wing::is_private(cc); }
fn ::is_public(cc: const wing::CacheControl&) -> bool { return wing::is_public(cc); }
fn ::is_immutable(cc: const wing::CacheControl&) -> bool { return wing::is_immutable(cc); }
fn ::is_only_if_cached(cc: const wing::CacheControl&) -> bool { return wing::is_only_if_cached(cc); }
fn ::weak_eq(a: const wing::EntityTag&, b: const wing::EntityTag&) -> bool { return wing::weak_eq(a, b); }
fn ::strong_eq(a: const wing::EntityTag&, b: const wing::EntityTag&) -> bool { return wing::strong_eq(a, b); }
fn ::matches_vary(snap: const wing::VarySnapshot&, incoming_req_headers: const wing::HeaderMap&) -> bool { return wing::matches_vary(snap, incoming_req_headers); }
fn ::lookup(cache: wing::HttpCache&, req: const wing::Request&, cur_now: core::Time, cur_mono: core::MonotonicInstant = core::MonotonicInstant { .. }) -> wing::LookupDecision {
    return wing::lookup(cache, req, cur_now, cur_mono);
}
fn ::on_response(cache: wing::HttpCache&, req: const wing::Request&, resp: const wing::Response&, ts: const wing::CacheTimestamps&, revalidate_entry_idx: i64 = -1) -> wing::ResponseDecision {
    return wing::on_response(cache, req, resp, ts, revalidate_entry_idx);
}
fn ::check_invalidation(cache: wing::HttpCache&, req: const wing::Request&, resp: const wing::Response&) -> i64 {
    return wing::check_invalidation(cache, req, resp);
}

// ---- resilient networking & transport ufcs bridges -------------------------

fn ::acquire_pooled_connection(pool: wing::StreamPool&, key: const wing::PoolKey&, target_resolved_ip: const u8[:], now_ns: i64, do_extensive_checks: bool = false) -> i32, bool {
    return wing::acquire_pooled_connection(pool, key, target_resolved_ip, now_ns, do_extensive_checks);
}

fn ::register_connection(pool: wing::StreamPool&, key: const wing::PoolKey&, proto: wing::NegotiatedProtocol, resolved_ip: const u8[:], max_streams: i32, now_ns: i64, respect_limits: wing::RespectLimits = wing::RespectLimits.Enabled) -> i32 {
    return wing::register_connection(pool, key, proto, resolved_ip, max_streams, now_ns, respect_limits);
}

fn ::release_connection(pool: wing::StreamPool&, conn_id: i32, now_ns: i64) -> bool {
    return wing::release_connection(pool, conn_id, now_ns);
}

fn ::is_connection_healthy(conn: wing::PooledConnection&, now_ns: i64, do_extensive_checks: bool = false, healthy_threshold_ns: i64 = wing::IDLE_CONNECTION_HEALTHY_NS) -> bool {
    return wing::is_connection_healthy(conn, now_ns, do_extensive_checks, healthy_threshold_ns);
}

fn ::push_want(q: wing::WantQueue&, item: wing::WantConn) -> bool {
    return wing::push_want(q, item);
}

fn ::pop_want(q: wing::WantQueue&) -> wing::WantConn, bool {
    return wing::pop_want(q);
}

fn ::cancel_want(q: wing::WantQueue&, req_id: u64) -> bool {
    return wing::cancel_want(q, req_id);
}

fn ::compute_effective_cad_ms(observed_rtt_ms: i64, rtt_known: bool, min_cad_ms: i64 = wing::HE_MIN_CAD_MS, max_cad_ms: i64 = wing::HE_MAX_CAD_MS) -> i64 {
    return wing::compute_effective_cad_ms(observed_rtt_ms, rtt_known, min_cad_ms, max_cad_ms);
}

fn ::start_attempt_race(manager: wing::AttemptManager&, candidates: const wing::DnsCandidate[:], now_ms: i64) {
    wing::start_attempt_race(manager, candidates, now_ms);
}

fn ::tick_attempt_manager(manager: wing::AttemptManager&, now_ms: i64) -> bool {
    return wing::tick_attempt_manager(manager, now_ms);
}

fn ::bind_winner_attempt(manager: wing::AttemptManager&, winner_id: i32, is_alternative_h3: bool = false) -> bool {
    return wing::bind_winner_attempt(manager, winner_id, is_alternative_h3);
}

fn ::verify_connect_tunnel_response(raw_response: const u8[:], sink_buffered_bytes: i64 = 0) -> wing::ConnectTunnelError {
    return wing::verify_connect_tunnel_response(raw_response, sink_buffered_bytes);
}

fn ::feed_header_bytes(reader: wing::HeaderReader&, chunk: const u8[:], now_mono_ns: i64) -> wing::SlowlorisViolation {
    return wing::feed_header_bytes(reader, chunk, now_mono_ns);
}

fn ::should_retry_tier1_stale_socket(reused_connection: bool, headers_received: bool, req: const wing::Request&) -> bool {
    return wing::should_retry_tier1_stale_socket(reused_connection, headers_received, req);
}

fn ::evaluate_tier1_retry(err_code: i32, reused_connection: bool, headers_received: bool, req: const wing::Request&) -> wing::Tier1Decision {
    return wing::evaluate_tier1_retry(err_code, reused_connection, headers_received, req);
}

fn ::compute_backoff_jitter_ms(cfg: const wing::BackoffConfig&, attempt: i64, prev_sleep_ms: i64&, rng_seed: u64&) -> i64 {
    return wing::compute_backoff_jitter_ms(cfg, attempt, prev_sleep_ms, rng_seed);
}

fn ::parse_retry_after_ms(header_raw: const u8[:], now_unix_ms: i64) -> i64, bool {
    return wing::parse_retry_after_ms(header_raw, now_unix_ms);
}

fn ::trip_circuit_breaker_if_exceeded(breaker: wing::HostCircuitBreaker&, host_str: const u8[:], retry_after_ms: i64, now_mono_ns: i64) -> bool {
    return wing::trip_circuit_breaker_if_exceeded(breaker, host_str, retry_after_ms, now_mono_ns);
}

fn ::is_host_circuit_broken(breaker: wing::HostCircuitBreaker&, host_str: const u8[:], now_mono_ns: i64) -> bool {
    return wing::is_host_circuit_broken(breaker, host_str, now_mono_ns);
}

fn ::record_primary_request(budget: wing::AdaptiveRetryBudget&, now_mono_ns: i64) {
    wing::record_primary_request(budget, now_mono_ns);
}

fn ::allow_retry_budget(budget: wing::AdaptiveRetryBudget&, now_mono_ns: i64) -> bool {
    return wing::allow_retry_budget(budget, now_mono_ns);
}

// ---- echelon 6 http/2 ufcs bridges -----------------------------------------

fn ::decode_hpack_header_block(dt: wing::DynamicTable&, src: const u8[:], out: wing::DecodedH2HeaderList&, max_header_list_size: u32 = 8192, validate_http2_rules: bool = true) -> u32 {
    return wing::decode_hpack_header_block(dt, src, out, max_header_list_size, validate_http2_rules);
}

fn ::encode_hpack_field<B>(dt: wing::DynamicTable&, out: B&, name: const u8[:], val: const u8[:], indexing: bool = true, use_huffman: bool = true) -> bool {
    return wing::encode_hpack_field(dt, out, name, val, indexing, use_huffman);
}

fn ::on_ingress_frame_header(s: wing::SessionState&, hdr: const wing::FrameHeader&, now_ms: u64) -> u32 {
    return wing::on_ingress_frame_header(s, hdr, now_ms);
}

fn ::apply_peer_initial_window_size_delta(s: wing::SessionState&, new_init_win: u32) -> u32 {
    return wing::apply_peer_initial_window_size_delta(s, new_init_win);
}

fn ::apply_window_update(s: wing::SessionState&, stream_id: u32, increment: u32) -> u32 {
    return wing::apply_window_update(s, stream_id, increment);
}

fn ::compute_stream_send_quota(s: const wing::SessionState&, stream_id: u32) -> i64 {
    return wing::compute_stream_send_quota(s, stream_id);
}

fn ::on_data_frame_received(s: wing::SessionState&, hdr: const wing::FrameHeader&, payload_len: u32) -> u32 {
    return wing::on_data_frame_received(s, hdr, payload_len);
}

fn ::apply_priority_update(s: wing::SessionState&, prioritized_stream_id: u32, prio: wing::PriorityParam) -> u32 {
    return wing::apply_priority_update(s, prioritized_stream_id, prio);
}

fn ::schedule_next_write(s: wing::SessionState&, max_frame_len: u32) -> u32, u32, bool {
    return wing::schedule_next_write(s, max_frame_len);
}

fn ::parse_priority_param_rfc9218(raw: const u8[:], default_incremental: bool = false) -> wing::PriorityParam, bool {
    return wing::parse_priority_param_rfc9218(raw, default_incremental);
}

fn ::write_priority_param_rfc9218<B>(prio: const wing::PriorityParam&, out: B&) {
    wing::write_priority_param_rfc9218(prio, out);
}

fn ::parse_priority_update_payload(payload: const u8[:], default_incremental: bool = false) -> u32, wing::PriorityParam, u32 {
    return wing::parse_priority_update_payload(payload, default_incremental);
}

fn ::encode_priority_update_payload<B>(prioritized_stream_id: u32, prio: const wing::PriorityParam&, out: B&) {
    wing::encode_priority_update_payload(prioritized_stream_id, prio, out);
}

fn ::extract_padded_frame_payload(hdr: const wing::FrameHeader&, payload: const u8[:]) -> const u8[:], u32 {
    return wing::extract_padded_frame_payload(hdr, payload);
}

fn ::extract_headers_frame_payload(hdr: const wing::FrameHeader&, payload: const u8[:], no_rfc7540_priorities: bool = true) -> const u8[:], u32 {
    return wing::extract_headers_frame_payload(hdr, payload, no_rfc7540_priorities);
}

fn ::validate_settings_parameter(param_id: u16, val: u32) -> u32 {
    return wing::validate_settings_parameter(param_id, val);
}
