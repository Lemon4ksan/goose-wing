// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal server pipeline stage execution, compression, auth, and body-stream helpers.
namespace server_internal;

import std;
import core;
import rfc.http;
import http.headers;
import http.request;
import http.response;
import http.negotiate;
import http.digest_fields;
import http.server_timing;
import http.problem;
import http.compression_dict;
import security.gcra;
import security.csrf;
import security.cors;
import security.crypto_jar;
import auth.jwt;
import auth.jwks;
import auth.dpop;
import wire.pipeline;
import .router;
import .router_internal;
import .pool;
import .edge_filter;
import .cache;
import .profiler;
import .pipeline;

inline fn is_valid_forwarded_quoted_body(inner: const u8[:]) -> bool {
    var rem = inner;
    while rem.len > 0 {
        let b = rem[0];
        if b == '\\' {
            guard rem.len >= 2 else { return false; }
            let esc = rem[1];
            guard esc == ' ' || esc == '\t' || (esc >= 0x21 && esc != 0x7F) else { return false; }
            rem = rem[2..];
            continue;
        }
        guard b != '"' && (b == ' ' || b == '\t' || (b >= 0x21 && b != 0x7F)) else { return false; }
        rem = rem[1..];
    }
    return true;
}

inline fn is_valid_forwarded_port(port_str: const u8[:]) -> bool {
    guard port_str.len > 0 else { return false; }
    if port_str[0] == '_' {
        guard port_str.len >= 2 else { return false; }
        for b in port_str[1..] {
            let ok = core::is_ascii_alphanumeric(b) || b == '.' || b == '_' || b == '-';
            guard ok else { return false; }
        }
        return true;
    }
    let port_num, ok_port = core::parse_port_number(port_str);
    return ok_port && port_num > 0;
}

inline fn is_valid_ipv4_address_slice(ip: const u8[:]) -> bool {
    var rest = ip;
    for _ in 3 {
        let head, tail, ok_dot = rest.split_once_byte('.');
        guard ok_dot && head.len > 0 else { return false; }
        let _, ok_oct = core::parse_ipv4_decimal_octet(head);
        guard ok_oct else { return false; }
        rest = tail;
    }
    let _, ok_last = core::parse_ipv4_decimal_octet(rest);
    return ok_last;
}

inline fn normalize_forwarded_bracket_ipv6(val: const u8[:]) -> const u8[:] {
    let after_open = val[1..];
    let v6_body, after_close, has_close = after_open.split_once_byte(']');
    var ipv6_buf: u8[..64] = [];
    guard has_close && v6_body.len > 0 && core::parse_and_compress_ipv6(v6_body, ipv6_buf) else {
        return "";
    }
    if after_close.len > 0 {
        guard after_close[0] == ':' && is_valid_forwarded_port(after_close[1..]) else {
            return "";
        }
    }
    return v6_body;
}

// RFC 7239 Section 6: Node Identifiers - normalizes a forwarded IP value, rejecting `unknown` and `_obfnode`.
//
// Example:
//   raw_val = "\"[2001:db8:cafe::17]:4711\""
//   returns: "2001:db8:cafe::17"
fn normalize_forwarded_ip(raw_val: const u8[:]) -> const u8[:] {
    guard raw_val.len > 0 else { return ""; }
    var val = raw_val;
    if val[0] == '"' {
        let after_q, ok_l = val.strip_prefix("\"");
        let inner_q, ok_r = after_q.strip_suffix("\"");
        guard ok_l && ok_r && is_valid_forwarded_quoted_body(inner_q) else { return ""; }
        val = inner_q;
    } else if val.contains_byte('"') {
        return "";
    }
    guard val.len > 0 && !val.eq_ascii_fold("unknown") && val[0] != '_' else { return ""; }
    if val[0] == '[' {
        return normalize_forwarded_bracket_ipv6(val);
    }

    let host_part, after_col1, has_col1 = val.split_once_byte(':');
    if !has_col1 {
        return if is_valid_ipv4_address_slice(val) { val } else { "" };
    }
    if after_col1.contains_byte(':') {
        var ipv6_buf: u8[..64] = [];
        return if core::parse_and_compress_ipv6(val, ipv6_buf) { val } else { "" };
    }
    guard host_part.len > 0 && is_valid_forwarded_port(after_col1) && is_valid_ipv4_address_slice(host_part) else {
        return "";
    }
    return host_part;
}

// RFC 7239 Section 4: Forwarded HTTP Header Field - parses a `for=` parameter pair without BWS around `=`.
//
// Example:
//   pair = "for=\"192.0.2.60:4711\""
//   returns: "192.0.2.60"
fn parse_forwarded_pair(pair: const u8[:]) -> const u8[:] {
    let trimmed = pair.trim_lws();
    let key, raw_val, has_eq = trimmed.split_once_byte('=');
    guard has_eq && key.eq_ascii_fold("for") && raw_val.len > 0 else { return ""; }
    if raw_val[0] == '"' {
        let after_q, ok_l = raw_val.strip_prefix("\"");
        let inner, ok_r = after_q.strip_suffix("\"");
        guard ok_l && ok_r && inner.len > 0 && is_valid_forwarded_quoted_body(inner) else { return ""; }
        let _, after_c1, has_c1 = inner.split_once_byte(':');
        if inner[0] != '[' && has_c1 && after_c1.contains_byte(':') {
            return "";
        }
        return normalize_forwarded_ip(inner);
    }
    for b in raw_val {
        guard core::is_tchar(b) else { return ""; }
    }
    return normalize_forwarded_ip(raw_val);
}

inline fn is_trusted_proxy_peer(trust_proxy_headers: bool, client_ip: const u8[:]) -> bool {
    return trust_proxy_headers || client_ip == "127.0.0.1" || client_ip == "::1";
}

fn has_custom_forwarding_header(map: const http::HeaderMap&) -> bool {
    for &e in map.entries {
        if e.well_known_id == 0xFF {
            return true;
        }
    }
    return false;
}

// Stage 13 (Server Ingress): Post-auth GCRA rate limiting keyed on verified JWT `sub:<subject>`.
fn stage_server_ratelimit_subject<Limiter>(
    limiter: Limiter&,
    enabled: bool,
    subject: const u8[:],
    now_ns:  u64,
    res:     http::Response&,
) -> wire::StageVerdict {
    guard enabled && subject.len > 0 else { return wire::StageVerdict.Continue; }
    let _prof = server::prof_enter("stage.ratelimit_subject");
    defer server::prof_leave(_prof);
    var composite_key: u8[..128] = [];
    composite_key.append("sub:");
    composite_key.append(subject[..min(subject.len, 96)]);
    let rl_decision = limiter.check_rate_limit(composite_key[..], 1, now_ns);
    security::apply_rate_limit_headers(res, limiter.quota, rl_decision);
    guard rl_decision.is_allowed() else {
        return wire::StageVerdict.ShortCircuit { status_code: 429 };
    }
    return wire::StageVerdict.Continue;
}

// RFC 6265 Section 4.2.1: Syntax - Extracts value of session cookie parameter.
//
// Example:
//   cookie_hdr = "id=123; session=abc456; theme=dark"
//   returns: "abc456"
fn extract_session_cookie_value(cookie_hdr: const u8[:]) -> const u8[:] {
    var pos = 0;
    while pos < cookie_hdr.len {
        while pos < cookie_hdr.len && (cookie_hdr[pos] == ' ' || cookie_hdr[pos] == '\t') {
            pos++;
        }
        let pair_start = pos;
        while pos < cookie_hdr.len && cookie_hdr[pos] != ';' {
            pos++;
        }
        let pair = cookie_hdr[pair_start..pos];
        if pos < cookie_hdr.len && cookie_hdr[pos] == ';' {
            pos++;
        }
        let eq_idx = pair.index_of_byte('=');
        if eq_idx > 0 && pair[..eq_idx].trim_lws() == "session" {
            return pair[(eq_idx + 1)..].trim_lws();
        }
    }
    return "";
}

// RFC 6750 Section 2.1: Authorization Request Header Field - "Bearer" 1*SP b64token
fn is_b64token_slice(tok: const u8[:]) -> bool {
    guard tok.len > 0 && tok[0] != '=' else { return false; }
    var seen_pad = false;
    for b in tok {
        if b == '=' {
            seen_pad = true;
        } else {
            let ok_ch = core::is_ascii_alphanumeric(b)
                || b == '-' || b == '.' || b == '_' || b == '~' || b == '+' || b == '/';
            guard !seen_pad && ok_ch else { return false; }
        }
    }
    return true;
}

// Extracts Bearer token from an Authorization header value (RFC 6750 §2.1).
//
// Example:
//   auth_hdr = "Bearer eyJhbGciOiJIUzI1NiJ9.e30.sig"
//   returns: "eyJhbGciOiJIUzI1NiJ9.e30.sig"
fn extract_bearer_token(auth_hdr: const u8[:]) -> const u8[:] {
    let trimmed = auth_hdr.trim_lws();
    let rest, ok_pfx = trimmed.strip_prefix_fold("Bearer ");
    guard ok_pfx else { return ""; }
    let tok = rest.trim_start_byte(' ');
    guard is_b64token_slice(tok) else { return ""; }
    return tok;
}

fn populate_cached_response(cache: const server::HttpRouteCache&, res: http::Response&) -> wire::StageVerdict {
    res.status_code = 200;
    let _ = res.body.try_set(cache.wire[..]);
    if cache.content_type.len > 0 {
        if !res.headers.append_known_pipeline_header(
            rfc::HEADER_CONTENT_TYPE,
            cache.content_type[..],
            http::SLOT_CONTENT_TYPE,
            0,
            HASH_HDR_CONTENT_TYPE,
            false,
        ) {
            let _ = http::append_header(res.headers, rfc::HEADER_CONTENT_TYPE, cache.content_type[..]);
        }
        res.presence_mask |= http::RES_PRESENCE_CONTENT_TYPE;
    }
    if cache.etag.len > 0 {
        if !res.headers.append_known_pipeline_header(
            rfc::HEADER_ETAG,
            cache.etag[..],
            http::SLOT_ETAG,
            0,
            http::HASH_HDR_ETAG,
            false,
        ) {
            let _ = http::append_header(res.headers, rfc::HEADER_ETAG, cache.etag[..]);
        }
    }
    return wire::StageVerdict.ShortCircuit { status_code: 200 };
}

fn populate_missing_response_etag(res: http::Response&, memo: server::ServerCompressAndEtagMemo&) {
    if res.body.len <= 512 && memo.etag_src.len > 0 && res.body[..] == memo.etag_src[..] {
        if !res.headers.append_known_pipeline_header(
            rfc::HEADER_ETAG,
            memo.etag_val[..],
            http::SLOT_ETAG,
            0,
            http::HASH_HDR_ETAG,
            false,
        ) {
            let _ = http::append_header(res.headers, rfc::HEADER_ETAG, memo.etag_val[..]);
        }
        return;
    }
    var etag_hdr: u8[..32] = [];
    etag_hdr.push('"');
    let body_hash = core::xxh64(res.body[..], 0);
    body_hash.format_u64_hex(etag_hdr);
    etag_hdr.push('"');
    if res.body.len <= 512 {
        let _ = memo.etag_src.try_set(res.body[..]);
        let _ = memo.etag_val.try_set(etag_hdr[..]);
    }
    if !res.headers.append_known_pipeline_header(
        rfc::HEADER_ETAG,
        etag_hdr[..],
        http::SLOT_ETAG,
        0,
        http::HASH_HDR_ETAG,
        false,
    ) {
        let _ = http::append_header(res.headers, rfc::HEADER_ETAG, etag_hdr[..]);
    }
}

fn append_vary_accept_encoding(res: http::Response&) {
    let cur = http::get_inline(res.headers, http::WellKnownHeader.Vary);
    if cur.len == 0 {
        if !res.headers.append_known_pipeline_header(
            rfc::HEADER_VARY,
            rfc::HEADER_ACCEPT_ENCODING,
            http::SLOT_VARY,
            0,
            rfc::HASH_HDR_VARY,
            false,
        ) {
            let _ = http::append_header(res.headers, rfc::HEADER_VARY, rfc::HEADER_ACCEPT_ENCODING);
        }
    } else if cur == rfc::FETCH_METADATA_VARY_VALUE {
        let combined = "Sec-Fetch-Dest, Sec-Fetch-Mode, Sec-Fetch-Site, Origin, Accept-Encoding";
        if !res.headers.update_single_vary_value(combined) {
            let _ = http::set_or_replace(res.headers, rfc::HEADER_VARY, combined, false);
        }
    } else if !cur.contains_fold(rfc::HEADER_ACCEPT_ENCODING) {
        var vbuf: u8[..128] = [];
        guard vbuf.try_set(cur) && vbuf.try_append(", Accept-Encoding") else { return; }
        if !res.headers.update_single_vary_value(vbuf[..]) {
            let _ = http::set_or_replace(res.headers, rfc::HEADER_VARY, vbuf[..], false);
        }
    }
}

fn finalize_compressed_response(res: http::Response&, encoding: const u8[:], suffix: const u8[:]) {
    if !res.headers.append_known_pipeline_header(
        rfc::HEADER_CONTENT_ENCODING,
        encoding,
        http::SLOT_CONTENT_ENCODING,
        0,
        http::HASH_HDR_CONTENT_ENCODING,
        false,
    ) {
        let _ = http::set_or_replace(res.headers, rfc::HEADER_CONTENT_ENCODING, encoding, false);
    }
    if http::get_inline(res.headers, http::WellKnownHeader.ContentLength).len > 0 {
        http::remove_header(res, rfc::HEADER_CONTENT_LENGTH);
    }
    let etag = http::get_inline(res.headers, http::WellKnownHeader.ETag);
    let last_idx = core::sub_sat_i64(etag.len, 1);
    if etag.len >= 2 && etag[last_idx] == '"' && core::add_sat_i64(etag.len, suffix.len) <= 64 {
        var new_etag: u8[..64] = [];
        new_etag.append(etag[..last_idx]);
        new_etag.append(suffix);
        new_etag.push('"');
        let _ = http::set_or_replace(res.headers, rfc::HEADER_ETAG, new_etag[..], false);
    }
    append_vary_accept_encoding(res);
}

const COMPRESS_INLINE_BODY_MAX: i64 = 7680;

fn try_compress_zstd(res: http::Response&, memo: server::ServerCompressAndEtagMemo&) -> bool {
    if res.body.len <= COMPRESS_INLINE_BODY_MAX {
        memo.compress_scratch.clear();
        if core::zstd_compress(res.body[..], memo.compress_scratch) {
            let _ = res.body.try_set(memo.compress_scratch[..]);
            finalize_compressed_response(res, "zstd", "-zstd");
            return true;
        }
    }
    var large_scratch: u8[>..] = [];
    guard core::zstd_compress(res.body[..], large_scratch) else { return false; }
    let _ = res.body.try_set(large_scratch[..]);
    finalize_compressed_response(res, "zstd", "-zstd");
    return true;
}

fn try_compress_brotli(res: http::Response&, memo: server::ServerCompressAndEtagMemo&) -> bool {
    if res.body.len <= COMPRESS_INLINE_BODY_MAX {
        memo.compress_scratch.clear();
        if core::brotli_compress(res.body[..], memo.compress_scratch, 1) {
            let _ = res.body.try_set(memo.compress_scratch[..]);
            finalize_compressed_response(res, "br", "-br");
            return true;
        }
    }
    var large_scratch: u8[>..] = [];
    guard core::brotli_compress(res.body[..], large_scratch, 1) else { return false; }
    let _ = res.body.try_set(large_scratch[..]);
    finalize_compressed_response(res, "br", "-br");
    return true;
}

fn maybe_store_gzip_memo(
    src:        const u8[:],
    compressed: const u8[:],
    gz_level:   i32,
    memo:       server::ServerCompressAndEtagMemo&,
) {
    if src.len <= 512 && compressed.len <= 512 {
        let _ = memo.gzip_src.try_set(src);
        let _ = memo.gzip_dst.try_set(compressed);
        memo.gzip_level = gz_level;
    }
}

fn try_apply_gzip_memo(
    res:      http::Response&,
    memo:     const server::ServerCompressAndEtagMemo&,
    gz_level: i32,
) -> bool {
    guard res.body.len <= 512 && memo.gzip_src.len > 0 && memo.gzip_level == gz_level else {
        return false;
    }
    guard res.body[..] == memo.gzip_src[..] else {
        return false;
    }
    let _ = res.body.try_set(memo.gzip_dst[..]);
    finalize_compressed_response(res, "gzip", "-gzip");
    return true;
}

fn compress_gzip_uncached(res: http::Response&, memo: server::ServerCompressAndEtagMemo&, level: i32 = 1) {
    let gz_level = server::select_dynamic_gzip_level(res.body.len, level);
    if res.body.len <= COMPRESS_INLINE_BODY_MAX {
        memo.compress_scratch.clear();
        if core::gzip_compress(res.body[..], memo.compress_scratch, gz_level) {
            maybe_store_gzip_memo(res.body[..], memo.compress_scratch[..], gz_level, memo);
            let _ = res.body.try_set(memo.compress_scratch[..]);
            finalize_compressed_response(res, "gzip", "-gzip");
            return;
        }
    }
    var large_scratch: u8[>..] = [];
    if core::gzip_compress(res.body[..], large_scratch, gz_level) {
        let _ = res.body.try_set(large_scratch[..]);
        finalize_compressed_response(res, "gzip", "-gzip");
    }
}

fn has_custom_header_hash(map: const http::HeaderMap&, name: const u8[:], hname: u32) -> bool {
    for &e in map.entries {
        if e.name_hash == hname && http::entry_name(map, e).eq_ascii_fold(name) {
            return true;
        }
    }
    return false;
}

fn is_clean_header_bytes(src: const u8[:]) -> bool {
    for b in src {
        if b == '\r' || b == '\n' || b == 0 {
            return false;
        }
    }
    return true;
}

fn append_matched_route_log_header(map: http::HeaderMap&, route_slice: const u8[:]) {
    if is_clean_header_bytes(route_slice) {
        let has_comma = route_slice.contains_byte(',');
        let flags = if has_comma { http::HEADER_FLAG_CONTAINS_COMMA } else { 0 };
        if !map.append_known_pipeline_header(
            "X-Matched-Route",
            route_slice,
            0xFF,
            flags,
            http::HASH_HDR_X_MATCHED_ROUTE,
            has_comma,
        ) {
            let _ = http::append_header(map, "X-Matched-Route", route_slice);
        }
        return;
    }
    var clean_route: u8[..256] = [];
    http::sanitize_header_bytes(route_slice, clean_route);
    if clean_route.len > 0 {
        let _ = http::append_header(map, "X-Matched-Route", clean_route[..]);
    }
}

// Extracts and decodes the 32-byte SHA-256 digest from an RFC 9530 Content-Digest header.
//
// Example:
//   hdr = "sha-256=:uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=:"
//   returns: [185, 77, 39, 185, ...], true
fn extract_sha256_content_digest(hdr: const u8[:]) -> u8[..32], bool {
    var out_sha256: u8[..32]                = [];
    var entries:    http::SfDictEntry[..16] = [];
    guard http::parse_sf_dict(hdr, entries) else { return out_sha256, false; }
    for &e in entries {
        guard e.key[..].eq_ascii_fold(rfc::DIGEST_ALG_SHA256) else { continue; }
        guard e.item.kind == http::SfType.Binary else { return out_sha256, false; }
        guard core::base64_decode(e.item.str_val[..], out_sha256) && out_sha256.len == 32 else {
            out_sha256.clear();
            return out_sha256, false;
        }
        return out_sha256, true;
    }
    return out_sha256, false;
}

fn decompress_buffered_server_stream(state: server::ServerBodyStreamState&, decoded: u8[..16384]&) -> bool {
    if state.compressed_buf.len == 0 {
        return true;
    }
    let ok = if state.decompress_zstd {
        let ok_z, _ = core::zstd_decompress_with_limit(state.compressed_buf[..], decoded, 16384);
        ok_z
    } else {
        let ok_g, _ = core::gzip_decompress_with_limit(state.compressed_buf[..], decoded, 16384);
        ok_g
    };
    state.compressed_buf.clear();
    return ok;
}

// Processes a streaming body chunk through decompression and SHA-256 digest verification with `wire::NoOpStage`.
fn feed_server_body_chunk(
    cfg:     server::ServerPipelineConfig&,
    state:   server::ServerBodyStreamState&,
    req:     const http::Request&,
    sctx:    server::ServerStageCtx&,
    chunk:   const u8[:],
    is_last: bool,
    res:     http::Response&,
) -> wire::StageVerdict {
    var noop = wire::NoOpStage {};
    return server::feed_server_body_chunk_with_stage(cfg, state, req, sctx, chunk, is_last, res, noop);
}

inline fn cors_short_circuit_outcome(status_code: u16) -> server::PipelineOutcome {
    if status_code == 403 {
        return server::PipelineOutcome.CsrfRejected;
    }
    return server::PipelineOutcome.CorsPreflight;
}

// Evaluates CORS policies and Sec-Fetch-* cross-origin isolation metadata.
// Returns (outcome, is_terminal): if is_terminal is true, the request must not proceed further.
fn evaluate_pipeline_cors_and_csrf(
    cfg:  server::ServerPipelineConfig&,
    req:  const http::Request&,
    res:  http::Response&,
    mask: u64 = server::STAGE_INGRESS_CORS_PREFLIGHT | server::STAGE_INGRESS_FETCH_CSRF,
) -> server::PipelineOutcome, bool {
    if (mask & (server::STAGE_INGRESS_CORS_PREFLIGHT | wire::STAGE_SRV_IN_CORS)) != 0 {
        let v_cors = server::stage_server_cors(cfg.cors_policy, cfg.enable_cors, req, res);
        match v_cors {
            ShortCircuit sc => {
                return cors_short_circuit_outcome(sc.status_code), true;
            },
            _ => {},
        };
    }

    if (mask & (server::STAGE_INGRESS_FETCH_CSRF | wire::STAGE_SRV_IN_CSRF)) != 0 {
        let scheme = if cfg.tls_enabled {
            security::CsrfTargetScheme.Https
        } else {
            security::CsrfTargetScheme.Http
        };
        let v_csrf = server::stage_server_csrf(
            cfg.csrf_guard, cfg.enable_csrf_guard, cfg.target_host[..], req, res, scheme,
        );
        match v_csrf {
            ShortCircuit _ => { return server::PipelineOutcome.CsrfRejected, true; },
            _ => {},
        };
    }

    return server::PipelineOutcome.Handled, false;
}

inline fn select_stage_limiter(cfg: server::ServerPipelineConfig&, param_slot: u8) -> security::ShardedGcraLimiter& {
    if param_slot < cfg.tier_limiters.len {
        return cfg.tier_limiters[param_slot];
    }
    return cfg.limiter;
}

fn execute_bound_ingress_stage_verdict<UserStage>(
    cfg:        server::ServerPipelineConfig&,
    b:          const wire::StageBinding&,
    req:        const http::Request&,
    res:        http::Response&,
    ext:        server_internal::RequestExtensions&,
    now_ns:     u64,
    sctx:       server::ServerStageCtx&,
    user_stage: UserStage&,
) -> wire::StageVerdict {
    if b.stage_id >= server::STAGE_ID_USER_0 && b.stage_id <= server::STAGE_ID_USER_3 {
        return server::on_server_custom_slot(user_stage, b.stage_id, b.param_slot, cfg, req, sctx, res);
    }
    if b.stage_id == wire::STAGE_ID_SRV_IN_EXPECT_100 {
        return server::stage_server_expect_100(req, res);
    }
    if b.stage_id == wire::STAGE_ID_SRV_IN_EDGE_FILTER {
        return server::stage_server_edge_filter(cfg.edge_filter, req, res);
    }
    if b.stage_id == wire::STAGE_ID_SRV_IN_RATELIMIT_IP {
        let lim .= select_stage_limiter(cfg, b.param_slot);
        return server::stage_server_ratelimit_ip(lim, cfg.enable_rate_limiter, ext.peer_ip[..], now_ns, res);
    }
    if b.stage_id == wire::STAGE_ID_SRV_IN_ROUTE_MATCH {
        var dummy_match = server::RouteMatchResult.NotFound;
        return server::stage_server_route_match(cfg.router, req, ext, dummy_match, res);
    }
    if b.stage_id == wire::STAGE_ID_SRV_IN_RATELIMIT_ROUTE {
        let lim .= select_stage_limiter(cfg, b.param_slot);
        let rpath = if ext.canon_url.len > 0 { ext.canon_url[..] } else { req.url[..] };
        return server::stage_server_ratelimit_route(lim, cfg.enable_rate_limiter, ext.peer_ip[..], rpath, now_ns, res);
    }
    if b.stage_id == wire::STAGE_ID_SRV_IN_CORS {
        return server::stage_server_cors(cfg.cors_policy, cfg.enable_cors, req, res);
    }
    if b.stage_id == wire::STAGE_ID_SRV_IN_CSRF {
        let scheme = if cfg.tls_enabled {
            security::CsrfTargetScheme.Https
        } else {
            security::CsrfTargetScheme.Http
        };
        return server::stage_server_csrf(
            cfg.csrf_guard, cfg.enable_csrf_guard, cfg.target_host[..], req, res, scheme,
        );
    }
    if b.stage_id == wire::STAGE_ID_SRV_IN_AUTH_COOKIE {
        return server::stage_server_auth_cookie(cfg.private_jar, req, ext, now_ns);
    }
    if b.stage_id == wire::STAGE_ID_SRV_IN_AUTH_JWT {
        return server::stage_server_auth_jwt(cfg.jwks, cfg.jwt_options, req, ext, now_ns, res);
    }
    if b.stage_id == wire::STAGE_ID_SRV_IN_RATELIMIT_SUBJECT {
        let lim .= select_stage_limiter(cfg, b.param_slot);
        return stage_server_ratelimit_subject(lim, cfg.enable_rate_limiter, ext.auth_subject[..], now_ns, res);
    }
    return wire::StageVerdict.Continue;
}

inline fn map_bound_stage_verdict(
    stage_id: u8,
    v:        wire::StageVerdict,
    res:      http::Response&,
) -> server::PipelineOutcome, bool {
    match v {
        Continue => { return server::PipelineOutcome.Handled, false; },
        ShortCircuit sc => {
            if res.status_code == 0 || (res.status_code == 200 && sc.status_code != 200) {
                res.status_code = sc.status_code;
            }
            if stage_id == wire::STAGE_ID_SRV_IN_EXPECT_100 {
                return server::PipelineOutcome.ExpectationFailed, true;
            }
            if stage_id == wire::STAGE_ID_SRV_IN_CORS {
                return cors_short_circuit_outcome(sc.status_code), true;
            }
            if sc.status_code == 404 {
                return server::PipelineOutcome.RouteNotFound, true;
            }
            if sc.status_code == 405 {
                return server::PipelineOutcome.MethodNotAllowed, true;
            }
            if sc.status_code == 429 {
                return server::PipelineOutcome.RateLimited, true;
            }
            return server::PipelineOutcome.CsrfRejected, true;
        },
        _ => { return server::PipelineOutcome.CsrfRejected, true; },
    };
}

fn evaluate_server_integrity_and_crypto(
    cfg:    server::ServerPipelineConfig&,
    req:    const http::Request&,
    now_ns: u64,
    res:    http::Response&,
) -> bool {
    if cfg.verify_request_digest
        && http::header(req, rfc::HEADER_CONTENT_DIGEST).len > 0
        && !http::verify_request_content_digest(req) {
        if cfg.emit_problem_details {
            http::respond_problem(res, 400, "Bad Request", "Content-Digest verification failed");
        } else {
            res.status_code = 400;
        }
        return false;
    }
    if cfg.verify_request_digest
        && http::header(req, rfc::HEADER_REPR_DIGEST).len > 0
        && !http::verify_request_repr_digest(req) {
        if cfg.emit_problem_details {
            http::respond_problem(res, 400, "Bad Request", "Repr-Digest verification failed");
        } else {
            res.status_code = 400;
        }
        return false;
    }
    if cfg.dpop_public_key.len > 0 {
        let dpop_jwt = http::header(req, "DPoP");
        let now_sec = (now_ns / 1000000000) as i64;
        let ok_dpop = dpop_jwt.len > 0 && auth::verify_dpop_proof_with_replay_cache(
            cfg.dpop_replay_cache, dpop_jwt, cfg.dpop_public_key[..], req.method[..], req.url[..], now_sec,
        );
        if !ok_dpop {
            res.status_code = 401;
            return false;
        }
    }
    if cfg.sig_public_key.len > 0 {
        if !http::verify_request_ed25519(req, cfg.sig_key_id[..], cfg.sig_public_key[..]) {
            res.status_code = 401;
            return false;
        }
    }
    return true;
}

// Executes pre-handler ingress stages matching the effective PSO or server ingress mask.
// Returns (outcome, is_terminal): if is_terminal is true, the request must not proceed further.
fn dispatch_ingress_pipeline<UserStage>(
    cfg:        server::ServerPipelineConfig&,
    req:        const http::Request&,
    res:        http::Response&,
    ext:        server_internal::RequestExtensions&,
    mask:       u64,
    now_ns:     u64,
    sctx:       server::ServerStageCtx&,
    user_stage: UserStage&,
) -> server::PipelineOutcome, bool {
    if cfg.wire_pipeline.has_custom_order {
        let custom_out, is_term = server::dispatch_custom_stage_bindings(
            cfg, req, res, ext, now_ns, sctx, user_stage,
        );
        guard !is_term else { return custom_out, true; }
        if !evaluate_server_integrity_and_crypto(cfg, req, now_ns, res) {
            return server::PipelineOutcome.CsrfRejected, true;
        }
        return server::PipelineOutcome.Handled, false;
    }

    // Stage: Expect 100-continue validation (RFC 9110 Section 10.1.1)
    if (mask & server::STAGE_INGRESS_EXPECT_100) != 0 {
        match server::stage_server_expect_100(req, res) {
            ShortCircuit _ => { return server::PipelineOutcome.ExpectationFailed, true; },
            _ => {},
        };
    }

    // Stage: EdgeFilter L7 inspection
    match server::stage_server_edge_filter(cfg.edge_filter, req, res) {
        ShortCircuit sc => {
            if sc.status_code == 429 {
                return server::PipelineOutcome.RateLimited, true;
            }
            return server::PipelineOutcome.CsrfRejected, true;
        },
        Abort _ => { return server::PipelineOutcome.CsrfRejected, true; },
        _ => {},
    };

    // Stage: Global GCRA IP rate limiter
    if (mask & server::STAGE_INGRESS_IP_RATELIMIT) != 0 {
        match server::stage_server_ratelimit_ip(cfg.limiter, cfg.enable_rate_limiter, ext.peer_ip[..], now_ns, res) {
            ShortCircuit _ => { return server::PipelineOutcome.RateLimited, true; },
            _ => {},
        };
    }

    // Stage: Per-route GCRA rate limiter
    if (mask & server::STAGE_INGRESS_ROUTE_RATELIMIT) != 0 {
        match server::stage_server_ratelimit_route(
            cfg.limiter,
            cfg.enable_rate_limiter,
            ext.peer_ip[..],
            ext.canon_url[..],
            now_ns,
            res,
        ) {
            ShortCircuit _ => { return server::PipelineOutcome.RateLimited, true; },
            _ => {},
        };
    }

    // Stage: CORS preflight and Fetch Metadata CSRF isolation
    let cors_csrf_mask = mask & (server::STAGE_INGRESS_CORS_PREFLIGHT | server::STAGE_INGRESS_FETCH_CSRF);
    if cors_csrf_mask != 0 && (cfg.enable_cors || cfg.enable_csrf_guard) {
        let sec_outcome, is_term = evaluate_pipeline_cors_and_csrf(cfg, req, res, cors_csrf_mask);
        guard !is_term else { return sec_outcome, true; }
    }

    // Stage: Authenticated session cookie decryption
    if (mask & server::STAGE_INGRESS_AUTH_COOKIE) != 0 {
        let _ = server::stage_server_auth_cookie(cfg.private_jar, req, ext, now_ns);
    }

    // Stage: JWT Bearer token verification
    if (mask & server::STAGE_INGRESS_AUTH_JWT) != 0 {
        match server::stage_server_auth_jwt(cfg.jwks, cfg.jwt_options, req, ext, now_ns, res) {
            ShortCircuit _ => { return server::PipelineOutcome.CsrfRejected, true; },
            _ => {},
        };
    }

    if !evaluate_server_integrity_and_crypto(cfg, req, now_ns, res) {
        return server::PipelineOutcome.CsrfRejected, true;
    }

    return server::PipelineOutcome.Handled, false;
}

fn maybe_store_server_route_cache(
    cfg:         server::ServerPipelineConfig&,
    req:         const http::Request&,
    now_ns:      u64,
    res:         http::Response&,
    handler_id:  i32,
    egress_mask: u64,
) {
    let has_auth = (req.presence_mask & http::HDR_PRESENCE_AUTHORIZATION) != 0
        || http::has_header(req.headers, rfc::HEADER_AUTHORIZATION);
    guard (egress_mask & wire::STAGE_SRV_OUT_CACHE_STORE) != 0 &&
          handler_id >= 0 && req.method[..] == "GET" && !has_auth else {
        cfg.route_cache.is_updating = false;
        return;
    }
    let now_ms, _ = core::div_rem_u64(now_ns, 1000000);
    let _ = server::stage_server_cache_store(cfg.route_cache, now_ms, res, handler_id, req.url[..]);
}

// Dispatches route payloads and headers registered in `cfg.router.static_payloads` for `handler_id`.
fn apply_route_payload(cfg: const server::ServerPipelineConfig&, handler_id: i32, res: http::Response&) {
    let _ = get_static_route_payload(cfg.router, handler_id, res);
}

fn execute_found_route_handler<UserStage>(
    cfg:          server::ServerPipelineConfig&,
    req:          const http::Request&,
    now_ns:       u64,
    res:          http::Response&,
    out_future:   server_internal::InlineHandlerFuture&,
    f:            const RouteMatchFound&,
    ext_slot_idx: i32,
    sctx:         server::ServerStageCtx&,
    user_stage:   UserStage&,
) -> server::PipelineOutcome {
    if req.method[..] == rfc::METHOD_QUERY && http::header(req, rfc::HEADER_CONTENT_TYPE).len == 0 {
        res.status_code = 400; // Bad Request
        return server::PipelineOutcome.Handled;
    }

    let wants_cookie = (f.entries_mask & server_internal::ENTRY_COOKIES) != 0;
    let cookie_unpopulated = (cfg.ext_pool.slots[ext_slot_idx].populated_entries & server_internal::ENTRY_COOKIES) == 0;
    if wants_cookie && cookie_unpopulated {
        let _ = server::stage_server_auth_cookie(cfg.private_jar, req, cfg.ext_pool.slots[ext_slot_idx], now_ns);
    }

    let now_ms = now_ns / 1000000;
    if (f.ingress_mask & wire::STAGE_SRV_IN_CACHE_LOOKUP) != 0 {
        let c_v = server::stage_server_cache_lookup(cfg.route_cache, req, now_ms, res, f.handler_id);
        let is_cached = match c_v { ShortCircuit _ => true, _ => false };
        if is_cached {
            return server::PipelineOutcome.Handled;
        }
    }

    let _prof_h = server::prof_enter("stage.handler");
    out_future = server_internal::new_inline_handler_future(f.handler_id as u16);
    server_internal::poll_future(out_future);

    res.status_code = 0;
    sctx.is_pending = false;
    let route_v = server::on_server_stage(user_stage, wire::ServerHookPhase.RouteHandler, cfg, req, sctx, res);
    match route_v {
        ShortCircuit sc => {
            if res.status_code == 0 {
                res.status_code = sc.status_code as i32;
            }
        },
        Abort _ => {
            server::prof_leave(_prof_h);
            cfg.route_cache.is_updating = false;
            return server::PipelineOutcome.CsrfRejected;
        },
        _ => {},
    };

    if sctx.is_pending {
        server::prof_leave(_prof_h);
        cfg.route_cache.is_updating = false;
        return server::PipelineOutcome.Pending;
    }

    if res.status_code == 0 {
        res.status_code = 200;
        apply_route_payload(cfg, f.handler_id, res);
    }
    server::prof_leave(_prof_h);
    maybe_store_server_route_cache(cfg, req, now_ns, res, f.handler_id, f.egress_mask);
    return server::PipelineOutcome.Handled;
}

fn dispatch_matched_route<UserStage>(
    cfg:          server::ServerPipelineConfig&,
    req:          const http::Request&,
    now_ns:       u64,
    res:          http::Response&,
    out_future:   server_internal::InlineHandlerFuture&,
    match_res:    server::RouteMatchResult,
    ext_slot_idx: i32,
    sctx:         server::ServerStageCtx&,
    user_stage:   UserStage&,
) -> server::PipelineOutcome {
    match match_res {
        NotFound => {
            if cfg.emit_problem_details {
                http::respond_problem(res, 404, "Not Found", "The requested resource was not found");
            } else {
                res.status_code = 404; // Not Found
            }
            return server::PipelineOutcome.RouteNotFound;
        },
        MethodNotAllowed mna => {
            if cfg.emit_problem_details {
                http::respond_problem(res, 405, "Method Not Allowed", "The HTTP method is not allowed");
            } else {
                res.status_code = 405; // Method Not Allowed
            }
            http::set_header(res, rfc::HEADER_ALLOW, mna.allow_header[..]);
            return server::PipelineOutcome.MethodNotAllowed;
        },
        Found f => {
            return execute_found_route_handler(
                cfg, req, now_ns, res, out_future, f, ext_slot_idx, sctx, user_stage,
            );
        },
    };
}

// RFC 9110 Section 9.3.2: HEAD - Suppress body for HEAD requests while preserving Content-Length.
fn handle_head_method_suppression(req_method: const u8[:], res: http::Response&) {
    guard req_method == rfc::METHOD_HEAD else { return; }
    if http::header(res, rfc::HEADER_CONTENT_LENGTH).len == 0 && res.body.len > 0 {
        var cl_buf: u8[..32] = [];
        res.body.len.format_i64_dec(cl_buf);
        http::set_header(res, rfc::HEADER_CONTENT_LENGTH, cl_buf[..]);
    }
    res.body.clear();
}

// Resolves the effective pipeline mask from route match result and server capabilities.
inline fn resolve_route_effective_pso(res: server::RouteMatchResult, caps: u64) -> u64 {
    return match res {
        Found f => f.pso_mask & caps,
        _ => (server::DEFAULT_ROUTE_PSO_MASK | server::STAGE_INGRESS_CORS_PREFLIGHT) & caps,
    };
}

// Updates `sctx` fields (`handler_id`, `entries_mask`, `ingress_mask`, `egress_mask`) from `match_res`.
inline fn sync_stage_ctx_with_route(sctx: server::ServerStageCtx&, match_res: server::RouteMatchResult) {
    let stream_bits = sctx.ingress_mask & (wire::STAGE_SRV_IN_CONTENT_DIGEST | wire::STAGE_SRV_IN_DECOMPRESS);
    match match_res {
        Found f => {
            sctx.handler_id = f.handler_id;
            sctx.entries_mask = f.entries_mask;
            sctx.ingress_mask = f.ingress_mask | stream_bits;
            sctx.egress_mask = f.egress_mask;
        },
        _ => {},
    };
}

fn resolve_pipeline_route_match(
    cfg:  server::ServerPipelineConfig&,
    req:  const http::Request&,
    ext:  server_internal::RequestExtensions&,
    sctx: server::ServerStageCtx&,
    res:  http::Response&,
) -> server::RouteMatchResult {
    var match_res = server::RouteMatchResult.NotFound;
    let saved_status = res.status_code;
    let rm_v = server::stage_server_route_match(cfg.router, req, ext, match_res, res);
    match rm_v {
        ShortCircuit sc => {
            res.status_code = saved_status;
            if sc.status_code == 405 {
                http::remove_header(res, rfc::HEADER_ALLOW);
            }
        },
        _ => {},
    };
    sync_stage_ctx_with_route(sctx, match_res);
    return match_res;
}

fn verify_pipeline_body_stream<UserStage>(
    cfg:        server::ServerPipelineConfig&,
    req:        const http::Request&,
    sctx:       server::ServerStageCtx&,
    res:        http::Response&,
    user_stage: UserStage&,
) -> bool {
    let stream_bits = wire::STAGE_SRV_IN_CONTENT_DIGEST | wire::STAGE_SRV_IN_DECOMPRESS;
    guard req.body.len > 0 && (sctx.ingress_mask & stream_bits) != 0 else {
        return true;
    }
    var body_stream, ok_bs = server::begin_server_body_stream(req, sctx.ingress_mask);
    guard ok_bs else {
        res.status_code = 400;
        return false;
    }
    let chunk_v = feed_server_body_chunk(cfg, body_stream, req, sctx, req.body[..], true, res);
    match chunk_v {
        Continue => {},
        _ => {
            if res.status_code < 400 {
                res.status_code = 400;
            }
            return false;
        },
    };
    let hook_v = server::on_server_stage(user_stage, wire::ServerHookPhase.BodyChunk, cfg, req, sctx, res);
    return match hook_v {
        Continue => true,
        _ => {
            if res.status_code < 400 {
                res.status_code = 400;
            }
            false
        },
    };
}

// Finalizes slowloris request lifecycle tracking.
inline fn notify_pipeline_timer_end(timer_enabled: bool, timer: server_internal::ConnectionTimer&) {
    if timer_enabled {
        server_internal::notify_request_end(timer);
    }
}

fn complete_pipeline_egress_and_hooks<UserStage>(
    cfg:           server::ServerPipelineConfig&,
    req:           const http::Request&,
    now_ns:        u64,
    res:           http::Response&,
    ext_slot_idx:  i32,
    effective_pso: u64,
    outcome:       server::PipelineOutcome,
    sctx:          server::ServerStageCtx&,
    user_stage:    UserStage&,
) -> server::PipelineOutcome {
    sctx.outcome = outcome;
    if outcome != server::PipelineOutcome.Handled || res.status_code >= 400 {
        let err_v = server::on_server_stage(user_stage, wire::ServerHookPhase.OnError, cfg, req, sctx, res);
        match err_v {
            ShortCircuit sc => {
                res.status_code = if res.status_code != 0 { res.status_code } else { sc.status_code as i32 };
            },
            _ => {},
        };
    }

    if outcome == server::PipelineOutcome.Handled {
        server::dispatch_egress_pipeline(cfg, req, res, effective_pso, now_ns, ext_slot_idx);
        let user_out_v = server::on_server_stage(user_stage, wire::ServerHookPhase.PreSerialize, cfg, req, sctx, res);
        match user_out_v {
            ShortCircuit sc => {
                res.status_code = sc.status_code as i32;
            },
            _ => {},
        };
    }

    handle_head_method_suppression(req.method[..], res);
    let _ = server::on_server_stage(user_stage, wire::ServerHookPhase.AfterResponse, cfg, req, sctx, res);
    return outcome;
}

fn finalize_post_auth_and_egress<UserStage>(
    cfg:           server::ServerPipelineConfig&,
    req:           const http::Request&,
    now_ns:        u64,
    res:           http::Response&,
    out_future:    server_internal::InlineHandlerFuture&,
    match_res:     server::RouteMatchResult,
    ext_slot_idx:  i32,
    effective_pso: u64,
    sctx:          server::ServerStageCtx&,
    user_stage:    UserStage&,
) -> server::PipelineOutcome {
    guard verify_pipeline_body_stream(cfg, req, sctx, res, user_stage) else {
        return server::PipelineOutcome.CsrfRejected;
    }
    var outcome = server::PipelineOutcome.Handled;
    var skip_route = false;
    let user_in_v = server::on_server_stage(user_stage, wire::ServerHookPhase.PostAuth, cfg, req, sctx, res);
    match user_in_v {
        ShortCircuit sc => {
            if res.status_code == 0 {
                res.status_code = sc.status_code as i32;
            }
            skip_route = true;
        },
        Abort _ => {
            outcome = server::PipelineOutcome.CsrfRejected;
            skip_route = true;
        },
        _ => {},
    };

    if !skip_route {
        outcome = dispatch_matched_route(
            cfg, req, now_ns, res, out_future, match_res, ext_slot_idx, sctx, user_stage,
        );
    }
    if outcome == server::PipelineOutcome.Pending {
        sctx.outcome = server::PipelineOutcome.Pending;
        return server::PipelineOutcome.Pending;
    }

    return complete_pipeline_egress_and_hooks(
        cfg, req, now_ns, res, ext_slot_idx, effective_pso, outcome, sctx, user_stage,
    );
}
