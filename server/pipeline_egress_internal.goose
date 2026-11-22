// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal server pipeline egress stages: cache, ETag, compression, security headers, and metrics.
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
import .router_l0_internal;
import .pool;
import .edge_filter;
import .cache;
import .profiler;
import .pipeline;

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
    let gz_level = select_dynamic_gzip_level(res.body.len, level);
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

// Stage 10 (Server Ingress): Coalescing route cache lookup via UFCS `cache.cache_lookup(now_ms)`.
fn stage_server_cache_lookup(
    cache:      server::HttpRouteCache&,
    req:        const http::Request&,
    now_ms:     u64,
    res:        http::Response&,
    handler_id: i32 = -1,
) -> wire::StageVerdict {
    // RFC 9111 Section 3.5: Storing Responses to Authenticated Requests - bypass shared route cache on Authorization
    let has_auth = (req.presence_mask & http::HDR_PRESENCE_AUTHORIZATION) != 0
        || http::has_header(req.headers, rfc::HEADER_AUTHORIZATION);
    guard !has_auth && (req.method[..] == "GET" || req.method[..] == "HEAD") else {
        return wire::StageVerdict.Continue;
    }
    let _prof = server::prof_enter("stage.cache_lookup");
    defer server::prof_leave(_prof);
    let lookup = cache.cache_lookup(now_ms, handler_id, req.url[..]);
    return match lookup {
        HitFresh => populate_cached_response(cache, res),
        HitStaleNeedsUpdate => {
            if !cache.is_updating {
                cache.is_updating = true;
                wire::StageVerdict.Continue
            } else {
                populate_cached_response(cache, res)
            }
        },
        Miss => wire::StageVerdict.Continue,
    };
}

// Stage 0 (Server Egress): RFC 9110 §8.8.3 ETag generation & §13.1.2 `If-None-Match` 304 evaluation.
fn stage_server_etag(
    req:  const http::Request&,
    res:  http::Response&,
    memo: server::ServerCompressAndEtagMemo& = server::ServerCompressAndEtagMemo { .. },
) -> wire::StageVerdict {
    guard res.status_code == 200 else { return wire::StageVerdict.Continue; }
    let _prof = server::prof_enter("stage.etag");
    defer server::prof_leave(_prof);
    if http::get_inline(res.headers, http::WellKnownHeader.ETag).len == 0 && res.body.len > 0 {
        populate_missing_response_etag(res, memo);
    }
    let etag_slice = http::get_inline(res.headers, http::WellKnownHeader.ETag);
    guard etag_slice.len > 0 else { return wire::StageVerdict.Continue; }
    let inm = http::get_inline(req.headers, http::WellKnownHeader.IfNoneMatch);
    if inm.len > 0 && (req.method[..] == "GET" || req.method[..] == "HEAD") {
        let parsed = http::parse_etag(etag_slice);
        if http::match_if_none_match(inm, parsed) {
            res.status_code = 304;
            res.body.clear();
            return wire::StageVerdict.ShortCircuit { status_code: 304 };
        }
    }
    return wire::StageVerdict.Continue;
}

inline fn select_dynamic_gzip_level(body_len: i64, configured_level: i32 = 1) -> i32 {
    if body_len < 128 {
        return 0;
    }
    if configured_level >= 1 && configured_level <= 9 {
        return configured_level;
    }
    return 1;
}

// RFC 9111 Section 5.2.2.6: no-transform - Returns true if Cache-Control contains the no-transform directive.
fn has_cache_no_transform(headers: const http::HeaderMap&) -> bool {
    let cc = http::get_inline(headers, http::WellKnownHeader.CacheControl);
    guard cc.len > 0 else { return false; }
    var tok = core::make_byte_tokenizer(cc, ',');
    while true {
        let dir, ok = core::token_next(tok);
        if !ok { break; }
        let name, _, _ = dir.trim_lws().split_once_byte('=');
        if name.trim_lws().eq_ascii_fold("no-transform") {
            return true;
        }
    }
    return false;
}

// Guard predicate for `stage_server_compress` before invoking zstd/brotli/gzip encoders.
inline fn is_compressible_response(res: const http::Response&, min_bytes: i64 = 1) -> bool {
    guard res.body.len >= min_bytes else { return false; }
    guard res.status_code != 204 && res.status_code != 206 && res.status_code != 304 else {
        return false;
    }
    guard http::get_inline(res.headers, http::WellKnownHeader.ContentEncoding).len == 0 else {
        return false;
    }
    return !has_cache_no_transform(res.headers);
}

// Stage 1..3 (Server Egress): Dynamic response compression (`zstd`, `br`, `gzip`) per `Accept-Encoding`.
fn stage_server_compress(
    req:   const http::Request&,
    res:   http::Response&,
    mask:  u64,
    memo:  server::ServerCompressAndEtagMemo& = server::ServerCompressAndEtagMemo { .. },
    level: i32                                = 1,
) -> wire::StageVerdict {
    guard is_compressible_response(res) else {
        return wire::StageVerdict.Continue;
    }
    let accept_enc = http::get_inline(req.headers, http::WellKnownHeader.AcceptEncoding);
    guard accept_enc.len > 0 else { return wire::StageVerdict.Continue; }
    let _prof = server::prof_enter("stage.compress");
    defer server::prof_leave(_prof);

    let allow_zstd = (mask & (server::STAGE_EGRESS_COMPRESS_ZSTD | wire::STAGE_SRV_OUT_COMPRESS_ZSTD)) != 0;
    let allow_br = (mask & (server::STAGE_EGRESS_COMPRESS_BROTLI | wire::STAGE_SRV_OUT_COMPRESS_BR)) != 0;
    let allow_gzip = (mask & (server::STAGE_EGRESS_COMPRESS_GZIP | wire::STAGE_SRV_OUT_COMPRESS_GZIP)) != 0;

    if allow_zstd && server::client_accepts_encoding(accept_enc, "zstd") && try_compress_zstd(res, memo) {
        return wire::StageVerdict.Continue;
    }
    if allow_br && server::client_accepts_encoding(accept_enc, "br") && try_compress_brotli(res, memo) {
        return wire::StageVerdict.Continue;
    }
    if allow_gzip && server::client_accepts_encoding(accept_enc, "gzip") {
        let gz_level = select_dynamic_gzip_level(res.body.len, level);
        if !try_apply_gzip_memo(res, memo, gz_level) {
            compress_gzip_uncached(res, memo, level);
        }
    }
    return wire::StageVerdict.Continue;
}

// Stage 4 (Server Egress): Coalescing route cache store via UFCS `cache.cache_store(now_ms, body)`.
fn stage_server_cache_store(
    cache:      server::HttpRouteCache&,
    now_ms:     u64,
    res:        http::Response&,
    handler_id: i32         = -1,
    url_key:    const u8[:] = "",
) -> wire::StageVerdict {
    let _prof = server::prof_enter("stage.cache_store");
    defer server::prof_leave(_prof);
    // RFC 9111 Section 4.1: Calculating Cache Keys with the Vary Header Field - skip unkeyed Vary responses
    if res.status_code == 200 && res.body.len > 0 && !http::has_header(res.headers, rfc::HEADER_VARY) {
        let ctype = http::get_inline(res.headers, http::WellKnownHeader.ContentType);
        let existing_etag = http::get_inline(res.headers, http::WellKnownHeader.ETag);
        if existing_etag.len > 0 {
            let _ = cache.cache_store(now_ms, res.body[..], handler_id, ctype, url_key, existing_etag);
        } else {
            var etag_buf: u8[..32] = [];
            etag_buf.push('"');
            let body_hash = core::xxh64(res.body[..], 0);
            body_hash.format_u64_hex(etag_buf);
            etag_buf.push('"');
            if !res.headers.append_known_pipeline_header(
                rfc::HEADER_ETAG,
                etag_buf[..],
                http::SLOT_ETAG,
                0,
                http::HASH_HDR_ETAG,
                false,
            ) {
                let _ = http::append_header(res.headers, rfc::HEADER_ETAG, etag_buf[..]);
            }
            let _ = cache.cache_store(now_ms, res.body[..], handler_id, ctype, url_key, etag_buf[..]);
        }
    } else {
        cache.is_updating = false;
    }
    return wire::StageVerdict.Continue;
}

// Stage 5 (Server Egress): Cross-origin isolation and HSTS security headers.
fn stage_server_security_headers(res: http::Response&) -> wire::StageVerdict {
    let _prof = server::prof_enter("stage.security_headers");
    defer server::prof_leave(_prof);
    let existing_vary = http::get_inline(res.headers, http::WellKnownHeader.Vary);
    let existing_hsts = http::get_inline(res.headers, http::WellKnownHeader.StrictTransportSecurity);
    if existing_hsts.len > 0 && core::starts_with(existing_vary, rfc::FETCH_METADATA_VARY_VALUE) {
        return wire::StageVerdict.Continue;
    }
    if existing_vary.len == 0 && existing_hsts.len == 0 {
        if !res.headers.append_known_pipeline_header(
            rfc::HEADER_VARY,
            rfc::FETCH_METADATA_VARY_VALUE,
            http::SLOT_VARY,
            http::HEADER_FLAG_CONTAINS_COMMA,
            rfc::HASH_HDR_VARY,
            true,
        ) {
            let _ = http::append_header(res.headers, rfc::HEADER_VARY, rfc::FETCH_METADATA_VARY_VALUE);
        }
        if !res.headers.append_known_pipeline_header(
            rfc::HEADER_STRICT_TRANSPORT_SECURITY,
            rfc::HSTS_DEFAULT_VALUE,
            http::SLOT_HSTS,
            http::HEADER_FLAG_SECURITY_STATE,
            rfc::HASH_HDR_STRICT_TRANSPORT_SECURITY,
            false,
        ) {
            let _ = http::append_header(res.headers, rfc::HEADER_STRICT_TRANSPORT_SECURITY, rfc::HSTS_DEFAULT_VALUE);
        }
        return wire::StageVerdict.Continue;
    }
    security::apply_isolation_headers(res);
    return wire::StageVerdict.Continue;
}

// Stage 7..8 (Server Egress): RFC 9218 / Server-Timing metrics and access log emission.
fn stage_server_metrics_log(
    ext:    const RequestExtensions&,
    res:    http::Response&,
    mask:   u64,
    now_ns: u64,
) -> wire::StageVerdict {
    let _prof = server::prof_enter("stage.metrics_log");
    defer server::prof_leave(_prof);
    let want_metrics = (mask & (server::STAGE_EGRESS_METRICS | wire::STAGE_SRV_OUT_METRICS)) != 0;
    let want_log = (mask & (server::STAGE_EGRESS_ACCESS_LOG | wire::STAGE_SRV_OUT_ACCESS_LOG)) != 0;
    let has_timing = has_custom_header_hash(
        res.headers,
        rfc::HEADER_SERVER_TIMING,
        http::HASH_HDR_SERVER_TIMING,
    );
    if want_metrics && !has_timing {
        let dur_ns = if now_ns >= ext.start_time_ns && ext.start_time_ns > 0 {
            core::sub_sat_u64(now_ns, ext.start_time_ns)
        } else {
            0
        };
        var timing_buf: u8[..64] = [];
        timing_buf.append("wing;dur=");
        let _ = http::format_dur_ms_tenths(dur_ns, timing_buf);
        if !res.headers.append_known_pipeline_header(
            rfc::HEADER_SERVER_TIMING,
            timing_buf[..],
            0xFF,
            0,
            http::HASH_HDR_SERVER_TIMING,
            false,
        ) {
            let _ = http::append_header(res.headers, rfc::HEADER_SERVER_TIMING, timing_buf[..]);
        }
    }
    if want_log
        && ext.matched_route.len > 0
        && !has_custom_header_hash(res.headers, "X-Matched-Route", http::HASH_HDR_X_MATCHED_ROUTE) {
        append_matched_route_log_header(res.headers, ext.matched_route[..]);
    }
    return wire::StageVerdict.Continue;
}

// Executes post-handler egress stages matching the effective PSO or server egress mask.
fn dispatch_egress_pipeline(
    cfg:          server::ServerPipelineConfig&,
    req:          const http::Request&,
    res:          http::Response&,
    mask:         u64,
    now_ns:       u64 = 0,
    ext_slot_idx: i32 = -1,
) {
    let egress_mask = mask & 0xFFFFFFFF00000000;
    let compress_bits = server::STAGE_EGRESS_COMPRESS_GZIP |
        server::STAGE_EGRESS_COMPRESS_BROTLI |
        server::STAGE_EGRESS_COMPRESS_ZSTD;
    if (egress_mask & compress_bits) != 0 {
        let _ = stage_server_compress(req, res, egress_mask, cfg.memo, cfg.gzip_level);
    }
    if http::header(req, rfc::HEADER_WANT_CONTENT_DIGEST).len > 0 && res.body.len > 0 {
        let _ = http::set_response_content_digest(res);
    }
    if (egress_mask & server::STAGE_EGRESS_ETAG) != 0 {
        let _ = stage_server_etag(req, res, cfg.memo);
    }
    if (egress_mask & server::STAGE_EGRESS_SECURITY_HEADERS) != 0 {
        let _ = stage_server_security_headers(res);
    }
    if (egress_mask & (server::STAGE_EGRESS_METRICS | server::STAGE_EGRESS_ACCESS_LOG)) != 0 {
        if ext_slot_idx >= 0 && ext_slot_idx < cfg.ext_pool.slots.len {
            let _ = stage_server_metrics_log(cfg.ext_pool.slots[ext_slot_idx], res, egress_mask, now_ns);
        } else {
            var dummy_ext = RequestExtensions { start_time_ns: now_ns, .. };
            let _ = stage_server_metrics_log(dummy_ext, res, egress_mask, now_ns);
        }
    }
}
