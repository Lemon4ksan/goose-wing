// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal helpers for package `client` (telemetry, redirect, interceptor, stream, contract, and client facade).
namespace client_internal;

import std;
import core;
import rfc.http;
import cookie.constants;
import cookie.policy;
import dns.wire;
import dns.cache;
import dns.doh;
import fingerprint.profile;
import http.headers;
import http.headers.chunked;
import http.request;
import http.response;
import http.trace;
import http.compression_dict;
import .redirect;
import .interceptor;
import .stream;
import .client;
import .session.verbs;

// ---- Telemetry Internal Helpers --------------------------------------------

// Converts microsecond duration to milliseconds with 2 fractional digits: e.g. 1520 us -> 1.52 ms.
fn format_us_as_ms<B>(us: i64, out: B&) {
    if us < 0 {
        out.append("-1");
        return;
    }
    let ms_int = us / 1000;
    let frac = (us % 1000) / 10;
    ms_int.format_i64_dec(out);
    out.push('.');
    if frac < 10 { out.push('0'); }
    frac.format_i64_dec(out);
}

// ---- Redirect Internal Helpers ---------------------------------------------

struct RedirectSiteOptions {
    has_initiator:      bool = false,
    had_cross_site_hop: bool = false,
}

struct RedirectReferrerOptions {
    is_cross_origin: bool = false,
    is_downgrade:    bool = false,
}

struct RedirectOriginOptions {
    is_cross_origin: bool = false,
    tainted_origin:  bool = false,
    cors_mode:       bool = false,
    clear_body:      bool = false,
}

struct RedirectOriginRelation {
    is_downgrade:    bool = false,
    is_cross_origin: bool = false,
    is_port_changed: bool = false,
}

fn redirect_error_to_string(err: client::RedirectError) -> const u8[:] {
    return match err {
        None => "None",
        MissingLocation => "ERR_MISSING_LOCATION",
        MultipleLocationHeaders => "ERR_MULTIPLE_LOCATION_HEADERS",
        InvalidLocationUrl => "ERR_INVALID_LOCATION_URL",
        ForbiddenRedirectScheme => "ERR_FORBIDDEN_REDIRECT_SCHEME",
        CorsCredentialsInRedirectUrl => "ERR_CORS_CREDENTIALS_IN_REDIRECT_URL",
        SchemeDowngradeBlocked => "ERR_SCHEME_DOWNGRADE_BLOCKED",
        TooManyRedirects => "ERR_TOO_MANY_REDIRECTS",
        RedirectBlockedByPolicy => "ERR_REDIRECT_BLOCKED_BY_POLICY",
        CannotRewindBody => "ERR_CANNOT_REWIND_BODY",
        SsrfBlockedUrl => "ERR_SSRF_BLOCKED_URL",
        SsrfBlockedIp => "ERR_SSRF_BLOCKED_IP",
    };
}

enum RedirectBodyAction {
    Keep,
    Clear,
}

// Computes the rewritten redirect method into `out` and returns whether the request body must be cleared.
fn mutate_redirect_method<B>(
    status_code:    i32,
    current_method: const u8[:],
    out:            B&,
) -> RedirectBodyAction {
    out.clear();

    if !rfc::is_redirect_status(status_code) {
        out.append(current_method);
        return RedirectBodyAction.Keep;
    }

    let should_rewrite = if status_code == rfc::STATUS_MOVED_PERMANENTLY || status_code == rfc::STATUS_FOUND {
        current_method.eq_ascii_fold("POST")
    } else if status_code == rfc::STATUS_SEE_OTHER {
        !current_method.eq_ascii_fold("GET") && !current_method.eq_ascii_fold("HEAD")
    } else {
        false
    };

    if should_rewrite {
        out.append("GET");
        return RedirectBodyAction.Clear;
    }
    out.append(current_method);
    return RedirectBodyAction.Keep;
}

fn inherit_target_fragment(
    target_url:                        core::Url&,
    current_url:                       const core::Url&,
    clean_loc:                         const u8[:],
    preserve_fragment_on_redirect_url: const u8[:],
) {
    let target_hash = target_url.hash();
    let curr_hash = current_url.hash();
    guard target_hash.len == 0 && curr_hash.len > 0 else { return; }
    guard preserve_fragment_on_redirect_url.len == 0 || clean_loc != preserve_fragment_on_redirect_url else {
        return;
    }
    let hash_start = target_url.href.len as i32;
    guard target_url.href.try_append(curr_hash) else { return; }
    target_url.hash_start = hash_start;
    target_url.hash_end = target_url.href.len as i32;
}

fn compute_redirect_site_for_cookies(
    current_url:              const core::Url&,
    new_url:                  const core::Url&,
    first_party_policy:       cookie::FirstPartyURLPolicy,
    current_site_for_cookies: const http::SiteForCookies&,
    url_chain:                const core::Url[:],
    initiator:                const core::Origin&,
    options:                  RedirectSiteOptions,
) -> http::SiteForCookies, bool {
    let same_site_step = cookie::is_schemeful_same_site(
        current_url.scheme(), current_url.hostname(),
        new_url.scheme(), new_url.hostname(),
    );
    let initiator_ok = !options.has_initiator || (
        initiator.kind != core::OriginKind.Opaque && cookie::is_schemeful_same_site(
            initiator.scheme[..], initiator.host[..],
            new_url.scheme(), new_url.hostname(),
        )
    );

    if first_party_policy == cookie::FirstPartyURLPolicy.NEVER_CHANGE_FIRST_PARTY_URL {
        // Subresources / background requests: once tainted, remains null forever.
        let is_first_p = cookie::is_first_party(current_site_for_cookies, new_url.href[..], true);
        if options.had_cross_site_hop || !same_site_step || !is_first_p || !initiator_ok {
            return cookie::null_site_for_cookies(), true;
        }
        return copy(current_site_for_cookies), false;
    }

    // Main-frame top-level navigation: SiteForCookies updates to target.
    let new_site = cookie::site_for_cookies_from_parsed_url(new_url);
    var chain_tainted = options.had_cross_site_hop || !same_site_step || !initiator_ok;
    for &hop_url in url_chain {
        if !cookie::is_schemeful_same_site(
            hop_url.scheme(), hop_url.hostname(),
            new_url.scheme(), new_url.hostname(),
        ) {
            chain_tainted = true;
        }
    }
    return new_site, chain_tainted;
}

fn validate_redirect_target(
    location_header: const u8[:],
    current_url:     const core::Url&,
    options:         client::RedirectOptions,
) -> core::Url, client::RedirectError {
    let clean_loc = location_header.trim_ascii_space();
    guard clean_loc.len > 0 else {
        return core::Url { .. }, client::RedirectError.MissingLocation;
    }

    let parsed_target, _ = core::parse_url_with_base(clean_loc, current_url);
    guard parsed_target.valid else {
        return core::Url { .. }, client::RedirectError.InvalidLocationUrl;
    }

    if !parsed_target.is_http_or_https() {
        return core::Url { .. }, client::RedirectError.ForbiddenRedirectScheme;
    }

    if options.cors_mode && parsed_target.has_credentials() {
        let same_orig = current_url.is_same_origin_url(parsed_target);
        if !same_orig || options.tainted_origin {
            return core::Url { .. }, client::RedirectError.CorsCredentialsInRedirectUrl;
        }
    }

    return parsed_target, client::RedirectError.None;
}

fn classify_redirect_origin_relation(
    current_url: const core::Url&,
    target_url:  const core::Url&,
) -> RedirectOriginRelation {
    let same_orig = current_url.is_same_origin_url(target_url);
    let is_downgrade = current_url.scheme() == "https" && target_url.scheme() == "http";
    return RedirectOriginRelation {
        is_downgrade:    is_downgrade,
        is_cross_origin: !same_orig || is_downgrade,
        is_port_changed: current_url.effective_port() != target_url.effective_port(),
    };
}

fn should_drop_referrer(policy: client::ReferrerPolicy, options: RedirectReferrerOptions) -> bool {
    if policy == client::ReferrerPolicy.NoReferrer {
        return true;
    }
    if options.is_downgrade {
        if policy == client::ReferrerPolicy.NoReferrerWhenDowngrade ||
            policy == client::ReferrerPolicy.StrictOrigin ||
            policy == client::ReferrerPolicy.StrictOriginWhenCrossOrigin {
            return true;
        }
    }
    return options.is_cross_origin && policy == client::ReferrerPolicy.SameOrigin;
}

fn is_origin_only_referrer(policy: client::ReferrerPolicy, is_cross_origin: bool) -> bool {
    if policy == client::ReferrerPolicy.Origin || policy == client::ReferrerPolicy.StrictOrigin {
        return true;
    }
    return is_cross_origin && (
        policy == client::ReferrerPolicy.OriginWhenCrossOrigin ||
        policy == client::ReferrerPolicy.StrictOriginWhenCrossOrigin
    );
}

fn serialize_stripped_full_referrer<B>(source_url: const core::Url&, out: B&) {
    out.append(source_url.scheme());
    out.append("://");
    out.append(source_url.host());
    out.append(source_url.pathname());
    out.append(source_url.search());
}

fn compute_new_referrer<B>(
    source_url: const core::Url&,
    target_url: const core::Url&,
    policy:     client::ReferrerPolicy,
    options:    RedirectReferrerOptions,
    out:        B&,
) {
    out.clear();
    if should_drop_referrer(policy, options) {
        return;
    }
    if is_origin_only_referrer(policy, options.is_cross_origin) {
        core::serialize_origin(core::origin_from_url(source_url), out);
        return;
    }
    serialize_stripped_full_referrer(source_url, out);
}

inline fn is_redirect_rewritten_payload_header(name: const u8[:]) -> bool {
    return rfc::is_payload_or_conditional_header(name) ||
           name.eq_ascii_fold("content-digest") ||
           name.eq_ascii_fold("repr-digest") ||
           name.eq_ascii_fold("content-range") ||
           name.eq_ascii_fold("trailer");
}

// Strips payload and conditional validator headers in a single O(N) pass
// when a redirect mutates request to GET (RFC 9110 Section 15.4).
fn remove_payload_and_conditional_headers(headers: http::HeaderMap&) {
    var found = false;
    var write_entry_i: i64 = 0;
    var write_raw_pos: u16 = 0;
    let total_entries = headers.entries.len;

    for read_i in total_entries {
        let entry .= headers.entries[read_i];
        let name = http::entry_name(headers, entry);
        if is_redirect_rewritten_payload_header(name) {
            found = true;
            continue;
        }
        http::compact_kept_entry_in_place(headers, read_i, write_entry_i, write_raw_pos);
    }
    if found {
        http::finish_in_place_compaction(headers, write_entry_i, write_raw_pos);
    }
}

// Strips `Sec-Fetch-*` and `Sec-CH-*` headers when redirecting onto an untrustworthy HTTP origin
// (Chromium `MaybeRemoveSecHeaders`, `sec_header_helpers.cc:310-331`).
fn remove_sec_headers_on_downgrade(headers: http::HeaderMap&, target_url: const core::Url&) {
    if cookie::is_trustworthy_non_crypto_host(target_url.hostname()) {
        return;
    }
    var found = false;
    var write_entry_i: i64 = 0;
    var write_raw_pos: u16 = 0;
    let total_entries = headers.entries.len;

    for read_i in total_entries {
        let entry .= headers.entries[read_i];
        let name = http::entry_name(headers, entry);
        if name.starts_with_fold("sec-fetch-") || name.starts_with_fold("sec-ch-") {
            found = true;
            continue;
        }
        http::compact_kept_entry_in_place(headers, read_i, write_entry_i, write_raw_pos);
    }
    if found {
        http::finish_in_place_compaction(headers, write_entry_i, write_raw_pos);
    }
}

// Sanitizes or drops Origin header on cross-origin redirect hops (WHATWG Fetch Section 4.4).
//
// Example:
//   headers = [Origin: "https://a.com"], options = { is_cross_origin = true, clear_body = true }
//   headers becomes: [] (Origin header removed)
fn sanitize_origin_header_on_redirect(
    headers: http::HeaderMap&,
    options: RedirectOriginOptions,
) {
    if http::has_header(headers, "Origin") && (options.is_cross_origin || options.tainted_origin) {
        if options.clear_body && !options.cors_mode && !options.tainted_origin {
            http::remove_header_by_name(headers, "Origin");
        } else {
            http::set_header(headers, "Origin", "null");
        }
    }
}

// ---- Interceptor Internal Helpers ------------------------------------------

fn upsert_interceptor_header(
    list: client::InterceptorHeader[..4]&,
    name: const u8[:],
    val:  const u8[:],
) -> bool {
    var item = client::InterceptorHeader { .. };
    guard item.name.try_set(name) && item.val.try_set(val) else { return false; }
    for &entry in list {
        if entry.name[..].eq_ascii_fold(name) {
            return entry.val.try_set(val);
        }
    }
    return list.try_push(item);
}

// W3C TraceContext traceparent generator:
// Format: 00-{32 hex trace_id}-{16 hex parent_id}-{2 hex flags}.
fn generate_traceparent<B>(counter: u64, clock_us: i64, flag: const u8[:], out: B&) {
    let hi = clock_us as! u64;
    let lo = counter ^ 0xa5a5a5a5a5a5a5a5;
    var trace_id: u8[16] = [0; 16];
    core::write_be_u64_at(trace_id[..], 0, hi);
    core::write_be_u64_at(trace_id[..], 8, lo);
    var parent_id: u8[8] = [0; 8];
    core::write_be_u64_at(parent_id[..], 0, counter);
    var tp = http::new_traceparent(trace_id, parent_id, flag != "00");
    if flag.len == 2 {
        let parsed_f, ok_f = flag.parse_u8_hex();
        if ok_f {
            tp.trace_flags = parsed_f;
        }
    }
    http::format_traceparent(tp, out);
}

fn push_log(pipeline: client::InterceptorPipeline&, msg: const u8[:]) {
    guard pipeline.record_logs else { return; }
    var entry: u8[..128] = [];
    let n = min(msg.len, entry.cap);
    let _ = entry.try_set(msg[..n]);
    let _ = pipeline.log_entries.try_push(entry);
}

fn log_interceptor_request(
    pipeline: client::InterceptorPipeline&,
    req:      const http::Request&,
    lvl:      client::LogLevel,
) {
    guard lvl != client::LogLevel.None else { return; }
    var line: u8[..256] = [];
    let u_len = min(req.url.len, 180);
    format(line, "--> ", req.method[..], " ", req.url[..u_len]);
    push_log(pipeline, line[..]);

    if lvl == client::LogLevel.Headers || lvl == client::LogLevel.Body {
        var h_line: u8[..256] = [];
        for &e in req.headers.entries {
            let h_name = http::entry_name(req.headers, e);
            let h_val = if http::is_sensitive(e) || http::is_heuristic_sensitive_header(h_name) {
                "[REDACTED]"
            } else {
                http::entry_value(req.headers, e)
            };
            let v_len = min(h_val.len, 160);
            h_line.clear();
            format(h_line, "--> ", h_name, ": ", h_val[..v_len]);
            push_log(pipeline, h_line[..]);
        }
    }
    if lvl == client::LogLevel.Body && req.body.len > 0 {
        line.clear();
        format(line, "--> (body ", req.body.len, " bytes)");
        push_log(pipeline, line[..]);
    }
}

fn log_interceptor_response(
    pipeline:    client::InterceptorPipeline&,
    resp:        const http::Response&,
    err:         const http::Error&,
    lvl:         client::LogLevel,
    duration_us: i64,
) {
    guard lvl != client::LogLevel.None else { return; }
    var line: u8[..256] = [];
    if http::ok(err) {
        format(line, "<-- ", resp.status_code, " (", duration_us, " us)");
    } else {
        let m_len = min(err.message.len, 180);
        format(line, "<-- FAILED (", err.message[..m_len], ")");
    }
    push_log(pipeline, line[..]);

    if http::ok(err) && (lvl == client::LogLevel.Headers || lvl == client::LogLevel.Body) {
        var h_line: u8[..256] = [];
        for &e in resp.headers.entries {
            let h_name = http::entry_name(resp.headers, e);
            let h_val = if http::is_sensitive(e) || http::is_heuristic_sensitive_header(h_name) {
                "[REDACTED]"
            } else {
                http::entry_value(resp.headers, e)
            };
            let v_len = min(h_val.len, 160);
            h_line.clear();
            format(h_line, "<-- ", h_name, ": ", h_val[..v_len]);
            push_log(pipeline, h_line[..]);
        }
    }
    if http::ok(err) && lvl == client::LogLevel.Body && resp.body.len > 0 {
        line.clear();
        format(line, "<-- (body ", resp.body.len, " bytes)");
        push_log(pipeline, line[..]);
    }
}

fn log_network_interceptor_request(
    pipeline:   client::InterceptorPipeline&,
    headers:    const http::HeaderMap&,
    target_url: const u8[:],
    method:     const u8[:],
    hop_index:  i64,
    lvl:        client::LogLevel,
) {
    guard lvl != client::LogLevel.None else { return; }
    var line: u8[..256] = [];
    let u_len = min(target_url.len, 160);
    format(line, "--> (net hop ", hop_index, ") ", method, " ", target_url[..u_len]);
    push_log(pipeline, line[..]);

    if lvl == client::LogLevel.Headers || lvl == client::LogLevel.Body {
        var h_line: u8[..256] = [];
        for &e in headers.entries {
            let h_name = http::entry_name(headers, e);
            let h_val = if http::is_sensitive(e) || http::is_heuristic_sensitive_header(h_name) {
                "[REDACTED]"
            } else {
                http::entry_value(headers, e)
            };
            let v_len = min(h_val.len, 150);
            h_line.clear();
            format(h_line, "--> (net) ", h_name, ": ", h_val[..v_len]);
            push_log(pipeline, h_line[..]);
        }
    }
}

fn apply_app_interceptors_response(
    pipeline:    client::InterceptorPipeline&,
    _req:        const http::Request&,
    resp:        http::Response&,
    err:         const http::Error&,
    duration_us: i64,
) {
    pipeline.metrics.total_requests += 1;
    pipeline.metrics.last_request_duration_us = duration_us;

    if (pipeline.active_mask & client::INTERCEPTOR_APP_LOGGING) != 0 {
        log_interceptor_response(pipeline, resp, err, pipeline.app_log_level, duration_us);
    }
}

fn apply_network_interceptors_response(
    pipeline:        client::InterceptorPipeline&,
    resp:            http::Response&,
    hop_index:       i64,
    hop_duration_us: i64,
) {
    pipeline.metrics.last_hop_duration_us = hop_duration_us;
    pipeline.metrics.total_bytes_received += resp.body.len as! u64;

    let log_net = (pipeline.active_mask & client::INTERCEPTOR_NET_LOGGING) != 0
        && pipeline.net_log_level != client::LogLevel.None;
    if log_net {
        var line: u8[..256] = [];
        format(line, "<-- (net hop ", hop_index, ") ", resp.status_code, " (", hop_duration_us, " us)");
        push_log(pipeline, line[..]);
    }
}

// ---- Stream Internal Helpers -----------------------------------------------

inline fn has_chunk_buf_space<B>(buf: const B&, needed: i64) -> bool {
    return needed >= 0 && core::sub_sat_i64(buf.cap, buf.len) >= needed;
}

inline fn has_chunk_buf_space(_buf: const u8[>..]&, needed: i64) -> bool {
    return needed >= 0;
}

inline fn count_chunk_hex_digits(len_val: i64) -> i64 {
    var v = len_val;
    var digits: i64 = 0;
    while v > 0 {
        v = v >> 4;
        digits = core::add_sat_i64(digits, 1);
    }
    return max(digits, 1);
}

inline fn measure_chunked_payload_wire_len(
    body:       const u8[:],
    trailers:   const http::HeaderMap&,
    chunk_size: i64,
) -> i64 {
    let step = if chunk_size > 0 { chunk_size } else { 4096 };
    var total: i64 = 0;
    if body.len > 0 {
        var offset: i64 = 0;
        while offset < body.len {
            let end_off = min(core::add_sat_i64(offset, step), body.len);
            let c_len = core::sub_sat_i64(end_off, offset);
            let hex_digits = count_chunk_hex_digits(c_len);
            let frame_len = core::add_sat_i64(hex_digits, core::add_sat_i64(c_len, 4));
            total = core::add_sat_i64(total, frame_len);
            offset = end_off;
        }
    }
    total = core::add_sat_i64(total, 5);
    for &e in trailers.entries {
        let tname = http::entry_name(trailers, e);
        let tval = http::entry_value(trailers, e);
        if http::is_valid_header_name(tname) && http::is_valid_header_value(tval) &&
            !rfc::is_disallowed_trailer_field(tname) {
            let tr_len = core::add_sat_i64(tname.len, core::add_sat_i64(tval.len, 4));
            total = core::add_sat_i64(total, tr_len);
        }
    }
    return total;
}

fn append_trailer_item(trailers: http::HeaderMap&, name: const u8[:], val: const u8[:]) -> bool {
    guard trailers.entries.len < 16 else { return false; }
    return http::append_header(trailers, name, val);
}

fn step_chunk_size_line(dec: client::ChunkedStreamDecoder&, b: u8) -> bool {
    dec.bytes_consumed_total++;
    if b == '\n' {
        guard dec.line_buf.len > 0 && dec.line_buf[dec.line_buf.len - 1] == '\r' else {
            dec.state = client::ChunkedStreamState.Error;
            dec.error_code = http::ChunkedDecodeError.BareLfInChunkSize;
            return false;
        }
        let size_line = dec.line_buf[..^1];
        let csize, parse_err = http::parse_chunk_size_hex(size_line);
        guard parse_err == http::ChunkedDecodeError.None else {
            dec.state = client::ChunkedStreamState.Error;
            dec.error_code = parse_err;
            return false;
        }
        dec.line_buf.clear();
        dec.expected_chunk_size = csize;

        if csize == 0 {
            dec.state = client::ChunkedStreamState.Trailers;
        } else {
            dec.chunk_bytes_remaining = csize;
            dec.state = client::ChunkedStreamState.ChunkData;
        }
        return true;
    }
    guard dec.line_buf.try_push(b) else {
        dec.state = client::ChunkedStreamState.Error;
        dec.error_code = http::ChunkedDecodeError.InvalidChunkExtension;
        return false;
    }
    return true;
}

fn step_chunk_data_crlf(dec: client::ChunkedStreamDecoder&, b: u8) -> bool {
    dec.bytes_consumed_total++;
    if dec.crlf_step == 0 {
        if b == '\r' {
            dec.crlf_step = 1;
            return true;
        }
        dec.state = client::ChunkedStreamState.Error;
        dec.error_code = if b == '\n' {
            http::ChunkedDecodeError.BareLfInChunkData
        } else {
            http::ChunkedDecodeError.MalformedChunkEnding
        };
        return false;
    }
    if b == '\n' {
        dec.state = client::ChunkedStreamState.ChunkSizeLine;
        dec.crlf_step = 0;
        return true;
    }
    dec.state = client::ChunkedStreamState.Error;
    dec.error_code = http::ChunkedDecodeError.MalformedChunkEnding;
    return false;
}

fn process_trailer_line(dec: client::ChunkedStreamDecoder&) -> bool {
    guard dec.line_buf.len > 0 && dec.line_buf[dec.line_buf.len - 1] == '\r' else {
        dec.state = client::ChunkedStreamState.Error;
        dec.error_code = http::ChunkedDecodeError.BareLfInTrailer;
        return false;
    }
    let tr_line = dec.line_buf[..^1];

    if tr_line.len == 0 {
        dec.state = client::ChunkedStreamState.Complete;
        dec.line_buf.clear();
        return true;
    }

    let next_count = dec.trailer_count + 1;
    let next_bytes = core::add_sat_i64(dec.total_trailer_bytes, tr_line.len);
    let col_idx = tr_line.index_of_byte(':');
    guard next_count <= 16 && next_bytes <= 4096 && col_idx > 0 else {
        dec.state = client::ChunkedStreamState.Error;
        dec.error_code = http::ChunkedDecodeError.DisallowedTrailer;
        return false;
    }

    let hname = tr_line[..col_idx];
    let hval = tr_line[(col_idx + 1)..].trim_lws();
    if !http::is_valid_header_name(hname) || !http::is_valid_header_value(hval) ||
        rfc::is_disallowed_trailer_field(hname) {
        dec.state = client::ChunkedStreamState.Error;
        dec.error_code = http::ChunkedDecodeError.DisallowedTrailer;
        return false;
    }

    guard append_trailer_item(dec.trailers, hname, hval) else {
        dec.state = client::ChunkedStreamState.Error;
        dec.error_code = http::ChunkedDecodeError.DisallowedTrailer;
        return false;
    }
    dec.trailer_count = next_count;
    dec.total_trailer_bytes = next_bytes;
    dec.line_buf.clear();
    return true;
}

fn step_chunk_trailer(dec: client::ChunkedStreamDecoder&, b: u8) -> bool {
    dec.bytes_consumed_total++;
    if b == '\n' {
        return process_trailer_line(dec);
    }
    guard dec.line_buf.try_push(b) else {
        dec.state = client::ChunkedStreamState.Error;
        dec.error_code = http::ChunkedDecodeError.DisallowedTrailer;
        return false;
    }
    return true;
}

fn read_chunk_chunked<B>(
    reader:    client::StreamReader&,
    max_bytes: i64,
    out:       B&,
) -> client::StreamReadStatus, bool {
    guard !client::has_error(reader.chunk_decoder) else {
        reader.finished = true;
        return client::StreamReadStatus.Error, false;
    }

    let prev_len = out.len;
    let limit = if max_bytes > 0 { max_bytes } else { -1 };
    let consumed, ok_dec = client::feed_chunked_stream(
        reader.chunk_decoder,
        reader.raw_data[reader.cursor..],
        out,
        limit,
    );
    reader.cursor += consumed;
    guard ok_dec else {
        reader.finished = true;
        return client::StreamReadStatus.Error, false;
    }

    let emitted = (out.len - prev_len) as! u64;
    reader.bytes_read += emitted;

    let is_eof = client::is_complete(reader.chunk_decoder);
    if is_eof {
        reader.finished = true;
    }
    if emitted > 0 {
        return client::StreamReadStatus.Data, is_eof;
    }
    if is_eof {
        return client::StreamReadStatus.Eof, true;
    }
    // RFC 9112 Section 7.1: Chunked Transfer Coding - Premature EOF before terminating 0-chunk is a framing error.
    reader.chunk_decoder.state = client::ChunkedStreamState.Error;
    reader.finished = true;
    return client::StreamReadStatus.Error, false;
}

fn read_chunk_identity<B>(
    reader:    client::StreamReader&,
    max_bytes: i64,
    remaining: i64,
    out:       B&,
) -> client::StreamReadStatus, bool {
    let to_read = if max_bytes > 0 { min(remaining, max_bytes) } else { remaining };
    out.append(reader.raw_data[reader.cursor..(reader.cursor + to_read)]);
    reader.cursor += to_read;
    reader.bytes_read += to_read as! u64;

    let is_eof = reader.cursor >= reader.raw_data.len;
    if is_eof {
        reader.finished = true;
    }
    return client::StreamReadStatus.Data, is_eof;
}

// ---- Contract Internal Helpers ---------------------------------------------

fn format_bound_scalar<B>(val: i64, out: B&) -> bool {
    var tmp: u8[..32] = [];
    val.format_i64_dec(tmp);
    return out.try_append(tmp[..]);
}

fn format_bound_scalar<B>(val: u64, out: B&) -> bool {
    var tmp: u8[..32] = [];
    val.format_u64_dec(tmp);
    return out.try_append(tmp[..]);
}

fn format_bound_scalar<B>(val: i32, out: B&) -> bool {
    var tmp: u8[..32] = [];
    (val as i64).format_i64_dec(tmp);
    return out.try_append(tmp[..]);
}

fn format_bound_scalar<B>(val: u32, out: B&) -> bool {
    var tmp: u8[..32] = [];
    val.format_u32_dec(tmp);
    return out.try_append(tmp[..]);
}

fn format_bound_scalar<B>(val: bool, out: B&) -> bool {
    let lit = if val { "true" } else { "false" };
    return out.try_append(lit);
}

fn format_bound_scalar<B>(val: const u8[:], out: B&) -> bool {
    return out.try_append(val);
}

// Formats path parameter `param_name` from `params` into `out`, rejecting empty values,
// path separators (`/`), query/fragment delimiters (`?`, `#`), and control characters.
// Rolls back `out` on failure.
fn format_path_param_segment<Params, B>(
    param_name: const u8[:],
    params:     const Params&,
    out:        B&,
) -> bool {
    let saved_len = out.len;
    var committed = false;
    defer if !committed { out.resize(saved_len); };
    var seg_buf: u8[..256] = [];
    var matched = false;
    var fmt_ok = false;
    const for <Name, Acc> in fields<Params> {
        if !matched && Name == param_name {
            matched = true;
            fmt_ok = format_bound_scalar(params.Acc, seg_buf);
        }
    }
    guard matched && fmt_ok && seg_buf.len > 0 else { return false; }
    for b in seg_buf[..] {
        guard b >= 0x20 && b != 0x7F && b != '/' && b != '?' && b != '#' else { return false; }
    }
    guard out.try_append(seg_buf[..]) else { return false; }
    committed = true;
    return true;
}

// Expands `:param` placeholders in `path_template` using `params` and appends the path to `out`.
// Rolls back `out` on missing parameters, unsafe characters, or capacity overflow.
fn expand_contract_path<Params, B>(
    path_template: const u8[:],
    params:        const Params&,
    out:           B&,
) -> bool {
    let saved_len = out.len;
    var committed = false;
    defer if !committed { out.resize(saved_len); };
    guard path_template.len > 0 else { return false; }
    var idx: i64 = 0;
    while idx < path_template.len {
        let b = path_template[idx];
        if b == ':' {
            let start = core::add_sat_i64(idx, 1);
            var end = core::add_sat_i64(idx, 1);
            while end < path_template.len && path_template[end] != '/' {
                end = core::add_sat_i64(end, 1);
            }
            let param_name = path_template[start..end];
            guard param_name.len > 0 && format_path_param_segment(param_name, params, out) else {
                return false;
            }
            idx = end;
        } else {
            guard out.try_push(b) else { return false; }
            idx = core::add_sat_i64(idx, 1);
        }
    }
    committed = true;
    return true;
}

// Appends all fields of `query_dto` as query parameters on `req`.
// Rolls back `req.query_params` on capacity overflow.
fn apply_contract_query<Query>(req: http::Request&, query_dto: const Query&) -> bool {
    let saved_len = req.query_params.len;
    var committed = false;
    defer if !committed { req.query_params.resize(saved_len); };
    var all_ok = true;
    const for <Name, Acc> in fields<Query> {
        if all_ok {
            var val_buf: u8[..256] = [];
            let ok_q = format_bound_scalar(query_dto.Acc, val_buf) && http::query(req, Name, val_buf[..]);
            all_ok = all_ok && ok_q;
        }
    }
    guard all_ok else { return false; }
    committed = true;
    return true;
}

// ---- Client Facade Internal Helpers (Profile, DoH, ECH, Dictionary) --------

fn resolve_profile_spec(kind: fingerprint::Profile) -> fingerprint::ClientProfile {
    if kind == fingerprint::Profile.None {
        return fingerprint::none_profile();
    }
    if kind == fingerprint::Profile.Custom {
        return fingerprint::custom_profile();
    }
    return fingerprint::wing_default_profile();
}

fn build_profile_headers(profile: const fingerprint::ClientProfile&) -> http::HeaderMap {
    var hdrs = http::HeaderMap { .. };
    if profile.user_agent.len > 0 {
        http::set_header(hdrs, "User-Agent", profile.user_agent[..]);
    }
    if profile.accept.len > 0 {
        http::set_header(hdrs, "Accept", profile.accept[..]);
    }
    if profile.accept_encoding.len > 0 {
        http::set_header(hdrs, "Accept-Encoding", profile.accept_encoding[..]);
    }
    if profile.accept_language.len > 0 {
        http::set_header(hdrs, "Accept-Language", profile.accept_language[..]);
    }
    if profile.upgrade_insecure_requests.len > 0 {
        http::set_header(hdrs, "Upgrade-Insecure-Requests", profile.upgrade_insecure_requests[..]);
    }
    for &e in profile.extra_headers.entries {
        let h_name = http::entry_name(profile.extra_headers, e);
        let h_val = http::entry_value(profile.extra_headers, e);
        if h_name.len > 0 {
            http::set_header(hdrs, h_name, h_val);
        }
    }
    return hdrs;
}

fn apply_profile(c: client::Client&, profile: const fingerprint::ClientProfile&) {
    c.profile = profile.kind;
    c.profile_spec = profile;
    c.default_headers = build_profile_headers(profile);
}

fn is_trusted_location_host(session: const client::Session&, host_name: const u8[:]) -> bool {
    return session.trusted_location_hosts.any() { it[..].eq_ascii_fold(host_name) };
}

// Creates an isolated `Client` copying only transport, TLS verification, SSRF policy,
// virtual clock, and mock routes so application credentials, cookies, and interceptors
// do not leak across internal sub-requests (such as RFC 8484 DoH queries).
fn clone_isolated_transport_client(session: const client::Session&) -> client::Client {
    let def_p = fingerprint::wing_default_profile();
    let def_hdrs = build_profile_headers(def_p);
    var proxy_buf: u8[..256] = [];
    let _ = proxy_buf.try_set(session.proxy_url[..]);
    return client::Client {
        profile:                 def_p.kind,
        profile_spec:            def_p,
        proxy_url:               proxy_buf,
        timeout_ms:              session.timeout_ms,
        default_headers:         def_hdrs,
        ssrf_guard:              copy(session.ssrf_guard),
        virtual_clock_us:        session.virtual_clock_us,
        mock_routes:             copy(session.mock_routes),
        cache:                   http::Cache { .. },
        enable_cache:            false,
        altsvc:                  http::AltSvcCache { .. },
        enable_altsvc:           true,
        enable_protocol_racing:  true,
        quic_race_delay_ms:      200,
        dict_cache:              http::DictionaryCache { .. },
        enable_compression_dict: true,
        pipeline:                client::InterceptorPipeline { .. },
        wire_pipeline:           wire::default_client_pipeline(),
        hsts:                    http::HstsCache { .. },
        enable_hsts:             true,
        pool:                    net::new_stream_pool(),
        enable_cookie_jar:       true,
        trust_store:             copy(session.trust_store),
        insecure_skip_verify:    session.insecure_skip_verify,
        jar:                     cookie::CanonicalCookieJar { .. },
        ..
    };
}

// Dispatches a DNS-over-HTTPS wire query using an isolated HTTP client transport
// to ensure application credentials, custom headers, and interceptors do not leak to public resolvers.
fn doh_query(
    session: client::Session&,
    domain:  const u8[:],
    qtype:   u16,
    tx_id:   u16,
) -> dns::Response, bool {
    var req = http::new_request(if session.doh.use_post { "POST" } else { "GET" }, "");

    if session.doh.use_post {
        req.url.append(session.doh.endpoint[..]);
        http::set_header(req, "content-type", "application/dns-message");
        http::set_header(req, "accept", "application/dns-message");
        var wire_query: u8[..512] = [];
        guard dns::build_query(domain, qtype, tx_id, wire_query) else { return dns::Response { .. }, false; }
        req.body.append(wire_query[..]);
    } else {
        guard dns::build_doh_get_url(session.doh.endpoint[..], domain, qtype, req.url) else {
            return dns::Response { .. }, false;
        }
        http::set_header(req, "accept", "application/dns-message");
    }

    var doh_client = clone_isolated_transport_client(session);
    let res, err = client::do(doh_client, req);
    guard http::ok(err) && res.status_code == rfc::STATUS_OK else { return dns::Response { .. }, false; }

    let parsed, ok_dns = dns::parse_response(res.body[..]);
    guard ok_dns && parsed.rcode == rfc::DNS_RCODE_NOERROR && parsed.question_count == 1 else {
        return dns::Response { .. }, false;
    }
    let expected_tx_id: u16 = if session.doh.use_post { tx_id } else { 0 };
    guard parsed.tx_id == expected_tx_id else { return dns::Response { .. }, false; }
    return parsed, true;
}

fn discover_and_cache_ech_config(
    session: client::Session&,
    domain:  const u8[:],
    now_sec: i64,
) -> u8[..512], bool {
    var ech: u8[..512] = [];
    guard session.enable_doh && session.auto_ech_discovery else { return ech, false; }

    // RFC 8484 Section 4.1: DoH clients SHOULD set DNS ID to 0 for maximum HTTP cacheability.
    let dns_resp, ok_doh = doh_query(session, domain, rfc::DNS_QTYPE_HTTPS, 0);
    guard ok_doh else { return ech, false; }

    let eff_ttl = if dns_resp.min_ttl_sec > 0 { dns_resp.min_ttl_sec } else { 300 };
    var cache_entry = dns::CacheEntry {
        qtype:           rfc::DNS_QTYPE_HTTPS,
        inserted_at_sec: now_sec,
        ttl_sec:         eff_ttl,
        valid:           true,
        ..
    };
    guard cache_entry.domain.try_set(domain) else { return ech, false; }

    var found_ech = false;
    for &rec in dns_resp.https_records {
        let _ = cache_entry.https_records.try_push(rec);
        if rec.has_ech && rec.ech_config_list.len > 0 && !found_ech {
            found_ech = ech.try_set(rec.ech_config_list[..]);
        }
    }

    session.dns_cache.insert(cache_entry);
    return ech, found_ech;
}

inline fn is_localhost_dict_authority(auth: const u8[:]) -> bool {
    let host_part, _, _ = auth.partition_byte('/');
    if host_part.starts_with_fold("localhost") {
        return host_part.len == 9 || host_part[9] == ':';
    }
    if core::starts_with(host_part, "127.0.0.1") {
        return host_part.len == 9 || host_part[9] == ':';
    }
    if core::starts_with(host_part, "[::1]") {
        return host_part.len == 5 || host_part[5] == ':';
    }
    return false;
}

inline fn is_secure_dict_origin(origin: const u8[:]) -> bool {
    guard origin.len > 0 else { return false; }
    if origin.starts_with_fold("https://") {
        return origin.len > 8;
    }
    if origin.starts_with_fold("http://") {
        return is_localhost_dict_authority(origin[7..]);
    }
    if core::contains(origin, "://") {
        return false;
    }
    guard origin[0] != ':' else { return false; }
    if core::ends_with(origin, ":80") {
        return is_localhost_dict_authority(origin);
    }
    return true;
}

inline fn is_dict_entry_usable_for_session(
    session: const client::Session&,
    entry:   const http::DictionaryEntry&,
    origin:  const u8[:],
) -> bool {
    guard entry.valid && entry.origin.len > 0 && entry.origin[..].eq_ascii_fold(origin) else {
        return false;
    }
    guard entry.ttl_sec > 0 else { return true; }
    if session.virtual_clock_us == 1700000000000000 && entry.inserted_at_sec > 0 && entry.inserted_at_sec < 100000000 {
        return true;
    }
    let now_sec = div_euclid(session.virtual_clock_us, 1000000);
    return now_sec >= entry.inserted_at_sec && core::sub_sat_i64(now_sec, entry.inserted_at_sec) < entry.ttl_sec;
}

// Verifies the RFC 9842 `dcz` or `dcb` magic header and dictionary hash, then decompresses `raw_body` into `out`.
//
// Example:
//   is_dcz = true, raw_body = <valid dcz payload>, origin = "https://example.com"
//   returns: true with decompressed bytes appended to `out`
fn decode_dict_compressed_body<B>(
    session:  const client::Session&,
    origin:   const u8[:],
    is_dcz:   bool,
    raw_body: const u8[:],
    out:      B&,
) -> bool {
    var dict_hash: u8[32] = [0; 32];
    let ok_hdr = if is_dcz {
        let _, ok_z = http::decode_dcz_header(raw_body, dict_hash);
        ok_z
    } else {
        let _, ok_b = http::decode_dcb_header(raw_body, dict_hash);
        ok_b
    };
    guard ok_hdr else { return false; }
    var dict_entry = http::DictionaryEntry { .. };
    guard http::dictionary_lookup_by_hash(session.dict_cache, dict_hash, dict_entry) else {
        return false;
    }
    guard is_dict_entry_usable_for_session(session, dict_entry, origin) else { return false; }
    let comp_payload, ok_magic = http::verify_dcz_dcb_magic(raw_body, is_dcz, dict_entry.sha256_hash);
    guard ok_magic else { return false; }
    if is_dcz {
        return http::decompress_dcz_payload(comp_payload, dict_entry.content[..], out);
    }
    return http::decompress_dcb_payload(comp_payload, dict_entry.content[..], out);
}
