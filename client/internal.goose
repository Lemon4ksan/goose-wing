// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal helpers for package client (telemetry, redirect, and interceptor).
namespace client_internal;

import std;
import core;
import rfc.http;
import cookie.constants;
import cookie.policy;
import http.headers;
import http.request;
import http.response;
import http.trace;
import .redirect;
import .interceptor;

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

    if parsed_target.has_credentials() {
        return core::Url { .. }, client::RedirectError.CorsCredentialsInRedirectUrl;
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
    var write_entry_i: i64        = 0;
    var new_raw:       u8[..8192] = [];
    defer core::secure_zeroize_slice(new_raw[..]);
    let total_entries = headers.entries.len;

    for read_i in total_entries {
        let entry .= headers.entries[read_i];
        let name = http::entry_name(headers, entry);
        if is_redirect_rewritten_payload_header(name) {
            found = true;
            continue;
        }
        http::compact_kept_entry_into(headers, read_i, write_entry_i, new_raw);
    }
    if found {
        http::finish_compaction(headers, write_entry_i, new_raw);
    }
}

// Strips `Sec-Fetch-*` and `Sec-CH-*` headers when redirecting onto an untrustworthy HTTP origin
// (Chromium `MaybeRemoveSecHeaders`, `sec_header_helpers.cc:310-331`).
fn remove_sec_headers_on_downgrade(headers: http::HeaderMap&, target_url: const core::Url&) {
    if cookie::is_trustworthy_non_crypto_host(target_url.hostname()) {
        return;
    }
    var found = false;
    var write_entry_i: i64        = 0;
    var new_raw:       u8[..8192] = [];
    defer core::secure_zeroize_slice(new_raw[..]);
    let total_entries = headers.entries.len;

    for read_i in total_entries {
        let entry .= headers.entries[read_i];
        let name = http::entry_name(headers, entry);
        if name.starts_with_fold("sec-fetch-") || name.starts_with_fold("sec-ch-") {
            found = true;
            continue;
        }
        http::compact_kept_entry_into(headers, read_i, write_entry_i, new_raw);
    }
    if found {
        http::finish_compaction(headers, write_entry_i, new_raw);
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
    if lvl == client::LogLevel.Body && req.body.len > 0 && !req.is_secret_body {
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
