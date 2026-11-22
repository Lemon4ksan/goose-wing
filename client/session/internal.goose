// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal helpers for `client/session/*` (SSRF, mock synthesis, cookie bridge, stage conveyor,
// H1/H2/H3 hop execution, and realtime/MASQUE setup).
namespace client_internal;

import std;
import os;
import core;
import rfc.http;
import rfc.h2;
import rfc.h3_quic;
import rfc.tls;
import cookie.constants;
import cookie.canonical;
import cookie.psl;
import cookie.parser;
import cookie.policy;
import cookie.engine;
import fingerprint.profile;
import http.request;
import http.response;
import http.headers;
import http.cache.cache_control;
import http.cache.freshness;
import http.cache.validators;
import http.cache.engine;
import http.altsvc;
import http.compression_dict;
import http.digest_fields;
import http.early_hints;
import http.hsts;
import http.signatures;
import dns.cache;
import auth.digest;
import auth.dpop;
import security.cors;
import security.cross_origin_isolation;
import security.privacypass;
import security.ssrf;
import realtime.websocket;
import realtime.sse;
import net.pool;
import net.isolation;
import net.proxy;
import net.socks5;
import net.http_connect;
import net.tcp;
import net.happy_eyeballs;
import net.retry;
import net.transport;
import net.masque;
import tls.types;
import tls.asn1;
import tls.x509;
import tls.pem;
import tls.crl;
import tls.handshake;
import tls.session;
import tls.backend;
import http2.framing;
import http2.hpack;
import wire.types;
import wire.hpack;
import wire.h2;
import wire.pipeline;
import client.redirect;
import client.interceptor;
import client.replay_guard;
import client.telemetry;
import client.client;
import client.internal;
import .ssrf;
import .mock;
import .cookie_bridge;
import .stages;
import .exec;
import .verbs;

extern fn native_crypto_random_bytes(out: u8[:]) -> i32 = "wing_crypto_random_bytes";

// ---- 1. SSRF & Mock Synthesis Helpers --------------------------------------

fn validate_resolved_ips_against_ssrf(
    ips:    const u8[:][:],
    policy: const security::SsrfGuardPolicy&,
) -> client::RedirectError {
    guard policy.enabled else { return client::RedirectError.None; }
    guard ips.len > 0 else { return client::RedirectError.SsrfBlockedIp; }
    for ip in ips {
        guard security::is_valid_resolved_ip_literal(ip) else {
            return client::RedirectError.SsrfBlockedIp;
        }
        let blocked = if policy.deny_local_network {
            security::is_private_or_reserved_ip(ip)
        } else {
            security::is_cloud_metadata_or_reserved_ip(ip)
        };
        if blocked {
            return client::RedirectError.SsrfBlockedIp;
        }
    }
    return client::RedirectError.None;
}

fn validate_mock_route_dns(
    route:        const client::MockExchange&,
    guard_config: const security::SsrfGuardPolicy&,
) -> client::RedirectError {
    if route.resolved_ips.len == 0 {
        return client::RedirectError.None;
    }
    var ips_slice: const u8[:][4] = ["", "", "", ""];
    for idx in route.resolved_ips.len {
        ips_slice[idx] = route.resolved_ips[idx][..];
    }
    return validate_resolved_ips_against_ssrf(ips_slice[..route.resolved_ips.len], guard_config);
}

// Extracts origin string "host:port" from parsed Url.
fn format_url_origin<B>(url_val: const core::Url&, out: B&) {
    let host = url_val.hostname();
    let port = url_val.effective_port();
    out.append(host);
    out.push(':');
    format(out, port);
}

fn target_has_scheme(target: const u8[:]) -> bool {
    guard target.len >= 4 else { return false; }
    return core::find(target, "://") >= 0;
}

fn resolve_target_origin<B>(target: const u8[:], out: B&) {
    if target_has_scheme(target) {
        let parsed, _ = core::parse_url(target);
        if parsed.valid {
            format_url_origin(parsed, out);
            return;
        }
    }
    out.append(target);
}

fn build_mock_response(
    route:        const client::MockExchange&,
    current_url:  const core::Url&,
    sent_headers: const http::HeaderMap&,
) -> http::Response {
    var resp = http::Response {
        status_code:   route.status_code,
        effective_url: copy(current_url.href),
        ..
    };
    if route.protocol.len > 0 {
        let _ = resp.protocol.try_set(route.protocol[..]);
    }
    http::copy_headers(route.headers, resp.headers);
    for &e in resp.headers.entries {
        http::update_response_presence(resp, http::entry_name(resp.headers, e));
    }
    resp.body.append(route.body[..]);
    http::copy_headers(sent_headers, resp.sent_headers);
    return resp;
}

// ---- 2. Cookie Bridge Helper -----------------------------------------------

// Computes the SameSite cookie context for Set-Cookie response ingestion
// (Chromium `net::cookie_util::ComputeSameSiteContextForResponse` / `MakeInclusiveForSet`,
// `cookie_util.cc:992-1047`): main-frame navigations whose target URL is first-party
// relative to `site_for_cookies` can set `SameSite=Lax` and `SameSite=Strict` cookies.
fn compute_hop_samesite_context_for_response(
    ctx:               const client::RequestExecutionContext&,
    current_url:       const core::Url&,
    req_samesite_eval: const cookie::SameSiteCookieContext&,
) -> cookie::SameSiteCookieContext {
    var resp_ctx = copy(req_samesite_eval);
    if ctx.is_main_frame && !ctx.site_for_cookies.is_null {
        let is_first_p = cookie::is_first_party(ctx.site_for_cookies, current_url.href[..], true);
        if is_first_p && resp_ctx.context_type == cookie::SameSiteContextType.CrossSite {
            resp_ctx.context_type = cookie::SameSiteContextType.SameSiteLax;
        }
    }
    return resp_ctx;
}

// ---- 3. Stage Conveyor Internal Helpers ------------------------------------

fn stage_client_url_hsts(
    url_buf:     u8[..2048]&,
    hsts:        const http::HstsCache&,
    enable_hsts: bool,
    now_sec:     i64,
) -> wire::StageVerdict {
    if enable_hsts {
        var upgraded_url: u8[..2048] = [];
        if http::hsts_upgrade_url(hsts, url_buf[..], now_sec, upgraded_url) {
            let _ = url_buf.try_set(upgraded_url[..]);
        }
    }
    return wire::StageVerdict.Continue;
}

fn stage_client_url_hsts(
    current_url: core::Url&,
    hsts:        const http::HstsCache&,
    enable_hsts: bool,
    now_sec:     i64,
) -> wire::StageVerdict {
    if enable_hsts && !current_url.is_secure_scheme() {
        var upgraded_url: u8[..2048] = [];
        if http::hsts_upgrade_url(hsts, current_url.href[..], now_sec, upgraded_url) {
            let parsed_upgraded, _ = core::parse_url(upgraded_url[..]);
            if parsed_upgraded.valid {
                current_url = parsed_upgraded;
            }
        }
    }
    return wire::StageVerdict.Continue;
}

fn stage_client_ssrf_guard(
    current_url: const core::Url&,
    https_only:  bool,
    policy:      const security::SsrfGuardPolicy&,
) -> wire::StageVerdict {
    if https_only && current_url.scheme() != "https" {
        return wire::StageVerdict.Abort { err_code: rfc::STATUS_BAD_REQUEST };
    }
    let ssrf_err = client::validate_url_against_ssrf(current_url, policy);
    if ssrf_err != client::RedirectError.None {
        return wire::StageVerdict.Abort { err_code: rfc::STATUS_FORBIDDEN };
    }
    return wire::StageVerdict.Continue;
}

fn apply_cache_revalidation_headers(cond_map: const http::HeaderMap&, headers: http::HeaderMap&) {
    for &c_entry in cond_map.entries {
        let c_name = http::entry_name(cond_map, c_entry);
        let c_val = http::entry_value(cond_map, c_entry);
        if !http::has_header(headers, c_name) {
            http::set_header(headers, c_name, c_val);
        }
    }
}

fn stage_client_dict_negotiate(
    headers:     http::HeaderMap&,
    dict_cache:  http::DictionaryCache&,
    enable_dict: bool,
    origin_buf:  const u8[:],
    curr_path:   const u8[:],
    is_https:    bool,
    now_sec:     i64,
) -> wire::StageVerdict {
    http::remove_header_by_name(headers, "Available-Dictionary");
    http::remove_header_by_name(headers, "Dictionary-ID");
    guard enable_dict && is_https else { return wire::StageVerdict.Continue; }
    let best_idx = http::find_best_matching_dict_idx(dict_cache, origin_buf, curr_path, now_sec);
    if best_idx >= 0 && best_idx < dict_cache.entries.len {
        let entry .= dict_cache.entries[best_idx];
        append_available_dict_header(headers, entry.sha256_base64[..]);
        if entry.id.len > 0 {
            var id_hdr: u8[..128] = [];
            http::format_dictionary_id_header(id_hdr, entry.id[..]);
            http::set_header(headers, "Dictionary-ID", id_hdr[..]);
        }
    }
    return wire::StageVerdict.Continue;
}

fn stage_client_auth_header(
    pipeline:       client::InterceptorPipeline&,
    headers:        http::HeaderMap&,
    href:           const u8[:],
    method:         const u8[:],
    body_len:       i64,
    redirect_count: i64,
) -> wire::StageVerdict {
    client::apply_network_interceptors_request(pipeline, headers, href, method, body_len, redirect_count);
    return wire::StageVerdict.Continue;
}

fn stage_client_cookie_store<Jar>(
    resp_headers:  const http::HeaderMap&,
    current_url:   const core::Url&,
    samesite_eval: const cookie::SameSiteCookieContext&,
    is_main_frame: bool,
    part_key:      const u8[:],
    now_us:        i64,
    jar:           Jar&,
    enable_jar:    bool,
) -> wire::StageVerdict {
    guard enable_jar else { return wire::StageVerdict.Continue; }
    var def_path: u8[..256] = [];
    cookie::compute_default_path(current_url.pathname(), def_path);
    let is_sec_channel = current_url.is_secure_scheme() ||
        cookie::is_trustworthy_non_crypto_host(current_url.hostname());
    let opts = cookie::InclusionOptions {
        is_main_frame:     is_main_frame,
        is_secure_channel: is_sec_channel,
    };
    for &e in resp_headers.entries {
        let ename = http::entry_name(resp_headers, e);
        guard ename.eq_ascii_fold("set-cookie") else { continue; }
        let set_cookie_str = http::entry_value(resp_headers, e);
        var parsed_cookie, _, cookie_ok = cookie::parse_canonical_set_cookie(
            set_cookie_str,
            current_url.hostname(),
            def_path[..],
            now_us,
        );
        guard cookie_ok else { continue; }
        let _, can_write = cookie::can_set_for_context(parsed_cookie, samesite_eval, opts);
        guard can_write else { continue; }
        jar.set_cookie_header(current_url.href[..], set_cookie_str, now_us, part_key);
    }
    return wire::StageVerdict.Continue;
}

fn stage_client_alt_svc(
    resp:          http::Response&,
    current_url:   const core::Url&,
    is_https:      bool,
    origin_buf:    const u8[:],
    curr_path:     const u8[:],
    now_sec:       i64,
    altsvc:        http::AltSvcCache&,
    enable_altsvc: bool,
    hsts:          http::HstsCache&,
    enable_hsts:   bool,
    dict_cache:    http::DictionaryCache&,
    enable_dict:   bool,
) -> wire::StageVerdict {
    let link_val = http::header(resp, "Link");
    if link_val.len > 0 {
        let eh, ok_eh = http::parse_early_hints(rfc::STATUS_EARLY_HINTS as! u16, link_val);
        if ok_eh {
            resp.early_hints = eh;
        }
    }
    if enable_altsvc && is_https {
        let alt_svc_val = http::header(resp, "Alt-Svc");
        if alt_svc_val.len > 0 {
            http::update(altsvc, origin_buf, alt_svc_val, now_sec);
        }
    }
    if enable_hsts && is_https {
        let hsts_val = http::header(resp, "Strict-Transport-Security");
        if hsts_val.len > 0 {
            http::hsts_cache_update(hsts, current_url.hostname(), hsts_val, now_sec);
        }
    }
    if enable_dict && is_https && http::header(resp, "Use-As-Dictionary").len > 0 {
        var mut_resp = copy(resp);
        client::ingest_compression_dict_header(dict_cache, origin_buf, curr_path, now_sec, mut_resp);
    }
    return wire::StageVerdict.Continue;
}

fn verify_dict_encoding_precheck(
    raw_body:   const u8[:],
    enc:        const u8[:],
    dict_cache: const http::DictionaryCache&,
    eff_url:    const u8[:] = "",
    now_sec:    i64         = 0,
) -> bool {
    var tokens: u8[..16][..4] = [];
    guard http::parse_content_encoding_chain(enc, tokens) else { return false; }
    guard tokens.len > 0 else { return true; }
    let outer_enc = tokens[core::sub_sat_i64(tokens.len, 1)][..];
    let is_dcz = outer_enc.eq_ascii_fold(rfc::ENCODING_DCZ);
    let is_dcb = outer_enc.eq_ascii_fold(rfc::ENCODING_DCB);
    guard is_dcz || is_dcb else { return true; }
    var dict_hash: u8[32] = [0; 32];
    if is_dcz {
        let _, ok_hdr = http::decode_dcz_header(raw_body, dict_hash);
        guard ok_hdr else { return false; }
    } else {
        let _, ok_hdr = http::decode_dcb_header(raw_body, dict_hash);
        guard ok_hdr else { return false; }
    }
    let idx = http::find_matching_dict_entry(dict_cache, dict_hash[..], eff_url, now_sec);
    guard idx >= 0 && idx < dict_cache.entries.len else { return false; }
    let _, ok_magic = http::verify_dcz_dcb_magic(raw_body, is_dcz, dict_cache.entries[idx].sha256_hash);
    return ok_magic;
}

fn stage_client_decompress(
    resp:        http::Response&,
    dict_cache:  const http::DictionaryCache&,
    strict_mode: bool = false,
    now_sec:     i64  = 0,
) -> wire::StageVerdict {
    let has_cd = http::header(resp, rfc::HEADER_CONTENT_DIGEST).len > 0;
    let cd_ok_pre = if strict_mode && has_cd { http::verify_response_content_digest(resp) } else { true };

    let enc = http::header(resp, "Content-Encoding");
    if enc.len > 0 {
        let ok_magic = verify_dict_encoding_precheck(resp.body[..], enc, dict_cache, resp.effective_url[..], now_sec);
        let ok_dec = ok_magic && http::decode_body_with_dictionary(resp, dict_cache, now_sec);
        if !ok_dec && strict_mode {
            return wire::StageVerdict.Abort { err_code: rfc::STATUS_BAD_GATEWAY };
        }
    }

    if strict_mode && has_cd && !cd_ok_pre && !http::verify_response_content_digest(resp) {
        return wire::StageVerdict.Abort { err_code: rfc::STATUS_BAD_GATEWAY };
    }
    if strict_mode && http::header(resp, rfc::HEADER_REPR_DIGEST).len > 0 && !http::verify_response_repr_digest(resp) {
        return wire::StageVerdict.Abort { err_code: rfc::STATUS_BAD_GATEWAY };
    }
    return wire::StageVerdict.Continue;
}

fn try_handle_early_data_or_dpop_challenge(
    session:       client::Client&,
    ctx:           client::RequestExecutionContext&,
    current_url:   const core::Url&,
    samesite_eval: const cookie::SameSiteCookieContext&,
    safe_method:   bool,
    resp:          const http::Response&,
) -> bool {
    guard !ctx.auth_retried else { return false; }
    let was_early = http::find_header(ctx.headers, "Early-Data").len > 0;
    let ed_dec = client::evaluate_early_data_response(resp.status_code as u16, was_early);
    if ed_dec == client::EarlyDataDecision.RetryOn1Rtt {
        ctx.auth_retried = true;
        http::remove_header_by_name(ctx.headers, "Early-Data");
        if ctx.body.len > 0 {
            ctx.body.clear();
            ctx.body.append(ctx.rewind_buf[..]);
        }
        ctx.body_consumed = false;
        return true;
    }

    let is_dpop_status = resp.status_code == rfc::STATUS_UNAUTHORIZED || resp.status_code == rfc::STATUS_BAD_REQUEST;
    guard session.dpop.has_key && is_dpop_status else { return false; }
    guard auth::extract_dpop_nonce(resp.headers, session.dpop.last_nonce) else { return false; }
    let now_sec = div_euclid(session.virtual_clock_us, 1000000);
    let htu_no_q, _, _ = current_url.href[..].partition_byte('?');
    let htu_clean, _, _ = htu_no_q.partition_byte('#');
    var proof: u8[..2048] = [];
    let ok_proof = auth::create_dpop_proof(
        session.dpop.private_key[..],
        ctx.current_method[..],
        htu_clean,
        session.dpop.access_token[..],
        session.dpop.last_nonce[..],
        now_sec,
        "",
        proof,
    );
    guard ok_proof else { return false; }
    ctx.auth_retried = true;
    if ctx.body.len > 0 {
        ctx.body.clear();
        ctx.body.append(ctx.rewind_buf[..]);
    }
    ctx.body_consumed = false;
    if session.enable_cookie_jar {
        client::ingest_hop_response_cookies(session, ctx, current_url, samesite_eval, resp.headers);
        http::remove_header_by_name(ctx.headers, "Cookie");
        client::prepare_hop_cookie_header(session, ctx, current_url, samesite_eval, safe_method);
    }
    http::set_header(ctx.headers, rfc::DPOP_HEADER, proof[..], true);
    return true;
}

fn stage_client_auth_challenge(
    session:       client::Client&,
    ctx:           client::RequestExecutionContext&,
    current_url:   const core::Url&,
    samesite_eval: const cookie::SameSiteCookieContext&,
    safe_method:   bool,
    resp:          http::Response&,
) -> wire::StageVerdict {
    guard ctx.body.len == 0 || ctx.rewindable else {
        return wire::StageVerdict.Continue;
    }
    if try_handle_early_data_or_dpop_challenge(session, ctx, current_url, samesite_eval, safe_method, resp) {
        return wire::StageVerdict.RetryAuth;
    }
    let has_auth_source = session.creds.has_credentials || session.private_token_cache.entries.len > 0;
    guard has_auth_source && resp.status_code == rfc::STATUS_UNAUTHORIZED else {
        return wire::StageVerdict.Continue;
    }
    var auth_header_val: u8[..4096] = [];
    guard find_auth_header_from_response(session, ctx, current_url, resp, auth_header_val) else {
        return wire::StageVerdict.Continue;
    }
    client::prepare_auth_retry_hop(session, ctx, current_url, samesite_eval, safe_method, resp, auth_header_val[..]);
    return wire::StageVerdict.RetryAuth;
}

fn stage_client_redirect(
    session:     client::Session&,
    ctx:         client::RequestExecutionContext&,
    resp:        http::Response&,
    current_url: const core::Url&,
    out_err:     http::Error&,
) -> wire::StageVerdict {
    let cors_err = client::validate_cors_and_corp_response(ctx, current_url, resp);
    if !http::ok(cors_err) {
        out_err = cors_err;
        return wire::StageVerdict.Abort { err_code: cors_err.code };
    }
    let loc_hdr = http::header(resp, "Location");
    if !http::is_redirect(resp) {
        finalize_success_response(ctx, resp);
        return wire::StageVerdict.Continue;
    }
    session.pipeline.metrics.redirect_hops += 1;
    let should_continue, red_err = process_redirect_hop(session, ctx, resp, current_url, loc_hdr);
    if !http::ok(red_err) {
        out_err = red_err;
        return wire::StageVerdict.Abort { err_code: red_err.code };
    }
    if should_continue {
        return wire::StageVerdict.FollowRedirect;
    }
    return wire::StageVerdict.Continue;
}

inline fn is_same_origin_session_hop(
    ctx:         const client::RequestExecutionContext&,
    current_url: const core::Url&,
) -> bool {
    guard !ctx.tainted_origin else { return false; }
    if ctx.url_chain.len <= 1 {
        return true;
    }
    return core::is_same_origin(core::origin_from_url(ctx.url_chain[0]), core::origin_from_url(current_url));
}

inline fn is_secure_dpop_hop_url(url_val: const core::Url&) -> bool {
    if url_val.is_secure_scheme() {
        return true;
    }
    guard url_val.scheme() == "http" else { return false; }
    let h = url_val.hostname();
    return h.eq_ascii_fold("localhost") || h == "127.0.0.1" || h == "::1" || h == "[::1]";
}

inline fn apply_client_early_data_and_dpop_headers(
    session:     const client::Client&,
    ctx:         client::RequestExecutionContext&,
    current_url: const core::Url&,
    now_sec:     i64,
) {
    if session.enable_early_data && !ctx.auth_retried && !ctx.early_data_disabled &&
        client::evaluate_early_data_request(ctx.current_method[..]) == client::EarlyDataDecision.Allow {
        http::set_header(ctx.headers, "Early-Data", "1");
    } else {
        http::remove_header_by_name(ctx.headers, "Early-Data");
    }
    guard session.dpop.has_key else { return; }
    guard is_same_origin_session_hop(ctx, current_url) else {
        http::remove_header_by_name(ctx.headers, rfc::DPOP_HEADER);
        return;
    }
    let existing_auth = http::find_header(ctx.headers, "Authorization").trim_lws();
    var token_buf: u8[..4096] = [];
    if existing_auth.len > 0 {
        let rest, is_dpop = existing_auth.strip_prefix_fold("dpop");
        guard is_dpop && rest.len > 0 && (rest[0] == ' ' || rest[0] == '\t') else {
            http::remove_header_by_name(ctx.headers, rfc::DPOP_HEADER);
            return;
        }
        let trimmed_tok = rest.trim_lws();
        guard trimmed_tok.len > 0 && token_buf.try_set(trimmed_tok) else { return; }
    } else if session.dpop.access_token.len > 0 {
        guard is_secure_dpop_hop_url(current_url) else {
            http::remove_header_by_name(ctx.headers, rfc::DPOP_HEADER);
            return;
        }
        guard token_buf.try_set(session.dpop.access_token[..]) else { return; }
    }
    let htu_no_q, _, _ = current_url.href[..].partition_byte('?');
    let htu_clean, _, _ = htu_no_q.partition_byte('#');
    var proof: u8[..4096] = [];
    guard auth::create_dpop_proof(
        session.dpop.private_key[..],
        ctx.current_method[..],
        htu_clean,
        token_buf[..],
        session.dpop.last_nonce[..],
        now_sec,
        "",
        proof,
    ) else { return; }
    http::set_header(ctx.headers, rfc::DPOP_HEADER, proof[..], true);
    if existing_auth.len == 0 && token_buf.len > 0 {
        var auth_val: u8[..4112] = [];
        guard auth_val.try_append("DPoP ") && auth_val.try_append(token_buf[..]) else { return; }
        http::set_header(ctx.headers, "Authorization", auth_val[..], true);
    }
}

fn apply_client_request_signature(
    session:     const client::Client&,
    ctx:         client::RequestExecutionContext&,
    current_url: const core::Url&,
) {
    guard session.sig_private_key.len == 32 else { return; }
    guard is_same_origin_session_hop(ctx, current_url) else {
        http::remove_header_by_name(ctx.headers, rfc::HEADER_SIGNATURE);
        http::remove_header_by_name(ctx.headers, rfc::HEADER_SIGNATURE_INPUT);
        return;
    }
    var sig_req = http::Request {
        method:  copy(ctx.current_method),
        url:     copy(current_url.href),
        headers: copy(ctx.headers),
        ..
    };
    if http::sign_request_ed25519(sig_req, session.sig_key_id[..], session.sig_private_key[..]) {
        ctx.headers = copy(sig_req.headers);
    }
}

fn ingest_session_dictionary_response(
    session:    client::Client&,
    is_https:   bool,
    origin_buf: const u8[:],
    resp:       const http::Response&,
) {
    let use_dict_hdr = http::header(resp, "Use-As-Dictionary");
    guard session.enable_compression_dict && is_https && use_dict_hdr.len > 0 && resp.body.len <= 2048 else {
        return;
    }
    var decoded_dict: u8[..2048] = [];
    let enc_hdr = http::header(resp, "Content-Encoding");
    let _ = client::process_dictionary_response(
        session,
        origin_buf,
        use_dict_hdr,
        enc_hdr,
        resp.body[..],
        decoded_dict,
    );
}

fn run_client_preflight_stages<UserStage>(
    session:              client::Client&,
    req:                  const http::Request&,
    raw_eff_url:          u8[..2048]&,
    cache_ts:             const http::CacheTimestamps&,
    ctx:                  client::RequestExecutionContext&,
    out_resp:             http::Response&,
    out_err:              http::Error&,
    cache_revalidate_idx: i64&,
    user_stage:           UserStage&,
) -> wire::StageVerdict {
    let now_sec = session.virtual_clock_us / 1000000;
    if wire::is_ingress_stage_enabled(session.wire_pipeline, wire::STAGE_ID_CLI_IN_URL_HSTS) {
        let _ = stage_client_url_hsts(raw_eff_url, session.hsts, session.enable_hsts, now_sec);
    }

    let parsed_initial, _ = core::parse_url(raw_eff_url[..]);
    guard parsed_initial.valid else {
        out_err = http::make_error(rfc::STATUS_BAD_REQUEST, "url_parse", "invalid request url");
        return wire::StageVerdict.Abort { err_code: rfc::STATUS_BAD_REQUEST };
    }

    ctx = client::init_execution_context(session, req, parsed_initial);

    if wire::is_ingress_stage_enabled(session.wire_pipeline, wire::STAGE_ID_CLI_IN_CACHE_LOOKUP) {
        var cache_hdrs = copy(ctx.headers);
        let cookie_stage_on = wire::is_ingress_stage_enabled(session.wire_pipeline, wire::STAGE_ID_CLI_IN_COOKIE_LOAD);
        if session.enable_cookie_jar && cookie_stage_on {
            var tmp_ctx = copy(ctx);
            let safe_m = rfc::is_safe_http_method(tmp_ctx.current_method[..]);
            let ss_eval = client::compute_hop_samesite_context(tmp_ctx, parsed_initial, safe_m);
            client::prepare_hop_cookie_header(session, tmp_ctx, parsed_initial, ss_eval, safe_m);
            cache_hdrs = copy(tmp_ctx.headers);
        }
        let v_cache, reval_idx = client::stage_cache_lookup(
            req,
            parsed_initial.href[..],
            cache_ts.now_sec,
            cache_hdrs,
            out_resp,
            session.cache,
            session.enable_cache,
        );
        cache_revalidate_idx = reval_idx;
        if cache_revalidate_idx >= 0 {
            let inm = http::get_header(cache_hdrs, "If-None-Match");
            if inm.len > 0 { http::set_header(ctx.headers, "If-None-Match", inm); }
            let ims = http::get_header(cache_hdrs, "If-Modified-Since");
            if ims.len > 0 { http::set_header(ctx.headers, "If-Modified-Since", ims); }
        }
        match v_cache {
            ShortCircuit _ => {
                out_err = http::Error { .. };
                return v_cache;
            },
            Abort ab => {
                out_err = http::make_error(ab.err_code, "cache", "504 Gateway Timeout (only-if-cached miss)");
                return v_cache;
            },
            _ => {},
        };
    }

    guard !client::is_noop_stage(user_stage) else { return wire::StageVerdict.Continue; }
    var s_ctx = client::StageCtx {
        current_url:    parsed_initial,
        current_method: copy(ctx.current_method),
        headers:        copy(ctx.headers),
        pipeline:       session.wire_pipeline,
        redirect_count: ctx.redirect_count as i32,
        auth_retried:   ctx.auth_retried,
        now_us:         session.virtual_clock_us,
        last_error:     out_err,
        resp:           copy(out_resp),
    };
    let u_verdict = client::invoke_stage_hook(user_stage, 0 as u8, wire::ClientHookPhase.PreFlight, s_ctx);
    ctx.headers = copy(s_ctx.headers);
    match u_verdict {
        ShortCircuit sc => {
            out_resp = copy(s_ctx.resp);
            if out_resp.status_code == 0 {
                out_resp.status_code = sc.status_code as i32;
            }
            return u_verdict;
        },
        Abort ab => {
            out_err = if !http::ok(s_ctx.last_error) {
                s_ctx.last_error
            } else {
                http::make_error(ab.err_code, "user_stage", "aborted by client pre-flight stage")
            };
            return u_verdict;
        },
        _ => {},
    };
    return wire::StageVerdict.Continue;
}

fn invoke_client_custom_slot<UserStage>(
    user_stage:  UserStage&,
    slot_id:     u8,
    session:     const client::Client&,
    ctx:         client::RequestExecutionContext&,
    current_url: const core::Url&,
    out_resp:    http::Response&,
    out_err:     http::Error&,
) -> wire::StageVerdict {
    guard !client::is_noop_stage(user_stage) else { return wire::StageVerdict.Continue; }
    var s_ctx = client::StageCtx {
        current_url:    current_url,
        current_method: copy(ctx.current_method),
        pipeline:       session.wire_pipeline,
        redirect_count: ctx.redirect_count as i32,
        auth_retried:   ctx.auth_retried,
        now_us:         session.virtual_clock_us,
        last_error:     out_err,
        ..
    };
    let v = client::on_custom_slot(user_stage, slot_id, s_ctx, ctx.headers, out_resp);
    if !http::ok(s_ctx.last_error) {
        out_err = s_ctx.last_error;
    }
    return v;
}

fn dispatch_client_ingress_stage(
    stage_id:      u8,
    session:       client::Client&,
    ctx:           client::RequestExecutionContext&,
    current_url:   core::Url&,
    samesite_eval: cookie::SameSiteCookieContext&,
    safe_method:   bool,
    now_sec:       i64,
    out_err:       http::Error&,
) -> wire::StageVerdict {
    if stage_id == wire::STAGE_ID_CLI_IN_URL_HSTS {
        let v = stage_client_url_hsts(current_url, session.hsts, session.enable_hsts, now_sec);
        let chain_len = ctx.url_chain.len;
        if chain_len > 0 && chain_len <= ctx.url_chain.cap {
            ctx.url_chain[chain_len - 1] = current_url;
        }
        return v;
    }
    if stage_id == wire::STAGE_ID_CLI_IN_SSRF_GUARD {
        let v_ssrf = stage_client_ssrf_guard(current_url, session.https_only, session.ssrf_guard);
        match v_ssrf {
            Abort ab => {
                out_err = validate_hop_prerequisites(session, current_url);
                return wire::StageVerdict.Abort { err_code: ab.err_code };
            },
            _ => {
                return wire::StageVerdict.Continue;
            },
        };
    }
    if stage_id == wire::STAGE_ID_CLI_IN_COOKIE_LOAD {
        samesite_eval = client::compute_hop_samesite_context(ctx, current_url, safe_method);
        var part_key: u8[..256] = [];
        client::compute_hop_partition_key(ctx, current_url, part_key);
        return client::stage_cookie_load(
            ctx.headers,
            current_url,
            samesite_eval,
            ctx.is_main_frame,
            part_key[..],
            safe_method,
            session.virtual_clock_us,
            session.jar,
            session.enable_cookie_jar,
        );
    }
    if stage_id == wire::STAGE_ID_CLI_IN_DICT_NEGOTIATE {
        var origin_buf: u8[..128] = [];
        format_url_origin(current_url, origin_buf);
        let is_https = current_url.is_secure_scheme();
        let curr_path = current_url.pathname();
        if is_https && session.enable_compression_dict {
            var dict_req = http::Request { headers: copy(ctx.headers), .. };
            if client::attach_dictionary_request_headers(session, origin_buf[..], curr_path, dict_req) {
                ctx.headers = copy(dict_req.headers);
            }
        }
        return stage_client_dict_negotiate(
            ctx.headers,
            session.dict_cache,
            session.enable_compression_dict,
            origin_buf[..],
            curr_path,
            is_https,
            now_sec,
        );
    }
    if stage_id == wire::STAGE_ID_CLI_IN_INTERCEPTOR_AUTH {
        apply_client_early_data_and_dpop_headers(session, ctx, current_url, now_sec);
        let v_auth = stage_client_auth_header(
            session.pipeline,
            ctx.headers,
            current_url.href[..],
            ctx.current_method[..],
            ctx.body.len,
            ctx.redirect_count,
        );
        apply_client_request_signature(session, ctx, current_url);
        return v_auth;
    }
    return wire::StageVerdict.Continue;
}

fn verify_raw_response_digests(resp: const http::Response&) -> bool {
    if http::header(resp, rfc::HEADER_CONTENT_DIGEST).len > 0 && !http::verify_response_content_digest(resp) {
        return false;
    }
    if http::header(resp, rfc::HEADER_REPR_DIGEST).len > 0 && !http::verify_response_repr_digest(resp) {
        return false;
    }
    return true;
}

fn check_response_body_size_limit(
    session: const client::Session&,
    resp:    http::Response&,
    out_err: http::Error&,
) -> bool {
    guard session.max_response_body_bytes > 0 && resp.body.len > session.max_response_body_bytes else {
        return true;
    }
    resp.body.clear();
    out_err = http::make_error(
        rfc::STATUS_CONTENT_TOO_LARGE,
        "protocol",
        "ERR_RESPONSE_BODY_TOO_LARGE: response body exceeds max_response_body_bytes",
    );
    return false;
}

fn run_client_decompress_and_limit_stage(
    session:     const client::Client&,
    req:         const http::Request&,
    current_url: const core::Url&,
    ctx:         const client::RequestExecutionContext&,
    out_resp:    http::Response&,
    out_err:     http::Error&,
) -> wire::StageVerdict {
    if !client::verify_response_signature(
        session, req, current_url, ctx.current_method[..], ctx.headers, out_resp,
    ) {
        out_err = http::make_error(
            rfc::STATUS_BAD_GATEWAY,
            "protocol",
            "ERR_SIGNATURE_VERIFICATION_FAILED: HTTP response signature verification failed",
        );
        return wire::StageVerdict.Abort { err_code: rfc::STATUS_BAD_GATEWAY };
    }
    guard check_response_body_size_limit(session, out_resp, out_err) else {
        return wire::StageVerdict.Abort { err_code: rfc::STATUS_CONTENT_TOO_LARGE };
    }
    let strict_dec = session.strict_content_decoding || session.verify_content_digest;
    if !session.auto_decompress {
        guard !strict_dec || verify_raw_response_digests(out_resp) else {
            out_err = http::make_error(
                rfc::STATUS_BAD_GATEWAY,
                "protocol",
                "ERR_CONTENT_DECODING_FAILED: response digest verification failed",
            );
            return wire::StageVerdict.Abort { err_code: rfc::STATUS_BAD_GATEWAY };
        }
        return wire::StageVerdict.Continue;
    }
    let dec_v = stage_client_decompress(
        out_resp,
        session.dict_cache,
        strict_dec,
        div_euclid(session.virtual_clock_us, 1000000),
    );
    match dec_v {
        Abort ab => {
            let dec_msg = "ERR_CONTENT_DECODING_FAILED: content-encoding decompression failed";
            out_err = http::make_error(ab.err_code, "protocol", dec_msg);
            return dec_v;
        },
        _ => {},
    };
    guard check_response_body_size_limit(session, out_resp, out_err) else {
        return wire::StageVerdict.Abort { err_code: rfc::STATUS_CONTENT_TOO_LARGE };
    }
    return dec_v;
}

fn dispatch_client_egress_stage(
    stage_id:             u8,
    session:              client::Client&,
    ctx:                  client::RequestExecutionContext&,
    req:                  const http::Request&,
    current_url:          const core::Url&,
    samesite_eval:        const cookie::SameSiteCookieContext&,
    safe_method:          bool,
    cache_ts:             http::CacheTimestamps&,
    cache_revalidate_idx: i64,
    out_resp:             http::Response&,
    out_err:              http::Error&,
) -> wire::StageVerdict {
    if stage_id == wire::STAGE_ID_CLI_OUT_AUTH_CHALLENGE {
        let auth_v = stage_client_auth_challenge(session, ctx, current_url, samesite_eval, safe_method, out_resp);
        if auth_v != wire::StageVerdict.RetryAuth {
            ctx.body_consumed = true;
        }
        return auth_v;
    }
    if stage_id == wire::STAGE_ID_CLI_OUT_COOKIE_STORE {
        var part_key: u8[..256] = [];
        client::compute_hop_partition_key(ctx, current_url, part_key);
        let resp_samesite = compute_hop_samesite_context_for_response(ctx, current_url, samesite_eval);
        return stage_client_cookie_store(
            out_resp.headers,
            current_url,
            resp_samesite,
            ctx.is_main_frame,
            part_key[..],
            session.virtual_clock_us,
            session.jar,
            session.enable_cookie_jar,
        );
    }
    if stage_id == wire::STAGE_ID_CLI_OUT_ALT_SVC {
        let is_https = current_url.is_secure_scheme();
        var origin_buf: u8[..128] = [];
        format_url_origin(current_url, origin_buf);
        let curr_path = current_url.pathname();
        let now_sec = div_euclid(session.virtual_clock_us, 1000000);
        ingest_session_dictionary_response(session, is_https, origin_buf[..], out_resp);
        return stage_client_alt_svc(
            out_resp,
            current_url,
            is_https,
            origin_buf[..],
            curr_path,
            now_sec,
            session.altsvc,
            session.enable_altsvc,
            session.hsts,
            session.enable_hsts && !session.insecure_skip_verify,
            session.dict_cache,
            session.enable_compression_dict,
        );
    }
    if stage_id == wire::STAGE_ID_CLI_OUT_DECOMPRESS {
        return run_client_decompress_and_limit_stage(session, req, current_url, ctx, out_resp, out_err);
    }
    if stage_id == wire::STAGE_ID_CLI_OUT_CACHE_STORE {
        return client::stage_cache_store(
            req,
            ctx.headers,
            current_url.href[..],
            ctx.current_method[..],
            out_resp,
            cache_ts,
            cache_revalidate_idx,
            session.cache,
            session.enable_cache,
        );
    }
    if stage_id == wire::STAGE_ID_CLI_OUT_REDIRECT {
        return stage_client_redirect(session, ctx, out_resp, current_url, out_err);
    }
    return wire::StageVerdict.Continue;
}

fn run_client_post_hop_stages<UserStage>(
    session:              client::Client&,
    ctx:                  client::RequestExecutionContext&,
    req:                  const http::Request&,
    current_url:          const core::Url&,
    samesite_eval:        const cookie::SameSiteCookieContext&,
    safe_method:          bool,
    cache_ts:             http::CacheTimestamps&,
    cache_revalidate_idx: i64,
    out_resp:             http::Response&,
    out_err:              http::Error&,
    user_stage:           UserStage&,
) -> wire::StageVerdict {
    var p = wire::begin_pipeline();
    if !client::is_noop_stage(user_stage) {
        var s_ctx = client::StageCtx {
            current_url:    current_url,
            current_method: copy(ctx.current_method),
            headers:        copy(ctx.headers),
            pipeline:       session.wire_pipeline,
            redirect_count: ctx.redirect_count as i32,
            auth_retried:   ctx.auth_retried,
            now_us:         session.virtual_clock_us,
            last_error:     out_err,
            resp:           copy(out_resp),
        };
        let hook_v = client::invoke_stage_hook(user_stage, 0 as u8, wire::ClientHookPhase.PostWireHop, s_ctx);
        out_resp = copy(s_ctx.resp);
        if !p.step(hook_v) {
            if !http::ok(s_ctx.last_error) {
                out_err = s_ctx.last_error;
            }
            return p.verdict;
        }
    }
    for i in session.wire_pipeline.egress_stages.len {
        let stage_id = session.wire_pipeline.egress_stages[i];
        guard wire::is_egress_stage_enabled(session.wire_pipeline, stage_id) else { continue; }
        let v = if wire::is_user_stage_slot(stage_id) {
            invoke_client_custom_slot(user_stage, stage_id, session, ctx, current_url, out_resp, out_err)
        } else {
            dispatch_client_egress_stage(
                stage_id, session, ctx, req, current_url, samesite_eval, safe_method,
                cache_ts, cache_revalidate_idx, out_resp, out_err,
            )
        };
        if !p.step(v) {
            return p.verdict;
        }
    }
    ctx.body_consumed = true;
    finalize_success_response(ctx, out_resp);
    return wire::StageVerdict.Continue;
}

fn execute_client_auth_retry_hop<UserStage>(
    session:              client::Client&,
    ctx:                  client::RequestExecutionContext&,
    req:                  const http::Request&,
    current_url:          const core::Url&,
    samesite_eval:        const cookie::SameSiteCookieContext&,
    safe_method:          bool,
    cache_ts:             http::CacheTimestamps&,
    cache_revalidate_idx: i64,
    resp:                 http::Response&,
    hop_err:              http::Error&,
    user_stage:           UserStage&,
) -> wire::StageVerdict, bool {
    let retry_start_us = session.virtual_clock_us;
    if wire::is_ingress_stage_enabled(session.wire_pipeline, wire::STAGE_ID_CLI_IN_INTERCEPTOR_AUTH) {
        let _ = stage_client_auth_header(
            session.pipeline, ctx.headers, current_url.href[..], ctx.current_method[..],
            ctx.body.len, ctx.redirect_count,
        );
        apply_client_request_signature(session, ctx, current_url);
    }
    resp, hop_err = execute_mock_or_echo_hop(session, ctx, current_url);
    let retry_dur_us = session.virtual_clock_us - retry_start_us;
    apply_network_interceptors_response(session.pipeline, resp, ctx.redirect_count, retry_dur_us);
    guard http::ok(hop_err) else { return wire::StageVerdict.Abort { err_code: hop_err.code }, false; }
    guard check_response_body_size_limit(session, resp, hop_err) else {
        return wire::StageVerdict.Abort { err_code: hop_err.code }, false;
    }

    let post_v = run_client_post_hop_stages(
        session, ctx, req, current_url, samesite_eval, safe_method,
        cache_ts, cache_revalidate_idx, resp, hop_err, user_stage,
    );
    return post_v, true;
}

fn resolve_client_verdict_outcome(
    v:       wire::StageVerdict,
    resp:    http::Response&,
    hop_err: http::Error&,
    err_msg: const u8[:],
) -> bool {
    match v {
        FollowRedirect => {
            return false;
        },
        ShortCircuit sc => {
            if resp.status_code == 0 {
                resp.status_code = sc.status_code;
            }
            hop_err = http::Error { .. };
            return true;
        },
        Abort ab => {
            if http::ok(hop_err) {
                hop_err = http::make_error(ab.err_code, "pipeline", err_msg);
            }
            return true;
        },
        _ => {
            hop_err = http::Error { .. };
            return true;
        },
    };
    return true;
}

fn run_client_auth_retry_loop<UserStage>(
    session:       client::Client&,
    ctx:           client::RequestExecutionContext&,
    req:           const http::Request&,
    current_url:   const core::Url&,
    samesite_eval: const cookie::SameSiteCookieContext&,
    safe_method:   bool,
    cache_ts:      http::CacheTimestamps&,
    hop_reval_idx: i64,
    resp:          http::Response&,
    hop_err:       http::Error&,
    user_stage:    UserStage&,
    post_v:        wire::StageVerdict&,
) -> bool {
    for _ in 2 {
        let is_retry_auth = match post_v { RetryAuth => true, _ => false };
        guard is_retry_auth else { break; }
        let next_v, retry_ok = execute_client_auth_retry_hop(
            session, ctx, req, current_url, samesite_eval, safe_method,
            cache_ts, hop_reval_idx, resp, hop_err, user_stage,
        );
        guard retry_ok else { return false; }
        post_v = next_v;
    }
    return true;
}

fn execute_single_client_hop_iteration<UserStage>(
    session:              client::Client&,
    ctx:                  client::RequestExecutionContext&,
    req:                  const http::Request&,
    cache_ts:             http::CacheTimestamps&,
    cache_revalidate_idx: i64,
    resp:                 http::Response&,
    hop_err:              http::Error&,
    user_stage:           UserStage&,
) -> bool {
    let chain_len = ctx.url_chain.len;
    guard chain_len > 0 && chain_len <= ctx.url_chain.cap else {
        hop_err = http::make_error(rfc::STATUS_BAD_REQUEST, "url_parse", "empty request url chain");
        return true;
    }
    var current_url = ctx.url_chain[chain_len - 1];
    let safe_method = rfc::is_safe_http_method(ctx.current_method[..]);
    var samesite_eval = client::compute_hop_samesite_context(ctx, current_url, safe_method);
    let now_sec = div_euclid(session.virtual_clock_us, 1000000);

    let pre_hop_v = client::run_pre_hop_stages(
        session, ctx, current_url, samesite_eval, safe_method, now_sec, resp, hop_err, user_stage,
    );
    var pre_p = wire::begin_pipeline();
    if !pre_p.step(pre_hop_v) {
        let _ = resolve_client_verdict_outcome(pre_hop_v, resp, hop_err, "aborted by client ingress stage");
        return true;
    }

    var hop_reval_idx = if ctx.redirect_count == 0 { cache_revalidate_idx } else { -1 };
    let cache_lookup_on = wire::is_ingress_stage_enabled(session.wire_pipeline, wire::STAGE_ID_CLI_IN_CACHE_LOOKUP);
    if ctx.redirect_count > 0 && cache_lookup_on {
        let v_redir_cache, r_idx = client::stage_cache_lookup(
            req, current_url.href[..], cache_ts.now_sec, ctx.headers, resp,
            session.cache, session.enable_cache, ctx.current_method[..],
        );
        hop_reval_idx = r_idx;
        if !pre_p.step(v_redir_cache) {
            finalize_success_response(ctx, resp);
            let _ = resolve_client_verdict_outcome(
                v_redir_cache, resp, hop_err, "504 Gateway Timeout (only-if-cached miss)",
            );
            return true;
        }
    }

    let hop_start_us = session.virtual_clock_us;
    resp, hop_err = execute_mock_or_echo_hop(session, ctx, current_url);
    guard http::ok(hop_err) else { return true; }
    guard check_response_body_size_limit(session, resp, hop_err) else { return true; }
    ctx.body_consumed = true;

    let hop_dur_us = session.virtual_clock_us - hop_start_us;
    apply_network_interceptors_response(session.pipeline, resp, ctx.redirect_count, hop_dur_us);

    var post_v = run_client_post_hop_stages(
        session, ctx, req, current_url, samesite_eval, safe_method,
        cache_ts, hop_reval_idx, resp, hop_err, user_stage,
    );
    guard run_client_auth_retry_loop(
        session, ctx, req, current_url, samesite_eval, safe_method,
        cache_ts, hop_reval_idx, resp, hop_err, user_stage, post_v,
    ) else {
        return true;
    }

    return resolve_client_verdict_outcome(post_v, resp, hop_err, "aborted by client egress stage");
}

// ---- 4. Exec Internal Helpers (URL, Redirect, DNS, Dial, H2, Live Hop) -----

inline fn append_single_query_param<B>(
    query_item: const http::QueryItem&,
    sep:        u8,
    out:        B&,
) -> bool {
    guard out.try_push(sep) else { return false; }
    guard core::append_query_component(query_item.key[..], out) else { return false; }
    guard out.try_push('=') else { return false; }
    return core::append_query_component(query_item.value[..], out);
}

fn validate_hop_prerequisites(session: const client::Session&, current_url: const core::Url&) -> http::Error {
    if session.https_only && current_url.scheme() != "https" {
        return http::make_error(rfc::STATUS_BAD_REQUEST, "ssrf_guard", "https_only policy violated");
    }
    let ssrf_err = client::validate_url_against_ssrf(current_url, session.ssrf_guard);
    if ssrf_err != client::RedirectError.None {
        return http::make_error(rfc::STATUS_FORBIDDEN, "ssrf_guard", redirect_error_to_string(ssrf_err));
    }
    return http::Error { .. };
}

fn finalize_success_response(ctx: const client::RequestExecutionContext&, resp: http::Response&) {
    resp.redirect_count = ctx.redirect_count;
    let _ = resp.final_method.try_set(ctx.current_method[..]);
    resp.url_chain.clear();
    for &hop_u in ctx.url_chain {
        var u_str: u8[..256] = [];
        let h = hop_u.href[..];
        let n = min(h.len, u_str.cap);
        let _ = u_str.try_set(h[..n]);
        guard resp.url_chain.try_push(u_str) else { break; }
    }
}

fn merge_session_and_request_headers(
    headers:         http::HeaderMap&,
    default_headers: const http::HeaderMap&,
    req_headers:     const http::HeaderMap&,
    profile:         fingerprint::Profile,
) {
    http::copy_headers(default_headers, headers);
    for &e in req_headers.entries {
        let name = http::entry_name(req_headers, e);
        http::remove_header_by_name(headers, name);
    }
    http::append_all_headers(req_headers, headers);
    if profile != fingerprint::Profile.None && http::find_header(headers, "accept-encoding").len == 0 {
        http::set_header(headers, "Accept-Encoding", "zstd, br, gzip");
    }
}

// Sanitizes the Hop-0 request `Referer` header and `ctx.current_referrer` according to `ctx.current_referrer_policy`.
//
// Example:
//   ctx.current_referrer = "https://a.example/secret?k=1", parsed_initial = "https://b.example/api"
//   sets ctx.current_referrer = "https://a.example/" and Referer header = "https://a.example/"
fn sanitize_initial_request_referrer(
    session:        const client::Session&,
    ctx:            client::RequestExecutionContext&,
    parsed_initial: const core::Url&,
) {
    guard ctx.current_referrer.len > 0 else { return; }
    let parsed_ref = core::new_url(ctx.current_referrer[..]);
    guard parsed_ref.valid else { return; }
    let rel = classify_redirect_origin_relation(parsed_ref, parsed_initial);
    var sanitized_ref: u8[..2048] = [];
    compute_new_referrer(
        parsed_ref,
        parsed_initial,
        ctx.current_referrer_policy,
        RedirectReferrerOptions {
            is_cross_origin: rel.is_cross_origin,
            is_downgrade:    rel.is_downgrade,
        },
        sanitized_ref,
    );
    let _ = ctx.current_referrer.try_set(sanitized_ref[..]);
    if session.enable_referer && sanitized_ref.len > 0 {
        http::set_header(ctx.headers, "Referer", sanitized_ref[..]);
    } else {
        http::remove_header_by_name(ctx.headers, "Referer");
    }
}

// RFC 9110 Section 15.4: Redirection 3xx - Checks whether response headers contain conflicting Location fields.
fn has_conflicting_location_headers(headers: const http::HeaderMap&, loc_hdr: const u8[:]) -> bool {
    let expected_loc = loc_hdr.trim_lws();
    for &e in headers.entries {
        guard http::entry_name(headers, e).eq_ascii_fold("location") else { continue; }
        if http::entry_value(headers, e).trim_lws() != expected_loc {
            return true;
        }
    }
    return false;
}

fn process_redirect_hop(
    session:     client::Session&,
    ctx:         client::RequestExecutionContext&,
    resp:        http::Response&,
    current_url: const core::Url&,
    loc_hdr:     const u8[:],
) -> bool, http::Error {
    if ctx.redirect_mode == client::RedirectMode.Manual {
        return false, http::Error { .. };
    }
    if ctx.redirect_mode == client::RedirectMode.Error {
        return false, http::make_error(rfc::STATUS_BAD_REQUEST, "redirect", "redirects disabled by mode");
    }
    if ctx.redirect_count >= ctx.max_redirects || ctx.url_chain.len >= ctx.url_chain.cap {
        return false, http::make_error(rfc::STATUS_BAD_REQUEST, "redirect", "maximum redirect hops exceeded");
    }
    if has_conflicting_location_headers(resp.headers, loc_hdr) {
        let err_msg = redirect_error_to_string(client::RedirectError.MultipleLocationHeaders);
        return false, http::make_error(rfc::STATUS_BAD_GATEWAY, "redirect", err_msg);
    }

    // RFC 6797 Section 8.3: URI Loading and Port Mapping - Upgrade http:// redirect target for known HSTS hosts.
    var upgraded_loc_buf: u8[..2048] = [];
    var hsts_upgraded = false;
    let hsts_stage_on = wire::is_ingress_stage_enabled(session.wire_pipeline, wire::STAGE_ID_CLI_IN_URL_HSTS);
    if session.enable_hsts && hsts_stage_on && loc_hdr.len > 0 {
        let prelim_target, prelim_err = core::parse_url_with_base(loc_hdr.trim_lws(), current_url);
        if prelim_err == core::UrlParseError.None && prelim_target.valid && !prelim_target.is_secure_scheme() {
            let now_sec = div_euclid(session.virtual_clock_us, 1000000);
            hsts_upgraded = http::hsts_upgrade_url(session.hsts, prelim_target.href[..], now_sec, upgraded_loc_buf);
        }
    }
    let eff_loc = if hsts_upgraded { upgraded_loc_buf[..] } else { loc_hdr };

    var combined_ref_policy: u8[..256] = [];
    let _ = http::get_combined(resp.headers, "Referrer-Policy", combined_ref_policy, 256);
    var redirect_info = client::compute_redirect_info(
        resp.status_code,
        ctx.current_method[..],
        current_url,
        eff_loc,
        combined_ref_policy[..],
        ctx.current_referrer_policy,
        ctx.current_referrer[..],
        ctx.site_for_cookies,
        ctx.first_party_policy,
        ctx.url_chain[..],
        ctx.initiator,
        client::RedirectOptions {
            has_initiator:      ctx.has_initiator,
            cors_mode:          ctx.cors_mode,
            tainted_origin:     ctx.tainted_origin,
            is_main_frame:      ctx.is_main_frame,
            had_cross_site_hop: ctx.had_cross_site_hop,
        },
    );
    redirect_info.insecure_scheme_was_upgraded = hsts_upgraded;

    guard redirect_info.error == client::RedirectError.None else {
        return false, http::make_error(
            rfc::STATUS_BAD_REQUEST, "redirect", redirect_error_to_string(redirect_info.error),
        );
    }

    let redirect_err = client::apply_redirect_transition(session, ctx, redirect_info);
    guard http::ok(redirect_err) else { return false, redirect_err; }

    let _ = ctx.url_chain.try_push(redirect_info.new_url);
    ctx.redirect_count += 1;
    return true, http::Error { .. };
}

fn append_available_dict_header(headers: http::HeaderMap&, dict_b64: const u8[:]) {
    http::set_header(headers, "Available-Dictionary", dict_b64);
    let val = http::find_header(headers, "accept-encoding");
    if val.len == 0 {
        http::set_header(headers, "Accept-Encoding", "dcb, dcz");
        return;
    }
    if !client::header_has_token(val, "dcb") {
        var new_ae: u8[..256] = [];
        guard new_ae.try_set(val) && new_ae.try_append(", dcb, dcz") else { return; }
        http::set_header(headers, "Accept-Encoding", new_ae[..]);
    }
}

fn resolve_mock_protocol_racing(
    session:    client::Session&,
    route:      const client::MockExchange&,
    is_https:   bool,
    origin_buf: const u8[:],
    has_h3:     bool,
    now_sec:    i64,
    resp:       http::Response&,
) {
    if !has_h3 {
        if route.protocol.len > 0 {
            let _ = resp.protocol.try_set(route.protocol[..]);
        }
        return;
    }

    let race_eligible = net::should_create_dns_alpn_h3_job(net::H3JobOptions {
        is_https:                   is_https,
        quic_enabled:               session.enable_protocol_racing,
        uses_proxy:                 session.proxy_url.len > 0,
        has_available_quic_session: false,
    });
    if race_eligible || session.enable_altsvc {
        if route.simulate_quic_blocked {
            http::record_failure(session.altsvc, origin_buf, now_sec);
            let proto = if route.protocol.len > 0 { route.protocol[..] } else { "HTTP/1.1" };
            let _ = resp.protocol.try_set(proto);
        } else {
            http::record_success(session.altsvc, origin_buf);
            let _ = resp.protocol.try_set("h3");
        }
    }
}

fn ingest_transport_response_headers(
    session:     client::Session&,
    current_url: const core::Url&,
    is_https:    bool,
    origin_buf:  const u8[:],
    curr_path:   const u8[:],
    now_sec:     i64,
    resp:        http::Response&,
) {
    let defer_to_strict_stage = session.strict_content_decoding
        || session.verify_content_digest
        || session.max_response_body_bytes > 0;
    if session.auto_decompress &&
        !defer_to_strict_stage &&
        wire::is_egress_stage_enabled(session.wire_pipeline, wire::STAGE_ID_CLI_OUT_DECOMPRESS) {
        let _ = stage_client_decompress(resp, session.dict_cache, false, now_sec);
    }

    if wire::is_egress_stage_enabled(session.wire_pipeline, wire::STAGE_ID_CLI_OUT_ALT_SVC) {
        let _ = stage_client_alt_svc(
            resp,
            current_url,
            is_https,
            origin_buf,
            curr_path,
            now_sec,
            session.altsvc,
            session.enable_altsvc,
            session.hsts,
            session.enable_hsts,
            session.dict_cache,
            session.enable_compression_dict,
        );
    }
}

fn try_match_mock_route(
    session:     client::Session&,
    ctx:         client::RequestExecutionContext&,
    current_url: const core::Url&,
    has_h3:      bool,
    origin_buf:  const u8[:],
    curr_path:   const u8[:],
    now_sec:     i64,
    out_dns_err: client::RedirectError&,
    out_resp:    http::Response&,
) -> bool {
    let curr_href = current_url.href[..];
    let curr_method = ctx.current_method[..];
    let is_https = current_url.is_secure_scheme();

    var matched_idx: i64 = -1;
    for &route, i in session.mock_routes {
        let method_match = route.method.len == 0 || route.method[..].eq_ascii_fold(curr_method);
        let url_match = route.pattern_url[..] == curr_href || core::starts_with(curr_href, route.pattern_url[..]);
        if method_match && url_match {
            matched_idx = i;
            break;
        }
    }
    guard matched_idx >= 0 else { return false; }

    let route .= session.mock_routes[matched_idx];
    let dns_err = validate_mock_route_dns(route, session.ssrf_guard);
    if dns_err != client::RedirectError.None {
        out_dns_err = dns_err;
        out_resp = http::Response {
            status_code:   rfc::STATUS_FORBIDDEN,
            effective_url: copy(current_url.href),
            ..
        };
        return true;
    }

    let mock_resp = build_mock_response(route, current_url, ctx.headers);
    out_resp = copy(mock_resp);
    if route.status_code == rfc::STATUS_SWITCHING_PROTOCOLS {
        let sent_key = http::find_header(ctx.headers, "sec-websocket-key");
        if sent_key.len > 0 && out_resp.header("sec-websocket-accept").len == 0 {
            var accept_buf: u8[..64] = [];
            realtime::compute_websocket_accept(sent_key, accept_buf);
            out_resp.set_header("Sec-WebSocket-Accept", accept_buf[..]);
        }
    }

    resolve_mock_protocol_racing(session, route, is_https, origin_buf, has_h3, now_sec, out_resp);
    ingest_transport_response_headers(session, current_url, is_https, origin_buf, curr_path, now_sec, out_resp);
    return true;
}

inline fn calc_effective_timeout_ms(session_timeout: i64, req_timeout: i64) -> u32 {
    let raw = if req_timeout > 0 { req_timeout } else { session_timeout };
    return min(max(raw, 1), 600000) as u32;
}

inline fn calc_phase_timeout_ms(phase_ms: i64, session_timeout: i64, req_timeout: i64) -> u32 {
    if phase_ms > 0 {
        let raw = if req_timeout > 0 { min(phase_ms, req_timeout) } else { phase_ms };
        return min(max(raw, 1), 600000) as u32;
    }
    return calc_effective_timeout_ms(session_timeout, req_timeout);
}

fn collect_ipv4_dns_candidates(
    ssrf_guard: const security::SsrfGuardPolicy&,
    a_entry:    const dns::CacheEntry&,
    port_num:   u16,
    out_list:   net::DnsCandidate[..8]&,
) -> bool {
    var ip4_buf: u8[..64] = [];
    for ip4 in a_entry.ipv4_hints {
        core::format_ipv4_u32(ip4, ip4_buf);
        if ssrf_guard.enabled && ssrf_guard.deny_local_network {
            guard !security::is_private_or_reserved_ip(ip4_buf[..]) else { return false; }
        }
        let _ = out_list.try_push(
            net::new_dns_candidate(net::AddressFamily.IPv4, ip4_buf[..], port_num, net::L4Protocol.Tcp, 40),
        );
    }
    return true;
}

fn collect_ipv6_dns_candidates(
    ssrf_guard: const security::SsrfGuardPolicy&,
    aaaa_entry: const dns::CacheEntry&,
    port_num:   u16,
    out_list:   net::DnsCandidate[..8]&,
) -> bool {
    var ip6_buf: u8[..64] = [];
    for &ip6 in aaaa_entry.ipv6_hints {
        core::format_ipv6_bytes(ip6, ip6_buf);
        if ssrf_guard.enabled && ssrf_guard.deny_local_network {
            guard !security::is_private_or_reserved_ip(ip6_buf[..]) else { return false; }
        }
        let _ = out_list.try_push(
            net::new_dns_candidate(net::AddressFamily.IPv6, ip6_buf[..], port_num, net::L4Protocol.Tcp, 50),
        );
    }
    return true;
}

fn append_svcb_hint_candidate(
    ssrf_guard: const security::SsrfGuardPolicy&,
    ip_str:     const u8[:],
    fam:        net::AddressFamily,
    eff_port:   u16,
    priority:   u8,
    out_list:   net::DnsCandidate[..8]&,
) -> bool {
    if ssrf_guard.enabled && ssrf_guard.deny_local_network {
        guard !security::is_private_or_reserved_ip(ip_str) else { return false; }
    }
    let _ = out_list.try_push(net::new_dns_candidate(fam, ip_str, eff_port, net::L4Protocol.Tcp, priority));
    return true;
}

fn collect_https_svcb_hint_candidates(
    ssrf_guard: const security::SsrfGuardPolicy&,
    meta:       const net::ConnectionEndpointMetadata&,
    eff_port:   u16,
    task:       net::DnsRaceTask&,
) -> bool {
    if task.ipv6_candidates.len == 0 {
        for &ip6_str in meta.ipv6_hints {
            guard append_svcb_hint_candidate(
                ssrf_guard, ip6_str[..], net::AddressFamily.IPv6, eff_port, 50, task.ipv6_candidates,
            ) else { return false; }
        }
    }
    if task.ipv4_candidates.len == 0 {
        for &ip4_str in meta.ipv4_hints {
            guard append_svcb_hint_candidate(
                ssrf_guard, ip4_str[..], net::AddressFamily.IPv4, eff_port, 40, task.ipv4_candidates,
            ) else { return false; }
        }
    }
    return true;
}

fn resolve_https_svcb_record<B>(
    session:      client::Session&,
    host_str:     const u8[:],
    port_num:     u16,
    now_sec:      i64,
    task:         net::DnsRaceTask&,
    out_ech_list: B&,
) -> bool {
    let https_entry, h_stat = session.dns_cache.lookup(host_str, rfc::DNS_QTYPE_HTTPS, now_sec);
    guard https_entry && h_stat != dns::CacheStatus.Expired && https_entry.https_records.len > 0 else {
        return true;
    }
    let meta, eff_port = net::extract_https_svcb_metadata(https_entry.https_records[0], port_num);
    task.metadata = meta;
    task.https_status = net::DnsQueryStatus.Success;
    if (session.enable_ech || session.auto_ech_discovery) && https_entry.https_records[0].has_ech {
        let _ = out_ech_list.try_set(https_entry.https_records[0].ech_config_list[..]);
    }
    return collect_https_svcb_hint_candidates(session.ssrf_guard, meta, eff_port, task);
}

fn lookup_dns_https_h3_endpoint(
    dns_cache:    const dns::Cache&,
    host_str:     const u8[:],
    default_port: u16,
    now_sec:      i64,
) -> http::AltSvcEndpoint, bool {
    var ep = http::AltSvcEndpoint { .. };
    let https_entry, h_stat = dns_cache.lookup(host_str, rfc::DNS_QTYPE_HTTPS, now_sec);
    guard https_entry && h_stat != dns::CacheStatus.Expired && https_entry.https_records.len > 0 else {
        return ep, false;
    }
    let meta, eff_port = net::extract_https_svcb_metadata(https_entry.https_records[0], default_port);
    guard meta.alpn_h3 else { return ep, false; }
    ep.port = eff_port;
    ep.max_age_sec = 86400;
    ep.persist = false;
    let _ = ep.proto.try_set("h3");
    let target_h = if meta.target_name.len > 0 { meta.target_name[..] } else { host_str };
    let _ = ep.host.try_append(target_h);
    return ep, true;
}

fn try_resolve_override_candidate(
    session:        const client::Session&,
    host_str:       const u8[:],
    port_num:       u16,
    out_candidates: net::DnsCandidate[..32]&,
) -> bool, http::Error {
    var ov_ip: u8[..64] = [];
    guard lookup_resolve_override(session, host_str, port_num, ov_ip) else {
        return false, http::Error { .. };
    }
    if session.ssrf_guard.enabled {
        let blocked = if session.ssrf_guard.deny_local_network {
            security::is_private_or_reserved_ip(ov_ip[..])
        } else {
            security::is_cloud_metadata_or_reserved_ip(ov_ip[..])
        };
        if blocked {
            return true, http::make_error(
                rfc::STATUS_FORBIDDEN, "ssrf_guard", "SSRF: resolve override to private IP blocked",
            );
        }
    }
    let is_v6 = ov_ip[..].contains_byte(':');
    let fam_mismatch = (session.ip_family == net::IpFamily.Ipv4Only && is_v6) ||
        (session.ip_family == net::IpFamily.Ipv6Only && !is_v6);
    if fam_mismatch {
        return true, http::make_error(
            rfc::STATUS_BAD_GATEWAY, "transport", "IP family mismatch for resolve override",
        );
    }
    let fam = if is_v6 { net::AddressFamily.IPv6 } else { net::AddressFamily.IPv4 };
    let _ = out_candidates.try_push(net::new_dns_candidate(fam, ov_ip[..], port_num, net::L4Protocol.Tcp, 50));
    return true, http::Error { .. };
}

fn resolve_and_validate_live_host<B>(
    session:        client::Session&,
    host_str:       const u8[:],
    port_num:       u16,
    now_sec:        i64,
    out_candidates: net::DnsCandidate[..32]&,
    out_ech_list:   B&,
) -> http::Error {
    var committed = false;
    defer if !committed { out_candidates.clear(); out_ech_list.clear(); };
    out_candidates.clear();
    out_ech_list.clear();

    let has_override, ov_err = try_resolve_override_candidate(session, host_str, port_num, out_candidates);
    if has_override {
        committed = http::ok(ov_err);
        return ov_err;
    }

    let now_ms = core::mul_sat_i64(now_sec, 1000);
    var task = net::new_dns_race_task(port_num);

    if session.ip_family != net::IpFamily.Ipv6Only {
        let a_entry, a_stat = session.dns_cache.lookup(host_str, rfc::DNS_QTYPE_A, now_sec);
        if a_entry && a_stat != dns::CacheStatus.Expired {
            guard collect_ipv4_dns_candidates(session.ssrf_guard, a_entry, port_num, task.ipv4_candidates) else {
                return http::make_error(rfc::STATUS_FORBIDDEN, "ssrf_guard", "SSRF: DNS rebinding to private IP blocked");
            }
            task.a_status = net::DnsQueryStatus.Success;
        }
    }

    if session.ip_family != net::IpFamily.Ipv4Only {
        let aaaa_entry, aaaa_stat = session.dns_cache.lookup(host_str, rfc::DNS_QTYPE_AAAA, now_sec);
        if aaaa_entry && aaaa_stat != dns::CacheStatus.Expired {
            guard collect_ipv6_dns_candidates(session.ssrf_guard, aaaa_entry, port_num, task.ipv6_candidates) else {
                return http::make_error(rfc::STATUS_FORBIDDEN, "ssrf_guard", "SSRF: DNS rebinding to private IP blocked");
            }
            task.aaaa_status = net::DnsQueryStatus.Success;
        }
    }

    guard resolve_https_svcb_record(session, host_str, port_num, now_sec, task, out_ech_list) else {
        return http::make_error(rfc::STATUS_FORBIDDEN, "ssrf_guard", "SSRF: HTTPS SVCB hint to private IP blocked");
    }
    if session.ip_family == net::IpFamily.Ipv6Only { task.ipv4_candidates.clear(); }
    if session.ip_family == net::IpFamily.Ipv4Only { task.ipv6_candidates.clear(); }

    let _ = task.check_dns_resolution_delay_tick(core::add_sat_i64(now_ms, rfc::HE_RESOLUTION_DELAY_MS));
    let pref_fam, _ = net::lookup_preferred_family(session.af_cache, host_str, now_sec);
    net::interleave_candidates_by_preference(
        task.ipv6_candidates[..], task.ipv4_candidates[..], pref_fam, out_candidates,
    );
    if out_candidates.len == 0 {
        let fb_fam = if session.ip_family == net::IpFamily.Ipv6Only || host_str.contains_byte(':') {
            net::AddressFamily.IPv6
        } else {
            net::AddressFamily.IPv4
        };
        let _ = out_candidates.try_push(
            net::new_dns_candidate(fb_fam, host_str, port_num, net::L4Protocol.Tcp, 40),
        );
    }
    committed = true;
    return http::Error { .. };
}

struct DialResult {
    sock: i64      = -1,
    ip:   u8[..64] = [],
}

fn build_proxy_basic_auth(p_user: const u8[:], p_pass: const u8[:], out_auth: u8[..256]&) -> bool {
    out_auth.clear();
    guard p_user.len > 0 else { return true; }
    var cred_raw: u8[..160] = [];
    defer core::secure_zeroize_slice(cred_raw[..]);
    guard cred_raw.try_append(p_user) && cred_raw.try_push(':') && cred_raw.try_append(p_pass) else {
        return false;
    }
    var cred_b64: u8[..224] = [];
    defer core::secure_zeroize_slice(cred_b64[..]);
    core::base64_encode(cred_raw[..], cred_b64);
    guard cred_b64.len > 0 && out_auth.try_append("Basic ") && out_auth.try_append(cred_b64[..]) else {
        core::secure_zeroize_slice(out_auth[..]);
        out_auth.clear();
        return false;
    }
    return true;
}

fn establish_https_proxy_transport(
    session:     const client::Session&,
    raw_sock:    i64,
    proxy_host:  const u8[:],
    eff_timeout: u32,
    now_sec:     i64,
) -> net::Transport, http::Error {
    let host_is_hsts = session.enable_hsts && session.hsts.is_hsts_host(proxy_host, now_sec);
    let effective_insecure_skip = session.insecure_skip_verify && !host_is_hsts;
    if session.tls_backend != tls::TlsBackendKind.PureGoose {
        var bcfg = tls::TlsBackendConfig {
            kind:                   session.tls_backend,
            min_version:            session.tls_min_version,
            is_server:              false,
            insecure_skip_verify:   effective_insecure_skip,
            use_system_roots:       session.tls_use_system_roots,
            trust_store:            session.trust_store,
            enable_pq_hybrid:       session.tls_enable_pq_hybrid,
            enable_session_tickets: session.tls_enable_session_tickets,
            require_ocsp_stapling:  session.tls_require_ocsp_stapling,
            ..
        };
        let _ = bcfg.server_name.try_set(proxy_host);
        let alpn_h1: u8[9] = [8, 'h', 't', 't', 'p', '/', '1', '.', '1'];
        let _ = bcfg.alpn_wire.try_set(alpn_h1[..]);
        if session.tls_ca_file.len > 0 {
            let _ = bcfg.ca_file.try_set(session.tls_ca_file[..]);
        }
        let ep_slot, _, st = tls::endpoint_client_handshake_fd(raw_sock, bcfg, eff_timeout);
        guard st == tls::TlsBackendStatus.Ok && ep_slot >= 0 else {
            return net::Transport.Disconnected,
                http::make_error(rfc::STATUS_BAD_GATEWAY, "tls", "HTTPS proxy TLS handshake failed");
        }
        return net::Transport.TlsBackend { fd: raw_sock, endpoint_slot: ep_slot }, http::Error { .. };
    }

    var tls_cfg = tls::ClientHandshakeConfig { .. };
    let _ = tls_cfg.server_name.try_set(proxy_host);
    let _ = tls_cfg.alpn.try_set("http/1.1");
    tls_cfg.trust_store = session.trust_store;
    tls_cfg.insecure_skip_verify = effective_insecure_skip;
    tls_cfg.use_system_roots = session.tls_use_system_roots;
    tls_cfg.enable_pq_hybrid = session.tls_enable_pq_hybrid;
    tls_cfg.enable_session_tickets = session.tls_enable_session_tickets;
    tls_cfg.require_ocsp_stapling = session.tls_require_ocsp_stapling;
    tls_cfg.handshake_timeout_ms = eff_timeout;
    tls_cfg.virtual_clock_sec = if session.virtual_clock_us == 1700000000000000 { 0 } else { now_sec };
    let slot_idx, ok_tls = tls::client_handshake(raw_sock, tls_cfg);
    guard ok_tls else {
        return net::Transport.Disconnected,
            http::make_error(rfc::STATUS_BAD_GATEWAY, "tls", "HTTPS proxy TLS 1.3 handshake failed");
    }
    return net::Transport.Tls { fd: raw_sock, record_seq_rx: 0, record_seq_tx: 0, cipher_slot: slot_idx },
        http::Error { .. };
}

fn dial_https_proxy_tunnel(
    session:     const client::Session&,
    raw_sock:    i64,
    proxy_host:  const u8[:],
    host_str:    const u8[:],
    port_num:    u16,
    proxy_auth:  const u8[:],
    eff_timeout: u32,
    now_sec:     i64,
) -> i64, http::Error {
    var outer_t, tls_err = establish_https_proxy_transport(session, raw_sock, proxy_host, eff_timeout, now_sec);
    guard http::ok(tls_err) else {
        net::fd_close(raw_sock);
        return -1, tls_err;
    }
    let c_err = net::http_connect_transport_handshake(
        outer_t, host_str, port_num, proxy_auth, "goose-wing/1.0", eff_timeout,
    );
    guard c_err == net::ConnectTunnelError.None else {
        outer_t.close();
        return -1, http::make_error(rfc::STATUS_BAD_GATEWAY, "transport", "HTTPS CONNECT tunnel failed");
    }
    let tun_fd, ok_tun = net::alloc_tunnel_fd(outer_t);
    guard ok_tun else {
        outer_t.close();
        return -1, http::make_error(rfc::STATUS_BAD_GATEWAY, "transport", "TLS tunnel descriptor table full");
    }
    return tun_fd, http::Error { .. };
}

fn dial_session_tcp(
    session:    const client::Session&,
    host:       const u8[:],
    port:       u16,
    timeout_ms: u32,
) -> i64 {
    let sock = net::tcp_connect_ex(host, port, timeout_ms, session.ip_family, session.local_bind_addr[..]);
    guard sock > 0 else { return -1; }
    let _ = net::tcp_set_nodelay(sock, session.tcp_nodelay);
    if session.tcp_keepalive_idle_sec > 0 &&
        session.tcp_keepalive_intvl_sec > 0 &&
        session.tcp_keepalive_cnt > 0 {
        let _ = net::tcp_set_keepalive(
            sock,
            session.tcp_keepalive_idle_sec,
            session.tcp_keepalive_intvl_sec,
            session.tcp_keepalive_cnt,
        );
    }
    return sock;
}

fn dial_proxy_hop(
    session:     const client::Session&,
    proxy_url:   const u8[:],
    ps:          const net::ProxyServer&,
    host_str:    const u8[:],
    port_num:    u16,
    candidates:  const net::DnsCandidate[:],
    eff_timeout: u32,
    now_sec:     i64,
) -> DialResult, http::Error {
    var res = DialResult { .. };
    let sock = dial_session_tcp(session, ps.host[..], ps.port, eff_timeout);
    guard sock > 0 else {
        return res, http::make_error(rfc::STATUS_BAD_GATEWAY, "transport", "Proxy TCP connect failed");
    }
    var proxy_ready = false;
    defer if !proxy_ready { net::fd_close(sock); };
    let p_url = core::new_url(proxy_url);
    let p_user = p_url.username();
    let p_pass = p_url.password();
    if ps.scheme == net::ProxyScheme.Socks5 || ps.scheme == net::ProxyScheme.Socks5h {
        let use_ip = ps.scheme == net::ProxyScheme.Socks5 && candidates.len > 0;
        let t_host = if use_ip { candidates[0].ip[..] } else { host_str };
        let s_err = net::socks5_client_handshake(sock, ps.scheme, t_host, port_num, p_user, p_pass, eff_timeout);
        guard s_err == net::Socks5Error.None else {
            return res, http::make_error(rfc::STATUS_BAD_GATEWAY, "transport", "SOCKS5 handshake failed");
        }
        proxy_ready = true;
        res.sock = sock;
        let _ = res.ip.try_set(ps.host[..]);
        return res, http::Error { .. };
    }
    var proxy_auth: u8[..256] = [];
    defer core::secure_zeroize_slice(proxy_auth[..]);
    guard build_proxy_basic_auth(p_user, p_pass, proxy_auth) else {
        return res, http::make_error(rfc::STATUS_BAD_REQUEST, "proxy", "Proxy credentials exceed capacity");
    }
    if ps.scheme == net::ProxyScheme.Https {
        proxy_ready = true;
        let tun_fd, h_err = dial_https_proxy_tunnel(
            session, sock, ps.host[..], host_str, port_num, proxy_auth[..], eff_timeout, now_sec,
        );
        guard http::ok(h_err) else { return res, h_err; }
        res.sock = tun_fd;
        let _ = res.ip.try_set(ps.host[..]);
        return res, http::Error { .. };
    }
    let c_err = net::http_connect_client_handshake(
        sock, host_str, port_num, proxy_auth[..], "goose-wing/1.0", eff_timeout,
    );
    guard c_err == net::ConnectTunnelError.None else {
        return res, http::make_error(rfc::STATUS_BAD_GATEWAY, "transport", "HTTP CONNECT tunnel failed");
    }
    proxy_ready = true;
    res.sock = sock;
    let _ = res.ip.try_set(ps.host[..]);
    return res, http::Error { .. };
}

fn dial_live_tcp_or_proxy(
    session:     const client::Session&,
    proxy_url:   const u8[:],
    proxy_chain: const net::ProxyChain&,
    host_str:    const u8[:],
    port_num:    u16,
    candidates:  const net::DnsCandidate[:],
    eff_timeout: u32,
    now_sec:     i64,
    now_ms:      i64,
) -> DialResult, http::Error {
    if !proxy_chain.is_direct && proxy_chain.servers.len > 0 {
        return dial_proxy_hop(
            session, proxy_url, proxy_chain.servers[0], host_str, port_num, candidates, eff_timeout, now_sec,
        );
    }
    var mgr = net::new_attempt_manager();
    mgr.start_attempt_race(candidates, now_ms);
    for &cand in candidates {
        let sock = dial_session_tcp(session, cand.ip[..], cand.port, eff_timeout);
        if sock > 0 {
            if mgr.attempts.len > 0 {
                let win_id = mgr.attempts[core::sub_sat_i64(mgr.attempts.len, 1)].attempt_id;
                let _ = mgr.bind_winner_attempt(win_id, false);
            }
            var res = DialResult { sock: sock, .. };
            let _ = res.ip.try_set(cand.ip[..]);
            return res, http::Error { .. };
        }
        let _ = mgr.tick_attempt_manager(core::add_sat_i64(now_ms, mgr.effective_cad_ms));
    }
    return DialResult { .. }, http::make_error(rfc::STATUS_BAD_GATEWAY, "transport", "TCP connect failed");
}

inline fn format_h2_request_target_path<B>(current_url: const core::Url&, out_path: B&) -> bool {
    let p_str = current_url.pathname();
    if p_str.len > 0 {
        guard out_path.try_append(p_str) else { return false; }
    } else {
        guard out_path.try_push('/') else { return false; }
    }
    let q_str = current_url.search();
    if q_str.len > 0 {
        guard out_path.try_append(q_str) else { return false; }
    }
    return out_path.len <= 1024;
}

fn build_h2_request_pseudo_headers(
    curr_method: const u8[:],
    current_url: const core::Url&,
    is_https:    bool,
    headers:     const http::HeaderMap&,
) -> http2::PseudoHeaders, bool {
    var pseudo = http2::PseudoHeaders { .. };
    let auth_str = current_url.host();
    let proto_hdr = http::find_header(headers, ":protocol");
    if curr_method.eq_ascii_fold("CONNECT") && proto_hdr.len == 0 {
        pseudo.has_method = true;
        pseudo.has_authority = true;
        let ok_c = pseudo.method.try_set("CONNECT") && pseudo.authority.try_set(auth_str);
        return pseudo, ok_c;
    }
    let scheme_str: const u8[:] = if is_https { "https" } else { "http" };
    var path_buf: u8[..2048] = [];
    guard format_h2_request_target_path(current_url, path_buf) else { return pseudo, false; }

    pseudo.has_method = true;
    pseudo.has_scheme = true;
    pseudo.has_authority = true;
    pseudo.has_path = true;
    guard pseudo.method.try_set(curr_method) &&
        pseudo.scheme.try_set(scheme_str) &&
        pseudo.authority.try_set(auth_str) &&
        pseudo.path.try_set(path_buf[..]) else {
        return pseudo, false;
    }
    if proto_hdr.len > 0 {
        pseudo.has_protocol = true;
        guard pseudo.protocol.try_set(proto_hdr) else { return pseudo, false; }
    }
    return pseudo, true;
}

fn process_h2_control_frame<B>(
    hdr:     const http2::FrameHeader&,
    payload: const u8[:],
    out:     B&,
) {
    if hdr.frame_type == rfc::H2_FRAME_SETTINGS && (hdr.flags & rfc::H2_FLAG_ACK) == 0 {
        let ack_hdr = wire::WireFrameHeader {
            length: 0, frame_type: rfc::H2_FRAME_SETTINGS, flags: rfc::H2_FLAG_ACK, stream_id: 0,
        };
        let _ = wire::encode_frame_header(ack_hdr, out);
    } else if hdr.frame_type == rfc::H2_FRAME_PING && (hdr.flags & rfc::H2_FLAG_ACK) == 0 && payload.len == 8 {
        var ping_data: u8[8] = [0; 8];
        for i in 8 { ping_data[i] = payload[i]; }
        let _ = wire::encode_ping_frame(ping_data, true, out);
    }
}

inline fn record_h2_rst_stream_error(payload: const u8[:], resp: http::Response&) {
    guard payload.len >= 4 else { return; }
    let rst_code = core::read_be_u32(payload, 0);
    var rst_buf: u8[..16] = [];
    rst_code.format_u64_dec(rst_buf);
    let _ = http::append_header(resp.trailers, "x-wing-h2-rst-code", rst_buf[..]);
}

inline fn verify_h2_response_content_length(resp: const http::Response&, is_head: bool) -> bool {
    if is_head || rfc::is_empty_body_status(resp.status_code) {
        return true;
    }
    let cl_hdr = http::header(resp, "Content-Length").trim_lws();
    if cl_hdr.len == 0 {
        return true;
    }
    let cl_val, ok_cl = cl_hdr.parse_u64_dec();
    return ok_cl && (resp.body.len as u64) == cl_val;
}

inline fn apply_initial_h2_response_headers(
    hdr:      const http2::FrameHeader&,
    frag:     const u8[:],
    dec_dt:   http2::DynamicTable&,
    resp:     http::Response&,
    got_hdrs: bool&,
) -> bool {
    var pseudo = http2::PseudoHeaders { .. };
    let d_err = wire::decode_hpack_to_map(dec_dt, frag, pseudo, resp.headers, 8192, true);
    guard d_err == rfc::H2_ERR_NO_ERROR && pseudo.has_status &&
        pseudo.status != rfc::STATUS_SWITCHING_PROTOCOLS else {
        return false;
    }
    resp.status_code = pseudo.status;
    for &e in resp.headers.entries { http::update_response_presence(resp, http::entry_name(resp.headers, e)); }
    if pseudo.status >= 100 && pseudo.status < 200 {
        guard (hdr.flags & rfc::H2_FLAG_END_STREAM) == 0 else { return false; }
        resp.headers.clear();
        resp.presence_mask = 0;
    } else {
        got_hdrs = true;
    }
    return true;
}

fn finish_h2_response_header_block(
    hdr:      const http2::FrameHeader&,
    frag:     const u8[:],
    is_head:  bool,
    dec_dt:   http2::DynamicTable&,
    resp:     http::Response&,
    got_hdrs: bool&,
) -> client::H2RecvStatus {
    if !got_hdrs {
        guard apply_initial_h2_response_headers(hdr, frag, dec_dt, resp, got_hdrs) else {
            return client::H2RecvStatus.Error;
        }
    } else {
        guard (hdr.flags & rfc::H2_FLAG_END_STREAM) != 0 else { return client::H2RecvStatus.Error; }
        var pseudo = http2::PseudoHeaders { is_trailer: true, .. };
        let d_err = wire::decode_hpack_to_map(dec_dt, frag, pseudo, resp.trailers, 8192, true);
        guard d_err == rfc::H2_ERR_NO_ERROR && !pseudo.has_status else { return client::H2RecvStatus.Error; }
    }
    let end_s = (hdr.flags & rfc::H2_FLAG_END_STREAM) != 0 ||
        (got_hdrs && (is_head || rfc::is_empty_body_status(resp.status_code)));
    if end_s {
        guard verify_h2_response_content_length(resp, is_head) else { return client::H2RecvStatus.Error; }
        return client::H2RecvStatus.Complete;
    }
    return client::H2RecvStatus.Continue;
}

fn process_h2_response_headers_frame(
    hdr:     const http2::FrameHeader&,
    payload: const u8[:],
    is_head: bool,
    dec_dt:  http2::DynamicTable&,
    resp:    http::Response&,
    state:   client::H2RecvState&,
) -> client::H2RecvStatus {
    let frag, f_err = http2::extract_headers_frame_payload(hdr, payload);
    guard f_err == rfc::H2_ERR_NO_ERROR else { return client::H2RecvStatus.Error; }
    if (hdr.flags & rfc::H2_FLAG_END_HEADERS) == 0 {
        state.cont_buf.clear();
        guard state.cont_buf.try_append(frag) else { return client::H2RecvStatus.Error; }
        state.cont_hdr = hdr;
        state.await_cont = true;
        return client::H2RecvStatus.Continue;
    }
    return finish_h2_response_header_block(hdr, frag, is_head, dec_dt, resp, state.got_hdrs);
}

fn process_h2_continuation_frame(
    hdr:       const http2::FrameHeader&,
    payload:   const u8[:],
    stream_id: u32,
    is_head:   bool,
    dec_dt:    http2::DynamicTable&,
    resp:      http::Response&,
    state:     client::H2RecvState&,
) -> client::H2RecvStatus {
    guard state.await_cont && hdr.frame_type == rfc::H2_FRAME_CONTINUATION && hdr.stream_id == stream_id else {
        return client::H2RecvStatus.Error;
    }
    guard state.cont_buf.try_append(payload) else { return client::H2RecvStatus.Error; }
    if (hdr.flags & rfc::H2_FLAG_END_HEADERS) == 0 {
        return client::H2RecvStatus.Continue;
    }
    state.await_cont = false;
    return finish_h2_response_header_block(
        state.cont_hdr, state.cont_buf[..], is_head, dec_dt, resp, state.got_hdrs,
    );
}

inline fn rollback_h2_response_preserving_rst(resp: http::Response&, saved_resp: const http::Response&) {
    let rst_val = http::trailer(resp, "x-wing-h2-rst-code");
    var rst_copy: u8[..16] = [];
    let has_rst = rst_val.len > 0 && rst_copy.try_set(rst_val);
    resp = copy(saved_resp);
    if has_rst {
        let _ = http::append_header(resp.trailers, "x-wing-h2-rst-code", rst_copy[..]);
    }
}

fn dispatch_pooled_h2_hop(
    session:     client::Session&,
    conn_id:     i32,
    curr_method: const u8[:],
    ctx:         client::RequestExecutionContext&,
    current_url: const core::Url&,
    is_https:    bool,
    origin_buf:  const u8[:],
    curr_path:   const u8[:],
    now_sec:     i64,
    now_ns:      i64,
    resp:        http::Response&,
) -> bool {
    let c_idx = session.pool.find_connection_index(conn_id);
    guard c_idx >= 0 else { return false; }
    var released = false;
    defer if !released { session.pool.close_pooled_connection(conn_id); };

    let conn .= session.pool.conns[c_idx];
    let hpack_idx = net::ensure_hpack_slot(conn);
    guard hpack_idx >= 0 else { return false; }
    let hpack_enc .= net::hpack_enc_slot(hpack_idx);
    let stream_id = conn.next_h2_stream_id;
    let send_preface = !conn.h2_preface_sent;
    var wire_out: u8[..65536] = [];
    guard client::encode_h2_request(
        curr_method, current_url, is_https, ctx, hpack_enc, stream_id, send_preface, wire_out,
    ) else {
        return false;
    }
    guard wing::send_all(conn.transport, wire_out[..]) else {
        return false;
    }
    conn.h2_preface_sent = true;
    conn.next_h2_stream_id += 2;
    http::reset_response(resp);
    let _ = resp.protocol.try_set("HTTP/2");
    let eff_timeout = calc_phase_timeout_ms(session.read_timeout_ms, session.timeout_ms, ctx.timeout_ms);
    let is_head = curr_method == "HEAD";
    guard client::recv_h2_response_loop(conn, stream_id, is_head, eff_timeout, resp) else {
        return false;
    }
    resp.effective_url = copy(current_url.href);
    http::copy_headers(ctx.headers, resp.sent_headers);
    ingest_transport_response_headers(session, current_url, is_https, origin_buf, curr_path, now_sec, resp);
    session.pool.release_connection(conn_id, now_ns);
    released = true;
    return true;
}

fn establish_backend_tls_connection(
    session:                 const client::Session&,
    sock:                    i64,
    host_str:                const u8[:],
    effective_insecure_skip: bool,
    tls_timeout_ms:          u32,
) -> i64, u8[..64], http::Error {
    var bcfg = tls::TlsBackendConfig {
        kind:                   session.tls_backend,
        min_version:            session.tls_min_version,
        is_server:              false,
        insecure_skip_verify:   effective_insecure_skip,
        use_system_roots:       session.tls_use_system_roots,
        trust_store:            session.trust_store,
        enable_pq_hybrid:       session.tls_enable_pq_hybrid,
        enable_session_tickets: session.tls_enable_session_tickets,
        require_ocsp_stapling:  session.tls_require_ocsp_stapling,
        ..
    };
    let _ = bcfg.server_name.try_set(host_str);
    let alpn_csv = if session.tls_alpn.len > 0 { session.tls_alpn[..] } else { "h2,http/1.1" };
    guard encode_alpn_csv_to_wire(alpn_csv, bcfg.alpn_wire) else {
        return -1, [], http::make_error(rfc::STATUS_BAD_GATEWAY, "tls", "invalid TLS ALPN configuration");
    }
    if session.tls_ca_file.len > 0 {
        let _ = bcfg.ca_file.try_set(session.tls_ca_file[..]);
    }
    if session.tls_client_cert_file.len > 0 || session.tls_client_key_file.len > 0 {
        guard session.tls_client_cert_file.len > 0 && session.tls_client_key_file.len > 0 else {
            return -1, [], http::make_error(rfc::STATUS_BAD_GATEWAY, "tls", "incomplete client mTLS configuration");
        }
        let _ = bcfg.cert_pem_file.try_set(session.tls_client_cert_file[..]);
        let _ = bcfg.key_pem_file.try_set(session.tls_client_key_file[..]);
    }
    if session.tls_crl_file.len > 0 {
        guard load_crl_der_file(session.tls_crl_file[..], bcfg.crl_der) else {
            return -1, [], http::make_error(rfc::STATUS_BAD_GATEWAY, "tls", "TLS CRL file load failed");
        }
    }
    if session.tls_keylog_file.len > 0 {
        let _ = bcfg.keylog_file.try_set(session.tls_keylog_file[..]);
    }
    let ep_slot, neg_alpn, st = tls::endpoint_client_handshake_fd(sock, bcfg, tls_timeout_ms);
    if st == tls::TlsBackendStatus.Ok && ep_slot >= 0 {
        return ep_slot, neg_alpn, http::Error { .. };
    }
    let msg = match st {
        VerifyError => "TLS certificate verification failed",
        Unavailable => "TLS backend unavailable",
        _ => "TLS handshake failed",
    };
    return -1, neg_alpn, http::make_error(rfc::STATUS_BAD_GATEWAY, "tls", msg);
}

fn prepare_pure_tls_client_config(
    session:                 const client::Session&,
    host_str:                const u8[:],
    ech_list:                const u8[:],
    effective_insecure_skip: bool,
    tls_timeout_ms:          u32,
    now_sec:                 i64,
    tls_cfg:                 tls::ClientHandshakeConfig&,
) -> http::Error {
    let _ = tls_cfg.server_name.try_set(host_str);
    let alpn_csv = if session.tls_alpn.len > 0 { session.tls_alpn[..] } else { "h2,http/1.1" };
    let _ = tls_cfg.alpn.try_set(alpn_csv);
    tls_cfg.trust_store = session.trust_store;
    if !effective_insecure_skip && tls_cfg.trust_store.anchors.len == 0 && session.tls_ca_file.len > 0 {
        let _, ok_ca = tls::load_trust_anchors_pem_file(tls_cfg.trust_store, session.tls_ca_file[..]);
        guard ok_ca else {
            return http::make_error(rfc::STATUS_BAD_GATEWAY, "tls", "TLS CA bundle load failed");
        }
    }
    tls_cfg.insecure_skip_verify = effective_insecure_skip;
    tls_cfg.use_system_roots = session.tls_use_system_roots;
    tls_cfg.virtual_clock_sec = if session.virtual_clock_us == 1700000000000000 { 0 } else { now_sec };
    tls_cfg.enable_pq_hybrid = session.tls_enable_pq_hybrid;
    tls_cfg.enable_session_tickets = session.tls_enable_session_tickets;
    tls_cfg.require_ocsp_stapling = session.tls_require_ocsp_stapling;
    tls_cfg.handshake_timeout_ms = tls_timeout_ms;
    if session.tls_keylog_file.len > 0 {
        let _ = tls_cfg.keylog_file.try_set(session.tls_keylog_file[..]);
    }
    if ech_list.len > 0 {
        let _ = tls_cfg.ech_config_list.try_set(ech_list);
    }
    if session.tls_client_cert_file.len > 0 || session.tls_client_key_file.len > 0 {
        guard load_client_mtls_pem_files(
            session.tls_client_cert_file[..], session.tls_client_key_file[..], tls_cfg,
        ) else {
            return http::make_error(rfc::STATUS_BAD_GATEWAY, "tls", "client mTLS credential load failed");
        }
    }
    if session.tls_crl_file.len > 0 {
        guard load_crl_der_file(session.tls_crl_file[..], tls_cfg.crl_der) else {
            return http::make_error(rfc::STATUS_BAD_GATEWAY, "tls", "TLS CRL file load failed");
        }
    }
    return http::Error { .. };
}

fn establish_https_transport(
    session:        const client::Session&,
    sock:           i64,
    host_str:       const u8[:],
    ech_list:       const u8[:],
    tls_timeout_ms: u32,
    now_sec:        i64,
) -> net::Transport, net::NegotiatedProtocol, http::Error {
    let host_is_hsts = session.enable_hsts && session.hsts.is_hsts_host(host_str, now_sec);
    let effective_insecure_skip = session.insecure_skip_verify && !host_is_hsts;
    if session.tls_backend != tls::TlsBackendKind.PureGoose {
        let ep_slot, neg_alpn, tls_err = establish_backend_tls_connection(
            session, sock, host_str, effective_insecure_skip, tls_timeout_ms,
        );
        guard http::ok(tls_err) else {
            return net::Transport.Disconnected, net::NegotiatedProtocol.Http11, tls_err;
        }
        let neg_proto = if neg_alpn[..] == "h2" {
            net::NegotiatedProtocol.Http2
        } else {
            net::NegotiatedProtocol.Http11
        };
        return net::Transport.TlsBackend { fd: sock, endpoint_slot: ep_slot }, neg_proto, http::Error { .. };
    }

    var tls_cfg = tls::ClientHandshakeConfig { .. };
    defer core::secure_zeroize_32(tls_cfg.client_priv_seed);
    let prep_err = prepare_pure_tls_client_config(
        session, host_str, ech_list, effective_insecure_skip, tls_timeout_ms, now_sec, tls_cfg,
    );
    guard http::ok(prep_err) else {
        return net::Transport.Disconnected, net::NegotiatedProtocol.Http11, prep_err;
    }

    let slot_idx, ok_tls = tls::client_handshake(sock, tls_cfg);
    guard ok_tls else {
        return net::Transport.Disconnected,
            net::NegotiatedProtocol.Http11,
            http::make_error(rfc::STATUS_BAD_GATEWAY, "tls", "TLS 1.3 handshake failed");
    }
    if session.enable_ktls_offload {
        let _, _ = tls::try_enable_ktls(slot_idx, sock);
    }
    let neg_proto = if tls::session_alpn(slot_idx) == "h2" {
        net::NegotiatedProtocol.Http2
    } else {
        net::NegotiatedProtocol.Http11
    };
    let t = net::Transport.Tls {
        fd: sock, record_seq_rx: 0, record_seq_tx: 0, cipher_slot: slot_idx,
    };
    return t, neg_proto, http::Error { .. };
}

fn establish_pooled_connection(
    session:            client::Session&,
    pool_key:           const net::PoolKey&,
    proxy_url:          const u8[:],
    proxy_chain:        const net::ProxyChain&,
    host_str:           const u8[:],
    port_num:           u16,
    is_https:           bool,
    dns_candidates:     const net::DnsCandidate[:],
    ech_list:           const u8[:],
    connect_timeout_ms: u32,
    tls_timeout_ms:     u32,
    now_sec:            i64,
    now_ms:             i64,
    now_ns:             i64,
) -> i32, http::Error {
    let dial_res, dial_err = dial_live_tcp_or_proxy(
        session, proxy_url, proxy_chain, host_str, port_num, dns_candidates, connect_timeout_ms, now_sec, now_ms,
    );
    guard http::ok(dial_err) else { return -1, dial_err; }
    let sock = dial_res.sock;
    if proxy_chain.is_direct {
        let win_fam = if dial_res.ip[..].contains_byte(':') {
            net::AddressFamily.IPv6
        } else {
            net::AddressFamily.IPv4
        };
        net::record_preferred_family(session.af_cache, host_str, win_fam, now_sec);
    }

    var t = net::Transport.Disconnected;
    var neg_proto = net::NegotiatedProtocol.Http11;
    if is_https {
        let https_t, https_proto, tls_err = establish_https_transport(
            session, sock, host_str, ech_list, tls_timeout_ms, now_sec,
        );
        guard http::ok(tls_err) else {
            net::fd_close(sock);
            return -1, tls_err;
        }
        t = https_t;
        neg_proto = https_proto;
    } else {
        if session.http2_prior_knowledge {
            neg_proto = net::NegotiatedProtocol.Http2;
        }
        t = net::Transport.Tcp { fd: sock };
    }
    let max_streams: i32 = if neg_proto == net::NegotiatedProtocol.Http2 { 100 } else { 1 };
    let conn_id = net::register_connection(session.pool, pool_key, neg_proto, t, dial_res.ip[..], max_streams, now_ns);
    guard conn_id > 0 else {
        t.close();
        return -1, http::make_error(rfc::STATUS_BAD_GATEWAY, "transport", "connection pool registration failed");
    }
    return conn_id, http::Error { .. };
}

fn execute_live_network_hop(
    session:     client::Session&,
    ctx:         client::RequestExecutionContext&,
    current_url: const core::Url&,
    is_https:    bool,
    origin_buf:  const u8[:],
    has_h3:      bool,
    h3_ep:       const http::AltSvcEndpoint&,
    resp:        http::Response&,
) -> http::Error {
    let now_ns = session.virtual_clock_us * 1000;
    let now_sec = session.virtual_clock_us / 1000000;
    let now_ms = session.virtual_clock_us / 1000;
    let host_str = current_url.hostname();
    sync_session_pool_knobs(session);
    if session.ssrf_guard.enabled {
        let blocked = if session.ssrf_guard.deny_local_network {
            security::is_private_or_reserved_ip(host_str)
        } else {
            security::is_cloud_metadata_or_reserved_ip(host_str)
        };
        if blocked {
            return http::make_error(rfc::STATUS_FORBIDDEN, "ssrf_guard", "SSRF: private IP blocked");
        }
    }

    let port_num = current_url.effective_port() as u16;
    var eff_proxy_url: u8[..256] = [];
    let proxy_chain, ok_proxy = resolve_effective_hop_proxy(session, host_str, is_https, eff_proxy_url);
    guard ok_proxy else {
        return http::make_error(rfc::STATUS_BAD_REQUEST, "proxy", "invalid proxy configuration");
    }
    var dns_candidates: net::DnsCandidate[..32] = [];
    var ech_list:       u8[..512]               = [];
    let needs_local_dns = proxy_chain.is_direct ||
        (proxy_chain.servers.len > 0 && proxy_chain.servers[0].scheme == net::ProxyScheme.Socks5);
    if needs_local_dns {
        let dns_err = resolve_and_validate_live_host(session, host_str, port_num, now_sec, dns_candidates, ech_list);
        guard http::ok(dns_err) else { return dns_err; }
    }
    if !proxy_chain.is_direct {
        net::sanitize_tunnel_headers_for_origin(ctx.headers);
    }
    if has_h3 && is_https && proxy_chain.is_direct && session.enable_protocol_racing {
        let saved_t = ctx.timeout_ms;
        if session.read_timeout_ms > 0 {
            ctx.timeout_ms = calc_phase_timeout_ms(session.read_timeout_ms, session.timeout_ms, saved_t);
        }
        let ok_h3 = client::execute_live_h3_hop(session, ctx, current_url, origin_buf, h3_ep, now_sec, resp);
        ctx.timeout_ms = saved_t;
        if ok_h3 {
            session.altsvc.record_success(origin_buf);
            return http::Error { .. };
        }
        session.altsvc.record_failure(origin_buf, now_sec);
    }

    let site_site = if ctx.top_frame_origin.host.len > 0 {
        ctx.top_frame_origin.host[..]
    } else if !ctx.site_for_cookies.is_null && ctx.site_for_cookies.registrable_domain.len > 0 {
        ctx.site_for_cookies.registrable_domain[..]
    } else {
        host_str
    };

    let pool_scheme = if is_https { net::PoolScheme.Https } else { net::PoolScheme.Http };
    let nik = net::new_network_isolation_key(site_site, site_site);
    let pool_key = net::new_pool_key(
        pool_scheme,
        host_str,
        port_num,
        proxy_chain,
        net::nik_to_anonymization_key(nik, ctx.had_cross_site_hop),
        net::TlsAndDnsPolicy { .. },
    );

    let first_ip = if dns_candidates.len > 0 { dns_candidates[0].ip[..] } else { "" };
    var conn_id, has_pooled = session.pool.acquire_pooled_connection(pool_key, first_ip, now_ns);
    if !has_pooled {
        let conn_t = calc_phase_timeout_ms(session.connect_timeout_ms, session.timeout_ms, ctx.timeout_ms);
        let tls_t = calc_phase_timeout_ms(session.tls_handshake_timeout_ms, session.timeout_ms, ctx.timeout_ms);
        let new_id, conn_err = establish_pooled_connection(
            session, pool_key, eff_proxy_url[..], proxy_chain, host_str, port_num, is_https,
            dns_candidates[..], ech_list[..], conn_t, tls_t, now_sec, now_ms, now_ns,
        );
        guard http::ok(conn_err) else { return conn_err; }
        conn_id = new_id;
    }

    let curr_path = current_url.pathname();
    let c_idx = session.pool.find_connection_index(conn_id);
    if c_idx >= 0 && session.pool.conns[c_idx].protocol == net::NegotiatedProtocol.Http2 {
        let ok_h2 = dispatch_pooled_h2_hop(
            session, conn_id, ctx.current_method[..], ctx, current_url, is_https,
            origin_buf, curr_path, now_sec, now_ns, resp,
        );
        guard ok_h2 else {
            return http::make_error(rfc::STATUS_BAD_GATEWAY, "transport", "HTTP/2 exchange failed");
        }
        return http::Error { .. };
    }

    let saved_h1_t = ctx.timeout_ms;
    if session.read_timeout_ms > 0 {
        ctx.timeout_ms = calc_phase_timeout_ms(session.read_timeout_ms, session.timeout_ms, saved_h1_t);
    }
    let ok_hop = client::dispatch_pooled_h1_hop(
        session, conn_id, ctx.current_method[..], ctx, current_url, is_https,
        origin_buf, curr_path, now_sec, now_ns, resp,
    );
    ctx.timeout_ms = saved_h1_t;
    guard ok_hop else {
        return http::make_error(rfc::STATUS_BAD_GATEWAY, "transport", "HTTP/1.1 exchange failed");
    }
    return http::Error { .. };
}

fn execute_mock_or_echo_hop(
    session:     client::Session&,
    ctx:         client::RequestExecutionContext&,
    current_url: const core::Url&,
) -> http::Response, http::Error {
    var origin_buf: u8[..128] = [];
    format_url_origin(current_url, origin_buf);
    let now_sec = session.virtual_clock_us / 1000000;
    let is_https = current_url.is_secure_scheme();

    var candidate_h3_ep = http::AltSvcEndpoint { .. };
    var has_h3 = false;
    if session.enable_altsvc && is_https {
        has_h3 = http::lookup_h3(session.altsvc, origin_buf[..], now_sec, candidate_h3_ep);
    }
    let race_dns_h3 = !has_h3 && is_https && session.enable_protocol_racing
        && !http::is_broken(session.altsvc, origin_buf[..], now_sec);
    if race_dns_h3 {
        let port_num = current_url.effective_port() as u16;
        let dns_ep, ok_dns_h3 = lookup_dns_https_h3_endpoint(
            session.dns_cache, current_url.hostname(), port_num, now_sec,
        );
        if ok_dns_h3 {
            candidate_h3_ep = dns_ep;
            has_h3 = true;
        }
    }

    let curr_path = current_url.pathname();
    if wire::is_ingress_stage_enabled(session.wire_pipeline, wire::STAGE_ID_CLI_IN_DICT_NEGOTIATE) {
        let _ = stage_client_dict_negotiate(
            ctx.headers, session.dict_cache, session.enable_compression_dict,
            origin_buf[..], curr_path, is_https, now_sec,
        );
    } else {
        http::remove_header_by_name(ctx.headers, "Available-Dictionary");
        http::remove_header_by_name(ctx.headers, "Dictionary-ID");
    }

    var resp = http::Response { .. };
    var dns_rebinding_err = client::RedirectError.None;
    let matched = try_match_mock_route(
        session, ctx, current_url, has_h3, origin_buf[..], curr_path, now_sec, dns_rebinding_err, resp,
    );
    if matched {
        if dns_rebinding_err != client::RedirectError.None {
            return resp, http::make_error(
                rfc::STATUS_FORBIDDEN, "ssrf_guard", redirect_error_to_string(dns_rebinding_err),
            );
        }
        return resp, http::Error { .. };
    }

    if session.mock_routes.len == 0 {
        let live_err = execute_live_network_hop(
            session, ctx, current_url, is_https, origin_buf[..], has_h3, candidate_h3_ep, resp,
        );
        return resp, live_err;
    }

    return resp, http::make_error(rfc::STATUS_BAD_GATEWAY, "mock", "no matching mock route for request");
}

// RFC 9110 Section 11.1: Authentication Scheme - Checks that `hdr` begins with `scheme_tok`
// followed by end-of-string or BWS/SP delimiter (`' '` or `'\t'`).
inline fn has_auth_scheme_prefix(hdr: const u8[:], scheme_tok: const u8[:]) -> bool {
    let s = hdr.trim_lws();
    guard s.starts_with_fold(scheme_tok) else { return false; }
    return s.len == scheme_tok.len || s[scheme_tok.len] == ' ' || s[scheme_tok.len] == '\t';
}

fn try_find_scheme_auth_header<B>(
    session:       client::Client&,
    ctx:           client::RequestExecutionContext&,
    current_url:   const core::Url&,
    resp:          const http::Response&,
    scheme_prefix: const u8[:],
    out:           B&,
) -> bool {
    for &e in resp.headers.entries {
        let h_name = http::entry_name(resp.headers, e);
        let h_val = http::entry_value(resp.headers, e);
        if h_name.eq_ascii_fold("WWW-Authenticate") && has_auth_scheme_prefix(h_val, scheme_prefix) {
            if client::compute_401_auth_header(session, ctx, current_url, h_val, out) {
                return true;
            }
        }
    }
    return false;
}

fn find_auth_header_from_response<B>(
    session:     client::Client&,
    ctx:         client::RequestExecutionContext&,
    current_url: const core::Url&,
    resp:        const http::Response&,
    out:         B&,
) -> bool {
    // Scan all WWW-Authenticate headers, prioritizing PrivateToken -> Digest -> Basic.
    if !ctx.auth_retried && session.private_token_cache.entries.len > 0 {
        let p_scheme = rfc::SCHEME_PRIVATE_TOKEN;
        if try_find_scheme_auth_header(session, ctx, current_url, resp, p_scheme, out) {
            return true;
        }
    }
    guard session.creds.has_credentials else { return false; }
    if try_find_scheme_auth_header(session, ctx, current_url, resp, "Digest", out) {
        return true;
    }
    if !ctx.auth_retried {
        return try_find_scheme_auth_header(session, ctx, current_url, resp, "Basic", out);
    }
    return false;
}

fn execute_request_inner(session: client::Client&, req: const http::Request&) -> http::Response, http::Error {
    var noop = wire::NoOpStage {};
    return client::execute_pipeline_with_stage(session, req, noop);
}

fn evaluate_response_retry_after(
    session:  client::Client&,
    host_str: const u8[:],
    resp:     const http::Response&,
    now_ns:   i64,
) {
    let ra_val = resp.header("Retry-After");
    guard ra_val.len > 0 else { return; }
    let now_ms = div_euclid(session.virtual_clock_us, 1000);
    let wait_ms, ok_ra = net::parse_retry_after_ms(ra_val, now_ms);
    if ok_ra {
        let _ = net::trip_circuit_breaker_if_exceeded(session.circuit_breaker, host_str, wait_ms, now_ns);
    }
}

fn record_client_har_telemetry(
    session:      client::Client&,
    req:          const http::Request&,
    resp:         const http::Response&,
    total_dur_us: i64,
) {
    guard session.enable_har_telemetry else { return; }
    let status_u16 = (resp.status_code as u64) as! u16;
    var entry = client::HarEntry {
        status:         status_u16,
        request_bytes:  req.body.len,
        response_bytes: resp.body.len,
        timings: client::RequestTimings {
            wait_us: max(0, total_dur_us),
            ..
        },
        ..
    };
    let _ = entry.started_iso8601.try_set("2026-01-01T00:00:00.000Z");
    let _ = entry.method.try_set(req.method[..]);
    let _ = entry.url.try_set(req.url[..]);
    let har_ver = if resp.is_http3() {
        "HTTP/3"
    } else if resp.is_http1() || http::protocol(resp).len == 0 {
        "HTTP/1.1"
    } else {
        http::protocol(resp)
    };
    let _ = entry.http_version.try_set(har_ver);
    session.last_har_json.clear();
    client::serialize_har_entry_json(entry, session.last_har_json);
}

// ---- 5. Realtime (WebSocket, SSE) & MASQUE Internal Helpers ----------------

fn normalize_realtime_url<B>(url: const u8[:], out: B&) {
    out.clear();
    if url.starts_with_fold("ws://") {
        let _ = out.try_append("http://");
        let _ = out.try_append(url[5..]);
    } else if url.starts_with_fold("wss://") {
        let _ = out.try_append("https://");
        let _ = out.try_append(url[6..]);
    } else {
        let _ = out.try_append(url);
    }
}

fn prepare_ws_upgrade_request<B>(
    session:        client::Session&,
    url:            const u8[:],
    out_client_key: B&,
) -> http::Request {
    var eff_url: u8[..2048] = [];
    normalize_realtime_url(url, eff_url);

    var req = http::new_request("GET", eff_url[..]);
    http::set_header(req, "Upgrade", "websocket");
    http::set_header(req, "Connection", "Upgrade");
    http::set_header(req, "Sec-WebSocket-Version", "13");

    var nonce: u8[16] = [0; 16];
    if !core::sim_rng_fill(nonce[..]) {
        let _ = native_crypto_random_bytes(nonce[..]);
    }
    var seed: u64 = (session.virtual_clock_us as u64) ^ (session.creds.nonce_counter as u64) ^ 0x5DEECE66D;
    for &b in nonce {
        seed ^= core::shl_sat_u64(seed, 13);
        seed ^= seed >> 7;
        seed ^= core::shl_sat_u64(seed, 17);
        b ^= (seed & 0xFF) as u8;
    }
    session.creds.nonce_counter = core::add_sat_u64(session.creds.nonce_counter as u64, 1) as u32;
    out_client_key.clear();
    realtime::generate_websocket_key(nonce, out_client_key);
    http::set_header(req, "Sec-WebSocket-Key", out_client_key[..]);
    return req;
}

fn ws_perform_handshake(
    session:    client::Session&,
    req:        http::Request&,
    client_key: const u8[:],
) -> realtime::WebSocketSession, http::Response, http::Error {
    let resp, err = client::do(session, req);
    guard http::ok(err) else {
        return realtime::new_websocket_session(true), resp, err;
    }

    // Validate 101 Switching Protocols (RFC 6455 Section 4.2.2, RFC 9931 Section 3).
    if resp.status_code != rfc::STATUS_SWITCHING_PROTOCOLS {
        return realtime::new_websocket_session(true), resp, http::make_error(
            resp.status_code,
            "websocket_handshake",
            "server did not return 101 Switching Protocols",
        );
    }

    let upg = http::header(resp, "Upgrade");
    if !client::header_has_token(upg, "websocket") {
        return realtime::new_websocket_session(true), resp, http::make_error(
            rfc::STATUS_BAD_REQUEST,
            "websocket_handshake",
            "missing or invalid Upgrade header in server response",
        );
    }

    let conn = http::header(resp, "Connection");
    if !client::header_has_token(conn, "upgrade") {
        return realtime::new_websocket_session(true), resp, http::make_error(
            rfc::STATUS_BAD_REQUEST,
            "websocket_handshake",
            "missing Connection: Upgrade header in server response",
        );
    }

    let server_accept = http::header(resp, "Sec-WebSocket-Accept");
    if !realtime::validate_websocket_accept(client_key, server_accept) {
        return realtime::new_websocket_session(true), resp, http::make_error(
            rfc::STATUS_BAD_REQUEST,
            "websocket_handshake",
            "invalid Sec-WebSocket-Accept key in server response",
        );
    }

    var ws_sess = realtime::new_websocket_session(true);
    let proto = http::header(resp, "Sec-WebSocket-Protocol");
    if proto.len > 0 {
        let req_proto = http::header(req, "Sec-WebSocket-Protocol");
        let valid_proto = req_proto.len > 0 &&
            !proto.contains_byte(',') &&
            realtime::has_subprotocol_token(req_proto, proto) &&
            ws_sess.subprotocol.try_set(proto);
        if !valid_proto {
            return realtime::new_websocket_session(true), resp, http::make_error(
                rfc::STATUS_BAD_REQUEST,
                "websocket_handshake",
                "server returned Sec-WebSocket-Protocol not offered by client",
            );
        }
    }

    return ws_sess, resp, http::Error { .. };
}

fn sse_perform_connect(
    session: client::Session&,
    sub:     realtime::SseSubscription,
    req:     http::Request&,
) -> realtime::SseSubscription, http::Response, http::Error {
    var eff_sub = sub;
    let resp, err = client::do(session, req);
    guard http::ok(err) else {
        return eff_sub, resp, err;
    }

    if resp.status_code != rfc::STATUS_OK {
        return eff_sub, resp, http::make_error(
            resp.status_code,
            "sse_connect",
            "server returned non-200 status for SSE stream",
        );
    }

    let ct = http::header(resp, "Content-Type");
    if !client::is_sse_content_type(ct) {
        return eff_sub, resp, http::make_error(
            rfc::STATUS_UNSUPPORTED_MEDIA_TYPE,
            "sse_connect",
            "server response is not text/event-stream",
        );
    }

    eff_sub.connected = true;
    return eff_sub, resp, http::Error { .. };
}

inline fn is_masque_reg_name_char(b: u8) -> bool {
    return core::is_uri_unreserved(b) ||
           b == '!' || b == '$' || b == '&' || b == '\'' ||
           b == '(' || b == ')' || b == '*' || b == '+' ||
           b == ',' || b == ';' || b == '=';
}

inline fn append_masque_ipv6_encoded<B>(v6_raw: const u8[:], out: B&) -> bool {
    var comp_v6: u8[..64] = [];
    guard core::parse_and_compress_ipv6(v6_raw, comp_v6) else { return false; }
    for b in v6_raw {
        let ok_b = if b == ':' { out.try_append("%3A") } else { out.try_push(b) };
        guard ok_b else { return false; }
    }
    return true;
}

// Normalizes a MASQUE target host by stripping IPv6 brackets and percent-encoding ':' as '%3A' (RFC 9298 Section 2).
//
// Example:
//   target_host = "[2001:db8::1]"
//   returns: out = "2001%3Adb8%3A%3A1", ok = true
fn encode_masque_target_host<B>(target_host: const u8[:], out: B&) -> bool {
    guard target_host.len > 0 && !target_host.contains_byte('%') else { return false; }
    var committed = false;
    defer if !committed { out.clear(); };
    out.clear();

    if core::starts_with(target_host, "[") || core::ends_with(target_host, "]") {
        let after_l, ok_l = target_host.strip_prefix("[");
        let inner, ok_r = after_l.strip_suffix("]");
        guard ok_l && ok_r && inner.len >= 2 && append_masque_ipv6_encoded(inner, out) else {
            return false;
        }
        committed = true;
        return true;
    }

    if target_host.contains_byte(':') {
        guard append_masque_ipv6_encoded(target_host, out) else { return false; }
        committed = true;
        return true;
    }

    for b in target_host {
        guard is_masque_reg_name_char(b) else { return false; }
    }
    guard out.try_set(target_host) else { return false; }
    committed = true;
    return true;
}

fn execute_masque_connect(
    session:    client::Session&,
    tunnel:     net::MasqueTunnelSession&,
    proxy_url:  const u8[:],
    reject_msg: const u8[:],
) -> net::MasqueTunnelSession, http::Response, http::Error {
    tunnel.state = net::MasqueTunnelState.Connecting;

    var req_path:    u8[..256]       = [];
    var req_headers: http::HeaderMap = http::HeaderMap { .. };
    net::build_masque_connect_request(tunnel, req_headers, req_path);

    var full_url: u8[..2048] = [];
    guard proxy_url.len > 0 && proxy_url.len <= 256 &&
          proxy_url.len + req_path.len <= full_url.cap else {
        tunnel.state = net::MasqueTunnelState.Failed;
        return tunnel, http::Response { .. }, http::make_error(
            rfc::STATUS_BAD_REQUEST, "masque", "proxy_url exceeds capacity",
        );
    }
    full_url.append(proxy_url.trim_end_byte('/'));
    full_url.append(req_path[..]);

    var req = http::new_request("CONNECT", full_url[..]);
    for &e in req_headers.entries {
        http::set_header(req, http::entry_name(req_headers, e), http::entry_value(req_headers, e));
    }

    let resp, err = client::do(session, req);
    if !http::ok(err) || !http::is_success(resp) {
        tunnel.state = net::MasqueTunnelState.Failed;
        let ret_err = if !http::ok(err) {
            err
        } else {
            http::make_error(resp.status_code, "masque", reject_msg)
        };
        return tunnel, resp, ret_err;
    }

    let caps_val = http::header(resp, "capsule-protocol");
    if !net::is_capsule_protocol_negotiated(caps_val) {
        tunnel.state = net::MasqueTunnelState.Failed;
        return tunnel, resp, http::make_error(
            rfc::STATUS_BAD_GATEWAY, "masque", "proxy missing required Capsule-Protocol: ?1 header",
        );
    }

    tunnel.state = net::MasqueTunnelState.Established;
    return tunnel, resp, http::Error { .. };
}

// ---- 6. Control Knob, TLS Credential Loader, Resolve & Proxy Helpers -------

fn sync_session_pool_knobs(session: client::Session&) {
    let idle_ns: i64 = if session.pool_idle_timeout_ms > 0 {
        core::mul_sat_i64(session.pool_idle_timeout_ms, 1000000)
    } else {
        -1
    };
    net::configure_stream_pool(
        session.pool,
        session.max_conns_per_host,
        session.disable_keepalive,
        idle_ns,
    );
}

fn apply_client_config_knobs(c: client::Client&, cfg: const client::Config&) {
    let eff_mode = if cfg.redirect_mode != client::RedirectMode.Follow {
        cfg.redirect_mode
    } else if !cfg.follow_redirects {
        client::RedirectMode.Manual
    } else {
        client::RedirectMode.Follow
    };
    c.redirect_mode = eff_mode;
    c.follow_redirects = (eff_mode == client::RedirectMode.Follow);
    c.max_redirects = cfg.max_redirects;
    c.https_only = cfg.https_only;
    c.ssrf_guard.https_only = cfg.https_only;
    c.enable_referer = cfg.enable_referer;
    c.default_referrer_policy = cfg.default_referrer_policy;
    c.enable_hsts = cfg.enable_hsts;
    c.enable_doh = cfg.enable_doh;
    c.enable_ech = cfg.enable_ech;
    c.http2_prior_knowledge = cfg.http2_prior_knowledge;
    c.auto_decompress = cfg.auto_decompress;
    c.max_response_body_bytes = max(cfg.max_response_body_bytes, 0);
    c.verify_content_digest = cfg.verify_content_digest;
    c.enable_early_data = cfg.enable_early_data;
    c.enable_har_telemetry = cfg.enable_har_telemetry;
    c.allow_loopback_ssrf = cfg.allow_loopback_ssrf;
    if cfg.allow_loopback_ssrf {
        c.ssrf_guard.deny_local_network = false;
    }
    c.max_retries = cfg.max_retries;
    if cfg.max_retries > 0 {
        let _ = client::add_retry(c.pipeline, cfg.max_retries, true);
    }
    c.connect_timeout_ms = max(cfg.connect_timeout_ms, 0);
    c.tls_handshake_timeout_ms = max(cfg.tls_handshake_timeout_ms, 0);
    c.read_timeout_ms = max(cfg.read_timeout_ms, 0);
    c.pool_idle_timeout_ms = max(cfg.pool_idle_timeout_ms, 0);
    let _ = c.tls_client_cert_file.try_set(cfg.tls_client_cert_file);
    let _ = c.tls_client_key_file.try_set(cfg.tls_client_key_file);
    c.tls_enable_pq_hybrid = cfg.tls_enable_pq_hybrid;
    let _ = c.tls_alpn.try_set(cfg.tls_alpn);
    c.tls_enable_session_tickets = cfg.tls_enable_session_tickets;
    c.tls_require_ocsp_stapling = cfg.tls_require_ocsp_stapling;
    let _ = c.tls_crl_file.try_set(cfg.tls_crl_file);
    let _ = c.tls_keylog_file.try_set(cfg.tls_keylog_file);
    c.enable_ktls_offload = cfg.enable_ktls_offload;
    c.ip_family = cfg.ip_family;
    let _ = c.local_bind_addr.try_set(cfg.local_bind_addr);
    c.tcp_nodelay = cfg.tcp_nodelay;
    c.tcp_keepalive_idle_sec = cfg.tcp_keepalive_idle_sec;
    c.tcp_keepalive_intvl_sec = cfg.tcp_keepalive_intvl_sec;
    c.tcp_keepalive_cnt = cfg.tcp_keepalive_cnt;
    c.disable_keepalive = cfg.disable_keepalive;
    c.max_conns_per_host = max(cfg.max_conns_per_host, 0);
    c.use_env_proxy = cfg.use_env_proxy;
    sync_session_pool_knobs(c);
}

// RFC 7301 Section 3.1: The Application-Layer Protocol Negotiation Extension -
// Encodes a comma-separated ALPN protocol list into length-prefixed wire bytes.
//
// Example:
//   alpn_csv = "h2,http/1.1"
//   returns: ok = true, out_wire = [2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1']
fn encode_alpn_csv_to_wire(alpn_csv: const u8[:], out_wire: u8[..64]&) -> bool {
    var wire_buf: u8[..64] = [];
    var tokenizer = core::make_byte_tokenizer(alpn_csv, ',');
    while true {
        let tok, has_tok = core::token_next(tokenizer);
        guard has_tok else { break; }
        let proto = tok.trim_lws();
        guard proto.len > 0 else { continue; }
        guard proto.len <= 255 else { return false; }
        guard wire_buf.try_push(proto.len as u8) && wire_buf.try_append(proto) else {
            return false;
        }
    }
    guard wire_buf.len > 0 else { return false; }
    return out_wire.try_set(wire_buf[..]);
}

// Parses leaf and up to 3 intermediate `"CERTIFICATE"` PEM blocks for client mTLS.
//
// Example:
//   raw_pem = "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n"
//   returns: ok = true, leaf_der populated with leaf X.509 DER
fn parse_client_pem_cert_chain(
    raw_pem:     const u8[:],
    leaf_der:    u8[..4096]&,
    chain_ders:  u8[..4096][..3]&,
    parsed_leaf: tls::ParsedCert&,
) -> bool {
    var idx:       i64             = 0;
    var label:     u8[..64]        = [];
    var der:       u8[..4096]      = [];
    var tmp_leaf:  u8[..4096]      = [];
    var tmp_chain: u8[..4096][..3] = [];
    var tmp_parsed = tls::ParsedCert { .. };
    guard tls::pem_next_block(raw_pem, idx, label, der) && label[..] == "CERTIFICATE" else {
        return false;
    }
    guard tls::parse_x509_certificate(der[..], tmp_parsed) && tmp_leaf.try_set(der[..]) else {
        return false;
    }
    while idx < raw_pem.len {
        if core::find(raw_pem[idx..], "-----BEGIN ") < 0 { break; }
        guard tls::pem_next_block(raw_pem, idx, label, der) else { return false; }
        guard label[..] == "CERTIFICATE" else { continue; }
        var chain_parsed = tls::ParsedCert { .. };
        guard tls::parse_x509_certificate(der[..], chain_parsed) else { return false; }
        guard tmp_chain.try_push(copy(der)) else { return false; }
    }
    guard leaf_der.try_set(tmp_leaf[..]) else { return false; }
    chain_ders = copy(tmp_chain);
    parsed_leaf = tmp_parsed;
    return true;
}

fn load_client_mtls_pem_files(
    cert_file: const u8[:],
    key_file:  const u8[:],
    cfg:       tls::ClientHandshakeConfig&,
) -> bool {
    guard cert_file.len > 0 && key_file.len > 0 else { return false; }
    var raw_cert: u8[>..] = [];
    var raw_key:  u8[>..] = [];
    defer core::secure_zeroize_slice(raw_cert[..]);
    defer core::secure_zeroize_slice(raw_key[..]);
    guard read_file(cert_file, raw_cert) && raw_cert.len > 0 && raw_cert.len <= 131072 else {
        return false;
    }
    guard read_file(key_file, raw_key) && raw_key.len > 0 && raw_key.len <= 65536 else {
        return false;
    }
    var leaf_der:   u8[..4096]      = [];
    var chain_ders: u8[..4096][..3] = [];
    var parsed_leaf = tls::ParsedCert { .. };
    guard parse_client_pem_cert_chain(raw_cert[..], leaf_der, chain_ders, parsed_leaf) else {
        return false;
    }
    var priv_seed: u8[32] = [0; 32];
    defer core::secure_zeroize_32(priv_seed);
    let key_kind, ok_key = tls::parse_private_key_pem(raw_key[..], priv_seed);
    guard ok_key else { return false; }
    let spki_oid = tls::span_slice(leaf_der[..], parsed_leaf.spki_alg_oid);
    let valid_alg = (key_kind == tls::PrivateKeyKind.Ed25519 && spki_oid == rfc::OID_ED25519[..]) ||
        (key_kind == tls::PrivateKeyKind.EcdsaP256 && spki_oid == rfc::OID_SECP256R1[..]);
    guard valid_alg else { return false; }
    guard cfg.client_cert_der.try_set(leaf_der[..]) else { return false; }
    cfg.client_chain_der = copy(chain_ders);
    cfg.client_priv_seed = priv_seed;
    return true;
}

fn load_crl_der_file(path: const u8[:], out_crl_der: u8[..4096]&) -> bool {
    guard path.len > 0 && path.len <= 4096 else { return false; }
    var raw: u8[>..] = [];
    defer core::secure_zeroize_slice(raw[..]);
    guard read_file(path, raw) && raw.len > 0 && raw.len <= 16384 else { return false; }
    var der_buf: u8[..4096] = [];
    if core::find(raw[..], "-----BEGIN ") >= 0 {
        var idx:   i64      = 0;
        var label: u8[..64] = [];
        guard tls::pem_next_block(raw[..], idx, label, der_buf) && label[..] == "X509 CRL" else {
            return false;
        }
    } else {
        guard der_buf.try_set(raw[..]) else { return false; }
    }
    var parsed = tls::ParsedCrl { .. };
    guard tls::parse_x509_crl(der_buf[..], parsed) else { return false; }
    return out_crl_der.try_set(der_buf[..]);
}

fn lookup_resolve_override(
    session:  const client::Session&,
    host_str: const u8[:],
    port_num: u16,
    out_ip:   u8[..64]&,
) -> bool {
    let clean_host = host_str.trim_lws().trim_end_byte('.');
    guard clean_host.len > 0 else { return false; }
    var wild_idx: i64 = -1;
    for &ov, i in session.resolve_overrides {
        guard ov.host[..].eq_ascii_fold(clean_host) else { continue; }
        if ov.port == port_num {
            return out_ip.try_set(ov.ip[..]);
        }
        if ov.port == 0 && wild_idx < 0 {
            wild_idx = i;
        }
    }
    if wild_idx >= 0 {
        return out_ip.try_set(session.resolve_overrides[wild_idx].ip[..]);
    }
    return false;
}

// Strips ASCII whitespace, IPv6 brackets, optional `:port`, and trailing `.` from a host token.
//
// Example:
//   raw = "[::1]:8443" -> "::1"
//   raw = "Api.Example.COM.:443" -> "Api.Example.COM"
fn normalize_no_proxy_host(raw: const u8[:]) -> const u8[:] {
    var s = raw.trim_ascii_space();
    guard s.len > 0 else { return ""; }
    if s[0] == '[' {
        let rb = s.index_of_byte(']');
        if rb > 1 {
            s = s[1..rb];
        }
    } else {
        let c1 = s.index_of_byte(':');
        if c1 > 0 && c1 == s.last_index_of_byte(':') {
            s = s[..c1];
        }
    }
    return s.trim_end_byte('.');
}

fn match_no_proxy_domain_suffix(pat: const u8[:], norm_host: const u8[:]) -> bool {
    let dot_sfx = if core::starts_with(pat, "*.") { pat[1..] } else { pat };
    let clean_sfx = dot_sfx.trim_end_byte('.');
    guard clean_sfx.len > 1 else { return false; }
    return norm_host.ends_with_fold(clean_sfx) || norm_host.eq_ascii_fold(clean_sfx[1..]);
}

fn match_no_proxy_pattern(pattern: const u8[:], norm_host: const u8[:]) -> bool {
    let pat = pattern.trim_ascii_space();
    guard pat.len > 0 && norm_host.len > 0 else { return false; }
    if pat == "*" { return true; }
    if pat.eq_ascii_fold("localhost") { return security::is_localhost_name(norm_host); }
    if pat.contains_byte('/') {
        let cidr, ok_cidr = core::parse_cidr(pat);
        let hip, ok_hip = core::parse_ip_addr(norm_host);
        return ok_cidr && ok_hip && core::cidr_contains_ip(cidr, hip);
    }
    if core::starts_with(pat, ".") || core::starts_with(pat, "*.") {
        return match_no_proxy_domain_suffix(pat, norm_host);
    }
    let norm_pat = normalize_no_proxy_host(pat);
    guard norm_pat.len > 0 else { return false; }
    let pip, ok_pip = core::parse_ip_addr(norm_pat);
    if ok_pip {
        let hip, ok_hip = core::parse_ip_addr(norm_host);
        return ok_hip && core::ip_addr_equals(pip, hip);
    }
    return norm_host.eq_ascii_fold(norm_pat);
}

fn matches_env_no_proxy(norm_host: const u8[:]) -> bool {
    var raw: u8[>..] = [];
    if !env("NO_PROXY", raw) || raw.len == 0 {
        raw.clear();
        guard env("no_proxy", raw) && raw.len > 0 else { return false; }
    }
    var tokenizer = core::make_byte_tokenizer(raw[..], ',');
    while true {
        let tok, has_tok = core::token_next(tokenizer);
        guard has_tok else { break; }
        if match_no_proxy_pattern(tok, norm_host) {
            return true;
        }
    }
    return false;
}

fn read_first_non_empty_env(names: const u8[:][:], out: u8[..256]&) -> bool {
    var raw: u8[>..] = [];
    for name in names {
        raw.clear();
        guard env(name, raw) else { continue; }
        let trimmed = raw[..].trim_ascii_space();
        guard trimmed.len > 0 else { continue; }
        return out.try_set(trimmed);
    }
    return false;
}

fn resolve_env_proxy_url(is_https: bool, out_url: u8[..256]&) -> bool {
    let https_vars: const u8[:][4] = ["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"];
    let http_vars:  const u8[:][4] = ["HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"];
    if is_https {
        return read_first_non_empty_env(https_vars[..], out_url);
    }
    return read_first_non_empty_env(http_vars[..], out_url);
}

fn build_proxy_chain_from_url(proxy_url: const u8[:]) -> net::ProxyChain, bool {
    guard proxy_url.len > 0 else { return net::new_direct_proxy_chain(), true; }
    let p_url = core::new_url(proxy_url);
    guard p_url.valid && p_url.hostname().len > 0 else { return net::new_direct_proxy_chain(), false; }
    let sc = p_url.scheme();
    var p_scheme = net::ProxyScheme.Http;
    if sc == "https" {
        p_scheme = net::ProxyScheme.Https;
    } else if sc == "socks5h" {
        p_scheme = net::ProxyScheme.Socks5h;
    } else if sc == "socks5" {
        p_scheme = net::ProxyScheme.Socks5;
    } else if sc != "http" {
        return net::new_direct_proxy_chain(), false;
    }
    let raw_port = p_url.effective_port();
    let p_port: u16 = if raw_port > 0 {
        raw_port as u16
    } else if p_scheme == net::ProxyScheme.Socks5 || p_scheme == net::ProxyScheme.Socks5h {
        1080
    } else if p_scheme == net::ProxyScheme.Https {
        443
    } else {
        80
    };
    let ps = net::new_proxy_server(p_scheme, p_url.hostname(), p_port);
    guard !ps.overflowed else { return net::new_direct_proxy_chain(), false; }
    return net::new_single_proxy_chain(ps), true;
}

fn resolve_effective_hop_proxy(
    session:       const client::Session&,
    host_str:      const u8[:],
    is_https:      bool,
    out_proxy_url: u8[..256]&,
) -> net::ProxyChain, bool {
    out_proxy_url.clear();
    if client::is_no_proxy_host(session, host_str) {
        return net::new_direct_proxy_chain(), true;
    }
    if session.proxy_url.len > 0 {
        let _ = out_proxy_url.try_set(session.proxy_url[..]);
        return client::resolve_hop_proxy_chain(session);
    }
    if session.use_env_proxy && resolve_env_proxy_url(is_https, out_proxy_url) {
        return build_proxy_chain_from_url(out_proxy_url[..]);
    }
    return net::new_direct_proxy_chain(), true;
}
