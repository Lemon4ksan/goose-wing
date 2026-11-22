// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal L7 client stage evaluation bricks (cache, cookies, CORS/CORP, signatures, Alt-Svc, decompress, auth).
namespace client_internal;

import std;
import core;
import rfc.http;
import cookie.constants;
import cookie.canonical;
import cookie.psl;
import cookie.parser;
import cookie.policy;
import cookie.engine;
import http.request;
import http.response;
import http.headers;
import http.cache.validators;
import http.cache.engine;
import http.altsvc;
import http.compression_dict;
import http.digest_fields;
import http.early_hints;
import http.hsts;
import http.signatures;
import security.cors;
import security.cross_origin_isolation;
import security.ssrf;
import wire.pipeline;
import client.redirect;
import client.interceptor;
import client.client;
import .ssrf;
import .hop_context_internal;
import .hop_auth_internal;

fn apply_cache_revalidation_headers(cond_map: const http::HeaderMap&, headers: http::HeaderMap&) {
    for &c_entry in cond_map.entries {
        let c_name = http::entry_name(cond_map, c_entry);
        let c_val = http::entry_value(cond_map, c_entry);
        if !http::has_header(headers, c_name) {
            http::set_header(headers, c_name, c_val);
        }
    }
}

// Performs RFC 9111 HTTP cache lookup and conditional header injection via UFCS on `cache: Cache&`.
// Returns `(StageVerdict.ShortCircuit, -1)` on fresh cache hit, `(StageVerdict.Abort, -1)` on
// `only-if-cached` miss, or `(StageVerdict.Continue, reval_idx)`.
fn stage_cache_lookup<Cache>(
    req:             const http::Request&,
    eff_url:         const u8[:],
    now_sec:         i64,
    headers:         http::HeaderMap&,
    out_resp:        http::Response&,
    cache:           Cache&,
    enable_cache:    bool,
    method_override: const u8[:] = "",
) -> wire::StageVerdict, i64 {
    guard enable_cache else { return wire::StageVerdict.Continue, -1; }
    var lookup_req = copy(req);
    let _ = lookup_req.url.try_set(eff_url);
    if method_override.len > 0 {
        let _ = lookup_req.method.try_set(method_override);
    }
    lookup_req.headers = copy(headers);
    let lookup_dec = cache.lookup(lookup_req, now_sec);
    if lookup_dec.kind == http::LookupResultKind.Hit {
        out_resp = copy(lookup_dec.cached_response);
        for &e in out_resp.headers.entries {
            http::update_response_presence(out_resp, http::entry_name(out_resp.headers, e));
        }
        http::copy_headers(headers, out_resp.sent_headers);
        return wire::StageVerdict.ShortCircuit { status_code: out_resp.status_code as u16 }, -1;
    }
    if lookup_dec.kind == http::LookupResultKind.Fail504 {
        out_resp = http::Response {
            status_code: rfc::STATUS_GATEWAY_TIMEOUT,
            ..
        };
        let _ = out_resp.effective_url.try_set(eff_url);
        return wire::StageVerdict.Abort { err_code: rfc::STATUS_GATEWAY_TIMEOUT }, -1;
    }
    var reval_idx: i64 = -1;
    if lookup_dec.kind == http::LookupResultKind.Revalidate {
        reval_idx = lookup_dec.entry_idx;
        if reval_idx >= 0 && reval_idx < cache.entries.len {
            let cond_map = cache.entries[reval_idx].build_revalidation_headers();
            apply_cache_revalidation_headers(cond_map, headers);
        }
    }
    return wire::StageVerdict.Continue, reval_idx;
}

// Loads matching cookies from `jar: Jar&` into `headers` via UFCS `jar.encode_cookie_header_to_map(...)`.
fn stage_cookie_load<Jar>(
    headers:       http::HeaderMap&,
    current_url:   const core::Url&,
    samesite_eval: const cookie::SameSiteCookieContext&,
    is_main_frame: bool,
    part_key:      const u8[:],
    safe_method:   bool,
    now_us:        i64,
    jar:           Jar&,
    enable_jar:    bool,
) -> wire::StageVerdict {
    guard enable_jar else { return wire::StageVerdict.Continue; }
    let is_sec_channel = current_url.is_secure_scheme() ||
        cookie::is_trustworthy_non_crypto_host(current_url.hostname());
    let is_top_nav = is_main_frame && samesite_eval.context_type != cookie::SameSiteContextType.CrossSite;
    let _ = jar.encode_cookie_header_to_map(
        current_url.hostname(),
        current_url.pathname(),
        current_url.scheme(),
        current_url.effective_port(),
        cookie::SourceOptions { is_http_api: true, url_is_secure: is_sec_channel },
        part_key,
        now_us,
        cookie::AccessOptions {
            is_same_site:            samesite_eval.context_type == cookie::SameSiteContextType.SameSiteStrict,
            is_top_level_navigation: is_top_nav,
            is_safe_method:          safe_method,
            had_cross_site_hop:      samesite_eval.had_cross_site_hop,
        },
        headers,
    );
    return wire::StageVerdict.Continue;
}

// Updates RFC 9111 HTTP cache and handles 304 Not Modified freshening via UFCS `cache.on_response(...)`.
fn stage_cache_store<Cache>(
    req:            const http::Request&,
    headers:        const http::HeaderMap&,
    effective_url:  const u8[:],
    method:         const u8[:],
    out_resp:       http::Response&,
    cache_ts:       http::CacheTimestamps&,
    revalidate_idx: i64,
    cache:          Cache&,
    enable_cache:   bool,
) -> wire::StageVerdict {
    guard enable_cache else { return wire::StageVerdict.Continue; }
    cache_ts.response_sec = cache_ts.now_sec;
    var hop_req = copy(req);
    let _ = hop_req.url.try_set(effective_url);
    let _ = hop_req.method.try_set(method);
    hop_req.headers = copy(headers);
    let resp_dec = cache.on_response(hop_req, out_resp, cache_ts, revalidate_idx);
    if resp_dec.kind == http::ResponseDecisionKind.FreshenAndReturn {
        out_resp = copy(resp_dec.response);
        for &e in out_resp.headers.entries {
            http::update_response_presence(out_resp, http::entry_name(out_resp.headers, e));
        }
    }
    return wire::StageVerdict.Continue;
}

fn check_client_cors_response(
    ctx:        const RequestExecutionContext&,
    resp:       const http::Response&,
    is_tainted: bool,
) -> http::Error {
    guard ctx.cors_mode else { return http::Error { .. }; }
    let raw_orig = http::find_header(ctx.headers, "Origin");
    let req_orig = if raw_orig.len > 0 { raw_orig } else if is_tainted { "null" } else { "" };
    guard req_orig.len > 0 else { return http::Error { .. }; }
    let include_creds = http::find_header(ctx.headers, "Cookie").len > 0 ||
        http::find_header(ctx.headers, "Authorization").len > 0;
    let cors_opts = security::ClientCorsVerifyOptions {
        tainted_origin:      is_tainted,
        include_credentials: include_creds,
    };
    if !security::verify_client_cors_response(resp.headers, req_orig, cors_opts) {
        return http::make_error(rfc::STATUS_FORBIDDEN, "cors", "ERR_FAILED: CORS response check failed");
    }
    return http::Error { .. };
}

// Validates client-side CORS (`Access-Control-Allow-Origin`) and CORP (`Cross-Origin-Resource-Policy`)
// on cross-origin responses when `ctx.cors_mode` or `Cross-Origin-Resource-Policy` is present.
fn validate_cors_and_corp_response(
    ctx:         const RequestExecutionContext&,
    current_url: const core::Url&,
    resp:        const http::Response&,
) -> http::Error {
    guard ctx.has_initiator else { return http::Error { .. }; }
    let is_opaque = ctx.initiator.kind == core::OriginKind.Opaque;
    let is_tainted = ctx.tainted_origin || is_opaque;
    let target_orig = core::origin_from_url(current_url);
    var init_orig_str:   u8[..256] = [];
    var target_orig_str: u8[..256] = [];
    core::serialize_origin(ctx.initiator, init_orig_str);
    core::serialize_origin(target_orig, target_orig_str);
    guard !init_orig_str[..].eq_ascii_fold(target_orig_str[..]) || is_tainted else {
        return http::Error { .. };
    }

    let corp_hdr = http::header(resp, "Cross-Origin-Resource-Policy");
    if corp_hdr.len > 0 {
        var iso_ctx = security::CrossOriginIsolationContext { .. };
        let _ = iso_ctx.document_origin.try_set(init_orig_str[..]);
        if !security::is_subresource_allowed(iso_ctx, target_orig_str[..], corp_hdr) {
            return http::make_error(rfc::STATUS_FORBIDDEN, "corp", "ERR_BLOCKED_BY_RESPONSE: CORP violation");
        }
    }
    return check_client_cors_response(ctx, resp, is_tainted);
}

fn verify_response_signature(
    session:     const client::Client&,
    req:         const http::Request&,
    current_url: const core::Url&,
    method:      const u8[:],
    headers:     const http::HeaderMap&,
    resp:        const http::Response&,
) -> bool {
    guard session.sig_public_key.len == 32 else { return true; }
    let has_sig = http::has_header(resp, rfc::HEADER_SIGNATURE) && http::has_header(resp, rfc::HEADER_SIGNATURE_INPUT);
    guard has_sig else { return false; }
    var hop_req = copy(req);
    let _ = hop_req.method.try_set(method);
    let _ = hop_req.url.try_set(current_url.href[..]);
    hop_req.headers = copy(headers);
    return http::verify_response_ed25519(resp, hop_req, session.sig_key_id[..], session.sig_public_key[..]);
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
        let early_hints_status: u16 = 103;
        let eh, ok_eh = http::parse_early_hints(early_hints_status, link_val);
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
        ingest_compression_dict_header(dict_cache, origin_buf, curr_path, now_sec, mut_resp);
    }
    return wire::StageVerdict.Continue;
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

fn stage_client_auth_challenge(
    session:       client::Client&,
    ctx:           RequestExecutionContext&,
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
    prepare_auth_retry_hop(session, ctx, current_url, samesite_eval, safe_method, resp, auth_header_val[..]);
    return wire::StageVerdict.RetryAuth;
}

fn stage_client_redirect(
    session:     client::Session&,
    ctx:         RequestExecutionContext&,
    resp:        http::Response&,
    current_url: const core::Url&,
    out_err:     http::Error&,
) -> wire::StageVerdict {
    let cors_err = validate_cors_and_corp_response(ctx, current_url, resp);
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
    ctx:         const RequestExecutionContext&,
    out_resp:    http::Response&,
    out_err:     http::Error&,
) -> wire::StageVerdict {
    if !verify_response_signature(
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
