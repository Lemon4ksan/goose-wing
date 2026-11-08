// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Tier 2 Composable L7 Client Stage Bricks, UFCS Subsystem Hooks, and Programmable Pipeline Conveyor.
namespace wing;

import std;
import core from "../..";
import cookie.constants;
import cookie.canonical;
import cookie.policy;
import cookie.engine;
import client.profile;
import client.request;
import client.response;
import client.redirect;
import client.interceptor;
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
import auth.digest;
import auth.dpop;
import security.cors;
import security.cross_origin_isolation;
import security.privacypass;
import client.replay_guard;
import client.session.ssrf;
import client.session.mock;
import client.client;
import client.session.cookie_bridge;
import client.session.exec;
import wire.pipeline;

// ---- Narrow-Input Autonomous Client Stage Bricks ----------------------------

// Upgrades an HTTP URL buffer in-place to HTTPS when the target host is in `hsts` (RFC 6797 §8.3).
fn stage_client_url_hsts(
    url_buf:     u8[..2048]&,
    hsts:        const HstsCache&,
    enable_hsts: bool,
    now_sec:     i64,
) -> wire::StageVerdict {
    if enable_hsts {
        var upgraded_url: u8[..2048] = [];
        if hsts_upgrade_url(hsts, url_buf[..], now_sec, upgraded_url) {
            let _ = url_buf.try_set(upgraded_url[..]);
        }
    }
    return wire::StageVerdict.Continue;
}

// Upgrades a parsed `core::Url` in-place to HTTPS when the target host is in `hsts` (RFC 6797 §8.3).
fn stage_client_url_hsts(
    current_url: core::Url&,
    hsts:        const HstsCache&,
    enable_hsts: bool,
    now_sec:     i64,
) -> wire::StageVerdict {
    if enable_hsts && !current_url.is_secure_scheme() {
        var upgraded_url: u8[..2048] = [];
        if hsts_upgrade_url(hsts, current_url.href[..], now_sec, upgraded_url) {
            let parsed_upgraded, _ = core::parse_url(upgraded_url[..]);
            if parsed_upgraded.valid {
                current_url = parsed_upgraded;
            }
        }
    }
    return wire::StageVerdict.Continue;
}

// Validates `current_url` against `https_only` and `SsrfGuardPolicy`.
// Returns `StageVerdict.Abort` with HTTP status code on policy violation.
fn stage_client_ssrf_guard(
    current_url: const core::Url&,
    https_only:  bool,
    policy:      const SsrfGuardPolicy&,
) -> wire::StageVerdict {
    if https_only && current_url.scheme() != "https" {
        return wire::StageVerdict.Abort { err_code: rfc::STATUS_BAD_REQUEST };
    }
    let ssrf_err = validate_url_against_ssrf(current_url, policy);
    if ssrf_err != RedirectError.None {
        return wire::StageVerdict.Abort { err_code: rfc::STATUS_FORBIDDEN };
    }
    return wire::StageVerdict.Continue;
}

// Performs RFC 9111 HTTP cache lookup and conditional header injection via UFCS on `cache: Cache&`.
// Returns `StageVerdict.ShortCircuit { status_code: 200 }` on fresh cache hit,
// `StageVerdict.Abort { err_code: 504 }` on `only-if-cached` miss, or `StageVerdict.Continue`.
fn stage_client_cache_lookup<Cache>(
    req:             const Request&,
    eff_url:         const u8[:],
    now_ts:          core::Time,
    headers:         HeaderMap&,
    out_resp:        Response&,
    out_reval_idx:   i64&,
    cache:           Cache&,
    enable_cache:    bool,
    method_override: const u8[:] = "",
) -> wire::StageVerdict {
    guard enable_cache else { return wire::StageVerdict.Continue; }
    var lookup_req = copy(req);
    let _ = lookup_req.url.try_set(eff_url);
    if method_override.len > 0 {
        let _ = lookup_req.method.try_set(method_override);
    }
    lookup_req.headers = copy(headers);
    let lookup_dec = cache.lookup(lookup_req, now_ts);
    if lookup_dec.kind == LookupResultKind.Hit {
        out_resp = copy(lookup_dec.cached_response);
        for &e in out_resp.headers.entries {
            update_response_presence(out_resp, entry_name(out_resp.headers, e));
        }
        copy_headers(headers, out_resp.sent_headers);
        return wire::StageVerdict.ShortCircuit { status_code: out_resp.status_code as u16 };
    }
    if lookup_dec.kind == LookupResultKind.Fail504 {
        out_resp = Response {
            status_code: rfc::STATUS_GATEWAY_TIMEOUT,
            ..
        };
        let _ = out_resp.effective_url.try_set(eff_url);
        return wire::StageVerdict.Abort { err_code: rfc::STATUS_GATEWAY_TIMEOUT };
    }
    if lookup_dec.kind == LookupResultKind.Revalidate {
        out_reval_idx = lookup_dec.entry_idx;
        if out_reval_idx >= 0 && out_reval_idx < cache.entries.len {
            let cond_map = cache.entries[out_reval_idx].build_revalidation_headers();
            apply_cache_revalidation_headers(cond_map, headers);
        }
    }
    return wire::StageVerdict.Continue;
}

fn apply_cache_revalidation_headers(cond_map: const HeaderMap&, headers: HeaderMap&) {
    for &c_entry in cond_map.entries {
        let c_name = entry_name(cond_map, c_entry);
        let c_val = entry_value(cond_map, c_entry);
        if !has_header(headers, c_name) {
            set_header(headers, c_name, c_val);
        }
    }
}

// Loads matching cookies from `jar: Jar&` into `headers` via UFCS `jar.encode_cookie_header_to_map(...)`.
fn stage_client_cookie_load<Jar>(
    headers:       HeaderMap&,
    current_url:   const core::Url&,
    samesite_eval: const SameSiteCookieContext&,
    is_main_frame: bool,
    part_key:      const u8[:],
    safe_method:   bool,
    now_us:        i64,
    jar:           Jar&,
    enable_jar:    bool,
) -> wire::StageVerdict {
    guard enable_jar else { return wire::StageVerdict.Continue; }
    let is_sec_channel = current_url.is_secure_scheme() || is_trustworthy_non_crypto_host(current_url.hostname());
    let is_top_nav = is_main_frame && samesite_eval.context_type != SameSiteContextType.CrossSite;
    let _ = jar.encode_cookie_header_to_map(
        current_url.hostname(),
        current_url.pathname(),
        current_url.scheme(),
        current_url.effective_port(),
        CookieSourceOptions { is_http_api: true, url_is_secure: is_sec_channel },
        part_key,
        now_us,
        CookieAccessOptions {
            is_same_site:            samesite_eval.context_type == SameSiteContextType.SameSiteStrict,
            is_top_level_navigation: is_top_nav,
            is_safe_method:          safe_method,
            had_cross_site_hop:      samesite_eval.had_cross_site_hop,
        },
        headers,
    );
    return wire::StageVerdict.Continue;
}

fn find_best_matching_dict_idx(
    dict_cache: const DictionaryCache&,
    origin_buf: const u8[:],
    curr_path:  const u8[:],
    now_sec:    i64,
) -> i64 {
    var best_idx:  i64 = -1;
    var best_len:  i64 = -1;
    var best_time: i64 = -1;
    for &entry, idx in dict_cache.entries {
        if dict_entry_matches_request(entry, origin_buf, curr_path, now_sec) {
            let pat_len = entry.match_pattern.len;
            if pat_len > best_len || (pat_len == best_len && entry.inserted_at_sec >= best_time) {
                best_idx = idx;
                best_len = pat_len;
                best_time = entry.inserted_at_sec;
            }
        }
    }
    return best_idx;
}

// Negotiates compression dictionary transport (`Available-Dictionary` and `Dictionary-ID`).
fn stage_client_dict_negotiate(
    headers:     HeaderMap&,
    dict_cache:  DictionaryCache&,
    enable_dict: bool,
    origin_buf:  const u8[:],
    curr_path:   const u8[:],
    is_https:    bool,
    now_sec:     i64,
) -> wire::StageVerdict {
    remove_header_by_name(headers, "Available-Dictionary");
    remove_header_by_name(headers, "Dictionary-ID");
    guard enable_dict && is_https else { return wire::StageVerdict.Continue; }
    let best_idx = find_best_matching_dict_idx(dict_cache, origin_buf, curr_path, now_sec);
    if best_idx >= 0 && best_idx < dict_cache.entries.len {
        let entry = dict_cache.entries[best_idx];
        append_available_dict_header(headers, entry.sha256_base64[..]);
        if entry.id.len > 0 {
            var id_hdr: u8[..128] = [];
            format_dictionary_id_header(id_hdr, entry.id[..]);
            set_header(headers, "Dictionary-ID", id_hdr[..]);
        }
    }
    return wire::StageVerdict.Continue;
}

// Applies pre-hop network interceptor request hooks (Bearer/Basic/API-Key/Header injection).
fn stage_client_auth_header(
    pipeline:       InterceptorPipeline&,
    headers:        HeaderMap&,
    href:           const u8[:],
    method:         const u8[:],
    body_len:       i64,
    redirect_count: i64,
) -> wire::StageVerdict {
    apply_network_interceptors_request(pipeline, headers, href, method, body_len, redirect_count);
    return wire::StageVerdict.Continue;
}

// Ingests `Set-Cookie` headers from `resp_headers` into `jar: Jar&` via UFCS `jar.set_cookie_header(...)`.
fn stage_client_cookie_store<Jar>(
    resp_headers:  const HeaderMap&,
    current_url:   const core::Url&,
    samesite_eval: const SameSiteCookieContext&,
    is_main_frame: bool,
    part_key:      const u8[:],
    now_us:        i64,
    jar:           Jar&,
    enable_jar:    bool,
) -> wire::StageVerdict {
    guard enable_jar else { return wire::StageVerdict.Continue; }
    for i in resp_headers.entries.len {
        let e = resp_headers.entries[i];
        let ename = entry_name(resp_headers, e);
        guard ename.eq_ascii_fold("set-cookie") else { continue; }
        let set_cookie_str = entry_value(resp_headers, e);
        var def_path: u8[..256] = [];
        compute_default_cookie_path(current_url.pathname(), def_path);
        var parsed_cookie, _, cookie_ok = parse_canonical_set_cookie(
            set_cookie_str,
            current_url.hostname(),
            def_path[..],
            now_us,
        );
        guard cookie_ok else { continue; }
        let is_sec_channel = current_url.is_secure_scheme() ||
            is_trustworthy_non_crypto_host(current_url.hostname());
        let opts = CookieInclusionOptions {
            is_main_frame:     is_main_frame,
            is_secure_channel: is_sec_channel,
        };
        let can_write, _ = can_set_canonical_cookie_for_context(
            parsed_cookie,
            samesite_eval,
            opts,
        );
        guard can_write else { continue; }
        jar.set_cookie_header(current_url.href[..], set_cookie_str, now_us, part_key);
    }
    return wire::StageVerdict.Continue;
}

// Ingests `Alt-Svc`, `Strict-Transport-Security`, `Use-As-Dictionary`, and `Link` Early Hints response headers.
fn stage_client_alt_svc(
    resp:          Response&,
    current_url:   const core::Url&,
    is_https:      bool,
    origin_buf:    const u8[:],
    curr_path:     const u8[:],
    now_sec:       i64,
    altsvc:        AltSvcCache&,
    enable_altsvc: bool,
    hsts:          HstsCache&,
    enable_hsts:   bool,
    dict_cache:    DictionaryCache&,
    enable_dict:   bool,
) -> wire::StageVerdict {
    let link_val = header(resp, "Link");
    if link_val.len > 0 {
        let eh, ok_eh = parse_early_hints(rfc::STATUS_EARLY_HINTS as! u16, link_val);
        if ok_eh {
            resp.early_hints = eh;
        }
    }
    if enable_altsvc && is_https {
        let alt_svc_val = header(resp, "Alt-Svc");
        if alt_svc_val.len > 0 {
            update(altsvc, origin_buf, alt_svc_val, now_sec);
        }
    }
    if enable_hsts && is_https {
        let hsts_val = header(resp, "Strict-Transport-Security");
        if hsts_val.len > 0 {
            hsts_cache_update(hsts, current_url.hostname(), hsts_val, now_sec);
        }
    }
    if enable_dict && is_https {
        var mut_resp = copy(resp);
        ingest_compression_dict_header(dict_cache, origin_buf, curr_path, now_sec, mut_resp);
    }
    return wire::StageVerdict.Continue;
}

// Decodes `Content-Encoding` (`gzip`, `br`, `zstd`, `dcb`, `dcz`) on `resp` using `dict_cache`
// and verifies RFC 9530 `Content-Digest` / `Repr-Digest` integrity when enabled.
fn stage_client_decompress(
    resp:        Response&,
    dict_cache:  const DictionaryCache&,
    strict_mode: bool = false,
) -> wire::StageVerdict {
    let has_cd = header(resp, rfc::HEADER_CONTENT_DIGEST).len > 0;
    let cd_ok_pre = if strict_mode && has_cd { verify_response_content_digest(resp) } else { true };

    let enc = header(resp, "Content-Encoding");
    if enc.len > 0 {
        let ok_dec = decode_body_with_dictionary(resp, dict_cache);
        if !ok_dec && strict_mode {
            return wire::StageVerdict.Abort { err_code: rfc::STATUS_BAD_GATEWAY };
        }
    }

    if strict_mode && has_cd && !cd_ok_pre {
        if !verify_response_content_digest(resp) {
            return wire::StageVerdict.Abort { err_code: rfc::STATUS_BAD_GATEWAY };
        }
    }
    if strict_mode && header(resp, rfc::HEADER_REPR_DIGEST).len > 0 {
        if !verify_response_repr_digest(resp) {
            return wire::StageVerdict.Abort { err_code: rfc::STATUS_BAD_GATEWAY };
        }
    }
    return wire::StageVerdict.Continue;
}

// Updates RFC 9111 HTTP cache and handles 304 Not Modified freshening via UFCS `cache.on_response(...)`.
fn stage_client_cache_store<Cache>(
    req:            const Request&,
    headers:        const HeaderMap&,
    current_url:    const core::Url&,
    method:         const u8[:],
    out_resp:       Response&,
    cache_ts:       CacheTimestamps&,
    revalidate_idx: i64,
    cache:          Cache&,
    enable_cache:   bool,
) -> wire::StageVerdict {
    guard enable_cache else { return wire::StageVerdict.Continue; }
    cache_ts.response_time = cache_ts.now;
    var hop_req = copy(req);
    let _ = hop_req.url.try_set(current_url.href[..]);
    let _ = hop_req.method.try_set(method);
    hop_req.headers = copy(headers);
    let resp_dec = cache.on_response(hop_req, out_resp, cache_ts, revalidate_idx);
    if resp_dec.kind == ResponseDecisionKind.FreshenAndReturn {
        out_resp = copy(resp_dec.response);
        for &e in out_resp.headers.entries {
            update_response_presence(out_resp, entry_name(out_resp.headers, e));
        }
    }
    return wire::StageVerdict.Continue;
}

fn try_handle_early_data_or_dpop_challenge(
    session:       Client&,
    ctx:           RequestExecutionContext&,
    current_url:   const core::Url&,
    samesite_eval: const SameSiteCookieContext&,
    safe_method:   bool,
    resp:          const Response&,
) -> bool {
    guard !ctx.auth_retried else { return false; }
    let was_early = find_header(ctx.headers, "Early-Data").len > 0;
    let ed_dec = evaluate_early_data_response(resp.status_code as u16, was_early);
    if ed_dec == EarlyDataDecision.RetryOn1Rtt {
        ctx.auth_retried = true;
        remove_header_by_name(ctx.headers, "Early-Data");
        if ctx.body.len > 0 {
            ctx.body.clear();
            ctx.body.append(ctx.rewind_buf[..]);
        }
        ctx.body_consumed = false;
        return true;
    }

    let is_dpop_status = resp.status_code == rfc::STATUS_UNAUTHORIZED || resp.status_code == rfc::STATUS_BAD_REQUEST;
    guard session.has_dpop_key && is_dpop_status else { return false; }
    guard extract_dpop_nonce(resp.headers, session.last_dpop_nonce) else { return false; }
    let now_sec = div_euclid(session.virtual_clock_us, 1000000);
    var proof: u8[..2048] = [];
    let ok_proof = create_dpop_proof(
        session.dpop_private_key[..],
        ctx.current_method[..],
        current_url.href[..],
        session.dpop_access_token[..],
        session.last_dpop_nonce[..],
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
        ingest_hop_response_cookies(session, ctx, current_url, samesite_eval, resp.headers);
        remove_header_by_name(ctx.headers, "Cookie");
        prepare_hop_cookie_header(session, ctx, current_url, samesite_eval, safe_method);
    }
    set_header(ctx.headers, rfc::DPOP_HEADER, proof[..], true);
    return true;
}

// Evaluates 401 WWW-Authenticate challenges (RFC 7616 Digest, RFC 7617 Basic, RFC 9577 PrivateToken),
// RFC 9449 DPoP-Nonce challenges, and RFC 8470 425 Too Early recovery.
// When challenge credentials can be synthesized, prepares `ctx` for an auth retry hop
// and returns `StageVerdict.RetryAuth`.
fn stage_client_auth_challenge(
    session:       Client&,
    ctx:           RequestExecutionContext&,
    current_url:   const core::Url&,
    samesite_eval: const SameSiteCookieContext&,
    safe_method:   bool,
    resp:          Response&,
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

// Validates client-side CORS (`Access-Control-Allow-Origin`) and CORP (`Cross-Origin-Resource-Policy`)
// on cross-origin responses when `ctx.cors_mode` or `Cross-Origin-Resource-Policy` is present.
fn validate_client_cors_and_corp_response(
    ctx:         const RequestExecutionContext&,
    current_url: const core::Url&,
    resp:        const Response&,
    out_err:     Error&,
) -> bool {
    guard ctx.has_initiator && ctx.initiator.kind != core::OriginKind.Opaque else { return true; }
    let target_orig = core::origin_from_url(current_url);
    var init_orig_str:   u8[..256] = [];
    var target_orig_str: u8[..256] = [];
    core::serialize_origin(ctx.initiator, init_orig_str);
    core::serialize_origin(target_orig, target_orig_str);
    guard !init_orig_str[..].eq_ascii_fold(target_orig_str[..]) || ctx.tainted_origin else {
        return true;
    }

    let corp_hdr = header(resp, "Cross-Origin-Resource-Policy");
    if corp_hdr.len > 0 {
        var iso_ctx = CrossOriginIsolationContext { .. };
        let _ = iso_ctx.document_origin.try_set(init_orig_str[..]);
        if !is_subresource_allowed(iso_ctx, target_orig_str[..], corp_hdr) {
            out_err = make_error(rfc::STATUS_FORBIDDEN, "corp", "ERR_BLOCKED_BY_RESPONSE: CORP violation");
            return false;
        }
    }

    if ctx.cors_mode {
        let req_orig = find_header(ctx.headers, "Origin");
        if req_orig.len > 0 {
            let include_creds = find_header(ctx.headers, "Cookie").len > 0 ||
                find_header(ctx.headers, "Authorization").len > 0;
            let cors_opts = ClientCorsVerifyOptions {
                tainted_origin:      ctx.tainted_origin,
                include_credentials: include_creds,
            };
            if !verify_client_cors_response(resp.headers, req_orig, cors_opts) {
                out_err = make_error(rfc::STATUS_FORBIDDEN, "cors", "ERR_FAILED: CORS response check failed");
                return false;
            }
        }
    }
    return true;
}

// Evaluates 3xx redirect responses (RFC 9110 §15.4).
// Returns `StageVerdict.FollowRedirect` when a redirect transition is prepared on `ctx`,
// `StageVerdict.Continue` when the response is final or `RedirectMode.Manual`,
// or `StageVerdict.Abort` when redirect limits or policies are violated.
fn stage_client_redirect(
    session:     Session&,
    ctx:         RequestExecutionContext&,
    resp:        Response&,
    current_url: const core::Url&,
    out_err:     Error&,
) -> wire::StageVerdict {
    if !validate_client_cors_and_corp_response(ctx, current_url, resp, out_err) {
        return wire::StageVerdict.Abort { err_code: out_err.code };
    }
    let loc_hdr = header(resp, "Location");
    let is_red = is_redirect(resp);
    if !is_red {
        finalize_success_response(ctx, resp);
        return wire::StageVerdict.Continue;
    }
    session.pipeline.metrics.redirect_hops += 1;
    let should_continue, red_err = process_redirect_hop(session, ctx, resp, current_url, loc_hdr);
    if !ok(red_err) {
        out_err = red_err;
        return wire::StageVerdict.Abort { err_code: red_err.code };
    }
    if should_continue {
        return wire::StageVerdict.FollowRedirect;
    }
    return wire::StageVerdict.Continue;
}

// ---- Programmable Client Stage Context & User Hooks -------------------------

// Context passed to user-injected client stages (`on_client_stage`).
struct ClientStageCtx {
    current_url:    core::Url          = core::Url { .. },
    current_method: u8[..16]           = [],
    headers:        HeaderMap          = HeaderMap { .. },
    pipeline:       wire::WirePipeline = wire::default_client_pipeline(),
    redirect_count: i32                = 0,
    auth_retried:   bool               = false,
    now_us:         i64                = 0,
    last_error:     Error              = Error { .. },
    // Resizable field must be final
    resp: Response = Response { .. },
}

// Default no-op hook for `wire::NoOpStage` by `ClientHookPhase`.
inline fn on_client_stage(
    _stage: wire::NoOpStage&,
    _phase: wire::ClientHookPhase,
    _ctx:   ClientStageCtx&,
) -> wire::StageVerdict {
    return wire::StageVerdict.Continue;
}

// Composes two independent client stages `<First, Next>` sequentially at each `ClientHookPhase`.
// Short-circuits, retries, or aborts immediately if `chain.first` does not return `StageVerdict.Continue`.
inline fn on_client_stage<First, Next>(
    chain: wire::StageChain<First, Next>&,
    phase: wire::ClientHookPhase,
    ctx:   ClientStageCtx&,
) -> wire::StageVerdict {
    var p = wire::begin_pipeline();
    if p.step(chain.first.on_client_stage(phase, ctx)) {
        let _ = p.step(chain.next.on_client_stage(phase, ctx));
    }
    return p.verdict;
}

// Runs pre-flight client stages (HSTS URL upgrade, initial URL parse, and HTTP cache lookup).
fn run_client_preflight_stages<UserStage>(
    session:              Client&,
    req:                  const Request&,
    raw_eff_url:          u8[..2048]&,
    cache_ts:             const CacheTimestamps&,
    ctx:                  RequestExecutionContext&,
    out_resp:             Response&,
    out_err:              Error&,
    cache_revalidate_idx: i64&,
    user_stage:           UserStage&,
) -> wire::StageVerdict {
    let now_sec = session.virtual_clock_us / 1000000;
    if wire::is_ingress_stage_enabled(session.wire_pipeline, wire::STAGE_ID_CLI_IN_URL_HSTS) {
        let _ = stage_client_url_hsts(raw_eff_url, session.hsts, session.enable_hsts, now_sec);
    }

    let parsed_initial, _ = core::parse_url(raw_eff_url[..]);
    guard parsed_initial.valid else {
        out_err = make_error(rfc::STATUS_BAD_REQUEST, "url_parse", "invalid request url");
        return wire::StageVerdict.Abort { err_code: rfc::STATUS_BAD_REQUEST };
    }

    ctx = init_execution_context(session, req, parsed_initial);

    if wire::is_ingress_stage_enabled(session.wire_pipeline, wire::STAGE_ID_CLI_IN_CACHE_LOOKUP) {
        var cache_hdrs = copy(ctx.headers);
        let cookie_stage_on = wire::is_ingress_stage_enabled(session.wire_pipeline, wire::STAGE_ID_CLI_IN_COOKIE_LOAD);
        if session.enable_cookie_jar && cookie_stage_on {
            var tmp_ctx = copy(ctx);
            let safe_m = rfc::is_safe_http_method(tmp_ctx.current_method[..]);
            let ss_eval = compute_hop_samesite_context(tmp_ctx, parsed_initial, safe_m);
            prepare_hop_cookie_header(session, tmp_ctx, parsed_initial, ss_eval, safe_m);
            cache_hdrs = copy(tmp_ctx.headers);
        }
        let v_cache = stage_client_cache_lookup(
            req,
            parsed_initial.href[..],
            cache_ts.now,
            cache_hdrs,
            out_resp,
            cache_revalidate_idx,
            session.cache,
            session.enable_cache,
        );
        if cache_revalidate_idx >= 0 {
            let inm = get_header(cache_hdrs, "If-None-Match");
            if inm.len > 0 { set_header(ctx.headers, "If-None-Match", inm); }
            let ims = get_header(cache_hdrs, "If-Modified-Since");
            if ims.len > 0 { set_header(ctx.headers, "If-Modified-Since", ims); }
        }
        match v_cache {
            ShortCircuit _ => {
                out_err = Error { .. };
                return v_cache;
            },
            Abort ab => {
                out_err = make_error(ab.err_code, "cache", "504 Gateway Timeout (only-if-cached miss)");
                return v_cache;
            },
            _ => {},
        };
    }

    var s_ctx = ClientStageCtx {
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
    let u_verdict = user_stage.on_client_stage(wire::ClientHookPhase.PreFlight, s_ctx);
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
            out_err = if !ok(s_ctx.last_error) {
                s_ctx.last_error
            } else {
                make_error(ab.err_code, "user_stage", "aborted by client pre-flight stage")
            };
            return u_verdict;
        },
        _ => {},
    };
    return wire::StageVerdict.Continue;
}

inline fn apply_client_early_data_and_dpop_headers(
    session:     const Client&,
    ctx:         RequestExecutionContext&,
    current_url: const core::Url&,
    now_sec:     i64,
) {
    if session.enable_early_data && !ctx.auth_retried {
        if evaluate_early_data_request(ctx.current_method[..]) == EarlyDataDecision.Allow {
            set_header(ctx.headers, "Early-Data", "1");
        }
    }
    guard session.has_dpop_key && find_header(ctx.headers, rfc::DPOP_HEADER).len == 0 else { return; }
    var proof: u8[..2048] = [];
    guard create_dpop_proof(
        session.dpop_private_key[..],
        ctx.current_method[..],
        current_url.href[..],
        session.dpop_access_token[..],
        session.last_dpop_nonce[..],
        now_sec,
        "",
        proof,
    ) else { return; }
    set_header(ctx.headers, rfc::DPOP_HEADER, proof[..], true);
    if session.dpop_access_token.len > 0 && find_header(ctx.headers, "Authorization").len == 0 {
        var auth_val: u8[..600] = [];
        auth_val.append("DPoP ");
        let _ = auth_val.try_append(session.dpop_access_token[..]);
        set_header(ctx.headers, "Authorization", auth_val[..], true);
    }
}

// Executes a single built-in client ingress stage by slot ID (`0..5`).
fn dispatch_client_ingress_stage(
    stage_id:      u8,
    session:       Client&,
    ctx:           RequestExecutionContext&,
    current_url:   core::Url&,
    samesite_eval: SameSiteCookieContext&,
    safe_method:   bool,
    now_sec:       i64,
    out_err:       Error&,
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
        samesite_eval = compute_hop_samesite_context(ctx, current_url, safe_method);
        var part_key: u8[..256] = [];
        compute_hop_partition_key(ctx, current_url, part_key);
        return stage_client_cookie_load(
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
        return stage_client_auth_header(
            session.pipeline,
            ctx.headers,
            current_url.href[..],
            ctx.current_method[..],
            ctx.body.len,
            ctx.redirect_count,
        );
    }
    return wire::StageVerdict.Continue;
}

// Runs all enabled pre-hop client ingress stages in `session.wire_pipeline.ingress_stages` order,
// followed by `<UserStage>` at `ClientHookPhase.PreWireHop`.
fn run_client_pre_hop_stages<UserStage>(
    session:       Client&,
    ctx:           RequestExecutionContext&,
    current_url:   core::Url&,
    samesite_eval: SameSiteCookieContext&,
    safe_method:   bool,
    now_sec:       i64,
    out_resp:      Response&,
    out_err:       Error&,
    user_stage:    UserStage&,
) -> wire::StageVerdict {
    var p = wire::begin_pipeline();
    for i in session.wire_pipeline.ingress_stages.len {
        let stage_id = session.wire_pipeline.ingress_stages[i];
        guard wire::is_ingress_stage_enabled(session.wire_pipeline, stage_id) else { continue; }
        let v = dispatch_client_ingress_stage(
            stage_id,
            session,
            ctx,
            current_url,
            samesite_eval,
            safe_method,
            now_sec,
            out_err,
        );
        if !p.step(v) {
            return p.verdict;
        }
    }

    var s_ctx = ClientStageCtx {
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
    let hook_v = user_stage.on_client_stage(wire::ClientHookPhase.PreWireHop, s_ctx);
    ctx.headers = copy(s_ctx.headers);
    if !p.step(hook_v) {
        out_resp = copy(s_ctx.resp);
        if !ok(s_ctx.last_error) {
            out_err = s_ctx.last_error;
        }
        return p.verdict;
    }
    return wire::StageVerdict.Continue;
}

// Executes a single built-in post-hop client egress stage by slot ID (`0..5`).
fn dispatch_client_egress_stage(
    stage_id:             u8,
    session:              Client&,
    ctx:                  RequestExecutionContext&,
    req:                  const Request&,
    current_url:          const core::Url&,
    samesite_eval:        const SameSiteCookieContext&,
    safe_method:          bool,
    cache_ts:             CacheTimestamps&,
    cache_revalidate_idx: i64,
    out_resp:             Response&,
    out_err:              Error&,
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
        compute_hop_partition_key(ctx, current_url, part_key);
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
        let dec_v = stage_client_decompress(
            out_resp,
            session.dict_cache,
            session.strict_content_decoding || session.verify_content_digest,
        );
        match dec_v {
            Abort ab => {
                out_err = make_error(ab.err_code, "protocol", "ERR_CONTENT_DECODING_FAILED: content-encoding decompression failed");
            },
            _ => {},
        };
        return dec_v;
    }
    if stage_id == wire::STAGE_ID_CLI_OUT_CACHE_STORE {
        return stage_client_cache_store(
            req,
            ctx.headers,
            current_url,
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

// Runs all enabled post-hop client egress stages in `session.wire_pipeline.egress_stages` order.
fn run_client_post_hop_stages<UserStage>(
    session:              Client&,
    ctx:                  RequestExecutionContext&,
    req:                  const Request&,
    current_url:          const core::Url&,
    samesite_eval:        const SameSiteCookieContext&,
    safe_method:          bool,
    cache_ts:             CacheTimestamps&,
    cache_revalidate_idx: i64,
    out_resp:             Response&,
    out_err:              Error&,
    user_stage:           UserStage&,
) -> wire::StageVerdict {
    var p = wire::begin_pipeline();
    var s_ctx = ClientStageCtx {
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
    let hook_v = user_stage.on_client_stage(wire::ClientHookPhase.PostWireHop, s_ctx);
    out_resp = copy(s_ctx.resp);
    if !p.step(hook_v) {
        if !ok(s_ctx.last_error) {
            out_err = s_ctx.last_error;
        }
        return p.verdict;
    }

    for i in session.wire_pipeline.egress_stages.len {
        let stage_id = session.wire_pipeline.egress_stages[i];
        guard wire::is_egress_stage_enabled(session.wire_pipeline, stage_id) else { continue; }
        let v = dispatch_client_egress_stage(
            stage_id,
            session,
            ctx,
            req,
            current_url,
            samesite_eval,
            safe_method,
            cache_ts,
            cache_revalidate_idx,
            out_resp,
            out_err,
        );
        if !p.step(v) {
            return p.verdict;
        }
    }

    ctx.body_consumed = true;
    finalize_success_response(ctx, out_resp);
    return wire::StageVerdict.Continue;
}

fn execute_client_auth_retry_hop<UserStage>(
    session:              Client&,
    ctx:                  RequestExecutionContext&,
    req:                  const Request&,
    current_url:          const core::Url&,
    samesite_eval:        const SameSiteCookieContext&,
    safe_method:          bool,
    cache_ts:             CacheTimestamps&,
    cache_revalidate_idx: i64,
    resp:                 Response&,
    hop_err:              Error&,
    user_stage:           UserStage&,
) -> wire::StageVerdict, bool {
    let retry_start_us = session.virtual_clock_us;
    if wire::is_ingress_stage_enabled(session.wire_pipeline, wire::STAGE_ID_CLI_IN_INTERCEPTOR_AUTH) {
        let _ = stage_client_auth_header(
            session.pipeline,
            ctx.headers,
            current_url.href[..],
            ctx.current_method[..],
            ctx.body.len,
            ctx.redirect_count,
        );
    }
    resp, hop_err = execute_mock_or_echo_hop(session, ctx, current_url);
    let retry_dur_us = session.virtual_clock_us - retry_start_us;
    apply_network_interceptors_response(session.pipeline, resp, ctx.redirect_count, retry_dur_us);
    guard ok(hop_err) else { return wire::StageVerdict.Abort { err_code: hop_err.code }, false; }

    let post_v = run_client_post_hop_stages(
        session,
        ctx,
        req,
        current_url,
        samesite_eval,
        safe_method,
        cache_ts,
        cache_revalidate_idx,
        resp,
        hop_err,
        user_stage,
    );
    return post_v, true;
}

fn resolve_client_verdict_outcome(
    v:        wire::StageVerdict,
    resp:     Response&,
    hop_err:  Error&,
    err_msg:  const u8[:],
    out_done: bool&,
) {
    match v {
        FollowRedirect => {
            out_done = false;
        },
        ShortCircuit sc => {
            if resp.status_code == 0 {
                resp.status_code = sc.status_code;
            }
            hop_err = Error { .. };
            out_done = true;
        },
        Abort ab => {
            if ok(hop_err) {
                hop_err = make_error(ab.err_code, "pipeline", err_msg);
            }
            out_done = true;
        },
        _ => {
            hop_err = Error { .. };
            out_done = true;
        },
    };
}

fn run_client_auth_retry_loop<UserStage>(
    session:       Client&,
    ctx:           RequestExecutionContext&,
    req:           const Request&,
    current_url:   const core::Url&,
    samesite_eval: const SameSiteCookieContext&,
    safe_method:   bool,
    cache_ts:      CacheTimestamps&,
    hop_reval_idx: i64,
    resp:          Response&,
    hop_err:       Error&,
    user_stage:    UserStage&,
    post_v:        wire::StageVerdict&,
) -> bool {
    for _ in 2 {
        let is_retry_auth = match post_v { RetryAuth => true, _ => false };
        guard is_retry_auth else { break; }
        let next_v, retry_ok = execute_client_auth_retry_hop(
            session,
            ctx,
            req,
            current_url,
            samesite_eval,
            safe_method,
            cache_ts,
            hop_reval_idx,
            resp,
            hop_err,
            user_stage,
        );
        guard retry_ok else { return false; }
        post_v = next_v;
    }
    return true;
}

fn execute_single_client_hop_iteration<UserStage>(
    session:              Client&,
    ctx:                  RequestExecutionContext&,
    req:                  const Request&,
    cache_ts:             CacheTimestamps&,
    cache_revalidate_idx: i64,
    resp:                 Response&,
    hop_err:              Error&,
    user_stage:           UserStage&,
) -> bool {
    let chain_len = ctx.url_chain.len;
    guard chain_len > 0 && chain_len <= ctx.url_chain.cap else {
        hop_err = make_error(rfc::STATUS_BAD_REQUEST, "url_parse", "empty request url chain");
        return true;
    }
    var current_url = ctx.url_chain[chain_len - 1];
    let safe_method = rfc::is_safe_http_method(ctx.current_method[..]);
    var samesite_eval = compute_hop_samesite_context(ctx, current_url, safe_method);
    let now_sec = div_euclid(session.virtual_clock_us, 1000000);

    let pre_hop_v = run_client_pre_hop_stages(
        session,
        ctx,
        current_url,
        samesite_eval,
        safe_method,
        now_sec,
        resp,
        hop_err,
        user_stage,
    );
    var pre_p = wire::begin_pipeline();
    if !pre_p.step(pre_hop_v) {
        var done = true;
        resolve_client_verdict_outcome(pre_hop_v, resp, hop_err, "aborted by client ingress stage", done);
        return true;
    }

    var hop_reval_idx = if ctx.redirect_count == 0 { cache_revalidate_idx } else { -1 };
    let cache_lookup_on = wire::is_ingress_stage_enabled(session.wire_pipeline, wire::STAGE_ID_CLI_IN_CACHE_LOOKUP);
    if ctx.redirect_count > 0 && cache_lookup_on {
        let v_redir_cache = stage_client_cache_lookup(
            req,
            current_url.href[..],
            cache_ts.now,
            ctx.headers,
            resp,
            hop_reval_idx,
            session.cache,
            session.enable_cache,
            ctx.current_method[..],
        );
        if !pre_p.step(v_redir_cache) {
            finalize_success_response(ctx, resp);
            var done = true;
            resolve_client_verdict_outcome(v_redir_cache, resp, hop_err, "504 Gateway Timeout (only-if-cached miss)", done);
            return true;
        }
    }

    let hop_start_us = session.virtual_clock_us;
    resp, hop_err = execute_mock_or_echo_hop(session, ctx, current_url);
    guard ok(hop_err) else { return true; }

    let hop_dur_us = session.virtual_clock_us - hop_start_us;
    apply_network_interceptors_response(session.pipeline, resp, ctx.redirect_count, hop_dur_us);

    var post_v = run_client_post_hop_stages(
        session,
        ctx,
        req,
        current_url,
        samesite_eval,
        safe_method,
        cache_ts,
        hop_reval_idx,
        resp,
        hop_err,
        user_stage,
    );
    guard run_client_auth_retry_loop(
        session,
        ctx,
        req,
        current_url,
        samesite_eval,
        safe_method,
        cache_ts,
        hop_reval_idx,
        resp,
        hop_err,
        user_stage,
        post_v,
    ) else {
        return true;
    }

    var done = true;
    resolve_client_verdict_outcome(post_v, resp, hop_err, "aborted by client egress stage", done);
    return done;
}

// Executes a client request through `session.wire_pipeline` with an injected compile-time `<UserStage>` hook.
fn execute_client_pipeline_with_stage<UserStage>(
    session:    Client&,
    req:        const Request&,
    user_stage: UserStage&,
) -> Response, Error {
    var raw_eff_url: u8[..2048] = [];
    build_effective_url(session.base_url[..], req.url[..], req.query_params[..], raw_eff_url);

    let req_time = div_euclid(session.virtual_clock_us, 1000000);
    let req_time_ns = ((session.virtual_clock_us % 1000000) * 1000) as u32;
    var cache_ts = CacheTimestamps {
        request_time: core::unix(req_time, req_time_ns),
        now:          core::unix(req_time, req_time_ns),
    };

    var ctx = RequestExecutionContext { .. };
    var pre_resp = Response { .. };
    var pre_err = Error { .. };
    var cache_revalidate_idx: i64 = -1;

    let pre_verdict = run_client_preflight_stages(
        session,
        req,
        raw_eff_url,
        cache_ts,
        ctx,
        pre_resp,
        pre_err,
        cache_revalidate_idx,
        user_stage,
    );
    var pre_p = wire::begin_pipeline();
    if !pre_p.step(pre_verdict) {
        return pre_resp, pre_err;
    }

    while ctx.redirect_count <= ctx.max_redirects {
        var resp = Response { .. };
        var hop_err = Error { .. };
        let done = execute_single_client_hop_iteration(
            session,
            ctx,
            req,
            cache_ts,
            cache_revalidate_idx,
            resp,
            hop_err,
            user_stage,
        );
        if done {
            return resp, hop_err;
        }
    }

    return Response { .. }, make_error(rfc::STATUS_BAD_REQUEST, "redirect", "maximum redirect hops exceeded");
}
