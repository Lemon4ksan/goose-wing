// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal 401/Digest/Basic/DPoP/Early-Data/Signature auth, retry policy, HAR telemetry, and compression dict.
namespace client_internal;

import std;
import core;
import rfc.http;
import cookie.policy;
import http.request;
import http.response;
import http.headers;
import http.compression_dict;
import http.signatures;
import auth.digest;
import auth.dpop;
import security.privacypass;
import net.retry;
import client.replay_guard;
import client.telemetry;
import client.client;
import client.stream_facade_internal;
import .hop_context_internal;
import .verbs;

inline fn is_same_origin_session_hop(
    ctx:         const RequestExecutionContext&,
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

fn resolve_dpop_token_for_hop(
    session:       const client::Client&,
    ctx:           RequestExecutionContext&,
    current_url:   const core::Url&,
    existing_auth: const u8[:],
    out_token:     u8[..4096]&,
) -> bool {
    if existing_auth.len > 0 {
        let rest, is_dpop = existing_auth.strip_prefix_fold("dpop");
        guard is_dpop && rest.len > 0 && (rest[0] == ' ' || rest[0] == '\t') else {
            http::remove_header_by_name(ctx.headers, rfc::DPOP_HEADER);
            return false;
        }
        let trimmed_tok = rest.trim_lws();
        return trimmed_tok.len > 0 && out_token.try_set(trimmed_tok);
    }
    if session.dpop.access_token.len > 0 {
        guard is_secure_dpop_hop_url(current_url) else {
            http::remove_header_by_name(ctx.headers, rfc::DPOP_HEADER);
            return false;
        }
        return out_token.try_set(session.dpop.access_token[..]);
    }
    return true;
}

inline fn apply_client_early_data_and_dpop_headers(
    session:     const client::Client&,
    ctx:         RequestExecutionContext&,
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
    guard resolve_dpop_token_for_hop(session, ctx, current_url, existing_auth, token_buf) else { return; }
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
    ctx:         RequestExecutionContext&,
    current_url: const core::Url&,
) {
    guard !session.has_invalid_sig_config && session.sig_private_key.len == 32 else { return; }
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

// RFC 9110 Section 11.1: Authentication Scheme - Checks that `hdr` begins with `scheme_tok`
// followed by end-of-string or BWS/SP delimiter (`' '` or `'\t'`).
inline fn has_auth_scheme_prefix(hdr: const u8[:], scheme_tok: const u8[:]) -> bool {
    let s = hdr.trim_lws();
    guard s.starts_with_fold(scheme_tok) else { return false; }
    return s.len == scheme_tok.len || s[scheme_tok.len] == ' ' || s[scheme_tok.len] == '\t';
}

inline fn generate_digest_cnonce_hex(out: u8[..32]&) -> bool {
    out.clear();
    var raw_cn: u8[16] = [0; 16];
    defer core::secure_zeroize_16(raw_cn);
    let got_cn = if core::sim_rng_is_active() {
        core::sim_rng_fill(raw_cn[..])
    } else {
        core::csprng_fill(raw_cn[..])
    };
    guard got_cn else { return false; }
    for b in raw_cn {
        core::format_u8_hex(b, out, false);
    }
    return true;
}

inline fn is_allowed_digest_challenge(
    allow_legacy_md5: bool,
    chal:             const auth::DigestChallenge&,
) -> bool {
    guard !allow_legacy_md5 else { return true; }
    let alg_slice = chal.algorithm[..];
    let is_md5 = alg_slice.len == 0 ||
        alg_slice.eq_ascii_fold(rfc::DIGEST_ALGO_MD5) ||
        alg_slice.eq_ascii_fold(rfc::DIGEST_ALGO_MD5_SESS);
    return !is_md5 && chal.qop.len > 0;
}

fn compute_401_digest_header<B>(
    session:     client::Client&,
    ctx:         RequestExecutionContext&,
    current_url: const core::Url&,
    www_auth:    const u8[:],
    out:         B&,
) -> bool {
    let chal, ok_c = auth::parse_digest_challenge(www_auth);
    guard ok_c && (!ctx.auth_retried || chal.stale) else { return false; }
    var uri_target: u8[..2048] = [];
    let _ = format_h2_request_target_path(current_url, uri_target);
    var c_creds = auth::DigestCredentials { .. };
    let _ = c_creds.username.try_set(session.creds.username[..]);
    let _ = c_creds.password.try_set(session.creds.password[..]);
    defer core::secure_zeroize_slice(c_creds.password[..]);

    var active_chal = chal;
    if chal.stale && session.creds.last_digest.valid {
        let _ = auth::sync_digest_stale_challenge(
            session.creds.last_digest, chal, c_creds, session.creds.nonce_counter,
        );
        active_chal = session.creds.last_digest;
    } else {
        session.creds.last_digest = chal;
    }
    guard is_allowed_digest_challenge(session.allow_legacy_md5_digest, active_chal) else {
        return false;
    }

    var fresh_cnonce: u8[..32] = [];
    defer core::secure_zeroize_slice(fresh_cnonce[..]);
    if session.creds.cnonce.len == 0 {
        guard generate_digest_cnonce_hex(fresh_cnonce) else { return false; }
    }
    let eff_cnonce = if session.creds.cnonce.len > 0 { session.creds.cnonce[..] } else { fresh_cnonce[..] };

    let ok_d = auth::compute_digest_response(
        active_chal, c_creds, ctx.current_method[..], uri_target[..],
        session.creds.nonce_counter, eff_cnonce, ctx.body[..], out,
    );
    guard ok_d else { return false; }
    session.creds.nonce_counter = min(core::add_sat_u64(session.creds.nonce_counter, 1), 0xFFFFFFFF) as u32;
    return true;
}

fn compute_401_basic_header<B>(session: const client::Client&, out: B&) -> bool {
    // RFC 7617 Section 2: The 'Basic' Authentication Scheme - user-id MUST NOT contain a colon.
    guard !session.creds.username[..].contains_byte(':') else { return false; }
    var user_pass: u8[..260] = [];
    defer core::secure_zeroize_slice(user_pass[..]);
    guard user_pass.try_append(session.creds.username[..])
        && user_pass.try_push(':')
        && user_pass.try_append(session.creds.password[..]) else {
        return false;
    }
    var b64_user_pass: u8[..360] = [];
    defer core::secure_zeroize_slice(b64_user_pass[..]);
    core::base64_encode(user_pass[..], b64_user_pass);
    return out.try_append("Basic ") && out.try_append(b64_user_pass[..]);
}

fn compute_401_auth_header<B>(
    session:     client::Client&,
    ctx:         RequestExecutionContext&,
    current_url: const core::Url&,
    www_auth:    const u8[:],
    out:         B&,
) -> bool {
    var committed = false;
    defer if !committed { out.clear(); };
    out.clear();
    if has_auth_scheme_prefix(www_auth, "Digest") {
        guard compute_401_digest_header(session, ctx, current_url, www_auth, out) else { return false; }
        committed = true;
        return true;
    }
    if has_auth_scheme_prefix(www_auth, rfc::SCHEME_PRIVATE_TOKEN) {
        var tok_key: u8[..512] = [];
        let chal, _, ok_ch = security::parse_private_token_challenge(www_auth, tok_key);
        guard ok_ch else { return false; }
        var raw_tok: u8[..512] = [];
        let now_sec = div_euclid(client::effective_clock_us(session), 1000000);
        let _, ok_tok = security::get_private_token(session.private_token_cache, chal, now_sec, raw_tok);
        guard ok_tok && security::format_private_token_authorization(raw_tok[..], out) else { return false; }
        committed = true;
        return true;
    }
    if has_auth_scheme_prefix(www_auth, "Basic") {
        guard compute_401_basic_header(session, out) else { return false; }
        committed = true;
        return true;
    }
    return false;
}

fn try_find_scheme_auth_header<B>(
    session:       client::Client&,
    ctx:           RequestExecutionContext&,
    current_url:   const core::Url&,
    resp:          const http::Response&,
    scheme_prefix: const u8[:],
    out:           B&,
) -> bool {
    for &e in resp.headers.entries {
        let h_name = http::entry_name(resp.headers, e);
        let h_val = http::entry_value(resp.headers, e);
        if h_name.eq_ascii_fold("WWW-Authenticate") && has_auth_scheme_prefix(h_val, scheme_prefix) {
            if compute_401_auth_header(session, ctx, current_url, h_val, out) {
                return true;
            }
        }
    }
    return false;
}

fn find_auth_header_from_response<B>(
    session:     client::Client&,
    ctx:         RequestExecutionContext&,
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

fn prepare_auth_retry_hop(
    session:       client::Client&,
    ctx:           RequestExecutionContext&,
    current_url:   const core::Url&,
    samesite_eval: const cookie::SameSiteCookieContext&,
    safe_method:   bool,
    resp:          const http::Response&,
    auth_val:      const u8[:],
) {
    ctx.auth_retried = true;
    if ctx.body.len > 0 {
        ctx.body.clear();
        ctx.body.append(ctx.rewind_buf[..]);
    }
    ctx.body_consumed = false;
    if session.enable_cookie_jar {
        ingest_hop_response_cookies(session, ctx, current_url, samesite_eval, resp.headers);
        http::remove_header_by_name(ctx.headers, "Cookie");
        prepare_hop_cookie_header(session, ctx, current_url, samesite_eval, safe_method);
    }
    http::set_header(ctx.headers, "Authorization", auth_val, true);
}

fn try_handle_early_data_or_dpop_challenge(
    session:       client::Client&,
    ctx:           RequestExecutionContext&,
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
    let now_sec = div_euclid(client::effective_clock_us(session), 1000000);
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
        ingest_hop_response_cookies(session, ctx, current_url, samesite_eval, resp.headers);
        http::remove_header_by_name(ctx.headers, "Cookie");
        prepare_hop_cookie_header(session, ctx, current_url, samesite_eval, safe_method);
    }
    http::set_header(ctx.headers, rfc::DPOP_HEADER, proof[..], true);
    return true;
}

fn should_retry_request(
    status_code: i32,
    err:         http::Error,
    method:      const u8[:],
    req:         const http::Request&,
    attempts:    i32,
    has_retry:   bool,
    max_retries: i32,
    retry_5xx:   bool,
) -> bool {
    if !http::ok(err) && attempts == 0 {
        let tier1 = net::evaluate_tier1_retry(err.code, false, req, status_code > 0);
        if tier1.retry_immediately {
            return true;
        }
    }

    let is_idem = rfc::is_idempotent_method(method) || net::has_idempotency_key(req);
    let can_retry = is_idem && (req.body.len == 0 || req.rewindable);
    guard can_retry else { return false; }

    if status_code == rfc::STATUS_TOO_EARLY {
        return attempts < 3;
    }
    guard has_retry && attempts < max_retries else { return false; }
    return !http::ok(err) || (retry_5xx && status_code >= rfc::STATUS_INTERNAL_SERVER_ERROR && status_code <= 599);
}

fn evaluate_response_retry_after(
    session:  client::Client&,
    host_str: const u8[:],
    resp:     const http::Response&,
    now_ns:   i64,
) {
    let ra_val = resp.header("Retry-After");
    guard ra_val.len > 0 else { return; }
    let now_ms = div_euclid(client::effective_clock_us(session), 1000);
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
    let clamped_status = min(max(resp.status_code, 0), 65535);
    let status_u16 = clamped_status as u16;
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

// RFC 9842 Section 2.2: Available-Dictionary - Attaches `Available-Dictionary` and `Dictionary-ID`
// request headers when a valid dictionary in `session.dict_cache` matches `(origin, url_path)`.
fn attach_dictionary_request_headers(
    session:  const client::Session&,
    origin:   const u8[:],
    url_path: const u8[:],
    req:      http::Request&,
) -> bool {
    guard session.enable_compression_dict && is_secure_dict_origin(origin) else { return false; }
    let now_sec = div_euclid(client::effective_clock_us(session), 1000000);
    let best_idx = http::find_best_matching_dict_idx(session.dict_cache, origin, url_path, now_sec);
    guard best_idx >= 0 && best_idx < session.dict_cache.entries.len else { return false; }
    let entry .= session.dict_cache.entries[best_idx];
    http::set_header(req, "Available-Dictionary", entry.sha256_base64[..]);
    if entry.id.len > 0 {
        var id_hdr: u8[..128] = [];
        http::format_dictionary_id_header(id_hdr, entry.id[..]);
        http::set_header(req, "Dictionary-ID", id_hdr[..]);
    }
    return true;
}

// RFC 9842 Section 2.1: Use-As-Dictionary - Registers a response body in `session.dict_cache` when
// `Use-As-Dictionary` is present, and verifies/decodes `dcz` or `dcb` Content-Encoding payloads.
fn process_dictionary_response<B>(
    session:          client::Session&,
    origin:           const u8[:],
    use_as_dict_hdr:  const u8[:],
    content_encoding: const u8[:],
    raw_body:         const u8[:],
    out:              B&,
) -> bool {
    guard is_secure_dict_origin(origin) else { return false; }
    let enc = content_encoding.trim_lws();
    let prev_len = out.len;
    var committed = false;
    defer if !committed { out.resize(prev_len); };
    if enc.eq_ascii_fold(rfc::ENCODING_DCZ) {
        guard decode_dict_compressed_body(session, origin, true, raw_body, out) else {
            return false;
        }
    } else if enc.eq_ascii_fold(rfc::ENCODING_DCB) {
        guard decode_dict_compressed_body(session, origin, false, raw_body, out) else {
            return false;
        }
    } else if enc.len == 0 || enc.eq_ascii_fold("identity") {
        guard out.try_append(raw_body) else { return false; }
    } else {
        return false;
    }

    if session.enable_compression_dict && use_as_dict_hdr.len > 0 {
        let params, ok_p = http::parse_use_as_dictionary_header(use_as_dict_hdr);
        if ok_p {
            let now_sec = div_euclid(client::effective_clock_us(session), 1000000);
            http::dictionary_cache_insert(
                session.dict_cache,
                origin,
                params.match_pattern[..],
                params.id[..],
                out[prev_len..],
                params.ttl_sec,
                now_sec,
            );
        }
    }
    committed = true;
    return true;
}

fn ingest_compression_dict_header(
    dict_cache: http::DictionaryCache&,
    origin_buf: const u8[:],
    curr_path:  const u8[:],
    now_sec:    i64,
    resp:       http::Response&,
) {
    let dict_hdr = http::header(resp, "Use-As-Dictionary");
    guard dict_hdr.len > 0 else { return; }
    let d_params, ok_p = http::parse_use_as_dictionary_header(dict_hdr);
    guard ok_p else { return; }
    let enc = http::header(resp, "Content-Encoding");
    if enc.len > 0 {
        guard http::decode_body_with_dictionary(resp, dict_cache, now_sec) else { return; }
    }
    let pat = if d_params.match_pattern.len > 0 {
        d_params.match_pattern[..]
    } else {
        curr_path
    };
    http::dictionary_cache_insert(
        dict_cache,
        origin_buf,
        pat,
        d_params.id[..],
        resp.body[..],
        d_params.ttl_sec,
        now_sec,
    );
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
    let _ = process_dictionary_response(
        session,
        origin_buf,
        use_dict_hdr,
        enc_hdr,
        resp.body[..],
        decoded_dict,
    );
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
