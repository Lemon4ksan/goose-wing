// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Live RFC 8555 ACME v2 HTTP-01 client over `client::Session` with JWS ES256 signing,
// automatic Replay-Nonce tracking, badNonce retry, and defer-guaranteed challenge cleanup.
namespace client;

import std;
import json;
import core;
import rfc.http;
import http.headers;
import http.request;
import http.response;
import auth.acme_wire;
import tls.x509_san;
import tls.csr;
import .redirect;
import .client;
import .session.ssrf;
import .session.verbs;

// ---- ACME Client Protocol Constants (RFC 8555) -----------------------------

const ACME_CONTENT_TYPE_JOSE_JSON: const u8[:] = "application/jose+json";             // RFC 8555 Section 6.2
const ACME_ACCEPT_JSON:            const u8[:] = "application/json";                  // RFC 8555 Section 7.1
const ACME_ACCEPT_PEM_CHAIN:       const u8[:] = "application/pem-certificate-chain"; // RFC 8555 Section 9.1
const ACME_HEADER_REPLAY_NONCE:    const u8[:] = "Replay-Nonce";                      // RFC 8555 Section 6.5.1
const ACME_ERR_BAD_NONCE:          const u8[:] = "urn:ietf:params:acme:error:badNonce";
const ACME_MAX_NONCE_LEN:          i64         = 128; // RFC 8555 Section 6.5.1
const ACME_MAX_BAD_NONCE_RETRIES:  i64         = 2;   // RFC 8555 Section 6.5
const ACME_MAX_POST_ATTEMPTS:      i64         = 3;   // 1 initial attempt + 2 badNonce retries (RFC 8555 Section 6.5)
// Matches AcmeOrder.authz_urls capacity.
const ACME_MAX_ORDER_DOMAINS:  i64 = 8;
const ACME_MAX_RESPONSE_BYTES: i64 = 262144;
const ACME_MAX_PEM_CERT_BYTES: i64 = 131072;

// ---- ACME Configuration & Session State ------------------------------------

// Configuration for ACME directory discovery, account registration, and order polling.
struct AcmeClientConfig {
    directory_url:     u8[..256] = [],
    contact_email:     u8[..128] = [],
    accept_tos:        bool      = false,
    poll_interval_ms:  i64       = 1000,
    max_poll_attempts: i32       = 30,
}

// Live ACME session state storing parsed directory endpoints, account `kid` URL, and latest `Replay-Nonce`.
struct AcmeSession {
    dir:   auth::AcmeDirectory = auth::AcmeDirectory { .. },
    kid:   u8[..256]           = [],
    nonce: u8[..128]           = [],
}

enum AcmeAuthMode {
    Jwk,
    Kid,
}

enum AcmeAcceptKind {
    Json,
    PemChain,
}

enum AcmePollTarget {
    ReadyOrValid,
    ValidOnly,
}

// ---- Nonce & Problem Document Helpers (RFC 8555 §6.5 / §6.7) ---------------

inline fn is_allowed_acme_session_url(sess: const Session&, url: const u8[:]) -> bool {
    guard auth::is_valid_acme_http_url(url) else { return false; }
    let parsed, err = core::parse_url(url);
    guard err == core::UrlParseError.None && parsed.valid else { return false; }
    if sess.https_only && parsed.scheme() != "https" { return false; }
    return validate_url_against_ssrf(parsed, sess.ssrf_guard) == RedirectError.None;
}

inline fn is_valid_replay_nonce(raw: const u8[:]) -> bool {
    guard raw.len > 0 && raw.len <= ACME_MAX_NONCE_LEN else { return false; }
    guard core::swar_find_ctl(raw) == raw.len else { return false; }
    for b in raw {
        guard core::is_ascii_vchar(b) else { return false; }
    }
    return true;
}

inline fn capture_replay_nonce(resp: const http::Response&, out_nonce: u8[..128]&) -> bool {
    let raw = http::header(resp, ACME_HEADER_REPLAY_NONCE).trim_lws();
    guard is_valid_replay_nonce(raw) else { return false; }
    return out_nonce.try_set(raw);
}

// Parses an RFC 7807 / RFC 8555 Section 6.7 ACME error problem document and returns true
// when `"type"` equals `"urn:ietf:params:acme:error:badNonce"`.
//
// Example:
//   body = "{\"type\":\"urn:ietf:params:acme:error:badNonce\",\"detail\":\"expired\"}"
//   returns: true
fn is_acme_bad_nonce_problem(body: const u8[:]) -> bool {
    guard body.len > 0 && body.len <= ACME_MAX_RESPONSE_BYTES && body.validate_utf8() else {
        return false;
    }
    var reader = json::reader(body);
    guard json::peek(reader) == '{' else { return false; }
    var is_bad_nonce = false;
    var err_type: u8[..128] = [];
    json::each_member(reader) { key =>
        if !key.contains('\\') && key == "type" && json::peek(reader) == '"' {
            if core::read_json_string_into(reader, err_type) &&
                err_type[..] == ACME_ERR_BAD_NONCE {
                is_bad_nonce = true;
            }
        } else {
            json::skip(reader);
        }
    };
    return json::finish(reader) && is_bad_nonce;
}

// ---- Directory & Nonce Discovery (RFC 8555 §7.1.1 / §7.2) ------------------

// RFC 8555 Section 7.1.1: Directory - fetches and validates the ACME directory JSON into `out_dir`.
// Resets `out_dir` on any transport, status, bounds, or parse error.
fn acme_fetch_directory(
    sess:    Session&,
    url:     const u8[:],
    out_dir: auth::AcmeDirectory&,
) -> bool {
    out_dir = auth::AcmeDirectory { .. };
    var committed = false;
    defer if !committed { out_dir = auth::AcmeDirectory { .. }; };

    guard is_allowed_acme_session_url(sess, url) else { return false; }
    var req = http::new_get(url);
    http::set_header(req, rfc::HEADER_ACCEPT, ACME_ACCEPT_JSON);

    let resp, err = do(sess, req);
    guard http::ok(err) && resp.status_code == rfc::STATUS_OK else { return false; }
    guard resp.body.len > 0 && resp.body.len <= ACME_MAX_RESPONSE_BYTES else { return false; }
    guard auth::acme_parse_directory(resp.body[..], out_dir) else { return false; }

    committed = true;
    return true;
}

// RFC 8555 Section 7.2: Getting a Nonce - issues HEAD `new_nonce_url` and validates `Replay-Nonce`.
// Clears `out_nonce` on any transport, status, or header validation error.
fn acme_fetch_nonce(
    sess:          Session&,
    new_nonce_url: const u8[:],
    out_nonce:     u8[..128]&,
) -> bool {
    out_nonce.clear();
    var committed = false;
    defer if !committed { out_nonce.clear(); };

    guard is_allowed_acme_session_url(sess, new_nonce_url) else { return false; }
    let req = http::new_request(rfc::METHOD_HEAD, new_nonce_url);
    let resp, err = do(sess, req);
    guard http::ok(err) else { return false; }
    guard resp.status_code == rfc::STATUS_OK || resp.status_code == rfc::STATUS_NO_CONTENT else {
        return false;
    }
    guard capture_replay_nonce(resp, out_nonce) else { return false; }

    committed = true;
    return true;
}

// ---- Authenticated JWS Transport & badNonce Retry (RFC 8555 §6.2 / §6.5) ---

fn send_acme_signed_post(
    sess:        Session&,
    url:         const u8[:],
    jws_bytes:   const u8[:],
    accept_kind: AcmeAcceptKind,
    out_nonce:   u8[..128]&,
    out_resp:    http::Response&,
) -> bool {
    // RFC 8555 Section 6.2 / 6.4: JWS protected "url" binds to the exact target; never auto-follow redirects.
    let saved_redirect_mode = sess.redirect_mode;
    let saved_follow_redirects = sess.follow_redirects;
    defer {
        sess.redirect_mode = saved_redirect_mode;
        sess.follow_redirects = saved_follow_redirects;
    };
    set_redirect_mode(sess, RedirectMode.Manual);

    var req = http::new_post(url);
    http::set_stream_body(req, jws_bytes, false);
    http::set_header(req, rfc::HEADER_CONTENT_TYPE, ACME_CONTENT_TYPE_JOSE_JSON);
    let accept_hdr = if accept_kind == AcmeAcceptKind.PemChain {
        ACME_ACCEPT_PEM_CHAIN
    } else {
        ACME_ACCEPT_JSON
    };
    http::set_header(req, rfc::HEADER_ACCEPT, accept_hdr);

    let resp, err = do(sess, req);
    guard http::ok(err) else { return false; }
    guard resp.body.len <= ACME_MAX_RESPONSE_BYTES else { return false; }
    // RFC 8555 Section 6.5: Capture fresh Replay-Nonce from every response, including 4xx errors.
    let _ = capture_replay_nonce(resp, out_nonce);
    out_resp = copy(resp);
    return true;
}

// RFC 8555 Section 6.2 & Section 6.5: Request Authentication and Replay Protection.
// Signs `payload_json` (or empty POST-as-GET per Section 6.3) with ES256 and retries up to 2 times on `badNonce`.
fn acme_post_jws(
    sess:         Session&,
    acme:         AcmeSession&,
    priv_key:     const u8[32]&,
    url:          const u8[:],
    payload_json: const u8[:],
    auth_mode:    AcmeAuthMode,
    accept_kind:  AcmeAcceptKind,
    out_resp:     http::Response&,
) -> bool {
    http::reset_response(out_resp);
    guard is_allowed_acme_session_url(sess, url) else { return false; }
    if auth_mode == AcmeAuthMode.Kid {
        guard acme.kid.len > 0 else { return false; }
    }
    let kid_slice = if auth_mode == AcmeAuthMode.Kid { acme.kid[..] } else { "" };

    var jws_buf: u8[>..] = [];
    for attempt in ACME_MAX_POST_ATTEMPTS {
        if acme.nonce.len == 0 {
            guard acme_fetch_nonce(sess, acme.dir.new_nonce[..], acme.nonce) else { return false; }
        }
        jws_buf.clear();
        guard auth::acme_sign_jws_es256(
            priv_key, url, acme.nonce[..], kid_slice, payload_json, jws_buf,
        ) else {
            return false;
        }
        // Single-use nonce consumed by this POST; cleared so missing Replay-Nonce triggers HEAD fallback.
        acme.nonce.clear();
        guard send_acme_signed_post(sess, url, jws_buf[..], accept_kind, acme.nonce, out_resp) else {
            return false;
        }
        let is_bad_nonce = out_resp.status_code == rfc::STATUS_BAD_REQUEST &&
            is_acme_bad_nonce_problem(out_resp.body[..]);
        if !is_bad_nonce {
            return true;
        }
        guard attempt < ACME_MAX_BAD_NONCE_RETRIES else {
            http::reset_response(out_resp);
            return false;
        }
    }
    return false;
}

// ---- Account Registration (RFC 8555 §7.3) ----------------------------------

fn build_acme_new_account_json(contact_email: const u8[:], out: u8[>..]&) -> bool {
    out.clear();
    out.append("{\"termsOfServiceAgreed\":true");
    if contact_email.len > 0 {
        guard core::swar_find_ctl(contact_email) == contact_email.len &&
            !contact_email.contains_byte(' ') else {
            out.clear();
            return false;
        }
        var mailto_buf: u8[..160] = "mailto:";
        guard mailto_buf.try_append(contact_email) else {
            out.clear();
            return false;
        }
        out.append(",\"contact\":[");
        core::format_json_string(out, mailto_buf[..]);
        out.push(']');
    }
    out.push('}');
    return true;
}

// RFC 8555 Section 7.3: Account Management - registers or recovers an ACME account (`acme.kid`)
// using JWK authentication (`kid == ""`) and explicit `cfg.accept_tos == true`.
fn acme_ensure_account(
    sess:     Session&,
    acme:     AcmeSession&,
    priv_key: const u8[32]&,
    cfg:      const AcmeClientConfig&,
) -> bool {
    guard cfg.accept_tos else { return false; }
    if acme.dir.new_nonce.len == 0 || acme.dir.new_account.len == 0 || acme.dir.new_order.len == 0 {
        guard acme_fetch_directory(sess, cfg.directory_url[..], acme.dir) else { return false; }
    }
    if acme.kid.len > 0 {
        return is_allowed_acme_session_url(sess, acme.kid[..]);
    }
    var payload: u8[>..] = [];
    guard build_acme_new_account_json(cfg.contact_email[..], payload) else { return false; }

    var resp = http::Response { .. };
    guard acme_post_jws(
        sess, acme, priv_key, acme.dir.new_account[..], payload[..],
        AcmeAuthMode.Jwk, AcmeAcceptKind.Json, resp,
    ) else {
        return false;
    }
    guard resp.status_code == rfc::STATUS_OK || resp.status_code == rfc::STATUS_CREATED else {
        return false;
    }
    let loc = http::header(resp, rfc::HEADER_LOCATION).trim_lws();
    guard is_allowed_acme_session_url(sess, loc) else { return false; }
    return acme.kid.try_set(loc);
}

// ---- Order Issuance & HTTP-01 Fulfillment (RFC 8555 §7.4 / §7.5 / §8.3) ----

fn validate_acme_order_domains(domains: const u8[..255][:]) -> bool {
    guard domains.len > 0 && domains.len <= ACME_MAX_ORDER_DOMAINS else { return false; }
    for &dom in domains {
        // RFC 8555 Section 8.3: HTTP Challenge does not support wildcard DNS identifiers.
        guard tls::validate_san_dns_name(dom[..]) && !dom[..].contains_byte('*') else {
            return false;
        }
    }
    return true;
}

fn build_acme_new_order_json(domains: const u8[..255][:], out: u8[>..]&) -> bool {
    out.clear();
    out.append("{\"identifiers\":[");
    for &dom, idx in domains {
        if idx > 0 { out.push(','); }
        out.append("{\"type\":\"dns\",\"value\":");
        core::format_json_string(out, dom[..]);
        out.push('}');
    }
    out.append("]}");
    return true;
}

// Parses an RFC 8555 Section 7.1.3 Order JSON payload while preserving `order.order_url`.
//
// Example:
//   raw_json = "{\"status\":\"ready\",\"authorizations\":[\"https://ex/az/1\"],\"finalize\":\"https://ex/fin\"}"
//   returns: true, order.status = AcmeOrderStatus.Ready, order.order_url preserved
fn parse_acme_order_preserving_url(raw_json: const u8[:], order: auth::AcmeOrder&) -> bool {
    let saved_url = order.order_url;
    var parsed = auth::AcmeOrder { .. };
    guard auth::acme_parse_order(raw_json, parsed) else { return false; }
    parsed.order_url = saved_url;
    order = parsed;
    return true;
}

fn create_acme_order(
    sess:         Session&,
    acme:         AcmeSession&,
    account_priv: const u8[32]&,
    domains:      const u8[..255][:],
    out_order:    auth::AcmeOrder&,
) -> bool {
    out_order = auth::AcmeOrder { .. };
    var payload: u8[>..] = [];
    guard build_acme_new_order_json(domains, payload) else { return false; }

    var resp = http::Response { .. };
    guard acme_post_jws(
        sess, acme, account_priv, acme.dir.new_order[..], payload[..],
        AcmeAuthMode.Kid, AcmeAcceptKind.Json, resp,
    ) else {
        return false;
    }
    guard resp.status_code == rfc::STATUS_CREATED else { return false; }

    var ord = auth::AcmeOrder { .. };
    guard auth::acme_parse_order(resp.body[..], ord) else { return false; }
    guard ord.authz_urls.len > 0 else { return false; }
    let loc = http::header(resp, rfc::HEADER_LOCATION).trim_lws();
    if ord.order_url.len == 0 {
        guard is_allowed_acme_session_url(sess, loc) && ord.order_url.try_set(loc) else { return false; }
    }
    guard ord.status != auth::AcmeOrderStatus.Invalid &&
        ord.status != auth::AcmeOrderStatus.Unknown else {
        return false;
    }
    out_order = ord;
    return true;
}

fn process_single_http01_authz<Hook>(
    sess:             Session&,
    acme:             AcmeSession&,
    account_priv:     const u8[32]&,
    thumbprint:       const u8[:],
    authz_url:        const u8[:],
    hook:             Hook&,
    published_tokens: u8[..128][..8]&,
) -> bool {
    var resp = http::Response { .. };
    guard acme_post_jws(
        sess, acme, account_priv, authz_url, "",
        AcmeAuthMode.Kid, AcmeAcceptKind.Json, resp,
    ) else {
        return false;
    }
    guard resp.status_code == rfc::STATUS_OK else { return false; }

    var ch = auth::AcmeHttp01Challenge { .. };
    guard auth::acme_parse_authz_http01(resp.body[..], thumbprint, ch) else { return false; }
    if ch.status == auth::AcmeOrderStatus.Valid {
        return true;
    }
    guard ch.status == auth::AcmeOrderStatus.Pending else { return false; }
    guard published_tokens.len < published_tokens.cap else { return false; }
    guard acme_publish_http01(hook, ch.token[..], ch.key_auth[..]) else { return false; }

    var tok_item: u8[..128] = [];
    guard tok_item.try_set(ch.token[..]) && published_tokens.try_push(tok_item) else {
        acme_clear_http01(hook, ch.token[..]);
        return false;
    }
    // RFC 8555 Section 7.5.1: Responding to Challenges - POST "{}" to trigger validation.
    guard acme_post_jws(
        sess, acme, account_priv, ch.url[..], "{}",
        AcmeAuthMode.Kid, AcmeAcceptKind.Json, resp,
    ) else {
        return false;
    }
    return resp.status_code == rfc::STATUS_OK;
}

inline fn order_reached_poll_target(status: auth::AcmeOrderStatus, target: AcmePollTarget) -> bool {
    if status == auth::AcmeOrderStatus.Valid { return true; }
    return target == AcmePollTarget.ReadyOrValid && status == auth::AcmeOrderStatus.Ready;
}

inline fn is_pollable_order_status(status: auth::AcmeOrderStatus) -> bool {
    return status == auth::AcmeOrderStatus.Pending ||
        status == auth::AcmeOrderStatus.Processing ||
        status == auth::AcmeOrderStatus.Ready;
}

inline fn sleep_acme_poll_interval(poll_interval_ms: i64, idx: i64, attempts: i64) {
    guard poll_interval_ms > 0 && core::add_sat_i64(idx, 1) < attempts else { return; }
    let sleep_ns = core::mul_sat_i64(poll_interval_ms, core::MILLISECOND);
    core::sleep(core::Duration { nanos: sleep_ns });
}

fn poll_acme_order_until(
    sess:     Session&,
    acme:     AcmeSession&,
    priv_key: const u8[32]&,
    cfg:      const AcmeClientConfig&,
    target:   AcmePollTarget,
    order:    auth::AcmeOrder&,
) -> bool {
    if order_reached_poll_target(order.status, target) { return true; }
    let attempts = max(cfg.max_poll_attempts as i64, 1);
    var resp = http::Response { .. };

    for idx in attempts {
        guard acme_post_jws(
            sess, acme, priv_key, order.order_url[..], "",
            AcmeAuthMode.Kid, AcmeAcceptKind.Json, resp,
        ) else {
            return false;
        }
        guard resp.status_code == rfc::STATUS_OK else { return false; }
        guard parse_acme_order_preserving_url(resp.body[..], order) else { return false; }
        if order_reached_poll_target(order.status, target) { return true; }
        guard is_pollable_order_status(order.status) else { return false; }
        sleep_acme_poll_interval(cfg.poll_interval_ms, idx, attempts);
    }
    return false;
}

fn finalize_acme_order(
    sess:         Session&,
    acme:         AcmeSession&,
    account_priv: const u8[32]&,
    csr_der:      const u8[:],
    order:        auth::AcmeOrder&,
) -> bool {
    var csr_b64: u8[>..] = [];
    core::base64url_encode(csr_der, csr_b64);

    var payload: u8[>..] = "{\"csr\":";
    core::format_json_string(payload, csr_b64[..]);
    payload.push('}');

    var resp = http::Response { .. };
    guard acme_post_jws(
        sess, acme, account_priv, order.finalize_url[..], payload[..],
        AcmeAuthMode.Kid, AcmeAcceptKind.Json, resp,
    ) else {
        return false;
    }
    guard resp.status_code == rfc::STATUS_OK else { return false; }
    guard parse_acme_order_preserving_url(resp.body[..], order) else { return false; }
    return order.status != auth::AcmeOrderStatus.Invalid &&
        order.status != auth::AcmeOrderStatus.Unknown;
}

fn download_acme_cert_pem(
    sess:              Session&,
    acme:              AcmeSession&,
    account_priv:      const u8[32]&,
    cert_url:          const u8[:],
    out_fullchain_pem: u8[>..]&,
) -> bool {
    guard auth::is_valid_acme_http_url(cert_url) else { return false; }
    var resp = http::Response { .. };
    guard acme_post_jws(
        sess, acme, account_priv, cert_url, "",
        AcmeAuthMode.Kid, AcmeAcceptKind.PemChain, resp,
    ) else {
        return false;
    }
    guard resp.status_code == rfc::STATUS_OK else { return false; }
    guard resp.body.len > 0 && resp.body.len <= ACME_MAX_PEM_CERT_BYTES else { return false; }
    guard core::contains(resp.body[..], "BEGIN CERTIFICATE") else { return false; }
    out_fullchain_pem.append(resp.body[..]);
    return true;
}

fn prepare_acme_order_inputs(
    sess:           Session&,
    acme:           AcmeSession&,
    account_priv:   const u8[32]&,
    cert_priv:      const u8[32]&,
    cfg:            const AcmeClientConfig&,
    domains:        const u8[..255][:],
    out_thumbprint: u8[..64]&,
    out_csr_der:    u8[>..]&,
) -> bool {
    var committed = false;
    defer if !committed {
        out_thumbprint.clear();
        out_csr_der.clear();
    };
    out_thumbprint.clear();
    out_csr_der.clear();

    guard validate_acme_order_domains(domains) else { return false; }
    guard auth::acme_jwk_thumbprint_p256(account_priv, out_thumbprint) else { return false; }
    guard tls::build_pkcs10_csr_p256_der(cert_priv, domains, out_csr_der) else { return false; }

    if acme.dir.new_nonce.len == 0 || acme.dir.new_order.len == 0 {
        guard acme_fetch_directory(sess, cfg.directory_url[..], acme.dir) else { return false; }
    }
    if acme.kid.len == 0 {
        guard acme_ensure_account(sess, acme, account_priv, cfg) else { return false; }
    } else {
        guard is_allowed_acme_session_url(sess, acme.kid[..]) else { return false; }
    }
    committed = true;
    return true;
}

fn run_http01_authorizations<Hook>(
    sess:             Session&,
    acme:             AcmeSession&,
    account_priv:     const u8[32]&,
    thumbprint:       const u8[:],
    authz_urls:       const u8[..256][:],
    hook:             Hook&,
    published_tokens: u8[..128][..8]&,
) -> bool {
    for &az_url in authz_urls {
        guard process_single_http01_authz(
            sess, acme, account_priv, thumbprint, az_url[..], hook, published_tokens,
        ) else {
            return false;
        }
    }
    return true;
}

// RFC 8555 Section 7.4 / Section 8.3: Applying for Certificate Issuance & HTTP Challenge.
// Executes full HTTP-01 order creation, challenge provisioning, polling, CSR finalization, and
// certificate chain download. Clears every published HTTP-01 token via `defer` on every exit path,
// and resets `out_fullchain_pem` on failure.
fn acme_obtain_cert_http01<Hook>(
    sess:              Session&,
    acme:              AcmeSession&,
    account_priv:      const u8[32]&,
    cert_priv:         const u8[32]&,
    cfg:               const AcmeClientConfig&,
    domains:           const u8[..255][:],
    hook:              Hook&,
    out_fullchain_pem: u8[>..]&,
) -> bool {
    out_fullchain_pem.clear();
    var committed = false;
    defer if !committed { out_fullchain_pem.clear(); };

    var thumbprint: u8[..64] = [];
    var csr_der:    u8[>..]  = [];
    guard prepare_acme_order_inputs(
        sess, acme, account_priv, cert_priv, cfg, domains, thumbprint, csr_der,
    ) else {
        return false;
    }

    var order = auth::AcmeOrder { .. };
    guard create_acme_order(sess, acme, account_priv, domains, order) else { return false; }

    var published_tokens: u8[..128][..8] = [];
    defer {
        for &tok in published_tokens {
            acme_clear_http01(hook, tok[..]);
        }
    };

    guard run_http01_authorizations(
        sess, acme, account_priv, thumbprint[..], order.authz_urls[..], hook, published_tokens,
    ) else {
        return false;
    }
    guard poll_acme_order_until(sess, acme, account_priv, cfg, AcmePollTarget.ReadyOrValid, order) else {
        return false;
    }
    if order.status == auth::AcmeOrderStatus.Ready {
        guard finalize_acme_order(sess, acme, account_priv, csr_der[..], order) else { return false; }
    }
    guard poll_acme_order_until(sess, acme, account_priv, cfg, AcmePollTarget.ValidOnly, order) else {
        return false;
    }
    guard download_acme_cert_pem(sess, acme, account_priv, order.certificate_url[..], out_fullchain_pem) else {
        return false;
    }

    committed = true;
    return true;
}
