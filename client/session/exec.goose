// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Execution pipeline, redirect state machine, and hop orchestration (Chromium net::URLRequest 6-phase pipeline).
namespace client;

import std;
import core from "../..";
import rfc.http;
import rfc.h2;
import rfc.h3_quic;
import cookie.constants;
import cookie.policy;
import fingerprint.profile;
import http.request;
import http.response;
import http.headers;
import http.altsvc;
import http.compression_dict;
import auth.digest;
import security.privacypass;
import security.ssrf;
import net.pool;
import net.proxy;
import net.retry;
import net.transport;
import http2.framing;
import http2.hpack;
import http3.connection;
import wire.types;
import wire.h1_exchange;
import wire.h2;
import client.redirect;
import client.interceptor;
import client.client;
import client.internal;
import client.session.cookie_bridge;
import client.session.stages;
import .internal;

// ---- url resolution helpers ------------------------------------------------

// Appends query parameters to a URL buffer, preserving trailing fragment if present (RFC 3986 Section 4.1).
fn append_query_params_preserving_fragment<B>(
    out:          B&,
    query_params: const http::QueryItem[:],
) {
    guard query_params.len > 0 else { return; }

    var hash_pos = -1;
    var has_query_mark = false;
    for scan_idx in out.len {
        let b = out[scan_idx];
        if b == '?' && hash_pos < 0 { has_query_mark = true; }
        else if b == '#' && hash_pos < 0 { hash_pos = scan_idx; }
    }

    var hash_buf: u8[..2048] = [];
    if hash_pos >= 0 {
        let _ = hash_buf.try_set(out[hash_pos..]);
        out.resize(hash_pos);
    }

    for &query_item, param_idx in query_params {
        let sep: u8 = if param_idx == 0 && !has_query_mark { '?' } else { '&' };
        guard client_internal::append_single_query_param(query_item, sep, out) else { break; }
    }

    if hash_buf.len > 0 {
        let _ = out.try_append(hash_buf[..]);
    }
}

// Builds the effective request URL from base_url, req_url, and query_params.
// Fragments are preserved and appended after query parameters (RFC 3986 Section 4.1).
fn build_effective_url<B>(
    base_url:     const u8[:],
    req_url:      const u8[:],
    query_params: const http::QueryItem[:],
    out:          B&,
) {
    out.clear();
    let parsed_base = core::new_url(base_url);
    if parsed_base.valid {
        let eff_url = parsed_base.resolve_endpoint(req_url);
        let _ = out.try_append(eff_url.href[..]);
    } else if req_url.starts_with_fold("http://") || req_url.starts_with_fold("https://") {
        let _ = out.try_append(req_url);
    } else {
        let _ = out.try_append(base_url);
        if base_url.len > 0 && base_url[base_url.len - 1] != '/' && (req_url.len == 0 || req_url[0] != '/') {
            let _ = out.try_push('/');
        }
        let _ = out.try_append(req_url);
    }

    append_query_params_preserving_fragment(out, query_params);
}

// ---- 6-phase execution context & redirect transition -----------------------

struct RequestExecutionContext {
    url_chain:           core::Url[..16]             = [],
    current_method:      u8[..16]                    = [],
    headers:             http::HeaderMap             = http::HeaderMap { .. },
    rewind_buf:          u8[..4096]                  = [],
    rewindable:          bool                        = true,
    body_consumed:       bool                        = false,
    initiator:           core::Origin                = core::Origin { .. },
    has_initiator:       bool                        = false,
    top_frame_origin:    core::Origin                = core::Origin { .. },
    site_for_cookies:    http::SiteForCookies        = http::SiteForCookies { .. },
    first_party_policy:  cookie::FirstPartyURLPolicy = cookie::FirstPartyURLPolicy.UPDATE_FIRST_PARTY_URL_ON_REDIRECT,
    is_main_frame:       bool                        = true,
    is_reload:           bool                        = false,
    redirect_mode:       RedirectMode                = RedirectMode.Follow,
    redirect_count:      i64                         = 0,
    max_redirects:       i64                         = 10,
    tainted_origin:      bool                        = false,
    had_cross_site_hop:  bool                        = false,
    cors_mode:           bool                        = false,
    auth_retried:        bool                        = false,
    early_data_disabled: bool                        = false,

    current_referrer:        u8[..2048]     = [],
    current_referrer_policy: ReferrerPolicy = ReferrerPolicy.StrictOriginWhenCrossOrigin,
    timeout_ms:              i64            = 0,
    body:                    u8[>..]        = [],
}

fn apply_redirect_transition(
    session:       const Session&,
    ctx:           RequestExecutionContext&,
    redirect_info: const RedirectInfo&,
) -> http::Error {
    if !redirect_info.clear_body && !ctx.rewindable && (ctx.body_consumed || ctx.body.len > 0) {
        return http::make_error(rfc::STATUS_BAD_REQUEST, "body_rewind", "http: cannot rewind body");
    }
    guard redirect_info.new_method.len <= ctx.current_method.cap &&
        redirect_info.new_referrer.len <= ctx.current_referrer.cap else {
        return http::make_error(rfc::STATUS_BAD_REQUEST, "redirect", "redirect state exceeds capacity");
    }

    ctx.had_cross_site_hop = ctx.had_cross_site_hop || redirect_info.is_cross_site_tainted;
    if ctx.cors_mode && redirect_info.is_cross_origin && ctx.url_chain.len > 0 {
        let prev_idx = core::sub_sat_i64(ctx.url_chain.len, 1);
        let prev_orig = core::origin_from_url(ctx.url_chain[prev_idx]);
        if !ctx.has_initiator || !core::is_same_origin(ctx.initiator, prev_orig) {
            ctx.tainted_origin = true;
        }
    }
    if ctx.is_main_frame && ctx.first_party_policy == cookie::FirstPartyURLPolicy.UPDATE_FIRST_PARTY_URL_ON_REDIRECT {
        ctx.top_frame_origin = core::origin_from_url(redirect_info.new_url);
    }
    ctx.site_for_cookies = redirect_info.new_site_for_cookies;
    ctx.auth_retried = false;
    let _ = ctx.current_method.try_set(redirect_info.new_method[..]);
    let _ = ctx.current_referrer.try_set(redirect_info.new_referrer[..]);
    ctx.current_referrer_policy = redirect_info.new_referrer_policy;

    if redirect_info.clear_body {
        ctx.body.clear();
        ctx.rewind_buf.clear();
        ctx.rewindable = false;
        ctx.body_consumed = false;
    } else {
        ctx.body.clear();
        ctx.body.append(ctx.rewind_buf[..]);
        ctx.body_consumed = false;
    }

    let is_trusted = client_internal::is_trusted_location_host(session, redirect_info.new_url.hostname());
    sanitize_headers_on_redirect(
        ctx.headers,
        redirect_info,
        RedirectSanitizeOptions {
            cors_mode:                   ctx.cors_mode,
            tainted_origin:              ctx.tainted_origin,
            enable_referer:              session.enable_referer,
            trusted_location_forwarding: is_trusted,
        },
    );
    return http::Error { .. };
}

fn init_execution_context(
    session:        const Session&,
    req:            const http::Request&,
    parsed_initial: const core::Url&,
) -> RequestExecutionContext {
    var ctx = RequestExecutionContext {
        current_method:          copy(req.method),
        rewindable:              req.rewindable,
        body_consumed:           false,
        early_data_disabled:     req.disallow_early_data,
        cors_mode:               req.cors_mode,
        tainted_origin:          req.tainted_origin,
        is_main_frame:           req.is_main_frame,
        is_reload:               req.is_reload,
        redirect_mode:           session.redirect_mode,
        redirect_count:          0,
        max_redirects:           session.max_redirects,
        first_party_policy:      req.first_party_policy,
        current_referrer_policy: session.default_referrer_policy,
        timeout_ms:              req.timeout,
        ..
    };

    let req_ref = http::header(req, "Referer");
    if req_ref.len > 0 {
        let _ = ctx.current_referrer.try_set(req_ref);
    }

    ctx.body.append(req.body[..]);
    if req.rewind_buf.len > 0 {
        let _ = ctx.rewind_buf.try_set(req.rewind_buf[..]);
    } else if req.rewindable && req.body.len <= 4096 {
        let _ = ctx.rewind_buf.try_set(req.body[..]);
    } else if ctx.body.len > 0 {
        ctx.rewindable = false;
    }

    if req.has_initiator {
        ctx.initiator = copy(req.initiator);
        ctx.has_initiator = true;
    } else {
        ctx.initiator = core::origin_from_url(parsed_initial);
        ctx.has_initiator = true;
    }

    if ctx.top_frame_origin.host.len == 0 {
        ctx.top_frame_origin = core::origin_from_url(parsed_initial);
    }

    if req.has_site_for_cookies {
        ctx.site_for_cookies = copy(req.site_for_cookies);
    } else {
        ctx.site_for_cookies = cookie::site_for_cookies_from_parsed_url(parsed_initial);
    }

    client_internal::merge_session_and_request_headers(
        ctx.headers, session.default_headers, req.headers, session.profile,
    );
    client_internal::sanitize_initial_request_referrer(session, ctx, parsed_initial);
    let _ = ctx.url_chain.try_push(parsed_initial);
    return ctx;
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

// ---- pooled H1, H2, and H3 hop engines -------------------------------------

fn dispatch_pooled_h1_hop(
    session:     Session&,
    conn_id:     i32,
    curr_method: const u8[:],
    ctx:         RequestExecutionContext&,
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

    var hop_req = http::Request { .. };
    let _ = hop_req.method.try_set(curr_method);
    http::copy_headers(ctx.headers, hop_req.headers);
    hop_req.body.append(ctx.body[..]);

    let eff_timeout = client_internal::calc_effective_timeout_ms(session.timeout_ms, ctx.timeout_ms);
    let ok_ex, keep_alive = wing::execute_h1_exchange(
        session.pool.conns[c_idx],
        hop_req,
        current_url,
        resp,
        eff_timeout,
    );
    guard ok_ex else { return false; }

    resp.effective_url = copy(current_url.href);
    http::copy_headers(ctx.headers, resp.sent_headers);
    client_internal::ingest_transport_response_headers(
        session, current_url, is_https, origin_buf, curr_path, now_sec, resp,
    );
    if keep_alive && resp.is_http1() && resp.status_code != rfc::STATUS_SWITCHING_PROTOCOLS {
        session.pool.release_connection(conn_id, now_ns);
        released = true;
    }
    return true;
}

fn resolve_hop_proxy_chain(session: const Session&) -> net::ProxyChain {
    if session.proxy_url.len == 0 {
        return net::new_direct_proxy_chain();
    }
    let p_url = core::new_url(session.proxy_url[..]);
    guard p_url.valid else { return net::new_direct_proxy_chain(); }
    let p_scheme = if p_url.scheme() == "https" {
        net::ProxyScheme.Https
    } else if p_url.scheme() == "socks5h" {
        net::ProxyScheme.Socks5h
    } else if p_url.scheme() == "socks5" {
        net::ProxyScheme.Socks5
    } else {
        net::ProxyScheme.Http
    };
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
    return net::new_single_proxy_chain(ps);
}

enum H2RecvStatus {
    Continue,
    Complete,
    Error,
}

struct H2RecvState {
    got_hdrs:   bool               = false,
    saw_goaway: bool               = false,
    await_cont: bool               = false,
    cont_hdr:   http2::FrameHeader = http2::FrameHeader { .. },
    cont_buf:   u8[..16384]        = [],
}

fn encode_h2_request<B>(
    curr_method:  const u8[:],
    current_url:  const core::Url&,
    is_https:     bool,
    ctx:          const RequestExecutionContext&,
    enc_dt:       http2::DynamicTable&,
    stream_id:    u32,
    send_preface: bool,
    out:          B&,
) -> bool {
    guard ctx.body.len <= (rfc::H2_DEFAULT_WINDOW_SIZE as i64) else { return false; }
    let pseudo, ok_pseudo = client_internal::build_h2_request_pseudo_headers(
        curr_method, current_url, is_https, ctx.headers,
    );
    guard ok_pseudo else { return false; }

    let saved_dt = copy(enc_dt);
    var committed = false;
    defer if !committed { out.clear(); enc_dt = copy(saved_dt); };
    out.clear();

    if send_preface {
        guard out.try_append(rfc::H2_CLIENT_PREFACE) else { return false; }
        let empty_settings: wire::WireSetting[..1] = [];
        guard wire::encode_settings_frame(empty_settings[..], out) else { return false; }
    }
    guard wire::encode_h2_headers_frame_from_map(
        enc_dt, stream_id, pseudo, ctx.headers, ctx.body.len == 0, out, 16384,
    ) else { return false; }
    var rem = ctx.body[..];
    while rem.len > 0 {
        let chunk_len = min(rem.len, rfc::H2_DEFAULT_MAX_FRAME_SIZE as i64);
        guard wire::encode_data_frame(stream_id, rem[..chunk_len], chunk_len >= rem.len, out) else {
            return false;
        }
        rem = rem[chunk_len..];
    }
    committed = true;
    return true;
}

fn process_h2_response_frame<B>(
    hdr:       const http2::FrameHeader&,
    payload:   const u8[:],
    stream_id: u32,
    is_head:   bool,
    dec_dt:    http2::DynamicTable&,
    resp:      http::Response&,
    state:     H2RecvState&,
    out_ctrl:  B&,
) -> H2RecvStatus {
    if state.await_cont {
        return client_internal::process_h2_continuation_frame(hdr, payload, stream_id, is_head, dec_dt, resp, state);
    }
    guard hdr.frame_type != rfc::H2_FRAME_CONTINUATION else { return H2RecvStatus.Error; }
    if hdr.stream_id == 0 && (hdr.frame_type == rfc::H2_FRAME_SETTINGS || hdr.frame_type == rfc::H2_FRAME_PING) {
        client_internal::process_h2_control_frame(hdr, payload, out_ctrl);
        return H2RecvStatus.Continue;
    }
    if hdr.frame_type == rfc::H2_FRAME_RST_STREAM && hdr.stream_id == stream_id {
        client_internal::record_h2_rst_stream_error(payload, resp);
        return H2RecvStatus.Error;
    }
    if hdr.frame_type == rfc::H2_FRAME_GOAWAY {
        guard hdr.stream_id == 0 && payload.len >= 8 && (core::read_be_u32(payload, 0) & 0x7FFFFFFF) >= stream_id else {
            return H2RecvStatus.Error;
        }
        state.saw_goaway = true;
        return H2RecvStatus.Continue;
    }
    if hdr.frame_type == rfc::H2_FRAME_WINDOW_UPDATE { return H2RecvStatus.Continue; }
    let saved_resp = copy(resp);
    let saved_state = state;
    let saved_dt = copy(dec_dt);
    var committed = false;
    defer if !committed { resp = copy(saved_resp); state = saved_state; dec_dt = copy(saved_dt); };
    if hdr.frame_type == rfc::H2_FRAME_HEADERS && hdr.stream_id == stream_id {
        let st = client_internal::process_h2_response_headers_frame(hdr, payload, is_head, dec_dt, resp, state);
        guard st != H2RecvStatus.Error else { return H2RecvStatus.Error; }
        committed = true;
        return st;
    }
    if hdr.frame_type == rfc::H2_FRAME_DATA && hdr.stream_id == stream_id {
        guard state.got_hdrs else { return H2RecvStatus.Error; }
        let d_slice, d_err = http2::extract_padded_frame_payload(hdr, payload);
        guard d_err == rfc::H2_ERR_NO_ERROR else { return H2RecvStatus.Error; }
        resp.body.append(d_slice);
        if hdr.length > 0 {
            let _ = wire::encode_window_update_frame(0, hdr.length, out_ctrl);
            let _ = wire::encode_window_update_frame(stream_id, hdr.length, out_ctrl);
        }
        let end_d = (hdr.flags & rfc::H2_FLAG_END_STREAM) != 0;
        if end_d {
            guard client_internal::verify_h2_response_content_length(resp, is_head) else { return H2RecvStatus.Error; }
        }
        committed = true;
        return if end_d { H2RecvStatus.Complete } else { H2RecvStatus.Continue };
    }
    committed = true;
    return H2RecvStatus.Continue;
}

fn drain_h2_response_frames<B1, B2>(
    rx_accum:  B1&,
    stream_id: u32,
    is_head:   bool,
    dec_dt:    http2::DynamicTable&,
    resp:      http::Response&,
    state:     H2RecvState&,
    out_ctrl:  B2&,
) -> H2RecvStatus {
    var consumed: i64 = 0;
    defer rx_accum.compact_wire_buffer(consumed);
    while rx_accum.len - consumed >= 9 {
        let hdr, h_err = http2::parse_frame_header(rx_accum[consumed..], 16384);
        guard h_err == rfc::H2_ERR_NO_ERROR else { return H2RecvStatus.Error; }
        let frame_total = 9 + (hdr.length as i64);
        guard rx_accum.len - consumed >= frame_total else { break; }
        let payload = rx_accum[consumed + 9..consumed + frame_total];
        consumed += frame_total;
        let st = process_h2_response_frame(
            hdr, payload, stream_id, is_head, dec_dt, resp, state, out_ctrl,
        );
        guard st != H2RecvStatus.Error else { return H2RecvStatus.Error; }
        if st == H2RecvStatus.Complete {
            return H2RecvStatus.Complete;
        }
    }
    return H2RecvStatus.Continue;
}

fn recv_h2_response_loop(
    conn:        net::PooledConnection&,
    stream_id:   u32,
    is_head:     bool,
    eff_timeout: u32,
    resp:        http::Response&,
) -> bool {
    let saved_resp = copy(resp);
    let saved_dt = copy(conn.hpack_dec);
    var committed = false;
    defer if !committed {
        client_internal::rollback_h2_response_preserving_rst(resp, saved_resp);
        conn.hpack_dec = copy(saved_dt);
    };
    var rx_accum: u8[..65536] = [];
    if conn.rx_buf.len > 0 {
        guard rx_accum.try_append(conn.rx_buf[..]) else { return false; }
        conn.rx_buf.clear();
    }
    var chunk: u8[4096] = [0; 4096];
    var state = H2RecvState { .. };
    var is_done = false;
    var ctrl_out: u8[..4096] = [];
    for _ in 4096 {
        if rx_accum.len >= 9 {
            ctrl_out.clear();
            let st_pre = drain_h2_response_frames(
                rx_accum, stream_id, is_head, conn.hpack_dec, resp, state, ctrl_out,
            );
            guard st_pre != H2RecvStatus.Error else { return false; }
            if ctrl_out.len > 0 { let _ = wing::send_all(conn.transport, ctrl_out[..]); }
            if st_pre == H2RecvStatus.Complete { is_done = true; break; }
        }
        let n = conn.transport.recv_slice(chunk[..], eff_timeout);
        if n > 0 {
            guard rx_accum.try_append(chunk[..n]) else { return false; }
        }
        ctrl_out.clear();
        let st = drain_h2_response_frames(
            rx_accum, stream_id, is_head, conn.hpack_dec, resp, state, ctrl_out,
        );
        guard st != H2RecvStatus.Error else { return false; }
        if ctrl_out.len > 0 { let _ = wing::send_all(conn.transport, ctrl_out[..]); }
        if st == H2RecvStatus.Complete { is_done = true; break; }
        if n <= 0 { break; }
    }
    guard state.got_hdrs && is_done && !state.await_cont else { return false; }
    guard conn.rx_buf.try_set(rx_accum[..]) else { return false; }
    if state.saw_goaway {
        conn.no_new_exchanges = true;
    }
    committed = true;
    return true;
}

fn encode_h3_request<B>(
    h3_conn:     http3::Connection&,
    sid:         u64,
    ctx:         const RequestExecutionContext&,
    current_url: const core::Url&,
    out:         B&,
) -> bool {
    var path_buf: u8[..2048] = [];
    guard client_internal::format_h2_request_target_path(current_url, path_buf) else { return false; }

    let saved_conn = copy(h3_conn);
    var committed = false;
    defer if !committed { out.clear(); h3_conn = copy(saved_conn); };
    out.clear();

    let has_body = ctx.body.len > 0;
    guard http3::send_request_headers(
        h3_conn, sid, ctx.current_method[..], "https", current_url.host(),
        path_buf[..], ctx.headers, !has_body, out,
    ) else { return false; }

    if has_body {
        guard http3::send_request_data(h3_conn, sid, ctx.body[..], true, out) else {
            return false;
        }
    }
    committed = true;
    return true;
}

// Executes an Unencrypted H3 over UDP (Datagram Direct) client hop (RFC 9114 framing + QPACK)
// when racing against a direct HTTP/3 UDP endpoint (`serve_h3` / `handle_h3_server_datagram`).
// For encrypted RFC 9000 + RFC 9001 TLS 1.3 QUIC v1 sessions, use `QuicConnection` + `H3Connection`.
fn execute_live_h3_hop(
    session:     Session&,
    ctx:         RequestExecutionContext&,
    current_url: const core::Url&,
    origin_buf:  const u8[:],
    h3_ep:       const http::AltSvcEndpoint&,
    now_sec:     i64,
    resp:        http::Response&,
) -> bool {
    let target_host = if h3_ep.host.len > 0 { h3_ep.host[..] } else { current_url.hostname() };
    let target_port = if h3_ep.port > 0 { h3_ep.port } else { current_url.effective_port() as u16 };
    if session.ssrf_guard.enabled && session.ssrf_guard.deny_local_network &&
        (security::is_private_or_reserved_ip(target_host) || security::is_dangerous_service_port(target_port)) {
        return false;
    }
    let udp_fd = net::udp_bind("0.0.0.0", 0);
    guard udp_fd > 0 else { return false; }
    defer net::tcp_close(udp_fd);

    let h3_settings = fingerprint::H3Settings { .. };
    var h3_conn = http3::new_client_connection(h3_settings);
    let sid, ok_s = http3::open_request_stream(h3_conn);
    guard ok_s else { return false; }
    var req_wire: u8[..4096] = [];
    guard encode_h3_request(h3_conn, sid, ctx, current_url, req_wire) else { return false; }
    let curr_path = current_url.pathname();
    let sent = net_internal::native_udp_sendto(udp_fd, req_wire[..], target_host, target_port);
    guard sent > 0 else { return false; }
    var rx_buf:    u8[1472] = [0; 1472];
    var peer_ip4:  u32      = 0;
    var peer_port: u16      = 0;
    let eff_timeout = client_internal::calc_effective_timeout_ms(session.timeout_ms, ctx.timeout_ms);
    let recvd = net::udp_recvfrom(udp_fd, rx_buf[..], min(eff_timeout, 250), peer_ip4, peer_port);
    guard recvd > 0 else { return false; }

    let h_err = http3::handle_stream_data(h3_conn, sid, true, rx_buf[..recvd], true);
    guard h_err == rfc::H3_ERR_NO_ERROR else { return false; }
    let sc, ok_sc = http3::get_status_code(h3_conn, sid);
    guard ok_sc else { return false; }

    http::reset_response(resp);
    resp.status_code = sc;
    let _ = resp.protocol.try_set("HTTP/3");
    let _ = http3::copy_stream_headers(h3_conn, sid, resp.headers);
    for &e in resp.headers.entries {
        http::update_response_presence(resp, http::entry_name(resp.headers, e));
    }
    let _ = http3::copy_stream_trailers(h3_conn, sid, resp.trailers);
    let body_slice, ok_b = http3::get_response_body(h3_conn, sid);
    if ok_b { resp.body.append(body_slice); }
    resp.effective_url = copy(current_url.href);
    http::copy_headers(ctx.headers, resp.sent_headers);
    client_internal::ingest_transport_response_headers(
        session, current_url, true, origin_buf, curr_path, now_sec, resp,
    );
    return true;
}

// ---- 401 challenge authentication & top-level execution loop ---------------

fn compute_401_auth_header<B>(
    session:     Client&,
    ctx:         RequestExecutionContext&,
    current_url: const core::Url&,
    www_auth:    const u8[:],
    out:         B&,
) -> bool {
    var committed = false;
    defer if !committed { out.clear(); };
    out.clear();
    if client_internal::has_auth_scheme_prefix(www_auth, "Digest") {
        let chal, ok_c = auth::parse_digest_challenge(www_auth);
        guard ok_c && (!ctx.auth_retried || chal.stale) else { return false; }
        var uri_target: u8[..2048] = [];
        let _ = client_internal::format_h2_request_target_path(current_url, uri_target);
        var c_creds = auth::DigestCredentials { .. };
        let _ = c_creds.username.try_set(session.creds.username[..]);
        let _ = c_creds.password.try_set(session.creds.password[..]);

        var active_chal = chal;
        if chal.stale && session.creds.last_digest.valid {
            let _ = auth::sync_digest_stale_challenge(
                session.creds.last_digest, chal, c_creds, session.creds.nonce_counter,
            );
            active_chal = session.creds.last_digest;
        } else {
            session.creds.last_digest = chal;
        }

        let ok_d = auth::compute_digest_response(
            active_chal, c_creds, ctx.current_method[..], uri_target[..],
            session.creds.nonce_counter, session.creds.cnonce[..], ctx.body[..], out,
        );
        core::secure_zeroize_slice(c_creds.password[..]);
        guard ok_d else { return false; }
        session.creds.nonce_counter += 1;
        committed = true;
        return true;
    }
    if client_internal::has_auth_scheme_prefix(www_auth, rfc::SCHEME_PRIVATE_TOKEN) {
        var tok_key: u8[..512] = [];
        let chal, _, ok_ch = security::parse_private_token_challenge(www_auth, tok_key);
        guard ok_ch else { return false; }
        var raw_tok: u8[..512] = [];
        let now_sec = div_euclid(session.virtual_clock_us, 1000000);
        let _, ok_tok = security::get_private_token(session.private_token_cache, chal, now_sec, raw_tok);
        guard ok_tok else { return false; }
        security::format_private_token_authorization(raw_tok[..], out);
        committed = true;
        return true;
    }
    if client_internal::has_auth_scheme_prefix(www_auth, "Basic") {
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
        guard out.try_append("Basic ") && out.try_append(b64_user_pass[..]) else { return false; }
        committed = true;
        return true;
    }
    return false;
}

inline fn prepare_auth_retry_hop(
    session:       Client&,
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

inline fn should_retry_request(
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

fn execute_request(session: Client&, req: const http::Request&) -> http::Response, http::Error {
    let start_us = session.virtual_clock_us;
    let now_ns = start_us * 1000;

    let parsed_url, url_err = core::parse_url(req.url[..]);
    let target_host = if url_err == core::UrlParseError.None { parsed_url.host() } else { "" };
    if target_host.len > 0 && net::is_host_circuit_broken(session.circuit_breaker, target_host, now_ns) {
        let err_cb = http::make_error(503, "circuit_breaker", "host circuit broken by Retry-After");
        return http::Response { status_code: 503, .. }, err_cb;
    }
    net::record_primary_request(session.retry_budget, now_ns);

    let retry_pol, has_retry = find_retry_policy(session.pipeline);

    var attempts:      i32 = 0;
    var prev_sleep_ms: i64 = 0;
    var rng_seed:      u64 = (start_us as u64) ^ 0x9E3779B97F4A7C15;
    loop {
        // Phase -1: Application Interceptors (Request Hook) per attempt
        var active_req = copy(req);
        active_req.disallow_early_data = req.disallow_early_data || attempts > 0;
        apply_app_interceptors_request(session.pipeline, active_req, session.virtual_clock_us);

        var resp, err = client_internal::execute_request_inner(session, active_req);
        client_internal::evaluate_response_retry_after(session, target_host, resp, now_ns);

        let retry = should_retry_request(
            resp.status_code, err, active_req.method[..], active_req,
            attempts, has_retry, retry_pol.max_retries, retry_pol.retry_on_5xx,
        );
        if retry && net::allow_retry_budget(session.retry_budget, now_ns) {
            let sleep_ms = net::compute_backoff_jitter_ms(session.backoff_config, attempts, prev_sleep_ms, rng_seed);
            session.virtual_clock_us += sleep_ms * 1000;
            attempts += 1;
            continue;
        }

        // Phase 6: Application Interceptors (Response Hook)
        let total_dur_us = session.virtual_clock_us - start_us;
        client_internal::apply_app_interceptors_response(session.pipeline, active_req, resp, err, total_dur_us);
        client_internal::record_client_har_telemetry(session, active_req, resp, total_dur_us);
        return resp, err;
    }
    let err_fail = http::make_error(rfc::STATUS_INTERNAL_SERVER_ERROR, "client", "request execution failed");
    return http::Response { .. }, err_fail;
}
