// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal HTTP/3 request encoding and live UDP datagram hop execution.
namespace client_internal;

import std;
import core;
import rfc.http;
import rfc.h3_quic;
import fingerprint.profile;
import http.response;
import http.headers;
import http.altsvc;
import security.ssrf;
import net.internal;
import net.tcp;
import net.udp;
import http3.connection;
import client.client;
import .dns_dial_internal;
import .hop_context_internal;
import .stage_bricks_internal;

fn encode_h3_request<B>(
    h3_conn:     http3::Connection&,
    sid:         u64,
    ctx:         const RequestExecutionContext&,
    current_url: const core::Url&,
    out:         B&,
) -> bool {
    var path_buf: u8[..2048] = [];
    guard format_h2_request_target_path(current_url, path_buf) else { return false; }

    let saved_conn = copy(h3_conn);
    var committed = false;
    defer if !committed { out.clear(); h3_conn = copy(saved_conn); };
    out.clear();

    let has_body = ctx.body.len > 0;
    guard http3::send_request_headers(
        h3_conn, sid, ctx.current_method[..], current_url.scheme(), current_url.host(),
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

fn populate_h3_response_from_stream(
    h3_conn:     const http3::Connection&,
    sid:         u64,
    status_code: i32,
    current_url: const core::Url&,
    sent_hdrs:   const http::HeaderMap&,
    resp:        http::Response&,
) {
    http::reset_response(resp);
    resp.status_code = status_code;
    let _ = resp.protocol.try_set("HTTP/3");
    let _ = http3::copy_stream_headers(h3_conn, sid, resp.headers);
    for &e in resp.headers.entries {
        http::update_response_presence(resp, http::entry_name(resp.headers, e));
    }
    let _ = http3::copy_stream_trailers(h3_conn, sid, resp.trailers);
    let body_slice, ok_b = http3::get_response_body(h3_conn, sid);
    if ok_b { resp.body.append(body_slice); }
    resp.effective_url = copy(current_url.href);
    http::copy_headers(sent_hdrs, resp.sent_headers);
}

// Executes an Unencrypted H3 over UDP (Datagram Direct) client hop (RFC 9114 framing + QPACK)
// when racing against a direct HTTP/3 UDP endpoint (`serve_h3` / `handle_h3_server_datagram`).
// For encrypted RFC 9000 + RFC 9001 TLS 1.3 QUIC v1 sessions, use `QuicConnection` + `H3Connection`.
fn execute_live_h3_hop(
    session:     client::Session&,
    ctx:         RequestExecutionContext&,
    current_url: const core::Url&,
    origin_buf:  const u8[:],
    h3_ep:       const http::AltSvcEndpoint&,
    now_sec:     i64,
    resp:        http::Response&,
) -> bool {
    // Unencrypted raw UDP datagram framing must never be used to fulfill https:// origins.
    guard !current_url.is_secure_scheme() else { return false; }

    let target_host = if h3_ep.host.len > 0 { h3_ep.host[..] } else { current_url.hostname() };
    let target_port = if h3_ep.port > 0 { h3_ep.port } else { current_url.effective_port() as u16 };
    if session.ssrf_guard.enabled {
        let blk_priv = session.ssrf_guard.deny_local_network && security::is_private_or_reserved_ip(target_host);
        if blk_priv || security::is_cloud_metadata_or_reserved_ip(target_host) ||
            security::is_dangerous_service_port(target_port) {
            return false;
        }
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
    let sent = net_internal::native_udp_sendto(udp_fd, req_wire[..], target_host, target_port);
    guard sent > 0 else { return false; }
    var rx_buf:    u8[1472] = [0; 1472];
    var peer_ip4:  u32      = 0;
    var peer_port: u16      = 0;
    let eff_timeout = calc_effective_timeout_ms(session.timeout_ms, ctx.timeout_ms);
    let recvd = net::udp_recvfrom(udp_fd, rx_buf[..], min(eff_timeout, 250), peer_ip4, peer_port);
    guard recvd > 0 else { return false; }

    let h_err = http3::handle_stream_data(h3_conn, sid, true, rx_buf[..recvd], true);
    guard h_err == rfc::H3_ERR_NO_ERROR else { return false; }
    let sc, ok_sc = http3::get_status_code(h3_conn, sid);
    guard ok_sc else { return false; }

    populate_h3_response_from_stream(h3_conn, sid, sc, current_url, ctx.headers, resp);
    ingest_transport_response_headers(
        session, current_url, false, origin_buf, current_url.pathname(), now_sec, resp,
    );
    return true;
}
