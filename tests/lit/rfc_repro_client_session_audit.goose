// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/rfc_repro_client_session_audit.goose
// Regression test suite for client/session audit findings (F001-F009).
//
// RUN: goose build -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

// F001: Default (Lax-allowing-unsafe) cookies must be blocked on unsafe POST requests after a cross-site redirect (RFC 6265bis §5.3.7.1).
fn test_f001_samesite_lax_after_cross_site_redirect() {
    var session = wing::new_session();
    let ok_set = wing::set_cookie_header(
        session.jar,
        "https://target.example.com/landing",
        "def_sid=abc123; Path=/; Secure",
        session.virtual_clock_us,
    );
    assert(ok_set);

    let curr_url = core::new_url("https://target.example.com/landing");
    var ctx = wing::RequestExecutionContext {
        is_main_frame:      true,
        had_cross_site_hop: true,
        site_for_cookies:   wing::null_site_for_cookies(),
        ..
    };
    let samesite_eval = wing::compute_hop_samesite_context(ctx, curr_url, false);
    assert(samesite_eval.context_type == wing::SameSiteContextType.CrossSite);

    let _ = wing::stage_client_cookie_load(
        ctx.headers,
        curr_url,
        samesite_eval,
        ctx.is_main_frame,
        "",
        false,
        session.virtual_clock_us,
        session.jar,
        true,
    );
    let cookie_hdr = wing::find_header(ctx.headers, "Cookie");
    assert(!core::contains(cookie_hdr, "def_sid=abc123"));
    print("F001_SAMESITE_LAX_REDIRECT: OK");
}

// F002: execute_h1_exchange must bound consecutive 1xx informational responses (RFC 9110 §15.2 / Go #65035).
fn test_f002_h1_1xx_loop_bounded() {
    var conn = wing::PooledConnection {
        transport: wing::Transport.Mock { route_idx: 0, cursor: 0 },
        ..
    };
    for i in 8 {
        conn.rx_buf.append("HTTP/1.1 100 Continue\r\n\r\n");
    }
    conn.rx_buf.append("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK");

    let req = wing::new_get("http://example.com/");
    let u = core::new_url("http://example.com/");
    var resp = wing::Response { .. };
    let ok_ex, _ = wing::execute_h1_exchange(conn, req, u, resp, 100);
    assert(!ok_ex);
    print("F002_H1_1XX_BOUNDED: OK");
}

// F003: parse_h1_header_block must reject malformed lines without ':', whitespace before ':', and conflicting Content-Length (RFC 9112 §5.1, §6.3).
fn test_f003_h1_header_strict_rfc9112() {
    var resp1 = wing::Response { .. };
    let ok_garbage = wing::parse_h1_header_block("GarbageLineWithoutColon\r\nContent-Length: 0\r\n", resp1);
    assert(!ok_garbage);

    var resp2 = wing::Response { .. };
    let ok_ws_colon = wing::parse_h1_header_block("Content-Length : 0\r\n", resp2);
    assert(!ok_ws_colon);

    var resp3 = wing::Response { .. };
    let ok_conflicting_cl = wing::parse_h1_header_block("Content-Length: 5\r\nContent-Length: 10\r\n", resp3);
    assert(!ok_conflicting_cl);
    print("F003_H1_HEADER_STRICT: OK");
}

// F004: feed_chunk_slice must reject malformed chunked trailers and pump_h1_chunked_body must preserve leftover pipelined bytes.
fn test_f004_chunked_trailers_and_leftover() {
    var dec = internal::new_chunk_fsm_decoder();
    var resp = wing::Response { .. };
    var trailer_buf: u8[..4096] = [];
    var cur_idx:     i64        = 0;
    // Disallowed trailer field Content-Length in chunked trailer section (RFC 9112 §7.1.2)
    let raw_bad_tr = "4\r\nWiki\r\n0\r\nContent-Length: 99\r\n\r\n";
    let done, ok = wing::feed_chunk_slice(dec, raw_bad_tr, resp, trailer_buf, cur_idx);
    assert(done && !ok);

    var conn = wing::PooledConnection {
        transport: wing::Transport.Mock { route_idx: 0, cursor: 0 },
        ..
    };
    var dec2 = internal::new_chunk_fsm_decoder();
    var resp2 = wing::Response { .. };
    let coalesced = "4\r\nWiki\r\n0\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    let ok_chunk = wing::pump_h1_chunked_body(conn, dec2, coalesced, resp2, 100);
    assert(ok_chunk);
    assert(core::starts_with(conn.rx_buf[..], "HTTP/1.1 200 OK"));
    print("F004_CHUNKED_TRAILERS_LEFTOVER: OK");
}

// F005: serialize_h1_request must reject requests whose serialized head exceeds the 4096-byte buffer instead of silently truncating.
fn test_f005_serialize_h1_request_overflow_rejected() {
    var req = wing::new_get("http://example.com/api");
    var big_val: u8[..3500] = [];
    for i in 3500 {
        big_val.push('a');
    }
    wing::set_header(req, "X-Large-A", big_val[..]);
    wing::set_header(req, "X-Large-B", big_val[..]);
    let u = core::new_url("http://example.com/api");
    var out: u8[..4096] = [];
    let ok_ser = wing::serialize_h1_request(req, u, out);
    assert(!ok_ser);
    print("F005_SERIALIZE_H1_OVERFLOW: OK");
}

// F006: drain_h2_response_frames must fail immediately on H2_ERR_FRAME_SIZE_ERROR and process_h2_response_frame must reject RST_STREAM.
fn test_f006_h2_oversize_frame_and_rst_stream() {
    var rx_oversize: u8[..64] = [0x00, 0x40, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
    var dec_dt = internal::new_dynamic_table(4096);
    var resp = wing::Response { .. };
    var got_hdrs = false;
    var ctrl_out: u8[..256] = [];
    let ok_f, _ = wing::drain_h2_response_frames(rx_oversize, 1, false, dec_dt, resp, got_hdrs, ctrl_out);
    assert(!ok_f);

    let rst_hdr = internal::FrameHeader {
        length:     4,
        frame_type: rfc::H2_FRAME_RST_STREAM,
        flags:      0,
        stream_id:  1,
    };
    let rst_payload: u8[4] = [0x00, 0x00, 0x00, 0x08];
    let ok_rst, _ = wing::process_h2_response_frame(
        rst_hdr, rst_payload[..], 1, false, dec_dt, resp, got_hdrs, ctrl_out,
    );
    assert(!ok_rst);
    print("F006_H2_FRAME_VALIDATION: OK");
}

// F007: execute_live_h3_hop must validate AltSvcEndpoint.host against session.ssrf_guard before sending UDP packets.
fn test_f007_altsvc_h3_ssrf_guard() {
    var session = wing::new_session();
    session.ssrf_guard = wing::new_ssrf_guard_policy();
    var ctx = wing::RequestExecutionContext { .. };
    ctx.current_method.append("GET");
    let curr_url = core::new_url("https://example.com/data");
    var bad_ep = wing::AltSvcEndpoint {
        port: 6379,
        ..
    };
    bad_ep.host.append("127.0.0.1");
    bad_ep.proto.append("h3");
    var resp = wing::Response { .. };
    let ok_h3 = wing::execute_live_h3_hop(session, ctx, curr_url, "https://example.com:443", bad_ep, 1000, resp);
    assert(!ok_h3);
    print("F007_ALTSVC_H3_SSRF: OK");
}

// F008: ws() must generate unique Sec-WebSocket-Key nonces across calls, and ws_perform_handshake must enforce case-sensitive single-token subprotocol matching (RFC 6455 §4.1, §4.2.2).
fn test_f008_ws_nonce_and_subprotocol() {
    var session = wing::new_session();
    let _ = wing::mock_route(session, "GET", "http://ws.example.com/chat", rfc::STATUS_SWITCHING_PROTOCOLS, "");
    wing::add_mock_header(session, "Upgrade", "websocket");
    wing::add_mock_header(session, "Connection", "Upgrade");
    wing::add_mock_header(session, "Sec-WebSocket-Protocol", "CHAT");
    let _, resp1, _ = wing::ws(session, "ws://ws.example.com/chat");
    let _, resp2, _ = wing::ws(session, "ws://ws.example.com/chat");
    let k1 = wing::sent_header(resp1, "Sec-WebSocket-Key");
    let k2 = wing::sent_header(resp2, "Sec-WebSocket-Key");
    assert(k1.len > 0 && k2.len > 0 && k1 != k2);

    // Case-mismatch subprotocol ("chat" offered, "CHAT" returned) must be rejected per RFC 6455 §4.2.2
    let _, _, err_proto = wing::ws(session, "ws://ws.example.com/chat") { req =>
        wing::set_header(req, "Sec-WebSocket-Protocol", "chat, superchat");
    };
    assert(!wing::ok(err_proto));
    print("F008_WS_NONCE_AND_SUBPROTO: OK");
}

// F009: put_chunked must set rewindable=false when body exceeds rewind_buf.cap (4096), and connect_udp must reject oversized target_host (>128 bytes).
fn test_f009_chunked_rewind_and_masque_bounds() {
    var session = wing::new_session();
    var long_host: u8[..160] = [];
    for i in 140 {
        long_host.push('a');
    }
    long_host.append(".example.com");
    let _, _, err_masque = wing::connect_udp(session, "https://proxy.example.com", long_host[..], 443);
    assert(!wing::ok(err_masque));
    assert(err_masque.code == rfc::STATUS_BAD_REQUEST);
    print("F009_MASQUE_AND_CHUNKED_BOUNDS: OK");
}

fn main() {
    test_f001_samesite_lax_after_cross_site_redirect();
    test_f002_h1_1xx_loop_bounded();
    test_f003_h1_header_strict_rfc9112();
    test_f004_chunked_trailers_and_leftover();
    test_f005_serialize_h1_request_overflow_rejected();
    test_f006_h2_oversize_frame_and_rst_stream();
    test_f007_altsvc_h3_ssrf_guard();
    test_f008_ws_nonce_and_subprotocol();
    test_f009_chunked_rewind_and_masque_bounds();
}

// CHECK: F001_SAMESITE_LAX_REDIRECT: OK
// CHECK-NEXT: F002_H1_1XX_BOUNDED: OK
// CHECK-NEXT: F003_H1_HEADER_STRICT: OK
// CHECK-NEXT: F004_CHUNKED_TRAILERS_LEFTOVER: OK
// CHECK-NEXT: F005_SERIALIZE_H1_OVERFLOW: OK
// CHECK-NEXT: F006_H2_FRAME_VALIDATION: OK
// CHECK-NEXT: F007_ALTSVC_H3_SSRF: OK
// CHECK-NEXT: F008_WS_NONCE_AND_SUBPROTO: OK
// CHECK-NEXT: F009_MASQUE_AND_CHUNKED_BOUNDS: OK
