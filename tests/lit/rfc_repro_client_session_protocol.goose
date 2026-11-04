// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/rfc_repro_client_session_protocol.goose
// Regression tests for client session execution, protocol verbs, SSRF, and 1xx handling.
//
// RUN: goose build -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

fn test_1xx_empty_body_status() {
    assert(rfc::is_empty_body_status(rfc::STATUS_CONTINUE));
    assert(rfc::is_empty_body_status(rfc::STATUS_SWITCHING_PROTOCOLS));
    assert(rfc::is_empty_body_status(rfc::STATUS_EARLY_HINTS));
    assert(rfc::is_empty_body_status(rfc::STATUS_NO_CONTENT));
    assert(rfc::is_empty_body_status(rfc::STATUS_NOT_MODIFIED));
    assert(!rfc::is_empty_body_status(rfc::STATUS_OK));
    assert(!rfc::is_empty_body_status(rfc::STATUS_BAD_REQUEST));
    print("CHECK_1XX_EMPTY_BODY: OK");
}

fn test_sse_content_type_validation() {
    assert(wing::is_sse_content_type("text/event-stream"));
    assert(wing::is_sse_content_type("text/event-stream; charset=utf-8"));
    assert(wing::is_sse_content_type("Text/Event-Stream; boundary=something"));
    assert(wing::is_sse_content_type("text/event-stream \t"));
    assert(!wing::is_sse_content_type("text/event-stream-custom"));
    assert(!wing::is_sse_content_type("application/json"));
    assert(!wing::is_sse_content_type(""));
    print("CHECK_SSE_CONTENT_TYPE: OK");
}

fn test_ws_header_tokens() {
    assert(wing::header_has_token("websocket, upgrade", "websocket"));
    assert(wing::header_has_token("keep-alive, upgrade", "upgrade"));
    assert(wing::header_has_token("Upgrade", "upgrade"));
    assert(!wing::header_has_token("non-upgrade", "upgrade"));
    assert(!wing::header_has_token("websocket-stream", "websocket"));
    print("CHECK_WS_TOKENS: OK");
}

fn test_multihop_redirect_body_clear() {
    var session = wing::new_session();
    var ctx = wing::RequestExecutionContext { .. };
    ctx.body.append("initial_body");
    ctx.rewind_buf.append("initial_body");
    ctx.rewindable = true;

    // Hop 1: 303 See Other (must clear body and rewind buffer)
    var red_303 = wing::RedirectInfo { .. };
    red_303.new_method.append("GET");
    red_303.clear_body = true;

    let err_303 = wing::apply_redirect_transition(session, ctx, red_303);
    assert(wing::ok(err_303));
    assert(ctx.body.len == 0);
    assert(ctx.rewind_buf.len == 0);
    assert(!ctx.rewindable);
    print("CHECK_MULTIHOP_BODY_CLEAR: OK");
}

fn test_multihop_no_resurrect() {
    var session = wing::new_session();
    var ctx = wing::RequestExecutionContext { .. };
    ctx.body.append("initial_payload");
    ctx.rewind_buf.append("initial_payload");
    ctx.rewindable = true;

    // Hop 1: 303 See Other
    var red_303 = wing::RedirectInfo { .. };
    red_303.new_method.append("GET");
    red_303.clear_body = true;
    let _ = wing::apply_redirect_transition(session, ctx, red_303);

    // Hop 2: 307 Temporary Redirect with body_consumed = true
    ctx.body_consumed = true;
    var red_307 = wing::RedirectInfo { .. };
    red_307.new_method.append("GET");
    red_307.clear_body = false;

    let err_307 = wing::apply_redirect_transition(session, ctx, red_307);
    assert(!wing::ok(err_307));
    assert(err_307.code == rfc::STATUS_BAD_REQUEST);
    print("CHECK_MULTIHOP_NO_RESURRECT: OK");
}

fn test_ssrf_6to4_three_octet() {
    // 2002:c000:0200:: = 192.0.2.0 (TEST-NET-1)
    assert(wing::is_private_or_reserved_ip("2002:c000:0200::1"));
    // 2002:c633:6400:: = 198.51.100.0 (TEST-NET-2)
    assert(wing::is_private_or_reserved_ip("2002:c633:6400::1"));
    // 2002:cb00:7100:: = 203.0.113.0 (TEST-NET-3)
    assert(wing::is_private_or_reserved_ip("2002:cb00:7100::1"));
    // 2002:c058:6300:: = 192.88.99.0 (6to4 Relay Anycast)
    assert(wing::is_private_or_reserved_ip("2002:c058:6300::1"));
    // Public IP via 6to4: 8.8.8.8 = 0808:0808
    assert(!wing::is_private_or_reserved_ip("2002:0808:0808::1"));
    print("CHECK_SSRF_6TO4: OK");
}

fn test_drain_rx_buf() {
    var rx: u8[..8192] = [];
    rx.append("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n\r\n");
    wing::drain_rx_buf(rx, 25);
    assert(core::starts_with(rx[..], "HTTP/1.1 200 OK"));
    print("CHECK_DRAIN_RX: OK");
}

fn main() {
    test_1xx_empty_body_status();
    test_sse_content_type_validation();
    test_ws_header_tokens();
    test_multihop_redirect_body_clear();
    test_multihop_no_resurrect();
    test_ssrf_6to4_three_octet();
    test_drain_rx_buf();
}

// CHECK: CHECK_1XX_EMPTY_BODY: OK
// CHECK-NEXT: CHECK_SSE_CONTENT_TYPE: OK
// CHECK-NEXT: CHECK_WS_TOKENS: OK
// CHECK-NEXT: CHECK_MULTIHOP_BODY_CLEAR: OK
// CHECK-NEXT: CHECK_MULTIHOP_NO_RESURRECT: OK
// CHECK-NEXT: CHECK_SSRF_6TO4: OK
// CHECK-NEXT: CHECK_DRAIN_RX: OK
