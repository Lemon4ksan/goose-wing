// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RUN: goose build -O0 --cc gcc -o %t.exe %s && %t.exe | %FileCheck %s

import std;
import wing from "../..";

struct WsAuthStage {
    expected_auth: u8[..64] = [],
}

fn server::on_server_stage(
    stage: WsAuthStage&,
    phase: wire::ServerHookPhase,
    _cfg:  server::ServerPipelineConfig&,
    req:   const http::Request&,
    _ctx:  server::ServerStageCtx&,
    res:   http::Response&,
) -> wire::StageVerdict {
    guard phase == wire::ServerHookPhase.WsUpgradeAuth else {
        return wire::StageVerdict.Continue;
    }
    if core::ct_eq_bytes(req.header("Authorization"), stage.expected_auth[..]) {
        return wire::StageVerdict.Continue;
    }
    res.status_code = 401;
    res.set_header("Content-Type", "text/plain");
    res.body.append("unauthorized");
    return wire::StageVerdict.ShortCircuit { status_code: 401 };
}

fn verify_fips197_aes256_decrypt() {
    let key: u8[32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    ];
    let pt: u8[16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    ];
    let expected_ct: u8[16] = [
        0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf,
        0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89,
    ];
    var ks = core::aes256_key_schedule(key);
    defer core::zeroize_aes256_ks(ks);

    let ct = core::aes_encrypt_block(ks, pt);
    assert(ct[..] == expected_ct[..]);

    let dec = core::aes256_decrypt_block(ks, expected_ct);
    assert(dec[..] == pt[..]);
    print("FIPS197_AES256_DEC_OK\n");
}

fn verify_ws_upgrade_auth_hook() {
    var srv = server::HttpServer { .. };
    server::init_http_server_inplace(srv, "127.0.0.1", 0);
    let beh = realtime::WsBehavior { .. };
    let _ = server::add_ws_route(srv, "/ws", beh);

    var stage = WsAuthStage { .. };
    let _ = stage.expected_auth.try_set("Bearer wing_ws_secret");

    let unauth_wire = "GET /ws HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";
    var out1: u8[>..] = [];
    let _, _ = server::handle_connection_wire(srv, "127.0.0.1", unauth_wire, 1000, out1, stage);
    assert(core::contains(out1[..], "HTTP/1.1 401 "));
    assert(!core::contains(out1[..], "101 Switching Protocols"));

    let auth_wire = "GET /ws HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer wing_ws_secret\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";
    var out2: u8[>..] = [];
    let _, _ = server::handle_connection_wire(srv, "127.0.0.1", auth_wire, 2000, out2, stage);
    assert(core::contains(out2[..], "HTTP/1.1 101 Switching Protocols"));
    assert(core::contains(out2[..], "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="));
    print("SERVER_WS_AUTH_HOOK_OK\n");
}

thread_fn ws_sse_server_worker(listen_fd: i64) {
    // 1. Accept WebSocket connection, echo one text frame + one binary frame after ping
    let fd1 = net::tcp_accept(listen_fd, 5000);
    if fd1 > 0 {
        var tr = net::Transport.Tcp { fd: fd1 };
        var head:  u8[..8192] = [];
        var trail: u8[>..]    = [];
        if realtime::read_http1_head(tr, head, trail, 3000) {
            var sconn = realtime::WsConn { .. };
            if realtime::ws_accept_transport(sconn, tr, head[..], trail[..], "binary") {
                var op:  u8      = 0;
                var msg: u8[>..] = [];
                if sconn.ws_recv_frame(op, msg, 3000) == 1 {
                    let _ = sconn.ws_send_text(msg[..]);
                }
                if sconn.ws_recv_frame(op, msg, 3000) == 1 {
                    let _ = sconn.ws_send_binary(msg[..]);
                }
                sconn.ws_close();
            } else {
                tr.close();
            }
        } else {
            tr.close();
        }
    }

    // 2. Accept SSE connection and stream chunked RFC 9112 events
    let fd2 = net::tcp_accept(listen_fd, 5000);
    if fd2 > 0 {
        var tr2 = net::Transport.Tcp { fd: fd2 };
        var head2:  u8[..8192] = [];
        var trail2: u8[>..]    = [];
        if realtime::read_http1_head(tr2, head2, trail2, 3000) {
            let hdrs = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream; charset=utf-8\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n";
            let c1 = "17\r\nid: 7\ndata: hello-sse\n\n\r\n";
            let c2 = "17\r\nid: 8\ndata: second-ev\n\n\r\n0\r\n\r\n";
            let _ = realtime::send_all_transport(tr2, hdrs);
            let _ = realtime::send_all_transport(tr2, c1);
            let _ = realtime::send_all_transport(tr2, c2);
        }
        tr2.close();
    }
    net::tcp_close(listen_fd);
}

fn verify_live_ws_and_sse_loopback() {
    assert(net::tcp_init());
    let port: u16 = 19841;
    let lfd = net::tcp_listen("127.0.0.1", port, 16);
    assert(lfd > 0);

    let th = thread_spawn(ws_sse_server_worker, lfd);

    var sess = client::new_session();
    sess.ssrf_guard.enabled = false;
    sess.timeout_ms = 5000;

    var ws_url: u8[..128] = [];
    let _ = ws_url.try_append("ws://127.0.0.1:");
    format(ws_url, port);
    let _ = ws_url.try_append("/ws");

    var wconn = client::WsConn { .. };
    assert(client::dial_ws(sess, ws_url[..], wconn, "Bearer tok", "binary"));
    assert(wconn.negotiated_subprotocol[..] == "binary");
    assert(wconn.ws_send_ping("hi"));
    assert(wconn.ws_send_text("hello-wing-ws"));
    var op: u8      = 0;
    var rx: u8[>..] = [];
    assert(wconn.ws_recv_frame(op, rx, 3000) == 1 && rx[..] == "hello-wing-ws");
    assert(wconn.ws_send_binary("\x01\x02\x03\x04"));
    assert(wconn.ws_recv_frame(op, rx, 3000) == 1 && rx[..] == "\x01\x02\x03\x04");
    wconn.ws_close();
    print("LIVE_WS_LOOPBACK_OK\n");

    var sse_url: u8[..128] = [];
    let _ = sse_url.try_append("http://127.0.0.1:");
    format(sse_url, port);
    let _ = sse_url.try_append("/v1/events");

    var sconn = client::SseConn { .. };
    assert(client::dial_sse(sess, sse_url[..], sconn, "tok", "6"));
    var ev1 = realtime::SseEvent { .. };
    var ev2 = realtime::SseEvent { .. };
    assert(sconn.sse_recv_event(ev1, 3000) == 1 && ev1.id[..] == "7" && ev1.data[..] == "hello-sse");
    assert(sconn.sse_recv_event(ev2, 3000) == 1 && ev2.id[..] == "8" && ev2.data[..] == "second-ev");
    assert(sconn.sse_recv_event(ev2, 3000) == 0);
    sconn.sse_close();
    print("LIVE_SSE_CHUNKED_OK\n");

    assert(thread_wait(th));
}

fn main() {
    verify_fips197_aes256_decrypt();
    verify_ws_upgrade_auth_hook();
    verify_live_ws_and_sse_loopback();
}

// CHECK: FIPS197_AES256_DEC_OK
// CHECK: SERVER_WS_AUTH_HOOK_OK
// CHECK: LIVE_WS_LOOPBACK_OK
// CHECK: LIVE_SSE_CHUNKED_OK
