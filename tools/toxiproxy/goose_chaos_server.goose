// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Standalone Live Goose-Wing Server for Toxiproxy Chaos & Security Attacks Testing.
// Handles HTTP/1.1, WebSocket (RFC 6455), and HTTP/2 (RFC 9113) natively in Goose!
import std;
import core from "../..";
import wing from "../..";

struct ChaosEchoStage {
    active:           bool = true,
    flaky_calls:      i32  = 0,
    flaky_post_calls: i32  = 0,
}

fn handle_digest_chaos_stage(req: const wing::Request&, res: wing::Response&) -> wire::StageVerdict {
    let auth_hdr = req.header("Authorization");
    if auth_hdr.len == 0 {
        res.status_code = 401;
        wing::set_header(
            res,
            "WWW-Authenticate",
            "Digest realm=\"chaos-realm\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", qop=\"auth\", algorithm=SHA-256, opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"",
        );
        wing::set_header(res, "Set-Cookie", "auth_sid=dig_77; Path=/");
        res.body.append("NEED_DIGEST");
        return wire::StageVerdict.ShortCircuit { status_code: 401 };
    }
    let ok_d = find(auth_hdr, "username=\"admin\"") >= 0 &&
        find(auth_hdr, "realm=\"chaos-realm\"") >= 0 &&
        find(auth_hdr, "algorithm=SHA-256") >= 0 &&
        find(auth_hdr, "uri=\"/digest-chaos\"") >= 0 &&
        find(auth_hdr, "response=\"") >= 0;
    let ck = req.header("Cookie");
    if ok_d && find(ck, "auth_sid=dig_77") >= 0 {
        res.body.append("DIGEST_CHAOS_OK");
        return wire::StageVerdict.ShortCircuit { status_code: 200 };
    }
    res.status_code = 403;
    res.body.append("BAD_DIGEST_OR_COOKIE");
    return wire::StageVerdict.ShortCircuit { status_code: 403 };
}

fn handle_cache_chaos_stage(req: const wing::Request&, res: wing::Response&) -> wire::StageVerdict {
    wing::set_header(res, "ETag", "\"chaos-etag-v1\"");
    if req.header("If-None-Match") == "\"chaos-etag-v1\"" {
        res.status_code = 304;
        wing::set_header(res, "Cache-Control", "max-age=60");
        wing::set_header(res, "X-Revalidated", "yes");
        return wire::StageVerdict.ShortCircuit { status_code: 304 };
    }
    wing::set_header(res, "Cache-Control", "max-age=10");
    wing::set_header(res, "X-Revalidated", "no");
    res.body.append("CACHED_CHAOS_BODY_V1");
    return wire::StageVerdict.ShortCircuit { status_code: 200 };
}

fn wing::on_server_stage(
    stage: ChaosEchoStage&,
    phase: wire::ServerHookPhase,
    _cfg:  wing::ServerPipelineConfig&,
    req:   const wing::Request&,
    _ctx:  wing::ServerStageCtx&,
    res:   wing::Response&,
) -> wire::StageVerdict {
    if phase == wire::ServerHookPhase.PreRoute && req.url[..] != "/shutdown" {
        res.status_code = 200;
        wing::set_header(res, "Content-Type", "text/plain");
        res.body.clear();
        if req.url[..] == "/echo" {
            res.body.append("ECHO:");
            res.body.append(req.body[..]);
        } else if req.url[..] == "/redirect-start" {
            res.status_code = 302;
            wing::set_header(res, "Location", "/redirect-final");
            wing::set_header(res, "Set-Cookie", "chaos_cookie=token_99; Path=/");
            res.body.append("REDIRECTING");
            return wire::StageVerdict.ShortCircuit { status_code: 302 };
        } else if req.url[..] == "/redirect-final" {
            let ck = req.header("Cookie");
            if find(ck, "chaos_cookie=token_99") >= 0 {
                res.body.append("REDIRECT_COOKIE_OK");
            } else {
                res.status_code = 403;
                res.body.append("MISSING_COOKIE");
                return wire::StageVerdict.ShortCircuit { status_code: 403 };
            }
        } else if req.url[..] == "/flaky" {
            stage.flaky_calls += 1;
            if (stage.flaky_calls % 2) == 1 {
                res.status_code = 503;
                res.body.append("TEMP_UNAVAILABLE");
                return wire::StageVerdict.ShortCircuit { status_code: 503 };
            }
            res.body.append("RETRY_RECOVERED_OK");
        } else if req.url[..] == "/flaky-post" {
            stage.flaky_post_calls += 1;
            if (stage.flaky_post_calls % 2) == 1 {
                res.status_code = 503;
                res.body.append("TEMP_POST_ERR");
                return wire::StageVerdict.ShortCircuit { status_code: 503 };
            }
            if req.header("Idempotency-Key") == "idem-chaos-88" {
                res.body.append("IDEM_POST_OK:");
                res.body.append(req.body[..]);
            } else {
                res.status_code = 400;
                res.body.append("MISSING_IDEM_KEY");
                return wire::StageVerdict.ShortCircuit { status_code: 400 };
            }
        } else if req.url[..] == "/digest-chaos" {
            return handle_digest_chaos_stage(req, res);
        } else if req.url[..] == "/cache-chaos" {
            return handle_cache_chaos_stage(req, res);
        } else if req.url[..] == "/proxy-up" {
            let xff = req.header("X-Forwarded-For");
            let via = req.header("Via");
            let dropped = req.header("X-Hop-Drop");
            if find(xff, "203.0.113.9") >= 0 && via.len > 0 && dropped.len == 0 {
                res.body.append("PROXY_FAILOVER_OK");
            } else {
                res.status_code = 400;
                res.body.append("BAD_PROXY_HEADERS");
                return wire::StageVerdict.ShortCircuit { status_code: 400 };
            }
        } else if req.url[..] == "/keepalive" {
            res.body.append("KEEPALIVE_OK");
        } else {
            res.body.append("OK");
        }
        return wire::StageVerdict.ShortCircuit { status_code: 200 };
    }
    return wire::StageVerdict.Continue;
}

fn drain_and_close(conn: i64) {
    var dummy: u8[..4096] = [];
    var loops = 0;
    while loops < 10 {
        let recvd = wing::tcp_recv(conn, dummy, 4096, 20);
        if recvd <= 0 {
            break;
        }
        loops++;
    }
    wing::tcp_close(conn);
}

fn handle_websocket_session(conn: i64, server: const wing::HttpServer&, req: const wing::Request&) {
    var ws_res = wing::Response { .. };
    var ws, ok_ws = wing::ws_upgrade_request(req, ws_res, "");
    if !ok_ws {
        return;
    }
    var handshake_resp: u8[>..] = [];
    wing::serialize_http1_response(ws_res, server.server_name[..], handshake_resp);
    wing::tcp_send(conn, handshake_resp[..]);
    var ws_buf:    u8[>..] = [];
    var frag_buf:  u8[>..] = [];
    var reply:     u8[>..] = [];
    var echo_wire: u8[>..] = [];
    while !ws.is_closed {
        var chunk: u8[..4096] = [];
        let recvd = wing::tcp_recv(conn, chunk, 4096, 500);
        if recvd == -2 {
            continue;
        }
        if recvd <= 0 {
            break;
        }
        ws_buf.append(chunk[..recvd]);

        var cursor: i64 = 0;
        while cursor + 2 <= ws_buf.len && !ws.is_closed {
            reply.clear();
            let consumed, handled, view = wing::consume_frame_view_into(
                ws,
                ws_buf[cursor..],
                frag_buf,
                16777216,
                reply,
            );
            if !handled {
                break;
            }
            cursor += consumed;

            if reply.len > 0 {
                wing::tcp_send(conn, reply[..]);
            }

            if view.is_valid && (view.opcode == rfc::WS_OPCODE_TEXT || view.opcode == rfc::WS_OPCODE_BINARY) {
                echo_wire.clear();
                if view.opcode == rfc::WS_OPCODE_TEXT {
                    wing::send_text(ws, view.payload, echo_wire);
                } else {
                    wing::send_binary(ws, view.payload, echo_wire);
                }
                if echo_wire.len > 0 {
                    wing::tcp_send(conn, echo_wire[..]);
                }
            }

            if ws.is_closed {
                drain_and_close(conn);
                return;
            }
        }

        if cursor > 0 {
            if cursor >= ws_buf.len {
                ws_buf.clear();
            } else {
                var remaining: u8[>..] = [];
                remaining.append(ws_buf[cursor..]);
                ws_buf.clear();
                ws_buf.append(remaining[..]);
            }
        }
    }
}

fn is_http1_request_ready(in_buf: const u8[:], hdr_end: i64) -> bool {
    let body_start = hdr_end + 4;
    var tracker = wing::HeaderPresenceTracker { .. };
    var parsed_start: i64 = 0;
    var probe_req = wing::Request { .. };
    guard wing::parse_http1_request_headers(in_buf, probe_req, tracker, parsed_start) else {
        return true;
    }
    let has_te = (tracker.mask & wing::HDR_PRESENCE_TRANSFER_ENCODING) != 0;
    let has_cl = (tracker.mask & wing::HDR_PRESENCE_CONTENT_LENGTH) != 0;
    if has_te && has_cl {
        return true;
    }
    if has_cl {
        return in_buf.len >= body_start + tracker.parsed_cl;
    }
    if has_te {
        return find(in_buf[body_start..], "0\r\n\r\n") >= 0;
    }
    return true;
}

fn handle_chaos_http1_request(
    conn:       i64,
    server:     wing::HttpServer&,
    in_buf:     const u8[:],
    echo_stage: ChaosEchoStage&,
    is_running: bool&,
) {
    var req = wing::new_request("GET", "");
    var out_wire: u8[>..] = [];
    let ok_req, _ = wing::parse_http1_wire_request(in_buf, req);
    guard ok_req else {
        wing::serialize_bad_request_error(server.server_name[..], out_wire);
        wing::tcp_send(conn, out_wire[..]);
        return;
    }

    if wing::is_websocket_upgrade_request(req) {
        handle_websocket_session(conn, server, req);
        return;
    }

    var res = wing::Response { .. };
    let now_ns = core::as_nanos(core::monotonic_now());
    let _ = wing::dispatch_server_request_with_stage(server, "127.0.0.1", req, now_ns, res, echo_stage);
    if req.url[..] == "/chunked-resp" {
        let raw_chunked = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\nTrailer: X-Chaos-Trailer\r\nConnection: close\r\n\r\n7\r\nCHUNK_A\r\n8\r\n_CHUNK_B\r\n0\r\nX-Chaos-Trailer: verified\r\n\r\n";
        wing::tcp_send(conn, raw_chunked);
        return;
    }
    if req.url[..] == "/sse-chaos" {
        if req.header("Last-Event-ID") == "ev-chaos-1" {
            let raw_sse2 = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\nid: ev-chaos-2\nevent: done\ndata: resumed-part\n\n";
            wing::tcp_send(conn, raw_sse2);
        } else {
            let raw_sse1 = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\nretry: 1200\nid: ev-chaos-1\nevent: update\ndata: line1\ndata: line2\n\n";
            wing::tcp_send(conn, raw_sse1);
        }
        return;
    }
    let is_ka_url = req.url[..] == "/keepalive" || req.url[..] == "/digest-chaos" || req.url[..] == "/cache-chaos";
    if is_ka_url {
        wing::set_header(res, "Connection", "keep-alive");
    } else {
        wing::set_header(res, "Connection", "close");
    }
    wing::serialize_http1_response(res, server.server_name[..], out_wire);
    wing::tcp_send(conn, out_wire[..]);

    if req.url[..] == "/shutdown" {
        is_running = false;
    }
}

fn serve_chaos_connection(
    conn:       i64,
    server:     wing::HttpServer&,
    in_buf:     u8[>..]&,
    echo_stage: ChaosEchoStage&,
    is_running: bool&,
) {
    in_buf.clear();
    var idle_count = 0;
    var ka_count = 0;
    var chunk: u8[..4096] = [];
    while in_buf.len < 65000 {
        chunk.clear();
        let recvd = wing::tcp_recv(conn, chunk, 4096, 500);
        if recvd == -2 {
            idle_count++;
            if idle_count >= 6 {
                break;
            }
            continue;
        }
        if recvd <= 0 {
            break;
        }
        idle_count = 0;
        in_buf.append(chunk[..recvd]);

        if wing::is_partial_h2_client_preface(in_buf[..]) {
            continue;
        }
        if wing::is_h2_client_preface(in_buf[..]) {
            let _ = wing::serve_h2_connection(server, conn, in_buf[..], 2000);
            break;
        }
        if in_buf.len >= 4 && in_buf[..4] == "PRI " {
            break;
        }

        let hdr_end = core::fast_find_crlfcrlf(in_buf[..]);
        if hdr_end >= 0 && is_http1_request_ready(in_buf[..], hdr_end) {
            let is_ka = core::starts_with(in_buf[..], "GET /keepalive ") ||
                core::starts_with(in_buf[..], "GET /digest-chaos ") ||
                core::starts_with(in_buf[..], "GET /cache-chaos ");
            handle_chaos_http1_request(conn, server, in_buf[..], echo_stage, is_running);
            if is_ka {
                ka_count++;
                if ka_count < 2 {
                    in_buf.clear();
                    continue;
                }
            }
            break;
        }
    }
}

fn main() {
    let port_env = wing::get_env_port(0);
    let listener = wing::tcp_listen("0.0.0.0", port_env, 128);
    if listener <= 0 {
        print("ERROR_FAILED_TO_LISTEN\n");
        return;
    }
    let port = wing::tcp_getsockname_port(listener);

    var server = wing::new_http_server("0.0.0.0", port);
    let _ = server.server_name.try_set("goose-chaos/1.0");
    wing::add_static_get_route(server, "/ping", "text/plain", "OK", 101);
    wing::add_static_route(server.pipeline.router, "POST", "/echo", "text/plain", "ECHO:H2ClientSlicedPayload_777", 202);
    wing::add_static_route(server.pipeline.router, "POST", "/h2-large", "text/plain", "H2_LARGE_MULTIFRAME_OK", 203);
    wing::add_static_get_route(server, "/shutdown", "text/plain", "BYE\n", 99);

    var echo_stage = ChaosEchoStage { .. };
    var in_buf: u8[>..] = [];
    print("READY_PORT:", port, "\n");

    var is_running = true;
    while is_running {
        let conn = wing::tcp_accept(listener, 500);
        if conn <= 0 {
            continue;
        }
        serve_chaos_connection(conn, server, in_buf, echo_stage, is_running);
        wing::tcp_close(conn);
    }

    wing::tcp_close(listener);
}
