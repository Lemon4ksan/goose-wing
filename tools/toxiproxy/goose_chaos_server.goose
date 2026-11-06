// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Standalone Live Goose-Wing Server for Toxiproxy Chaos & Security Attacks Testing.
// Handles HTTP/1.1, WebSocket (RFC 6455), and HTTP/2 (RFC 9113) natively in Goose!
import std;
import core from "../..";
import wing from "../..";

struct ChaosEchoStage {
    active:           bool = true,
    flaky_calls:      u64  = 0,
    flaky_post_calls: u64  = 0,
}

fn handle_digest_chaos_stage(req: const wing::Request&, res: wing::Response&) -> wire::StageVerdict {
    wing::set_header(res, "Connection", "keep-alive");
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
    wing::set_header(res, "Connection", "keep-alive");
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

fn handle_chunked_chaos_stage(res: wing::Response&) -> wire::StageVerdict {
    wing::set_header(res, "Transfer-Encoding", "chunked");
    wing::set_header(res, "Trailer", "X-Chaos-Trailer");
    wing::set_header(res, "Connection", "close");
    wing::add_trailer(res, "X-Chaos-Trailer", "verified");
    res.body.append("CHUNK_A_CHUNK_B");
    return wire::StageVerdict.ShortCircuit { status_code: 200 };
}

fn handle_sse_chaos_stage(req: const wing::Request&, res: wing::Response&) -> wire::StageVerdict {
    wing::set_header(res, "Content-Type", "text/event-stream");
    wing::set_header(res, "Connection", "close");
    if req.header("Last-Event-ID") == "ev-chaos-1" {
        res.body.append("id: ev-chaos-2\nevent: done\ndata: resumed-part\n\n");
    } else {
        res.body.append("retry: 1200\nid: ev-chaos-1\nevent: update\ndata: line1\ndata: line2\n\n");
    }
    return wire::StageVerdict.ShortCircuit { status_code: 200 };
}

fn handle_flaky_post_chaos_stage(
    stage: ChaosEchoStage&,
    req:   const wing::Request&,
    res:   wing::Response&,
) -> wire::StageVerdict {
    stage.flaky_post_calls = core::add_sat_u64(stage.flaky_post_calls, 1);
    if (stage.flaky_post_calls & 1) == 1 {
        res.status_code = 503;
        res.body.append("TEMP_POST_ERR");
        return wire::StageVerdict.ShortCircuit { status_code: 503 };
    }
    if req.header("Idempotency-Key") == "idem-chaos-88" {
        res.body.append("IDEM_POST_OK:");
        res.body.append(req.body[..]);
        return wire::StageVerdict.ShortCircuit { status_code: 200 };
    }
    res.status_code = 400;
    res.body.append("MISSING_IDEM_KEY");
    return wire::StageVerdict.ShortCircuit { status_code: 400 };
}

fn handle_proxy_up_chaos_stage(req: const wing::Request&, res: wing::Response&) -> wire::StageVerdict {
    let xff = req.header("X-Forwarded-For");
    let via = req.header("Via");
    let dropped = req.header("X-Hop-Drop");
    if find(xff, "203.0.113.9") >= 0 && via.len > 0 && dropped.len == 0 {
        res.body.append("PROXY_FAILOVER_OK");
        return wire::StageVerdict.ShortCircuit { status_code: 200 };
    }
    res.status_code = 400;
    res.body.append("BAD_PROXY_HEADERS");
    return wire::StageVerdict.ShortCircuit { status_code: 400 };
}

fn wing::on_server_stage(
    stage: ChaosEchoStage&,
    phase: wire::ServerHookPhase,
    _cfg:  wing::ServerPipelineConfig&,
    req:   const wing::Request&,
    _ctx:  wing::ServerStageCtx&,
    res:   wing::Response&,
) -> wire::StageVerdict {
    guard phase == wire::ServerHookPhase.PreRoute && req.url[..] != "/shutdown" else {
        return wire::StageVerdict.Continue;
    }
    res.status_code = 200;
    wing::set_header(res, "Content-Type", "text/plain");
    res.body.clear();
    if req.url[..] == "/echo" {
        res.body.append("ECHO:");
        res.body.append(req.body[..]);
    } else if req.url[..] == "/chunked-resp" {
        return handle_chunked_chaos_stage(res);
    } else if req.url[..] == "/sse-chaos" {
        return handle_sse_chaos_stage(req, res);
    } else if req.url[..] == "/redirect-start" {
        res.status_code = 302;
        wing::set_header(res, "Location", "/redirect-final");
        wing::set_header(res, "Set-Cookie", "chaos_cookie=token_99; Path=/");
        res.body.append("REDIRECTING");
        return wire::StageVerdict.ShortCircuit { status_code: 302 };
    } else if req.url[..] == "/redirect-final" {
        if find(req.header("Cookie"), "chaos_cookie=token_99") < 0 {
            res.status_code = 403;
            res.body.append("MISSING_COOKIE");
            return wire::StageVerdict.ShortCircuit { status_code: 403 };
        }
        res.body.append("REDIRECT_COOKIE_OK");
    } else if req.url[..] == "/flaky" {
        stage.flaky_calls = core::add_sat_u64(stage.flaky_calls, 1);
        if (stage.flaky_calls & 1) == 1 {
            res.status_code = 503;
            res.body.append("TEMP_UNAVAILABLE");
            return wire::StageVerdict.ShortCircuit { status_code: 503 };
        }
        res.body.append("RETRY_RECOVERED_OK");
    } else if req.url[..] == "/flaky-post" {
        return handle_flaky_post_chaos_stage(stage, req, res);
    } else if req.url[..] == "/digest-chaos" {
        return handle_digest_chaos_stage(req, res);
    } else if req.url[..] == "/cache-chaos" {
        return handle_cache_chaos_stage(req, res);
    } else if req.url[..] == "/proxy-up" {
        return handle_proxy_up_chaos_stage(req, res);
    } else if req.url[..] == "/keepalive" {
        wing::set_header(res, "Connection", "keep-alive");
        res.body.append("KEEPALIVE_OK");
    } else {
        res.body.append("OK");
    }
    return wire::StageVerdict.ShortCircuit { status_code: 200 };
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
    print("READY_PORT:", port, "\n");
    wing::serve_http_listener(listener, server, echo_stage, 500);
    wing::tcp_close(listener);
}
