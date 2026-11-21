// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Compile-time composable Vulkan HTTP/1.1 pipeline ("pay only for what you wire").
// Chains zero-copy Tcp/Memory -> RingBuffer -> RequestView -> <Stage> -> Router -> <Handler>.
namespace h1;

import std;
import core.bytes.case;
import core.math.arithmetic;
import core.io.ring;
import .transport;
import .wire;
import .router;

enum StageVerdict {
    Continue,
    ShortCircuit,
    Abort,
}

// Per-request routing and parameter context (~800 B on stack, zero heap).
struct StageCtx {
    handler_id: i32         = -1,
    stage_mask: u64         = 0,
    params:     RouteParams = RouteParams { .. },
    canon_path: u8[..512]   = [],
}

// Looks up a captured route parameter by `name` as a zero-copy slice of `ctx.canon_path`.
fn route_param(ctx: const StageCtx&, name: const u8[:]) -> const u8[:], bool {
    return param_by_name(ctx.params, name, ctx.canon_path[..]);
}

// Zero-size no-op middleware stage when no custom stage is wired.
struct NoOpStage {}

// Compile-time monomorphized stage combinator chaining two stages without vtables or heap.
struct StageChain<First, Next> {
    first: First,
    next:  Next,
}

inline fn chain_stages<First, Next>(first: First, next: Next) -> StageChain<First, Next> {
    return StageChain<First, Next> {
        first: first,
        next:  next,
    };
}

inline fn on_ingress(
    _stage: NoOpStage&,
    _req:   const RequestView&,
    _ctx:   StageCtx&,
    _res:   ResponseView&,
) -> StageVerdict {
    return StageVerdict.Continue;
}

inline fn on_egress(
    _stage: NoOpStage&,
    _req:   const RequestView&,
    _ctx:   const StageCtx&,
    _res:   ResponseView&,
) {}

inline fn on_ingress<First, Next>(
    chain: StageChain<First, Next>&,
    req:   const RequestView&,
    ctx:   StageCtx&,
    res:   ResponseView&,
) -> StageVerdict {
    let v1 = chain.first.on_ingress(req, ctx, res);
    guard v1 == StageVerdict.Continue else { return v1; }
    return chain.next.on_ingress(req, ctx, res);
}

inline fn on_egress<First, Next>(
    chain: StageChain<First, Next>&,
    req:   const RequestView&,
    ctx:   const StageCtx&,
    res:   ResponseView&,
) {
    chain.next.on_egress(req, ctx, res);
    chain.first.on_egress(req, ctx, res);
}

// Routes and dispatches a zero-copy `RequestView` through `<Stage>` and `<Handler>` into `res`.
// Returns false only when `<Stage>` returns `StageVerdict.Abort`.
fn dispatch_request<Stage, Handler>(
    router:  const Router&,
    req:     const RequestView&,
    stage:   Stage&,
    handler: Handler&,
    res:     ResponseView&,
) -> bool {
    reset_response(res);
    var ctx = StageCtx { .. };
    let matched = match_route(router, req.method, req.path, ctx.params, ctx.canon_path);
    var route_found = false;
    match matched {
        Found f => {
            ctx.handler_id = f.handler_id;
            ctx.stage_mask = f.stage_mask;
            route_found = true;
        },
        MethodNotAllowed m => {
            set_text_view(res, 405, "Method Not Allowed");
            let _ = add_header(res, "Allow", m.allow[..]);
        },
        NotFound => {
            set_text_view(res, 404, "Not Found");
        },
    };

    let verdict = stage.on_ingress(req, ctx, res);
    if verdict == StageVerdict.Abort {
        return false;
    }
    if verdict == StageVerdict.Continue && route_found {
        handler.handle_route(req, ctx, res);
    }
    stage.on_egress(req, ctx, res);
    if wants_close(req) {
        res.close_conn = true;
    }
    return true;
}

inline fn write_parse_error_response<OutBuf>(status: ParseStatus, wire_out: OutBuf&) {
    var err_res = ResponseView { .. };
    err_res.close_conn = true;
    match status {
        HeadersTooLarge => {
            set_text_view(err_res, 431, "Request Header Fields Too Large");
        },
        PayloadTooLarge => {
            set_text_view(err_res, 413, "Content Too Large");
        },
        _ => {
            set_text_view(err_res, 400, "Bad Request");
        },
    };
    let _ = serialize_response(err_res, false, wire_out);
}

// Processes one or more pipelined HTTP/1.1 requests directly from borrowed `wire_in`.
// Returns `(requests_handled, bytes_consumed, ok, wants_close)`.
fn serve_wire_pipelined<Stage, Handler, OutBuf>(
    router:   const Router&,
    wire_in:  const u8[:],
    stage:    Stage&,
    handler:  Handler&,
    wire_out: OutBuf&,
) -> i64, i64, bool, bool {
    wire_out.clear();
    var handled:      i64  = 0;
    var consumed:     i64  = 0;
    var should_close: bool = false;
    var res = ResponseView { .. };

    while consumed < wire_in.len {
        let req, step_len, st = parse_request_view(wire_in[consumed..]);
        if st == ParseStatus.Incomplete {
            break;
        }
        if st != ParseStatus.Complete {
            write_parse_error_response(st, wire_out);
            return handled, consumed, false, true;
        }
        consumed = core::add_sat_i64(consumed, step_len);
        guard dispatch_request(router, req, stage, handler, res) else {
            return handled, consumed, false, true;
        }
        let is_head = req.method == "HEAD";
        guard serialize_response(res, is_head, wire_out) else {
            return handled, consumed, false, true;
        }
        handled = core::add_sat_i64(handled, 1);
        if res.close_conn {
            should_close = true;
            break;
        }
    }
    return handled, consumed, true, should_close;
}

// Processes all complete pipelined HTTP/1.1 requests buffered inside `rx_ring` zero-copy.
// Discards consumed bytes from `rx_ring` and returns `(requests_handled, ok, wants_close)`.
fn serve_ring_pipelined<Stage, Handler, OutBuf>(
    router:   const Router&,
    rx_ring:  core::RingBuffer&,
    stage:    Stage&,
    handler:  Handler&,
    wire_out: OutBuf&,
) -> i64, bool, bool {
    let readable = core::contiguous_readable_slice(rx_ring);
    guard readable.len > 0 else {
        wire_out.clear();
        return 0, true, false;
    }
    let handled, consumed, ok, should_close = serve_wire_pipelined(
        router, readable, stage, handler, wire_out,
    );
    if consumed > 0 {
        let _ = core::discard(rx_ring, consumed);
    }
    return handled, ok, should_close;
}

// Runs a full keep-alive and pipelined HTTP/1.1 connection over `<Io>` (`TcpStream` or `MemoryStream`).
// Uses ~12 KB total stack space (4 KB `RingBuffer` + 4 KB output buffer + ~4 KB views).
fn serve_stream<Io, Stage, Handler>(
    io:         Io&,
    router:     const Router&,
    stage:      Stage&,
    handler:    Handler&,
    timeout_ms: u32 = 2000,
) -> i64 {
    var rx_ring = core::RingBuffer { .. };
    var wire_out:      u8[..4096] = [];
    var total_handled: i64        = 0;

    loop {
        let recvd = recv_into_ring(io, rx_ring, timeout_ms);
        if recvd <= 0 {
            break;
        }
        let handled, ok, should_close = serve_ring_pipelined(
            router, rx_ring, stage, handler, wire_out,
        );
        total_handled = core::add_sat_i64(total_handled, handled);
        if wire_out.len > 0 {
            guard send_all(io, wire_out[..]) else { break; }
        }
        if !ok || should_close {
            break;
        }
    }
    return total_handled;
}

// Accepts up to `max_conns` TCP connections on `lis` and serves each through `serve_stream`.
fn serve_tcp_listener<Stage, Handler>(
    lis:        const TcpListener&,
    router:     const Router&,
    stage:      Stage&,
    handler:    Handler&,
    max_conns:  i64 = 1,
    timeout_ms: u32 = 2000,
) -> i64 {
    guard lis.fd > 0 && max_conns > 0 else { return 0; }
    var total_reqs:   i64 = 0;
    var served_conns: i64 = 0;
    while served_conns < max_conns {
        var conn, ok = accept(lis, timeout_ms);
        if !ok { break; }
        defer close(conn);
        let n = serve_stream(conn, router, stage, handler, timeout_ms);
        total_reqs = core::add_sat_i64(total_reqs, n);
        served_conns = core::add_sat_i64(served_conns, 1);
    }
    return total_reqs;
}
