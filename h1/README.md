# Modular HTTP/1.1 pipeline (`wing_h1.goose`)

Compile-time modular HTTP/1.1 package entrypoint (`namespace h1`) that excludes
`tls`, `http2`, `http3`, `quic`, `grpc`, `realtime`, `auth`, `cookie`, `dns`,
`security`, `core.compress`, and asymmetric crypto when wiring only
`Tcp -> Http1 -> Router`.

`wing_h1.build` compiles two C shims (`shim/simd.c` and `shim/tcp.c`) and
exports `core::csprng_fill` and `core::csprng_u64` alongside zero-copy HTTP/1.1
framing, routing, middleware chaining, and a minimal client exchange path.

## Quick start

```goose
import std;
import wing_h1 from "github.com/Lemon4ksan/goose-wing@v0.1.0";

struct AppHandler {}

fn handle_route(
    _h:  AppHandler&,
    req: const h1::RequestView&,
    ctx: const h1::StageCtx&,
    res: h1::ResponseView&,
) {
    if ctx.handler_id == 1 {
        h1::set_json_view(res, 200, "{\"ok\":true}");
        return;
    }
    let uid, ok = h1::route_param(ctx, "id");
    let _ = h1::set_body_buf(res, 200, "text/plain", if ok { uid } else { "" });
}

fn main() {
    var router = h1::Router { .. };
    let _ = h1::add_route(router, "GET", "/health", 1);
    let _ = h1::add_route(router, "GET", "/users/:id", 2);

    var lis, ok = h1::tcp_listen("127.0.0.1", 8080, 128);
    guard ok else { return; }
    defer h1::close(lis);

    var stage = h1::NoOpStage {};
    var handler = AppHandler {};
    let _ = h1::serve_tcp_listener(lis, router, stage, handler, 1024, 5000);
}
```

## Submodules

### `h1/transport.goose`: L4 TCP and in-memory streams

```goose
struct TcpListener { fd: i64, port: u16 }
struct TcpStream { fd: i64 }
struct MemoryStream { rx: core::RingBuffer, tx: core::RingBuffer, closed: bool }

fn tcp_listen(host: const u8[:], port: u16 = 0, backlog: i32 = 128) -> TcpListener, bool
fn accept(lis: const TcpListener&, timeout_ms: u32 = 1000) -> TcpStream, bool
fn close(lis: TcpListener&)
fn tcp_connect(host: const u8[:], port: u16, timeout_ms: u32 = 5000) -> TcpStream, bool
fn send(s: TcpStream&, data: const u8[:]) -> i32
fn send_all<Io>(io: Io&, data: const u8[:]) -> bool
fn send2(s: TcpStream&, hdr: const u8[:], body: const u8[:]) -> i32
fn recv_slice(s: TcpStream&, dst: u8[:], timeout_ms: u32 = 5000) -> i32
fn close(s: TcpStream&)
fn recv_into_ring<Io>(io: Io&, rb: core::RingBuffer&, timeout_ms: u32 = 5000) -> i32
fn feed_input(ms: MemoryStream&, data: const u8[:]) -> bool
fn drain_output(ms: MemoryStream&, out: u8[:]) -> i64
```

`TcpStream` and `MemoryStream` satisfy `core::stream_send<Io>`,
`core::stream_recv<Io>`, and `core::stream_close<Io>`. `recv_into_ring` reads
directly from `<Io>` into `core::RingBuffer`'s writable span without an
intermediate bounce buffer.

### `h1/wire.goose`: zero-copy HTTP/1.1 request and response codec

```goose
enum ParseStatus { Complete, Incomplete, BadRequest, HeadersTooLarge, PayloadTooLarge }
enum QueryMatch { Missing, Valueless, Value }
struct HeaderSlice { name_start: u16, name_end: u16, val_start: u16, val_end: u16 }
struct RequestView { raw, method, target, path, query, body, host: const u8[:], headers: HeaderSlice[..64], content_length: i64, flags: u16 }
struct ResponseView { status_code: u16, content_type: u8[..64], extra_hdrs: u8[..512], body: const u8[:], body_buf: u8[..2048], close_conn: bool }

fn parse_request_view(wire: const u8[:]) -> RequestView, i64, ParseStatus
fn decode_chunked_body<B>(raw_chunked: const u8[:], out: B&) -> i64, ParseStatus
fn header(req: const RequestView&, name: const u8[:]) -> const u8[:]
fn has_header(req: const RequestView&, name: const u8[:]) -> bool
fn wants_close(req: const RequestView&) -> bool
fn query_param_raw(req: const RequestView&, key: const u8[:]) -> const u8[:], QueryMatch
fn query_param<B>(req: const RequestView&, key: const u8[:], out: B&) -> QueryMatch
fn set_text_view(res: ResponseView&, status: u16, body_view: const u8[:])
fn set_json_view(res: ResponseView&, status: u16, body_view: const u8[:])
fn set_body_buf(res: ResponseView&, status: u16, content_type: const u8[:], body: const u8[:]) -> bool
fn write_body(res: ResponseView&, chunk: const u8[:]) -> bool
fn add_header(res: ResponseView&, name: const u8[:], val: const u8[:]) -> bool
fn serialize_response_head<B>(res: const ResponseView&, is_head_req: bool, out: B&) -> bool
fn serialize_response<B>(res: const ResponseView&, is_head_req: bool, out: B&) -> bool
fn send_response_vectored(s: TcpStream&, res: const ResponseView&, is_head_req: bool) -> bool
```

`RequestView` (~640 B on the stack) borrows `method`, `target`, `path`, `query`,
`host`, `body`, and up to 64 header offset spans directly from the ingress
buffer. The parser enforces RFC 9112 framing rules: rejecting
`Transfer-Encoding` and `Content-Length` co-presence, duplicate `Host`, missing
HTTP/1.1 `Host`, bare CR/LF, and invalid header tokens. `send_response_vectored`
writes headers into a 1 KB stack buffer and sends headers and body in one
syscall via `wing_tcp_send2`.

### `h1/router.goose`: compact zero-copy router

```goose
struct RouteParamSpan { name: u8[..24], val_start: u16, val_end: u16 }
struct RouteParams { spans: RouteParamSpan[8], len: i64 }
struct Router { routes: RouteEntry[..64] }
enum RouteMatch { Found { handler_id: i32, stage_mask: u64 }, NotFound, MethodNotAllowed { allow: u8[..64] } }

fn canonicalize_path<B>(raw_path: const u8[:], out: B&) -> bool
fn add_route(router: Router&, method: const u8[:], pattern: const u8[:], handler_id: i32, stage_mask: u64 = 0) -> bool
fn match_route<B>(router: const Router&, method: const u8[:], raw_path: const u8[:], params: RouteParams&, out_canon: B&) -> RouteMatch
fn param_by_name(params: const RouteParams&, name: const u8[:], path: const u8[:]) -> const u8[:], bool
```

`Router` (~11 KB on the stack) supports static paths, `:param` and `{param}`
segments, `*wildcard` and `{*wildcard}` catch-alls, RFC 3986 Section 5.2.4 dot
canonicalization, insertion-order independent precedence (static > param >
wildcard), automatic `HEAD` to `GET` fallback (RFC 9110 Section 9.3.2), and
`405 Method Not Allowed` with `Allow` headers.

### `h1/pipeline.goose`: compile-time stage pipeline

```goose
enum StageVerdict { Continue, ShortCircuit, Abort }
struct StageCtx { handler_id: i32, stage_mask: u64, params: RouteParams, canon_path: u8[..512] }
struct NoOpStage {}
struct StageChain<First, Next> { first: First, next: Next }

fn chain_stages<First, Next>(first: First, next: Next) -> StageChain<First, Next>
fn route_param(ctx: const StageCtx&, name: const u8[:]) -> const u8[:], bool
fn dispatch_request<Stage, Handler>(router: const Router&, req: const RequestView&, stage: Stage&, handler: Handler&, res: ResponseView&) -> bool
fn serve_wire_pipelined<Stage, Handler, OutBuf>(router: const Router&, wire_in: const u8[:], stage: Stage&, handler: Handler&, wire_out: OutBuf&) -> i64, i64, bool, bool
fn serve_ring_pipelined<Stage, Handler, OutBuf>(router: const Router&, rx_ring: core::RingBuffer&, stage: Stage&, handler: Handler&, wire_out: OutBuf&) -> i64, bool, bool
fn serve_stream<Io, Stage, Handler>(io: Io&, router: const Router&, stage: Stage&, handler: Handler&, timeout_ms: u32 = 2000) -> i64
fn serve_tcp_listener<Stage, Handler>(lis: const TcpListener&, router: const Router&, stage: Stage&, handler: Handler&, max_conns: i64 = 1, timeout_ms: u32 = 2000) -> i64
```

Custom middleware stages implement `fn h1::on_ingress(...) -> h1::StageVerdict`
and `fn h1::on_egress(...)` and compose at compile time with `h1::chain_stages`.
Unwired stages are absent from memory and generated C. `serve_stream` uses a
single 4 KB `core::RingBuffer` and a 4 KB output buffer (~12 KB total stack
frame per connection) and runs on the default 2 MB Windows stack.

### `h1/client.goose`: minimal zero-copy HTTP/1.1 client

```goose
struct ResponseHeadView { raw: const u8[:], status_code: u16, headers: HeaderSlice[..64], body: const u8[:], content_length: i64, flags: u16 }

fn header(res: const ResponseHeadView&, name: const u8[:]) -> const u8[:]
fn encode_client_request<B>(method: const u8[:], target: const u8[:], host: const u8[:], extra_hdrs: const u8[:], body: const u8[:], out: B&) -> bool
fn parse_response_view(wire: const u8[:], is_head_req: bool) -> ResponseHeadView, i64, ParseStatus
fn exchange_stream<Io, RxBuf>(io: Io&, method: const u8[:], target: const u8[:], host: const u8[:], extra_hdrs: const u8[:], req_body: const u8[:], rx_buf: RxBuf&, timeout_ms: u32 = 5000) -> ResponseHeadView, bool
```

## Footprint comparison

Measured on a minimal routed `GET /health` HTTP/1.1 service on Windows x64
(MinGW GCC 16.2, `--debug -O0` executable build):

| Metric | Full `wing` + `server::HttpServer` | Modular `wing_h1` + `h1::Router` |
| :--- | :---: | :---: |
| Generated C (`-O0`) | 8.26 MB (3,933 ms) | 277.6 KB (77 ms) |
| Generated C (`-O2`) | 16.66 MB (6,167 ms) | 476.4 KB (100 ms) |
| Native build (`--debug -O0`) | 39,891 ms | 3,980 ms cold / 1,002 ms warm |
| Executable size (`--debug -O0`) | 7.14 MB | 903.8 KB |
| `tls_`, `http2_`, `http3_`, `quic_`, `grpc_` symbols | Present | 0 |
| Default 2 MB Windows stack | Requires larger stack | Passes |
