# `grpc`

Package `grpc` (`namespace grpc;`) implements the gRPC and Connect-RPC transport
protocol engine over HTTP/2, HTTP/3, and gRPC-Web (binary and Base64 text),
providing Length-Prefixed Message framing, Protobuf `google.rpc.Status` codecs,
Connect envelopes, health checks, client RPCs, and server dispatching.

Internal helpers are isolated in `namespace grpc_internal;` across
`grpc/internal.goose` and `grpc/server_internal.goose`.

```goose
import wing;

var cfg = grpc::new_call_config("helloworld.Greeter", "SayHello");
var req = wing::Request { .. };
cfg.build_http_request("https://api.example.com", payload, req);
```

## Public API

### 1. Canonical status codes, error details & wire helpers (`grpc/constants.goose`)

```goose
enum StatusCode {
    Ok, Cancelled, Unknown, InvalidArgument, DeadlineExceeded, NotFound,
    AlreadyExists, PermissionDenied, ResourceExhausted, FailedPrecondition,
    Aborted, OutOfRange, Unimplemented, Internal, Unavailable, DataLoss,
    Unauthenticated,
}

struct Metadata { key: u8[..64], value: u8[..256] }
struct ErrorDetail { type_url: u8[..128], value: u8[..256] }
struct Status {
    code:    StatusCode,
    message: u8[..256],
    details: ErrorDetail[..4],
}

fn status_name(code: StatusCode) -> const u8[:]
fn status_to_code(code: StatusCode) -> u32
fn status_from_code(code: u32) -> StatusCode
fn status_from_http(http_status: i32) -> StatusCode
fn is_content_type(ct: const u8[:]) -> bool
fn h2_error_to_status(h2_err: u32) -> StatusCode
```

Defines canonical wire status mappings (`0`..`16`), HTTP status fallback
mappings (`400`, `401`, `403`, `404`, `429`, `502`, `503`, `504`), and RFC 9113
HTTP/2 `RST_STREAM` / `GOAWAY` error mappings. Wire constants
(`GRPC_LPM_HEADER_LEN`, `GRPC_FLAG_COMPRESSED`, `GRPC_WEB_FLAG_TRAILERS`,
`GRPC_DEFAULT_MAX_MESSAGE_SIZE`, content types, and protocol header names) live
in `namespace rfc;` (`rfc/grpc.goose`).

### 2. Length-prefixed message framing & Protobuf primitives (`grpc/framing.goose`)

```goose
struct StreamParser {
    max_size:  u32,
    read_pos:  i64,
    has_error: bool,
    buf:       u8[>..],
}

const PB_WIRE_VARINT:   u32 = 0
const PB_WIRE_I64:      u32 = 1
const PB_WIRE_LEN:      u32 = 2
const PB_WIRE_I32:      u32 = 5
const PB_MAX_FIELD_NUM: u32 = 0x1FFFFFFF

fn encode_lpm<B>(payload: const u8[:], out: B&, compressed: bool = false)
fn decode_lpm_slice(wire: const u8[:], offset: u32) -> const u8[:], bool, u32, bool
fn decode_lpm<B>(wire: const u8[:], offset: u32, out: B&, out_compressed: bool&) -> u32, bool
fn new_stream_parser(max_msg_size: u32 = rfc::GRPC_DEFAULT_MAX_MESSAGE_SIZE) -> StreamParser
fn reset(p: StreamParser&)
fn feed(p: StreamParser&, chunk: const u8[:]) -> bool
fn next_message<B>(p: StreamParser&, out: B&, out_compressed: bool&) -> bool
fn encode_web_trailers_with_meta<B>(status: StatusCode, message: const u8[:], extra_trailers: const Metadata[:], out: B&)
fn encode_web_trailers<B>(status: StatusCode, message: const u8[:], out: B&)
fn decode_web_frame<B>(wire: const u8[:], offset: u32, out: B&, out_is_trailers: bool&, out_compressed: bool&) -> u32, bool
fn parse_web_trailers<B>(trailer_bytes: const u8[:], out_status: StatusCode&, out_message: B&) -> bool
fn encode_web_text<B>(binary_lpm: const u8[:], out: B&)
fn decode_web_text<B>(b64_stream: const u8[:], out: B&) -> bool
fn pb_read_varint(wire: const u8[:], idx: i64&) -> u64, bool
fn pb_write_varint<B>(val: u64, out: B&) -> bool
fn pb_skip_field(wire: const u8[:], idx: i64&, wire_type: u32) -> bool
fn pb_read_varint_field(wire: const u8[:], field_num: u32) -> u64, bool
fn pb_write_varint_field<B>(field_num: u32, val: u64, out: B&) -> bool
fn pb_read_bytes_field(wire: const u8[:], field_num: u32) -> const u8[:], bool
fn pb_write_bytes_field<B>(field_num: u32, payload: const u8[:], out: B&) -> bool
```

Length-Prefixed Messages use a 5-byte header
(`[flag: u8][len: u32_be][payload]`) where flag `0x01` marks compressed payloads
and `0x80` marks gRPC-Web trailer frames. `decode_lpm_slice` returns
`(payload_slice, is_compressed, bytes_consumed, ok)` without copying;
`StreamParser` reassembles segmented HTTP/2 or HTTP/3 `DATA` chunks and rejects
frames exceeding `max_size`.

### 3. Connect protocol codec (`grpc/connect.goose`)

```goose
const CONNECT_FLAG_END_STREAM: u8          = 0x02
const CONNECT_CONTENT_PREFIX:  const u8[:] = "application/connect+"
const CONNECT_MIME_PROTO:      const u8[:] = "application/proto"
const CONNECT_MIME_JSON:       const u8[:] = "application/json"

struct ConnectUnaryGetParams {
    encoding:    u8[..16],
    compression: u8[..16],
    base64:      bool,
    has_version: bool,
}

fn parse_connect_get_query(query: const u8[:], out_params: ConnectUnaryGetParams&, out_payload: u8[>..]&) -> StatusCode
fn encode_connect_end_stream<B>(code: StatusCode, message: const u8[:], trailers: const wing::HeaderMap&, out: B&) -> bool
fn parse_connect_end_stream<B>(json_bytes: const u8[:], out_status: StatusCode&, out_message: B&, out_trailers: wing::HeaderMap&) -> bool
```

Decodes Connect Protocol unary HTTP GET query strings (`connect=v1`) and
encodes/parses streaming `EndStream` (`0x02`) JSON error and trailer envelopes.

### 4. Status header, timeout & rich error codecs (`grpc/status.goose`, RFC 3986)

```goose
fn ok() -> Status
fn error(code: StatusCode, message: const u8[:]) -> Status
fn encode_message<B>(raw: const u8[:], out: B&, max_out_len: i64 = -1)
fn decode_message<B>(encoded: const u8[:], out: B&)
fn encode_timeout<B>(timeout_ms: u64, out: B&)
fn parse_timeout(val: const u8[:]) -> u64, bool
fn extract_status<B>(headers: const wing::HeaderMap&, trailers: const wing::HeaderMap&, out_status: StatusCode&, out_message: B&) -> bool
fn build_status_details(code: i32, msg: const u8[:], dst: u8[:]) -> i32, bool
fn decode_status_details<B>(b64_val: const u8[:], expected_code: StatusCode, out_status: StatusCode&, out_msg: B&, out_details: ErrorDetail[..4]&) -> bool
```

Serializes and parses Protobuf `google.rpc.Status` messages and nested
`google.protobuf.Any` error details (`ErrorDetail`) in Base64 for
`grpc-status-details-bin`, percent-encodes `grpc-message` header values, and
converts `grpc-timeout` strings across `H`, `M`, `S`, `m`, `u`, and `n` units.
`extract_status` inspects HTTP trailers or `Trailers-Only` response headers and
falls back to HTTP status code mapping when `grpc-status` is absent.

### 5. gRPC client (`grpc/client.goose`)

```goose
struct CallConfig { .. }
struct Response {
    status:           StatusCode,
    message:          u8[..256],
    details:          ErrorDetail[..4],
    is_compressed:    bool,
    is_trailers_only: bool,
    payload:          u8[>..],
}
struct ClientStreamOptions { .. }
struct ClientStream { .. }

fn new_call_config(service: const u8[:], method: const u8[:]) -> CallConfig
fn is_success(res: const Response&) -> bool
fn build_request_headers(cfg: const CallConfig&, host: const u8[:], scheme: const u8[:], out_headers: wing::HeaderMap&)
fn build_http_request(cfg: const CallConfig&, base_url: const u8[:], serialized_msg: const u8[:], out_req: wing::Request&)
fn parse_unary_response(res_headers: const wing::HeaderMap&, res_trailers: const wing::HeaderMap&, body: const u8[:], is_web: bool, out_resp: Response&) -> bool
fn parse_status_code(status_val: const u8[:]) -> u32
fn process_web_response(body: const u8[:], ct: const u8[:], out_resp: Response&) -> bool
fn unary_call(session: wing::Session&, base_url: const u8[:], cfg: const CallConfig&, request_msg: const u8[:], out_resp: Response&) -> bool
fn new_client_stream(stream_id: u32, opts: ClientStreamOptions = ClientStreamOptions { .. }) -> ClientStream
fn write_stream_message<B>(stream: ClientStream&, payload: const u8[:], out: B&)
fn feed_stream_chunk(stream: ClientStream&, chunk: const u8[:]) -> bool
fn read_stream_message<B>(stream: ClientStream&, out: B&, out_compressed: bool&) -> bool
```

`CallConfig` specifies the target service, method, timeout, compression,
gRPC-Web mode (`is_web`, `is_web_text`), and custom metadata headers.
`unary_call` executes a unary exchange over `wing::Session`, while
`ClientStream` frames outbound streaming messages
(`stream.write_stream_message`) and reassembles inbound `DATA` chunks
(`stream.feed_stream_chunk`, `stream.read_stream_message`).

### 6. gRPC server dispatcher & built-in health service (`grpc/server.goose`, `grpc/health.goose`)

```goose
enum MethodType { Unary, ClientStreaming, ServerStreaming, BidiStreaming }
enum Idempotency { Default, Idempotent, NoSideEffects }
enum ServingStatus { Unknown, Serving, NotServing, ServiceUnknown }
struct HealthServiceEntry { service: u8[..128], status: ServingStatus }
struct ServerContext { .. }
struct MethodEntry { .. }
struct ServerDispatcher {
    methods:          MethodEntry[..64],
    health_entries:   HealthServiceEntry[..32],
    max_message_size: u32,
    enable_web:       bool,
}
struct MessageSpan { offset: u32, len: u32, compressed: bool }
struct ClientStreamReader { .. }
struct ServerStreamWriter { .. }
enum H2StreamState { Idle, ReservedLocal, ReservedRemote, Open, HalfClosedLocal, HalfClosedRemote, Closed }
struct H2Stream { .. }
struct LpmReader { .. }
struct LpmWriter { .. }

fn parse_path<S, M>(path: const u8[:], out_service: S&, out_method: M&) -> bool
fn get_metadata(ctx: const ServerContext&, key: const u8[:]) -> const u8[:]
fn add_response_metadata(ctx: ServerContext&, key: const u8[:], value: const u8[:]) -> bool
fn add_response_trailer(ctx: ServerContext&, key: const u8[:], value: const u8[:]) -> bool
fn is_deadline_exceeded(ctx: const ServerContext&, now_mono_ns: u64) -> bool
fn new_server_dispatcher(max_msg_size: u32 = rfc::GRPC_DEFAULT_MAX_MESSAGE_SIZE) -> ServerDispatcher
fn set_service_health(d: ServerDispatcher&, service: const u8[:], status: ServingStatus) -> bool
fn lookup_service_health(d: const ServerDispatcher&, service: const u8[:]) -> ServingStatus, bool
fn register_unary(d: ServerDispatcher&, service: const u8[:], method: const u8[:], handler_id: u16, idempotency: Idempotency = Idempotency.Default) -> bool
fn register_server_streaming(d: ServerDispatcher&, service: const u8[:], method: const u8[:], handler_id: u16) -> bool
fn register_client_streaming(d: ServerDispatcher&, service: const u8[:], method: const u8[:], handler_id: u16) -> bool
fn register_bidi_streaming(d: ServerDispatcher&, service: const u8[:], method: const u8[:], handler_id: u16) -> bool
fn find_method(d: const ServerDispatcher&, full_path: const u8[:]) -> i64, bool
fn find_method_by_name(d: const ServerDispatcher&, service: const u8[:], method: const u8[:]) -> i64, bool
fn parse_client_stream(raw_body: const u8[:], is_web_text: bool, out_reader: ClientStreamReader&) -> bool
fn get_client_stream_message(reader: const ClientStreamReader&, idx: i64) -> const u8[:]
fn write_stream_message(writer: ServerStreamWriter&, payload: const u8[:], compressed: bool = false)
fn validate_recv_compression(is_compressed: bool, enc: const u8[:], is_server: bool) -> StatusCode
fn handle_builtin_health_check(d: const ServerDispatcher&, req: const wing::Request&, ctx: const ServerContext&, res: wing::Response&) -> bool
fn dispatch_unary<HandlerFn: fn(u16, ServerContext&, const u8[:], u8[>..]&) -> Status>(d: const ServerDispatcher&, req: const wing::Request&, now_mono_ns: u64, res: wing::Response&, req_start_mono_ns: u64 = 0) -> bool
fn on_unary<B>(_stage: wire::NoOpStage&, _handler_id: u16, _ctx: ServerContext&, _req_bytes: const u8[:], _res_bytes: B&) -> Status
fn dispatch_unary_stage<Stage>(d: const ServerDispatcher&, stage: Stage&, req: const wing::Request&, now_mono_ns: u64, res: wing::Response&, req_start_mono_ns: u64 = 0) -> bool
fn dispatch_server_streaming<HandlerFn: fn(u16, ServerContext&, const u8[:], ServerStreamWriter&) -> Status>(d: const ServerDispatcher&, req: const wing::Request&, now_mono_ns: u64, res: wing::Response&, req_start_mono_ns: u64 = 0) -> bool
fn dispatch_client_streaming<HandlerFn: fn(u16, ServerContext&, const ClientStreamReader&, u8[>..]&) -> Status>(d: const ServerDispatcher&, req: const wing::Request&, now_mono_ns: u64, res: wing::Response&, req_start_mono_ns: u64 = 0) -> bool
fn feed_lpm_reader(reader: LpmReader&, raw: const u8[:]) -> bool
fn read_next_lpm(reader: LpmReader&) -> const u8[:], bool
fn write_lpm_frame(writer: LpmWriter&, payload: const u8[:], compressed: bool = false) -> bool
fn dispatch_bidi_streaming(conn: H2Stream&, reader: LpmReader&, writer: LpmWriter&) -> bool
fn emit_h2_response_frames<B>(hpack_enc: http2::DynamicTable&, stream_id: u32, res: const wing::Response&, out: B&)
fn handle_h2_control_frame(conn: i64, hdr: const wire::WireFrameHeader&, payload: const u8[:]) -> bool
fn handle_h2_wire_frame<HandlerFn: fn(u16, ServerContext&, const u8[:], u8[>..]&) -> Status>(conn: i64, server: wing::HttpServer&, d: const ServerDispatcher&, client_ip: const u8[:], hpack_dec: http2::DynamicTable&, hpack_enc: http2::DynamicTable&, pending: wing::Request&, pending_stream_id: u32&, hdr: const wire::WireFrameHeader&, payload: const u8[:], out_wire: u8[..65536]&) -> bool
fn serve_listener<HandlerFn: fn(u16, ServerContext&, const u8[:], u8[>..]&) -> Status>(listener_fd: i64, server: wing::HttpServer&, d: const ServerDispatcher&)
```

`ServerDispatcher` routes up to 64 registered methods (`MethodEntry[..64]`) and
32 `grpc.health.v1.Health` service entries (`HealthServiceEntry[..32]`),
handling unary, server-streaming, client-streaming, bidirectional LPM streaming,
Connect-RPC GET/POST, and gRPC-Web requests while tracking per-call monotonic
deadlines in `ServerContext`.
