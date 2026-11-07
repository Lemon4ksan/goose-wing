# gRPC & Connect-RPC Protocol Engine (`grpc/`)

gRPC and Connect-RPC transport protocol engine over HTTP/2, HTTP/3, and gRPC-Web
(binary and Base64 text), implementing Length-Prefixed Message (LPM) binary
framing, Protobuf wire-format `google.rpc.Status` codecs
(`grpc-status-details-bin`), Connect unary GET and streaming end-stream
envelopes, built-in `grpc.health.v1.Health` checks, client RPC execution, and
server dispatching.

```goose
import wing;

var cfg = new_grpc_call_config("helloworld.Greeter", "SayHello");
var req = Request { .. };
build_grpc_http_request(cfg, "https://api.example.com", payload, req);
```

## Public API

### Canonical Status Codes, Error Details & Wire Constants (`grpc/constants.goose`)

```goose
enum GrpcStatusCode {
    Ok, Cancelled, Unknown, InvalidArgument, DeadlineExceeded, NotFound,
    AlreadyExists, PermissionDenied, ResourceExhausted, FailedPrecondition,
    Aborted, OutOfRange, Unimplemented, Internal, Unavailable, DataLoss,
    Unauthenticated,
}
struct GrpcMetadata { key: u8[..64], value: u8[..256] }
struct GrpcErrorDetail { type_url: u8[..128], value: u8[..256] }
struct GrpcStatus {
    code: GrpcStatusCode,
    message: u8[..256],
    details: GrpcErrorDetail[..4],
}

const GRPC_LPM_HEADER_LEN: u32 = 5
const GRPC_FLAG_COMPRESSED: u8 = 0x01
const GRPC_WEB_FLAG_TRAILERS: u8 = 0x80
const CONNECT_FLAG_END_STREAM: u8 = 0x02
const GRPC_DEFAULT_MAX_MESSAGE_SIZE: u32 = 4194304
const CONNECT_CONTENT_PREFIX: const u8[:] = "application/connect+"
const CONNECT_MIME_PROTO: const u8[:] = "application/proto"
const CONNECT_MIME_JSON: const u8[:] = "application/json"

fn grpc_status_name(code: GrpcStatusCode) -> const u8[:]
fn connect_status_name(code: GrpcStatusCode) -> const u8[:]
fn parse_connect_status_code(name: const u8[:]) -> GrpcStatusCode
fn grpc_status_to_code(code: GrpcStatusCode) -> u32
fn grpc_status_from_code(code: u32) -> GrpcStatusCode
fn grpc_status_from_http(http_status: i32) -> GrpcStatusCode
fn h2_error_to_grpc_status(h2_error_code: u32) -> GrpcStatusCode
```

Defines wire status mappings (`0`..`16`), HTTP status fallback mappings (`400`,
`401`, `403`, `404`, `429`, `502`, `503`, `504`), RFC 9113 HTTP/2 `RST_STREAM`
and `GOAWAY` error mappings, MIME content-type constants (`GRPC_CONTENT_TYPE`,
`GRPC_CONTENT_TYPE_PROTO`, `GRPC_CONTENT_TYPE_JSON`, `GRPC_WEB_CONTENT_TYPE`,
`GRPC_WEB_CONTENT_TYPE_PROTO`, `GRPC_WEB_CONTENT_TYPE_JSON`,
`GRPC_WEB_TEXT_CONTENT_TYPE`, `GRPC_WEB_TEXT_PROTO`, `CONNECT_MIME_PROTO`,
`CONNECT_MIME_JSON`, `CONNECT_CONTENT_PREFIX`), and protocol header names
(`HEADER_GRPC_STATUS`, `HEADER_GRPC_MESSAGE`, `HEADER_GRPC_TIMEOUT`,
`HEADER_GRPC_ENCODING`, `HEADER_GRPC_ACCEPT_ENCODING`,
`HEADER_GRPC_STATUS_DETAILS_BIN`).

### Length-Prefixed Message Framing & Connect Envelopes (`grpc/framing.goose`)

```goose
struct GrpcStreamParser { max_size: u32, buf: u8[>..] }
struct ConnectUnaryGetParams {
    encoding: u8[..16],
    message_payload: u8[..4096],
    base64_encoded: bool,
    compression: u8[..16],
    connect_v1: bool,
}

fn encode_grpc_lpm<B>(payload: const u8[:], out: B&, compressed: bool = false)
fn decode_grpc_lpm_slice(wire: const u8[:], offset: u32) -> const u8[:], bool, u32, bool
fn decode_grpc_lpm<B>(wire: const u8[:], offset: u32, out_payload: B&, out_compressed: bool&) -> bool, u32
fn new_grpc_stream_parser(max_msg_size: u32 = GRPC_DEFAULT_MAX_MESSAGE_SIZE) -> GrpcStreamParser
fn reset(p: GrpcStreamParser&)
fn feed(p: GrpcStreamParser&, chunk: const u8[:]) -> bool
fn next_message<B>(p: GrpcStreamParser&, out_payload: B&, out_compressed: bool&) -> bool
fn is_valid_grpc_custom_metadata(key: const u8[:], val: const u8[:]) -> bool
fn encode_grpc_web_trailers<B>(status: GrpcStatusCode, message: const u8[:], out: B&)
fn encode_grpc_web_trailers_with_meta<B>(status: GrpcStatusCode, message: const u8[:], extra_trailers: const GrpcMetadata[:], out: B&)
fn decode_grpc_web_frame<B>(wire: const u8[:], offset: u32, out_payload: B&, out_is_trailers: bool&, out_compressed: bool&) -> bool, u32
fn parse_grpc_web_trailers(trailer_bytes: const u8[:], out_status: GrpcStatusCode&, out_message: u8[..256]&) -> bool
fn encode_grpc_web_text<B>(binary_lpm: const u8[:], out: B&)
fn decode_grpc_web_text<B>(b64_stream: const u8[:], out: B&) -> bool
fn pb_read_varint(buf: const u8[:], idx: i64&) -> u64, bool
fn pb_write_varint<B>(val: u64, out: B&)
fn pb_skip_field(buf: const u8[:], idx: i64&, wire_type: u8) -> bool
fn pb_read_varint_field(buf: const u8[:], idx: i64&, expected_field: u32) -> u64, bool
fn pb_write_varint_field<B>(field_num: u32, val: u64, out: B&)
fn pb_read_bytes_field(buf: const u8[:], idx: i64&) -> const u8[:], bool
fn pb_write_bytes_field<B>(field_num: u32, data: const u8[:], out: B&)
fn parse_connect_get_query(query: const u8[:], out_params: ConnectUnaryGetParams&, out_payload: u8[>..]&) -> GrpcStatusCode
fn encode_connect_end_stream<B>(code: GrpcStatusCode, message: const u8[:], trailers: const HeaderMap&, out: B&) -> bool
fn parse_connect_end_stream(json_bytes: const u8[:], out_status: GrpcStatusCode&, out_message: u8[..256]&, out_trailers: HeaderMap&) -> bool
```

Length-Prefixed Messages use a 5-byte header
(`[flag: u8][len: u32_be][payload]`) where flag `0x01` marks compressed
payloads, `0x80` marks gRPC-Web trailer frames, and `0x02` marks Connect-RPC
streaming end-stream JSON envelopes. `decode_grpc_lpm_slice` returns
`(payload_slice, is_compressed, bytes_consumed,
ok)` without copying; `GrpcStreamParser` reassembles segmented HTTP/2 or HTTP/3
`DATA` chunks and rejects frames exceeding `max_size`.

### Status Header, Timeout & Rich Error Codecs (`grpc/status.goose`, RFC 3986)

```goose
fn grpc_ok() -> GrpcStatus
fn grpc_error(code: GrpcStatusCode, message: const u8[:]) -> GrpcStatus
fn build_grpc_status_details<B>(status: const GrpcStatus&, out_b64: B&)
fn decode_grpc_status_details(b64_val: const u8[:], out_status: GrpcStatus&) -> bool
fn decode_grpc_any_detail(raw_any: const u8[:], out_detail: GrpcErrorDetail&) -> bool
fn encode_grpc_message<B>(raw: const u8[:], out: B&)
fn decode_grpc_message<B>(encoded: const u8[:], out: B&)
fn encode_grpc_timeout<B>(timeout_ms: u64, out: B&)
fn parse_grpc_timeout(val: const u8[:]) -> u64, bool
fn extract_grpc_status(headers: const HeaderMap&, trailers: const HeaderMap&, out_status: GrpcStatusCode&, out_message: u8[..256]&) -> bool
```

Serializes and parses Protobuf `google.rpc.Status` messages and nested
`google.protobuf.Any` error details (`GrpcErrorDetail`) in Base64 for
`grpc-status-details-bin`, percent-encodes `grpc-message` header values, and
converts `grpc-timeout` strings across `H`, `M`, `S`, `m`, `u`, and `n` units.
`extract_grpc_status` inspects HTTP trailers or `Trailers-Only` response headers
and falls back to HTTP status code mapping when `grpc-status` is absent.

### gRPC Client (`grpc/client.goose`)

```goose
struct GrpcCallConfig { .. }
struct GrpcResponse {
    status: GrpcStatusCode,
    message: u8[..256],
    is_compressed: bool,
    is_trailers_only: bool,
    payload: u8[>..],
}
struct GrpcClientStreamOptions { .. }
struct GrpcClientStream { .. }

fn new_grpc_call_config(service: const u8[:], method: const u8[:]) -> GrpcCallConfig
fn is_grpc_success(res: const GrpcResponse&) -> bool
fn build_grpc_request_headers(cfg: const GrpcCallConfig&, host: const u8[:], scheme: const u8[:], out_headers: HeaderMap&)
fn build_grpc_http_request(cfg: const GrpcCallConfig&, base_url: const u8[:], serialized_msg: const u8[:], out_req: Request&)
fn parse_grpc_unary_response(res_headers: const HeaderMap&, res_trailers: const HeaderMap&, body: const u8[:], is_web: bool, out_resp: GrpcResponse&) -> bool
fn grpc_unary_call(session: Session&, base_url: const u8[:], cfg: const GrpcCallConfig&, request_msg: const u8[:], out_resp: GrpcResponse&) -> bool
fn new_grpc_client_stream(stream_id: u32, opts: GrpcClientStreamOptions = GrpcClientStreamOptions { .. }) -> GrpcClientStream
fn write_stream_message<B>(stream: GrpcClientStream&, payload: const u8[:], out: B&)
fn feed_stream_chunk(stream: GrpcClientStream&, chunk: const u8[:]) -> bool
fn read_stream_message<B>(stream: GrpcClientStream&, out_payload: B&, out_compressed: bool&) -> bool
```

`GrpcCallConfig` specifies the target service, method, timeout, compression,
gRPC-Web mode (`is_web`, `is_web_text`), and custom metadata headers.
`grpc_unary_call` executes a unary exchange over `Session`, while
`GrpcClientStream` frames outbound streaming messages (`write_stream_message`)
and reassembles inbound `DATA` chunks (`feed_stream_chunk`,
`read_stream_message`).

### gRPC Server Dispatcher & Built-in Health Service (`grpc/server.goose`)

```goose
enum GrpcMethodType { Unary, ClientStreaming, ServerStreaming, BidiStreaming }
enum GrpcIdempotency { Default, Idempotent, NoSideEffects }
enum GrpcServingStatus { Unknown, Serving, NotServing, ServiceUnknown }
struct GrpcServerContext { .. }
struct GrpcMethodEntry { .. }
struct GrpcHealthServiceEntry { .. }
struct GrpcServerDispatcher {
    methods: GrpcMethodEntry[..64],
    health_entries: GrpcHealthServiceEntry[..16],
    max_message_size: u32,
    enable_web: bool,
}
struct GrpcClientStreamReader { .. }
struct GrpcServerStreamWriter { .. }

fn get_metadata(ctx: const GrpcServerContext&, key: const u8[:]) -> const u8[:]
fn add_response_metadata(ctx: GrpcServerContext&, key: const u8[:], value: const u8[:]) -> bool
fn add_response_trailer(ctx: GrpcServerContext&, key: const u8[:], value: const u8[:]) -> bool
fn is_deadline_exceeded(ctx: const GrpcServerContext&, now_mono_ns: u64) -> bool
fn new_grpc_server_dispatcher(max_msg_size: u32 = GRPC_DEFAULT_MAX_MESSAGE_SIZE) -> GrpcServerDispatcher
fn set_grpc_service_health(d: GrpcServerDispatcher&, service_name: const u8[:], status: GrpcServingStatus) -> bool
fn lookup_grpc_service_health(d: const GrpcServerDispatcher&, service_name: const u8[:]) -> GrpcServingStatus
fn handle_builtin_grpc_health_check(d: const GrpcServerDispatcher&, req_payload: const u8[:], res: Response&) -> bool
fn register_unary(d: GrpcServerDispatcher&, service: const u8[:], method: const u8[:], handler_id: u16) -> bool
fn register_server_streaming(d: GrpcServerDispatcher&, service: const u8[:], method: const u8[:], handler_id: u16) -> bool
fn register_client_streaming(d: GrpcServerDispatcher&, service: const u8[:], method: const u8[:], handler_id: u16) -> bool
fn register_bidi_streaming(d: GrpcServerDispatcher&, service: const u8[:], method: const u8[:], handler_id: u16) -> bool
fn get_client_stream_message(reader: const GrpcClientStreamReader&, idx: i64) -> const u8[:]
fn dispatch_grpc_unary<HandlerFn>(d: const GrpcServerDispatcher&, req: const Request&, now_mono_ns: u64, res: Response&, req_start_mono_ns: u64 = 0) -> bool
fn dispatch_grpc_server_streaming<HandlerFn>(d: const GrpcServerDispatcher&, req: const Request&, now_mono_ns: u64, res: Response&, req_start_mono_ns: u64 = 0) -> bool
fn dispatch_grpc_client_streaming<HandlerFn>(d: const GrpcServerDispatcher&, req: const Request&, now_mono_ns: u64, res: Response&, req_start_mono_ns: u64 = 0) -> bool
```

`GrpcServerDispatcher` routes up to 64 registered methods
(`GrpcMethodEntry[..64]`) and 16 `grpc.health.v1.Health` service entries
(`GrpcHealthServiceEntry[..16]`), handling unary, server-streaming,
client-streaming, Connect-RPC GET/POST, and gRPC-Web requests while tracking
per-call monotonic deadlines in `GrpcServerContext`.
