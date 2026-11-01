# `grpc`

gRPC transport protocol engine over HTTP/2, HTTP/3, and gRPC-Web (binary and Base64 text), implementing Length-Prefixed Message (LPM) binary framing, canonical status code codecs, client RPC execution, and server dispatching.

## Public API

### Canonical Status Codes & Wire Constants (`constants.goose`)

- **`enum GrpcStatusCode`**: Canonical gRPC status codes (`Ok`, `Cancelled`, `Unknown`, `InvalidArgument`, `DeadlineExceeded`, `NotFound`, `AlreadyExists`, `PermissionDenied`, `ResourceExhausted`, `FailedPrecondition`, `Aborted`, `OutOfRange`, `Unimplemented`, `Internal`, `Unavailable`, `DataLoss`, `Unauthenticated`).
- **`fn grpc_status_name(code: GrpcStatusCode) -> const u8[:]`**: Converts a `GrpcStatusCode` to its standard string representation (`"OK"`, `"NOT_FOUND"`, etc.).
- **`fn grpc_status_to_code(code: GrpcStatusCode) -> u32`**: Converts a `GrpcStatusCode` enum variant to its numeric wire value (`0`..`16`).
- **`fn grpc_status_from_code(code: u32) -> GrpcStatusCode`**: Maps a numeric wire status code to its typed `GrpcStatusCode` variant (unknown values map to `GrpcStatusCode.Unknown`).
- **`fn grpc_status_from_http(http_status: i32) -> GrpcStatusCode`**: Maps standard HTTP response codes to canonical gRPC status codes per specification.
- **`struct GrpcMetadata`**: Key-value metadata pair (`key: u8[..64]`, `value: u8[..256]`).
- **Wire Constants**: `GRPC_LPM_HEADER_LEN` (`5`), `GRPC_FLAG_COMPRESSED` (`0x01`), `GRPC_WEB_FLAG_TRAILERS` (`0x80`), `GRPC_DEFAULT_MAX_MESSAGE_SIZE` (`4194304`).
- **Content-Type Constants**: `GRPC_CONTENT_TYPE`, `GRPC_CONTENT_TYPE_PROTO`, `GRPC_CONTENT_TYPE_JSON`, `GRPC_WEB_CONTENT_TYPE`, `GRPC_WEB_CONTENT_TYPE_PROTO`, `GRPC_WEB_CONTENT_TYPE_JSON`, `GRPC_WEB_TEXT_CONTENT_TYPE`, `GRPC_WEB_TEXT_PROTO`.
- **Header Constants**: `HEADER_GRPC_STATUS`, `HEADER_GRPC_MESSAGE`, `HEADER_GRPC_TIMEOUT`, `HEADER_GRPC_ENCODING`, `HEADER_GRPC_ACCEPT_ENCODING`, `HEADER_GRPC_STATUS_DETAILS_BIN`.

### Length-Prefixed Message Framing & gRPC-Web Codecs (`framing.goose`)

- **`fn encode_grpc_lpm<B>(payload: const u8[:], out: B&, compressed: bool = false)`**: Encodes payload into standard 5-byte Length-Prefixed Message format (`[flag: u8][len: u32_be][payload]`).
- **`fn decode_grpc_lpm_slice(wire: const u8[:], offset: u32) -> const u8[:], bool, u32, bool`**: Zero-copy LPM decoder returning `(payload_slice, is_compressed, bytes_consumed, ok)`.
- **`fn decode_grpc_lpm<B>(wire: const u8[:], offset: u32, out_payload: B&, out_compressed: bool&) -> bool, u32`**: Decodes a single LPM frame into a target buffer.
- **`struct GrpcStreamParser`**: Streaming message reassembler for segmented HTTP/2 or HTTP/3 DATA chunks (`max_size: u32`, `buf: u8[>..]`).
- **`fn new_grpc_stream_parser(max_msg_size: u32 = GRPC_DEFAULT_MAX_MESSAGE_SIZE) -> GrpcStreamParser`**: Initializes a streaming LPM parser.
- **`fn reset(p: GrpcStreamParser&)`**: Clears the internal stream parser buffer.
- **`fn feed(p: GrpcStreamParser&, chunk: const u8[:]) -> bool`**: Ingests incoming wire bytes enforcing maximum message bounds.
- **`fn next_message<B>(p: GrpcStreamParser&, out_payload: B&, out_compressed: bool&) -> bool`**: Extracts the next complete message from the stream buffer.
- **`fn encode_grpc_web_trailers<B>(status: GrpcStatusCode, message: const u8[:], out: B&)`**: Serializes gRPC-Web trailers frame with flag `0x80`.
- **`fn encode_grpc_web_trailers_with_meta<B>(status: GrpcStatusCode, message: const u8[:], extra_trailers: const GrpcMetadata[:], out: B&)`**: Serializes gRPC-Web trailers frame including custom metadata.
- **`fn decode_grpc_web_frame<B>(wire: const u8[:], offset: u32, out_payload: B&, out_is_trailers: bool&, out_compressed: bool&) -> bool, u32`**: Decodes gRPC-Web frames distinguishing message data from trailer blocks.
- **`fn parse_grpc_web_trailers(trailer_bytes: const u8[:], out_status: GrpcStatusCode&, out_message: u8[..256]&) -> bool`**: Parses gRPC-Web body trailers block to extract status and percent-decoded message.
- **`fn encode_grpc_web_text<B>(binary_lpm: const u8[:], out: B&)`**: Encodes binary LPM wire stream into standard Base64 for `application/grpc-web-text`.
- **`fn decode_grpc_web_text<B>(b64_stream: const u8[:], out: B&) -> bool`**: Decodes `application/grpc-web-text` Base64 stream into raw binary LPM frames.

### Status Header & Timeout Codecs (`status.goose`, RFC 3986)

- **`fn encode_grpc_message<B>(raw: const u8[:], out: B&)`**: Percent-encodes error message strings for `grpc-message` headers.
- **`fn decode_grpc_message<B>(encoded: const u8[:], out: B&)`**: Percent-decodes `grpc-message` headers into raw UTF-8 string bytes.
- **`fn encode_grpc_timeout<B>(timeout_ms: u64, out: B&)`**: Formats a millisecond duration into standard gRPC timeout notation (`H`, `M`, `S`, `m`).
- **`fn parse_grpc_timeout(val: const u8[:]) -> u64, bool`**: Parses a gRPC timeout string into milliseconds supporting `H`, `M`, `S`, `m`, `u`, and `n` units.
- **`fn extract_grpc_status(headers: const HeaderMap&, trailers: const HeaderMap&, out_status: GrpcStatusCode&, out_message: u8[..256]&) -> bool`**: Extracts status code and message from trailers or headers (Trailers-Only), with fallback to HTTP status mapping.

### gRPC Client (`client.goose`)

- **`struct GrpcCallConfig`**: RPC call parameters (`service`, `method`, `timeout_ms`, `is_web`, `is_web_text`, `use_compression`, `metadata`).
- **`fn new_grpc_call_config(service: const u8[:], method: const u8[:]) -> GrpcCallConfig`**: Initializes an RPC call configuration.
- **`struct GrpcResponse`**: Parsed RPC response representation (`status`, `message`, `is_compressed`, `is_trailers_only`, `payload`).
- **`fn is_grpc_success(res: const GrpcResponse&) -> bool`**: Returns `true` if `res.status == GrpcStatusCode.Ok`.
- **`fn build_grpc_request_headers(cfg: const GrpcCallConfig&, host: const u8[:], scheme: const u8[:], out_headers: HeaderMap&)`**: Builds low-level HTTP/2 or HTTP/3 headers for gRPC wire dispatch.
- **`fn build_grpc_http_request(cfg: const GrpcCallConfig&, base_url: const u8[:], serialized_msg: const u8[:], out_req: Request&)`**: Builds high-level `Request` with URL path formatting and LPM body encoding.
- **`fn parse_grpc_unary_response(res_headers: const HeaderMap&, res_trailers: const HeaderMap&, body: const u8[:], is_web: bool, out_resp: GrpcResponse&) -> bool`**: Parses a unary RPC response from wire headers, trailers, and body bytes.
- **`fn grpc_unary_call(session: Session&, base_url: const u8[:], cfg: const GrpcCallConfig&, request_msg: const u8[:], out_resp: GrpcResponse&) -> bool`**: Executes a complete end-to-end Unary RPC exchange through a client `Session`.
- **`struct GrpcClientStream`**: Client-side streaming session manager (`stream_id`, `is_active`, `is_web`, `use_compression`, `parser`).
- **`fn new_grpc_client_stream(stream_id: u32, opts: GrpcClientStreamOptions = GrpcClientStreamOptions { .. }) -> GrpcClientStream`**: Initializes a client streaming context.
- **`fn write_stream_message<B>(stream: GrpcClientStream&, payload: const u8[:], out: B&)`**: Serializes an outbound message into wire LPM format for streaming send.
- **`fn feed_stream_chunk(stream: GrpcClientStream&, chunk: const u8[:]) -> bool`**: Ingests an inbound streaming DATA chunk into the client stream parser.
- **`fn read_stream_message<B>(stream: GrpcClientStream&, out_payload: B&, out_compressed: bool&) -> bool`**: Reads the next completed inbound message from the stream.

### gRPC Server Dispatcher (`server.goose`)

- **`enum GrpcMethodType`**: Method archetype (`Unary`, `ClientStreaming`, `ServerStreaming`, `BidiStreaming`).
- **`struct GrpcServerContext`**: Ingress RPC invocation context holding service, method, client peer IP, timeout, monotonic deadline, and metadata headers.
- **`fn get_metadata(ctx: const GrpcServerContext&, key: const u8[:]) -> const u8[:]`**: Case-insensitive lookup of request metadata header.
- **`fn add_response_metadata(ctx: GrpcServerContext&, key: const u8[:], value: const u8[:]) -> bool`**: Buffers a response header entry.
- **`fn add_response_trailer(ctx: GrpcServerContext&, key: const u8[:], value: const u8[:]) -> bool`**: Buffers a response trailer entry.
- **`fn is_deadline_exceeded(ctx: const GrpcServerContext&, now_mono_ns: u64) -> bool`**: Checks if request deadline has expired against current monotonic clock.
- **`struct GrpcServerDispatcher`**: Multi-method RPC dispatcher (`methods: GrpcMethodEntry[..64]`, `max_message_size: u32`, `enable_web: bool`).
- **`fn new_grpc_server_dispatcher(max_msg_size: u32 = GRPC_DEFAULT_MAX_MESSAGE_SIZE) -> GrpcServerDispatcher`**: Initializes a server dispatcher.
- **`fn register_unary(d: GrpcServerDispatcher&, service: const u8[:], method: const u8[:], handler_id: u16) -> bool`**: Registers a unary RPC handler.
- **`fn register_server_streaming(d: GrpcServerDispatcher&, service: const u8[:], method: const u8[:], handler_id: u16) -> bool`**: Registers a server-streaming RPC handler.
- **`fn register_client_streaming(d: GrpcServerDispatcher&, service: const u8[:], method: const u8[:], handler_id: u16) -> bool`**: Registers a client-streaming RPC handler.
- **`fn register_bidi_streaming(d: GrpcServerDispatcher&, service: const u8[:], method: const u8[:], handler_id: u16) -> bool`**: Registers a bidirectional streaming RPC handler.
- **`struct GrpcClientStreamReader`**: Zero-copy client stream inspector providing indexed message access (`get_client_stream_message`).
- **`struct GrpcServerStreamWriter`**: Server stream message writer (`write_stream_message`).
- **`fn dispatch_grpc_unary<HandlerFn>(d: const GrpcServerDispatcher&, req: const Request&, now_mono_ns: u64, res: Response&, req_start_mono_ns: u64 = 0) -> bool`**: Dispatches a unary RPC request to its registered handler.
- **`fn dispatch_grpc_server_streaming<HandlerFn>(d: const GrpcServerDispatcher&, req: const Request&, now_mono_ns: u64, res: Response&, req_start_mono_ns: u64 = 0) -> bool`**: Dispatches a server-streaming RPC request.
- **`fn dispatch_grpc_client_streaming<HandlerFn>(d: const GrpcServerDispatcher&, req: const Request&, now_mono_ns: u64, res: Response&, req_start_mono_ns: u64 = 0) -> bool`**: Dispatches a client-streaming RPC request.
