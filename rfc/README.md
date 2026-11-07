# RFC Protocol Constants & Pure Predicates (`rfc.goose`)

Centralized wire constants, status codes, frame types, cryptographic
identifiers, and stateless validation predicates for HTTP, HTTP/2, HTTP/3, QUIC,
TLS 1.3, WebSocket, and gRPC.

Top-level umbrella module `rfc.goose` re-exports `rfc/http.goose`,
`rfc/h2.goose`, `rfc/h3_quic.goose`, `rfc/tls.goose`, `rfc/ws.goose`, and
`rfc/grpc.goose` into the `rfc` namespace.

```goose
import rfc;

if is_safe_http_method(METHOD_GET) && is_redirect_status(302) {
    let line = status_line_h1(STATUS_OK);
}
```

## Submodules

### HTTP Semantics, Caching, Security & Auth Constants (`rfc/http.goose`)

```goose
const STATUS_CONTINUE: i32 = 100
const STATUS_NETWORK_AUTHENTICATION_REQUIRED: i32 = 511
const HTTP1_STATUS_200: const u8[:]
const HTTP1_STATUS_504: const u8[:]

const METHOD_GET: const u8[:] = "GET"
const METHOD_HEAD: const u8[:] = "HEAD"
const METHOD_POST: const u8[:] = "POST"
const METHOD_PUT: const u8[:] = "PUT"
const METHOD_DELETE: const u8[:] = "DELETE"
const METHOD_CONNECT: const u8[:] = "CONNECT"
const METHOD_OPTIONS: const u8[:] = "OPTIONS"
const METHOD_TRACE: const u8[:] = "TRACE"
const METHOD_PATCH: const u8[:] = "PATCH"
const METHOD_QUERY: const u8[:] = "QUERY"

const HEADER_HOST: const u8[:]
const HEADER_CONTENT_DISPOSITION: const u8[:]
const HEADER_CONTENT_DIGEST: const u8[:]
const HEADER_SIGNATURE_INPUT: const u8[:]
const MIME_TEXT_PLAIN: const u8[:]
const MIME_PARTIAL_UPLOAD: const u8[:]

const BHTTP_FRAME_KNOWN_LEN_REQUEST: u8 = 0
const BHTTP_FRAME_KNOWN_LEN_RESPONSE: u8 = 1
const OHTTP_HDR_LEN: i64 = 7
const DCZ_MAGIC_BYTE0: u8 = 0xFF
const DCB_MAGIC_BYTE0: u8 = 0xFF
const PRIORITY_URGENCY_HIGHEST: u8 = 0
const PRIORITY_URGENCY_DEFAULT: u8 = 3
const PRIORITY_URGENCY_LOWEST: u8 = 7
const SCHEME_PRIVATE_TOKEN: const u8[:] = "PrivateToken"

fn status_phrase(code: i32) -> const u8[:]
fn status_line_h1(code: i32) -> const u8[:]
fn is_empty_body_status(code: i32) -> bool
fn is_redirect_status(code: i32) -> bool
fn is_heuristically_cacheable_status(status_code: i32) -> bool
fn is_safe_http_method(method: const u8[:]) -> bool
fn is_idempotent_method(method: const u8[:]) -> bool
fn is_safe_for_early_data(method: const u8[:]) -> bool
fn is_disallowed_control_trailer(name: const u8[:]) -> bool
fn is_disallowed_content_or_cond_trailer(name: const u8[:]) -> bool
fn is_disallowed_trailer_field(hname: const u8[:]) -> bool
fn is_payload_or_conditional_header(hname: const u8[:]) -> bool
fn bhttp_is_reserved_pseudo(name: const u8[:]) -> bool
fn is_supported_digest_algo(algo: const u8[:]) -> bool
fn is_sess_digest_algo(algo: const u8[:]) -> bool
fn is_valid_dpop_nonce(nonce: const u8[:]) -> bool
fn is_standard_jws_header_param(name: const u8[:]) -> bool
fn is_jwt_standard_claim_name(name: const u8[:]) -> bool
fn is_grease_token_type(t: u16) -> bool
```

Covers RFC 9110 and RFC 9112 status codes (`100`..`511`), pre-formatted HTTP/1.1
status lines, safe and idempotent method classifiers (including RFC 8470 `0-RTT`
early data rules), forbidden trailer field checks (RFC 9110 §6.5.1), Binary HTTP
(RFC 9292), Oblivious HTTP (RFC 9458), Compression Dictionaries (RFC 9842),
Extensible Priorities (RFC 9218), HTTP Message Signatures (RFC 9421), Digest
Fields (RFC 9530), HTTP Digest Auth (RFC 7616), OAuth 2.0 DPoP (RFC 9449), and
Privacy Pass (RFC 9577).

### HTTP/2 & HPACK Wire Constants (`rfc/h2.goose`, RFC 9113, RFC 7541)

```goose
const H2_FRAME_DATA: u8 = 0x00
const H2_FRAME_PRIORITY_UPDATE: u8 = 0x10
const H2_FLAG_END_STREAM: u8 = 0x01
const H2_FLAG_ACK: u8 = 0x01
const H2_FLAG_END_HEADERS: u8 = 0x04
const H2_FLAG_PADDED: u8 = 0x08
const H2_FLAG_PRIORITY: u8 = 0x20
const H2_ERR_NO_ERROR: u32 = 0x00
const H2_ERR_HTTP_1_1_REQUIRED: u32 = 0x0D
const H2_SETTING_HEADER_TABLE_SIZE: u16 = 0x01
const H2_SETTING_NO_RFC7540_PRIORITIES: u16 = 0x09
const H2_FRAME_HEADER_LEN: i64 = 9
const H2_DEFAULT_WINDOW_SIZE: i64 = 65535
const H2_MAX_WINDOW_SIZE: i64 = 2147483647
const H2_DEFAULT_MAX_FRAME_SIZE: u32 = 16384
const H2_MAX_FRAME_SIZE_LIMIT: u32 = 16777215
const HPACK_STATIC_TABLE_ENTRIES: u64 = 61
const HPACK_ENTRY_OVERHEAD: u64 = 32
const HPACK_DEFAULT_MAX_DYN_SIZE: u64 = 4096
let H2_CLIENT_PREFACE: const u8[24]

fn validate_stream_id_association(stream_id: u32, frame_type: u8) -> u32
fn validate_goaway_last_stream_id(last_stream_id: u32, sender_is_client: bool) -> bool
```

Defines RFC 9113 9-byte frame headers, frame types (`0x00`..`0x10`), flags,
error codes (`0x00`..`0x0D`), settings parameters (`0x01`..`0x09`), flow-control
window limits, and RFC 7541 HPACK table sizing constants.
`validate_stream_id_association` returns `H2_ERR_NO_ERROR` when `stream_id` is
valid for `frame_type` (`0` for connection-level frames, non-zero for
stream-level frames) or `H2_ERR_PROTOCOL_ERROR` otherwise.

### QUIC, HTTP/3, QPACK, MASQUE & DNS Constants (`rfc/h3_quic.goose`)

```goose
const QUIC_VERSION_1: u32 = 0x00000001
const QUIC_VERSION_2: u32 = 0x6b3343cf
const QUIC_VERSION_NEGOTIATION: u32 = 0x00000000
const QUIC_MIN_INITIAL_DATAGRAM_LEN: i64 = 1200
const QUIC_MAX_CID_LEN: i64 = 20
const QUIC_VARINT_MAX: u64 = 4611686018427387903
const QUIC_ERR_NO_ERROR: u64 = 0x00
const QUIC_ERR_NO_VIABLE_PATH: u64 = 0x10
const QUIC_FRAME_PADDING: u64 = 0x00
const QUIC_FRAME_ACK_FREQUENCY: u64 = 0xaf
const QUIC_TP_ORIGINAL_DESTINATION_CONNECTION_ID: u64 = 0x00
const QUIC_TP_MIN_ACK_DELAY: u64
const QUIC_V1_INITIAL_SALT: const u8[20]
const QUIC_V2_INITIAL_SALT: const u8[20]
const PMTU_BASE: i64 = 1200
const PMTU_ETHERNET: i64 = 1500

const QPACK_STATIC_TABLE_SIZE: i64 = 99
const QPACK_ENTRY_OVERHEAD: i64 = 32
const H3_ERR_NO_ERROR: u64 = 0x0100
const H3_ERR_QPACK_DECODER_STREAM_ERROR: u64 = 0x0202
const H3_FRAME_DATA: u64 = 0x00
const H3_FRAME_PRIORITY_UPDATE_PUSH: u64 = 0x0f0701
const H3_STREAM_CONTROL: u64 = 0x00
const H3_STREAM_PUSH: u64 = 0x01
const H3_STREAM_QPACK_ENCODER: u64 = 0x02
const H3_STREAM_QPACK_DECODER: u64 = 0x03
const H3_SETTING_QPACK_MAX_TABLE_CAPACITY: u64 = 0x01
const H3_SETTING_H3_DATAGRAM: u64 = 0x33

const CAPSULE_DATAGRAM: u64 = 0x00
const WEBTRANSPORT_ERROR_LAST: u64
const DNS_QTYPE_A: u16 = 1
const DNS_QTYPE_AAAA: u16 = 28
const DNS_QTYPE_HTTPS: u16 = 65
const SVC_PARAM_ALPN: u16 = 1
const SVC_PARAM_IPV6HINT: u16 = 6
const SOCKS5_VER: u8 = 0x05
const SOCKS5_CMD_CONNECT: u8 = 0x01
const SOCKS5_ATYP_IPV4: u8 = 0x01
const SOCKS5_ATYP_DOMAIN: u8 = 0x03
const SOCKS5_ATYP_IPV6: u8 = 0x04

fn is_h3_grease_frame(frame_type: u64) -> bool
fn is_h2_reserved_frame_in_h3(frame_type: u64) -> bool
fn is_allowed_on_control_stream(frame_type: u64) -> bool
fn is_allowed_on_request_stream(frame_type: u64) -> bool
fn is_h2_reserved_setting_in_h3(id: u64) -> bool
```

Covers QUIC v1 and v2 (RFC 9000, RFC 9369), HTTP/3 frame and stream rules (RFC
9114), QPACK (RFC 9204), MASQUE and WebTransport capsules (RFC 9297, RFC 9298,
RFC 9484), DNS SVCB/HTTPS records (RFC 9460), and SOCKS5 (RFC 1928).

### TLS 1.3, X.509, HPKE/ECH & Post-Quantum Constants (`rfc/tls.goose`)

```goose
const TLS_CONTENT_CHANGE_CIPHER_SPEC: u8 = 20
const TLS_CONTENT_APPLICATION_DATA: u8 = 23
const TLS_VERSION_1_3: u16 = 0x0304
const TLS_MAX_RECORD_PLAINTEXT_LEN: i64 = 16384
const TLS_MAX_INNER_PLAINTEXT_LEN: i64 = 16385
const TLS_MAX_RECORD_CIPHERTEXT_LEN: i64 = 16640
const TLS_HS_CLIENT_HELLO: u8 = 1
const TLS_HS_MESSAGE_HASH: u8 = 254
const TLS_EXT_SERVER_NAME: u16 = 0
const TLS_EXT_QUIC_TRANSPORT_PARAMETERS: u16 = 0x0039
const TLS_ALERT_CLOSE_NOTIFY: u8 = 0
const TLS_ALERT_NO_APPLICATION_PROTOCOL: u8 = 120
const TLS_CIPHER_AES_128_GCM_SHA256: u16 = 0x1301
const TLS_CIPHER_AES_256_GCM_SHA384: u16 = 0x1302
const TLS_CIPHER_CHACHA20_POLY1305_SHA256: u16 = 0x1303
const HRR_RANDOM: const u8[32]
const DOWNGRADE_SENTINEL_TLS12: const u8[8]
const DOWNGRADE_SENTINEL_TLS11: const u8[8]

const CERT_COMPRESSION_ZLIB: u16 = 1
const CERT_COMPRESSION_BROTLI: u16 = 2
const CERT_COMPRESSION_ZSTD: u16 = 3
const GROUP_SECP256R1: u16 = 0x0017
const GROUP_SECP384R1: u16 = 0x0018
const GROUP_X25519: u16 = 0x001D
const GROUP_X25519_MLKEM768: u16 = 0x11EC
const GROUP_SECP256R1_MLKEM768: u16
const GROUP_SECP384R1_MLKEM1024: u16
const ASN1_TAG_BOOLEAN: u8 = 0x01
const ASN1_TAG_SET: u8 = 0x31
const OID_COMMON_NAME: const u8[:]
const OID_SIG_SHA1_DSA: const u8[:]
const SIG_SCHEME_RSA_PKCS1_SHA256: u16 = 0x0401
const SIG_SCHEME_ED25519: u16 = 0x0807

fn is_valid_ccs_payload(payload: const u8[:]) -> bool
fn is_known_tls_extension(ext_type: u16) -> bool
fn is_permitted_cert_req_extension(ext_type: u16) -> bool
fn is_forbidden_cert_req_extension(ext_type: u16) -> bool
fn is_forbidden_nst_extension(ext_type: u16) -> bool
fn is_forbidden_ch_extension(ext_type: u16) -> bool
fn is_permitted_sh_extension(ext_type: u16) -> bool
fn is_forbidden_sh_extension(ext_type: u16) -> bool
fn is_permitted_hrr_extension(ext_type: u16) -> bool
fn is_forbidden_hrr_extension(ext_type: u16) -> bool
fn is_permitted_ee_extension(ext_type: u16) -> bool
fn is_forbidden_ee_extension(ext_type: u16) -> bool
fn is_supported_tls13_cipher_suite(cs: u16) -> bool
fn tls13_cipher_suite_key_len(cs: u16) -> u16
fn tls13_cipher_suite_hash_len(cs: u16) -> u8
fn is_valid_compression_algorithm(algo: u16) -> bool
fn is_within_decompression_ratio(uncompressed_len: u32, compressed_len: u32) -> bool
fn is_x25519_pq_group(group: u16) -> bool
fn is_post_quantum_group(group: u16) -> bool
fn is_forbidden_tls13_sig_scheme(sig_scheme: u16) -> bool
fn is_forbidden_cert_signature_algorithm(sig_alg_oid: const u8[:]) -> bool
fn is_grease_u16(val: u16) -> bool
```

Enforces RFC 8446 TLS 1.3 handshake extension placement rules across
`ClientHello`, `ServerHello`, `HelloRetryRequest`, `EncryptedExtensions`,
`CertificateRequest`, and `NewSessionTicket`, RFC 8879 certificate compression
limits, RFC 9180 HPKE/ECH parameters, post-quantum hybrid key exchange groups
(`X25519MLKEM768`, `SecP256r1MLKEM768`, `SecP384r1MLKEM1024`), and ASN.1 DER
X.509 signature OIDs.

### WebSocket Framing & Close Code Constants (`rfc/ws.goose`, RFC 6455)

```goose
const WS_OPCODE_CONTINUATION: u8 = 0x00
const WS_OPCODE_TEXT: u8 = 0x01
const WS_OPCODE_BINARY: u8 = 0x02
const WS_OPCODE_CLOSE: u8 = 0x08
const WS_OPCODE_PING: u8 = 0x09
const WS_OPCODE_PONG: u8 = 0x0A
const WS_STATUS_NORMAL: u16 = 1000
const WS_STATUS_INTERNAL_ERROR: u16 = 1011
let WS_HANDSHAKE_GUID: const u8[:]
const WS_OPCODE_LUT: const bool[256]

fn is_ws_control_opcode(opcode: u8) -> bool
fn is_valid_ws_opcode(opcode: u8) -> bool
fn is_valid_ws_close_code(code: u16) -> bool
```

Defines RFC 6455 frame opcodes (`0x00`..`0x0A`), close status codes
(`1000`..`1011`), and the handshake GUID
(`258EAFA5-E914-47DA-95CA-C5AB0DC85B11`). `is_valid_ws_close_code` rejects
reserved wire codes (`1004`, `1005`, `1006`, `1015`) and out-of-range values
outside `1000..4999`.

### gRPC & gRPC-Web Framing Constants (`rfc/grpc.goose`)

```goose
const GRPC_DEFAULT_MAX_MESSAGE_SIZE: u32 = 4194304
const GRPC_LPM_HEADER_LEN: u32 = 5
const GRPC_FLAG_UNCOMPRESSED: u8 = 0x00
const GRPC_FLAG_COMPRESSED: u8 = 0x01
const GRPC_WEB_FLAG_TRAILERS: u8 = 0x80
const MIME_GRPC: const u8[:]
const MIME_GRPC_PROTO: const u8[:]
const PROTO_TAG_STATUS_CODE: u8 = 0x08
const PROTO_TAG_STATUS_MESSAGE: u8 = 0x12
const GRPC_CONTENT_TYPE: const u8[:]
const GRPC_WEB_TEXT_PROTO: const u8[:]
const HEADER_GRPC_STATUS: const u8[:]
const HEADER_GRPC_MESSAGE: const u8[:]
const HEADER_GRPC_TIMEOUT: const u8[:]
const HEADER_GRPC_ENCODING: const u8[:]
const HEADER_GRPC_ACCEPT_ENCODING: const u8[:]
const HEADER_GRPC_STATUS_DETAILS_BIN: const u8[:]
```

Defines 5-byte Length-Prefixed Message header flags, Protobuf
`google.rpc.Status` wire tags, MIME types, and metadata header names for gRPC
and gRPC-Web.
