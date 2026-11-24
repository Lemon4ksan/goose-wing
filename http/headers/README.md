# `http/headers`

Zero-allocation lexical scanner, perfect hashing, and chunked transfer decoding
engine for HTTP headers (RFC 9110, RFC 9112).

## Public API

### Well-Known Header Perfect Hash (`perfect_hash.goose`)

```goose
enum KnownHeaderId {
    Unknown, Host, Date, Accept, Cookie, Origin, Server, Connection,
    UserAgent, ContentType, ContentLength, Authorization,
    TransferEncoding, SecWebSocketKey, Upgrade, Expect,
}

inline fn header_id_to_bit(id: KnownHeaderId) -> u32
fn identify_known_header(name: const u8[:]) -> KnownHeaderId
```

`identify_known_header` classifies an ASCII header name into a `KnownHeaderId`
in O(1) time by branching on slice length and leading byte before comparing the
remaining characters case-insensitively. `header_id_to_bit` converts the
identifier into a 32-bit presence mask bit.

```goose
let id = http::identify_known_header("Content-Length");
let mask_bit = http::header_id_to_bit(id);
```

### Lexical Validation & SWAR Transformations (`lexical.goose`)

```goose
struct HeaderPresenceTracker

fn track_known_header_presence(tracker: HeaderPresenceTracker&, id: KnownHeaderId, val: const u8[:], hdr_idx: i16) -> bool
inline fn track_header_presence(tracker: HeaderPresenceTracker&, name: const u8[:], val: const u8[:], hdr_idx: i16) -> bool
fn swar_to_lower_64(v: u64) -> u64
checkfree inline fn is_valid_header_value_byte(b: u8) -> bool
fn match_http_method_u32(raw: const u8[:]) -> const u8[:], i64, bool
fn is_valid_token_swar(src: const u8[:]) -> bool
fn scan_token_swar(src: const u8[:]) -> i64, bool
fn is_valid_header_name(name: const u8[:]) -> bool
fn is_valid_header_name_h2(name: const u8[:]) -> bool
fn is_valid_header_value(val: const u8[:]) -> bool
fn validate_content_length_value(val: const u8[:]) -> i64, bool
fn is_valid_transfer_coding(coding: const u8[:]) -> bool
fn validate_transfer_encoding_value(val: const u8[:]) -> bool
fn hash_header_name(name: const u8[:]) -> u32
fn scan_header_field_name_swar(src: const u8[:]) -> i64, bool
fn scan_header_field_value_swar(src: const u8[:]) -> i64, i64, bool
```

`HeaderPresenceTracker` maintains well-known header presence bitmasks and
first-seen indices to reject duplicate singleton headers and `Content-Length` /
`Transfer-Encoding` smuggling conflicts (`HDR_PRESENCE_SMUGGLING_MASK`). The
lexical scanners validate RFC 9110 §5.6.2 tokens (`core::TCHAR_LUT`) and §5.5
field values (`HEADER_VAL_LUT`) using 8-byte SWAR word scans
(`is_valid_token_swar`, `scan_token_swar`, `scan_header_field_name_swar`,
`scan_header_field_value_swar`). `validate_content_length_value` rejects
negative or conflicting multi-value `Content-Length` strings, while
`is_valid_transfer_coding` and `validate_transfer_encoding_value` verify
`chunked`, `gzip`, `deflate`, `compress`, and `x-gzip` codings.

### Chunked Transfer Framing & Smuggling Defense (`chunked.goose`)

```goose
enum ChunkedDecodeError {
    None, EmptyInput, InvalidChunkSizeHex, BareLfInChunkSize,
    BareLfInChunkData, BareLfInTrailer, InvalidChunkExtension,
    ChunkSizeOverflow, UnexpectedEof, MalformedChunkEnding,
    DisallowedTrailer, ExcessiveFramingOverhead,
}

fn parse_chunk_extensions(s: const u8[:], cursor: i64&) -> ChunkedDecodeError
fn parse_chunk_size_hex(chunk_size_line: const u8[:]) -> u64, ChunkedDecodeError
fn parse_single_trailer_field(tr_line: const u8[:], out_trailers: HeaderMap&) -> ChunkedDecodeError
fn parse_chunked_trailers_with_out(raw: const u8[:], cursor: i64&, out_trailers: HeaderMap&) -> ChunkedDecodeError
fn decode_chunked_body_with_trailers(raw: const u8[:], out_body: u8[>..]&, out_trailers: HeaderMap&) -> ChunkedDecodeError, i64
fn decode_chunked_body(raw: const u8[:], out_body: u8[>..]&) -> ChunkedDecodeError
```

Decodes RFC 9112 §7.1 chunked transfer streams while rejecting bare LF line
endings (`BareLfInChunkSize`, `BareLfInChunkData`, `BareLfInTrailer`),
overflowed hex chunk sizes, and excessive framing overhead.
`parse_single_trailer_field` and `parse_chunked_trailers_with_out` reject
forbidden framing, routing, authentication, and conditional trailer fields per
RFC 9112 §7.1.2. Functions taking `cursor: i64&` advance `cursor` past consumed
bytes and stop at the offending offset on error.

### Streaming 64-Bit Register Chunked FSM (`chunked_fsm.goose`)

```goose
enum ChunkFsmStatus { NeedMore, YieldChunk, Complete, Error }
struct ChunkFsmDecoder

fn new_chunk_fsm_decoder() -> ChunkFsmDecoder
fn chunk_fsm_reset(dec: ChunkFsmDecoder&)
fn chunk_fsm_feed(dec: ChunkFsmDecoder&, data: const u8[:]) -> ChunkFsmStatus, i64, const u8[:]
```

`ChunkFsmDecoder` packs the streaming chunked state machine, extension/trailer
byte budgets, and framing overhead counters into a compact register state.
`chunk_fsm_feed` accepts arbitrary wire slices and returns `(status, consumed,
chunk_slice)`, where `chunk_slice` is a zero-copy view into `data` when `status`
is `ChunkFsmStatus.YieldChunk`.
