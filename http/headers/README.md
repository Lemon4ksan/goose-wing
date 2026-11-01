# `http/headers`

Zero-allocation lexical scanner, perfect hashing, and chunked transfer decoding engine for HTTP headers (RFC 9110, RFC 9112).

## Public API

### Well-Known Header Perfect Hash (`perfect_hash.goose`)

- **`enum KnownHeaderId`**: Enumeration of pre-hashed HTTP headers (Host, Date, Accept, Cookie, Origin, Server, Connection, UserAgent, ContentType, ContentLength, Authorization, TransferEncoding, SecWebSocketKey, Upgrade, Expect).
- **`fn header_id_to_bit(id: KnownHeaderId) -> u32`**: Maps a `KnownHeaderId` to a 32-bit presence mask bit.
- **`fn classify_well_known_header(name: const u8[:]) -> KnownHeaderId`**: O(1) discriminator classifying an ASCII header name.
- **`fn well_known_header_name(id: KnownHeaderId) -> const u8[:]`**: Returns the canonical byte slice for a `KnownHeaderId`.

### Lexical Validation & SWAR Transformations (`lexical.goose`)

- **`fn swar_to_lower_64(v: u64) -> u64`**: Evaluates 8 ASCII bytes in parallel, translating uppercase characters in 4 CPU cycles.
- **`fn swar_to_lower(slice: u8[:])`**: In-place SIMD/SWAR lowercasing of byte slices.
- **`fn validate_header_name(name: const u8[:]) -> bool`**: Validates header name conforming to RFC 9110 §5.1 token grammar.
- **`fn validate_header_value(val: const u8[:]) -> bool`**: Verifies header field value bytes against RFC 9110 §5.5 (VCHAR and SP/HTAB).
- **`fn validate_token(s: const u8[:]) -> bool`**: Validates RFC 9110 §5.6.2 token format.
- **`fn trim_ows(s: const u8[:]) -> const u8[:]`**: Trims optional whitespace (SP/HTAB) from byte slice boundaries per RFC 9110 §5.6.3.
- **`fn trim_lws(s: const u8[:]) -> const u8[:]`**: Trims leading and trailing linear whitespace.

### Chunked Transfer Framing & Smuggling Defense (`chunked.goose`)

- **`fn is_disallowed_control_trailer(name: const u8[:]) -> bool`**: Checks if trailer name matches forbidden framing or routing fields (RFC 9112 §7.1.2).
- **`fn is_disallowed_content_or_cond_trailer(name: const u8[:]) -> bool`**: Checks if trailer matches forbidden content or conditional state headers.
- **`fn validate_trailer_name(name: const u8[:]) -> bool`**: Validates whether a trailer field name is permitted on the wire.
- **`fn parse_chunk_header(line: const u8[:]) -> u64, bool`**: Parses chunk-size hex and validates chunk extensions.
- **`fn decode_chunked_body(raw: const u8[:], out_body: u8[>..]&) -> bool`**: Decodes a complete chunked transfer encoded stream into a contiguous body.
- **`fn decode_chunked_with_trailers(raw: const u8[:], out_body: u8[>..]&, out_trailers: HeaderMap&) -> bool`**: Decodes chunked body while validating and populating sanitized trailer headers.
