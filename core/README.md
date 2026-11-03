# `core`

Goose Core Systems Library providing zero-allocation byte string utilities, streaming I/O abstractions, constant-time cryptographic primitives, RFC-compliant compression containers, civil time/duration arithmetic, concurrency/CSP primitives, and WHATWG URL parsers.

## Public API

### Byte Strings & UTF-8 Codecs (`core/bytes/`)

- **ASCII Predicates & Folding (`case.goose`)**: `is_ascii`, `is_digit`, `is_hex_digit`, `is_alpha`, `is_alnum`, `to_ascii_lower`, `to_ascii_upper`, `eq_ascii_fold(a, b) -> bool`.
- **Trimming (`trim.goose`)**: `trim_lws(s) -> const u8[:]` (linear whitespace), `trim_ascii_whitespace(s) -> const u8[:]`, `trim_byte_set(s, cutset) -> const u8[:]`.
- **Search & Scanning (`search.goose`)**: `starts_with(s, prefix) -> bool`, `starts_with_fold(s, prefix) -> bool`, `ends_with(s, suffix) -> bool`, `index_of_byte(s, b) -> i64`, `index_of_slice(s, needle) -> i64`, `count_byte(s, b) -> i64`.
- **Splitting & Tokenization (`split.goose`)**: `split_once_byte(s, delim) -> (const u8[:], const u8[:], bool)`, `split_once_slice(s, needle) -> (const u8[:], const u8[:], bool)`, `struct ByteTokenizer` (`new_byte_tokenizer`, `next_token`).
- **Parsing & Formatting (`parse.goose`, `format.goose`)**: `parse_u64_dec(s) -> u64, bool`, `parse_i64_dec(s) -> i64, bool`, `parse_u32_dec(s) -> u32, bool`, `parse_hex_u64(s) -> u64, bool`, `format_u64_dec<B>(val, out: B&)`, `format_i64_dec<B>(val, out: B&)`.
- **UTF-8 Validation (`utf8.goose`, RFC 3629)**: `validate_utf8(s) -> bool`, `step_utf8_multibyte(s, idx) -> i64` with strict rejection of surrogate halves (U+D800..U+DFFF) and overlong encodings.

### Streaming I/O Abstractions (`core/io/`)

- **`enum IoError`**: Stream outcome statuses (`None`, `Eof`, `UnexpectedEof`, `BufferFull`, `InvalidData`).
- **`struct RingBuffer`**: Circular FIFO byte queue for zero-allocation socket streaming.
- **`struct PipeBuffer`**: Two-cursor sliding ring buffer supporting zero-copy read/write advancement.
- **`struct CorkBuffer`**: 16 KB outbound packet aggregator coalescing small framing writes into unified syscall bursts.
- **`struct IoVec`**: Vectorized Scatter/Gather I/O memory buffer descriptor.
- **`struct PageRingBuffer`**: Hardware Virtual Memory Page-Mirrored Ring Buffer for zero-wraparound streaming I/O.
- **`struct GuardedArena`**: Guarded virtual memory arena with overflow guard pages.

### Constant-Time Cryptography & Key Schedule (`core/crypto/`)

- **Constant-Time Primitives (`ct.goose`)**: `ct_eq_bytes(a, b) -> bool`, `ct_select_u8(mask, a, b) -> u8`, `ct_max_u64(a, b) -> u64`.
- **Secure Key Storage (`ct.goose`)**: `struct KeySlot` holding cryptographic secrets with automatic memory wiping on release.
- **Hash Functions & HKDF (`sha.goose`, `md5.goose`, FIPS 180-4, RFC 1321, RFC 5869)**: `sha256(data) -> u8[32]`, `sha384(data) -> u8[48]`, `sha512(data) -> u8[64]`, `sha1(data) -> u8[20]`, `md5(data) -> u8[16]`, `hmac_sha256(key, data) -> u8[32]`, `hkdf_extract`, `hkdf_expand`.
- **Symmetric Ciphers & AEAD (`aes.goose`, `chacha.goose`, NIST SP 800-38D, RFC 8439)**: `aes128_gcm_encrypt`, `aes128_gcm_decrypt`, `chacha20_poly1305_encrypt`, `chacha20_poly1305_decrypt`, `xchacha20_poly1305_encrypt`.
- **Asymmetric Key Exchange & Signatures (`x25519.goose`, `ed25519.goose`, RFC 7748, RFC 8032)**: `x25519_diffie_hellman(secret, peer_pub) -> u8[32], bool`, `ed25519_sign`, `ed25519_verify`.
- **Base64 Codecs (`base64.goose`, RFC 4648)**: `base64_encode<B>(data, out: B&)`, `base64_decode<B>(b64, out: B&) -> bool`, `base64_url_encode`, `base64_url_decode`.

### Compression & Decompression (`core/compress/`)

- **Checksums (`checksum.goose`)**: `crc32_ieee(data) -> u32`, `adler32(data) -> u32`.
- **Deflate & Inflate (`deflate.goose`, RFC 1951)**: Zero-allocation fixed and dynamic Huffman decompressor with sliding 32 KB window.
- **Gzip & Zlib Containers (`gzip.goose`, `zlib.goose`, RFC 1952, RFC 1950)**: Streaming compressor and decompressor with header validation and CRC-32/Adler-32 verification.
- **Zstandard (`zstd.goose`, RFC 8878)**: Zstandard frame decoder with FSE (Finite State Entropy) and Huffman sequence decoding.
- **Brotli (`brotli.goose`, RFC 7932)**: Brotli decompressor with embedded 122 KB static dictionary transforms.
- **Shared Compression Dictionaries (`compression_dict.goose`, RFC 9842)**: Dictionary-Compressed Zstandard (DCZ) decoder with client dictionary caching.

### Math, Random & Network Rate Estimators (`core/math/`)

- **Constant-Time & Saturated Arithmetic (`ct.goose`, `arithmetic.goose`)**: `add_sat_u64(a, b) -> u64`, `sub_sat_u64(a, b) -> u64`, `mul_sat_u64(a, b) -> u64`, `euclidean_div_i64`.
- **Bit Manipulation (`bits.goose`)**: `read_be_u16`, `read_be_u32`, `read_be_u64`, `read_le_u64`, `write_be_u16`, `write_be_u32`, `write_be_u64`, `ctz_u64`, `clz_u64`.
- **PRNG & Fast Mapping (`random.goose`)**: `WyrandRng` (WyRand v4.2), `Xoroshiro64Rng`, `fast_range_u64(r, n)` (Lemire divisionless range mapping).
- **Network Rate & Jitter Estimators (`network.goose`)**: `JacobsonEwma` (RFC 6298 / RFC 9002 RTT estimation), `exponential_backoff_with_jitter` (AWS / RFC 8305 Happy Eyeballs pacing).

### Concurrency & Worker Coordination (`core/sync/`)

- **`struct SingleflightGroup`**: Duplicate concurrent request deduplication eliminating cache stampedes.
- **`struct SpscRing`**: Single-Producer Single-Consumer lock-free ring buffer for thread-safe worker messaging.

### Time, Monotonic Clocks & Calendar (`core/time/`)

- **Duration Arithmetic (`duration.goose`)**: `struct Duration` (nanosecond resolution, signed math, truncation, string formatting and parsing per Go-compatible syntax).
- **Monotonic Clocks (`clock.goose`)**: `monotonic_now() -> Instant`, `Stopwatch` (high-resolution profiling), `Deadline` (anti-overflow timeout enforcement).
- **Civil Calendar & Clock (`calendar.goose`, `time.goose`)**: Proleptic Gregorian civil date arithmetic, leap year validation, UTC timezone conversions.
- **Date Codecs (`format.goose`)**: `format_rfc3339`, `parse_rfc3339` (ISO 8601), `format_http_date`, `parse_http_date` (RFC 9110 §5.6.7 supporting IMF-fixdate, RFC 850, and asctime formats).

### WHATWG URL Standard & Origin Security (`core/url/`)

- **`struct Url` & `struct UrlView`**: Fully parsed URL holding scheme, username, password, host, port, path, query, and fragment.
- **`fn parse_url(raw: const u8[:]) -> Url, bool`**: WHATWG URL Standard parser with RFC 5952 IPv6 compression and path normalization.
- **`fn resolve_url(base: const Url&, ref: const u8[:]) -> Url, bool`**: RFC 3986 relative reference resolution.
- **`fn parse_query_params(query: const u8[:]) -> QueryTokens`**: Zero-copy 64-bit token slicer (1 KB stack footprint) with SWAR word scanning, CVE-2021-31525 semicolon-splitting defense, and CVE-2026-39825 truncation protection.
- **`fn compute_origin<B>(u: const Url&, out: B&)`**: Computes serialized web origin string (`scheme://host:port`) for CORS and isolation checks.
