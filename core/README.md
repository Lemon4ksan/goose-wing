# Core Primitives (`core.goose`)

Foundational zero-allocation primitives for byte scanning, I/O buffering,
cryptography, compression, math, concurrency, time, and URL parsing.

Top-level sub-module aggregators (`core/bytes.goose`, `core/io.goose`,
`core/crypto.goose`, `core/compress.goose`, `core/math.goose`,
`core/sync.goose`, `core/time.goose`, `core/url.goose`) and UFCS method bridges
(`core/ufcs.goose`) re-export all symbols into the `core` namespace.

```goose
import core;

let host, port_str, has_port = split_once_byte("example.com:8443", ':');
let port, ok = parse_u32_dec(port_str);
let digest = sha256("hello");
```

## Submodules

### `core/bytes/`: Byte Manipulation & Text Scanning

```goose
// core/bytes/case.goose
fn is_ascii_alpha(b: u8) -> bool            fn is_ascii_digit(b: u8) -> bool
fn is_ascii_hexdigit(b: u8) -> bool         fn is_ascii_vchar(b: u8) -> bool
fn is_ascii_printable(b: u8) -> bool        fn is_tchar(b: u8) -> bool
fn is_uri_unreserved(b: u8) -> bool
fn to_lower_ascii_byte(b: u8) -> u8         fn to_upper_ascii_byte(b: u8) -> u8
fn make_ascii_lowercase(buf: u8[:])         fn make_ascii_uppercase(buf: u8[:])
fn eq_ascii_fold(str_a: const u8[:], str_b: const u8[:]) -> bool
fn starts_with_fold(s: const u8[:], prefix: const u8[:]) -> bool
fn ends_with_fold(s: const u8[:], suffix: const u8[:]) -> bool
fn index_of_fold(haystack: const u8[:], needle: const u8[:]) -> i64
fn contains_fold(haystack: const u8[:], needle: const u8[:]) -> bool

// core/bytes/trim.goose
fn is_lws(b: u8) -> bool                    fn is_ascii_space(b: u8) -> bool
fn trim_lws(s: const u8[:]) -> const u8[:]
fn trim_ascii_space(s: const u8[:]) -> const u8[:]
fn trim_byte(s: const u8[:], target: u8) -> const u8[:]
fn trim_bytes(s: const u8[:], cutset: const u8[:]) -> const u8[:]

// core/bytes/search.goose
fn equal_short(a: const u8[:], b: const u8[:]) -> bool
fn starts_with(s: const u8[:], prefix: const u8[:]) -> bool
fn ends_with(s: const u8[:], suffix: const u8[:]) -> bool
fn index_of_byte(s: const u8[:], target: u8) -> i64
fn last_index_of_byte(s: const u8[:], target: u8) -> i64
fn count_byte(s: const u8[:], target: u8) -> i64
fn find_byteset(s: const u8[:], set: const u8[:]) -> i64
fn find(haystack: const u8[:], needle: const u8[:]) -> i64
fn rfind(haystack: const u8[:], needle: const u8[:]) -> i64
fn contains(haystack: const u8[:], needle: const u8[:]) -> bool
fn swar_find_ctl(s: const u8[:]) -> i64
fn fast_find_crlfcrlf(s: const u8[:]) -> i64
fn fence_wire_slice(s: const u8[:], start: i64, end: i64) -> const u8[:], bool

// core/bytes/split.goose
struct ByteTokenizer { .. }
fn split_once_byte(s: const u8[:], delim: u8) -> const u8[:], const u8[:], bool
fn rsplit_once_byte(s: const u8[:], delim: u8) -> const u8[:], const u8[:], bool
fn split_once(s: const u8[:], delim: const u8[:]) -> const u8[:], const u8[:], bool
fn split_once_fold(s: const u8[:], delim: const u8[:]) -> const u8[:], const u8[:], bool
fn find_unquoted_byte(s: const u8[:], delim: u8) -> i64
fn split_once_unquoted_byte(s: const u8[:], delim: u8) -> const u8[:], const u8[:], bool
fn make_byte_tokenizer(s: const u8[:], delim: u8) -> ByteTokenizer
fn token_next(t: ByteTokenizer&) -> const u8[:], bool

// core/bytes/parse.goose & core/bytes/format.goose
fn hex_digit_to_val(b: u8) -> u8, bool
fn parse_u64_dec(s: const u8[:]) -> u64, bool
fn parse_i64_dec(s: const u8[:]) -> i64, bool
fn parse_u32_dec(s: const u8[:]) -> u32, bool
fn parse_i32_dec(s: const u8[:]) -> i32, bool
fn parse_u64_hex(s: const u8[:]) -> u64, bool
fn parse_u32_hex(s: const u8[:]) -> u32, bool
fn parse_u8_hex(s: const u8[:]) -> u8, bool
fn format_u64_dec<B>(val: u64, out: B&)     fn format_i64_dec<B>(val: i64, out: B&)
fn format_u32_dec<B>(val: u32, out: B&)     fn format_u64_hex<B>(val: u64, out: B&)
fn format_u32_hex<B>(val: u32, out: B&)     fn format_u8_hex<B>(val: u8, out: B&)
fn format_u64_hex_fixed<B>(val: u64, width: i64, out: B&)
fn fast_u64toa(val: u64, dst: u8[:]) -> i64
fn fast_u32toa_hex(val: u32, dst: u8[:]) -> i64

// core/bytes/json.goose, core/bytes/utf8.goose & core/ufcs.goose
fn is_json_plain_string(s: const u8[:]) -> bool
fn escape_json_string<B>(s: const u8[:], out: B&)
fn format_json_string<B>(s: const u8[:], out: B&)
fn format_json_key<B>(key: const u8[:], out: B&)
fn decode_json_string_into<B>(raw: const u8[:], out: B&) -> bool
fn read_json_string_into<B>(src: const u8[:], idx: i64&, out: B&) -> bool
fn is_pure_ascii(s: const u8[:]) -> bool
fn find_crlf(s: const u8[:]) -> i64
fn validate_utf8(s: const u8[:]) -> bool
fn step_utf8_multibyte(s: const u8[:], idx: i64, state: u32&) -> bool
fn validate_utf8_dfa_chunk(s: const u8[:], state: u32&) -> u32
fn validate_utf8_streaming(chunk: const u8[:], state: u32&) -> bool
fn decode_utf8(s: const u8[:]) -> u32, i64
fn decode_last_utf8(s: const u8[:]) -> u32, i64
fn decode_utf8_lossy<B>(s: const u8[:], out: B&)
fn char_indices(s: const u8[:]) -> i64[>..]
fn try_push<B, T>(dst: B&, elem: T) -> bool
fn try_append<B>(dst: B&, src: const u8[:]) -> bool
fn try_set<B>(dst: B&, src: const u8[:]) -> bool
fn compact_wire_buffer<B>(buf: B&, consumed: i64)
```

Provides branchless ASCII character classification (`core/bytes/case.goose`),
whitespace trimming (`core/bytes/trim.goose`), SWAR-accelerated byte and control
character scanning (`core/bytes/search.goose`), quote-aware delimiter splitting
(`core/bytes/split.goose`), overflow-checked integer parsing and formatting
(`core/bytes/parse.goose`, `core/bytes/format.goose`), RFC 8259 JSON string
escaping (`core/bytes/json.goose`), DFA UTF-8 validation
(`core/bytes/utf8.goose`), and bounded buffer UFCS helpers (`core/ufcs.goose`).
Index searches return `-1` when no match is found, and `split_once*` returns
`(s, "", false)` when the delimiter is absent.

### `core/io/`: Zero-Copy Buffers & Cursors

```goose
// core/io/types.goose & core/io/ring.goose
enum IoError { .. }
enum PollInterest { None, Read, Write, ReadWrite }
enum PollTrigger { Level, Edge }
struct PollReadyEvent { .. }
struct DialTarget { .. }
const DEFAULT_RING_BUFFER_CAP: i64 = 4096
const POLL_NONE: u32 = 0
const POLL_READ: u32 = 1 << 0
const POLL_WRITE: u32 = 1 << 1
const POLL_ERROR: u32 = 1 << 2
const POLL_HANGUP: u32 = 1 << 3
const POLL_TIMER: u32 = 1 << 4
const POLL_WAKE: u32 = 1 << 5
struct RingBuffer { .. }
fn io_error_name(err: IoError) -> const u8[:]
fn new_ring_buffer(cap: i64 = DEFAULT_RING_BUFFER_CAP) -> RingBuffer
fn write(rb: RingBuffer&, data: const u8[:]) -> i64
fn read(rb: RingBuffer&, out: u8[:]) -> i64
fn peek(rb: const RingBuffer&, out: u8[:]) -> i64
fn discard(rb: RingBuffer&, n: i64) -> i64
fn read_slices(rb: const RingBuffer&) -> const u8[:], const u8[:]
fn write_slices(rb: RingBuffer&) -> u8[:], u8[:]
fn commit_written(rb: RingBuffer&, n: i64)
fn contiguous_readable(rb: const RingBuffer&) -> const u8[:]

// core/io/pipe.goose & core/io/cork.goose
struct PipeBuffer { .. }
struct CorkBuffer { .. }
fn new_pipe_buffer(cap: i64 = 65536) -> PipeBuffer
fn readable_slice(p: const PipeBuffer&) -> const u8[:]
fn unexamined_slice(p: const PipeBuffer&) -> const u8[:]
fn compact_pipe(p: PipeBuffer&)
fn advance_to(p: PipeBuffer&, consumed: i64, examined: i64)
fn get_write_span(p: PipeBuffer&, min_size: i64) -> u8[:]
fn commit_write(p: PipeBuffer&, bytes_written: i64)
fn complete_pipe(p: PipeBuffer&, is_err: bool = false)
fn pipe_reset(p: PipeBuffer&)
fn new_cork_buffer() -> CorkBuffer
fn cork_pending(c: const CorkBuffer&) -> i64
fn cork_available(c: const CorkBuffer&) -> i64
fn cork_as_slice(c: const CorkBuffer&) -> const u8[:]
fn cork_write(c: CorkBuffer&, data: const u8[:]) -> i64
fn cork_write_exact(c: CorkBuffer&, data: const u8[:]) -> bool
fn cork_write_u8(c: CorkBuffer&, val: u8) -> bool
fn cork_write_u16_be(c: CorkBuffer&, val: u16) -> bool
fn cork_write_u24_be(c: CorkBuffer&, val: u32) -> bool
fn cork_write_u32_be(c: CorkBuffer&, val: u32) -> bool
fn cork_write_u64_be(c: CorkBuffer&, val: u64) -> bool
fn cork_consume(c: CorkBuffer&, n: i64)
fn cork_reset(c: CorkBuffer&)

// core/io/cursor.goose & core/io/vec.goose
struct ByteCursor { .. }
struct ByteBuilder { .. }
struct IoVec { .. }
struct IoVecArray { .. }
fn cursor_from(data: const u8[:]) -> ByteCursor
fn get_u8(c: ByteCursor&) -> u8, bool       fn get_u16(c: ByteCursor&) -> u16, bool
fn get_u24(c: ByteCursor&) -> u32, bool     fn get_u32(c: ByteCursor&) -> u32, bool
fn get_bytes(c: ByteCursor&, len: i64) -> const u8[:], bool
fn get_u8_length_prefixed(c: ByteCursor&) -> const u8[:], bool
fn get_u16_length_prefixed(c: ByteCursor&) -> const u8[:], bool
fn get_u24_length_prefixed(c: ByteCursor&) -> const u8[:], bool
fn builder_init(b: ByteBuilder&, max_cap: i64 = 65536)
fn put_u8(b: ByteBuilder&, v: u8) -> bool   fn put_u16(b: ByteBuilder&, v: u16) -> bool
fn put_u24(b: ByteBuilder&, v: u32) -> bool fn put_u32(b: ByteBuilder&, v: u32) -> bool
fn put_bytes(b: ByteBuilder&, data: const u8[:]) -> bool
fn start_u16_prefix(b: ByteBuilder&) -> i64, bool
fn finish_u16_prefix(b: ByteBuilder&, token: i64) -> bool
fn new_iovec_array() -> IoVecArray
fn iovec_push(arr: IoVecArray&, slice: const u8[:]) -> bool
fn iovec_get(arr: const IoVecArray&, idx: i64) -> const u8[:]
fn iovec_total_bytes(arr: const IoVecArray&) -> i64
fn iovec_compact(arr: IoVecArray&)
fn iovec_flatten<B>(arr: const IoVecArray&, out: B&)
fn iovec_copy_to(arr: const IoVecArray&, dst: u8[:]) -> i64
fn iovec_consume(arr: IoVecArray&, bytes_sent: i64)

// core/io/page_ring.goose & core/io/page_mem.goose
struct PageRingBuffer { .. }
struct GuardedArena { .. }
struct MmapFile { .. }
struct PinnedBuffer { .. }
fn page_ring_init(rb: PageRingBuffer&, min_size: i64 = 65536) -> bool
fn page_ring_close(rb: PageRingBuffer&)
fn page_ring_available(rb: const PageRingBuffer&) -> i64
fn page_ring_write(rb: PageRingBuffer&, src: const u8[:]) -> i64
fn page_ring_read(rb: PageRingBuffer&, dst: u8[:]) -> i64
fn page_ring_peek(rb: const PageRingBuffer&, dst: u8[:]) -> i64
fn page_ring_discard(rb: PageRingBuffer&, n: i64)
fn page_ring_recv(rb: PageRingBuffer&, fd: i64) -> i64
fn page_ring_send(rb: PageRingBuffer&, fd: i64) -> i64
fn page_ring_find_crlf(rb: const PageRingBuffer&) -> i64
fn page_ring_find_crlfcrlf(rb: const PageRingBuffer&) -> i64
fn guarded_arena_init(a: GuardedArena&, size: i64) -> bool
fn guarded_arena_close(a: GuardedArena&)
fn guarded_arena_write(a: GuardedArena&, data: const u8[:]) -> bool
fn guarded_arena_read(a: const GuardedArena&) -> const u8[:]
fn guarded_arena_reset(a: GuardedArena&)
fn guarded_arena_clear_zero(a: GuardedArena&)
fn mmap_file_open(m: MmapFile&, path: const u8[:]) -> bool
fn mmap_file_close(m: MmapFile&)
fn mmap_file_read(m: const MmapFile&, offset: i64, len: i64) -> const u8[:], bool
fn mmap_file_send(m: const MmapFile&, sock_fd: i64, offset: i64, count: i64) -> i64
fn pinned_buffer_init(p: PinnedBuffer&, size: i64) -> bool
fn pinned_buffer_close(p: PinnedBuffer&)
fn pinned_buffer_write(p: PinnedBuffer&, offset: i64, src: const u8[:]) -> bool
fn pinned_buffer_read(p: const PinnedBuffer&, offset: i64, len: i64) -> const u8[:], bool

// core/io/reactor.goose & types.goose (Stream, Host Push/Completion, IoC Contract)
enum ConnectAddr { Tcp { host: const u8[:], port: u16 }, Unix { path: const u8[:] } }
enum ConnectStatus { Connected, InProgress, InvalidArgument, Failed }
enum LinkEventKind { Accepted, Connected, Data, Writable, Eof, Closed, Timer, Wake, Pump }
struct IoLink { raw: u64 = 0 }
struct WakeToken { owner: u16, gen: u16, slot: u32, stream_id: u32, req_seq: u32 }
struct LinkEvent { kind: LinkEventKind, link: IoLink, listener: IoLink, tag: u64, data: const u8[:], err: IoError, timer_id: u64, token: WakeToken }
struct IoDriverChain<First, Next> { first: First, next: Next }
fn stream_send<Io>(io: Io&, data: const u8[:]) -> i32
fn stream_recv<Io>(io: Io&, dst: u8[:], timeout_ms: u32 = 5000) -> i32
fn stream_close<Io>(io: Io&)
fn stream_try_send<Io>(io: Io&, data: const u8[:]) -> i32, IoError
fn stream_try_recv<Io>(io: Io&, dst: u8[:]) -> i32, IoError
fn reactor_dial<D>(dialer: D&, target: DialTarget) -> i64, IoError
fn reactor_register<R>(r: R&, fd: i32, tag: u64, interest: PollInterest, trigger: PollTrigger = PollTrigger.Level) -> bool
fn reactor_modify<R>(r: R&, fd: i32, tag: u64, interest: PollInterest, trigger: PollTrigger = PollTrigger.Level) -> bool
fn reactor_deregister<R>(r: R&, fd: i32) -> bool
fn reactor_add_timer<R>(r: R&, timer_id: u64, delay_ms: u64, tag: u64, periodic: bool = false, now_ns: u64 = 0) -> bool
fn reactor_cancel_timer<R>(r: R&, timer_id: u64) -> bool
fn reactor_wake<R>(r: R&, tag: u64) -> bool
fn reactor_poll<R>(r: R&, timeout_ms: i64, now_ns: u64, out_events: PollReadyEvent[..64]&) -> i32
fn host_listen<H>(host: H&, addr: ConnectAddr, owner: u16, tag: u64 = 0, backlog: i32 = 128) -> IoLink, IoError
fn host_connect<H>(host: H&, addr: ConnectAddr, owner: u16, tag: u64 = 0) -> IoLink, ConnectStatus
fn host_send<H>(host: H&, link: IoLink, data: const u8[:]) -> i32, IoError
fn host_set_rx_paused<H>(host: H&, link: IoLink, paused: bool) -> bool
fn host_shutdown_write<H>(host: H&, link: IoLink) -> bool
fn host_close<H>(host: H&, link: IoLink) -> bool
fn host_add_timer<H>(host: H&, timer_id: u64, delay_ms: u64, owner: u16, tag: u64, periodic: bool = false, now_ns: u64 = 0) -> bool
fn host_cancel_timer<H>(host: H&, timer_id: u64) -> bool
fn host_wake<H>(host: H&, token: WakeToken) -> bool
fn host_step<H, D>(host: H&, driver: D&, timeout_ms: i64, now_ns: u64) -> i32
fn chain_io_drivers<First, Next>(first: First, next: Next) -> IoDriverChain<First, Next>
```

Implements circular queues (`core/io/ring.goose`, `core/io/types.goose`),
zero-shim cross-framework UFCS stream, readiness, and host-owned push link
contracts (`core/io/reactor.goose`), producer/consumer pipes
(`core/io/pipe.goose`), write-combining frame coalescers (`core/io/cork.goose`),
network-order wire cursors and length-prefixed builders
(`core/io/cursor.goose`), scatter-gather vectors (`core/io/vec.goose`), OS
virtual-memory mirrored ring buffers (`core/io/page_ring.goose`), and
guard-paged arenas, memory-mapped files, and `mlock`-pinned secret buffers
(`core/io/page_mem.goose`). `ByteCursor` getters leave the cursor unchanged when
returning `false` on truncated input.

### `core/crypto/`: Constant-Time Cryptography

```goose
// core/crypto/ct.goose, core/crypto/csprng.goose & core/crypto/base64.goose
struct KeySlot { .. }
struct DudectContext { .. }
fn csprng_fill(dst: u8[:]) -> bool
fn csprng_u64() -> u64, bool
fn ct_eq_u8(a: u8, b: u8) -> u8
fn ct_select_u8(mask: u8, a: u8, b: u8) -> u8
fn ct_eq_bytes(a: const u8[:], b: const u8[:]) -> bool
fn ct_eq_tag16(a: const u8[16]&, b: const u8[16]&) -> bool
fn ct_eq_tag32(a: const u8[32]&, b: const u8[32]&) -> bool
fn ct_eq_tag48(a: const u8[48]&, b: const u8[48]&) -> bool
fn ct_copy_bytes(dst: u8[:], src: const u8[:])
fn ct_declassify_slice(buf: const u8[:])
fn ct_declassify_u8(val: u8) -> u8
fn secure_zeroize_32(buf: u8[32]&)          fn secure_zeroize_slice(buf: u8[:])
fn new_key_slot(raw_key: const u8[32]&) -> KeySlot
fn zeroize_key_slot(slot: KeySlot&)
fn display_redacted<B>(slot: const KeySlot&, out: B&)
fn new_dudect_context() -> DudectContext
fn dudect_push_sample(ctx: DudectContext&, clazz: u8, exec_time_ns: i64)
fn dudect_is_constant_time(ctx: const DudectContext&) -> bool
fn base64_encode<B>(src: const u8[:], out: B&)
fn base64_decode<B>(src: const u8[:], out: B&) -> bool
fn base64url_encode<B>(src: const u8[:], out: B&)
fn base64url_decode<B>(src: const u8[:], out: B&) -> bool

// core/crypto/sha.goose & core/crypto/md5.goose
struct Sha256Ctx { .. }                     struct Sha384Ctx { .. }
struct Sha512Ctx { .. }                     struct Sha512_256Ctx { .. }
struct Md5Context { .. }
fn sha256(data: const u8[:]) -> u8[32]      fn sha384(data: const u8[:]) -> u8[48]
fn sha512(data: const u8[:]) -> u8[64]      fn sha512_256(data: const u8[:]) -> u8[32]
fn sha1(data: const u8[:]) -> u8[20]        fn md5(data: const u8[:]) -> u8[16]
fn hmac_sha256(key: const u8[:], msg: const u8[:]) -> u8[32]
fn hmac_sha384(key: const u8[:], msg: const u8[:]) -> u8[48]
fn hmac_sha512(key: const u8[:], msg: const u8[:]) -> u8[64]
fn hkdf_extract(salt: const u8[:], ikm: const u8[:]) -> u8[32]
fn hkdf_extract_384(salt: const u8[:], ikm: const u8[:]) -> u8[48]
fn hkdf_expand_32(prk: const u8[32]&, info: const u8[:]) -> u8[32]
fn hkdf_sha256_32(salt: const u8[:], ikm: const u8[:], info: const u8[:]) -> u8[32]
fn hkdf_expand_bytes_256(prk: const u8[32]&, info: const u8[:], out: u8[:])
fn hkdf_expand_bytes_384(prk: const u8[48]&, info: const u8[:], out: u8[:])

// core/crypto/aes.goose, core/crypto/fusion.goose & core/crypto/chacha.goose
struct Aes128KeySchedule { .. }             struct Aes256KeySchedule { .. }
fn aes128_gcm_seal<B>(key: const u8[16]&, nonce: const u8[12]&, aad: const u8[:], plaintext: const u8[:], out_ciphertext: B&, out_tag: u8[16]&)
fn aes128_gcm_open<B>(key: const u8[16]&, nonce: const u8[12]&, aad: const u8[:], ciphertext: const u8[:], tag: const u8[16]&, out_plaintext: B&) -> bool
fn aes128_gcm_seal_inplace(key: const u8[16]&, nonce: const u8[12]&, aad: const u8[:], buf: u8[:], out_tag: u8[16]&)
fn aes128_gcm_open_inplace(key: const u8[16]&, nonce: const u8[12]&, aad: const u8[:], buf: u8[:], tag: const u8[16]&) -> bool
fn aes256_gcm_seal<B>(key: const u8[32]&, nonce: const u8[12]&, aad: const u8[:], plaintext: const u8[:], out_ciphertext: B&, out_tag: u8[16]&)
fn aes256_gcm_open<B>(key: const u8[32]&, nonce: const u8[12]&, aad: const u8[:], ciphertext: const u8[:], tag: const u8[16]&, out_plaintext: B&) -> bool
fn aes256_gcm_seal_inplace(key: const u8[32]&, nonce: const u8[12]&, aad: const u8[:], buf: u8[:], out_tag: u8[16]&)
fn aes256_gcm_open_inplace(key: const u8[32]&, nonce: const u8[12]&, aad: const u8[:], buf: u8[:], tag: const u8[16]&) -> bool
fn hkdf_aes256_gcm_seal<B>(ikm: const u8[:], salt: const u8[:], info: const u8[:], nonce: const u8[12]&, aad: const u8[:], plaintext: const u8[:], out: B&)
fn hkdf_aes256_gcm_open<B>(ikm: const u8[:], salt: const u8[:], info: const u8[:], nonce: const u8[12]&, aad: const u8[:], ciphertext_and_tag: const u8[:], out: B&) -> bool
fn fused_aes128_gcm_encrypt_4blocks(ks: const Aes128KeySchedule&, h: const u8[16]&, j0_counter: u32, nonce_prefix: const u8[12]&, in64: const u8[64]&, out64: u8[64]&, ghash_state: u8[16]&)
fn fused_aes128_gcm_decrypt_4blocks(ks: const Aes128KeySchedule&, h: const u8[16]&, j0_counter: u32, nonce_prefix: const u8[12]&, in64: const u8[64]&, out64: u8[64]&, ghash_state: u8[16]&)
fn fused_aes_gcm_encrypt<B>(key: const u8[16]&, nonce: const u8[12]&, aad: const u8[:], plaintext: const u8[:], out_ciphertext: B&, out_tag: u8[16]&)
fn fused_aes_gcm_decrypt<B>(key: const u8[16]&, nonce: const u8[12]&, aad: const u8[:], ciphertext: const u8[:], tag: const u8[16]&, out_plaintext: B&) -> bool
fn hchacha20(key: const u8[32]&, nonce: const u8[16]&) -> u8[32]
fn chacha20_block(key: const u8[32]&, counter: u32, nonce: const u8[12]&) -> u8[64]
fn chacha20_xor<B>(key: const u8[32]&, counter: u32, nonce12: const u8[12]&, input: const u8[:], out: B&) -> bool
fn poly1305_mac(key: const u8[32]&, msg: const u8[:]) -> u8[16]
fn chacha20_poly1305_seal<B>(key: const u8[32]&, nonce: const u8[12]&, aad: const u8[:], plaintext: const u8[:], out_ciphertext: B&, out_tag: u8[16]&)
fn chacha20_poly1305_open<B>(key: const u8[32]&, nonce: const u8[12]&, aad: const u8[:], ciphertext: const u8[:], tag: const u8[16]&, out_plaintext: B&) -> bool
fn chacha20_poly1305_seal_inplace(key: const u8[32]&, nonce: const u8[12]&, aad: const u8[:], buf: u8[:], out_tag: u8[16]&)
fn chacha20_poly1305_open_inplace(key: const u8[32]&, nonce: const u8[12]&, aad: const u8[:], buf: u8[:], tag: const u8[16]&) -> bool
fn xchacha20_poly1305_seal<B>(key: const u8[32]&, nonce24: const u8[24]&, plaintext: const u8[:], aad: const u8[:], out_ciphertext: B&) -> u8[16], bool
fn xchacha20_poly1305_open<B>(key: const u8[32]&, nonce: const u8[24]&, aad: const u8[:], ciphertext: const u8[:], tag: const u8[16]&, out_plaintext: B&) -> bool

// core/crypto/x25519.goose, core/crypto/ed25519.goose, core/crypto/ecdsa.goose & core/crypto/rsa.goose
struct Fe10 { .. }                          struct EdPoint { .. }
struct Ed25519KeyPair { .. }                struct U256 { .. }
struct P256Point { .. }                     struct U384 { .. }
struct P384Point { .. }
fn x25519_scalarmult(scalar: const u8[32]&, point: const u8[32]&) -> u8[32]
fn x25519_base_scalarmult(scalar: const u8[32]&) -> u8[32]
fn x25519_shared_secret(private_key: const u8[32]&, peer_public: const u8[32]&) -> u8[32], bool
fn ed25519_public_key(seed: const u8[32]&) -> u8[32]
fn ed25519_keypair(seed: const u8[32]&) -> Ed25519KeyPair
fn ed25519_sign(seed: const u8[32]&, msg: const u8[:]) -> u8[64]
fn ed25519_verify(pub_key: const u8[32]&, msg: const u8[:], sig: const u8[64]&) -> bool
fn decode_p256_public_key(sec1: const u8[:]) -> P256Point, bool
fn ecdsa_p256_decode_der_sig(der: const u8[:]) -> u8[64], bool
fn ecdsa_p256_encode_der_sig<B>(raw_sig: const u8[64]&, out: B&)
fn ecdsa_p256_public_key(priv_key: const u8[32]&) -> u8[65], bool
fn ecdsa_p256_sign(priv_key: const u8[32]&, msg: const u8[:]) -> u8[64], bool
fn ecdsa_p256_verify(pub_key_sec1: const u8[:], msg: const u8[:], sig_raw_or_der: const u8[:]) -> bool
fn decode_p384_public_key(sec1: const u8[:]) -> P384Point, bool
fn ecdsa_p384_decode_der_sig(der: const u8[:]) -> u8[96], bool
fn ecdsa_p384_public_key(priv_key: const u8[48]&) -> u8[97], bool
fn ecdsa_p384_sign(priv_key: const u8[48]&, msg: const u8[:]) -> u8[96], bool
fn ecdsa_p384_verify(pub_key_sec1: const u8[:], msg: const u8[:], sig_raw_or_der: const u8[:]) -> bool
fn rsa_mod_exp(base_be: const u8[:], exp_be: const u8[:], mod_be: const u8[:], out: u8[:]) -> bool
fn parse_rsa_public_key_der(spki_or_pkcs1: const u8[:]) -> const u8[:], const u8[:], bool
fn rsa_pkcs1_sha256_verify(n_be: const u8[:], e_be: const u8[:], msg: const u8[:], sig: const u8[:]) -> bool
fn rsa_pkcs1_sha384_verify(n_be: const u8[:], e_be: const u8[:], msg: const u8[:], sig: const u8[:]) -> bool
fn rsa_pkcs1_sha256_verify_der(spki_der: const u8[:], msg: const u8[:], sig: const u8[:]) -> bool
fn rsa_pkcs1_sha256_sign(n_be: const u8[:], d_be: const u8[:], msg: const u8[:], out_sig: u8[:]) -> bool
fn rsa_pss_sha256_verify(n_be: const u8[:], e_be: const u8[:], msg: const u8[:], sig: const u8[:]) -> bool
fn rsa_pss_sha384_verify(n_be: const u8[:], e_be: const u8[:], msg: const u8[:], sig: const u8[:]) -> bool
fn rsa_pss_sha512_verify(n_be: const u8[:], e_be: const u8[:], msg: const u8[:], sig: const u8[:]) -> bool
fn rsa_pss_sha256_verify_der(spki_der: const u8[:], msg: const u8[:], sig: const u8[:]) -> bool
fn rsa_pss_sha384_verify_der(spki_der: const u8[:], msg: const u8[:], sig: const u8[:]) -> bool
fn rsa_pss_sha256_sign(n_be: const u8[:], d_be: const u8[:], msg: const u8[:], salt: const u8[:], out_sig: u8[:]) -> bool
fn rsa_pss_sha512_sign(n_be: const u8[:], d_be: const u8[:], msg: const u8[:], salt: const u8[:], out_sig: u8[:]) -> bool
```

Provides constant-time comparisons, zeroization, and DudeCT timing verification
(`core/crypto/ct.goose`), OS-backed CSPRNG byte generation via `BCryptGenRandom`
on Windows and `getrandom(2)` or `/dev/urandom` on POSIX
(`core/crypto/csprng.goose`), RFC 4648 Base64 and Base64url codecs
(`core/crypto/base64.goose`), SHA-2/SHA-1/MD5 digests, HMAC, and HKDF
(`core/crypto/sha.goose`, `core/crypto/md5.goose`), AES-GCM and vector-fused
GHASH (`core/crypto/aes.goose`, `core/crypto/fusion.goose`), RFC 8439
ChaCha20-Poly1305 and XChaCha20-Poly1305 (`core/crypto/chacha.goose`), RFC 7748
X25519 (`core/crypto/x25519.goose`), RFC 8032 Ed25519
(`core/crypto/ed25519.goose`), FIPS 186-5 ECDSA P-256/P-384
(`core/crypto/ecdsa.goose`), and RFC 8017 RSA-PKCS1v1.5 and RSA-PSS
(`core/crypto/rsa.goose`). All AEAD `*_open` routines verify the 16-byte tag in
constant time before releasing plaintext, and `x25519_shared_secret` rejects
low-order all-zero shared secrets by returning `false`.

### `core/compress/`: Lossless Compression & Checksums

```goose
// core/compress/checksum.goose & core/compress/deflate.goose
enum CompressError { .. }
struct DeflateConfig { .. }
fn crc32(buf: const u8[:]) -> u32           fn crc32_update(crc: u32, buf: const u8[:]) -> u32
fn adler32(buf: const u8[:]) -> u32         fn adler32_update(adler: u32, buf: const u8[:]) -> u32
fn xxh64(buf: const u8[:], seed: u64 = 0) -> u64
fn xxh64_digest_32(buf: const u8[:]) -> u32
fn deflate<B>(src: const u8[:], out: B&) -> bool
fn deflate_with_dict<B>(src: const u8[:], dict: const u8[:], out: B&) -> bool
fn deflate_block<B>(src: const u8[:], is_final: bool, out: B&) -> bool
fn inflate<B>(src: const u8[:], out: B&) -> bool
fn inflate_ex<B>(src: const u8[:], out: B&) -> CompressError
fn inflate_with_dict<B>(src: const u8[:], dict: const u8[:], out: B&) -> bool
fn inflate_with_limit<B>(src: const u8[:], out: B&, max_output_len: i64) -> CompressError
fn inflate_with_dict_limit<B>(src: const u8[:], dict: const u8[:], out: B&, max_output_len: i64) -> CompressError

// core/compress/gzip.goose, core/compress/zlib.goose & core/compress/zstd.goose
fn gzip_compress<B>(src: const u8[:], out: B&) -> bool
fn gzip_compress_with_header<B>(src: const u8[:], filename: const u8[:], comment: const u8[:], mtime: u32, out: B&) -> bool
fn gzip_decompress<B>(src: const u8[:], out: B&) -> bool
fn gzip_decompress_with_limit<B>(src: const u8[:], out: B&, max_output_len: i64) -> CompressError
fn parse_gzip_header_offset(src: const u8[:]) -> i64, bool
fn zlib_compress<B>(src: const u8[:], out: B&) -> bool
fn zlib_compress_with_dict<B>(src: const u8[:], dict: const u8[:], out: B&) -> bool
fn zlib_decompress<B>(src: const u8[:], out: B&) -> bool
fn zlib_decompress_with_dict<B>(src: const u8[:], dict: const u8[:], out: B&) -> bool
fn zlib_decompress_with_limit<B>(src: const u8[:], out: B&, max_output_len: i64) -> CompressError
fn zlib_decompress_with_dict_limit<B>(src: const u8[:], dict: const u8[:], out: B&, max_output_len: i64) -> CompressError
fn zstd_compress<B>(src: const u8[:], out: B&) -> bool
fn zstd_compress_level<B>(src: const u8[:], level: i32, out: B&) -> bool
fn zstd_compress_with_dict<B>(src: const u8[:], dict: const u8[:], out: B&) -> bool
fn zstd_decompress<B>(src: const u8[:], out: B&) -> bool
fn zstd_decompress_with_limit<B>(src: const u8[:], out: B&, max_output_len: i64) -> CompressError
fn zstd_decompress_with_dict<B>(src: const u8[:], dict: const u8[:], out: B&) -> bool
fn zstd_decompress_frames_incremental<B>(src: const u8[:], out: B&) -> i64, bool

// core/compress/brotli_dict.goose, core/compress/brotli.goose & core/compress/stream.goose
const BROTLI_DICTIONARY: const u8[:]
enum FlushMode { .. }                       enum ContainerFormat { .. }
struct ZStreamCompressor { .. }             struct ZStreamDecompressor { .. }
fn brotli_transform_word<B>(word: const u8[:], transform_idx: u32, out: B&) -> bool
fn brotli_lookup_dictionary_word<B>(distance: u32, max_dist: u32, copy_len: u32, out: B&) -> bool
fn brotli_compress<B>(src: const u8[:], out: B&) -> bool
fn brotli_compress_level0<B>(src: const u8[:], out: B&) -> bool
fn brotli_compress_level1<B>(src: const u8[:], out: B&) -> bool
fn brotli_decompress<B>(src: const u8[:], out: B&) -> bool
fn brotli_decompress_with_limit<B>(src: const u8[:], out: B&, max_output_len: i64) -> CompressError
fn brotli_decompress_with_dict<B>(src: const u8[:], dict: const u8[:], out: B&) -> bool
fn detect_container_format(src: const u8[:]) -> ContainerFormat
fn new_zstream_compressor(fmt: ContainerFormat = ContainerFormat.Deflate) -> ZStreamCompressor
fn zstream_write<B>(zs: ZStreamCompressor&, chunk: const u8[:], out: B&) -> bool
fn zstream_sync_flush<B>(zs: ZStreamCompressor&, out: B&) -> bool
fn zstream_full_flush<B>(zs: ZStreamCompressor&, out: B&) -> bool
fn zstream_finish<B>(zs: ZStreamCompressor&, out: B&) -> bool
fn zstream_set_dictionary(zs: ZStreamCompressor&, dict: const u8[:])
fn new_zstream_decompressor(fmt: ContainerFormat = ContainerFormat.Deflate) -> ZStreamDecompressor
fn zstream_decompress_write<B>(zd: ZStreamDecompressor&, chunk: const u8[:], out: B&) -> bool
fn zstream_decompress_write_limit<B>(zd: ZStreamDecompressor&, chunk: const u8[:], out: B&, max_output_len: i64) -> CompressError
fn zstream_decompress_set_dictionary(zd: ZStreamDecompressor&, dict: const u8[:])
fn decompress_auto<B>(src: const u8[:], out: B&, max_output_len: i64 = 16777216) -> CompressError
```

Implements CRC-32, Adler-32, and XXH64 checksums
(`core/compress/checksum.goose`), RFC 1951 DEFLATE
(`core/compress/deflate.goose`), RFC 1952 GZIP (`core/compress/gzip.goose`), RFC
1950 ZLIB (`core/compress/zlib.goose`), RFC 8878 Zstandard
(`core/compress/zstd.goose`), RFC 7932 Brotli and its 120 KiB static dictionary
(`core/compress/brotli.goose`, `core/compress/brotli_dict.goose`), and streaming
auto-detecting codecs (`core/compress/stream.goose`). All `*_with_limit`
functions abort decompression immediately with
`CompressError.OutputLimitExceeded` if uncompressed output exceeds
`max_output_len`.

### `core/math/`: Checked Arithmetic, Bit Manipulation & PRNG

```goose
// core/math/ct.goose & core/math/arithmetic.goose
struct CheckedU32 { val: u32, overflow: bool }
struct CheckedU64 { val: u64, overflow: bool }
struct CheckedI64 { val: i64, overflow: bool }
fn ct_is_zero_u32(x: u32) -> u32            fn ct_is_zero_u64(x: u64) -> u64
fn ct_eq_u32(a: u32, b: u32) -> u32         fn ct_eq_u64(a: u64, b: u64) -> u64
fn ct_lt_u32(a: u32, b: u32) -> u32         fn ct_lt_u64(a: u64, b: u64) -> u64
fn ct_select_u32(mask: u32, a: u32, b: u32) -> u32
fn ct_select_u64(mask: u64, a: u64, b: u64) -> u64
fn ct_min_u64(a: u64, b: u64) -> u64        fn ct_max_u64(a: u64, b: u64) -> u64
fn clamp_i32(val: i32, lo: i32, hi: i32) -> i32
fn clamp_u32(val: u32, lo: u32, hi: u32) -> u32
fn clamp_u64(val: u64, lo: u64, hi: u64) -> u64
fn clamp_i64(val: i64, lo: i64, hi: i64) -> i64
fn mul_wide_u64(a: u64, b: u64) -> u64, u64
fn wymum(a: u64, b: u64) -> u64
fn add_sat_u32(a: u32, b: u32) -> u32       fn add_sat_u64(a: u64, b: u64) -> u64
fn sub_sat_u32(a: u32, b: u32) -> u32       fn sub_sat_u64(a: u64, b: u64) -> u64
fn mul_sat_u32(a: u32, b: u32) -> u32       fn mul_sat_u64(a: u64, b: u64) -> u64
fn add_checked_u32(a: u32, b: u32) -> CheckedU32
fn add_checked_u64(a: u64, b: u64) -> CheckedU64
fn mul_checked_i64(a: i64, b: i64) -> CheckedI64
fn rem_euclid_i64(a: i64, b: i64) -> i64    fn div_euclid_i64(a: i64, b: i64) -> i64

// core/math/bits.goose & core/math/hash.goose
fn rotl32(x: u32, k: u32) -> u32            fn rotr32(x: u32, k: u32) -> u32
fn rotl64(x: u64, k: u32) -> u64            fn rotr64(x: u64, k: u32) -> u64
fn is_pow2_u64(x: u64) -> bool              fn next_pow2_u64(x: u64) -> u64
fn bswap16(x: u16) -> u16                   fn bswap32(x: u32) -> u32
fn bswap64(x: u64) -> u64
fn read_be_u16(b: const u8[:], off: i64 = 0) -> u16
fn read_be_u24(b: const u8[:], off: i64 = 0) -> u32
fn read_be_u32(b: const u8[:], off: i64 = 0) -> u32
fn read_be_u64(b: const u8[:], off: i64 = 0) -> u64
fn write_be_u16(b: u8[:], off: i64, val: u16)
fn write_be_u32(b: u8[:], off: i64, val: u32)
fn write_be_u64(b: u8[:], off: i64, val: u64)
fn read_le_u16(b: const u8[:], off: i64 = 0) -> u16
fn read_le_u32(b: const u8[:], off: i64 = 0) -> u32
fn read_le_u64(b: const u8[:], off: i64 = 0) -> u64
fn write_le_u16(b: u8[:], off: i64, val: u16)
fn write_le_u32(b: u8[:], off: i64, val: u32)
fn write_le_u64(b: u8[:], off: i64, val: u64)
fn swar_has_zero_byte(w: u64) -> bool
fn swar_has_byte(w: u64, target: u8) -> bool
fn swar_has_ctl_or_del(w: u64) -> bool
fn fnv1a_32(data: const u8[:]) -> u32       fn fnv1a_64(data: const u8[:]) -> u64
fn xxhash32(data: const u8[:], seed: u32 = 0) -> u32
fn wyhash64(data: const u8[:], seed: u64 = 0) -> u64
fn wyhash64_with_secret(data: const u8[:], seed: u64, secret: const u64[4]&) -> u64
fn hash_combine_u64(seed: u64, val: u64) -> u64
fn hash_combine_u32(seed: u32, val: u32) -> u32

// core/math/random.goose & core/math/network.goose
struct WyRand { .. }                        struct Xoroshiro64StarStar { .. }
struct JacobsonRttEstimator { .. }
fn splitmix64(state: u64&) -> u64
fn new_wyrand(seed: u64) -> WyRand
fn next_u64(rng: WyRand&) -> u64            fn next_u32(rng: WyRand&) -> u32
fn new_xoroshiro64_star_star(seed: u64) -> Xoroshiro64StarStar
fn fast_range_biased_u32(random_word: u32, range: u32) -> u32
fn fast_range_biased_u64(random_word: u64, range: u64) -> u64
fn fast_range_unbiased_u32(rng: WyRand&, range: u32) -> u32
fn fast_range_unbiased_u64(rng: WyRand&, range: u64) -> u64
fn new_jacobson_rtt_estimator() -> JacobsonRttEstimator
fn on_rtt_sample(est: JacobsonRttEstimator&, rtt_us: i64, ack_delay_us: i64 = 0)
fn probe_timeout_us(est: const JacobsonRttEstimator&, max_ack_delay_us: i64, pto_count: u32) -> i64
fn loss_time_threshold_us(est: const JacobsonRttEstimator&) -> i64
fn backoff_full_jitter_ms(rng: WyRand&, base_ms: i64, cap_ms: i64, attempt: u32) -> i64
fn backoff_equal_jitter_ms(rng: WyRand&, base_ms: i64, cap_ms: i64, attempt: u32) -> i64
fn backoff_decorrelated_jitter_ms(rng: WyRand&, base_ms: i64, cap_ms: i64, prev_sleep_ms: i64) -> i64
fn clamp_happy_eyeballs_delay_ms(delay_ms: i64) -> i64
fn retry_after_sec_to_ms_sat(sec: i64) -> i64
fn socks5_expected_frame_len_ct(atyp: u8, domain_len: u8) -> i64
```

Includes branchless integer masks (`core/math/ct.goose`), saturating and checked
arithmetic (`core/math/arithmetic.goose`), big-endian and little-endian wire
encoders and SWAR word predicates (`core/math/bits.goose`), FNV-1a, XXHash32,
and WyHash64 non-cryptographic hashes (`core/math/hash.goose`), SplitMix64,
WyRand, Xoroshiro64**, and Lemire divisionless range reduction
(`core/math/random.goose`), and RFC 6298 / RFC 9002 RTT estimation and jittered
backoff calculators (`core/math/network.goose`).

### `core/sync/`: Concurrency & Request Coalescing

```goose
// core/sync/singleflight.goose & core/sync/spsc_ring.goose
struct FlightEntry { .. }
struct SingleflightGroup { .. }
struct SpscRing { .. }
fn start_or_join(g: SingleflightGroup&, key: const u8[:]) -> i64, bool
fn finish_call(g: SingleflightGroup&, slot_idx: i64, val: i64, ok: bool)
fn forget(g: SingleflightGroup&, key: const u8[:])
fn forget_unshared(g: SingleflightGroup&, slot_idx: i64)
fn is_in_flight(g: const SingleflightGroup&, key: const u8[:]) -> bool
fn waiter_count(g: const SingleflightGroup&, slot_idx: i64) -> i32
fn is_shared(g: const SingleflightGroup&, slot_idx: i64) -> bool
fn result_value(g: const SingleflightGroup&, slot_idx: i64) -> i64, bool
fn spsc_init(r: SpscRing&, cap: i64) -> bool
fn spsc_close(r: SpscRing&)
fn spsc_push(r: SpscRing&, val: u64) -> bool
fn spsc_pop(r: SpscRing&) -> u64, bool
fn spsc_count(r: const SpscRing&) -> i64
fn spsc_available(r: const SpscRing&) -> i64
```

`SingleflightGroup` (`core/sync/singleflight.goose`) coalesces concurrent
in-flight calls for the same key, returning `(slot_idx, is_leader)` from
`start_or_join`. `SpscRing` (`core/sync/spsc_ring.goose`) provides a bounded
single-producer single-consumer ring queue of `u64` words.

### `core/time/`: Clocks, Durations & RFC Date Formatting

```goose
// core/time/duration.goose & core/time/clock.goose
struct Duration { ns: i64 }
struct MonotonicInstant { ns: i64 }
struct Stopwatch { .. }
struct Deadline { .. }
fn nanos(n: i64) -> Duration                fn micros(u: i64) -> Duration
fn millis(m: i64) -> Duration               fn secs(s: i64) -> Duration
fn mins(m: i64) -> Duration                 fn hours(h: i64) -> Duration
fn days(d: i64) -> Duration                 fn weeks(w: i64) -> Duration
fn as_nanos(d: Duration) -> i64             fn as_micros(d: Duration) -> i64
fn as_millis(d: Duration) -> i64            fn as_secs(d: Duration) -> i64
fn parse_duration(raw_str: const u8[:]) -> Duration, bool
fn monotonic_now() -> MonotonicInstant
fn duration_since(later: MonotonicInstant, earlier: MonotonicInstant) -> Duration
fn stopwatch() -> Stopwatch
fn elapsed(sw: const Stopwatch&) -> Duration
fn restart(sw: Stopwatch&) -> Duration
fn deadline_after(dur: Duration) -> Deadline
fn is_expired(dl: const Deadline&) -> bool
fn remaining(dl: const Deadline&) -> Duration
fn sleep(dur: Duration)

// core/time/calendar.goose, core/time/time.goose & core/time/format.goose
enum Month { .. }                           enum Weekday { .. }
struct Time { .. }
fn days_to_civil(z: i64) -> i32, u8, u8     fn civil_to_days(y: i32, m: u8, d: u8) -> i64
fn is_leap_year(y: i32) -> bool             fn days_in_month(y: i32, m: u8) -> u8
fn now() -> Time                            fn utc(t: Time) -> Time
fn unix(t: Time) -> i64                     fn unix_milli(t: Time) -> i64
fn unix_micro(t: Time) -> i64               fn unix_nano(t: Time) -> i64
fn date(year: i32, month: u8, day: u8, hour: u8 = 0, min: u8 = 0, sec: u8 = 0, nsec: i32 = 0) -> Time
fn civil_parts(t: Time) -> i32, u8, u8, u8, u8, u8
fn add(t: Time, d: Duration) -> Time        fn sub(t: Time, d: Duration) -> Time
fn since(later: Time, earlier: Time) -> Duration
fn until(target: Time, now_t: Time) -> Duration
fn before(a: Time, b: Time) -> bool         fn after(a: Time, b: Time) -> bool
fn format_rfc3339<B>(t: Time, out: B&)      fn format_rfc3339_nano<B>(t: Time, out: B&)
fn parse_rfc3339(raw_str: const u8[:]) -> Time, bool
fn format_http<B>(t: Time, out: B&)
fn parse_http_date(raw_str: const u8[:]) -> Time, bool
```

Provides nanosecond durations (`core/time/duration.goose`), monotonic clocks,
stopwatches, and deadlines (`core/time/clock.goose`), Howard Hinnant civil
calendar algorithms (`core/time/calendar.goose`), UTC wall-clock timestamps
(`core/time/time.goose`), and RFC 3339 and RFC 9110 §5.6.7 HTTP date
(`IMF-fixdate`, `rfc850-date`, `asctime-date`) parsers and formatters
(`core/time/format.goose`).

### `core/url/`: WHATWG URL & Origin Parsing

```goose
// core/url/types.goose & core/url/parser.goose
enum UrlParseError { .. }                   enum OriginKind { .. }
struct Url { .. }                           struct UrlView { .. }
struct Origin { .. }                        struct RegistrableSite { .. }
fn parse_url(raw: const u8[:]) -> Url, bool
fn parse_url_with_base(raw: const u8[:], base: const Url&) -> Url, bool
fn effective_port(u: const Url&) -> u16
fn is_http_or_https(u: const Url&) -> bool
fn is_secure_scheme(u: const Url&) -> bool
fn format_url_without_query_or_hash<B>(u: const Url&, out: B&)
fn normalize_http_target_uri<B>(raw_path: const u8[:], out: B&)
fn parse_url_view(raw: const u8[:]) -> UrlView, bool
fn new_url_view() -> UrlView
fn validate_host_punycode_labels(host: const u8[:]) -> bool

// core/url/path.goose, core/url/origin.goose & core/url/query.goose
struct QueryTokens { .. }
fn percent_decode<B>(src: const u8[:], out: B&) -> bool
fn percent_encode_path_segment<B>(src: const u8[:], out: B&)
fn new_file_url(path: const u8[:]) -> Url, bool
fn is_file_url(u: const Url&) -> bool
fn file_path<B>(u: const Url&, out: B&) -> bool
fn resolve_reference(base_url: const Url&, ref_str: const u8[:]) -> Url, bool
fn parse_reference(raw: const u8[:]) -> Url, bool
fn resolve_endpoint(base_url: const Url&, ref_str: const u8[:]) -> Url, bool
fn parse_endpoint(raw: const u8[:]) -> Url, bool
fn strip_ipv6_zone_id(host: const u8[:]) -> const u8[:]
fn format_outgoing_host<B>(u: const Url&, out: B&)
fn origin_from_url(u: const Url&) -> Origin
fn extract_etld_plus_one(host: const u8[:]) -> const u8[:]
fn public_suffix_with_icann(host: const u8[:]) -> const u8[:], bool
fn registrable_site_from_url(u: const Url&) -> RegistrableSite
fn is_same_origin(a: const Origin&, b: const Origin&) -> bool
fn is_same_origin_url(a: const Url&, b: const Url&) -> bool
fn serialize_origin<B>(orig: const Origin&, out: B&)
fn is_schemeful_same_site_urls(a: const Url&, b: const Url&) -> bool
fn is_same_site_origin_url(site_url: const Url&, target_url: const Url&) -> bool
fn parse_query_params(query: const u8[:]) -> QueryTokens
fn get_query_param(tokens: const QueryTokens&, key: const u8[:]) -> const u8[:], bool
fn has_query_param(tokens: const QueryTokens&, key: const u8[:]) -> bool
fn get_query_param_decoded<B>(tokens: const QueryTokens&, key: const u8[:], out: B&) -> bool
fn validate_query_param_count(query: const u8[:], max_params: i64) -> bool
enum QueryParamMatch { Missing, Valueless, Value }
fn get_query_param_fast<B>(raw_query: const u8[:], key: const u8[:], out: B&) -> QueryParamMatch
fn has_query_param_fast(raw_query: const u8[:], key: const u8[:]) -> bool
fn append_query_component<B>(raw: const u8[:], out: B&) -> bool
```

Implements owned (`Url`) and borrowed (`UrlView`) URL parsing and IDNA Punycode
label validation (`core/url/types.goose`, `core/url/parser.goose`), RFC 3986
dot-segment normalization, percent-encoding, and relative reference resolution
(`core/url/path.goose`), RFC 6454 origin comparison, ICANN public suffix
(`eTLD+1`) extraction, and schemeful same-site checks (`core/url/origin.goose`),
and zero-copy query string lookup (`core/url/query.goose`).
