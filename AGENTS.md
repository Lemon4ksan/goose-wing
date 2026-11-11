# Agent rules and repository architecture (Part 1 of 2)

This file (`AGENTS.md`) and [`.agents/AGENTS.md`](file:///.agents/AGENTS.md)
form the two-part rulebook for `goose-wing`. Both are loaded into
`<user_rules>`; keep each under 13.5 KB so neither is truncated.

- **Part 1 (`AGENTS.md`)**: Module map, canonical `core::` and UFCS primitives
  catalog, Goose memory model, and verified compiler idioms.
- **Part 2 ([`.agents/AGENTS.md`](file:///.agents/AGENTS.md))**: CI,
  `goose-lit`, all 19 static invariants (`scripts/lint_invariants.py`), RFC
  citations, code geometry, and communication rules.

## Repository architecture and module map

- [`core.goose`](file:///core.goose) (`namespace core`): Zero-allocation
  primitives (`core/bytes`, `core/math`, `core/io`, `core/crypto`, `core/time`,
  `core/url`, `core/sync`, `core/compress`, `core/ufcs`).
- [`wing.goose`](file:///wing.goose) (`namespace wing`): Networking,
  cryptographic transport, and protocol stack:
  - `rfc/*`: Shared RFC grammar helpers (`rfc9110`, `rfc8941` Structured Fields,
    `rfc9111` cache directives, `rfc6265` cookies).
  - `wire/*`: Vulkan-style wire framing (`WireResult`, `WireFrame`,
    `CommandBuffer`, `SubmissionRing`, `WireConnection`, `WireDevice`).
  - `http/*`: HTTP/1.1 parser (`parser.goose`), `HeaderMap` with 64-bit Bloom
    filter (`headers.goose`), chunked framing, Range, Alt-Svc, Digest/Bearer,
    ETag, Problem Details (RFC 9457), Content-Digest (RFC 9530), WebSocket (RFC
    6455).
  - `http2/*`: HTTP/2 framing (RFC 9113), HPACK (RFC 7541), priority (RFC 9218),
    stream FSM, Rapid Reset defense.
  - `quic/*` & `http3/*`: QUIC transport (RFC 9000), BBR/NewReno congestion (RFC
    9002), TLS-QUIC keys (RFC 9001), QPACK (RFC 9204), HTTP/3 (RFC 9114),
    WebTransport.
  - `tls/*`: TLS 1.3 record layer, key schedule, handshake FSM, X.509 ASN.1 DER
    verifier, ALPN, SNI, session tickets (RFC 8446).
  - `auth/*`: JWT/JWS (RFC 7515/7519), JWKS (RFC 7517), PKCE (RFC 7636), DPoP
    (RFC 9449), HTTP Message Signatures (RFC 9421), Digest (RFC 7616), Basic
    (RFC 7617), PAKE.
  - `security/*`: CORS, CSRF, HSTS, CSP, SSRF IP/CIDR classifier, rate limiting,
    sanitizer, decompression bomb guard.
  - `dns/*`: Deterministic DNS wire codec (RFC 1035), RFC 9460 HTTPS/SVCB
    Type 65, RFC 8484 DoH query builders, and RFC 5861 LRU cache.
  - `net/*`, `client/*`, `server/*`, `proxy/*`, `realtime/*`, `grpc/*`,
    `cookie/*`, `fingerprint/*`: L4 sockets (`io_uring`, `kqueue`, Winsock RIO,
    AF_XDP, DPDK), connection pools, SoA timer wheels (`server/soa_timer.goose`),
    reverse proxy, SSE/WebSocket hubs, and gRPC framing.

## Canonical `core` and UFCS primitives catalog

Never re-implement byte scanners, character tables, trimmers, integer parsers,
endian readers, saturating math, or UTF-8/JSON helpers. Import `core.bytes`,
`core.math`, `core.io`, `core.crypto`, `core.url`, and `core.ufcs` and use:

### 1. Character classes and ASCII case folding (`core/bytes/case.goose`)

- **Predicates**: `core::is_tchar(b)` (RFC 9110), `core::is_uri_unreserved(b)`
  (RFC 3986), `core::is_ascii_vchar(b)`, `core::is_ascii_printable(b)`,
  `core::is_ascii_alpha(b)`, `core::is_ascii_alnum(b)`,
  `core::is_ascii_digit(b)`, `core::is_ascii_hexdigit(b)`,
  `core::is_ascii_ctl(b)`, `core::hex_digit_to_val(b) -> i32`.
- **Case conversion**: `core::to_lower_byte(b)`, `core::to_upper_byte(b)`,
  `s.to_lower_ascii(out)`, `s.to_upper_ascii(out)`.
- **Case-insensitive UFCS on `const u8[:]`**: `a.eq_ascii_fold(b)`,
  `s.starts_with_fold(prefix)`, `s.ends_with_fold(suffix)`,
  `s.contains_fold(needle)`, `s.index_of_fold(needle) -> i64`.

### 2. Zero-copy whitespace and byte trimming (`core/bytes/trim.goose`)

- **RFC 9110 OWS/LWS (`' '` or `'\t'`)**: `core::is_lws(b)`, `s.trim_lws()`,
  `s.trim_lws_start()`, `s.trim_lws_end()`.
- **ASCII whitespace (`SP`, `TAB`, `LF`, `CR`, `VT`, `FF`)**:
  `core::is_ascii_space(b)`, `s.trim_ascii_space()`,
  `s.trim_ascii_space_start()`, `s.trim_ascii_space_end()`.
- **Byte & cutset trimming**: `s.trim_byte(b)`, `s.trim_start_byte(b)`,
  `s.trim_end_byte(b)`, `s.trim_bytes(cutset)`, `s.trim_start_bytes(cutset)`,
  `s.trim_end_bytes(cutset)`.

### 3. Searching, splitting, and unquoted scanners (`core/bytes/search.goose`, `split.goose`)

- **Search**: `core::equal_short(a, b)`, `core::starts_with(s, p)`,
  `core::ends_with(s, sfx)`, `s.contains_byte(b)`, `s.index_of_byte(b) -> i64`,
  `s.last_index_of_byte(b) -> i64`, `s.count_byte(b) -> i64`,
  `core::find(haystack, needle) -> i64`, `core::rfind(haystack, needle) -> i64`,
  `core::contains(haystack, needle)`, `core::find_byteset(s, set)`,
  `core::find_not_byteset(s, set)`, `core::swar_find_ctl(s)`,
  `core::fast_find_crlfcrlf(s)`, `core::find_crlf(s)`.
- **Prefix/suffix stripping & splitting (UFCS on `const u8[:]`)**:
  `s.strip_prefix(p)`, `s.strip_suffix(sfx)`, `s.strip_prefix_fold(p)`,
  `s.strip_suffix_fold(sfx)` -> `(rest, bool)`; `s.split_once_byte('=')`,
  `s.rsplit_once_byte('/')`, `s.split_once("::")`, `s.split_once_fold(": ")` ->
  `(prefix, suffix, bool)`; `s.partition_byte('?') -> (head, sep, tail)`;
  `core::collapse_repeats_in_place(buf, '/') -> i64`; `core::each_pair<T, F>(xs)`,
  `core::each_window<T, F>(xs, k)`.
- **Quote-aware RFC parameter splitting (honors `\"` and `\\` inside `"..."`)**:
  `s.find_unquoted_byte(';') -> i64`,
  `s.split_once_unquoted_byte(';') -> (head, tail, bool)`.
- **Tokenizer**: `var tok = core::make_byte_tokenizer(s, ',');` with
  `core::token_next(tok) -> (const u8[:], bool)`,
  `core::token_peek(tok) -> (const u8[:], bool)`,
  `core::token_rest(tok) -> const u8[:]`, and
  `for t in s.each_non_empty_token('.') { ... }`.

### 4. Integer parsing, formatting, UTF-8, and JSON (`core/bytes/*`)

- **Parsing (UFCS on `const u8[:]`, rejects overflow/empty)**:
  `s.parse_u64_dec()`, `s.parse_i64_dec()`, `s.parse_u32_dec()`,
  `s.parse_i32_dec()`, `s.parse_u64_hex()`, `s.parse_u32_hex()`,
  `s.parse_u8_hex()` -> `(T, bool)`.
- **Formatting (UFCS on integers into `out: B&`)**: `val.format_u64_dec(out)`,
  `val.format_i64_dec(out)`, `val.format_u32_dec(out)`,
  `val.format_u64_hex(out, upper)`, `val.format_u32_hex(out, upper)`,
  `val.format_u8_hex(out, upper)`, `core::format_u64_hex_fixed(val, w, out, u)`.
- **UTF-8**: `s.validate_utf8()`, `core::is_pure_ascii(s)`,
  `core::validate_utf8_dfa_chunk(data, state, is_fin)`,
  `core::validate_utf8_streaming(data, is_final)`, `core::decode_utf8(s)`,
  `core::char_indices<F>(s)`.
- **Bounded JSON (zero `u8[>..]` scratch allocation)**:
  `core::read_json_string_into(r, dst) -> bool`,
  `core::decode_json_string_into(text, start, end, dst) -> bool`,
  `core::format_json_string(out, s)`, `core::format_json_key(out, key)`,
  `core::escape_json_string(s, out)`.

### 5. Safe buffer UFCS, endian codecs, math, crypto, and I/O (`core/*`)

- **Buffer UFCS (`u8[..k]&`, `T[..k]&`)**: `buf.try_push(item) -> bool`,
  `buf.try_append(slice) -> bool`, `buf.try_set(slice) -> bool` (clears and
  copies if `slice.len <= buf.cap`), `buf.compact_wire_buffer(consumed)`.
- **Endian**: `out.append_u16_be(v)`, `out.append_u24_be(v)`,
  `out.append_u32_be(v)`, `out.append_u64_be(v)`,
  `core::read_be_u16/u24/u32/u64(data, off)`,
  `core::read_le_u16/u24/u32/u64(data, off)`,
  `core::write_be_u16_at/u32_at/u64_at(dst, off, val)`,
  `core::bswap16/32/64(x)`.
- **Saturating math (eliminates signed `ovf_ops` in G-CRAP)**:
  `core::add_sat_i64(a, b)`, `core::sub_sat_i64(a, b)`,
  `core::add_sat_u64(a, b)`, `core::sub_sat_u64(a, b)`,
  `core::mul_sat_u64(a, b)`, `core::shl_sat_u64(a, shift)`,
  `core::add_checked_u64(a, b)`, `core::mul_checked_i64(a, b)`.
- **Crypto & zeroization**: `core::ct_eq_bytes(a, b)`,
  `core::ct_eq_tag16(a, b)`, `core::ct_eq_tag32(a, b)`,
  `core::secure_zeroize_16/24/32/48/64(buf)`, `core::secure_zeroize_slice(s)`,
  `core::KeySlot` (`core::zeroize_key_slot(slot)`),
  `core::base64_decode(src, dst)`, `core::base64url_decode(src, dst)`.
- **Binary cursors, rings, & URLs**: `core::ByteCursor` (`read_u8/u16/u24/u32`,
  `read_bytes`, `read_u16_prefixed`, `read_u24_prefixed`, `read_sub_cursor`,
  `read_u8/u16/u24_sub_cursor`), `core::BitStreamReader` (`make_bit_reader`,
  `read_bits`), `core::ByteBuilder` (`start_u16_prefix`, `finish_u16_prefix`,
  `start_u24_prefix`, `finish_u24_prefix`), `core::RingBuffer`
  (`rotate_left_in_place`, `realign_ring`, `contiguous_readable_slice`),
  `core::PipeBuffer`, `core::CorkBuffer`, `core::PageRingBuffer`,
  `core::GuardedArena`, `core::parse_url(raw)`,
  `core::normalize_http_target_uri(raw, out)`,
  `raw_query.get_query_param_fast(key, out)`,
  `raw_query.has_query_param_fast(key)`.

## Goose language rules and compiler idioms

### 1. Data-stack memory model and size classes

- Goose has no heap allocator, GC, reference counting, destructors, or lifetime
  annotations. Memory lives on the call stack, static data, and compile-time
  **data stacks**.
- Three size classes:
  - **Fixed** (compile-time size): scalars, `T[k]`, `T[..k]`, fixed structs,
    `T&`, `T[:]`, fixed enums (`Shape`).
  - **Variable** (construction-time size, frozen): `T[]`, `T[varint]`, `T[..]`,
    variable enums (`Shape..`). `u8[][>..]` is sequential only; keep a side
    array `(T&)[>..]` for random access.
  - **Resizable** (growable on a data stack): `T[>..]` (grow-only; references
    into it remain valid across pushes) and `T[>..<]` (grow-shrink). At most
    one resizable field may appear as the **final field** of an ordinary
    struct.
- **Root owners (`root struct`)**: Containers with multiple growing arrays (SoA
  tables in `server/soa_timer.goose`, `slot_pool<T>`, `slice_pool<T>`) must be
  declared `root struct` (local or global only, passed by reference `Pool&`).

### 2. References, copies, arithmetic, and `checkfree fn` BCE

- References (`T&`) and nullable references (`T?`, narrowed via `if x`,
  `guard x`, `while x`, `assert(x)`) are transparent. Use `.=` to bind or
  rebind a reference (`let conn .= pool.conns[idx];` binds an 8-byte reference
  without copying `PooledConnection` and mutates `pool.conns[idx]` in place) and
  `.==` / `.!=` for identity.
- Fixed-size values copy implicitly on `=` and in `for x in xs`. Iterate by
  reference (`for &x in xs`) to mutate elements in place or take slices that
  outlive a loop iteration. Non-fixed values (`T[>..]`) bind by reference on
  `var b = a;`; write `copy(a)` for an explicit copy.
- Arithmetic has no implicit cross-width promotion. Unsigned overflow wraps;
  **signed overflow aborts in `--debug` builds**. `%` is Euclidean (`-7 % 3 == 2`).
  Narrowing requires `as` (checked) or `as!` (unchecked).
- `checkfree fn` makes any uneliminated bounds check a **compile error**
  (`goose check --stats` or `--bce-lines`). Prove bounds at entry with `guard`
  or Euclidean `%`.
- Extern syntax:
  `extern fn native_fast_u64toa(val: u64, dst: u8[:]) -> i32 = "wing_fast_u64toa";`.

### 3. Verified Goose compiler idioms and anti-hallucination rules

- **Zero integer suffixes or `usize`/`isize`**: `1u64`, `0xFFu32`, `usize`, and
  `isize` do not exist. Slice `.len` and indexing use `i64` or `u64`. Cast hex
  literals `>= 0x8000000000000000` via `(lit as! i64)` when assigning to `i64`.
- **Built-in `min(a, b)` and `max(a, b)`**: Use `min` and `max` from `std`
  instead of ternary clamping (`if x > 96 { 96 } else { x }`) to avoid adding
  branches to `EffCC` and `G-CRAP`.
- **Generic trailing blocks (`<T, F>`)**: Function types (`fn(...)`) are
  compile-time only and cannot be passed as runtime parameters in non-generic
  functions. Declare callbacks/trailing blocks as a generic parameter `F`:
  ```goose
  fn with_pool_slot<T, F>(pool: slot_pool<T>&, init_val: T) -> bool {
      let idx = pool.alloc_index(init_val);
      defer pool.free(idx);
      F(pool.items[idx]);
      return true;
  }
  ```
- **Compile-time reflection (`const for`)**:
  - In `const for <N, A> in fields<T>`, accessor `A` is bound strictly to `T`
    (`rec.A`) and cannot index a different struct type `U`.
  - In `const for <N, V> in variants<E>`, `V` is the variant subtype
    (`E.Variant`). Construct an enum value via `let v: E = default<V>();`
    before comparing `val == v`.
- **Slice caret (`^k`) vs element indexing**: `^k` (`len - k`) is valid only in
  slice bounds (`s[..^1]`, `s[^2..]`, `s[..^sfx.len]`). Single-element end
  indexing uses `s[s.len - 1]`.
- **`slot_pool<T>` API (`import slot_pool`)**: Use `pool.alloc_index(val) -> i64`,
  `pool.alloc_ref(val) -> T&`, `pool.alloc_with() -> T&`, `pool.free(idx)`,
  `pool.free_ref(ref)`, `pool.recycle_all()`, and `pool.items[idx]`.
- **Transactional rollback (`errdefer` pattern)**: Implement cursor and
  out-buffer rollback (Invariants 5 and 18) with a `committed` guard:
  ```goose
  let saved_idx = idx;
  let saved_len = out.len;
  var committed = false;
  defer if !committed { idx = saved_idx; out.resize(saved_len); };
  // ... early `return false;` paths roll back `idx` and `out` ...
  committed = true;
  return true;
  ```
- **`print` spacing in LIT tests**: `print(a, b)` concatenates arguments
  without spaces; pass explicit `" "` separators (`print("ok:", ok)`).

See [`.agents/AGENTS.md`](file:///.agents/AGENTS.md) for Part 2.
