// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// http/headers/chunked_fsm.goose
// Compact 64-bit Single-Register FSM Chunked Transfer Coding Decoder (uWebSockets ChunkedEncoding.h).
// Bit-packed streaming chunked decoder based on the uWebSockets design.
// Encodes all parser sub-states and chunk size in a single u64 register (0 heap allocations).
namespace http_internal;

import std;
import core;
import http.headers.chunked;
import http.headers.lexical;

const CHUNK_STATE_HAS_SIZE:               u64 = 0x8000000000000000;
const CHUNK_STATE_IS_CHUNKED:             u64 = 0x4000000000000000;
const CHUNK_STATE_EXTENSION_MODE:         u64 = 0x2000000000000000;
const CHUNK_STATE_TRAILER_MODE:           u64 = 0x1000000000000000;
const CHUNK_STATE_EXTENSION_EXPECTS_NAME: u64 = 0x0800000000000000;
const CHUNK_STATE_EXTENSION_QUOTED:       u64 = 0x0400000000000000;
const CHUNK_STATE_EXTENSION_EXPECTS_LF:   u64 = 0x0200000000000000;
const CHUNK_STATE_EXTENSION_IN_NAME:      u64 = 0x0100000000000000;
const CHUNK_STATE_EXTENSION_EXPECTS_VAL:  u64 = 0x0020000000000000;
const CHUNK_STATE_EXTENSION_ESCAPED:      u64 = 0x0010000000000000;
const CHUNK_STATE_EXTENSION_DONE_QUOTED:  u64 = 0x0008000000000000;
const CHUNK_STATE_SEEN_HEX:               u64 = 0x0080000000000000;
const CHUNK_STATE_SEEN_BWS:               u64 = 0x0040000000000000;

const CHUNK_STATE_EXTENSION_INCOMPLETE_FLAGS: u64 =
    CHUNK_STATE_EXTENSION_EXPECTS_NAME |
    CHUNK_STATE_EXTENSION_EXPECTS_VAL |
    CHUNK_STATE_EXTENSION_QUOTED |
    CHUNK_STATE_EXTENSION_ESCAPED |
    CHUNK_STATE_SEEN_BWS;

const CHUNK_STATE_SIZE_MASK:     u64 = 0x0000FFFFFFFFFFFF;
const CHUNK_STATE_SIZE_OVERFLOW: u64 = 0x0000F00000000000;
const CHUNK_STATE_IS_ERROR:      u64 = 0xFFFFFFFFFFFFFFFF;

enum ChunkFsmStatus {
    NeedMore,
    YieldChunk,
    Complete,
    Error,
}

struct ChunkFsmDecoder {
    state:              u64      = 0,
    ext_bytes:          u32      = 0,
    trailer_bytes:      u32      = 0,
    total_read:         i64      = 0,
    total_overhead:     i64      = 0,
    last_trailer_start: i64      = -1,
    trailer_name:       u8[..64] = [],
}

checkfree fn new_chunk_fsm_decoder() -> ChunkFsmDecoder {
    return ChunkFsmDecoder {
        state:              0,
        ext_bytes:          0,
        trailer_bytes:      0,
        total_read:         0,
        total_overhead:     0,
        last_trailer_start: -1,
        ..
    };
}

checkfree fn chunk_fsm_reset(dec: ChunkFsmDecoder&) {
    dec.state = 0;
    dec.ext_bytes = 0;
    dec.trailer_bytes = 0;
    dec.total_read = 0;
    dec.total_overhead = 0;
    dec.last_trailer_start = -1;
    dec.trailer_name.clear();
}

inline fn record_chunk_fsm_overhead(
    dec:          ChunkFsmDecoder&,
    st:           ChunkFsmStatus,
    consumed_len: i64,
    payload_len:  i64,
) -> ChunkFsmStatus {
    guard st != ChunkFsmStatus.Error else { return st; }
    let read_add = max(0, consumed_len);
    let ovh_add = core::sub_sat_i64(read_add, max(0, payload_len));
    dec.total_read = core::add_sat_i64(dec.total_read, read_add);
    dec.total_overhead = core::add_sat_i64(dec.total_overhead, ovh_add);
    if http::is_chunk_overhead_excessive(dec.total_read, dec.total_overhead) {
        dec.state = CHUNK_STATE_IS_ERROR;
        return ChunkFsmStatus.Error;
    }
    return st;
}

checkfree inline fn chunk_fsm_size(state: u64) -> u64 {
    return state & CHUNK_STATE_SIZE_MASK;
}

checkfree inline fn chunk_fsm_has_size(state: u64) -> bool {
    return (state & CHUNK_STATE_HAS_SIZE) != 0;
}

checkfree inline fn fail_chunk_trailer(dec: ChunkFsmDecoder&) -> ChunkFsmStatus {
    dec.state = CHUNK_STATE_IS_ERROR;
    return ChunkFsmStatus.Error;
}

// Consumes trailer headers until final empty line CRLF (RFC 9112 §7.1.2).
//
// Example:
//   data = "Trailer-Key: val\r\n\r\n", offset = 0
//   returns: Complete, offset = 20
fn feed_chunk_trailer(
    dec:    ChunkFsmDecoder&,
    data:   const u8[:],
    offset: i64&,
) -> ChunkFsmStatus {
    while offset < data.len {
        dec.trailer_bytes++;
        guard dec.trailer_bytes <= 4096 else { return fail_chunk_trailer(dec); }
        let c = data[offset];
        offset++;
        let sub_st = chunk_fsm_size(dec.state);
        if sub_st == 0 {
            if c == '\r' {
                dec.state = (dec.state & ~CHUNK_STATE_SIZE_MASK) | 1;
            } else if core::is_tchar(c) {
                dec.trailer_name.clear();
                dec.trailer_name.push(c);
                dec.state = (dec.state & ~CHUNK_STATE_SIZE_MASK) | 2;
            } else {
                return fail_chunk_trailer(dec);
            }
        } else if sub_st == 1 {
            guard c == '\n' else { return fail_chunk_trailer(dec); }
            dec.state = 0;
            dec.ext_bytes = 0;
            dec.trailer_bytes = 0;
            dec.trailer_name.clear();
            return ChunkFsmStatus.Complete;
        } else if sub_st == 2 {
            if c == ':' {
                guard !rfc::is_disallowed_trailer_field(dec.trailer_name[..]) else { return fail_chunk_trailer(dec); }
                dec.state = (dec.state & ~CHUNK_STATE_SIZE_MASK) | 4;
            } else if core::is_tchar(c) && dec.trailer_name.try_push(c) {
                // trailer name byte appended
            } else {
                return fail_chunk_trailer(dec);
            }
        } else if sub_st == 4 {
            if c == '\r' {
                dec.state = (dec.state & ~CHUNK_STATE_SIZE_MASK) | 3;
            } else if c == '\n' || c == 0x00 || (c < 0x20 && c != '\t') || c == 0x7F {
                return fail_chunk_trailer(dec);
            }
        } else if sub_st == 3 {
            guard c == '\n' else { return fail_chunk_trailer(dec); }
            dec.state = (dec.state & ~CHUNK_STATE_SIZE_MASK) | 0;
        }
    }
    return ChunkFsmStatus.NeedMore;
}

// Consumes a single character of chunk hex size or delimiter (RFC 9112 §7.1.1).
checkfree fn feed_chunk_hex_char(dec: ChunkFsmDecoder&, c: u8) -> bool {
    dec.ext_bytes++;
    if dec.ext_bytes > 1024 {
        dec.state = CHUNK_STATE_IS_ERROR;
        return false;
    }
    if c == ' ' || c == '\t' {
        // RFC 9112 Section 7.1.1: BWS preceding semicolon in chunk extension
        guard (dec.state & CHUNK_STATE_SEEN_HEX) != 0 else {
            dec.state = CHUNK_STATE_IS_ERROR;
            return false;
        }
        dec.state |= CHUNK_STATE_SEEN_BWS;
        return true;
    }

    if c == ';' {
        guard (dec.state & CHUNK_STATE_SEEN_HEX) != 0 else {
            dec.state = CHUNK_STATE_IS_ERROR;
            return false;
        }
        dec.state &= ~CHUNK_STATE_SEEN_BWS;
        dec.state |= CHUNK_STATE_EXTENSION_MODE | CHUNK_STATE_EXTENSION_EXPECTS_NAME;
        return true;
    }

    if c == '\r' {
        // RFC 9112 Section 7.1.1: Whitespace preceding CRLF without extension is strictly forbidden
        guard (dec.state & CHUNK_STATE_SEEN_HEX) != 0 && (dec.state & CHUNK_STATE_SEEN_BWS) == 0 else {
            dec.state = CHUNK_STATE_IS_ERROR;
            return false;
        }
        dec.state |= CHUNK_STATE_EXTENSION_MODE | CHUNK_STATE_EXTENSION_EXPECTS_LF;
        return true;
    }

    if c == '\n' {
        // RFC 9112 Section 7.1 & Section 2.2: Bare LF in chunk size is forbidden (CVE-2023-45287)
        dec.state = CHUNK_STATE_IS_ERROR;
        return false;
    }

    // If BWS was already seen, further hex digits are forbidden
    if (dec.state & CHUNK_STATE_SEEN_BWS) != 0 {
        dec.state = CHUNK_STATE_IS_ERROR;
        return false;
    }

    var num: u64 = 0;
    if c >= '0' && c <= '9' {
        num = c - '0';
    } else if c >= 'a' && c <= 'f' {
        num = c - 'a' + 10;
    } else if c >= 'A' && c <= 'F' {
        num = c - 'A' + 10;
    } else {
        dec.state = CHUNK_STATE_IS_ERROR;
        return false;
    }

    if (chunk_fsm_size(dec.state) & CHUNK_STATE_SIZE_OVERFLOW) != 0 {
        dec.state = CHUNK_STATE_IS_ERROR;
        return false;
    }

    let bits = dec.state & (CHUNK_STATE_IS_CHUNKED | CHUNK_STATE_SEEN_HEX | CHUNK_STATE_SEEN_BWS);
    dec.state = (dec.state & CHUNK_STATE_SIZE_MASK) * 16 + num;
    dec.state |= bits | CHUNK_STATE_SEEN_HEX;
    return true;
}

checkfree inline fn finish_chunk_ext_lf(dec: ChunkFsmDecoder&, done: bool&) -> bool {
    let cur_sz = dec.state & CHUNK_STATE_SIZE_MASK;
    guard cur_sz <= CHUNK_STATE_SIZE_MASK - 2 else {
        dec.state = CHUNK_STATE_IS_ERROR;
        return false;
    };
    dec.state = (cur_sz + 2) | CHUNK_STATE_HAS_SIZE | CHUNK_STATE_IS_CHUNKED;
    dec.ext_bytes = 0;
    done = true;
    return true;
}

// Consumes a single character of chunk extensions (RFC 9112 §7.1.1).
checkfree fn feed_chunk_ext_char(dec: ChunkFsmDecoder&, c: u8, done: bool&) -> bool {
    dec.ext_bytes++;
    if dec.ext_bytes > 1024 {
        dec.state = CHUNK_STATE_IS_ERROR;
        return false;
    }

    if (dec.state & CHUNK_STATE_EXTENSION_EXPECTS_LF) != 0 {
        if c != '\n' {
            dec.state = CHUNK_STATE_IS_ERROR;
            return false;
        }
        return finish_chunk_ext_lf(dec, done);
    }

    if c == 0x00 || (c < 0x20 && c != '\r' && c != '\n' && c != '\t') || c == 0x7F {
        dec.state = CHUNK_STATE_IS_ERROR;
        return false;
    }

    if c == '\r' {
        if (dec.state & CHUNK_STATE_EXTENSION_INCOMPLETE_FLAGS) != 0 {
            dec.state = CHUNK_STATE_IS_ERROR;
            return false;
        }
        dec.state |= CHUNK_STATE_EXTENSION_EXPECTS_LF;
        return true;
    }

    if (dec.state & CHUNK_STATE_EXTENSION_EXPECTS_NAME) != 0 {
        if c == ' ' || c == '\t' {
            return true; // BWS after ';'
        }
        if !http::is_tchar(c) {
            dec.state = CHUNK_STATE_IS_ERROR;
            return false;
        }
        dec.state &= ~CHUNK_STATE_EXTENSION_EXPECTS_NAME;
        dec.state |= CHUNK_STATE_EXTENSION_IN_NAME;
    } else if (dec.state & CHUNK_STATE_EXTENSION_IN_NAME) != 0 {
        if c == '=' {
            dec.state &= ~(CHUNK_STATE_EXTENSION_IN_NAME | CHUNK_STATE_SEEN_BWS);
            dec.state |= CHUNK_STATE_EXTENSION_EXPECTS_VAL;
        } else if c == ';' {
            dec.state &= ~(CHUNK_STATE_EXTENSION_IN_NAME | CHUNK_STATE_SEEN_BWS);
            dec.state |= CHUNK_STATE_EXTENSION_EXPECTS_NAME;
        } else if c == ' ' || c == '\t' {
            dec.state |= CHUNK_STATE_SEEN_BWS;
        } else if (dec.state & CHUNK_STATE_SEEN_BWS) != 0 || !http::is_tchar(c) {
            dec.state = CHUNK_STATE_IS_ERROR;
            return false;
        }
    } else if (dec.state & CHUNK_STATE_EXTENSION_EXPECTS_VAL) != 0 {
        if c == ' ' || c == '\t' {
            return true; // BWS after '='
        }
        if c == '"' {
            dec.state &= ~CHUNK_STATE_EXTENSION_EXPECTS_VAL;
            dec.state |= CHUNK_STATE_EXTENSION_QUOTED;
        } else if http::is_tchar(c) {
            dec.state &= ~CHUNK_STATE_EXTENSION_EXPECTS_VAL;
        } else {
            dec.state = CHUNK_STATE_IS_ERROR;
            return false;
        }
    } else {
        if (dec.state & CHUNK_STATE_EXTENSION_QUOTED) != 0 {
            if (dec.state & CHUNK_STATE_EXTENSION_ESCAPED) != 0 {
                // RFC 9110 §5.6.4: Consumed escaped char in quoted-pair (e.g. \" or \\)
                dec.state &= ~CHUNK_STATE_EXTENSION_ESCAPED;
            } else if c == '\\' {
                dec.state |= CHUNK_STATE_EXTENSION_ESCAPED;
            } else if c == '"' {
                dec.state &= ~CHUNK_STATE_EXTENSION_QUOTED;
                dec.state |= CHUNK_STATE_EXTENSION_DONE_QUOTED;
            }
        } else if (dec.state & (CHUNK_STATE_SEEN_BWS | CHUNK_STATE_EXTENSION_DONE_QUOTED)) != 0 {
            if c == ';' {
                dec.state &= ~(CHUNK_STATE_SEEN_BWS | CHUNK_STATE_EXTENSION_DONE_QUOTED);
                dec.state |= CHUNK_STATE_EXTENSION_EXPECTS_NAME;
            } else if c == ' ' || c == '\t' {
                dec.state |= CHUNK_STATE_SEEN_BWS;
            } else {
                dec.state = CHUNK_STATE_IS_ERROR;
                return false;
            }
        } else {
            if c == ';' {
                dec.state |= CHUNK_STATE_EXTENSION_EXPECTS_NAME;
            } else if c == ' ' || c == '\t' {
                dec.state |= CHUNK_STATE_SEEN_BWS;
            } else if !http::is_tchar(c) {
                dec.state = CHUNK_STATE_IS_ERROR;
                return false;
            }
        }
    }

    if c == '\n' {
        // RFC 9112 Section 7.1: Bare LF in chunk extension is forbidden
        dec.state = CHUNK_STATE_IS_ERROR;
        return false;
    }
    return true;
}

// Consumes chunk hex size and extensions up to trailing CRLF (RFC 9112 §7.1).
//
// Example:
//   data = "1A;ext=val\r\n", offset = 0
//   returns: NeedMore (header ready), offset = 12
checkfree fn feed_chunk_header(
    dec:    ChunkFsmDecoder&,
    data:   const u8[:],
    offset: i64&,
) -> ChunkFsmStatus {
    var pos = offset;
    guard pos >= 0 else {
        dec.state = CHUNK_STATE_IS_ERROR;
        return ChunkFsmStatus.Error;
    }
    while pos < data.len {
        let c = data[pos];
        if (dec.state & CHUNK_STATE_EXTENSION_MODE) == 0 {
            guard feed_chunk_hex_char(dec, c) else {
                offset = pos;
                return ChunkFsmStatus.Error;
            }
            pos++;
        } else {
            var done = false;
            guard feed_chunk_ext_char(dec, c, done) else {
                offset = pos;
                return ChunkFsmStatus.Error;
            }
            pos++;
            if done {
                break;
            }
        }
    }
    offset = pos;

    if dec.state == CHUNK_STATE_IS_ERROR {
        return ChunkFsmStatus.Error;
    }

    // If we parsed final chunk size 0 (stored as size 2 due to +2 CRLF)
    if chunk_fsm_has_size(dec.state) && chunk_fsm_size(dec.state) == 2 {
        dec.state = CHUNK_STATE_TRAILER_MODE | 0;
    }

    return ChunkFsmStatus.NeedMore;
}

// Emits complete chunk payload and verifies trailing CRLF boundary (RFC 9112 §7.1).
//
// Example:
//   data = "hello\r\n", offset = 0, size = 7
//   returns: YieldChunk, chunk = "hello"
checkfree fn feed_chunk_body_full(
    dec:    ChunkFsmDecoder&,
    data:   const u8[:],
    offset: i64&,
    size:   u64,
) -> ChunkFsmStatus, const u8[:] {
    let pos = offset;
    guard pos >= 0 && pos <= data.len else {
        dec.state = CHUNK_STATE_IS_ERROR;
        return ChunkFsmStatus.Error, data[..0];
    }
    let tail = data[pos..];
    if size > 2 {
        let chunk_len = (size - 2) as i64;
        guard chunk_len >= 0 && chunk_len <= tail.len - 2 else {
            dec.state = CHUNK_STATE_IS_ERROR;
            return ChunkFsmStatus.Error, data[..0];
        }
        let crlf = tail[chunk_len..];
        if crlf.len < 2 || crlf[0] != '\r' || crlf[1] != '\n' {
            dec.state = CHUNK_STATE_IS_ERROR;
            return ChunkFsmStatus.Error, data[..0];
        }
        let chunk_slice = tail[..chunk_len];
        offset = pos + (size as i64);
        dec.state = CHUNK_STATE_IS_CHUNKED;
        dec.ext_bytes = 0;
        return ChunkFsmStatus.YieldChunk, chunk_slice;
    }
    if size == 2 {
        if tail.len < 2 || tail[0] != '\r' || tail[1] != '\n' {
            dec.state = CHUNK_STATE_IS_ERROR;
            return ChunkFsmStatus.Error, data[..0];
        }
        offset = pos + 2;
        dec.state = CHUNK_STATE_IS_CHUNKED;
        dec.ext_bytes = 0;
        return ChunkFsmStatus.NeedMore, data[..0];
    }
    // Split CRLF: previously consumed body and '\r', expecting final '\n'
    if tail.len < 1 || tail[0] != '\n' {
        dec.state = CHUNK_STATE_IS_ERROR;
        return ChunkFsmStatus.Error, data[..0];
    }
    offset = pos + 1;
    dec.state = CHUNK_STATE_IS_CHUNKED;
    dec.ext_bytes = 0;
    return ChunkFsmStatus.NeedMore, data[..0];
}

// Emits partial chunk payload available across TCP boundary (RFC 9112 §7.1).
//
// Example:
//   data = "hel", offset = 0, size = 7, rem_data = 3
//   returns: YieldChunk, chunk = "hel"
checkfree fn feed_chunk_body_partial(
    dec:      ChunkFsmDecoder&,
    data:     const u8[:],
    offset:   i64&,
    size:     u64,
    rem_data: i64,
) -> ChunkFsmStatus, const u8[:] {
    let pos = offset;
    guard pos >= 0 && pos <= data.len && rem_data >= 0 && (rem_data as u64) <= size else {
        dec.state = CHUNK_STATE_IS_ERROR;
        return ChunkFsmStatus.Error, data[..0];
    }
    let tail = data[pos..];
    var chunk_slice: const u8[:] = data[..0];
    if size > 2 {
        let max_app_emit = (size - 2) as i64;
        if rem_data > max_app_emit && max_app_emit >= 0 && max_app_emit < tail.len {
            if tail[max_app_emit] != '\r' {
                dec.state = CHUNK_STATE_IS_ERROR;
                return ChunkFsmStatus.Error, data[..0];
            }
            chunk_slice = tail[..max_app_emit];
        } else {
            chunk_slice = tail;
        }
    } else if size == 2 {
        // RFC 9112 §7.1 & §2.2: Body already consumed; first byte of split CRLF terminator MUST be CR
        if tail.len < 1 || tail[0] != '\r' {
            dec.state = CHUNK_STATE_IS_ERROR;
            return ChunkFsmStatus.Error, data[..0];
        }
    }

    let consumed_bytes = rem_data as u64;
    dec.state = (dec.state & ~CHUNK_STATE_SIZE_MASK) | (size - consumed_bytes);
    dec.state |= CHUNK_STATE_IS_CHUNKED;
    offset = pos + rem_data;
    if chunk_slice.len > 0 {
        return ChunkFsmStatus.YieldChunk, chunk_slice;
    }
    return ChunkFsmStatus.NeedMore, data[..0];
}

// Emits decoded chunk body payload and validates CRLF boundary (RFC 9112 §7.1).
//
// Example:
//   data = "hello\r\n", offset = 0, size = 7 (5 + 2)
//   returns: YieldChunk, chunk = "hello", offset = 7
checkfree fn feed_chunk_body(
    dec:    ChunkFsmDecoder&,
    data:   const u8[:],
    offset: i64&,
) -> ChunkFsmStatus, const u8[:] {
    let pos = offset;
    if pos < 0 || pos > data.len {
        dec.state = CHUNK_STATE_IS_ERROR;
        return ChunkFsmStatus.Error, data[..0];
    }
    let size = chunk_fsm_size(dec.state);
    let rem_data = data.len - pos;

    if (rem_data as u64) >= size {
        return feed_chunk_body_full(dec, data, offset, size);
    }
    return feed_chunk_body_partial(dec, data, offset, size, rem_data);
}

// Feeds incoming data into the 64-bit FSM chunked decoder (RFC 9112 §7.1).
// Yields slices of decoded payload without allocating memory.
//
// Example:
//   data = "5\r\nhello\r\n", dec = new_chunk_fsm_decoder()
//   returns: YieldChunk, offset = 10, chunk = "hello"
fn chunk_fsm_feed(
    dec:  ChunkFsmDecoder&,
    data: const u8[:],
) -> ChunkFsmStatus, i64, const u8[:] {
    dec.last_trailer_start = -1;
    if dec.state == CHUNK_STATE_IS_ERROR {
        return ChunkFsmStatus.Error, 0, data[..0];
    }

    var offset: i64 = 0;
    while offset < data.len {
        // 1. Trailer mode
        if (dec.state & CHUNK_STATE_TRAILER_MODE) != 0 {
            let st = feed_chunk_trailer(dec, data, offset);
            return record_chunk_fsm_overhead(dec, st, offset, 0), offset, data[..0];
        }

        // 2. Consume chunk hex size and extensions
        if !chunk_fsm_has_size(dec.state) {
            let st = feed_chunk_header(dec, data, offset);
            if st == ChunkFsmStatus.Error {
                return ChunkFsmStatus.Error, offset, data[..0];
            }
            if (dec.state & CHUNK_STATE_TRAILER_MODE) != 0 {
                dec.last_trailer_start = offset;
                continue;
            }
            if !chunk_fsm_has_size(dec.state) {
                return record_chunk_fsm_overhead(dec, ChunkFsmStatus.NeedMore, offset, 0), offset, data[..0];
            }
        }

        // 3. Emit chunk body payload
        let st_body, chunk = feed_chunk_body(dec, data, offset);
        if st_body == ChunkFsmStatus.YieldChunk || st_body == ChunkFsmStatus.Error {
            return record_chunk_fsm_overhead(dec, st_body, offset, chunk.len), offset, chunk;
        }
    }

    return record_chunk_fsm_overhead(dec, ChunkFsmStatus.NeedMore, offset, 0), offset, data[..0];
}
