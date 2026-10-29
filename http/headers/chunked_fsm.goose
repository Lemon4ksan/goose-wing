// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// http/headers/chunked_fsm.goose
// Compact 64-bit Single-Register FSM Chunked Transfer Coding Decoder (uWebSockets ChunkedEncoding.h).
// Bit-packed streaming chunked decoder based on the uWebSockets design.
// Encodes all parser sub-states and chunk size in a single u64 register (0 heap allocations).
namespace internal;

import std;
import core from "../..";

const CHUNK_STATE_HAS_SIZE: u64 = 0x8000000000000000;
const CHUNK_STATE_IS_CHUNKED: u64 = 0x4000000000000000;
const CHUNK_STATE_EXTENSION_MODE: u64 = 0x2000000000000000;
const CHUNK_STATE_TRAILER_MODE: u64 = 0x1000000000000000;
const CHUNK_STATE_EXTENSION_EXPECTS_NAME: u64 = 0x0800000000000000;
const CHUNK_STATE_EXTENSION_QUOTED: u64 = 0x0400000000000000;
const CHUNK_STATE_EXTENSION_EXPECTS_LF: u64 = 0x0200000000000000;
const CHUNK_STATE_EXTENSION_IN_NAME: u64 = 0x0100000000000000;
const CHUNK_STATE_EXTENSION_EXPECTS_VAL: u64 = 0x0020000000000000;
const CHUNK_STATE_EXTENSION_ESCAPED: u64 = 0x0010000000000000;
const CHUNK_STATE_SEEN_HEX: u64 = 0x0080000000000000;
const CHUNK_STATE_SEEN_BWS: u64 = 0x0040000000000000;

const CHUNK_STATE_EXTENSION_ALL_FLAGS: u64 =
    CHUNK_STATE_EXTENSION_MODE |
    CHUNK_STATE_EXTENSION_EXPECTS_NAME |
    CHUNK_STATE_EXTENSION_IN_NAME |
    CHUNK_STATE_EXTENSION_EXPECTS_VAL |
    CHUNK_STATE_EXTENSION_QUOTED |
    CHUNK_STATE_EXTENSION_ESCAPED |
    CHUNK_STATE_EXTENSION_EXPECTS_LF |
    CHUNK_STATE_SEEN_HEX |
    CHUNK_STATE_SEEN_BWS;

const CHUNK_STATE_EXTENSION_INCOMPLETE_FLAGS: u64 =
    CHUNK_STATE_EXTENSION_EXPECTS_NAME |
    CHUNK_STATE_EXTENSION_EXPECTS_VAL |
    CHUNK_STATE_EXTENSION_QUOTED |
    CHUNK_STATE_EXTENSION_ESCAPED;

const CHUNK_STATE_SIZE_MASK: u64 = 0x0000FFFFFFFFFFFF;
const CHUNK_STATE_SIZE_OVERFLOW: u64 = 0x0000F00000000000;
const CHUNK_STATE_IS_ERROR: u64 = 0xFFFFFFFFFFFFFFFF;

enum ChunkFsmStatus {
    NeedMore,
    YieldChunk,
    Complete,
    Error,
}

struct ChunkFsmDecoder {
    state: u64 = 0,
    ext_bytes: u32 = 0,
    trailer_bytes: u32 = 0,
}

fn new_chunk_fsm_decoder() -> ChunkFsmDecoder {
    return ChunkFsmDecoder { state: 0, ext_bytes: 0, trailer_bytes: 0 };
}

fn chunk_fsm_reset(dec: ChunkFsmDecoder&) {
    dec.state = 0;
    dec.ext_bytes = 0;
    dec.trailer_bytes = 0;
}

inline fn chunk_fsm_size(state: u64) -> u64 {
    return state & CHUNK_STATE_SIZE_MASK;
}

inline fn chunk_fsm_has_size(state: u64) -> bool {
    return (state & CHUNK_STATE_HAS_SIZE) != 0;
}

inline fn is_chunk_token_char(c: u8) -> bool {
    if c < 0x20 || c >= 0x7F { return false; }
    if c == '(' || c == ')' || c == '<' || c == '>' || c == '@' ||
       c == ',' || c == ';' || c == ':' || c == '\\' || c == '"' ||
       c == '/' || c == '[' || c == ']' || c == '?' || c == '=' ||
       c == '{' || c == '}' || c == ' ' || c == '\t' {
        return false;
    }
    return true;
}

// Consumes trailer headers until final empty line CRLF (RFC 9112 §7.1.2).
//
// Example:
//   data = "Trailer-Key: val\r\n\r\n", offset = 0
//   returns: Complete, offset = 20
fn feed_chunk_trailer(
    dec: ChunkFsmDecoder&,
    data: const u8[:],
    offset: i64&,
) -> ChunkFsmStatus {
    while offset < data.len {
        dec.trailer_bytes++;
        if dec.trailer_bytes > 4096 {
            dec.state = CHUNK_STATE_IS_ERROR;
            return ChunkFsmStatus.Error;
        }
        let c = data[offset];
        offset++;
        let sub_st = chunk_fsm_size(dec.state);
        if sub_st == 0 {
            if c == '\r' {
                dec.state = (dec.state & ~CHUNK_STATE_SIZE_MASK) | 1;
            } else if is_chunk_token_char(c) {
                dec.state = (dec.state & ~CHUNK_STATE_SIZE_MASK) | 2;
            } else {
                dec.state = CHUNK_STATE_IS_ERROR;
                return ChunkFsmStatus.Error;
            }
        } else if sub_st == 1 {
            if c == '\n' {
                dec.state = 0;
                dec.ext_bytes = 0;
                dec.trailer_bytes = 0;
                return ChunkFsmStatus.Complete;
            }
            dec.state = CHUNK_STATE_IS_ERROR;
            return ChunkFsmStatus.Error;
        } else if sub_st == 2 {
            if c == ':' {
                dec.state = (dec.state & ~CHUNK_STATE_SIZE_MASK) | 4;
            } else if !is_chunk_token_char(c) {
                dec.state = CHUNK_STATE_IS_ERROR;
                return ChunkFsmStatus.Error;
            }
        } else if sub_st == 4 {
            if c == '\r' {
                dec.state = (dec.state & ~CHUNK_STATE_SIZE_MASK) | 3;
            } else if c == '\n' || c == 0x00 || (c < 0x20 && c != '\t') || c == 0x7F {
                dec.state = CHUNK_STATE_IS_ERROR;
                return ChunkFsmStatus.Error;
            }
        } else if sub_st == 3 {
            if c == '\n' {
                dec.state = (dec.state & ~CHUNK_STATE_SIZE_MASK) | 0;
            } else {
                dec.state = CHUNK_STATE_IS_ERROR;
                return ChunkFsmStatus.Error;
            }
        }
    }
    return ChunkFsmStatus.NeedMore;
}

// Consumes a single character of chunk hex size or delimiter (RFC 9112 §7.1.1).
inline fn feed_chunk_hex_char(dec: ChunkFsmDecoder&, c: u8) -> bool {
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

// Consumes a single character of chunk extensions (RFC 9112 §7.1.1).
inline fn feed_chunk_ext_char(dec: ChunkFsmDecoder&, c: u8, done: bool&) -> bool {
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
        dec.state += 2;
        dec.state |= CHUNK_STATE_HAS_SIZE | CHUNK_STATE_IS_CHUNKED;
        dec.state &= ~CHUNK_STATE_EXTENSION_ALL_FLAGS;
        dec.ext_bytes = 0;
        done = true;
        return true;
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
        if !is_chunk_token_char(c) {
            dec.state = CHUNK_STATE_IS_ERROR;
            return false;
        }
        dec.state &= ~CHUNK_STATE_EXTENSION_EXPECTS_NAME;
        dec.state |= CHUNK_STATE_EXTENSION_IN_NAME;
    } else if (dec.state & CHUNK_STATE_EXTENSION_IN_NAME) != 0 {
        if c == '=' {
            dec.state &= ~CHUNK_STATE_EXTENSION_IN_NAME;
            dec.state |= CHUNK_STATE_EXTENSION_EXPECTS_VAL;
        } else if c == ';' {
            dec.state &= ~CHUNK_STATE_EXTENSION_IN_NAME;
            dec.state |= CHUNK_STATE_EXTENSION_EXPECTS_NAME;
        } else if !is_chunk_token_char(c) {
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
        } else if is_chunk_token_char(c) {
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
                dec.state |= CHUNK_STATE_SEEN_BWS;
            }
        } else if (dec.state & CHUNK_STATE_SEEN_BWS) != 0 {
            if c == ';' {
                dec.state &= ~CHUNK_STATE_SEEN_BWS;
                dec.state |= CHUNK_STATE_EXTENSION_EXPECTS_NAME;
            } else if c != ' ' && c != '\t' {
                dec.state = CHUNK_STATE_IS_ERROR;
                return false;
            }
        } else {
            if c == ';' {
                dec.state |= CHUNK_STATE_EXTENSION_EXPECTS_NAME;
            } else if c == ' ' || c == '\t' {
                dec.state |= CHUNK_STATE_SEEN_BWS;
            } else if !is_chunk_token_char(c) {
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
fn feed_chunk_header(
    dec: ChunkFsmDecoder&,
    data: const u8[:],
    offset: i64&,
) -> ChunkFsmStatus {
    while offset < data.len {
        let c = data[offset];
        if (dec.state & CHUNK_STATE_EXTENSION_MODE) == 0 {
            guard feed_chunk_hex_char(dec, c) else {
                return ChunkFsmStatus.Error;
            }
            offset++;
        } else {
            var done = false;
            guard feed_chunk_ext_char(dec, c, done) else {
                return ChunkFsmStatus.Error;
            }
            offset++;
            if done {
                break;
            }
        }
    }

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
inline fn feed_chunk_body_full(
    dec: ChunkFsmDecoder&,
    data: const u8[:],
    offset: i64&,
    size: u64,
) -> ChunkFsmStatus, const u8[:] {
    if size > 2 {
        let chunk_len = (size - 2) as i64;
        if data[offset + chunk_len] != '\r' || data[offset + chunk_len + 1] != '\n' {
            dec.state = CHUNK_STATE_IS_ERROR;
            return ChunkFsmStatus.Error, data[..0];
        }
        let chunk_slice = data[offset..(offset + chunk_len)];
        offset += size as i64;
        dec.state = CHUNK_STATE_IS_CHUNKED;
        dec.ext_bytes = 0;
        return ChunkFsmStatus.YieldChunk, chunk_slice;
    }
    if size == 2 {
        if data[offset] != '\r' || data[offset + 1] != '\n' {
            dec.state = CHUNK_STATE_IS_ERROR;
            return ChunkFsmStatus.Error, data[..0];
        }
        offset += 2;
        dec.state = CHUNK_STATE_IS_CHUNKED;
        dec.ext_bytes = 0;
        return ChunkFsmStatus.NeedMore, data[..0];
    }
    // Split CRLF: previously consumed body and '\r', expecting final '\n'
    if data[offset] != '\n' {
        dec.state = CHUNK_STATE_IS_ERROR;
        return ChunkFsmStatus.Error, data[..0];
    }
    offset += 1;
    dec.state = CHUNK_STATE_IS_CHUNKED;
    dec.ext_bytes = 0;
    return ChunkFsmStatus.NeedMore, data[..0];
}

// Emits partial chunk payload available across TCP boundary (RFC 9112 §7.1).
//
// Example:
//   data = "hel", offset = 0, size = 7, rem_data = 3
//   returns: YieldChunk, chunk = "hel"
inline fn feed_chunk_body_partial(
    dec: ChunkFsmDecoder&,
    data: const u8[:],
    offset: i64&,
    size: u64,
    rem_data: i64,
) -> ChunkFsmStatus, const u8[:] {
    var chunk_slice: const u8[:] = data[..0];
    if size > 2 {
        let max_app_emit = (size - 2) as i64;
        if rem_data > max_app_emit {
            if data[offset + max_app_emit] != '\r' {
                dec.state = CHUNK_STATE_IS_ERROR;
                return ChunkFsmStatus.Error, data[..0];
            }
            chunk_slice = data[offset..(offset + max_app_emit)];
        } else {
            chunk_slice = data[offset..];
        }
    } else if size == 2 {
        // RFC 9112 §7.1 & §2.2: Body already consumed; first byte of split CRLF terminator MUST be CR
        if data[offset] != '\r' {
            dec.state = CHUNK_STATE_IS_ERROR;
            return ChunkFsmStatus.Error, data[..0];
        }
    }

    let consumed_bytes = rem_data as u64;
    dec.state = (dec.state & ~CHUNK_STATE_SIZE_MASK) | (size - consumed_bytes);
    dec.state |= CHUNK_STATE_IS_CHUNKED;
    offset += rem_data;
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
fn feed_chunk_body(
    dec: ChunkFsmDecoder&,
    data: const u8[:],
    offset: i64&,
) -> ChunkFsmStatus, const u8[:] {
    let size = chunk_fsm_size(dec.state);
    let rem_data = data.len - offset;

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
    dec: ChunkFsmDecoder&,
    data: const u8[:],
) -> ChunkFsmStatus, i64, const u8[:] {
    if dec.state == CHUNK_STATE_IS_ERROR {
        return ChunkFsmStatus.Error, 0, data[..0];
    }

    var offset: i64 = 0;
    while offset < data.len {
        // 1. Trailer mode
        if (dec.state & CHUNK_STATE_TRAILER_MODE) != 0 {
            let st = feed_chunk_trailer(dec, data, offset);
            return st, offset, data[..0];
        }

        // 2. Consume chunk hex size and extensions
        if !chunk_fsm_has_size(dec.state) {
            let st = feed_chunk_header(dec, data, offset);
            if st == ChunkFsmStatus.Error {
                return ChunkFsmStatus.Error, offset, data[..0];
            }
            if (dec.state & CHUNK_STATE_TRAILER_MODE) != 0 {
                continue;
            }
            if !chunk_fsm_has_size(dec.state) {
                return ChunkFsmStatus.NeedMore, offset, data[..0];
            }
        }

        // 3. Emit chunk body payload
        let st_body, chunk = feed_chunk_body(dec, data, offset);
        if st_body == ChunkFsmStatus.YieldChunk || st_body == ChunkFsmStatus.Error {
            return st_body, offset, chunk;
        }
    }

    return ChunkFsmStatus.NeedMore, offset, data[..0];
}
