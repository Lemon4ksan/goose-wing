// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// http/headers/chunked_fsm.goose
// Compact 64-bit Single-Register FSM Chunked Transfer Coding Decoder (uWebSockets ChunkedEncoding.h).
// Pure clean-room implementation of uWS bit-packed streaming chunked decoder.
// Encodes all parser sub-states and chunk size in a single u64 register (0 heap allocations).
namespace internal;

import std;
import core from "../..";

const CHUNK_STATE_HAS_SIZE: u64               = 0x8000000000000000;
const CHUNK_STATE_IS_CHUNKED: u64             = 0x4000000000000000;
const CHUNK_STATE_EXTENSION_MODE: u64         = 0x2000000000000000;
const CHUNK_STATE_TRAILER_MODE: u64           = 0x1000000000000000;
const CHUNK_STATE_EXTENSION_EXPECTS_NAME: u64 = 0x0800000000000000;
const CHUNK_STATE_EXTENSION_QUOTED: u64       = 0x0400000000000000;
const CHUNK_STATE_EXTENSION_EXPECTS_LF: u64   = 0x0200000000000000;
const CHUNK_STATE_EXTENSION_IN_NAME: u64      = 0x0100000000000000;

const CHUNK_STATE_SIZE_MASK: u64              = 0x00FFFFFFFFFFFFFF;
const CHUNK_STATE_SIZE_OVERFLOW: u64          = 0x000F000000000000;
const CHUNK_STATE_IS_ERROR: u64               = 0xFFFFFFFFFFFFFFFF;

enum ChunkFsmStatus {
    NeedMore,
    YieldChunk,
    Complete,
    Error,
}

struct ChunkFsmDecoder {
    state: u64 = 0,
}

fn new_chunk_fsm_decoder() -> ChunkFsmDecoder {
    return ChunkFsmDecoder { state: 0 };
}

fn chunk_fsm_reset(dec: ChunkFsmDecoder&) {
    dec.state = 0;
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

// Feeds incoming data into the 64-bit FSM chunked decoder.
// Yields slices of decoded payload without allocating memory.
// Returns (status, bytes_consumed, out_chunk_slice).
fn chunk_fsm_feed(
    dec: ChunkFsmDecoder&,
    data: const u8[:]
) -> ChunkFsmStatus, i64, const u8[:] {
    var offset: i64 = 0;
    while offset < data.len {
        // 1. Trailer mode
        if (dec.state & CHUNK_STATE_TRAILER_MODE) != 0 {
            while offset < data.len {
                let c = data[offset];
                offset++;
                let sub_st = chunk_fsm_size(dec.state);
                if sub_st == 0 {
                    if c == '\r' {
                        dec.state = (dec.state & ~CHUNK_STATE_SIZE_MASK) | 1;
                    } else if c == '\n' {
                        dec.state = CHUNK_STATE_IS_ERROR;
                        return ChunkFsmStatus.Error, offset, data[..0];
                    } else {
                        dec.state = (dec.state & ~CHUNK_STATE_SIZE_MASK) | 2;
                    }
                } else if sub_st == 1 {
                    if c == '\n' {
                        dec.state = 0;
                        return ChunkFsmStatus.Complete, offset, data[..0];
                    }
                    dec.state = CHUNK_STATE_IS_ERROR;
                    return ChunkFsmStatus.Error, offset, data[..0];
                } else if sub_st == 2 {
                    if c == '\r' {
                        dec.state = (dec.state & ~CHUNK_STATE_SIZE_MASK) | 3;
                    } else if c == '\n' {
                        dec.state = CHUNK_STATE_IS_ERROR;
                        return ChunkFsmStatus.Error, offset, data[..0];
                    }
                } else if sub_st == 3 {
                    if c == '\n' {
                        dec.state = (dec.state & ~CHUNK_STATE_SIZE_MASK) | 0;
                    } else if c != '\r' {
                        dec.state = (dec.state & ~CHUNK_STATE_SIZE_MASK) | 2;
                    }
                }
            }
            return ChunkFsmStatus.NeedMore, offset, data[..0];
        }

        // 2. Consume chunk hex size and extensions
        if !chunk_fsm_has_size(dec.state) {
            while offset < data.len {
                let c = data[offset];

                if (dec.state & CHUNK_STATE_EXTENSION_MODE) == 0 {
                    if c == ';' {
                        if !chunk_fsm_has_size(dec.state) && chunk_fsm_size(dec.state) == 0 && (dec.state & CHUNK_STATE_IS_CHUNKED) == 0 {
                            dec.state = CHUNK_STATE_IS_ERROR;
                            return ChunkFsmStatus.Error, offset, data[..0];
                        }
                        dec.state |= CHUNK_STATE_EXTENSION_MODE | CHUNK_STATE_EXTENSION_EXPECTS_NAME;
                        offset++;
                        continue;
                    }

                    if c == '\r' {
                        dec.state |= CHUNK_STATE_EXTENSION_MODE | CHUNK_STATE_EXTENSION_EXPECTS_LF;
                        offset++;
                        continue;
                    }

                    if c == '\n' {
                        offset++;
                        dec.state += 2; // +2 for trailing CRLF after chunk data
                        dec.state |= CHUNK_STATE_HAS_SIZE | CHUNK_STATE_IS_CHUNKED;
                        dec.state &= ~(CHUNK_STATE_EXTENSION_MODE | CHUNK_STATE_EXTENSION_EXPECTS_NAME | CHUNK_STATE_EXTENSION_IN_NAME | CHUNK_STATE_EXTENSION_QUOTED | CHUNK_STATE_EXTENSION_EXPECTS_LF);
                        break;
                    }

                    var num: u64 = 0;
                    if c >= '0' && c <= '9' {
                        num = (c - '0');
                    } else if c >= 'a' && c <= 'f' {
                        num = (c - 'a' + 10);
                    } else if c >= 'A' && c <= 'F' {
                        num = (c - 'A' + 10);
                    } else {
                        dec.state = CHUNK_STATE_IS_ERROR;
                        return ChunkFsmStatus.Error, offset, data[..0];
                    }

                    if (chunk_fsm_size(dec.state) & CHUNK_STATE_SIZE_OVERFLOW) != 0 {
                        dec.state = CHUNK_STATE_IS_ERROR;
                        return ChunkFsmStatus.Error, offset, data[..0];
                    }

                    let bits = dec.state & CHUNK_STATE_IS_CHUNKED;
                    dec.state = (dec.state & CHUNK_STATE_SIZE_MASK) * 16 + num;
                    dec.state |= bits;
                    offset++;
                } else {
                    if (dec.state & CHUNK_STATE_EXTENSION_EXPECTS_LF) != 0 {
                        if c != '\n' {
                            dec.state = CHUNK_STATE_IS_ERROR;
                            return ChunkFsmStatus.Error, offset, data[..0];
                        }
                        offset++;
                        dec.state += 2;
                        dec.state |= CHUNK_STATE_HAS_SIZE | CHUNK_STATE_IS_CHUNKED;
                        dec.state &= ~(CHUNK_STATE_EXTENSION_MODE | CHUNK_STATE_EXTENSION_EXPECTS_NAME | CHUNK_STATE_EXTENSION_IN_NAME | CHUNK_STATE_EXTENSION_QUOTED | CHUNK_STATE_EXTENSION_EXPECTS_LF);
                        break;
                    }

                    if c == 0x00 || (c < 0x20 && c != '\r' && c != '\n' && c != '\t') {
                        dec.state = CHUNK_STATE_IS_ERROR;
                        return ChunkFsmStatus.Error, offset, data[..0];
                    }

                    if c == '\r' {
                        if (dec.state & CHUNK_STATE_EXTENSION_EXPECTS_NAME) != 0 {
                            dec.state = CHUNK_STATE_IS_ERROR;
                            return ChunkFsmStatus.Error, offset, data[..0];
                        }
                        dec.state |= CHUNK_STATE_EXTENSION_EXPECTS_LF;
                        offset++;
                        continue;
                    }

                    if (dec.state & CHUNK_STATE_EXTENSION_EXPECTS_NAME) != 0 {
                        if !is_chunk_token_char(c) {
                            dec.state = CHUNK_STATE_IS_ERROR;
                            return ChunkFsmStatus.Error, offset, data[..0];
                        }
                        dec.state &= ~CHUNK_STATE_EXTENSION_EXPECTS_NAME;
                        dec.state |= CHUNK_STATE_EXTENSION_IN_NAME;
                    } else if (dec.state & CHUNK_STATE_EXTENSION_IN_NAME) != 0 {
                        if c == '=' {
                            dec.state &= ~CHUNK_STATE_EXTENSION_IN_NAME;
                        } else if c == ';' {
                            dec.state &= ~CHUNK_STATE_EXTENSION_IN_NAME;
                            dec.state |= CHUNK_STATE_EXTENSION_EXPECTS_NAME;
                        } else if !is_chunk_token_char(c) {
                            dec.state = CHUNK_STATE_IS_ERROR;
                            return ChunkFsmStatus.Error, offset, data[..0];
                        }
                    } else {
                        if c == '"' {
                            dec.state ^= CHUNK_STATE_EXTENSION_QUOTED;
                        }
                        if c == ';' && (dec.state & CHUNK_STATE_EXTENSION_QUOTED) == 0 {
                            dec.state |= CHUNK_STATE_EXTENSION_EXPECTS_NAME;
                        }
                    }

                    offset++;
                    if c == '\n' && (dec.state & CHUNK_STATE_EXTENSION_QUOTED) == 0 {
                        if (dec.state & CHUNK_STATE_EXTENSION_EXPECTS_NAME) != 0 {
                            dec.state = CHUNK_STATE_IS_ERROR;
                            return ChunkFsmStatus.Error, offset, data[..0];
                        }
                        dec.state += 2;
                        dec.state |= CHUNK_STATE_HAS_SIZE | CHUNK_STATE_IS_CHUNKED;
                        dec.state &= ~(CHUNK_STATE_EXTENSION_MODE | CHUNK_STATE_EXTENSION_EXPECTS_NAME | CHUNK_STATE_EXTENSION_IN_NAME | CHUNK_STATE_EXTENSION_QUOTED | CHUNK_STATE_EXTENSION_EXPECTS_LF);
                        break;
                    }
                }
            }

            if dec.state == CHUNK_STATE_IS_ERROR {
                return ChunkFsmStatus.Error, offset, data[..0];
            }

            // If we parsed final chunk size 0 (stored as size 2 due to +2 CRLF)
            if chunk_fsm_has_size(dec.state) && chunk_fsm_size(dec.state) == 2 {
                dec.state = CHUNK_STATE_TRAILER_MODE | 0;
                continue;
            }

            if !chunk_fsm_has_size(dec.state) {
                return ChunkFsmStatus.NeedMore, offset, data[..0];
            }
        }

        // 3. Emit chunk body payload
        let size = chunk_fsm_size(dec.state);
        let rem_data = data.len - offset;

        if (rem_data as u64) >= size {
            // Full chunk and trailing CRLF is in the buffer
            if size > 2 {
                let chunk_len = (size - 2) as i64;
                if data[offset + chunk_len] != '\r' || data[offset + chunk_len + 1] != '\n' {
                    dec.state = CHUNK_STATE_IS_ERROR;
                    return ChunkFsmStatus.Error, offset, data[..0];
                }
                let chunk_slice = data[offset .. (offset + chunk_len)];
                offset += size as i64;
                dec.state = CHUNK_STATE_IS_CHUNKED;
                return ChunkFsmStatus.YieldChunk, offset, chunk_slice;
            } else if size == 2 {
                if data[offset] != '\r' || data[offset + 1] != '\n' {
                    dec.state = CHUNK_STATE_IS_ERROR;
                    return ChunkFsmStatus.Error, offset, data[..0];
                }
                offset += 2;
                dec.state = CHUNK_STATE_IS_CHUNKED;
                continue;
            }
        } else {
            // Partial chunk payload available across TCP boundary
            var chunk_slice: const u8[:] = data[..0];
            if size > 2 {
                let max_app_emit = (size - 2) as i64;
                if rem_data > max_app_emit {
                    if data[offset + max_app_emit] != '\r' {
                        dec.state = CHUNK_STATE_IS_ERROR;
                        return ChunkFsmStatus.Error, offset, data[..0];
                    }
                    chunk_slice = data[offset .. (offset + max_app_emit)];
                } else {
                    chunk_slice = data[offset..];
                }
            }

            let consumed_bytes = rem_data as u64;
            dec.state = (dec.state & ~CHUNK_STATE_SIZE_MASK) | (size - consumed_bytes);
            dec.state |= CHUNK_STATE_IS_CHUNKED;
            offset += rem_data;
            if chunk_slice.len > 0 {
                return ChunkFsmStatus.YieldChunk, offset, chunk_slice;
            }
            return ChunkFsmStatus.NeedMore, offset, data[..0];
        }
    }

    return ChunkFsmStatus.NeedMore, offset, data[..0];
}
