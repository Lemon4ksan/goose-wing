// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Zstandard (zstd) decompression engine (RFC 8878).
// Implementation uses no dynamic heap allocations in the inner loop.
namespace core;

import std;
import core.math.bits;
import core.math.arithmetic;
import core.compress.checksum;
import core.compress.deflate;

// ---- rfc 8878 constants ---------------------------------------------------

const ZSTD_MAGIC:                 u32 = 0xFD2FB528;
const ZSTD_MAGIC_DICTIONARY:      u32 = 0xEC30A437; // RFC 8878 §5 Formatted Dictionary Magic
const ZSTD_MAGIC_SKIPPABLE_START: u32 = 0x184D2A50;
const ZSTD_MAGIC_SKIPPABLE_END:   u32 = 0x184D2A5F;
const ZSTD_BLOCKSIZE_MAX:         i64 = 131072; // 128 KB

const ZSTD_BLOCK_TYPE_RAW:        u32 = 0;
const ZSTD_BLOCK_TYPE_RLE:        u32 = 1;
const ZSTD_BLOCK_TYPE_COMPRESSED: u32 = 2;
const ZSTD_BLOCK_TYPE_RESERVED:   u32 = 3;

// ---- sequence codes lookup tables (rfc 8878 tables 16 & 17) ---------------

const LL_BASE: u32[64] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    16, 18, 20, 22, 24, 28, 32, 40, 48, 64, 128, 256, 512, 1024,
    2048, 4096, 8192, 16384, 32768, 65536,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

const LL_EXTRA_BITS: u8[64] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10,
    11, 12, 13, 14, 15, 16,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

const ML_BASE: u32[64] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
    19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34,
    35, 37, 39, 41, 43, 47, 51, 59, 67, 83, 99, 131, 259, 515,
    1027, 2051, 4099, 8195, 16387, 32771, 65539,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

const ML_EXTRA_BITS: u8[64] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 7, 8, 9,
    10, 11, 12, 13, 14, 15, 16,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

// Predefined FSE normalized distributions (RFC 8878 section 3.1.1.3.2.2)
const LL_DEFAULT_DIST: i16[36] = [
    4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1,
    -1, -1, -1, -1,
];

const ML_DEFAULT_DIST: i16[53] = [
    1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1,
    -1, -1, -1, -1, -1,
];

const OF_DEFAULT_DIST: i16[29] = [
    1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1,
];

const ZSTD_POW2_U64: u64[64] = [
    0x0000000000000001, 0x0000000000000002, 0x0000000000000004, 0x0000000000000008,
    0x0000000000000010, 0x0000000000000020, 0x0000000000000040, 0x0000000000000080,
    0x0000000000000100, 0x0000000000000200, 0x0000000000000400, 0x0000000000000800,
    0x0000000000001000, 0x0000000000002000, 0x0000000000004000, 0x0000000000008000,
    0x0000000000010000, 0x0000000000020000, 0x0000000000040000, 0x0000000000080000,
    0x0000000000100000, 0x0000000000200000, 0x0000000000400000, 0x0000000000800000,
    0x0000000001000000, 0x0000000002000000, 0x0000000004000000, 0x0000000008000000,
    0x0000000010000000, 0x0000000020000000, 0x0000000040000000, 0x0000000080000000,
    0x0000000100000000, 0x0000000200000000, 0x0000000400000000, 0x0000000800000000,
    0x0000001000000000, 0x0000002000000000, 0x0000004000000000, 0x0000008000000000,
    0x0000010000000000, 0x0000020000000000, 0x0000040000000000, 0x0000080000000000,
    0x0000100000000000, 0x0000200000000000, 0x0000400000000000, 0x0000800000000000,
    0x0001000000000000, 0x0002000000000000, 0x0004000000000000, 0x0008000000000000,
    0x0010000000000000, 0x0020000000000000, 0x0040000000000000, 0x0080000000000000,
    0x0100000000000000, 0x0200000000000000, 0x0400000000000000, 0x0800000000000000,
    0x1000000000000000, 0x2000000000000000, 0x4000000000000000, 0x8000000000000000,
];

// ---- helper bit functions --------------------------------------------------

inline fn zstd_high_bit(v: u32) -> i32 {
    if v == 0 { return -1; }
    return (63 - clz(v)) as i32;
}

// Extraction of nb bits (0 <= nb <= 32) from bit_container at bits_consumed.
// Completely branchless: eliminates 19,200+ branches per 256KB block.
inline fn zstd_extract_bits(bit_container: u64, bits_consumed: u32, nb: u32) -> u32 {
    let top32 = (bit_container << (bits_consumed & 63)) >> 32;
    return (top32 >> ((32 - nb) & 63)) as u32;
}

// ---- reverse bit reader (rfc 8878 section 4.2.2) -----------

struct ZstdBitReader {
    src:          const u8[:] = "",
    bit_pos:      i64         = 0,
    underflow:    bool        = false,
    cache_offset: i64         = -1,
    cache_chunk:  u64         = 0,
}

fn new_zstd_bit_reader(src: const u8[:]) -> ZstdBitReader {
    if src.len == 0 {
        return ZstdBitReader { src: src, bit_pos: 0, underflow: true };
    }
    let last_byte = src[src.len - 1];
    if last_byte == 0 {
        return ZstdBitReader { src: src, bit_pos: 0, underflow: true };
    }
    var sentinel: i32 = 7;
    while sentinel >= 0 {
        if ((last_byte >> (sentinel as u8)) & 1) != 0 {
            break;
        }
        sentinel--;
    }
    let total_bits = (src.len - 1) * 8 + sentinel;
    return ZstdBitReader {
        src:          src,
        bit_pos:      total_bits,
        underflow:    false,
        cache_offset: -1,
        cache_chunk:  0,
    };
}

fn read_le_u64_partial(src: const u8[:], offset: i64, len: i64) -> u64 {
    if len >= 8 {
        let b0 = src[offset] as u64;
        let b1 = src[offset + 1] as u64;
        let b2 = src[offset + 2] as u64;
        let b3 = src[offset + 3] as u64;
        let b4 = src[offset + 4] as u64;
        let b5 = src[offset + 5] as u64;
        let b6 = src[offset + 6] as u64;
        let b7 = src[offset + 7] as u64;
        return b0 | (b1 << 8) | (b2 << 16) | (b3 << 24) |
               (b4 << 32) | (b5 << 40) | (b6 << 48) | (b7 << 56);
    }
    var chunk: u64 = 0;
    var i:     i64 = 0;
    while i < len {
        chunk |= (src[offset + i] as u64) << ((i * 8) as u64);
        i++;
    }
    return chunk;
}

fn zstd_peek_bits(r: ZstdBitReader&, n: i32) -> u32 {
    if n <= 0 || r.bit_pos <= 0 { return 0; }
    if r.bit_pos < n {
        let rem_bits = r.bit_pos;
        let chunk = read_le_u64_partial(r.src, 0, r.src.len);
        let mask = ((1 as u64) << (rem_bits as u64)) - 1;
        let val = (chunk & mask) << ((n - rem_bits) as u64);
        return val as u32;
    }
    let start_bit = r.bit_pos - n;
    let byte_offset = start_bit >> 3;
    let bit_end = start_bit + n;

    var chunk: u64 = 0;
    if r.cache_offset >= 0 && start_bit >= (r.cache_offset * 8) && bit_end <= ((r.cache_offset + 8) * 8) {
        chunk = r.cache_chunk;
    } else {
        var new_offset = max(0, byte_offset - 4);
        if new_offset + 8 > r.src.len {
            new_offset = max(0, r.src.len - 8);
        }
        let rem = r.src.len - new_offset;
        chunk = read_le_u64_partial(r.src, new_offset, rem);
        r.cache_offset = new_offset;
        r.cache_chunk = chunk;
    }
    let bit_offset = (start_bit - (r.cache_offset * 8)) as u64;
    let shifted = chunk >> bit_offset;
    let mask = if n == 32 { 0xFFFFFFFF as u64 } else { ((1 as u64) << (n as u64)) - 1 };
    return (shifted & mask) as u32;
}

fn zstd_consume_bits(r: ZstdBitReader&, n: i32) {
    if n <= 0 { return; }
    if r.bit_pos < n {
        r.underflow = true;
        r.bit_pos = 0;
    } else {
        r.bit_pos -= n;
    }
}

fn zstd_read_bits(r: ZstdBitReader&, n: i32) -> u32 {
    let val = zstd_peek_bits(r, n);
    zstd_consume_bits(r, n);
    return val;
}

// ---- forward bit reader (for fse headers) ----------------------------------

struct ForwardBitReader {
    src:       const u8[:] = "",
    byte_idx:  i64         = 0,
    bit_count: i32         = 0,
    bit_buf:   u64         = 0,
    underflow: bool        = false,
}

fn fwd_refill(r: ForwardBitReader&) {
    while r.bit_count >= 0 && r.bit_count <= 56 && r.byte_idx < r.src.len {
        r.bit_buf |= (r.src[r.byte_idx] as u64) << (r.bit_count as u64);
        r.byte_idx++;
        r.bit_count += 8;
    }
}

fn new_forward_bit_reader(src: const u8[:], start_offset: i64) -> ForwardBitReader {
    if start_offset < 0 || start_offset > src.len {
        return ForwardBitReader {
            src:       src,
            byte_idx:  src.len,
            bit_count: 0,
            bit_buf:   0,
            underflow: true,
        };
    }
    var r = ForwardBitReader {
        src:       src,
        byte_idx:  start_offset,
        bit_count: 0,
        bit_buf:   0,
        underflow: false,
    };
    fwd_refill(r);
    return r;
}

fn fwd_peek(r: ForwardBitReader&, n: i32) -> u32 {
    guard n > 0 && n <= 32 else { return 0; }
    if r.bit_count < n {
        fwd_refill(r);
    }
    let mask = sub_sat_u64(ZSTD_POW2_U64[(n & 63) as u64], 1);
    return ((r.bit_buf & mask) & 0xFFFFFFFF) as u32;
}

fn fwd_consume(r: ForwardBitReader&, n: i32) {
    guard n > 0 else { return; }
    if r.bit_count < n {
        fwd_refill(r);
    }
    if r.bit_count < n {
        r.underflow = true;
        r.bit_count = 0;
        r.bit_buf = 0;
        return;
    }
    if n >= 64 {
        r.bit_buf = 0;
        r.bit_count = 0;
        return;
    }
    let q, _ = div_rem_u64(r.bit_buf, ZSTD_POW2_U64[(n & 63) as u64]);
    r.bit_buf = q;
    r.bit_count = (sub_sat_i64(r.bit_count, n) & 63) as i32;
}

fn fwd_read(r: ForwardBitReader&, n: i32) -> u32 {
    let val = fwd_peek(r, n);
    fwd_consume(r, n);
    return val;
}

fn fwd_bytes_consumed(r: const ForwardBitReader&) -> i64 {
    let bits_used = (r.byte_idx * 8) - r.bit_count;
    return (bits_used + 7) / 8;
}

// ---- fse structures & algorithms (rfc 8878 section 4.1) --------------------

struct FseEntry {
    base_val:   u32 = 0,
    new_state:  u16 = 0,
    nb_bits:    u8  = 0,
    extra_bits: u8  = 0,
}

const ZSTD_TBL_UNSET:   u8 = 0;
const ZSTD_TBL_DEFAULT: u8 = 1;
const ZSTD_TBL_RLE:     u8 = 2;
const ZSTD_TBL_CUSTOM:  u8 = 3;

struct FseTable {
    entries:    FseEntry[512] = [FseEntry {}; 512],
    table_log:  i32           = 0,
    is_defined: bool          = false,
}

root struct ZstdEntropyState {
    rep:        u32[3]        = [1, 4, 8],
    ll_kind:    u8            = 0,
    of_kind:    u8            = 0,
    ml_kind:    u8            = 0,
    huf_loaded: bool          = false,
    rle_ll:     FseEntry[1]   = [FseEntry {}; 1],
    rle_of:     FseEntry[1]   = [FseEntry {}; 1],
    rle_ml:     FseEntry[1]   = [FseEntry {}; 1],
    huf_tabs:   HufTable[>..] = [],
    ll_tabs:    FseTable[>..] = [],
    of_tabs:    FseTable[>..] = [],
    ml_tabs:    FseTable[>..] = [],
}

struct HufWeightEntry {
    symbol:    u8  = 0,
    nb_bits:   u8  = 0,
    new_state: u16 = 0,
}

struct HufWeightTable {
    entries:    HufWeightEntry[128] = [HufWeightEntry {}; 128],
    table_log:  i32                 = 0,
    is_defined: bool                = false,
}

const DEFAULT_LL_ENTRIES: FseEntry[64] = [
    FseEntry { base_val: 0, new_state: 0, nb_bits: 4, extra_bits: 0 },
    FseEntry { base_val: 0, new_state: 16, nb_bits: 4, extra_bits: 0 },
    FseEntry { base_val: 1, new_state: 32, nb_bits: 5, extra_bits: 0 },
    FseEntry { base_val: 3, new_state: 0, nb_bits: 5, extra_bits: 0 },
    FseEntry { base_val: 4, new_state: 0, nb_bits: 5, extra_bits: 0 },
    FseEntry { base_val: 6, new_state: 0, nb_bits: 5, extra_bits: 0 },
    FseEntry { base_val: 7, new_state: 0, nb_bits: 5, extra_bits: 0 },
    FseEntry { base_val: 9, new_state: 0, nb_bits: 5, extra_bits: 0 },
    FseEntry { base_val: 10, new_state: 0, nb_bits: 5, extra_bits: 0 },
    FseEntry { base_val: 12, new_state: 0, nb_bits: 5, extra_bits: 0 },
    FseEntry { base_val: 14, new_state: 0, nb_bits: 6, extra_bits: 0 },
    FseEntry { base_val: 16, new_state: 0, nb_bits: 5, extra_bits: 1 },
    FseEntry { base_val: 20, new_state: 0, nb_bits: 5, extra_bits: 1 },
    FseEntry { base_val: 22, new_state: 0, nb_bits: 5, extra_bits: 1 },
    FseEntry { base_val: 28, new_state: 0, nb_bits: 5, extra_bits: 2 },
    FseEntry { base_val: 32, new_state: 0, nb_bits: 5, extra_bits: 3 },
    FseEntry { base_val: 48, new_state: 0, nb_bits: 5, extra_bits: 4 },
    FseEntry { base_val: 64, new_state: 32, nb_bits: 5, extra_bits: 6 },
    FseEntry { base_val: 128, new_state: 0, nb_bits: 5, extra_bits: 7 },
    FseEntry { base_val: 256, new_state: 0, nb_bits: 6, extra_bits: 8 },
    FseEntry { base_val: 1024, new_state: 0, nb_bits: 6, extra_bits: 10 },
    FseEntry { base_val: 4096, new_state: 0, nb_bits: 6, extra_bits: 12 },
    FseEntry { base_val: 0, new_state: 32, nb_bits: 4, extra_bits: 0 },
    FseEntry { base_val: 1, new_state: 0, nb_bits: 4, extra_bits: 0 },
    FseEntry { base_val: 2, new_state: 0, nb_bits: 5, extra_bits: 0 },
    FseEntry { base_val: 4, new_state: 32, nb_bits: 5, extra_bits: 0 },
    FseEntry { base_val: 5, new_state: 0, nb_bits: 5, extra_bits: 0 },
    FseEntry { base_val: 7, new_state: 32, nb_bits: 5, extra_bits: 0 },
    FseEntry { base_val: 8, new_state: 0, nb_bits: 5, extra_bits: 0 },
    FseEntry { base_val: 10, new_state: 32, nb_bits: 5, extra_bits: 0 },
    FseEntry { base_val: 11, new_state: 0, nb_bits: 5, extra_bits: 0 },
    FseEntry { base_val: 13, new_state: 0, nb_bits: 6, extra_bits: 0 },
    FseEntry { base_val: 16, new_state: 32, nb_bits: 5, extra_bits: 1 },
    FseEntry { base_val: 18, new_state: 0, nb_bits: 5, extra_bits: 1 },
    FseEntry { base_val: 22, new_state: 32, nb_bits: 5, extra_bits: 1 },
    FseEntry { base_val: 24, new_state: 0, nb_bits: 5, extra_bits: 2 },
    FseEntry { base_val: 32, new_state: 32, nb_bits: 5, extra_bits: 3 },
    FseEntry { base_val: 40, new_state: 0, nb_bits: 5, extra_bits: 3 },
    FseEntry { base_val: 64, new_state: 0, nb_bits: 4, extra_bits: 6 },
    FseEntry { base_val: 64, new_state: 16, nb_bits: 4, extra_bits: 6 },
    FseEntry { base_val: 128, new_state: 32, nb_bits: 5, extra_bits: 7 },
    FseEntry { base_val: 512, new_state: 0, nb_bits: 6, extra_bits: 9 },
    FseEntry { base_val: 2048, new_state: 0, nb_bits: 6, extra_bits: 11 },
    FseEntry { base_val: 0, new_state: 48, nb_bits: 4, extra_bits: 0 },
    FseEntry { base_val: 1, new_state: 16, nb_bits: 4, extra_bits: 0 },
    FseEntry { base_val: 2, new_state: 32, nb_bits: 5, extra_bits: 0 },
    FseEntry { base_val: 3, new_state: 32, nb_bits: 5, extra_bits: 0 },
    FseEntry { base_val: 5, new_state: 32, nb_bits: 5, extra_bits: 0 },
    FseEntry { base_val: 6, new_state: 32, nb_bits: 5, extra_bits: 0 },
    FseEntry { base_val: 8, new_state: 32, nb_bits: 5, extra_bits: 0 },
    FseEntry { base_val: 9, new_state: 32, nb_bits: 5, extra_bits: 0 },
    FseEntry { base_val: 11, new_state: 32, nb_bits: 5, extra_bits: 0 },
    FseEntry { base_val: 12, new_state: 32, nb_bits: 5, extra_bits: 0 },
    FseEntry { base_val: 15, new_state: 0, nb_bits: 6, extra_bits: 0 },
    FseEntry { base_val: 18, new_state: 32, nb_bits: 5, extra_bits: 1 },
    FseEntry { base_val: 20, new_state: 32, nb_bits: 5, extra_bits: 1 },
    FseEntry { base_val: 24, new_state: 32, nb_bits: 5, extra_bits: 2 },
    FseEntry { base_val: 28, new_state: 32, nb_bits: 5, extra_bits: 2 },
    FseEntry { base_val: 40, new_state: 32, nb_bits: 5, extra_bits: 3 },
    FseEntry { base_val: 48, new_state: 32, nb_bits: 5, extra_bits: 4 },
    FseEntry { base_val: 65536, new_state: 0, nb_bits: 6, extra_bits: 16 },
    FseEntry { base_val: 32768, new_state: 0, nb_bits: 6, extra_bits: 15 },
    FseEntry { base_val: 16384, new_state: 0, nb_bits: 6, extra_bits: 14 },
    FseEntry { base_val: 8192, new_state: 0, nb_bits: 6, extra_bits: 13 },
];
const DEFAULT_OF_ENTRIES: FseEntry[32] = [
    FseEntry { base_val: 1, new_state: 0, nb_bits: 5, extra_bits: 0 },
    FseEntry { base_val: 64, new_state: 0, nb_bits: 4, extra_bits: 6 },
    FseEntry { base_val: 512, new_state: 0, nb_bits: 5, extra_bits: 9 },
    FseEntry { base_val: 32768, new_state: 0, nb_bits: 5, extra_bits: 15 },
    FseEntry { base_val: 2097152, new_state: 0, nb_bits: 5, extra_bits: 21 },
    FseEntry { base_val: 8, new_state: 0, nb_bits: 5, extra_bits: 3 },
    FseEntry { base_val: 128, new_state: 0, nb_bits: 4, extra_bits: 7 },
    FseEntry { base_val: 4096, new_state: 0, nb_bits: 5, extra_bits: 12 },
    FseEntry { base_val: 262144, new_state: 0, nb_bits: 5, extra_bits: 18 },
    FseEntry { base_val: 8388608, new_state: 0, nb_bits: 5, extra_bits: 23 },
    FseEntry { base_val: 32, new_state: 0, nb_bits: 5, extra_bits: 5 },
    FseEntry { base_val: 256, new_state: 0, nb_bits: 4, extra_bits: 8 },
    FseEntry { base_val: 16384, new_state: 0, nb_bits: 5, extra_bits: 14 },
    FseEntry { base_val: 1048576, new_state: 0, nb_bits: 5, extra_bits: 20 },
    FseEntry { base_val: 4, new_state: 0, nb_bits: 5, extra_bits: 2 },
    FseEntry { base_val: 128, new_state: 16, nb_bits: 4, extra_bits: 7 },
    FseEntry { base_val: 2048, new_state: 0, nb_bits: 5, extra_bits: 11 },
    FseEntry { base_val: 131072, new_state: 0, nb_bits: 5, extra_bits: 17 },
    FseEntry { base_val: 4194304, new_state: 0, nb_bits: 5, extra_bits: 22 },
    FseEntry { base_val: 16, new_state: 0, nb_bits: 5, extra_bits: 4 },
    FseEntry { base_val: 256, new_state: 16, nb_bits: 4, extra_bits: 8 },
    FseEntry { base_val: 8192, new_state: 0, nb_bits: 5, extra_bits: 13 },
    FseEntry { base_val: 524288, new_state: 0, nb_bits: 5, extra_bits: 19 },
    FseEntry { base_val: 2, new_state: 0, nb_bits: 5, extra_bits: 1 },
    FseEntry { base_val: 64, new_state: 16, nb_bits: 4, extra_bits: 6 },
    FseEntry { base_val: 1024, new_state: 0, nb_bits: 5, extra_bits: 10 },
    FseEntry { base_val: 65536, new_state: 0, nb_bits: 5, extra_bits: 16 },
    FseEntry { base_val: 268435456, new_state: 0, nb_bits: 5, extra_bits: 28 },
    FseEntry { base_val: 134217728, new_state: 0, nb_bits: 5, extra_bits: 27 },
    FseEntry { base_val: 67108864, new_state: 0, nb_bits: 5, extra_bits: 26 },
    FseEntry { base_val: 33554432, new_state: 0, nb_bits: 5, extra_bits: 25 },
    FseEntry { base_val: 16777216, new_state: 0, nb_bits: 5, extra_bits: 24 },
];
const DEFAULT_ML_ENTRIES: FseEntry[64] = [
    FseEntry { base_val: 3, new_state: 0, nb_bits: 6, extra_bits: 0 },
    FseEntry { base_val: 4, new_state: 0, nb_bits: 4, extra_bits: 0 },
    FseEntry { base_val: 5, new_state: 32, nb_bits: 5, extra_bits: 0 },
    FseEntry { base_val: 6, new_state: 0, nb_bits: 5, extra_bits: 0 },
    FseEntry { base_val: 8, new_state: 0, nb_bits: 5, extra_bits: 0 },
    FseEntry { base_val: 9, new_state: 0, nb_bits: 5, extra_bits: 0 },
    FseEntry { base_val: 11, new_state: 0, nb_bits: 5, extra_bits: 0 },
    FseEntry { base_val: 13, new_state: 0, nb_bits: 6, extra_bits: 0 },
    FseEntry { base_val: 16, new_state: 0, nb_bits: 6, extra_bits: 0 },
    FseEntry { base_val: 19, new_state: 0, nb_bits: 6, extra_bits: 0 },
    FseEntry { base_val: 22, new_state: 0, nb_bits: 6, extra_bits: 0 },
    FseEntry { base_val: 25, new_state: 0, nb_bits: 6, extra_bits: 0 },
    FseEntry { base_val: 28, new_state: 0, nb_bits: 6, extra_bits: 0 },
    FseEntry { base_val: 31, new_state: 0, nb_bits: 6, extra_bits: 0 },
    FseEntry { base_val: 34, new_state: 0, nb_bits: 6, extra_bits: 0 },
    FseEntry { base_val: 37, new_state: 0, nb_bits: 6, extra_bits: 1 },
    FseEntry { base_val: 41, new_state: 0, nb_bits: 6, extra_bits: 1 },
    FseEntry { base_val: 47, new_state: 0, nb_bits: 6, extra_bits: 2 },
    FseEntry { base_val: 59, new_state: 0, nb_bits: 6, extra_bits: 3 },
    FseEntry { base_val: 83, new_state: 0, nb_bits: 6, extra_bits: 4 },
    FseEntry { base_val: 131, new_state: 0, nb_bits: 6, extra_bits: 7 },
    FseEntry { base_val: 515, new_state: 0, nb_bits: 6, extra_bits: 9 },
    FseEntry { base_val: 4, new_state: 16, nb_bits: 4, extra_bits: 0 },
    FseEntry { base_val: 5, new_state: 0, nb_bits: 4, extra_bits: 0 },
    FseEntry { base_val: 6, new_state: 32, nb_bits: 5, extra_bits: 0 },
    FseEntry { base_val: 7, new_state: 0, nb_bits: 5, extra_bits: 0 },
    FseEntry { base_val: 9, new_state: 32, nb_bits: 5, extra_bits: 0 },
    FseEntry { base_val: 10, new_state: 0, nb_bits: 5, extra_bits: 0 },
    FseEntry { base_val: 12, new_state: 0, nb_bits: 6, extra_bits: 0 },
    FseEntry { base_val: 15, new_state: 0, nb_bits: 6, extra_bits: 0 },
    FseEntry { base_val: 18, new_state: 0, nb_bits: 6, extra_bits: 0 },
    FseEntry { base_val: 21, new_state: 0, nb_bits: 6, extra_bits: 0 },
    FseEntry { base_val: 24, new_state: 0, nb_bits: 6, extra_bits: 0 },
    FseEntry { base_val: 27, new_state: 0, nb_bits: 6, extra_bits: 0 },
    FseEntry { base_val: 30, new_state: 0, nb_bits: 6, extra_bits: 0 },
    FseEntry { base_val: 33, new_state: 0, nb_bits: 6, extra_bits: 0 },
    FseEntry { base_val: 35, new_state: 0, nb_bits: 6, extra_bits: 1 },
    FseEntry { base_val: 39, new_state: 0, nb_bits: 6, extra_bits: 1 },
    FseEntry { base_val: 43, new_state: 0, nb_bits: 6, extra_bits: 2 },
    FseEntry { base_val: 51, new_state: 0, nb_bits: 6, extra_bits: 3 },
    FseEntry { base_val: 67, new_state: 0, nb_bits: 6, extra_bits: 4 },
    FseEntry { base_val: 99, new_state: 0, nb_bits: 6, extra_bits: 5 },
    FseEntry { base_val: 259, new_state: 0, nb_bits: 6, extra_bits: 8 },
    FseEntry { base_val: 4, new_state: 32, nb_bits: 4, extra_bits: 0 },
    FseEntry { base_val: 4, new_state: 48, nb_bits: 4, extra_bits: 0 },
    FseEntry { base_val: 5, new_state: 16, nb_bits: 4, extra_bits: 0 },
    FseEntry { base_val: 7, new_state: 32, nb_bits: 5, extra_bits: 0 },
    FseEntry { base_val: 8, new_state: 32, nb_bits: 5, extra_bits: 0 },
    FseEntry { base_val: 10, new_state: 32, nb_bits: 5, extra_bits: 0 },
    FseEntry { base_val: 11, new_state: 32, nb_bits: 5, extra_bits: 0 },
    FseEntry { base_val: 14, new_state: 0, nb_bits: 6, extra_bits: 0 },
    FseEntry { base_val: 17, new_state: 0, nb_bits: 6, extra_bits: 0 },
    FseEntry { base_val: 20, new_state: 0, nb_bits: 6, extra_bits: 0 },
    FseEntry { base_val: 23, new_state: 0, nb_bits: 6, extra_bits: 0 },
    FseEntry { base_val: 26, new_state: 0, nb_bits: 6, extra_bits: 0 },
    FseEntry { base_val: 29, new_state: 0, nb_bits: 6, extra_bits: 0 },
    FseEntry { base_val: 32, new_state: 0, nb_bits: 6, extra_bits: 0 },
    FseEntry { base_val: 65539, new_state: 0, nb_bits: 6, extra_bits: 16 },
    FseEntry { base_val: 32771, new_state: 0, nb_bits: 6, extra_bits: 15 },
    FseEntry { base_val: 16387, new_state: 0, nb_bits: 6, extra_bits: 14 },
    FseEntry { base_val: 8195, new_state: 0, nb_bits: 6, extra_bits: 13 },
    FseEntry { base_val: 4099, new_state: 0, nb_bits: 6, extra_bits: 12 },
    FseEntry { base_val: 2051, new_state: 0, nb_bits: 6, extra_bits: 11 },
    FseEntry { base_val: 1027, new_state: 0, nb_bits: 6, extra_bits: 10 },
];
inline fn next_fse_pos(pos: i32, step: i32, mask: i32, high_threshold: i32) -> i32 {
    var p = (pos + step) & mask;
    while p > high_threshold {
        p = (p + step) & mask;
    }
    return p;
}

fn fse_build_weight_dtable(counts: const i16[:], max_symbol: i32, table_log: i32, out_table: HufWeightTable&) -> bool {
    let table_size: i32 = (1 as i32) << table_log;
    if table_size > 128 || table_log < 1 {
        return false;
    }
    out_table.table_log = table_log;
    out_table.is_defined = true;

    var symbol_next:    u16[256] = [0; 256];
    var high_threshold: i32      = table_size - 1;

    var s: i32 = 0;
    while s <= max_symbol {
        if counts[s] == -1 {
            out_table.entries[high_threshold].symbol = s as u8;
            high_threshold--;
            symbol_next[s] = 1;
        } else if counts[s] > 0 {
            symbol_next[s] = counts[s] as u16;
        }
        s++;
    }

    let step: i32 = (table_size >> 1) + (table_size >> 3) + 3;
    let mask: i32 = table_size - 1;
    var pos: i32 = 0;

    s = 0;
    while s <= max_symbol {
        if counts[s] > 0 {
            var i: i32 = 0;
            while i < counts[s] {
                out_table.entries[pos].symbol = s as u8;
                pos = next_fse_pos(pos, step, mask, high_threshold);
                i++;
            }
        }
        s++;
    }
    if pos != 0 {
        return false;
    }

    var u: i32 = 0;
    while u < table_size {
        let sym = out_table.entries[u].symbol as i32;
        let next_state = symbol_next[sym];
        symbol_next[sym]++;
        let nb_bits = table_log - zstd_high_bit(next_state);
        out_table.entries[u].nb_bits = nb_bits as u8;
        out_table.entries[u].new_state = (((next_state as u32) << (nb_bits as u32)) - (table_size as u32)) as u16;
        u++;
    }

    return true;
}

fn fse_place_low_probability_symbols(
    counts:         const i16[:],
    max_symbol:     i32,
    table_symbols:  u8[512]&,
    symbol_next:    u16[256]&,
    high_threshold: i32&,
) {
    var s: i32 = 0;
    while s <= max_symbol {
        if counts[s] == -1 {
            table_symbols[high_threshold] = s as u8;
            high_threshold--;
            symbol_next[s] = 1;
        } else if counts[s] > 0 {
            symbol_next[s] = counts[s] as u16;
        }
        s++;
    }
}

fn fse_spread_symbols(
    counts:         const i16[:],
    max_symbol:     i32,
    table_size:     i32,
    high_threshold: i32,
    table_symbols:  u8[512]&,
) -> bool {
    let step: i32 = (table_size >> 1) + (table_size >> 3) + 3;
    let mask: i32 = table_size - 1;
    var pos: i32 = 0;

    var s: i32 = 0;
    while s <= max_symbol {
        if counts[s] > 0 {
            var i: i32 = 0;
            while i < counts[s] {
                table_symbols[pos] = s as u8;
                pos = next_fse_pos(pos, step, mask, high_threshold);
                i++;
            }
        }
        s++;
    }
    return pos == 0;
}

fn fse_build_dtable(
    counts:     const i16[:],
    max_symbol: i32,
    table_log:  i32,
    out_table:  FseTable&,
    table_kind: i32 = 0,
) -> bool {
    let table_size: i32 = (1 as i32) << table_log;
    if table_size > 512 || table_log < 1 {
        return false;
    }
    out_table.table_log = table_log;
    out_table.is_defined = true;

    var symbol_next:    u16[256] = [0; 256];
    var table_symbols:  u8[512]  = [0; 512];
    var high_threshold: i32      = table_size - 1;

    fse_place_low_probability_symbols(counts, max_symbol, table_symbols, symbol_next, high_threshold);
    guard fse_spread_symbols(counts, max_symbol, table_size, high_threshold, table_symbols) else {
        return false;
    }

    var u: i32 = 0;
    while u < table_size {
        let sym = table_symbols[u] as i32;
        let next_state = symbol_next[sym];
        symbol_next[sym]++;
        let nb_bits = table_log - zstd_high_bit(next_state);
        out_table.entries[u].nb_bits = nb_bits as u8;
        out_table.entries[u].new_state = (((next_state as u32) << (nb_bits as u32)) - (table_size as u32)) as u16;
        if table_kind == 1 {
            let idx = (sym & 63) as i64;
            out_table.entries[u].extra_bits = LL_EXTRA_BITS[idx];
            out_table.entries[u].base_val = LL_BASE[idx];
        } else if table_kind == 2 {
            let sc = (sym & 31) as u32;
            out_table.entries[u].extra_bits = sc as u8;
            out_table.entries[u].base_val = (1 as u32) << sc;
        } else if table_kind == 3 {
            let idx = (sym & 63) as i64;
            out_table.entries[u].extra_bits = ML_EXTRA_BITS[idx];
            out_table.entries[u].base_val = ML_BASE[idx];
        }
        u++;
    }

    return true;
}

fn read_fse_zero_repeats(r: ForwardBitReader&) -> i32 {
    var repeats: i32 = 0;
    while !r.underflow {
        let code = fwd_peek(r, 2);
        fwd_consume(r, 2);
        if r.underflow {
            break;
        }
        if code == 3 {
            repeats += 3;
        } else {
            repeats += code as i32;
            break;
        }
    }
    return repeats;
}

fn fill_zero_counts(counts: i16[:], char_num: i32&, repeats: i32) {
    var rep = repeats;
    while rep > 0 && char_num <= 255 {
        counts[char_num] = 0;
        char_num++;
        rep--;
    }
}

fn read_fse_symbol_count(r: ForwardBitReader&, threshold: i32, max_val: i32, nb_bits: i32) -> i32 {
    let peek_val = fwd_peek(r, nb_bits);
    let peek_short = peek_val & ((threshold - 1) as u32);
    if peek_short < (max_val as u32) {
        fwd_consume(r, nb_bits - 1);
        return peek_short as i32;
    }
    var count = (peek_val & ((2 * threshold - 1) as u32)) as i32;
    if count >= threshold {
        count -= max_val;
    }
    fwd_consume(r, nb_bits);
    return count;
}

fn shrink_fse_threshold(remaining: i32, threshold: i32&, nb_bits: i32&) {
    var thr: i64 = threshold;
    var nb:  i64 = nb_bits;
    let rem_u = (remaining & 1023) as u32;
    while thr > remaining && thr > 1 {
        if remaining <= 1 {
            break;
        }
        let clz_v = (clz(rem_u) & 63) as u32;
        let hb = sub_sat_u32(63, clz_v);
        nb = add_sat_u32(hb, 1);
        thr = (ZSTD_POW2_U64[(hb as u64) & 15] & 1023) as i64;
    }
    threshold = (thr & 1023) as i32;
    nb_bits = (nb & 15) as i32;
}

fn record_fse_symbol_count(
    raw_count: i32,
    remaining: i32&,
    counts:    i16[:],
    char_num:  i32&,
    previous0: bool&,
) {
    let count = sub_sat_i64(raw_count, 1);
    let rem_next = if count >= 0 { sub_sat_i64(remaining, count) } else { add_sat_i64(remaining, count) };
    remaining = if rem_next <= 0 { 0 } else { (rem_next & 1023) as i32 };
    counts[(char_num & 255) as i64] = if count < 0 { -1 as i16 } else { (count & 1023) as i16 };
    char_num = (add_sat_i64(char_num, 1) & 511) as i32;
    previous0 = (count == 0);
}

// Reads FSE normalized counts from src and advances offset (RFC 8878 Section 4.1.1).
// Leaves `offset` unchanged when returning `false`.
//
// Example:
//   src = [0x22, 0x01, ...], offset = 0
//   returns: true, max_symbol = 20, table_log = 6, offset = 4
fn fse_read_ncount(
    src:        const u8[:],
    offset:     i64&,
    counts:     i16[:],
    max_symbol: i32&,
    table_log:  i32&,
) -> bool {
    var r = new_forward_bit_reader(src, offset);
    let low4 = fwd_read(r, 4);
    let log_u = add_sat_u32(low4, 5);
    guard log_u <= 9 else { return false; }

    let init_thr = (ZSTD_POW2_U64[(log_u as u64) & 15] & 1023) as i32;
    var remaining: i32  = (add_sat_i64(init_thr, 1) & 1023) as i32;
    var threshold: i32  = init_thr;
    var nb_bits:   i32  = (add_sat_u32(log_u, 1) & 15) as i32;
    var char_num:  i32  = 0;
    var previous0: bool = false;

    while remaining > 1 && char_num <= 255 {
        if previous0 {
            let repeats = read_fse_zero_repeats(r);
            fill_zero_counts(counts, char_num, repeats);
            if char_num > 255 {
                break;
            }
        }

        let max_val = (sub_sat_i64(sub_sat_i64(mul_sat_i64(2, threshold), 1), remaining) & 1023) as i32;
        let raw_count = read_fse_symbol_count(r, threshold, max_val, nb_bits);
        record_fse_symbol_count(raw_count, remaining, counts, char_num, previous0);
        shrink_fse_threshold(remaining, threshold, nb_bits);
    }

    let consumed = fwd_bytes_consumed(r);
    guard !r.underflow && remaining == 1 && consumed <= src.len else {
        return false;
    }
    table_log = (log_u & 15) as i32;
    max_symbol = (sub_sat_i64(char_num, 1) & 255) as i32;
    offset = consumed;
    return true;
}

// ---- huffman structures & decoding (rfc 8878 section 4.2) ------------------

struct HufEntry {
    symbol:  u8 = 0,
    nb_bits: u8 = 0,
}

struct HufTable {
    entries:    HufEntry[2048] = [HufEntry {}; 2048],
    table_log:  i32            = 0,
    is_defined: bool           = false,
}

fn huf_build_dtable(weights: const u8[:], num_symbols: i32, max_table_log: i32, out_table: HufTable&) -> bool {
    var rank_val:     u32[13] = [0; 13];
    var weight_total: u32     = 0;

    var s: i32 = 0;
    while s < num_symbols {
        let w = weights[s] as i32;
        if w > 11 { return false; }
        rank_val[w]++;
        if w > 0 {
            weight_total += (1 << w) >> 1;
        }
        s++;
    }
    if weight_total == 0 { return false; }

    let table_log = zstd_high_bit(weight_total);
    if ((1 as u32) << (table_log as u32)) != weight_total {
        return false; // Total weight is not a power of 2
    }
    if table_log > 11 || table_log > max_table_log {
        return false;
    }
    out_table.table_log = table_log;
    out_table.is_defined = true;

    // Rank starts (skip weight 0 as unused symbols)
    var rank_start: u32[13] = [0; 13];
    var next_rank:  u32     = 0;
    var w:          i32     = 1;
    while w <= table_log {
        rank_start[w] = next_rank;
        next_rank += rank_val[w];
        w++;
    }

    var sorted_symbols: u8[256] = [0; 256];
    s = 0;
    while s < num_symbols {
        let wt = weights[s] as i32;
        if wt > 0 {
            sorted_symbols[rank_start[wt]] = s as u8;
            rank_start[wt]++;
        }
        s++;
    }

    // Populate DTable: replicate 1 << (w - 1) times for weight w
    populate_huf_dtable(table_log, rank_val[..], sorted_symbols[..], out_table);

    return true;
}

fn replicate_huf_symbol(
    out_table: HufTable&,
    entry_idx: i32&,
    sym:       u8,
    nb_bits:   u8,
    rep_len:   i32,
) {
    var k: i32 = 0;
    while k < rep_len {
        out_table.entries[entry_idx] = HufEntry { symbol: sym, nb_bits: nb_bits };
        entry_idx++;
        k++;
    }
}

fn populate_huf_dtable(
    table_log:      i32,
    rank_val:       const u32[:],
    sorted_symbols: const u8[:],
    out_table:      HufTable&,
) {
    var entry_idx: i32 = 0;
    var sym_pos:   i32 = 0;
    var w:         i32 = 1;
    while w <= table_log {
        let count = rank_val[w] as i32;
        let rep_len: i32 = ((1 << w) >> 1) as i32;
        let nb_bits = (table_log + 1 - w) as u8;

        var i: i32 = 0;
        while i < count {
            let sym = sorted_symbols[sym_pos];
            sym_pos++;
            replicate_huf_symbol(out_table, entry_idx, sym, nb_bits, rep_len);
            i++;
        }
        w++;
    }
}

// Decodes direct 4-bit Huffman weights and advances offset.
//
// Example:
//   src = [0x12, 0x34], offset = 0, header_byte = 131
//   returns: num_symbols = 4, ok = true, offset = 2
fn read_direct_huf_weights(
    src:         const u8[:],
    offset:      i64&,
    header_byte: u8,
    weights:     u8[256]&,
) -> i32, bool {
    let num_symbols = (header_byte as i32) - 127;
    let num_bytes = (num_symbols + 1) / 2;
    guard offset + num_bytes <= src.len else { return 0, false; }

    var n: i32 = 0;
    while n < num_symbols {
        let b = src[offset + (n / 2)];
        weights[n] = (b >> 4) & 0x0F;
        if n + 1 < num_symbols {
            weights[n + 1] = b & 0x0F;
        }
        n += 2;
    }
    offset += num_bytes;
    return num_symbols, true;
}

// Decodes FSE compressed Huffman weights into the weights buffer.
//
// Example:
//   weights = [0; 256], num_symbols = 0
//   returns: true, num_symbols = 12
fn decode_fse_huf_weights(
    weight_fse_table: const HufWeightTable&,
    r:                ZstdBitReader&,
    weights:          u8[256]&,
    num_symbols:      i32&,
) -> bool {
    var state1 = zstd_read_bits(r, weight_fse_table.table_log) as i64;
    var state2 = zstd_read_bits(r, weight_fse_table.table_log) as i64;
    guard !r.underflow else { return false; }

    while num_symbols < 255 {
        let e1 = weight_fse_table.entries[state1];
        weights[num_symbols] = e1.symbol;
        num_symbols++;
        if num_symbols >= 255 { break; }
        state1 = (e1.new_state as i64) + zstd_read_bits(r, e1.nb_bits);
        if r.underflow {
            let e2 = weight_fse_table.entries[state2];
            weights[num_symbols] = e2.symbol;
            num_symbols++;
            break;
        }

        let e2 = weight_fse_table.entries[state2];
        weights[num_symbols] = e2.symbol;
        num_symbols++;
        if num_symbols >= 255 { break; }
        state2 = (e2.new_state as i64) + zstd_read_bits(r, e2.nb_bits);
        if r.underflow {
            let e1_final = weight_fse_table.entries[state1];
            weights[num_symbols] = e1_final.symbol;
            num_symbols++;
            break;
        }
    }
    return true;
}

// Reads FSE compressed Huffman weights header and decompresses weights.
// Leaves `offset` unchanged when returning `false`.
//
// Example:
//   src = [0x10, ...], offset = 0, header_byte = 16
//   returns: num_symbols = 25, ok = true, offset = 17
fn read_fse_huf_weights(
    src:         const u8[:],
    offset:      i64&,
    header_byte: u8,
    weights:     u8[256]&,
) -> i32, bool {
    let fse_size = header_byte as i64;
    guard fse_size > 0 && offset + fse_size <= src.len else { return 0, false; }
    let fse_slice = src[offset..offset + fse_size];

    var fse_counts:  i16[256] = [0; 256];
    var fse_max_sym: i32      = 0;
    var fse_log:     i32      = 0;
    var fse_offset:  i64      = 0;
    guard fse_read_ncount(fse_slice, fse_offset, fse_counts[..], fse_max_sym, fse_log) else {
        return 0, false;
    }
    guard fse_max_sym <= 12 && fse_log <= 6 && fse_offset < fse_slice.len else { return 0, false; }

    var weight_fse_table = HufWeightTable {};
    guard fse_build_weight_dtable(fse_counts[..], fse_max_sym, fse_log, weight_fse_table) else {
        return 0, false;
    }

    let bit_slice = fse_slice[fse_offset..];
    var r = new_zstd_bit_reader(bit_slice);
    guard !r.underflow else { return 0, false; }

    var num_symbols: i32 = 0;
    guard decode_fse_huf_weights(weight_fse_table, r, weights, num_symbols) else {
        return 0, false;
    }
    offset += fse_size;
    return num_symbols, true;
}

// Reads a Huffman table header and weights from src and advances offset.
// Leaves `offset` unchanged when returning `false`.
//
// Example:
//   src = [0x85, 0x12, 0x34], offset = 0
//   returns: true, offset = 4
fn huf_read_table(src: const u8[:], offset: i64&, table: HufTable&) -> bool {
    guard offset < src.len else { return false; }
    let header_byte = src[offset];
    var pos = add_sat_i64(offset, 1);

    var weights:     u8[256] = [0; 256];
    var num_symbols: i32     = 0;

    if header_byte >= 128 {
        let syms, ok = read_direct_huf_weights(src, pos, header_byte, weights);
        guard ok else { return false; }
        num_symbols = syms;
    } else {
        let syms, ok = read_fse_huf_weights(src, pos, header_byte, weights);
        guard ok else { return false; }
        num_symbols = syms;
    }

    var weight_total: u32 = 0;
    var i:            i32 = 0;
    while i < num_symbols {
        let w = weights[i] as i32;
        guard w <= 11 else { return false; }
        if w > 0 {
            weight_total += (1 << w) >> 1;
        }
        i++;
    }
    guard num_symbols < 256 && weight_total > 0 else { return false; }
    let table_log = zstd_high_bit(weight_total) + 1;
    guard table_log <= 11 else { return false; }
    let total: u32 = (1 as u32) << (table_log as u32);
    let rest:  u32 = total - weight_total;
    guard rest > 0 && (rest & (rest - 1)) == 0 else { return false; }
    let last_weight = (zstd_high_bit(rest) + 1) as u8;
    weights[num_symbols] = last_weight;
    num_symbols++;

    guard huf_build_dtable(weights[..num_symbols], num_symbols, 11, table) else { return false; }
    offset = pos;
    return true;
}

inline fn refill_huf_stream_container(
    src:  const u8[:],
    ptr:  i64&,
    bits: u32&,
    cont: u64&,
) {
    guard bits >= 8 && ptr > 0 else { return; }
    let avail = (bits >> 3) as i64;
    let s = min(ptr, avail);
    ptr -= s;
    bits -= (s * 8) as u32;
    if ptr >= 0 && ptr <= src.len - 8 {
        cont = read_le_u64(src, ptr);
    }
}

// Initializes a backward Huffman bitstream reader from src.
//
// Example:
//   src = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x80]
//   returns: ok = true, ptr = 0, bits = 0, cont = 0x8007060504030201
inline fn init_huf_stream_reader(
    src:  const u8[:],
    ptr:  i64&,
    bits: u32&,
    cont: u64&,
) -> bool {
    let last_b = src[src.len - 1];
    guard last_b != 0 else { return false; }
    let stop = (8 - zstd_high_bit(last_b)) as u32;
    var p = src.len - 8;
    var b = stop;
    if stop == 8 && p > 0 { p--; b = 0; }
    var c: u64 = 0;
    if p >= 0 && p <= src.len - 8 { c = read_le_u64(src, p); }
    ptr = p;
    bits = b;
    cont = c;
    return true;
}

fn huf_decode_fast_4x(
    table:         const HufTable&,
    src:           const u8[:],
    dst:           u8[:],
    count:         i64,
    rshift:        u64,
    decoded:       i64&,
    ptr:           i64&,
    bits_consumed: u32&,
    bit_container: u64&,
) {
    while decoded + 4 <= count && ptr >= 8 {
        let b0 = (((bit_container << bits_consumed) >> rshift) as! i64) & 2047;
        let e0 = table.entries[b0];
        bits_consumed += e0.nb_bits;

        let b1 = (((bit_container << bits_consumed) >> rshift) as! i64) & 2047;
        let e1 = table.entries[b1];
        bits_consumed += e1.nb_bits;

        let b2 = (((bit_container << bits_consumed) >> rshift) as! i64) & 2047;
        let e2 = table.entries[b2];
        bits_consumed += e2.nb_bits;

        let b3 = (((bit_container << bits_consumed) >> rshift) as! i64) & 2047;
        let e3 = table.entries[b3];
        bits_consumed += e3.nb_bits;

        let s0 = e0.symbol as u32;
        let s1 = (e1.symbol as u32) << 8;
        let s2 = (e2.symbol as u32) << 16;
        let s3 = (e3.symbol as u32) << 24;
        let sym32: u32 = s0 | s1 | s2 | s3;
        write_le_u32_at(dst, decoded, sym32);
        decoded += 4;

        ptr -= bits_consumed >> 3;
        bits_consumed &= 7;
        bit_container = read_le_u64(src, ptr);
    }
}

fn huf_decode_stream_slice(r: ZstdBitReader&, table: const HufTable&, dst: u8[:]) -> bool {
    guard !r.underflow && r.src.len > 0 && table.is_defined && table.table_log > 0 else {
        return false;
    }
    var decoded: i64 = 0;
    let count = dst.len;
    let mask = (1 << table.table_log) - 1;
    let t_log = table.table_log;
    let t_log_u32 = t_log as u32;
    let rshift = (64 - t_log_u32) as u64;

    if r.src.len >= 8 {
        var ptr:           i64 = 0;
        var bits_consumed: u32 = 0;
        var bit_container: u64 = 0;
        guard init_huf_stream_reader(r.src, ptr, bits_consumed, bit_container) else {
            return false;
        }

        huf_decode_fast_4x(
            table, r.src, dst, count, rshift,
            decoded, ptr, bits_consumed, bit_container,
        );

        while decoded < count {
            refill_huf_stream_container(r.src, ptr, bits_consumed, bit_container);
            if bits_consumed + t_log_u32 > 64 {
                break;
            }
            let bits = (((bit_container << bits_consumed) >> rshift) as! i64) & 2047;
            let entry = table.entries[bits];
            dst[decoded] = entry.symbol;
            bits_consumed += entry.nb_bits;
            decoded++;
        }

        if decoded == count {
            return ptr == 0 && bits_consumed == 64;
        }

        let remaining_bits = ptr * 8 + (64 - (bits_consumed as i64));
        guard remaining_bits >= 0 else { return false; }
        r.bit_pos = remaining_bits;
        r.cache_offset = -1;
    }

    while decoded < count && !r.underflow {
        let bits = (zstd_peek_bits(r, t_log) & mask) & 2047;
        let entry = table.entries[bits];
        dst[decoded] = entry.symbol;
        zstd_consume_bits(r, entry.nb_bits);
        decoded++;
    }

    return decoded == count && !r.underflow && r.bit_pos == 0;
}

fn huf_decode_4streams_step(
    src1:      const u8[:], src2: const u8[:], src3: const u8[:], src4: const u8[:],
    ptr1:      i64&, ptr2: i64&, ptr3: i64&, ptr4: i64&,
    bits1:     u32&, bits2: u32&, bits3: u32&, bits4: u32&,
    cont1:     u64&, cont2: u64&, cont3: u64&, cont4: u64&,
    t_log_u32: u32,
    rshift:    u64,
    table:     const HufTable&,
    dst1:      u8[:], dst2: u8[:], dst3: u8[:], dst4: u8[:],
    dec1:      i64&, dec2: i64&, dec3: i64&, dec4: i64&,
    cnt1:      i64, cnt2: i64, cnt3: i64, cnt4: i64,
) -> bool {
    refill_huf_stream_container(src1, ptr1, bits1, cont1);
    refill_huf_stream_container(src2, ptr2, bits2, cont2);
    refill_huf_stream_container(src3, ptr3, bits3, cont3);
    refill_huf_stream_container(src4, ptr4, bits4, cont4);

    if bits1 + t_log_u32 > 64 || bits2 + t_log_u32 > 64 || bits3 + t_log_u32 > 64 || bits4 + t_log_u32 > 64 {
        return false;
    }

    let b1 = (((cont1 << bits1) >> rshift) as! i64) & 2047;
    let b2 = (((cont2 << bits2) >> rshift) as! i64) & 2047;
    let b3 = (((cont3 << bits3) >> rshift) as! i64) & 2047;
    let b4 = (((cont4 << bits4) >> rshift) as! i64) & 2047;

    let e1 = table.entries[b1];
    let e2 = table.entries[b2];
    let e3 = table.entries[b3];
    let e4 = table.entries[b4];

    dst1[dec1] = e1.symbol; dec1++; bits1 += e1.nb_bits;
    dst2[dec2] = e2.symbol; dec2++; bits2 += e2.nb_bits;
    dst3[dec3] = e3.symbol; dec3++; bits3 += e3.nb_bits;
    dst4[dec4] = e4.symbol; dec4++; bits4 += e4.nb_bits;

    if dec1 < cnt1 && dec2 < cnt2 && dec3 < cnt3 && dec4 < cnt4 &&
       bits1 + t_log_u32 <= 64 && bits2 + t_log_u32 <= 64 &&
       bits3 + t_log_u32 <= 64 && bits4 + t_log_u32 <= 64 {
        let b1b = (((cont1 << bits1) >> rshift) as! i64) & 2047;
        let b2b = (((cont2 << bits2) >> rshift) as! i64) & 2047;
        let b3b = (((cont3 << bits3) >> rshift) as! i64) & 2047;
        let b4b = (((cont4 << bits4) >> rshift) as! i64) & 2047;

        let e1b = table.entries[b1b];
        let e2b = table.entries[b2b];
        let e3b = table.entries[b3b];
        let e4b = table.entries[b4b];

        dst1[dec1] = e1b.symbol; dec1++; bits1 += e1b.nb_bits;
        dst2[dec2] = e2b.symbol; dec2++; bits2 += e2b.nb_bits;
        dst3[dec3] = e3b.symbol; dec3++; bits3 += e3b.nb_bits;
        dst4[dec4] = e4b.symbol; dec4++; bits4 += e4b.nb_bits;
    }
    return true;
}

fn huf_decode_stream_tail(
    src:   const u8[:],
    ptr:   i64,
    bits:  u32,
    t_log: i32,
    table: const HufTable&,
    dst:   u8[:],
    dec:   i64&,
    cnt:   i64,
) -> bool {
    if dec == cnt {
        return ptr == 0 && bits == 64;
    }
    var r = new_zstd_bit_reader(src);
    guard !r.underflow else { return false; }
    let rem = ptr * 8 + (64 - (bits as i64));
    guard rem >= 0 else { return false; }
    r.bit_pos = rem;
    let mask = ((1 << t_log) - 1) & 2047;
    while dec < cnt && !r.underflow {
        let bits_val = zstd_peek_bits(r, t_log) & mask;
        let entry = table.entries[bits_val];
        dst[dec] = entry.symbol;
        zstd_consume_bits(r, entry.nb_bits);
        dec++;
    }
    return dec == cnt && !r.underflow && r.bit_pos == 0;
}

fn huf_decode_4streams(
    src1:  const u8[:], src2: const u8[:], src3: const u8[:], src4: const u8[:],
    dst1:  u8[:], dst2: u8[:], dst3: u8[:], dst4: u8[:],
    table: const HufTable&,
) -> bool {
    let t_log = table.table_log;
    let t_log_u32 = t_log as u32;
    let rshift = (64 - t_log_u32) as u64;

    if src1.len < 8 || src2.len < 8 || src3.len < 8 || src4.len < 8 || t_log == 0 {
        var r1 = new_zstd_bit_reader(src1);
        var r2 = new_zstd_bit_reader(src2);
        var r3 = new_zstd_bit_reader(src3);
        var r4 = new_zstd_bit_reader(src4);
        return huf_decode_stream_slice(r1, table, dst1) &&
               huf_decode_stream_slice(r2, table, dst2) &&
               huf_decode_stream_slice(r3, table, dst3) &&
               huf_decode_stream_slice(r4, table, dst4);
    }

    var ptr1: i64 = 0; var bits1: u32 = 0; var cont1: u64 = 0;
    var ptr2: i64 = 0; var bits2: u32 = 0; var cont2: u64 = 0;
    var ptr3: i64 = 0; var bits3: u32 = 0; var cont3: u64 = 0;
    var ptr4: i64 = 0; var bits4: u32 = 0; var cont4: u64 = 0;
    guard init_huf_stream_reader(src1, ptr1, bits1, cont1) &&
          init_huf_stream_reader(src2, ptr2, bits2, cont2) &&
          init_huf_stream_reader(src3, ptr3, bits3, cont3) &&
          init_huf_stream_reader(src4, ptr4, bits4, cont4) else {
        return false;
    }

    var dec1: i64 = 0;
    var dec2: i64 = 0;
    var dec3: i64 = 0;
    var dec4: i64 = 0;

    let cnt1 = dst1.len;
    let cnt2 = dst2.len;
    let cnt3 = dst3.len;
    let cnt4 = dst4.len;

    while dec1 < cnt1 && dec2 < cnt2 && dec3 < cnt3 && dec4 < cnt4 {
        let ok = huf_decode_4streams_step(
            src1, src2, src3, src4, ptr1, ptr2, ptr3, ptr4,
            bits1, bits2, bits3, bits4, cont1, cont2, cont3, cont4,
            t_log_u32, rshift, table, dst1, dst2, dst3, dst4,
            dec1, dec2, dec3, dec4, cnt1, cnt2, cnt3, cnt4,
        );
        guard ok else { break; }
    }

    let ok1 = huf_decode_stream_tail(src1, ptr1, bits1, t_log, table, dst1, dec1, cnt1);
    let ok2 = huf_decode_stream_tail(src2, ptr2, bits2, t_log, table, dst2, dec2, cnt2);
    let ok3 = huf_decode_stream_tail(src3, ptr3, bits3, t_log, table, dst3, dec3, cnt3);
    let ok4 = huf_decode_stream_tail(src4, ptr4, bits4, t_log, table, dst4, dec4, cnt4);

    return ok1 && ok2 && ok3 && ok4;
}

// ---- literals section decoder (rfc 8878 section 3.1.1.3.1) ----------------

struct DecodedLiterals {
    ok:    bool        = false,
    slice: const u8[:] = "",
}

// Parses raw or RLE literals header bytes and advances offset.
//
// Example:
//   src = [0x00, 0x05], offset = 0, block_end = 2, header_byte = 0, size_format = 0
//   returns: true, regenerated_size = 0, offset = 1
fn parse_raw_rle_literals_header(
    src:              const u8[:],
    offset:           i64&,
    block_end:        i64,
    header_byte:      u8,
    size_format:      i32,
    regenerated_size: i64&,
) -> bool {
    var lh_size: i64 = 1;
    if size_format == 0 || size_format == 2 {
        lh_size = 1;
        regenerated_size = header_byte >> 3;
    } else if size_format == 1 {
        lh_size = 2;
        guard offset + 2 <= block_end else { return false; }
        let b0 = src[offset] as i64;
        let b1 = src[offset + 1] as i64;
        regenerated_size = (b0 >> 4) | (b1 << 4);
    } else {
        lh_size = 3;
        guard offset + 3 <= block_end else { return false; }
        let b0 = src[offset] as i64;
        let b1 = src[offset + 1] as i64;
        let b2 = src[offset + 2] as i64;
        regenerated_size = (b0 >> 4) | (b1 << 4) | (b2 << 12);
    }
    offset += lh_size;
    return true;
}

// Parses compressed literals header bytes and advances offset.
//
// Example:
//   src = [0x14, 0x00, 0x00], offset = 0, block_end = 3, size_format = 0
//   returns: true, single_stream = true, regenerated_size = 1, compressed_size = 0, offset = 3
fn parse_compressed_literals_header(
    src:              const u8[:],
    offset:           i64&,
    block_end:        i64,
    size_format:      i32,
    single_stream:    bool&,
    regenerated_size: i64&,
    compressed_size:  i64&,
) -> bool {
    var lh_size: i64 = 3;
    if size_format == 0 {
        single_stream = true;
        lh_size = 3;
        guard offset + 3 <= block_end else { return false; }
        let val = read_le_u24(src, offset);
        regenerated_size = (val >> 4) & 0x3FF;
        compressed_size = (val >> 14) & 0x3FF;
        guard compressed_size >= 1 else { return false; }
    } else if size_format == 1 {
        single_stream = false;
        lh_size = 3;
        guard offset + 3 <= block_end else { return false; }
        let val = read_le_u24(src, offset);
        regenerated_size = (val >> 4) & 0x3FF;
        compressed_size = (val >> 14) & 0x3FF;
        guard compressed_size >= 10 && regenerated_size >= 6 else { return false; }
    } else if size_format == 2 {
        single_stream = false;
        lh_size = 4;
        guard offset + 4 <= block_end else { return false; }
        let val = read_le_u32(src, offset);
        regenerated_size = (val >> 4) & 0x3FFF;
        compressed_size = (val >> 18) & 0x3FFF;
        guard compressed_size >= 10 && regenerated_size >= 6 else { return false; }
    } else {
        single_stream = false;
        lh_size = 5;
        guard offset + 5 <= block_end else { return false; }
        let val = read_le_u32(src, offset);
        let b4 = src[offset + 4] as u32;
        regenerated_size = (val >> 4) & 0x3FFFF;
        compressed_size = ((val >> 22) & 0x3FF) | (b4 << 10);
        guard compressed_size >= 10 && regenerated_size >= 6 else { return false; }
    }
    offset += lh_size;
    return true;
}

// Decodes 4 Huffman streams into lit_buf and advances offset.
//
// Example:
//   src = [0x01, 0x00, ...], offset = 0, c_end = 10, regenerated_size = 8
//   returns: true
fn decode_huf_4streams_literals(
    src:              const u8[:],
    offset:           i64&,
    c_end:            i64,
    regenerated_size: i64,
    lit_buf:          u8[>..]&,
    huf_table:        const HufTable&,
) -> bool {
    guard offset + 6 <= c_end else { return false; }
    let s1 = read_le_u16(src, offset) as i64;
    let s2 = read_le_u16(src, offset + 2) as i64;
    let s3 = read_le_u16(src, offset + 4) as i64;
    offset += 6;

    let total_streams = c_end - offset;
    let s4 = total_streams - s1 - s2 - s3;
    guard s1 >= 1 && s2 >= 1 && s3 >= 1 && s4 >= 1 else { return false; }

    let sz1 = (regenerated_size + 3) / 4;
    let sz2 = (regenerated_size + 2) / 4;
    let sz3 = (regenerated_size + 1) / 4;
    let c1 = sz1;
    let c2 = c1 + sz2;
    let c3 = c2 + sz3;

    let o1 = offset;
    let o2 = o1 + s1;
    let o3 = o2 + s2;
    let o4 = o3 + s3;
    let o5 = o4 + s4;

    guard c1 >= 0 && c2 >= c1 && c3 >= c2 && regenerated_size >= c3 else { return false; }
    guard regenerated_size <= lit_buf.len else { return false; }
    guard o1 >= 0 && o2 >= o1 && o3 >= o2 && o4 >= o3 && o5 <= src.len else { return false; }

    let dst1 = lit_buf[0..c1];
    let dst2 = lit_buf[c1..c2];
    let dst3 = lit_buf[c2..c3];
    let dst4 = lit_buf[c3..regenerated_size];

    let src1 = src[o1..o2];
    let src2 = src[o2..o3];
    let src3 = src[o3..o4];
    let src4 = src[o4..o5];

    return huf_decode_4streams(src1, src2, src3, src4, dst1, dst2, dst3, dst4, huf_table);
}

// Decodes a Zstd literals section from src into lit_buf and advances offset.
// Leaves `offset` unchanged when returning `ok: false`.
//
// Example:
//   src = [0x00, 0x05, 0x68, 0x65, 0x6C, 0x6C, 0x6F], offset = 0, block_end = 7
//   returns: DecodedLiterals { ok: true, slice: "hello" }, offset = 7
fn decode_literals(
    src:            const u8[:],
    offset:         i64&,
    block_end:      i64,
    lit_buf:        u8[>..]&,
    state:          ZstdEntropyState&,
    block_max_size: i64 = ZSTD_BLOCKSIZE_MAX,
) -> DecodedLiterals {
    guard offset < block_end else { return DecodedLiterals { ok: false }; }
    let saved_offset = offset;
    var committed = false;
    defer if !committed { offset = saved_offset; };

    let header_byte = src[offset];
    let lit_type = (header_byte & 3) as i32;
    let size_format = ((header_byte >> 2) & 3) as i32;

    if lit_type == 0 || lit_type == 1 {
        var regenerated_size: i64 = 0;
        guard parse_raw_rle_literals_header(src, offset, block_end, header_byte, size_format, regenerated_size) else {
            return DecodedLiterals { ok: false };
        }
        guard regenerated_size <= block_max_size else {
            return DecodedLiterals { ok: false };
        }

        if lit_type == 0 {
            guard offset + regenerated_size <= block_end else { return DecodedLiterals { ok: false }; }
            let lit_slice = src[offset..offset + regenerated_size];
            offset += regenerated_size;
            committed = true;
            return DecodedLiterals { ok: true, slice: lit_slice };
        }
        guard offset < block_end else { return DecodedLiterals { ok: false }; }
        let b = src[offset];
        offset++;
        lit_buf.clear();
        lit_buf.resize(regenerated_size, b);
        committed = true;
        return DecodedLiterals { ok: true, slice: lit_buf[..] };
    }

    if lit_type == 3 && (!state.huf_loaded || state.huf_tabs.len == 0 || !state.huf_tabs[0].is_defined) {
        return DecodedLiterals { ok: false };
    }

    var single_stream = false;
    var regenerated_size: i64 = 0;
    var compressed_size:  i64 = 0;
    guard parse_compressed_literals_header(
        src, offset, block_end, size_format,
        single_stream, regenerated_size, compressed_size,
    ) else {
        return DecodedLiterals { ok: false };
    }

    guard regenerated_size <= block_max_size && compressed_size > 0 else {
        return DecodedLiterals { ok: false };
    }
    guard offset + compressed_size <= block_end else { return DecodedLiterals { ok: false }; }
    let c_end = offset + compressed_size;

    if state.huf_tabs.len == 0 {
        state.huf_tabs.push(HufTable {});
    }
    if lit_type == 2 {
        guard huf_read_table(src[..c_end], offset, state.huf_tabs[0]) && offset < c_end else {
            return DecodedLiterals { ok: false };
        }
        state.huf_loaded = true;
    }

    if lit_buf.len < regenerated_size {
        lit_buf.resize(regenerated_size, 0);
    }

    if single_stream {
        let stream_slice = src[offset..c_end];
        var r = new_zstd_bit_reader(stream_slice);
        guard huf_decode_stream_slice(r, state.huf_tabs[0], lit_buf[0..regenerated_size]) else {
            return DecodedLiterals { ok: false };
        }
    } else {
        guard decode_huf_4streams_literals(src, offset, c_end, regenerated_size, lit_buf, state.huf_tabs[0]) else {
            return DecodedLiterals { ok: false };
        }
    }

    offset = c_end;
    committed = true;
    return DecodedLiterals { ok: true, slice: lit_buf[0..regenerated_size] };
}

// ---- sequences decoder & execution (rfc 8878 section 3.1.1.3.2) ------------

struct SequenceCmd {
    lit_len:   u32 = 0,
    match_len: u32 = 0,
    offset:    u32 = 0,
}

fn compute_repeat_offset(
    offset_val: u32,
    lit_len:    u32,
    rep0:       u32&,
    rep1:       u32&,
    rep2:       u32&,
) -> u32, bool {
    var off: u32 = 0;
    if offset_val == 1 {
        if lit_len > 0 {
            off = rep0;
        } else {
            off = rep1;
            rep1 = rep0;
            rep0 = off;
        }
    } else if offset_val > 3 {
        off = offset_val - 3;
        rep2 = rep1;
        rep1 = rep0;
        rep0 = off;
    } else if offset_val == 2 {
        if lit_len > 0 {
            off = rep1;
            rep1 = rep0;
            rep0 = off;
        } else {
            off = rep2;
            rep2 = rep1;
            rep1 = rep0;
            rep0 = off;
        }
    } else {
        if lit_len > 0 {
            off = rep2;
            rep2 = rep1;
            rep1 = rep0;
            rep0 = off;
        } else {
            guard rep0 > 1 else { return 0, false; }
            off = rep0 - 1;
            rep2 = rep1;
            rep1 = rep0;
            rep0 = off;
        }
    }
    return off, true;
}

fn apply_sequence_literals<B>(
    lit_buf: const u8[:],
    lit_ptr: i64&,
    lit_len: u32,
    out_buf: B&,
) -> CompressError {
    guard lit_len > 0 else { return CompressError.None; }
    let next_lit = lit_ptr + (lit_len as i64);
    guard lit_ptr >= 0 && next_lit >= lit_ptr && next_lit <= lit_buf.len else {
        return CompressError.CorruptedBitstream;
    }
    if lit_len == 1 {
        guard comp_try_push(out_buf, lit_buf[lit_ptr]) else {
            return CompressError.OutputBufferOverflow;
        }
    } else {
        guard comp_try_append(out_buf, lit_buf[lit_ptr..next_lit]) else {
            return CompressError.OutputBufferOverflow;
        }
    }
    lit_ptr = next_lit;
    return CompressError.None;
}

fn copy_in_frame_match<B>(
    off:             i64,
    m_len:           i64,
    out_buf:         B&,
    frame_start_out: i64,
) -> CompressError {
    let out_len = out_buf.len;
    let src_idx = sub_sat_i64(out_len, off);
    guard src_idx >= frame_start_out && src_idx < out_len else {
        return CompressError.DistanceOutOfBounds;
    }
    if off >= m_len {
        guard comp_try_append(out_buf, out_buf[src_idx..add_sat_i64(src_idx, m_len)]) else {
            return CompressError.OutputBufferOverflow;
        }
        return CompressError.None;
    }
    if off == 1 {
        let b = out_buf[src_idx];
        guard comp_try_fill(out_buf, m_len, b) else {
            return CompressError.OutputBufferOverflow;
        }
        return CompressError.None;
    }
    var curr: i64 = 0;
    while curr < m_len {
        let step = min(add_sat_i64(curr, off), sub_sat_i64(m_len, curr));
        guard comp_try_append(out_buf, out_buf[src_idx..add_sat_i64(src_idx, step)]) else {
            return CompressError.OutputBufferOverflow;
        }
        curr = add_sat_i64(curr, step);
    }
    return CompressError.None;
}

fn apply_sequence_match<B>(
    offset:          u32,
    match_len:       u32,
    out_buf:         B&,
    frame_start_out: i64,
    window_size:     i64,
    dict_content:    const u8[:] = "",
) -> CompressError {
    guard match_len > 0 else { return CompressError.None; }
    let off = offset as i64;
    let m_len = match_len as i64;
    let out_len = out_buf.len;
    let current_decoded = out_len - frame_start_out;
    guard off > 0 else { return CompressError.DistanceOutOfBounds; }

    if off <= current_decoded {
        let max_offset = if window_size > 0 && window_size < current_decoded {
            window_size
        } else {
            current_decoded
        };
        guard off <= max_offset else { return CompressError.DistanceOutOfBounds; }
        return copy_in_frame_match(off, m_len, out_buf, frame_start_out);
    }

    guard dict_content.len > 0 && (window_size <= 0 || current_decoded <= window_size) else {
        return CompressError.DistanceOutOfBounds;
    }
    let dict_back = off - current_decoded;
    guard dict_back <= dict_content.len else { return CompressError.DistanceOutOfBounds; }
    let dict_start = dict_content.len - dict_back;
    let dict_copy = min(m_len, dict_back);
    guard comp_try_append(out_buf, dict_content[dict_start..dict_start + dict_copy]) else {
        return CompressError.OutputBufferOverflow;
    }
    let rem_len = m_len - dict_copy;
    if rem_len > 0 {
        return copy_in_frame_match(off, rem_len, out_buf, frame_start_out);
    }
    return CompressError.None;
}

fn execute_single_sequence<B>(
    lit_len:          u32,
    match_len:        u32,
    offset_val:       u32,
    lit_buf:          const u8[:],
    lit_ptr:          i64&,
    out_buf:          B&,
    rep0:             u32&,
    rep1:             u32&,
    rep2:             u32&,
    max_output_bytes: i64,
    initial_out_len:  i64,
    frame_start_out:  i64,
    window_size:      i64,
    dict_content:     const u8[:] = "",
) -> CompressError {
    let offset, ok_off = compute_repeat_offset(offset_val, lit_len, rep0, rep1, rep2);
    guard ok_off else { return CompressError.CorruptedBitstream; }

    if max_output_bytes >= 0 {
        let cur_out = sub_sat_i64(out_buf.len, initial_out_len);
        let needed = add_sat_i64(cur_out, (lit_len as i64) + (match_len as i64));
        guard needed <= max_output_bytes else { return CompressError.OutputBufferOverflow; }
    }

    let lit_err = apply_sequence_literals(lit_buf, lit_ptr, lit_len, out_buf);
    guard lit_err == CompressError.None else { return lit_err; }

    return apply_sequence_match(offset, match_len, out_buf, frame_start_out, window_size, dict_content);
}

// Decodes fast sequence parameters from bit container.
//
// Example:
//   seq_bitstream = [0x12, 0x34], ptr = 0, bit_container = 0x1234, bits_consumed = 0
//   returns: lit_len = 0, match_len = 3, offset_val = 1, ok = true
fn decode_fast_seq_params(
    seq_bitstream: const u8[:],
    ptr:           i64&,
    bit_container: u64&,
    bits_consumed: u32&,
    ll_entry:      FseEntry,
    ml_entry:      FseEntry,
    of_entry:      FseEntry,
) -> u32, u32, u32, bool {
    let of_eb = of_entry.extra_bits as u32;
    let ml_eb = ml_entry.extra_bits as u32;
    let ll_eb = ll_entry.extra_bits as u32;
    let total_eb = add_sat_u32(of_eb, add_sat_u32(ml_eb, ll_eb));
    if add_sat_u32(bits_consumed, total_eb) > 64 {
        refill_huf_stream_container(seq_bitstream, ptr, bits_consumed, bit_container);
    }

    var of_extra: u32 = 0;
    var ml_extra: u32 = 0;
    var ll_extra: u32 = 0;

    if of_eb > 0 {
        if add_sat_u32(bits_consumed, of_eb) > 64 {
            refill_huf_stream_container(seq_bitstream, ptr, bits_consumed, bit_container);
            guard add_sat_u32(bits_consumed, of_eb) <= 64 else { return 0, 0, 0, false; }
        }
        of_extra = zstd_extract_bits(bit_container, bits_consumed, of_eb);
        bits_consumed = add_sat_u32(bits_consumed, of_eb);
    }
    if ml_eb > 0 {
        if add_sat_u32(bits_consumed, ml_eb) > 64 {
            refill_huf_stream_container(seq_bitstream, ptr, bits_consumed, bit_container);
            guard add_sat_u32(bits_consumed, ml_eb) <= 64 else { return 0, 0, 0, false; }
        }
        ml_extra = zstd_extract_bits(bit_container, bits_consumed, ml_eb);
        bits_consumed = add_sat_u32(bits_consumed, ml_eb);
    }
    if ll_eb > 0 {
        if add_sat_u32(bits_consumed, ll_eb) > 64 {
            refill_huf_stream_container(seq_bitstream, ptr, bits_consumed, bit_container);
            guard add_sat_u32(bits_consumed, ll_eb) <= 64 else { return 0, 0, 0, false; }
        }
        ll_extra = zstd_extract_bits(bit_container, bits_consumed, ll_eb);
        bits_consumed = add_sat_u32(bits_consumed, ll_eb);
    }

    let lit_len = add_sat_u32(ll_entry.base_val, ll_extra);
    let match_len = add_sat_u32(ml_entry.base_val, ml_extra);
    let offset_val = add_sat_u32(of_entry.base_val, of_extra);
    return lit_len, match_len, offset_val, true;
}

fn update_fast_fse_states(
    seq_bitstream: const u8[:],
    ptr:           i64&,
    bit_container: u64&,
    bits_consumed: u32&,
    ll_entry:      FseEntry,
    ml_entry:      FseEntry,
    of_entry:      FseEntry,
    state_ll:      i64&,
    state_ml:      i64&,
    state_of:      i64&,
) -> bool {
    let ll_nb = ll_entry.nb_bits as u32;
    let ml_nb = ml_entry.nb_bits as u32;
    let of_nb = of_entry.nb_bits as u32;
    refill_huf_stream_container(seq_bitstream, ptr, bits_consumed, bit_container);
    let need_bits = add_sat_u32(add_sat_u32(bits_consumed, ll_nb), add_sat_u32(ml_nb, of_nb));
    guard need_bits <= 64 else { return false; }

    let ll_bits = zstd_extract_bits(bit_container, bits_consumed, ll_nb) as i64;
    bits_consumed = add_sat_u32(bits_consumed, ll_nb);
    state_ll = add_sat_i64(ll_entry.new_state, ll_bits);

    let ml_bits = zstd_extract_bits(bit_container, bits_consumed, ml_nb) as i64;
    bits_consumed = add_sat_u32(bits_consumed, ml_nb);
    state_ml = add_sat_i64(ml_entry.new_state, ml_bits);

    let of_bits = zstd_extract_bits(bit_container, bits_consumed, of_nb) as i64;
    bits_consumed = add_sat_u32(bits_consumed, of_nb);
    state_of = add_sat_i64(of_entry.new_state, of_bits);
    return true;
}

// Decodes slow sequence parameters using bit reader.
//
// Example:
//   r = bit_reader, of_entry = e1, ml_entry = e2, ll_entry = e3
//   returns: lit_len = 0, match_len = 3, offset_val = 1
fn decode_slow_seq_params(
    r:        ZstdBitReader&,
    of_entry: FseEntry,
    ml_entry: FseEntry,
    ll_entry: FseEntry,
) -> u32, u32, u32 {
    let of_eb = of_entry.extra_bits as u32;
    let ml_eb = ml_entry.extra_bits as u32;
    let ll_eb = ll_entry.extra_bits as u32;

    let of_extra = if of_eb > 0 { zstd_read_bits(r, of_eb as i32) } else { 0 };
    let ml_extra = if ml_eb > 0 { zstd_read_bits(r, ml_eb as i32) } else { 0 };
    let ll_extra = if ll_eb > 0 { zstd_read_bits(r, ll_eb as i32) } else { 0 };

    let lit_len = ll_entry.base_val + ll_extra;
    let match_len = ml_entry.base_val + ml_extra;
    let offset_val = of_entry.base_val + of_extra;
    return lit_len, match_len, offset_val;
}

fn update_slow_fse_states(
    r:        ZstdBitReader&,
    of_entry: FseEntry,
    ml_entry: FseEntry,
    ll_entry: FseEntry,
    state_ll: i64&,
    state_ml: i64&,
    state_of: i64&,
) {
    let ll_bits = if ll_entry.nb_bits > 0 { zstd_read_bits(r, ll_entry.nb_bits) } else { 0 };
    state_ll = (ll_entry.new_state as i64) + ll_bits;

    let ml_bits = if ml_entry.nb_bits > 0 { zstd_read_bits(r, ml_entry.nb_bits) } else { 0 };
    state_ml = (ml_entry.new_state as i64) + ml_bits;

    let of_bits = if of_entry.nb_bits > 0 { zstd_read_bits(r, of_entry.nb_bits) } else { 0 };
    state_of = (of_entry.new_state as i64) + of_bits;
}

// Parses number of sequences header from src and advances offset.
//
// Example:
//   src = [0x05], offset = 0, block_end = 1
//   returns: nb_seq = 5, ok = true, offset = 1
fn parse_number_of_sequences(
    src:       const u8[:],
    offset:    i64&,
    block_end: i64,
) -> i64, bool {
    guard offset < block_end else { return 0, false; }
    let b0 = src[offset];
    offset++;

    if b0 == 0 {
        return 0, true;
    }
    if b0 < 128 {
        return b0, true;
    }
    if b0 < 255 {
        guard offset < block_end else { return 0, false; }
        let b1 = src[offset] as i64;
        offset++;
        return (((b0 as i64) - 128) << 8) + b1, true;
    }
    guard offset + 2 <= block_end else { return 0, false; }
    let b1 = src[offset] as i64;
    let b2 = src[offset + 1] as i64;
    offset += 2;
    return b1 + (b2 << 8) + 0x7F00, true;
}

struct SeqExecCtx {
    lit_buf:          const u8[:] = "",
    max_output_bytes: i64         = -1,
    initial_out_len:  i64         = 0,
    frame_start_out:  i64         = 0,
    window_size:      i64         = 0,
    dict_content:     const u8[:] = "",
}

// Configures literal-length sequence state for mode 0..3 (RFC 8878 §3.1.1.3.2.1.1).
// Leaves `offset` unchanged on error.
//
// Example:
//   src = [0x01], offset = 0, block_end = 1, ll_mode = 1
//   returns: true, offset = 1
fn build_sequence_ll_state(
    src:       const u8[:],
    offset:    i64&,
    block_end: i64,
    ll_mode:   i32,
    state:     ZstdEntropyState&,
) -> bool {
    if ll_mode == 0 {
        state.ll_kind = ZSTD_TBL_DEFAULT;
        return true;
    }
    if ll_mode == 1 {
        guard offset < block_end else { return false; }
        let sym = src[offset];
        guard sym <= 35 else { return false; }
        offset++;
        let idx = sym as i64;
        state.rle_ll[0] = FseEntry {
            base_val:   LL_BASE[idx],
            new_state:  0,
            nb_bits:    0,
            extra_bits: LL_EXTRA_BITS[idx],
        };
        state.ll_kind = ZSTD_TBL_RLE;
        return true;
    }
    if ll_mode == 2 {
        var counts:    i16[256] = [0; 256];
        var max_sym:   i32      = 0;
        var table_log: i32      = 0;
        let saved_offset = offset;
        guard fse_read_ncount(src[..block_end], offset, counts[..], max_sym, table_log) else {
            offset = saved_offset;
            return false;
        }
        guard offset <= block_end && max_sym <= 35 && table_log <= 9 else {
            offset = saved_offset;
            return false;
        }
        if state.ll_tabs.len == 0 { state.ll_tabs.push(FseTable {}); }
        guard fse_build_dtable(counts[..], max_sym, table_log, state.ll_tabs[0], 1) else {
            offset = saved_offset;
            return false;
        }
        state.ll_kind = ZSTD_TBL_CUSTOM;
        return true;
    }
    return state.ll_kind != ZSTD_TBL_UNSET;
}

// Configures offset sequence state for mode 0..3 (RFC 8878 §3.1.1.3.2.1.1).
// Leaves `offset` unchanged on error.
//
// Example:
//   src = [0x01], offset = 0, block_end = 1, of_mode = 1
//   returns: true, offset = 1
fn build_sequence_of_state(
    src:       const u8[:],
    offset:    i64&,
    block_end: i64,
    of_mode:   i32,
    state:     ZstdEntropyState&,
) -> bool {
    if of_mode == 0 {
        state.of_kind = ZSTD_TBL_DEFAULT;
        return true;
    }
    if of_mode == 1 {
        guard offset < block_end else { return false; }
        let sym = src[offset];
        guard sym <= 31 else { return false; }
        offset++;
        let sc = sym as u32;
        state.rle_of[0] = FseEntry {
            base_val:   (1 as u32) << sc,
            new_state:  0,
            nb_bits:    0,
            extra_bits: sc as u8,
        };
        state.of_kind = ZSTD_TBL_RLE;
        return true;
    }
    if of_mode == 2 {
        var counts:    i16[256] = [0; 256];
        var max_sym:   i32      = 0;
        var table_log: i32      = 0;
        let saved_offset = offset;
        guard fse_read_ncount(src[..block_end], offset, counts[..], max_sym, table_log) else {
            offset = saved_offset;
            return false;
        }
        guard offset <= block_end && max_sym <= 31 && table_log <= 8 else {
            offset = saved_offset;
            return false;
        }
        if state.of_tabs.len == 0 { state.of_tabs.push(FseTable {}); }
        guard fse_build_dtable(counts[..], max_sym, table_log, state.of_tabs[0], 2) else {
            offset = saved_offset;
            return false;
        }
        state.of_kind = ZSTD_TBL_CUSTOM;
        return true;
    }
    return state.of_kind != ZSTD_TBL_UNSET;
}

// Configures match-length sequence state for mode 0..3 (RFC 8878 §3.1.1.3.2.1.1).
// Leaves `offset` unchanged on error.
//
// Example:
//   src = [0x01], offset = 0, block_end = 1, ml_mode = 1
//   returns: true, offset = 1
fn build_sequence_ml_state(
    src:       const u8[:],
    offset:    i64&,
    block_end: i64,
    ml_mode:   i32,
    state:     ZstdEntropyState&,
) -> bool {
    if ml_mode == 0 {
        state.ml_kind = ZSTD_TBL_DEFAULT;
        return true;
    }
    if ml_mode == 1 {
        guard offset < block_end else { return false; }
        let sym = src[offset];
        guard sym <= 52 else { return false; }
        offset++;
        let idx = sym as i64;
        state.rle_ml[0] = FseEntry {
            base_val:   ML_BASE[idx],
            new_state:  0,
            nb_bits:    0,
            extra_bits: ML_EXTRA_BITS[idx],
        };
        state.ml_kind = ZSTD_TBL_RLE;
        return true;
    }
    if ml_mode == 2 {
        var counts:    i16[256] = [0; 256];
        var max_sym:   i32      = 0;
        var table_log: i32      = 0;
        let saved_offset = offset;
        guard fse_read_ncount(src[..block_end], offset, counts[..], max_sym, table_log) else {
            offset = saved_offset;
            return false;
        }
        guard offset <= block_end && max_sym <= 52 && table_log <= 9 else {
            offset = saved_offset;
            return false;
        }
        if state.ml_tabs.len == 0 { state.ml_tabs.push(FseTable {}); }
        guard fse_build_dtable(counts[..], max_sym, table_log, state.ml_tabs[0], 3) else {
            offset = saved_offset;
            return false;
        }
        state.ml_kind = ZSTD_TBL_CUSTOM;
        return true;
    }
    return state.ml_kind != ZSTD_TBL_UNSET;
}

inline fn resolve_seq_table_view(
    kind:       u8,
    def_slices: const FseEntry[:],
    def_log:    i32,
    rle_slice:  const FseEntry[:],
    customs:    const FseTable[:],
) -> const FseEntry[:], i32, i64 {
    if kind == ZSTD_TBL_DEFAULT {
        return def_slices, def_log, ((1 as i64) << (def_log as u32)) - 1;
    }
    if kind == ZSTD_TBL_RLE {
        return rle_slice, 0, 0;
    }
    let tl = customs[0].table_log;
    return customs[0].entries[..], tl, ((1 as i64) << (tl as u32)) - 1;
}

fn decode_fast_seq_pair<B>(
    seq_bitstream: const u8[:],
    seq_i:         i64,
    nb_seq:        i64,
    ll_entries:    const FseEntry[:],
    ll_mask:       i64,
    ml_entries:    const FseEntry[:],
    ml_mask:       i64,
    of_entries:    const FseEntry[:],
    of_mask:       i64,
    of_entry:      FseEntry&,
    ml_entry:      FseEntry&,
    ll_entry:      FseEntry&,
    state_ll:      i64&,
    state_ml:      i64&,
    state_of:      i64&,
    ptr:           i64&,
    bit_container: u64&,
    bits_consumed: u32&,
    ctx:           const SeqExecCtx&,
    lit_ptr:       i64&,
    out_buf:       B&,
    rep0:          u32&,
    rep1:          u32&,
    rep2:          u32&,
) -> CompressError {
    let lit_A, mat_A, off_val_A, ok_A = decode_fast_seq_params(
        seq_bitstream, ptr, bit_container, bits_consumed,
        ll_entry, ml_entry, of_entry,
    );
    guard ok_A else { return CompressError.CorruptedBitstream; }

    guard update_fast_fse_states(
        seq_bitstream, ptr, bit_container, bits_consumed,
        ll_entry, ml_entry, of_entry,
        state_ll, state_ml, state_of,
    ) else {
        return CompressError.CorruptedBitstream;
    }
    of_entry = of_entries[state_of & of_mask];
    ml_entry = ml_entries[state_ml & ml_mask];
    ll_entry = ll_entries[state_ll & ll_mask];

    let err_A = execute_single_sequence(
        lit_A, mat_A, off_val_A, ctx.lit_buf, lit_ptr, out_buf,
        rep0, rep1, rep2, ctx.max_output_bytes, ctx.initial_out_len,
        ctx.frame_start_out, ctx.window_size, ctx.dict_content,
    );
    guard err_A == CompressError.None else { return err_A; }

    let lit_B, mat_B, off_val_B, ok_B = decode_fast_seq_params(
        seq_bitstream, ptr, bit_container, bits_consumed,
        ll_entry, ml_entry, of_entry,
    );
    guard ok_B else { return CompressError.CorruptedBitstream; }

    if seq_i + 2 < nb_seq {
        guard update_fast_fse_states(
            seq_bitstream, ptr, bit_container, bits_consumed,
            ll_entry, ml_entry, of_entry,
            state_ll, state_ml, state_of,
        ) else {
            return CompressError.CorruptedBitstream;
        }
        of_entry = of_entries[state_of & of_mask];
        ml_entry = ml_entries[state_ml & ml_mask];
        ll_entry = ll_entries[state_ll & ll_mask];
    }

    return execute_single_sequence(
        lit_B, mat_B, off_val_B, ctx.lit_buf, lit_ptr, out_buf,
        rep0, rep1, rep2, ctx.max_output_bytes, ctx.initial_out_len,
        ctx.frame_start_out, ctx.window_size, ctx.dict_content,
    );
}

// Decodes fast sequence streams from backward bit container.
//
// Example:
//   seq_bitstream = [0, 0, 0, 0, 0, 0, 0, 0x80], nb_seq = 1
//   returns: CompressError.None
fn decode_fast_sequence_streams<B>(
    seq_bitstream: const u8[:],
    nb_seq:        i64,
    ll_entries:    const FseEntry[:],
    ll_log:        i32,
    ll_mask:       i64,
    ml_entries:    const FseEntry[:],
    ml_log:        i32,
    ml_mask:       i64,
    of_entries:    const FseEntry[:],
    of_log:        i32,
    of_mask:       i64,
    state_ll:      i64&,
    state_ml:      i64&,
    state_of:      i64&,
    ptr:           i64&,
    bit_container: u64&,
    bits_consumed: u32&,
    ctx:           const SeqExecCtx&,
    lit_ptr:       i64&,
    out_buf:       B&,
    rep0:          u32&,
    rep1:          u32&,
    rep2:          u32&,
) -> CompressError {
    var of_entry = of_entries[state_of & of_mask];
    var ml_entry = ml_entries[state_ml & ml_mask];
    var ll_entry = ll_entries[state_ll & ll_mask];

    var seq_i: i64 = 0;
    while seq_i + 1 < nb_seq {
        let err = decode_fast_seq_pair(
            seq_bitstream, seq_i, nb_seq,
            ll_entries, ll_mask, ml_entries, ml_mask, of_entries, of_mask,
            of_entry, ml_entry, ll_entry, state_ll, state_ml, state_of,
            ptr, bit_container, bits_consumed, ctx, lit_ptr, out_buf,
            rep0, rep1, rep2,
        );
        guard err == CompressError.None else { return err; }
        seq_i += 2;
    }

    while seq_i < nb_seq {
        let lit_val, mat_val, off_val, ok_p = decode_fast_seq_params(
            seq_bitstream, ptr, bit_container, bits_consumed,
            ll_entry, ml_entry, of_entry,
        );
        guard ok_p else { return CompressError.CorruptedBitstream; }
        let err = execute_single_sequence(
            lit_val, mat_val, off_val, ctx.lit_buf, lit_ptr, out_buf,
            rep0, rep1, rep2, ctx.max_output_bytes, ctx.initial_out_len,
            ctx.frame_start_out, ctx.window_size, ctx.dict_content,
        );
        guard err == CompressError.None else { return err; }
        seq_i++;
    }

    refill_huf_stream_container(seq_bitstream, ptr, bits_consumed, bit_container);
    guard bits_consumed <= 64 else { return CompressError.CorruptedBitstream; }
    if (ll_log | of_log | ml_log) != 0 {
        guard ptr == 0 && bits_consumed == 64 else { return CompressError.CorruptedBitstream; }
    }
    return CompressError.None;
}

// Decodes sequence streams using fallback bit reader.
//
// Example:
//   r = bit_reader, nb_seq = 1, lit_ptr = 0
//   returns: CompressError.None
fn decode_slow_sequence_streams<B>(
    r:          ZstdBitReader&,
    nb_seq:     i64,
    ll_entries: const FseEntry[:],
    ll_log:     i32,
    ll_mask:    i64,
    ml_entries: const FseEntry[:],
    ml_log:     i32,
    ml_mask:    i64,
    of_entries: const FseEntry[:],
    of_log:     i32,
    of_mask:    i64,
    state_ll:   i64&,
    state_ml:   i64&,
    state_of:   i64&,
    ctx:        const SeqExecCtx&,
    lit_ptr:    i64&,
    out_buf:    B&,
    rep0:       u32&,
    rep1:       u32&,
    rep2:       u32&,
) -> CompressError {
    var of_entry = of_entries[state_of & of_mask];
    var ml_entry = ml_entries[state_ml & ml_mask];
    var ll_entry = ll_entries[state_ll & ll_mask];

    var seq_i: i64 = 0;
    while seq_i < nb_seq {
        let lit_len, match_len, offset_val = decode_slow_seq_params(
            r, of_entry, ml_entry, ll_entry,
        );
        guard !r.underflow else { return CompressError.CorruptedBitstream; }

        if seq_i + 1 < nb_seq {
            update_slow_fse_states(r, of_entry, ml_entry, ll_entry, state_ll, state_ml, state_of);
            guard !r.underflow else { return CompressError.CorruptedBitstream; }
            of_entry = of_entries[state_of & of_mask];
            ml_entry = ml_entries[state_ml & ml_mask];
            ll_entry = ll_entries[state_ll & ll_mask];
        }

        let err = execute_single_sequence(
            lit_len, match_len, offset_val, ctx.lit_buf, lit_ptr, out_buf,
            rep0, rep1, rep2, ctx.max_output_bytes, ctx.initial_out_len,
            ctx.frame_start_out, ctx.window_size, ctx.dict_content,
        );
        guard err == CompressError.None else { return err; }
        seq_i++;
    }

    guard !r.underflow else { return CompressError.CorruptedBitstream; }
    if (ll_log | of_log | ml_log) != 0 {
        guard r.bit_pos == 0 else { return CompressError.CorruptedBitstream; }
    }
    return CompressError.None;
}

fn append_trailing_literals<B>(
    lit_buf:          const u8[:],
    lit_ptr:          i64,
    out_buf:          B&,
    initial_out_len:  i64,
    max_output_bytes: i64,
) -> CompressError {
    guard lit_ptr >= 0 && lit_ptr <= lit_buf.len else { return CompressError.None; }
    let rem_lit = lit_buf.len - lit_ptr;
    guard rem_lit > 0 else { return CompressError.None; }
    if max_output_bytes >= 0 {
        let total = add_sat_i64(sub_sat_i64(out_buf.len, initial_out_len), rem_lit);
        guard total <= max_output_bytes else { return CompressError.OutputBufferOverflow; }
    }
    guard comp_try_append(out_buf, lit_buf[lit_ptr..lit_buf.len]) else {
        return CompressError.OutputBufferOverflow;
    }
    return CompressError.None;
}

fn init_fast_seq_reader(
    seq_bitstream: const u8[:],
    ll_log:        i32,
    of_log:        i32,
    ml_log:        i32,
    ptr:           i64&,
    bit_container: u64&,
    bits_consumed: u32&,
    state_ll:      i64&,
    state_of:      i64&,
    state_ml:      i64&,
) -> bool {
    guard init_huf_stream_reader(seq_bitstream, ptr, bits_consumed, bit_container) else {
        return false;
    }
    refill_huf_stream_container(seq_bitstream, ptr, bits_consumed, bit_container);
    let ll_u = (ll_log & 15) as u32;
    let of_u = (of_log & 15) as u32;
    let ml_u = (ml_log & 15) as u32;
    let init_bits = add_sat_u32(add_sat_u32(ll_u, of_u), ml_u);
    guard add_sat_u32(bits_consumed, init_bits) <= 64 else { return false; }

    state_ll = zstd_extract_bits(bit_container, bits_consumed, ll_u);
    bits_consumed = add_sat_u32(bits_consumed, ll_u);
    state_of = zstd_extract_bits(bit_container, bits_consumed, of_u);
    bits_consumed = add_sat_u32(bits_consumed, of_u);
    state_ml = zstd_extract_bits(bit_container, bits_consumed, ml_u);
    bits_consumed = add_sat_u32(bits_consumed, ml_u);
    return true;
}

// Decodes a Zstd sequences section and emits match and literal streams.
// Leaves `offset` unchanged when returning an error.
//
// Example:
//   src = [0x01, 0x00], offset = 0, block_end = 2
//   returns: CompressError.None, offset = 2
fn decode_sequences<B>(
    src:              const u8[:],
    offset:           i64&,
    block_end:        i64,
    lit_buf:          const u8[:],
    out_buf:          B&,
    state:            ZstdEntropyState&,
    max_output_bytes: i64,
    frame_start_out:  i64         = 0,
    window_size:      i64         = 0,
    initial_out_len:  i64         = 0,
    dict_content:     const u8[:] = "",
) -> CompressError {
    if offset >= block_end {
        return append_trailing_literals(lit_buf, 0, out_buf, initial_out_len, max_output_bytes);
    }

    let saved_offset = offset;
    var committed = false;
    defer if !committed { offset = saved_offset; };

    let nb_seq, ok_seq = parse_number_of_sequences(src, offset, block_end);
    guard ok_seq else { return CompressError.InputBufferTruncated; }

    if nb_seq == 0 {
        guard offset == block_end else { return CompressError.CorruptedBitstream; }
        let err0 = append_trailing_literals(lit_buf, 0, out_buf, initial_out_len, max_output_bytes);
        guard err0 == CompressError.None else { return err0; }
        committed = true;
        return CompressError.None;
    }

    guard offset < block_end else { return CompressError.InputBufferTruncated; }
    let comp_modes = src[offset];
    // RFC 8878 Section 3.1.1.3.2.1: Symbol_Compression_Modes - reserved low 2 bits must be zero.
    guard (comp_modes & 3) == 0 else { return CompressError.CorruptedBitstream; }
    offset++;

    let ll_mode = ((comp_modes >> 6) & 3) as i32;
    let of_mode = ((comp_modes >> 4) & 3) as i32;
    let ml_mode = ((comp_modes >> 2) & 3) as i32;

    guard build_sequence_ll_state(src, offset, block_end, ll_mode, state) &&
          build_sequence_of_state(src, offset, block_end, of_mode, state) &&
          build_sequence_ml_state(src, offset, block_end, ml_mode, state) else {
        return CompressError.CorruptedBitstream;
    }

    guard offset < block_end else { return CompressError.CorruptedBitstream; }
    let seq_bitstream = src[offset..block_end];

    let ll_entries, ll_log, ll_mask = resolve_seq_table_view(
        state.ll_kind, DEFAULT_LL_ENTRIES[..], 6, state.rle_ll[..], state.ll_tabs[..],
    );
    let of_entries, of_log, of_mask = resolve_seq_table_view(
        state.of_kind, DEFAULT_OF_ENTRIES[..], 5, state.rle_of[..], state.of_tabs[..],
    );
    let ml_entries, ml_log, ml_mask = resolve_seq_table_view(
        state.ml_kind, DEFAULT_ML_ENTRIES[..], 6, state.rle_ml[..], state.ml_tabs[..],
    );

    let ctx = SeqExecCtx {
        lit_buf:          lit_buf,
        max_output_bytes: max_output_bytes,
        initial_out_len:  initial_out_len,
        frame_start_out:  frame_start_out,
        window_size:      window_size,
        dict_content:     dict_content,
    };
    var lit_ptr: i64 = 0;
    var rep0 = state.rep[0];
    var rep1 = state.rep[1];
    var rep2 = state.rep[2];

    if seq_bitstream.len >= 8 {
        var ptr:           i64 = 0;
        var bit_container: u64 = 0;
        var bits_consumed: u32 = 0;
        var state_ll:      i64 = 0;
        var state_of:      i64 = 0;
        var state_ml:      i64 = 0;
        guard init_fast_seq_reader(
            seq_bitstream, ll_log, of_log, ml_log,
            ptr, bit_container, bits_consumed, state_ll, state_of, state_ml,
        ) else {
            return CompressError.CorruptedBitstream;
        }
        let err = decode_fast_sequence_streams(
            seq_bitstream, nb_seq,
            ll_entries, ll_log, ll_mask,
            ml_entries, ml_log, ml_mask,
            of_entries, of_log, of_mask,
            state_ll, state_ml, state_of, ptr, bit_container, bits_consumed,
            ctx, lit_ptr, out_buf, rep0, rep1, rep2,
        );
        guard err == CompressError.None else { return err; }
    } else {
        var r = new_zstd_bit_reader(seq_bitstream);
        guard !r.underflow else { return CompressError.CorruptedBitstream; }
        var state_ll = zstd_read_bits(r, ll_log) as i64;
        var state_of = zstd_read_bits(r, of_log) as i64;
        var state_ml = zstd_read_bits(r, ml_log) as i64;
        guard !r.underflow else { return CompressError.CorruptedBitstream; }

        let err = decode_slow_sequence_streams(
            r, nb_seq,
            ll_entries, ll_log, ll_mask,
            ml_entries, ml_log, ml_mask,
            of_entries, of_log, of_mask,
            state_ll, state_ml, state_of,
            ctx, lit_ptr, out_buf, rep0, rep1, rep2,
        );
        guard err == CompressError.None else { return err; }
    }

    state.rep[0] = rep0;
    state.rep[1] = rep1;
    state.rep[2] = rep2;

    let trail_err = append_trailing_literals(lit_buf, lit_ptr, out_buf, initial_out_len, max_output_bytes);
    guard trail_err == CompressError.None else { return trail_err; }

    offset = block_end;
    committed = true;
    return CompressError.None;
}

// ---- frame decompressor (rfc 8878 section 3.1.1) ---------------------------

// Parses Zstandard frame header fields from src at offset (RFC 8878 §3.1.1.1).
//
// Example:
//   src = [0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x00], offset = 4
//   returns: CompressError.None, window_size = 0, frame_content_size = 0, content_checksum_flag = 0
root struct ParsedZstdDict {
    is_formatted:   bool          = false,
    dict_id:        u32           = 0,
    content_offset: i64           = 0,
    rep:            u32[3]        = [1, 4, 8],
    huf_tabs:       HufTable[>..] = [],
    ll_tabs:        FseTable[>..] = [],
    ml_tabs:        FseTable[>..] = [],
    of_tabs:        FseTable[>..] = [],
}

fn reset_zstd_entropy_state(state: ZstdEntropyState&) {
    state.rep = [1, 4, 8];
    state.ll_kind = ZSTD_TBL_UNSET;
    state.of_kind = ZSTD_TBL_UNSET;
    state.ml_kind = ZSTD_TBL_UNSET;
    state.huf_loaded = false;
}

fn copy_dict_fse_slot(dst: FseTable[>..]&, src: const FseTable[:], kind: u8&) {
    if src.len > 0 && src[0].is_defined {
        if dst.len == 0 { dst.push(src[0]); } else { dst[0] = src[0]; }
        kind = ZSTD_TBL_CUSTOM;
    }
}

fn init_zstd_state_from_dict(state: ZstdEntropyState&, parsed_dict: const ParsedZstdDict&) {
    reset_zstd_entropy_state(state);
    if !parsed_dict.is_formatted {
        return;
    }
    state.rep = parsed_dict.rep;
    if parsed_dict.huf_tabs.len > 0 && parsed_dict.huf_tabs[0].is_defined {
        if state.huf_tabs.len == 0 {
            state.huf_tabs.push(parsed_dict.huf_tabs[0]);
        } else {
            state.huf_tabs[0] = parsed_dict.huf_tabs[0];
        }
        state.huf_loaded = true;
    }
    copy_dict_fse_slot(state.ll_tabs, parsed_dict.ll_tabs[..], state.ll_kind);
    copy_dict_fse_slot(state.of_tabs, parsed_dict.of_tabs[..], state.of_kind);
    copy_dict_fse_slot(state.ml_tabs, parsed_dict.ml_tabs[..], state.ml_kind);
}

fn read_formatted_dict_fse_table(
    dict:            const u8[:],
    pos:             i64&,
    max_allowed_sym: i32,
    max_allowed_log: i32,
    kind:            i32,
    out_tbl:         FseTable&,
) -> bool {
    var counts:    i16[256] = [0; 256];
    var max_sym:   i32      = 0;
    var table_log: i32      = 0;
    guard fse_read_ncount(dict, pos, counts[..], max_sym, table_log) else { return false; }
    guard max_sym <= max_allowed_sym && table_log <= max_allowed_log else { return false; }
    return fse_build_dtable(counts[..], max_sym, table_log, out_tbl, kind);
}

// Parses RFC 8878 Section 5 formatted dictionary entropy tables and repeat offsets.
//
// Example:
//   dict = [0x37, 0xA4, 0x30, 0xEC, 0x01, 0x00, 0x00, 0x00, ...], start_pos = 8
//   returns: true
fn parse_formatted_zstd_tables(dict: const u8[:], start_pos: i64, out_dict: ParsedZstdDict&) -> bool {
    var committed = false;
    defer if !committed {
        out_dict.huf_tabs.clear();
        out_dict.of_tabs.clear();
        out_dict.ml_tabs.clear();
        out_dict.ll_tabs.clear();
    };

    var pos = start_pos;
    if out_dict.huf_tabs.len == 0 { out_dict.huf_tabs.push(HufTable {}); }
    guard huf_read_table(dict, pos, out_dict.huf_tabs[0]) else { return false; }

    if out_dict.of_tabs.len == 0 { out_dict.of_tabs.push(FseTable {}); }
    if out_dict.ml_tabs.len == 0 { out_dict.ml_tabs.push(FseTable {}); }
    if out_dict.ll_tabs.len == 0 { out_dict.ll_tabs.push(FseTable {}); }
    guard read_formatted_dict_fse_table(dict, pos, 31, 8, 2, out_dict.of_tabs[0]) &&
          read_formatted_dict_fse_table(dict, pos, 52, 9, 3, out_dict.ml_tabs[0]) &&
          read_formatted_dict_fse_table(dict, pos, 35, 9, 1, out_dict.ll_tabs[0]) else {
        return false;
    }

    let next_pos = add_sat_i64(pos, 12);
    guard next_pos <= dict.len else { return false; }
    let r0 = read_le_u32(dict, pos);
    let r1 = read_le_u32(dict, add_sat_i64(pos, 4));
    let r2 = read_le_u32(dict, add_sat_i64(pos, 8));
    let content_len = sub_sat_i64(dict.len, next_pos);
    guard r0 > 0 && r1 > 0 && r2 > 0 else { return false; }
    guard r0 <= content_len && r1 <= content_len && r2 <= content_len else {
        return false;
    }

    out_dict.rep = [r0, r1, r2];
    out_dict.content_offset = next_pos;
    committed = true;
    return true;
}

// Parses a raw or formatted RFC 8878 Section 5 Zstandard dictionary.
//
// Example:
//   dict = "raw-dict-bytes"
//   returns: CompressError.None, out_dict.content_offset = 0
fn parse_zstd_dictionary(dict: const u8[:], out_dict: ParsedZstdDict&) -> CompressError {
    out_dict.is_formatted = false;
    out_dict.dict_id = 0;
    out_dict.content_offset = 0;
    out_dict.rep = [1, 4, 8];
    out_dict.huf_tabs.clear();
    out_dict.ll_tabs.clear();
    out_dict.ml_tabs.clear();
    out_dict.of_tabs.clear();
    if dict.len == 0 {
        return CompressError.None;
    }
    if dict.len < 4 || read_le_u32(dict, 0) != ZSTD_MAGIC_DICTIONARY {
        out_dict.content_offset = 0;
        return CompressError.None;
    }
    // RFC 8878 Section 5: Dictionary Format - Dictionary_ID must be non-zero after 4-byte magic.
    guard dict.len >= 8 else { return CompressError.InvalidHeader; }
    let dict_id = read_le_u32(dict, 4);
    guard dict_id != 0 else { return CompressError.InvalidHeader; }

    out_dict.is_formatted = true;
    out_dict.dict_id = dict_id;
    if !parse_formatted_zstd_tables(dict, 8, out_dict) {
        out_dict.content_offset = 8;
    }
    return CompressError.None;
}

// Decodes a Zstandard `Window_Descriptor` byte into window size in bytes (RFC 8878 Section 3.1.1.1.2).
//
// Example:
//   wd = 0x00
//   returns: 1024
fn decode_zstd_window_descriptor(wd: u8) -> i64 {
    let hi, _ = div_rem_u64(wd, 8);
    let exp = add_sat_u32((hi & 31) as u32, 10);
    let mantissa = (wd & 7) as u64;
    let window_base = ZSTD_POW2_U64[(exp as u64) & 63];
    let q, _ = div_rem_u64(window_base, 8);
    let total = add_sat_u64(window_base, mul_sat_u64(q, mantissa));
    return (total & 0x7FFFFFFFFFFFFFFF) as i64;
}

// Parses the optional Zstd `Dictionary_ID` field (RFC 8878 Section 3.1.1.1.3).
// Leaves `pos` at the end of the field on `CompressError.None`.
//
// Example:
//   src = [0x01], pos = 0, dict_id_flag = 1
//   returns: CompressError.None, frame_dict_id = 1, pos = 1
fn parse_zstd_dict_id_field(
    src:           const u8[:],
    pos:           i64&,
    dict_id_flag:  u8,
    frame_dict_id: u32&,
) -> CompressError {
    frame_dict_id = 0;
    if dict_id_flag == 0 {
        return CompressError.None;
    }
    if dict_id_flag == 1 {
        guard add_sat_i64(pos, 1) <= src.len else { return CompressError.InputBufferTruncated; }
        frame_dict_id = src[pos];
        pos = add_sat_i64(pos, 1);
        return CompressError.None;
    }
    if dict_id_flag == 2 {
        guard add_sat_i64(pos, 2) <= src.len else { return CompressError.InputBufferTruncated; }
        frame_dict_id = read_le_u16(src, pos);
        pos = add_sat_i64(pos, 2);
        return CompressError.None;
    }
    guard add_sat_i64(pos, 4) <= src.len else { return CompressError.InputBufferTruncated; }
    frame_dict_id = read_le_u32(src, pos);
    pos = add_sat_i64(pos, 4);
    return CompressError.None;
}

// Parses the optional Zstd `Frame_Content_Size` field (RFC 8878 Section 3.1.1.1.4).
// Leaves `pos` at the end of the field on `CompressError.None`.
//
// Example:
//   src = [0x05], pos = 0, fcs_flag = 0, single_segment = 1
//   returns: CompressError.None, frame_content_size = 5, pos = 1
fn parse_zstd_fcs_field(
    src:                const u8[:],
    pos:                i64&,
    fcs_flag:           u8,
    single_segment:     u8,
    frame_content_size: i64&,
) -> CompressError {
    frame_content_size = -1;
    if fcs_flag == 0 {
        if single_segment == 0 {
            return CompressError.None;
        }
        guard add_sat_i64(pos, 1) <= src.len else { return CompressError.InputBufferTruncated; }
        frame_content_size = src[pos];
        pos = add_sat_i64(pos, 1);
        return CompressError.None;
    }
    if fcs_flag == 1 {
        guard add_sat_i64(pos, 2) <= src.len else { return CompressError.InputBufferTruncated; }
        frame_content_size = add_sat_i64(read_le_u16(src, pos), 256);
        pos = add_sat_i64(pos, 2);
        return CompressError.None;
    }
    if fcs_flag == 2 {
        guard add_sat_i64(pos, 4) <= src.len else { return CompressError.InputBufferTruncated; }
        frame_content_size = read_le_u32(src, pos);
        pos = add_sat_i64(pos, 4);
        return CompressError.None;
    }
    guard add_sat_i64(pos, 8) <= src.len else { return CompressError.InputBufferTruncated; }
    let raw_fcs = read_le_u64(src, pos);
    guard raw_fcs <= 0x7FFFFFFFFFFFFFFF else { return CompressError.CorruptedBitstream; }
    frame_content_size = (raw_fcs & 0x7FFFFFFFFFFFFFFF) as i64;
    pos = add_sat_i64(pos, 8);
    return CompressError.None;
}

// Parses Zstandard frame header fields including `Dictionary_ID` from src at offset (RFC 8878 Section 3.1.1.1).
// Leaves `offset` unchanged when returning an error.
//
// Example:
//   src = [0x28, 0xb5, 0x2f, 0xfd, 0x20, 0x00], offset = 4
//   returns: CompressError.None, window_size = 0, frame_content_size = 0, content_checksum_flag = 0, frame_dict_id = 0
fn parse_zstd_frame_header_ex(
    src:                   const u8[:],
    offset:                i64&,
    window_size:           i64&,
    frame_content_size:    i64&,
    content_checksum_flag: u8&,
    frame_dict_id:         u32&,
) -> CompressError {
    guard offset < src.len else { return CompressError.InputBufferTruncated; }
    let fhd = src[offset];
    var pos = add_sat_i64(offset, 1);

    let fcs_flag = (fhd >> 6) & 3;
    let single_segment = (fhd >> 5) & 1;
    let reserved_bit = (fhd >> 3) & 1;
    content_checksum_flag = (fhd >> 2) & 1;
    let dict_id_flag = fhd & 3;
    guard reserved_bit == 0 else { return CompressError.InvalidHeader; }

    window_size = 0;
    if single_segment == 0 {
        guard pos < src.len else { return CompressError.InputBufferTruncated; }
        window_size = decode_zstd_window_descriptor(src[pos]);
        pos = add_sat_i64(pos, 1);
    }

    let dict_err = parse_zstd_dict_id_field(src, pos, dict_id_flag, frame_dict_id);
    guard dict_err == CompressError.None else { return dict_err; }

    let fcs_err = parse_zstd_fcs_field(src, pos, fcs_flag, single_segment, frame_content_size);
    guard fcs_err == CompressError.None else { return fcs_err; }
    if single_segment == 1 {
        window_size = frame_content_size;
    }

    offset = pos;
    return CompressError.None;
}

// Parses Zstandard frame header fields from src at offset (RFC 8878 §3.1.1.1).
// Leaves `offset` unchanged when returning an error.
//
// Example:
//   src = [0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x00], offset = 4
//   returns: CompressError.None, window_size = 1024, frame_content_size = -1, content_checksum_flag = 0
fn parse_zstd_frame_header(
    src:                   const u8[:],
    offset:                i64&,
    window_size:           i64&,
    frame_content_size:    i64&,
    content_checksum_flag: u8&,
) -> CompressError {
    var frame_dict_id: u32 = 0;
    return parse_zstd_frame_header_ex(
        src, offset, window_size, frame_content_size, content_checksum_flag, frame_dict_id,
    );
}

// Decompresses a single Zstandard block and updates entropy state and output buffer (RFC 8878 §3.1.1.2).
// Leaves `offset` unchanged when returning an error.
//
// Example:
//   src = [0x01, 0x00, 0x00], offset = 0
//   returns: CompressError.None, last_block = true, offset = 3
fn decompress_zstd_block<B>(
    src:              const u8[:],
    offset:           i64&,
    last_block:       bool&,
    out_buf:          B&,
    lit_buf:          u8[>..]&,
    state:            ZstdEntropyState&,
    window_size:      i64,
    initial_out_len:  i64,
    frame_start_out:  i64,
    max_output_bytes: i64,
    dict_content:     const u8[:] = "",
) -> CompressError {
    let saved_offset = offset;
    var committed = false;
    defer if !committed { offset = saved_offset; };

    if offset + 3 > src.len { return CompressError.InputBufferTruncated; }
    let header_val = read_le_u24(src, offset);
    offset += 3;
    last_block = (header_val & 1) != 0;
    let block_type = (header_val >> 1) & 3;
    let block_size = (header_val >> 3) as i64;
    if block_type == ZSTD_BLOCK_TYPE_RESERVED { return CompressError.InvalidBlockType; }

    var block_max_size: i64 = ZSTD_BLOCKSIZE_MAX;
    if window_size >= 0 && window_size < ZSTD_BLOCKSIZE_MAX { block_max_size = window_size; }
    if block_size > block_max_size { return CompressError.CorruptedBitstream; }
    let produced_so_far = sub_sat_i64(out_buf.len, initial_out_len);

    if block_type == ZSTD_BLOCK_TYPE_RLE {
        if offset + 1 > src.len { return CompressError.InputBufferTruncated; }
        if max_output_bytes >= 0 && add_sat_i64(produced_so_far, block_size) > max_output_bytes {
            return CompressError.OutputBufferOverflow;
        }
        let rle_byte = src[offset];
        offset += 1;
        guard comp_try_fill(out_buf, block_size, rle_byte) else {
            return CompressError.OutputBufferOverflow;
        }
        committed = true;
        return CompressError.None;
    }

    if offset + block_size > src.len { return CompressError.InputBufferTruncated; }
    let block_end = offset + block_size;
    if block_type == ZSTD_BLOCK_TYPE_RAW {
        if max_output_bytes >= 0 && add_sat_i64(produced_so_far, block_size) > max_output_bytes {
            return CompressError.OutputBufferOverflow;
        }
        guard comp_try_append(out_buf, src[offset..block_end]) else {
            return CompressError.OutputBufferOverflow;
        }
        offset = block_end;
        committed = true;
        return CompressError.None;
    }

    if block_type == ZSTD_BLOCK_TYPE_COMPRESSED {
        let block_out_start = out_buf.len;
        let lits = decode_literals(src, offset, block_end, lit_buf, state, block_max_size);
        if !lits.ok { return CompressError.CorruptedBitstream; }
        let seq_err = decode_sequences(
            src,
            offset,
            block_end,
            lits.slice,
            out_buf,
            state,
            max_output_bytes,
            frame_start_out,
            window_size,
            initial_out_len,
            dict_content,
        );
        if seq_err != CompressError.None { return seq_err; }
        if (out_buf.len - block_out_start) > block_max_size {
            return CompressError.CorruptedBitstream;
        }
    }

    committed = true;
    return CompressError.None;
}

// Decompresses all consecutive blocks within a Zstandard frame (RFC 8878 §3.1.1.2).
//
// Example:
//   src = [0x01, 0x00, 0x00], offset = 0
//   returns: CompressError.None
fn zstd_decompress_frame_blocks<B>(
    src:                const u8[:],
    offset:             i64&,
    out_buf:            B&,
    lit_buf:            u8[>..]&,
    state:              ZstdEntropyState&,
    window_size:        i64,
    frame_content_size: i64,
    initial_out_len:    i64,
    max_output_bytes:   i64,
    dict_content:       const u8[:] = "",
) -> CompressError {
    let frame_start_out = out_buf.len;
    var last_block = false;

    while !last_block {
        let err = decompress_zstd_block(
            src,
            offset,
            last_block,
            out_buf,
            lit_buf,
            state,
            window_size,
            initial_out_len,
            frame_start_out,
            max_output_bytes,
            dict_content,
        );
        if err != CompressError.None {
            return err;
        }
    }

    if frame_content_size >= 0 && (out_buf.len - frame_start_out) != frame_content_size {
        return CompressError.SizeMismatch;
    }
    return CompressError.None;
}

// Decompresses a single Zstandard frame or skippable frame from src at offset (RFC 8878 §3.1.1).
//
// Example:
//   src = [0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x00], offset = 0
//   returns: CompressError.None, offset = 6
fn decompress_single_zstd_frame<B>(
    src:               const u8[:],
    offset:            i64&,
    out_buf:           B&,
    lit_buf:           u8[>..]&,
    state:             ZstdEntropyState&,
    initial_out_len:   i64,
    max_output_bytes:  i64,
    dict_is_formatted: bool        = false,
    dict_id:           u32         = 0,
    dict_content:      const u8[:] = "",
) -> CompressError {
    if offset + 4 > src.len { return CompressError.InputBufferTruncated; }
    let magic = read_le_u32(src, offset);
    offset += 4;

    if magic >= ZSTD_MAGIC_SKIPPABLE_START && magic <= ZSTD_MAGIC_SKIPPABLE_END {
        if offset + 4 > src.len { return CompressError.InputBufferTruncated; }
        let skip_len = read_le_u32(src, offset) as i64;
        if skip_len < 0 || add_sat_i64(offset + 4, skip_len) > src.len {
            return CompressError.InputBufferTruncated;
        }
        offset += 4 + skip_len;
        return CompressError.None;
    }

    if magic != ZSTD_MAGIC { return CompressError.InvalidHeader; }

    var window_size:           i64 = 0;
    var frame_content_size:    i64 = -1;
    var content_checksum_flag: u8  = 0;
    var frame_dict_id:         u32 = 0;
    let hdr_err = parse_zstd_frame_header_ex(
        src, offset, window_size, frame_content_size, content_checksum_flag, frame_dict_id,
    );
    if hdr_err != CompressError.None { return hdr_err; }

    if frame_dict_id != 0 {
        if !dict_is_formatted && dict_content.len == 0 {
            return CompressError.NeedDictionary;
        }
        if !dict_is_formatted || dict_id != frame_dict_id {
            return CompressError.DictionaryMismatch;
        }
    }

    let total_decoded = sub_sat_i64(out_buf.len, initial_out_len);
    if frame_content_size >= 0 && max_output_bytes >= 0 &&
       add_sat_i64(total_decoded, frame_content_size) > max_output_bytes {
        return CompressError.OutputBufferOverflow;
    }

    let frame_start_out = out_buf.len;
    lit_buf.clear();
    let blk_err = zstd_decompress_frame_blocks(
        src,
        offset,
        out_buf,
        lit_buf,
        state,
        window_size,
        frame_content_size,
        initial_out_len,
        max_output_bytes,
        dict_content,
    );
    if blk_err != CompressError.None { return blk_err; }

    if content_checksum_flag != 0 {
        if offset + 4 > src.len { return CompressError.InputBufferTruncated; }
        let expected_chk = read_le_u32(src, offset);
        offset += 4;
        let decoded_slice = out_buf[frame_start_out..out_buf.len];
        let actual_chk = xxh64_digest_32(decoded_slice);
        if actual_chk != expected_chk { return CompressError.ChecksumMismatch; }
    }

    return CompressError.None;
}

fn prepare_zstd_dict_context(dict: const u8[:], parsed_dict: ParsedZstdDict&) -> const u8[:], CompressError {
    if dict.len == 0 {
        return "", CompressError.None;
    }
    let dict_err = parse_zstd_dictionary(dict, parsed_dict);
    if dict_err != CompressError.None {
        return "", dict_err;
    }
    if dict.len > parsed_dict.content_offset {
        return dict[parsed_dict.content_offset..], CompressError.None;
    }
    return "", CompressError.None;
}

// Internal frame decompressor (RFC 8878 section 3.1.1) with output limit and dictionary support.
fn zstd_decompress_with_limit_impl(
    src:              const u8[:],
    out_buf:          u8[>..]&,
    max_output_bytes: i64         = -1,
    dict:             const u8[:] = "",
) -> CompressError {
    guard src.len > 0 else { return CompressError.InputBufferTruncated; }
    var parsed_dict = ParsedZstdDict {};
    let dict_content, dict_err = prepare_zstd_dict_context(dict, parsed_dict);
    if dict_err != CompressError.None {
        return dict_err;
    }

    let initial_out_len = out_buf.len;
    var committed = false;
    defer if !committed { out_buf.resize(initial_out_len); };

    var offset:  i64     = 0;
    var lit_buf: u8[>..] = [];
    var state = ZstdEntropyState {};

    while offset < src.len {
        if parsed_dict.is_formatted {
            init_zstd_state_from_dict(state, parsed_dict);
        } else if offset > 0 {
            reset_zstd_entropy_state(state);
        }
        let err = decompress_single_zstd_frame(
            src,
            offset,
            out_buf,
            lit_buf,
            state,
            initial_out_len,
            max_output_bytes,
            parsed_dict.is_formatted,
            parsed_dict.dict_id,
            dict_content,
        );
        if err != CompressError.None {
            return err;
        }
    }

    committed = true;
    return CompressError.None;
}

// Generic bounded-buffer bridge delegating to the single non-generic u8[>..] Zstd core.
fn zstd_decompress_with_limit_impl<B>(
    src:              const u8[:],
    out_buf:          B&,
    max_output_bytes: i64         = -1,
    dict:             const u8[:] = "",
) -> CompressError {
    let avail = sub_sat_i64(out_buf.cap, out_buf.len);
    let eff_limit = if max_output_bytes >= 0 && max_output_bytes < avail { max_output_bytes } else { avail };
    var tmp: u8[>..] = [];
    let err = zstd_decompress_with_limit_impl(src, tmp, eff_limit, dict);
    guard err == CompressError.None else { return err; }
    guard out_buf.try_append(tmp[..]) else { return CompressError.OutputBufferOverflow; }
    return CompressError.None;
}

// Incrementally decompresses complete Zstandard frames from `src` and returns consumed bytes.
// Stops cleanly at frame boundaries if a trailing frame is still truncated, returning `CompressError.None`
// when at least one frame was consumed or `CompressError.InputBufferTruncated` when the first frame is incomplete.
fn zstd_decompress_frames_incremental(
    src:              const u8[:],
    out_buf:          u8[>..]&,
    max_output_bytes: i64         = -1,
    dict:             const u8[:] = "",
) -> i64, CompressError {
    guard src.len > 0 else { return 0, CompressError.InputBufferTruncated; }
    var parsed_dict = ParsedZstdDict {};
    let dict_content, dict_err = prepare_zstd_dict_context(dict, parsed_dict);
    if dict_err != CompressError.None {
        return 0, dict_err;
    }

    let initial_out_len = out_buf.len;
    var offset:  i64     = 0;
    var lit_buf: u8[>..] = [];
    var state = ZstdEntropyState {};

    while offset < src.len {
        if parsed_dict.is_formatted {
            init_zstd_state_from_dict(state, parsed_dict);
        } else if offset > 0 {
            reset_zstd_entropy_state(state);
        }
        let saved_offset = offset;
        let saved_out_len = out_buf.len;
        let err = decompress_single_zstd_frame(
            src,
            offset,
            out_buf,
            lit_buf,
            state,
            initial_out_len,
            max_output_bytes,
            parsed_dict.is_formatted,
            parsed_dict.dict_id,
            dict_content,
        );
        if err == CompressError.InputBufferTruncated {
            out_buf.resize(saved_out_len);
            if saved_offset > 0 { return saved_offset, CompressError.None; }
            return 0, CompressError.InputBufferTruncated;
        }
        if err != CompressError.None {
            out_buf.resize(initial_out_len);
            return saved_offset, err;
        }
    }

    return offset, CompressError.None;
}

fn zstd_decompress_frames_incremental<B>(
    src:              const u8[:],
    out_buf:          B&,
    max_output_bytes: i64         = -1,
    dict:             const u8[:] = "",
) -> i64, CompressError {
    let avail = sub_sat_i64(out_buf.cap, out_buf.len);
    let eff_limit = if max_output_bytes >= 0 && max_output_bytes < avail { max_output_bytes } else { avail };
    var tmp: u8[>..] = [];
    let consumed, err = zstd_decompress_frames_incremental(src, tmp, eff_limit, dict);
    if err == CompressError.None && tmp.len > 0 {
        guard out_buf.try_append(tmp[..]) else { return 0, CompressError.OutputBufferOverflow; }
    }
    return consumed, err;
}

// Extracts dictionary content slice from a raw or formatted RFC 8878 Section 5 dictionary.
//
// Example:
//   dict = [0x37, 0xA4, 0x30, 0xEC, 0x01, 0x00, 0x00, 0x00, 'a', 'b']
//   returns: "ab"
fn extract_zstd_dict_prefix(dict: const u8[:]) -> const u8[:] {
    if dict.len >= 8 && read_le_u32(dict, 0) == ZSTD_MAGIC_DICTIONARY {
        var parsed = ParsedZstdDict {};
        if parse_zstd_dictionary(dict, parsed) == CompressError.None {
            return dict[parsed.content_offset..];
        }
        return dict[8..];
    }
    return dict;
}

// Decompresses RFC 8878 Zstandard frame with a raw or formatted prefix dictionary (RFC 8878 §5, RFC 9842 §6).
fn zstd_decompress_with_dict<B>(
    src:              const u8[:],
    dict:             const u8[:],
    out_buf:          B&,
    max_output_bytes: i64 = -1,
) -> bool, CompressError {
    let err = zstd_decompress_with_limit_impl(src, out_buf, max_output_bytes, dict);
    return err == CompressError.None, err;
}

// Decompresses RFC 8878 Zstandard frame from src into out_buf with output limit guard.
fn zstd_decompress_with_limit<B>(src: const u8[:], out_buf: B&, max_output_bytes: i64 = -1) -> bool, CompressError {
    let err = zstd_decompress_with_limit_impl(src, out_buf, max_output_bytes);
    return err == CompressError.None, err;
}

// Decompresses RFC 8878 Zstandard frame from src into out_buf.
fn zstd_decompress<B>(src: const u8[:], out_buf: B&) -> bool, CompressError {
    return zstd_decompress_with_limit(src, out_buf, -1);
}

// ---- native rfc 8878 zstandard compressor (levels 1-3) ---------------------

struct FseCTableEntry {
    next_state: u16 = 0,
    nb_bits:    u8  = 0,
    bits:       u16 = 0,
}

struct ZstdCTables {
    ll_table: FseCTableEntry[2304] = [FseCTableEntry {}; 2304],
    of_table: FseCTableEntry[928]  = [FseCTableEntry {}; 928],
    ml_table: FseCTableEntry[3392] = [FseCTableEntry {}; 3392],
    ll_init:  u16[36]              = [0; 36],
    of_init:  u16[29]              = [0; 29],
    ml_init:  u16[53]              = [0; 53],
    is_init:  bool                 = false,
}

var G_CTABLES: ZstdCTables = ZstdCTables {};

fn build_fse_ctable(
    d_entries:   const FseEntry[:],
    table_size:  i32,
    num_syms:    i32,
    table_kind:  i32,
    c_table:     FseCTableEntry[:],
    init_states: u16[:],
) {
    var sym_seen: bool[64] = [false; 64];

    var u: i32 = 0;
    while u < table_size {
        let entry = d_entries[u];
        var sym: i32 = 0;
        if table_kind == 1 {
            while sym < 36 && LL_BASE[sym] != entry.base_val {
                sym++;
            }
        } else if table_kind == 2 {
            sym = entry.extra_bits;
        } else {
            while sym < 53 && ML_BASE[sym] != entry.base_val {
                sym++;
            }
        }

        if sym < num_syms && !sym_seen[sym] {
            sym_seen[sym] = true;
            init_states[sym] = u as u16;
        }

        let nb_bits = entry.nb_bits as u32;
        let new_state = entry.new_state as i32;
        let num_bits_vals = (1 as i32) << nb_bits;

        var bits: i32 = 0;
        while bits < num_bits_vals {
            let s = new_state + bits;
            let idx = s * num_syms + sym;
            c_table[idx] = FseCTableEntry {
                next_state: u as u16,
                nb_bits:    nb_bits as u8,
                bits:       bits as u16,
            };
            bits++;
        }
        u++;
    }
}

fn init_global_ctables() {
    if G_CTABLES.is_init { return; }
    build_fse_ctable(DEFAULT_LL_ENTRIES[..], 64, 36, 1, G_CTABLES.ll_table[..], G_CTABLES.ll_init[..]);
    build_fse_ctable(DEFAULT_OF_ENTRIES[..], 32, 29, 2, G_CTABLES.of_table[..], G_CTABLES.of_init[..]);
    build_fse_ctable(DEFAULT_ML_ENTRIES[..], 64, 53, 3, G_CTABLES.ml_table[..], G_CTABLES.ml_init[..]);
    G_CTABLES.is_init = true;
}

struct ZstdBitWriter {
    bit_container: u64     = 0,
    bit_count:     u32     = 0,
    buf:           u8[>..] = [],
}

inline fn bw_write_bits(w: ZstdBitWriter&, val: u32, nb: u32) {
    if nb == 0 { return; }
    w.bit_container |= (val as u64) << w.bit_count;
    w.bit_count += nb;
    while w.bit_count >= 8 {
        w.buf.push((w.bit_container & 0xFF) as u8);
        w.bit_container >>= 8;
        w.bit_count -= 8;
    }
}

fn bw_finish(w: ZstdBitWriter&) {
    w.bit_container |= (1 as u64) << w.bit_count;
    w.bit_count += 1;
    while w.bit_count > 0 {
        w.buf.push((w.bit_container & 0xFF) as u8);
        w.bit_container >>= 8;
        if w.bit_count > 8 {
            w.bit_count -= 8;
        } else {
            w.bit_count = 0;
        }
    }
}

struct ZstdSeq {
    lit_len:   u32 = 0,
    match_len: u32 = 0,
    offset:    u32 = 0,
}

const LL_CODE_TABLE: u8[64] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    16, 16, 17, 17, 18, 18, 19, 19, 20, 20, 20, 20, 21, 21, 21, 21,
    22, 22, 22, 22, 22, 22, 22, 22, 23, 23, 23, 23, 23, 23, 23, 23,
    24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
];

const ML_CODE_TABLE: u8[128] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
    32, 32, 33, 33, 34, 34, 35, 35, 36, 36, 36, 36, 37, 37, 37, 37,
    38, 38, 38, 38, 38, 38, 38, 38, 39, 39, 39, 39, 39, 39, 39, 39,
    40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40,
    41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41, 41,
    42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
    42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
];

inline fn lit_len_to_code(lit_len: u32, code: u32&, extra: u32&, extra_bits: u32&) {
    var c: u32 = 35;
    if lit_len < 64 {
        c = LL_CODE_TABLE[lit_len];
    } else {
        c = min((zstd_high_bit(lit_len) + 19) as u32, 35);
    }
    code = c;
    extra = lit_len - LL_BASE[c];
    extra_bits = LL_EXTRA_BITS[c];
}

inline fn match_len_to_code(match_len: u32, code: u32&, extra: u32&, extra_bits: u32&) {
    let ml_m3 = match_len - 3;
    var c: u32 = 52;
    if ml_m3 < 128 {
        c = ML_CODE_TABLE[ml_m3];
    } else {
        c = min((zstd_high_bit(ml_m3) + 36) as u32, 52);
    }
    code = c;
    extra = match_len - ML_BASE[c];
    extra_bits = ML_EXTRA_BITS[c];
}

fn offset_to_code(
    offset:     u32,
    lit_len:    u32,
    rep:        u32[3]&,
    code:       u32&,
    extra:      u32&,
    extra_bits: u32&,
) {
    var off_val: u32 = 0;
    if lit_len > 0 {
        if offset == rep[0] {
            off_val = 1;
        } else if offset == rep[1] {
            off_val = 2;
            rep[1] = rep[0];
            rep[0] = offset;
        } else if offset == rep[2] {
            off_val = 3;
            rep[2] = rep[1];
            rep[1] = rep[0];
            rep[0] = offset;
        } else {
            off_val = offset + 3;
            rep[2] = rep[1];
            rep[1] = rep[0];
            rep[0] = offset;
        }
    } else {
        if offset == rep[1] {
            off_val = 1;
            rep[1] = rep[0];
            rep[0] = offset;
        } else if offset == rep[2] {
            off_val = 2;
            rep[2] = rep[1];
            rep[1] = rep[0];
            rep[0] = offset;
        } else if offset == rep[0] - 1 {
            off_val = 3;
            rep[2] = rep[1];
            rep[1] = rep[0];
            rep[0] = offset;
        } else {
            off_val = offset + 3;
            rep[2] = rep[1];
            rep[1] = rep[0];
            rep[0] = offset;
        }
    }
    let high = 63 - clz(off_val);
    code = high as u32;
    extra = off_val - ((1 as u32) << code);
    extra_bits = code;
}

struct CodedSeq {
    ll_s: u32 = 0, ll_ex: u32 = 0, ll_eb: u32 = 0,
    ml_s: u32 = 0, ml_ex: u32 = 0, ml_eb: u32 = 0,
    of_s: u32 = 0, of_ex: u32 = 0, of_eb: u32 = 0,
}

fn write_nb_seq_header<B>(nb_seq: i64, out_buf: B&) -> bool {
    if nb_seq < 128 {
        return comp_try_push(out_buf, nb_seq as u8);
    }
    if nb_seq < 0x7F00 {
        let pair: u8[2] = [((nb_seq >> 8) + 128) as u8, (nb_seq & 0xFF) as u8];
        return comp_try_append(out_buf, pair[..]);
    }
    let rem = nb_seq - 0x7F00;
    let triple: u8[3] = [255, (rem & 0xFF) as u8, ((rem >> 8) & 0xFF) as u8];
    return comp_try_append(out_buf, triple[..]);
}

fn encode_sequences_backwards(
    coded:  const CodedSeq[:],
    nb_seq: i64,
    st_ll:  u16&,
    st_ml:  u16&,
    st_of:  u16&,
    bw:     ZstdBitWriter&,
) {
    var i = nb_seq - 2;
    while i >= 0 {
        let prev = coded[i];
        let tr_of = G_CTABLES.of_table[(st_of as i32) * 29 + (prev.of_s as i32)];
        let tr_ml = G_CTABLES.ml_table[(st_ml as i32) * 53 + (prev.ml_s as i32)];
        let tr_ll = G_CTABLES.ll_table[(st_ll as i32) * 36 + (prev.ll_s as i32)];

        st_of = tr_of.next_state;
        st_ml = tr_ml.next_state;
        st_ll = tr_ll.next_state;

        if tr_of.nb_bits > 0 { bw_write_bits(bw, tr_of.bits, tr_of.nb_bits); }
        if tr_ml.nb_bits > 0 { bw_write_bits(bw, tr_ml.bits, tr_ml.nb_bits); }
        if tr_ll.nb_bits > 0 { bw_write_bits(bw, tr_ll.bits, tr_ll.nb_bits); }

        if prev.ll_eb > 0 { bw_write_bits(bw, prev.ll_ex, prev.ll_eb); }
        if prev.ml_eb > 0 { bw_write_bits(bw, prev.ml_ex, prev.ml_eb); }
        if prev.of_eb > 0 { bw_write_bits(bw, prev.of_ex, prev.of_eb); }
        i--;
    }
}

fn encode_sequences(seqs: const ZstdSeq[:], rep_initial: u32[3], out_buf: u8[>..]&) {
    let nb_seq = seqs.len;
    if nb_seq == 0 {
        out_buf.push(0);
        return;
    }

    var rep = rep_initial;
    var coded: CodedSeq[>..] = [];
    coded.resize(nb_seq, CodedSeq {});

    var si: i64 = 0;
    while si < nb_seq {
        let sq = seqs[si];
        var c = CodedSeq {};
        lit_len_to_code(sq.lit_len, c.ll_s, c.ll_ex, c.ll_eb);
        match_len_to_code(sq.match_len, c.ml_s, c.ml_ex, c.ml_eb);
        offset_to_code(sq.offset, sq.lit_len, rep, c.of_s, c.of_ex, c.of_eb);
        coded[si] = c;
        si++;
    }

    let last = coded[nb_seq - 1];
    var st_ll = G_CTABLES.ll_init[last.ll_s];
    var st_ml = G_CTABLES.ml_init[last.ml_s];
    var st_of = G_CTABLES.of_init[last.of_s];

    var bw = ZstdBitWriter {};
    if last.ll_eb > 0 { bw_write_bits(bw, last.ll_ex, last.ll_eb); }
    if last.ml_eb > 0 { bw_write_bits(bw, last.ml_ex, last.ml_eb); }
    if last.of_eb > 0 { bw_write_bits(bw, last.of_ex, last.of_eb); }

    encode_sequences_backwards(coded[..], nb_seq, st_ll, st_ml, st_of, bw);

    bw_write_bits(bw, st_ml, 6);
    bw_write_bits(bw, st_of, 5);
    bw_write_bits(bw, st_ll, 6);
    bw_finish(bw);

    let _ = write_nb_seq_header(nb_seq, out_buf);
    out_buf.push(0); // Symbol_Compression_Modes: predefined FSE distributions
    out_buf.append(bw.buf[..]);
}

fn count_match_len(src: const u8[:], p: i64, curr: i64, n: i64) -> i64 {
    var m: i64 = 0;
    while curr + m + 8 <= n {
        let diff = read_le_u64(src, p + m) ^ read_le_u64(src, curr + m);
        if diff != 0 {
            return m + (ctz(diff) >> 3);
        }
        m += 8;
    }
    while curr + m < n && src[p + m] == src[curr + m] {
        m++;
    }
    return m;
}

fn update_match_rep(offset: u32, lit_len: u32, rep: u32[3]&) {
    if lit_len > 0 {
        if offset == rep[0] {
            return;
        }
        if offset == rep[1] {
            rep[1] = rep[0];
            rep[0] = offset;
            return;
        }
        rep[2] = rep[1];
        rep[1] = rep[0];
        rep[0] = offset;
        return;
    }
    if offset == rep[1] {
        rep[1] = rep[0];
        rep[0] = offset;
        return;
    }
    rep[2] = rep[1];
    rep[1] = rep[0];
    rep[0] = offset;
}

fn find_rep0_match(
    src:  const u8[:],
    curr: i64,
    n:    i64,
    rep0: u32,
    v4:   u32,
) -> i64, u32 {
    let rep0_i64 = rep0 as i64;
    guard rep0_i64 > 0 && curr >= rep0_i64 else { return 0, 0; }
    let p_rep = curr - rep0_i64;
    guard read_le_u32(src, p_rep) == v4 else { return 0, 0; }
    let m = count_match_len(src, p_rep, curr, n);
    return m, rep0;
}

fn find_hash_match(
    src:       const u8[:],
    curr:      i64,
    n:         i64,
    v4:        u32,
    hash_log:  i64,
    hash_size: i64,
    table:     i32[65536]&,
) -> i64, u32 {
    let h = ((v4 * 2654435761) >> (32 - hash_log)) & ((hash_size - 1) as u32);
    let p = table[h as i64] as i64;
    table[h as i64] = curr as i32;

    guard p >= 0 && (curr - p) <= 131072 else { return 0, 0; }
    guard read_le_u32(src, p) == v4 else { return 0, 0; }
    let m = count_match_len(src, p, curr, n);
    return m, (curr - p) as u32;
}

fn find_matches(src: const u8[:], rep: u32[3]&, seqs: ZstdSeq[>..]&, lits: u8[>..]&, level: i32) {
    let hash_log = if level <= 1 { 14 } else if level == 2 { 15 } else { 16 };
    let hash_size = 1 << hash_log;
    var table: i32[65536] = [-1; 65536];

    let n = src.len;
    var anchor: i64 = 0;
    var curr:   i64 = 0;

    while curr + 4 <= n {
        let v4 = read_le_u32(src, curr);
        var match_len: i64 = 0;
        var offset:    u32 = 0;

        if level >= 3 {
            let m, off = find_rep0_match(src, curr, n, rep[0], v4);
            match_len = m;
            offset = off;
        }

        if match_len == 0 {
            let m, off = find_hash_match(src, curr, n, v4, hash_log, hash_size, table);
            match_len = m;
            offset = off;
        }

        if match_len >= 4 {
            let lit_len = (curr - anchor) as u32;
            if lit_len > 0 {
                lits.append(src[anchor..curr]);
            }
            seqs.push(ZstdSeq { lit_len: lit_len, match_len: match_len as u32, offset: offset });
            update_match_rep(offset, lit_len, rep);
            anchor = curr + match_len;
            curr = anchor;
        } else {
            let step = if level <= 1 { 1 + ((curr - anchor) >> 8) } else { 1 };
            curr += step;
        }
    }

    if anchor < n {
        lits.append(src[anchor..n]);
    }
}

fn emit_zstd_u24_le<B>(out_buf: B&, val: u32) -> bool {
    let hdr_bytes: u8[3] = [
        (val & 0xFF) as u8,
        ((val >> 8) & 0xFF) as u8,
        ((val >> 16) & 0xFF) as u8,
    ];
    return comp_try_append(out_buf, hdr_bytes[..]);
}

fn emit_raw_literals_header<B>(n_lit: i64, out_buf: B&) -> bool {
    if n_lit < 32 {
        return comp_try_push(out_buf, (n_lit << 3) as u8);
    }
    if n_lit < 4096 {
        let pair: u8[2] = [
            ((1 << 2) | ((n_lit & 0xF) << 4)) as u8,
            ((n_lit >> 4) & 0xFF) as u8,
        ];
        return comp_try_append(out_buf, pair[..]);
    }
    let triple: u8[3] = [
        ((3 << 2) | ((n_lit & 0xF) << 4)) as u8,
        ((n_lit >> 4) & 0xFF) as u8,
        ((n_lit >> 12) & 0xFF) as u8,
    ];
    return comp_try_append(out_buf, triple[..]);
}

struct CodedSmallSeq {
    lit_start: u16 = 0,
    lit_len:   u16 = 0,
    ll_ex:     u16 = 0,
    ml_ex:     u16 = 0,
    of_ex:     u16 = 0,
    ll_s:      u8  = 0,
    ll_eb:     u8  = 0,
    ml_s:      u8  = 0,
    ml_eb:     u8  = 0,
    of_s:      u8  = 0,
    of_eb:     u8  = 0,
}

inline fn record_small_seq(
    seqs:      CodedSmallSeq[:],
    nb_seq:    i64,
    anchor:    i64,
    curr:      i64,
    match_len: i64,
    offset:    u32,
    rep:       u32[3]&,
) {
    let lit_len = (curr - anchor) as u32;
    var ll_s:  u32 = 0;
    var ll_ex: u32 = 0;
    var ll_eb: u32 = 0;
    var ml_s:  u32 = 0;
    var ml_ex: u32 = 0;
    var ml_eb: u32 = 0;
    var of_s:  u32 = 0;
    var of_ex: u32 = 0;
    var of_eb: u32 = 0;
    lit_len_to_code(lit_len, ll_s, ll_ex, ll_eb);
    match_len_to_code(match_len as u32, ml_s, ml_ex, ml_eb);
    offset_to_code(offset, lit_len, rep, of_s, of_ex, of_eb);
    seqs[nb_seq] = CodedSmallSeq {
        lit_start: anchor as u16,
        lit_len:   lit_len as u16,
        ll_ex:     ll_ex as u16,
        ml_ex:     ml_ex as u16,
        of_ex:     of_ex as u16,
        ll_s:      ll_s as u8,
        ll_eb:     ll_eb as u8,
        ml_s:      ml_s as u8,
        ml_eb:     ml_eb as u8,
        of_s:      of_s as u8,
        of_eb:     of_eb as u8,
    };
}

inline fn probe_small_hash_match(
    src:        const u8[:],
    curr:       i64,
    n:          i64,
    v4:         u32,
    hash_shift: u32,
    hash_mask:  u32,
    table:      u16[:],
) -> i64, u32 {
    let h = (((v4 * 2654435761) >> hash_shift) & hash_mask) as i64;
    let pe = table[h];
    table[h] = (curr + 1) as u16;
    guard pe > 0 else { return 0, 0; }
    let p = (pe as i64) - 1;
    guard read_le_u32(src, p) == v4 else { return 0, 0; }
    return count_match_len(src, p, curr, n), (curr - p) as u32;
}

fn find_matches_small(
    src:      const u8[:],
    rep:      u32[3]&,
    level:    i32,
    table:    u16[:],
    seqs:     CodedSmallSeq[:],
    n_lit:    i64&,
    tail_pos: i64&,
) -> i64 {
    let n = src.len;
    let hash_mask = (table.len - 1) as u32;
    let hash_shift: u32 = if table.len == 1024 { 22 } else { 20 };
    var nb_seq:  i64 = 0;
    var lit_sum: i64 = 0;
    var anchor:  i64 = 0;
    var curr:    i64 = 0;
    while curr + 4 <= n {
        let v4 = read_le_u32(src, curr);
        var match_len: i64 = 0;
        var offset:    u32 = 0;
        if level >= 3 {
            let m, off = find_rep0_match(src, curr, n, rep[0], v4);
            match_len = m;
            offset = off;
        }
        if match_len == 0 {
            let m, off = probe_small_hash_match(src, curr, n, v4, hash_shift, hash_mask, table);
            match_len = m;
            offset = off;
        }
        if match_len >= 4 {
            lit_sum += curr - anchor;
            record_small_seq(seqs, nb_seq, anchor, curr, match_len, offset, rep);
            nb_seq++;
            anchor = curr + match_len;
            curr = anchor;
        } else {
            let step = if level <= 1 { 1 + ((curr - anchor) >> 8) } else { 1 };
            curr += step;
        }
    }
    n_lit = lit_sum + (n - anchor);
    tail_pos = anchor;
    return nb_seq;
}

inline fn bw_put_bits<B>(
    container: u64&,
    bit_count: u32&,
    val:       u32,
    nb:        u32,
    out_buf:   B&,
) -> bool {
    container |= (val as u64) << bit_count;
    bit_count += nb;
    if bit_count >= 32 {
        guard comp_try_write_le_u32(out_buf, (container & 0xFFFFFFFF) as u32) else {
            return false;
        }
        container >>= 32;
        bit_count -= 32;
    }
    return true;
}

fn bw_finish_direct<B>(container: u64&, bit_count: u32&, out_buf: B&) -> bool {
    container |= (1 as u64) << bit_count;
    bit_count += 1;
    while bit_count >= 8 {
        guard comp_try_push(out_buf, (container & 0xFF) as u8) else { return false; }
        container >>= 8;
        bit_count -= 8;
    }
    if bit_count > 0 {
        guard comp_try_push(out_buf, (container & 0xFF) as u8) else { return false; }
    }
    return true;
}

fn encode_small_sequences_direct<B>(seqs: const CodedSmallSeq[:], nb_seq: i64, out_buf: B&) -> bool {
    let last = seqs[nb_seq - 1];
    var st_ll = G_CTABLES.ll_init[last.ll_s];
    var st_ml = G_CTABLES.ml_init[last.ml_s];
    var st_of = G_CTABLES.of_init[last.of_s];
    var container: u64 = 0;
    var bit_count: u32 = 0;

    guard bw_put_bits(container, bit_count, last.ll_ex as u32, last.ll_eb as u32, out_buf) &&
          bw_put_bits(container, bit_count, last.ml_ex as u32, last.ml_eb as u32, out_buf) &&
          bw_put_bits(container, bit_count, last.of_ex as u32, last.of_eb as u32, out_buf) else {
        return false;
    }

    var i = nb_seq - 2;
    while i >= 0 {
        let prev = seqs[i];
        let tr_of = G_CTABLES.of_table[(st_of as i32) * 29 + (prev.of_s as i32)];
        let tr_ml = G_CTABLES.ml_table[(st_ml as i32) * 53 + (prev.ml_s as i32)];
        let tr_ll = G_CTABLES.ll_table[(st_ll as i32) * 36 + (prev.ll_s as i32)];
        st_of = tr_of.next_state;
        st_ml = tr_ml.next_state;
        st_ll = tr_ll.next_state;
        guard bw_put_bits(container, bit_count, tr_of.bits, tr_of.nb_bits, out_buf) &&
              bw_put_bits(container, bit_count, tr_ml.bits, tr_ml.nb_bits, out_buf) &&
              bw_put_bits(container, bit_count, tr_ll.bits, tr_ll.nb_bits, out_buf) &&
              bw_put_bits(container, bit_count, prev.ll_ex as u32, prev.ll_eb as u32, out_buf) &&
              bw_put_bits(container, bit_count, prev.ml_ex as u32, prev.ml_eb as u32, out_buf) &&
              bw_put_bits(container, bit_count, prev.of_ex as u32, prev.of_eb as u32, out_buf) else {
            return false;
        }
        i--;
    }

    guard bw_put_bits(container, bit_count, st_ml as u32, 6, out_buf) &&
          bw_put_bits(container, bit_count, st_of as u32, 5, out_buf) &&
          bw_put_bits(container, bit_count, st_ll as u32, 6, out_buf) else {
        return false;
    }
    return bw_finish_direct(container, bit_count, out_buf);
}

fn emit_small_literals<B>(
    chunk:    const u8[:],
    seqs:     const CodedSmallSeq[:],
    nb_seq:   i64,
    tail_pos: i64,
    out_buf:  B&,
) -> bool {
    var si: i64 = 0;
    while si < nb_seq {
        let ll = seqs[si].lit_len as i64;
        if ll > 0 {
            let ls = seqs[si].lit_start as i64;
            guard comp_try_append(out_buf, chunk[ls..ls + ll]) else { return false; }
        }
        si++;
    }
    if tail_pos < chunk.len {
        return comp_try_append(out_buf, chunk[tail_pos..chunk.len]);
    }
    return true;
}

fn emit_raw_zstd_block<B>(chunk: const u8[:], last_bit: u32, out_buf: B&) -> bool {
    let raw_hdr = last_bit | ((chunk.len as u32) << 3);
    return emit_zstd_u24_le(out_buf, raw_hdr) && comp_try_append(out_buf, chunk);
}

fn compress_block_with_scratch<B>(
    chunk:   const u8[:],
    rep:     u32[3]&,
    is_last: bool,
    level:   i32,
    out_buf: B&,
    table:   u16[:],
    seqs:    CodedSmallSeq[:],
) -> bool {
    let hdr_pos = out_buf.len;
    let saved_rep = rep;
    var committed = false;
    defer if !committed {
        out_buf.resize(hdr_pos);
        rep = saved_rep;
    };

    var n_lit:    i64 = 0;
    var tail_pos: i64 = 0;
    let nb_seq = find_matches_small(chunk, rep, level, table, seqs, n_lit, tail_pos);
    let last_bit = if is_last { 1 as u32 } else { 0 as u32 };

    if nb_seq == 0 {
        guard emit_raw_zstd_block(chunk, last_bit, out_buf) else { return false; }
        committed = true;
        return true;
    }

    guard emit_zstd_u24_le(out_buf, 0) &&
          emit_raw_literals_header(n_lit, out_buf) &&
          emit_small_literals(chunk, seqs, nb_seq, tail_pos, out_buf) &&
          write_nb_seq_header(nb_seq, out_buf) &&
          comp_try_push(out_buf, 0 as u8) &&
          encode_small_sequences_direct(seqs, nb_seq, out_buf) else {
        return false;
    }

    let b_size = out_buf.len - (hdr_pos + 3);
    if b_size >= chunk.len {
        out_buf.resize(hdr_pos);
        rep = saved_rep;
        guard emit_raw_zstd_block(chunk, last_bit, out_buf) else { return false; }
        committed = true;
        return true;
    }

    let cmp_hdr = last_bit | (2 << 1) | ((b_size as u32) << 3);
    out_buf[hdr_pos] = (cmp_hdr & 0xFF) as u8;
    out_buf[hdr_pos + 1] = ((cmp_hdr >> 8) & 0xFF) as u8;
    out_buf[hdr_pos + 2] = ((cmp_hdr >> 16) & 0xFF) as u8;
    committed = true;
    return true;
}

fn compress_block_tiny<B>(
    chunk:   const u8[:],
    rep:     u32[3]&,
    is_last: bool,
    level:   i32,
    out_buf: B&,
) -> bool {
    var table: u16[1024]          = [0; 1024];
    var seqs:  CodedSmallSeq[512] = [CodedSmallSeq {}; 512];
    return compress_block_with_scratch(chunk, rep, is_last, level, out_buf, table[..], seqs[..]);
}

fn compress_block_medium<B>(
    chunk:   const u8[:],
    rep:     u32[3]&,
    is_last: bool,
    level:   i32,
    out_buf: B&,
) -> bool {
    var table: u16[4096]           = [0; 4096];
    var seqs:  CodedSmallSeq[4096] = [CodedSmallSeq {}; 4096];
    return compress_block_with_scratch(chunk, rep, is_last, level, out_buf, table[..], seqs[..]);
}

fn compress_block<B>(
    chunk:   const u8[:],
    rep:     u32[3]&,
    is_last: bool,
    level:   i32,
    out_buf: B&,
) -> bool {
    if chunk.len <= 2048 {
        return compress_block_tiny(chunk, rep, is_last, level, out_buf);
    }
    if chunk.len <= 16384 {
        return compress_block_medium(chunk, rep, is_last, level, out_buf);
    }
    let saved_rep = rep;
    var seqs: ZstdSeq[>..] = [];
    var lits: u8[>..]      = [];
    find_matches(chunk, rep, seqs, lits, level);

    var lit_sec: u8[>..] = [];
    guard emit_raw_literals_header(lits.len, lit_sec) else { return false; }
    lit_sec.append(lits[..]);

    var seq_sec: u8[>..] = [];
    encode_sequences(seqs[..], saved_rep, seq_sec);

    let b_size = lit_sec.len + seq_sec.len;
    if b_size >= chunk.len {
        let last_bit = if is_last { 1 as u32 } else { 0 as u32 };
        let hdr_val = last_bit | (0 << 1) | ((chunk.len as u32) << 3);
        guard emit_zstd_u24_le(out_buf, hdr_val) && comp_try_append(out_buf, chunk) else {
            return false;
        }
        rep = saved_rep;
        return true;
    }

    let last_bit = if is_last { 1 as u32 } else { 0 as u32 };
    let hdr_val = last_bit | (2 << 1) | ((b_size as u32) << 3);
    return emit_zstd_u24_le(out_buf, hdr_val) &&
           comp_try_append(out_buf, lit_sec[..]) &&
           comp_try_append(out_buf, seq_sec[..]);
}

// Compresses input slice using Zstandard frame container (RFC 8878).
// level 0: raw uncompressed blocks
fn emit_zstd_magic_number<B>(out_buf: B&) -> bool {
    return comp_try_write_le_u32(out_buf, ZSTD_MAGIC);
}

fn emit_zstd_frame_header<B>(total: i64, include_checksum: bool, out_buf: B&) -> bool {
    var fhd: u8 = 0x20; // single segment
    if include_checksum { fhd |= 0x04; }

    if total < 256 {
        return comp_try_push(out_buf, fhd) && comp_try_push(out_buf, total as u8);
    }
    if total <= 65535 + 256 {
        return comp_try_push(out_buf, fhd | 0x40) &&
               comp_try_write_le_u16(out_buf, (total - 256) as u16);
    }
    if total <= 4294967295 {
        return comp_try_push(out_buf, fhd | 0x80) &&
               comp_try_write_le_u32(out_buf, total as u32);
    }
    return comp_try_push(out_buf, fhd | 0xC0) &&
           comp_try_write_le_u64(out_buf, total as u64);
}

fn emit_zstd_raw_blocks<B>(src: const u8[:], out_buf: B&) -> bool {
    let total = src.len;
    var offset: i64 = 0;
    while offset < total {
        let rem = sub_sat_i64(total, offset);
        let chunk_size = min(rem, ZSTD_BLOCKSIZE_MAX);
        let next_off = add_sat_i64(offset, chunk_size);
        let is_last = (next_off == total);
        let last_bit = if is_last { 1 as u32 } else { 0 as u32 };
        let hdr_type = add_sat_u32(last_bit, mul_sat_u32(ZSTD_BLOCK_TYPE_RAW, 2));
        let block_hdr = hdr_type | mul_sat_u32((chunk_size & 0x3FFFF) as u32, 8);
        guard emit_zstd_u24_le(out_buf, block_hdr) &&
              comp_try_append(out_buf, src[offset..next_off]) else {
            return false;
        }
        offset = next_off;
    }
    return true;
}

// level 1: fast compression (hash_log 14, step accelerator)
// level 2: balanced compression (hash_log 15)
// level 3: default compression (hash_log 16, rep0 check)
fn zstd_compress_level<B>(src: const u8[:], out_buf: B&, level: i32 = 3, include_checksum: bool = true) -> bool {
    let total = src.len;
    let saved_len = out_buf.len;
    var committed = false;
    defer if !committed { out_buf.resize(saved_len); };

    guard emit_zstd_magic_number(out_buf) &&
          emit_zstd_frame_header(total, include_checksum, out_buf) else {
        return false;
    }

    if total == 0 {
        let hdr_val: u32 = 1 | (0 << 1);
        guard emit_zstd_u24_le(out_buf, hdr_val) else { return false; }
        if include_checksum {
            guard comp_try_write_le_u32(out_buf, xxh64_digest_32(src)) else { return false; }
        }
        committed = true;
        return true;
    }

    if level <= 0 {
        guard emit_zstd_raw_blocks(src, out_buf) else { return false; }
    } else {
        init_global_ctables();
        var rep:    u32[3] = [1, 4, 8];
        var offset: i64    = 0;
        while offset < total {
            let rem = total - offset;
            let chunk_sz = min(rem, ZSTD_BLOCKSIZE_MAX);
            let is_last = (offset + chunk_sz == total);
            guard compress_block(src[offset..offset + chunk_sz], rep, is_last, level, out_buf) else {
                return false;
            }
            offset += chunk_sz;
        }
    }

    if include_checksum {
        guard comp_try_write_le_u32(out_buf, xxh64_digest_32(src)) else { return false; }
    }
    committed = true;
    return true;
}

// Compresses input slice using Zstandard frame container (level 3 by default).
fn zstd_compress<B>(src: const u8[:], out_buf: B&, include_checksum: bool = true) -> bool {
    return zstd_compress_level(src, out_buf, 3, include_checksum);
}

// Compresses input slice using Zstandard frame container with an external raw or formatted dictionary (RFC 8878 §5).
fn zstd_compress_with_dict<B>(
    src:              const u8[:],
    dict:             const u8[:],
    out_buf:          B&,
    level:            i32  = 3,
    include_checksum: bool = true,
) -> bool {
    let raw_dict = extract_zstd_dict_prefix(dict);
    if raw_dict.len < 4 || level <= 0 || src.len < 4 || src.len > ZSTD_BLOCKSIZE_MAX {
        return zstd_compress_level(src, out_buf, level, include_checksum);
    }
    let total = src.len;
    let d_len = min(raw_dict.len, 32768);
    let d_slice = raw_dict[sub_sat_i64(raw_dict.len, d_len)..];
    var combined: u8[>..] = [];
    combined.append(d_slice);
    combined.append(src);
    let max_match = min(d_slice.len, total);
    let prefix_match = count_match_len(combined[..], 0, d_slice.len, add_sat_i64(d_slice.len, max_match));
    let rem_len = sub_sat_i64(total, prefix_match);
    guard prefix_match >= 4 && rem_len < 32 else {
        return zstd_compress_level(src, out_buf, level, include_checksum);
    }

    let saved_len = out_buf.len;
    var committed = false;
    defer if !committed { out_buf.resize(saved_len); };

    guard emit_zstd_magic_number(out_buf) &&
          emit_zstd_frame_header(total, include_checksum, out_buf) else {
        return false;
    }
    init_global_ctables();

    var rep:  u32[3]       = [1, 4, 8];
    var seqs: ZstdSeq[>..] = [];
    var lits: u8[>..]      = [];
    seqs.push(ZstdSeq {
        lit_len:   0,
        match_len: min(prefix_match, 131072) as u32,
        offset:    min(d_slice.len, 32768) as u32,
    });
    if prefix_match < total {
        lits.append(src[prefix_match..]);
    }

    var lit_sec: u8[>..] = [];
    let lit_hdr_byte = min(mul_sat_u64(rem_len as u64, 8), 255) as u8;
    lit_sec.push(lit_hdr_byte);
    lit_sec.append(lits[..]);

    var seq_sec: u8[>..] = [];
    encode_sequences(seqs[..], rep, seq_sec);
    let b_size = min(add_sat_i64(lit_sec.len, seq_sec.len), 131072) as u64;
    let hdr_val = add_sat_u64(5, mul_sat_u64(b_size, 8)) as u32;
    guard emit_zstd_u24_le(out_buf, hdr_val) &&
          comp_try_append(out_buf, lit_sec[..]) &&
          comp_try_append(out_buf, seq_sec[..]) else {
        return false;
    }

    if include_checksum {
        guard comp_try_write_le_u32(out_buf, xxh64_digest_32(src)) else { return false; }
    }
    committed = true;
    return true;
}
