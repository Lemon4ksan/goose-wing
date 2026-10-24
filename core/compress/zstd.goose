// The Goose Zstandard (zstd) decompression engine: RFC 8878 Specification.
// Clean-Room Native Implementation with zero dynamic heap allocations in inner loop.
namespace core;

import std;
import core.math.bits;
import core.compress.checksum;
import core.compress.deflate;

// ---- rfc 8878 constants ---------------------------------------------------

const ZSTD_MAGIC: u32 = 0xFD2FB528;
const ZSTD_MAGIC_SKIPPABLE_START: u32 = 0x184D2A50;
const ZSTD_MAGIC_SKIPPABLE_END: u32 = 0x184D2A5F;
const ZSTD_BLOCKSIZE_MAX: i64 = 131072; // 128 KB

const ZSTD_BLOCK_TYPE_RAW: u32 = 0;
const ZSTD_BLOCK_TYPE_RLE: u32 = 1;
const ZSTD_BLOCK_TYPE_COMPRESSED: u32 = 2;
const ZSTD_BLOCK_TYPE_RESERVED: u32 = 3;

// ---- sequence codes lookup tables (rfc 8878 tables 16 & 17) ---------------

const LL_BASE: u32[64] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    16, 18, 20, 22, 24, 28, 32, 40, 48, 64, 128, 256, 512, 1024,
    2048, 4096, 8192, 16384, 32768, 65536,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
];

const LL_EXTRA_BITS: u8[64] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10,
    11, 12, 13, 14, 15, 16,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
];

const ML_BASE: u32[64] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
    19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34,
    35, 37, 39, 41, 43, 47, 51, 59, 67, 83, 99, 131, 259, 515,
    1027, 2051, 4099, 8195, 16387, 32771, 65539,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
];

const ML_EXTRA_BITS: u8[64] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 7, 8, 9,
    10, 11, 12, 13, 14, 15, 16,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
];

// Predefined FSE normalized distributions (RFC 8878 section 3.1.1.3.2.2)
const LL_DEFAULT_DIST: i16[36] = [
    4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1,
    -1, -1, -1, -1
];

const ML_DEFAULT_DIST: i16[53] = [
    1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1,
    -1, -1, -1, -1, -1
];

const OF_DEFAULT_DIST: i16[29] = [
    1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1
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
    src: const u8[:] = "",
    bit_pos: i64 = 0,
    underflow: bool = false,
    cache_offset: i64 = -1,
    cache_chunk: u64 = 0,
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
        src: src,
        bit_pos: total_bits,
        underflow: false,
        cache_offset: -1,
        cache_chunk: 0,
    };
}

fn zstd_peek_bits(r: ZstdBitReader&, n: i32) -> u32 {
    if n <= 0 || r.bit_pos <= 0 { return 0; }
    if r.bit_pos < n {
        let rem_bits = r.bit_pos;
        var chunk: u64 = 0;
        let rem = r.src.len;
        if rem >= 8 {
            let b0 = r.src[0] as u64;
            let b1 = r.src[1] as u64;
            let b2 = r.src[2] as u64;
            let b3 = r.src[3] as u64;
            let b4 = r.src[4] as u64;
            let b5 = r.src[5] as u64;
            let b6 = r.src[6] as u64;
            let b7 = r.src[7] as u64;
            chunk = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24) | (b4 << 32) | (b5 << 40) | (b6 << 48) | (b7 << 56);
        } else {
            var i: i64 = 0;
            while i < rem {
                chunk |= (r.src[i] as u64) << ((i * 8) as u64);
                i++;
            }
        }
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
        var new_offset = if byte_offset >= 4 { byte_offset - 4 } else { 0 };
        if new_offset + 8 > r.src.len {
            new_offset = if r.src.len >= 8 { r.src.len - 8 } else { 0 };
        }
        let rem = r.src.len - new_offset;
        if rem >= 8 {
            let b0 = r.src[new_offset] as u64;
            let b1 = r.src[new_offset + 1] as u64;
            let b2 = r.src[new_offset + 2] as u64;
            let b3 = r.src[new_offset + 3] as u64;
            let b4 = r.src[new_offset + 4] as u64;
            let b5 = r.src[new_offset + 5] as u64;
            let b6 = r.src[new_offset + 6] as u64;
            let b7 = r.src[new_offset + 7] as u64;
            chunk = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24) | (b4 << 32) | (b5 << 40) | (b6 << 48) | (b7 << 56);
            r.cache_offset = new_offset;
            r.cache_chunk = chunk;
        } else {
            var i: i64 = 0;
            while i < rem {
                chunk |= (r.src[new_offset + i] as u64) << ((i * 8) as u64);
                i++;
            }
            r.cache_offset = new_offset;
            r.cache_chunk = chunk;
        }
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
    src: const u8[:] = "",
    byte_idx: i64 = 0,
    bit_count: i32 = 0,
    bit_buf: u64 = 0,
}

fn fwd_refill(r: ForwardBitReader&) {
    while r.bit_count <= 56 && r.byte_idx < r.src.len {
        r.bit_buf |= (r.src[r.byte_idx] as u64) << (r.bit_count as u64);
        r.byte_idx++;
        r.bit_count += 8;
    }
}

fn new_forward_bit_reader(src: const u8[:], start_offset: i64) -> ForwardBitReader {
    var r = ForwardBitReader {
        src: src,
        byte_idx: start_offset,
        bit_count: 0,
        bit_buf: 0,
    };
    fwd_refill(r);
    return r;
}

fn fwd_peek(r: ForwardBitReader&, n: i32) -> u32 {
    if r.bit_count < n {
        fwd_refill(r);
    }
    let mask = ((1 as u64) << (n as u64)) - 1;
    return (r.bit_buf & mask) as u32;
}

fn fwd_consume(r: ForwardBitReader&, n: i32) {
    r.bit_buf >>= (n as u64);
    r.bit_count -= n;
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
    base_val: u32 = 0,
    new_state: u16 = 0,
    nb_bits: u8 = 0,
    extra_bits: u8 = 0,
}

struct FseTable {
    entries: FseEntry[512] = [FseEntry {}; 512],
    table_log: i32 = 0,
    is_defined: bool = false,
}

struct HufWeightEntry {
    symbol: u8 = 0,
    nb_bits: u8 = 0,
    new_state: u16 = 0,
}

struct HufWeightTable {
    entries: HufWeightEntry[128] = [HufWeightEntry {}; 128],
    table_log: i32 = 0,
    is_defined: bool = false,
}

const EMPTY_HUF_TABLE: HufTable = HufTable {};
const EMPTY_FSE_TABLE: FseTable = FseTable {};
const EMPTY_HUF_WEIGHT_TABLE: HufWeightTable = HufWeightTable {};

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
inline fn fse_init_default_ll(out_table: FseTable&) {
out_table.table_log = 6;
out_table.is_defined = true;
for i in 64 { out_table.entries[i] = DEFAULT_LL_ENTRIES[i]; }
}
inline fn fse_init_default_of(out_table: FseTable&) {
out_table.table_log = 5;
out_table.is_defined = true;
for i in 32 { out_table.entries[i] = DEFAULT_OF_ENTRIES[i]; }
}
inline fn fse_init_default_ml(out_table: FseTable&) {
out_table.table_log = 6;
out_table.is_defined = true;
for i in 64 { out_table.entries[i] = DEFAULT_ML_ENTRIES[i]; }
}

fn fse_build_weight_dtable(counts: const i16[:], max_symbol: i32, table_log: i32, out_table: HufWeightTable&) -> bool {
    let table_size: i32 = (1 as i32) << table_log;
    if table_size > 128 || table_log < 1 {
        return false;
    }
    out_table.table_log = table_log;
    out_table.is_defined = true;

    var symbol_next: u16[256] = [0; 256];
    var high_threshold: i32 = table_size - 1;

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
                pos = (pos + step) & mask;
                while pos > high_threshold {
                    pos = (pos + step) & mask;
                }
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

fn fse_build_dtable(counts: const i16[:], max_symbol: i32, table_log: i32, out_table: FseTable&, table_kind: i32 = 0) -> bool {
    let table_size: i32 = (1 as i32) << table_log;
    if table_size > 512 || table_log < 1 {
        return false;
    }
    out_table.table_log = table_log;
    out_table.is_defined = true;

    var symbol_next: u16[256] = [0; 256];
    var table_symbols: u8[512] = [0; 512];
    var high_threshold: i32 = table_size - 1;

    // 1. Place low-probability (-1) symbols at the top of the table
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

    // 2. Spread normal symbols
    let step: i32 = (table_size >> 1) + (table_size >> 3) + 3;
    let mask: i32 = table_size - 1;
    var pos: i32 = 0;

    s = 0;
    while s <= max_symbol {
        if counts[s] > 0 {
            var i: i32 = 0;
            while i < counts[s] {
                table_symbols[pos] = s as u8;
                pos = (pos + step) & mask;
                while pos > high_threshold {
                    pos = (pos + step) & mask;
                }
                i++;
            }
        }
        s++;
    }
    if pos != 0 {
        return false; // Distribution did not fill table cleanly
    }

    // 3. Build decoding table
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

fn fse_read_ncount(src: const u8[:], offset: i64&, counts: i16[:], max_symbol: i32&, table_log: i32&) -> bool {
    var r = new_forward_bit_reader(src, offset);
    let low4 = fwd_read(r, 4);
    let log = (low4 + 5) as i32;
    if log > 9 {
        return false;
    }
    table_log = log;

    var remaining: i32 = ((1 as i32) << log) + 1;
    var threshold: i32 = (1 as i32) << log;
    var nb_bits: i32 = log + 1;
    var char_num: i32 = 0;
    var previous0: bool = false;

    while remaining > 1 && char_num <= 255 {
        if previous0 {
            var repeats: i32 = 0;
            while true {
                let code = fwd_peek(r, 2);
                if code == 3 {
                    repeats += 3;
                    fwd_consume(r, 2);
                } else {
                    repeats += code as i32;
                    fwd_consume(r, 2);
                    break;
                }
            }
            while repeats > 0 && char_num <= 255 {
                counts[char_num] = 0;
                char_num++;
                repeats--;
            }
            if remaining <= 1 || char_num > 255 {
                break;
            }
        }

        let max_val: i32 = (2 * threshold - 1) - remaining;
        var count: i32 = 0;
        let peek_val = fwd_peek(r, nb_bits);
        let peek_short = peek_val & ((threshold - 1) as u32);

        if peek_short < (max_val as u32) {
            count = peek_short as i32;
            fwd_consume(r, nb_bits - 1);
        } else {
            count = (peek_val & ((2 * threshold - 1) as u32)) as i32;
            if count >= threshold {
                count -= max_val;
            }
            fwd_consume(r, nb_bits);
        }

        count--; // prob = count - 1
        if count >= 0 {
            remaining -= count;
        } else {
            remaining += count; // -1 counts as 1 point
        }
        counts[char_num] = count as i16;
        char_num++;
        previous0 = (count == 0);

        while remaining < threshold && threshold > 1 {
            if remaining <= 1 { break; }
            nb_bits = zstd_high_bit(remaining as u32) + 1;
            threshold = (1 as i32) << (nb_bits - 1);
        }
    }

    if remaining != 1 {
        return false;
    }
    max_symbol = char_num - 1;
    offset = fwd_bytes_consumed(r);
    return true;
}

// ---- huffman structures & decoding (rfc 8878 section 4.2) ------------------

struct HufEntry {
    symbol: u8 = 0,
    nb_bits: u8 = 0,
}

struct HufTable {
    entries: HufEntry[2048] = [HufEntry {}; 2048],
    table_log: i32 = 0,
    is_defined: bool = false,
}

fn huf_build_dtable(weights: const u8[:], num_symbols: i32, max_table_log: i32, out_table: HufTable&) -> bool {
    var rank_val: u32[13] = [0; 13];
    var weight_total: u32 = 0;

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
    var next_rank: u32 = 0;
    var w: i32 = 1;
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
    var entry_idx: i32 = 0;
    var sym_pos: i32 = 0;
    w = 1;
    while w <= table_log {
        let count = rank_val[w] as i32;
        let rep_len = (1 << w) >> 1;
        let nb_bits = (table_log + 1 - w) as u8;

        var i: i32 = 0;
        while i < count {
            let sym = sorted_symbols[sym_pos];
            sym_pos++;
            var k: i32 = 0;
            while k < rep_len {
                out_table.entries[entry_idx] = HufEntry { symbol: sym, nb_bits: nb_bits };
                entry_idx++;
                k++;
            }
            i++;
        }
        w++;
    }

    return true;
}

fn huf_read_table(src: const u8[:], offset: i64&, table: HufTable&) -> bool {
    if offset >= src.len { return false; }
    let header_byte = src[offset];
    offset++;

    var weights: u8[256] = [0; 256];
    var num_symbols: i32 = 0;

    if header_byte >= 128 {
        // Direct 4-bit representation
        num_symbols = header_byte - 127;
        let num_bytes = (num_symbols + 1) / 2;
        if offset + num_bytes > src.len { return false; }

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
    } else {
        // FSE compressed weights
        let fse_size = header_byte as i64;
        if offset + fse_size > src.len { return false; }
        let fse_slice = src[offset .. offset + fse_size];
        offset += fse_size;

        var fse_counts: i16[256] = [0; 256];
        var fse_max_sym: i32 = 0;
        var fse_log: i32 = 0;
        var fse_offset: i64 = 0;
        if !fse_read_ncount(fse_slice, fse_offset, fse_counts[..], fse_max_sym, fse_log) {
            return false;
        }

        var weight_fse_table = EMPTY_HUF_WEIGHT_TABLE;
        if !fse_build_weight_dtable(fse_counts[..], fse_max_sym, fse_log, weight_fse_table) {
            return false;
        }

        let bit_slice = fse_slice[fse_offset..];
        var r = new_zstd_bit_reader(bit_slice);
        if r.underflow { return false; }

        var state1 = zstd_read_bits(r, weight_fse_table.table_log) as i64;
        var state2 = zstd_read_bits(r, weight_fse_table.table_log) as i64;

        while num_symbols < 255 {
            let e1 = weight_fse_table.entries[state1];
            weights[num_symbols] = e1.symbol;
            num_symbols++;
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
            state2 = (e2.new_state as i64) + zstd_read_bits(r, e2.nb_bits);
            if r.underflow {
                let e1_final = weight_fse_table.entries[state1];
                weights[num_symbols] = e1_final.symbol;
                num_symbols++;
                break;
            }
        }
    }

    // Determine last symbol weight
    var weight_total: u32 = 0;
    var i: i32 = 0;
    while i < num_symbols {
        let w = weights[i] as i32;
        if w > 0 {
            weight_total += (1 << w) >> 1;
        }
        i++;
    }
    let table_log = zstd_high_bit(weight_total) + 1;
    let total: u32 = (1 as u32) << (table_log as u32);
    let rest: u32 = total - weight_total;
    let last_weight = (zstd_high_bit(rest) + 1) as u8;
    weights[num_symbols] = last_weight;
    num_symbols++;

    return huf_build_dtable(weights[..num_symbols], num_symbols, 11, table);
}

fn huf_decode_stream_slice(r: ZstdBitReader&, table: const HufTable&, dst: u8[:]) -> bool {
    var decoded: i64 = 0;
    let count = dst.len;
    let mask = (1 << table.table_log) - 1;
    let t_log = table.table_log;
    let t_log_u32 = t_log as u32;
    let rshift = (64 - t_log_u32) as u64;

    if r.src.len >= 8 && !r.underflow && t_log > 0 {
        let last_byte = r.src[r.src.len - 1];
        let stop_bit = if last_byte != 0 { (8 - zstd_high_bit(last_byte)) as! u32 } else { 0 };

        var ptr: i64 = r.src.len - 8;
        var bit_consumed_init = stop_bit;
        if stop_bit == 8 && ptr > 0 {
            ptr--;
            bit_consumed_init = 0;
        }
        var bit_container = xxh64_read_le64(r.src, ptr);
        var bits_consumed: u32 = bit_consumed_init;

        // Fast 4x unrolled loop: 4 symbols * 11 max bits = 44 bits <= 57 available bits
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

            let sym32: u32 = e0.symbol |
                             ((e1.symbol as u32) << 8) |
                             ((e2.symbol as u32) << 16) |
                             ((e3.symbol as u32) << 24);
            write_le_u32_at(dst, decoded, sym32);
            decoded += 4;

            ptr -= bits_consumed >> 3;
            bits_consumed &= 7;
            bit_container = xxh64_read_le64(r.src, ptr);
        }

        while decoded < count {
            if bits_consumed > 32 && ptr > 0 {
                let avail = (bits_consumed >> 3) as i64;
                let shift_bytes = if ptr < avail { ptr } else { avail };
                ptr -= shift_bytes;
                bits_consumed -= (shift_bytes * 8) as u32;
                if ptr >= 0 && ptr <= r.src.len - 8 {
                    bit_container = xxh64_read_le64(r.src, ptr);
                }
            }

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
            return true;
        }

        // Synchronize fallback bit reader for remaining symbols
        let remaining_bits = if ptr == 0 {
            if 64 >= bits_consumed { (64 - bits_consumed) as i64 } else { 0 }
        } else {
            ptr * 8 + (64 - (bits_consumed as i64))
        };
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

    return decoded == count;
}

fn huf_decode_4streams(
    src1: const u8[:], src2: const u8[:], src3: const u8[:], src4: const u8[:],
    dst1: u8[:], dst2: u8[:], dst3: u8[:], dst4: u8[:],
    table: const HufTable&
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

    let last_b1 = src1[src1.len - 1];
    let last_b2 = src2[src2.len - 1];
    let last_b3 = src3[src3.len - 1];
    let last_b4 = src4[src4.len - 1];
    if last_b1 == 0 || last_b2 == 0 || last_b3 == 0 || last_b4 == 0 {
        return false;
    }

    let stop1 = (8 - zstd_high_bit(last_b1)) as u32;
    let stop2 = (8 - zstd_high_bit(last_b2)) as u32;
    let stop3 = (8 - zstd_high_bit(last_b3)) as u32;
    let stop4 = (8 - zstd_high_bit(last_b4)) as u32;

    var ptr1: i64 = src1.len - 8;
    var ptr2: i64 = src2.len - 8;
    var ptr3: i64 = src3.len - 8;
    var ptr4: i64 = src4.len - 8;

    var bits1 = stop1;
    if stop1 == 8 && ptr1 > 0 { ptr1--; bits1 = 0; }
    var bits2 = stop2;
    if stop2 == 8 && ptr2 > 0 { ptr2--; bits2 = 0; }
    var bits3 = stop3;
    if stop3 == 8 && ptr3 > 0 { ptr3--; bits3 = 0; }
    var bits4 = stop4;
    if stop4 == 8 && ptr4 > 0 { ptr4--; bits4 = 0; }

    var cont1: u64 = 0;
    if ptr1 >= 0 && ptr1 <= src1.len - 8 { cont1 = xxh64_read_le64(src1, ptr1); }
    var cont2: u64 = 0;
    if ptr2 >= 0 && ptr2 <= src2.len - 8 { cont2 = xxh64_read_le64(src2, ptr2); }
    var cont3: u64 = 0;
    if ptr3 >= 0 && ptr3 <= src3.len - 8 { cont3 = xxh64_read_le64(src3, ptr3); }
    var cont4: u64 = 0;
    if ptr4 >= 0 && ptr4 <= src4.len - 8 { cont4 = xxh64_read_le64(src4, ptr4); }

    var dec1: i64 = 0;
    var dec2: i64 = 0;
    var dec3: i64 = 0;
    var dec4: i64 = 0;

    let cnt1 = dst1.len;
    let cnt2 = dst2.len;
    let cnt3 = dst3.len;
    let cnt4 = dst4.len;

    while dec1 < cnt1 && dec2 < cnt2 && dec3 < cnt3 && dec4 < cnt4 {
        if bits1 > 32 {
            if ptr1 >= 8 {
                let s = (bits1 >> 3) as i64;
                ptr1 -= s;
                bits1 &= 7;
                if ptr1 >= 0 && ptr1 <= src1.len - 8 {
                    cont1 = xxh64_read_le64(src1, ptr1);
                }
            } else if ptr1 > 0 {
                let avail = (bits1 >> 3) as i64;
                let s = if ptr1 < avail { ptr1 } else { avail };
                ptr1 -= s;
                bits1 -= (s * 8) as u32;
                if ptr1 >= 0 && ptr1 <= src1.len - 8 {
                    cont1 = xxh64_read_le64(src1, ptr1);
                }
            }
        }
        if bits2 > 32 {
            if ptr2 >= 8 {
                let s = (bits2 >> 3) as i64;
                ptr2 -= s;
                bits2 &= 7;
                if ptr2 >= 0 && ptr2 <= src2.len - 8 {
                    cont2 = xxh64_read_le64(src2, ptr2);
                }
            } else if ptr2 > 0 {
                let avail = (bits2 >> 3) as i64;
                let s = if ptr2 < avail { ptr2 } else { avail };
                ptr2 -= s;
                bits2 -= (s * 8) as u32;
                if ptr2 >= 0 && ptr2 <= src2.len - 8 {
                    cont2 = xxh64_read_le64(src2, ptr2);
                }
            }
        }
        if bits3 > 32 {
            if ptr3 >= 8 {
                let s = (bits3 >> 3) as i64;
                ptr3 -= s;
                bits3 &= 7;
                if ptr3 >= 0 && ptr3 <= src3.len - 8 {
                    cont3 = xxh64_read_le64(src3, ptr3);
                }
            } else if ptr3 > 0 {
                let avail = (bits3 >> 3) as i64;
                let s = if ptr3 < avail { ptr3 } else { avail };
                ptr3 -= s;
                bits3 -= (s * 8) as u32;
                if ptr3 >= 0 && ptr3 <= src3.len - 8 {
                    cont3 = xxh64_read_le64(src3, ptr3);
                }
            }
        }
        if bits4 > 32 {
            if ptr4 >= 8 {
                let s = (bits4 >> 3) as i64;
                ptr4 -= s;
                bits4 &= 7;
                if ptr4 >= 0 && ptr4 <= src4.len - 8 {
                    cont4 = xxh64_read_le64(src4, ptr4);
                }
            } else if ptr4 > 0 {
                let avail = (bits4 >> 3) as i64;
                let s = if ptr4 < avail { ptr4 } else { avail };
                ptr4 -= s;
                bits4 -= (s * 8) as u32;
                if ptr4 >= 0 && ptr4 <= src4.len - 8 {
                    cont4 = xxh64_read_le64(src4, ptr4);
                }
            }
        }

        if bits1 + t_log_u32 > 64 || bits2 + t_log_u32 > 64 || bits3 + t_log_u32 > 64 || bits4 + t_log_u32 > 64 {
            break;
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
    }

    if dec1 < cnt1 {
        var r1 = new_zstd_bit_reader(src1);
        let rem1 = if ptr1 == 0 { if 64 >= bits1 { (64 - bits1) as i64 } else { 0 } } else { ptr1 * 8 + (64 - (bits1 as i64)) };
        r1.bit_pos = rem1;
        while dec1 < cnt1 && !r1.underflow {
            let bits = (zstd_peek_bits(r1, t_log) & ((1 << t_log) - 1)) & 2047;
            let entry = table.entries[bits];
            dst1[dec1] = entry.symbol;
            zstd_consume_bits(r1, entry.nb_bits);
            dec1++;
        }
    }
    if dec2 < cnt2 {
        var r2 = new_zstd_bit_reader(src2);
        let rem2 = if ptr2 == 0 { if 64 >= bits2 { (64 - bits2) as i64 } else { 0 } } else { ptr2 * 8 + (64 - (bits2 as i64)) };
        r2.bit_pos = rem2;
        while dec2 < cnt2 && !r2.underflow {
            let bits = (zstd_peek_bits(r2, t_log) & ((1 << t_log) - 1)) & 2047;
            let entry = table.entries[bits];
            dst2[dec2] = entry.symbol;
            zstd_consume_bits(r2, entry.nb_bits);
            dec2++;
        }
    }
    if dec3 < cnt3 {
        var r3 = new_zstd_bit_reader(src3);
        let rem3 = if ptr3 == 0 { if 64 >= bits3 { (64 - bits3) as i64 } else { 0 } } else { ptr3 * 8 + (64 - (bits3 as i64)) };
        r3.bit_pos = rem3;
        while dec3 < cnt3 && !r3.underflow {
            let bits = (zstd_peek_bits(r3, t_log) & ((1 << t_log) - 1)) & 2047;
            let entry = table.entries[bits];
            dst3[dec3] = entry.symbol;
            zstd_consume_bits(r3, entry.nb_bits);
            dec3++;
        }
    }
    if dec4 < cnt4 {
        var r4 = new_zstd_bit_reader(src4);
        let rem4 = if ptr4 == 0 { if 64 >= bits4 { (64 - bits4) as i64 } else { 0 } } else { ptr4 * 8 + (64 - (bits4 as i64)) };
        r4.bit_pos = rem4;
        while dec4 < cnt4 && !r4.underflow {
            let bits = (zstd_peek_bits(r4, t_log) & ((1 << t_log) - 1)) & 2047;
            let entry = table.entries[bits];
            dst4[dec4] = entry.symbol;
            zstd_consume_bits(r4, entry.nb_bits);
            dec4++;
        }
    }

    return dec1 == cnt1 && dec2 == cnt2 && dec3 == cnt3 && dec4 == cnt4;
}

// ---- literals section decoder (rfc 8878 section 3.1.1.3.1) ----------------

struct DecodedLiterals {
    ok: bool = false,
    slice: const u8[:] = "",
}

fn decode_literals(src: const u8[:], offset: i64&, block_end: i64, lit_buf: u8[>..]&, huf_table: HufTable&) -> DecodedLiterals {
    if offset >= block_end { return DecodedLiterals { ok: false }; }
    let header_byte = src[offset];
    let lit_type = header_byte & 3;
    let size_format = (header_byte >> 2) & 3;

    if lit_type == 0 || lit_type == 1 {
        // Raw or RLE Literals
        var lh_size: i64 = 1;
        var regenerated_size: i64 = 0;

        if size_format == 0 || size_format == 2 {
            lh_size = 1;
            regenerated_size = header_byte >> 3;
        } else if size_format == 1 {
            lh_size = 2;
            if offset + 2 > block_end { return DecodedLiterals { ok: false }; }
            let b0 = src[offset] as i64;
            let b1 = src[offset + 1] as i64;
            regenerated_size = (b0 >> 4) | (b1 << 4);
        } else {
            lh_size = 3;
            if offset + 3 > block_end { return DecodedLiterals { ok: false }; }
            let b0 = src[offset] as i64;
            let b1 = src[offset + 1] as i64;
            let b2 = src[offset + 2] as i64;
            regenerated_size = (b0 >> 4) | (b1 << 4) | (b2 << 12);
        }
        offset += lh_size;

        if lit_type == 0 {
            // Raw Literals: Zero copy directly from src!
            if offset + regenerated_size > block_end { return DecodedLiterals { ok: false }; }
            let lit_slice = src[offset .. offset + regenerated_size];
            offset += regenerated_size;
            return DecodedLiterals { ok: true, slice: lit_slice };
        } else {
            // RLE Literals
            if offset >= block_end { return DecodedLiterals { ok: false }; }
            let b = src[offset];
            offset++;
            lit_buf.clear();
            lit_buf.resize(regenerated_size, b);
            return DecodedLiterals { ok: true, slice: lit_buf[..] };
        }
    } else {
        // Compressed (2) or Treeless (3)
        if lit_type == 3 && !huf_table.is_defined {
            return DecodedLiterals { ok: false }; // Treeless without prior Huffman table
        }

        var lh_size: i64 = 3;
        var single_stream = false;
        var regenerated_size: i64 = 0;
        var compressed_size: i64 = 0;

        if size_format == 0 {
            single_stream = true;
            lh_size = 3;
            if offset + 3 > block_end { return DecodedLiterals { ok: false }; }
            let val = read_le_u24(src, offset);
            regenerated_size = (val >> 4) & 0x3FF;
            compressed_size = (val >> 14) & 0x3FF;
        } else if size_format == 1 {
            single_stream = false;
            lh_size = 3;
            if offset + 3 > block_end { return DecodedLiterals { ok: false }; }
            let val = read_le_u24(src, offset);
            regenerated_size = (val >> 4) & 0x3FF;
            compressed_size = (val >> 14) & 0x3FF;
        } else if size_format == 2 {
            single_stream = false;
            lh_size = 4;
            if offset + 4 > block_end { return DecodedLiterals { ok: false }; }
            let val = read_le_u32(src, offset);
            regenerated_size = (val >> 4) & 0x3FFF;
            compressed_size = (val >> 18) & 0x3FFF;
        } else {
            single_stream = false;
            lh_size = 5;
            if offset + 5 > block_end { return DecodedLiterals { ok: false }; }
            let val = read_le_u32(src, offset);
            let b4 = src[offset + 4] as u32;
            regenerated_size = (val >> 4) & 0x3FFFF;
            compressed_size = ((val >> 22) & 0x3FF) | (b4 << 10);
        }
        offset += lh_size;

        if offset + compressed_size > block_end { return DecodedLiterals { ok: false }; }
        let c_start = offset;
        let c_end = offset + compressed_size;

        if lit_type == 2 {
            // Read Huffman tree description
            if !huf_read_table(src, offset, huf_table) {
                return DecodedLiterals { ok: false };
            }
        }

        if lit_buf.len < regenerated_size {
            lit_buf.resize(regenerated_size, 0);
        }

        if single_stream {
            let stream_slice = src[offset .. c_end];
            var r = new_zstd_bit_reader(stream_slice);
            if !huf_decode_stream_slice(r, huf_table, lit_buf[0 .. regenerated_size]) {
                return DecodedLiterals { ok: false };
            }
        } else {
            // 4 streams: read 6-byte Jump Table
            if offset + 6 > c_end { return DecodedLiterals { ok: false }; }
            let s1 = read_le_u16(src, offset) as i64;
            let s2 = read_le_u16(src, offset + 2) as i64;
            let s3 = read_le_u16(src, offset + 4) as i64;
            offset += 6;

            let total_streams = c_end - offset;
            let s4 = total_streams - s1 - s2 - s3;
            if s4 < 0 { return DecodedLiterals { ok: false }; }

            let stream_size_chunk = (regenerated_size + 3) / 4;
            let c1 = stream_size_chunk;
            let c2 = c1 + stream_size_chunk;
            let c3 = c2 + stream_size_chunk;

            let o1 = offset;
            let o2 = o1 + s1;
            let o3 = o2 + s2;
            let o4 = o3 + s3;
            let o5 = o4 + s4;

            if c1 >= 0 && c2 >= c1 && c3 >= c2 && regenerated_size >= c3 && regenerated_size <= lit_buf.len &&
               o1 >= 0 && o2 >= o1 && o3 >= o2 && o4 >= o3 && o5 <= src.len {
                let dst1 = lit_buf[0 .. c1];
                let dst2 = lit_buf[c1 .. c2];
                let dst3 = lit_buf[c2 .. c3];
                let dst4 = lit_buf[c3 .. regenerated_size];

                let src1 = src[o1 .. o2];
                let src2 = src[o2 .. o3];
                let src3 = src[o3 .. o4];
                let src4 = src[o4 .. o5];

                if !huf_decode_4streams(src1, src2, src3, src4, dst1, dst2, dst3, dst4, huf_table) {
                    return DecodedLiterals { ok: false };
                }
            } else {
                return DecodedLiterals { ok: false };
            }
        }

        offset = c_end;
        return DecodedLiterals { ok: true, slice: lit_buf[0 .. regenerated_size] };
    }
}

// ---- sequences decoder & execution (rfc 8878 section 3.1.1.3.2) ------------

struct SequenceCmd {
    lit_len: u32 = 0,
    match_len: u32 = 0,
    offset: u32 = 0,
}

fn decode_sequences<B>(
    src: const u8[:],
    offset: i64&,
    block_end: i64,
    lit_buf: const u8[:],
    out_buf: B&,
    rep: u32[3]&,
    ll_table: FseTable&,
    ml_table: FseTable&,
    of_table: FseTable&,
    max_output_bytes: i64,
) -> CompressError {
    if offset >= block_end {
        // No sequences section: block is purely literals
        out_buf.append(lit_buf);
        return CompressError.None;
    }

    let b0 = src[offset];
    offset++;
    var nb_seq: i64 = 0;

    if b0 == 0 {
        // 0 sequences: remaining data is literals
        out_buf.append(lit_buf);
        return CompressError.None;
    } else if b0 < 128 {
        nb_seq = b0 as i64;
    } else if b0 < 255 {
        if offset >= block_end { return CompressError.InputBufferTruncated; }
        let b1 = src[offset] as i64;
        offset++;
        nb_seq = (((b0 as i64) - 128) << 8) + b1;
    } else {
        if offset + 2 > block_end { return CompressError.InputBufferTruncated; }
        let b1 = src[offset] as i64;
        let b2 = src[offset + 1] as i64;
        offset += 2;
        nb_seq = b1 + (b2 << 8) + 0x7F00;
    }

    if offset >= block_end { return CompressError.InputBufferTruncated; }
    let comp_modes = src[offset];
    offset++;

    let ll_mode = (comp_modes >> 6) & 3;
    let of_mode = (comp_modes >> 4) & 3;
    let ml_mode = (comp_modes >> 2) & 3;

    // Build or update LL table
    if ll_mode == 0 {
        fse_init_default_ll(ll_table);
    } else if ll_mode == 1 {
        // RLE: 1 byte symbol
        if offset >= block_end { return CompressError.InputBufferTruncated; }
        let sym = src[offset]; offset++;
        let idx = (sym & 63) as i64;
        ll_table.table_log = 0;
        ll_table.is_defined = true;
        ll_table.entries[0] = FseEntry {
            base_val: LL_BASE[idx],
            new_state: 0,
            nb_bits: 0,
            extra_bits: LL_EXTRA_BITS[idx],
        };
    } else if ll_mode == 2 {
        var counts: i16[256] = [0; 256];
        var max_sym: i32 = 0;
        var table_log: i32 = 0;
        if !fse_read_ncount(src, offset, counts[..], max_sym, table_log) {
            return CompressError.CorruptedBitstream;
        }
        if !fse_build_dtable(counts[..], max_sym, table_log, ll_table, 1) {
            return CompressError.CorruptedBitstream;
        }
    } else {
        if !ll_table.is_defined { return CompressError.CorruptedBitstream; }
    }

    // Build or update OF table
    if of_mode == 0 {
        fse_init_default_of(of_table);
    } else if of_mode == 1 {
        if offset >= block_end { return CompressError.InputBufferTruncated; }
        let sym = src[offset]; offset++;
        let sc = (sym & 31) as u32;
        of_table.table_log = 0;
        of_table.is_defined = true;
        of_table.entries[0] = FseEntry {
            base_val: (1 as u32) << sc,
            new_state: 0,
            nb_bits: 0,
            extra_bits: sc as u8,
        };
    } else if of_mode == 2 {
        var counts: i16[256] = [0; 256];
        var max_sym: i32 = 0;
        var table_log: i32 = 0;
        if !fse_read_ncount(src, offset, counts[..], max_sym, table_log) {
            return CompressError.CorruptedBitstream;
        }
        if !fse_build_dtable(counts[..], max_sym, table_log, of_table, 2) {
            return CompressError.CorruptedBitstream;
        }
    } else {
        if !of_table.is_defined { return CompressError.CorruptedBitstream; }
    }

    // Build or update ML table
    if ml_mode == 0 {
        fse_init_default_ml(ml_table);
    } else if ml_mode == 1 {
        if offset >= block_end { return CompressError.InputBufferTruncated; }
        let sym = src[offset]; offset++;
        let idx = (sym & 63) as i64;
        ml_table.table_log = 0;
        ml_table.is_defined = true;
        ml_table.entries[0] = FseEntry {
            base_val: ML_BASE[idx],
            new_state: 0,
            nb_bits: 0,
            extra_bits: ML_EXTRA_BITS[idx],
        };
    } else if ml_mode == 2 {
        var counts: i16[256] = [0; 256];
        var max_sym: i32 = 0;
        var table_log: i32 = 0;
        if !fse_read_ncount(src, offset, counts[..], max_sym, table_log) {
            return CompressError.CorruptedBitstream;
        }
        if !fse_build_dtable(counts[..], max_sym, table_log, ml_table, 3) {
            return CompressError.CorruptedBitstream;
        }
    } else {
        if !ml_table.is_defined { return CompressError.CorruptedBitstream; }
    }

    // Reverse bitstream for sequences
    let seq_bitstream = src[offset .. block_end];
    if seq_bitstream.len == 0 { return CompressError.CorruptedBitstream; }

    var r = new_zstd_bit_reader(seq_bitstream);
    if r.underflow { return CompressError.CorruptedBitstream; }

    var state_ll: i64 = 0;
    var state_of: i64 = 0;
    var state_ml: i64 = 0;

    let use_fast_dstream = seq_bitstream.len >= 8;
    var ptr: i64 = 0;
    var bit_container: u64 = 0;
    var bits_consumed: u32 = 0;

    if use_fast_dstream {
        ptr = seq_bitstream.len - 8;
        if ptr >= 0 && ptr <= seq_bitstream.len - 8 {
            bit_container = xxh64_read_le64(seq_bitstream, ptr);
        }
        let last_byte = seq_bitstream[seq_bitstream.len - 1];
        if last_byte == 0 { return CompressError.CorruptedBitstream; }
        let high_bit = zstd_high_bit(last_byte as u32);
        bits_consumed = (8 - high_bit) as u32;

        state_ll = ((bit_container << (bits_consumed & 63)) >> ((64 - ll_table.table_log) & 63)) as i64;
        bits_consumed += ll_table.table_log as u32;

        state_of = ((bit_container << (bits_consumed & 63)) >> ((64 - of_table.table_log) & 63)) as i64;
        bits_consumed += of_table.table_log as u32;

        state_ml = ((bit_container << (bits_consumed & 63)) >> ((64 - ml_table.table_log) & 63)) as i64;
        bits_consumed += ml_table.table_log as u32;
    } else {
        state_ll = zstd_read_bits(r, ll_table.table_log) as i64;
        state_of = zstd_read_bits(r, of_table.table_log) as i64;
        state_ml = zstd_read_bits(r, ml_table.table_log) as i64;
    }

    var lit_ptr: i64 = 0;
    var rep0 = rep[0];
    var rep1 = rep[1];
    var rep2 = rep[2];

    var of_entry = of_table.entries[state_of & 511];
    var ml_entry = ml_table.entries[state_ml & 511];
    var ll_entry = ll_table.entries[state_ll & 511];

    if use_fast_dstream {
        var seq_i: i64 = 0;
        while seq_i + 1 < nb_seq {
            // --- Sequence A ---
            let of_eb_A = of_entry.extra_bits as u32;
            let ml_eb_A = ml_entry.extra_bits as u32;
            let ll_eb_A = ll_entry.extra_bits as u32;

            var of_extra_A: u32 = 0;
            var ml_extra_A: u32 = 0;
            var ll_extra_A: u32 = 0;

            if bits_consumed > 32 {
                if ptr >= 8 {
                    let s = (bits_consumed >> 3) as i64;
                    ptr -= s;
                    bits_consumed &= 7;
                    if ptr >= 0 && ptr <= seq_bitstream.len - 8 {
                        bit_container = xxh64_read_le64(seq_bitstream, ptr);
                    }
                } else if ptr > 0 {
                    let avail = (bits_consumed >> 3) as i64;
                    let s = if ptr < avail { ptr } else { avail };
                    ptr -= s;
                    bits_consumed -= (s * 8) as u32;
                    if ptr >= 0 && ptr <= seq_bitstream.len - 8 {
                        bit_container = xxh64_read_le64(seq_bitstream, ptr);
                    }
                }
            }

            if of_eb_A > 0 {
                of_extra_A = zstd_extract_bits(bit_container, bits_consumed, of_eb_A);
                bits_consumed += of_eb_A;
            }
            if ml_eb_A > 0 {
                ml_extra_A = zstd_extract_bits(bit_container, bits_consumed, ml_eb_A);
                bits_consumed += ml_eb_A;
            }
            if ll_eb_A > 0 {
                ll_extra_A = zstd_extract_bits(bit_container, bits_consumed, ll_eb_A);
                bits_consumed += ll_eb_A;
            }

            let lit_len_A = ll_entry.base_val + ll_extra_A;
            let match_len_A = ml_entry.base_val + ml_extra_A;
            let offset_val_A = of_entry.base_val + of_extra_A;

            // FSE update for Sequence B
            if bits_consumed > 32 {
                if ptr >= 8 {
                    let s = (bits_consumed >> 3) as i64;
                    ptr -= s;
                    bits_consumed &= 7;
                    if ptr >= 0 && ptr <= seq_bitstream.len - 8 {
                        bit_container = xxh64_read_le64(seq_bitstream, ptr);
                    }
                } else if ptr > 0 {
                    let avail = (bits_consumed >> 3) as i64;
                    let s = if ptr < avail { ptr } else { avail };
                    ptr -= s;
                    bits_consumed -= (s * 8) as u32;
                    if ptr >= 0 && ptr <= seq_bitstream.len - 8 {
                        bit_container = xxh64_read_le64(seq_bitstream, ptr);
                    }
                }
            }

            let ll_nb_A = ll_entry.nb_bits as u32;
            let ll_bits_A = zstd_extract_bits(bit_container, bits_consumed, ll_nb_A) as i64;
            bits_consumed += ll_nb_A;
            state_ll = (ll_entry.new_state as i64) + ll_bits_A;

            let ml_nb_A = ml_entry.nb_bits as u32;
            let ml_bits_A = zstd_extract_bits(bit_container, bits_consumed, ml_nb_A) as i64;
            bits_consumed += ml_nb_A;
            state_ml = (ml_entry.new_state as i64) + ml_bits_A;

            let of_nb_A = of_entry.nb_bits as u32;
            let of_bits_A = zstd_extract_bits(bit_container, bits_consumed, of_nb_A) as i64;
            bits_consumed += of_nb_A;
            state_of = (of_entry.new_state as i64) + of_bits_A;

            of_entry = of_table.entries[state_of & 511];
            ml_entry = ml_table.entries[state_ml & 511];
            ll_entry = ll_table.entries[state_ll & 511];

            // Sequence A offset
            var offset_A: u32 = 0;
            if offset_val_A == 1 {
                if lit_len_A > 0 { offset_A = rep0; }
                else { offset_A = rep1; rep1 = rep0; rep0 = offset_A; }
            } else if offset_val_A > 3 {
                offset_A = offset_val_A - 3; rep2 = rep1; rep1 = rep0; rep0 = offset_A;
            } else if offset_val_A == 2 {
                if lit_len_A > 0 { offset_A = rep1; rep1 = rep0; rep0 = offset_A; }
                else { offset_A = rep2; rep2 = rep1; rep1 = rep0; rep0 = offset_A; }
            } else {
                if lit_len_A > 0 { offset_A = rep2; rep2 = rep1; rep1 = rep0; rep0 = offset_A; }
                else { offset_A = rep0 - 1; rep2 = rep1; rep1 = rep0; rep0 = offset_A; }
            }

            if max_output_bytes >= 0 {
                if (out_buf.len as i64) + (lit_len_A as i64) + (match_len_A as i64) > max_output_bytes {
                    return CompressError.OutputBufferOverflow;
                }
            }

            // Sequence A literals
            if lit_len_A == 1 {
                if lit_ptr >= 0 && lit_ptr < lit_buf.len {
                    out_buf.push(lit_buf[lit_ptr]);
                    lit_ptr++;
                } else { return CompressError.CorruptedBitstream; }
            } else if lit_len_A > 1 {
                let next_lit = lit_ptr + (lit_len_A as i64);
                if lit_ptr >= 0 && next_lit >= lit_ptr && next_lit <= lit_buf.len {
                    if lit_len_A == 2 {
                        out_buf.push(lit_buf[lit_ptr]);
                        out_buf.push(lit_buf[lit_ptr + 1]);
                    } else if lit_len_A == 3 {
                        out_buf.push(lit_buf[lit_ptr]);
                        out_buf.push(lit_buf[lit_ptr + 1]);
                        out_buf.push(lit_buf[lit_ptr + 2]);
                    } else if lit_len_A == 4 {
                        out_buf.push(lit_buf[lit_ptr]);
                        out_buf.push(lit_buf[lit_ptr + 1]);
                        out_buf.push(lit_buf[lit_ptr + 2]);
                        out_buf.push(lit_buf[lit_ptr + 3]);
                    } else {
                        out_buf.append(lit_buf[lit_ptr .. next_lit]);
                    }
                    lit_ptr = next_lit;
                } else { return CompressError.CorruptedBitstream; }
            }

            // Sequence A match
            if match_len_A > 0 {
                let off = offset_A as i64;
                let m_len = match_len_A as i64;
                let out_len = out_buf.len;
                if off <= 0 || off > out_len { return CompressError.DistanceOutOfBounds; }
                let src_idx = out_len - off;
                if off >= m_len {
                    let src_end = src_idx + m_len;
                    if src_idx >= 0 && src_end <= out_len {
                        out_buf.append(out_buf[src_idx .. src_end]);
                    } else { return CompressError.DistanceOutOfBounds; }
                } else if off == 1 {
                    if src_idx >= 0 && src_idx < out_len {
                        let b = out_buf[src_idx];
                        out_buf.resize(out_len + m_len, b);
                    } else { return CompressError.DistanceOutOfBounds; }
                } else {
                    var curr: i64 = 0;
                    while curr < m_len {
                        let avail = curr + off;
                        let rem = m_len - curr;
                        let step = if avail < rem { avail } else { rem };
                        out_buf.append(out_buf[src_idx .. src_idx + step]);
                        curr += step;
                    }
                }
            }

            // --- Sequence B ---
            let of_eb_B = of_entry.extra_bits as u32;
            let ml_eb_B = ml_entry.extra_bits as u32;
            let ll_eb_B = ll_entry.extra_bits as u32;

            var of_extra_B: u32 = 0;
            var ml_extra_B: u32 = 0;
            var ll_extra_B: u32 = 0;

            if bits_consumed > 32 {
                if ptr >= 8 {
                    let s = (bits_consumed >> 3) as i64;
                    ptr -= s;
                    bits_consumed &= 7;
                    if ptr >= 0 && ptr <= seq_bitstream.len - 8 {
                        bit_container = xxh64_read_le64(seq_bitstream, ptr);
                    }
                } else if ptr > 0 {
                    let avail = (bits_consumed >> 3) as i64;
                    let s = if ptr < avail { ptr } else { avail };
                    ptr -= s;
                    bits_consumed -= (s * 8) as u32;
                    if ptr >= 0 && ptr <= seq_bitstream.len - 8 {
                        bit_container = xxh64_read_le64(seq_bitstream, ptr);
                    }
                }
            }

            if of_eb_B > 0 {
                of_extra_B = zstd_extract_bits(bit_container, bits_consumed, of_eb_B);
                bits_consumed += of_eb_B;
            }
            if ml_eb_B > 0 {
                ml_extra_B = zstd_extract_bits(bit_container, bits_consumed, ml_eb_B);
                bits_consumed += ml_eb_B;
            }
            if ll_eb_B > 0 {
                ll_extra_B = zstd_extract_bits(bit_container, bits_consumed, ll_eb_B);
                bits_consumed += ll_eb_B;
            }

            let lit_len_B = ll_entry.base_val + ll_extra_B;
            let match_len_B = ml_entry.base_val + ml_extra_B;
            let offset_val_B = of_entry.base_val + of_extra_B;

            // FSE update for Sequence A (next iteration)
            if seq_i + 2 < nb_seq {
                if bits_consumed > 32 {
                    if ptr >= 8 {
                        let s = (bits_consumed >> 3) as i64;
                        ptr -= s;
                        bits_consumed &= 7;
                        if ptr >= 0 && ptr <= seq_bitstream.len - 8 {
                            bit_container = xxh64_read_le64(seq_bitstream, ptr);
                        }
                    } else if ptr > 0 {
                        let avail = (bits_consumed >> 3) as i64;
                        let s = if ptr < avail { ptr } else { avail };
                        ptr -= s;
                        bits_consumed -= (s * 8) as u32;
                        if ptr >= 0 && ptr <= seq_bitstream.len - 8 {
                            bit_container = xxh64_read_le64(seq_bitstream, ptr);
                        }
                    }
                }

                let ll_nb_B = ll_entry.nb_bits as u32;
                let ll_bits_B = zstd_extract_bits(bit_container, bits_consumed, ll_nb_B) as i64;
                bits_consumed += ll_nb_B;
                state_ll = (ll_entry.new_state as i64) + ll_bits_B;

                let ml_nb_B = ml_entry.nb_bits as u32;
                let ml_bits_B = zstd_extract_bits(bit_container, bits_consumed, ml_nb_B) as i64;
                bits_consumed += ml_nb_B;
                state_ml = (ml_entry.new_state as i64) + ml_bits_B;

                let of_nb_B = of_entry.nb_bits as u32;
                let of_bits_B = zstd_extract_bits(bit_container, bits_consumed, of_nb_B) as i64;
                bits_consumed += of_nb_B;
                state_of = (of_entry.new_state as i64) + of_bits_B;

                of_entry = of_table.entries[state_of & 511];
                ml_entry = ml_table.entries[state_ml & 511];
                ll_entry = ll_table.entries[state_ll & 511];
            }

            // Sequence B offset
            var offset_B: u32 = 0;
            if offset_val_B == 1 {
                if lit_len_B > 0 { offset_B = rep0; }
                else { offset_B = rep1; rep1 = rep0; rep0 = offset_B; }
            } else if offset_val_B > 3 {
                offset_B = offset_val_B - 3; rep2 = rep1; rep1 = rep0; rep0 = offset_B;
            } else if offset_val_B == 2 {
                if lit_len_B > 0 { offset_B = rep1; rep1 = rep0; rep0 = offset_B; }
                else { offset_B = rep2; rep2 = rep1; rep1 = rep0; rep0 = offset_B; }
            } else {
                if lit_len_B > 0 { offset_B = rep2; rep2 = rep1; rep1 = rep0; rep0 = offset_B; }
                else { offset_B = rep0 - 1; rep2 = rep1; rep1 = rep0; rep0 = offset_B; }
            }

            if max_output_bytes >= 0 {
                if (out_buf.len as i64) + (lit_len_B as i64) + (match_len_B as i64) > max_output_bytes {
                    return CompressError.OutputBufferOverflow;
                }
            }

            // Sequence B literals
            if lit_len_B == 1 {
                if lit_ptr >= 0 && lit_ptr < lit_buf.len {
                    out_buf.push(lit_buf[lit_ptr]);
                    lit_ptr++;
                } else { return CompressError.CorruptedBitstream; }
            } else if lit_len_B > 1 {
                let next_lit = lit_ptr + (lit_len_B as i64);
                if lit_ptr >= 0 && next_lit >= lit_ptr && next_lit <= lit_buf.len {
                    if lit_len_B == 2 {
                        out_buf.push(lit_buf[lit_ptr]);
                        out_buf.push(lit_buf[lit_ptr + 1]);
                    } else if lit_len_B == 3 {
                        out_buf.push(lit_buf[lit_ptr]);
                        out_buf.push(lit_buf[lit_ptr + 1]);
                        out_buf.push(lit_buf[lit_ptr + 2]);
                    } else if lit_len_B == 4 {
                        out_buf.push(lit_buf[lit_ptr]);
                        out_buf.push(lit_buf[lit_ptr + 1]);
                        out_buf.push(lit_buf[lit_ptr + 2]);
                        out_buf.push(lit_buf[lit_ptr + 3]);
                    } else {
                        out_buf.append(lit_buf[lit_ptr .. next_lit]);
                    }
                    lit_ptr = next_lit;
                } else { return CompressError.CorruptedBitstream; }
            }

            // Sequence B match
            if match_len_B > 0 {
                let off = offset_B as i64;
                let m_len = match_len_B as i64;
                let out_len = out_buf.len;
                if off <= 0 || off > out_len { return CompressError.DistanceOutOfBounds; }
                let src_idx = out_len - off;
                if off >= m_len {
                    let src_end = src_idx + m_len;
                    if src_idx >= 0 && src_end <= out_len {
                        out_buf.append(out_buf[src_idx .. src_end]);
                    } else { return CompressError.DistanceOutOfBounds; }
                } else if off == 1 {
                    if src_idx >= 0 && src_idx < out_len {
                        let b = out_buf[src_idx];
                        out_buf.resize(out_len + m_len, b);
                    } else { return CompressError.DistanceOutOfBounds; }
                } else {
                    var curr: i64 = 0;
                    while curr < m_len {
                        let avail = curr + off;
                        let rem = m_len - curr;
                        let step = if avail < rem { avail } else { rem };
                        out_buf.append(out_buf[src_idx .. src_idx + step]);
                        curr += step;
                    }
                }
            }

            seq_i += 2;
        }

        // Trailing odd sequence if nb_seq was odd
        while seq_i < nb_seq {
            let of_eb = of_entry.extra_bits as u32;
            let ml_eb = ml_entry.extra_bits as u32;
            let ll_eb = ll_entry.extra_bits as u32;

            var of_extra: u32 = 0;
            var ml_extra: u32 = 0;
            var ll_extra: u32 = 0;

            if bits_consumed > 32 {
                if ptr >= 8 {
                    let s = (bits_consumed >> 3) as i64;
                    ptr -= s;
                    bits_consumed &= 7;
                    if ptr >= 0 && ptr <= seq_bitstream.len - 8 {
                        bit_container = xxh64_read_le64(seq_bitstream, ptr);
                    }
                } else if ptr > 0 {
                    let avail = (bits_consumed >> 3) as i64;
                    let s = if ptr < avail { ptr } else { avail };
                    ptr -= s;
                    bits_consumed -= (s * 8) as u32;
                    if ptr >= 0 && ptr <= seq_bitstream.len - 8 {
                        bit_container = xxh64_read_le64(seq_bitstream, ptr);
                    }
                }
            }

            if of_eb > 0 {
                of_extra = zstd_extract_bits(bit_container, bits_consumed, of_eb);
                bits_consumed += of_eb;
            }
            if ml_eb > 0 {
                ml_extra = zstd_extract_bits(bit_container, bits_consumed, ml_eb);
                bits_consumed += ml_eb;
            }
            if ll_eb > 0 {
                ll_extra = zstd_extract_bits(bit_container, bits_consumed, ll_eb);
                bits_consumed += ll_eb;
            }

            let lit_len = ll_entry.base_val + ll_extra;
            let match_len = ml_entry.base_val + ml_extra;
            let offset_val = of_entry.base_val + of_extra;

            var offset: u32 = 0;
            if offset_val == 1 {
                if lit_len > 0 { offset = rep0; }
                else { offset = rep1; rep1 = rep0; rep0 = offset; }
            } else if offset_val > 3 {
                offset = offset_val - 3; rep2 = rep1; rep1 = rep0; rep0 = offset;
            } else if offset_val == 2 {
                if lit_len > 0 { offset = rep1; rep1 = rep0; rep0 = offset; }
                else { offset = rep2; rep2 = rep1; rep1 = rep0; rep0 = offset; }
            } else {
                if lit_len > 0 { offset = rep2; rep2 = rep1; rep1 = rep0; rep0 = offset; }
                else { offset = rep0 - 1; rep2 = rep1; rep1 = rep0; rep0 = offset; }
            }

            if max_output_bytes >= 0 {
                if (out_buf.len as i64) + (lit_len as i64) + (match_len as i64) > max_output_bytes {
                    return CompressError.OutputBufferOverflow;
                }
            }

            if lit_len == 1 {
                if lit_ptr >= 0 && lit_ptr < lit_buf.len {
                    out_buf.push(lit_buf[lit_ptr]);
                    lit_ptr++;
                } else { return CompressError.CorruptedBitstream; }
            } else if lit_len > 1 {
                let next_lit = lit_ptr + (lit_len as i64);
                if lit_ptr >= 0 && next_lit >= lit_ptr && next_lit <= lit_buf.len {
                    if lit_len == 2 {
                        out_buf.push(lit_buf[lit_ptr]);
                        out_buf.push(lit_buf[lit_ptr + 1]);
                    } else if lit_len == 3 {
                        out_buf.push(lit_buf[lit_ptr]);
                        out_buf.push(lit_buf[lit_ptr + 1]);
                        out_buf.push(lit_buf[lit_ptr + 2]);
                    } else if lit_len == 4 {
                        out_buf.push(lit_buf[lit_ptr]);
                        out_buf.push(lit_buf[lit_ptr + 1]);
                        out_buf.push(lit_buf[lit_ptr + 2]);
                        out_buf.push(lit_buf[lit_ptr + 3]);
                    } else {
                        out_buf.append(lit_buf[lit_ptr .. next_lit]);
                    }
                    lit_ptr = next_lit;
                } else { return CompressError.CorruptedBitstream; }
            }

            if match_len > 0 {
                let off = offset as i64;
                let m_len = match_len as i64;
                let out_len = out_buf.len;
                if off <= 0 || off > out_len { return CompressError.DistanceOutOfBounds; }
                let src_idx = out_len - off;
                if off >= m_len {
                    let src_end = src_idx + m_len;
                    if src_idx >= 0 && src_end <= out_len {
                        out_buf.append(out_buf[src_idx .. src_end]);
                    } else { return CompressError.DistanceOutOfBounds; }
                } else if off == 1 {
                    if src_idx >= 0 && src_idx < out_len {
                        let b = out_buf[src_idx];
                        out_buf.resize(out_len + m_len, b);
                    } else { return CompressError.DistanceOutOfBounds; }
                } else {
                    var curr: i64 = 0;
                    while curr < m_len {
                        let avail = curr + off;
                        let rem = m_len - curr;
                        let step = if avail < rem { avail } else { rem };
                        out_buf.append(out_buf[src_idx .. src_idx + step]);
                        curr += step;
                    }
                }
            }

            seq_i++;
        }
    } else {
        var seq_i: i64 = 0;
        while seq_i < nb_seq {
            let of_eb = of_entry.extra_bits as u32;
            let ml_eb = ml_entry.extra_bits as u32;
            let ll_eb = ll_entry.extra_bits as u32;

            let of_extra = if of_eb > 0 { zstd_read_bits(r, of_eb as i32) } else { 0 };
            let ml_extra = if ml_eb > 0 { zstd_read_bits(r, ml_eb as i32) } else { 0 };
            let ll_extra = if ll_eb > 0 { zstd_read_bits(r, ll_eb as i32) } else { 0 };

            let lit_len = ll_entry.base_val + ll_extra;
            let match_len = ml_entry.base_val + ml_extra;
            let offset_val = of_entry.base_val + of_extra;

            if seq_i + 1 < nb_seq {
                let ll_bits = if ll_entry.nb_bits > 0 { zstd_read_bits(r, ll_entry.nb_bits as i32) } else { 0 };
                state_ll = (ll_entry.new_state as i64) + (ll_bits as i64);

                let ml_bits = if ml_entry.nb_bits > 0 { zstd_read_bits(r, ml_entry.nb_bits as i32) } else { 0 };
                state_ml = (ml_entry.new_state as i64) + (ml_bits as i64);

                let of_bits = if of_entry.nb_bits > 0 { zstd_read_bits(r, of_entry.nb_bits as i32) } else { 0 };
                state_of = (of_entry.new_state as i64) + (of_bits as i64);

                of_entry = of_table.entries[state_of & 511];
                ml_entry = ml_table.entries[state_ml & 511];
                ll_entry = ll_table.entries[state_ll & 511];
            }

            var offset: u32 = 0;
            if offset_val == 1 {
                if lit_len > 0 {
                    offset = rep0;
                } else {
                    offset = rep1;
                    rep1 = rep0;
                    rep0 = offset;
                }
            } else if offset_val > 3 {
                offset = offset_val - 3;
                rep2 = rep1;
                rep1 = rep0;
                rep0 = offset;
            } else if offset_val == 2 {
                if lit_len > 0 {
                    offset = rep1;
                    rep1 = rep0;
                    rep0 = offset;
                } else {
                    offset = rep2;
                    rep2 = rep1;
                    rep1 = rep0;
                    rep0 = offset;
                }
            } else {
                if lit_len > 0 {
                    offset = rep2;
                    rep2 = rep1;
                    rep1 = rep0;
                    rep0 = offset;
                } else {
                    offset = rep0 - 1;
                    rep2 = rep1;
                    rep1 = rep0;
                    rep0 = offset;
                }
            }

            if max_output_bytes >= 0 {
                if (out_buf.len as i64) + (lit_len as i64) + (match_len as i64) > max_output_bytes {
                    return CompressError.OutputBufferOverflow;
                }
            }

            if lit_len == 1 {
                if lit_ptr >= 0 && lit_ptr < lit_buf.len {
                    out_buf.push(lit_buf[lit_ptr]);
                    lit_ptr++;
                } else {
                    return CompressError.CorruptedBitstream;
                }
            } else if lit_len > 1 {
                let next_lit = lit_ptr + (lit_len as i64);
                if lit_ptr >= 0 && next_lit >= lit_ptr && next_lit <= lit_buf.len {
                    if lit_len == 2 {
                        out_buf.push(lit_buf[lit_ptr]);
                        out_buf.push(lit_buf[lit_ptr + 1]);
                    } else if lit_len == 3 {
                        out_buf.push(lit_buf[lit_ptr]);
                        out_buf.push(lit_buf[lit_ptr + 1]);
                        out_buf.push(lit_buf[lit_ptr + 2]);
                    } else if lit_len == 4 {
                        out_buf.push(lit_buf[lit_ptr]);
                        out_buf.push(lit_buf[lit_ptr + 1]);
                        out_buf.push(lit_buf[lit_ptr + 2]);
                        out_buf.push(lit_buf[lit_ptr + 3]);
                    } else {
                        out_buf.append(lit_buf[lit_ptr .. next_lit]);
                    }
                    lit_ptr = next_lit;
                } else {
                    return CompressError.CorruptedBitstream;
                }
            }

            if match_len > 0 {
                let off = offset as i64;
                let m_len = match_len as i64;
                let out_len = out_buf.len;
                if off <= 0 || off > out_len {
                    return CompressError.DistanceOutOfBounds;
                }
                let src_idx = out_len - off;
                if off >= m_len {
                    let src_end = src_idx + m_len;
                    if src_idx >= 0 && src_end <= out_len {
                        out_buf.append(out_buf[src_idx .. src_end]);
                    } else {
                        return CompressError.DistanceOutOfBounds;
                    }
                } else if off == 1 {
                    if src_idx >= 0 && src_idx < out_len {
                        let b = out_buf[src_idx];
                        out_buf.resize(out_len + m_len, b);
                    } else {
                        return CompressError.DistanceOutOfBounds;
                    }
                } else {
                    var curr: i64 = 0;
                    while curr < m_len {
                        let avail = curr + off;
                        let rem = m_len - curr;
                        let step = if avail < rem { avail } else { rem };
                        out_buf.append(out_buf[src_idx .. src_idx + step]);
                        curr += step;
                    }
                }
            }

            seq_i++;
        }
    }

    rep[0] = rep0;
    rep[1] = rep1;
    rep[2] = rep2;

    // Append remaining literals
    if lit_ptr >= 0 && lit_ptr <= lit_buf.len {
        let rem_lit = lit_buf.len - lit_ptr;
        if rem_lit > 0 {
            if max_output_bytes >= 0 && (out_buf.len as i64) + rem_lit > max_output_bytes {
                return CompressError.OutputBufferOverflow;
            }
            out_buf.append(lit_buf[lit_ptr .. lit_buf.len]);
        }
    }

    offset = block_end;
    return CompressError.None;
}

// ---- frame decompressor (rfc 8878 section 3.1.1) ---------------------------

// Decompresses Zstandard frame from src into out_buf with output limit guard.
fn zstd_decompress_with_limit<B>(src: const u8[:], out_buf: B&, max_output_bytes: i64 = -1) -> CompressError {
    var offset: i64 = 0;
    let initial_out_len = out_buf.len;

    while offset < src.len {
        if offset + 4 > src.len { return CompressError.InputBufferTruncated; }
        let magic = xxh64_read_le32(src, offset);
        offset += 4;

        if magic >= ZSTD_MAGIC_SKIPPABLE_START && magic <= ZSTD_MAGIC_SKIPPABLE_END {
            if offset + 4 > src.len { return CompressError.InputBufferTruncated; }
            let skip_len = xxh64_read_le32(src, offset) as i64;
            offset += 4 + skip_len;
            continue;
        }

        if magic != ZSTD_MAGIC {
            return CompressError.InvalidHeader;
        }

        // Parse Frame Header Descriptor (FHD)
        if offset >= src.len { return CompressError.InputBufferTruncated; }
        let fhd = src[offset];
        offset++;

        let fcs_flag = (fhd >> 6) & 3;
        let single_segment = (fhd >> 5) & 1;
        let reserved_bit = (fhd >> 3) & 1;
        let content_checksum_flag = (fhd >> 2) & 1;
        let dict_id_flag = fhd & 3;

        if reserved_bit != 0 {
            return CompressError.InvalidHeader;
        }

        var window_size: i64 = 0;
        if single_segment == 0 {
            if offset >= src.len { return CompressError.InputBufferTruncated; }
            let wd = src[offset]; offset++;
            let exp = (wd >> 3) as i64;
            let mantissa = (wd & 7) as i64;
            let window_base = 1 as i64 << (10 + exp);
            let window_add = (window_base / 8) * mantissa;
            window_size = window_base + window_add;
        }

        if dict_id_flag == 1 {
            offset += 1;
        } else if dict_id_flag == 2 {
            offset += 2;
        } else if dict_id_flag == 3 {
            offset += 4;
        }

        var frame_content_size: i64 = -1;
        if single_segment == 1 {
            if fcs_flag == 0 {
                if offset >= src.len { return CompressError.InputBufferTruncated; }
                frame_content_size = src[offset] as i64; offset += 1;
            } else if fcs_flag == 1 {
                if offset + 2 > src.len { return CompressError.InputBufferTruncated; }
                frame_content_size = (src[offset] as i64) | ((src[offset + 1] as i64) << 8) + 256;
                offset += 2;
            } else if fcs_flag == 2 {
                if offset + 4 > src.len { return CompressError.InputBufferTruncated; }
                frame_content_size = xxh64_read_le32(src, offset) as i64;
                offset += 4;
            } else {
                if offset + 8 > src.len { return CompressError.InputBufferTruncated; }
                frame_content_size = xxh64_read_le64(src, offset) as i64;
                offset += 8;
            }
            window_size = frame_content_size;
        } else {
            if fcs_flag == 1 {
                if offset + 2 > src.len { return CompressError.InputBufferTruncated; }
                frame_content_size = (src[offset] as i64) | ((src[offset + 1] as i64) << 8) + 256;
                offset += 2;
            } else if fcs_flag == 2 {
                if offset + 4 > src.len { return CompressError.InputBufferTruncated; }
                frame_content_size = xxh64_read_le32(src, offset) as i64;
                offset += 4;
            } else if fcs_flag == 3 {
                if offset + 8 > src.len { return CompressError.InputBufferTruncated; }
                frame_content_size = xxh64_read_le64(src, offset) as i64;
                offset += 8;
            }
        }

        if frame_content_size >= 0 && max_output_bytes >= 0 && frame_content_size > max_output_bytes {
            return CompressError.OutputBufferOverflow;
        }

        // Initialize block state
        var rep: u32[3] = [1, 4, 8];
        var huf_table = EMPTY_HUF_TABLE;
        var ll_table = EMPTY_FSE_TABLE;
        var ml_table = EMPTY_FSE_TABLE;
        var of_table = EMPTY_FSE_TABLE;
        var lit_buf: u8[>..] = [];

        let frame_start_out = out_buf.len;
        var last_block = false;

        while !last_block {
            if offset + 3 > src.len { return CompressError.InputBufferTruncated; }
            let header_val = read_le_u24(src, offset);
            offset += 3;
            last_block = (header_val & 1) != 0;
            let block_type = (header_val >> 1) & 3;
            let block_size = (header_val >> 3) as i64;

            if block_type == ZSTD_BLOCK_TYPE_RESERVED {
                return CompressError.InvalidBlockType;
            }

            if block_size > ZSTD_BLOCKSIZE_MAX || offset + block_size > src.len {
                return CompressError.InputBufferTruncated;
            }
            let block_end = offset + block_size;

            if block_type == ZSTD_BLOCK_TYPE_RAW {
                if max_output_bytes >= 0 && (out_buf.len as i64) + block_size > max_output_bytes {
                    return CompressError.OutputBufferOverflow;
                }
                out_buf.append(src[offset .. block_end]);
                offset = block_end;
            } else if block_type == ZSTD_BLOCK_TYPE_RLE {
                if max_output_bytes >= 0 && (out_buf.len as i64) + block_size > max_output_bytes {
                    return CompressError.OutputBufferOverflow;
                }
                let rle_byte = src[offset];
                offset = block_end;
                out_buf.resize(out_buf.len + block_size, rle_byte);
            } else if block_type == ZSTD_BLOCK_TYPE_COMPRESSED {
                let lits = decode_literals(src, offset, block_end, lit_buf, huf_table);
                if !lits.ok {
                    return CompressError.CorruptedBitstream;
                }

                let seq_err = decode_sequences(
                    src,
                    offset,
                    block_end,
                    lits.slice,
                    out_buf,
                    rep,
                    ll_table,
                    ml_table,
                    of_table,
                    max_output_bytes,
                );
                if seq_err != CompressError.None {
                    return seq_err;
                }
            }
        }

        // Validate Content Checksum if present
        if content_checksum_flag != 0 {
            if offset + 4 > src.len { return CompressError.InputBufferTruncated; }
            let expected_chk = xxh64_read_le32(src, offset);
            offset += 4;

            let decoded_slice = out_buf[frame_start_out .. out_buf.len];
            let actual_chk = xxh64_digest_32(decoded_slice);
            if actual_chk != expected_chk {
                return CompressError.ChecksumMismatch;
            }
        }
    }

    return CompressError.None;
}

// Decompresses standard Zstandard frame from src into out_buf.
fn zstd_decompress<B>(src: const u8[:], out_buf: B&) -> CompressError {
    return zstd_decompress_with_limit(src, out_buf, -1);
}

// ---- native rfc 8878 zstandard compressor (levels 1-3) ---------------------

struct FseCTableEntry {
    next_state: u16 = 0,
    nb_bits: u8 = 0,
    bits: u16 = 0,
}

struct ZstdCTables {
    ll_table: FseCTableEntry[2304] = [FseCTableEntry {}; 2304],
    of_table: FseCTableEntry[928] = [FseCTableEntry {}; 928],
    ml_table: FseCTableEntry[3392] = [FseCTableEntry {}; 3392],
    ll_init: u16[36] = [0; 36],
    of_init: u16[29] = [0; 29],
    ml_init: u16[53] = [0; 53],
    is_init: bool = false,
}

var G_CTABLES: ZstdCTables = ZstdCTables {};

fn build_fse_ctable(
    d_entries: const FseEntry[:],
    table_size: i32,
    num_syms: i32,
    table_kind: i32,
    c_table: FseCTableEntry[:],
    init_states: u16[:]
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
                nb_bits: nb_bits as u8,
                bits: bits as u16,
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
    bit_container: u64 = 0,
    bit_count: u32 = 0,
    buf: u8[>..] = [],
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
    lit_len: u32 = 0,
    match_len: u32 = 0,
    offset: u32 = 0,
}

inline fn lit_len_to_code(lit_len: u32, code: u32&, extra: u32&, extra_bits: u32&) {
    var i: u32 = 0;
    while i < 35 {
        if lit_len >= LL_BASE[i] && lit_len < LL_BASE[i + 1] {
            code = i;
            extra = lit_len - LL_BASE[i];
            extra_bits = LL_EXTRA_BITS[i];
            return;
        }
        i++;
    }
    code = 35;
    extra = lit_len - LL_BASE[35];
    extra_bits = LL_EXTRA_BITS[35];
}

inline fn match_len_to_code(match_len: u32, code: u32&, extra: u32&, extra_bits: u32&) {
    var i: u32 = 0;
    while i < 52 {
        if match_len >= ML_BASE[i] && match_len < ML_BASE[i + 1] {
            code = i;
            extra = match_len - ML_BASE[i];
            extra_bits = ML_EXTRA_BITS[i];
            return;
        }
        i++;
    }
    code = 52;
    extra = match_len - ML_BASE[52];
    extra_bits = ML_EXTRA_BITS[52];
}

inline fn offset_to_code(offset: u32, lit_len: u32, rep: u32[3]&, code: u32&, extra: u32&, extra_bits: u32&) {
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

    bw_write_bits(bw, st_ml, 6);
    bw_write_bits(bw, st_of, 5);
    bw_write_bits(bw, st_ll, 6);
    bw_finish(bw);

    // Number_of_Sequences Header (RFC 8878 Section 3.1.1.3.2)
    if nb_seq < 128 {
        out_buf.push(nb_seq as u8);
    } else if nb_seq < 0x7F00 {
        out_buf.push(((nb_seq >> 8) + 128) as u8);
        out_buf.push((nb_seq & 0xFF) as u8);
    } else {
        out_buf.push(255);
        let rem = nb_seq - 0x7F00;
        out_buf.push((rem & 0xFF) as u8);
        out_buf.push(((rem >> 8) & 0xFF) as u8);
    }
    out_buf.push(0); // Symbol_Compression_Modes: predefined FSE distributions
    out_buf.append(bw.buf[..]);
}

fn find_matches(src: const u8[:], rep: u32[3]&, seqs: ZstdSeq[>..]&, lits: u8[>..]&, level: i32) {
    let hash_log = if level <= 1 { 14 } else if level == 2 { 15 } else { 16 };
    let hash_size = 1 << hash_log;
    var table: i32[65536] = [-1; 65536];

    let n = src.len;
    var anchor: i64 = 0;
    var curr: i64 = 0;

    while curr + 4 <= n {
        let v4 = xxh64_read_le32(src, curr);

        var match_len: i64 = 0;
        var offset: u32 = 0;

        // Check rep0 match for level >= 3
        if level >= 3 {
            let rep0 = rep[0] as i64;
            if rep0 > 0 && curr >= rep0 {
                let p_rep = curr - rep0;
                if xxh64_read_le32(src, p_rep) == v4 {
                    var m: i64 = 4;
                    while curr + m < n && src[p_rep + m] == src[curr + m] {
                        m++;
                    }
                    match_len = m;
                    offset = rep[0];
                }
            }
        }

        if match_len == 0 {
            let h = ((v4 * 2654435761) >> (32 - hash_log)) & ((hash_size - 1) as u32);
            let p = table[h as i64] as i64;
            table[h as i64] = curr as i32;

            if p >= 0 && (curr - p) <= 131072 {
                if xxh64_read_le32(src, p) == v4 {
                    var m: i64 = 4;
                    while curr + m < n && src[p + m] == src[curr + m] {
                        m++;
                    }
                    match_len = m;
                    offset = (curr - p) as u32;
                }
            }
        }

        if match_len >= 4 {
            let lit_len = (curr - anchor) as u32;
            if lit_len > 0 {
                lits.append(src[anchor .. curr]);
            }
            seqs.push(ZstdSeq { lit_len: lit_len, match_len: match_len as u32, offset: offset });

            // update rep
            if lit_len > 0 {
                if offset == rep[0] {
                } else if offset == rep[1] {
                    rep[1] = rep[0]; rep[0] = offset;
                } else if offset == rep[2] {
                    rep[2] = rep[1]; rep[1] = rep[0]; rep[0] = offset;
                } else {
                    rep[2] = rep[1]; rep[1] = rep[0]; rep[0] = offset;
                }
            } else {
                if offset == rep[1] {
                    rep[1] = rep[0]; rep[0] = offset;
                } else if offset == rep[2] {
                    rep[2] = rep[1]; rep[1] = rep[0]; rep[0] = offset;
                } else if offset == rep[0] - 1 {
                    rep[2] = rep[1]; rep[1] = rep[0]; rep[0] = offset;
                } else {
                    rep[2] = rep[1]; rep[1] = rep[0]; rep[0] = offset;
                }
            }

            anchor = curr + match_len;
            curr = anchor;
        } else {
            let step = if level <= 1 { 1 + ((curr - anchor) >> 8) } else { 1 };
            curr += step;
        }
    }

    if anchor < n {
        lits.append(src[anchor .. n]);
    }
}

fn compress_block<B>(chunk: const u8[:], rep: u32[3]&, is_last: bool, level: i32, out_buf: B&) {
    let saved_rep = rep;
    var seqs: ZstdSeq[>..] = [];
    var lits: u8[>..] = [];
    find_matches(chunk, rep, seqs, lits, level);

    var lit_sec: u8[>..] = [];
    let n_lit = lits.len;
    if n_lit < 32 {
        lit_sec.push(((n_lit << 3) | 0) as u8);
    } else if n_lit < 4096 {
        lit_sec.push((0 | (1 << 2) | ((n_lit & 0xF) << 4)) as u8);
        lit_sec.push(((n_lit >> 4) & 0xFF) as u8);
    } else {
        lit_sec.push((0 | (3 << 2) | ((n_lit & 0xF) << 4)) as u8);
        lit_sec.push(((n_lit >> 4) & 0xFF) as u8);
        lit_sec.push(((n_lit >> 12) & 0xFF) as u8);
    }
    lit_sec.append(lits[..]);

    var seq_sec: u8[>..] = [];
    encode_sequences(seqs[..], saved_rep, seq_sec);

    let b_size = lit_sec.len + seq_sec.len;
    if b_size >= chunk.len {
        // Raw block fallback
        let last_bit = if is_last { 1 as u32 } else { 0 as u32 };
        let hdr_val = last_bit | (0 << 1) | ((chunk.len as u32) << 3);
        out_buf.push((hdr_val & 0xFF) as u8);
        out_buf.push(((hdr_val >> 8) & 0xFF) as u8);
        out_buf.push(((hdr_val >> 16) & 0xFF) as u8);
        out_buf.append(chunk);
        rep = saved_rep;
        return;
    }

    let last_bit = if is_last { 1 as u32 } else { 0 as u32 };
    let hdr_val = last_bit | (2 << 1) | ((b_size as u32) << 3);
    out_buf.push((hdr_val & 0xFF) as u8);
    out_buf.push(((hdr_val >> 8) & 0xFF) as u8);
    out_buf.push(((hdr_val >> 16) & 0xFF) as u8);
    out_buf.append(lit_sec[..]);
    out_buf.append(seq_sec[..]);
}

// Compresses input slice using Zstandard frame container (RFC 8878).
// level 0: raw uncompressed blocks
// level 1: fast compression (hash_log 14, step accelerator)
// level 2: balanced compression (hash_log 15)
// level 3: default compression (hash_log 16, rep0 check)
fn zstd_compress_level<B>(src: const u8[:], out_buf: B&, level: i32 = 3, include_checksum: bool = true) -> bool {
    let total = src.len;

    // 1. Magic Number (0xFD2FB528 in little-endian)
    out_buf.push(0x28);
    out_buf.push(0xB5);
    out_buf.push(0x2F);
    out_buf.push(0xFD);

    // 2. Frame Header Descriptor (FHD)
    var fhd: u8 = 0x20; // single segment
    if include_checksum { fhd |= 0x04; }

    if total < 256 {
        out_buf.push(fhd);
        out_buf.push(total as u8);
    } else if total <= 65535 + 256 {
        out_buf.push(fhd | 0x40);
        let fcs = (total - 256) as u16;
        out_buf.push((fcs & 0xFF) as u8);
        out_buf.push(((fcs >> 8) & 0xFF) as u8);
    } else {
        out_buf.push(fhd | 0x80);
        let fcs = total as u32;
        out_buf.push((fcs & 0xFF) as u8);
        out_buf.push(((fcs >> 8) & 0xFF) as u8);
        out_buf.push(((fcs >> 16) & 0xFF) as u8);
        out_buf.push(((fcs >> 24) & 0xFF) as u8);
    }

    if total == 0 {
        let hdr_val = 1 | (0 << 1); // 1 empty raw block
        out_buf.push((hdr_val & 0xFF) as u8);
        out_buf.push(((hdr_val >> 8) & 0xFF) as u8);
        out_buf.push(((hdr_val >> 16) & 0xFF) as u8);
        if include_checksum {
            let chk = xxh64_digest_32(src);
            out_buf.push((chk & 0xFF) as u8);
            out_buf.push(((chk >> 8) & 0xFF) as u8);
            out_buf.push(((chk >> 16) & 0xFF) as u8);
            out_buf.push(((chk >> 24) & 0xFF) as u8);
        }
        return true;
    }

    if level <= 0 {
        // Raw blocks (level 0)
        var offset: i64 = 0;
        while offset < total {
            let rem = total - offset;
            let chunk_size = if rem < ZSTD_BLOCKSIZE_MAX { rem } else { ZSTD_BLOCKSIZE_MAX };
            let is_last = (offset + chunk_size == total);
            let last_bit = if is_last { 1 as u32 } else { 0 as u32 };
            let block_hdr = last_bit | (ZSTD_BLOCK_TYPE_RAW << 1) | ((chunk_size as u32) << 3);
            out_buf.push((block_hdr & 0xFF) as u8);
            out_buf.push(((block_hdr >> 8) & 0xFF) as u8);
            out_buf.push(((block_hdr >> 16) & 0xFF) as u8);
            out_buf.append(src[offset .. offset + chunk_size]);
            offset += chunk_size;
        }
    } else {
        init_global_ctables();
        var rep: u32[3] = [1, 4, 8];
        var offset: i64 = 0;
        while offset < total {
            let rem = total - offset;
            let chunk_sz = if rem < ZSTD_BLOCKSIZE_MAX { rem } else { ZSTD_BLOCKSIZE_MAX };
            let is_last = (offset + chunk_sz == total);
            compress_block(src[offset .. offset + chunk_sz], rep, is_last, level, out_buf);
            offset += chunk_sz;
        }
    }

    if include_checksum {
        let chk = xxh64_digest_32(src);
        out_buf.push((chk & 0xFF) as u8);
        out_buf.push(((chk >> 8) & 0xFF) as u8);
        out_buf.push(((chk >> 16) & 0xFF) as u8);
        out_buf.push(((chk >> 24) & 0xFF) as u8);
    }
    return true;
}

// Compresses input slice using Zstandard frame container (level 3 by default).
fn zstd_compress<B>(src: const u8[:], out_buf: B&, include_checksum: bool = true) -> bool {
    return zstd_compress_level(src, out_buf, 3, include_checksum);
}
