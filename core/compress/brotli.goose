// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Brotli compression and decompression engine (RFC 7932).
// Implementation uses no dynamic heap allocations in the inner loop.
// Features:
// 1. RFC 7932 bitstream framing and sliding window negotiation (WBITS 10..24)
// 2. Uncompressed, metadata, and compressed meta-blocks
// 3. Simple (1..4 symbols) and Complex canonical Huffman prefix code decoders
// 4. Command decoding over 704-symbol alphabet with algorithmic mapping
// 5. Context modeling (LSB6, MSB6, UTF8, Signed) and distance ring buffer (4 elements)
// 6. Sliding window LZ77 copy and RFC 7932 122 KB built-in static dictionary with 121 transforms
// 7. Fast Level 0 (Uncompressed Meta-Blocks) and Level 1 (Fast Greedy LZ77) encoders
namespace core;

import std;
import core.math.bits;
import core.math.arithmetic;
import core.compress.deflate;
import core.compress.brotli_dict;

// ---- RFC 7932 Constants and Lookups ---------------------------------------

const BROTLI_MIN_WINDOW_BITS: u32 = 10;
const BROTLI_MAX_WINDOW_BITS: u32 = 24;

const BROTLI_CODE_LENGTH_ORDER: i32[18] = [
    1, 2, 3, 4, 0, 5, 17, 6, 16, 7, 8, 9, 10, 11, 12, 13, 14, 15,
];

// RFC 7932 Section 5: Insert length base offsets and extra bits
const INSERT_LENGTH_BASE: u32[24] = [
    0, 1, 2, 3, 4, 5, 6, 8, 10, 14, 18, 26, 34, 50, 66, 98,
    130, 194, 322, 578, 1090, 2114, 6210, 22594,
];

const INSERT_LENGTH_EXTRA_BITS: u8[24] = [
    0, 0, 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5,
    6, 7, 8, 9, 10, 12, 14, 24,
];

// RFC 7932 Section 5: Copy length base offsets and extra bits
const COPY_LENGTH_BASE: u32[24] = [
    2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 14, 18, 22, 30, 38, 54,
    70, 102, 134, 198, 326, 582, 1094, 2118,
];

const COPY_LENGTH_EXTRA_BITS: u8[24] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4,
    5, 5, 6, 7, 8, 9, 10, 24,
];

// RFC 7932 Section 6: Block length base offsets and extra bits
const BROTLI_BLOCK_LEN_BASE: u32[26] = [
    1, 5, 9, 13, 17, 25, 33, 41, 49, 65, 81, 97, 113,
    145, 177, 209, 241, 305, 369, 497, 753, 1265, 2289, 4337, 8433, 16625,
];

const BROTLI_BLOCK_LEN_EXTRA: u8[26] = [
    2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5,
    5, 5, 5, 6, 6, 7, 8, 9, 10, 11, 12, 13, 24,
];

// RFC 7932 Section 7.1: Context lookup tables for UTF8 (LUT_0, LUT_1) and Signed (LUT_2) modes
const BROTLI_CONTEXT_LUT_0: u8[256] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 4, 0, 0, 4, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    8, 12, 16, 12, 12, 20, 12, 16, 24, 28, 12, 12, 32, 12, 36, 12,
    44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 32, 32, 24, 40, 28, 12,
    12, 48, 52, 52, 52, 48, 52, 52, 52, 48, 52, 52, 52, 52, 52, 48,
    52, 52, 52, 52, 52, 48, 52, 52, 52, 52, 52, 24, 12, 28, 12, 12,
    12, 56, 60, 60, 60, 56, 60, 60, 60, 56, 60, 60, 60, 60, 60, 56,
    60, 60, 60, 60, 60, 56, 60, 60, 60, 60, 60, 24, 12, 28, 12, 0,
    0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
    0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
    0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
    0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
    2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3,
    2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3,
    2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3,
    2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3,
];

const BROTLI_CONTEXT_LUT_1: u8[256] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1,
    1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1,
    1, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 1, 1, 1, 1, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
];

const BROTLI_CONTEXT_LUT_2: u8[256] = [
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
    6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 7,
];

// RFC 7932 Section 5: Cell mappings for 704-command alphabet
const CELL_INS_BASE:  u8[11] = [0, 0, 0, 0, 8, 8, 0, 16, 8, 16, 16];
const CELL_COPY_BASE: u8[11] = [0, 8, 0, 8, 0, 8, 16, 0, 16, 8, 16];

// Decodes a 704-alphabet command code into (insert_code, copy_code, distance_is_zero).
//
// Example:
//   code = 128
//   returns: ins_code = 0, copy_code = 8, dist_zero = false
fn decode_cmd_code(code: u32) -> u32, u32, bool {
    let cell = (code >> 6) as i64;
    let ins_base = CELL_INS_BASE[cell] as u32;
    let copy_base = CELL_COPY_BASE[cell] as u32;
    let copy_code = copy_base + (code & 7);
    let ins_code = ins_base + ((code >> 3) & 7);
    let dist_zero = code < 128;
    return ins_code, copy_code, dist_zero;
}

// Variable-length code length symbol representation (RFC 7932 Section 3.5)
const CL_CODE_SYMBOLS: u8[6] = [0, 4, 3, 2, 1, 5];
const CL_CODE_LENS:    u8[6] = [2, 2, 2, 3, 4, 4];
const CL_CODE_BITS:    u8[6] = [0, 1, 2, 3, 7, 15]; // LSB-first values

const BROTLI_REV8: u8[256] = [
    0x00, 0x80, 0x40, 0xC0, 0x20, 0xA0, 0x60, 0xE0, 0x10, 0x90, 0x50, 0xD0, 0x30, 0xB0, 0x70, 0xF0,
    0x08, 0x88, 0x48, 0xC8, 0x28, 0xA8, 0x68, 0xE8, 0x18, 0x98, 0x58, 0xD8, 0x38, 0xB8, 0x78, 0xF8,
    0x04, 0x84, 0x44, 0xC4, 0x24, 0xA4, 0x64, 0xE4, 0x14, 0x94, 0x54, 0xD4, 0x34, 0xB4, 0x74, 0xF4,
    0x0C, 0x8C, 0x4C, 0xCC, 0x2C, 0xAC, 0x6C, 0xEC, 0x1C, 0x9C, 0x5C, 0xDC, 0x3C, 0xBC, 0x7C, 0xFC,
    0x02, 0x82, 0x42, 0xC2, 0x22, 0xA2, 0x62, 0xE2, 0x12, 0x92, 0x52, 0xD2, 0x32, 0xB2, 0x72, 0xF2,
    0x0A, 0x8A, 0x4A, 0xCA, 0x2A, 0xAA, 0x6A, 0xEA, 0x1A, 0x9A, 0x5A, 0xDA, 0x3A, 0xBA, 0x7A, 0xFA,
    0x06, 0x86, 0x46, 0xC6, 0x26, 0xA6, 0x66, 0xE6, 0x16, 0x96, 0x56, 0xD6, 0x36, 0xB6, 0x76, 0xF6,
    0x0E, 0x8E, 0x4E, 0xCE, 0x2E, 0xAE, 0x6E, 0xEE, 0x1E, 0x9E, 0x5E, 0xDE, 0x3E, 0xBE, 0x7E, 0xFE,
    0x01, 0x81, 0x41, 0xC1, 0x21, 0xA1, 0x61, 0xE1, 0x11, 0x91, 0x51, 0xD1, 0x31, 0xB1, 0x71, 0xF1,
    0x09, 0x89, 0x49, 0xC9, 0x29, 0xA9, 0x69, 0xE9, 0x19, 0x99, 0x59, 0xD9, 0x39, 0xB9, 0x79, 0xF9,
    0x05, 0x85, 0x45, 0xC5, 0x25, 0xA5, 0x65, 0xE5, 0x15, 0x95, 0x55, 0xD5, 0x35, 0xB5, 0x75, 0xF5,
    0x0D, 0x8D, 0x4D, 0xCD, 0x2D, 0xAD, 0x6D, 0xED, 0x1D, 0x9D, 0x5D, 0xDD, 0x3D, 0xBD, 0x7D, 0xFD,
    0x03, 0x83, 0x43, 0xC3, 0x23, 0xA3, 0x63, 0xE3, 0x13, 0x93, 0x53, 0xD3, 0x33, 0xB3, 0x73, 0xF3,
    0x0B, 0x8B, 0x4B, 0xCB, 0x2B, 0xAB, 0x6B, 0xEB, 0x1B, 0x9B, 0x5B, 0xDB, 0x3B, 0xBB, 0x7B, 0xFB,
    0x07, 0x87, 0x47, 0xC7, 0x27, 0xA7, 0x67, 0xE7, 0x17, 0x97, 0x57, 0xD7, 0x37, 0xB7, 0x77, 0xF7,
    0x0F, 0x8F, 0x4F, 0xCF, 0x2F, 0xAF, 0x6F, 0xEF, 0x1F, 0x9F, 0x5F, 0xDF, 0x3F, 0xBF, 0x7F, 0xFF,
];

const BROTLI_INS_CODE_64: u8[64] = [
    0, 1, 2, 3, 4, 5, 6, 6, 7, 7, 8, 8, 8, 8, 9, 9,
    9, 9, 10, 10, 10, 10, 10, 10, 10, 10, 11, 11, 11, 11, 11, 11,
    11, 11, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12,
    12, 12, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
];

const BROTLI_COPY_CODE_64: u8[64] = [
    0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 8, 9, 9, 10, 10,
    10, 10, 11, 11, 11, 11, 12, 12, 12, 12, 12, 12, 12, 12, 13, 13,
    13, 13, 13, 13, 13, 13, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
    14, 14, 14, 14, 14, 14, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
];

// ---- Zero-Heap Bit Reader and Bit Writer ----------------------------------

struct BrotliBitReader {
    src:       const u8[:] = "",
    pos:       i64         = 0,
    bit_buf:   u64         = 0,
    bit_count: u32         = 0,
    underflow: bool        = false,
}

fn new_brotli_bit_reader(src: const u8[:]) -> BrotliBitReader {
    var r = BrotliBitReader {
        src:       src,
        pos:       0,
        bit_buf:   0,
        bit_count: 0,
        underflow: false,
    };
    brotli_fill_bits(r);
    return r;
}

inline fn brotli_fill_bits(r: BrotliBitReader&) {
    if r.bit_count <= 32 && r.pos + 4 <= r.src.len {
        let w = read_le_u32(r.src, r.pos) as u64;
        r.bit_buf |= w << r.bit_count;
        r.pos += 4;
        r.bit_count += 32;
    }
    if r.bit_count <= 32 && r.pos + 4 <= r.src.len {
        let w = read_le_u32(r.src, r.pos) as u64;
        r.bit_buf |= w << r.bit_count;
        r.pos += 4;
        r.bit_count += 32;
    }
    while r.bit_count <= 56 && r.pos < r.src.len {
        r.bit_buf |= (r.src[r.pos] as u64) << r.bit_count;
        r.pos += 1;
        r.bit_count += 8;
    }
}

inline fn brotli_read_bits(r: BrotliBitReader&, n: u32) -> u32 {
    if r.bit_count < n {
        brotli_fill_bits(r);
        if r.bit_count < n {
            r.underflow = true;
        }
    }
    let mask = if n >= 32 { 0xFFFFFFFF as u64 } else { ((1 as u64) << n) - 1 };
    let val = (r.bit_buf & mask) as u32;
    r.bit_buf >>= n;
    r.bit_count = sub_sat_u32(r.bit_count, n);
    return val;
}

inline fn brotli_peek_bits(r: BrotliBitReader&, n: u32) -> u32 {
    if r.bit_count < n {
        brotli_fill_bits(r);
    }
    let mask = if n >= 32 { 0xFFFFFFFF as u64 } else { ((1 as u64) << n) - 1 };
    return (r.bit_buf & mask) as u32;
}

inline fn brotli_drop_bits(r: BrotliBitReader&, n: u32) {
    if r.bit_count < n {
        brotli_fill_bits(r);
        if r.bit_count < n {
            r.underflow = true;
        }
    }
    r.bit_buf >>= n;
    r.bit_count = sub_sat_u32(r.bit_count, n);
}

struct BrotliBitWriter {
    bit_buf:   u64  = 0,
    bit_count: u32  = 0,
    overflow:  bool = false,
}

inline fn brotli_write_bits<B>(w: BrotliBitWriter&, n: u32, val: u64, out: B&) {
    let mask = if n >= 32 { 0xFFFFFFFF as u64 } else { ((1 as u64) << (n as u64)) - 1 };
    w.bit_buf |= (val & mask) << (w.bit_count as u64);
    w.bit_count += n;
    if w.bit_count >= 32 {
        if !comp_try_write_le_u32(out, (w.bit_buf & 0xFFFFFFFF) as u32) {
            w.overflow = true;
        }
        w.bit_buf >>= 32;
        w.bit_count -= 32;
    }
}

fn brotli_write_byte_align<B>(w: BrotliBitWriter&, out: B&) {
    while w.bit_count >= 8 {
        if !comp_try_push(out, (w.bit_buf & 0xFF) as u8) {
            w.overflow = true;
        }
        w.bit_buf >>= 8;
        w.bit_count -= 8;
    }
    if w.bit_count > 0 {
        if !comp_try_push(out, (w.bit_buf & 0xFF) as u8) {
            w.overflow = true;
        }
        w.bit_buf = 0;
        w.bit_count = 0;
    }
}

// ---- Canonical Huffman Table with Fast 10-bit Lookahead ------------------

const BROTLI_FLAT_NONE: u8 = 0;
const BROTLI_FLAT_8:    u8 = 1; // 256 symbols, length 8
const BROTLI_FLAT_6:    u8 = 2; // 64 symbols, length 6
const BROTLI_FLAT_704:  u8 = 3; // 320 len-9 + 384 len-10

struct BrotliTreeDesc {
    single_symbol: i32 = -1,
    flat_kind:     u8  = 0,
    max_len:       u8  = 0,
    table_idx:     i32 = -1,
}

struct BrotliHuffmanTable {
    count:         i32[16]   = [0; 16],
    symbol:        u16[704]  = [0; 704],
    fast:          u16[1024] = [0; 1024], // 10-bit lookahead: (len << 10) | symbol (0 = miss)
    total_symbols: i32       = 0,
    single_symbol: i32       = -1,        // For NSYM = 1 (0-bit codes)
    max_len:       i32       = 0,
    is_flat8:      bool      = false,
}

struct BrotliClTable {
    fast:          u16[32] = [0; 32], // 5-bit lookahead: (len << 5) | sym (0 = miss)
    single_symbol: i32     = -1,
}

inline fn bit_reverse_8(val: u32, len: i32) -> u32 {
    if len <= 8 {
        return (BROTLI_REV8[(val & 0xFF) as i64] as u32) >> ((8 - len) as u32);
    }
    let rev16 = ((BROTLI_REV8[(val & 0xFF) as i64] as u32) << 8) |
                BROTLI_REV8[((val >> 8) & 0xFF) as i64];
    return rev16 >> ((16 - len) as u32);
}

fn insert_brotli_huffman_symbol(
    table:     BrotliHuffmanTable&,
    s:         i32,
    len:       i32,
    offs:      i32[16]&,
    next_code: u32[16]&,
) {
    if len > 10 {
        let sym_idx = offs[len];
        if sym_idx < 704 {
            table.symbol[sym_idx] = s as u16;
        }
        offs[len]++;
        next_code[len]++;
        return;
    }

    let c = next_code[len];
    next_code[len]++;
    let rev_code = bit_reverse_8(c, len) as i64;
    let entry = (((len as u32) << 10) | (s as u32)) as u16;
    if len == 10 {
        table.fast[rev_code] = entry;
    } else if len == 9 {
        table.fast[rev_code] = entry;
        table.fast[rev_code + 512] = entry;
    } else if len == 8 {
        table.fast[rev_code] = entry;
        table.fast[rev_code + 256] = entry;
        table.fast[rev_code + 512] = entry;
        table.fast[rev_code + 768] = entry;
    } else {
        let step = (1 as i64) << (len as u32);
        var idx = rev_code;
        while idx < 1024 {
            table.fast[idx] = entry;
            idx += step;
        }
    }
}

fn populate_brotli_huffman_table(
    lengths:   const u8[:],
    n_symbols: i32,
    max_len:   i32,
    left:      i32,
    table:     BrotliHuffmanTable&,
) {
    if max_len > 10 || left != 0 {
        table.fast = [0; 1024];
    }
    var offs: i32[16] = [0; 16];
    if max_len > 10 {
        var prefix_sum: i32 = 0;
        for l in 1..16 {
            offs[l] = prefix_sum;
            prefix_sum += table.count[l];
        }
    }
    var code:      u32     = 0;
    var next_code: u32[16] = [0; 16];
    for l in 1..16 {
        code = (code + (table.count[l - 1] as u32)) << 1;
        next_code[l] = code;
    }
    for s in n_symbols {
        let len = lengths[s] as i32;
        if len != 0 && len <= 15 {
            insert_brotli_huffman_symbol(table, s, len, offs, next_code);
        }
    }
}

// Constructs canonical Huffman decode table from a list of code lengths.
fn construct_brotli_huffman_table(lengths: const u8[:], n_symbols: i32, table: BrotliHuffmanTable&) -> i32 {
    table.total_symbols = n_symbols;
    table.single_symbol = -1;
    table.is_flat8 = false;
    table.max_len = 0;
    table.count = [0; 16];

    var non_zeros = 0;
    var last_sym: i32 = -1;
    var max_len:  i32 = 0;
    for s in n_symbols {
        let len = lengths[s] as i32;
        if len > 0 && len <= 15 {
            table.count[len]++;
            non_zeros += 1;
            last_sym = s;
            if len > max_len { max_len = len; }
        }
    }
    table.max_len = max_len;

    if non_zeros == 0 { return 0; }
    if non_zeros == 1 {
        table.single_symbol = last_sym;
        return 0;
    }
    if n_symbols == 256 && non_zeros == 256 && table.count[8] == 256 {
        table.is_flat8 = true;
        return 0;
    }

    var left: i32 = 1;
    for l in 1..16 {
        left <<= 1;
        left -= table.count[l];
        if left < 0 { return left; }
    }

    populate_brotli_huffman_table(lengths, n_symbols, max_len, left, table);
    return left;
}

// Decodes a Huffman symbol whose code length exceeds 10 bits using canonical traversal.
//
// Example:
//   table.single_symbol = -1, bit stream contains canonical 11-bit code
//   returns: sym, true
fn decode_brotli_symbol_slow(r: BrotliBitReader&, table: const BrotliHuffmanTable&) -> i32, bool {
    var code:  i32 = 0;
    var first: i32 = 0;
    var index: i32 = 0;

    for l in 1..16 {
        let b = brotli_read_bits(r, 1) as i32;
        code = (code << 1) | b;
        let count = table.count[l];
        if (code - first) < count {
            let s_idx = index + (code - first);
            if s_idx < 704 {
                return table.symbol[s_idx], true;
            }
            return -1, false;
        }
        index += count;
        first = (first + count) << 1;
    }

    return -1, false;
}

// Decodes a single Huffman symbol from the bitstream.
//
// Example:
//   table.single_symbol = 5
//   returns: 5, true
fn decode_brotli_symbol(r: BrotliBitReader&, table: const BrotliHuffmanTable&) -> i32, bool {
    if table.single_symbol >= 0 {
        return table.single_symbol, true;
    }
    if table.is_flat8 {
        let raw_b = brotli_read_bits(r, 8);
        guard !r.underflow else { return -1, false; }
        return BROTLI_REV8[(raw_b & 0xFF) as i64], true;
    }

    if r.bit_count < 15 {
        brotli_fill_bits(r);
    }
    let entry = table.fast[(r.bit_buf & 0x3FF) as i64];
    if entry != 0 {
        let len = (entry >> 10) as u32;
        if r.bit_count < len {
            r.underflow = true;
            return -1, false;
        }
        r.bit_buf >>= (len as u64);
        r.bit_count -= len;
        return entry & 0x3FF, true;
    }

    return decode_brotli_symbol_slow(r, table);
}

// Decodes a symbol from a `BrotliTreeDesc`, handling algebraic flat trees in O(1) without table allocation.
//
// Example:
//   desc.single_symbol = 5
//   returns: 5, true
fn decode_brotli_tree_symbol(
    r:      BrotliBitReader&,
    desc:   const BrotliTreeDesc&,
    tables: const BrotliHuffmanTable[:],
) -> i32, bool {
    if desc.single_symbol >= 0 {
        return desc.single_symbol, true;
    }
    if desc.flat_kind == BROTLI_FLAT_704 {
        if r.bit_count < 10 {
            brotli_fill_bits(r);
        }
        let p10 = (r.bit_buf & 0x3FF) as u32;
        let c9 = bit_reverse_8(p10 & 0x1FF, 9);
        let len: u32 = if c9 < 320 { 9 } else { 10 };
        guard r.bit_count >= len else {
            r.underflow = true;
            return -1, false;
        }
        r.bit_buf >>= (len as u64);
        r.bit_count -= len;
        if c9 < 320 {
            return c9 as i32, true;
        }
        let c10 = (c9 << 1) | ((p10 >> 9) & 1);
        return (c10 - 320) as i32, true;
    }
    if desc.flat_kind == BROTLI_FLAT_6 {
        let b6 = brotli_read_bits(r, 6);
        guard !r.underflow else { return -1, false; }
        return (BROTLI_REV8[b6 & 0x3F] >> 2), true;
    }
    if desc.flat_kind == BROTLI_FLAT_8 {
        let raw_b = brotli_read_bits(r, 8);
        guard !r.underflow else { return -1, false; }
        return BROTLI_REV8[(raw_b & 0xFF) as i64], true;
    }
    guard desc.table_idx >= 0 && desc.table_idx < tables.len else { return -1, false; }
    return decode_brotli_symbol(r, tables[desc.table_idx]);
}

fn construct_brotli_cl_table(lengths: const i32[18]&, cl_table: BrotliClTable&) {
    cl_table.single_symbol = -1;
    var count:     i32[6] = [0; 6];
    var non_zeros: i32    = 0;
    var last_sym:  i32    = -1;
    for s in 18 {
        let len = lengths[s];
        if len > 0 && len <= 5 {
            count[len]++;
            non_zeros += 1;
            last_sym = s as i32;
        }
    }
    if non_zeros == 1 {
        cl_table.single_symbol = last_sym;
        return;
    }
    var code:      u32    = 0;
    var next_code: u32[6] = [0; 6];
    for l in 1..6 {
        code = (code + (count[l - 1] as u32)) << 1;
        next_code[l] = code;
    }
    for s in 18 {
        let len = lengths[s];
        if len > 0 && len <= 5 {
            let c = next_code[len];
            next_code[len]++;
            let rev = bit_reverse_8(c, len);
            let step = (1 as i64) << (len as u32);
            var idx = rev as i64;
            let entry = (((len as u32) << 5) | (s as u32)) as u16;
            while idx < 32 {
                cl_table.fast[idx] = entry;
                idx += step;
            }
        }
    }
}

// Decodes one RFC 7932 Section 3.5 code-length symbol (0..17, max 5 bits) from `cl_table`.
//
// Example:
//   cl_table.single_symbol = 8
//   returns: 8, true
fn decode_brotli_cl_symbol(r: BrotliBitReader&, cl_table: const BrotliClTable&) -> i32, bool {
    if cl_table.single_symbol >= 0 {
        return cl_table.single_symbol, true;
    }
    if r.bit_count < 5 {
        brotli_fill_bits(r);
    }
    let entry = cl_table.fast[(r.bit_buf & 0x1F) as i64];
    guard entry != 0 else { return -1, false; }
    let len = (entry >> 5) as u32;
    guard r.bit_count >= len else {
        r.underflow = true;
        return -1, false;
    }
    r.bit_buf >>= (len as u64);
    r.bit_count -= len;
    return entry & 0x1F, true;
}

// Builds a Simple Prefix Code (RFC 7932 Section 3.4) with 1..4 symbols.
fn build_simple_prefix_code(
    r:             BrotliBitReader&,
    alphabet_size: i32,
    table:         BrotliHuffmanTable&,
) -> bool {
    let nsym_minus_1 = brotli_read_bits(r, 2);
    let nsym = (nsym_minus_1 + 1) as i32;

    let alphabet_bits: u32 = if alphabet_size <= 2 {
        1
    } else {
        (64 - clz((alphabet_size - 1) as u64)) as u32
    };

    var symbols: i32[4] = [0; 4];
    for i in nsym {
        let s = brotli_read_bits(r, alphabet_bits) as i32;
        guard s < alphabet_size else { return false; }
        for j in i {
            guard symbols[j] != s else { return false; }
        }
        symbols[i] = s;
    }

    if nsym == 1 {
        table.single_symbol = symbols[0];
        table.total_symbols = alphabet_size;
        table.max_len = 0;
        table.is_flat8 = false;
        return true;
    }

    var lengths: u8[704] = [0; 704];
    if nsym == 2 {
        lengths[symbols[0]] = 1;
        lengths[symbols[1]] = 1;
    } else if nsym == 3 {
        lengths[symbols[0]] = 1;
        lengths[symbols[1]] = 2;
        lengths[symbols[2]] = 2;
    } else if nsym == 4 {
        let tree_select = brotli_read_bits(r, 1);
        if tree_select == 0 {
            lengths[symbols[0]] = 2;
            lengths[symbols[1]] = 2;
            lengths[symbols[2]] = 2;
            lengths[symbols[3]] = 2;
        } else {
            lengths[symbols[0]] = 1;
            lengths[symbols[1]] = 2;
            lengths[symbols[2]] = 3;
            lengths[symbols[3]] = 3;
        }
    }

    let err = construct_brotli_huffman_table(lengths[..alphabet_size], alphabet_size, table);
    return err == 0;
}

const CODE_LENGTH_PREFIX_LENGTH: u8[16] = [
    2, 2, 2, 3, 2, 2, 2, 4, 2, 2, 2, 3, 2, 2, 2, 4,
];
const CODE_LENGTH_PREFIX_VALUE: u8[16] = [
    0, 4, 3, 2, 0, 4, 3, 1, 0, 4, 3, 2, 0, 4, 3, 5,
];

fn read_code_length_code_lengths(
    r:        BrotliBitReader&,
    hskip:    u32,
    cl_table: BrotliClTable&,
) -> bool {
    var code_lengths: i32[18] = [0; 18];
    var space:        i32     = 32;
    var num_codes:    u32     = 0;
    var idx = hskip as i64;
    while idx < 18 {
        let ix = brotli_peek_bits(r, 4);
        let v = CODE_LENGTH_PREFIX_VALUE[ix as i64] as u32;
        let l = CODE_LENGTH_PREFIX_LENGTH[ix as i64] as u32;
        brotli_drop_bits(r, l);
        code_lengths[BROTLI_CODE_LENGTH_ORDER[idx]] = v as i32;
        if v != 0 {
            space -= (32 >> v) as i32;
            num_codes += 1;
            if space <= 0 {
                break;
            }
        }
        idx += 1;
    }

    guard !r.underflow else { return false; }
    guard num_codes == 1 || space == 0 else { return false; }
    construct_brotli_cl_table(code_lengths, cl_table);
    return true;
}

fn apply_repeat_code(
    r:               BrotliBitReader&,
    target_len:      i32,
    extra_bits:      u32,
    alphabet_size:   i32,
    main_lengths:    u8[704]&,
    sym_idx:         i32&,
    repeat:          i32&,
    repeat_code_len: i32&,
    space_symbols:   i32&,
) -> bool {
    let count = 3 + (brotli_read_bits(r, extra_bits) as i32);
    var old_repeat = repeat;
    if repeat_code_len != target_len {
        repeat = 0;
        repeat_code_len = target_len;
        old_repeat = 0;
    }
    if repeat > 0 {
        repeat = (repeat - 2) << extra_bits;
    }
    repeat += count;
    let delta = repeat - old_repeat;
    guard sym_idx + delta <= alphabet_size else { return false; }
    let rep_byte = repeat_code_len as u8;
    for i in delta {
        main_lengths[sym_idx + i] = rep_byte;
    }
    sym_idx += delta;
    if repeat_code_len > 0 {
        space_symbols -= delta << (15 - repeat_code_len);
    }
    return true;
}

fn read_main_alphabet_lengths(
    r:             BrotliBitReader&,
    cl_table:      const BrotliClTable&,
    alphabet_size: i32,
    main_lengths:  u8[704]&,
) -> bool {
    var sym_idx:         i32 = 0;
    var prev_len:        i32 = 8;
    var repeat:          i32 = 0;
    var repeat_code_len: i32 = 0;
    var space_symbols:   i32 = 32768;

    while sym_idx < alphabet_size && space_symbols > 0 {
        let sym, ok = decode_brotli_cl_symbol(r, cl_table);
        guard ok else { return false; }

        if sym < 16 {
            main_lengths[sym_idx] = sym as u8;
            if sym > 0 {
                prev_len = sym;
                space_symbols -= 1 << (15 - sym);
            }
            sym_idx += 1;
            repeat = 0;
        } else if sym == 16 || sym == 17 {
            let target_len = if sym == 16 { prev_len } else { 0 };
            let extra_bits: u32 = if sym == 16 { 2 } else { 3 };
            guard apply_repeat_code(
                r, target_len, extra_bits, alphabet_size, main_lengths,
                sym_idx, repeat, repeat_code_len, space_symbols,
            ) else {
                return false;
            }
        }
    }

    while sym_idx < alphabet_size {
        main_lengths[sym_idx] = 0;
        sym_idx += 1;
    }
    return space_symbols == 0;
}

// Reads and builds a Complex Prefix Code (RFC 7932 Section 3.5).
fn read_complex_prefix_code(
    r:             BrotliBitReader&,
    hskip:         u32,
    alphabet_size: i32,
    table:         BrotliHuffmanTable&,
) -> bool {
    var cl_table = BrotliClTable { .. };
    guard read_code_length_code_lengths(r, hskip, cl_table) else { return false; }

    var main_lengths: u8[704] = [0; 704];
    guard read_main_alphabet_lengths(r, cl_table, alphabet_size, main_lengths) else {
        return false;
    }

    let m_err = construct_brotli_huffman_table(main_lengths[..alphabet_size], alphabet_size, table);
    return m_err == 0;
}

fn build_brotli_tree_from_lengths(
    lengths:       const u8[:],
    alphabet_size: i32,
    desc:          BrotliTreeDesc&,
    tables:        BrotliHuffmanTable[>..]&,
) -> bool {
    var count:       i32[16] = [0; 16];
    var non_zeros:   i32     = 0;
    var last_sym:    i32     = -1;
    var max_len:     i32     = 0;
    var first_320_9: bool    = (alphabet_size == 704);
    for s in alphabet_size {
        let len = lengths[s] as i32;
        if s < 320 && len != 9 { first_320_9 = false; }
        if len > 0 && len <= 15 {
            count[len]++;
            non_zeros += 1;
            last_sym = s;
            if len > max_len { max_len = len; }
        }
    }
    desc = BrotliTreeDesc { max_len: max_len as u8 };
    if non_zeros == 0 { return true; }
    if non_zeros == 1 {
        desc.single_symbol = last_sym;
        return true;
    }
    if alphabet_size == 256 && non_zeros == 256 && count[8] == 256 {
        desc.flat_kind = BROTLI_FLAT_8;
        return true;
    }
    if alphabet_size == 64 && non_zeros == 64 && count[6] == 64 {
        desc.flat_kind = BROTLI_FLAT_6;
        return true;
    }
    if first_320_9 && non_zeros == 704 && count[9] == 320 && count[10] == 384 {
        desc.flat_kind = BROTLI_FLAT_704;
        return true;
    }
    let idx = tables.len;
    tables.push(BrotliHuffmanTable { .. });
    guard construct_brotli_huffman_table(lengths, alphabet_size, tables[idx]) == 0 else {
        return false;
    }
    desc.table_idx = idx as i32;
    return true;
}

fn read_brotli_tree_desc(
    r:             BrotliBitReader&,
    alphabet_size: i32,
    desc:          BrotliTreeDesc&,
    tables:        BrotliHuffmanTable[>..]&,
    scratch_lens:  u8[704]&,
) -> bool {
    let hskip = brotli_read_bits(r, 2);
    if hskip == 1 {
        let idx = tables.len;
        tables.push(BrotliHuffmanTable { .. });
        guard build_simple_prefix_code(r, alphabet_size, tables[idx]) else { return false; }
        desc = BrotliTreeDesc {
            single_symbol: tables[idx].single_symbol,
            max_len:       tables[idx].max_len as u8,
            table_idx:     idx as i32,
        };
        return true;
    }
    var cl_table = BrotliClTable { .. };
    guard read_code_length_code_lengths(r, hskip, cl_table) else { return false; }
    guard read_main_alphabet_lengths(r, cl_table, alphabet_size, scratch_lens) else {
        return false;
    }
    return build_brotli_tree_from_lengths(scratch_lens[..alphabet_size], alphabet_size, desc, tables);
}

// Parses either simple or complex prefix code (RFC 7932 Section 3.4 & 3.5).
fn read_brotli_prefix_code(
    r:             BrotliBitReader&,
    alphabet_size: i32,
    table:         BrotliHuffmanTable&,
) -> bool {
    let hskip = brotli_read_bits(r, 2);
    if hskip == 1 {
        return build_simple_prefix_code(r, alphabet_size, table);
    }
    return read_complex_prefix_code(r, hskip, alphabet_size, table);
}

// ---- Distance Calculation (RFC 7932 Section 4) ----------------------------

const BROTLI_DIST_RING_IDX:   u8[16] = [0, 1, 2, 3, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1];
const BROTLI_DIST_RING_DELTA: i8[16] = [0, 0, 0, 0, -1, 1, -2, 2, -3, 3, -1, 1, -2, 2, -3, 3];

inline fn push_brotli_dist_ring(dist_ring: u32[4]&, dist: u32) {
    dist_ring[3] = dist_ring[2];
    dist_ring[2] = dist_ring[1];
    dist_ring[1] = dist_ring[0];
    dist_ring[0] = dist;
}

// Decodes a Brotli distance code using distance parameters and ring buffer.
//
// Example:
//   dcode = 0, dist_ring[0] = 4
//   returns: 4
fn decode_brotli_distance(
    r:         BrotliBitReader&,
    dcode:     u32,
    npostfix:  u32,
    ndirect:   u32,
    dist_ring: u32[4]&,
) -> u32 {
    // Special distances 0..15 (RFC 7932 Section 4)
    if dcode < 16 {
        let base = dist_ring[BROTLI_DIST_RING_IDX[dcode as i64] as i64];
        let delta = BROTLI_DIST_RING_DELTA[dcode as i64];
        let dist = if delta < 0 { sub_sat_u32(base, (-delta) as u32) } else { base + (delta as u32) };
        if dist == 0 { return 0; }
        if dcode > 0 { push_brotli_dist_ring(dist_ring, dist); }
        return dist;
    }

    // Direct distance codes (16 .. 15 + NDIRECT)
    if ndirect > 0 && dcode < (16 + ndirect) {
        let dist = dcode - 15;
        push_brotli_dist_ring(dist_ring, dist);
        return dist;
    }

    // Extra bit distance codes
    let postfix_mask = ((1 as u32) << npostfix) - 1;
    let delta = dcode - ndirect - 16;
    let ndistbits = 1 + (delta >> (npostfix + 1));
    let dextra = brotli_read_bits(r, ndistbits);

    let hcode = delta >> npostfix;
    let lcode = delta & postfix_mask;
    let offset = ((2 + (hcode & 1)) << ndistbits) - 4;
    let dist = ((offset + dextra) << npostfix) + lcode + ndirect + 1;
    push_brotli_dist_ring(dist_ring, dist);
    return dist;
}

// ---- Level 0 and Level 1 Brotli Encoders ----------------------------------

struct BrotliLz77Cmd {
    ins_start: u32 = 0,
    ins_len:   u32 = 0,
    copy_len:  u32 = 0,
    distance:  u32 = 0,
}

// Maps an insert length to RFC 7932 Section 5 `(ins_code, extra_bits, extra_val)`.
//
// Example:
//   ins_len = 7
//   returns: code = 6, extra_bits = 1, extra_val = 1
fn encode_brotli_insert_len(ins_len: u32) -> u32, u32, u32 {
    if ins_len < 64 {
        let code: u32 = BROTLI_INS_CODE_64[ins_len as i64];
        let eb:   u32 = INSERT_LENGTH_EXTRA_BITS[code];
        return code, eb, ins_len - INSERT_LENGTH_BASE[code as i64];
    }
    if ins_len < 66 {
        return 13, 4, ins_len - 50;
    }
    for i in 10 {
        let idx = 23 - i;
        let base = INSERT_LENGTH_BASE[idx];
        if ins_len >= base {
            let eb: u32 = INSERT_LENGTH_EXTRA_BITS[idx];
            return idx as u32, eb, ins_len - base;
        }
    }
    return 0, 0, 0;
}

// Maps a copy length (>= 2) to RFC 7932 Section 5 `(copy_code, extra_bits, extra_val)`.
//
// Example:
//   copy_len = 4
//   returns: code = 2, extra_bits = 0, extra_val = 0
fn encode_brotli_copy_len(copy_len: u32) -> u32, u32, u32 {
    if copy_len < 64 {
        let code: u32 = BROTLI_COPY_CODE_64[copy_len as i64];
        let base = COPY_LENGTH_BASE[code as i64];
        let eb: u32 = COPY_LENGTH_EXTRA_BITS[code as i64];
        return code, eb, sub_sat_u32(copy_len, base);
    }
    if copy_len < 70 {
        return 15, 4, copy_len - 54;
    }
    for i in 8 {
        let idx = 23 - i;
        let base = COPY_LENGTH_BASE[idx];
        if copy_len >= base {
            let eb: u32 = COPY_LENGTH_EXTRA_BITS[idx];
            return idx as u32, eb, copy_len - base;
        }
    }
    return 0, 0, 0;
}

// Encodes `(ins_code, copy_code, dist_zero)` into the 704-symbol command alphabet (RFC 7932 Section 5).
//
// Example:
//   ins_code = 0, copy_code = 2, dist_zero = false
//   returns: 130
fn encode_brotli_cmd_code(ins_code: u32, copy_code: u32, dist_zero: bool) -> u32 {
    let ins_hi = ins_code >> 3;
    let copy_hi = copy_code >> 3;
    var cell: u32 = 2;
    if dist_zero && ins_hi == 0 && copy_hi < 2 {
        cell = copy_hi;
    } else if ins_hi == 0 {
        cell = if copy_hi == 0 { 2 } else if copy_hi == 1 { 3 } else { 6 };
    } else if ins_hi == 1 {
        cell = if copy_hi == 0 { 4 } else if copy_hi == 1 { 5 } else { 8 };
    } else {
        cell = if copy_hi == 0 { 7 } else if copy_hi == 1 { 9 } else { 10 };
    }
    return (cell << 6) | ((ins_code & 7) << 3) | (copy_code & 7);
}

// Encodes a positive backward distance (with NPOSTFIX = 0, NDIRECT = 0) into `(dcode, extra_bits, extra_val)`.
//
// Example:
//   dist = 4, dist_ring = [4, 11, 15, 16]
//   returns: dcode = 0, extra_bits = 0, extra_val = 0
fn encode_brotli_distance_code(dist: u32, dist_ring: u32[4]&) -> u32, u32, u32 {
    if dist == dist_ring[0] {
        return 0, 0, 0;
    }
    var dcode: u32 = 16;
    var eb:    u32 = 0;
    var ev:    u32 = 0;
    if dist == dist_ring[1] {
        dcode = 1;
    } else if dist == dist_ring[2] {
        dcode = 2;
    } else if dist == dist_ring[3] {
        dcode = 3;
    } else {
        let d = dist + 3;
        let nbits = max(62 - clz(d), 1) as u32;
        let hbit = (d >> nbits) & 1;
        dcode = 16 + ((nbits - 1) << 1) + hbit;
        eb = nbits;
        ev = d - ((2 + hbit) << nbits);
    }
    push_brotli_dist_ring(dist_ring, dist);
    return dcode, eb, ev;
}

// Emits a flat RFC 7932 prefix code covering `alphabet_size` symbols (`256`, `704`, or `64`).
fn emit_brotli_flat_prefix_code<B>(w: BrotliBitWriter&, alphabet_size: i32, out: B&) {
    brotli_write_bits(w, 2, 0, out);
    if alphabet_size == 256 {
        brotli_write_bits(w, 26, 0x01C70000, out);
        brotli_write_bits(w, 13, 0x06DA, out);
    } else if alphabet_size == 704 {
        brotli_write_bits(w, 30, 0x1B070000, out);
        brotli_write_bits(w, 14, 0x0499, out);
        brotli_write_bits(w, 25, 0x0082F6DB, out);
    } else {
        brotli_write_bits(w, 22, 0x001DC000, out);
        brotli_write_bits(w, 10, 0x00DA, out);
    }
}

inline fn write_canonical_sym<B>(w: BrotliBitWriter&, sym: u32, alphabet_size: i32, out: B&) {
    if alphabet_size == 256 {
        let rev = bit_reverse_8(sym, 8);
        brotli_write_bits(w, 8, rev as u64, out);
    } else if alphabet_size == 64 {
        let rev = bit_reverse_8(sym, 6);
        brotli_write_bits(w, 6, rev as u64, out);
    } else if sym < 320 {
        let rev = bit_reverse_8(sym, 9);
        brotli_write_bits(w, 9, rev as u64, out);
    } else {
        let code = 640 + (sym - 320);
        let rev = bit_reverse_8(code, 10);
        brotli_write_bits(w, 10, rev as u64, out);
    }
}

inline fn hash4_brotli(chunk: const u8[:], pos: i64, shift: u32 = 20) -> i64 {
    let v = read_le_u32(chunk, pos);
    return (v * 0x1E35A7BD) >> shift;
}

fn measure_lz77_match(chunk: const u8[:], cand: i64, pos: i64) -> i64 {
    guard cand >= 0 && (pos - cand) <= 65500 else { return 0; }
    var mlen: i64 = 0;
    let max_m = min(chunk.len - pos, 2048);
    while mlen + 8 <= max_m {
        let diff = read_le_u64(chunk, cand + mlen) ^ read_le_u64(chunk, pos + mlen);
        if diff != 0 {
            return mlen + (ctz(diff) >> 3);
        }
        mlen += 8;
    }
    while mlen < max_m && chunk[cand + mlen] == chunk[pos + mlen] {
        mlen += 1;
    }
    return mlen;
}

// Scans a small chunk (<= 2048 B) with a 2 KB hash table and records LZ77 commands into `cmds`.
//
// Example:
//   chunk = "AAAAAAAA", cmds = []
//   returns: 8
fn scan_brotli_lz77_small(chunk: const u8[:], cmds: BrotliLz77Cmd[..4096]&) -> i64 {
    var htable:        u16[1024] = [0; 1024];
    var pos:           i64       = 0;
    var lit_start:     i64       = 0;
    var matched_bytes: i64       = 0;

    while pos + 4 <= chunk.len {
        let h = hash4_brotli(chunk, pos, 22);
        let stored = htable[h];
        let cand = if stored == 0 { -1 } else { (stored - 1) as i64 };
        let mlen = measure_lz77_match(chunk, cand, pos);
        if mlen >= 4 {
            let cmd = BrotliLz77Cmd {
                ins_start: lit_start as u32,
                ins_len:   (pos - lit_start) as u32,
                copy_len:  mlen as u32,
                distance:  (pos - cand) as u32,
            };
            guard cmds.try_push(cmd) else { break; }
            htable[h] = (pos + 1) as u16;
            matched_bytes += mlen;
            pos += mlen;
            lit_start = pos;
            continue;
        }
        htable[h] = (pos + 1) as u16;
        pos += 1;
    }

    if lit_start < chunk.len && cmds.len > 0 {
        let tail_cmd = BrotliLz77Cmd {
            ins_start: lit_start as u32,
            ins_len:   (chunk.len - lit_start) as u32,
            copy_len:  2,
            distance:  1,
        };
        guard cmds.try_push(tail_cmd) else { return 0; }
    }
    return matched_bytes;
}

// Scans `chunk` with an adaptive greedy hash table and records LZ77 commands into `cmds`.
//
// Example:
//   chunk = "AAAAAAAA", cmds = []
//   returns: 8
fn scan_brotli_lz77_commands(chunk: const u8[:], cmds: BrotliLz77Cmd[..4096]&) -> i64 {
    cmds.clear();
    if chunk.len <= 2048 {
        return scan_brotli_lz77_small(chunk, cmds);
    }
    var htable:        i32[4096] = [-1; 4096];
    var pos:           i64       = 0;
    var lit_start:     i64       = 0;
    var matched_bytes: i64       = 0;

    while pos + 4 <= chunk.len {
        let h = hash4_brotli(chunk, pos, 20);
        let cand = htable[h] as i64;
        let mlen = measure_lz77_match(chunk, cand, pos);
        if mlen >= 4 {
            let cmd = BrotliLz77Cmd {
                ins_start: lit_start as u32,
                ins_len:   (pos - lit_start) as u32,
                copy_len:  mlen as u32,
                distance:  (pos - cand) as u32,
            };
            guard cmds.try_push(cmd) else { break; }
            htable[h] = pos as i32;
            matched_bytes += mlen;
            pos += mlen;
            lit_start = pos;
            continue;
        }
        htable[h] = pos as i32;
        pos += 1;
    }

    if lit_start < chunk.len && cmds.len > 0 {
        let tail_cmd = BrotliLz77Cmd {
            ins_start: lit_start as u32,
            ins_len:   (chunk.len - lit_start) as u32,
            copy_len:  2,
            distance:  1,
        };
        guard cmds.try_push(tail_cmd) else { return 0; }
    }
    return matched_bytes;
}

fn emit_brotli_compressed_chunk<B>(
    w:         BrotliBitWriter&,
    chunk:     const u8[:],
    cmds:      const BrotliLz77Cmd[:],
    dist_ring: u32[4]&,
    out:       B&,
) {
    brotli_write_bits(w, 1, 0, out); // ISLAST = 0
    brotli_write_bits(w, 2, 0, out); // MNIBBLES = 0 (4 nibbles = 16 bits)
    brotli_write_bits(w, 16, (chunk.len - 1) as u64, out);
    brotli_write_bits(w, 1, 0, out); // ISUNCOMPRESSED = 0

    // 3x num_block_types = 1 (3 zero bits), dist_params = 0 (6 zero bits),
    // context_mode = 0 (2 zero bits), num_lit_htrees = 1 (1 zero bit), num_dist_htrees = 1 (1 zero bit)
    brotli_write_bits(w, 13, 0, out);

    emit_brotli_flat_prefix_code(w, 256, out);
    emit_brotli_flat_prefix_code(w, 704, out);
    emit_brotli_flat_prefix_code(w, 64, out);

    for &cmd in cmds {
        let ins_code, ins_eb, ins_ev = encode_brotli_insert_len(cmd.ins_len);
        let copy_code, copy_eb, copy_ev = encode_brotli_copy_len(cmd.copy_len);
        let dist_zero = (cmd.distance == dist_ring[0]) && (ins_code < 8) && (copy_code < 16);
        let cmd_sym = encode_brotli_cmd_code(ins_code, copy_code, dist_zero);

        write_canonical_sym(w, cmd_sym, 704, out);
        if ins_eb > 0 {
            brotli_write_bits(w, ins_eb, ins_ev as u64, out);
        }
        if copy_eb > 0 {
            brotli_write_bits(w, copy_eb, copy_ev as u64, out);
        }
        let s_idx = cmd.ins_start as i64;
        let ins_end = cmd.ins_len as i64;
        var k: i64 = 0;
        while k + 4 <= ins_end {
            let b0 = BROTLI_REV8[chunk[s_idx + k] as i64] as u64;
            let b1 = BROTLI_REV8[chunk[s_idx + k + 1] as i64] as u64;
            let b2 = BROTLI_REV8[chunk[s_idx + k + 2] as i64] as u64;
            let b3 = BROTLI_REV8[chunk[s_idx + k + 3] as i64] as u64;
            brotli_write_bits(w, 32, b0 | (b1 << 8) | (b2 << 16) | (b3 << 24), out);
            k += 4;
        }
        while k < ins_end {
            brotli_write_bits(w, 8, BROTLI_REV8[chunk[s_idx + k] as i64] as u64, out);
            k += 1;
        }
        if (s_idx + ins_end) >= chunk.len {
            break;
        }
        if !dist_zero {
            let dcode, deb, dev = encode_brotli_distance_code(cmd.distance, dist_ring);
            write_canonical_sym(w, dcode, 64, out);
            if deb > 0 {
                brotli_write_bits(w, deb, dev as u64, out);
            }
        }
    }
}

// Emits an authentic RFC 7932 uncompressed stream.
fn emit_brotli_stream_header<B>(w: BrotliBitWriter&, out: B&) {
    brotli_write_bits(w, 1, 0, out);
}

fn emit_brotli_uncompressed_chunk<B>(w: BrotliBitWriter&, chunk: const u8[:], out: B&) {
    brotli_write_bits(w, 1, 0, out);
    brotli_write_bits(w, 2, 0, out);
    brotli_write_bits(w, 16, (chunk.len - 1) as u64, out);
    brotli_write_bits(w, 1, 1, out);
    brotli_write_byte_align(w, out);
    if !comp_try_append(out, chunk) {
        w.overflow = true;
    }
}

fn emit_brotli_final_empty_metablock<B>(w: BrotliBitWriter&, out: B&) {
    brotli_write_bits(w, 1, 1, out);
    brotli_write_bits(w, 1, 1, out);
    brotli_write_byte_align(w, out);
}

fn encode_brotli_level1_chunk<B>(
    w:         BrotliBitWriter&,
    chunk:     const u8[:],
    cmds:      BrotliLz77Cmd[..4096]&,
    dist_ring: u32[4]&,
    out:       B&,
) {
    let matched = scan_brotli_lz77_commands(chunk, cmds);
    if cmds.len > 0 && matched > (cmds.len * 3 + 64) {
        emit_brotli_compressed_chunk(w, chunk, cmds[..], dist_ring, out);
    } else {
        emit_brotli_uncompressed_chunk(w, chunk, out);
    }
}

fn brotli_compress_stream<B>(src: const u8[:], level: i32, out: B&) -> bool {
    if src.len == 0 {
        return comp_try_push(out, 6 as u8);
    }

    var w = BrotliBitWriter { .. };
    emit_brotli_stream_header(w, out);
    var dist_ring: u32[4]                = [4, 11, 15, 16];
    var cmds:      BrotliLz77Cmd[..4096] = [];
    let max_chunk: i64 = if level <= 0 { 65536 } else { 65500 };

    let total = src.len;
    var offset: i64 = 0;
    while offset < total {
        let next_offset = min(offset + max_chunk, total);
        let chunk = src[offset..next_offset];
        if level <= 0 {
            emit_brotli_uncompressed_chunk(w, chunk, out);
        } else {
            encode_brotli_level1_chunk(w, chunk, cmds, dist_ring, out);
        }
        guard !w.overflow else { return false; }
        offset = next_offset;
    }

    emit_brotli_final_empty_metablock(w, out);
    return !w.overflow;
}

// Universal Brotli compression entry point.
fn brotli_compress<B>(src: const u8[:], out: B&, level: i32 = 0) -> bool {
    let saved_len = out.len;
    let ok = brotli_compress_stream(src, if level <= 0 { 0 } else { 1 }, out);
    if !ok {
        out.resize(saved_len);
    }
    return ok;
}

// ---- Main RFC 7932 Brotli Decompressor -----------------------------------

// Decodes a variable-length unsigned 8-bit integer from the bitstream.
//
// Example:
//   r = bit 0
//   returns: 0
fn decode_varlen_uint8(r: BrotliBitReader&) -> u32 {
    let b = brotli_read_bits(r, 1);
    if b == 0 {
        return 0;
    }
    let b3 = brotli_read_bits(r, 3);
    if b3 == 0 {
        return 1;
    }
    let bits = brotli_read_bits(r, b3);
    return ((1 as u32) << b3) + bits;
}

// Decodes Brotli sliding window size bits (RFC 7932 Section 9.1).
//
// Example:
//   r = bit 0
//   returns: CompressError.None, out_wbits = 16
fn decode_brotli_window_bits(r: BrotliBitReader&, out_wbits: u32&) -> CompressError {
    let wbit0 = brotli_read_bits(r, 1);
    guard !r.underflow else { return CompressError.InputBufferTruncated; }
    if wbit0 == 0 {
        out_wbits = 16;
        return CompressError.None;
    }
    let n = brotli_read_bits(r, 3);
    guard !r.underflow else { return CompressError.InputBufferTruncated; }
    if n != 0 {
        out_wbits = 17 + n;
        return CompressError.None;
    }
    let m = brotli_read_bits(r, 3);
    guard !r.underflow else { return CompressError.InputBufferTruncated; }
    if m != 0 {
        let wbits = 8 + m;
        guard wbits >= BROTLI_MIN_WINDOW_BITS && wbits <= BROTLI_MAX_WINDOW_BITS else {
            return CompressError.InvalidHeader;
        }
        out_wbits = wbits;
        return CompressError.None;
    }
    out_wbits = 17;
    return CompressError.None;
}

root struct BrotliBlockState {
    num_block_types: u32[3]                  = [1, 1, 1],
    block_type:      u32[3]                  = [0, 0, 0],
    prev_type0:      u32[3]                  = [0, 0, 0],
    prev_type1:      u32[3]                  = [1, 1, 1],
    block_len:       u32[3]                  = [0, 0, 0],
    context_modes:   u8[256]                 = [0; 256],
    num_lit_htrees:  u32                     = 1,
    num_dist_htrees: u32                     = 1,
    lit0_desc:       BrotliTreeDesc          = BrotliTreeDesc { .. },
    cmd0_desc:       BrotliTreeDesc          = BrotliTreeDesc { .. },
    dist0_desc:      BrotliTreeDesc          = BrotliTreeDesc { .. },
    bt_tables:       BrotliHuffmanTable[>..] = [],
    bl_tables:       BrotliHuffmanTable[>..] = [],
    c_map_lit:       u8[>..]                 = [],
    c_map_dist:      u8[>..]                 = [],
    lit_descs:       BrotliTreeDesc[>..]     = [],
    cmd_descs:       BrotliTreeDesc[>..]     = [],
    dist_descs:      BrotliTreeDesc[>..]     = [],
    tables:          BrotliHuffmanTable[>..] = [],
}

// Decodes a block length from `bl_table` and extra bits (RFC 7932 Section 6).
//
// Example:
//   bl_table.single_symbol = 0, extra = 0
//   returns: len = 1, ok = true
fn decode_brotli_block_len(
    r:        BrotliBitReader&,
    bl_table: const BrotliHuffmanTable&,
) -> u32, bool {
    let code, ok = decode_brotli_symbol(r, bl_table);
    guard ok && code >= 0 && code < 26 else { return 0, false; }
    let eb = BROTLI_BLOCK_LEN_EXTRA[code as i64] as u32;
    let extra = if eb > 0 { brotli_read_bits(r, eb) } else { 0 };
    return add_sat_u32(BROTLI_BLOCK_LEN_BASE[code as i64], extra), !r.underflow;
}

// Switches to the next block of category `cat` (`0` = literal, `1` = command, `2` = distance)
// when `bs.block_len[cat]` reaches 0 (RFC 7932 Section 6).
//
// Example:
//   cat = 0, bs.num_block_types[0] = 2
//   returns: true
fn switch_brotli_block(
    r:   BrotliBitReader&,
    bs:  BrotliBlockState&,
    cat: i64,
) -> bool {
    let nbt = bs.num_block_types[cat];
    guard nbt >= 2 else {
        bs.block_len[cat] = 0x10000000;
        return true;
    }
    guard cat < bs.bt_tables.len && cat < bs.bl_tables.len else { return false; }
    let tcode, ok_t = decode_brotli_symbol(r, bs.bt_tables[cat]);
    guard ok_t && tcode >= 0 else { return false; }
    let tc = tcode as u32;
    var next_type: u32 = 0;
    if tc == 0 {
        next_type = bs.prev_type0[cat];
    } else if tc == 1 {
        let inc = add_sat_u32(bs.block_type[cat], 1);
        next_type = if inc >= nbt { 0 } else { inc };
    } else {
        next_type = sub_sat_u32(tc, 2);
        guard next_type < nbt else { return false; }
    }
    bs.prev_type0[cat] = bs.prev_type1[cat];
    bs.prev_type1[cat] = next_type;
    bs.block_type[cat] = next_type;

    let blen, ok_l = decode_brotli_block_len(r, bs.bl_tables[cat]);
    guard ok_l else { return false; }
    bs.block_len[cat] = blen;
    return true;
}

fn read_brotli_block_types(r: BrotliBitReader&, bs: BrotliBlockState&) -> CompressError {
    for i in 3 {
        let nbt = add_sat_u32(decode_varlen_uint8(r), 1);
        bs.num_block_types[i] = nbt;
        bs.block_type[i] = 0;
        bs.prev_type0[i] = 0;
        bs.prev_type1[i] = 1;
        if nbt >= 2 {
            if bs.bt_tables.len < 3 {
                bs.bt_tables.resize(3, BrotliHuffmanTable { .. });
                bs.bl_tables.resize(3, BrotliHuffmanTable { .. });
            }
            let bt_alpha = add_sat_u32(nbt, 2) as i32;
            let ok_bt = read_brotli_prefix_code(r, bt_alpha, bs.bt_tables[i]);
            guard ok_bt else { return CompressError.InvalidHuffmanCode; }
            let ok_bl = read_brotli_prefix_code(r, 26, bs.bl_tables[i]);
            guard ok_bl else { return CompressError.InvalidHuffmanCode; }
            let blen, ok_len = decode_brotli_block_len(r, bs.bl_tables[i]);
            guard ok_len else { return CompressError.CorruptedBitstream; }
            bs.block_len[i] = blen;
        } else {
            bs.block_len[i] = 0x10000000;
        }
    }
    return CompressError.None;
}

fn read_literal_context_modes(r: BrotliBitReader&, bs: BrotliBlockState&) {
    let count = bs.num_block_types[0];
    for i in count {
        let mode = brotli_read_bits(r, 2) as u8;
        if (i as i64) < 256 {
            bs.context_modes[i as i64] = mode;
        }
    }
}

fn inverse_move_to_front_transform(v: u8[:]) {
    var mtf: u8[256] = [0; 256];
    for i in 256 {
        mtf[i] = i as u8;
    }
    for i in v.len {
        let idx = v[i] as i64;
        let val = mtf[idx];
        v[i] = val;
        for k in idx {
            let dst = sub_sat_i64(idx, k);
            mtf[dst] = mtf[sub_sat_i64(dst, 1)];
        }
        mtf[0] = val;
    }
}

// Decodes RLE-encoded context map entries using `cmap_table` (RFC 7932 Section 7.3).
//
// Example:
//   rlemax = 2, map_size = 4, symbols = [1 (0 bits), 3, 4]
//   returns: true, out_map = [0, 0, 1, 2]
fn decode_context_map_entries(
    r:          BrotliBitReader&,
    cmap_table: const BrotliHuffmanTable&,
    rlemax:     u32,
    map_size:   i64,
    out_map:    u8[:],
) -> bool {
    var i: i64 = 0;
    while i < map_size {
        let code, ok = decode_brotli_symbol(r, cmap_table);
        guard ok && code >= 0 else { return false; }
        let c = code as u32;
        if c == 0 {
            out_map[i] = 0;
            i = add_sat_i64(i, 1);
        } else if c <= rlemax {
            let base_rep = (shl_sat_u64(1, c) & 0xFFFF) as u32;
            let reps = add_sat_u32(base_rep, brotli_read_bits(r, c)) as i64;
            guard add_sat_i64(i, reps) <= map_size else { return false; }
            for _ in reps {
                out_map[i] = 0;
                i = add_sat_i64(i, 1);
            }
        } else {
            out_map[i] = sub_sat_u32(c, rlemax) as u8;
            i = add_sat_i64(i, 1);
        }
    }
    return true;
}

// Decodes a context map of size `map_size` mapping contexts to `0..num_trees - 1` (RFC 7932 Section 7.3).
//
// Example:
//   num_trees = 1, map_size = 64
//   returns: true
fn decode_brotli_context_map(
    r:         BrotliBitReader&,
    num_trees: u32,
    map_size:  i64,
    out_map:   u8[>..]&,
) -> bool {
    if num_trees <= 1 {
        return true;
    }
    if out_map.len < map_size {
        out_map.resize(map_size, 0);
    }

    let use_rle = brotli_read_bits(r, 1) != 0;
    let rlemax = if use_rle { add_sat_u32(brotli_read_bits(r, 4), 1) } else { 0 };
    let alphabet_size = add_sat_u32(num_trees, rlemax) as i32;

    var cmap_table = BrotliHuffmanTable { .. };
    guard read_brotli_prefix_code(r, alphabet_size, cmap_table) else { return false; }
    guard decode_context_map_entries(r, cmap_table, rlemax, map_size, out_map[..]) else { return false; }

    let imtf_bit = brotli_read_bits(r, 1);
    if imtf_bit != 0 {
        inverse_move_to_front_transform(out_map[..map_size]);
    }
    return !r.underflow;
}

// Computes the 6-bit literal context ID (0..63) from the previous two uncompressed bytes `p1` and `p2`
// under `mode` (`0` = LSB6, `1` = MSB6, `2` = UTF8, `3` = Signed) per RFC 7932 Section 7.1.
//
// Example:
//   p1 = 0x41, p2 = 0x20, mode = 0
//   returns: 1
inline fn compute_brotli_literal_context(p1: u8, p2: u8, mode: u8) -> i64 {
    if mode == 0 {
        return p1 & 0x3F;
    }
    if mode == 1 {
        return p1 >> 2;
    }
    if mode == 2 {
        return (BROTLI_CONTEXT_LUT_0[p1 as i64] | BROTLI_CONTEXT_LUT_1[p2]);
    }
    return ((BROTLI_CONTEXT_LUT_2[p1 as i64] << 3) | BROTLI_CONTEXT_LUT_2[p2]);
}

inline fn resolve_literal_htree_idx(bs: const BrotliBlockState&, p1: u8, p2: u8) -> i64 {
    if bs.num_lit_htrees <= 1 {
        return 0;
    }
    let btype = (bs.block_type[0] & 0xFF) as i64;
    let mode = bs.context_modes[btype];
    let ctx = compute_brotli_literal_context(p1, p2, mode) & 63;
    let map_idx = ((btype << 6) | ctx) & 16383;
    return bs.c_map_lit[map_idx] & 63;
}

inline fn resolve_distance_htree_idx(bs: const BrotliBlockState&, copy_len: u32) -> i64 {
    if bs.num_dist_htrees <= 1 {
        return 0;
    }
    let dctx = if copy_len > 4 { 3 } else { (sub_sat_u32(copy_len, 2) & 3) as i64 };
    let btype = (bs.block_type[2] & 0xFF) as i64;
    let map_idx = ((btype << 2) | dctx) & 1023;
    return bs.c_map_dist[map_idx] & 63;
}

fn read_brotli_tree_group(
    r:             BrotliBitReader&,
    alphabet_size: i32,
    count:         u32,
    first_desc:    BrotliTreeDesc&,
    extra_descs:   BrotliTreeDesc[>..]&,
    tables:        BrotliHuffmanTable[>..]&,
    scratch_lens:  u8[704]&,
) -> bool {
    guard read_brotli_tree_desc(r, alphabet_size, first_desc, tables, scratch_lens) else { return false; }
    if count > 1 {
        let need = sub_sat_u32(count, 1) as i64;
        if extra_descs.len < need {
            extra_descs.resize(need, BrotliTreeDesc { .. });
        }
        for i in need {
            guard read_brotli_tree_desc(r, alphabet_size, extra_descs[i], tables, scratch_lens) else {
                return false;
            }
        }
    }
    return true;
}

fn read_brotli_tree_arrays(
    r:        BrotliBitReader&,
    ndirect:  u32,
    npostfix: u32,
    bs:       BrotliBlockState&,
) -> bool {
    guard bs.num_lit_htrees <= 64 && bs.num_block_types[1] <= 64 && bs.num_dist_htrees <= 64 else {
        return false;
    }
    var scratch_lens: u8[704] = [0; 704];
    let dist_alpha = (16 + ndirect + ((48 as u32) << (npostfix & 3))) as i32;
    guard read_brotli_tree_group(
        r, 256, bs.num_lit_htrees, bs.lit0_desc, bs.lit_descs, bs.tables, scratch_lens,
    ) else { return false; }
    guard read_brotli_tree_group(
        r, 704, bs.num_block_types[1], bs.cmd0_desc, bs.cmd_descs, bs.tables, scratch_lens,
    ) else { return false; }
    return read_brotli_tree_group(
        r, dist_alpha, bs.num_dist_htrees, bs.dist0_desc, bs.dist_descs, bs.tables, scratch_lens,
    );
}

// Decodes an RFC 7932 Section 9.2 metadata meta-block.
//
// Example:
//   r = reserved bit 0
//   returns: CompressError.None
fn decode_brotli_metadata_block(r: BrotliBitReader&) -> CompressError {
    let reserved = brotli_read_bits(r, 1);
    guard !r.underflow else { return CompressError.InputBufferTruncated; }
    guard reserved == 0 else { return CompressError.CorruptedBitstream; }

    let mskipbytes = brotli_read_bits(r, 2);
    guard !r.underflow else { return CompressError.InputBufferTruncated; }
    var mskiplen: u32 = 0;
    if mskipbytes > 0 {
        var last_byte: u32 = 0;
        for i in mskipbytes {
            let b = brotli_read_bits(r, 8);
            mskiplen |= b << (8 * i);
            last_byte = b;
        }
        guard !r.underflow else { return CompressError.InputBufferTruncated; }
        guard mskipbytes == 1 || last_byte != 0 else {
            return CompressError.CorruptedBitstream;
        }
        mskiplen += 1;
    }

    let rem_bits = r.bit_count & 7;
    if rem_bits > 0 {
        let fill = brotli_read_bits(r, rem_bits);
        guard !r.underflow else { return CompressError.InputBufferTruncated; }
        guard fill == 0 else { return CompressError.CorruptedBitstream; }
    }

    for i in mskiplen {
        if r.bit_count < 8 && r.pos >= r.src.len {
            return CompressError.InputBufferTruncated;
        }
        let _ = brotli_read_bits(r, 8);
    }
    return CompressError.None;
}

// Decodes an RFC 7932 Section 9.2 uncompressed meta-block.
//
// Example:
//   mlen = 0
//   returns: CompressError.None
fn decode_brotli_uncompressed_block<B>(
    r:       BrotliBitReader&,
    mlen:    u32,
    out:     B&,
    prev_p1: u8&,
    prev_p2: u8&,
) -> CompressError {
    let align_bits = r.bit_count & 7;
    if align_bits > 0 {
        let align_pad = brotli_read_bits(r, align_bits);
        guard !r.underflow else { return CompressError.InputBufferTruncated; }
        guard align_pad == 0 else { return CompressError.CorruptedBitstream; }
    }
    let buffered_bytes = (r.bit_count >> 3) as i64;
    r.pos = sub_sat_i64(r.pos, buffered_bytes);
    r.bit_buf = 0;
    r.bit_count = 0;

    let need = mlen as i64;
    guard need <= sub_sat_i64(r.src.len, r.pos) else {
        r.pos = r.src.len;
        r.underflow = true;
        return CompressError.InputBufferTruncated;
    }
    let src_end = add_sat_i64(r.pos, need);
    let slice = r.src[r.pos..src_end];
    guard comp_try_append(out, slice) else { return CompressError.OutputBufferOverflow; }
    r.pos = src_end;
    if need >= 2 {
        prev_p1 = slice[need - 1];
        prev_p2 = slice[need - 2];
    } else if need == 1 {
        prev_p2 = prev_p1;
        prev_p1 = slice[0];
    }
    brotli_fill_bits(r);
    return CompressError.None;
}

// Decodes meta-block uncompressed length from nibbles (RFC 7932 Section 9.2).
//
// Example:
//   mnibbles = 0
//   returns: mlen = 1, ok = true
fn decode_meta_block_length(r: BrotliBitReader&, mnibbles: u32) -> u32, bool {
    let num_nibbles = if mnibbles == 0 { 4 } else if mnibbles == 1 { 5 } else { 6 };
    var mlen:     u32 = 0;
    var last_nib: u32 = 0;
    for i in num_nibbles {
        let nib = brotli_read_bits(r, 4);
        mlen |= nib << (4 * i);
        last_nib = nib;
    }
    guard num_nibbles <= 4 || last_nib != 0 else {
        return 0, false;
    }
    return mlen + 1, true;
}

inline fn brotli_read_backward_byte<B>(
    out:           const B&,
    out_start_pos: i64,
    dict:          const u8[:],
    dist_offset:   i64,
) -> u8 {
    let produced = sub_sat_i64(out.len, out_start_pos);
    if dist_offset <= produced {
        return out[sub_sat_i64(out.len, dist_offset)];
    }
    let dict_back = sub_sat_i64(dist_offset, produced);
    return dict[sub_sat_i64(dict.len, dict_back)];
}

fn apply_brotli_dict_copy<B>(
    out:                  B&,
    out_start_pos:        i64,
    distance:             u32,
    copy_len:             u32,
    max_allowed_backward: u32,
    max_output_bytes:     i64,
    meta_block_remaining: u32&,
    dist_ring:            u32[4]&,
    dist_ring_prev:       const u32[4]&,
    prev_p1:              u8&,
    prev_p2:              u8&,
) -> CompressError {
    guard is_valid_brotli_dict_word(distance, max_allowed_backward, copy_len) else {
        return CompressError.DistanceOutOfBounds;
    }
    dist_ring = dist_ring_prev;
    let len_before = out.len;
    guard brotli_lookup_dictionary_word(distance, max_allowed_backward, copy_len, out) else {
        return CompressError.OutputBufferOverflow;
    }
    let dict_len = sub_sat_i64(out.len, len_before) as u32;
    guard meta_block_remaining >= dict_len else {
        return CompressError.CorruptedBitstream;
    }
    if max_output_bytes >= 0 && sub_sat_i64(out.len, out_start_pos) > max_output_bytes {
        return CompressError.OutputBufferOverflow;
    }
    meta_block_remaining = sub_sat_u32(meta_block_remaining, dict_len);
    if dict_len >= 2 {
        prev_p1 = out[sub_sat_i64(out.len, 1)];
        prev_p2 = out[sub_sat_i64(out.len, 2)];
    } else if dict_len == 1 {
        prev_p2 = prev_p1;
        prev_p1 = out[sub_sat_i64(out.len, 1)];
    }
    return CompressError.None;
}

fn apply_brotli_in_frame_copy<B>(
    out:         B&,
    dist_offset: i64,
    copy_len:    u32,
    prev_p1:     u8&,
    prev_p2:     u8&,
) -> CompressError {
    let src_idx = sub_sat_i64(out.len, dist_offset);
    let c_len = copy_len as i64;
    if dist_offset >= c_len {
        let src_end = add_sat_i64(src_idx, c_len);
        guard comp_try_append(out, out[src_idx..src_end]) else {
            return CompressError.OutputBufferOverflow;
        }
    } else if dist_offset == 1 {
        guard comp_try_fill(out, c_len, out[src_idx]) else {
            return CompressError.OutputBufferOverflow;
        }
    } else {
        var curr: i64 = 0;
        while curr < c_len {
            let step = min(curr + dist_offset, c_len - curr);
            guard comp_try_append(out, out[src_idx..src_idx + step]) else {
                return CompressError.OutputBufferOverflow;
            }
            curr += step;
        }
    }
    if c_len >= 2 {
        prev_p1 = out[sub_sat_i64(out.len, 1)];
        prev_p2 = out[sub_sat_i64(out.len, 2)];
    } else if c_len == 1 {
        prev_p2 = prev_p1;
        prev_p1 = out[sub_sat_i64(out.len, 1)];
    }
    return CompressError.None;
}

fn apply_brotli_copy<B>(
    out:                  B&,
    out_start_pos:        i64,
    dict:                 const u8[:],
    distance:             u32,
    copy_len:             u32,
    max_allowed_backward: u32,
    max_output_bytes:     i64,
    meta_block_remaining: u32&,
    dist_ring:            u32[4]&,
    dist_ring_prev:       const u32[4]&,
    prev_p1:              u8&,
    prev_p2:              u8&,
) -> CompressError {
    if distance > max_allowed_backward {
        return apply_brotli_dict_copy(
            out, out_start_pos, distance, copy_len, max_allowed_backward,
            max_output_bytes, meta_block_remaining, dist_ring, dist_ring_prev,
            prev_p1, prev_p2,
        );
    }
    guard meta_block_remaining >= copy_len else {
        return CompressError.CorruptedBitstream;
    }
    let produced = sub_sat_i64(out.len, out_start_pos);
    if max_output_bytes >= 0 && add_sat_i64(produced, copy_len as i64) > max_output_bytes {
        return CompressError.OutputBufferOverflow;
    }
    let dist_offset = distance as i64;
    guard dist_offset <= add_sat_i64(produced, dict.len) else { return CompressError.DistanceOutOfBounds; }

    if dist_offset <= produced {
        let err = apply_brotli_in_frame_copy(out, dist_offset, copy_len, prev_p1, prev_p2);
        guard err == CompressError.None else { return err; }
    } else {
        for k in copy_len {
            let b = brotli_read_backward_byte(out, out_start_pos, dict, dist_offset);
            guard comp_try_push(out, b) else { return CompressError.OutputBufferOverflow; }
            prev_p2 = prev_p1;
            prev_p1 = b;
        }
    }
    meta_block_remaining = sub_sat_u32(meta_block_remaining, copy_len);
    return CompressError.None;
}

fn insert_brotli_literals_ctx<B>(
    r:       BrotliBitReader&,
    ins_len: u32,
    bs:      BrotliBlockState&,
    prev_p1: u8&,
    prev_p2: u8&,
    out:     B&,
) -> CompressError {
    for _ in ins_len {
        if bs.block_len[0] == 0 {
            guard switch_brotli_block(r, bs, 0) else { return CompressError.CorruptedBitstream; }
        }
        bs.block_len[0] = sub_sat_u32(bs.block_len[0], 1);

        let htree_idx = resolve_literal_htree_idx(bs, prev_p1, prev_p2);
        var lit:  i32  = -1;
        var ok_l: bool = false;
        if htree_idx == 0 {
            lit, ok_l = decode_brotli_tree_symbol(r, bs.lit0_desc, bs.tables[..]);
        } else {
            lit, ok_l = decode_brotli_tree_symbol(r, bs.lit_descs[htree_idx - 1], bs.tables[..]);
        }
        guard ok_l && lit >= 0 else { return CompressError.CorruptedBitstream; }
        let lit_byte = lit as u8;
        guard comp_try_push(out, lit_byte) else { return CompressError.OutputBufferOverflow; }
        prev_p2 = prev_p1;
        prev_p1 = lit_byte;
    }
    return CompressError.None;
}

fn insert_brotli_flat8_literals<B>(r: BrotliBitReader&, ins_len: u32, out: B&) -> CompressError {
    var i: i64 = 0;
    let n = ins_len as i64;
    guard comp_has_room(out, n) else { return CompressError.OutputBufferOverflow; }
    while i + 4 <= n && r.pos + 4 <= r.src.len {
        if r.bit_count < 32 {
            let w = read_le_u32(r.src, r.pos) as u64;
            r.bit_buf |= w << r.bit_count;
            r.pos += 4;
            r.bit_count += 32;
        }
        let w32 = (r.bit_buf & 0xFFFFFFFF) as u32;
        r.bit_buf >>= 32;
        r.bit_count -= 32;
        let b0: u32 = BROTLI_REV8[(w32 & 0xFF) as i64];
        let b1: u32 = BROTLI_REV8[((w32 >> 8) & 0xFF) as i64];
        let b2: u32 = BROTLI_REV8[((w32 >> 16) & 0xFF) as i64];
        let b3: u32 = BROTLI_REV8[((w32 >> 24) & 0xFF) as i64];
        let packed = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
        guard comp_try_write_le_u32(out, packed) else { return CompressError.OutputBufferOverflow; }
        i += 4;
    }
    while i < n {
        let b_code = brotli_read_bits(r, 8);
        guard !r.underflow else { return CompressError.CorruptedBitstream; }
        guard comp_try_push(out, BROTLI_REV8[(b_code & 0xFF) as i64]) else {
            return CompressError.OutputBufferOverflow;
        }
        i += 1;
    }
    return CompressError.None;
}

fn insert_brotli_fast_literals<B>(
    r:       BrotliBitReader&,
    ins_len: u32,
    desc:    const BrotliTreeDesc&,
    tables:  const BrotliHuffmanTable[:],
    out:     B&,
) -> CompressError {
    if desc.single_symbol >= 0 {
        guard comp_try_fill(out, ins_len as i64, desc.single_symbol as u8) else {
            return CompressError.OutputBufferOverflow;
        }
        return CompressError.None;
    }
    if desc.flat_kind == BROTLI_FLAT_8 {
        return insert_brotli_flat8_literals(r, ins_len, out);
    }
    guard desc.table_idx >= 0 && (desc.table_idx as i64) < tables.len else {
        return CompressError.CorruptedBitstream;
    }
    let lit_table .= tables[desc.table_idx as i64];
    var i: i64 = 0;
    let n = ins_len as i64;
    if lit_table.max_len <= 10 {
        while i + 2 <= n && r.pos + 8 <= r.src.len {
            if r.bit_count < 32 {
                brotli_fill_bits(r);
            }
            let e0 = lit_table.fast[(r.bit_buf & 0x3FF) as i64];
            let l0 = (e0 >> 10) as u32;
            r.bit_buf >>= l0;
            r.bit_count -= l0;

            let e1 = lit_table.fast[(r.bit_buf & 0x3FF) as i64];
            guard e0 != 0 && e1 != 0 else { return CompressError.CorruptedBitstream; }
            let l1 = (e1 >> 10) as u32;
            r.bit_buf >>= l1;
            r.bit_count -= l1;

            let pair: u8[2] = [(e0 & 0xFF) as u8, (e1 & 0xFF) as u8];
            guard comp_try_append(out, pair[..]) else { return CompressError.OutputBufferOverflow; }
            i += 2;
        }
    }
    while i < n {
        let lit, ok_l = decode_brotli_symbol(r, lit_table);
        guard ok_l && lit >= 0 else { return CompressError.CorruptedBitstream; }
        guard comp_try_push(out, lit as u8) else { return CompressError.OutputBufferOverflow; }
        i += 1;
    }
    return CompressError.None;
}

fn insert_brotli_literals<B>(
    r:                BrotliBitReader&,
    ins_len:          u32,
    bs:               BrotliBlockState&,
    max_output_bytes: i64,
    prev_p1:          u8&,
    prev_p2:          u8&,
    out:              B&,
    out_start_pos:    i64,
) -> CompressError {
    guard ins_len > 0 else { return CompressError.None; }
    let produced = sub_sat_i64(out.len, out_start_pos);
    if max_output_bytes >= 0 && add_sat_i64(produced, ins_len as i64) > max_output_bytes {
        return CompressError.OutputBufferOverflow;
    }
    let err = if bs.num_lit_htrees > 1 || bs.num_block_types[0] > 1 {
        insert_brotli_literals_ctx(r, ins_len, bs, prev_p1, prev_p2, out)
    } else {
        insert_brotli_fast_literals(r, ins_len, bs.lit0_desc, bs.tables[..], out)
    };
    guard err == CompressError.None else { return err; }
    let out_end = out.len;
    if ins_len >= 2 {
        prev_p1 = out[sub_sat_i64(out_end, 1)];
        prev_p2 = out[sub_sat_i64(out_end, 2)];
    } else if bs.num_lit_htrees <= 1 && bs.num_block_types[0] <= 1 {
        prev_p2 = prev_p1;
        prev_p1 = out[sub_sat_i64(out_end, 1)];
    }
    return CompressError.None;
}

fn read_brotli_command_distance(
    r:         BrotliBitReader&,
    dist_zero: bool,
    copy_len:  u32,
    bs:        BrotliBlockState&,
    npostfix:  u32,
    ndirect:   u32,
    dist_ring: u32[4]&,
) -> u32, CompressError {
    if dist_zero {
        return dist_ring[0], CompressError.None;
    }
    if bs.num_block_types[2] > 1 {
        if bs.block_len[2] == 0 {
            guard switch_brotli_block(r, bs, 2) else { return 0, CompressError.CorruptedBitstream; }
        }
        bs.block_len[2] = sub_sat_u32(bs.block_len[2], 1);
    }

    let htree_idx = resolve_distance_htree_idx(bs, copy_len);
    var dcode: i32  = -1;
    var ok_d:  bool = false;
    if htree_idx == 0 {
        dcode, ok_d = decode_brotli_tree_symbol(r, bs.dist0_desc, bs.tables[..]);
    } else {
        dcode, ok_d = decode_brotli_tree_symbol(r, bs.dist_descs[htree_idx - 1], bs.tables[..]);
    }
    guard ok_d && dcode >= 0 else { return 0, CompressError.CorruptedBitstream; }
    let distance = decode_brotli_distance(r, dcode as u32, npostfix, ndirect, dist_ring);
    guard distance > 0 else { return 0, CompressError.DistanceOutOfBounds; }
    return distance, CompressError.None;
}

fn read_brotli_cmd_lengths(r: BrotliBitReader&, cmd_code: u32) -> u32, u32, bool {
    let ins_code, copy_code, dist_zero = decode_cmd_code(cmd_code);
    let ins_extra = INSERT_LENGTH_EXTRA_BITS[ins_code as i64] as u32;
    let ins_extra_val = if ins_extra > 0 { brotli_read_bits(r, ins_extra) } else { 0 };
    let ins_len = INSERT_LENGTH_BASE[ins_code as i64] + ins_extra_val;

    let copy_extra = COPY_LENGTH_EXTRA_BITS[copy_code as i64] as u32;
    let copy_extra_val = if copy_extra > 0 { brotli_read_bits(r, copy_extra) } else { 0 };
    let copy_len = COPY_LENGTH_BASE[copy_code as i64] + copy_extra_val;
    return ins_len, copy_len, dist_zero;
}

fn read_next_brotli_cmd_code(r: BrotliBitReader&, bs: BrotliBlockState&) -> u32, bool {
    if bs.num_block_types[1] > 1 {
        if bs.block_len[1] == 0 {
            guard switch_brotli_block(r, bs, 1) else { return 0, false; }
        }
        bs.block_len[1] = sub_sat_u32(bs.block_len[1], 1);
    }

    let cmd_btype = (bs.block_type[1] & 63) as i64;
    var cmd_code: i32  = -1;
    var ok_c:     bool = false;
    if cmd_btype == 0 {
        cmd_code, ok_c = decode_brotli_tree_symbol(r, bs.cmd0_desc, bs.tables[..]);
    } else {
        cmd_code, ok_c = decode_brotli_tree_symbol(r, bs.cmd_descs[cmd_btype - 1], bs.tables[..]);
    }
    guard ok_c && cmd_code >= 0 && cmd_code < 704 else {
        return 0, false;
    }
    return cmd_code as u32, true;
}

// Decodes Brotli commands and applies literal insertions and distance copies.
//
// Example:
//   mlen = 0
//   returns: CompressError.None
fn decode_brotli_commands<B>(
    r:                   BrotliBitReader&,
    mlen:                u32,
    bs:                  BrotliBlockState&,
    npostfix:            u32,
    ndirect:             u32,
    max_window_distance: u32,
    max_output_bytes:    i64,
    dist_ring:           u32[4]&,
    prev_p1:             u8&,
    prev_p2:             u8&,
    out:                 B&,
    dict:                const u8[:] = "",
    out_start_pos:       i64         = 0,
) -> CompressError {
    var meta_block_remaining = mlen;
    while meta_block_remaining > 0 {
        let cmd_code, ok_c = read_next_brotli_cmd_code(r, bs);
        guard ok_c else { return CompressError.CorruptedBitstream; }

        let ins_len, copy_len, dist_zero = read_brotli_cmd_lengths(r, cmd_code);

        guard meta_block_remaining >= ins_len else {
            return CompressError.CorruptedBitstream;
        }
        let ins_err = insert_brotli_literals(
            r, ins_len, bs, max_output_bytes, prev_p1, prev_p2, out, out_start_pos,
        );
        guard ins_err == CompressError.None else { return ins_err; }

        meta_block_remaining = sub_sat_u32(meta_block_remaining, ins_len);
        if meta_block_remaining == 0 {
            break;
        }

        var dist_ring_prev = dist_ring;
        let distance, dist_err = read_brotli_command_distance(r, dist_zero, copy_len, bs, npostfix, ndirect, dist_ring);
        guard dist_err == CompressError.None else { return dist_err; }

        let produced = out.len - out_start_pos;
        let total_hist = min(produced + dict.len, max_window_distance as i64);
        let max_allowed_backward = total_hist as u32;

        let copy_err = apply_brotli_copy(
            out,
            out_start_pos,
            dict,
            distance,
            copy_len,
            max_allowed_backward,
            max_output_bytes,
            meta_block_remaining,
            dist_ring,
            dist_ring_prev,
            prev_p1,
            prev_p2,
        );
        guard copy_err == CompressError.None else { return copy_err; }
    }
    return CompressError.None;
}

fn read_brotli_meta_block_header(
    r:            BrotliBitReader&,
    bs:           BrotliBlockState&,
    out_npostfix: u32&,
    out_ndirect:  u32&,
) -> CompressError {
    let bt_err = read_brotli_block_types(r, bs);
    guard bt_err == CompressError.None else { return bt_err; }

    let dist_params = brotli_read_bits(r, 6);
    let npostfix = dist_params & 3;
    let ndirect = (shl_sat_u64(dist_params >> 2, npostfix) as u32) & 0xFFFF;
    out_npostfix = npostfix;
    out_ndirect = ndirect;

    read_literal_context_modes(r, bs);

    bs.num_lit_htrees = add_sat_u32(decode_varlen_uint8(r), 1);
    let lit_map_size = (shl_sat_u64(bs.num_block_types[0] & 255, 6) & 32767) as i64;
    guard decode_brotli_context_map(r, bs.num_lit_htrees, lit_map_size, bs.c_map_lit) else {
        return CompressError.CorruptedBitstream;
    }

    bs.num_dist_htrees = add_sat_u32(decode_varlen_uint8(r), 1);
    let dist_map_size = (shl_sat_u64(bs.num_block_types[2] & 255, 2) & 2047) as i64;
    guard decode_brotli_context_map(r, bs.num_dist_htrees, dist_map_size, bs.c_map_dist) else {
        return CompressError.CorruptedBitstream;
    }

    guard read_brotli_tree_arrays(r, ndirect, npostfix, bs) else {
        return CompressError.InvalidHuffmanCode;
    }
    return CompressError.None;
}

// Decodes a compressed Brotli meta-block after block header parsing (RFC 7932 Section 9.2).
//
// Example:
//   mlen = 5, max_window_distance = 65520
//   returns: CompressError.None
fn decode_brotli_compressed_metablock<B>(
    r:                   BrotliBitReader&,
    mlen:                u32,
    max_window_distance: u32,
    max_output_bytes:    i64,
    dist_ring:           u32[4]&,
    prev_p1:             u8&,
    prev_p2:             u8&,
    out:                 B&,
    dict:                const u8[:],
    out_start_pos:       i64,
) -> CompressError {
    var bs = BrotliBlockState { .. };
    var npostfix: u32 = 0;
    var ndirect:  u32 = 0;
    let hdr_err = read_brotli_meta_block_header(r, bs, npostfix, ndirect);
    guard hdr_err == CompressError.None else { return hdr_err; }

    return decode_brotli_commands(
        r,
        mlen,
        bs,
        npostfix,
        ndirect,
        max_window_distance,
        max_output_bytes,
        dist_ring,
        prev_p1,
        prev_p2,
        out,
        dict,
        out_start_pos,
    );
}

// Decodes a single Brotli meta-block (RFC 7932 Section 9.2).
//
// Example:
//   r = bit 1, is_last = true
//   returns: CompressError.None
fn decode_brotli_meta_block<B>(
    r:                   BrotliBitReader&,
    max_window_distance: u32,
    max_output_bytes:    i64,
    dist_ring:           u32[4]&,
    prev_p1:             u8&,
    prev_p2:             u8&,
    out:                 B&,
    is_last:             bool&,
    dict:                const u8[:] = "",
    out_start_pos:       i64         = 0,
) -> CompressError {
    is_last = brotli_read_bits(r, 1) != 0;
    guard !r.underflow else { return CompressError.InputBufferTruncated; }
    if is_last {
        let is_last_empty = brotli_read_bits(r, 1) != 0;
        guard !r.underflow else { return CompressError.InputBufferTruncated; }
        if is_last_empty {
            return CompressError.None;
        }
    }

    let mnibbles = brotli_read_bits(r, 2);
    guard !r.underflow else { return CompressError.InputBufferTruncated; }
    if mnibbles == 3 {
        return decode_brotli_metadata_block(r);
    }

    let mlen, ok_len = decode_meta_block_length(r, mnibbles);
    guard !r.underflow else { return CompressError.InputBufferTruncated; }
    guard ok_len else { return CompressError.CorruptedBitstream; }

    let produced_so_far = sub_sat_i64(out.len, out_start_pos);
    if max_output_bytes >= 0 && add_sat_i64(produced_so_far, mlen as i64) > max_output_bytes {
        return CompressError.OutputBufferOverflow;
    }

    var is_uncompressed = false;
    if !is_last {
        is_uncompressed = brotli_read_bits(r, 1) != 0;
        guard !r.underflow else { return CompressError.InputBufferTruncated; }
    }
    if is_uncompressed {
        return decode_brotli_uncompressed_block(r, mlen, out, prev_p1, prev_p2);
    }

    return decode_brotli_compressed_metablock(
        r, mlen, max_window_distance, max_output_bytes, dist_ring,
        prev_p1, prev_p2, out, dict, out_start_pos,
    );
}

fn brotli_dict_tail_bytes(dict: const u8[:]) -> u8, u8 {
    let p1 = if dict.len > 0 { dict[dict.len - 1] } else { 0 };
    let p2 = if dict.len > 1 { dict[dict.len - 2] } else { 0 };
    return p1, p2;
}

// Internal Brotli decompressor (RFC 7932) with optional shared dictionary and max output limit protection.
fn brotli_decompress_with_limit_impl(
    src:              const u8[:],
    out:              u8[>..]&,
    max_output_bytes: i64         = -1,
    dict:             const u8[:] = "",
) -> CompressError {
    guard src.len > 0 else {
        return CompressError.InputBufferTruncated;
    }

    let out_start_pos = out.len;
    var committed = false;
    defer if !committed { out.resize(out_start_pos); };

    var r = new_brotli_bit_reader(src);

    var wbits: u32 = 16;
    let header_err = decode_brotli_window_bits(r, wbits);
    guard header_err == CompressError.None else { return header_err; }

    let max_window_distance = ((1 as u32) << wbits) - 16;
    var dist_ring: u32[4] = [4, 11, 15, 16];
    var prev_p1, prev_p2 = brotli_dict_tail_bytes(dict);

    var is_last = false;
    while !is_last {
        let meta_err = decode_brotli_meta_block(
            r,
            max_window_distance,
            max_output_bytes,
            dist_ring,
            prev_p1,
            prev_p2,
            out,
            is_last,
            dict,
            out_start_pos,
        );
        guard meta_err == CompressError.None else { return meta_err; }
        guard !r.underflow else { return CompressError.InputBufferTruncated; }
    }

    guard !r.underflow else { return CompressError.InputBufferTruncated; }
    let pad_bits = r.bit_count & 7;
    if pad_bits > 0 {
        let padding_val = brotli_read_bits(r, pad_bits);
        guard !r.underflow else { return CompressError.InputBufferTruncated; }
        guard padding_val == 0 else { return CompressError.CorruptedBitstream; }
    }
    if r.bit_count > 0 || r.pos < r.src.len {
        return CompressError.CorruptedBitstream;
    }

    committed = true;
    return CompressError.None;
}

// Generic bounded-buffer bridge delegating to the single non-generic u8[>..] Brotli core.
fn brotli_decompress_with_limit_impl<B>(
    src:              const u8[:],
    out:              B&,
    max_output_bytes: i64         = -1,
    dict:             const u8[:] = "",
) -> CompressError {
    let avail = sub_sat_i64(out.cap, out.len);
    let eff_limit = if max_output_bytes >= 0 && max_output_bytes < avail { max_output_bytes } else { avail };
    var tmp: u8[>..] = [];
    let err = brotli_decompress_with_limit_impl(src, tmp, eff_limit, dict);
    guard err == CompressError.None else { return err; }
    guard out.try_append(tmp[..]) else { return CompressError.OutputBufferOverflow; }
    return CompressError.None;
}

// Decompresses an RFC 7932 Brotli stream with max output limit protection.
fn brotli_decompress_with_limit<B>(
    src:              const u8[:],
    out:              B&,
    max_output_bytes: i64 = -1,
) -> bool, CompressError {
    let err = brotli_decompress_with_limit_impl(src, out, max_output_bytes, "");
    return err == CompressError.None, err;
}

// Decompresses an RFC 7932 Brotli stream using a shared dictionary (RFC 9842 `dcb`) with max output limit protection.
fn brotli_decompress_with_dict<B>(
    src:              const u8[:],
    dict:             const u8[:],
    out:              B&,
    max_output_bytes: i64 = -1,
) -> bool, CompressError {
    let err = brotli_decompress_with_limit_impl(src, out, max_output_bytes, dict);
    return err == CompressError.None, err;
}

// Decompresses an RFC 7932 Brotli stream from src into out.
fn brotli_decompress<B>(src: const u8[:], out: B&) -> bool, CompressError {
    return brotli_decompress_with_limit(src, out, -1);
}
