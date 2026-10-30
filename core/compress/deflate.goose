// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// The Goose Deflate / Inflate compression engine: RFC 1951 Specification.
namespace core;

import std;

// ---- compression error codes -----------------------------------------------

enum CompressError {
    None,
    InvalidHeader,
    InvalidBlockType,
    LengthMismatch,
    OutputBufferOverflow,
    InputBufferTruncated,
    CorruptedBitstream,
    InvalidHuffmanCode,
    DistanceOutOfBounds,
    InvalidDistanceCode,
    TooManyLengthOrDistanceCodes,
    CodeLengthsOverSubscribed,
    CodeLengthsIncomplete,
    RepeatWithoutPreviousLength,
    ChecksumMismatch,
    SizeMismatch,
    NeedDictionary,
    DictionaryMismatch,
}

// Returns true if the compression error is CompressError.None.
inline fn ok(err: CompressError) -> bool {
    return err == CompressError.None;
}

// ---- rfc 1951 constants & lookup tables -----------------------------------

const MAX_BITS:   i32 = 15;
const MAX_LCODES: i32 = 286;
const MAX_DCODES: i32 = 30;
const MAX_CODES:  i32 = 316;
const FIX_LCODES: i32 = 288;

const CODE_LENGTH_ORDER: i32[19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

const LENS_BASE: i32[32] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
    35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258,
    0, 0, 0,
];

const LENS_EXTRA: i32[32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
    3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
    0, 0, 0,
];

const DISTS_BASE: i32[32] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
    257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145,
    8193, 12289, 16385, 24577,
    0, 0,
];

const DISTS_EXTRA: i32[32] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
    7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13,
    0, 0,
];

// Precomputed fixed literal/length Huffman code tables (bit-reversed for LSB-first emission)
const FIXED_LIT_CODE: u16[288] = [
    0x000C, 0x008C, 0x004C, 0x00CC, 0x002C, 0x00AC, 0x006C, 0x00EC,
    0x001C, 0x009C, 0x005C, 0x00DC, 0x003C, 0x00BC, 0x007C, 0x00FC,
    0x0002, 0x0082, 0x0042, 0x00C2, 0x0022, 0x00A2, 0x0062, 0x00E2,
    0x0012, 0x0092, 0x0052, 0x00D2, 0x0032, 0x00B2, 0x0072, 0x00F2,
    0x000A, 0x008A, 0x004A, 0x00CA, 0x002A, 0x00AA, 0x006A, 0x00EA,
    0x001A, 0x009A, 0x005A, 0x00DA, 0x003A, 0x00BA, 0x007A, 0x00FA,
    0x0006, 0x0086, 0x0046, 0x00C6, 0x0026, 0x00A6, 0x0066, 0x00E6,
    0x0016, 0x0096, 0x0056, 0x00D6, 0x0036, 0x00B6, 0x0076, 0x00F6,
    0x000E, 0x008E, 0x004E, 0x00CE, 0x002E, 0x00AE, 0x006E, 0x00EE,
    0x001E, 0x009E, 0x005E, 0x00DE, 0x003E, 0x00BE, 0x007E, 0x00FE,
    0x0001, 0x0081, 0x0041, 0x00C1, 0x0021, 0x00A1, 0x0061, 0x00E1,
    0x0011, 0x0091, 0x0051, 0x00D1, 0x0031, 0x00B1, 0x0071, 0x00F1,
    0x0009, 0x0089, 0x0049, 0x00C9, 0x0029, 0x00A9, 0x0069, 0x00E9,
    0x0019, 0x0099, 0x0059, 0x00D9, 0x0039, 0x00B9, 0x0079, 0x00F9,
    0x0005, 0x0085, 0x0045, 0x00C5, 0x0025, 0x00A5, 0x0065, 0x00E5,
    0x0015, 0x0095, 0x0055, 0x00D5, 0x0035, 0x00B5, 0x0075, 0x00F5,
    0x000D, 0x008D, 0x004D, 0x00CD, 0x002D, 0x00AD, 0x006D, 0x00ED,
    0x001D, 0x009D, 0x005D, 0x00DD, 0x003D, 0x00BD, 0x007D, 0x00FD,
    0x0013, 0x0113, 0x0093, 0x0193, 0x0053, 0x0153, 0x00D3, 0x01D3,
    0x0033, 0x0133, 0x00B3, 0x01B3, 0x0073, 0x0173, 0x00F3, 0x01F3,
    0x000B, 0x010B, 0x008B, 0x018B, 0x004B, 0x014B, 0x00CB, 0x01CB,
    0x002B, 0x012B, 0x00AB, 0x01AB, 0x006B, 0x016B, 0x00EB, 0x01EB,
    0x001B, 0x011B, 0x009B, 0x019B, 0x005B, 0x015B, 0x00DB, 0x01DB,
    0x003B, 0x013B, 0x00BB, 0x01BB, 0x007B, 0x017B, 0x00FB, 0x01FB,
    0x0007, 0x0107, 0x0087, 0x0187, 0x0047, 0x0147, 0x00C7, 0x01C7,
    0x0027, 0x0127, 0x00A7, 0x01A7, 0x0067, 0x0167, 0x00E7, 0x01E7,
    0x0017, 0x0117, 0x0097, 0x0197, 0x0057, 0x0157, 0x00D7, 0x01D7,
    0x0037, 0x0137, 0x00B7, 0x01B7, 0x0077, 0x0177, 0x00F7, 0x01F7,
    0x000F, 0x010F, 0x008F, 0x018F, 0x004F, 0x014F, 0x00CF, 0x01CF,
    0x002F, 0x012F, 0x00AF, 0x01AF, 0x006F, 0x016F, 0x00EF, 0x01EF,
    0x001F, 0x011F, 0x009F, 0x019F, 0x005F, 0x015F, 0x00DF, 0x01DF,
    0x003F, 0x013F, 0x00BF, 0x01BF, 0x007F, 0x017F, 0x00FF, 0x01FF,
    0x0000, 0x0040, 0x0020, 0x0060, 0x0010, 0x0050, 0x0030, 0x0070,
    0x0008, 0x0048, 0x0028, 0x0068, 0x0018, 0x0058, 0x0038, 0x0078,
    0x0004, 0x0044, 0x0024, 0x0064, 0x0014, 0x0054, 0x0034, 0x0074,
    0x0003, 0x0083, 0x0043, 0x00C3, 0x0023, 0x00A3, 0x0063, 0x00E3,
];

const FIXED_LIT_LEN: u8[288] = [
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
    9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
    9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
    9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
    9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
    9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
    9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 8, 8, 8, 8, 8, 8, 8, 8,
];

const FIXED_DIST_CODE: u8[32] = [
    0x00, 0x10, 0x08, 0x18, 0x04, 0x14, 0x0C, 0x1C,
    0x02, 0x12, 0x0A, 0x1A, 0x06, 0x16, 0x0E, 0x1E,
    0x01, 0x11, 0x09, 0x19, 0x05, 0x15, 0x0D, 0x1D,
    0x03, 0x13, 0x0B, 0x1B, 0x07, 0x17, 0x0F, 0x1F,
];

// ---- bitstream reader & writer ---------------------------------------------

struct BitReader {
    src:       const u8[:],
    pos:       i64 = 0,
    bit_buf:   u64 = 0,
    bit_count: i32 = 0,
}

fn new_bit_reader(src: const u8[:]) -> BitReader {
    return BitReader { src: src, pos: 0, bit_buf: 0, bit_count: 0 };
}

fn read_bits(r: BitReader&, need: i32) -> u32, bool {
    while r.bit_count < need {
        if r.pos >= r.src.len {
            return 0, false;
        }
        let b = r.src[r.pos] as u64;
        r.pos++;
        r.bit_buf |= b << r.bit_count;
        r.bit_count += 8;
    }
    let mask = (1 << need) - 1;
    let val = (r.bit_buf as u32) & (mask as u32);
    r.bit_buf >>= need;
    r.bit_count -= need;
    return val, true;
}

fn align_to_byte(r: BitReader&) {
    let whole_bytes = (r.bit_count / 8) as i64;
    r.pos -= whole_bytes;
    r.bit_buf = 0;
    r.bit_count = 0;
}

struct BitWriter {
    bit_buf:   u64 = 0,
    bit_count: i32 = 0,
}

fn write_bits<B>(w: BitWriter&, val: u32, n_bits: i32, out: B&) {
    w.bit_buf |= (val as u64) << w.bit_count;
    w.bit_count += n_bits;
    while w.bit_count >= 8 {
        out.push((w.bit_buf & 0xFF) as u8);
        w.bit_buf >>= 8;
        w.bit_count -= 8;
    }
}

fn flush_bits<B>(w: BitWriter&, out: B&) {
    if w.bit_count > 0 {
        out.push((w.bit_buf & 0xFF) as u8);
        w.bit_buf = 0;
        w.bit_count = 0;
    }
}

// ---- canonical huffman table -----------------------------------------------

struct HuffmanTable {
    count:  i32[16]  = [0; 16],
    symbol: i32[288] = [0; 288],
    fast:   i32[512] = [-1; 512],
}

fn bit_reverse_9(val: u32, len: i32) -> u32 {
    var res: u32 = 0;
    var v = val;
    for i in len {
        res = (res << 1) | (v & 1);
        v >>= 1;
    }
    return res;
}

inline fn insert_deflate_huffman_symbol(
    table:     HuffmanTable&,
    s:         i32,
    len:       i32,
    offs:      i32[16]&,
    next_code: u32[16]&,
) {
    table.symbol[offs[len]] = s;
    offs[len]++;

    let c = next_code[len];
    next_code[len]++;
    guard len <= 9 else { return; }

    let rev_code = bit_reverse_9(c, len);
    let step = (1 as i64) << (len as u32);
    var idx = rev_code as i64;
    let entry = (len << 16) | s;
    while idx < 512 {
        table.fast[idx] = entry;
        idx += step;
    }
}

// Constructs canonical Huffman decode table from a list of code lengths.
// Populates both canonical bit-by-bit decode tree and fast 9-bit lookahead table.
// Returns 0 on complete code set, >0 on incomplete code set, or <0 on over-subscribed code set.
fn construct_huffman_table(lengths: const i32[:], n_symbols: i32, table: HuffmanTable&) -> i32 {
    for l in 16 {
        table.count[l] = 0;
    }
    for i in 512 {
        table.fast[i] = -1;
    }
    var non_zero_count: i32 = 0;
    for s in n_symbols {
        let len = lengths[s];
        if len > 0 && len <= MAX_BITS {
            table.count[len]++;
            non_zero_count++;
        }
    }
    if non_zero_count == 0 {
        return 0;
    }

    var left: i32 = 1;
    for l in 1..16 {
        left <<= 1;
        left -= table.count[l];
        if left < 0 {
            return left; // Over-subscribed
        }
    }

    var offs: i32[16] = [0; 16];
    for l in 1..15 {
        offs[l + 1] = offs[l] + table.count[l];
    }

    var code:      u32     = 0;
    var next_code: u32[16] = [0; 16];
    for l in 1..16 {
        code = (code + (table.count[l - 1] as u32)) << 1;
        next_code[l] = code;
    }

    for s in n_symbols {
        let len = lengths[s];
        if len != 0 {
            insert_deflate_huffman_symbol(table, s, len, offs, next_code);
        }
    }

    return left;
}

// Decodes the next symbol from the bitstream using the HuffmanTable.
// Fast path: O(1) 9-bit lookahead table handles 95%+ of all symbols in 1 cycle.
// Slow path: Canonical bit-by-bit tree handles codes > 9 bits.
//
// Example:
//   r.bit_count = 16, table.fast[0] = (3 << 16) | 5
//   returns: 5, true
fn decode_huffman_symbol(r: BitReader&, table: const HuffmanTable&) -> i32, bool {
    // Refill bit buffer up to 56 bits for single-cycle lookup
    if r.bit_count < 15 {
        if r.pos + 8 <= r.src.len {
            let chunk = read_le_u64(r.src, r.pos);
            r.bit_buf |= chunk << ((r.bit_count & 63) as u64);
            let bytes_added = (63 - r.bit_count) >> 3;
            r.pos += bytes_added;
            r.bit_count += bytes_added * 8;
        } else {
            while r.bit_count <= 56 && r.pos < r.src.len {
                let b = r.src[r.pos] as u64;
                r.pos++;
                r.bit_buf |= b << ((r.bit_count & 63) as u64);
                r.bit_count += 8;
            }
        }
    }

    // Fast 9-bit lookahead path
    if r.bit_count >= 9 {
        let fast_val = table.fast[(r.bit_buf & 0x1FF) as i64];
        if fast_val >= 0 {
            let fast_len = fast_val >> 16;
            r.bit_buf >>= fast_len;
            r.bit_count -= fast_len;
            return fast_val & 0xFFFF, true;
        }
    }

    // Canonical slow path for codes > 9 bits or tail of stream
    var code:  i32 = 0;
    var first: i32 = 0;
    var index: i32 = 0;

    for len in 1..16 {
        let b, ok = read_bits(r, 1);
        if !ok { return -1, false; }
        code |= b as i32;
        let count = table.count[len];
        if code - count < first {
            let sym_idx = index + (code - first);
            return table.symbol[sym_idx], true;
        }
        index += count;
        first += count;
        first <<= 1;
        code <<= 1;
    }

    return -1, true;
}

// ---- decompressor: rfc 1951 inflate ----------------------------------------

fn apply_deflate_match<B>(
    out:           B&,
    dist_i64:      i64,
    match_len:     i32,
    out_start_pos: i64,
    dict:          const u8[:],
) {
    let curr_decoded = out.len - out_start_pos;
    if dist_i64 <= curr_decoded {
        let back_idx = out.len - dist_i64;
        let m_len = match_len as i64;
        if dist_i64 >= m_len {
            out.append(out[back_idx..back_idx + m_len]);
            return;
        }
        var curr: i64 = 0;
        while curr < m_len {
            let avail = curr + dist_i64;
            let rem = m_len - curr;
            let step = if avail < rem { avail } else { rem };
            out.append(out[back_idx..back_idx + step]);
            curr += step;
        }
        return;
    }

    for i in match_len {
        let curr = out.len - out_start_pos;
        if dist_i64 <= curr {
            let b = out[out.len - dist_i64];
            out.push(b);
        } else {
            let dict_back = dist_i64 - curr;
            let dict_idx = dict.len - dict_back;
            let b = dict[dict_idx];
            out.push(b);
        }
    }
}

// Decodes match length and distance parameters for a Deflate match code.
//
// Example:
//   sym = 257
//   returns: match_len = 3, match_dist = 1, CompressError.None
fn decode_deflate_match_params(
    r:          BitReader&,
    dist_table: const HuffmanTable&,
    sym:        i32,
) -> i32, i32, CompressError {
    let len_idx = sym - 257;
    guard len_idx < 29 else { return 0, 0, CompressError.CorruptedBitstream; }

    let extra_bits = LENS_EXTRA[len_idx & 31];
    var match_len = LENS_BASE[len_idx & 31];
    if extra_bits > 0 {
        let xval, ok_x = read_bits(r, extra_bits);
        guard ok_x else { return 0, 0, CompressError.InputBufferTruncated; }
        match_len += xval as i32;
    }

    let dist_sym, ok_dist = decode_huffman_symbol(r, dist_table);
    guard ok_dist else { return 0, 0, CompressError.InputBufferTruncated; }
    guard dist_sym >= 0 && dist_sym < 30 else { return 0, 0, CompressError.InvalidDistanceCode; }

    let dist_extra = DISTS_EXTRA[dist_sym & 31];
    var match_dist = DISTS_BASE[dist_sym & 31];
    if dist_extra > 0 {
        let dxval, ok_dx = read_bits(r, dist_extra);
        guard ok_dx else { return 0, 0, CompressError.InputBufferTruncated; }
        match_dist += dxval as i32;
    }

    return match_len, match_dist, CompressError.None;
}

// Decodes literal/length and distance Huffman codes for a Deflate block.
//
// Example:
//   sym = 256
//   returns: CompressError.None
fn decode_block_codes<B>(
    r:                BitReader&,
    lit_table:        const HuffmanTable&,
    dist_table:       const HuffmanTable&,
    out:              B&,
    dict:             const u8[:] = "",
    out_start_pos:    i64         = 0,
    max_output_bytes: i64         = 0,
) -> CompressError {
    let d_len = if dict.len > 32768 { 32768 as i64 } else { dict.len };
    loop {
        // Fast path: tight inline decoding of consecutive 9-bit literals
        while r.bit_count >= 15 {
            if max_output_bytes > 0 && (out.len - out_start_pos) >= max_output_bytes {
                return CompressError.OutputBufferOverflow;
            }
            let fast_val = lit_table.fast[(r.bit_buf & 0x1FF) as i64];
            if fast_val < 0 { break; }
            let sym = fast_val & 0xFFFF;
            if sym >= 256 { break; }
            let fast_len = fast_val >> 16;
            r.bit_buf >>= fast_len;
            r.bit_count -= fast_len;
            out.push(sym as u8);
        }

        let sym, ok_sym = decode_huffman_symbol(r, lit_table);
        guard ok_sym else { return CompressError.InputBufferTruncated; }
        guard sym >= 0 else { return CompressError.InvalidHuffmanCode; }

        if sym < 256 {
            if max_output_bytes > 0 && (out.len - out_start_pos) >= max_output_bytes {
                return CompressError.OutputBufferOverflow;
            }
            out.push(sym as u8);
            continue;
        }
        if sym == 256 {
            break; // End of block (EOB)
        }

        let match_len, match_dist, m_err = decode_deflate_match_params(r, dist_table, sym);
        guard m_err == CompressError.None else { return m_err; }

        if max_output_bytes > 0 && (out.len - out_start_pos) + (match_len as i64) > max_output_bytes {
            return CompressError.OutputBufferOverflow;
        }

        let dist_i64 = match_dist as i64;
        let curr_decoded = out.len - out_start_pos;
        let max_avail_dist = curr_decoded + d_len;
        guard dist_i64 <= max_avail_dist else {
            return CompressError.DistanceOutOfBounds;
        }

        apply_deflate_match(out, dist_i64, match_len, out_start_pos, dict);
    }
    return CompressError.None;
}

fn inflate_stored_block<B>(
    r:                BitReader&,
    out:              B&,
    out_start_pos:    i64,
    max_output_bytes: i64,
) -> CompressError {
    align_to_byte(r);
    guard r.pos + 4 <= r.src.len else {
        return CompressError.InputBufferTruncated;
    }
    let len = (r.src[r.pos] as u32) | ((r.src[r.pos + 1] as u32) << 8);
    let nlen = (r.src[r.pos + 2] as u32) | ((r.src[r.pos + 3] as u32) << 8);
    r.pos += 4;
    guard ((len ^ 0xFFFF) & 0xFFFF) == nlen else {
        return CompressError.LengthMismatch;
    }
    guard r.pos + (len as i64) <= r.src.len else {
        return CompressError.InputBufferTruncated;
    }
    if max_output_bytes > 0 && (out.len - out_start_pos) + (len as i64) > max_output_bytes {
        return CompressError.OutputBufferOverflow;
    }
    for i in (len as i64) {
        out.push(r.src[r.pos + i]);
    }
    r.pos += len as i64;
    return CompressError.None;
}

fn inflate_fixed_block<B>(
    r:                BitReader&,
    out:              B&,
    dict:             const u8[:],
    out_start_pos:    i64,
    max_output_bytes: i64,
) -> CompressError {
    var fixed_lit = HuffmanTable { .. };
    var lit_lens: i32[288] = [0; 288];
    for i in 144 { lit_lens[i] = 8; }
    for i in 144..256 { lit_lens[i] = 9; }
    for i in 256..280 { lit_lens[i] = 7; }
    for i in 280..288 { lit_lens[i] = 8; }
    construct_huffman_table(lit_lens[..], 288, fixed_lit);

    var fixed_dist = HuffmanTable { .. };
    var dist_lens: i32[32] = [5; 32];
    construct_huffman_table(dist_lens[..], 32, fixed_dist);

    return decode_block_codes(r, fixed_lit, fixed_dist, out, dict, out_start_pos, max_output_bytes);
}

fn read_dynamic_code_lengths(
    r:             BitReader&,
    h_code:        const HuffmanTable&,
    total_codes:   i32,
    lit_dist_lens: i32[320]&,
) -> CompressError {
    var cur_idx: i32 = 0;
    while cur_idx < total_codes {
        let sym, ok_s = decode_huffman_symbol(r, h_code);
        guard ok_s else { return CompressError.InputBufferTruncated; }
        guard sym >= 0 else { return CompressError.InvalidHuffmanCode; }

        if sym < 16 {
            lit_dist_lens[cur_idx] = sym;
            cur_idx++;
            continue;
        }
        if sym == 16 {
            guard cur_idx > 0 else { return CompressError.RepeatWithoutPreviousLength; }
            let prev_len = lit_dist_lens[cur_idx - 1];
            let rpt_bits, ok_rb = read_bits(r, 2);
            guard ok_rb else { return CompressError.InputBufferTruncated; }
            let count = (rpt_bits as i32) + 3;
            guard cur_idx + count <= total_codes else {
                return CompressError.TooManyLengthOrDistanceCodes;
            }
            for i in count {
                lit_dist_lens[cur_idx] = prev_len;
                cur_idx++;
            }
            continue;
        }
        if sym == 17 {
            let rpt_bits, ok_rb = read_bits(r, 3);
            guard ok_rb else { return CompressError.InputBufferTruncated; }
            let count = (rpt_bits as i32) + 3;
            guard cur_idx + count <= total_codes else {
                return CompressError.TooManyLengthOrDistanceCodes;
            }
            for i in count {
                lit_dist_lens[cur_idx] = 0;
                cur_idx++;
            }
            continue;
        }
        if sym == 18 {
            let rpt_bits, ok_rb = read_bits(r, 7);
            guard ok_rb else { return CompressError.InputBufferTruncated; }
            let count = (rpt_bits as i32) + 11;
            guard cur_idx + count <= total_codes else {
                return CompressError.TooManyLengthOrDistanceCodes;
            }
            for i in count {
                lit_dist_lens[cur_idx] = 0;
                cur_idx++;
            }
            continue;
        }
        return CompressError.InvalidHuffmanCode;
    }
    return CompressError.None;
}

fn validate_incomplete_distance_codes(lit_dist_lens: const i32[:], nlen: i32, ndist: i32) -> bool {
    var dist_non_zero: i32 = 0;
    var max_dist_len:  i32 = 0;
    for d in ndist {
        let dl = lit_dist_lens[(nlen + d) as i64];
        if dl > 0 {
            dist_non_zero++;
            if dl > max_dist_len { max_dist_len = dl; }
        }
    }
    return dist_non_zero == 0 || (dist_non_zero == 1 && max_dist_len == 1);
}

fn read_code_length_alphabet(r: BitReader&, ncode: i32, code_lens_table: i32[19]&) -> bool {
    for i in ncode {
        let clen, ok_cl = read_bits(r, 3);
        guard ok_cl else { return false; }
        code_lens_table[CODE_LENGTH_ORDER[i]] = clen as i32;
    }
    return true;
}

fn inflate_dynamic_block<B>(
    r:                BitReader&,
    out:              B&,
    dict:             const u8[:],
    out_start_pos:    i64,
    max_output_bytes: i64,
) -> CompressError {
    let hlit_val, ok_hlit = read_bits(r, 5);
    guard ok_hlit else { return CompressError.InputBufferTruncated; }
    guard hlit_val <= 29 else { return CompressError.TooManyLengthOrDistanceCodes; }
    let nlen = (hlit_val as i32) + 257;

    let hdist_val, ok_hdist = read_bits(r, 5);
    guard ok_hdist else { return CompressError.InputBufferTruncated; }
    guard hdist_val <= 29 else { return CompressError.TooManyLengthOrDistanceCodes; }
    let ndist = (hdist_val as i32) + 1;

    let hclen_val, ok_hclen = read_bits(r, 4);
    guard ok_hclen else { return CompressError.InputBufferTruncated; }
    let ncode = (hclen_val as i32) + 4;

    var code_lens_table: i32[19] = [0; 19];
    guard read_code_length_alphabet(r, ncode, code_lens_table) else {
        return CompressError.InputBufferTruncated;
    }

    var h_code = HuffmanTable { .. };
    let res_c = construct_huffman_table(code_lens_table[..], 19, h_code);
    guard res_c == 0 else {
        return if res_c < 0 {
            CompressError.CodeLengthsOverSubscribed
        } else {
            CompressError.CodeLengthsIncomplete
        };
    }

    var lit_dist_lens: i32[320] = [0; 320];
    let total_codes = nlen + ndist;
    let r_err = read_dynamic_code_lengths(r, h_code, total_codes, lit_dist_lens);
    guard r_err == CompressError.None else { return r_err; }

    // RFC 1951 §3.2.7: End-of-Block symbol 256 MUST have a non-zero code length
    guard lit_dist_lens[256] > 0 else { return CompressError.CodeLengthsIncomplete; }

    var dyn_lit = HuffmanTable { .. };
    let res_lit = construct_huffman_table(lit_dist_lens[..nlen], nlen, dyn_lit);
    guard res_lit == 0 else {
        return if res_lit < 0 {
            CompressError.CodeLengthsOverSubscribed
        } else {
            CompressError.CodeLengthsIncomplete
        };
    }

    var dyn_dist = HuffmanTable { .. };
    let res_dist = construct_huffman_table(lit_dist_lens[nlen..nlen + ndist], ndist, dyn_dist);
    if res_dist < 0 {
        return CompressError.CodeLengthsOverSubscribed;
    } else if res_dist > 0 {
        guard validate_incomplete_distance_codes(lit_dist_lens[..], nlen, ndist) else {
            return CompressError.CodeLengthsIncomplete;
        }
    }

    return decode_block_codes(r, dyn_lit, dyn_dist, out, dict, out_start_pos, max_output_bytes);
}

// Extended inflate: supports preset dictionary, max_output_bytes quota, and reports bytes consumed from src.
fn inflate_ex<B>(
    src:              const u8[:],
    out:              B&,
    dict:             const u8[:] = "",
    max_output_bytes: i64         = 0,
) -> CompressError, i64 {
    let out_start_pos = out.len;
    var r = new_bit_reader(src);
    var is_final: u32 = 0;

    while is_final == 0 {
        let fin, ok_fin = read_bits(r, 1);
        guard ok_fin else { return CompressError.InputBufferTruncated, r.pos; }
        is_final = fin;

        let btype, ok_type = read_bits(r, 2);
        guard ok_type else { return CompressError.InputBufferTruncated, r.pos; }

        if btype == 0 {
            let err = inflate_stored_block(r, out, out_start_pos, max_output_bytes);
            guard err == CompressError.None else { return err, r.pos; }
        } else if btype == 1 {
            let err = inflate_fixed_block(r, out, dict, out_start_pos, max_output_bytes);
            guard err == CompressError.None else { return err, r.pos; }
        } else if btype == 2 {
            let err = inflate_dynamic_block(r, out, dict, out_start_pos, max_output_bytes);
            guard err == CompressError.None else { return err, r.pos; }
        } else {
            return CompressError.InvalidBlockType, r.pos;
        }
    }

    align_to_byte(r);
    return CompressError.None, r.pos;
}

// Inflates RFC 1951 raw deflate stream from src into out.
fn inflate<B>(src: const u8[:], out: B&) -> bool, CompressError {
    let err, _ = inflate_ex(src, out, "", 0);
    return err == CompressError.None, err;
}

// Inflates RFC 1951 raw deflate stream from src into out with a preset dictionary.
fn inflate_with_dict<B>(src: const u8[:], out: B&, dict: const u8[:]) -> bool, CompressError {
    let err, _ = inflate_ex(src, out, dict, 0);
    return err == CompressError.None, err;
}

// Inflates RFC 1951 raw deflate stream with an output quota limit.
fn inflate_with_limit<B>(src: const u8[:], out: B&, max_output_bytes: i64) -> bool, CompressError {
    let err, _ = inflate_ex(src, out, "", max_output_bytes);
    return err == CompressError.None, err;
}

// Inflates RFC 1951 raw deflate stream from src into out with a preset dictionary and an output quota limit.
fn inflate_with_dict_limit<B>(
    src:              const u8[:],
    out:              B&,
    dict:             const u8[:],
    max_output_bytes: i64,
) -> bool, CompressError {
    let err, _ = inflate_ex(src, out, dict, max_output_bytes);
    return err == CompressError.None, err;
}

// ---- dynamic huffman builder (moffat-katajainen in-place algorithm) --------

struct SymFreq {
    key: i32 = 0,
    sym: i32 = 0,
}

// In-place minimum redundancy code length calculation (Alistair Moffat & Jyrki Katajainen, 1996).
// Runs in O(N) time without tree pointer allocations.
fn calculate_minimum_redundancy(A: SymFreq[>..]&, n: i32) {
    if n <= 0 { return; }
    if n == 1 {
        A[0].key = 1;
        return;
    }
    A[0].key += A[1].key;
    var root: i32 = 0;
    var leaf: i32 = 2;
    for next_idx in 1..(n - 1) {
        if leaf >= n || A[root].key < A[leaf].key {
            A[next_idx].key = A[root].key;
            A[root].key = next_idx;
            root++;
        } else {
            A[next_idx].key = A[leaf].key;
            leaf++;
        }
        if leaf >= n || (root < next_idx && A[root].key < A[leaf].key) {
            A[next_idx].key += A[root].key;
            A[root].key = next_idx;
            root++;
        } else {
            A[next_idx].key += A[leaf].key;
            leaf++;
        }
    }
    A[n - 2].key = 0;
    var back_idx = n - 3;
    while back_idx >= 0 {
        let parent = A[back_idx].key;
        A[back_idx].key = A[parent].key + 1;
        back_idx--;
    }
    var avbl: i32 = 1;
    var used: i32 = 0;
    var dpth: i32 = 0;
    root = n - 2;
    var next_slot = n - 1;
    while avbl > 0 {
        while root >= 0 && A[root].key == dpth {
            used++;
            root--;
        }
        while avbl > used {
            A[next_slot].key = dpth;
            next_slot--;
            avbl--;
        }
        avbl = 2 * used;
        dpth++;
        used = 0;
    }
}

// Limits canonical Huffman code table max code size to max_code_size (<= 15 bits).
fn enforce_max_code_size(num_codes: i32[33]&, code_list_len: i32, max_code_size: i32) {
    if code_list_len <= 1 { return; }
    var idx = max_code_size + 1;
    while idx <= 32 {
        num_codes[max_code_size] += num_codes[idx];
        num_codes[idx] = 0;
        idx++;
    }
    var total: u32 = 0;
    var i = max_code_size;
    while i > 0 {
        total += (num_codes[i] as u32) << ((max_code_size - i) as u32);
        i--;
    }
    let target = (1 as u32) << (max_code_size as u32);
    while total != target {
        num_codes[max_code_size]--;
        var j = max_code_size - 1;
        while j > 0 {
            if num_codes[j] > 0 {
                num_codes[j]--;
                num_codes[j + 1] += 2;
                break;
            }
            j--;
        }
        total--;
    }
}

inline fn reverse_bits_16(c: u32, l: i32) -> u16 {
    var rev: u16 = 0;
    for k in l {
        if ((c >> ((l - 1 - k) as u32)) & 1) != 0 {
            rev |= (1 as u16) << (k as u16);
        }
    }
    return rev;
}

fn assign_huffman_code_lens(
    syms:          const SymFreq[:],
    num_codes:     const i32[:],
    max_code_size: i32,
    code_lens:     i32[>..]&,
) {
    var cur_sym_idx = syms.len as i32;
    for len_val in 1..(max_code_size + 1) {
        var count = num_codes[len_val];
        while count > 0 {
            cur_sym_idx--;
            let target_sym = syms[cur_sym_idx as i64].sym as i64;
            code_lens[target_sym] = len_val;
            count--;
        }
    }
}

// Builds canonical Huffman bit lengths and bit-reversed codes for a frequency table.
fn build_huffman_codes(
    counts:        const i32[:],
    max_code_size: i32,
    code_lens:     i32[>..]&,
    codes:         u16[>..]&,
) {
    code_lens.clear();
    codes.clear();
    for i in counts.len {
        code_lens.push(0);
        codes.push(0);
    }

    var syms: SymFreq[>..] = [];
    for i in counts.len {
        if counts[i] > 0 {
            syms.push(SymFreq { key: counts[i], sym: i as i32 });
        }
    }

    if syms.len == 0 {
        return;
    }
    if syms.len == 1 {
        let s = syms[0].sym as i64;
        code_lens[s] = 1;
        codes[s] = 0;
        return;
    }

    sort(syms) { x, y => x.key < y.key };
    calculate_minimum_redundancy(syms, syms.len as i32);

    var num_codes: i32[33] = [0; 33];
    for &s in syms {
        if s.key >= 0 && s.key <= 32 {
            num_codes[s.key]++;
        }
    }

    enforce_max_code_size(num_codes, syms.len as i32, max_code_size);
    assign_huffman_code_lens(syms[..], num_codes[..], max_code_size, code_lens);

    var next_code:    u32[33] = [0; 33];
    var running_code: u32     = 0;
    for len_val in 1..(max_code_size + 1) {
        running_code = (running_code + (num_codes[len_val - 1] as u32)) << 1;
        next_code[len_val] = running_code;
    }

    for i in counts.len {
        let l = code_lens[i];
        if l > 0 {
            let c = next_code[l];
            next_code[l]++;
            codes[i] = reverse_bits_16(c, l);
        }
    }
}

// Run-length encoded representation of literal/distance code lengths.
struct RleToken {
    sym:        i32 = 0,
    extra_val:  u32 = 0,
    extra_bits: i32 = 0,
}

fn rle_encode_lengths(lens: const i32[:], out: RleToken[>..]&) {
    out.clear();
    var i: i64 = 0;
    let n = lens.len;
    while i < n {
        let cur = lens[i];
        var run: i64 = 1;
        while i + run < n && lens[i + run] == cur {
            run++;
        }
        if cur == 0 {
            while run >= 11 {
                let take = if run < 138 { run } else { 138 };
                out.push(RleToken { sym: 18, extra_val: (take - 11) as u32, extra_bits: 7 });
                run -= take;
                i += take;
            }
            if run >= 3 {
                out.push(RleToken { sym: 17, extra_val: (run - 3) as u32, extra_bits: 3 });
                i += run;
                run = 0;
            }
            for k in run {
                out.push(RleToken { sym: 0, extra_val: 0, extra_bits: 0 });
                i++;
            }
        } else {
            out.push(RleToken { sym: cur, extra_val: 0, extra_bits: 0 });
            i++;
            run--;
            while run >= 3 {
                let take = if run < 6 { run } else { 6 };
                out.push(RleToken { sym: 16, extra_val: (take - 3) as u32, extra_bits: 2 });
                run -= take;
                i += take;
            }
            for k in run {
                out.push(RleToken { sym: cur, extra_val: 0, extra_bits: 0 });
                i++;
            }
        }
    }
}

// Flat LZ77 token representing an uncompressed literal or a length-distance match.
struct LzToken {
    is_match:        bool = false,
    sym:             u16  = 0,
    extra_val:       u16  = 0,
    extra_bits:      u8   = 0,
    dist_sym:        u8   = 0,
    dist_extra_val:  u16  = 0,
    dist_extra_bits: u8   = 0,
}

// ---- compressor: rfc 1951 deflate ------------------------------------------

fn find_length_symbol(l: i32) -> i32, i32, u32 {
    var idx = 28;
    while idx >= 0 {
        if LENS_BASE[idx] <= l {
            let extra = (l - LENS_BASE[idx]) as u32;
            return 257 + (idx as i32), LENS_EXTRA[idx], extra;
        }
        idx--;
    }
    return 257, 0, 0;
}

fn find_distance_symbol(d: i32) -> i32, i32, u32 {
    var idx = 29;
    while idx >= 0 {
        if DISTS_BASE[idx] <= d {
            let extra = (d - DISTS_BASE[idx]) as u32;
            return idx as i32, DISTS_EXTRA[idx], extra;
        }
        idx--;
    }
    return 0, 0, 0;
}

// Compression tuning parameters per level (0..9) matching zlib-ng standards.
struct DeflateConfig {
    max_chain: i32,
    good_len:  i32,
    max_lazy:  i32,
    nice_len:  i32,
}

fn get_deflate_config(level: i32) -> DeflateConfig {
    if level <= 1 {
        return DeflateConfig { max_chain: 4, good_len: 4, max_lazy: 0, nice_len: 8 };
    } else if level == 2 {
        return DeflateConfig { max_chain: 8, good_len: 4, max_lazy: 0, nice_len: 16 };
    } else if level == 3 {
        return DeflateConfig { max_chain: 32, good_len: 4, max_lazy: 0, nice_len: 32 };
    } else if level == 4 {
        return DeflateConfig { max_chain: 16, good_len: 4, max_lazy: 4, nice_len: 16 };
    } else if level == 5 {
        return DeflateConfig { max_chain: 32, good_len: 8, max_lazy: 16, nice_len: 32 };
    } else if level == 6 {
        return DeflateConfig { max_chain: 128, good_len: 8, max_lazy: 16, nice_len: 128 };
    } else if level == 7 {
        return DeflateConfig { max_chain: 256, good_len: 8, max_lazy: 32, nice_len: 128 };
    } else if level == 8 {
        return DeflateConfig { max_chain: 1024, good_len: 32, max_lazy: 128, nice_len: 258 };
    } else {
        return DeflateConfig { max_chain: 4096, good_len: 32, max_lazy: 258, nice_len: 258 };
    }
}

// Emits uncompressed RFC 1951 Stored blocks (BTYPE 00).
fn emit_stored_blocks<B>(src: const u8[:], out: B&, w: BitWriter&, is_final: bool) {
    var offset: i64 = 0;
    while offset < src.len || (src.len == 0 && offset == 0) {
        let remaining = src.len - offset;
        let block_size = if remaining < 65535 { remaining } else { 65535 };
        let is_last = is_final && (offset + block_size >= src.len);
        let bfinal_bit: u32 = if is_last { 1 } else { 0 };

        write_bits(w, bfinal_bit, 3, out);
        flush_bits(w, out);

        let len_u16 = block_size as u32;
        let nlen_u16 = (~len_u16) & 0xFFFF;
        out.push((len_u16 & 0xFF) as u8);
        out.push(((len_u16 >> 8) & 0xFF) as u8);
        out.push((nlen_u16 & 0xFF) as u8);
        out.push(((nlen_u16 >> 8) & 0xFF) as u8);

        for i in block_size {
            out.push(src[offset + i]);
        }
        offset += block_size;
        if src.len == 0 { break; }
    }
}

// Emits RFC 1951 Fixed Huffman block (BTYPE 01).
fn emit_fixed_block<B>(tokens: const LzToken[:], out: B&, w: BitWriter&, is_final: bool) {
    let bfinal_bit: u32 = if is_final { 1 } else { 0 };
    write_bits(w, bfinal_bit | (1 << 1), 3, out);

    for &tok in tokens {
        if tok.is_match {
            let sym_idx = tok.sym as i64;
            let lit_code = FIXED_LIT_CODE[sym_idx] as u32;
            let lit_nbits = FIXED_LIT_LEN[sym_idx] as i32;
            write_bits(w, lit_code, lit_nbits, out);
            if tok.extra_bits > 0 {
                write_bits(w, tok.extra_val as u32, tok.extra_bits as i32, out);
            }

            let dsym_idx = tok.dist_sym as i64;
            let dist_code = FIXED_DIST_CODE[dsym_idx] as u32;
            write_bits(w, dist_code, 5, out);
            if tok.dist_extra_bits > 0 {
                write_bits(w, tok.dist_extra_val as u32, tok.dist_extra_bits as i32, out);
            }
        } else {
            let sym_idx = tok.sym as i64;
            let lit_code = FIXED_LIT_CODE[sym_idx] as u32;
            let lit_nbits = FIXED_LIT_LEN[sym_idx] as i32;
            write_bits(w, lit_code, lit_nbits, out);
        }
    }
    if is_final {
        flush_bits(w, out);
    }
}

// Compresses src into out as an RFC 1951 Deflate block.
// - level == 0: Stored uncompressed blocks.
// - level 1..3: Fast Greedy LZ77 match-finding.
// - level 4..9: Optimal Lazy Match LZ77 with deep chains (up to 4096).
// - Exact Bit-Cost selection chooses the minimal payload among Stored, Fixed, and Dynamic.
// - is_final: Sets BFINAL bit (1 if last block, 0 if streaming intermediate).
// - dict: Optional pre-shared dictionary (up to 32 KB).
inline fn get_deflate_byte(pos: i64, dict_slice: const u8[:], dict_len: i64, src: const u8[:]) -> u8 {
    return if pos < dict_len { dict_slice[pos] } else { src[pos - dict_len] };
}

fn update_skip_hash(
    skip_pos:   i64,
    total_len:  i64,
    dict_slice: const u8[:],
    dict_len:   i64,
    src:        const u8[:],
    head:       i32[4096]&,
    prev:       i32[32768]&,
) {
    if skip_pos + 2 < total_len {
        let sb0 = get_deflate_byte(skip_pos, dict_slice, dict_len, src) as i32;
        let sb1 = get_deflate_byte(skip_pos + 1, dict_slice, dict_len, src) as i32;
        let sb2 = get_deflate_byte(skip_pos + 2, dict_slice, dict_len, src) as i32;
        let sh = ((sb0 << 8) ^ (sb1 << 4) ^ sb2) & 4095;
        prev[skip_pos & 32767] = head[sh];
        head[sh] = skip_pos as i32;
    }
}

fn update_match_skip_hashes(
    start_pos:  i64,
    count:      i32,
    total_len:  i64,
    dict_slice: const u8[:],
    dict_len:   i64,
    src:        const u8[:],
    head:       i32[4096]&,
    prev:       i32[32768]&,
) {
    for k in 1..count {
        let skip_pos = start_pos + (k as i64);
        update_skip_hash(skip_pos, total_len, dict_slice, dict_len, src, head, prev);
    }
}

fn match_len_at_offset(
    pos:        i64,
    cand:       i64,
    dict_slice: const u8[:],
    dict_len:   i64,
    src:        const u8[:],
    total_len:  i64,
) -> i32 {
    var l: i32 = 0;
    let rem = (total_len - pos) as i32;
    let max_l = if rem < 258 { rem } else { 258 };

    let s_off = pos - dict_len;
    let c_off = cand - dict_len;
    if c_off >= 0 {
        while l + 8 <= max_l {
            let diff = read_le_u64(src, s_off + (l as i64)) ^ read_le_u64(src, c_off + (l as i64));
            if diff != 0 {
                l += (ctz(diff) >> 3) as i32;
                break;
            }
            l += 8;
        }
    }

    while l < max_l {
        let p_s = pos + (l as i64);
        let p_c = cand + (l as i64);
        let byte_s = get_deflate_byte(p_s, dict_slice, dict_len, src);
        let byte_c = get_deflate_byte(p_c, dict_slice, dict_len, src);
        if byte_s != byte_c { break; }
        l++;
    }
    return l;
}

inline fn match_endpoint_mismatch(
    pos:        i64,
    cand:       i64,
    cur_len:    i32,
    total_len:  i64,
    dict_slice: const u8[:],
    dict_len:   i64,
    src:        const u8[:],
) -> bool {
    guard cur_len > 0 else { return false; }
    let p_s_check = pos + (cur_len as i64);
    guard p_s_check < total_len else { return false; }
    let p_c_check = cand + (cur_len as i64);
    let b_s = get_deflate_byte(p_s_check, dict_slice, dict_len, src);
    let b_c = get_deflate_byte(p_c_check, dict_slice, dict_len, src);
    return b_s != b_c;
}

fn find_longest_match(
    pos:        i64,
    cand_init:  i32,
    max_chain:  i32,
    nice_len:   i32,
    dict_slice: const u8[:],
    dict_len:   i64,
    src:        const u8[:],
    total_len:  i64,
    prev:       const i32[:],
) -> i32, i32 {
    var cur_len:  i32 = 0;
    var cur_dist: i32 = 0;
    var cand = cand_init;
    var chain_count = 0;

    while cand != -1 && chain_count < max_chain {
        let dist = (pos as i32) - cand;
        if dist > 32768 || dist <= 0 { break; }

        if match_endpoint_mismatch(pos, cand as i64, cur_len, total_len, dict_slice, dict_len, src) {
            cand = prev[cand & 32767];
            chain_count++;
            continue;
        }

        let l = match_len_at_offset(pos, cand as i64, dict_slice, dict_len, src, total_len);
        if l > cur_len {
            cur_len = l;
            cur_dist = dist;
            if cur_len >= nice_len || cur_len >= 258 { break; }
        }

        cand = prev[cand & 32767];
        chain_count++;
    }

    return cur_len, cur_dist;
}

fn push_match_token(
    match_len:  i32,
    match_dist: i32,
    tokens:     LzToken[>..]&,
    lit_count:  i32[288]&,
    dist_count: i32[32]&,
) {
    let sym, xbits, xval = find_length_symbol(match_len);
    let dsym, dxbits, dxval = find_distance_symbol(match_dist);
    tokens.push(LzToken {
        is_match:        true,
        sym:             sym as u16,
        extra_val:       xval as u16,
        extra_bits:      xbits as u8,
        dist_sym:        dsym as u8,
        dist_extra_val:  dxval as u16,
        dist_extra_bits: dxbits as u8,
    });
    lit_count[sym as i64]++;
    dist_count[dsym as i64]++;
}

fn push_literal_token(
    sym:       u16,
    tokens:    LzToken[>..]&,
    lit_count: i32[288]&,
) {
    tokens.push(LzToken {
        is_match:        false,
        sym:             sym,
        extra_val:       0,
        extra_bits:      0,
        dist_sym:        0,
        dist_extra_val:  0,
        dist_extra_bits: 0,
    });
    lit_count[sym as i64]++;
}

fn init_dict_hash_table(
    dict_slice: const u8[:],
    dict_len:   i64,
    head:       i32[4096]&,
    prev:       i32[32768]&,
) {
    if dict_len >= 3 {
        for p in (dict_len - 2) {
            let b0 = dict_slice[p] as i32;
            let b1 = dict_slice[p + 1] as i32;
            let b2 = dict_slice[p + 2] as i32;
            let h = ((b0 << 8) ^ (b1 << 4) ^ b2) & 4095;
            prev[p & 32767] = head[h];
            head[h] = p as i32;
        }
    }
}

// Emits a greedy match token or literal token and advances pos.
//
// Example:
//   pos = 10, cur_len = 3, cur_dist = 5
//   advances: pos = 13
fn process_greedy_token(
    cur_len:    i32,
    cur_dist:   i32,
    pos:        i64&,
    total_len:  i64,
    dict_slice: const u8[:],
    dict_len:   i64,
    src:        const u8[:],
    head:       i32[4096]&,
    prev:       i32[32768]&,
    tokens:     LzToken[>..]&,
    lit_count:  i32[288]&,
    dist_count: i32[32]&,
) {
    if cur_len >= 3 {
        push_match_token(cur_len, cur_dist, tokens, lit_count, dist_count);
        update_match_skip_hashes(pos, cur_len, total_len, dict_slice, dict_len, src, head, prev);
        pos += cur_len as i64;
    } else {
        let b = get_deflate_byte(pos, dict_slice, dict_len, src);
        push_literal_token(b as u16, tokens, lit_count);
        pos++;
    }
}

// Evaluates lazy match candidate when a previous match is available.
//
// Example:
//   pos = 10, cur_len = 4, prev_len = 3
//   advances: pos = 11, match_available = true
fn process_lazy_match_available(
    cfg:             DeflateConfig,
    cur_len:         i32,
    cur_dist:        i32,
    prev_len:        i32&,
    prev_dist:       i32&,
    match_available: bool&,
    pos:             i64&,
    total_len:       i64,
    dict_slice:      const u8[:],
    dict_len:        i64,
    src:             const u8[:],
    head:            i32[4096]&,
    prev:            i32[32768]&,
    tokens:          LzToken[>..]&,
    lit_count:       i32[288]&,
    dist_count:      i32[32]&,
) {
    if cur_len > prev_len {
        let b = get_deflate_byte(pos - 1, dict_slice, dict_len, src);
        push_literal_token(b as u16, tokens, lit_count);
        prev_len = cur_len;
        prev_dist = cur_dist;

        if cur_len >= cfg.max_lazy || cur_len >= 258 {
            push_match_token(prev_len, prev_dist, tokens, lit_count, dist_count);
            update_match_skip_hashes(pos, prev_len, total_len, dict_slice, dict_len, src, head, prev);
            pos += prev_len as i64;
            match_available = false;
        } else {
            match_available = true;
            pos++;
        }
    } else {
        push_match_token(prev_len, prev_dist, tokens, lit_count, dist_count);
        let match_end = (pos - 1) + (prev_len as i64);
        var k = pos + 1;
        while k < match_end {
            update_skip_hash(k, total_len, dict_slice, dict_len, src, head, prev);
            k++;
        }
        pos = match_end;
        match_available = false;
    }
}

// Evaluates initial match candidate when no previous match is pending.
//
// Example:
//   pos = 10, cur_len = 4
//   advances: pos = 11, match_available = true
fn process_lazy_match_unavailable(
    cfg:             DeflateConfig,
    cur_len:         i32,
    cur_dist:        i32,
    prev_len:        i32&,
    prev_dist:       i32&,
    match_available: bool&,
    pos:             i64&,
    total_len:       i64,
    dict_slice:      const u8[:],
    dict_len:        i64,
    src:             const u8[:],
    head:            i32[4096]&,
    prev:            i32[32768]&,
    tokens:          LzToken[>..]&,
    lit_count:       i32[288]&,
    dist_count:      i32[32]&,
) {
    if cur_len >= 3 {
        prev_len = cur_len;
        prev_dist = cur_dist;
        if cur_len >= cfg.max_lazy || cur_len >= 258 {
            push_match_token(prev_len, prev_dist, tokens, lit_count, dist_count);
            update_match_skip_hashes(pos, prev_len, total_len, dict_slice, dict_len, src, head, prev);
            pos += prev_len as i64;
        } else {
            match_available = true;
            pos++;
        }
    } else {
        let b = get_deflate_byte(pos, dict_slice, dict_len, src);
        push_literal_token(b as u16, tokens, lit_count);
        pos++;
    }
}

fn update_hash_and_get_cand(
    pos:        i64,
    total_len:  i64,
    dict_slice: const u8[:],
    dict_len:   i64,
    src:        const u8[:],
    head:       i32[4096]&,
    prev:       i32[32768]&,
) -> i32 {
    guard pos + 2 < total_len else { return -1; }
    let b0 = get_deflate_byte(pos, dict_slice, dict_len, src) as i32;
    let b1 = get_deflate_byte(pos + 1, dict_slice, dict_len, src) as i32;
    let b2 = get_deflate_byte(pos + 2, dict_slice, dict_len, src) as i32;
    let h = ((b0 << 8) ^ (b1 << 4) ^ b2) & 4095;
    let cand = head[h];
    head[h] = pos as i32;
    prev[pos & 32767] = cand;
    return cand;
}

fn lz77_find_matches(
    src:        const u8[:],
    dict_slice: const u8[:],
    dict_len:   i64,
    total_len:  i64,
    cfg:        DeflateConfig,
    tokens:     LzToken[>..]&,
    lit_count:  i32[288]&,
    dist_count: i32[32]&,
) {
    var head: i32[4096]  = [-1; 4096];
    var prev: i32[32768] = [-1; 32768];

    init_dict_hash_table(dict_slice, dict_len, head, prev);

    var pos:             i64  = dict_len;
    var prev_len:        i32  = 0;
    var prev_dist:       i32  = 0;
    var match_available: bool = false;

    while pos < total_len {
        let cand = update_hash_and_get_cand(pos, total_len, dict_slice, dict_len, src, head, prev);

        var cur_len:  i32 = 0;
        var cur_dist: i32 = 0;
        if cand != -1 {
            var max_chain = cfg.max_chain;
            if match_available && prev_len >= cfg.good_len {
                max_chain >>= 2;
            }
            cur_len, cur_dist = find_longest_match(
                pos, cand, max_chain, cfg.nice_len,
                dict_slice, dict_len, src, total_len, prev[..],
            );
        }

        if cfg.max_lazy == 0 {
            process_greedy_token(
                cur_len, cur_dist, pos, total_len, dict_slice, dict_len, src,
                head, prev, tokens, lit_count, dist_count,
            );
        } else if match_available {
            process_lazy_match_available(
                cfg, cur_len, cur_dist, prev_len, prev_dist, match_available, pos, total_len,
                dict_slice, dict_len, src, head, prev, tokens, lit_count, dist_count,
            );
        } else {
            process_lazy_match_unavailable(
                cfg, cur_len, cur_dist, prev_len, prev_dist, match_available, pos, total_len,
                dict_slice, dict_len, src, head, prev, tokens, lit_count, dist_count,
            );
        }
    }

    if match_available {
        push_match_token(prev_len, prev_dist, tokens, lit_count, dist_count);
    }
    push_literal_token(256, tokens, lit_count);
}

fn calc_fixed_bits(tokens: const LzToken[:]) -> i64 {
    var fixed_bits: i64 = 3;
    for &tok in tokens {
        let sym_idx = tok.sym as i64;
        if tok.is_match {
            let dsym_idx = tok.dist_sym as i64;
            let m_cost = (FIXED_LIT_LEN[sym_idx] as i64) + (tok.extra_bits as i64);
            let d_cost = (5 as i64) + (tok.dist_extra_bits as i64);
            fixed_bits += m_cost + d_cost;
        } else {
            fixed_bits += FIXED_LIT_LEN[sym_idx] as i64;
        }
    }
    return fixed_bits;
}

fn build_dynamic_combined_lens(
    dyn_lit_lens:  const i32[:],
    dyn_dist_lens: const i32[:],
    combined_lens: i32[>..]&,
) -> i32, i32 {
    var nlen: i32 = 286;
    while nlen > 257 && dyn_lit_lens[(nlen - 1) as i64] == 0 {
        nlen--;
    }
    var ndist: i32 = 30;
    while ndist > 1 && dyn_dist_lens[(ndist - 1) as i64] == 0 {
        ndist--;
    }
    for i in nlen {
        combined_lens.push(dyn_lit_lens[i as i64]);
    }
    for j in ndist {
        combined_lens.push(dyn_dist_lens[j as i64]);
    }
    return nlen, ndist;
}

fn calc_dynamic_bit_cost(
    ncode:         i32,
    rle_tokens:    const RleToken[:],
    hclen_lens:    const i32[:],
    tokens:        const LzToken[:],
    dyn_lit_lens:  const i32[:],
    dyn_dist_lens: const i32[:],
) -> i64 {
    var dyn_bits: i64 = 3 + 5 + 5 + 4 + (ncode as i64) * 3;
    for &rt in rle_tokens {
        let sym_idx = rt.sym as i64;
        dyn_bits += (hclen_lens[sym_idx] as i64) + (rt.extra_bits as i64);
    }
    for &tok in tokens {
        if tok.is_match {
            let sym_idx = tok.sym as i64;
            let dsym_idx = tok.dist_sym as i64;
            let m_cost = (dyn_lit_lens[sym_idx] as i64) + (tok.extra_bits as i64);
            let d_cost = (dyn_dist_lens[dsym_idx] as i64) + (tok.dist_extra_bits as i64);
            dyn_bits += m_cost + d_cost;
        } else {
            let sym_idx = tok.sym as i64;
            dyn_bits += dyn_lit_lens[sym_idx] as i64;
        }
    }
    return dyn_bits;
}

fn build_dynamic_code_length_tree(
    rle_tokens:  const RleToken[:],
    hclen_lens:  i32[>..]&,
    hclen_codes: u16[>..]&,
) -> i32 {
    var code_len_counts: i32[19] = [0; 19];
    for &rt in rle_tokens {
        if rt.sym >= 0 && rt.sym < 19 {
            code_len_counts[rt.sym]++;
        }
    }

    build_huffman_codes(code_len_counts[..], 7, hclen_lens, hclen_codes);

    var ncode: i32 = 19;
    while ncode > 4 && hclen_lens[CODE_LENGTH_ORDER[(ncode - 1) as i64] as i64] == 0 {
        ncode--;
    }
    return ncode;
}

fn write_dynamic_block_header<B>(
    w:          BitWriter&,
    bfinal_bit: u32,
    nlen:       i32,
    ndist:      i32,
    ncode:      i32,
    hclen_lens: const i32[:],
    out:        B&,
) {
    write_bits(w, bfinal_bit | (2 << 1), 3, out);
    write_bits(w, (nlen - 257) as u32, 5, out);
    write_bits(w, (ndist - 1) as u32, 5, out);
    write_bits(w, (ncode - 4) as u32, 4, out);

    for i in ncode {
        let order_sym = CODE_LENGTH_ORDER[i as i64] as i64;
        let clen_val = hclen_lens[order_sym] as u32;
        write_bits(w, clen_val, 3, out);
    }
}

fn write_dynamic_huffman_payload<B>(
    tokens:         const LzToken[:],
    rle_tokens:     const RleToken[:],
    hclen_codes:    const u16[:],
    hclen_lens:     const i32[:],
    dyn_lit_codes:  const u16[:],
    dyn_lit_lens:   const i32[:],
    dyn_dist_codes: const u16[:],
    dyn_dist_lens:  const i32[:],
    w:              BitWriter&,
    out:            B&,
) {
    for &rt in rle_tokens {
        let sym_idx = rt.sym as i64;
        let c = hclen_codes[sym_idx] as u32;
        let l = hclen_lens[sym_idx];
        write_bits(w, c, l, out);
        if rt.extra_bits > 0 {
            write_bits(w, rt.extra_val, rt.extra_bits, out);
        }
    }

    for &tok in tokens {
        if tok.is_match {
            let sym_idx = tok.sym as i64;
            let c = dyn_lit_codes[sym_idx] as u32;
            let l = dyn_lit_lens[sym_idx];
            write_bits(w, c, l, out);
            if tok.extra_bits > 0 {
                write_bits(w, tok.extra_val as u32, tok.extra_bits as i32, out);
            }

            let dsym_idx = tok.dist_sym as i64;
            let dc = dyn_dist_codes[dsym_idx] as u32;
            let dl = dyn_dist_lens[dsym_idx];
            write_bits(w, dc, dl, out);
            if tok.dist_extra_bits > 0 {
                write_bits(w, tok.dist_extra_val as u32, tok.dist_extra_bits as i32, out);
            }
        } else {
            let sym_idx = tok.sym as i64;
            let c = dyn_lit_codes[sym_idx] as u32;
            let l = dyn_lit_lens[sym_idx];
            write_bits(w, c, l, out);
        }
    }
}

fn emit_dynamic_deflate_block<B>(
    tokens:      const LzToken[:],
    lit_count:   const i32[:],
    dist_count:  i32[32]&,
    out:         B&,
    w:           BitWriter&,
    bfinal_bit:  u32,
    stored_bits: i64,
    fixed_bits:  i64,
    src:         const u8[:],
    is_final:    bool,
) -> bool {
    var total_dists: i32 = 0;
    for i in 32 { total_dists += dist_count[i]; }
    if total_dists == 0 {
        dist_count[0] = 1;
    }

    var dyn_lit_lens:  i32[>..] = [];
    var dyn_lit_codes: u16[>..] = [];
    build_huffman_codes(lit_count, 15, dyn_lit_lens, dyn_lit_codes);

    var dyn_dist_lens:  i32[>..] = [];
    var dyn_dist_codes: u16[>..] = [];
    build_huffman_codes(dist_count[..], 15, dyn_dist_lens, dyn_dist_codes);

    var combined_lens: i32[>..] = [];
    let nlen, ndist = build_dynamic_combined_lens(dyn_lit_lens[..], dyn_dist_lens[..], combined_lens);

    var rle_tokens: RleToken[>..] = [];
    rle_encode_lengths(combined_lens[..], rle_tokens);

    var hclen_lens:  i32[>..] = [];
    var hclen_codes: u16[>..] = [];
    let ncode = build_dynamic_code_length_tree(rle_tokens[..], hclen_lens, hclen_codes);

    let dyn_bits = calc_dynamic_bit_cost(
        ncode, rle_tokens[..], hclen_lens[..],
        tokens, dyn_lit_lens[..], dyn_dist_lens[..],
    );

    if stored_bits <= fixed_bits && stored_bits <= dyn_bits {
        emit_stored_blocks(src, out, w, is_final);
        return true;
    } else if fixed_bits <= dyn_bits {
        emit_fixed_block(tokens, out, w, is_final);
        return true;
    }

    write_dynamic_block_header(w, bfinal_bit, nlen, ndist, ncode, hclen_lens[..], out);
    write_dynamic_huffman_payload(
        tokens, rle_tokens[..], hclen_codes[..], hclen_lens[..],
        dyn_lit_codes[..], dyn_lit_lens[..], dyn_dist_codes[..], dyn_dist_lens[..],
        w, out,
    );

    if is_final {
        flush_bits(w, out);
    }
    return true;
}

fn deflate_block<B>(
    src:      const u8[:],
    out:      B&,
    w:        BitWriter&,
    level:    i32         = 6,
    is_final: bool        = true,
    dict:     const u8[:] = "",
) -> bool {
    let bfinal_bit: u32 = if is_final { 1 } else { 0 };

    if level <= 0 {
        emit_stored_blocks(src, out, w, is_final);
        return true;
    }

    let cfg = get_deflate_config(level);

    var tokens:     LzToken[>..] = [];
    var lit_count:  i32[288]     = [0; 288];
    var dist_count: i32[32]      = [0; 32];

    let dict_slice = if dict.len > 32768 { dict[dict.len - 32768..] } else { dict };
    let dict_len = dict_slice.len;
    let total_len = dict_len + src.len;

    lz77_find_matches(
        src, dict_slice, dict_len, total_len, cfg,
        tokens, lit_count, dist_count,
    );

    let num_chunks = if src.len == 0 { 1 as i64 } else { (src.len + 65534) / 65535 };
    let stored_bits: i64 = num_chunks * 40 + (src.len * 8);
    let fixed_bits = calc_fixed_bits(tokens[..]);

    if level < 6 || src.len < 128 {
        if stored_bits <= fixed_bits {
            emit_stored_blocks(src, out, w, is_final);
        } else {
            emit_fixed_block(tokens[..], out, w, is_final);
        }
        return true;
    }

    return emit_dynamic_deflate_block(
        tokens[..], lit_count[..], dist_count, out, w,
        bfinal_bit, stored_bits, fixed_bits, src, is_final,
    );
}

// Compresses src into out using RFC 1951 Deflate.
// - level == 0: Stored uncompressed blocks.
// - level 1..5: Fast LZ77 match-finding + Fixed Huffman coding.
// - level >= 6: Full LZ77 match-finding + Dynamic Huffman coding (optimal trees).
fn deflate<B>(src: const u8[:], out: B&, level: i32 = 6) -> bool {
    var w = BitWriter { bit_buf: 0, bit_count: 0 };
    return deflate_block(src, out, w, level, true, "");
}

// Compresses src into out using RFC 1951 Deflate with a preset dictionary.
fn deflate_with_dict<B>(src: const u8[:], out: B&, level: i32, dict: const u8[:]) -> bool {
    var w = BitWriter { bit_buf: 0, bit_count: 0 };
    return deflate_block(src, out, w, level, true, dict);
}
