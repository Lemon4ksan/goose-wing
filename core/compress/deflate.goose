// The Goose Deflate / Inflate compression engine: RFC 1951 Specification.
namespace wing;

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
}

// ---- rfc 1951 constants & lookup tables -----------------------------------

const MAX_BITS: i32 = 15;
const MAX_LCODES: i32 = 286;
const MAX_DCODES: i32 = 30;
const MAX_CODES: i32 = 316;
const FIX_LCODES: i32 = 288;

const CODE_LENGTH_ORDER: i32[19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15
];

const LENS_BASE: i32[29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
    35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258
];

const LENS_EXTRA: i32[29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
    3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0
];

const DISTS_BASE: i32[30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
    257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145,
    8193, 12289, 16385, 24577
];

const DISTS_EXTRA: i32[30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
    7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13
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
    src: const u8[:],
    pos: i64 = 0,
    bit_buf: u64 = 0,
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
    r.bit_buf = 0;
    r.bit_count = 0;
}

struct BitWriter {
    bit_buf: u64 = 0,
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
    count: i32[16] = [0; 16],
    symbol: i32[288] = [0; 288],
}

// Constructs canonical Huffman decode table from a list of code lengths.
// Returns 0 on complete code set, >0 on incomplete code set, or <0 on over-subscribed code set.
fn construct_huffman_table(lengths: const i32[:], n_symbols: i32, table: HuffmanTable&) -> i32 {
    for l in 16 {
        table.count[l] = 0;
    }
    for s in n_symbols {
        let len = lengths[s];
        if len > 0 && len <= MAX_BITS {
            table.count[len]++;
        }
    }
    if table.count[0] == n_symbols {
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

    for s in n_symbols {
        let len = lengths[s];
        if len != 0 {
            table.symbol[offs[len]] = s;
            offs[len]++;
        }
    }

    return left;
}

// Decodes the next symbol from the bitstream using the HuffmanTable.
fn decode_huffman_symbol(r: BitReader&, table: const HuffmanTable&) -> i32, bool {
    var code: i32 = 0;
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

    return -1, false;
}

// ---- decompressor: rfc 1951 inflate ----------------------------------------

fn decode_block_codes<B>(
    r: BitReader&,
    lit_table: const HuffmanTable&,
    dist_table: const HuffmanTable&,
    out: B&,
) -> CompressError {
    loop {
        let sym, ok_sym = decode_huffman_symbol(r, lit_table);
        guard ok_sym && sym >= 0 else { return CompressError.InvalidHuffmanCode; }

        if sym < 256 {
            out.push(sym as u8);
        } else if sym == 256 {
            break; // End of block (EOB)
        } else {
            let len_idx = sym - 257;
            guard len_idx < 29 else { return CompressError.CorruptedBitstream; }

            let extra_bits = LENS_EXTRA[len_idx];
            var match_len = LENS_BASE[len_idx];
            if extra_bits > 0 {
                let xval, ok_x = read_bits(r, extra_bits);
                guard ok_x else { return CompressError.InputBufferTruncated; }
                match_len += xval as i32;
            }

            let dist_sym, ok_dist = decode_huffman_symbol(r, dist_table);
            guard ok_dist && dist_sym >= 0 && dist_sym < 30 else { return CompressError.InvalidDistanceCode; }

            let dist_extra = DISTS_EXTRA[dist_sym];
            var match_dist = DISTS_BASE[dist_sym];
            if dist_extra > 0 {
                let dxval, ok_dx = read_bits(r, dist_extra);
                guard ok_dx else { return CompressError.InputBufferTruncated; }
                match_dist += dxval as i32;
            }

            guard (match_dist as i64) <= out.len else { return CompressError.DistanceOutOfBounds; }

            // Copy match bytes backwards from output buffer (supporting overlapping runs)
            let copy_dist = match_dist as i64;
            for i in match_len {
                let back_idx = out.len - copy_dist;
                let b = out[back_idx];
                out.push(b);
            }
        }
    }
    return CompressError.None;
}

// Inflates RFC 1951 raw deflate stream from src into out.
fn inflate<B>(src: const u8[:], out: B&) -> CompressError {
    var r = new_bit_reader(src);
    var is_final: u32 = 0;

    while is_final == 0 {
        let fin, ok_fin = read_bits(r, 1);
        guard ok_fin else { return CompressError.InputBufferTruncated; }
        is_final = fin;

        let btype, ok_type = read_bits(r, 2);
        guard ok_type else { return CompressError.InputBufferTruncated; }

        if btype == 0 {
            // Stored block (uncompressed)
            align_to_byte(r);
            if r.pos + 4 > r.src.len {
                return CompressError.InputBufferTruncated;
            }
            let len = (r.src[r.pos] as u32) | ((r.src[r.pos + 1] as u32) << 8);
            let nlen = (r.src[r.pos + 2] as u32) | ((r.src[r.pos + 3] as u32) << 8);
            r.pos += 4;
            if ((len ^ 0xFFFF) & 0xFFFF) != nlen {
                return CompressError.LengthMismatch;
            }
            if r.pos + (len as i64) > r.src.len {
                return CompressError.InputBufferTruncated;
            }
            for i in (len as i64) {
                out.push(r.src[r.pos + i]);
            }
            r.pos += len as i64;
        } else if btype == 1 {
            // Fixed Huffman block
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

            let err = decode_block_codes(r, fixed_lit, fixed_dist, out);
            guard err == CompressError.None else { return err; }
        } else if btype == 2 {
            // Dynamic Huffman block
            let hlit_val, ok_hlit = read_bits(r, 5);
            guard ok_hlit else { return CompressError.InputBufferTruncated; }
            let nlen = (hlit_val as i32) + 257;

            let hdist_val, ok_hdist = read_bits(r, 5);
            guard ok_hdist else { return CompressError.InputBufferTruncated; }
            let ndist = (hdist_val as i32) + 1;

            let hclen_val, ok_hclen = read_bits(r, 4);
            guard ok_hclen else { return CompressError.InputBufferTruncated; }
            let ncode = (hclen_val as i32) + 4;

            var code_lens_table: i32[19] = [0; 19];
            for i in ncode {
                let clen, ok_cl = read_bits(r, 3);
                guard ok_cl else { return CompressError.InputBufferTruncated; }
                code_lens_table[CODE_LENGTH_ORDER[i]] = clen as i32;
            }

            var h_code = HuffmanTable { .. };
            let res_c = construct_huffman_table(code_lens_table[..], 19, h_code);
            guard res_c >= 0 else { return CompressError.CodeLengthsOverSubscribed; }

            var lit_dist_lens: i32[320] = [0; 320];
            var cur_idx: i32 = 0;
            let total_codes = nlen + ndist;

            while cur_idx < total_codes {
                let sym, ok_s = decode_huffman_symbol(r, h_code);
                guard ok_s && sym >= 0 else { return CompressError.InvalidHuffmanCode; }

                if sym < 16 {
                    lit_dist_lens[cur_idx] = sym;
                    cur_idx++;
                } else if sym == 16 {
                    guard cur_idx > 0 else { return CompressError.RepeatWithoutPreviousLength; }
                    let prev_len = lit_dist_lens[cur_idx - 1];
                    let rpt_bits, ok_rb = read_bits(r, 2);
                    guard ok_rb else { return CompressError.InputBufferTruncated; }
                    let count = (rpt_bits as i32) + 3;
                    for i in count {
                        guard cur_idx < total_codes else { return CompressError.TooManyLengthOrDistanceCodes; }
                        lit_dist_lens[cur_idx] = prev_len;
                        cur_idx++;
                    }
                } else if sym == 17 {
                    let rpt_bits, ok_rb = read_bits(r, 3);
                    guard ok_rb else { return CompressError.InputBufferTruncated; }
                    let count = (rpt_bits as i32) + 3;
                    for i in count {
                        guard cur_idx < total_codes else { return CompressError.TooManyLengthOrDistanceCodes; }
                        lit_dist_lens[cur_idx] = 0;
                        cur_idx++;
                    }
                } else if sym == 18 {
                    let rpt_bits, ok_rb = read_bits(r, 7);
                    guard ok_rb else { return CompressError.InputBufferTruncated; }
                    let count = (rpt_bits as i32) + 11;
                    for i in count {
                        guard cur_idx < total_codes else { return CompressError.TooManyLengthOrDistanceCodes; }
                        lit_dist_lens[cur_idx] = 0;
                        cur_idx++;
                    }
                }
            }

            var dyn_lit = HuffmanTable { .. };
            let res_lit = construct_huffman_table(lit_dist_lens[..nlen], nlen, dyn_lit);
            guard res_lit >= 0 else { return CompressError.CodeLengthsOverSubscribed; }

            var dyn_dist = HuffmanTable { .. };
            let res_dist = construct_huffman_table(lit_dist_lens[nlen..nlen + ndist], ndist, dyn_dist);
            guard res_dist >= 0 else { return CompressError.CodeLengthsOverSubscribed; }

            let err = decode_block_codes(r, dyn_lit, dyn_dist, out);
            guard err == CompressError.None else { return err; }
        } else {
            return CompressError.InvalidBlockType;
        }
    }

    return CompressError.None;
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

// Compresses src into out using RFC 1951 Deflate.
// - level == 0: Stored uncompressed blocks.
// - level >= 1: LZ77 match-finding + Fixed Huffman coding.
fn deflate<B>(src: const u8[:], out: B&, level: i32 = 6) -> bool {
    var w = BitWriter { bit_buf: 0, bit_count: 0 };

    if level == 0 {
        // Stored block mode
        var offset: i64 = 0;
        while offset < src.len || src.len == 0 {
            let remaining = src.len - offset;
            let block_size = if remaining < 65535 { remaining } else { 65535 };
            let is_last = (offset + block_size >= src.len);

            // BFINAL (1 bit) + BTYPE 00 (2 bits)
            write_bits(w, if is_last { 1 } else { 0 }, 1, out);
            write_bits(w, 0, 2, out);
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
        return true;
    }

    // Level >= 1: LZ77 + Fixed Huffman encoding
    // BFINAL = 1 (1 bit) | BTYPE = 01 (2 bits) -> 3 bits: 1 | (1 << 1) = 3
    write_bits(w, 3, 3, out);

    var head: i32[4096] = [-1; 4096];
    var prev: i32[32768] = [-1; 32768];

    var pos: i64 = 0;
    while pos < src.len {
        var best_len: i32 = 0;
        var best_dist: i32 = 0;

        if pos + 2 < src.len {
            let b0 = src[pos] as i32;
            let b1 = src[pos + 1] as i32;
            let b2 = src[pos + 2] as i32;
            let h = ((b0 << 8) ^ (b1 << 4) ^ b2) & 4095;

            var cand = head[h];
            head[h] = pos as i32;
            prev[pos & 32767] = cand;

            var chain_count = 0;
            let max_chain = if level >= 6 { 32 } else { 8 };

            while cand != -1 && chain_count < max_chain {
                let dist = (pos as i32) - cand;
                if dist > 32768 || dist <= 0 { break; }

                var l: i32 = 0;
                let rem = (src.len - pos) as i32;
                let max_l = if rem < 258 { rem } else { 258 };

                while l < max_l && src[pos + (l as i64)] == src[(cand as i64) + (l as i64)] {
                    l++;
                }

                if l > best_len {
                    best_len = l;
                    best_dist = dist;
                    if best_len >= 258 { break; }
                }

                cand = prev[cand & 32767];
                chain_count++;
            }
        }

        if best_len >= 3 {
            let sym, xbits, xval = find_length_symbol(best_len);
            let lit_code = FIXED_LIT_CODE[sym] as u32;
            let lit_nbits = FIXED_LIT_LEN[sym] as i32;
            write_bits(w, lit_code, lit_nbits, out);
            if xbits > 0 {
                write_bits(w, xval, xbits, out);
            }

            let dsym, dxbits, dxval = find_distance_symbol(best_dist);
            let dist_code = FIXED_DIST_CODE[dsym] as u32;
            write_bits(w, dist_code, 5, out);
            if dxbits > 0 {
                write_bits(w, dxval, dxbits, out);
            }

            // Insert skipped positions into hash chain
            for k in 1..best_len {
                let skip_pos = pos + (k as i64);
                if skip_pos + 2 < src.len {
                    let sb0 = src[skip_pos] as i32;
                    let sb1 = src[skip_pos + 1] as i32;
                    let sb2 = src[skip_pos + 2] as i32;
                    let sh = ((sb0 << 8) ^ (sb1 << 4) ^ sb2) & 4095;
                    prev[skip_pos & 32767] = head[sh];
                    head[sh] = skip_pos as i32;
                }
            }
            pos += best_len as i64;
        } else {
            let b = src[pos] as i32;
            let lit_code = FIXED_LIT_CODE[b] as u32;
            let lit_nbits = FIXED_LIT_LEN[b] as i32;
            write_bits(w, lit_code, lit_nbits, out);
            pos++;
        }
    }

    // Emit End-of-Block (EOB 256)
    let eob_code = FIXED_LIT_CODE[256] as u32;
    let eob_nbits = FIXED_LIT_LEN[256] as i32;
    write_bits(w, eob_code, eob_nbits, out);
    flush_bits(w, out);

    return true;
}
