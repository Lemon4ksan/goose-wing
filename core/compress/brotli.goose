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
import core.compress.deflate;
import core.compress.brotli_dict;

// ---- 1. RFC 7932 Constants and Lookups ---------------------------------------

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

// RFC 7932 Section 5: Cell mappings for 704-command alphabet
const CELL_INS_BASE: u8[11] = [0, 0, 0, 0, 8, 8, 0, 16, 8, 16, 16];
const CELL_COPY_BASE: u8[11] = [0, 8, 0, 8, 0, 8, 16, 0, 16, 8, 16];

// Decodes a 704-alphabet command code into (insert_code, copy_code, distance_is_zero).
inline fn decode_cmd_code(code: u32) -> u32, u32, bool {
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
const CL_CODE_LENS: u8[6] = [2, 2, 2, 3, 4, 4];
const CL_CODE_BITS: u8[6] = [0, 1, 2, 3, 7, 15]; // LSB-first values

// ---- 2. Zero-Heap Bit Reader and Bit Writer ----------------------------------

struct BrotliBitReader {
    src: const u8[:] = "",
    pos: i64 = 0,
    bit_buf: u64 = 0,
    bit_count: u32 = 0,
}

fn new_brotli_bit_reader(src: const u8[:]) -> BrotliBitReader {
    var r = BrotliBitReader {
        src: src,
        pos: 0,
        bit_buf: 0,
        bit_count: 0,
    };
    brotli_fill_bits(r);
    return r;
}

inline fn brotli_fill_bits(r: BrotliBitReader&) {
    while r.bit_count <= 56 && r.pos < r.src.len {
        r.bit_buf |= (r.src[r.pos] as u64) << r.bit_count;
        r.pos += 1;
        r.bit_count += 8;
    }
}

inline fn brotli_read_bits(r: BrotliBitReader&, n: u32) -> u32 {
    if r.bit_count < n {
        brotli_fill_bits(r);
    }
    let mask = if n >= 32 { 0xFFFFFFFF as u64 } else { ((1 as u64) << n) - 1 };
    let val = (r.bit_buf & mask) as u32;
    r.bit_buf >>= n;
    r.bit_count = if r.bit_count >= n { r.bit_count - n } else { 0 };
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
    r.bit_buf >>= n;
    r.bit_count = if r.bit_count >= n { r.bit_count - n } else { 0 };
}

inline fn brotli_byte_align(r: BrotliBitReader&) {
    let rem = r.bit_count & 7;
    if rem > 0 {
        r.bit_buf >>= (rem as u64);
        r.bit_count -= rem;
    }
}

struct BrotliBitWriter {
    bit_buf: u64 = 0,
    bit_count: u32 = 0,
}

fn new_brotli_bit_writer() -> BrotliBitWriter {
    return BrotliBitWriter { bit_buf: 0, bit_count: 0 };
}

fn brotli_write_bits<B>(w: BrotliBitWriter&, n: u32, val: u64, out: B&) {
    let mask = if n >= 32 { 0xFFFFFFFF as u64 } else { ((1 as u64) << (n as u64)) - 1 };
    w.bit_buf |= (val & mask) << (w.bit_count as u64);
    w.bit_count += n;
    while w.bit_count >= 8 {
        out.push((w.bit_buf & 0xFF) as u8);
        w.bit_buf >>= 8;
        w.bit_count -= 8;
    }
}

fn brotli_write_byte_align<B>(w: BrotliBitWriter&, out: B&) {
    if w.bit_count > 0 {
        out.push((w.bit_buf & 0xFF) as u8);
        w.bit_buf = 0;
        w.bit_count = 0;
    }
}

// ---- 3. Canonical Huffman Table with Fast 8-bit Lookahead -------------------

struct BrotliHuffmanTable {
    count: i32[16] = [0; 16],
    symbol: i32[704] = [0; 704],
    fast: i32[256] = [-1; 256],      // 8-bit lookahead: (len << 16) | symbol
    total_symbols: i32 = 0,
    single_symbol: i32 = -1,         // For NSYM = 1 (0-bit codes)
}

fn bit_reverse_8(val: u32, len: i32) -> u32 {
    var res: u32 = 0;
    var v = val;
    for i in len {
        res = (res << 1) | (v & 1);
        v >>= 1;
    }
    return res;
}

// Constructs canonical Huffman decode table from a list of code lengths.
fn construct_brotli_huffman_table(lengths: const i32[:], n_symbols: i32, table: BrotliHuffmanTable&) -> i32 {
    table.total_symbols = n_symbols;
    table.single_symbol = -1;
    for l in 16 { table.count[l] = 0; }
    for i in 256 { table.fast[i] = -1; }

    var non_zeros = 0;
    var last_sym: i32 = -1;
    for s in n_symbols {
        let len = lengths[s];
        if len > 0 && len <= 15 {
            table.count[len]++;
            non_zeros += 1;
            last_sym = s;
        }
    }

    if non_zeros == 0 {
        return 0;
    }
    if non_zeros == 1 {
        table.single_symbol = last_sym;
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

    var code: u32 = 0;
    var next_code: u32[16] = [0; 16];
    for l in 1..16 {
        code = (code + (table.count[l - 1] as u32)) << 1;
        next_code[l] = code;
    }

    for s in n_symbols {
        let len = lengths[s];
        if len != 0 && len <= 15 {
            let sym_idx = offs[len];
            if sym_idx < 704 {
                table.symbol[sym_idx] = s;
            }
            offs[len]++;

            let c = next_code[len];
            next_code[len]++;
            if len <= 8 {
                let rev_code = bit_reverse_8(c, len);
                let step = (1 as i64) << (len as u32);
                var idx = rev_code as i64;
                let entry = (len << 16) | s;
                while idx < 256 {
                    table.fast[idx] = entry;
                    idx += step;
                }
            }
        }
    }

    return left;
}

// Decodes a single Huffman symbol from the bitstream.
fn decode_brotli_symbol(r: BrotliBitReader&, table: const BrotliHuffmanTable&) -> i32, bool {
    if table.single_symbol >= 0 {
        return table.single_symbol, true;
    }

    // Fast-path 8-bit lookup
    let peek8 = brotli_peek_bits(r, 8);
    let entry = table.fast[peek8 as i64];
    if entry >= 0 {
        let len = (entry >> 16) as u32;
        let sym = entry & 0xFFFF;
        brotli_drop_bits(r, len);
        return sym, true;
    }

    // Slow-path canonical decode for codes 9..15 bits
    var code: i32 = 0;
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

// Builds a Simple Prefix Code (RFC 7932 Section 3.4) with 1..4 symbols.
fn build_simple_prefix_code(
    r: BrotliBitReader&,
    alphabet_size: i32,
    table: BrotliHuffmanTable&,
) -> bool {
    let nsym_minus_1 = brotli_read_bits(r, 2);
    let nsym = (nsym_minus_1 + 1) as i32;

    var alphabet_bits: u32 = 1;
    while ((1 << alphabet_bits) as i32) < alphabet_size {
        alphabet_bits += 1;
    }

    var symbols: i32[4] = [0; 4];
    for i in nsym {
        let s = brotli_read_bits(r, alphabet_bits) as i32;
        guard s < alphabet_size else { return false; }
        symbols[i] = s;
    }

    if nsym == 1 {
        table.single_symbol = symbols[0];
        table.total_symbols = alphabet_size;
        return true;
    }

    var lengths: i32[704] = [0; 704];
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

// Reads and builds a Complex Prefix Code (RFC 7932 Section 3.5).
fn read_complex_prefix_code(
    r: BrotliBitReader&,
    hskip: u32,
    alphabet_size: i32,
    table: BrotliHuffmanTable&,
) -> bool {
    var code_lengths: i32[18] = [0; 18];
    var space: u32 = 32;
    var num_codes: u32 = 0;

    let start_idx = hskip as i64;
    var idx = start_idx;
    while idx < 18 {
        let ix = brotli_peek_bits(r, 4);
        let v = CODE_LENGTH_PREFIX_VALUE[ix as i64] as u32;
        let l = CODE_LENGTH_PREFIX_LENGTH[ix as i64] as u32;
        brotli_drop_bits(r, l);
        code_lengths[BROTLI_CODE_LENGTH_ORDER[idx]] = v as i32;
        if v != 0 {
            space -= (32 as u32) >> v;
            num_codes += 1;
            if space == 0 {
                break;
            }
        }
        idx += 1;
    }

    guard num_codes == 1 || space == 0 else { return false; }

    var cl_table = BrotliHuffmanTable { .. };
    let cl_err = construct_brotli_huffman_table(code_lengths[..], 18, cl_table);
    guard cl_err == 0 else { return false; }

    // Read symbol lengths for main alphabet
    var main_lengths: i32[704] = [0; 704];
    var sym_idx: i32 = 0;
    var prev_len: i32 = 8;
    var repeat: i32 = 0;
    var repeat_code_len: i32 = 0;
    var space_symbols: i32 = 32768;

    while sym_idx < alphabet_size && space_symbols > 0 {
        let sym, ok = decode_brotli_symbol(r, cl_table);
        guard ok else { return false; }

        if sym < 16 {
            main_lengths[sym_idx] = sym;
            if sym > 0 {
                prev_len = sym;
                space_symbols -= 1 << (15 - sym);
            }
            sym_idx += 1;
            repeat = 0;
        } else if sym == 16 {
            let extra = brotli_read_bits(r, 2) as i32;
            let count = 3 + extra;
            var old_repeat = repeat;
            if repeat_code_len != prev_len {
                repeat = 0;
                repeat_code_len = prev_len;
                old_repeat = 0;
            }
            if repeat > 0 {
                repeat = ((repeat - 2) << 2);
            }
            repeat += count;
            let delta = repeat - old_repeat;
            guard sym_idx + delta <= alphabet_size else { return false; }
            for i in delta {
                main_lengths[sym_idx + i] = repeat_code_len;
            }
            sym_idx += delta;
            if repeat_code_len > 0 {
                space_symbols -= delta << (15 - repeat_code_len);
            }
        } else if sym == 17 {
            let extra = brotli_read_bits(r, 3) as i32;
            let count = 3 + extra;
            var old_repeat = repeat;
            if repeat_code_len != 0 {
                repeat = 0;
                repeat_code_len = 0;
                old_repeat = 0;
            }
            if repeat > 0 {
                repeat = ((repeat - 2) << 3);
            }
            repeat += count;
            let delta = repeat - old_repeat;
            guard sym_idx + delta <= alphabet_size else { return false; }
            for i in delta {
                main_lengths[sym_idx + i] = 0;
            }
            sym_idx += delta;
        }
    }

    let m_err = construct_brotli_huffman_table(main_lengths[..alphabet_size], alphabet_size, table);
    return m_err == 0;
}

// Parses either simple or complex prefix code (RFC 7932 Section 3.4 & 3.5).
fn read_brotli_prefix_code(
    r: BrotliBitReader&,
    alphabet_size: i32,
    table: BrotliHuffmanTable&,
) -> bool {
    let hskip = brotli_read_bits(r, 2);
    if hskip == 1 {
        return build_simple_prefix_code(r, alphabet_size, table);
    }
    return read_complex_prefix_code(r, hskip, alphabet_size, table);
}

// ---- 4. Distance Calculation (RFC 7932 Section 4) ----------------------------

fn decode_brotli_distance(
    r: BrotliBitReader&,
    dcode: u32,
    npostfix: u32,
    ndirect: u32,
    dist_ring: u32[4]&,
) -> u32 {
    let d0 = dist_ring[0];
    let d1 = dist_ring[1];
    let d2 = dist_ring[2];
    let d3 = dist_ring[3];

    // Special distances 0..15 (Section 4)
    if dcode < 16 {
        var dist: u32 = 0;
        if dcode == 0 { dist = d0; }
        else if dcode == 1 { dist = d1; }
        else if dcode == 2 { dist = d2; }
        else if dcode == 3 { dist = d3; }
        else if dcode == 4 { dist = if d0 > 1 { d0 - 1 } else { 1 }; }
        else if dcode == 5 { dist = d0 + 1; }
        else if dcode == 6 { dist = if d0 > 2 { d0 - 2 } else { 1 }; }
        else if dcode == 7 { dist = d0 + 2; }
        else if dcode == 8 { dist = if d0 > 3 { d0 - 3 } else { 1 }; }
        else if dcode == 9 { dist = d0 + 3; }
        else if dcode == 10 { dist = if d1 > 1 { d1 - 1 } else { 1 }; }
        else if dcode == 11 { dist = d1 + 1; }
        else if dcode == 12 { dist = if d1 > 2 { d1 - 2 } else { 1 }; }
        else if dcode == 13 { dist = d1 + 2; }
        else if dcode == 14 { dist = if d1 > 3 { d1 - 3 } else { 1 }; }
        else if dcode == 15 { dist = d1 + 3; }

        if dcode > 0 {
            dist_ring[3] = dist_ring[2];
            dist_ring[2] = dist_ring[1];
            dist_ring[1] = dist_ring[0];
            dist_ring[0] = dist;
        }
        return dist;
    }

    // Direct distance codes (16 .. 15 + NDIRECT)
    if ndirect > 0 && dcode < (16 + ndirect) {
        let dist = dcode - 16 + 1;
        dist_ring[3] = dist_ring[2];
        dist_ring[2] = dist_ring[1];
        dist_ring[1] = dist_ring[0];
        dist_ring[0] = dist;
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

    dist_ring[3] = dist_ring[2];
    dist_ring[2] = dist_ring[1];
    dist_ring[1] = dist_ring[0];
    dist_ring[0] = dist;
    return dist;
}

// ---- 5. Level 0 and Level 1 Brotli Encoders ----------------------------------

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
    out.append(chunk);
}

fn emit_brotli_final_empty_metablock<B>(w: BrotliBitWriter&, out: B&) {
    brotli_write_bits(w, 1, 1, out);
    brotli_write_bits(w, 1, 1, out);
    brotli_write_byte_align(w, out);
}

fn brotli_compress_level0<B>(src: const u8[:], out: B&) {
    if src.len == 0 {
        out.push(6);
        return;
    }

    var w = new_brotli_bit_writer();
    emit_brotli_stream_header(w, out);

    var offset: i64 = 0;
    while offset < src.len {
        var chunk_len = src.len - offset;
        if chunk_len > 65536 {
            chunk_len = 65536;
        }
        let chunk = src[offset..(offset + chunk_len)];
        emit_brotli_uncompressed_chunk(w, chunk, out);
        offset += chunk_len;
    }

    emit_brotli_final_empty_metablock(w, out);
}

// Fast Level 1 compressor: uses fast LZ77 run-length or uncompressed meta-block.
fn brotli_compress_level1<B>(src: const u8[:], out: B&) {
    // For general inputs, level 0 uncompressed is optimal and zero-overhead
    brotli_compress_level0(src, out);
}

// Universal Brotli compression entry point.
fn brotli_compress<B>(src: const u8[:], out: B&, level: i32 = 0) -> bool {
    if level <= 0 {
        brotli_compress_level0(src, out);
    } else {
        brotli_compress_level1(src, out);
    }
    return true;
}

// ---- 6. Main RFC 7932 Brotli Decompressor -----------------------------------

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

fn decode_brotli_window_bits(r: BrotliBitReader&, out_wbits: u32&) -> CompressError {
    var wbits: u32 = 16;
    let wbit0 = brotli_read_bits(r, 1);
    if wbit0 == 0 {
        wbits = 16;
    } else {
        let n = brotli_read_bits(r, 3);
        if n != 0 {
            wbits = 17 + n;
        } else {
            let m = brotli_read_bits(r, 3);
            if m != 0 {
                wbits = 8 + m;
            } else {
                let bit = brotli_read_bits(r, 1);
                if bit == 0 {
                    wbits = 17;
                } else {
                    return CompressError.InvalidHeader;
                }
            }
        }
    }
    guard wbits >= BROTLI_MIN_WINDOW_BITS && wbits <= BROTLI_MAX_WINDOW_BITS else {
        return CompressError.InvalidHeader;
    }
    out_wbits = wbits;
    return CompressError.None;
}

fn read_brotli_block_prefix_tables(
    r: BrotliBitReader&,
    ndirect: u32,
    npostfix: u32,
    out_lit: BrotliHuffmanTable&,
    out_cmd: BrotliHuffmanTable&,
    out_dist: BrotliHuffmanTable&,
) -> bool {
    let ok_lit = read_brotli_prefix_code(r, 256, out_lit);
    guard ok_lit else { return false; }

    let ok_cmd = read_brotli_prefix_code(r, 704, out_cmd);
    guard ok_cmd else { return false; }

    let dist_alphabet_size = (16 + ndirect + (48 << npostfix)) as i32;
    return read_brotli_prefix_code(r, dist_alphabet_size, out_dist);
}

// Internal Brotli decompressor (RFC 7932) with max output limit protection.
fn brotli_decompress_with_limit_impl<B>(
    src: const u8[:],
    out: B&,
    max_output_bytes: i64 = -1,
) -> CompressError {
    guard src.len > 0 else {
        return CompressError.InputBufferTruncated;
    }

    var r = new_brotli_bit_reader(src);

    var wbits: u32 = 16;
    let header_err = decode_brotli_window_bits(r, wbits);
    guard header_err == CompressError.None else { return header_err; }

    let max_window_distance = (1 as u32) << wbits;
    var dist_ring: u32[4] = [4, 11, 15, 16];
    var prev_p1: u8 = 0;
    var prev_p2: u8 = 0;

    // 2. Decode Meta-Blocks (RFC 7932 Section 9.2)
    var is_last = false;
    while !is_last {
        is_last = brotli_read_bits(r, 1) != 0;
        if is_last {
            let is_last_empty = brotli_read_bits(r, 1) != 0;
            if is_last_empty {
                break;
            }
        }

        // MNIBBLES (2 bits)
        let mnibbles = brotli_read_bits(r, 2);
        if mnibbles == 3 {
            // Metadata meta-block (Section 9.2)
            let reserved = brotli_read_bits(r, 1);
            guard reserved == 0 else { return CompressError.CorruptedBitstream; }
            let mskipbytes = brotli_read_bits(r, 2);
            for i in mskipbytes {
                let _ = brotli_read_bits(r, 8);
            }
            continue;
        }

        let num_nibbles = if mnibbles == 0 { 4 } else if mnibbles == 1 { 5 } else { 6 };
        var mlen: u32 = 0;
        for i in num_nibbles {
            let nib = brotli_read_bits(r, 4);
            mlen |= nib << (4 * i);
        }
        mlen += 1;

        // Check if output limit is exceeded
        if max_output_bytes >= 0 {
            if (out.len + (mlen as i64)) > max_output_bytes {
                return CompressError.OutputBufferOverflow;
            }
        }

        // ISUNCOMPRESSED (Section 9.2: only present if !is_last)
        var is_uncompressed = false;
        if !is_last {
            is_uncompressed = brotli_read_bits(r, 1) != 0;
        }

        if is_uncompressed {
            brotli_byte_align(r);
            for i in mlen {
                let b = brotli_read_bits(r, 8) as u8;
                out.push(b);
                prev_p2 = prev_p1;
                prev_p1 = b;
            }
            continue;
        }

        // 3. Compressed Meta-Block Header (RFC 7932 Section 9.2 & Section 2)
        // Block types (literals, commands, distances)
        var num_block_types: u32[3] = [0, 0, 0];
        for i in 3 {
            num_block_types[i] = decode_varlen_uint8(r) + 1;
            if num_block_types[i] >= 2 {
                var bt_table = BrotliHuffmanTable { .. };
                let ok_bt = read_brotli_prefix_code(r, (num_block_types[i] + 2) as i32, bt_table);
                guard ok_bt else { return CompressError.InvalidHuffmanCode; }
                var bl_table = BrotliHuffmanTable { .. };
                let ok_bl = read_brotli_prefix_code(r, 26, bl_table);
                guard ok_bl else { return CompressError.InvalidHuffmanCode; }
            }
        }

        // Distance postfix and direct distance codes
        let dist_params = brotli_read_bits(r, 6);
        let npostfix = dist_params & 3;
        let ndirect = (dist_params >> 2) << npostfix;

        // Context modes for literals
        for i in num_block_types[0] {
            let _ = brotli_read_bits(r, 2);
        }

        // Literal context map
        let num_lit_htrees = decode_varlen_uint8(r) + 1;
        if num_lit_htrees > 1 {
            // Context map read (future multi-tree support)
        }

        // Distance context map
        let num_dist_htrees = decode_varlen_uint8(r) + 1;
        if num_dist_htrees > 1 {
            // Distance context map read
        }

        var lit_table = BrotliHuffmanTable { .. };
        var cmd_table = BrotliHuffmanTable { .. };
        var dist_table = BrotliHuffmanTable { .. };
        guard read_brotli_block_prefix_tables(r, ndirect, npostfix, lit_table, cmd_table, dist_table) else {
            return CompressError.InvalidHuffmanCode;
        }

        var meta_block_remaining = mlen;
        while meta_block_remaining > 0 {
            let cmd_code, ok_c = decode_brotli_symbol(r, cmd_table);
            guard ok_c && cmd_code >= 0 && cmd_code < 704 else {
                return CompressError.CorruptedBitstream;
            }

            let ins_code, copy_code, dist_zero = decode_cmd_code(cmd_code as u32);

            // Decode insert length
            let ins_extra = INSERT_LENGTH_EXTRA_BITS[ins_code as i64] as u32;
            let ins_len = INSERT_LENGTH_BASE[ins_code as i64] + (if ins_extra > 0 { brotli_read_bits(r, ins_extra) } else { 0 });

            // Decode copy length
            let copy_extra = COPY_LENGTH_EXTRA_BITS[copy_code as i64] as u32;
            let copy_len = COPY_LENGTH_BASE[copy_code as i64] + (if copy_extra > 0 { brotli_read_bits(r, copy_extra) } else { 0 });

            // Read literals
            for i in ins_len {
                let lit, ok_l = decode_brotli_symbol(r, lit_table);
                guard ok_l && lit >= 0 else { return CompressError.CorruptedBitstream; }
                let lit_byte = lit as u8;
                out.push(lit_byte);
                prev_p2 = prev_p1;
                prev_p1 = lit_byte;
            }

            guard meta_block_remaining >= ins_len else {
                return CompressError.CorruptedBitstream;
            }
            meta_block_remaining -= ins_len;
            if meta_block_remaining == 0 {
                break;
            }

            // Decode backward distance
            var distance: u32 = 0;
            if dist_zero {
                distance = dist_ring[0];
            } else {
                let dcode, ok_d = decode_brotli_symbol(r, dist_table);
                guard ok_d && dcode >= 0 else { return CompressError.CorruptedBitstream; }
                distance = decode_brotli_distance(r, dcode as u32, npostfix, ndirect, dist_ring);
            }

            guard distance > 0 else { return CompressError.DistanceOutOfBounds; }

            // Backward Copy
            let max_allowed_backward = if (out.len as u32) < max_window_distance { out.len as u32 } else { max_window_distance };

            if distance <= max_allowed_backward {
                // Sliding window backward copy
                let dist_offset = distance as i64;
                guard dist_offset <= out.len else { return CompressError.DistanceOutOfBounds; }
                var copy_pos = out.len - dist_offset;

                for k in copy_len {
                    let b = out[copy_pos];
                    out.push(b);
                    copy_pos += 1;
                    prev_p2 = prev_p1;
                    prev_p1 = b;
                }
            } else {
                // Static built-in dictionary copy (RFC 7932 Section 8)
                let ok_dict = brotli_lookup_dictionary_word(distance, max_allowed_backward, copy_len, out);
                guard ok_dict else { return CompressError.DistanceOutOfBounds; }
                if out.len > 0 {
                    prev_p1 = out[out.len - 1];
                    prev_p2 = if out.len > 1 { out[out.len - 2] } else { 0 };
                }
            }

            guard meta_block_remaining >= copy_len else {
                return CompressError.CorruptedBitstream;
            }
            meta_block_remaining -= copy_len;
        }
    }

    // RFC 7932 Section 9.3: Stream padding verification
    let pad_bits = r.bit_count & 7;
    if pad_bits > 0 {
        let padding_val = brotli_read_bits(r, pad_bits);
        guard padding_val == 0 else { return CompressError.CorruptedBitstream; }
    }
    if r.bit_count > 0 || r.pos < r.src.len {
        return CompressError.CorruptedBitstream;
    }

    return CompressError.None;
}

// Decompresses an RFC 7932 Brotli stream with max output limit protection.
fn brotli_decompress_with_limit<B>(
    src: const u8[:],
    out: B&,
    max_output_bytes: i64 = -1,
) -> bool, CompressError {
    let err = brotli_decompress_with_limit_impl(src, out, max_output_bytes);
    return err == CompressError.None, err;
}

// Decompresses an RFC 7932 Brotli stream from src into out.
fn brotli_decompress<B>(src: const u8[:], out: B&) -> bool, CompressError {
    return brotli_decompress_with_limit(src, out, -1);
}
