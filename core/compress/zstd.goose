// The Goose Zstandard (zstd) decompression engine: RFC 8878 Specification.
// Clean-Room Native Implementation with zero dynamic heap allocations in inner loop.
namespace wing;

import std;
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

const LL_BASE: u32[36] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    16, 18, 20, 22, 24, 28, 32, 40, 48, 64, 128, 256, 512, 1024,
    2048, 4096, 8192, 16384, 32768, 65536
];

const LL_EXTRA_BITS: u8[36] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10,
    11, 12, 13, 14, 15, 16
];

const ML_BASE: u32[53] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
    19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34,
    35, 37, 39, 41, 43, 47, 51, 59, 67, 83, 99, 131, 259, 515,
    1027, 2051, 4099, 8195, 16387, 32771, 65539
];

const ML_EXTRA_BITS: u8[53] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 7, 8, 9,
    10, 11, 12, 13, 14, 15, 16
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

fn zstd_high_bit(v: u32) -> i32 {
    if v == 0 { return -1; }
    var bit: i32 = 31;
    while bit >= 0 {
        if ((v >> (bit as u8)) & 1) != 0 {
            return bit;
        }
        bit--;
    }
    return -1;
}

// ---- reverse bit reader (rfc 8878 section 4.2.2 / 3.1.1.3.2.1.2) -----------

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
    let bit_offset = (start_bit & 7) as u64;

    var chunk: u64 = 0;
    if byte_offset == r.cache_offset {
        chunk = r.cache_chunk;
    } else {
        let rem = r.src.len - byte_offset;
        if rem >= 8 {
            let b0 = r.src[byte_offset] as u64;
            let b1 = r.src[byte_offset + 1] as u64;
            let b2 = r.src[byte_offset + 2] as u64;
            let b3 = r.src[byte_offset + 3] as u64;
            let b4 = r.src[byte_offset + 4] as u64;
            let b5 = r.src[byte_offset + 5] as u64;
            let b6 = r.src[byte_offset + 6] as u64;
            let b7 = r.src[byte_offset + 7] as u64;
            chunk = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24) | (b4 << 32) | (b5 << 40) | (b6 << 48) | (b7 << 56);
            r.cache_offset = byte_offset;
            r.cache_chunk = chunk;
        } else {
            var i: i64 = 0;
            while i < rem {
                chunk |= (r.src[byte_offset + i] as u64) << ((i * 8) as u64);
                i++;
            }
        }
    }
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
    symbol: u8 = 0,
    nb_bits: u8 = 0,
    new_state: u16 = 0,
}

struct FseTable {
    entries: FseEntry[512] = [FseEntry {}; 512],
    table_log: i32 = 0,
    is_defined: bool = false,
}

fn fse_build_dtable(counts: const i16[:], max_symbol: i32, table_log: i32, out_table: FseTable&) -> bool {
    let table_size: i32 = (1 as i32) << table_log;
    if table_size > 512 || table_log < 1 {
        return false;
    }
    out_table.table_log = table_log;
    out_table.is_defined = true;

    var symbol_next: u16[256] = [0; 256];
    var high_threshold: i32 = table_size - 1;

    // 1. Place low-probability (-1) symbols at the top of the table
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

    // 2. Spread normal symbols
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
        return false; // Distribution did not fill table cleanly
    }

    // 3. Build decoding table
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

        var weight_fse_table = FseTable {};
        if !fse_build_dtable(fse_counts[..], fse_max_sym, fse_log, weight_fse_table) {
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

fn huf_decode_stream(r: ZstdBitReader&, table: const HufTable&, lit_buf: u8[>..]&, count: i64) -> bool {
    var decoded: i64 = 0;
    let mask = (1 << table.table_log) - 1;
    let t_log = table.table_log;

    while decoded < count && !r.underflow {
        let bits = (zstd_peek_bits(r, t_log) as i32) & mask;
        let entry = table.entries[bits];
        lit_buf.push(entry.symbol);
        zstd_consume_bits(r, entry.nb_bits);
        decoded++;
    }

    return decoded == count;
}

// ---- literals section decoder (rfc 8878 section 3.1.1.3.1) ----------------

fn decode_literals(src: const u8[:], offset: i64&, block_end: i64, lit_buf: u8[>..]&, huf_table: HufTable&) -> bool {
    if offset >= block_end { return false; }
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
            if offset + 2 > block_end { return false; }
            let b0 = src[offset] as i64;
            let b1 = src[offset + 1] as i64;
            regenerated_size = (b0 >> 4) | (b1 << 4);
        } else {
            lh_size = 3;
            if offset + 3 > block_end { return false; }
            let b0 = src[offset] as i64;
            let b1 = src[offset + 1] as i64;
            let b2 = src[offset + 2] as i64;
            regenerated_size = (b0 >> 4) | (b1 << 4) | (b2 << 12);
        }
        offset += lh_size;

        if lit_type == 0 {
            // Raw Literals
            if offset + regenerated_size > block_end { return false; }
            lit_buf.append(src[offset .. offset + regenerated_size]);
            offset += regenerated_size;
            return true;
        } else {
            // RLE Literals
            if offset >= block_end { return false; }
            let b = src[offset];
            offset++;
            var i: i64 = 0;
            while i < regenerated_size {
                lit_buf.push(b);
                i++;
            }
            return true;
        }
    } else {
        // Compressed (2) or Treeless (3)
        if lit_type == 3 && !huf_table.is_defined {
            return false; // Treeless without prior Huffman table
        }

        var lh_size: i64 = 3;
        var single_stream = false;
        var regenerated_size: i64 = 0;
        var compressed_size: i64 = 0;

        if size_format == 0 {
            single_stream = true;
            lh_size = 3;
            if offset + 3 > block_end { return false; }
            let b0 = src[offset] as u32;
            let b1 = src[offset + 1] as u32;
            let b2 = src[offset + 2] as u32;
            let val = b0 | (b1 << 8) | (b2 << 16);
            regenerated_size = (val >> 4) & 0x3FF;
            compressed_size = (val >> 14) & 0x3FF;
        } else if size_format == 1 {
            single_stream = false;
            lh_size = 3;
            if offset + 3 > block_end { return false; }
            let b0 = src[offset] as u32;
            let b1 = src[offset + 1] as u32;
            let b2 = src[offset + 2] as u32;
            let val = b0 | (b1 << 8) | (b2 << 16);
            regenerated_size = (val >> 4) & 0x3FF;
            compressed_size = (val >> 14) & 0x3FF;
        } else if size_format == 2 {
            single_stream = false;
            lh_size = 4;
            if offset + 4 > block_end { return false; }
            let b0 = src[offset] as u32;
            let b1 = src[offset + 1] as u32;
            let b2 = src[offset + 2] as u32;
            let b3 = src[offset + 3] as u32;
            let val = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
            regenerated_size = (val >> 4) & 0x3FFF;
            compressed_size = (val >> 18) & 0x3FFF;
        } else {
            single_stream = false;
            lh_size = 5;
            if offset + 5 > block_end { return false; }
            let b0 = src[offset] as u32;
            let b1 = src[offset + 1] as u32;
            let b2 = src[offset + 2] as u32;
            let b3 = src[offset + 3] as u32;
            let b4 = src[offset + 4] as u32;
            let val = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
            regenerated_size = (val >> 4) & 0x3FFFF;
            compressed_size = ((val >> 22) & 0x3FF) | (b4 << 10);
        }
        offset += lh_size;

        if offset + compressed_size > block_end { return false; }
        let c_start = offset;
        let c_end = offset + compressed_size;

        if lit_type == 2 {
            // Read Huffman tree description
            if !huf_read_table(src, offset, huf_table) {
                return false;
            }
        }

        if single_stream {
            let stream_slice = src[offset .. c_end];
            var r = new_zstd_bit_reader(stream_slice);
            if !huf_decode_stream(r, huf_table, lit_buf, regenerated_size) {
                return false;
            }
        } else {
            // 4 streams: read 6-byte Jump Table
            if offset + 6 > c_end { return false; }
            let s1 = src[offset] | ((src[offset + 1] as i64) << 8);
            let s2 = src[offset + 2] | ((src[offset + 3] as i64) << 8);
            let s3 = src[offset + 4] | ((src[offset + 5] as i64) << 8);
            offset += 6;

            let total_streams = c_end - offset;
            let s4 = total_streams - s1 - s2 - s3;
            if s4 < 0 { return false; }

            let stream_size_chunk = (regenerated_size + 3) / 4;
            let rem_last = regenerated_size - stream_size_chunk * 3;

            // Stream 1
            var r1 = new_zstd_bit_reader(src[offset .. offset + s1]); offset += s1;
            if !huf_decode_stream(r1, huf_table, lit_buf, stream_size_chunk) { return false; }

            // Stream 2
            var r2 = new_zstd_bit_reader(src[offset .. offset + s2]); offset += s2;
            if !huf_decode_stream(r2, huf_table, lit_buf, stream_size_chunk) { return false; }

            // Stream 3
            var r3 = new_zstd_bit_reader(src[offset .. offset + s3]); offset += s3;
            if !huf_decode_stream(r3, huf_table, lit_buf, stream_size_chunk) { return false; }

            // Stream 4
            var r4 = new_zstd_bit_reader(src[offset .. offset + s4]); offset += s4;
            if !huf_decode_stream(r4, huf_table, lit_buf, rem_last) { return false; }
        }

        offset = c_end;
        return true;
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
        fse_build_dtable(LL_DEFAULT_DIST[..], 35, 6, ll_table);
    } else if ll_mode == 1 {
        // RLE: 1 byte symbol
        if offset >= block_end { return CompressError.InputBufferTruncated; }
        let sym = src[offset]; offset++;
        ll_table.table_log = 0;
        ll_table.is_defined = true;
        ll_table.entries[0] = FseEntry { symbol: sym, nb_bits: 0, new_state: 0 };
    } else if ll_mode == 2 {
        var counts: i16[256] = [0; 256];
        var max_sym: i32 = 0;
        var table_log: i32 = 0;
        if !fse_read_ncount(src, offset, counts[..], max_sym, table_log) {
            return CompressError.CorruptedBitstream;
        }
        if !fse_build_dtable(counts[..], max_sym, table_log, ll_table) {
            return CompressError.CorruptedBitstream;
        }
    } else {
        if !ll_table.is_defined { return CompressError.CorruptedBitstream; }
    }

    // Build or update OF table
    if of_mode == 0 {
        fse_build_dtable(OF_DEFAULT_DIST[..], 28, 5, of_table);
    } else if of_mode == 1 {
        if offset >= block_end { return CompressError.InputBufferTruncated; }
        let sym = src[offset]; offset++;
        of_table.table_log = 0;
        of_table.is_defined = true;
        of_table.entries[0] = FseEntry { symbol: sym, nb_bits: 0, new_state: 0 };
    } else if of_mode == 2 {
        var counts: i16[256] = [0; 256];
        var max_sym: i32 = 0;
        var table_log: i32 = 0;
        if !fse_read_ncount(src, offset, counts[..], max_sym, table_log) {
            return CompressError.CorruptedBitstream;
        }
        if !fse_build_dtable(counts[..], max_sym, table_log, of_table) {
            return CompressError.CorruptedBitstream;
        }
    } else {
        if !of_table.is_defined { return CompressError.CorruptedBitstream; }
    }

    // Build or update ML table
    if ml_mode == 0 {
        fse_build_dtable(ML_DEFAULT_DIST[..], 52, 6, ml_table);
    } else if ml_mode == 1 {
        if offset >= block_end { return CompressError.InputBufferTruncated; }
        let sym = src[offset]; offset++;
        ml_table.table_log = 0;
        ml_table.is_defined = true;
        ml_table.entries[0] = FseEntry { symbol: sym, nb_bits: 0, new_state: 0 };
    } else if ml_mode == 2 {
        var counts: i16[256] = [0; 256];
        var max_sym: i32 = 0;
        var table_log: i32 = 0;
        if !fse_read_ncount(src, offset, counts[..], max_sym, table_log) {
            return CompressError.CorruptedBitstream;
        }
        if !fse_build_dtable(counts[..], max_sym, table_log, ml_table) {
            return CompressError.CorruptedBitstream;
        }
    } else {
        if !ml_table.is_defined { return CompressError.CorruptedBitstream; }
    }

    // Reverse bitstream for sequences
    let seq_bitstream = src[offset .. block_end];
    var r = new_zstd_bit_reader(seq_bitstream);
    if r.underflow { return CompressError.CorruptedBitstream; }

    var state_ll = zstd_read_bits(r, ll_table.table_log) as i64;
    var state_of = zstd_read_bits(r, of_table.table_log) as i64;
    var state_ml = zstd_read_bits(r, ml_table.table_log) as i64;

    var lit_ptr: i64 = 0;

    var seq_i: i64 = 0;
    while seq_i < nb_seq {
        let of_entry = of_table.entries[state_of];
        let ml_entry = ml_table.entries[state_ml];
        let ll_entry = ll_table.entries[state_ll];

        let of_code = of_entry.symbol as u32;
        let ml_code = ml_entry.symbol as u32;
        let ll_code = ll_entry.symbol as u32;

        let of_extra_bits = of_code as i32;
        let ml_extra_bits = ML_EXTRA_BITS[ml_code as i64] as i32;
        let ll_extra_bits = LL_EXTRA_BITS[ll_code as i64] as i32;

        let of_extra = zstd_read_bits(r, of_extra_bits);
        let ml_extra = zstd_read_bits(r, ml_extra_bits);
        let ll_extra = zstd_read_bits(r, ll_extra_bits);

        let lit_len = LL_BASE[ll_code as i64] + ll_extra;
        let match_len = ML_BASE[ml_code as i64] + ml_extra;
        let offset_val = (1 << of_code) + of_extra;

        var offset: u32 = 0;
        if offset_val > 3 {
            offset = offset_val - 3;
            rep[2] = rep[1];
            rep[1] = rep[0];
            rep[0] = offset;
        } else {
            // Repeat offset codes
            if lit_len > 0 {
                if offset_val == 1 {
                    offset = rep[0];
                } else if offset_val == 2 {
                    offset = rep[1];
                    rep[1] = rep[0];
                    rep[0] = offset;
                } else {
                    offset = rep[2];
                    rep[2] = rep[1];
                    rep[1] = rep[0];
                    rep[0] = offset;
                }
            } else {
                // When literals_length == 0, repeated offsets are shifted by 1
                if offset_val == 1 {
                    offset = rep[1];
                    rep[1] = rep[0];
                    rep[0] = offset;
                } else if offset_val == 2 {
                    offset = rep[2];
                    rep[2] = rep[1];
                    rep[1] = rep[0];
                    rep[0] = offset;
                } else {
                    offset = rep[0] - 1;
                    rep[2] = rep[1];
                    rep[1] = rep[0];
                    rep[0] = offset;
                }
            }
        }

        // Execute sequence
        if lit_ptr + (lit_len as i64) > lit_buf.len {
            return CompressError.CorruptedBitstream;
        }
        if max_output_bytes >= 0 && (out_buf.len as i64) + (lit_len as i64) + (match_len as i64) > max_output_bytes {
            return CompressError.OutputBufferOverflow;
        }

        if lit_len > 0 {
            out_buf.append(lit_buf[lit_ptr .. lit_ptr + (lit_len as i64)]);
            lit_ptr += lit_len as i64;
        }

        if match_len > 0 {
            let off = offset as i64;
            let m_len = match_len as i64;
            if off == 0 || off > (out_buf.len as i64) {
                return CompressError.DistanceOutOfBounds;
            }
            let src_idx = (out_buf.len as i64) - off;
            if off >= m_len {
                out_buf.append(out_buf[src_idx .. src_idx + m_len]);
            } else if off == 1 {
                let b = out_buf[src_idx];
                let pattern: u8[16] = [b; 16];
                var m: i64 = 0;
                while m + 16 <= m_len {
                    out_buf.append(pattern[..]);
                    m += 16;
                }
                while m < m_len {
                    out_buf.push(b);
                    m++;
                }
            } else {
                var m: i64 = 0;
                while m + off <= m_len {
                    out_buf.append(out_buf[src_idx + m .. src_idx + m + off]);
                    m += off;
                }
                while m < m_len {
                    out_buf.push(out_buf[src_idx + m]);
                    m++;
                }
            }
        }

        // Update states for next sequence
        if seq_i + 1 < nb_seq {
            let ll_bits = zstd_read_bits(r, ll_entry.nb_bits as i32);
            state_ll = (ll_entry.new_state as i64) + (ll_bits as i64);

            let ml_bits = zstd_read_bits(r, ml_entry.nb_bits as i32);
            state_ml = (ml_entry.new_state as i64) + (ml_bits as i64);

            let of_bits = zstd_read_bits(r, of_entry.nb_bits as i32);
            state_of = (of_entry.new_state as i64) + (of_bits as i64);
        }

        seq_i++;
    }

    // Append remaining literals
    if lit_ptr < lit_buf.len {
        let rem_lit = lit_buf.len - lit_ptr;
        if max_output_bytes >= 0 && (out_buf.len as i64) + rem_lit > max_output_bytes {
            return CompressError.OutputBufferOverflow;
        }
        out_buf.append(lit_buf[lit_ptr..]);
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
        var huf_table = HufTable {};
        var ll_table = FseTable {};
        var ml_table = FseTable {};
        var of_table = FseTable {};

        let frame_start_out = out_buf.len;
        var last_block = false;

        while !last_block {
            if offset + 3 > src.len { return CompressError.InputBufferTruncated; }
            let b0 = src[offset] as u32;
            let b1 = src[offset + 1] as u32;
            let b2 = src[offset + 2] as u32;
            offset += 3;

            let header_val = b0 | (b1 << 8) | (b2 << 16);
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
                var i: i64 = 0;
                while i < block_size {
                    out_buf.push(rle_byte);
                    i++;
                }
            } else if block_type == ZSTD_BLOCK_TYPE_COMPRESSED {
                var lit_buf: u8[>..] = [];
                if !decode_literals(src, offset, block_end, lit_buf, huf_table) {
                    return CompressError.CorruptedBitstream;
                }

                let seq_err = decode_sequences(
                    src,
                    offset,
                    block_end,
                    lit_buf[..],
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

// ---- frame compressor (clean-room rfc 8878 raw block generator) ------------

// Compresses input slice using Zstandard frame container (standard raw blocks with optional XXH64 checksum).
fn zstd_compress<B>(src: const u8[:], out_buf: B&, include_checksum: bool = true) -> bool {
    let len = src.len;

    // 1. Magic Number (0xFD2FB528 in little-endian)
    out_buf.push(0x28);
    out_buf.push(0xB5);
    out_buf.push(0x2F);
    out_buf.push(0xFD);

    // 2. Frame Header Descriptor
    // Single_Segment = 1 (bit 5: 0x20)
    var fhd: u8 = 0x20;
    if include_checksum {
        fhd |= 0x04; // Content_Checksum_Flag = 1 (bit 2)
    }

    if len < 256 {
        // FCS_Field_Size = 1 byte (fcs_flag = 0)
        out_buf.push(fhd);
        out_buf.push(len as u8);
    } else if len <= 65535 + 256 {
        // FCS_Field_Size = 2 bytes (fcs_flag = 1, bit 7-6: 01 -> 0x40)
        out_buf.push(fhd | 0x40);
        let fcs_val = (len - 256) as u16;
        out_buf.push((fcs_val & 0xFF) as u8);
        out_buf.push(((fcs_val >> 8) & 0xFF) as u8);
    } else {
        // FCS_Field_Size = 4 bytes (fcs_flag = 2, bit 7-6: 10 -> 0x80)
        out_buf.push(fhd | 0x80);
        let fcs_val = len as u32;
        out_buf.push((fcs_val & 0xFF) as u8);
        out_buf.push(((fcs_val >> 8) & 0xFF) as u8);
        out_buf.push(((fcs_val >> 16) & 0xFF) as u8);
        out_buf.push(((fcs_val >> 24) & 0xFF) as u8);
    }

    // 3. Blocks: chunk into blocks of at most 128 KB
    if len == 0 {
        // Empty frame: 1 empty raw block (last_block = 1, block_type = 0, size = 0)
        let hdr = 1 as u32; // bit 0 = 1
        out_buf.push((hdr & 0xFF) as u8);
        out_buf.push(((hdr >> 8) & 0xFF) as u8);
        out_buf.push(((hdr >> 16) & 0xFF) as u8);
    } else {
        var offset: i64 = 0;
        while offset < len {
            let rem = len - offset;
            let chunk_size = if rem < ZSTD_BLOCKSIZE_MAX { rem } else { ZSTD_BLOCKSIZE_MAX };
            let is_last = (offset + chunk_size == len);

            let last_bit = if is_last { 1 as u32 } else { 0 as u32 };
            let block_hdr = last_bit | (ZSTD_BLOCK_TYPE_RAW << 1) | ((chunk_size as u32) << 3);

            out_buf.push((block_hdr & 0xFF) as u8);
            out_buf.push(((block_hdr >> 8) & 0xFF) as u8);
            out_buf.push(((block_hdr >> 16) & 0xFF) as u8);

            out_buf.append(src[offset .. offset + chunk_size]);
            offset += chunk_size;
        }
    }

    // 4. Content Checksum (lower 32-bits of XXH64)
    if include_checksum {
        let chk = xxh64_digest_32(src);
        out_buf.push((chk & 0xFF) as u8);
        out_buf.push(((chk >> 8) & 0xFF) as u8);
        out_buf.push(((chk >> 16) & 0xFF) as u8);
        out_buf.push(((chk >> 24) & 0xFF) as u8);
    }

    return true;
}

