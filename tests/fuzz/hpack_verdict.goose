// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Differential HPACK codec runner (RFC 7541) against tests/fuzz/hpackoracle.
// Usage:
//   hpack_verdict decode <batch_file>
//   hpack_verdict encode <batch_file> [huffman:0|1]

import core from "../..";
import wing from "../..";
import std;

// Decodes a hex string or "-" (empty sentinel) into `dst`.
// Rolls back `dst` on invalid hex or capacity overflow.
//
// Example:
//   hex_s = "6162" -> dst = "ab", returns true
//   hex_s = "-" -> dst = "", returns true
fn decode_hex_or_dash(hex_s: const u8[:], dst: u8[>..]&) -> bool {
    dst.clear();
    if hex_s == "-" || hex_s.len == 0 {
        return true;
    }
    guard (hex_s.len % 2) == 0 else { return false; }
    var i: i64 = 0;
    while i + 1 < hex_s.len {
        let hi = core::hex_digit_to_val(hex_s[i]);
        let lo = core::hex_digit_to_val(hex_s[i + 1]);
        guard hi >= 0 && lo >= 0 else {
            dst.clear();
            return false;
        }
        dst.push(((hi << 4) | lo) as! u8);
        i += 2;
    }
    return true;
}

fn append_hex_or_dash(out: u8[>..]&, s: const u8[:]) {
    if s.len == 0 {
        out.append("-");
        return;
    }
    for b in s {
        core::format_u8_hex(b, out, false);
    }
}

fn append_field_line(out: u8[>..]&, name: const u8[:], val: const u8[:], sensitive: bool) {
    out.append("field ");
    append_hex_or_dash(out, name);
    out.push(' ');
    append_hex_or_dash(out, val);
    if sensitive {
        out.append(" 1\n");
    } else {
        out.append(" 0\n");
    }
}

fn decode_hpack_step(
    dt:              internal::DynamicTable&,
    blk:             const u8[:],
    offset:          u64&,
    updates_allowed: bool&,
    update_count:    u32&,
    fields_out:      u8[>..]&,
) -> bool {
    let b = blk[offset];
    if (b & 0x80) != 0 {
        updates_allowed = false;
        let idx, next_off, ok_i = internal::hpack_decode_int(blk, offset, 7);
        guard ok_i && idx != 0 else { return false; }
        let n_s, v_s, ok_g = internal::get_indexed_header_slices(dt, idx);
        guard ok_g else { return false; }
        append_field_line(fields_out, n_s, v_s, false);
        offset = next_off;
        return true;
    }
    if (b & 0xC0) == 0x40 {
        updates_allowed = false;
        var n_buf: u8[..256]  = [];
        var v_buf: u8[..8192] = [];
        let next_off, err = internal::decode_literal_field_slices(dt, blk, offset, 6, n_buf, v_buf);
        guard err == 0 else { return false; }
        internal::insert_header(dt, n_buf[..], v_buf[..], false);
        append_field_line(fields_out, n_buf[..], v_buf[..], false);
        offset = next_off;
        return true;
    }
    if (b & 0xE0) == 0x20 {
        guard updates_allowed else { return false; }
        update_count += 1;
        guard update_count <= 16 else { return false; }
        let new_sz, next_off, ok_s = internal::hpack_decode_int(blk, offset, 5);
        guard ok_s && internal::update_dynamic_table_max_size(dt, new_sz) else { return false; }
        offset = next_off;
        return true;
    }
    updates_allowed = false;
    let is_never = (b & 0x10) != 0;
    var n_buf: u8[..256]  = [];
    var v_buf: u8[..8192] = [];
    let next_off, err = internal::decode_literal_field_slices(dt, blk, offset, 4, n_buf, v_buf);
    guard err == 0 else { return false; }
    append_field_line(fields_out, n_buf[..], v_buf[..], is_never);
    offset = next_off;
    return true;
}

// Decodes a serialized HPACK block under RFC 7541 rules using `dt`.
// Leaves `fields_out` cleared if decoding fails.
//
// Example:
//   blk = [0x82] -> fields_out = "field 3a6d6574686f64 474554 0\n", returns true
fn decode_hpack_block_fields(
    dt:         internal::DynamicTable&,
    blk:        const u8[:],
    fields_out: u8[>..]&,
) -> bool {
    fields_out.clear();
    var offset:          u64  = 0;
    var updates_allowed: bool = true;
    var update_count:    u32  = 0;
    while offset < (blk.len as u64) {
        guard decode_hpack_step(dt, blk, offset, updates_allowed, update_count, fields_out) else {
            fields_out.clear();
            return false;
        }
    }
    return true;
}

fn handle_decode_line(
    line:       const u8[:],
    dt:         internal::DynamicTable&,
    block_buf:  u8[>..]&,
    fields_out: u8[>..]&,
) {
    let cmd, arg, ok = line.split_once_byte(' ');
    guard ok else { return; }
    if cmd == "conn" {
        let lim, ok_u = arg.parse_u64_dec();
        if ok_u {
            dt = internal::new_dynamic_table(lim);
        }
        return;
    }
    if cmd == "block" {
        guard decode_hex_or_dash(arg, block_buf) else {
            print("error");
            return;
        }
        if decode_hpack_block_fields(dt, block_buf[..], fields_out) {
            print("ok");
            if fields_out.len > 0 {
                // Trim trailing newline since `print` adds one
                print(fields_out[..^1]);
            }
        } else {
            print("error");
        }
    }
}

fn handle_encode_field(
    rest:      const u8[:],
    dt:        internal::DynamicTable&,
    block_out: u8[>..]&,
    n_buf:     u8[>..]&,
    v_buf:     u8[>..]&,
    use_huff:  bool,
) {
    let n_hex, after_n, ok1 = rest.split_once_byte(' ');
    guard ok1 else { return; }
    let v_hex, s_flag, ok2 = after_n.split_once_byte(' ');
    guard ok2 else { return; }
    guard decode_hex_or_dash(n_hex, n_buf) && decode_hex_or_dash(v_hex, v_buf) else { return; }
    let idx_mode = if s_flag == "1" {
        internal::HpackIndexing.NeverIndexed
    } else {
        internal::HpackIndexing.Incremental
    };
    let _ = internal::encode_hpack_field(dt, block_out, n_buf[..], v_buf[..], idx_mode, use_huff);
}

fn run_decode_batch(raw_batch: const u8[:]) {
    var dt = internal::new_dynamic_table(4096);
    var block_buf:  u8[>..] = [];
    var fields_out: u8[>..] = [];
    var pos:        i64     = 0;
    let total = raw_batch.len;
    while pos < total {
        var end = pos;
        while end < total && raw_batch[end] != '\n' {
            end += 1;
        }
        let line = raw_batch[pos..end].trim_end_byte('\r');
        pos = core::add_sat_i64(end, 1);
        if line.len > 0 {
            handle_decode_line(line, dt, block_buf, fields_out);
        }
    }
}

fn handle_encode_line(
    line:      const u8[:],
    dt:        internal::DynamicTable&,
    block_out: u8[>..]&,
    line_out:  u8[>..]&,
    n_buf:     u8[>..]&,
    v_buf:     u8[>..]&,
    use_huff:  bool,
) {
    if line == "endblock" {
        line_out.clear();
        line_out.append("block ");
        append_hex_or_dash(line_out, block_out[..]);
        print(line_out[..]);
        block_out.clear();
        return;
    }
    let cmd, arg, ok = line.split_once_byte(' ');
    guard ok else { return; }
    if cmd == "conn" {
        let lim, ok_u = arg.parse_u64_dec();
        if ok_u {
            dt = internal::new_dynamic_table(lim);
            block_out.clear();
        }
        return;
    }
    if cmd == "limit" {
        let lim, ok_u = arg.parse_u64_dec();
        if ok_u && internal::update_dynamic_table_max_size(dt, lim) {
            let _ = internal::hpack_encode_int(block_out, lim, 5, 0x20);
        }
        return;
    }
    if cmd == "field" {
        handle_encode_field(arg, dt, block_out, n_buf, v_buf, use_huff);
    }
}

fn run_encode_batch(raw_batch: const u8[:], use_huff: bool) {
    var dt = internal::new_dynamic_table(4096);
    var block_out: u8[>..] = [];
    var line_out:  u8[>..] = [];
    var n_buf:     u8[>..] = [];
    var v_buf:     u8[>..] = [];
    var pos:       i64     = 0;
    let total = raw_batch.len;
    while pos < total {
        var end = pos;
        while end < total && raw_batch[end] != '\n' {
            end += 1;
        }
        let line = raw_batch[pos..end].trim_end_byte('\r');
        pos = core::add_sat_i64(end, 1);
        if line.len > 0 {
            handle_encode_line(line, dt, block_out, line_out, n_buf, v_buf, use_huff);
        }
    }
}

fn main() {
    let a = args();
    if a.len < 3 {
        print("ERR:ARGS");
        exit(1);
    }
    var raw_batch: u8[>..] = [];
    guard read_file(a[2], raw_batch) else {
        print("ERR:READ_FILE");
        exit(1);
    }
    if a[1] == "decode" {
        run_decode_batch(raw_batch[..]);
        return;
    }
    if a[1] == "encode" {
        let use_huff = if a.len >= 4 { a[3] == "1" } else { true };
        run_encode_batch(raw_batch[..], use_huff);
        return;
    }
    print("ERR:MODE");
    exit(1);
}
