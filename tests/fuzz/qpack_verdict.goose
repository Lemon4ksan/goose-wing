// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Differential QPACK codec runner (RFC 9204) against reference oracles.
// Usage:
//   qpack_verdict decode <batch_file>
//   qpack_verdict encode <batch_file> [huffman:0|1]

import core from "../..";
import wing from "../..";
import std;

struct FieldItem {
    name: u8[..256]  = [],
    val:  u8[..4096] = [],
}

// Decodes an even-length hex string or "-" (empty sentinel) into `dst`.
// Leaves `dst` empty and returns false if length is odd or a byte is non-hex.
//
// Example:
//   hex_s = "6162", dst = []
//   returns: true, dst = "ab"
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

fn append_field_line(out: u8[>..]&, name: const u8[:], val: const u8[:]) {
    out.append("field ");
    append_hex_or_dash(out, name);
    out.push(' ');
    append_hex_or_dash(out, val);
    out.push('\n');
}

// Applies zero or more encoder stream instructions sequentially.
//
// Example:
//   data = [0x3f, 0x01], offset = 0
//   returns: true (capacity updated)
fn apply_encoder_instructions(
    tbl:  http3::QpackTable&,
    data: const u8[:],
) -> bool {
    var off: u64 = 0;
    let total = data.len as u64;
    while off < total {
        let next_off, err = http3::qpack_process_encoder_instruction(tbl, data, off);
        guard err == http3::QpackError.None && next_off > off else {
            return false;
        }
        off = next_off;
    }
    return true;
}

fn handle_decode_line(
    line:       const u8[:],
    tbl:        http3::QpackTable&,
    cur_stream: u64&,
    raw_buf:    u8[>..]&,
    fields_out: u8[>..]&,
    decoded:    http3::HeaderField[>..]&,
) {
    let cmd, arg, ok = line.split_once_byte(' ');
    guard ok else { return; }
    if cmd == "conn" {
        let cap_s, blk_s, ok_sp = arg.split_once_byte(' ');
        let cap, ok_c = (if ok_sp { cap_s } else { arg }).parse_u64_dec();
        var blk: u64 = 16;
        var ok_b = true;
        if ok_sp {
            blk, ok_b = blk_s.parse_u64_dec();
        }
        if ok_c && ok_b {
            tbl = http3::new_qpack_table(cap, blk as u32, cap);
        }
        return;
    }
    if cmd == "stream" {
        let s_id, ok_s = arg.parse_u64_dec();
        if ok_s {
            cur_stream = s_id;
        }
        return;
    }
    if cmd == "encoder_inst" {
        guard decode_hex_or_dash(arg, raw_buf) else {
            print("error");
            return;
        }
        if raw_buf.len > 0 {
            guard apply_encoder_instructions(tbl, raw_buf[..]) else {
                print("error");
                return;
            }
        }
        return;
    }
    if cmd == "block" {
        guard decode_hex_or_dash(arg, raw_buf) else {
            print("error");
            return;
        }
        decoded.clear();
        let err = http3::decode_qpack_section(tbl, raw_buf[..], decoded, 16384);
        if err == http3::QpackError.None {
            print("ok");
            fields_out.clear();
            for f in decoded {
                append_field_line(fields_out, f.name[..], f.value[..]);
            }
            if fields_out.len > 0 {
                print(fields_out[..^1]);
            }
        } else {
            print("error");
        }
    }
}

fn run_decode_batch(raw_batch: const u8[:]) {
    var tbl = http3::new_qpack_table(4096, 16, 4096);
    var cur_stream: u64                     = 0;
    var raw_buf:    u8[>..]                 = [];
    var fields_out: u8[>..]                 = [];
    var decoded:    http3::HeaderField[>..] = [];
    var pos:        i64                     = 0;
    let total = raw_batch.len;
    while pos < total {
        var end = pos;
        while end < total && raw_batch[end] != '\n' {
            end += 1;
        }
        let line = raw_batch[pos..end].trim_end_byte('\r');
        pos = core::add_sat_i64(end, 1);
        if line.len > 0 {
            handle_decode_line(line, tbl, cur_stream, raw_buf, fields_out, decoded);
        }
    }
}

fn emit_encoded_block(
    tbl:        http3::QpackTable&,
    cur_stream: u64,
    items:      FieldItem[>..]&,
    use_huff:   bool,
    sec_out:    u8[>..]&,
    enc_out:    u8[>..]&,
    full_blk:   u8[>..]&,
    line_buf:   u8[>..]&,
) {
    sec_out.clear();
    enc_out.clear();
    full_blk.clear();
    var max_dyn_abs: u64 = 0;
    var used_any_dyn = false;
    let base = tbl.insert_count;

    for &item in items {
        http3::encode_qpack_field_dynamic(
            tbl, cur_stream, base, item.name[..], item.val[..],
            sec_out, enc_out, max_dyn_abs, used_any_dyn, use_huff,
        );
    }

    if used_any_dyn {
        let ric = max_dyn_abs + 1;
        let _ = http3::qpack_track_unacked_stream(tbl, cur_stream, ric);
        let _ = http3::qpack_ack_section(tbl, cur_stream, ric);
        let enc_ric = http3::encode_ric(ric, tbl.max_capacity_bytes);
        let _ = http2::hpack_encode_int(full_blk, enc_ric, 8, 0x00);
        let sign_bit, delta_base = http3::encode_base(base, ric);
        let sign_mask: u8 = if sign_bit != 0 { 0x80 } else { 0x00 };
        let _ = http2::hpack_encode_int(full_blk, delta_base, 7, sign_mask);
    } else {
        full_blk.push(0x00);
        full_blk.push(0x00);
    }
    full_blk.append(sec_out[..]);

    if enc_out.len > 0 {
        line_buf.clear();
        line_buf.append("encoder_inst ");
        append_hex_or_dash(line_buf, enc_out[..]);
        print(line_buf[..]);
    }

    line_buf.clear();
    line_buf.append("block ");
    append_hex_or_dash(line_buf, full_blk[..]);
    print(line_buf[..]);

    items.clear();
}

fn handle_encode_line(
    line:       const u8[:],
    tbl:        http3::QpackTable&,
    cur_stream: u64&,
    items:      FieldItem[>..]&,
    use_huff:   bool,
    sec_out:    u8[>..]&,
    enc_out:    u8[>..]&,
    full_blk:   u8[>..]&,
    line_buf:   u8[>..]&,
    n_buf:      u8[>..]&,
    v_buf:      u8[>..]&,
) {
    if line == "endblock" {
        emit_encoded_block(tbl, cur_stream, items, use_huff, sec_out, enc_out, full_blk, line_buf);
        return;
    }
    let cmd, arg, ok = line.split_once_byte(' ');
    guard ok else { return; }
    if cmd == "conn" {
        let cap_s, blk_s, ok_sp = arg.split_once_byte(' ');
        let cap, ok_c = (if ok_sp { cap_s } else { arg }).parse_u64_dec();
        var blk: u64 = 16;
        var ok_b = true;
        if ok_sp {
            blk, ok_b = blk_s.parse_u64_dec();
        }
        if ok_c && ok_b {
            tbl = http3::new_qpack_table(cap, blk as u32, cap);
            items.clear();
            print(line);
        }
        return;
    }
    if cmd == "stream" {
        let s_id, ok_s = arg.parse_u64_dec();
        if ok_s {
            cur_stream = s_id;
            print(line);
        }
        return;
    }
    if cmd == "field" {
        let n_hex, v_hex, ok_f = arg.split_once_byte(' ');
        guard ok_f else { return; }
        guard decode_hex_or_dash(n_hex, n_buf) && decode_hex_or_dash(v_hex, v_buf) else { return; }
        var item = FieldItem { .. };
        guard item.name.try_set(n_buf[..]) && item.val.try_set(v_buf[..]) else { return; }
        items.push(item);
    }
}

fn run_encode_batch(raw_batch: const u8[:], use_huff: bool) {
    var tbl = http3::new_qpack_table(4096, 16, 4096);
    var cur_stream: u64            = 0;
    var items:      FieldItem[>..] = [];
    var sec_out:    u8[>..]        = [];
    var enc_out:    u8[>..]        = [];
    var full_blk:   u8[>..]        = [];
    var line_buf:   u8[>..]        = [];
    var n_buf:      u8[>..]        = [];
    var v_buf:      u8[>..]        = [];
    var pos:        i64            = 0;
    let total = raw_batch.len;
    while pos < total {
        var end = pos;
        while end < total && raw_batch[end] != '\n' {
            end += 1;
        }
        let line = raw_batch[pos..end].trim_end_byte('\r');
        pos = core::add_sat_i64(end, 1);
        if line.len > 0 {
            handle_encode_line(
                line, tbl, cur_stream, items, use_huff,
                sec_out, enc_out, full_blk, line_buf, n_buf, v_buf,
            );
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
