// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Differential verdict runner for core/url (parse_url and parse_url_with_base).
// Reads a batch file of hex-encoded P/R operations and prints parsed components.

import core from "../..";
import std;

// Decodes a lowercase/uppercase hex string or "-" (empty sentinel) into `dst`.
// Rolls back `dst` on invalid hex input.
//
// Example:
//   hex_s = "68747470" -> dst = "http", returns true
//   hex_s = "-" -> dst unchanged, returns true
fn decode_url_hex_into(hex_s: const u8[:], dst: u8[..4096]&) -> bool {
    dst.clear();
    if hex_s == "-" || hex_s.len == 0 {
        return true;
    }
    guard (hex_s.len % 2) == 0 else {
        return false;
    }
    var i: i64 = 0;
    while i + 1 < hex_s.len {
        let hi = core::hex_digit_to_val(hex_s[i]);
        let lo = core::hex_digit_to_val(hex_s[i + 1]);
        guard hi >= 0 && lo >= 0 else {
            dst.clear();
            return false;
        }
        let byte_val = ((hi << 4) | lo) as! u8;
        guard dst.try_push(byte_val) else {
            dst.clear();
            return false;
        }
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

fn emit_url_verdict(out: u8[>..]&, u: const core::Url&) {
    out.append("OK\t");
    append_hex_or_dash(out, core::scheme(u));
    out.push('\t');
    append_hex_or_dash(out, core::username(u));
    out.push('\t');
    append_hex_or_dash(out, core::password(u));
    out.push('\t');
    append_hex_or_dash(out, core::hostname(u));
    out.push('\t');
    append_hex_or_dash(out, core::port_str(u));
    out.push('\t');
    append_hex_or_dash(out, core::pathname(u));
    out.push('\t');
    append_hex_or_dash(out, core::search(u));
    out.push('\t');
    append_hex_or_dash(out, core::hash(u));
    out.push('\t');
    append_hex_or_dash(out, core::href(u));
}

fn process_url_line(
    raw_line: const u8[:],
    buf_a:    u8[..4096]&,
    buf_b:    u8[..4096]&,
    out:      u8[>..]&,
) {
    out.clear();
    let line = raw_line.trim_end_byte('\r');
    if line.len == 0 {
        return;
    }
    let op, rest, ok_op = line.split_once_byte('\t');
    guard ok_op else {
        out.append("ERR");
        return;
    }
    if op == "P" {
        guard decode_url_hex_into(rest, buf_a) else {
            out.append("ERR");
            return;
        }
        let u, err = core::parse_url(buf_a[..]);
        guard core::is_ok(err) && u.valid else {
            out.append("ERR");
            return;
        }
        emit_url_verdict(out, u);
        return;
    }
    if op == "R" {
        let base_hex, ref_hex, ok_args = rest.split_once_byte('\t');
        guard ok_args else {
            out.append("ERR");
            return;
        }
        guard decode_url_hex_into(base_hex, buf_a) &&
              decode_url_hex_into(ref_hex, buf_b) else {
            out.append("ERR");
            return;
        }
        let bu, berr = core::parse_url(buf_a[..]);
        guard core::is_ok(berr) && bu.valid else {
            out.append("ERR");
            return;
        }
        let u, err = core::parse_url_with_base(buf_b[..], bu);
        guard core::is_ok(err) && u.valid else {
            out.append("ERR");
            return;
        }
        emit_url_verdict(out, u);
        return;
    }
    out.append("ERR");
}

fn main() {
    let a = args();
    if a.len < 2 {
        print("ERR:NO_ARG");
        exit(1);
    }
    var raw_batch: u8[>..] = [];
    guard read_file(a[1], raw_batch) else {
        print("ERR:READ_FILE");
        exit(1);
    }
    var buf_a: u8[..4096] = [];
    var buf_b: u8[..4096] = [];
    var out:   u8[>..]    = [];
    var pos:   i64        = 0;
    let total = raw_batch.len;
    while pos < total {
        var end = pos;
        while end < total && raw_batch[end] != '\n' {
            end += 1;
        }
        let line = raw_batch[pos..end];
        pos = core::add_sat_i64(end, 1);
        process_url_line(line, buf_a, buf_b, out);
        if out.len > 0 {
            print(out[..]);
        }
    }
}
