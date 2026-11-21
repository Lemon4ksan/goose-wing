// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// HTTP/1.1 smuggling differential oracle harness for modular `wing_h1` (`h1::parse_request_view`).
// Reads TSV lines `<name>\t<hex_wire>` from argv[1] and prints per-case verdicts.
import std;
import os;
import wing_h1 from "../..";

// Decodes an even-length hexadecimal ASCII string into `out`.
// Clears `out` and returns false on odd length or invalid hex digit.
//
// Example:
//   hex_str = "474554"
//   returns: true, out = "GET"
fn decode_hex_payload(hex_str: const u8[:], out: u8[>..]&) -> bool {
    out.clear();
    guard (hex_str.len & 1) == 0 else { return false; }
    var i: i64 = 0;
    while i < hex_str.len {
        let next_i = core::add_sat_i64(i, 2);
        let b, ok = core::parse_u8_hex(hex_str[i..next_i]);
        guard ok else {
            out.clear();
            return false;
        }
        out.push(b);
        i = next_i;
    }
    return true;
}

// Encodes up to 128 bytes of `data` as lowercase hexadecimal into `out`, or "-" when empty.
fn format_body_preview_hex(data: const u8[:], out: u8[..260]&) {
    out.clear();
    if data.len == 0 {
        let _ = h1::buf_push(out, '-');
        return;
    }
    let take = min(data.len, 128);
    for i in take {
        core::format_u64_hex_fixed(data[i], 2, out, false);
    }
}

fn status_tag(st: h1::ParseStatus) -> const u8[:] {
    return match st {
        Complete => "ACCEPT",
        Incomplete => "INCOMPLETE",
        BadRequest => "REJECT",
        HeadersTooLarge => "REJECT_431",
        PayloadTooLarge => "REJECT_413",
    };
}

fn eval_single_vector(
    name:        const u8[:],
    wire_data:   const u8[:],
    decoded_buf: u8[..16384]&,
    body_hex:    u8[..260]&,
) {
    let req, consumed, st = h1::parse_request_view(wire_data);
    guard st == h1::ParseStatus.Complete else {
        print(name, "\t", status_tag(st), "\t0\t-\t-\t0\t-");
        return;
    }

    if (req.flags & h1::H1_FLAG_HAS_TE) != 0 {
        decoded_buf.clear();
        let _, dec_st = h1::decode_chunked_body(req.body, decoded_buf);
        guard dec_st == h1::ParseStatus.Complete else {
            print(name, "\t", status_tag(dec_st), "\t0\t-\t-\t0\t-");
            return;
        }
        format_body_preview_hex(decoded_buf[..], body_hex);
        print(
            name, "\tACCEPT\t", consumed, "\t", req.method, "\t", req.target,
            "\t", decoded_buf.len, "\t", body_hex[..],
        );
        return;
    }

    format_body_preview_hex(req.body, body_hex);
    print(
        name, "\tACCEPT\t", consumed, "\t", req.method, "\t", req.target,
        "\t", req.body.len, "\t", body_hex[..],
    );
}

fn process_vector_batch(batch_raw: const u8[:]) {
    var wire_buf:    u8[>..]     = [];
    var decoded_buf: u8[..16384] = [];
    var body_hex:    u8[..260]   = [];

    var tok = core::make_byte_tokenizer(batch_raw, '\n');
    while true {
        let raw_line, has_more = core::token_next(tok);
        guard has_more else { break; }
        let line = core::trim_end_byte(raw_line, '\r');
        guard line.len > 0 else { continue; }
        let name, hex_str, ok_cols = core::split_once_byte(line, '\t');
        guard ok_cols && decode_hex_payload(hex_str, wire_buf) else {
            print(name, "\tERROR\t0\t-\t-\t0\t-");
            continue;
        }
        eval_single_vector(name, wire_buf[..], decoded_buf, body_hex);
    }
}

fn main() {
    let a = args();
    guard a.len >= 2 else {
        print("ERR:USAGE\n");
        exit(2);
    }
    var batch_raw: u8[>..] = [];
    guard read_file(a[1], batch_raw) else {
        print("ERR:READ_FILE\n");
        exit(2);
    }
    process_vector_batch(batch_raw[..]);
}
