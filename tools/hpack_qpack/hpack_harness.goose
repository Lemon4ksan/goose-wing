// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// HPACK RFC 7541 & http2jp/hpack-test-case interop harness for `http2`.
// Reads TSV commands (`STORY` / `CASE`) from argv[1], decodes wire blocks while
// preserving dynamic table state across requests, and verifies encoder roundtrip.
import std;
import wing from "../..";

// Decodes an even-length ASCII hex string into `out`.
// Clears `out` and returns false on odd length or invalid hex digit.
//
// Example:
//   hex_str = "828684"
//   returns: true, out = [0x82, 0x86, 0x84]
fn decode_hex_bytes(hex_str: const u8[:], out: u8[>..]&) -> bool {
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

fn append_hex_slice(src: const u8[:], out: u8[>..]&) {
    var tmp: u8[..4] = [];
    for b in src {
        tmp.clear();
        core::format_u64_hex_fixed(b, 2, tmp, false);
        out.append(tmp[..]);
    }
}

fn append_hex_pair(name: const u8[:], val: const u8[:], out: u8[>..]&) {
    if out.len > 0 {
        out.push(',');
    }
    append_hex_slice(name, out);
    out.push(':');
    append_hex_slice(val, out);
}

fn serialize_decoded_headers(
    pseudo: const http2::PseudoHeaders&,
    hmap:   const http::HeaderMap&,
    out:    u8[>..]&,
) {
    out.clear();
    if pseudo.has_method { append_hex_pair(":method", pseudo.method[..], out); }
    if pseudo.has_scheme { append_hex_pair(":scheme", pseudo.scheme[..], out); }
    if pseudo.has_authority { append_hex_pair(":authority", pseudo.authority[..], out); }
    if pseudo.has_path { append_hex_pair(":path", pseudo.path[..], out); }
    if pseudo.has_protocol { append_hex_pair(":protocol", pseudo.protocol[..], out); }
    if pseudo.has_status {
        var st_buf: u8[..16] = [];
        pseudo.status.format_i64_dec(st_buf);
        append_hex_pair(":status", st_buf[..], out);
    }
    for &e in hmap.entries {
        append_hex_pair(http::entry_name(hmap, e), http::entry_value(hmap, e), out);
    }
}

fn encode_pseudo_headers(
    enc_dt: http2::DynamicTable&,
    pseudo: const http2::PseudoHeaders&,
    out:    u8[..16384]&,
) -> bool {
    let idx = http2::HpackIndexing.Incremental;
    if pseudo.has_method {
        guard http2::encode_hpack_field(enc_dt, out, ":method", pseudo.method[..], idx, true) else {
            return false;
        }
    }
    if pseudo.has_scheme {
        guard http2::encode_hpack_field(enc_dt, out, ":scheme", pseudo.scheme[..], idx, true) else {
            return false;
        }
    }
    if pseudo.has_authority {
        guard http2::encode_hpack_field(enc_dt, out, ":authority", pseudo.authority[..], idx, true) else {
            return false;
        }
    }
    if pseudo.has_path {
        guard http2::encode_hpack_field(enc_dt, out, ":path", pseudo.path[..], idx, true) else {
            return false;
        }
    }
    if pseudo.has_protocol {
        guard http2::encode_hpack_field(enc_dt, out, ":protocol", pseudo.protocol[..], idx, true) else {
            return false;
        }
    }
    if pseudo.has_status {
        var st_buf: u8[..16] = [];
        pseudo.status.format_i64_dec(st_buf);
        guard http2::encode_hpack_field(enc_dt, out, ":status", st_buf[..], idx, true) else {
            return false;
        }
    }
    return true;
}

fn encode_regular_headers(
    enc_dt: http2::DynamicTable&,
    hmap:   const http::HeaderMap&,
    out:    u8[..16384]&,
) -> bool {
    let idx = http2::HpackIndexing.Incremental;
    for &e in hmap.entries {
        let name = http::entry_name(hmap, e);
        let val = http::entry_value(hmap, e);
        guard http2::encode_hpack_field(enc_dt, out, name, val, idx, true) else {
            return false;
        }
    }
    return true;
}

fn sync_table_limit(dt: http2::DynamicTable&, new_limit: u64) {
    guard new_limit != dt.max_allowed_size else { return; }
    dt.max_allowed_size = new_limit;
    if new_limit < dt.current_max_size {
        let _ = http2::update_dynamic_table_max_size(dt, new_limit);
    }
}

fn sync_encoder_table_limit(
    enc_dt: http2::DynamicTable&,
    rt_dt:  http2::DynamicTable&,
    out:    u8[..16384]&,
    limit:  u64,
) -> bool {
    guard limit != enc_dt.max_allowed_size else { return true; }
    enc_dt.max_allowed_size = limit;
    rt_dt.max_allowed_size = limit;
    let _ = http2::update_dynamic_table_max_size(enc_dt, limit);
    return http2::hpack_encode_int(out, limit, 5, 0x20);
}

struct HpackHarnessState {
    dec_dt:    http2::DynamicTable  = http2::DynamicTable { .. },
    enc_dt:    http2::DynamicTable  = http2::DynamicTable { .. },
    rt_dt:     http2::DynamicTable  = http2::DynamicTable { .. },
    pseudo:    http2::PseudoHeaders = http2::PseudoHeaders { .. },
    hmap:      http::HeaderMap      = http::HeaderMap { .. },
    rt_pseudo: http2::PseudoHeaders = http2::PseudoHeaders { .. },
    rt_hmap:   http::HeaderMap      = http::HeaderMap { .. },
    name_buf:  u8[..256]            = [],
    val_buf:   u8[..8192]           = [],
    reenc:     u8[..16384]          = [],
}

fn reset_story_tables(st: HpackHarnessState&, max_size: u64) {
    st.dec_dt = http2::new_dynamic_table(max_size);
    st.enc_dt = http2::new_dynamic_table(max_size);
    st.rt_dt = http2::new_dynamic_table(max_size);
}

fn run_encoder_roundtrip(
    st:      HpackHarnessState&,
    limit:   u64,
    dec_hex: const u8[:],
    rt_hex:  u8[>..]&,
) -> bool {
    st.reenc.clear();
    guard sync_encoder_table_limit(st.enc_dt, st.rt_dt, st.reenc, limit) else { return false; }
    guard encode_pseudo_headers(st.enc_dt, st.pseudo, st.reenc) else { return false; }
    guard encode_regular_headers(st.enc_dt, st.hmap, st.reenc) else { return false; }
    let rt_err = http2::decode_hpack_to_map_with_scratch(
        st.rt_dt,
        st.reenc[..],
        st.rt_pseudo,
        st.rt_hmap,
        st.name_buf,
        st.val_buf,
        65536,
        false,
    );
    guard rt_err == rfc::H2_ERR_NO_ERROR else { return false; }
    serialize_decoded_headers(st.rt_pseudo, st.rt_hmap, rt_hex);
    return rt_hex[..] == dec_hex;
}

fn eval_hpack_case(
    st:        HpackHarnessState&,
    case_id:   const u8[:],
    tbl_limit: u64,
    wire:      const u8[:],
    dec_hex:   u8[>..]&,
    rt_hex:    u8[>..]&,
) {
    let eff_limit = if tbl_limit > 0 { tbl_limit } else { st.dec_dt.max_allowed_size };
    sync_table_limit(st.dec_dt, eff_limit);
    let err = http2::decode_hpack_to_map_with_scratch(
        st.dec_dt,
        wire,
        st.pseudo,
        st.hmap,
        st.name_buf,
        st.val_buf,
        65536,
        false,
    );
    if err != rfc::H2_ERR_NO_ERROR {
        print("RESULT\t", case_id, "\tERR\t", err, "\t0\t", st.dec_dt.count, "\t", st.dec_dt.used_bytes, "\t-\n");
        return;
    }
    serialize_decoded_headers(st.pseudo, st.hmap, dec_hex);
    let rt_ok = run_encoder_roundtrip(st, eff_limit, dec_hex[..], rt_hex);
    let hdr_out = if dec_hex.len > 0 { dec_hex[..] } else { "-" };
    print(
        "RESULT\t", case_id, "\tOK\t0\t", if rt_ok { 1 } else { 0 },
        "\t", st.dec_dt.count, "\t", st.dec_dt.used_bytes, "\t", hdr_out, "\n",
    );
}

fn dispatch_hpack_line(
    st:       HpackHarnessState&,
    line:     const u8[:],
    wire_buf: u8[>..]&,
    dec_hex:  u8[>..]&,
    rt_hex:   u8[>..]&,
) {
    let cmd, rest, ok_cmd = line.split_once_byte('\t');
    guard ok_cmd else { return; }
    if cmd == "STORY" {
        let _, size_str, ok_s = rest.split_once_byte('\t');
        var init_sz: u64 = 4096;
        if ok_s {
            let sz, ok_sz = size_str.parse_u64_dec();
            if ok_sz { init_sz = sz; }
        }
        reset_story_tables(st, init_sz);
        return;
    }
    guard cmd == "CASE" else { return; }
    let case_id, rem1, ok1 = rest.split_once_byte('\t');
    let lim_str, hex_wire, ok2 = rem1.split_once_byte('\t');
    let lim_val, ok_lim = lim_str.parse_u64_dec();
    guard ok1 && ok2 && ok_lim && decode_hex_bytes(hex_wire, wire_buf) else {
        print("RESULT\t", case_id, "\tERR\t999\t0\t0\t0\t-\n");
        return;
    }
    eval_hpack_case(st, case_id, lim_val, wire_buf[..], dec_hex, rt_hex);
}

fn process_hpack_batch(batch_raw: const u8[:]) {
    var st = HpackHarnessState { .. };
    reset_story_tables(st, 4096);
    var wire_buf: u8[>..] = [];
    var dec_hex:  u8[>..] = [];
    var rt_hex:   u8[>..] = [];

    var tok = core::make_byte_tokenizer(batch_raw, '\n');
    while true {
        let raw_line, has_more = core::token_next(tok);
        guard has_more else { break; }
        let line = raw_line.trim_end_byte('\r');
        guard line.len > 0 else { continue; }
        dispatch_hpack_line(st, line, wire_buf, dec_hex, rt_hex);
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
    process_hpack_batch(batch_raw[..]);
}
