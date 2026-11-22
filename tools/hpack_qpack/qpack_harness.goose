// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// QPACK RFC 9204 & quicwg/qpack interop harness for `http3`.
// Reads TSV commands (`STORY`, `ENC`, `DEC`, `SEC`, `UNBLOCK`) from argv[1],
// executes encoder/decoder stream instructions and field sections, and verifies
// QPACK dynamic-table encoder->decoder roundtrip parity.
import std;
import wing from "../..";

// Decodes an even-length ASCII hex string into `out`.
// Clears `out` and returns false on odd length or invalid hex digit.
//
// Example:
//   hex_str = "0000d1"
//   returns: true, out = [0x00, 0x00, 0xD1]
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

fn qpack_err_tag(err: http3::QpackError) -> const u8[:] {
    return match err {
        None => "None",
        StreamBlocked => "StreamBlocked",
        DecompressionFailed => "DecompressionFailed",
        EncoderStreamError => "EncoderStreamError",
        DecoderStreamError => "DecoderStreamError",
        HeaderListTooLarge => "HeaderListTooLarge",
        BlockedStreamsExhausted => "BlockedStreamsExhausted",
        ClosedCriticalStream => "ClosedCriticalStream",
        StreamCreationError => "StreamCreationError",
        FrameEncodingError => "FrameEncodingError",
        MessageError => "MessageError",
    };
}

fn append_hex_slice(src: const u8[:], out: u8[>..]&) {
    var tmp: u8[..4] = [];
    for b in src {
        tmp.clear();
        core::format_u64_hex_fixed(b, 2, tmp, false);
        out.append(tmp[..]);
    }
}

fn serialize_qpack_fields(fields: const http3::HeaderField[>..]&, out: u8[>..]&) {
    out.clear();
    for &f in fields {
        if out.len > 0 {
            out.push(',');
        }
        append_hex_slice(f.name[..], out);
        out.push(':');
        append_hex_slice(f.value[..], out);
    }
}

struct QpackHarnessState {
    dec_tbl:    http3::QpackTable = http3::QpackTable { .. },
    enc_tbl:    http3::QpackTable = http3::QpackTable { .. },
    rt_tbl:     http3::QpackTable = http3::QpackTable { .. },
    enc_stream: u8[..8192]        = [],
    sec_body:   u8[..8192]        = [],
    sec_full:   u8[..8192]        = [],
}

fn apply_encoder_stream_bytes(tbl: http3::QpackTable&, wire: const u8[:]) -> http3::QpackError {
    var off: u64 = 0;
    let total = wire.len as u64;
    while off < total {
        let next_off, err = http3::qpack_process_encoder_instruction(tbl, wire, off);
        guard err == http3::QpackError.None else { return err; }
        guard next_off > off else { return http3::QpackError.EncoderStreamError; }
        off = next_off;
    }
    return http3::QpackError.None;
}

fn apply_decoder_stream_bytes(tbl: http3::QpackTable&, wire: const u8[:]) -> http3::QpackError {
    var off: u64 = 0;
    let total = wire.len as u64;
    while off < total {
        let next_off, err = http3::qpack_process_decoder_instruction(tbl, wire, off);
        guard err == http3::QpackError.None else { return err; }
        guard next_off > off else { return http3::QpackError.DecoderStreamError; }
        off = next_off;
    }
    return http3::QpackError.None;
}

fn reset_qpack_story(st: QpackHarnessState&, max_cap: u64, max_blk: u32, init_cap: u64) {
    st.dec_tbl = http3::new_qpack_table(max_cap, max_blk, init_cap);
    st.enc_tbl = http3::new_qpack_table(max_cap, max_blk, 0);
    st.rt_tbl = http3::new_qpack_table(max_cap, max_blk, 0);
    st.enc_stream.clear();
    if max_cap > 0 {
        let ok_cap = http3::encode_qpack_set_capacity(st.enc_tbl, max_cap, st.enc_stream);
        if ok_cap {
            let _ = apply_encoder_stream_bytes(st.rt_tbl, st.enc_stream[..]);
        }
        st.enc_stream.clear();
    }
}

fn encode_qpack_prefix(
    tbl:          http3::QpackTable&,
    stream_id:    u64,
    base:         u64,
    max_dyn_abs:  u64,
    used_any_dyn: bool,
    out:          u8[..8192]&,
) -> u64, bool {
    guard used_any_dyn else {
        return 0, out.try_push(0x00) && out.try_push(0x00);
    }
    let ric = core::add_sat_u64(max_dyn_abs, 1);
    let _ = http3::qpack_track_unacked_stream(tbl, stream_id, ric);
    let enc_ric = http3::encode_ric(ric, tbl.max_capacity_bytes);
    let sign_bit, delta_base = http3::encode_base(base, ric);
    let sign_mask: u8 = if sign_bit != 0 { 0x80 } else { 0x00 };
    let ok = http2::hpack_encode_int(out, enc_ric, 8, 0x00)
        && http2::hpack_encode_int(out, delta_base, 7, sign_mask);
    return ric, ok;
}

fn run_qpack_roundtrip(
    st:        QpackHarnessState&,
    stream_id: u64,
    fields:    const http3::HeaderField[>..]&,
    dec_hex:   const u8[:],
    rt_fields: http3::HeaderField[>..]&,
    rt_hex:    u8[>..]&,
) -> bool {
    st.enc_stream.clear();
    st.sec_body.clear();
    st.sec_full.clear();

    let base = st.enc_tbl.insert_count;
    var max_dyn_abs: u64 = 0;
    var used_any_dyn = false;
    for &f in fields {
        let ok = http3::encode_qpack_field_dynamic(
            st.enc_tbl,
            stream_id,
            base,
            f.name[..],
            f.value[..],
            st.sec_body,
            st.enc_stream,
            max_dyn_abs,
            used_any_dyn,
            true,
        );
        guard ok else { return false; }
    }
    let ric, ok_pfx = encode_qpack_prefix(
        st.enc_tbl, stream_id, base, max_dyn_abs, used_any_dyn, st.sec_full,
    );
    guard ok_pfx && st.sec_full.try_append(st.sec_body[..]) else { return false; }

    if st.enc_stream.len > 0 {
        let enc_err = apply_encoder_stream_bytes(st.rt_tbl, st.enc_stream[..]);
        guard enc_err == http3::QpackError.None else { return false; }
    }

    rt_fields.clear();
    let dec_err = http3::decode_qpack_section(st.rt_tbl, st.sec_full[..], rt_fields, 65536);
    if used_any_dyn {
        let _ = http3::qpack_ack_section(st.enc_tbl, stream_id, ric);
    }
    guard dec_err == http3::QpackError.None else { return false; }
    serialize_qpack_fields(rt_fields, rt_hex);
    return rt_hex[..] == dec_hex;
}

fn eval_qpack_section(
    st:        QpackHarnessState&,
    step_id:   const u8[:],
    stream_id: u64,
    wire:      const u8[:],
    fields:    http3::HeaderField[>..]&,
    rt_fields: http3::HeaderField[>..]&,
    dec_hex:   u8[>..]&,
    rt_hex:    u8[>..]&,
) {
    fields.clear();
    let err = http3::decode_or_block_qpack_section(st.dec_tbl, stream_id, wire, fields, 65536);
    if err != http3::QpackError.None {
        print("SEC_RES\t", step_id, "\t", qpack_err_tag(err), "\t0\t", st.dec_tbl.insert_count, "\t-\n");
        return;
    }
    serialize_qpack_fields(fields, dec_hex);
    let rt_ok = run_qpack_roundtrip(st, stream_id, fields, dec_hex[..], rt_fields, rt_hex);
    let out_hdr = if dec_hex.len > 0 { dec_hex[..] } else { "-" };
    print(
        "SEC_RES\t", step_id, "\tNone\t", if rt_ok { 1 } else { 0 },
        "\t", st.dec_tbl.insert_count, "\t", out_hdr, "\n",
    );
}

fn eval_qpack_unblock(
    st:        QpackHarnessState&,
    step_id:   const u8[:],
    stream_id: u64,
    fields:    http3::HeaderField[>..]&,
    dec_hex:   u8[>..]&,
) {
    var found_idx: i64 = -1;
    for &b, i in st.dec_tbl.blocked_streams {
        if b.stream_id == stream_id && b.req_insert_count <= st.dec_tbl.insert_count {
            found_idx = i;
            break;
        }
    }
    guard found_idx >= 0 && found_idx < st.dec_tbl.blocked_streams.len else {
        print("SEC_RES\t", step_id, "\tStreamBlocked\t0\t", st.dec_tbl.insert_count, "\t-\n");
        return;
    }
    var saved_wire: u8[..4096] = [];
    let ok_cp = saved_wire.try_set(st.dec_tbl.blocked_streams[found_idx].encoded_data[..]);
    guard ok_cp else {
        print("SEC_RES\t", step_id, "\tDecompressionFailed\t0\t", st.dec_tbl.insert_count, "\t-\n");
        return;
    }
    let _ = http3::qpack_unblock_stream(st.dec_tbl, stream_id);
    fields.clear();
    let err = http3::decode_qpack_section(st.dec_tbl, saved_wire[..], fields, 65536);
    if err != http3::QpackError.None {
        print("SEC_RES\t", step_id, "\t", qpack_err_tag(err), "\t0\t", st.dec_tbl.insert_count, "\t-\n");
        return;
    }
    serialize_qpack_fields(fields, dec_hex);
    let out_hdr = if dec_hex.len > 0 { dec_hex[..] } else { "-" };
    print("SEC_RES\t", step_id, "\tNone\t1\t", st.dec_tbl.insert_count, "\t", out_hdr, "\n");
}

fn handle_story_cmd(st: QpackHarnessState&, rest: const u8[:]) {
    let _, r1, ok1 = rest.split_once_byte('\t');
    let cap_s, r2, ok2 = r1.split_once_byte('\t');
    let blk_s, init_s, ok3 = r2.split_once_byte('\t');
    guard ok1 && ok2 && ok3 else { return; }
    let max_cap, ok_c = cap_s.parse_u64_dec();
    let max_blk, ok_b = blk_s.parse_u64_dec();
    let init_cap, ok_i = init_s.parse_u64_dec();
    guard ok_c && ok_b && ok_i else { return; }
    reset_qpack_story(st, max_cap, min(max_blk, 0xFFFFFFFF) as u32, init_cap);
}

fn handle_stream_cmd(
    st:       QpackHarnessState&,
    is_enc:   bool,
    rest:     const u8[:],
    wire_buf: u8[>..]&,
) {
    let step_id, hex_wire, ok = rest.split_once_byte('\t');
    guard ok && decode_hex_bytes(hex_wire, wire_buf) else {
        print(if is_enc { "ENC_RES\t" } else { "DEC_RES\t" }, step_id, "\tFrameEncodingError\t0\n");
        return;
    }
    if is_enc {
        let err = apply_encoder_stream_bytes(st.dec_tbl, wire_buf[..]);
        print(
            "ENC_RES\t", step_id, "\t", qpack_err_tag(err), "\t",
            st.dec_tbl.insert_count, "\t", st.dec_tbl.used_bytes, "\t",
            st.dec_tbl.capacity_bytes, "\n",
        );
        return;
    }
    let err = apply_decoder_stream_bytes(st.dec_tbl, wire_buf[..]);
    print("DEC_RES\t", step_id, "\t", qpack_err_tag(err), "\t", st.dec_tbl.known_rcvd_count, "\n");
}

fn dispatch_qpack_line(
    st:        QpackHarnessState&,
    line:      const u8[:],
    wire_buf:  u8[>..]&,
    fields:    http3::HeaderField[>..]&,
    rt_fields: http3::HeaderField[>..]&,
    dec_hex:   u8[>..]&,
    rt_hex:    u8[>..]&,
) {
    let cmd, rest, ok_cmd = line.split_once_byte('\t');
    guard ok_cmd else { return; }
    if cmd == "STORY" { handle_story_cmd(st, rest); return; }
    if cmd == "ENC" { handle_stream_cmd(st, true, rest, wire_buf); return; }
    if cmd == "DEC" { handle_stream_cmd(st, false, rest, wire_buf); return; }
    if cmd == "UNBLOCK" {
        let step_id, sid_s, ok_u = rest.split_once_byte('\t');
        let sid, ok_id = sid_s.parse_u64_dec();
        guard ok_u && ok_id else { return; }
        eval_qpack_unblock(st, step_id, sid, fields, dec_hex);
        return;
    }
    guard cmd == "SEC" else { return; }
    let step_id, r1, ok1 = rest.split_once_byte('\t');
    let sid_s, hex_wire, ok2 = r1.split_once_byte('\t');
    let sid, ok_id = sid_s.parse_u64_dec();
    guard ok1 && ok2 && ok_id && decode_hex_bytes(hex_wire, wire_buf) else {
        print("SEC_RES\t", step_id, "\tFrameEncodingError\t0\t0\t-\n");
        return;
    }
    eval_qpack_section(st, step_id, sid, wire_buf[..], fields, rt_fields, dec_hex, rt_hex);
}

fn process_qpack_batch(batch_raw: const u8[:]) {
    var st = QpackHarnessState { .. };
    reset_qpack_story(st, 4096, 16, 0);
    var wire_buf:  u8[>..]                 = [];
    var fields:    http3::HeaderField[>..] = [];
    var rt_fields: http3::HeaderField[>..] = [];
    var dec_hex:   u8[>..]                 = [];
    var rt_hex:    u8[>..]                 = [];

    var tok = core::make_byte_tokenizer(batch_raw, '\n');
    while true {
        let raw_line, has_more = core::token_next(tok);
        guard has_more else { break; }
        let line = raw_line.trim_end_byte('\r');
        guard line.len > 0 else { continue; }
        dispatch_qpack_line(st, line, wire_buf, fields, rt_fields, dec_hex, rt_hex);
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
    process_qpack_batch(batch_raw[..]);
}
