// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_quic_frames_rfc9000.goose
// Pathological verification suite for RFC 9000 §19 QUIC transport frames:
// STREAM frame flag matrix (OFF, LEN, FIN), zero-length stream edges,
// 62-bit VarInt boundary attacks, reassembly chaos, and differential mutation fuzzing.
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";
import wire_kit from ".";

// ---- RFC 9000 §19.8 STREAM Frame Representation ----------------------------

struct QuicStreamFrame {
    stream_id:        u64         = 0,
    offset:           u64         = 0,
    length:           u64         = 0,
    is_fin:           bool        = false,
    has_explicit_len: bool        = false,
    data:             const u8[:] = "",
}

// Parses header fields of an RFC 9000 §19.8 STREAM frame (0x08..0x0F).
// Returns (stream_id, stream_off, data_len, is_fin, has_len, payload_off, ok).
// crap:trusted-bounds
fn parse_quic_stream_header(
    src:    const u8[:],
    offset: u64,
    limit:  u64,
) -> u64, u64, u64, bool, bool, u64, bool {
    var cur = offset;
    guard cur < limit else { return 0, 0, 0, false, false, offset, false; }

    let ftype, next_cur, ok_type = internal::quic_decode_varint(src, cur);
    guard ok_type && ftype >= 0x08 && ftype <= 0x0F else {
        return 0, 0, 0, false, false, offset, false;
    }
    cur = next_cur;

    let has_off = (ftype & 0x04) != 0;
    let has_len = (ftype & 0x02) != 0;
    let is_fin = (ftype & 0x01) != 0;

    let stream_id, cur_sid, ok_sid = internal::quic_decode_varint(src, cur);
    guard ok_sid else { return 0, 0, 0, false, false, offset, false; }
    cur = cur_sid;

    var stream_off: u64 = 0;
    if has_off {
        let off_val, cur_off, ok_off = internal::quic_decode_varint(src, cur);
        guard ok_off else { return 0, 0, 0, false, false, offset, false; }
        stream_off = off_val;
        cur = cur_off;
    }

    var data_len: u64 = 0;
    if has_len {
        let len_val, cur_len, ok_len = internal::quic_decode_varint(src, cur);
        guard ok_len else { return 0, 0, 0, false, false, offset, false; }
        data_len = len_val;
        cur = cur_len;
    } else {
        guard cur <= limit else { return 0, 0, 0, false, false, offset, false; }
        data_len = core::sub_sat_u64(limit, cur);
    }

    return stream_id, stream_off, data_len, is_fin, has_len, cur, true;
}

// Parses an RFC 9000 §19.8 STREAM frame (0x08..0x0F) from packet wire slice.
// Returns (frame, next_offset, ok).
// crap:trusted-bounds
fn parse_quic_stream_frame(src: const u8[:], offset: u64, packet_end: u64 = 0) -> QuicStreamFrame, u64, bool {
    let limit = if packet_end > 0 && packet_end <= (src.len as u64) { packet_end } else { src.len as u64 };
    let sid, soff, dlen, is_fin, has_len, payload_off, ok = parse_quic_stream_header(src, offset, limit);
    guard ok else { return QuicStreamFrame {}, offset, false; }

    // RFC 9000 §4.5: Offset + Length cannot exceed 2^62 - 1
    guard core::sub_sat_u64(0x3FFFFFFFFFFFFFFF, soff) >= dlen else {
        return QuicStreamFrame {}, offset, false;
    }

    // Truncation check: data_len must not exceed remaining bytes in packet
    guard core::sub_sat_u64(limit, payload_off) >= dlen else {
        return QuicStreamFrame {}, offset, false;
    }

    let st_idx = payload_off as i64;
    let end_off = core::add_sat_u64(payload_off, dlen);
    let en_idx = end_off as i64;
    guard st_idx >= 0 && en_idx >= st_idx && en_idx <= src.len else {
        return QuicStreamFrame {}, offset, false;
    }

    let data_slice = src[st_idx..en_idx];

    return QuicStreamFrame {
        stream_id:        sid,
        offset:           soff,
        length:           dlen,
        is_fin:           is_fin,
        has_explicit_len: has_len,
        data:             data_slice,
    }, end_off, true;
}

// Encodes an RFC 9000 §19.8 STREAM frame with explicit flag bits into buffer.
// flags: lower 3 bits represent OFF (0x04), LEN (0x02), FIN (0x01).
// crap:trusted-bounds
fn encode_quic_stream_frame<B>(
    out:       B&,
    flags:     u8,
    stream_id: u64,
    offset:    u64,
    payload:   const u8[:],
) -> bool {
    let ftype: u64 = 0x08 | ((flags & 0x07) as u64);
    guard internal::quic_encode_varint(out, ftype) else { return false; }
    guard internal::quic_encode_varint(out, stream_id) else { return false; }
    if (flags & 0x04) != 0 {
        guard internal::quic_encode_varint(out, offset) else { return false; }
    }
    if (flags & 0x02) != 0 {
        guard internal::quic_encode_varint(out, payload.len as u64) else { return false; }
    }
    out.append(payload);
    return true;
}

// Adapter for wire_kit split_stream and fuzz_payload verification
// crap:trusted-bounds
fn parse_stream_wire_step(buf: const u8[:]) -> i64 {
    let frame, next_off, ok = parse_quic_stream_frame(buf, 0);
    if !ok || (next_off as i64) != buf.len {
        return 0;
    }
    return frame.length as i64;
}

// ---- Section 1: VarInt Codec Bounds & Pathological Attacks -----------------

// crap:trusted-bounds
fn test_quic_varint_pathological() {
    // 1. Minimum and Maximum RFC 9000 VarInt values across all 4 encodings
    // 1-byte: 0, 63
    var buf1: u8[>..] = [];
    assert(internal::quic_encode_varint(buf1, 0));
    assert(internal::quic_encode_varint(buf1, 63));
    assert(buf1.len == 2);
    let v0, o1, ok0 = internal::quic_decode_varint(buf1[..], 0);
    let v63, o2, ok63 = internal::quic_decode_varint(buf1[..], o1);
    assert(ok0 && v0 == 0 && ok63 && v63 == 63 && o2 == 2);

    // 2-byte: 64, 16383
    var buf2: u8[>..] = [];
    assert(internal::quic_encode_varint(buf2, 64));
    assert(internal::quic_encode_varint(buf2, 16383));
    assert(buf2.len == 4);
    let v64, o3, ok64 = internal::quic_decode_varint(buf2[..], 0);
    let v16k, o4, ok16k = internal::quic_decode_varint(buf2[..], o3);
    assert(ok64 && v64 == 64 && ok16k && v16k == 16383 && o4 == 4);

    // 4-byte: 16384, 1073741823
    var buf4: u8[>..] = [];
    assert(internal::quic_encode_varint(buf4, 16384));
    assert(internal::quic_encode_varint(buf4, 1073741823));
    assert(buf4.len == 8);
    let v164, o5, ok164 = internal::quic_decode_varint(buf4[..], 0);
    let v1g, o6, ok1g = internal::quic_decode_varint(buf4[..], o5);
    assert(ok164 && v164 == 16384 && ok1g && v1g == 1073741823 && o6 == 8);

    // 8-byte: 1073741824, 0x3FFFFFFFFFFFFFFF (2^62 - 1)
    var buf8: u8[>..] = [];
    assert(internal::quic_encode_varint(buf8, 1073741824));
    assert(internal::quic_encode_varint(buf8, 0x3FFFFFFFFFFFFFFF));
    assert(buf8.len == 16);
    let v1g1, o7, ok1g1 = internal::quic_decode_varint(buf8[..], 0);
    let vmax, o8, okmax = internal::quic_decode_varint(buf8[..], o7);
    assert(ok1g1 && v1g1 == 1073741824 && okmax && vmax == 0x3FFFFFFFFFFFFFFF && o8 == 16);

    // 2. Reject integer exceeding 62-bit RFC 9000 limit
    var buf_ovf: u8[>..] = [];
    let ok_ovf = internal::quic_encode_varint(buf_ovf, 0x4000000000000000);
    assert(!ok_ovf);

    // 3. Truncated VarInt byte streams (Buffer underrun defense)
    let trunc_2byte: const u8[1] = [0x40];
    let _, _, ok_tr2 = internal::quic_decode_varint(trunc_2byte[..], 0);
    assert(!ok_tr2);

    let trunc_4byte: const u8[2] = [0x80, 0x01];
    let _, _, ok_tr4 = internal::quic_decode_varint(trunc_4byte[..], 0);
    assert(!ok_tr4);

    let trunc_8byte: const u8[5] = [0xC0, 0x01, 0x02, 0x03, 0x04];
    let _, _, ok_tr8 = internal::quic_decode_varint(trunc_8byte[..], 0);
    assert(!ok_tr8);

    print("VARINT_BOUNDS: OK max_62bit=4611686018427387903 trunc_rejected=true");
}

// ---- Section 2: RFC 9000 §19.8 STREAM Frame Flag Matrix (0x08..0x0F) --------

// crap:trusted-bounds
fn verify_single_stream_flag(flags: u8, payload: const u8[:]) {
    var wire: u8[>..] = [];
    let stream_id: u64 = (flags as u64) << 2;
    let offset:    u64 = if (flags & 0x04) != 0 { 1024 } else { 0 };
    assert(encode_quic_stream_frame(wire, flags, stream_id, offset, payload));

    let frame, next_off, dec_ok = parse_quic_stream_frame(wire[..], 0);
    assert(dec_ok);
    assert((next_off as i64) == wire.len);
    assert(frame.stream_id == stream_id);
    assert(frame.offset == offset);
    assert(frame.is_fin == ((flags & 0x01) != 0));
    assert(frame.has_explicit_len == ((flags & 0x02) != 0));
    assert(frame.data == payload);
}

// crap:trusted-bounds
fn test_quic_stream_flag_matrix() {
    let payload = "STREAM_PAYLOAD_DATA";
    for flags in 8 {
        verify_single_stream_flag(flags as u8, payload);
    }
    print("STREAM_FLAG_MATRIX: passed=8/8");
}

// ---- Section 3: Zero-Length Stream Frames & Stream ID Classification -------

// crap:trusted-bounds
fn test_quic_stream_zero_length() {
    // 1. Zero-length payload WITHOUT FIN (flags = 0x0A: LEN only)
    var wire_empty: u8[>..] = [];
    assert(encode_quic_stream_frame(wire_empty, 0x02, 10, 0, ""));
    let f_empty, _, ok_empty = parse_quic_stream_frame(wire_empty[..], 0);
    assert(ok_empty);
    assert(f_empty.length == 0);
    assert(!f_empty.is_fin);
    assert(f_empty.data.len == 0);

    // 2. Zero-length payload WITH FIN (flags = 0x0B: LEN | FIN)
    var wire_fin: u8[>..] = [];
    assert(encode_quic_stream_frame(wire_fin, 0x03, 10, 0, ""));
    let f_fin, _, ok_fin = parse_quic_stream_frame(wire_fin[..], 0);
    assert(ok_fin);
    assert(f_fin.length == 0);
    assert(f_fin.is_fin);
    assert(f_fin.data.len == 0);

    // 3. Zero-length payload with non-zero offset AND FIN (flags = 0x07: OFF | LEN | FIN)
    var wire_off_fin: u8[>..] = [];
    assert(encode_quic_stream_frame(wire_off_fin, 0x07, 10, 4096, ""));
    let f_off_fin, _, ok_off_fin = parse_quic_stream_frame(wire_off_fin[..], 0);
    assert(ok_off_fin);
    assert(f_off_fin.offset == 4096);
    assert(f_off_fin.length == 0);
    assert(f_off_fin.is_fin);

    // 4. Stream ID Classification (RFC 9000 §2.1)
    let s0_bidi_c = internal::quic_is_client_stream(0) && internal::quic_is_bidi_stream(0);
    let s1_bidi_s = internal::quic_is_server_stream(1) && internal::quic_is_bidi_stream(1);
    let s2_uni_c = internal::quic_is_client_stream(2) && internal::quic_is_uni_stream(2);
    let s3_uni_s = internal::quic_is_server_stream(3) && internal::quic_is_uni_stream(3);
    assert(s0_bidi_c && s1_bidi_s && s2_uni_c && s3_uni_s);

    print("STREAM_ZERO_LENGTH: empty_ok=", ok_empty, " fin_ok=", ok_fin, " off_fin_ok=", ok_off_fin, " stream_ids_ok=true");
}

// ---- Section 4: Truncation Attacks & Boundary Violations -------------------

// crap:trusted-bounds
fn test_quic_stream_truncation_attacks() {
    // 1. Truncation attack: Length field claims 100 bytes, but wire only holds 10 bytes
    var wire_trunc: u8[>..] = [];
    assert(internal::quic_encode_varint(wire_trunc, 0x0A));
    assert(internal::quic_encode_varint(wire_trunc, 4));
    assert(internal::quic_encode_varint(wire_trunc, 100));
    wire_trunc.append("0123456789");
    let _, _, ok_trunc = parse_quic_stream_frame(wire_trunc[..], 0);
    assert(!ok_trunc);

    // 2. Stream offset + length overflow (> 2^62 - 1)
    var wire_ovf: u8[>..] = [];
    assert(internal::quic_encode_varint(wire_ovf, 0x0E));
    assert(internal::quic_encode_varint(wire_ovf, 4));
    assert(internal::quic_encode_varint(wire_ovf, 0x3FFFFFFFFFFFFFF0));
    assert(internal::quic_encode_varint(wire_ovf, 32));
    wire_ovf.resize((wire_ovf.len + 32) as i64, 0);
    let _, _, ok_ovf = parse_quic_stream_frame(wire_ovf[..], 0);
    assert(!ok_ovf);

    // 3. Truncated VarInt Stream ID
    var wire_bad_sid: u8[>..] = [];
    wire_bad_sid.push(0x0A);
    wire_bad_sid.push(0x80);
    let _, _, ok_bad_sid = parse_quic_stream_frame(wire_bad_sid[..], 0);
    assert(!ok_bad_sid);

    print("STREAM_TRUNCATION: payload_trunc_rejected=", !ok_trunc, " offset_ovf_rejected=", !ok_ovf, " sid_trunc_rejected=", !ok_bad_sid);
}

// ---- Section 5: Reassembly Chaos & Final Size Invariants --------------------

// crap:trusted-bounds
fn test_quic_stream_reassembly_chaos() {
    var r_buf = internal::new_reassembly_buffer(1048576);

    // 1. In-order arrival: [0, 5) -> "HELLO"
    let ok1 = internal::insert_fragment(r_buf, 0, "HELLO", false);
    assert(ok1);

    // 2. Out-of-order gap: [10, 15) -> "QUIC!" with FIN
    let ok2 = internal::insert_fragment(r_buf, 10, "QUIC!", true);
    assert(ok2);
    assert(r_buf.fin_received);
    assert(r_buf.final_size == 15);

    // 3. Contiguous read from head: should only yield first 5 bytes due to gap at [5, 10)
    var out1: u8[>..] = [];
    let r1 = internal::read_contiguous(r_buf, out1);
    assert(r1 == 5);
    assert(out1 == "HELLO");
    assert(r_buf.consumed_offset == 5);

    // 4. Final Size Violation attack 1: Inject data exceeding established final size 15
    let ok_bad_data = internal::insert_fragment(r_buf, 12, "OVERFLOW_AFTER_FIN", false);
    assert(!ok_bad_data);

    // 5. Final Size Violation attack 2: Re-declare differing FIN at offset 20 != 15
    let ok_diff_fin = internal::insert_fragment(r_buf, 10, "DIFFERENT_FINAL_SZ", true);
    assert(!ok_diff_fin);

    // 6. Fill the missing gap: [5, 10) -> " RFC "
    let ok3 = internal::insert_fragment(r_buf, 5, " RFC ", false);
    assert(ok3);

    // 7. Contiguous read tail: reads remaining 10 bytes up to final size 15
    var out2: u8[>..] = [];
    let r2 = internal::read_contiguous(r_buf, out2);
    assert(r2 == 10);
    assert(out2 == " RFC QUIC!");
    assert(r_buf.consumed_offset == 15);

    // 8. Reassembly interval overlap and duplicates
    var r_buf2 = internal::new_reassembly_buffer(1048576);
    assert(internal::insert_fragment(r_buf2, 0, "ABCDEF", false));
    assert(internal::insert_fragment(r_buf2, 3, "DEFGHI", false));
    assert(internal::insert_fragment(r_buf2, 0, "ABC", false));
    var out_ovl: u8[>..] = [];
    let r_ovl = internal::read_contiguous(r_buf2, out_ovl);
    assert(r_ovl == 9);
    assert(out_ovl == "ABCDEFGHI");

    print("STREAM_REASSEMBLY: gap_handled=true final_size_enforced=true overlap_merged=true");
}

// ---- Section 6: RFC 9000 §19 Control Frames Demuxing -----------------------

// crap:trusted-bounds
fn demux_stream_mgmt_frame(ftype: u64, src: const u8[:], cur: u64) -> u64, bool {
    if ftype == internal::QUIC_FRAME_RESET_STREAM {
        let _, cur1, ok1 = internal::quic_decode_varint(src, cur);
        guard ok1 else { return cur, false; }
        let _, cur2, ok2 = internal::quic_decode_varint(src, cur1);
        guard ok2 else { return cur, false; }
        let _, cur3, ok3 = internal::quic_decode_varint(src, cur2);
        guard ok3 else { return cur, false; }
        return cur3, true;
    }

    if ftype == internal::QUIC_FRAME_STOP_SENDING {
        let _, cur1, ok1 = internal::quic_decode_varint(src, cur);
        guard ok1 else { return cur, false; }
        let _, cur2, ok2 = internal::quic_decode_varint(src, cur1);
        guard ok2 else { return cur, false; }
        return cur2, true;
    }

    return cur, false;
}

// crap:trusted-bounds
fn demux_flow_frame(ftype: u64, src: const u8[:], cur: u64) -> u64, bool {
    if ftype == internal::QUIC_FRAME_MAX_DATA {
        let _, cur1, ok1 = internal::quic_decode_varint(src, cur);
        guard ok1 else { return cur, false; }
        return cur1, true;
    }

    if ftype == internal::QUIC_FRAME_MAX_STREAM_DATA {
        let _, cur1, ok1 = internal::quic_decode_varint(src, cur);
        guard ok1 else { return cur, false; }
        let _, cur2, ok2 = internal::quic_decode_varint(src, cur1);
        guard ok2 else { return cur, false; }
        return cur2, true;
    }

    return cur, false;
}

// Demuxes non-STREAM RFC 9000 §19 control frames from packet payload
// crap:trusted-bounds
fn demux_control_frame(src: const u8[:], offset: u64) -> u64, u64, bool {
    var cur = offset;
    guard cur < (src.len as u64) else { return 0, offset, false; }

    let ftype, next_cur, ok_type = internal::quic_decode_varint(src, cur);
    guard ok_type else { return 0, offset, false; }
    cur = next_cur;

    if ftype == internal::QUIC_FRAME_PADDING {
        return ftype, cur, true;
    }

    if ftype == internal::QUIC_FRAME_PING {
        return ftype, cur, true;
    }

    let end_mgmt, ok_mgmt = demux_stream_mgmt_frame(ftype, src, cur);
    if ok_mgmt { return ftype, end_mgmt, true; }

    let end_flow, ok_flow = demux_flow_frame(ftype, src, cur);
    if ok_flow { return ftype, end_flow, true; }

    return ftype, cur, false;
}

// crap:trusted-bounds
fn test_quic_control_frames_demux() {
    var packet: u8[>..] = [];

    // 1. PADDING run (8 zeroes)
    for _ in 8 { packet.push(0x00); }

    // 2. PING (0x01)
    packet.push(0x01);

    // 3. RESET_STREAM (0x04, stream_id=12, err=0x42, final_size=1024)
    assert(internal::quic_encode_varint(packet, internal::QUIC_FRAME_RESET_STREAM));
    assert(internal::quic_encode_varint(packet, 12));
    assert(internal::quic_encode_varint(packet, 0x42));
    assert(internal::quic_encode_varint(packet, 1024));

    // 4. STOP_SENDING (0x05, stream_id=12, err=0x19)
    assert(internal::quic_encode_varint(packet, internal::QUIC_FRAME_STOP_SENDING));
    assert(internal::quic_encode_varint(packet, 12));
    assert(internal::quic_encode_varint(packet, 0x19));

    // 5. MAX_DATA (0x10, max_data=65536)
    assert(internal::quic_encode_varint(packet, internal::QUIC_FRAME_MAX_DATA));
    assert(internal::quic_encode_varint(packet, 65536));

    // 6. MAX_STREAM_DATA (0x11, stream_id=12, max_data=32768)
    assert(internal::quic_encode_varint(packet, internal::QUIC_FRAME_MAX_STREAM_DATA));
    assert(internal::quic_encode_varint(packet, 12));
    assert(internal::quic_encode_varint(packet, 32768));

    // Demux the multi-frame packet
    var cur_off: u64 = 0;
    while cur_off < (packet.len as u64) {
        let _, next_off, ok = demux_control_frame(packet[..], cur_off);
        assert(ok);
        assert(next_off > cur_off);
        cur_off = next_off;
    }

    assert(cur_off == (packet.len as u64));

    print("CONTROL_FRAMES_DEMUX: frames_parsed=6 all_consumed=true");
}

// ---- Section 7: Differential Mutation Fuzzing with wire_kit -----------------

// crap:trusted-bounds
fn test_quic_stream_mutation_fuzzing() {
    var valid_frame: u8[>..] = [];
    assert(encode_quic_stream_frame(valid_frame, 0x07, 100, 2048, "MUTATION_SEED_PAYLOAD_32_BYTES!!"));

    // 1. Split-stream prefix validation: ensure partial reads never panic
    let split_ok = wire_kit::verify_split_stream(valid_frame[..], 0, 32, parse_stream_wire_step);
    assert(split_ok);

    // 2. Fuzzing with 200 random single-bit flips, boundary injections, and swaps
    let fuzz_ok = wire_kit::fuzz_payload(valid_frame[..], 200, parse_stream_wire_step);
    assert(fuzz_ok);

    print("STREAM_MUTATION_FUZZ: split_ok=true fuzz_200_iters=true");
}

// ---- Main Entry Point ------------------------------------------------------

// crap:trusted-bounds
fn main() {
    print("=== LIT RFC 9000 QUIC Frames Pathological Verification ===");
    test_quic_varint_pathological();
    test_quic_stream_flag_matrix();
    test_quic_stream_zero_length();
    test_quic_stream_truncation_attacks();
    test_quic_stream_reassembly_chaos();
    test_quic_control_frames_demux();
    test_quic_stream_mutation_fuzzing();
}

// CHECK: === LIT RFC 9000 QUIC Frames Pathological Verification ===
// CHECK-NEXT: VARINT_BOUNDS: OK max_62bit=4611686018427387903 trunc_rejected=true
// CHECK-NEXT: STREAM_FLAG_MATRIX: passed=8/8
// CHECK-NEXT: STREAM_ZERO_LENGTH: empty_ok=true fin_ok=true off_fin_ok=true stream_ids_ok=true
// CHECK-NEXT: STREAM_TRUNCATION: payload_trunc_rejected=true offset_ovf_rejected=true sid_trunc_rejected=true
// CHECK-NEXT: STREAM_REASSEMBLY: gap_handled=true final_size_enforced=true overlap_merged=true
// CHECK-NEXT: CONTROL_FRAMES_DEMUX: frames_parsed=6 all_consumed=true
// CHECK-NEXT: STREAM_MUTATION_FUZZ: split_ok=true fuzz_200_iters=true
