// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

// Verification of HTTP/2 wire frame bounds and RFC invariants (RFC 9113, RFC 9218).
import std;
import core from "../..";
import wing from "../..";

fn main() {
    print("=== VERIFY_WIRE_BOUNDS ===\n");

    var buf: u8[..256] = [];

    // Case 1: DATA frame MUST reject stream_id = 0 (RFC 9113 Section 6.1)
    let data_zero_sid = wire::encode_data_frame(0, "payload", true, buf);
    assert(!data_zero_sid);
    print("DATA_ZERO_SID_REJECTED: OK\n");
    // CHECK: DATA_ZERO_SID_REJECTED: OK

    // Case 2: RST_STREAM frame MUST reject stream_id = 0 (RFC 9113 Section 6.4)
    buf.clear();
    let rst_zero_sid = wire::encode_rst_stream_frame(0, 1, buf);
    assert(!rst_zero_sid);
    print("RST_ZERO_SID_REJECTED: OK\n");
    // CHECK: RST_ZERO_SID_REJECTED: OK

    // Case 3: WINDOW_UPDATE frame MUST reject increment = 0 (RFC 9113 Section 6.9)
    buf.clear();
    let win_zero_inc = wire::encode_window_update_frame(1, 0, buf);
    assert(!win_zero_inc);
    print("WINDOW_UPDATE_ZERO_INC_REJECTED: OK\n");
    // CHECK: WINDOW_UPDATE_ZERO_INC_REJECTED: OK

    // Case 4: PRIORITY_UPDATE frame MUST reject prioritized_stream_id = 0 (RFC 9218 Section 7.1)
    buf.clear();
    let prio_zero_psid = wire::encode_priority_update_frame(0, 0, false, buf);
    assert(!prio_zero_psid);
    print("PRIORITY_UPDATE_ZERO_PSID_REJECTED: OK\n");
    // CHECK: PRIORITY_UPDATE_ZERO_PSID_REJECTED: OK

    // Case 5: parse_frame_header returns error code 0 (Incomplete), not 1 (PROTOCOL_ERROR), on buf.len < 9
    let short_buf: const u8[:] = "\x00\x00\x04\x00";
    let hdr, err_code, ok = wire::parse_frame_header(short_buf);
    assert(!ok);
    assert(err_code == 0);
    print("SHORT_HEADER_NO_PROTOCOL_ERROR: OK\n");
    // CHECK: SHORT_HEADER_NO_PROTOCOL_ERROR: OK

    // Case 6 (F-WIRE-001): encode_h1_response fails closed and rolls back on small buffer overflow
    var small_h1: u8[..32] = [];
    small_h1.append("PREFIX");
    var h1_hdrs = wing::HeaderMap { .. };
    wing::append_header(h1_hdrs, "X-Long-Header", "0123456789abcdef0123456789abcdef");
    assert(!wire::encode_h1_response(200, "OK", "goose-wing", h1_hdrs, "hello", false, small_h1));
    assert(small_h1[..] == "PREFIX");
    assert(!wire::encode_h1_request(
        "GET", "/path", "example.com", h1_hdrs, "",
        wire::H1HeaderFilterMode.PreserveAll, small_h1,
    ));
    assert(small_h1[..] == "PREFIX");
    print("H1_RESPONSE_TRANSACTIONAL_BOUNDS: OK\n");
    // CHECK: H1_RESPONSE_TRANSACTIONAL_BOUNDS: OK

    // Case 7 (F-WIRE-002): Host header rejects control bytes/spaces & decode_h1_response_head returns MalformedStatusLine
    var host_out: u8[..128] = [];
    let empty_hdrs = wing::HeaderMap { .. };
    assert(!wire::encode_h1_request(
        "GET", "/", "bad host.example.com", empty_hdrs, "",
        wire::H1HeaderFilterMode.PreserveAll, host_out,
    ));
    assert(!wire::encode_h1_request(
        "GET", "/", "bad\thost.example.com", empty_hdrs, "",
        wire::H1HeaderFilterMode.PreserveAll, host_out,
    ));
    var bad_status: u16 = 0;
    var parsed_hdrs = wing::HeaderMap { .. };
    let _, bad_st_err = wire::decode_h1_response_head("HTTP/2.0 200 OK\r\n\r\n", bad_status, parsed_hdrs);
    assert(bad_st_err == wing::HeaderParseError.MalformedStatusLine);
    print("H1_HOST_AND_STATUS_LINE_BOUNDS: OK\n");
    // CHECK: H1_HOST_AND_STATUS_LINE_BOUNDS: OK

    // Case 8 (F-WIRE-003): H2 stream_id MSB (0x80000000), >24-bit length, urgency > 7, transactional rollback, and CONTINUATION
    buf.clear();
    assert(!wire::encode_data_frame(0x80000000, "x", false, buf));
    assert(!wire::encode_rst_stream_frame(0x80000000, 1, buf));
    assert(!wire::encode_priority_update_frame(0x80000000, 0, false, buf));
    assert(!wire::encode_window_update_frame(0x80000000, 1, buf));
    assert(!wire::encode_priority_update_frame(1, 8, false, buf));
    let ovf_hdr = wire::WireFrameHeader {
        length:     0x01000000,
        frame_type: rfc::H2_FRAME_DATA,
        flags:      0,
        stream_id:  1,
    };
    assert(!wire::encode_frame_header(ovf_hdr, buf));
    var tight_h2: u8[..12] = [];
    tight_h2.append("AB"); // 10 bytes left: fits 9-byte header, but not 4-byte payload
    assert(!wire::encode_window_update_frame(0, 1024, tight_h2));
    assert(tight_h2[..] == "AB");
    assert(!wire::encode_rst_stream_frame(1, 1, tight_h2));
    assert(tight_h2[..] == "AB");
    assert(!wire::encode_data_frame(1, "1234", false, tight_h2));
    assert(tight_h2[..] == "AB");
    var cont_dt = internal::new_dynamic_table(4096);
    var cont_pseudo = internal::H2PseudoHeaders { has_status: true, status: 200, .. };
    var cont_hdrs = wing::HeaderMap { .. };
    wing::append_header(cont_hdrs, "x-cont-test", "0123456789abcdef0123456789abcdef");
    var cont_out: u8[..256] = [];
    assert(wire::encode_h2_headers_frame_from_map(cont_dt, 1, cont_pseudo, cont_hdrs, true, cont_out, 16));
    var f_reader = wire::new_wire_h2_frame_reader(cont_out[..]);
    let fh1, _, ok_f1 = wire::next_frame(f_reader);
    let fh2, _, ok_f2 = wire::next_frame(f_reader);
    assert(ok_f1 && fh1.frame_type == rfc::H2_FRAME_HEADERS && (fh1.flags & rfc::H2_FLAG_END_HEADERS) == 0);
    assert(ok_f2 && fh2.frame_type == rfc::H2_FRAME_CONTINUATION);
    print("H2_FRAME_BOUNDS_AND_CONTINUATION: OK\n");
    // CHECK: H2_FRAME_BOUNDS_AND_CONTINUATION: OK

    // Case 9 (F-WIRE-004 & F-WIRE-005): HPACK & QPACK map overflow and invalid status rejection
    var fresh_dt = internal::new_dynamic_table(4096);
    var small_hpack: u8[..16] = [];
    small_hpack.append("XY");
    assert(!wire::hpack_encode_literal_without_indexing(small_hpack, "x-custom-name", "long-value-12345"));
    assert(small_hpack[..] == "XY");
    assert(!wire::encode_hpack_from_map(fresh_dt, cont_pseudo, cont_hdrs, small_hpack, false));
    assert(small_hpack[..] == "XY");
    var bad_h2_pseudo = internal::H2PseudoHeaders { has_status: true, status: 0, .. };
    var tmp_hpack: u8[..64] = [];
    assert(!wire::encode_hpack_from_map(cont_dt, bad_h2_pseudo, empty_hdrs, tmp_hpack, false));
    var qp_tbl = internal::new_qpack_table(4096);
    var bad_h3_pseudo = internal::H3PseudoHeaders { has_status: true, status: 0, .. };
    var qp_enc: u8[..64] = [];
    var qp_frm: u8[..64] = [];
    assert(!wire::encode_h3_headers_from_map(qp_tbl, 0, bad_h3_pseudo, empty_hdrs, qp_enc, qp_frm));
    var ok_h3_pseudo = internal::H3PseudoHeaders { has_status: true, status: 200, .. };
    var tiny_enc: u8[..4] = [];
    tiny_enc.append("E");
    var tiny_frm: u8[..16] = [];
    tiny_frm.append("F");
    assert(!wire::encode_h3_headers_from_map(qp_tbl, 0, ok_h3_pseudo, cont_hdrs, tiny_enc, tiny_frm));
    assert(tiny_enc[..] == "E");
    assert(tiny_frm[..] == "F");
    print("HPACK_QPACK_MAP_BOUNDS: OK\n");
    // CHECK: HPACK_QPACK_MAP_BOUNDS: OK

    // Case 10 (F-WIRE-006 & F-WIRE-007): Pool arena slot 0 protection, double-free guard, and submit state checks
    let inst = wire::WireInstance { .. };
    var phys: wire::WirePhysicalDevice[..4] = [];
    let _ = wire::enumerate_physical_devices(inst, phys);
    let dev_info = wire::WireDeviceCreateInfo { .. };
    var dev, _ = wire::create_wire_device(phys[0], dev_info);
    let pool_info = wire::WireCommandPoolCreateInfo { .. };
    var pool, _ = wire::create_command_pool(dev, pool_info);
    var pcmd1, _ = wire::allocate_command_buffer(pool);
    var pcmd2, _ = wire::allocate_command_buffer(pool);
    let begin_info = wire::WireCommandBufferBeginInfo { .. };
    let _ = wire::begin_command_buffer(pcmd1, begin_info);
    assert(wire::write_h2_preface(pcmd1));
    let _ = wire::end_command_buffer(pcmd1);
    let slice1, ok_c1 = wire::commit_command_buffer_to_arena(pool, pcmd1);
    assert(ok_c1 && slice1 == rfc::H2_CLIENT_PREFACE);
    var standalone = wire::new_command_buffer();
    assert(wire::write_raw(standalone, "CORRUPT_SLOT_ZERO_______"));
    let _, ok_standalone_commit = wire::commit_command_buffer_to_arena(pool, standalone);
    assert(!ok_standalone_commit);
    assert(pool.arena[..24] == rfc::H2_CLIENT_PREFACE);
    wire::free_command_buffer(pool, pcmd2);
    wire::free_command_buffer(pool, pcmd2); // double-free must not decrement allocated_count to 0
    assert(pool.allocated_count == 1 && pool.arena.len >= 24);
    var q = wire::get_device_queue(dev, 0, 0);
    q.driver = wire::WireDriverKind.Mock;
    q.is_connected = true;
    let _, ok_sub_freed = wire::submit(q, pcmd2);
    assert(!ok_sub_freed);
    print("POOL_AND_SUBMIT_STATE_BOUNDS: OK\n");
    // CHECK: POOL_AND_SUBMIT_STATE_BOUNDS: OK

    print("ALL_WIRE_BOUNDS_VERIFIED: OK\n");
    // CHECK: ALL_WIRE_BOUNDS_VERIFIED: OK
}
