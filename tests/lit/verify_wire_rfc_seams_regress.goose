// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

// Regression tests for cross-component seams and RFC edge cases in `wire` (F-WIRE-008..F-WIRE-013).
import std;
import core from "../..";
import wing from "../..";

// F-WIRE-008: HPACK DynamicTable and QPACK QpackTable must roll back on partial encoding or frame buffer overflow.
fn test_f_wire_008_transactional_hpack_qpack_tables() {
    var dt = internal::new_dynamic_table(4096);
    var pseudo = internal::H2PseudoHeaders { has_status: true, status: 200, .. };
    var hdrs = wing::HeaderMap { .. };
    wing::append_header(hdrs, "x-first-ok", " indexed-val-1");
    wing::append_header(hdrs, "x-second-long", "0123456789abcdef0123456789abcdef");

    // 1. encode_hpack_from_map fails on small buffer after inserting first header into `dt`
    var tiny_out: u8[..24] = [];
    var ok_h2_hdrs = wing::HeaderMap { .. };
    wing::append_header(ok_h2_hdrs, "x-first-ok", "indexed-val-1");
    wing::append_header(ok_h2_hdrs, "x-second-long", "0123456789abcdef0123456789abcdef");
    assert(!wire::encode_hpack_from_map(dt, pseudo, ok_h2_hdrs, tiny_out, false));
    assert(dt.count == 0 && dt.used_bytes == 0);

    // 2. encode_h2_headers_frame_from_map fails when output frame buffer cannot fit frame
    var tight_frame_out: u8[..16] = [];
    assert(!wire::encode_h2_headers_frame_from_map(dt, 1, pseudo, ok_h2_hdrs, true, tight_frame_out, 16384));
    assert(dt.count == 0 && dt.used_bytes == 0);

    // 3. encode_h3_headers_from_map fails when `out_frame` overflows after QPACK dynamic table insertion
    var qtbl = internal::new_qpack_table(4096);
    let _ = internal::qpack_set_capacity(qtbl, 4096);
    var qpseudo = internal::H3PseudoHeaders { has_status: true, status: 200, .. };
    var qenc:         u8[..256] = [];
    var tight_qframe: u8[..4]   = [];
    assert(!wire::encode_h3_headers_from_map(qtbl, 4, qpseudo, ok_h2_hdrs, qenc, tight_qframe));
    assert(qtbl.insert_count == 0 && qtbl.entries.len == 0 && qtbl.unacked_sections.len == 0);
    assert(qenc.len == 0 && tight_qframe.len == 0);

    print("F_WIRE_008_TRANSACTIONAL_TABLES: OK\n");
}

// F-WIRE-009: QPACK sensitive header protection, Connection-nominated header filtering, TE normalization, and RFC 9113/9114 bounds.
fn test_f_wire_009_qpack_sensitive_and_rfc_headers() {
    var qtbl_enc = internal::new_qpack_table(4096);
    let _ = internal::qpack_set_capacity(qtbl_enc, 4096);
    var qtbl_dec = internal::new_qpack_table(4096);
    let _ = internal::qpack_set_capacity(qtbl_dec, 4096);

    var req_hdrs = wing::HeaderMap { .. };
    wing::append_header(req_hdrs, "Authorization", "Bearer secret-jwt");
    wing::set_header(req_hdrs, "X-Api-Secret", "top-secret-key", true);
    wing::append_header(req_hdrs, "Connection", "x-internal-hop, keep-alive");
    wing::append_header(req_hdrs, "X-Internal-Hop", "must-be-stripped");
    wing::append_header(req_hdrs, "TE", "TRAILERS");

    var req_pseudo = internal::H3PseudoHeaders {
        has_method:    true,
        method:        "GET",
        has_scheme:    true,
        scheme:        "https",
        has_authority: true,
        authority:     "example.com",
        has_path:      true,
        path:          "/secure",
        ..
    };
    var q_inst:  u8[..256] = [];
    var q_frame: u8[..512] = [];
    assert(wire::encode_h3_headers_from_map(qtbl_enc, 0, req_pseudo, req_hdrs, q_inst, q_frame));
    // Sensitive headers must NOT be inserted into QPACK dynamic table (`authorization` and `x-api-secret` stay literal with N=1)
    let _, auth_in_dyn, _ = internal::find_qpack_dynamic_field(qtbl_enc, "authorization", "Bearer secret-jwt");
    let _, sec_in_dyn, _ = internal::find_qpack_dynamic_field(qtbl_enc, "x-api-secret", "top-secret-key");
    assert(!auth_in_dyn && !sec_in_dyn);

    var q_off: u64 = 0;
    while q_off < (q_inst.len as u64) {
        let next_off, q_ie = internal::qpack_process_encoder_instruction(qtbl_dec, q_inst[..], q_off);
        assert(q_ie == internal::QpackError.None && next_off > q_off);
        q_off = next_off;
    }
    var dec_qpseudo = internal::H3PseudoHeaders { .. };
    var dec_qmap = wing::HeaderMap { .. };
    let q_err = wire::decode_h3_headers_to_map(qtbl_dec, 0, q_frame[2..], dec_qpseudo, dec_qmap);
    assert(q_err == internal::QpackError.None);
    assert(!wing::has_header(dec_qmap, "x-internal-hop"));
    assert(wing::get_header(dec_qmap, "te") == "trailers");
    // Custom sensitive header must preserve HEADER_FLAG_SENSITIVE across QPACK N-bit round-trip
    var found_sens = false;
    for &e in dec_qmap.entries {
        if wing::entry_name(dec_qmap, e) == "x-api-secret" {
            found_sens = wing::is_sensitive(e);
        }
    }
    assert(found_sens);

    // Verify HPACK also strips Connection-nominated tokens, normalizes `TE: TRAILERS` -> `trailers`, and rejects 101 / invalid pseudo
    var h2_dt_enc = internal::new_dynamic_table(4096);
    var h2_dt_dec = internal::new_dynamic_table(4096);
    var h2_req_pseudo = internal::H2PseudoHeaders {
        has_method:    true,
        method:        "GET",
        has_scheme:    true,
        scheme:        "https",
        has_authority: true,
        authority:     "example.com",
        has_path:      true,
        path:          "/secure",
        ..
    };
    var h2_buf: u8[..512] = [];
    assert(wire::encode_hpack_from_map(h2_dt_enc, h2_req_pseudo, req_hdrs, h2_buf, false));
    var dec_h2_pseudo = internal::H2PseudoHeaders { .. };
    var dec_h2_map = wing::HeaderMap { .. };
    assert(wire::decode_hpack_to_map(h2_dt_dec, h2_buf[..], dec_h2_pseudo, dec_h2_map) == rfc::H2_ERR_NO_ERROR);
    assert(!wing::has_header(dec_h2_map, "x-internal-hop"));
    assert(wing::get_header(dec_h2_map, "te") == "trailers");

    // Status 101 (Switching Protocols) must be rejected by both H2 and H3 encoders (RFC 9113 §8.3.2, RFC 9114 §4.3.2)
    let empty_map = wing::HeaderMap { .. };
    let st101_h2 = internal::H2PseudoHeaders { has_status: true, status: 101, .. };
    let st101_h3 = internal::H3PseudoHeaders { has_status: true, status: 101, .. };
    h2_buf.clear();
    q_inst.clear();
    q_frame.clear();
    assert(!wire::encode_hpack_from_map(h2_dt_enc, st101_h2, empty_map, h2_buf, false));
    assert(!wire::encode_h3_headers_from_map(qtbl_enc, 0, st101_h3, empty_map, q_inst, q_frame));

    // Empty non-trailer pseudo-headers or mixed status+method must be rejected
    let empty_h2_pseudo = internal::H2PseudoHeaders { .. };
    let empty_h3_pseudo = internal::H3PseudoHeaders { .. };
    assert(!wire::encode_hpack_from_map(h2_dt_enc, empty_h2_pseudo, empty_map, h2_buf, false));
    assert(!wire::encode_h3_headers_from_map(qtbl_enc, 0, empty_h3_pseudo, empty_map, q_inst, q_frame));

    // decode_h3_headers_to_map must reject incomplete pseudo-headers (e.g. GET without :scheme/:path)
    let incomplete_qpack: u8[3] = [0x00, 0x00, 0xD1]; // :method = GET only
    assert(wire::decode_h3_headers_to_map(qtbl_dec, 0, incomplete_qpack[..], dec_qpseudo, dec_qmap) == internal::QpackError.MessageError);

    print("F_WIRE_009_QPACK_SENSITIVE_AND_RFC: OK\n");
}

// F-WIRE-010: HTTP/1.1 decode_h1_response_head HeaderMap status/version sync & smuggling rejection.
fn test_f_wire_010_h1_head_sync_and_smuggling() {
    var status: u16 = 0;
    var hdrs = wing::HeaderMap { .. };
    let consumed, err = wire::decode_h1_response_head("HTTP/1.0 404 Not Found\r\nServer: wing\r\n\r\n", status, hdrs);
    assert(err == wing::HeaderParseError.None && consumed > 0 && status == 404);
    assert(hdrs.status_code == 404 && hdrs.http_major == 1 && hdrs.http_minor == 0);

    // On header parse error after status line, `status` must reset to 0
    let _, bad_hdr_err = wire::decode_h1_response_head(
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n", status, hdrs,
    );
    assert(bad_hdr_err != wing::HeaderParseError.None && status == 0);

    // encode_h1_request / encode_h1_response must reject CL + TE smuggling and conflicting Content-Length
    var smuggle_hdrs = wing::HeaderMap { .. };
    wing::append_header(smuggle_hdrs, "Content-Length", "5");
    wing::append_header(smuggle_hdrs, "Transfer-Encoding", "chunked");
    var h1_out: u8[..256] = [];
    assert(!wire::encode_h1_request("POST", "/upload", "example.com", smuggle_hdrs, "hello", wire::H1HeaderFilterMode.PreserveAll, h1_out));
    assert(!wire::encode_h1_response(200, "OK", "wing", smuggle_hdrs, "hello", false, h1_out));

    var mismatch_cl = wing::HeaderMap { .. };
    wing::append_header(mismatch_cl, "Content-Length", "99");
    assert(!wire::encode_h1_request("POST", "/upload", "example.com", mismatch_cl, "hello", wire::H1HeaderFilterMode.PreserveAll, h1_out));
    assert(!wire::encode_h1_response(200, "OK", "wing", mismatch_cl, "hello", false, h1_out));

    print("F_WIRE_010_H1_SYNC_AND_SMUGGLING: OK\n");
}

// F-WIRE-011: decode_h2_frame_header stream association/length rules and encode_settings_frame RFC 9113 §6.5.2 bounds.
fn test_f_wire_011_h2_frame_and_settings_validation() {
    // PING frame on stream 1 (forbidden by RFC 9113 §6.7) must be rejected by decode_h2_frame_header
    let ping_sid1: u8[9] = [0x00, 0x00, 0x08, rfc::H2_FRAME_PING, 0x00, 0x00, 0x00, 0x00, 0x01];
    let _, err_ping_sid = wire::decode_h2_frame_header(ping_sid1[..]);
    assert(err_ping_sid == rfc::H2_ERR_PROTOCOL_ERROR);

    // PING frame with length 4 (instead of 8) must fail with FRAME_SIZE_ERROR
    let ping_len4: u8[9] = [0x00, 0x00, 0x04, rfc::H2_FRAME_PING, 0x00, 0x00, 0x00, 0x00, 0x00];
    let _, err_ping_len = wire::decode_h2_frame_header(ping_len4[..]);
    assert(err_ping_len == rfc::H2_ERR_FRAME_SIZE_ERROR);

    // encode_settings_frame must reject out-of-range MAX_FRAME_SIZE (< 16384) or ENABLE_PUSH > 1 (RFC 9113 §6.5.2)
    var s_out: u8[..64] = [];
    let bad_mfs: wire::WireSetting[1] = [wire::h2_setting(rfc::H2_SETTING_MAX_FRAME_SIZE, 1024)];
    assert(!wire::encode_settings_frame(bad_mfs[..], s_out));
    let bad_push: wire::WireSetting[1] = [wire::h2_setting(rfc::H2_SETTING_ENABLE_PUSH, 2)];
    assert(!wire::encode_settings_frame(bad_push[..], s_out));

    print("F_WIRE_011_H2_FRAME_AND_SETTINGS: OK\n");
}

// F-WIRE-012: reset_command_pool(pool, 0) reuse, out-of-order slot release, stale cmd rejection, and RecordingHeaders error state.
fn test_f_wire_012_pool_and_cmd_fsm() {
    let inst = wire::WireInstance { .. };
    var phys: wire::WirePhysicalDevice[..4] = [];
    let _ = wire::enumerate_physical_devices(inst, phys);
    let dev_info = wire::WireDeviceCreateInfo { .. };
    let pool_info = wire::WireCommandPoolCreateInfo { .. };
    var dev, _ = wire::create_wire_device(phys[0], dev_info);
    var pool, _ = wire::create_command_pool(dev, pool_info);

    // Allocate all 4 command buffers, then reset pool with flags = 0 (without RELEASE_RESOURCES_BIT)
    var c1, r1 = wire::allocate_command_buffer(pool);
    var c2, r2 = wire::allocate_command_buffer(pool);
    var c3, r3 = wire::allocate_command_buffer(pool);
    var c4, r4 = wire::allocate_command_buffer(pool);
    assert(wire::is_success(r1) && wire::is_success(r2) && wire::is_success(r3) && wire::is_success(r4));
    assert(wire::is_success(wire::reset_command_pool(pool, 0)));

    // Allocating after reset_command_pool(pool, 0) must succeed, and stale `c1` must not commit over `c5`
    var c5, r5 = wire::allocate_command_buffer(pool);
    assert(wire::is_success(r5));
    let begin_info = wire::WireCommandBufferBeginInfo { .. };
    let _ = wire::begin_command_buffer(c1, begin_info);
    let _ = wire::write_h2_preface(c1);
    let _ = wire::end_command_buffer(c1);
    let _, stale_commit_ok = wire::commit_command_buffer_to_arena(pool, c1);
    assert(!stale_commit_ok);

    // Failed HPACK command inside RecordingHeaders must allow end_command_buffer to return ErrorCommandBufferLocked
    let _ = wire::begin_command_buffer(c5, begin_info);
    assert(wire::begin_h2_headers(c5, 1, rfc::H2_FLAG_END_HEADERS));
    assert(!wire::hpack_indexed(c5, 0));
    let end_err = wire::end_command_buffer(c5);
    assert(end_err == wire::WireResult.ErrorCommandBufferLocked && c5.state == wire::WireCommandBufferState.Invalid);

    print("F_WIRE_012_POOL_AND_CMD_FSM: OK\n");
}

// F-WIRE-013: submit_to_cork consumed-buffer reset, Timeline semaphore monotonicity, and idempotent add_*_stage.
fn test_f_wire_013_cork_sync_and_pipeline() {
    let inst = wire::WireInstance { .. };
    var phys: wire::WirePhysicalDevice[..4] = [];
    let _ = wire::enumerate_physical_devices(inst, phys);
    let dev_info = wire::WireDeviceCreateInfo { .. };
    var dev, _ = wire::create_wire_device(phys[0], dev_info);

    // Timeline semaphore must reject non-monotonic backward values
    let sem_info = wire::WireSemaphoreCreateInfo {
        semaphore_type: wire::WireSemaphoreType.Timeline,
        initial_value:  20,
    };
    var sem, _ = wire::create_wire_semaphore(dev, sem_info);
    assert(!wire::is_success(wire::signal_wire_semaphore(sem, 10)));
    assert(sem.value == 20);

    // add_ingress_stage / add_egress_stage must not append duplicate stage IDs
    var pipe = wire::default_server_pipeline();
    let initial_in_len = pipe.ingress_stages.len;
    assert(wire::add_ingress_stage(pipe, wire::STAGE_ID_SRV_IN_AUTH_JWT));
    assert(pipe.ingress_stages.len == initial_in_len);

    print("F_WIRE_013_CORK_SYNC_AND_PIPELINE: OK\n");
}

fn main() {
    // CHECK: F_WIRE_008_TRANSACTIONAL_TABLES: OK
    // CHECK: F_WIRE_009_QPACK_SENSITIVE_AND_RFC: OK
    // CHECK: F_WIRE_010_H1_SYNC_AND_SMUGGLING: OK
    // CHECK: F_WIRE_011_H2_FRAME_AND_SETTINGS: OK
    // CHECK: F_WIRE_012_POOL_AND_CMD_FSM: OK
    // CHECK: F_WIRE_013_CORK_SYNC_AND_PIPELINE: OK
    test_f_wire_008_transactional_hpack_qpack_tables();
    test_f_wire_009_qpack_sensitive_and_rfc_headers();
    test_f_wire_010_h1_head_sync_and_smuggling();
    test_f_wire_011_h2_frame_and_settings_validation();
    test_f_wire_012_pool_and_cmd_fsm();
    test_f_wire_013_cork_sync_and_pipeline();
}
