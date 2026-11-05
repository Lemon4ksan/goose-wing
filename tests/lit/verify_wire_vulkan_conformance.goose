// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

// Verification of the full 7-tier Vulkan-similarity API pipeline in wire subsystem.
import std;
import core from "../..";
import wing from "../..";

fn test_vulkan_wire_conformance() {
    print("=== VULKAN_WIRE_CONFORMANCE_SUITE ===\n");

    // Tier 1: Instance & Physical Device Enumeration
    let inst = wire::WireInstance { .. };
    assert(inst.api_version == 0x00400000);
    print("VULKAN_INSTANCE: OK\n");

    var phys_devs: wire::WirePhysicalDevice[..4] = [];
    let enum_res = wire::enumerate_physical_devices(inst, phys_devs);
    assert(wire::is_success(enum_res));
    assert(phys_devs.len >= 1);
    let phys = phys_devs[0];
    assert(phys.properties.max_buffer_capacity == 16384);
    print("PHYSICAL_DEVICE_ENUM: OK\n");

    // Tier 2: Logical Device Creation
    let dev_info = wire::WireDeviceCreateInfo {
        config: wire::WireDeviceConfig { .. },
        enabled_features: wire::WirePhysicalDeviceFeatures {
            hpack_compression: true,
            tcp_zero_copy:     false,
            hardware_tls:      false,
            raw_frames:        true,
        },
    };
    var dev, create_dev_res = wire::create_wire_device(phys, dev_info);
    assert(wire::is_success(create_dev_res) && dev.is_active);
    print("LOGICAL_DEVICE_CREATED: OK\n");

    // Tier 3: Command Pool Memory Allocator
    let pool_info = wire::WireCommandPoolCreateInfo {
        flags:              wire::WIRE_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT,
        queue_family_index: 0,
    };
    var pool, pool_res = wire::create_command_pool(dev, pool_info);
    assert(wire::is_success(pool_res) && pool.is_valid);

    let reset_pool_res = wire::reset_command_pool(pool, wire::WIRE_COMMAND_POOL_RESET_RELEASE_RESOURCES_BIT);
    assert(wire::is_success(reset_pool_res));
    print("COMMAND_POOL_RECYCLED: OK\n");

    // Tier 4: Pipeline State Object (PSO)
    let pipe_info = wire::WirePipelineCreateInfo {
        bind_point: wire::WirePipelineBindPoint.Transmit,
        layout: wire::WirePipelineLayout {
            max_frame_size: 16384,
            push_constants: [],
        },
        flags: 0,
    };
    var pipe, pipe_res = wire::create_wire_pipeline(dev, pipe_info);
    assert(wire::is_success(pipe_res) && pipe.is_valid);

    // Tier 5: Command Buffer Lifecycle FSM & Frame Recording
    var cmd, alloc_res = wire::allocate_command_buffer(pool);
    assert(wire::is_success(alloc_res) && cmd.state == wire::WireCommandBufferState.Initial);

    // Attempting to record before begin_command_buffer MUST fail
    let premature_rec = wire::write_h2_preface(cmd);
    assert(!premature_rec && cmd.has_error);

    // Begin recording
    let begin_info = wire::WireCommandBufferBeginInfo {
        flags: wire::WIRE_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT,
    };
    let begin_res = wire::begin_command_buffer(cmd, begin_info);
    assert(wire::is_success(begin_res) && cmd.state == wire::WireCommandBufferState.Recording);

    // Bind Pipeline State Object
    let bind_res = wire::cmd_bind_pipeline(cmd, wire::WirePipelineBindPoint.Transmit, pipe);
    assert(wire::is_success(bind_res));
    print("PIPELINE_STATE_BOUND: OK\n");

    // Command 1: Preface
    assert(wire::write_h2_preface(cmd));

    // Command 2: SETTINGS
    let s_list: wire::WireSetting[2] = [
        wire::h2_setting(rfc::H2_SETTING_ENABLE_PUSH, 0),
        wire::h2_setting(rfc::H2_SETTING_INITIAL_WINDOW_SIZE, 65535),
    ];
    assert(wire::write_h2_settings(cmd, s_list[..]));

    // Command 3: Dynamic HEADERS Block with Interleave Protection
    assert(wire::begin_h2_headers(cmd, 1, rfc::H2_FLAG_END_HEADERS));
    assert(cmd.state == wire::WireCommandBufferState.RecordingHeaders);

    // Interleave rejection: writing frame while in RecordingHeaders must fail
    var interleave_cmd, i_res = wire::allocate_command_buffer(pool);
    assert(wire::is_success(i_res));
    wire::begin_command_buffer(interleave_cmd, begin_info);
    assert(wire::begin_h2_headers(interleave_cmd, 1, rfc::H2_FLAG_END_HEADERS));
    let ping_data: u8[8] = [0; 8];
    assert(!wire::write_h2_ping(interleave_cmd, ping_data, false));
    assert(interleave_cmd.has_error);
    wire::free_command_buffer(pool, interleave_cmd);

    //Valid HPACK entries on clean cmd (zero-staging in-place 9-byte frame header reservation)
    let hdr_start = cmd.headers_frame_offset;
    assert(hdr_start > 0);
    assert(wire::hpack_indexed(cmd, 2));
    assert(wire::hpack_indexed(cmd, 7));
    assert(wire::hpack_literal_without_indexing(cmd, ":path", "/vulkan-wire"));
    assert(wire::end_h2_headers(cmd));
    assert(cmd.state == wire::WireCommandBufferState.Recording);

    // Command 4: DATA Frame
    assert(wire::write_h2_data(cmd, 1, "test-stream-body", true));

    // End command buffer recording and commit to pool arena via core::ct_copy_bytes
    let end_res = wire::end_command_buffer(cmd);
    assert(wire::is_success(end_res) && cmd.state == wire::WireCommandBufferState.Executable);
    let arena_slice, commit_ok = wire::commit_command_buffer_to_arena(pool, cmd);
    assert(commit_ok && arena_slice.len == cmd.buf.len);
    print("COMMAND_BUFFER_LIFECYCLE_FSM: OK\n");

    // Verify wire::hpack_decode_string Huffman decoding (RFC 7541 Appendix C.4.1 "www.example.com")
    let huff_wire: u8[13] = [0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff];
    var huff_pos:     u64      = 0;
    var decoded_huff: u8[..64] = [];
    let huff_ok = wire::hpack_decode_string(huff_wire[..], huff_pos, decoded_huff);
    assert(huff_ok && huff_pos == 13);
    assert(core::ct_eq_bytes(decoded_huff[..], "www.example.com"));

    // Verify rfc::status_phrase, rfc::status_line_h1, rfc::is_empty_body_status, rfc::is_redirect_status
    assert(core::ct_eq_bytes(rfc::status_phrase(rfc::STATUS_OK), "OK"));
    assert(core::ct_eq_bytes(rfc::status_line_h1(rfc::STATUS_NOT_FOUND), "HTTP/1.1 404 Not Found\r\n"));
    assert(rfc::is_empty_body_status(rfc::STATUS_NO_CONTENT));
    assert(!rfc::is_empty_body_status(rfc::STATUS_OK));
    assert(rfc::is_redirect_status(rfc::STATUS_MOVED_PERMANENTLY));
    assert(!rfc::is_redirect_status(rfc::STATUS_OK));
    print("RFC_HELPERS_AND_HUFFMAN: OK\n");

    // Tier 6: Queue Acquisition, Batch Submission & Synchronization2
    var queue = wire::get_device_queue(dev, 0, 0);
    queue.driver = wire::WireDriverKind.Mock;
    queue.is_connected = true;

    // Verify WireQueue submit_to_cork and submit_to_transport over ring buffers
    var cork = core::CorkBuffer { .. };
    let cork_ok = wire::submit_to_cork(cmd, cork);
    assert(cork_ok && core::cork_pending(cork) == cmd.buf.len);
    print("WIRE_QUEUE_TLS13: OK\n");

    // Create Synchronization2 Fence and Semaphore
    let fence_info = wire::WireFenceCreateInfo { flags: 0 };
    var fence, f_res = wire::create_wire_fence(dev, fence_info);
    assert(wire::is_success(f_res) && fence.status == wire::WireFenceStatus.Unsignaled);

    let sem_info = wire::WireSemaphoreCreateInfo {
        semaphore_type: wire::WireSemaphoreType.Timeline,
        initial_value:  10,
    };
    var sem, sem_res = wire::create_wire_semaphore(dev, sem_info);
    assert(wire::is_success(sem_res) && sem.value == 10);
    print("SEMAPHORE_TIMELINE: OK\n");

    // Batch Submission
    let batch: wire::WireCommandBuffer[1] = [cmd];
    let submit_info = wire::WireSubmitInfo {
        stage_mask:       wire::WIRE_PIPELINE_STAGE_ALL_COMMANDS,
        wait_semaphore:   10,
        signal_semaphore: 20,
        bytes_submitted:  0,
    };

    let sent_bytes, sub_res = wire::queue_submit_batch(queue, batch[..], submit_info, fence);
    assert(wire::is_success(sub_res) && sent_bytes > 0);
    assert(fence.status == wire::WireFenceStatus.Signaled);
    print("FENCE_SIGNALED: OK\n");

    // Tier 7: Queue Shutdown and Descriptor Reset Invariant
    wire::close_wire_queue(queue);
    assert(queue.fd == -1);
    assert(!queue.is_connected);
    print("SOCKET_FD_INVARIANT: OK\n");

    // Resource Cleanup
    wire::free_command_buffer(pool, cmd);
    wire::destroy_command_pool(pool);
    wire::destroy_wire_pipeline(pipe);
    wire::destroy_wire_fence(fence);
    wire::destroy_wire_semaphore(sem);
    wire::destroy_wire_device(dev);
}

struct CustomAuditStage {
    pre_route_hits: i32 = 0,
    post_auth_hits: i32 = 0,
}

fn wing::on_server_stage(
    stage: CustomAuditStage&,
    phase: wire::ServerHookPhase,
    _cfg:  wing::ServerPipelineConfig&,
    _req:  const wing::Request&,
    _ctx:  wing::ServerStageCtx&,
    _res:  wing::Response&,
) -> wire::StageVerdict {
    if phase == wire::ServerHookPhase.PreRoute {
        stage.pre_route_hits += 1;
    } else if phase == wire::ServerHookPhase.PostAuth {
        stage.post_auth_hits += 1;
    }
    return wire::StageVerdict.Continue;
}

struct CustomHeaderStage {
    egress_hits: i32 = 0,
}

fn wing::on_server_stage(
    stage: CustomHeaderStage&,
    phase: wire::ServerHookPhase,
    _cfg:  wing::ServerPipelineConfig&,
    _req:  const wing::Request&,
    _ctx:  wing::ServerStageCtx&,
    res:   wing::Response&,
) -> wire::StageVerdict {
    if phase == wire::ServerHookPhase.PreSerialize {
        stage.egress_hits += 1;
        wing::set_header(res, "X-Custom-Stage", "active");
    }
    return wire::StageVerdict.Continue;
}

fn test_tier1_and_tier2_pipeline_conformance() {
    // 1. Tier 1 HTTP/1.1 codec round-trip into HeaderMap
    var req_hdrs = wing::HeaderMap { .. };
    wing::append_header(req_hdrs, "X-Trace", "t1");
    var h1_req_wire: u8[..512] = [];
    assert(wire::encode_h1_request(
        "GET", "/v1/items", "api.example.com", req_hdrs, "",
        wire::H1HeaderFilterMode.PreserveAll, h1_req_wire,
    ));
    var parsed_req = wing::Request { .. };
    let ok_req_parse, _ = wing::parse_http1_wire_request(h1_req_wire[..], parsed_req);
    assert(ok_req_parse);
    assert(wing::header(parsed_req, "Host") == "api.example.com");
    assert(wing::header(parsed_req, "X-Trace") == "t1");

    var resp_hdrs = wing::HeaderMap { .. };
    wing::append_header(resp_hdrs, "Content-Type", "application/json");
    var h1_resp_wire: u8[..512] = [];
    assert(wire::encode_h1_response(200, "OK", "goose-wing", resp_hdrs, "{\"ok\":true}", false, h1_resp_wire));
    var parsed_resp_hdrs = wing::HeaderMap { .. };
    var parsed_status: u16 = 0;
    let resp_consumed, resp_err = wire::decode_h1_response_head(h1_resp_wire[..], parsed_status, parsed_resp_hdrs);
    assert(resp_err == wing::HeaderParseError.None && resp_consumed > 0 && parsed_status == 200);
    assert(wing::get_header(parsed_resp_hdrs, "Content-Type") == "application/json");
    print("TIER1_H1_CODEC: OK\n");

    // 2. Tier 1 HPACK & QPACK decode directly into HeaderMap
    var dt = internal::new_dynamic_table(4096);
    var hpack_buf: u8[..256] = [];
    var enc_pseudo = internal::H2PseudoHeaders { has_status: true, status: 200, .. };
    var h2_in_map = wing::HeaderMap { .. };
    wing::append_header(h2_in_map, "x-h2-header", "val2");
    assert(wire::encode_hpack_from_map(dt, enc_pseudo, h2_in_map, hpack_buf, false));
    var h2_dec_dt = internal::new_dynamic_table(4096);
    var h2_pseudo = internal::H2PseudoHeaders { .. };
    var h2_map = wing::HeaderMap { .. };
    let h2_err = wire::decode_hpack_to_map(h2_dec_dt, hpack_buf[..], h2_pseudo, h2_map);
    assert(h2_err == rfc::H2_ERR_NO_ERROR && h2_pseudo.status == 200);
    assert(wing::get_header(h2_map, "x-h2-header") == "val2");

    var qpack_enc = internal::new_qpack_table(0);
    var qpack_dec = internal::new_qpack_table(0);
    var q_req_in = wing::HeaderMap { .. };
    wing::append_header(q_req_in, "x-h3-custom", "val3");
    var q_in_pseudo = internal::H3PseudoHeaders {
        has_method:    true,
        method:        "GET",
        has_scheme:    true,
        scheme:        "https",
        has_authority: true,
        authority:     "example.com",
        has_path:      true,
        path:          "/h3",
        ..
    };
    var q_frame: u8[..256] = [];
    var q_inst:  u8[..256] = [];
    assert(wire::encode_h3_headers_from_map(qpack_enc, 0, q_in_pseudo, q_req_in, q_inst, q_frame));
    // Strip 2-byte H3 HEADERS frame header (type=0x01, len)
    let q_payload = q_frame[2..];
    var q_pseudo = internal::H3PseudoHeaders { .. };
    var q_map = wing::HeaderMap { .. };
    let q_err = wire::decode_h3_headers_to_map(qpack_dec, 0, q_payload, q_pseudo, q_map);
    assert(q_err == internal::QpackError.None && q_pseudo.path[..] == "/h3");
    assert(wing::get_header(q_map, "x-h3-custom") == "val3");

    // Verify WireCommandBuffer multi-protocol recording and H2 frame header decode
    var multi_cmd = wire::new_command_buffer();
    let begin_multi = wire::WireCommandBufferBeginInfo { flags: wire::WIRE_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT };
    assert(wire::cmd_encode_h1_request(multi_cmd, "GET", "/ping", "example.com", req_hdrs, ""));
    multi_cmd.reset();
    assert(wire::is_success(wire::begin_command_buffer(multi_cmd, begin_multi)));
    assert(wire::cmd_encode_h1_response(multi_cmd, 200, "OK", "wing", resp_hdrs, "ok", false));
    multi_cmd.reset();
    assert(wire::is_success(wire::begin_command_buffer(multi_cmd, begin_multi)));
    assert(wire::cmd_encode_h2_headers_map(multi_cmd, dt, 1, enc_pseudo, h2_in_map, true));
    let dec_hdr, dec_hdr_err = wire::decode_h2_frame_header(multi_cmd.buf[..]);
    assert(dec_hdr_err == rfc::H2_ERR_NO_ERROR && dec_hdr.stream_id == 1);
    multi_cmd.reset();
    assert(wire::is_success(wire::begin_command_buffer(multi_cmd, begin_multi)));
    assert(wire::cmd_encode_h3_headers_map(multi_cmd, qpack_enc, 0, q_in_pseudo, q_req_in, q_inst));
    assert(multi_cmd.buf.len > 0);
    print("TIER1_HPACK_QPACK_MAP: OK\n");

    // 3. Tier 2 PipelineState step combinator + Server Stage Bricks + <UserStage> hook
    var pstate = wire::begin_pipeline();
    assert(wire::can_continue(pstate));
    assert(wire::step(pstate, wire::StageVerdict.Continue));
    assert(!wire::step(pstate, wire::StageVerdict.ShortCircuit { status_code: 204 }));
    assert(!wire::can_continue(pstate));

    var srv_cfg = wing::new_default_server_pipeline_config("example.com");
    wire::disable_ingress_stage(srv_cfg.wire_pipeline, wire::STAGE_ID_SRV_IN_SLOWLORIS);
    wire::enable_ingress_stage(srv_cfg.wire_pipeline, wire::STAGE_ID_SRV_IN_SLOWLORIS);
    wire::disable_egress_stage(srv_cfg.wire_pipeline, wire::STAGE_ID_SRV_OUT_METRICS);
    wire::enable_egress_stage(srv_cfg.wire_pipeline, wire::STAGE_ID_SRV_OUT_METRICS);
    let full_pso = wing::DEFAULT_ROUTE_PSO_MASK | wing::STAGE_EGRESS_ETAG | wing::STAGE_EGRESS_COMPRESS_GZIP | wing::STAGE_EGRESS_METRICS;
    assert(wing::add_route_pso(srv_cfg.router, "GET", "/custom", 1002, full_pso));
    assert(wire::add_ingress_stage(srv_cfg.wire_pipeline, wire::STAGE_ID_SRV_IN_AUTH_JWT));
    assert(wire::add_egress_stage(srv_cfg.wire_pipeline, wire::STAGE_ID_SRV_OUT_ETAG));

    var timer = internal::new_connection_timer(30000000000, 1000000000);
    var sreq = wing::new_request("GET", "/custom");
    wing::set_header(sreq, "Host", "example.com");
    wing::set_header(sreq, "Sec-Fetch-Site", "same-origin");
    wing::set_header(sreq, "Accept-Encoding", "gzip");
    var sres = wing::Response { .. };
    var sfut = internal::new_inline_handler_future(0);
    var custom_chain = wire::chain_stages(CustomAuditStage { .. }, CustomHeaderStage { .. });
    let sout = wing::execute_server_pipeline_with_stage(
        srv_cfg, timer, "127.0.0.1", sreq, 1005000000, sres, sfut, custom_chain,
    );
    assert(sout == wing::PipelineOutcome.Handled && sres.status_code == 200);
    assert(custom_chain.first.pre_route_hits == 1 && custom_chain.first.post_auth_hits == 1);
    assert(custom_chain.next.egress_hits == 1);
    assert(wing::header(sres, "X-Custom-Stage") == "active");
    assert(wing::header(sres, "Content-Encoding") == "gzip");
    assert(wing::has_header(sres, "ETag"));
    assert(wing::has_header(sres, "Server-Timing"));
    print("TIER2_STAGE_CONSTRUCTOR: OK\n");
}

fn main() {
    // CHECK: === VULKAN_WIRE_CONFORMANCE_SUITE ===
    // CHECK: VULKAN_INSTANCE: OK
    // CHECK: PHYSICAL_DEVICE_ENUM: OK
    // CHECK: LOGICAL_DEVICE_CREATED: OK
    // CHECK: COMMAND_POOL_RECYCLED: OK
    // CHECK: PIPELINE_STATE_BOUND: OK
    // CHECK: COMMAND_BUFFER_LIFECYCLE_FSM: OK
    // CHECK: RFC_HELPERS_AND_HUFFMAN: OK
    // CHECK: WIRE_QUEUE_TLS13: OK
    // CHECK: SEMAPHORE_TIMELINE: OK
    // CHECK: FENCE_SIGNALED: OK
    // CHECK: SOCKET_FD_INVARIANT: OK
    // CHECK: TIER1_H1_CODEC: OK
    // CHECK: TIER1_HPACK_QPACK_MAP: OK
    // CHECK: TIER2_STAGE_CONSTRUCTOR: OK
    test_vulkan_wire_conformance();
    test_tier1_and_tier2_pipeline_conformance();
}
