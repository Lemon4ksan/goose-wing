// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Complete 7-tier Vulkan-similarity explicit networking pipeline demonstration in goose-wing.
import std;
import core from "..";
import wing from "..";

fn main() {
    print("=== goose-wing 7-Tier Vulkan-Style Wire Pipeline Reference ===\n");

    // Tier 1: Instance & Physical Device Enumeration
    print("[1] Initializing Vulkan Wire Instance and Enumerating Physical Devices:");
    let inst = wire::WireInstance { .. };
    var phys_devs: wire::WirePhysicalDevice[..4] = [];
    let enum_res = wire::enumerate_physical_devices(inst, phys_devs);
    assert(wire::is_success(enum_res));
    let phys = phys_devs[0];
    print("    Vulkan API Version: 0x", inst.api_version);
    print("    Device Driver:      Standard POSIX / WinSock2");
    print("    Buffer Capacity:    ", phys.properties.max_buffer_capacity, " bytes");

    // Tier 2: Logical Device Creation
    print("\n[2] Creating Logical Wire Device with Configured Features:");
    let dev_info = wire::WireDeviceCreateInfo {
        config: wire::WireDeviceConfig {
            driver:            wire::WireDriverKind.Standard,
            tcp_nodelay:       true,
            tcp_keepalive:     true,
            has_dont_fragment: true,
            ip_ttl:            128,
            rx_buf_size:       65536,
            tx_buf_size:       65536,
            wscale:            8,
            mss:               1460,
        },
        enabled_features: wire::WirePhysicalDeviceFeatures {
            hpack_compression: true,
            tcp_zero_copy:     false,
            hardware_tls:      false,
            raw_frames:        true,
        },
    };
    var dev, create_dev_res = wire::create_wire_device(phys, dev_info);
    assert(wire::is_success(create_dev_res) && dev.is_active);
    print("    Logical Device:     ACTIVE (TCP_NODELAY enabled, TTL=128)");

    // Tier 3: Command Pool Memory Allocator
    print("\n[3] Creating Explicit Memory Command Pool:");
    let pool_info = wire::WireCommandPoolCreateInfo {
        flags:              wire::WIRE_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT,
        queue_family_index: 0,
    };
    var pool, pool_res = wire::create_command_pool(dev, pool_info);
    assert(wire::is_success(pool_res) && pool.is_valid);
    print("    Command Pool:       64 KB Arena Recycler Ready");

    // Tier 4: Pipeline State Object (PSO)
    print("\n[4] Creating and Configuring Pipeline State Object (PSO):");
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
    print("    Pipeline Bind Point: Transmit (Max Frame Size: 16384 bytes)");

    // Tier 5: Command Buffer Recording via Lifecycle FSM
    print("\n[5] Allocating Command Buffer and Recording Protocol Frames:");
    var cmd, alloc_res = wire::allocate_command_buffer(pool);
    assert(wire::is_success(alloc_res) && cmd.state == wire::WireCommandBufferState.Initial);

    let begin_info = wire::WireCommandBufferBeginInfo {
        flags: wire::WIRE_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT,
    };
    assert(wire::is_success(wire::begin_command_buffer(cmd, begin_info)));
    assert(wire::is_success(wire::cmd_bind_pipeline(cmd, wire::WirePipelineBindPoint.Transmit, pipe)));

    // Command 1: Write HTTP/2 Client Connection Preface (24 bytes)
    assert(wire::write_h2_preface(cmd));
    print("    Recorded: HTTP/2 Client Preface (24 bytes)");

    // Command 2: Write SETTINGS Frame (Stream 0)
    let settings_list: wire::WireSetting[3] = [
        wire::h2_setting(wire::H2_SETTING_ENABLE_PUSH, 0),
        wire::h2_setting(wire::H2_SETTING_INITIAL_WINDOW_SIZE, 131072),
        wire::h2_setting(wire::H2_SETTING_NO_RFC7540_PRIORITIES, 1),
    ];
    assert(wire::write_h2_settings(cmd, settings_list[..]));
    print("    Recorded: SETTINGS Frame (3 parameters)");

    // Command 3: Write WINDOW_UPDATE Frame (Stream 0, +512 KB credit)
    assert(wire::write_h2_window_update(cmd, 0, 524288));
    print("    Recorded: WINDOW_UPDATE Frame (Stream 0, +512 KB)");

    // Command 4: Dynamic HEADERS Frame with HPACK Staging
    assert(wire::begin_h2_headers(cmd, 1, wire::H2_FLAG_END_HEADERS));
    assert(wire::hpack_indexed(cmd, 2)); // :method: GET
    assert(wire::hpack_indexed(cmd, 7)); // :scheme: https
    assert(wire::hpack_literal_without_indexing(cmd, ":path", "/v1/orders"));
    assert(wire::hpack_literal_without_indexing(cmd, ":authority", "wire.mesh.local"));
    assert(wire::hpack_literal_never_indexed(cmd, "authorization", "Bearer super-secret-token"));
    assert(wire::end_h2_headers(cmd));
    print("    Recorded: Dynamic HEADERS with Back-Patched HPACK Length");

    // Command 5: Write DATA Frame (Stream 1, payload, END_STREAM)
    let payload = "{\"action\":\"submit_order\",\"units\":10}";
    assert(wire::write_h2_data(cmd, 1, payload, true));
    print("    Recorded: DATA Frame (Stream 1, END_STREAM=true)");

    // End command buffer recording -> transitions to Executable
    assert(wire::is_success(wire::end_command_buffer(cmd)));
    print("    Command Buffer State: Executable (", cmd.buf.len, " bytes)");

    // Tier 6: Queue Acquisition, Batch Submission & Synchronization2
    print("\n[6] Acquiring Device Queue and Submitting Batch with Fence:");
    var queue = wire::get_device_queue(dev, 0, 0);
    queue.driver = wire::WireDriverKind.Mock;
    queue.is_connected = true;

    let fence_info = wire::WireFenceCreateInfo { flags: 0 };
    var fence, f_res = wire::create_wire_fence(dev, fence_info);
    assert(wire::is_success(f_res));

    let batch: wire::WireCommandBuffer[1] = [cmd];
    let submit_info = wire::WireSubmitInfo {
        stage_mask:       wire::WIRE_PIPELINE_STAGE_ALL_COMMANDS,
        wait_semaphore:   0,
        signal_semaphore: 0,
        bytes_submitted:  0,
    };

    let sent_bytes, sub_res = wire::queue_submit_batch(queue, batch[..], submit_info, fence);
    assert(wire::is_success(sub_res) && sent_bytes > 0);
    assert(fence.status == wire::WireFenceStatus.Signaled);
    print("    Batch Submitted:    ", sent_bytes, " bytes");
    print("    Fence Status:       Signaled (CPU-GPU synchronization point)");

    // Tier 7: Ingress Stream Demuxing Verification
    print("\n[7] Demuxing Ingress Wire Stream with Zero-Copy WireH2FrameReader:");
    let wire_bytes = cmd.buf[..];
    let frame_stream = wire_bytes[24..];
    var reader = wire::new_wire_h2_frame_reader(frame_stream);
    var frame_count: i32 = 0;

    while wire::has_next(reader) {
        let hdr, frame_payload, ok = wire::next_frame(reader);
        assert(ok);
        frame_count += 1;
        print("    Frame ", frame_count, ": Type=0x", if hdr.frame_type < 16 { "0" } else { "" },
              hdr.frame_type, " Stream=", hdr.stream_id, " Length=", hdr.length);
    }
    assert(frame_count == 4);

    // Teardown and Cleanup
    wire::close_wire_queue(queue);
    wire::free_command_buffer(pool, cmd);
    wire::destroy_wire_fence(fence);
    wire::destroy_wire_pipeline(pipe);
    wire::destroy_command_pool(pool);
    wire::destroy_wire_device(dev);
    print("\n[8] Full 7-tier pipeline execution verified successfully.");
}
