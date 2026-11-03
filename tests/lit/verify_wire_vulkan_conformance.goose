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
        wire::h2_setting(wire::H2_SETTING_ENABLE_PUSH, 0),
        wire::h2_setting(wire::H2_SETTING_INITIAL_WINDOW_SIZE, 65535),
    ];
    assert(wire::write_h2_settings(cmd, s_list[..]));

    // Command 3: Dynamic HEADERS Block with Interleave Protection
    assert(wire::begin_h2_headers(cmd, 1, wire::H2_FLAG_END_HEADERS));
    assert(cmd.state == wire::WireCommandBufferState.RecordingHeaders);

    // Interleave rejection: writing frame while in RecordingHeaders must fail
    var interleave_cmd, i_res = wire::allocate_command_buffer(pool);
    assert(wire::is_success(i_res));
    wire::begin_command_buffer(interleave_cmd, begin_info);
    assert(wire::begin_h2_headers(interleave_cmd, 1, wire::H2_FLAG_END_HEADERS));
    let ping_data: u8[8] = [0; 8];
    assert(!wire::write_h2_ping(interleave_cmd, ping_data, false));
    assert(interleave_cmd.has_error);
    wire::free_command_buffer(pool, interleave_cmd);

    // Valid HPACK entries on clean cmd
    assert(wire::hpack_indexed(cmd, 2));
    assert(wire::hpack_indexed(cmd, 7));
    assert(wire::hpack_literal_without_indexing(cmd, ":path", "/vulkan-wire"));
    assert(wire::end_h2_headers(cmd));
    assert(cmd.state == wire::WireCommandBufferState.Recording);

    // Command 4: DATA Frame
    assert(wire::write_h2_data(cmd, 1, "test-stream-body", true));

    // End command buffer recording
    let end_res = wire::end_command_buffer(cmd);
    assert(wire::is_success(end_res) && cmd.state == wire::WireCommandBufferState.Executable);
    print("COMMAND_BUFFER_LIFECYCLE_FSM: OK\n");

    // Tier 6: Queue Acquisition, Batch Submission & Synchronization2
    var queue = wire::get_device_queue(dev, 0, 0);
    queue.driver = wire::WireDriverKind.Mock;
    queue.is_connected = true;

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

fn main() {
    // CHECK: === VULKAN_WIRE_CONFORMANCE_SUITE ===
    // CHECK: VULKAN_INSTANCE: OK
    // CHECK: PHYSICAL_DEVICE_ENUM: OK
    // CHECK: LOGICAL_DEVICE_CREATED: OK
    // CHECK: COMMAND_POOL_RECYCLED: OK
    // CHECK: PIPELINE_STATE_BOUND: OK
    // CHECK: COMMAND_BUFFER_LIFECYCLE_FSM: OK
    // CHECK: SEMAPHORE_TIMELINE: OK
    // CHECK: FENCE_SIGNALED: OK
    // CHECK: SOCKET_FD_INVARIANT: OK
    test_vulkan_wire_conformance();
}
