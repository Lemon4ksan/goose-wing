// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

fn test_wire_result() {
    let ok_res = wire::WireResult.Success;
    let err_res = wire::WireResult.ErrorDeviceLost;

    if wire::is_success(ok_res) {
        print("OK_RES_SUCCESS: 1\n");
    }
    if !wire::is_error(ok_res) {
        print("OK_RES_NOT_ERROR: 1\n");
    }
    if wire::is_error(err_res) {
        print("ERR_RES_IS_ERROR: 1\n");
    }
}

fn test_device_hierarchy() {
    let inst = wire::WireInstance { .. };
    var phys_devs: wire::WirePhysicalDevice[..4] = [];
    let enum_res = wire::enumerate_physical_devices(inst, phys_devs);
    if wire::is_success(enum_res) && phys_devs.len == 1 {
        print("ENUM_PHYSICAL_DEV_OK: 1\n");
    }

    let dev_info = wire::WireDeviceCreateInfo {
        config: wire::WireDeviceConfig { .. },
        enabled_features: wire::WirePhysicalDeviceFeatures {
            hpack_compression: true,
            tcp_zero_copy:     false,
            hardware_tls:      false,
            raw_frames:        true,
        },
    };

    var dev, create_res = wire::create_wire_device(phys_devs[0], dev_info);
    if wire::is_success(create_res) && dev.is_active {
        print("CREATE_WIRE_DEVICE_OK: 1\n");
    }

    test_command_pool(dev);
    test_pipeline(dev);
    test_sync_primitives(dev);

    wire::destroy_wire_device(dev);
    if !dev.is_active {
        print("DESTROY_WIRE_DEVICE_OK: 1\n");
    }
}

fn test_command_pool(dev: const wire::WireDevice&) {
    let pool_info = wire::WireCommandPoolCreateInfo {
        flags:              wire::WIRE_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT,
        queue_family_index: 0,
    };
    var pool, pool_res = wire::create_command_pool(dev, pool_info);
    if wire::is_success(pool_res) && pool.is_valid {
        print("CREATE_COMMAND_POOL_OK: 1\n");
    }

    let reset_res = wire::reset_command_pool(pool, wire::WIRE_COMMAND_POOL_RESET_RELEASE_RESOURCES_BIT);
    if wire::is_success(reset_res) {
        print("RESET_COMMAND_POOL_OK: 1\n");
    }

    test_cmd_buffer_fsm(pool);

    wire::trim_command_pool(pool);
    print("TRIM_COMMAND_POOL_OK: 1\n");

    wire::destroy_command_pool(pool);
    if !pool.is_valid {
        print("DESTROY_COMMAND_POOL_OK: 1\n");
    }
}

fn test_cmd_buffer_fsm(pool: wire::WireCommandPool&) {
    var cmd, alloc_res = wire::allocate_command_buffer(pool);
    if wire::is_success(alloc_res) && cmd.state == wire::WireCommandBufferState.Initial {
        print("ALLOC_CMD_BUF_OK: 1\n");
    }

    let begin_info = wire::WireCommandBufferBeginInfo {
        flags: wire::WIRE_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT,
    };
    let begin_res = wire::begin_command_buffer(cmd, begin_info);
    if wire::is_success(begin_res) && cmd.state == wire::WireCommandBufferState.Recording {
        print("BEGIN_CMD_BUF_OK: 1\n");
    }

    // 24-bit overflow test (BUG-09)
    let ovf_24 = wire::write_u24_be(cmd, 0x01000000);
    if !ovf_24 && cmd.has_error {
        print("U24_OVERFLOW_GUARD_OK: 1\n");
    }

    // Reset buffer for further clean recording
    wire::reset_command_buffer(cmd, 0);
    wire::begin_command_buffer(cmd, begin_info);

    // Dynamic headers interleave protection (BUG-04 & BUG-17)
    assert(wire::begin_h2_headers(cmd, 1, wire::H2_FLAG_END_HEADERS));
    assert(cmd.state == wire::WireCommandBufferState.RecordingHeaders);

    // Attempting frame write inside headers block must fail (BUG-17)
    let ping_data: u8[8] = [0; 8];
    let interleave_res = wire::write_h2_ping(cmd, ping_data, false);
    if !interleave_res && cmd.has_error {
        print("HEADERS_INTERLEAVE_GUARD_OK: 1\n");
    }

    // Reset and complete clean recording
    wire::reset_command_buffer(cmd, 0);
    wire::begin_command_buffer(cmd, begin_info);
    assert(wire::write_h2_preface(cmd));
    let end_res = wire::end_command_buffer(cmd);
    if wire::is_success(end_res) && cmd.state == wire::WireCommandBufferState.Executable {
        print("END_CMD_BUF_OK: 1\n");
    }

    wire::free_command_buffer(pool, cmd);
    if cmd.state == wire::WireCommandBufferState.Invalid {
        print("FREE_CMD_BUF_OK: 1\n");
    }
}

fn test_pipeline(dev: const wire::WireDevice&) {
    let pipe_info = wire::WirePipelineCreateInfo {
        bind_point: wire::WirePipelineBindPoint.Transmit,
        layout: wire::WirePipelineLayout {
            max_frame_size: 16384,
            push_constants: [],
        },
        flags: 0,
    };
    var pipe, pipe_res = wire::create_wire_pipeline(dev, pipe_info);
    if wire::is_success(pipe_res) && pipe.is_valid {
        print("CREATE_WIRE_PIPELINE_OK: 1\n");
    }

    var cmd = wire::new_command_buffer();
    let bind_res = wire::cmd_bind_pipeline(cmd, wire::WirePipelineBindPoint.Transmit, pipe);
    if wire::is_success(bind_res) {
        print("BIND_WIRE_PIPELINE_OK: 1\n");
    }

    wire::destroy_wire_pipeline(pipe);
    if !pipe.is_valid {
        print("DESTROY_WIRE_PIPELINE_OK: 1\n");
    }
}

fn test_sync_primitives(dev: const wire::WireDevice&) {
    // 1. Fence test
    let fence_info = wire::WireFenceCreateInfo {
        flags: wire::WIRE_FENCE_CREATE_SIGNALED_BIT,
    };
    var fence, f_res = wire::create_wire_fence(dev, fence_info);
    if wire::is_success(f_res) && fence.is_valid {
        print("CREATE_WIRE_FENCE_OK: 1\n");
    }
    let wait_res = wire::wait_for_wire_fence(fence, 1000);
    if wire::is_success(wait_res) {
        print("WAIT_WIRE_FENCE_OK: 1\n");
    }
    let status_res = wire::get_wire_fence_status(fence);
    if wire::is_success(status_res) {
        print("STATUS_WIRE_FENCE_OK: 1\n");
    }
    let reset_res = wire::reset_wire_fence(fence);
    if wire::is_success(reset_res) && fence.status == wire::WireFenceStatus.Unsignaled {
        print("RESET_WIRE_FENCE_OK: 1\n");
    }
    wire::destroy_wire_fence(fence);
    if !fence.is_valid {
        print("DESTROY_WIRE_FENCE_OK: 1\n");
    }

    // 2. Semaphore test
    let sem_info = wire::WireSemaphoreCreateInfo {
        semaphore_type: wire::WireSemaphoreType.Timeline,
        initial_value:  0,
    };
    var sem, sem_res = wire::create_wire_semaphore(dev, sem_info);
    if wire::is_success(sem_res) && sem.is_valid {
        print("CREATE_WIRE_SEMAPHORE_OK: 1\n");
    }
    wire::signal_wire_semaphore(sem, 42);
    let sem_wait = wire::wait_wire_semaphore(sem, 42);
    if wire::is_success(sem_wait) {
        print("WAIT_WIRE_SEMAPHORE_OK: 1\n");
    }
    wire::destroy_wire_semaphore(sem);
    if !sem.is_valid {
        print("DESTROY_WIRE_SEMAPHORE_OK: 1\n");
    }
}

fn main() {
    // CHECK: OK_RES_SUCCESS: 1
    // CHECK: OK_RES_NOT_ERROR: 1
    // CHECK: ERR_RES_IS_ERROR: 1
    // CHECK: ENUM_PHYSICAL_DEV_OK: 1
    // CHECK: CREATE_WIRE_DEVICE_OK: 1
    // CHECK: CREATE_COMMAND_POOL_OK: 1
    // CHECK: RESET_COMMAND_POOL_OK: 1
    // CHECK: ALLOC_CMD_BUF_OK: 1
    // CHECK: BEGIN_CMD_BUF_OK: 1
    // CHECK: U24_OVERFLOW_GUARD_OK: 1
    // CHECK: HEADERS_INTERLEAVE_GUARD_OK: 1
    // CHECK: END_CMD_BUF_OK: 1
    // CHECK: FREE_CMD_BUF_OK: 1
    // CHECK: TRIM_COMMAND_POOL_OK: 1
    // CHECK: DESTROY_COMMAND_POOL_OK: 1
    // CHECK: CREATE_WIRE_PIPELINE_OK: 1
    // CHECK: BIND_WIRE_PIPELINE_OK: 1
    // CHECK: DESTROY_WIRE_PIPELINE_OK: 1
    // CHECK: CREATE_WIRE_FENCE_OK: 1
    // CHECK: WAIT_WIRE_FENCE_OK: 1
    // CHECK: STATUS_WIRE_FENCE_OK: 1
    // CHECK: RESET_WIRE_FENCE_OK: 1
    // CHECK: DESTROY_WIRE_FENCE_OK: 1
    // CHECK: CREATE_WIRE_SEMAPHORE_OK: 1
    // CHECK: WAIT_WIRE_SEMAPHORE_OK: 1
    // CHECK: DESTROY_WIRE_SEMAPHORE_OK: 1
    // CHECK: DESTROY_WIRE_DEVICE_OK: 1
    test_wire_result();
    test_device_hierarchy();
}
