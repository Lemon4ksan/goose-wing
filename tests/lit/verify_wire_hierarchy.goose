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

    wire::trim_command_pool(pool);
    print("TRIM_COMMAND_POOL_OK: 1\n");

    wire::destroy_command_pool(pool);
    if !pool.is_valid {
        print("DESTROY_COMMAND_POOL_OK: 1\n");
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
    // CHECK: TRIM_COMMAND_POOL_OK: 1
    // CHECK: DESTROY_COMMAND_POOL_OK: 1
    // CHECK: DESTROY_WIRE_DEVICE_OK: 1
    test_wire_result();
    test_device_hierarchy();
}
