// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Explicit Vulkan-style memory allocator and command pool lifecycle management.
namespace wire;

import std;
import .result;
import .types;

// Command Pool Creation Flags (matching VkCommandPoolCreateFlagBits).
const WIRE_COMMAND_POOL_CREATE_TRANSIENT_BIT:            u32 = 0x00000001;
const WIRE_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT: u32 = 0x00000002;

// Command Pool Reset Flags (matching VkCommandPoolResetFlagBits).
const WIRE_COMMAND_POOL_RESET_RELEASE_RESOURCES_BIT: u32 = 0x00000001;

// Configuration parameters for creating a command pool (VkCommandPoolCreateInfo).
struct WireCommandPoolCreateInfo {
    flags:              u32 = 0,
    queue_family_index: u32 = 0,
}

// Bounded explicit memory allocator pool managing reusable command buffers (VkCommandPool).
struct WireCommandPool {
    flags:              u32         = 0,
    queue_family_index: u32         = 0,
    allocated_count:    u32         = 0,
    slot_mask:          u8          = 0,
    generation:         u32         = 1,
    is_valid:           bool        = false,
    arena:              u8[..65536] = [],
}

// Allocates an explicit WireCommandPool from the logical device.
fn create_command_pool(
    dev:  const WireDevice&,
    info: const WireCommandPoolCreateInfo&,
) -> WireCommandPool, WireResult {
    guard dev.is_active else {
        return WireCommandPool { .. }, WireResult.ErrorInitializationFailed;
    }
    return WireCommandPool {
        flags:              info.flags,
        queue_family_index: info.queue_family_index,
        allocated_count:    0,
        slot_mask:          0,
        generation:         1,
        is_valid:           true,
        arena:              [],
    }, WireResult.Success;
}

// Resets all resources allocated from the pool (VkResetCommandPool).
fn reset_command_pool(pool: WireCommandPool&, flags: u32) -> WireResult {
    let next_gen = pool.generation + 1;
    guard pool.is_valid else {
        return WireResult.ErrorInitializationFailed;
    }
    pool.allocated_count = 0;
    pool.slot_mask = 0;
    pool.generation = if next_gen == 0 { 1 } else { next_gen };
    pool.arena.clear();
    let _ = flags;
    return WireResult.Success;
}

// Trims unused memory capacity in the command pool (VkTrimCommandPool).
fn trim_command_pool(pool: WireCommandPool&) {
    if pool.allocated_count == 0 {
        pool.slot_mask = 0;
        pool.arena.clear();
    }
}

// Destroys the command pool and invalidates allocations (VkDestroyCommandPool).
fn destroy_command_pool(pool: WireCommandPool&) {
    pool.is_valid = false;
    pool.allocated_count = 0;
    pool.slot_mask = 0;
    pool.generation = 0;
    pool.arena.clear();
}
