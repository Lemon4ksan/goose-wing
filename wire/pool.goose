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

// Fixed-capacity wire scratch buffer pool for scoped `@contextmanager` slot leases.
struct WireBufferPool {
    slot_mask:       u8      = 0,
    allocated_count: u32     = 0,
    is_valid:        bool    = true,
    buffers:         u8[..4] = [],
}

inline fn find_free_wire_slot(slot_mask: u8) -> i32, i64, u8 {
    if (slot_mask & 1) == 0 {
        return 0, 16384, 1;
    }
    if (slot_mask & 2) == 0 {
        return 1, 32768, 2;
    }
    if (slot_mask & 4) == 0 {
        return 2, 49152, 4;
    }
    if (slot_mask & 8) == 0 {
        return 3, 65536, 8;
    }
    return -1, 0, 0;
}

inline fn wire_slot_bit(idx: i32) -> u8 {
    if idx == 0 {
        return 1;
    }
    if idx == 1 {
        return 2;
    }
    if idx == 2 {
        return 4;
    }
    if idx == 3 {
        return 8;
    }
    return 0;
}

inline fn wire_slot_arena_bounds(idx: i32) -> i64, i64 {
    if idx == 0 {
        return 0, 16384;
    }
    if idx == 1 {
        return 16384, 32768;
    }
    if idx == 2 {
        return 32768, 49152;
    }
    return 49152, 65536;
}

// Acquires a 16 KiB buffer slot index (`0..3`) from `pool`.
fn acquire_buffer(pool: WireCommandPool&) -> i32, WireResult {
    guard pool.is_valid else {
        return -1, WireResult.ErrorInitializationFailed;
    }
    let idx, req_len, bit = find_free_wire_slot(pool.slot_mask);
    guard bit != 0 else {
        return -1, WireResult.ErrorOutOfDeviceMemory;
    }
    pool.slot_mask = pool.slot_mask | bit;
    pool.allocated_count = popcount(pool.slot_mask) as u32;
    if pool.arena.len < req_len {
        pool.arena.resize(req_len, 0);
    }
    return idx, WireResult.Success;
}

// Releases a leased buffer slot index (`0..3`) back to `pool`.
fn release_buffer(pool: WireCommandPool&, idx: i32) {
    let bit = wire_slot_bit(idx);
    guard pool.is_valid && bit != 0 && (pool.slot_mask & bit) != 0 else { return; }
    pool.slot_mask = pool.slot_mask & (~bit);
    pool.allocated_count = popcount(pool.slot_mask) as u32;
    if pool.allocated_count == 0 {
        pool.arena.clear();
    }
}

// Acquires a scratch buffer slot index (`0..3`) from `pool`.
fn acquire_buffer(pool: WireBufferPool&) -> i32, WireResult {
    guard pool.is_valid else {
        return -1, WireResult.ErrorInitializationFailed;
    }
    let idx, _, bit = find_free_wire_slot(pool.slot_mask);
    guard bit != 0 else {
        return -1, WireResult.ErrorOutOfDeviceMemory;
    }
    pool.slot_mask = pool.slot_mask | bit;
    pool.allocated_count = popcount(pool.slot_mask) as u32;
    if pool.buffers.len < 4 {
        pool.buffers.resize(4, 0);
    }
    return idx, WireResult.Success;
}

// Releases a leased scratch buffer slot index (`0..3`) back to `pool`.
fn release_buffer(pool: WireBufferPool&, idx: i32) {
    let bit = wire_slot_bit(idx);
    guard pool.is_valid && bit != 0 && (pool.slot_mask & bit) != 0 else { return; }
    pool.slot_mask = pool.slot_mask & (~bit);
    pool.allocated_count = popcount(pool.slot_mask) as u32;
    if pool.allocated_count == 0 {
        pool.buffers.clear();
    }
}

// Acquires a buffer slot from `pool`, invokes `F(idx)` with the acquired slot index,
// and guarantees `release_buffer(pool, idx)` via `defer` on all exit paths.
inline fn with_wire_buffer<F>(pool: WireBufferPool&) -> bool {
    let idx, res = acquire_buffer(pool);
    guard res == WireResult.Success && idx >= 0 else { return false; }
    defer release_buffer(pool, idx);
    F(idx);
    return true;
}

// Acquires a 16 KiB arena slot from `pool`, invokes `F(idx)` with the slot index,
// and guarantees `release_buffer(pool, idx)` via `defer` on all exit paths.
inline fn with_wire_buffer<F>(pool: WireCommandPool&) -> bool {
    let idx, res = acquire_buffer(pool);
    guard res == WireResult.Success && idx >= 0 else { return false; }
    defer release_buffer(pool, idx);
    F(idx);
    return true;
}

// Scoped `@contextmanager` helper that leases a 16 KiB arena slice from `pool`,
// invokes `F(slice)`, and guarantees `release_buffer(pool, idx)` via `defer` on all exit paths.
inline fn with_pool_buffer<F>(pool: WireCommandPool&) -> bool {
    return with_wire_buffer(pool) { idx =>
        let start, end = wire_slot_arena_bounds(idx);
        F(pool.arena[start..end]);
    };
}

// Allocates an explicit WireCommandPool from the logical device.
fn create_command_pool(
    dev:  const WireDevice&,
    info: const WireCommandPoolCreateInfo&,
) -> WireCommandPool, WireResult {
    guard dev.is_active else {
        return WireCommandPool { .. }, WireResult.ErrorInitializationFailed;
    }
    var scratch = WireBufferPool { .. };
    let scratch_ok = with_wire_buffer(scratch) { idx =>
        scratch.buffers[idx] = 0;
    };
    guard scratch_ok else {
        return WireCommandPool { .. }, WireResult.ErrorInitializationFailed;
    }
    var pool = WireCommandPool {
        flags:              info.flags,
        queue_family_index: info.queue_family_index,
        allocated_count:    0,
        slot_mask:          0,
        generation:         1,
        is_valid:           true,
        arena:              [],
    };
    let pool_ok = with_pool_buffer(pool) { buf =>
        buf[0] = 0;
    };
    guard pool_ok else {
        return WireCommandPool { .. }, WireResult.ErrorInitializationFailed;
    }
    return pool, WireResult.Success;
}

// Resets all resources allocated from the pool (VkResetCommandPool).
fn reset_command_pool(pool: WireCommandPool&, flags: u32) -> WireResult {
    let next_gen = pool.generation + 1;
    guard pool.is_valid else {
        return WireResult.ErrorInitializationFailed;
    }
    pool.allocated_count = 0;
    pool.slot_mask = 0;
    pool.generation = max(next_gen, 1);
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
