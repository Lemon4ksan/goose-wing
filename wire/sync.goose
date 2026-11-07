// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Vulkan Synchronization2 primitives (fences, semaphores, pipeline stages) for wire batches.
namespace wire;

import std;
import .result;
import .types;

// Vulkan Synchronization2 Pipeline Stage Flags (VkPipelineStageFlagBits2).
const WIRE_PIPELINE_STAGE_NONE:         u64 = 0x00000000;
const WIRE_PIPELINE_STAGE_HOST_BIT:     u64 = 0x00000001;
const WIRE_PIPELINE_STAGE_TRANSFER_BIT: u64 = 0x00000002;
const WIRE_PIPELINE_STAGE_SOCKET_BIT:   u64 = 0x00000004;
const WIRE_PIPELINE_STAGE_NIC_TX_BIT:   u64 = 0x00000008;
const WIRE_PIPELINE_STAGE_ALL_COMMANDS: u64 = 0x00000010;

// Current execution state of a wire fence.
enum WireFenceStatus {
    Unsignaled,
    Signaled,
}

// Fence creation flags (VkFenceCreateFlagBits).
const WIRE_FENCE_CREATE_SIGNALED_BIT: u32 = 0x00000001;

// Configuration parameters for creating a fence (VkFenceCreateInfo).
struct WireFenceCreateInfo {
    flags: u32 = 0,
}

// Host-to-device/queue synchronization primitive (VkFence).
struct WireFence {
    status:       WireFenceStatus = WireFenceStatus.Unsignaled,
    signaled_val: u64             = 0,
    is_valid:     bool            = false,
}

// Creates a wire synchronization fence (VkCreateFence).
fn create_wire_fence(dev: const WireDevice&, info: const WireFenceCreateInfo&) -> WireFence, WireResult {
    guard dev.is_active else {
        return WireFence { .. }, WireResult.ErrorInitializationFailed;
    }
    let is_signaled = (info.flags & WIRE_FENCE_CREATE_SIGNALED_BIT) != 0;
    let init_status = if is_signaled {
        WireFenceStatus.Signaled
    } else {
        WireFenceStatus.Unsignaled
    };
    return WireFence {
        status:       init_status,
        signaled_val: if is_signaled { 1 } else { 0 },
        is_valid:     true,
    }, WireResult.Success;
}

// Resets a fence to the unsignaled state (VkResetFences).
fn reset_wire_fence(fence: WireFence&) -> WireResult {
    guard fence.is_valid else {
        return WireResult.ErrorInitializationFailed;
    }
    fence.status = WireFenceStatus.Unsignaled;
    fence.signaled_val = 0;
    return WireResult.Success;
}

// Polls or waits for fence completion (VkWaitForFences).
fn wait_for_wire_fence(fence: const WireFence&, timeout_ns: u64) -> WireResult {
    guard fence.is_valid else {
        return WireResult.ErrorInitializationFailed;
    }
    return if fence.status == WireFenceStatus.Signaled {
        WireResult.Success
    } else {
        WireResult.Timeout
    };
}

// Queries the current status of a fence without blocking (VkGetFenceStatus).
fn get_wire_fence_status(fence: const WireFence&) -> WireResult {
    guard fence.is_valid else {
        return WireResult.ErrorInitializationFailed;
    }
    return if fence.status == WireFenceStatus.Signaled {
        WireResult.Success
    } else {
        WireResult.NotReady
    };
}

// Destroys a wire synchronization fence (VkDestroyFence).
fn destroy_wire_fence(fence: WireFence&) {
    fence.is_valid = false;
    fence.status = WireFenceStatus.Unsignaled;
    fence.signaled_val = 0;
}

// Type classification for synchronization semaphores (VkSemaphoreType).
enum WireSemaphoreType {
    Binary,
    Timeline,
}

// Configuration parameters for creating a semaphore (VkSemaphoreCreateInfo).
struct WireSemaphoreCreateInfo {
    semaphore_type: WireSemaphoreType = WireSemaphoreType.Binary,
    initial_value:  u64               = 0,
}

// Inter-queue and batch synchronization primitive (VkSemaphore).
struct WireSemaphore {
    semaphore_type: WireSemaphoreType = WireSemaphoreType.Binary,
    value:          u64               = 0,
    is_valid:       bool              = false,
}

// Creates a binary or timeline semaphore (VkCreateSemaphore).
fn create_wire_semaphore(
    dev:  const WireDevice&,
    info: const WireSemaphoreCreateInfo&,
) -> WireSemaphore, WireResult {
    guard dev.is_active else {
        return WireSemaphore { .. }, WireResult.ErrorInitializationFailed;
    }
    return WireSemaphore {
        semaphore_type: info.semaphore_type,
        value:          info.initial_value,
        is_valid:       true,
    }, WireResult.Success;
}

// Signals a semaphore to target value (VkSignalSemaphore).
fn signal_wire_semaphore(sem: WireSemaphore&, val: u64) -> WireResult {
    guard sem.is_valid else {
        return WireResult.ErrorInitializationFailed;
    }
    if sem.semaphore_type == WireSemaphoreType.Timeline && val < sem.value {
        return WireResult.ErrorInitializationFailed;
    }
    sem.value = val;
    return WireResult.Success;
}

// Queries or waits for semaphore to reach or exceed target value (VkWaitSemaphores).
fn wait_wire_semaphore(sem: const WireSemaphore&, val: u64) -> WireResult {
    guard sem.is_valid else {
        return WireResult.ErrorInitializationFailed;
    }
    return if sem.value >= val {
        WireResult.Success
    } else {
        WireResult.Timeout
    };
}

// Destroys a wire semaphore (VkDestroySemaphore).
fn destroy_wire_semaphore(sem: WireSemaphore&) {
    sem.is_valid = false;
    sem.value = 0;
}

// Batch queue submission info with synchronization barriers (VkSubmitInfo2).
struct WireSubmitInfo {
    stage_mask:       u64 = WIRE_PIPELINE_STAGE_ALL_COMMANDS,
    wait_semaphore:   u64 = 0,
    signal_semaphore: u64 = 0,
    bytes_submitted:  u64 = 0,
}
