// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Vulkan-style typed result codes for explicit wire operations.
namespace wire;

enum WireResult {
    Success,
    NotReady,
    Timeout,
    Incomplete,
    ErrorOutOfHostMemory,
    ErrorOutOfDeviceMemory,
    ErrorInitializationFailed,
    ErrorDeviceLost,
    ErrorInvalidStreamId,
    ErrorFrameTooLarge,
    ErrorCommandRecordingActive,
    ErrorCommandNotRecording,
    ErrorCommandBufferLocked,
    ErrorUnknown,
}

// Returns true if the wire result indicates a non-error completion.
inline fn is_success(r: WireResult) -> bool {
    return r == WireResult.Success;
}

// Returns true if the wire result represents an operational or validation error.
inline fn is_error(r: WireResult) -> bool {
    return match r {
        Success => false,
        NotReady => false,
        Timeout => false,
        Incomplete => false,
        _ => true,
    };
}
