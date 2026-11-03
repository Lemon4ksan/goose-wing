// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Vulkan-style Pipeline State Objects (PSO) for explicit wire protocols.
namespace wire;

import std;
import .result;
import .types;
import .cmd;

// Pipeline bind point distinguishing transmission from reception pipelines.
enum WirePipelineBindPoint {
    Transmit,
    Receive,
}

// Pipeline layout defining static protocol limits and push constants (VkPipelineLayout).
struct WirePipelineLayout {
    max_frame_size: u32      = 16384,
    push_constants: u8[..64] = [],
}

// Pipeline creation parameters (VkGraphicsPipelineCreateInfo / VkComputePipelineCreateInfo).
struct WirePipelineCreateInfo {
    bind_point: WirePipelineBindPoint = WirePipelineBindPoint.Transmit,
    layout:     WirePipelineLayout    = WirePipelineLayout { .. },
    flags:      u32                   = 0,
}

// Immutable Pipeline State Object configuring protocol framing and validation (VkPipeline).
struct WirePipeline {
    bind_point: WirePipelineBindPoint = WirePipelineBindPoint.Transmit,
    layout:     WirePipelineLayout    = WirePipelineLayout { .. },
    is_valid:   bool                  = false,
}

// Creates an immutable Pipeline State Object (VkCreateGraphicsPipelines).
fn create_wire_pipeline(
    dev:  const WireDevice&,
    info: const WirePipelineCreateInfo&,
) -> WirePipeline, WireResult {
    guard dev.is_active else {
        return WirePipeline { .. }, WireResult.ErrorInitializationFailed;
    }
    return WirePipeline {
        bind_point: info.bind_point,
        layout:     info.layout,
        is_valid:   true,
    }, WireResult.Success;
}

// Binds a Pipeline State Object to the command buffer (VkCmdBindPipeline).
fn cmd_bind_pipeline(
    cmd:        WireCommandBuffer&,
    bind_point: WirePipelineBindPoint,
    pipe:       const WirePipeline&,
) -> WireResult {
    guard cmd.state == WireCommandBufferState.Recording else {
        cmd.has_error = true;
        return WireResult.ErrorCommandNotRecording;
    }
    guard pipe.is_valid && pipe.bind_point == bind_point else {
        cmd.has_error = true;
        return WireResult.ErrorInitializationFailed;
    }
    return WireResult.Success;
}

// Destroys a pipeline object and releases its configuration (VkDestroyPipeline).
fn destroy_wire_pipeline(pipe: WirePipeline&) {
    pipe.is_valid = false;
}
