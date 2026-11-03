// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Vulkan-style zero-allocation wire framing primitives and queue configurations.
namespace wire;

import std;
import .result;

// ---- Transport Driver Kinds & Capabilities -------------------------------

enum WireDriverKind {
    Standard,
    WindowsRIO,
    IoUring,
    Kqueue,
    AfXdp,
    Mock,
}

// Low-level socket configuration matching physical device creation parameters.
struct WireDeviceConfig {
    driver:            WireDriverKind = WireDriverKind.Standard,
    tcp_nodelay:       bool           = true,
    tcp_keepalive:     bool           = true,
    has_dont_fragment: bool           = true,
    ip_ttl:            i32            = 64,
    rx_buf_size:       i32            = 65536,
    tx_buf_size:       i32            = 65536,
    wscale:            i32            = 8,
    mss:               i32            = 1460,
}

// ---- HTTP/2 Wire Frame Types (RFC 9113 §6 & RFC 9218 §7.1) ----------------

const H2_FRAME_DATA:            u8 = 0x00;
const H2_FRAME_HEADERS:         u8 = 0x01;
const H2_FRAME_PRIORITY:        u8 = 0x02;
const H2_FRAME_RST_STREAM:      u8 = 0x03;
const H2_FRAME_SETTINGS:        u8 = 0x04;
const H2_FRAME_PUSH_PROMISE:    u8 = 0x05;
const H2_FRAME_PING:            u8 = 0x06;
const H2_FRAME_GOAWAY:          u8 = 0x07;
const H2_FRAME_WINDOW_UPDATE:   u8 = 0x08;
const H2_FRAME_CONTINUATION:    u8 = 0x09;
const H2_FRAME_PRIORITY_UPDATE: u8 = 0x10; // RFC 9218 Section 7.1

// ---- HTTP/2 Wire Flags (RFC 9113 §4.1) -----------------------------------

const H2_FLAG_NONE:        u8 = 0x00;
const H2_FLAG_END_STREAM:  u8 = 0x01;
const H2_FLAG_ACK:         u8 = 0x01;
const H2_FLAG_END_HEADERS: u8 = 0x04;
const H2_FLAG_PADDED:      u8 = 0x08;
const H2_FLAG_PRIORITY:    u8 = 0x20;

// ---- HTTP/2 Setting Identifiers (RFC 9113 §6.5.2 & RFC 9218 §5.1) --------

const H2_SETTING_HEADER_TABLE_SIZE:      u16 = 0x01; // default 4096
const H2_SETTING_ENABLE_PUSH:            u16 = 0x02; // default 1
const H2_SETTING_MAX_CONCURRENT_STREAMS: u16 = 0x03; // unlimited
const H2_SETTING_INITIAL_WINDOW_SIZE:    u16 = 0x04; // default 65535
const H2_SETTING_MAX_FRAME_SIZE:         u16 = 0x05; // default 16384
const H2_SETTING_MAX_HEADER_LIST_SIZE:   u16 = 0x06; // unlimited
const H2_SETTING_ENABLE_CONNECT_PROTO:   u16 = 0x08; // RFC 8441
const H2_SETTING_NO_RFC7540_PRIORITIES:  u16 = 0x09; // RFC 9218 Section 5.1

// Single HTTP/2 setting parameter.
struct WireSetting {
    id:  u16 = 0,
    val: u32 = 0,
}

// Constructs a WireSetting entry without alias overhead.
inline fn h2_setting(setting_id: u16, setting_val: u32) -> WireSetting {
    return WireSetting {
        id:  setting_id,
        val: setting_val,
    };
}

// 9-byte HTTP/2 Binary Frame Header (RFC 9113 Section 4.1).
struct WireFrameHeader {
    length:     u32 = 0, // 24-bit big-endian unsigned
    frame_type: u8  = 0, // 8-bit wire frame type code
    flags:      u8  = 0, // 8-bit type-specific bitmask
    stream_id:  u32 = 0, // 31-bit stream identifier
}

// Client Connection Preface (RFC 9113 Section 3.4).
let H2_CLIENT_PREFACE: const u8[24] = [
    'P', 'R', 'I', ' ', '*', ' ', 'H', 'T', 'T', 'P', '/', '2', '.', '0',
    '\r', '\n', '\r', '\n', 'S', 'M', '\r', '\n', '\r', '\n',
];

// ---- Vulkan Device, Physical Device & Queue Object Hierarchy -------------

// Queue Family Capability Bitmasks (matching VkQueueFlagBits).
const WIRE_QUEUE_TRANSMIT_BIT: u32 = 0x00000001;
const WIRE_QUEUE_RECEIVE_BIT:  u32 = 0x00000002;
const WIRE_QUEUE_BATCH_BIT:    u32 = 0x00000004;

// Properties of a queue family exposed by a physical device.
struct WireQueueFamilyProperties {
    queue_flags: u32 = 0,
    queue_count: u32 = 1,
}

// Physical transport device hardware capabilities and limits.
struct WirePhysicalDeviceProperties {
    device_id:           u32            = 0,
    driver_kind:         WireDriverKind = WireDriverKind.Standard,
    max_buffer_capacity: u64            = 16384,
    max_batch_size:      u32            = 64,
    hardware_checksum:   bool           = false,
    zero_copy_supported: bool           = false,
}

// Fine-grained optional hardware/kernel acceleration features.
struct WirePhysicalDeviceFeatures {
    hpack_compression: bool = true,
    tcp_zero_copy:     bool = false,
    hardware_tls:      bool = false,
    raw_frames:        bool = true,
}

// Physical device representation (VkPhysicalDevice).
struct WirePhysicalDevice {
    properties:   WirePhysicalDeviceProperties = WirePhysicalDeviceProperties { .. },
    features:     WirePhysicalDeviceFeatures   = WirePhysicalDeviceFeatures { .. },
    queue_family: WireQueueFamilyProperties    = WireQueueFamilyProperties { .. },
}

// Root instance context managing physical devices and runtime drivers (VkInstance).
struct WireInstance {
    api_version:       u32 = 0x00400000,
    device_count:      u32 = 1,
    supported_drivers: u32 = 1,
}

// Creation parameters for requesting device queues.
struct WireDeviceQueueCreateInfo {
    queue_family_index: u32 = 0,
    queue_count:        u32 = 1,
}

// Logical device creation info (VkDeviceCreateInfo).
struct WireDeviceCreateInfo {
    config:           WireDeviceConfig           = WireDeviceConfig { .. },
    enabled_features: WirePhysicalDeviceFeatures = WirePhysicalDeviceFeatures { .. },
}

// Logical device handle managing active queues and memory resources (VkDevice).
struct WireDevice {
    physical_device:  WirePhysicalDevice         = WirePhysicalDevice { .. },
    config:           WireDeviceConfig           = WireDeviceConfig { .. },
    enabled_features: WirePhysicalDeviceFeatures = WirePhysicalDeviceFeatures { .. },
    is_active:        bool                       = false,
}

// Creates a logical WireDevice backed by a physical device and requested features.
fn create_wire_device(phys: const WirePhysicalDevice&, info: const WireDeviceCreateInfo&) -> WireDevice, WireResult {
    guard phys.properties.max_buffer_capacity > 0 else {
        return WireDevice { .. }, WireResult.ErrorInitializationFailed;
    }
    return WireDevice {
        physical_device:  phys,
        config:           info.config,
        enabled_features: info.enabled_features,
        is_active:        true,
    }, WireResult.Success;
}

// Releases active logical WireDevice resources.
fn destroy_wire_device(dev: WireDevice&) {
    dev.is_active = false;
}

// Enumerates available physical transport devices associated with the instance.
fn enumerate_physical_devices(inst: const WireInstance&, out: WirePhysicalDevice[..4]&) -> WireResult {
    guard inst.device_count > 0 else {
        return WireResult.ErrorInitializationFailed;
    }
    let default_phys = WirePhysicalDevice {
        properties: WirePhysicalDeviceProperties {
            device_id:           0,
            driver_kind:         WireDriverKind.Standard,
            max_buffer_capacity: 16384,
            max_batch_size:      64,
            hardware_checksum:   false,
            zero_copy_supported: false,
        },
        features: WirePhysicalDeviceFeatures {
            hpack_compression: true,
            tcp_zero_copy:     false,
            hardware_tls:      false,
            raw_frames:        true,
        },
        queue_family: WireQueueFamilyProperties {
            queue_flags: WIRE_QUEUE_TRANSMIT_BIT | WIRE_QUEUE_RECEIVE_BIT | WIRE_QUEUE_BATCH_BIT,
            queue_count: 1,
        },
    };
    guard out.try_push(default_phys) else {
        return WireResult.ErrorOutOfHostMemory;
    }
    return WireResult.Success;
}
