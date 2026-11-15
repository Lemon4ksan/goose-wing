// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Vulkan-style zero-allocation wire framing primitives and queue configurations.
namespace wire;

import std;
import net.driver;
import .result;

// ---- Transport Driver Kinds & Capabilities -------------------------------

enum WireDriverKind {
    Auto,
    Standard,
    WindowsRIO,
    IoUring,
    Kqueue,
    AfXdp,
    Dpdk,
    SmartNicOffload,
    Mock,
}

inline fn map_transport_to_wire_driver(kind: net_internal::TransportDriverKind) -> WireDriverKind {
    return match kind {
        Auto => WireDriverKind.Auto,
        Standard => WireDriverKind.Standard,
        WindowsRIO => WireDriverKind.WindowsRIO,
        IoUring => WireDriverKind.IoUring,
        Kqueue => WireDriverKind.Kqueue,
        AfXdp => WireDriverKind.AfXdp,
        Dpdk => WireDriverKind.Dpdk,
        SmartNicOffload => WireDriverKind.SmartNicOffload,
    };
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
    let plat = net_internal::detect_target_platform();
    let probe = net_internal::probe_transport_driver_for_platform(net_internal::TransportDriverKind.Auto, plat);
    let active_driver = if probe.available {
        map_transport_to_wire_driver(probe.kind)
    } else {
        WireDriverKind.Standard
    };
    let caps = if probe.available { probe.capabilities } else { net_internal::CAP_NONE };
    let has_zero_copy = (caps & net_internal::CAP_ZERO_COPY) != 0;
    let has_hw_tls = (caps & net_internal::CAP_NIC_TLS_OFFLOAD) != 0;
    let has_batch = (caps & net_internal::CAP_BATCH_IO) != 0;
    let q_flags = WIRE_QUEUE_TRANSMIT_BIT | WIRE_QUEUE_RECEIVE_BIT |
        (if has_batch { WIRE_QUEUE_BATCH_BIT } else { 0 });

    let primary_phys = WirePhysicalDevice {
        properties: WirePhysicalDeviceProperties {
            device_id:           0,
            driver_kind:         active_driver,
            max_buffer_capacity: 16384,
            max_batch_size:      64,
            hardware_checksum:   has_hw_tls,
            zero_copy_supported: has_zero_copy,
        },
        features: WirePhysicalDeviceFeatures {
            hpack_compression: true,
            tcp_zero_copy:     has_zero_copy,
            hardware_tls:      has_hw_tls,
            raw_frames:        true,
        },
        queue_family: WireQueueFamilyProperties {
            queue_flags: q_flags,
            queue_count: 1,
        },
    };
    guard out.try_push(primary_phys) else {
        return WireResult.ErrorOutOfHostMemory;
    }
    return WireResult.Success;
}
