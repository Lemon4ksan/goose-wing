// Layer 4 Transport Driver types, capabilities, and configurations.
namespace wing;

import std;
import os;

// ---- 1. Driver Kinds & Capabilities ----------------------------------------

enum TransportDriverKind {
    Auto,
    Standard,
    IoUring,
    WindowsRIO,
    Kqueue,
    AfXdp,
    Dpdk,
    SmartNicOffload,
}

// Returns human-readable driver identifier
fn driver_kind_name(kind: TransportDriverKind) -> u8[:] {
    return match kind {
        Auto => "Auto",
        Standard => "Standard",
        IoUring => "io_uring",
        WindowsRIO => "Windows RIO",
        Kqueue => "kqueue",
        AfXdp => "AF_XDP (XSK Kernel-Bypass)",
        Dpdk => "DPDK (Poll Mode Driver)",
        SmartNicOffload => "SmartNIC (Hardware kTLS Offload)",
    };
}

// Driver capability bitmask flags
const CAP_NONE: u32                = 0;
const CAP_KERNEL_BYPASS: u32       = 1 << 0; // Direct hardware/kernel bypass rings
const CAP_ZERO_COPY: u32           = 1 << 1; // Zero copy between userspace and NIC/kernel
const CAP_RING_COMPLETION: u32     = 1 << 2; // Circular submission/completion ring queues
const CAP_BATCH_IO: u32            = 1 << 3; // Batched syscall submission / CQ reaping
const CAP_PAGE_LOCKED_BUFFERS: u32 = 1 << 4; // Pre-registered pinned virtual memory
const CAP_DIRECT_DESCRIPTORS: u32  = 1 << 5; // Fixed socket table without fd lookup overhead
const CAP_MULTISHOT_RECV: u32      = 1 << 6; // Repeated receive events on single submission
const CAP_EXACT_BUF_METRICS: u32   = 1 << 7; // Kernel reports exact unread bytes in buffer
const CAP_NIC_TLS_OFFLOAD: u32     = 1 << 8; // SmartNIC hardware TLS crypto offload (kTLS / Mellanox / BlueField)
const CAP_AF_XDP_UMEM: u32         = 1 << 9; // Linux AF_XDP zero-copy UMEM ring buffer
const CAP_DPDK_PMD: u32            = 1 << 10; // DPDK Poll Mode Driver (PCIe BAR ring)

// Transport driver error status codes
const ERR_SUCCESS: i32             = 0;
const ERR_ENOSYS: i32              = -38; // POSIX ENOSYS: function not implemented

// Default buffer and queue sizing
const DEFAULT_RING_SIZE: u32              = 1024;
const DEFAULT_REGISTERED_BUFFER_SIZE: u32 = 65536;

// Checks if a capability bit is enabled
fn driver_has_cap(caps: u32, cap: u32) -> bool {
    return (caps & cap) != 0;
}

// ---- 2. Target Platform Probing --------------------------------------------

enum TargetPlatform {
    Windows,
    Linux,
    Darwin,
    Unknown,
}

fn platform_name(plat: TargetPlatform) -> u8[:] {
    return match plat {
        Windows => "Windows",
        Linux => "Linux",
        Darwin => "macOS",
        Unknown => "Unknown",
    };
}

// Detects the underlying OS platform via system environment indicators
fn detect_target_platform() -> TargetPlatform {
    var env_buf: u8[>..] = [];
    if env("WINDIR", env_buf) || env("OS", env_buf) {
        return TargetPlatform.Windows;
    }
    env_buf.clear();
    if env("DYLD_LIBRARY_PATH", env_buf) {
        return TargetPlatform.Darwin;
    }
    return TargetPlatform.Linux;
}

// Probe result for a transport driver
struct DriverProbeResult {
    kind: TransportDriverKind = TransportDriverKind.Standard,
    available: bool = true,
    capabilities: u32 = CAP_NONE,
    error_code: i32 = 0,
    reason: u8[..128] = [],
}

// Transport driver configuration
struct TransportDriverConfig {
    preferred_kind: TransportDriverKind = TransportDriverKind.Standard,
    ring_size: u32 = DEFAULT_RING_SIZE,
    enable_kernel_bypass: bool = false,
    registered_buffer_size: u32 = DEFAULT_REGISTERED_BUFFER_SIZE,
    active_kind: TransportDriverKind = TransportDriverKind.Standard,
    capabilities: u32 = CAP_NONE,
    is_probed: bool = false,
    status_message: u8[..128] = [],
}
