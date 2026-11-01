# `net/driver`

Package `net/driver` houses the internal hardware-accelerated and kernel-bypass network drivers for `goose-wing`. It powers the event reactor (`net/poller.goose`) by auto-probing and dynamically binding to the highest-performance I/O backend supported by the host operating system and network interface.

## Supported Drivers

| Driver | Target Platform | Architecture | Capability Bits |
| :--- | :--- | :--- | :--- |
| **Standard** | Cross-platform | POSIX `poll()` / Windows `WSAPoll()` | Standard non-blocking multiplexing |
| **IoUring** | Linux $\ge 5.1$ | Kernel SQ/CQ asynchronous submission rings | Zero-copy send/recv, multishot accept |
| **Kqueue** | macOS / FreeBSD | Mach kevent event notification | Zero-overhead timer and socket events |
| **WindowsRio** | Windows 8+ / Server 2012+ | Registered I/O (RIO) pre-pinned buffers | Zero-copy user-space ring queues |
| **AfXdp** | Linux $\ge 4.18$ | XDP (eXpress Data Path) kernel-bypass | Direct NIC frame transmission via UMEM |
| **Dpdk** | Linux user-space | Data Plane Development Kit PMD drivers | 100GbE line-rate lockless mempool |
| **SmartNic** | Linux / Windows | Mellanox ConnectX / BlueField hardware offload | Hardware kTLS wire encryption offload |

## Driver API Reference (`namespace internal;`)

```goose
enum TransportDriverKind {
    Standard,
    IoUring,
    Kqueue,
    WindowsRio,
    AfXdp,
    Dpdk,
    SmartNic,
}

enum TargetPlatform {
    Windows,
    Linux,
    Darwin,
    Unknown,
}

struct DriverProbeResult {
    kind:         TransportDriverKind = TransportDriverKind.Standard,
    available:    bool                = true,
    capabilities: u32                 = CAP_NONE,
    error_code:   i32                 = 0,
    reason:       u8[..128]           = [],
}

struct TransportDriverConfig {
    preferred_kind:         TransportDriverKind = TransportDriverKind.Standard,
    ring_size:              u32                 = DEFAULT_RING_SIZE,
    enable_kernel_bypass:   bool                = false,
    registered_buffer_size: u32                 = DEFAULT_REGISTERED_BUFFER_SIZE,
    active_kind:            TransportDriverKind = TransportDriverKind.Standard,
}

// Probing and initialization
fn probe_transport_driver(kind: TransportDriverKind) -> DriverProbeResult;
fn init_transport_driver(cfg: TransportDriverConfig&) -> bool;
fn auto_transport_driver_config(enable_bypass: bool = false) -> TransportDriverConfig;

// Platform detection
fn detect_target_platform() -> TargetPlatform;
fn driver_kind_name(kind: TransportDriverKind) -> u8[:];
```
