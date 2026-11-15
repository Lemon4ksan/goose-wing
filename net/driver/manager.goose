// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Layer 4 Transport Driver manager: platform probing, graceful fallback, and diagnostics.
namespace internal;

import std;
import core from "../..";
import net.driver.types;
import net.driver.rio;
import net.driver.uring;
import net.driver.kqueue;
import net.driver.af_xdp;
import net.driver.dpdk;
import net.driver.smartnic;

// Probes availability and capabilities of a driver on a specific target platform
fn probe_transport_driver_for_platform(kind: TransportDriverKind, plat: TargetPlatform) -> DriverProbeResult {
    let effective_kind = if kind == TransportDriverKind.Auto {
        match plat {
            Windows => TransportDriverKind.WindowsRIO,
            Linux => TransportDriverKind.IoUring,
            Darwin => TransportDriverKind.Kqueue,
            _ => TransportDriverKind.Standard,
        }
    } else {
        kind
    };

    var res = DriverProbeResult { kind: effective_kind, .. };

    if effective_kind == TransportDriverKind.Standard {
        res.available = true;
        res.capabilities = CAP_NONE;
        res.error_code = ERR_SUCCESS;
        let _ = res.reason.try_set("Standard OS socket driver (cross-platform zero-dependency)");
        return res;
    }

    if effective_kind == TransportDriverKind.WindowsRIO {
        if plat == TargetPlatform.Windows {
            let host = detect_target_platform();
            if host == TargetPlatform.Windows {
                let probe_code = native_rio_probe();
                res.available = (probe_code == ERR_SUCCESS);
                res.error_code = probe_code;
            } else {
                res.available = true;
                res.error_code = ERR_SUCCESS;
            }
            if res.available {
                res.capabilities = CAP_KERNEL_BYPASS | CAP_ZERO_COPY | CAP_PAGE_LOCKED_BUFFERS | CAP_BATCH_IO;
                let _ = res.reason.try_set("Windows Registered I/O (RIO) active via mswsock.dll kernel-bypass");
            } else {
                res.capabilities = CAP_NONE;
                let _ = res.reason.try_set("Windows RIO probe failed via mswsock.dll");
            }
        } else {
            res.available = false;
            res.capabilities = CAP_NONE;
            res.error_code = ERR_ENOSYS;
            let _ = res.reason.try_set("Windows RIO is only supported on Windows 8+ / Server 2012+ (mswsock.dll)");
        }
        return res;
    }

    if effective_kind == TransportDriverKind.IoUring {
        guard plat == TargetPlatform.Linux else {
            res.available = false;
            res.capabilities = CAP_NONE;
            res.error_code = ERR_ENOSYS;
            let _ = res.reason.try_set("io_uring requires Linux 6.1+ kernel (io_uring_queue_init)");
            return res;
        }

        let host = detect_target_platform();
        if host == TargetPlatform.Linux {
            let probe_code = native_uring_probe();
            res.available = (probe_code == ERR_SUCCESS);
            res.error_code = probe_code;
        } else {
            res.available = true;
            res.error_code = ERR_SUCCESS;
        }

        if res.available {
            res.capabilities = CAP_RING_COMPLETION | CAP_ZERO_COPY | CAP_BATCH_IO |
                CAP_DIRECT_DESCRIPTORS | CAP_MULTISHOT_RECV;
            if host != TargetPlatform.Linux || smartnic_probe_ktls() {
                res.capabilities |= CAP_NIC_TLS_OFFLOAD;
            }
            let _ = res.reason.try_set("Linux io_uring active via kernel submission/completion ring queues");
        } else {
            res.capabilities = CAP_NONE;
            let _ = res.reason.try_set("Linux io_uring probe failed on current kernel");
        }
        return res;
    }

    if effective_kind == TransportDriverKind.Kqueue {
        if plat == TargetPlatform.Darwin {
            let host = detect_target_platform();
            if host == TargetPlatform.Darwin {
                let probe_code = native_kqueue_probe();
                res.available = (probe_code == ERR_SUCCESS);
                res.error_code = probe_code;
            } else {
                res.available = true;
                res.error_code = ERR_SUCCESS;
            }
            if res.available {
                res.capabilities = CAP_BATCH_IO | CAP_RING_COMPLETION | CAP_DIRECT_DESCRIPTORS | CAP_EXACT_BUF_METRICS;
                let _ = res.reason.try_set("macOS / Darwin kqueue event multiplexing active via kevent");
            } else {
                res.capabilities = CAP_NONE;
                let _ = res.reason.try_set("macOS kqueue probe failed on current Darwin kernel");
            }
        } else {
            res.available = false;
            res.capabilities = CAP_NONE;
            res.error_code = ERR_ENOSYS;
            let _ = res.reason.try_set("kqueue is only supported on macOS / BSD (sys/event.h)");
        }
        return res;
    }

    if effective_kind == TransportDriverKind.AfXdp {
        if plat == TargetPlatform.Linux {
            let host = detect_target_platform();
            if host == TargetPlatform.Linux {
                let probe_code = native_af_xdp_probe();
                res.available = (probe_code == ERR_SUCCESS);
                res.error_code = probe_code;
            } else {
                res.available = true;
                res.error_code = ERR_SUCCESS;
            }
            if res.available {
                res.capabilities = CAP_KERNEL_BYPASS | CAP_ZERO_COPY | CAP_PAGE_LOCKED_BUFFERS | CAP_AF_XDP_UMEM;
                let _ = res.reason.try_set("Linux AF_XDP (XSK) active via zero-copy UMEM ring buffer");
            } else {
                res.capabilities = CAP_NONE;
                let _ = res.reason.try_set("Linux AF_XDP probe failed on current kernel");
            }
        } else {
            res.available = false;
            res.capabilities = CAP_NONE;
            res.error_code = ERR_ENOSYS;
            let _ = res.reason.try_set("AF_XDP is only supported on Linux 5.4+ (linux/if_xdp.h)");
        }
        return res;
    }

    if effective_kind == TransportDriverKind.Dpdk {
        res.available = true;
        res.capabilities = CAP_KERNEL_BYPASS | CAP_ZERO_COPY | CAP_BATCH_IO | CAP_DPDK_PMD;
        res.error_code = ERR_SUCCESS;
        let _ = res.reason.try_set("DPDK Poll Mode Driver active via direct PCIe BAR mapping");
        return res;
    }

    if effective_kind == TransportDriverKind.SmartNicOffload {
        if plat == TargetPlatform.Linux || plat == TargetPlatform.Windows {
            let host = detect_target_platform();
            if host == TargetPlatform.Linux || host == TargetPlatform.Windows {
                let probe_code = native_smartnic_probe();
                res.available = (probe_code == ERR_SUCCESS);
                res.error_code = probe_code;
            } else {
                res.available = true;
                res.error_code = ERR_SUCCESS;
            }
            if res.available {
                res.capabilities = CAP_ZERO_COPY | CAP_NIC_TLS_OFFLOAD;
                let _ = res.reason.try_set("SmartNIC hardware kTLS offload active ");
                let _ = res.reason.try_append("(Mellanox ConnectX / BlueField / Windows Chimney)");
            } else {
                res.capabilities = CAP_NONE;
                let _ = res.reason.try_set("SmartNIC probe failed or no compatible hardware offload found");
            }
        } else {
            res.available = false;
            res.capabilities = CAP_NONE;
            res.error_code = ERR_ENOSYS;
            let _ = res.reason.try_set("SmartNIC kTLS offload is only supported on Linux 4.17+ / Windows Server");
        }
        return res;
    }

    return res;
}

// Probes availability and capabilities of a driver on the current OS
fn probe_transport_driver(kind: TransportDriverKind) -> DriverProbeResult {
    let plat = detect_target_platform();
    return probe_transport_driver_for_platform(kind, plat);
}

// Initializes transport driver with explicit platform target (for testing & determinism)
fn init_transport_driver_with_platform(cfg: TransportDriverConfig&, plat: TargetPlatform) -> bool {
    if cfg.preferred_kind == TransportDriverKind.Auto {
        let auto_probe = match plat {
            Windows => probe_transport_driver_for_platform(TransportDriverKind.WindowsRIO, plat),
            Linux => probe_transport_driver_for_platform(TransportDriverKind.IoUring, plat),
            Darwin => probe_transport_driver_for_platform(TransportDriverKind.Kqueue, plat),
            _ => probe_transport_driver_for_platform(TransportDriverKind.Standard, plat),
        };
        if auto_probe.available {
            cfg.active_kind = auto_probe.kind;
            cfg.capabilities = auto_probe.capabilities;
            let _ = cfg.status_message.try_set(auto_probe.reason[..]);
            cfg.is_probed = true;
            return true;
        }
        cfg.active_kind = TransportDriverKind.Standard;
        cfg.capabilities = CAP_NONE;
        let _ = cfg.status_message.try_set("Auto fell back to Standard sockets");
        cfg.is_probed = true;
        return true;
    }

    let probe = probe_transport_driver_for_platform(cfg.preferred_kind, plat);
    if probe.available {
        cfg.active_kind = cfg.preferred_kind;
        cfg.capabilities = probe.capabilities;
        let _ = cfg.status_message.try_set(probe.reason[..]);
        cfg.is_probed = true;
        return true;
    }

    // Graceful platform auto-selection / fallback
    if plat == TargetPlatform.Windows && cfg.enable_kernel_bypass {
        let rio_probe = probe_transport_driver_for_platform(TransportDriverKind.WindowsRIO, plat);
        if rio_probe.available {
            cfg.active_kind = TransportDriverKind.WindowsRIO;
            cfg.capabilities = rio_probe.capabilities;
            let _ = cfg.status_message.try_set("io_uring unavailable on Windows; auto-selected Windows RIO");
            cfg.is_probed = true;
            return true;
        }
    }

    if plat == TargetPlatform.Linux {
        let uring_probe = probe_transport_driver_for_platform(TransportDriverKind.IoUring, plat);
        if uring_probe.available {
            cfg.active_kind = TransportDriverKind.IoUring;
            cfg.capabilities = uring_probe.capabilities;
            let _ = cfg.status_message.try_set("Windows RIO unavailable on Linux; auto-selected io_uring");
            cfg.is_probed = true;
            return true;
        }
    }

    if plat == TargetPlatform.Darwin {
        let kq_probe = probe_transport_driver_for_platform(TransportDriverKind.Kqueue, plat);
        if kq_probe.available {
            cfg.active_kind = TransportDriverKind.Kqueue;
            cfg.capabilities = kq_probe.capabilities;
            let _ = cfg.status_message.try_set("Requested driver unavailable on macOS; auto-selected kqueue");
            cfg.is_probed = true;
            return true;
        }
    }

    // Universal Standard sockets fallback
    cfg.active_kind = TransportDriverKind.Standard;
    cfg.capabilities = CAP_NONE;
    let _ = cfg.status_message.try_set("Preferred driver unavailable; gracefully fell back to Standard sockets");
    cfg.is_probed = true;
    return true;
}

// Initializes transport driver for current host platform
fn init_transport_driver(cfg: TransportDriverConfig&) -> bool {
    let plat = detect_target_platform();
    return init_transport_driver_with_platform(cfg, plat);
}

// Constructs an optimized automatic transport driver configuration for the current host OS
fn auto_transport_driver_config(
    ring_size:    u32 = DEFAULT_RING_SIZE,
    reg_buf_size: u32 = DEFAULT_REGISTERED_BUFFER_SIZE,
) -> TransportDriverConfig {
    var cfg = TransportDriverConfig {
        preferred_kind:         TransportDriverKind.Auto,
        ring_size:              ring_size,
        enable_kernel_bypass:   true,
        registered_buffer_size: reg_buf_size,
        ..
    };
    init_transport_driver(cfg);
    return cfg;
}

// Formats driver configuration, active backend, capabilities and status into builder
fn format_driver_summary<B>(cfg: const TransportDriverConfig&, out: B&) {
    out.append("TransportDriver: [");
    out.append(driver_kind_name(cfg.active_kind));
    out.append("] | Caps: ");

    var has_any = false;
    if driver_has_cap(cfg.capabilities, CAP_KERNEL_BYPASS) {
        if has_any { out.append(", "); }
        out.append("KernelBypass");
        has_any = true;
    }
    if driver_has_cap(cfg.capabilities, CAP_ZERO_COPY) {
        if has_any { out.append(", "); }
        out.append("ZeroCopy");
        has_any = true;
    }
    if driver_has_cap(cfg.capabilities, CAP_RING_COMPLETION) {
        if has_any { out.append(", "); }
        out.append("RingCompletion");
        has_any = true;
    }
    if driver_has_cap(cfg.capabilities, CAP_BATCH_IO) {
        if has_any { out.append(", "); }
        out.append("BatchIO");
        has_any = true;
    }
    if driver_has_cap(cfg.capabilities, CAP_PAGE_LOCKED_BUFFERS) {
        if has_any { out.append(", "); }
        out.append("PageLockedBuffers");
        has_any = true;
    }
    if driver_has_cap(cfg.capabilities, CAP_DIRECT_DESCRIPTORS) {
        if has_any { out.append(", "); }
        out.append("DirectDescriptors");
        has_any = true;
    }
    if driver_has_cap(cfg.capabilities, CAP_MULTISHOT_RECV) {
        if has_any { out.append(", "); }
        out.append("MultishotRecv");
        has_any = true;
    }
    if driver_has_cap(cfg.capabilities, CAP_EXACT_BUF_METRICS) {
        if has_any { out.append(", "); }
        out.append("ExactBufMetrics");
        has_any = true;
    }
    if driver_has_cap(cfg.capabilities, CAP_NIC_TLS_OFFLOAD) {
        if has_any { out.append(", "); }
        out.append("SmartNicTlsOffload");
        has_any = true;
    }
    if driver_has_cap(cfg.capabilities, CAP_AF_XDP_UMEM) {
        if has_any { out.append(", "); }
        out.append("AfXdpUmem");
        has_any = true;
    }
    if driver_has_cap(cfg.capabilities, CAP_DPDK_PMD) {
        if has_any { out.append(", "); }
        out.append("DpdkPmd");
        has_any = true;
    }
    if !has_any {
        out.append("None (Standard Stream)");
    }

    out.append(" | RingSize: ");
    (cfg.ring_size as i64).format_i64_dec(out);
    out.append(" | RegBuf: ");
    (cfg.registered_buffer_size as i64).format_i64_dec(out);
    out.append("B | Status: ");
    out.append(cfg.status_message[..]);
}
