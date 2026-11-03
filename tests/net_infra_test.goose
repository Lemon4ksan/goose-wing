// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Consolidated Verification Suite: Network Transport Drivers, Connection Pool, and Poller Suite
//
// RUN: goose build -o %t.exe %s
// RUN: %t.exe
import std;
import core from "..";
import wing from "..";
import lit from "github.com/Lemon4ksan/goose-lit@v0.1.0";

// --- Component: net_transport_driver ---
// Verification suite for Layer 4 Transport Driver Architecture (net/driver.goose):
// - Platform probing across Windows, Linux, and macOS
// - Driver capability bitmasks (KernelBypass, ZeroCopy, RingCompletion, BatchIO, ExactBufMetrics)
// - Graceful auto-selection and fallback handling across the Big Three (RIO, io_uring, kqueue)
// - Windows RIO page-locked zero-copy buffer lifecycle
// - Linux io_uring SQE/CQE batch submission and ring state tracking
// - macOS / Darwin kqueue event multiplexing (struct kevent, byte-accurate accounting, EOF detection)
// - Diagnostic summary string formatting

fn test_driver_probing(t: lit::T&) {
    t.run("Standard Driver Probing (Universal)") { sub =>
        let p_win = internal::probe_transport_driver_for_platform(internal::TransportDriverKind.Standard, internal::TargetPlatform.Windows);
        sub.assert_true(p_win.available, "Standard available on Windows");
        sub.assert_eq(p_win.error_code, internal::ERR_SUCCESS, "Standard error code 0 on Windows");

        let p_linux = internal::probe_transport_driver_for_platform(internal::TransportDriverKind.Standard, internal::TargetPlatform.Linux);
        sub.assert_true(p_linux.available, "Standard available on Linux");
        sub.assert_eq(p_linux.error_code, internal::ERR_SUCCESS, "Standard error code 0 on Linux");

        let p_mac = internal::probe_transport_driver_for_platform(internal::TransportDriverKind.Standard, internal::TargetPlatform.Darwin);
        sub.assert_true(p_mac.available, "Standard available on macOS");
        sub.assert_eq(p_mac.error_code, internal::ERR_SUCCESS, "Standard error code 0 on macOS");
    };

    t.run("Windows RIO Probing") { sub =>
        let p_win = internal::probe_transport_driver_for_platform(internal::TransportDriverKind.WindowsRIO, internal::TargetPlatform.Windows);
        sub.assert_true(p_win.available, "RIO available on Windows");
        sub.assert_eq(p_win.error_code, internal::ERR_SUCCESS, "RIO error code 0 on Windows");
        sub.assert_true(internal::driver_has_cap(p_win.capabilities, internal::CAP_KERNEL_BYPASS), "RIO has KernelBypass");
        sub.assert_true(internal::driver_has_cap(p_win.capabilities, internal::CAP_ZERO_COPY), "RIO has ZeroCopy");
        sub.assert_true(internal::driver_has_cap(p_win.capabilities, internal::CAP_PAGE_LOCKED_BUFFERS), "RIO has PageLockedBuffers");
        sub.assert_true(internal::driver_has_cap(p_win.capabilities, internal::CAP_BATCH_IO), "RIO has BatchIO");

        let p_linux = internal::probe_transport_driver_for_platform(internal::TransportDriverKind.WindowsRIO, internal::TargetPlatform.Linux);
        sub.assert_false(p_linux.available, "RIO unavailable on Linux");
        sub.assert_eq(p_linux.error_code, internal::ERR_ENOSYS, "RIO returns -ENOSYS on Linux");

        let p_mac = internal::probe_transport_driver_for_platform(internal::TransportDriverKind.WindowsRIO, internal::TargetPlatform.Darwin);
        sub.assert_false(p_mac.available, "RIO unavailable on macOS");
        sub.assert_eq(p_mac.error_code, internal::ERR_ENOSYS, "RIO returns -ENOSYS on macOS");
    };

    t.run("Linux io_uring Probing") { sub =>
        let p_linux = internal::probe_transport_driver_for_platform(internal::TransportDriverKind.IoUring, internal::TargetPlatform.Linux);
        sub.assert_true(p_linux.available, "io_uring available on Linux");
        sub.assert_eq(p_linux.error_code, internal::ERR_SUCCESS, "io_uring error code 0 on Linux");
        sub.assert_true(internal::driver_has_cap(p_linux.capabilities, internal::CAP_RING_COMPLETION), "io_uring has RingCompletion");
        sub.assert_true(internal::driver_has_cap(p_linux.capabilities, internal::CAP_ZERO_COPY), "io_uring has ZeroCopy");
        sub.assert_true(internal::driver_has_cap(p_linux.capabilities, internal::CAP_BATCH_IO), "io_uring has BatchIO");
        sub.assert_true(internal::driver_has_cap(p_linux.capabilities, internal::CAP_DIRECT_DESCRIPTORS), "io_uring has DirectDescriptors");
        sub.assert_true(internal::driver_has_cap(p_linux.capabilities, internal::CAP_MULTISHOT_RECV), "io_uring has MultishotRecv");

        let p_win = internal::probe_transport_driver_for_platform(internal::TransportDriverKind.IoUring, internal::TargetPlatform.Windows);
        sub.assert_false(p_win.available, "io_uring unavailable on Windows");
        sub.assert_eq(p_win.error_code, internal::ERR_ENOSYS, "io_uring returns -ENOSYS on Windows");

        let p_mac = internal::probe_transport_driver_for_platform(internal::TransportDriverKind.IoUring, internal::TargetPlatform.Darwin);
        sub.assert_false(p_mac.available, "io_uring unavailable on macOS");
        sub.assert_eq(p_mac.error_code, internal::ERR_ENOSYS, "io_uring returns -ENOSYS on macOS");
    };

    t.run("macOS kqueue Probing") { sub =>
        let p_mac = internal::probe_transport_driver_for_platform(internal::TransportDriverKind.Kqueue, internal::TargetPlatform.Darwin);
        sub.assert_true(p_mac.available, "kqueue available on macOS");
        sub.assert_eq(p_mac.error_code, internal::ERR_SUCCESS, "kqueue error code 0 on macOS");
        sub.assert_true(internal::driver_has_cap(p_mac.capabilities, internal::CAP_BATCH_IO), "kqueue has BatchIO");
        sub.assert_true(internal::driver_has_cap(p_mac.capabilities, internal::CAP_RING_COMPLETION), "kqueue has RingCompletion");
        sub.assert_true(internal::driver_has_cap(p_mac.capabilities, internal::CAP_DIRECT_DESCRIPTORS), "kqueue has DirectDescriptors");
        sub.assert_true(internal::driver_has_cap(p_mac.capabilities, internal::CAP_EXACT_BUF_METRICS), "kqueue has ExactBufMetrics");

        let p_win = internal::probe_transport_driver_for_platform(internal::TransportDriverKind.Kqueue, internal::TargetPlatform.Windows);
        sub.assert_false(p_win.available, "kqueue unavailable on Windows");
        sub.assert_eq(p_win.error_code, internal::ERR_ENOSYS, "kqueue returns -ENOSYS on Windows");

        let p_linux = internal::probe_transport_driver_for_platform(internal::TransportDriverKind.Kqueue, internal::TargetPlatform.Linux);
        sub.assert_false(p_linux.available, "kqueue unavailable on Linux");
        sub.assert_eq(p_linux.error_code, internal::ERR_ENOSYS, "kqueue returns -ENOSYS on Linux");
    };

    t.run("Linux AF_XDP (XSK Kernel-Bypass) Probing") { sub =>
        let p_linux = internal::probe_transport_driver_for_platform(internal::TransportDriverKind.AfXdp, internal::TargetPlatform.Linux);
        sub.assert_true(p_linux.available, "AF_XDP available on Linux target");
        sub.assert_eq(p_linux.error_code, internal::ERR_SUCCESS, "AF_XDP error code 0 on Linux");
        sub.assert_true(internal::driver_has_cap(p_linux.capabilities, internal::CAP_KERNEL_BYPASS), "AF_XDP has KernelBypass");
        sub.assert_true(internal::driver_has_cap(p_linux.capabilities, internal::CAP_ZERO_COPY), "AF_XDP has ZeroCopy");
        sub.assert_true(internal::driver_has_cap(p_linux.capabilities, internal::CAP_PAGE_LOCKED_BUFFERS), "AF_XDP has PageLockedBuffers");
        sub.assert_true(internal::driver_has_cap(p_linux.capabilities, internal::CAP_AF_XDP_UMEM), "AF_XDP has AfXdpUmem");

        let p_win = internal::probe_transport_driver_for_platform(internal::TransportDriverKind.AfXdp, internal::TargetPlatform.Windows);
        sub.assert_false(p_win.available, "AF_XDP unavailable on Windows");
        sub.assert_eq(p_win.error_code, internal::ERR_ENOSYS, "AF_XDP returns -ENOSYS on Windows");

        let p_mac = internal::probe_transport_driver_for_platform(internal::TransportDriverKind.AfXdp, internal::TargetPlatform.Darwin);
        sub.assert_false(p_mac.available, "AF_XDP unavailable on macOS");
        sub.assert_eq(p_mac.error_code, internal::ERR_ENOSYS, "AF_XDP returns -ENOSYS on macOS");
    };

    t.run("DPDK Poll Mode Driver Probing") { sub =>
        let p_linux = internal::probe_transport_driver_for_platform(internal::TransportDriverKind.Dpdk, internal::TargetPlatform.Linux);
        sub.assert_true(p_linux.available, "DPDK PMD available");
        sub.assert_eq(p_linux.error_code, internal::ERR_SUCCESS, "DPDK error code 0");
        sub.assert_true(internal::driver_has_cap(p_linux.capabilities, internal::CAP_KERNEL_BYPASS), "DPDK has KernelBypass");
        sub.assert_true(internal::driver_has_cap(p_linux.capabilities, internal::CAP_ZERO_COPY), "DPDK has ZeroCopy");
        sub.assert_true(internal::driver_has_cap(p_linux.capabilities, internal::CAP_BATCH_IO), "DPDK has BatchIO");
        sub.assert_true(internal::driver_has_cap(p_linux.capabilities, internal::CAP_DPDK_PMD), "DPDK has DpdkPmd");
    };

    t.run("SmartNIC Hardware TLS Offload Probing") { sub =>
        let p_linux = internal::probe_transport_driver_for_platform(internal::TransportDriverKind.SmartNicOffload, internal::TargetPlatform.Linux);
        sub.assert_true(p_linux.available, "SmartNIC available on Linux");
        sub.assert_true(internal::driver_has_cap(p_linux.capabilities, internal::CAP_ZERO_COPY), "SmartNIC has ZeroCopy");
        sub.assert_true(internal::driver_has_cap(p_linux.capabilities, internal::CAP_NIC_TLS_OFFLOAD), "SmartNIC has NicTlsOffload");

        let p_win = internal::probe_transport_driver_for_platform(internal::TransportDriverKind.SmartNicOffload, internal::TargetPlatform.Windows);
        sub.assert_true(p_win.available, "SmartNIC available on Windows");
        sub.assert_true(internal::driver_has_cap(p_win.capabilities, internal::CAP_NIC_TLS_OFFLOAD), "SmartNIC has NicTlsOffload on Windows");

        let p_mac = internal::probe_transport_driver_for_platform(internal::TransportDriverKind.SmartNicOffload, internal::TargetPlatform.Darwin);
        sub.assert_false(p_mac.available, "SmartNIC unavailable on macOS");
        sub.assert_eq(p_mac.error_code, internal::ERR_ENOSYS, "SmartNIC returns -ENOSYS on macOS");
    };
}

fn test_driver_fallback_and_selection(t: lit::T&) {
    t.run("Standard Selection Everywhere") { sub =>
        var cfg = internal::TransportDriverConfig {
            preferred_kind: internal::TransportDriverKind.Standard,
            ..
        };
        sub.assert_true(internal::init_transport_driver_with_platform(cfg, internal::TargetPlatform.Windows), "Init ok on Windows");
        sub.assert_true(cfg.active_kind == internal::TransportDriverKind.Standard, "Active is Standard");
        sub.assert_true(cfg.is_probed, "Is probed");
    };

    t.run("Windows Auto-Selection: io_uring preferred with kernel bypass") { sub =>
        var cfg = internal::TransportDriverConfig {
            preferred_kind:       internal::TransportDriverKind.IoUring,
            enable_kernel_bypass: true,
            ..
        };
        sub.assert_true(internal::init_transport_driver_with_platform(cfg, internal::TargetPlatform.Windows), "Init ok");
        sub.assert_true(cfg.active_kind == internal::TransportDriverKind.WindowsRIO, "Auto-selected WindowsRIO");
        sub.assert_true(internal::driver_has_cap(cfg.capabilities, internal::CAP_KERNEL_BYPASS), "Has KernelBypass");
    };

    t.run("Windows Graceful Fallback: io_uring preferred without bypass") { sub =>
        var cfg = internal::TransportDriverConfig {
            preferred_kind:       internal::TransportDriverKind.IoUring,
            enable_kernel_bypass: false,
            ..
        };
        sub.assert_true(internal::init_transport_driver_with_platform(cfg, internal::TargetPlatform.Windows), "Init ok");
        sub.assert_true(cfg.active_kind == internal::TransportDriverKind.Standard, "Fell back to Standard");
    };

    t.run("Linux Auto-Selection: WindowsRIO preferred") { sub =>
        var cfg = internal::TransportDriverConfig {
            preferred_kind: internal::TransportDriverKind.WindowsRIO,
            ..
        };
        sub.assert_true(internal::init_transport_driver_with_platform(cfg, internal::TargetPlatform.Linux), "Init ok");
        sub.assert_true(cfg.active_kind == internal::TransportDriverKind.IoUring, "Auto-selected io_uring");
        sub.assert_true(internal::driver_has_cap(cfg.capabilities, internal::CAP_RING_COMPLETION), "Has RingCompletion");
    };

    t.run("macOS Auto-Selection: io_uring or WindowsRIO preferred") { sub =>
        var cfg = internal::TransportDriverConfig {
            preferred_kind: internal::TransportDriverKind.IoUring,
            ..
        };
        sub.assert_true(internal::init_transport_driver_with_platform(cfg, internal::TargetPlatform.Darwin), "Init ok");
        sub.assert_true(cfg.active_kind == internal::TransportDriverKind.Kqueue, "Auto-selected kqueue on macOS");
        sub.assert_true(internal::driver_has_cap(cfg.capabilities, internal::CAP_EXACT_BUF_METRICS), "Has ExactBufMetrics");
    };

    t.run("Universal Auto Driver Selection (Windows, Linux, macOS)") { sub =>
        var cfg_win = internal::TransportDriverConfig { preferred_kind: internal::TransportDriverKind.Auto, .. };
        sub.assert_true(internal::init_transport_driver_with_platform(cfg_win, internal::TargetPlatform.Windows), "Auto on Windows ok");
        sub.assert_true(cfg_win.active_kind == internal::TransportDriverKind.WindowsRIO, "Auto Windows activates RIO");

        var cfg_linux = internal::TransportDriverConfig { preferred_kind: internal::TransportDriverKind.Auto, .. };
        sub.assert_true(internal::init_transport_driver_with_platform(cfg_linux, internal::TargetPlatform.Linux), "Auto on Linux ok");
        sub.assert_true(cfg_linux.active_kind == internal::TransportDriverKind.IoUring, "Auto Linux activates io_uring");

        var cfg_mac = internal::TransportDriverConfig { preferred_kind: internal::TransportDriverKind.Auto, .. };
        sub.assert_true(internal::init_transport_driver_with_platform(cfg_mac, internal::TargetPlatform.Darwin), "Auto on macOS ok");
        sub.assert_true(cfg_mac.active_kind == internal::TransportDriverKind.Kqueue, "Auto macOS activates kqueue");

        let auto_cfg = internal::auto_transport_driver_config(2048, 131072);
        sub.assert_true(auto_cfg.is_probed, "Host auto config is probed");
        sub.assert_eq(auto_cfg.ring_size, 2048, "Ring size set");
        sub.assert_eq(auto_cfg.registered_buffer_size, 131072, "Reg buf size set");
    };
}

fn test_rio_buffer_lifecycle(t: lit::T&) {
    t.run("RIO Buffer Registration and Slicing") { sub =>
        var buf = internal::new_rio_buffer(1001, 65536);
        sub.assert_eq(buf.buffer_id, 1001, "Buffer ID matches");
        sub.assert_eq(buf.offset, 0, "Initial offset is 0");
        sub.assert_eq(buf.length, 65536, "Length is 65536");
        sub.assert_true(buf.is_registered, "Buffer is registered");
        sub.assert_true(buf.page_locked, "Buffer is page-locked");

        sub.assert_true(internal::rio_can_zero_copy(buf, 1024), "Can zero-copy 1024B");
        sub.assert_true(internal::rio_can_zero_copy(buf, 65536), "Can zero-copy 65536B");
        sub.assert_false(internal::rio_can_zero_copy(buf, 70000), "Cannot zero-copy 70000B");

        // Sub-slice
        let sub_buf = internal::rio_sub_buffer(buf, 4096, 2048);
        sub.assert_eq(sub_buf.buffer_id, 1001, "Sub-slice keeps buffer ID");
        sub.assert_eq(sub_buf.offset, 4096, "Sub-slice offset is 4096");
        sub.assert_eq(sub_buf.length, 2048, "Sub-slice length is 2048");
        sub.assert_true(sub_buf.is_registered, "Sub-slice is registered");

        // Out of bounds sub-slice
        let oob_buf = internal::rio_sub_buffer(buf, 60000, 10000);
        sub.assert_false(oob_buf.is_registered, "OOB slice fails safely");

        // Deregister
        internal::rio_deregister_buffer(buf);
        sub.assert_false(buf.is_registered, "Buffer deregistered");
        sub.assert_false(buf.page_locked, "Page lock released");
        sub.assert_false(internal::rio_can_zero_copy(buf, 100), "Cannot zero-copy after deregister");
    };

    t.run("Physical Windows RIO Kernel Registration") { sub =>
        if internal::detect_target_platform() == internal::TargetPlatform.Windows {
            let avail = internal::native_rio_available();
            sub.assert_eq(avail, 1, "Native RIO is available in mswsock.dll");
            let probe = internal::native_rio_probe();
            sub.assert_eq(probe, 0, "Native RIO probe succeeds");
        }
    };
}

fn test_uring_sqe_cqe_batch(t: lit::T&) {
    t.run("io_uring SQE Preparation") { sub =>
        var sqe_send = internal::UringSqe { .. };
        internal::uring_prep_send(sqe_send, 42, 0x1000, 2048, 999, true);
        sub.assert_eq(sqe_send.opcode, internal::URING_OP_SEND_ZC, "Send opcode is SEND_ZC");
        sub.assert_eq(sqe_send.fd, 42, "FD matches");
        sub.assert_eq(sqe_send.addr, 0x1000, "Addr matches");
        sub.assert_eq(sqe_send.len, 2048, "Len matches");
        sub.assert_eq(sqe_send.user_data, 999, "Tag matches");

        var sqe_recv = internal::UringSqe { .. };
        internal::uring_prep_recv(sqe_recv, 42, 0x2000, 4096, 1000, true);
        sub.assert_eq(sqe_recv.opcode, internal::URING_OP_RECV, "Recv opcode is RECV");
        sub.assert_eq(sqe_recv.flags, internal::URING_SQE_BUFFER_SELECT, "Multishot buffer select set");

        var sqe_accept = internal::UringSqe { .. };
        internal::uring_prep_accept(sqe_accept, 5, 1001);
        sub.assert_eq(sqe_accept.opcode, internal::URING_OP_ACCEPT, "Accept opcode matches");

        var sqe_cancel = internal::UringSqe { .. };
        internal::uring_prep_cancel(sqe_cancel, 999);
        sub.assert_eq(sqe_cancel.opcode, internal::URING_OP_ASYNC_CANCEL, "Cancel opcode matches");
        sub.assert_eq(sqe_cancel.addr, 999, "Tag to cancel stored in addr");
    };

    t.run("io_uring Batch Submission and CQE Reaping") { sub =>
        var state = internal::new_ring_queue_state(128);
        var sqes: internal::UringSqe[4] = [
            internal::UringSqe { opcode: internal::URING_OP_SEND, len: 512, user_data: 101, .. },
            internal::UringSqe { opcode: internal::URING_OP_SEND_ZC, len: 1024, user_data: 102, .. },
            internal::UringSqe { opcode: internal::URING_OP_RECV, flags: internal::URING_SQE_BUFFER_SELECT, len: 4096, user_data: 103, .. },
            internal::UringSqe { opcode: internal::URING_OP_NOP, len: 0, user_data: 104, .. },
        ];

        var cqes: internal::UringCqe[..32] = [];
        let submitted = internal::uring_submit_batch(state, sqes[..], cqes);
        sub.assert_eq(submitted, 4, "Submitted 4 SQEs");
        sub.assert_eq(cqes.len, 4, "Reaped 4 CQEs");
        sub.assert_eq(state.submissions_total, 4, "State submissions total is 4");
        sub.assert_eq(state.completions_total, 4, "State completions total is 4");

        // Verify CQE contents
        sub.assert_eq(cqes[0].user_data, 101, "CQE 0 tag matches");
        sub.assert_eq(cqes[0].res, 512, "CQE 0 res matches len");
        sub.assert_eq(cqes[1].user_data, 102, "CQE 1 tag matches");
        sub.assert_eq(cqes[1].res, 1024, "CQE 1 res matches len");
        sub.assert_eq(cqes[2].user_data, 103, "CQE 2 tag matches");
        sub.assert_eq(cqes[2].res, 4096, "CQE 2 res matches len");
        sub.assert_true((cqes[2].flags & internal::URING_CQE_F_MORE) != 0, "Multishot CQE has F_MORE flag");
    };
}

fn test_kqueue_event_lifecycle(t: lit::T&) {
    t.run("kqueue Kevent Preparation and Buffer Metrics") { sub =>
        var ev_read = internal::Kevent { .. };
        internal::kevent_prep_read(ev_read, 12, 501, true);
        sub.assert_eq(ev_read.ident, 12, "Read ident is fd 12");
        sub.assert_eq(ev_read.filter, internal::EVFILT_READ, "Filter is EVFILT_READ");
        sub.assert_true((ev_read.flags & internal::EV_CLEAR) != 0, "Edge-triggered EV_CLEAR is set");
        sub.assert_eq(ev_read.udata, 501, "udata matches tag 501");

        var ev_write = internal::Kevent { .. };
        internal::kevent_prep_write(ev_write, 14, 502, false);
        sub.assert_eq(ev_write.ident, 14, "Write ident is fd 14");
        sub.assert_eq(ev_write.filter, internal::EVFILT_WRITE, "Filter is EVFILT_WRITE");
        sub.assert_false((ev_write.flags & internal::EV_CLEAR) != 0, "Level-triggered EV_CLEAR not set");

        var ev_timer = internal::Kevent { .. };
        internal::kevent_prep_timer(ev_timer, 99, 250, 503);
        sub.assert_eq(ev_timer.ident, 99, "Timer ident is 99");
        sub.assert_eq(ev_timer.filter, internal::EVFILT_TIMER, "Filter is EVFILT_TIMER");
        sub.assert_eq(ev_timer.data, 250, "Timer period is 250ms");

        // Test exact buffer metrics
        ev_read.data = 16384;
        sub.assert_eq(internal::kevent_bytes_available(ev_read), 16384, "Exact 16384 bytes available in kernel buffer");

        // Test EOF flag
        sub.assert_false(internal::kevent_is_eof(ev_read), "Not EOF yet");
        ev_read.flags |= internal::EV_EOF;
        sub.assert_true(internal::kevent_is_eof(ev_read), "EOF flag detected cleanly");
    };
}

fn test_driver_summary_formatter(t: lit::T&) {
    t.run("Summary String Formatting") { sub =>
        var cfg_rio = internal::TransportDriverConfig {
            preferred_kind:         internal::TransportDriverKind.WindowsRIO,
            ring_size:              2048,
            registered_buffer_size: 131072,
            ..
        };
        internal::init_transport_driver_with_platform(cfg_rio, internal::TargetPlatform.Windows);

        var summary_buf: u8[>..] = [];
        internal::format_driver_summary(cfg_rio, summary_buf);

        sub.assert_true(summary_buf.len > 0, "Summary buffer is not empty");
        sub.assert_contains(summary_buf[..], "Windows RIO", "Contains Windows RIO");
        sub.assert_contains(summary_buf[..], "KernelBypass", "Contains KernelBypass");
        sub.assert_contains(summary_buf[..], "ZeroCopy", "Contains ZeroCopy");
        sub.assert_contains(summary_buf[..], "2048", "Contains ring size 2048");
        sub.assert_contains(summary_buf[..], "131072B", "Contains buffer size 131072B");

        var cfg_kq = internal::TransportDriverConfig {
            preferred_kind: internal::TransportDriverKind.Kqueue,
            ..
        };
        internal::init_transport_driver_with_platform(cfg_kq, internal::TargetPlatform.Darwin);
        summary_buf.clear();
        internal::format_driver_summary(cfg_kq, summary_buf);
        sub.assert_contains(summary_buf[..], "kqueue", "Contains kqueue");
        sub.assert_contains(summary_buf[..], "ExactBufMetrics", "Contains ExactBufMetrics");
        sub.assert_contains(summary_buf[..], "BatchIO", "Contains BatchIO");

        var cfg_std = internal::TransportDriverConfig {
            preferred_kind: internal::TransportDriverKind.Standard,
            ..
        };
        internal::init_transport_driver_with_platform(cfg_std, internal::TargetPlatform.Linux);
        summary_buf.clear();
        internal::format_driver_summary(cfg_std, summary_buf);
        sub.assert_contains(summary_buf[..], "Standard", "Contains Standard");
        sub.assert_contains(summary_buf[..], "None (Standard Stream)", "Contains None");
    };
}

fn test_af_xdp_and_dpdk_kernel_bypass(t: lit::T&) {
    t.run("AF_XDP UMEM Descriptor Lifecycle") { sub =>
        var umem = internal::AfXdpUmem {
            addr:          0x10000000,
            len:           8388608, // 8 MB UMEM
            chunk_size:    2048,
            headroom:      0,
            is_registered: true,
        };
        sub.assert_true(umem.is_registered, "UMEM registered");
        sub.assert_eq(umem.chunk_size, 2048, "Chunk size is 2048 bytes");

        // Verify XdpDesc packet descriptor
        var desc = internal::XdpDesc {
            addr:    0x10000800,
            len:     1460, // MSS payload
            options: 0,
        };
        sub.assert_eq(desc.addr, 0x10000800, "Packet buffer offset mapped");
        sub.assert_eq(desc.len, 1460, "Packet length 1460 bytes");
    };

    t.run("DPDK Port and Mempool Interface") { sub =>
        var dev = internal::new_dpdk_device(0);
        sub.assert_false(dev.is_initialized, "starts uninitialized");

        var pcfg = internal::DpdkPortConfig {
            port_id:      0,
            rx_queues:    4,
            tx_queues:    4,
            rx_ring_size: 1024,
            tx_ring_size: 1024,
            promiscuous:  true,
        };
        let init_res = internal::dpdk_init_port(dev, pcfg);
        sub.assert_eq(init_res, 0, "dpdk_init_port succeeded");
        sub.assert_true(dev.is_initialized, "dev is initialized");

        let start_res = internal::dpdk_start_port(dev);
        sub.assert_eq(start_res, 0, "dpdk_start_port succeeded");
        sub.assert_true(dev.is_started, "dev is started and polling NIC BAR");

        let pool = internal::dpdk_create_mempool(4096, 2048);
        sub.assert_true(pool.is_created, "mempool created");
        sub.assert_eq(pool.n_elements, 4096, "4096 packet mbufs");

        internal::dpdk_stop_port(dev);
        sub.assert_false(dev.is_started, "dev stopped cleanly");
    };
}

fn test_smartnic_ktls_offload(t: lit::T&) {
    t.run("SmartNIC Hardware Model Identification") { sub =>
        sub.assert_contains(internal::smartnic_model_name(internal::SmartNicModel.MellanoxConnectX6Dx), "Mellanox ConnectX-6", "Identified CX-6 Dx");
        sub.assert_contains(internal::smartnic_model_name(internal::SmartNicModel.NvidiaBlueField3), "NVIDIA BlueField-3", "Identified BlueField-3 DPU");
        sub.assert_contains(internal::smartnic_model_name(internal::SmartNicModel.IntelMountEvans), "Intel Mount Evans", "Identified Mount Evans IPU");
    };

    t.run("SmartNIC AES-GCM-128 / 256 Key Offload Configuration") { sub =>
        let tx_key:  u8[16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let tx_iv:   u8[4]  = [0xA1, 0xB2, 0xC3, 0xD4];
        let tx_salt: u8[4]  = [0xE5, 0xF6, 0x07, 0x18];
        let tx_seq:  u8[8]  = [0, 0, 0, 0, 0, 0, 0, 1];

        let rx_key:  u8[16] = [17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32];
        let rx_iv:   u8[4]  = [0x1A, 0x2B, 0x3C, 0x4D];
        let rx_salt: u8[4]  = [0x5E, 0x6F, 0x70, 0x81];
        let rx_seq:  u8[8]  = [0, 0, 0, 0, 0, 0, 0, 1];

        // Attach to socket (dummy fd = 100 for test) with separate TX and RX contexts
        let sess, err = internal::smartnic_attach_hardware_tls(
            100,
            internal::SmartNicCipherSuite.AesGcm128,
            tx_key[..],
            tx_iv[..],
            tx_salt[..],
            tx_seq[..],
            rx_key[..],
            rx_iv[..],
            rx_salt[..],
            rx_seq[..],
        );
        sub.assert_eq(err, 0, "smartnic_attach_hardware_tls succeeded");
        sub.assert_true(sess.ktls_active, "kTLS active");
        sub.assert_true(sess.tx_offloaded, "TX offloaded");
        sub.assert_true(sess.rx_offloaded, "RX offloaded");
        sub.assert_eq(sess.fd, 100, "Target fd retained");

        // Verify invalid fd rejects immediately with error
        let sess_bad, err_bad = internal::smartnic_attach_hardware_tls(
            -1,
            internal::SmartNicCipherSuite.AesGcm128,
            tx_key[..],
            tx_iv[..],
            tx_salt[..],
            tx_seq[..],
        );
        sub.assert_true(err_bad != 0, "Invalid fd rejects offload");
        sub.assert_false(sess_bad.tx_offloaded, "TX not offloaded on invalid fd");
    };
}

// --- Component: net_pool ---
// Verification suite for net/pool: 5-dimensional PoolKey isolation,
// two-slice WantQueue, liveness health checks, HTTP/2 IP coalescing, soft-cap quotas,
// CVE-2026-94441, CVE-2026-56866, and Go #23427 / #49377 defenses.

fn test_pool_key_dimensions_and_isolation(t: lit::T&) {
    t.run("5-Dimensional PoolKey Exact Match and Partition Isolation") { sub =>
        let nak1 = wing::new_network_anonymization_key("https://a.com", false, 0, 1, 0);
        let nak2 = wing::new_network_anonymization_key("https://a.com", false, 0, 1, 0);
        let nak_cross = wing::new_network_anonymization_key("https://a.com", true, 0, 1, 0);
        let nak_nonce = wing::new_network_anonymization_key("https://a.com", false, 42, 1, 0);
        let nak_part = wing::new_network_anonymization_key("https://a.com", false, 0, 2, 0);
        let nak_worker = wing::new_network_anonymization_key("https://a.com", false, 0, 1, 99);

        sub.assert_true(wing::network_anonymization_key_equals(nak1, nak2), "Identical NAK matches");
        sub.assert_false(wing::network_anonymization_key_equals(nak1, nak_cross), "Cross-site flag isolates partition");
        sub.assert_false(wing::network_anonymization_key_equals(nak1, nak_nonce), "Ephemeral nonce isolates partition");
        sub.assert_false(wing::network_anonymization_key_equals(nak1, nak_part), "Network isolation partition isolates partition");
        sub.assert_false(wing::network_anonymization_key_equals(nak1, nak_worker), "Worker session ID isolates proxy automation workers");

        // Case insensitivity of top frame site
        let nak_upper = wing::new_network_anonymization_key("HTTPS://A.COM", false, 0, 1, 0);
        sub.assert_true(wing::network_anonymization_key_equals(nak1, nak_upper), "Top frame site matches case-insensitively");

        let direct_chain = wing::new_direct_proxy_chain();
        let socks_proxy = wing::new_proxy_server(wing::ProxyScheme.Socks5h, "proxy.local", 1080);
        let socks_chain = wing::new_single_proxy_chain(socks_proxy);
        let http_proxy = wing::new_proxy_server(wing::ProxyScheme.Http, "proxy.local", 8080);
        let http_chain = wing::new_single_proxy_chain(http_proxy);

        let default_policy = wing::TlsAndDnsPolicy { .. };
        var privacy_policy = wing::TlsAndDnsPolicy { .. };
        privacy_policy.privacy_mode = wing::PrivacyMode.Enabled;

        var doh_policy = wing::TlsAndDnsPolicy { .. };
        doh_policy.secure_dns_policy = wing::SecureDnsPolicy.Disable;

        var cert_policy = wing::TlsAndDnsPolicy { .. };
        cert_policy.disable_cert_network_fetches = true;

        var net_policy = wing::TlsAndDnsPolicy { .. };
        net_policy.target_network_id = 999;

        let key1 = wing::new_pool_key(wing::PoolScheme.Https, "api.service.com", 443, direct_chain, nak1, default_policy);
        let key2 = wing::new_pool_key(wing::PoolScheme.Https, "api.service.com", 443, direct_chain, nak2, default_policy);
        let key_case = wing::new_pool_key(wing::PoolScheme.Https, "API.SERVICE.COM", 443, direct_chain, nak1, default_policy);
        let key_port = wing::new_pool_key(wing::PoolScheme.Https, "api.service.com", 8443, direct_chain, nak1, default_policy);
        let key_scheme = wing::new_pool_key(wing::PoolScheme.Http, "api.service.com", 80, direct_chain, nak1, default_policy);
        let key_h2c = wing::new_pool_key(wing::PoolScheme.H2c, "api.service.com", 80, direct_chain, nak1, default_policy);
        let key_proxy_socks = wing::new_pool_key(wing::PoolScheme.Https, "api.service.com", 443, socks_chain, nak1, default_policy);
        let key_proxy_http = wing::new_pool_key(wing::PoolScheme.Https, "api.service.com", 443, http_chain, nak1, default_policy);
        let key_priv = wing::new_pool_key(wing::PoolScheme.Https, "api.service.com", 443, direct_chain, nak1, privacy_policy);
        let key_doh = wing::new_pool_key(wing::PoolScheme.Https, "api.service.com", 443, direct_chain, nak1, doh_policy);
        let key_cert = wing::new_pool_key(wing::PoolScheme.Https, "api.service.com", 443, direct_chain, nak1, cert_policy);
        let key_net = wing::new_pool_key(wing::PoolScheme.Https, "api.service.com", 443, direct_chain, nak1, net_policy);

        sub.assert_true(wing::pool_key_equals(key1, key2), "Key1 equals Key2 with identical dimensions");
        sub.assert_true(wing::pool_key_equals(key1, key_case), "Host matches case-insensitively");
        sub.assert_false(wing::pool_key_equals(key1, key_port), "Port mismatch isolates socket group");
        sub.assert_false(wing::pool_key_equals(key1, key_scheme), "Scheme mismatch isolates socket group");
        sub.assert_false(wing::pool_key_equals(key1, key_h2c), "H2c plaintext scheme isolates socket group (CVE-2026-94441)");
        sub.assert_false(wing::pool_key_equals(key_scheme, key_h2c), "Http and H2c schemes are strictly isolated");
        sub.assert_false(wing::pool_key_equals(key1, key_proxy_socks), "Proxy chain mismatch isolates socket group");
        sub.assert_false(wing::pool_key_equals(key_proxy_socks, key_proxy_http), "Different proxy protocols isolated");
        sub.assert_false(wing::pool_key_equals(key1, key_priv), "Privacy mode mismatch isolates socket group");
        sub.assert_false(wing::pool_key_equals(key1, key_doh), "Secure DNS policy mismatch isolates socket group");
        sub.assert_false(wing::pool_key_equals(key1, key_cert), "Cert network fetch flag mismatch isolates socket group");
        sub.assert_false(wing::pool_key_equals(key1, key_net), "Target network ID mismatch isolates socket group");

        let h1 = wing::pool_key_hash(key1);
        let h2 = wing::pool_key_hash(key2);
        let h_case = wing::pool_key_hash(key_case);
        let h_port = wing::pool_key_hash(key_port);
        let h_scheme = wing::pool_key_hash(key_scheme);
        sub.assert_eq(h1, h2, "Identical PoolKey produces identical hash");
        sub.assert_eq(h1, h_case, "Case-folded host produces identical hash");
        sub.assert_ne(h1, h_port, "Port difference changes hash");
        sub.assert_ne(h1, h_scheme, "Scheme difference changes hash");
    };

    t.run("Preconnect Scheme Normalization") { sub =>
        sub.assert_true(wing::normalize_preconnect_scheme(wing::PoolScheme.Ws) == wing::PoolScheme.Http, "WS maps to HTTP");
        sub.assert_true(wing::normalize_preconnect_scheme(wing::PoolScheme.Wss) == wing::PoolScheme.Https, "WSS maps to HTTPS");
        sub.assert_true(wing::normalize_preconnect_scheme(wing::PoolScheme.Http) == wing::PoolScheme.Http, "HTTP preserved");
        sub.assert_true(wing::normalize_preconnect_scheme(wing::PoolScheme.Https) == wing::PoolScheme.Https, "HTTPS preserved");
        sub.assert_true(wing::normalize_preconnect_scheme(wing::PoolScheme.H2c) == wing::PoolScheme.H2c, "H2c preserved");

        sub.assert_true(wing::is_cryptographic_scheme(wing::PoolScheme.Https), "HTTPS is cryptographic");
        sub.assert_true(wing::is_cryptographic_scheme(wing::PoolScheme.Wss), "WSS is cryptographic");
        sub.assert_false(wing::is_cryptographic_scheme(wing::PoolScheme.Http), "HTTP is not cryptographic");
        sub.assert_false(wing::is_cryptographic_scheme(wing::PoolScheme.Ws), "WS is not cryptographic");
        sub.assert_false(wing::is_cryptographic_scheme(wing::PoolScheme.H2c), "H2c is not cryptographic");
    };
}

fn test_want_queue_dual_slice(t: lit::T&) {
    t.run("FIFO Operations and Reallocation-Free Promotion") { sub =>
        var q = wing::WantQueue { .. };
        sub.assert_true(wing::is_queue_empty(q), "Initial queue is empty");
        sub.assert_eq(wing::queue_len(q), 0, "Initial queue len is 0");

        let nak = wing::new_network_anonymization_key("https://origin.io");
        let key = wing::new_pool_key(wing::PoolScheme.Https, "origin.io", 443, wing::new_direct_proxy_chain(), nak, wing::TlsAndDnsPolicy { .. });

        var w1 = wing::WantConn { req_id: 101, .. };
        var w2 = wing::WantConn { req_id: 102, .. };
        var w3 = wing::WantConn { req_id: 103, .. };

        sub.assert_true(wing::push_want(q, w1), "Pushed w1");
        sub.assert_true(wing::push_want(q, w2), "Pushed w2");
        sub.assert_true(wing::push_want(q, w3), "Pushed w3");
        sub.assert_eq(wing::queue_len(q), 3, "Queue len == 3");
        sub.assert_false(wing::is_queue_empty(q), "Queue is not empty");

        let p1, ok1 = wing::pop_want(q);
        sub.assert_true(ok1 && p1.req_id == 101, "Popped w1 in FIFO order");
        sub.assert_eq(wing::queue_len(q), 2, "Queue len == 2 after popping w1");

        // Cancel w2 while still in queue
        sub.assert_true(wing::cancel_want(q, 102), "Cancelled w2");
        sub.assert_false(wing::cancel_want(q, 99999), "Non-existent request ID cancellation returns false");

        let p3, ok3 = wing::pop_want(q);
        sub.assert_true(ok3 && p3.req_id == 103, "Popped w3, skipping cancelled w2");
        sub.assert_eq(wing::queue_len(q), 0, "Queue len == 0 after skipping w2 and popping w3");

        let p_none, ok_none = wing::pop_want(q);
        sub.assert_false(ok_none, "Queue exhausted");
        sub.assert_true(wing::is_queue_empty(q), "Queue is empty when exhausted");
    };

    t.run("Tail-to-Head Compaction Under Sustained Load") { sub =>
        var q = wing::WantQueue { .. };
        let nak = wing::new_network_anonymization_key("https://origin.io");
        let key = wing::new_pool_key(wing::PoolScheme.Https, "origin.io", 443, wing::new_direct_proxy_chain(), nak, wing::TlsAndDnsPolicy { .. });

        // Fill tail slice to maximum capacity (32 items)
        for i in 32 {
            var item = wing::WantConn { req_id: (i + 1) as u64, .. };
            let pushed = wing::push_want(q, item);
            sub.assert_true(pushed, "Pushed item into tail");
        }
        sub.assert_eq(wing::queue_len(q), 32, "Queue filled with 32 items");

        // Pop 16 items: first pop transfers tail into head, then advances head_pos
        for i in 16 {
            let item, ok = wing::pop_want(q);
            sub.assert_true(ok, "Popped item cleanly");
            sub.assert_eq(item.req_id, (i + 1) as u64, "Popped in strictly ascending FIFO order");
        }
        sub.assert_eq(wing::queue_len(q), 16, "16 items remaining in head");

        // Push 16 more items into freshly empty tail slice
        for i in 16 {
            var item = wing::WantConn { req_id: (100 + i) as u64, .. };
            let pushed = wing::push_want(q, item);
            sub.assert_true(pushed, "Pushed into tail slice while head has items");
        }
        sub.assert_eq(wing::queue_len(q), 32, "Queue has 16 in head + 16 in tail = 32 total");

        // Pop remaining 16 from head
        for i in 16 {
            let item, ok = wing::pop_want(q);
            sub.assert_true(ok, "Popped item from head");
            sub.assert_eq(item.req_id, (17 + i) as u64, "Expected head item id");
        }

        // Next pop triggers compaction of tail into head
        let item100, ok100 = wing::pop_want(q);
        sub.assert_true(ok100, "Popped first item from compacted tail");
        sub.assert_eq(item100.req_id, 100, "Compacted tail item preserved FIFO order");
    };
}

fn test_connection_liveness_and_extensive_checks(t: lit::T&) {
    t.run("OkHttp isHealthy and Non-Blocking FIN Detection") { sub =>
        let nak = wing::new_network_anonymization_key("https://example.com");
        let key = wing::new_pool_key(wing::PoolScheme.Https, "example.com", 443, wing::new_direct_proxy_chain(), nak, wing::TlsAndDnsPolicy { .. });

        var conn = wing::PooledConnection {
            conn_id:            1,
            key:                copy(key),
            protocol:           wing::NegotiatedProtocol.Http11,
            active_allocations: 0,
            idle_at_ns:         1000000000, // Idle at 1.0s
            ..
        };

        // Within healthy threshold (500ms idle) -> healthy without extensive checks
        sub.assert_true(wing::is_connection_healthy(conn, 1500000000, false), "Fresh idle connection is healthy");

        // After healthy threshold (2.5s idle) without FIN -> healthy
        sub.assert_true(wing::is_connection_healthy(conn, 3500000000, true), "Idle connection with open socket is healthy");

        // Remote closed socket (FIN received / source_exhausted)
        conn.source_exhausted = true;
        sub.assert_false(wing::is_connection_healthy(conn, 3500000000, true), "Extensive check detects source_exhausted EOF/FIN");
        sub.assert_true(conn.no_new_exchanges, "Connection marked no_new_exchanges on EOF");
        sub.assert_true(conn.closed, "Connection marked closed on EOF");

        // Already closed connection
        sub.assert_false(wing::is_connection_healthy(conn, 3600000000, false), "Closed connection is unhealthy");

        // Remote RST received
        var conn_rst = wing::PooledConnection {
            conn_id:    2,
            key:        copy(key),
            remote_rst: true,
            ..
        };
        sub.assert_false(wing::is_connection_healthy(conn_rst, 2000000000, false), "Connection with remote RST is unhealthy");

        // Marked no_new_exchanges (e.g. Connection: close header received)
        var conn_no_new = wing::PooledConnection {
            conn_id:          3,
            key:              copy(key),
            no_new_exchanges: true,
            ..
        };
        sub.assert_false(wing::is_connection_healthy(conn_no_new, 2000000000, false), "Connection with no_new_exchanges is unhealthy");

        // Active multiplexed streams on HTTP/2 remain healthy while active
        var conn_h2 = wing::PooledConnection {
            conn_id:            4,
            key:                copy(key),
            protocol:           wing::NegotiatedProtocol.Http2,
            active_allocations: 5,
            ..
        };
        sub.assert_true(wing::is_connection_healthy(conn_h2, 5000000000, false), "Active HTTP/2 multiplexed stream is healthy");

        // Idle connection past 90 seconds timeout becomes unhealthy
        var conn_idle_timeout = wing::PooledConnection {
            conn_id:            5,
            key:                copy(key),
            active_allocations: 0,
            idle_at_ns:         1000000000,
            ..
        };
        sub.assert_false(wing::is_connection_healthy(conn_idle_timeout, 96000000000, false), "Connection idle > 90s is unhealthy");
        sub.assert_true(conn_idle_timeout.closed, "Expired idle connection marked closed");
    };
}

fn test_http2_ip_coalescing_and_san_matching(t: lit::T&) {
    t.run("Chromium H2 IP Coalescing with Wildcard SAN & Security Boundaries") { sub =>
        let nak = wing::new_network_anonymization_key("https://example.com");
        let nak_other = wing::new_network_anonymization_key("https://other-site.com");
        let key_a = wing::new_pool_key(wing::PoolScheme.Https, "alpha.example.com", 443, wing::new_direct_proxy_chain(), nak, wing::TlsAndDnsPolicy { .. });
        let key_b = wing::new_pool_key(wing::PoolScheme.Https, "beta.example.com", 443, wing::new_direct_proxy_chain(), nak, wing::TlsAndDnsPolicy { .. });
        let key_deep = wing::new_pool_key(wing::PoolScheme.Https, "sub.beta.example.com", 443, wing::new_direct_proxy_chain(), nak, wing::TlsAndDnsPolicy { .. });
        let key_apex = wing::new_pool_key(wing::PoolScheme.Https, "example.com", 443, wing::new_direct_proxy_chain(), nak, wing::TlsAndDnsPolicy { .. });
        let key_unrelated = wing::new_pool_key(wing::PoolScheme.Https, "other.org", 443, wing::new_direct_proxy_chain(), nak, wing::TlsAndDnsPolicy { .. });
        let key_nak_mismatch = wing::new_pool_key(wing::PoolScheme.Https, "beta.example.com", 443, wing::new_direct_proxy_chain(), nak_other, wing::TlsAndDnsPolicy { .. });
        let key_http_plaintext = wing::new_pool_key(wing::PoolScheme.Http, "beta.example.com", 80, wing::new_direct_proxy_chain(), nak, wing::TlsAndDnsPolicy { .. });

        var conn = wing::PooledConnection {
            conn_id:                10,
            key:                    copy(key_a),
            protocol:               wing::NegotiatedProtocol.Http2,
            max_concurrent_streams: 100,
            active_allocations:     1,
            cert_valid:             true,
            ..
        };
        conn.resolved_ip.append("93.184.216.34");
        var san1: u8[..128] = [];
        san1.append("alpha.example.com");
        conn.san_hosts.push(san1);
        var san_wild: u8[..128] = [];
        san_wild.append("*.example.com");
        conn.san_hosts.push(san_wild);

        // 1. Target beta.example.com resolves to same IP 93.184.216.34 and matches *.example.com SAN
        let can_coalesce_b, is_neg_b = wing::can_coalesce_h2_connection(conn, key_b, "93.184.216.34");
        sub.assert_true(can_coalesce_b, "H2 connection coalesced for beta.example.com under *.example.com");
        sub.assert_false(is_neg_b, "Not a negative IP pool result");

        // 2. Wildcard boundary: multi-level subdomain (*.example.com must NOT match sub.beta.example.com)
        let can_coalesce_deep, is_neg_deep = wing::can_coalesce_h2_connection(conn, key_deep, "93.184.216.34");
        sub.assert_false(can_coalesce_deep, "Wildcard *.example.com does NOT cover multi-level sub.beta.example.com");
        sub.assert_true(is_neg_deep, "Negative IP pool result recorded");

        // 3. Wildcard boundary: apex domain (*.example.com must NOT match example.com)
        let can_coalesce_apex, is_neg_apex = wing::can_coalesce_h2_connection(conn, key_apex, "93.184.216.34");
        sub.assert_false(can_coalesce_apex, "Wildcard *.example.com does NOT cover apex domain example.com");
        sub.assert_true(is_neg_apex, "Negative IP pool result recorded");

        // 4. Target other.org resolves to same IP but SAN does NOT match
        let can_coalesce_other, is_neg_other = wing::can_coalesce_h2_connection(conn, key_unrelated, "93.184.216.34");
        sub.assert_false(can_coalesce_other, "H2 connection rejected for unrelated domain");
        sub.assert_true(is_neg_other, "Recorded negative IP pool result for metric tracking");

        // 5. Partition isolation: NAK mismatch blocks coalescing even if IP and SAN match
        let can_coalesce_nak, is_neg_nak = wing::can_coalesce_h2_connection(conn, key_nak_mismatch, "93.184.216.34");
        sub.assert_false(can_coalesce_nak, "NAK cross-site partition mismatch blocks coalescing");

        // 6. Security invariant CVE-2026-94441: Scheme mismatch blocks coalescing
        let can_coalesce_plain, is_neg_plain = wing::can_coalesce_h2_connection(conn, key_http_plaintext, "93.184.216.34");
        sub.assert_false(can_coalesce_plain, "Plaintext HTTP connection cannot coalesce with HTTPS (CVE-2026-94441)");

        // 7. Invalid certificate: cert_valid = false blocks coalescing
        var conn_bad_cert = copy(conn);
        conn_bad_cert.cert_valid = false;
        let can_coalesce_cert, is_neg_cert = wing::can_coalesce_h2_connection(conn_bad_cert, key_b, "93.184.216.34");
        sub.assert_false(can_coalesce_cert, "Invalid certificate blocks coalescing");
        sub.assert_true(is_neg_cert, "Recorded negative result on invalid certificate");

        // 8. IP mismatch: 93.184.216.34 vs 93.184.216.99
        let can_coalesce_ip, is_neg_ip = wing::can_coalesce_h2_connection(conn, key_b, "93.184.216.99");
        sub.assert_false(can_coalesce_ip, "Different IP address blocks coalescing");
    };
}

fn test_stream_pool_quotas_and_eviction(t: lit::T&) {
    t.run("Soft-Cap LRU Eviction and Priority Reuse") { sub =>
        var pool = wing::new_stream_pool(6, 32, 2); // Soft-cap of 2 connections
        let nak = wing::new_network_anonymization_key("https://service.net");
        let key = wing::new_pool_key(wing::PoolScheme.Https, "service.net", 443, wing::new_direct_proxy_chain(), nak, wing::TlsAndDnsPolicy { .. });

        // Add 2 connections
        let c1 = wing::register_connection(pool, key, wing::NegotiatedProtocol.Http11, "1.1.1.1", 1, 1000000);
        let c2 = wing::register_connection(pool, key, wing::NegotiatedProtocol.Http11, "1.1.1.1", 1, 2000000);

        // Release c1 at t=3.0s, making it idle
        wing::release_connection(pool, c1, 3000000000);
        let grp_idx = pool.find_group_index(key);
        sub.assert_true(grp_idx >= 0, "Group index exists");
        sub.assert_eq(pool.groups[grp_idx].active_conns, 1, "1 active conn in group");
        sub.assert_eq(pool.groups[grp_idx].idle_conns, 1, "1 idle conn in group");

        // Adding 3rd connection exceeds soft-cap (2) -> triggers eviction of oldest idle (c1)
        let c3 = wing::register_connection(pool, key, wing::NegotiatedProtocol.Http11, "1.1.1.1", 1, 4000000);

        sub.assert_true(pool.conns[0].closed, "Oldest idle connection c1 was evicted");
        sub.assert_eq(c3, 3, "New connection c3 registered successfully");

        // OkHttp Priority Rule: acquire_pooled_connection prefers healthy pooled connection
        let acquired_id, ok_acq = wing::acquire_pooled_connection(pool, key, "1.1.1.1", 5000000000);
        // c2 was active with allocation 1, but c3 was active with allocation 1. If we release c2:
        wing::release_connection(pool, c2, 4500000000);
        let acquired_c2, ok_c2 = wing::acquire_pooled_connection(pool, key, "1.1.1.1", 5000000000);
        sub.assert_true(ok_c2 && acquired_c2 == c2, "Reused pooled connection c2 over new dial");

        // Multiple releases do not corrupt active allocations count below 0
        wing::release_connection(pool, c2, 5000000000);
        sub.assert_eq(pool.conns[1].active_allocations, 0, "Active allocations clamped to 0");
    };

    t.run("Active Connections Immune to Soft-Cap Eviction") { sub =>
        var pool = wing::new_stream_pool(6, 32, 2);
        let nak = wing::new_network_anonymization_key("https://busy.net");
        let key = wing::new_pool_key(wing::PoolScheme.Https, "busy.net", 443, wing::new_direct_proxy_chain(), nak, wing::TlsAndDnsPolicy { .. });

        // Register 2 connections and keep both active (active_allocations == 1)
        let c1 = wing::register_connection(pool, key, wing::NegotiatedProtocol.Http11, "2.2.2.2", 1, 1000000);
        let c2 = wing::register_connection(pool, key, wing::NegotiatedProtocol.Http11, "2.2.2.2", 1, 2000000);

        // Neither is released, so both have active_allocations = 1.
        // Registering a 3rd connection exceeds soft-cap (2), but neither can be evicted because both are active!
        let c3 = wing::register_connection(pool, key, wing::NegotiatedProtocol.Http11, "2.2.2.2", 1, 3000000);

        sub.assert_false(pool.conns[0].closed, "Active connection c1 not evicted");
        sub.assert_false(pool.conns[1].closed, "Active connection c2 not evicted");
        sub.assert_eq(c3, 3, "New connection c3 accepted under soft-cap pressure");
    };
}

fn test_cve_2026_56866_connect_rejection_pool_safety(t: lit::T&) {
    t.run("CVE-2026-56866: Rejected CONNECT Sockets Must Never Be Returned to Pool") { sub =>
        let nak = wing::new_network_anonymization_key("https://proxy-target.com");
        let key = wing::new_pool_key(wing::PoolScheme.Https, "proxy-target.com", 443, wing::new_direct_proxy_chain(), nak, wing::TlsAndDnsPolicy { .. });

        // Simulate a socket where CONNECT tunnel was rejected (e.g. 407 Proxy Auth or 502 Bad Gateway)
        var failed_tunnel_conn = wing::PooledConnection {
            conn_id:          101,
            key:              copy(key),
            protocol:         wing::NegotiatedProtocol.Http11,
            no_new_exchanges: true, // Marked immediately on CONNECT rejection
            closed:           true, // Marked closed to prevent reuse
            ..
        };

        // Liveness check must immediately report unhealthy
        let healthy = wing::is_connection_healthy(failed_tunnel_conn, 2000000000, false);
        sub.assert_false(healthy, "Rejected CONNECT connection is strictly unhealthy");

        // Attempting to acquire from a pool containing closed/no_new_exchanges connection must fail
        var pool = wing::new_stream_pool(6, 32, 10);
        pool.conns.push(failed_tunnel_conn);

        let acq_id, ok_acq = wing::acquire_pooled_connection(pool, key, "", 2500000000);
        sub.assert_false(ok_acq, "Acquire never returns a rejected CONNECT socket (prevents response desync)");
    };
}

// --- Component: net_poller_event_loop ---
// tests/poller_event_loop_test.goose
// Verification suite for Non-blocking Poller & Event Loop over L4 Transport Drivers.
// 1. Poller Creation & Lifecycle across L4 Driver Backends
// 2. Socket Registration, Interest Modification, and Readiness Multiplexing
// 3. High-Resolution Timer Wheel (One-shot, Periodic, Cancellation)
// 4. Non-blocking EventLoop I/O (Read/Write Buffers & Dispatching)
// 5. Bidirectional Client-Server Mock Cycle over EventLoop

// ----------------------------------------------------------------------------
// 1. Poller Creation & Lifecycle across L4 Driver Backends
// ----------------------------------------------------------------------------
fn test_poller_creation_and_lifecycle(t: lit::T&) {
    t.run("Standard Driver Poller Lifecycle") { sub =>
        var cfg = internal::auto_transport_driver_config();
        cfg.active_kind = internal::TransportDriverKind.Standard;

        var poller = wing::new_poller(cfg);
        sub.assert_true(poller.is_open, "Poller is open");
        sub.assert_eq(poller.active_fd_count, 0, "No active fds initially");
        sub.assert_eq(poller.active_timer_count, 0, "No active timers initially");

        wing::close_poller(poller);
        sub.assert_false(poller.is_open, "Poller closed cleanly");
    };

    t.run("Windows RIO / io_uring / kqueue Probed Poller Creation") { sub =>
        let plat = internal::detect_target_platform();
        var cfg = internal::auto_transport_driver_config();

        var poller = wing::new_poller(cfg);
        sub.assert_true(poller.is_open, "Poller created successfully with auto-selected driver");

        if plat == internal::TargetPlatform.Windows && cfg.active_kind == internal::TransportDriverKind.WindowsRIO {
            sub.assert_true(poller.rio_cq_id != 0, "Windows RIO completion queue initialized");
        }

        wing::close_poller(poller);
        sub.assert_false(poller.is_open, "Poller closed");
    };
}

// ----------------------------------------------------------------------------
// 2. Socket Registration & Readiness Multiplexing
// ----------------------------------------------------------------------------
fn test_poller_registration_and_readiness(t: lit::T&) {
    var cfg = internal::auto_transport_driver_config();
    var poller = wing::new_poller(cfg);

    t.run("Registration Table: Add, Duplicate Guard, Modify, Deregister") { sub =>
        // Register fd 10
        let ok_reg = wing::register_socket(poller, 10, 1001, wing::PollInterest.Read, wing::PollTrigger.Level);
        sub.assert_true(ok_reg, "Socket 10 registered");
        sub.assert_eq(poller.active_fd_count, 1, "1 active fd");

        // Duplicate registration rejected
        let dup_reg = wing::register_socket(poller, 10, 1002, wing::PollInterest.Write, wing::PollTrigger.Level);
        sub.assert_false(dup_reg, "Duplicate fd 10 registration rejected");

        // Modify interest to ReadWrite
        let ok_mod = wing::modify_socket(poller, 10, 1001, wing::PollInterest.ReadWrite, wing::PollTrigger.Edge);
        sub.assert_true(ok_mod, "Socket 10 modified");

        let idx = wing::find_registration(poller, 10);
        sub.assert_true(idx >= 0, "Socket 10 found");
        sub.assert_eq(poller.registrations[idx].interest, wing::PollInterest.ReadWrite, "Interest is ReadWrite");
        sub.assert_eq(poller.registrations[idx].trigger, wing::PollTrigger.Edge, "Trigger is Edge");

        // Deregister
        let ok_dereg = wing::deregister_socket(poller, 10);
        sub.assert_true(ok_dereg, "Socket 10 deregistered");
        sub.assert_eq(poller.active_fd_count, 0, "0 active fds");
        sub.assert_eq(wing::find_registration(poller, 10), -1, "Socket 10 no longer found");
    };

    t.run("Readiness Multiplexing: Read, Write, Error, Hangup") { sub =>
        wing::register_socket(poller, 20, 2001, wing::PollInterest.Read, wing::PollTrigger.Level);
        wing::register_socket(poller, 21, 2002, wing::PollInterest.Write, wing::PollTrigger.Level);
        wing::register_socket(poller, 22, 2003, wing::PollInterest.ReadWrite, wing::PollTrigger.Level);

        // Simulate events
        wing::simulate_read_ready(poller, 20, 512); // fd 20 has 512 bytes unread
        wing::simulate_write_ready(poller, 21);      // fd 21 ready to write
        wing::simulate_hangup(poller, 22);           // fd 22 hangup/EOF

        var events: wing::PollReadyEvent[..64] = [];
        let count = wing::poll_events(poller, 0, 1000000000, events);

        sub.assert_eq(count, 3, "3 readiness events harvested");

        // Validate fd 20 event
        var found_20 = false;
        var found_21 = false;
        var found_22 = false;

        for i in events.len {
            if events[i].tag == 2001 {
                found_20 = true;
                sub.assert_eq(events[i].fd, 20, "fd is 20");
                sub.assert_true((events[i].events & wing::POLL_READ) != 0, "Event has POLL_READ");
                sub.assert_eq(events[i].bytes_available, 512, "Reported 512 bytes available");
                sub.assert_false(events[i].is_eof, "Not EOF");
            } else if events[i].tag == 2002 {
                found_21 = true;
                sub.assert_eq(events[i].fd, 21, "fd is 21");
                sub.assert_true((events[i].events & wing::POLL_WRITE) != 0, "Event has POLL_WRITE");
            } else if events[i].tag == 2003 {
                found_22 = true;
                sub.assert_eq(events[i].fd, 22, "fd is 22");
                sub.assert_true((events[i].events & wing::POLL_HANGUP) != 0, "Event has POLL_HANGUP");
                sub.assert_true(events[i].is_eof, "Event is EOF");
            }
        }

        sub.assert_true(found_20, "fd 20 event processed");
        sub.assert_true(found_21, "fd 21 event processed");
        sub.assert_true(found_22, "fd 22 event processed");

        wing::deregister_socket(poller, 20);
        wing::deregister_socket(poller, 21);
        wing::deregister_socket(poller, 22);
    };

    wing::close_poller(poller);
}

// ----------------------------------------------------------------------------
// 3. High-Resolution Timer Wheel
// ----------------------------------------------------------------------------
fn test_poller_timer_wheel(t: lit::T&) {
    var cfg = internal::auto_transport_driver_config();
    var poller = wing::new_poller(cfg);

    t.run("One-shot Timer Expiration") { sub =>
        let now_ns: u64 = 1000000000; // 1.0s
        // Schedule one-shot timer for 50ms (deadline 1.05s)
        let ok_add = wing::add_timer(poller, 101, 50, 9101, false, now_ns);
        sub.assert_true(ok_add, "Timer 101 added");
        sub.assert_eq(poller.active_timer_count, 1, "1 active timer");

        // Poll at 1.04s (40ms elapsed) -> timer should NOT fire
        var events40: wing::PollReadyEvent[..64] = [];
        let c40 = wing::poll_events(poller, 0, now_ns + 40000000, events40);
        sub.assert_eq(c40, 0, "Timer not yet expired at 40ms");

        // Poll at 1.06s (60ms elapsed) -> timer should fire!
        var events60: wing::PollReadyEvent[..64] = [];
        let c60 = wing::poll_events(poller, 0, now_ns + 60000000, events60);
        sub.assert_eq(c60, 1, "Timer fired at 60ms");
        sub.assert_eq(events60[0].tag, 9101, "Timer tag matches");
        sub.assert_true(events60[0].is_timer, "is_timer flag is true");
        sub.assert_true((events60[0].events & wing::POLL_TIMER) != 0, "POLL_TIMER flag set");

        // One-shot timer is now deactivated
        sub.assert_eq(poller.active_timer_count, 0, "0 active timers left");

        // Subsequent poll should not fire
        var events70: wing::PollReadyEvent[..64] = [];
        let c70 = wing::poll_events(poller, 0, now_ns + 70000000, events70);
        sub.assert_eq(c70, 0, "No duplicate timer triggers");
    };

    t.run("Periodic Timer & Cancellation") { sub =>
        let now_ns: u64 = 1000000000;
        // Schedule periodic timer every 100ms
        wing::add_timer(poller, 202, 100, 9202, true, now_ns);

        // 1st tick at 110ms
        var ev1: wing::PollReadyEvent[..64] = [];
        let c1 = wing::poll_events(poller, 0, now_ns + 110000000, ev1);
        sub.assert_eq(c1, 1, "1st tick fired");
        sub.assert_eq(ev1[0].tag, 9202, "Tag matches");

        // Timer still active (periodic)
        sub.assert_eq(poller.active_timer_count, 1, "Timer still active");

        // 2nd tick at 220ms
        var ev2: wing::PollReadyEvent[..64] = [];
        let c2 = wing::poll_events(poller, 0, now_ns + 220000000, ev2);
        sub.assert_eq(c2, 1, "2nd tick fired");

        // Cancel timer
        let ok_cancel = wing::cancel_timer(poller, 202);
        sub.assert_true(ok_cancel, "Timer cancelled");
        sub.assert_eq(poller.active_timer_count, 0, "0 active timers");

        // 3rd tick should NOT fire after cancellation
        var ev3: wing::PollReadyEvent[..64] = [];
        let c3 = wing::poll_events(poller, 0, now_ns + 330000000, ev3);
        sub.assert_eq(c3, 0, "No tick after cancellation");
    };

    wing::close_poller(poller);
}

// ----------------------------------------------------------------------------
// 4. Non-blocking EventLoop I/O
// ----------------------------------------------------------------------------
fn dummy_event_handler(tag: u64, ev: const wing::PollReadyEvent&, el: wing::EventLoop&) {
    if tag == 5001 {
        if (ev.events & wing::POLL_READ) != 0 {
            var msg_buf: u8[>..] = [];
            wing::consume_read(el, tag, msg_buf);
            // Echo back with prefix "ACK:"
            var reply: u8[..64] = "ACK:";
            reply.append(msg_buf[..]);
            wing::queue_write(el, tag, reply[..]);
        }
    }
}

fn test_event_loop_io(t: lit::T&) {
    var cfg = internal::auto_transport_driver_config();
    var el = wing::new_event_loop(cfg);

    t.run("Bind Connection, Queue Write, Feed Read & Consume") { sub =>
        let ok_bind = wing::bind_connection(el, 30, 5001, wing::PollInterest.ReadWrite);
        sub.assert_true(ok_bind, "Connection 5001 bound");

        // Feed incoming data
        let ok_feed = wing::feed_read(el, 5001, "REQUEST_DATA_01");
        sub.assert_true(ok_feed, "Data fed into read buffer");

        // Run event loop once
        let dispatched = wing::run_loop_once(el, 0, 1000000000, dummy_event_handler);
        sub.assert_eq(dispatched, 1, "1 event dispatched in loop");
        sub.assert_eq(el.iteration_count, 1, "Iteration count is 1");
        sub.assert_eq(el.events_dispatched_total, 1, "1 total dispatched event");

        // The handler consumed the read and queued an "ACK:REQUEST_DATA_01" response
        let b_idx = wing::find_connection_buffer(el, 5001);
        sub.assert_true(b_idx >= 0, "Buffer found");
        sub.assert_bytes_eq(el.buffers[b_idx].write_buf[..], "ACK:REQUEST_DATA_01", "Outbound reply queued");

        // Flush writes
        let flushed = wing::flush_writes(el, 5001);
        sub.assert_eq(flushed, 19, "Flushed 19 bytes");
        sub.assert_eq(el.buffers[b_idx].write_buf.len, 0, "Write buffer cleared");

        // Unbind
        sub.assert_true(wing::unbind_connection(el, 5001), "Unbound");
    };

    wing::close_event_loop(el);
}

// ----------------------------------------------------------------------------
// 5. Bidirectional Client-Server Mock Cycle over EventLoop
// ----------------------------------------------------------------------------
var g_server_received: u8[..64] = [];
var g_client_received: u8[..64] = [];

fn bidi_network_handler(tag: u64, ev: const wing::PollReadyEvent&, el: wing::EventLoop&) {
    if tag == 6001 { // Server connection
        if (ev.events & wing::POLL_READ) != 0 {
            var buf: u8[>..] = [];
            wing::consume_read(el, tag, buf);
            g_server_received.clear();
            g_server_received.append(buf[..]);

            // Server responds
            wing::queue_write(el, tag, "SERVER_OK");
        }
    } else if tag == 6002 { // Client connection
        if (ev.events & wing::POLL_READ) != 0 {
            var buf: u8[>..] = [];
            wing::consume_read(el, tag, buf);
            g_client_received.clear();
            g_client_received.append(buf[..]);
        }
    }
}

fn test_bidi_client_server_cycle(t: lit::T&) {
    var cfg = internal::auto_transport_driver_config();
    var el = wing::new_event_loop(cfg);

    t.run("Complete Non-blocking Bidi Request-Response Roundtrip") { sub =>
        g_server_received.clear();
        g_client_received.clear();

        wing::bind_connection(el, 40, 6001, wing::PollInterest.ReadWrite); // Server
        wing::bind_connection(el, 41, 6002, wing::PollInterest.ReadWrite); // Client

        // 1. Client sends request to Server
        wing::feed_read(el, 6001, "PING_FROM_CLIENT");

        // 2. EventLoop Step 1: Server receives request and queues response
        wing::run_loop_once(el, 0, 1000000000, bidi_network_handler);

        sub.assert_bytes_eq(g_server_received[..], "PING_FROM_CLIENT", "Server processed request");

        // 3. Network forwards Server's outbound response to Client's inbound buffer
        let s_idx = wing::find_connection_buffer(el, 6001);
        let s_out = el.buffers[s_idx].write_buf[..];
        sub.assert_bytes_eq(s_out, "SERVER_OK", "Server queued reply");
        wing::feed_read(el, 6002, s_out);
        wing::flush_writes(el, 6001);

        // 4. EventLoop Step 2: Client receives Server's response
        wing::run_loop_once(el, 0, 1000001000, bidi_network_handler);

        sub.assert_bytes_eq(g_client_received[..], "SERVER_OK", "Client received server reply");

        wing::unbind_connection(el, 6001);
        wing::unbind_connection(el, 6002);
    };

    wing::close_event_loop(el);
}

// ----------------------------------------------------------------------------
// 6. 15-bit / 4-second Coarse Socket Timeouts (uWebSockets Pattern)
// ----------------------------------------------------------------------------
fn test_coarse_socket_timeouts(t: lit::T&) {
    var cfg = internal::auto_transport_driver_config();
    var poller = wing::new_poller(cfg);

    t.run("Coarse 4-second Socket Timeout Expiry & Cancellation") { sub =>
        let now_ns: u64 = 1000000000; // 1.0s
        wing::register_socket(poller, 50, 7001, wing::PollInterest.Read, wing::PollTrigger.Level);

        // Initial timeout is disabled (255)
        sub.assert_eq(wing::get_socket_timeout(poller, 50), wing::COARSE_TIMEOUT_DISABLED, "Timeout disabled initially");

        // Set 4-second timeout (1 tick ahead)
        let ok_set = wing::set_socket_timeout(poller, 50, 4);
        sub.assert_true(ok_set, "Set 4s coarse timeout");
        sub.assert_true(wing::get_socket_timeout(poller, 50) != wing::COARSE_TIMEOUT_DISABLED, "Timeout tick armed");

        // First poll: initial anchor (delta 0s)
        var evs1: wing::PollReadyEvent[..64] = [];
        let c1 = wing::poll_events(poller, 0, now_ns, evs1);
        sub.assert_eq(c1, 0, "No events at initial poll");

        // Second poll: +2.0s (less than 4s threshold)
        var evs2: wing::PollReadyEvent[..64] = [];
        let c2 = wing::poll_events(poller, 0, now_ns + 2000000000, evs2);
        sub.assert_eq(c2, 0, "No timeout event before 4 seconds");

        // Third poll: +4.1s (4-second boundary crossed, tick matches)
        var evs3: wing::PollReadyEvent[..64] = [];
        let c3 = wing::poll_events(poller, 0, now_ns + 4100000000, evs3);
        sub.assert_eq(c3, 1, "Coarse timeout event fired at 4s boundary");
        sub.assert_true(evs3[0].is_timer, "Event is marked as timer");
        sub.assert_eq(evs3[0].tag, 7001, "Event tag matches socket 50 tag");
        sub.assert_eq(evs3[0].fd, 50, "Event fd matches socket 50");
        sub.assert_eq(wing::get_socket_timeout(poller, 50), wing::COARSE_TIMEOUT_DISABLED, "Timeout reset to disabled after firing");

        // Arm and cancel with seconds = 0
        wing::set_socket_timeout(poller, 50, 16);
        sub.assert_true(wing::get_socket_timeout(poller, 50) != wing::COARSE_TIMEOUT_DISABLED, "Armed 16s timeout");
        wing::set_socket_timeout(poller, 50, 0); // Disable
        sub.assert_eq(wing::get_socket_timeout(poller, 50), wing::COARSE_TIMEOUT_DISABLED, "Disabled via seconds=0");

        wing::deregister_socket(poller, 50);
    };

    t.run("Multi-Tick Jump Expiry Without Skips (elapsed_ticks > 1)") { sub =>
        let now_ns: u64 = 10000000000; // 10.0s
        wing::register_socket(poller, 60, 8001, wing::PollInterest.Read, wing::PollTrigger.Level);

        // Arm timeout for 4 seconds (target = current_tick + 1)
        wing::set_socket_timeout(poller, 60, 4);

        // Advance poll by 12 seconds (elapsed_ticks = 3, skips over tick + 1)
        var evs: wing::PollReadyEvent[..64] = [];
        let fired = wing::poll_events(poller, 0, now_ns + 12000000000, evs);
        sub.assert_eq(fired, 1, "Coarse timeout fired even when time jumped 3 ticks ahead");
        sub.assert_true(evs[0].is_timer, "Event is marked as timer");
        sub.assert_eq(evs[0].fd, 60, "Event fd matches socket 60");

        wing::deregister_socket(poller, 60);
    };

    wing::close_poller(poller);
}

// ----------------------------------------------------------------------------
// Suite Runner
// ----------------------------------------------------------------------------

// --- Component: net_happy_eyeballs ---
// Verification suite for net/happy_eyeballs: RFC 8305 and HEv3 connection racing,
// CAD calculations, 50 ms Resolution Delay, candidate interleaving, and AttemptManager coordination.
// Defenses for Go #59494 / #35122 (Windows leaked dial timers) and RFC 8305 congestion collapse.

fn test_cad_calculation_and_absolute_floor(t: lit::T&) {
    t.run("CAD Clamping and Strict Absolute Floor >= 10 ms") { sub =>
        // Default when RTT is unknown: 250 ms
        let cad_default = wing::compute_effective_cad_ms(0, false);
        sub.assert_eq(cad_default, 250, "Default CAD is 250 ms (RFC 8305)");

        // Observed RTT within normal window [100 ms, 2000 ms]
        let cad_normal = wing::compute_effective_cad_ms(180, true);
        sub.assert_eq(cad_normal, 180, "Observed RTT 180 ms preserved");

        // Observed RTT below recommended minimum 100 ms
        let cad_clamped_min = wing::compute_effective_cad_ms(45, true, 100, 2000);
        sub.assert_eq(cad_clamped_min, 100, "RTT 45 ms clamped to min 100 ms");

        // Observed RTT above max 2000 ms
        let cad_clamped_max = wing::compute_effective_cad_ms(4500, true, 100, 2000);
        sub.assert_eq(cad_clamped_max, 2000, "RTT 4500 ms clamped to max 2000 ms");

        // Normative safety barrier: MUST NOT be less than 10 ms even with caller override
        let cad_floor1 = wing::compute_effective_cad_ms(2, true, 4, 1000);
        sub.assert_eq(cad_floor1, 10, "CAD strictly clamped to absolute floor >= 10 ms");

        // 0 ms RTT (e.g. localhost or loopback)
        let cad_zero = wing::compute_effective_cad_ms(0, true, 0, 1000);
        sub.assert_eq(cad_zero, 10, "0 ms RTT clamped to 10 ms absolute floor");

        // Negative RTT (clock jump backwards or uncalibrated timer)
        let cad_neg = wing::compute_effective_cad_ms(-250, true, 0, 1000);
        sub.assert_eq(cad_neg, 10, "Negative RTT clamped safely to 10 ms absolute floor");

        // Custom bounds [500 ms, 1500 ms]
        let cad_custom = wing::compute_effective_cad_ms(200, true, 500, 1500);
        sub.assert_eq(cad_custom, 500, "Custom min 500 ms applied");

        let cad_custom_high = wing::compute_effective_cad_ms(1800, true, 500, 1500);
        sub.assert_eq(cad_custom_high, 1500, "Custom max 1500 ms applied");
    };
}

fn test_rfc6724_and_hev3_interleaving(t: lit::T&) {
    t.run("First Address Family Count = 1 Interleaving Matrix") { sub =>
        var ipv6_list: wing::DnsCandidate[..8] = [];
        ipv6_list.push(wing::new_dns_candidate(wing::AddressFamily.IPv6, "2001:db8::1", 443));
        ipv6_list.push(wing::new_dns_candidate(wing::AddressFamily.IPv6, "2001:db8::2", 443));

        var ipv4_list: wing::DnsCandidate[..8] = [];
        ipv4_list.push(wing::new_dns_candidate(wing::AddressFamily.IPv4, "198.51.100.1", 443));
        ipv4_list.push(wing::new_dns_candidate(wing::AddressFamily.IPv4, "198.51.100.2", 443));

        var interleaved: wing::DnsCandidate[..32] = [];
        wing::interleave_candidates_he(ipv6_list[..], ipv4_list[..], interleaved, 1);

        sub.assert_eq(interleaved.len, 4, "4 candidates interleaved");
        sub.assert_true(interleaved[0].family == wing::AddressFamily.IPv6, "Candidate 0 is IPv6_1");
        sub.assert_true(interleaved[1].family == wing::AddressFamily.IPv4, "Candidate 1 is IPv4_1");
        sub.assert_true(interleaved[2].family == wing::AddressFamily.IPv6, "Candidate 2 is IPv6_2");
        sub.assert_true(interleaved[3].family == wing::AddressFamily.IPv4, "Candidate 3 is IPv4_2");
    };

    t.run("Asymmetric Candidate Interleaving (IPv6 Heavily Dominates)") { sub =>
        var ipv6_list: wing::DnsCandidate[..8] = [];
        ipv6_list.push(wing::new_dns_candidate(wing::AddressFamily.IPv6, "2001:db8::1", 443));
        ipv6_list.push(wing::new_dns_candidate(wing::AddressFamily.IPv6, "2001:db8::2", 443));
        ipv6_list.push(wing::new_dns_candidate(wing::AddressFamily.IPv6, "2001:db8::3", 443));
        ipv6_list.push(wing::new_dns_candidate(wing::AddressFamily.IPv6, "2001:db8::4", 443));

        var ipv4_list: wing::DnsCandidate[..8] = [];
        ipv4_list.push(wing::new_dns_candidate(wing::AddressFamily.IPv4, "198.51.100.1", 443));

        var interleaved: wing::DnsCandidate[..32] = [];
        wing::interleave_candidates_he(ipv6_list[..], ipv4_list[..], interleaved, 1);

        sub.assert_eq(interleaved.len, 5, "5 candidates total");
        sub.assert_true(interleaved[0].family == wing::AddressFamily.IPv6, "0 is IPv6");
        sub.assert_true(interleaved[1].family == wing::AddressFamily.IPv4, "1 is IPv4");
        sub.assert_true(interleaved[2].family == wing::AddressFamily.IPv6, "2 is IPv6");
        sub.assert_true(interleaved[3].family == wing::AddressFamily.IPv6, "3 is IPv6");
        sub.assert_true(interleaved[4].family == wing::AddressFamily.IPv6, "4 is IPv6");
    };

    t.run("Asymmetric Candidate Interleaving (IPv4 Heavily Dominates)") { sub =>
        var ipv6_list: wing::DnsCandidate[..8] = [];
        ipv6_list.push(wing::new_dns_candidate(wing::AddressFamily.IPv6, "2001:db8::1", 443));

        var ipv4_list: wing::DnsCandidate[..8] = [];
        ipv4_list.push(wing::new_dns_candidate(wing::AddressFamily.IPv4, "198.51.100.1", 443));
        ipv4_list.push(wing::new_dns_candidate(wing::AddressFamily.IPv4, "198.51.100.2", 443));
        ipv4_list.push(wing::new_dns_candidate(wing::AddressFamily.IPv4, "198.51.100.3", 443));

        var interleaved: wing::DnsCandidate[..32] = [];
        wing::interleave_candidates_he(ipv6_list[..], ipv4_list[..], interleaved, 1);

        sub.assert_eq(interleaved.len, 4, "4 candidates total");
        sub.assert_true(interleaved[0].family == wing::AddressFamily.IPv6, "0 is IPv6");
        sub.assert_true(interleaved[1].family == wing::AddressFamily.IPv4, "1 is IPv4");
        sub.assert_true(interleaved[2].family == wing::AddressFamily.IPv4, "2 is IPv4");
        sub.assert_true(interleaved[3].family == wing::AddressFamily.IPv4, "3 is IPv4");
    };

    t.run("Single-Stack Fallbacks (0 IPv6 or 0 IPv4)") { sub =>
        var ipv6_only: wing::DnsCandidate[..8] = [];
        ipv6_only.push(wing::new_dns_candidate(wing::AddressFamily.IPv6, "2001:db8::1", 443));
        ipv6_only.push(wing::new_dns_candidate(wing::AddressFamily.IPv6, "2001:db8::2", 443));
        var empty_ipv4: wing::DnsCandidate[..8] = [];

        var res_v6: wing::DnsCandidate[..32] = [];
        wing::interleave_candidates_he(ipv6_only[..], empty_ipv4[..], res_v6, 1);
        sub.assert_eq(res_v6.len, 2, "IPv6-only preserved 2 candidates");
        sub.assert_true(res_v6[0].family == wing::AddressFamily.IPv6, "Res 0 is IPv6");
        sub.assert_true(res_v6[1].family == wing::AddressFamily.IPv6, "Res 1 is IPv6");

        var empty_ipv6: wing::DnsCandidate[..8] = [];
        var ipv4_only:  wing::DnsCandidate[..8] = [];
        ipv4_only.push(wing::new_dns_candidate(wing::AddressFamily.IPv4, "1.1.1.1", 80));
        var res_v4: wing::DnsCandidate[..32] = [];
        wing::interleave_candidates_he(empty_ipv6[..], ipv4_only[..], res_v4, 1);
        sub.assert_eq(res_v4.len, 1, "IPv4-only preserved 1 candidate");
        sub.assert_true(res_v4[0].family == wing::AddressFamily.IPv4, "Res 0 is IPv4");
    };

    t.run("HEv3 Protocol Interleaving (QUIC vs TCP)") { sub =>
        var list: wing::DnsCandidate[..8] = [];
        list.push(wing::new_dns_candidate(wing::AddressFamily.IPv6, "2001:db8::1", 443));
        list.push(wing::new_dns_candidate(wing::AddressFamily.IPv4, "198.51.100.1", 443));

        var proto_interleaved: wing::DnsCandidate[..32] = [];
        wing::interleave_protocols_hev3(list[..], proto_interleaved);

        sub.assert_eq(proto_interleaved.len, 4, "4 protocol attempts generated (QUIC + TCP for both)");
        sub.assert_true(proto_interleaved[0].l4_proto == wing::L4Protocol.QuicUdp, "Attempt 0 is QUIC/UDP IPv6");
        sub.assert_true(proto_interleaved[1].l4_proto == wing::L4Protocol.Tcp, "Attempt 1 is TCP IPv6");
        sub.assert_true(proto_interleaved[2].l4_proto == wing::L4Protocol.QuicUdp, "Attempt 2 is QUIC/UDP IPv4");
        sub.assert_true(proto_interleaved[3].l4_proto == wing::L4Protocol.Tcp, "Attempt 3 is TCP IPv4");
    };
}

fn test_dns_race_and_resolution_delay(t: lit::T&) {
    t.run("Asymmetric Priority: AAAA First Cancels Delay") { sub =>
        var task = wing::new_dns_race_task();
        let ip6: const u8[:][1] = ["2001:db8::1"];
        wing::on_dns_aaaa_response(task, ip6[..], 100);

        sub.assert_true(task.ready_to_connect, "Ready to connect immediately on AAAA");
        sub.assert_false(task.rd_timer_armed, "RD timer NOT armed when AAAA arrives first");
        sub.assert_eq(task.ipv6_candidates.len, 1, "IPv6 candidate ready");
    };

    t.run("A First Arms 50 ms Resolution Delay Timer") { sub =>
        var task = wing::new_dns_race_task();
        let ip4: const u8[:][1] = ["198.51.100.1"];
        wing::on_dns_a_response(task, ip4[..], 100);

        sub.assert_false(task.ready_to_connect, "Not ready immediately: waiting for AAAA in RD window");
        sub.assert_true(task.rd_timer_armed, "RD timer armed for 50 ms");
        sub.assert_eq(task.rd_deadline_ms, 150, "RD deadline set to now + 50 ms");

        // Positive AAAA arrives at t=120 (< 150)
        let ip6: const u8[:][1] = ["2001:db8::1"];
        wing::on_dns_aaaa_response(task, ip6[..], 120);
        sub.assert_true(task.ready_to_connect, "Unblocked by late AAAA before RD deadline");
        sub.assert_false(task.rd_timer_armed, "RD timer cancelled on positive AAAA");
    };

    t.run("RD Expiration Unblocks IPv4") { sub =>
        var task = wing::new_dns_race_task();
        let ip4: const u8[:][1] = ["198.51.100.1"];
        wing::on_dns_a_response(task, ip4[..], 100);

        // Tick before deadline
        let unblocked_early = wing::check_dns_resolution_delay_tick(task, 140);
        sub.assert_false(unblocked_early, "Not unblocked at t=140");

        // Tick at deadline (t=150)
        let unblocked = wing::check_dns_resolution_delay_tick(task, 150);
        sub.assert_true(unblocked, "Unblocked at t=150 (50 ms RD expired)");
        sub.assert_true(task.ready_to_connect, "Ready to connect with IPv4");
    };

    t.run("Negative AAAA Immediately Unblocks IPv4") { sub =>
        var task = wing::new_dns_race_task();
        let ip4: const u8[:][1] = ["198.51.100.1"];
        wing::on_dns_a_response(task, ip4[..], 100);

        // Empty AAAA response (NODATA / negative)
        let empty_ip6: const u8[:][0] = [];
        wing::on_dns_aaaa_response(task, empty_ip6[..], 110);
        sub.assert_true(task.ready_to_connect, "Negative AAAA immediately unblocks IPv4 without waiting for 50 ms");
        sub.assert_false(task.rd_timer_armed, "RD timer disarmed");
    };
}

fn test_attempt_manager_racing_and_winner(t: lit::T&) {
    t.run("Staggered Connection Racing, Winner Binding & Loser Cancellation (Go #59494)") { sub =>
        var mgr = wing::new_attempt_manager(250); // CAD = 250 ms

        var candidates: wing::DnsCandidate[..4] = [];
        candidates.push(wing::new_dns_candidate(wing::AddressFamily.IPv6, "2001:db8::1", 443));
        candidates.push(wing::new_dns_candidate(wing::AddressFamily.IPv4, "198.51.100.1", 443));
        candidates.push(wing::new_dns_candidate(wing::AddressFamily.IPv6, "2001:db8::2", 443));

        wing::start_attempt_race(mgr, candidates[..], 0);

        sub.assert_eq(mgr.attempts.len, 1, "First attempt launched at t=0");
        sub.assert_eq(mgr.attempts[0].attempt_id, 1, "Attempt 1 launched");

        // Tick at t=100 (< CAD 250 ms) -> no new attempt
        let launched_early = wing::tick_attempt_manager(mgr, 100);
        sub.assert_false(launched_early, "No attempt launched at t=100");
        sub.assert_eq(mgr.attempts.len, 1, "Still 1 attempt");

        // Tick at t=250 (= CAD) -> launches second attempt (IPv4)
        let launched_cad = wing::tick_attempt_manager(mgr, 250);
        sub.assert_true(launched_cad, "Second attempt launched at t=250");
        sub.assert_eq(mgr.attempts.len, 2, "2 attempts now active");

        // Tick at t=500 (= 2*CAD) -> launches third attempt (IPv6_2)
        let launched_third = wing::tick_attempt_manager(mgr, 500);
        sub.assert_true(launched_third, "Third attempt launched at t=500");
        sub.assert_eq(mgr.attempts.len, 3, "3 attempts now active");

        // Attempt 2 (IPv4) wins at t=550
        // Defense (Go #59494, #35122): All other attempts (1 and 3) must be cancelled immediately to prevent leaked dials on Windows!
        let won = wing::bind_winner_attempt(mgr, 2);
        sub.assert_true(won, "Attempt 2 bound as winner");
        sub.assert_true(mgr.has_winner, "Manager marked has_winner");
        sub.assert_true(mgr.attempts[0].state == wing::AttemptState.Cancelled, "Attempt 1 cancelled");
        sub.assert_true(mgr.attempts[1].state == wing::AttemptState.Connected, "Attempt 2 connected");
        sub.assert_true(mgr.attempts[2].state == wing::AttemptState.Cancelled, "Attempt 3 cancelled");

        // Attempting to tick after winner does not launch further attempts
        let tick_post_winner = wing::tick_attempt_manager(mgr, 750);
        sub.assert_false(tick_post_winner, "No attempts launched after winner is bound");
    };

    t.run("Last Resort Local Synthesis Delay (2000 ms)") { sub =>
        var mgr = wing::new_attempt_manager(250);
        var candidates: wing::DnsCandidate[..2] = [];
        candidates.push(wing::new_dns_candidate(wing::AddressFamily.IPv6, "2001:db8::99", 443));

        wing::start_attempt_race(mgr, candidates[..], 0);
        sub.assert_true(mgr.last_resort_armed, "Last resort synthesis armed for last IPv6 attempt");
        sub.assert_eq(mgr.last_resort_deadline_ms, 2000, "Deadline set to 2000 ms");

        // Tick at t=1999 -> not triggered
        wing::tick_attempt_manager(mgr, 1999);
        sub.assert_false(mgr.last_resort_triggered, "Not triggered before 2000 ms");

        // Tick at t=2000 -> triggers RFC 7050 NAT64 synthesis
        wing::tick_attempt_manager(mgr, 2000);
        sub.assert_true(mgr.last_resort_triggered, "Last resort synthesis triggered at 2000 ms");
        sub.assert_true(mgr.pending_candidates.len >= 2, "Synthesized NAT64 candidate injected into pending queue");

        // With an IPv4 candidate present, synthesizes 64:ff9b::<ipv4> with target port
        var mgr4 = wing::new_attempt_manager(250);
        var cands4: wing::DnsCandidate[..2] = [];
        cands4.push(wing::new_dns_candidate(wing::AddressFamily.IPv6, "2001:db8::1", 8443));
        cands4.push(wing::new_dns_candidate(wing::AddressFamily.IPv4, "192.0.2.33", 8443));
        wing::start_attempt_race(mgr4, cands4[..], 0);
        wing::tick_attempt_manager(mgr4, 2000);
        sub.assert_true(mgr4.last_resort_triggered, "Triggered for mixed list");
        let last_cand = mgr4.pending_candidates[mgr4.pending_candidates.len - 1];
        sub.assert_bytes_eq(last_cand.ip[..], "64:ff9b::192.0.2.33", "NAT64 synthesized from candidate IPv4");
        sub.assert_eq(last_cand.port, 8443, "Target port 8443 preserved");
    };

    t.run("Chromium JobController Creation Rules and Waiting Delay") { sub =>
        // dns_alpn_h3_job rules: HTTPS + QUIC + no proxy + no active QUIC session
        sub.assert_true(wing::should_create_dns_alpn_h3_job(wing::H3JobOptions { is_https: true, quic_enabled: true, uses_proxy: false, has_available_quic_session: false }), "Created on HTTPS, QUIC, direct, no active session");
        sub.assert_false(wing::should_create_dns_alpn_h3_job(wing::H3JobOptions { is_https: false, quic_enabled: true, uses_proxy: false, has_available_quic_session: false }), "Not created on plain HTTP");
        sub.assert_false(wing::should_create_dns_alpn_h3_job(wing::H3JobOptions { is_https: true, quic_enabled: false, uses_proxy: false, has_available_quic_session: false }), "Not created when QUIC disabled");
        sub.assert_false(wing::should_create_dns_alpn_h3_job(wing::H3JobOptions { is_https: true, quic_enabled: true, uses_proxy: true, has_available_quic_session: false }), "Not created when proxy is configured");
        sub.assert_false(wing::should_create_dns_alpn_h3_job(wing::H3JobOptions { is_https: true, quic_enabled: true, uses_proxy: false, has_available_quic_session: true }), "Not created when active QUIC session can be reused");

        // Waiting delay cancelled when open TCP socket already exists in pool
        let delay_open_tcp = wing::compute_main_job_waiting_delay_ms(true, 200, false);
        sub.assert_eq(delay_open_tcp, 0, "Waiting delay cancelled (0 ms) when open TCP socket exists");

        // Waiting delay cancelled when DNS confirms no HTTP/3 ALPN support
        let delay_no_h3 = wing::compute_main_job_waiting_delay_ms(false, 200, true);
        sub.assert_eq(delay_no_h3, 0, "Waiting delay cancelled (0 ms) when DNS confirms no HTTP/3");

        // Default waiting delay when cold
        let delay_cold = wing::compute_main_job_waiting_delay_ms(false, 200, false);
        sub.assert_eq(delay_cold, 200, "Default waiting delay applied when cold");
    };
}

// --- Component: net_retry ---
// Verification suite for net/retry: Tier 1 zero-delay stale socket recovery,
// one-shot stream bug guards, QUIC protocol fallback, Full/Equal/Decorrelated Jitter,
// RFC 9110 Retry-After parser, circuit breaker, Google SRE adaptive retry budget,
// and Go #81671 (idempotent QUERY method).

fn test_tier1_stale_socket_and_quic_fallback(t: lit::T&) {
    t.run("Tier 1 4-Condition Invariant Evaluation") { sub =>
        // 1. Standard idempotent GET on reused Keep-Alive connection before headers
        var req_get = wing::new_request("GET", "https://api.io/items");
        sub.assert_true(wing::should_retry_tier1_stale_socket(true, req_get), "Reused GET before headers approved for immediate Tier 1 retry");

        // 2. Fresh dial connection failure: MUST NOT retry at Tier 1 (fails fast)
        sub.assert_false(wing::should_retry_tier1_stale_socket(false, req_get), "Fresh connection failure rejected for Tier 1 retry");

        // 3. Response headers already received: MUST NOT retry at Tier 1
        sub.assert_false(wing::should_retry_tier1_stale_socket(true, req_get, true), "Failure after response headers rejected for Tier 1 retry");

        // 4. Non-idempotent POST without Idempotency-Key: MUST NOT retry
        var req_post = wing::new_request("POST", "https://api.io/payments");
        sub.assert_false(wing::should_retry_tier1_stale_socket(true, req_post), "Non-idempotent POST without Idempotency-Key rejected");

        // 5. Non-idempotent POST WITH Idempotency-Key: approved for retry
        wing::set_header(req_post, "Idempotency-Key", "uuid-v4-998811-aabbcc");
        sub.assert_true(wing::should_retry_tier1_stale_socket(true, req_post), "POST with Idempotency-Key approved for Tier 1 retry");

        // 6. Non-idempotent PATCH without Idempotency-Key: rejected
        var req_patch = wing::new_request("PATCH", "https://api.io/items/1");
        sub.assert_false(wing::should_retry_tier1_stale_socket(true, req_patch), "PATCH without Idempotency-Key rejected");

        // 7. Non-idempotent PATCH WITH Idempotency-Key: approved
        wing::set_header(req_patch, "Idempotency-Key", "patch-key-1");
        sub.assert_true(wing::should_retry_tier1_stale_socket(true, req_patch), "PATCH with Idempotency-Key approved");

        // 8. Idempotent RFC methods sweep
        var req_head = wing::new_request("HEAD", "https://api.io/items");
        sub.assert_true(wing::should_retry_tier1_stale_socket(true, req_head), "HEAD is idempotent");

        var req_put = wing::new_request("PUT", "https://api.io/items/1");
        sub.assert_true(wing::should_retry_tier1_stale_socket(true, req_put), "PUT is idempotent");

        var req_del = wing::new_request("DELETE", "https://api.io/items/1");
        sub.assert_true(wing::should_retry_tier1_stale_socket(true, req_del), "DELETE is idempotent");

        var req_opt = wing::new_request("OPTIONS", "https://api.io/items");
        sub.assert_true(wing::should_retry_tier1_stale_socket(true, req_opt), "OPTIONS is idempotent");

        var req_trace = wing::new_request("TRACE", "https://api.io/items");
        sub.assert_true(wing::should_retry_tier1_stale_socket(true, req_trace), "TRACE is idempotent");
    };

    t.run("Go #81671 & RFC 9110: QUERY Method Safe & Replayable") { sub =>
        // RFC 9110 and draft-ietf-httpbis-safe-method-w-body:
        // QUERY method is safe and idempotent, and carries a request body.
        // It MUST be replayable on stale socket disconnections.
        var req_query = wing::new_request("QUERY", "https://api.io/search");
        wing::text(req_query, "SELECT id, name FROM users WHERE active = true");
        sub.assert_true(wing::is_idempotent_method("QUERY"), "QUERY recognized as idempotent");
        sub.assert_true(wing::should_retry_tier1_stale_socket(true, req_query), "QUERY with rewindable body replayable on stale socket drop");
    };

    t.run("Defense against One-Shot Stream Retry Bug (Go #41907 / #41913)") { sub =>
        // Request with non-empty body that is NOT rewindable (already consumed stream)
        var req_stream = wing::new_request("PUT", "https://api.io/upload");
        req_stream.body.append("multipart-stream-chunk-data");
        req_stream.rewindable = false;
        req_stream.body_consumed = true;

        sub.assert_false(wing::should_retry_tier1_stale_socket(true, req_stream), "Unrewindable consumed body stream rejected (prevents sending empty body)");

        // Non-empty body with rewindable = false but body_consumed = false
        var req_unrewind = wing::new_request("PUT", "https://api.io/upload");
        req_unrewind.body.append("data");
        req_unrewind.rewindable = false;
        sub.assert_false(wing::should_retry_tier1_stale_socket(true, req_unrewind), "Unrewindable body rejected");

        // Non-empty body with rewindable = true and body_consumed = true
        var req_consumed = wing::new_request("PUT", "https://api.io/upload");
        req_consumed.body.append("data");
        req_consumed.rewindable = true;
        req_consumed.body_consumed = true;
        sub.assert_false(wing::should_retry_tier1_stale_socket(true, req_consumed), "Already-consumed rewindable body rejected");

        // Request with rewindable body buffer (GetBody pattern)
        var req_rewindable = wing::new_request("PUT", "https://api.io/upload");
        wing::text(req_rewindable, "rewindable-payload-data");
        sub.assert_true(wing::should_retry_tier1_stale_socket(true, req_rewindable), "Rewindable body approved for retry");
    };

    t.run("Chromium ERR_QUIC_PROTOCOL_ERROR Automatic TCP Fallback") { sub =>
        var req = wing::new_request("GET", "https://quic.example.com");
        let dec = wing::evaluate_tier1_retry(wing::ERR_QUIC_PROTOCOL_ERROR, false, req);

        sub.assert_true(dec.retry_immediately, "Immediate retry on ERR_QUIC_PROTOCOL_ERROR");
        sub.assert_true(dec.disable_alternative_services, "disable_alternative_services flagged to force reliable TCP/TLS");

        // If headers were already received, cannot fallback immediately
        let dec_headers = wing::evaluate_tier1_retry(wing::ERR_QUIC_PROTOCOL_ERROR, false, req, true);
        sub.assert_false(dec_headers.retry_immediately, "QUIC error after headers received does not trigger blind retry");
    };
}

fn test_tier2_exponential_backoff_and_jitter(t: lit::T&) {
    t.run("Deterministic Backoff and 3 Jitter Strategies") { sub =>
        var seed:       u64 = 123456789;
        var prev_sleep: i64 = 0;

        let cfg_full = wing::new_backoff_config(100, 5000, wing::JitterStrategy.FullJitter);
        let cfg_equal = wing::new_backoff_config(100, 5000, wing::JitterStrategy.EqualJitter);
        let cfg_decorr = wing::new_backoff_config(100, 5000, wing::JitterStrategy.DecorrelatedJitter);
        let cfg_none = wing::new_backoff_config(100, 5000, wing::JitterStrategy.None);

        // Attempt 0: target 100 ms
        let t0 = wing::compute_backoff_jitter_ms(cfg_none, 0, prev_sleep, seed);
        sub.assert_eq(t0, 100, "Attempt 0 deterministic delay is 100 ms");

        // Attempt 1: target 200 ms
        let t1 = wing::compute_backoff_jitter_ms(cfg_none, 1, prev_sleep, seed);
        sub.assert_eq(t1, 200, "Attempt 1 deterministic delay is 200 ms");

        // Attempt 3: target 100 * 2^3 = 800 ms
        let t3 = wing::compute_backoff_jitter_ms(cfg_none, 3, prev_sleep, seed);
        sub.assert_eq(t3, 800, "Attempt 3 deterministic delay is 800 ms");

        // Attempt 10: target 100 * 2^10 = 102400 ms -> clamped to cap 5000 ms
        let t10 = wing::compute_backoff_jitter_ms(cfg_none, 10, prev_sleep, seed);
        sub.assert_eq(t10, 5000, "Attempt 10 clamped to cap 5000 ms");

        // Attempt 50: large attempt number must NOT overflow 64-bit integer
        let t50 = wing::compute_backoff_jitter_ms(cfg_none, 50, prev_sleep, seed);
        sub.assert_eq(t50, 5000, "Attempt 50 clamped safely without integer overflow");

        // Full Jitter: in range [0, 800]
        for i in 20 {
            let fj = wing::compute_backoff_jitter_ms(cfg_full, 3, prev_sleep, seed);
            sub.assert_true(fj >= 0 && fj <= 800, "Full Jitter within [0, 800]");
        }

        // Equal Jitter: in range [half, target] = [400, 800]
        for i in 20 {
            let ej = wing::compute_backoff_jitter_ms(cfg_equal, 3, prev_sleep, seed);
            sub.assert_true(ej >= 400 && ej <= 800, "Equal Jitter maintains non-zero floor within [400, 800]");
        }

        // Decorrelated Jitter bounded by [base, cap]
        prev_sleep = 100;
        for i in 20 {
            let dj = wing::compute_backoff_jitter_ms(cfg_decorr, 3, prev_sleep, seed);
            sub.assert_true(dj >= 100 && dj <= 5000, "Decorrelated Jitter bounded by [base, cap]");
        }
    };
}

fn test_rfc9110_retry_after_parser(t: lit::T&) {
    t.run("delay-seconds (1*DIGIT) Parsing") { sub =>
        let now_ms: i64 = 1700000000000;

        let ms0, ok0 = wing::parse_retry_after_ms("0", now_ms);
        sub.assert_true(ok0, "Parsed delay-seconds '0'");
        sub.assert_eq(ms0, 0, "0 seconds is 0 ms");

        let ms1, ok1 = wing::parse_retry_after_ms("1", now_ms);
        sub.assert_true(ok1, "Parsed delay-seconds '1'");
        sub.assert_eq(ms1, 1000, "1 second is 1000 ms");

        let ms120, ok120 = wing::parse_retry_after_ms("120", now_ms);
        sub.assert_true(ok120, "Parsed delay-seconds '120'");
        sub.assert_eq(ms120, 120000, "120 seconds is 120,000 ms");

        let ms86400, ok86400 = wing::parse_retry_after_ms("86400", now_ms);
        sub.assert_true(ok86400, "Parsed delay-seconds '86400'");
        sub.assert_eq(ms86400, 86400000, "86400 seconds is 86,400,000 ms (24h)");

        // Leading/trailing whitespace trimmed
        let ms_ws, ok_ws = wing::parse_retry_after_ms("  45  ", now_ms);
        sub.assert_true(ok_ws, "Parsed delay-seconds with whitespace");
        sub.assert_eq(ms_ws, 45000, "45 seconds is 45,000 ms");

        // Invalid integer formats rejected
        let _, bad1 = wing::parse_retry_after_ms("120s", now_ms);
        sub.assert_false(bad1, "Rejected unit suffix '120s'");

        let _, bad2 = wing::parse_retry_after_ms("-10", now_ms);
        sub.assert_false(bad2, "Rejected negative delay-seconds '-10'");

        let _, bad3 = wing::parse_retry_after_ms("+10", now_ms);
        sub.assert_false(bad3, "Rejected explicit positive sign '+10'");

        let _, bad4 = wing::parse_retry_after_ms("12.5", now_ms);
        sub.assert_false(bad4, "Rejected decimal delay-seconds '12.5'");

        let _, bad5 = wing::parse_retry_after_ms("abc", now_ms);
        sub.assert_false(bad5, "Rejected alphanumeric string");

        let _, bad6 = wing::parse_retry_after_ms("", now_ms);
        sub.assert_false(bad6, "Rejected empty string");

        let _, bad7 = wing::parse_retry_after_ms("   ", now_ms);
        sub.assert_false(bad7, "Rejected whitespace-only string");
    };

    t.run("IMF-fixdate Parsing and Exact UTC Round-Trip Validation") { sub =>
        // Wednesday, 21 Oct 2015 07:28:00 GMT = 1445412480000 ms
        let http_date = "Wed, 21 Oct 2015 07:28:00 GMT";

        // If current time is earlier (e.g. 1445412470000, 10s earlier)
        let delta_ms, ok_date = wing::parse_retry_after_ms(http_date, 1445412470000);
        sub.assert_true(ok_date, "Parsed valid future IMF-fixdate");
        sub.assert_eq(delta_ms, 10000, "Calculated 10,000 ms delta");

        // If date is in the past: clamped to 0 ms
        let delta_past, ok_past = wing::parse_retry_after_ms(http_date, 1500000000000);
        sub.assert_true(ok_past, "Parsed past IMF-fixdate");
        sub.assert_eq(delta_past, 0, "Past date clamped to 0 ms (never negative)");

        // Invalid calendar date: Feb 31 rejected by round-trip check
        let bad_date = "Wed, 31 Feb 2024 12:00:00 GMT";
        let _, ok_bad = wing::parse_retry_after_ms(bad_date, 1700000000000);
        sub.assert_false(ok_bad, "Invalid calendar day 31 Feb rejected by round-trip validator");

        // Invalid month string
        let bad_month = "Wed, 21 Foo 2026 07:28:00 GMT";
        let _, ok_bm = wing::parse_retry_after_ms(bad_month, 1700000000000);
        sub.assert_false(ok_bm, "Invalid month 'Foo' rejected");
    };
}

fn test_circuit_breaker_and_adaptive_retry_budget(t: lit::T&) {
    t.run("Host Circuit Breaker on Excessive Retry-After") { sub =>
        var breaker = wing::new_host_circuit_breaker(60000); // 60s max wait

        // Retry-After of 30s does not trip circuit breaker
        let tripped_small = wing::trip_circuit_breaker_if_exceeded(breaker, "api.overloaded.com", 30000, 0);
        sub.assert_false(tripped_small, "30s does not trip circuit breaker");
        sub.assert_false(wing::is_host_circuit_broken(breaker, "api.overloaded.com", 0), "Host not blocked");

        // Retry-After of 300s (> 60s) trips circuit breaker
        let tripped_large = wing::trip_circuit_breaker_if_exceeded(breaker, "api.overloaded.com", 300000, 1000000000);
        sub.assert_true(tripped_large, "300s trips circuit breaker");
        sub.assert_true(wing::is_host_circuit_broken(breaker, "api.overloaded.com", 2000000000), "Host blocked by circuit breaker");

        // Advance beyond unblock deadline (1s + 300s = 301s)
        sub.assert_false(wing::is_host_circuit_broken(breaker, "api.overloaded.com", 302000000000), "Host unblocked after cool-down");

        // Different host is not blocked
        sub.assert_false(wing::is_host_circuit_broken(breaker, "other.healthy.com", 2000000000), "Other host is not blocked");
    };

    t.run("Google SRE Adaptive Retry Budget") { sub =>
        // 20% max ratio, 2 retries/sec floor, 10s window (floor = 20 retries allowed)
        var budget = wing::new_adaptive_retry_budget(20, 2, 10);

        // Record 100 primary requests
        for i in 100 {
            wing::record_primary_request(budget, 1000000000);
        }

        // Allowed retries: max(100 * 20% = 20, 2 * 10 = 20) = 20 retries
        for i in 20 {
            let ok = wing::allow_retry_budget(budget, 1000000000);
            sub.assert_true(ok, "Retry within budget allowed");
        }

        // 21st retry attempt exceeds budget during flood
        let blocked = wing::allow_retry_budget(budget, 1000000000);
        sub.assert_false(blocked, "Retry exceeding 20% budget rejected to prevent retry storm");

        // After window advances (t = 12s, delta = 11s > 10s window), budget resets
        wing::record_primary_request(budget, 12000000000);
        sub.assert_eq(budget.retried_requests, 0, "Retried requests reset in new window");
        let ok_new = wing::allow_retry_budget(budget, 12000000000);
        sub.assert_true(ok_new, "Retry permitted after window resets");
    };
}

// --- Component: net_dns_svcb_ech ---
// tests/dns_svcb_ech_test.goose
// Verification Suite for RFC 9460 (HTTPS/SVCB DNS Resource Records),
// Encrypted Client Hello (ECH) parameter extraction, and DNS Cache Lifecycle.

fn test_rfc9460_svcb_https_rdata(t: lit::T&) {
    t.run("1. Multi-ALPN, Port, and Dual-Stack IP Hints") { sub =>
        // Parameter wire block:
        // Key 1 (ALPN, len 6): "h3" (len 2) + "h2" (len 2) -> 02 68 33 02 68 32
        // Key 2 (NoDefaultAlpn, len 0)
        // Key 3 (Port, len 2): 8443 (0x20FB)
        // Key 4 (IPv4Hint, len 8): 192.0.2.1 (0xC0000201), 198.51.100.1 (0xC6336401)
        // Key 5 (ECH, len 10): 01 02 03 04 05 06 07 08 09 0A
        // Key 6 (IPv6Hint, len 16): 2001:0db8::1
        var raw_params: u8[>..] = [];
        // Key 1
        raw_params.append([0x00, 0x01, 0x00, 0x06, 0x02, 'h', '3', 0x02, 'h', '2']);
        // Key 2
        raw_params.append([0x00, 0x02, 0x00, 0x00]);
        // Key 3
        raw_params.append([0x00, 0x03, 0x00, 0x02, 0x20, 0xFB]);
        // Key 4
        raw_params.append([0x00, 0x04, 0x00, 0x08, 0xC0, 0x00, 0x02, 0x01, 0xC6, 0x33, 0x64, 0x01]);
        // Key 5
        raw_params.append([0x00, 0x05, 0x00, 0x0A, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A]);
        // Key 6
        raw_params.append([
            0x00, 0x06, 0x00, 0x10,
            0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ]);

        var rec = wing::HttpsRecord { .. };
        let ok = wing::parse_https_svc_params(raw_params[..], rec);
        sub.assert_true(ok, "parse_https_svc_params succeeds on well-formed ascending keys");

        sub.assert_eq(rec.alpns.len, 2, "Parsed 2 ALPN protocols");
        sub.assert_bytes_eq(rec.alpns[0], "h3", "First ALPN is h3");
        sub.assert_bytes_eq(rec.alpns[1], "h2", "Second ALPN is h2");

        sub.assert_true(rec.no_default_alpn, "no_default_alpn flag parsed");
        sub.assert_eq(rec.port, 8443, "Custom port parsed");

        sub.assert_eq(rec.ipv4_hints.len, 2, "Parsed 2 IPv4 hints");
        sub.assert_eq(rec.ipv4_hints[0], 0xC0000201, "First IPv4 hint matches 192.0.2.1");
        sub.assert_eq(rec.ipv4_hints[1], 0xC6336401, "Second IPv4 hint matches 198.51.100.1");

        sub.assert_true(rec.has_ech, "ECH flag set");
        sub.assert_eq(rec.ech_config_list.len, 10, "ECHConfigList length is 10 bytes");
        sub.assert_eq(rec.ech_config_list[0], 1, "First byte of ECHConfigList matches");

        sub.assert_eq(rec.ipv6_hints.len, 1, "Parsed 1 IPv6 hint");
        sub.assert_eq(rec.ipv6_hints[0][0], 0x20, "First byte of IPv6 hint is 0x20");
        sub.assert_eq(rec.ipv6_hints[0][15], 0x01, "Last byte of IPv6 hint is 0x01");
    };

    t.run("2. RFC 9460 Invariant Rejections (Order & Bounds)") { sub =>
        // Reject out-of-order keys: Key 4 followed by Key 3
        var out_of_order: u8[>..] = [];
        out_of_order.append([0x00, 0x04, 0x00, 0x04, 0xC0, 0x00, 0x02, 0x01]);
        out_of_order.append([0x00, 0x03, 0x00, 0x02, 0x01, 0xBB]);
        var r1 = wing::HttpsRecord { .. };
        sub.assert_false(wing::parse_https_svc_params(out_of_order[..], r1), "Out-of-order keys rejected");

        // Reject duplicate keys: Key 3 twice
        var duplicate_key: u8[>..] = [];
        duplicate_key.append([0x00, 0x03, 0x00, 0x02, 0x01, 0xBB]);
        duplicate_key.append([0x00, 0x03, 0x00, 0x02, 0x01, 0xBB]);
        var r2 = wing::HttpsRecord { .. };
        sub.assert_false(wing::parse_https_svc_params(duplicate_key[..], r2), "Duplicate keys rejected");

        // Reject bad port length: 1 byte
        var bad_port: u8[>..] = [];
        bad_port.append([0x00, 0x03, 0x00, 0x01, 0x50]);
        var r3 = wing::HttpsRecord { .. };
        sub.assert_false(wing::parse_https_svc_params(bad_port[..], r3), "Port length != 2 rejected");

        // Reject bad IPv4 length: 6 bytes (not multiple of 4)
        var bad_ip4: u8[>..] = [];
        bad_ip4.append([0x00, 0x04, 0x00, 0x06, 0xC0, 0x00, 0x02, 0x01, 0x00, 0x01]);
        var r4 = wing::HttpsRecord { .. };
        sub.assert_false(wing::parse_https_svc_params(bad_ip4[..], r4), "IPv4 hint length not multiple of 4 rejected");

        // Reject truncated parameter value (stated length 4, actual bytes 2)
        var trunc_val: u8[>..] = [];
        trunc_val.append([0x00, 0x04, 0x00, 0x04, 0xC0, 0x00]);
        var r5 = wing::HttpsRecord { .. };
        sub.assert_false(wing::parse_https_svc_params(trunc_val[..], r5), "Truncated parameter value rejected");
    };
}

fn test_doh_query_generation(t: lit::T&) {
    t.run("1. DoH POST Body and GET URL Construction") { sub =>
        var post_body: u8[>..] = [];
        let ok_post = wing::build_doh_post_body("cloudflare.com", rfc::DNS_QTYPE_HTTPS, 0x1234, post_body);
        sub.assert_true(ok_post, "build_doh_post_body succeeds");
        sub.assert_true(post_body.len >= 12, "Post body at least DNS header size (12 bytes)");

        // Header check: tx_id 0x1234
        sub.assert_eq(post_body[0], 0x12, "Tx ID byte 0");
        sub.assert_eq(post_body[1], 0x34, "Tx ID byte 1");

        // GET URL with base64url query parameter
        var get_url: u8[>..] = [];
        let ok_get = wing::build_doh_get_url("https://1.1.1.1/dns-query", "cloudflare.com", rfc::DNS_QTYPE_HTTPS, get_url);
        sub.assert_true(ok_get, "build_doh_get_url succeeds");
        sub.assert_true(core::starts_with(get_url[..], "https://1.1.1.1/dns-query?dns="), "URL starts with endpoint and ?dns=");
    };
}

fn test_dns_cache_lifecycle(t: lit::T&) {
    t.run("1. Freshness, Stale-While-Revalidate Window, and Expiration") { sub =>
        var cache = wing::DnsCache { .. };

        var entry = wing::DnsCacheEntry { .. };
        entry.domain.append("api.example.com");
        entry.qtype = rfc::DNS_QTYPE_A;
        entry.ipv4_hints.push(0x7F000001); // 127.0.0.1
        entry.inserted_at_sec = 1000;
        entry.ttl_sec = 60;
        entry.stale_ttl_sec = 300; // Stale window: 1060 .. 1360
        entry.valid = true;

        wing::dns_cache_insert(cache, entry);
        sub.assert_eq(cache.entries.len, 1, "Cache holds 1 entry");

        // Lookup at t = 1030 (Fresh, elapsed 30 < 60)
        var out1 = wing::DnsCacheEntry { .. };
        let st1 = wing::dns_cache_lookup(cache, "api.example.com", rfc::DNS_QTYPE_A, 1030, out1);
        sub.assert_eq(st1, wing::DnsCacheStatus.Fresh, "Lookup at t=1030 is Fresh");
        sub.assert_eq(out1.ipv4_hints.len, 1, "Output holds 1 IP");
        sub.assert_eq(out1.ipv4_hints[0], 0x7F000001, "IP matches");

        // Lookup at t = 1100 (Stale, elapsed 100 >= 60 but < 360)
        var out2 = wing::DnsCacheEntry { .. };
        let st2 = wing::dns_cache_lookup(cache, "api.example.com", rfc::DNS_QTYPE_A, 1100, out2);
        sub.assert_eq(st2, wing::DnsCacheStatus.Stale, "Lookup at t=1100 is Stale");

        // Lookup at t = 1400 (Expired, elapsed 400 >= 360)
        var out3 = wing::DnsCacheEntry { .. };
        let st3 = wing::dns_cache_lookup(cache, "api.example.com", rfc::DNS_QTYPE_A, 1400, out3);
        sub.assert_eq(st3, wing::DnsCacheStatus.Expired, "Lookup at t=1400 is Expired");

        // Overwrite existing entry with refreshed TTL
        var updated = entry;
        updated.inserted_at_sec = 1400;
        updated.ttl_sec = 120;
        wing::dns_cache_insert(cache, updated);
        sub.assert_eq(cache.entries.len, 1, "Cache still holds 1 entry after update");

        var out4 = wing::DnsCacheEntry { .. };
        let st4 = wing::dns_cache_lookup(cache, "api.example.com", rfc::DNS_QTYPE_A, 1450, out4);
        sub.assert_eq(st4, wing::DnsCacheStatus.Fresh, "Lookup after refresh is Fresh");
    };
}

fn main() {
    var runner = lit::new_runner("Network Transport Drivers, Connection Pool, and Poller Suite", lit::Verbosity.Verbose);

    lit::run_case(runner, "1. Transport Driver Probing", test_driver_probing);
    lit::run_case(runner, "2. Driver Fallback and Auto-Selection", test_driver_fallback_and_selection);
    lit::run_case(runner, "3. Windows RIO Buffer Lifecycle", test_rio_buffer_lifecycle);
    lit::run_case(runner, "4. io_uring SQE/CQE Batch Submissions", test_uring_sqe_cqe_batch);
    lit::run_case(runner, "5. macOS kqueue Event Lifecycle", test_kqueue_event_lifecycle);
    lit::run_case(runner, "6. Driver Summary Formatter", test_driver_summary_formatter);
    lit::run_case(runner, "7. AF_XDP & DPDK Kernel-Bypass Architecture", test_af_xdp_and_dpdk_kernel_bypass);
    lit::run_case(runner, "8. SmartNIC & Hardware kTLS Crypto Offload", test_smartnic_ktls_offload);
    lit::run_case(runner, "9. PoolKey Dimensions & Isolation", test_pool_key_dimensions_and_isolation);
    lit::run_case(runner, "10. WantQueue Dual-Slice FIFO", test_want_queue_dual_slice);
    lit::run_case(runner, "11. Connection Liveness & Extensive Checks", test_connection_liveness_and_extensive_checks);
    lit::run_case(runner, "12. HTTP/2 IP Coalescing & SAN Matching", test_http2_ip_coalescing_and_san_matching);
    lit::run_case(runner, "13. StreamPool Quotas & Eviction", test_stream_pool_quotas_and_eviction);
    lit::run_case(runner, "14. CVE-2026-56866 CONNECT Rejection Pool Safety", test_cve_2026_56866_connect_rejection_pool_safety);
    lit::run_case(runner, "15. Poller Creation & Lifecycle across L4 Driver Backends", test_poller_creation_and_lifecycle);
    lit::run_case(runner, "16. Socket Registration & Readiness Multiplexing", test_poller_registration_and_readiness);
    lit::run_case(runner, "17. High-Resolution Timer Wheel", test_poller_timer_wheel);
    lit::run_case(runner, "18. Non-blocking EventLoop I/O", test_event_loop_io);
    lit::run_case(runner, "19. Bidirectional Client-Server Mock Cycle", test_bidi_client_server_cycle);
    lit::run_case(runner, "20. 15-bit Coarse Socket Timeouts", test_coarse_socket_timeouts);
    lit::run_case(runner, "21. CAD Calculation & Absolute Floor", test_cad_calculation_and_absolute_floor);
    lit::run_case(runner, "22. RFC 6724 & HEv3 Interleaving", test_rfc6724_and_hev3_interleaving);
    lit::run_case(runner, "23. DNS Race & Resolution Delay", test_dns_race_and_resolution_delay);
    lit::run_case(runner, "24. AttemptManager Racing & Winner", test_attempt_manager_racing_and_winner);
    lit::run_case(runner, "25. Tier 1 Stale Socket & QUIC Fallback", test_tier1_stale_socket_and_quic_fallback);
    lit::run_case(runner, "26. Tier 2 Backoff & Jitter Strategies", test_tier2_exponential_backoff_and_jitter);
    lit::run_case(runner, "27. RFC 9110 Retry-After Parser", test_rfc9110_retry_after_parser);
    lit::run_case(runner, "28. Circuit Breaker & Adaptive Retry Budget", test_circuit_breaker_and_adaptive_retry_budget);
    lit::run_case(runner, "29. RFC 9460 HTTPS/SVCB Parameter Parsing", test_rfc9460_svcb_https_rdata);
    lit::run_case(runner, "30. DoH Query Serialization", test_doh_query_generation);
    lit::run_case(runner, "31. DNS Cache Lifecycle & Stale-While-Revalidate", test_dns_cache_lifecycle);

    let ok = lit::finish(runner);
    assert(ok);
}
