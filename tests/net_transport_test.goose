// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Consolidated Verification Suite: Network Transport Drivers, Connection Pool, and Poller Suite
//
// RUN: goose build -o %t.exe %s
// RUN: %t.exe
import std;
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

// ----------------------------------------------------------------------------
// 1. Transport Driver Probing
// ----------------------------------------------------------------------------
fn test_driver_probing(t: lit::T&) {
    t.run("Standard Driver Probing (Universal)") { sub =>
        let p_win = net_internal::probe_transport_driver_for_platform(net_internal::TransportDriverKind.Standard, net_internal::TargetPlatform.Windows);
        sub.assert_true(p_win.available, "Standard available on Windows");
        sub.assert_eq(p_win.error_code, net_internal::ERR_SUCCESS, "Standard error code 0 on Windows");

        let p_linux = net_internal::probe_transport_driver_for_platform(net_internal::TransportDriverKind.Standard, net_internal::TargetPlatform.Linux);
        sub.assert_true(p_linux.available, "Standard available on Linux");
        sub.assert_eq(p_linux.error_code, net_internal::ERR_SUCCESS, "Standard error code 0 on Linux");

        let p_mac = net_internal::probe_transport_driver_for_platform(net_internal::TransportDriverKind.Standard, net_internal::TargetPlatform.Darwin);
        sub.assert_true(p_mac.available, "Standard available on macOS");
        sub.assert_eq(p_mac.error_code, net_internal::ERR_SUCCESS, "Standard error code 0 on macOS");
    };

    t.run("Windows RIO Probing") { sub =>
        let p_win = net_internal::probe_transport_driver_for_platform(net_internal::TransportDriverKind.WindowsRIO, net_internal::TargetPlatform.Windows);
        sub.assert_true(p_win.available, "RIO available on Windows");
        sub.assert_eq(p_win.error_code, net_internal::ERR_SUCCESS, "RIO error code 0 on Windows");
        sub.assert_true(net_internal::driver_has_cap(p_win.capabilities, net_internal::CAP_KERNEL_BYPASS), "RIO has KernelBypass");
        sub.assert_true(net_internal::driver_has_cap(p_win.capabilities, net_internal::CAP_ZERO_COPY), "RIO has ZeroCopy");
        sub.assert_true(net_internal::driver_has_cap(p_win.capabilities, net_internal::CAP_PAGE_LOCKED_BUFFERS), "RIO has PageLockedBuffers");
        sub.assert_true(net_internal::driver_has_cap(p_win.capabilities, net_internal::CAP_BATCH_IO), "RIO has BatchIO");

        let p_linux = net_internal::probe_transport_driver_for_platform(net_internal::TransportDriverKind.WindowsRIO, net_internal::TargetPlatform.Linux);
        sub.assert_false(p_linux.available, "RIO unavailable on Linux");
        sub.assert_eq(p_linux.error_code, net_internal::ERR_ENOSYS, "RIO returns -ENOSYS on Linux");

        let p_mac = net_internal::probe_transport_driver_for_platform(net_internal::TransportDriverKind.WindowsRIO, net_internal::TargetPlatform.Darwin);
        sub.assert_false(p_mac.available, "RIO unavailable on macOS");
        sub.assert_eq(p_mac.error_code, net_internal::ERR_ENOSYS, "RIO returns -ENOSYS on macOS");
    };

    t.run("Linux io_uring Probing") { sub =>
        let p_linux = net_internal::probe_transport_driver_for_platform(net_internal::TransportDriverKind.IoUring, net_internal::TargetPlatform.Linux);
        sub.assert_true(p_linux.available, "io_uring available on Linux");
        sub.assert_eq(p_linux.error_code, net_internal::ERR_SUCCESS, "io_uring error code 0 on Linux");
        sub.assert_true(net_internal::driver_has_cap(p_linux.capabilities, net_internal::CAP_RING_COMPLETION), "io_uring has RingCompletion");
        sub.assert_true(net_internal::driver_has_cap(p_linux.capabilities, net_internal::CAP_ZERO_COPY), "io_uring has ZeroCopy");
        sub.assert_true(net_internal::driver_has_cap(p_linux.capabilities, net_internal::CAP_BATCH_IO), "io_uring has BatchIO");
        sub.assert_true(net_internal::driver_has_cap(p_linux.capabilities, net_internal::CAP_DIRECT_DESCRIPTORS), "io_uring has DirectDescriptors");
        sub.assert_true(net_internal::driver_has_cap(p_linux.capabilities, net_internal::CAP_MULTISHOT_RECV), "io_uring has MultishotRecv");

        let p_win = net_internal::probe_transport_driver_for_platform(net_internal::TransportDriverKind.IoUring, net_internal::TargetPlatform.Windows);
        sub.assert_false(p_win.available, "io_uring unavailable on Windows");
        sub.assert_eq(p_win.error_code, net_internal::ERR_ENOSYS, "io_uring returns -ENOSYS on Windows");

        let p_mac = net_internal::probe_transport_driver_for_platform(net_internal::TransportDriverKind.IoUring, net_internal::TargetPlatform.Darwin);
        sub.assert_false(p_mac.available, "io_uring unavailable on macOS");
        sub.assert_eq(p_mac.error_code, net_internal::ERR_ENOSYS, "io_uring returns -ENOSYS on macOS");
    };

    t.run("macOS kqueue Probing") { sub =>
        let p_mac = net_internal::probe_transport_driver_for_platform(net_internal::TransportDriverKind.Kqueue, net_internal::TargetPlatform.Darwin);
        sub.assert_true(p_mac.available, "kqueue available on macOS");
        sub.assert_eq(p_mac.error_code, net_internal::ERR_SUCCESS, "kqueue error code 0 on macOS");
        sub.assert_true(net_internal::driver_has_cap(p_mac.capabilities, net_internal::CAP_BATCH_IO), "kqueue has BatchIO");
        sub.assert_true(net_internal::driver_has_cap(p_mac.capabilities, net_internal::CAP_RING_COMPLETION), "kqueue has RingCompletion");
        sub.assert_true(net_internal::driver_has_cap(p_mac.capabilities, net_internal::CAP_DIRECT_DESCRIPTORS), "kqueue has DirectDescriptors");
        sub.assert_true(net_internal::driver_has_cap(p_mac.capabilities, net_internal::CAP_EXACT_BUF_METRICS), "kqueue has ExactBufMetrics");

        let p_win = net_internal::probe_transport_driver_for_platform(net_internal::TransportDriverKind.Kqueue, net_internal::TargetPlatform.Windows);
        sub.assert_false(p_win.available, "kqueue unavailable on Windows");
        sub.assert_eq(p_win.error_code, net_internal::ERR_ENOSYS, "kqueue returns -ENOSYS on Windows");

        let p_linux = net_internal::probe_transport_driver_for_platform(net_internal::TransportDriverKind.Kqueue, net_internal::TargetPlatform.Linux);
        sub.assert_false(p_linux.available, "kqueue unavailable on Linux");
        sub.assert_eq(p_linux.error_code, net_internal::ERR_ENOSYS, "kqueue returns -ENOSYS on Linux");
    };

    t.run("Linux AF_XDP (XSK Kernel-Bypass) Probing") { sub =>
        let p_linux = net_internal::probe_transport_driver_for_platform(net_internal::TransportDriverKind.AfXdp, net_internal::TargetPlatform.Linux);
        sub.assert_true(p_linux.available, "AF_XDP available on Linux target");
        sub.assert_eq(p_linux.error_code, net_internal::ERR_SUCCESS, "AF_XDP error code 0 on Linux");
        sub.assert_true(net_internal::driver_has_cap(p_linux.capabilities, net_internal::CAP_KERNEL_BYPASS), "AF_XDP has KernelBypass");
        sub.assert_true(net_internal::driver_has_cap(p_linux.capabilities, net_internal::CAP_ZERO_COPY), "AF_XDP has ZeroCopy");
        sub.assert_true(net_internal::driver_has_cap(p_linux.capabilities, net_internal::CAP_PAGE_LOCKED_BUFFERS), "AF_XDP has PageLockedBuffers");
        sub.assert_true(net_internal::driver_has_cap(p_linux.capabilities, net_internal::CAP_AF_XDP_UMEM), "AF_XDP has AfXdpUmem");

        let p_win = net_internal::probe_transport_driver_for_platform(net_internal::TransportDriverKind.AfXdp, net_internal::TargetPlatform.Windows);
        sub.assert_false(p_win.available, "AF_XDP unavailable on Windows");
        sub.assert_eq(p_win.error_code, net_internal::ERR_ENOSYS, "AF_XDP returns -ENOSYS on Windows");

        let p_mac = net_internal::probe_transport_driver_for_platform(net_internal::TransportDriverKind.AfXdp, net_internal::TargetPlatform.Darwin);
        sub.assert_false(p_mac.available, "AF_XDP unavailable on macOS");
        sub.assert_eq(p_mac.error_code, net_internal::ERR_ENOSYS, "AF_XDP returns -ENOSYS on macOS");
    };

    t.run("DPDK Poll Mode Driver Probing") { sub =>
        let p_linux = net_internal::probe_transport_driver_for_platform(net_internal::TransportDriverKind.Dpdk, net_internal::TargetPlatform.Linux);
        sub.assert_true(p_linux.available, "DPDK PMD available on Linux");
        sub.assert_eq(p_linux.error_code, net_internal::ERR_SUCCESS, "DPDK error code 0");
        sub.assert_true(net_internal::driver_has_cap(p_linux.capabilities, net_internal::CAP_KERNEL_BYPASS), "DPDK has KernelBypass");
        sub.assert_true(net_internal::driver_has_cap(p_linux.capabilities, net_internal::CAP_ZERO_COPY), "DPDK has ZeroCopy");
        sub.assert_true(net_internal::driver_has_cap(p_linux.capabilities, net_internal::CAP_BATCH_IO), "DPDK has BatchIO");
        sub.assert_true(net_internal::driver_has_cap(p_linux.capabilities, net_internal::CAP_DPDK_PMD), "DPDK has DpdkPmd");

        let p_win = net_internal::probe_transport_driver_for_platform(net_internal::TransportDriverKind.Dpdk, net_internal::TargetPlatform.Windows);
        sub.assert_false(p_win.available, "DPDK unavailable on Windows");
        sub.assert_eq(p_win.error_code, net_internal::ERR_ENOSYS, "DPDK returns -ENOSYS on Windows");

        let p_mac = net_internal::probe_transport_driver_for_platform(net_internal::TransportDriverKind.Dpdk, net_internal::TargetPlatform.Darwin);
        sub.assert_false(p_mac.available, "DPDK unavailable on macOS");
        sub.assert_eq(p_mac.error_code, net_internal::ERR_ENOSYS, "DPDK returns -ENOSYS on macOS");
    };

    t.run("SmartNIC Hardware TLS Offload Probing") { sub =>
        let p_linux = net_internal::probe_transport_driver_for_platform(net_internal::TransportDriverKind.SmartNicOffload, net_internal::TargetPlatform.Linux);
        sub.assert_true(p_linux.available, "SmartNIC available on Linux");
        sub.assert_true(net_internal::driver_has_cap(p_linux.capabilities, net_internal::CAP_ZERO_COPY), "SmartNIC has ZeroCopy");
        sub.assert_true(net_internal::driver_has_cap(p_linux.capabilities, net_internal::CAP_NIC_TLS_OFFLOAD), "SmartNIC has NicTlsOffload");

        let p_win = net_internal::probe_transport_driver_for_platform(net_internal::TransportDriverKind.SmartNicOffload, net_internal::TargetPlatform.Windows);
        sub.assert_true(p_win.available, "SmartNIC available on Windows");
        sub.assert_true(net_internal::driver_has_cap(p_win.capabilities, net_internal::CAP_NIC_TLS_OFFLOAD), "SmartNIC has NicTlsOffload on Windows");

        let p_mac = net_internal::probe_transport_driver_for_platform(net_internal::TransportDriverKind.SmartNicOffload, net_internal::TargetPlatform.Darwin);
        sub.assert_false(p_mac.available, "SmartNIC unavailable on macOS");
        sub.assert_eq(p_mac.error_code, net_internal::ERR_ENOSYS, "SmartNIC returns -ENOSYS on macOS");
    };
}

// ----------------------------------------------------------------------------
// 2. Driver Fallback and Auto-Selection
// ----------------------------------------------------------------------------
fn test_driver_fallback_and_selection(t: lit::T&) {
    t.run("Standard Selection Everywhere") { sub =>
        var cfg = net_internal::TransportDriverConfig {
            preferred_kind: net_internal::TransportDriverKind.Standard,
            ..
        };
        sub.assert_true(net_internal::init_transport_driver_with_platform(cfg, net_internal::TargetPlatform.Windows), "Init ok on Windows");
        sub.assert_true(cfg.active_kind == net_internal::TransportDriverKind.Standard, "Active is Standard");
        sub.assert_true(cfg.is_probed, "Is probed");
    };

    t.run("Windows Auto-Selection: io_uring preferred with kernel bypass") { sub =>
        var cfg = net_internal::TransportDriverConfig {
            preferred_kind:       net_internal::TransportDriverKind.IoUring,
            enable_kernel_bypass: true,
            ..
        };
        sub.assert_true(net_internal::init_transport_driver_with_platform(cfg, net_internal::TargetPlatform.Windows), "Init ok");
        sub.assert_true(cfg.active_kind == net_internal::TransportDriverKind.WindowsRIO, "Auto-selected WindowsRIO");
        sub.assert_true(net_internal::driver_has_cap(cfg.capabilities, net_internal::CAP_KERNEL_BYPASS), "Has KernelBypass");
    };

    t.run("Windows Graceful Fallback: io_uring preferred without bypass") { sub =>
        var cfg = net_internal::TransportDriverConfig {
            preferred_kind:       net_internal::TransportDriverKind.IoUring,
            enable_kernel_bypass: false,
            ..
        };
        sub.assert_true(net_internal::init_transport_driver_with_platform(cfg, net_internal::TargetPlatform.Windows), "Init ok");
        sub.assert_true(cfg.active_kind == net_internal::TransportDriverKind.Standard, "Fell back to Standard");
    };

    t.run("Linux Auto-Selection: WindowsRIO preferred") { sub =>
        var cfg = net_internal::TransportDriverConfig {
            preferred_kind: net_internal::TransportDriverKind.WindowsRIO,
            ..
        };
        sub.assert_true(net_internal::init_transport_driver_with_platform(cfg, net_internal::TargetPlatform.Linux), "Init ok");
        sub.assert_true(cfg.active_kind == net_internal::TransportDriverKind.IoUring, "Auto-selected io_uring");
        sub.assert_true(net_internal::driver_has_cap(cfg.capabilities, net_internal::CAP_RING_COMPLETION), "Has RingCompletion");
    };

    t.run("macOS Auto-Selection: io_uring or WindowsRIO preferred") { sub =>
        var cfg = net_internal::TransportDriverConfig {
            preferred_kind: net_internal::TransportDriverKind.IoUring,
            ..
        };
        sub.assert_true(net_internal::init_transport_driver_with_platform(cfg, net_internal::TargetPlatform.Darwin), "Init ok");
        sub.assert_true(cfg.active_kind == net_internal::TransportDriverKind.Kqueue, "Auto-selected kqueue on macOS");
        sub.assert_true(net_internal::driver_has_cap(cfg.capabilities, net_internal::CAP_EXACT_BUF_METRICS), "Has ExactBufMetrics");
    };

    t.run("Universal Auto Driver Selection (Windows, Linux, macOS)") { sub =>
        var cfg_win = net_internal::TransportDriverConfig { preferred_kind: net_internal::TransportDriverKind.Auto, .. };
        sub.assert_true(net_internal::init_transport_driver_with_platform(cfg_win, net_internal::TargetPlatform.Windows), "Auto on Windows ok");
        sub.assert_true(cfg_win.active_kind == net_internal::TransportDriverKind.WindowsRIO, "Auto Windows activates RIO");

        var cfg_linux = net_internal::TransportDriverConfig { preferred_kind: net_internal::TransportDriverKind.Auto, .. };
        sub.assert_true(net_internal::init_transport_driver_with_platform(cfg_linux, net_internal::TargetPlatform.Linux), "Auto on Linux ok");
        sub.assert_true(cfg_linux.active_kind == net_internal::TransportDriverKind.IoUring, "Auto Linux activates io_uring");

        var cfg_mac = net_internal::TransportDriverConfig { preferred_kind: net_internal::TransportDriverKind.Auto, .. };
        sub.assert_true(net_internal::init_transport_driver_with_platform(cfg_mac, net_internal::TargetPlatform.Darwin), "Auto on macOS ok");
        sub.assert_true(cfg_mac.active_kind == net_internal::TransportDriverKind.Kqueue, "Auto macOS activates kqueue");

        let auto_cfg = net_internal::auto_transport_driver_config(2048, 131072);
        sub.assert_true(auto_cfg.is_probed, "Host auto config is probed");
        sub.assert_eq(auto_cfg.ring_size, 2048, "Ring size set");
        sub.assert_eq(auto_cfg.registered_buffer_size, 131072, "Reg buf size set");
    };
}

// ----------------------------------------------------------------------------
// 3. Windows RIO Buffer Lifecycle
// ----------------------------------------------------------------------------
fn test_rio_buffer_lifecycle(t: lit::T&) {
    t.run("RIO Buffer Registration and Slicing") { sub =>
        var buf = net_internal::new_rio_buffer(1001, 65536);
        sub.assert_eq(buf.buffer_id, 1001, "Buffer ID matches");
        sub.assert_eq(buf.offset, 0, "Initial offset is 0");
        sub.assert_eq(buf.length, 65536, "Length is 65536");
        sub.assert_true(buf.is_registered, "Buffer is registered");
        sub.assert_true(buf.page_locked, "Buffer is page-locked");

        sub.assert_true(net_internal::rio_can_zero_copy(buf, 1024), "Can zero-copy 1024B");
        sub.assert_true(net_internal::rio_can_zero_copy(buf, 65536), "Can zero-copy 65536B");
        sub.assert_false(net_internal::rio_can_zero_copy(buf, 70000), "Cannot zero-copy 70000B");

        // Sub-slice
        let sub_buf = net_internal::rio_sub_buffer(buf, 4096, 2048);
        sub.assert_eq(sub_buf.buffer_id, 1001, "Sub-slice keeps buffer ID");
        sub.assert_eq(sub_buf.offset, 4096, "Sub-slice offset is 4096");
        sub.assert_eq(sub_buf.length, 2048, "Sub-slice length is 2048");
        sub.assert_true(sub_buf.is_registered, "Sub-slice is registered");

        // Out of bounds sub-slice
        let oob_buf = net_internal::rio_sub_buffer(buf, 60000, 10000);
        sub.assert_false(oob_buf.is_registered, "OOB slice fails safely");

        // Deregister
        net_internal::rio_deregister_buffer(buf);
        sub.assert_false(buf.is_registered, "Buffer deregistered");
        sub.assert_false(buf.page_locked, "Page lock released");
        sub.assert_false(net_internal::rio_can_zero_copy(buf, 100), "Cannot zero-copy after deregister");
        sub.assert_eq(net_internal::rio_submit_send(0, buf, 0), -1, "rio_submit_send rejects unregistered buffer");
        sub.assert_eq(net_internal::rio_submit_recv(0, buf, 0), -1, "rio_submit_recv rejects unregistered buffer");
    };

    t.run("Physical Windows RIO Kernel Registration") { sub =>
        if net_internal::detect_target_platform() == net_internal::TargetPlatform.Windows {
            let avail = net_internal::native_rio_available();
            sub.assert_eq(avail, 1, "Native RIO is available in mswsock.dll");
            let probe = net_internal::native_rio_probe();
            sub.assert_eq(probe, 0, "Native RIO probe succeeds");
        }
    };
}

// ----------------------------------------------------------------------------
// 4. io_uring SQE/CQE Batch Submissions
// ----------------------------------------------------------------------------
fn test_uring_sqe_cqe_batch(t: lit::T&) {
    t.run("io_uring SQE Preparation") { sub =>
        var sqe_send = net_internal::UringSqe { .. };
        net_internal::uring_prep_send(sqe_send, 42, 0x1000, 2048, 999, true);
        sub.assert_eq(sqe_send.opcode, net_internal::URING_OP_SEND_ZC, "Send opcode is SEND_ZC");
        sub.assert_eq(sqe_send.fd, 42, "FD matches");
        sub.assert_eq(sqe_send.addr, 0x1000, "Addr matches");
        sub.assert_eq(sqe_send.len, 2048, "Len matches");
        sub.assert_eq(sqe_send.user_data, 999, "Tag matches");

        var sqe_recv = net_internal::UringSqe { .. };
        net_internal::uring_prep_recv(sqe_recv, 42, 0x2000, 4096, 1000, true);
        sub.assert_eq(sqe_recv.opcode, net_internal::URING_OP_RECV, "Recv opcode is RECV");
        sub.assert_eq(sqe_recv.flags, net_internal::URING_SQE_BUFFER_SELECT, "Multishot buffer select set");

        var sqe_accept = net_internal::UringSqe { .. };
        net_internal::uring_prep_accept(sqe_accept, 5, 1001);
        sub.assert_eq(sqe_accept.opcode, net_internal::URING_OP_ACCEPT, "Accept opcode matches");

        var sqe_cancel = net_internal::UringSqe { .. };
        net_internal::uring_prep_cancel(sqe_cancel, 999);
        sub.assert_eq(sqe_cancel.opcode, net_internal::URING_OP_ASYNC_CANCEL, "Cancel opcode matches");
        sub.assert_eq(sqe_cancel.addr, 999, "Tag to cancel stored in addr");
    };

    t.run("io_uring Batch Submission and CQE Reaping") { sub =>
        var state = net_internal::new_ring_queue_state(128);
        var sqes: net_internal::UringSqe[4] = [
            net_internal::UringSqe { opcode: net_internal::URING_OP_SEND, len: 512, user_data: 101, .. },
            net_internal::UringSqe { opcode: net_internal::URING_OP_SEND_ZC, len: 1024, user_data: 102, .. },
            net_internal::UringSqe { opcode: net_internal::URING_OP_RECV, flags: net_internal::URING_SQE_BUFFER_SELECT, len: 4096, user_data: 103, .. },
            net_internal::UringSqe { opcode: net_internal::URING_OP_NOP, len: 0, user_data: 104, .. },
        ];

        var cqes: net_internal::UringCqe[..32] = [];
        let submitted = net_internal::uring_submit_batch(state, sqes[..], cqes);
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
        sub.assert_true((cqes[2].flags & net_internal::URING_CQE_F_MORE) != 0, "Multishot CQE has F_MORE flag");

        // Invalid live kernel ring_fd (>= 0) must never fabricate loopback CQEs
        var bad_live_state = net_internal::new_ring_queue_state(128, 9999);
        var bad_cqes: net_internal::UringCqe[..32] = [];
        let bad_submitted = net_internal::uring_submit_batch(bad_live_state, sqes[..], bad_cqes);
        sub.assert_eq(bad_submitted, 0, "Invalid live ring_fd submits 0 SQEs");
        sub.assert_eq(bad_cqes.len, 0, "Invalid live ring_fd fabricates 0 CQEs");
        sub.assert_eq(bad_live_state.submissions_total, 0, "Invalid live ring_fd records 0 submissions");
        sub.assert_eq(bad_live_state.completions_total, 0, "Invalid live ring_fd records 0 completions");
    };
}

// ----------------------------------------------------------------------------
// 5. macOS kqueue Event Lifecycle
// ----------------------------------------------------------------------------
fn test_kqueue_event_lifecycle(t: lit::T&) {
    t.run("kqueue Kevent Preparation and Buffer Metrics") { sub =>
        var ev_read = net_internal::Kevent { .. };
        net_internal::kevent_prep_read(ev_read, 12, 501, true);
        sub.assert_eq(ev_read.ident, 12, "Read ident is fd 12");
        sub.assert_eq(ev_read.filter, net_internal::EVFILT_READ, "Filter is EVFILT_READ");
        sub.assert_true((ev_read.flags & net_internal::EV_CLEAR) != 0, "Edge-triggered EV_CLEAR is set");
        sub.assert_eq(ev_read.udata, 501, "udata matches tag 501");

        var ev_write = net_internal::Kevent { .. };
        net_internal::kevent_prep_write(ev_write, 14, 502, false);
        sub.assert_eq(ev_write.ident, 14, "Write ident is fd 14");
        sub.assert_eq(ev_write.filter, net_internal::EVFILT_WRITE, "Filter is EVFILT_WRITE");
        sub.assert_false((ev_write.flags & net_internal::EV_CLEAR) != 0, "Level-triggered EV_CLEAR not set");

        var ev_timer = net_internal::Kevent { .. };
        net_internal::kevent_prep_timer(ev_timer, 99, 250, 503);
        sub.assert_eq(ev_timer.ident, 99, "Timer ident is 99");
        sub.assert_eq(ev_timer.filter, net_internal::EVFILT_TIMER, "Filter is EVFILT_TIMER");
        sub.assert_eq(ev_timer.data, 250, "Timer period is 250ms");

        // Test exact buffer metrics
        ev_read.data = 16384;
        sub.assert_eq(net_internal::kevent_bytes_available(ev_read), 16384, "Exact 16384 bytes available in kernel buffer");

        // Test EOF flag
        sub.assert_false(net_internal::kevent_is_eof(ev_read), "Not EOF yet");
        ev_read.flags |= net_internal::EV_EOF;
        sub.assert_true(net_internal::kevent_is_eof(ev_read), "EOF flag detected cleanly");
    };
}

// ----------------------------------------------------------------------------
// 6. Driver Summary Formatter
// ----------------------------------------------------------------------------
fn test_driver_summary_formatter(t: lit::T&) {
    t.run("Summary String Formatting") { sub =>
        var cfg_rio = net_internal::TransportDriverConfig {
            preferred_kind:         net_internal::TransportDriverKind.WindowsRIO,
            ring_size:              2048,
            registered_buffer_size: 131072,
            ..
        };
        net_internal::init_transport_driver_with_platform(cfg_rio, net_internal::TargetPlatform.Windows);

        var summary_buf: u8[>..] = [];
        net_internal::format_driver_summary(cfg_rio, summary_buf);

        sub.assert_true(summary_buf.len > 0, "Summary buffer is not empty");
        sub.assert_contains(summary_buf[..], "Windows RIO", "Contains Windows RIO");
        sub.assert_contains(summary_buf[..], "KernelBypass", "Contains KernelBypass");
        sub.assert_contains(summary_buf[..], "ZeroCopy", "Contains ZeroCopy");
        sub.assert_contains(summary_buf[..], "2048", "Contains ring size 2048");
        sub.assert_contains(summary_buf[..], "131072B", "Contains buffer size 131072B");

        var cfg_kq = net_internal::TransportDriverConfig {
            preferred_kind: net_internal::TransportDriverKind.Kqueue,
            ..
        };
        net_internal::init_transport_driver_with_platform(cfg_kq, net_internal::TargetPlatform.Darwin);
        summary_buf.clear();
        net_internal::format_driver_summary(cfg_kq, summary_buf);
        sub.assert_contains(summary_buf[..], "kqueue", "Contains kqueue");
        sub.assert_contains(summary_buf[..], "ExactBufMetrics", "Contains ExactBufMetrics");
        sub.assert_contains(summary_buf[..], "BatchIO", "Contains BatchIO");

        var cfg_std = net_internal::TransportDriverConfig {
            preferred_kind: net_internal::TransportDriverKind.Standard,
            ..
        };
        net_internal::init_transport_driver_with_platform(cfg_std, net_internal::TargetPlatform.Linux);
        summary_buf.clear();
        net_internal::format_driver_summary(cfg_std, summary_buf);
        sub.assert_contains(summary_buf[..], "Standard", "Contains Standard");
        sub.assert_contains(summary_buf[..], "None (Standard Stream)", "Contains None");
    };
}

// ----------------------------------------------------------------------------
// 7. AF_XDP & DPDK Kernel-Bypass Architecture
// ----------------------------------------------------------------------------
fn test_af_xdp_and_dpdk_kernel_bypass(t: lit::T&) {
    t.run("AF_XDP UMEM Descriptor Lifecycle") { sub =>
        var umem = net_internal::AfXdpUmem {
            addr:          0x10000000,
            len:           8388608, // 8 MB UMEM
            chunk_size:    2048,
            headroom:      0,
            is_registered: true,
        };
        sub.assert_true(umem.is_registered, "UMEM registered");
        sub.assert_eq(umem.chunk_size, 2048, "Chunk size is 2048 bytes");

        // Verify XdpDesc packet descriptor
        var desc = net_internal::XdpDesc {
            addr:    0x10000800,
            len:     1460, // MSS payload
            options: 0,
        };
        sub.assert_eq(desc.addr, 0x10000800, "Packet buffer offset mapped");
        sub.assert_eq(desc.len, 1460, "Packet length 1460 bytes");

        var xsk = net_internal::new_af_xdp_socket();
        sub.assert_false(net_internal::af_xdp_fill_push(xsk, 0x10000800), "fill_push rejects unbound socket");
        sub.assert_false(net_internal::af_xdp_tx_submit(xsk, desc), "tx_submit rejects unbound socket");
        let _, rx_ok = net_internal::af_xdp_rx_poll(xsk);
        sub.assert_false(rx_ok, "rx_poll rejects unbound socket");
        let _, comp_ok = net_internal::af_xdp_complete_pop(xsk);
        sub.assert_false(comp_ok, "complete_pop rejects unbound socket");
        net_internal::af_xdp_close(xsk);
    };

    t.run("DPDK Port and Mempool Interface") { sub =>
        var dev = net_internal::new_dpdk_device(0);
        sub.assert_false(dev.is_initialized, "starts uninitialized");

        var pcfg = net_internal::DpdkPortConfig {
            port_id:      0,
            rx_queues:    4,
            tx_queues:    4,
            rx_ring_size: 1024,
            tx_ring_size: 1024,
            promiscuous:  true,
        };
        let init_res = net_internal::dpdk_init_port(dev, pcfg);
        sub.assert_eq(init_res, 0, "dpdk_init_port succeeded");
        sub.assert_true(dev.is_initialized, "dev is initialized");

        let start_res = net_internal::dpdk_start_port(dev);
        sub.assert_eq(start_res, 0, "dpdk_start_port succeeded");
        sub.assert_true(dev.is_started, "dev is started and polling NIC BAR");

        let pool = net_internal::dpdk_create_mempool(4096, 2048);
        sub.assert_true(pool.is_created, "mempool created");
        sub.assert_eq(pool.n_elements, 4096, "4096 packet mbufs");

        let tx_mbufs: u64[2] = [0xA001, 0xA002];
        let sent_pkts = net_internal::dpdk_tx_burst(dev, 0, tx_mbufs[..]);
        sub.assert_eq(sent_pkts, 2 as u16, "dpdk_tx_burst sent 2 packets");
        var rx_mbufs: u64[..32] = [];
        let recvd_pkts = net_internal::dpdk_rx_burst(dev, 0, rx_mbufs, 32);
        sub.assert_eq(recvd_pkts, 2 as u16, "dpdk_rx_burst received 2 packets");
        sub.assert_eq(rx_mbufs[0], 0xA001 as u64, "mbuf 0 matches");
        sub.assert_eq(rx_mbufs[1], 0xA002 as u64, "mbuf 1 matches");

        net_internal::dpdk_stop_port(dev);
        sub.assert_false(dev.is_started, "dev stopped cleanly");
    };
}

// ----------------------------------------------------------------------------
// 8. SmartNIC & Hardware kTLS Crypto Offload
// ----------------------------------------------------------------------------
fn test_smartnic_ktls_offload(t: lit::T&) {
    t.run("SmartNIC Hardware Model Identification") { sub =>
        sub.assert_contains(net_internal::smartnic_model_name(net_internal::SmartNicModel.MellanoxConnectX6Dx), "Mellanox ConnectX-6", "Identified CX-6 Dx");
        sub.assert_contains(net_internal::smartnic_model_name(net_internal::SmartNicModel.NvidiaBlueField3), "NVIDIA BlueField-3", "Identified BlueField-3 DPU");
        sub.assert_contains(net_internal::smartnic_model_name(net_internal::SmartNicModel.IntelMountEvans), "Intel Mount Evans", "Identified Mount Evans IPU");
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
        let sess, err = net_internal::smartnic_attach_hardware_tls(
            100,
            net_internal::SmartNicCipherSuite.AesGcm128,
            tx_key[..],
            tx_iv[..],
            tx_salt[..],
            tx_seq[..],
            rx_key[..],
            rx_iv[..],
            rx_salt[..],
            rx_seq[..],
        );
        if net_internal::detect_target_platform() == net_internal::TargetPlatform.Linux && err == 0 {
            sub.assert_true(sess.ktls_active, "kTLS active");
            sub.assert_true(sess.tx_offloaded, "TX offloaded");
            sub.assert_true(sess.rx_offloaded, "RX offloaded");
            sub.assert_eq(sess.fd, 100, "Target fd retained");
        } else {
            sub.assert_true(err != 0, "Non-Linux or non-kTLS socket rejects fake kTLS offload");
            sub.assert_false(sess.tx_offloaded, "TX not falsely marked offloaded");
            sub.assert_false(sess.rx_offloaded, "RX not falsely marked offloaded");
        }

        // Verify invalid fd rejects immediately with error
        let sess_bad, err_bad = net_internal::smartnic_attach_hardware_tls(
            -1,
            net_internal::SmartNicCipherSuite.AesGcm128,
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

// ----------------------------------------------------------------------------
// 9. PoolKey Dimensions & Isolation
// ----------------------------------------------------------------------------
fn test_pool_key_dimensions_and_isolation(t: lit::T&) {
    t.run("5-Dimensional PoolKey Exact Match and Partition Isolation") { sub =>
        let nak1 = net::new_network_anonymization_key("https://a.com", false, 0, 1, 0);
        let nak2 = net::new_network_anonymization_key("https://a.com", false, 0, 1, 0);
        let nak_cross = net::new_network_anonymization_key("https://a.com", true, 0, 1, 0);
        let nak_nonce = net::new_network_anonymization_key("https://a.com", false, 42, 1, 0);
        let nak_part = net::new_network_anonymization_key("https://a.com", false, 0, 2, 0);
        let nak_worker = net::new_network_anonymization_key("https://a.com", false, 0, 1, 99);

        sub.assert_true(net::network_anonymization_key_equals(nak1, nak2), "Identical NAK matches");
        sub.assert_false(net::network_anonymization_key_equals(nak1, nak_cross), "Cross-site flag isolates partition");
        sub.assert_false(net::network_anonymization_key_equals(nak1, nak_nonce), "Ephemeral nonce isolates partition");
        sub.assert_false(net::network_anonymization_key_equals(nak1, nak_part), "Network isolation partition isolates partition");
        sub.assert_false(net::network_anonymization_key_equals(nak1, nak_worker), "Worker session ID isolates proxy automation workers");

        // Case insensitivity of top frame site
        let nak_upper = net::new_network_anonymization_key("HTTPS://A.COM", false, 0, 1, 0);
        sub.assert_true(net::network_anonymization_key_equals(nak1, nak_upper), "Top frame site matches case-insensitively");

        let direct_chain = net::new_direct_proxy_chain();
        let socks_proxy = net::new_proxy_server(net::ProxyScheme.Socks5h, "proxy.local", 1080);
        let socks_chain = net::new_single_proxy_chain(socks_proxy);
        let http_proxy = net::new_proxy_server(net::ProxyScheme.Http, "proxy.local", 8080);
        let http_chain = net::new_single_proxy_chain(http_proxy);

        let default_policy = net::TlsAndDnsPolicy { .. };
        var privacy_policy = net::TlsAndDnsPolicy { .. };
        privacy_policy.privacy_mode = net::PrivacyMode.Enabled;

        var doh_policy = net::TlsAndDnsPolicy { .. };
        doh_policy.secure_dns_policy = net::SecureDnsPolicy.Disable;

        var cert_policy = net::TlsAndDnsPolicy { .. };
        cert_policy.disable_cert_network_fetches = true;

        var net_policy = net::TlsAndDnsPolicy { .. };
        net_policy.target_network_id = 999;

        let key1 = net::new_pool_key(net::PoolScheme.Https, "api.service.com", 443, direct_chain, nak1, default_policy);
        let key2 = net::new_pool_key(net::PoolScheme.Https, "api.service.com", 443, direct_chain, nak2, default_policy);
        let key_case = net::new_pool_key(net::PoolScheme.Https, "API.SERVICE.COM", 443, direct_chain, nak1, default_policy);
        let key_port = net::new_pool_key(net::PoolScheme.Https, "api.service.com", 8443, direct_chain, nak1, default_policy);
        let key_scheme = net::new_pool_key(net::PoolScheme.Http, "api.service.com", 80, direct_chain, nak1, default_policy);
        let key_h2c = net::new_pool_key(net::PoolScheme.H2c, "api.service.com", 80, direct_chain, nak1, default_policy);
        let key_proxy_socks = net::new_pool_key(net::PoolScheme.Https, "api.service.com", 443, socks_chain, nak1, default_policy);
        let key_proxy_http = net::new_pool_key(net::PoolScheme.Https, "api.service.com", 443, http_chain, nak1, default_policy);
        let key_priv = net::new_pool_key(net::PoolScheme.Https, "api.service.com", 443, direct_chain, nak1, privacy_policy);
        let key_doh = net::new_pool_key(net::PoolScheme.Https, "api.service.com", 443, direct_chain, nak1, doh_policy);
        let key_cert = net::new_pool_key(net::PoolScheme.Https, "api.service.com", 443, direct_chain, nak1, cert_policy);
        let key_net = net::new_pool_key(net::PoolScheme.Https, "api.service.com", 443, direct_chain, nak1, net_policy);

        sub.assert_true(net::pool_key_equals(key1, key2), "Key1 equals Key2 with identical dimensions");
        sub.assert_true(net::pool_key_equals(key1, key_case), "Host matches case-insensitively");
        sub.assert_false(net::pool_key_equals(key1, key_port), "Port mismatch isolates socket group");
        sub.assert_false(net::pool_key_equals(key1, key_scheme), "Scheme mismatch isolates socket group");
        sub.assert_false(net::pool_key_equals(key1, key_h2c), "H2c plaintext scheme isolates socket group (CVE-2026-94441)");
        sub.assert_false(net::pool_key_equals(key_scheme, key_h2c), "Http and H2c schemes are strictly isolated");
        sub.assert_false(net::pool_key_equals(key1, key_proxy_socks), "Proxy chain mismatch isolates socket group");
        sub.assert_false(net::pool_key_equals(key_proxy_socks, key_proxy_http), "Different proxy protocols isolated");
        sub.assert_false(net::pool_key_equals(key1, key_priv), "Privacy mode mismatch isolates socket group");
        sub.assert_false(net::pool_key_equals(key1, key_doh), "Secure DNS policy mismatch isolates socket group");
        sub.assert_false(net::pool_key_equals(key1, key_cert), "Cert network fetch flag mismatch isolates socket group");
        sub.assert_false(net::pool_key_equals(key1, key_net), "Target network ID mismatch isolates socket group");

        let h1 = net::pool_key_hash(key1);
        let h2 = net::pool_key_hash(key2);
        let h_case = net::pool_key_hash(key_case);
        let h_port = net::pool_key_hash(key_port);
        let h_scheme = net::pool_key_hash(key_scheme);
        sub.assert_eq(h1, h2, "Identical PoolKey produces identical hash");
        sub.assert_eq(h1, h_case, "Case-folded host produces identical hash");
        sub.assert_ne(h1, h_port, "Port difference changes hash");
        sub.assert_ne(h1, h_scheme, "Scheme difference changes hash");
    };

    t.run("Preconnect Scheme Normalization") { sub =>
        sub.assert_true(net::normalize_preconnect_scheme(net::PoolScheme.Ws) == net::PoolScheme.Http, "WS maps to HTTP");
        sub.assert_true(net::normalize_preconnect_scheme(net::PoolScheme.Wss) == net::PoolScheme.Https, "WSS maps to HTTPS");
        sub.assert_true(net::normalize_preconnect_scheme(net::PoolScheme.Http) == net::PoolScheme.Http, "HTTP preserved");
        sub.assert_true(net::normalize_preconnect_scheme(net::PoolScheme.Https) == net::PoolScheme.Https, "HTTPS preserved");
        sub.assert_true(net::normalize_preconnect_scheme(net::PoolScheme.H2c) == net::PoolScheme.H2c, "H2c preserved");

        sub.assert_true(net::is_cryptographic_scheme(net::PoolScheme.Https), "HTTPS is cryptographic");
        sub.assert_true(net::is_cryptographic_scheme(net::PoolScheme.Wss), "WSS is cryptographic");
        sub.assert_false(net::is_cryptographic_scheme(net::PoolScheme.Http), "HTTP is not cryptographic");
        sub.assert_false(net::is_cryptographic_scheme(net::PoolScheme.Ws), "WS is not cryptographic");
        sub.assert_false(net::is_cryptographic_scheme(net::PoolScheme.H2c), "H2c is not cryptographic");
    };
}

// ----------------------------------------------------------------------------
// 10. WantQueue Dual-Slice FIFO
// ----------------------------------------------------------------------------
fn test_want_queue_dual_slice(t: lit::T&) {
    t.run("FIFO Operations and Reallocation-Free Promotion") { sub =>
        var q = net::WantQueue { .. };
        sub.assert_true(net::is_queue_empty(q), "Initial queue is empty");
        sub.assert_eq(net::queue_len(q), 0, "Initial queue len is 0");

        let nak = net::new_network_anonymization_key("https://origin.io");
        let key = net::new_pool_key(net::PoolScheme.Https, "origin.io", 443, net::new_direct_proxy_chain(), nak, net::TlsAndDnsPolicy { .. });

        var w1 = net::WantConn { req_id: 101, .. };
        var w2 = net::WantConn { req_id: 102, .. };
        var w3 = net::WantConn { req_id: 103, .. };

        sub.assert_true(net::push_want(q, w1), "Pushed w1");
        sub.assert_true(net::push_want(q, w2), "Pushed w2");
        sub.assert_true(net::push_want(q, w3), "Pushed w3");
        sub.assert_eq(net::queue_len(q), 3, "Queue len == 3");
        sub.assert_false(net::is_queue_empty(q), "Queue is not empty");

        let p1, ok1 = net::pop_want(q);
        sub.assert_true(ok1 && p1.req_id == 101, "Popped w1 in FIFO order");
        sub.assert_eq(net::queue_len(q), 2, "Queue len == 2 after popping w1");

        // Cancel w2 while still in queue
        sub.assert_true(net::cancel_want(q, 102), "Cancelled w2");
        sub.assert_false(net::cancel_want(q, 99999), "Non-existent request ID cancellation returns false");

        let p3, ok3 = net::pop_want(q);
        sub.assert_true(ok3 && p3.req_id == 103, "Popped w3, skipping cancelled w2");
        sub.assert_eq(net::queue_len(q), 0, "Queue len == 0 after skipping w2 and popping w3");

        let p_none, ok_none = net::pop_want(q);
        sub.assert_false(ok_none, "Queue exhausted");
        sub.assert_true(net::is_queue_empty(q), "Queue is empty when exhausted");
    };

    t.run("Tail-to-Head Compaction Under Sustained Load") { sub =>
        var q = net::WantQueue { .. };
        let nak = net::new_network_anonymization_key("https://origin.io");
        let key = net::new_pool_key(net::PoolScheme.Https, "origin.io", 443, net::new_direct_proxy_chain(), nak, net::TlsAndDnsPolicy { .. });

        // Fill tail slice to maximum capacity (32 items)
        for i in 32 {
            var item = net::WantConn { req_id: (i + 1) as u64, .. };
            let pushed = net::push_want(q, item);
            sub.assert_true(pushed, "Pushed item into tail");
        }
        sub.assert_eq(net::queue_len(q), 32, "Queue filled with 32 items");

        // Pop 16 items: first pop transfers tail into head, then advances head_pos
        for i in 16 {
            let item, ok = net::pop_want(q);
            sub.assert_true(ok, "Popped item cleanly");
            sub.assert_eq(item.req_id, (i + 1) as u64, "Popped in strictly ascending FIFO order");
        }
        sub.assert_eq(net::queue_len(q), 16, "16 items remaining in head");

        // Push 16 more items into freshly empty tail slice
        for i in 16 {
            var item = net::WantConn { req_id: (100 + i) as u64, .. };
            let pushed = net::push_want(q, item);
            sub.assert_true(pushed, "Pushed into tail slice while head has items");
        }
        sub.assert_eq(net::queue_len(q), 32, "Queue has 16 in head + 16 in tail = 32 total");

        // Pop remaining 16 from head
        for i in 16 {
            let item, ok = net::pop_want(q);
            sub.assert_true(ok, "Popped item from head");
            sub.assert_eq(item.req_id, (17 + i) as u64, "Expected head item id");
        }

        // Next pop triggers compaction of tail into head
        let item100, ok100 = net::pop_want(q);
        sub.assert_true(ok100, "Popped first item from compacted tail");
        sub.assert_eq(item100.req_id, 100, "Compacted tail item preserved FIFO order");
    };
}

// ----------------------------------------------------------------------------
// 11. Connection Liveness & Extensive Checks
// ----------------------------------------------------------------------------
fn test_connection_liveness_and_extensive_checks(t: lit::T&) {
    t.run("OkHttp isHealthy and Non-Blocking FIN Detection") { sub =>
        let nak = net::new_network_anonymization_key("https://example.com");
        let key = net::new_pool_key(net::PoolScheme.Https, "example.com", 443, net::new_direct_proxy_chain(), nak, net::TlsAndDnsPolicy { .. });

        var conn = net::PooledConnection {
            conn_id:            1,
            key:                copy(key),
            protocol:           net::NegotiatedProtocol.Http11,
            active_allocations: 0,
            idle_at_ns:         1000000000, // Idle at 1.0s
            ..
        };

        // Within healthy threshold (500ms idle) -> healthy without extensive checks
        sub.assert_true(net::is_connection_healthy(conn, 1500000000, false), "Fresh idle connection is healthy");

        // After healthy threshold (2.5s idle) without FIN -> healthy
        sub.assert_true(net::is_connection_healthy(conn, 3500000000, true), "Idle connection with open socket is healthy");

        // Remote closed socket (FIN received / source_exhausted)
        conn.source_exhausted = true;
        sub.assert_false(net::is_connection_healthy(conn, 3500000000, true), "Extensive check detects source_exhausted EOF/FIN");
        sub.assert_true(conn.no_new_exchanges, "Connection marked no_new_exchanges on EOF");
        sub.assert_true(conn.closed, "Connection marked closed on EOF");

        // Already closed connection
        sub.assert_false(net::is_connection_healthy(conn, 3600000000, false), "Closed connection is unhealthy");

        // Remote RST received
        var conn_rst = net::PooledConnection {
            conn_id:    2,
            key:        copy(key),
            remote_rst: true,
            ..
        };
        sub.assert_false(net::is_connection_healthy(conn_rst, 2000000000, false), "Connection with remote RST is unhealthy");

        // Marked no_new_exchanges (e.g. Connection: close header received)
        var conn_no_new = net::PooledConnection {
            conn_id:          3,
            key:              copy(key),
            no_new_exchanges: true,
            ..
        };
        sub.assert_false(net::is_connection_healthy(conn_no_new, 2000000000, false), "Connection with no_new_exchanges is unhealthy");

        // Active multiplexed streams on HTTP/2 remain healthy while active
        var conn_h2 = net::PooledConnection {
            conn_id:            4,
            key:                copy(key),
            protocol:           net::NegotiatedProtocol.Http2,
            active_allocations: 5,
            ..
        };
        sub.assert_true(net::is_connection_healthy(conn_h2, 5000000000, false), "Active HTTP/2 multiplexed stream is healthy");

        // Idle connection past 90 seconds timeout becomes unhealthy
        var conn_idle_timeout = net::PooledConnection {
            conn_id:            5,
            key:                copy(key),
            active_allocations: 0,
            idle_at_ns:         1000000000,
            ..
        };
        sub.assert_false(net::is_connection_healthy(conn_idle_timeout, 96000000000, false), "Connection idle > 90s is unhealthy");
        sub.assert_true(conn_idle_timeout.closed, "Expired idle connection marked closed");
    };
}

// ----------------------------------------------------------------------------
// 12. HTTP/2 IP Coalescing & SAN Matching
// ----------------------------------------------------------------------------
fn test_http2_ip_coalescing_and_san_matching(t: lit::T&) {
    t.run("Chromium H2 IP Coalescing with Wildcard SAN & Security Boundaries") { sub =>
        let nak = net::new_network_anonymization_key("https://example.com");
        let nak_other = net::new_network_anonymization_key("https://other-site.com");
        let key_a = net::new_pool_key(net::PoolScheme.Https, "alpha.example.com", 443, net::new_direct_proxy_chain(), nak, net::TlsAndDnsPolicy { .. });
        let key_b = net::new_pool_key(net::PoolScheme.Https, "beta.example.com", 443, net::new_direct_proxy_chain(), nak, net::TlsAndDnsPolicy { .. });
        let key_deep = net::new_pool_key(net::PoolScheme.Https, "sub.beta.example.com", 443, net::new_direct_proxy_chain(), nak, net::TlsAndDnsPolicy { .. });
        let key_apex = net::new_pool_key(net::PoolScheme.Https, "example.com", 443, net::new_direct_proxy_chain(), nak, net::TlsAndDnsPolicy { .. });
        let key_unrelated = net::new_pool_key(net::PoolScheme.Https, "other.org", 443, net::new_direct_proxy_chain(), nak, net::TlsAndDnsPolicy { .. });
        let key_nak_mismatch = net::new_pool_key(net::PoolScheme.Https, "beta.example.com", 443, net::new_direct_proxy_chain(), nak_other, net::TlsAndDnsPolicy { .. });
        let key_http_plaintext = net::new_pool_key(net::PoolScheme.Http, "beta.example.com", 80, net::new_direct_proxy_chain(), nak, net::TlsAndDnsPolicy { .. });

        var conn = net::PooledConnection {
            conn_id:                10,
            key:                    copy(key_a),
            protocol:               net::NegotiatedProtocol.Http2,
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
        let can_coalesce_b, is_neg_b = net::can_coalesce_h2_connection(conn, key_b, "93.184.216.34");
        sub.assert_true(can_coalesce_b, "H2 connection coalesced for beta.example.com under *.example.com");
        sub.assert_false(is_neg_b, "Not a negative IP pool result");

        // 2. Wildcard boundary: multi-level subdomain (*.example.com must NOT match sub.beta.example.com)
        let can_coalesce_deep, is_neg_deep = net::can_coalesce_h2_connection(conn, key_deep, "93.184.216.34");
        sub.assert_false(can_coalesce_deep, "Wildcard *.example.com does NOT cover multi-level sub.beta.example.com");
        sub.assert_true(is_neg_deep, "Negative IP pool result recorded");

        // 3. Wildcard boundary: apex domain (*.example.com must NOT match example.com)
        let can_coalesce_apex, is_neg_apex = net::can_coalesce_h2_connection(conn, key_apex, "93.184.216.34");
        sub.assert_false(can_coalesce_apex, "Wildcard *.example.com does NOT cover apex domain example.com");
        sub.assert_true(is_neg_apex, "Negative IP pool result recorded");

        // 4. Target other.org resolves to same IP but SAN does NOT match
        let can_coalesce_other, is_neg_other = net::can_coalesce_h2_connection(conn, key_unrelated, "93.184.216.34");
        sub.assert_false(can_coalesce_other, "H2 connection rejected for unrelated domain");
        sub.assert_true(is_neg_other, "Recorded negative IP pool result for metric tracking");

        // 5. Partition isolation: NAK mismatch blocks coalescing even if IP and SAN match
        let can_coalesce_nak, is_neg_nak = net::can_coalesce_h2_connection(conn, key_nak_mismatch, "93.184.216.34");
        sub.assert_false(can_coalesce_nak, "NAK cross-site partition mismatch blocks coalescing");

        // 6. Security invariant CVE-2026-94441: Scheme mismatch blocks coalescing
        let can_coalesce_plain, is_neg_plain = net::can_coalesce_h2_connection(conn, key_http_plaintext, "93.184.216.34");
        sub.assert_false(can_coalesce_plain, "Plaintext HTTP connection cannot coalesce with HTTPS (CVE-2026-94441)");

        // 7. Invalid certificate: cert_valid = false blocks coalescing
        var conn_bad_cert = copy(conn);
        conn_bad_cert.cert_valid = false;
        let can_coalesce_cert, is_neg_cert = net::can_coalesce_h2_connection(conn_bad_cert, key_b, "93.184.216.34");
        sub.assert_false(can_coalesce_cert, "Invalid certificate blocks coalescing");
        sub.assert_true(is_neg_cert, "Recorded negative result on invalid certificate");

        // 8. IP mismatch: 93.184.216.34 vs 93.184.216.99
        let can_coalesce_ip, is_neg_ip = net::can_coalesce_h2_connection(conn, key_b, "93.184.216.99");
        sub.assert_false(can_coalesce_ip, "Different IP address blocks coalescing");
    };
}

// ----------------------------------------------------------------------------
// 13. StreamPool Quotas & Eviction
// ----------------------------------------------------------------------------
fn test_stream_pool_quotas_and_eviction(t: lit::T&) {
    t.run("Soft-Cap LRU Eviction and Priority Reuse") { sub =>
        var pool = net::new_stream_pool(6, 32, 2); // Soft-cap of 2 connections
        let nak = net::new_network_anonymization_key("https://service.net");
        let key = net::new_pool_key(net::PoolScheme.Https, "service.net", 443, net::new_direct_proxy_chain(), nak, net::TlsAndDnsPolicy { .. });

        // Add 2 connections
        let c1 = net::register_connection(pool, key, net::NegotiatedProtocol.Http11, "1.1.1.1", 1, 1000000);
        let c2 = net::register_connection(pool, key, net::NegotiatedProtocol.Http11, "1.1.1.1", 1, 2000000);

        // Release c1 at t=3.0s, making it idle
        net::release_connection(pool, c1, 3000000000);
        let grp_idx = pool.find_group_index(key);
        sub.assert_true(grp_idx >= 0, "Group index exists");
        sub.assert_eq(pool.groups[grp_idx].active_conns, 1, "1 active conn in group");
        sub.assert_eq(pool.groups[grp_idx].idle_conns, 1, "1 idle conn in group");

        // Adding 3rd connection exceeds soft-cap (2) -> triggers eviction of oldest idle (c1)
        let c3 = net::register_connection(pool, key, net::NegotiatedProtocol.Http11, "1.1.1.1", 1, 4000000);

        sub.assert_true(pool.conns[0].closed, "Oldest idle connection c1 was evicted");
        sub.assert_eq(c3, 3, "New connection c3 registered successfully");

        // OkHttp Priority Rule: acquire_pooled_connection prefers healthy pooled connection
        let acquired_id, ok_acq = net::acquire_pooled_connection(pool, key, "1.1.1.1", 5000000000);
        // c2 was active with allocation 1, but c3 was active with allocation 1. If we release c2:
        net::release_connection(pool, c2, 4500000000);
        let acquired_c2, ok_c2 = net::acquire_pooled_connection(pool, key, "1.1.1.1", 5000000000);
        sub.assert_true(ok_c2 && acquired_c2 == c2, "Reused pooled connection c2 over new dial");

        // Multiple releases do not corrupt active allocations count below 0
        net::release_connection(pool, c2, 5000000000);
        sub.assert_eq(pool.conns[1].active_allocations, 0, "Active allocations clamped to 0");
    };

    t.run("Active Connections Immune to Soft-Cap Eviction") { sub =>
        var pool = net::new_stream_pool(6, 32, 2);
        let nak = net::new_network_anonymization_key("https://busy.net");
        let key = net::new_pool_key(net::PoolScheme.Https, "busy.net", 443, net::new_direct_proxy_chain(), nak, net::TlsAndDnsPolicy { .. });

        // Register 2 connections and keep both active (active_allocations == 1)
        let c1 = net::register_connection(pool, key, net::NegotiatedProtocol.Http11, "2.2.2.2", 1, 1000000);
        let c2 = net::register_connection(pool, key, net::NegotiatedProtocol.Http11, "2.2.2.2", 1, 2000000);

        // Neither is released, so both have active_allocations = 1.
        // Registering a 3rd connection exceeds soft-cap (2), but neither can be evicted because both are active!
        let c3 = net::register_connection(pool, key, net::NegotiatedProtocol.Http11, "2.2.2.2", 1, 3000000);

        sub.assert_false(pool.conns[0].closed, "Active connection c1 not evicted");
        sub.assert_false(pool.conns[1].closed, "Active connection c2 not evicted");
        sub.assert_eq(c3, 3, "New connection c3 accepted under soft-cap pressure");
    };
}

// ----------------------------------------------------------------------------
// 14. CVE-2026-56866 CONNECT Rejection Pool Safety
// ----------------------------------------------------------------------------
fn test_cve_2026_56866_connect_rejection_pool_safety(t: lit::T&) {
    t.run("CVE-2026-56866: Rejected CONNECT Sockets Must Never Be Returned to Pool") { sub =>
        let nak = net::new_network_anonymization_key("https://proxy-target.com");
        let key = net::new_pool_key(net::PoolScheme.Https, "proxy-target.com", 443, net::new_direct_proxy_chain(), nak, net::TlsAndDnsPolicy { .. });

        // Simulate a socket where CONNECT tunnel was rejected (e.g. 407 Proxy Auth or 502 Bad Gateway)
        var failed_tunnel_conn = net::PooledConnection {
            conn_id:          101,
            key:              copy(key),
            protocol:         net::NegotiatedProtocol.Http11,
            no_new_exchanges: true, // Marked immediately on CONNECT rejection
            closed:           true, // Marked closed to prevent reuse
            ..
        };

        // Liveness check must immediately report unhealthy
        let healthy = net::is_connection_healthy(failed_tunnel_conn, 2000000000, false);
        sub.assert_false(healthy, "Rejected CONNECT connection is strictly unhealthy");

        // Attempting to acquire from a pool containing closed/no_new_exchanges connection must fail
        var pool = net::new_stream_pool(6, 32, 10);
        pool.conns.push(failed_tunnel_conn);

        let acq_id, ok_acq = net::acquire_pooled_connection(pool, key, "", 2500000000);
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
// 15. Poller Creation & Lifecycle across L4 Driver Backends
// ----------------------------------------------------------------------------
fn test_poller_creation_and_lifecycle(t: lit::T&) {
    t.run("Standard Driver Poller Lifecycle") { sub =>
        var cfg = net_internal::auto_transport_driver_config();
        cfg.active_kind = net_internal::TransportDriverKind.Standard;

        var poller = net::new_poller(cfg);
        sub.assert_true(poller.is_open, "Poller is open");
        sub.assert_eq(poller.active_fd_count, 0, "No active fds initially");
        sub.assert_eq(poller.active_timer_count, 0, "No active timers initially");

        net::close_poller(poller);
        sub.assert_false(poller.is_open, "Poller closed cleanly");
    };

    t.run("Windows RIO / io_uring / kqueue Probed Poller Creation") { sub =>
        let plat = net_internal::detect_target_platform();
        var cfg = net_internal::auto_transport_driver_config();

        var poller = net::new_poller(cfg);
        sub.assert_true(poller.is_open, "Poller created successfully with auto-selected driver");

        if plat == net_internal::TargetPlatform.Windows && cfg.active_kind == net_internal::TransportDriverKind.WindowsRIO {
            sub.assert_true(poller.rio_cq_id != 0, "Windows RIO completion queue initialized");
        }

        net::close_poller(poller);
        sub.assert_false(poller.is_open, "Poller closed");
    };
}

// ----------------------------------------------------------------------------
// 16. Socket Registration & Readiness Multiplexing
// ----------------------------------------------------------------------------
fn test_poller_registration_and_readiness(t: lit::T&) {
    var cfg = net_internal::auto_transport_driver_config();
    var poller = net::new_poller(cfg);

    t.run("Registration Table: Add, Duplicate Guard, Modify, Deregister") { sub =>
        // Register fd 10
        let ok_reg = net::register_socket(poller, 10, 1001, core::PollInterest.Read, core::PollTrigger.Level);
        sub.assert_true(ok_reg, "Socket 10 registered");
        sub.assert_eq(poller.active_fd_count, 1, "1 active fd");

        // Duplicate registration rejected
        let dup_reg = net::register_socket(poller, 10, 1002, core::PollInterest.Write, core::PollTrigger.Level);
        sub.assert_false(dup_reg, "Duplicate fd 10 registration rejected");

        // Modify interest to ReadWrite
        let ok_mod = net::modify_socket(poller, 10, 1001, core::PollInterest.ReadWrite, core::PollTrigger.Edge);
        sub.assert_true(ok_mod, "Socket 10 modified");

        let idx = net::find_registration(poller, 10);
        sub.assert_true(idx >= 0, "Socket 10 found");
        sub.assert_eq(poller.registrations[idx].interest, core::PollInterest.ReadWrite, "Interest is ReadWrite");
        sub.assert_eq(poller.registrations[idx].trigger, core::PollTrigger.Edge, "Trigger is Edge");

        // Deregister
        let ok_dereg = net::deregister_socket(poller, 10);
        sub.assert_true(ok_dereg, "Socket 10 deregistered");
        sub.assert_eq(poller.active_fd_count, 0, "0 active fds");
        sub.assert_eq(net::find_registration(poller, 10), -1, "Socket 10 no longer found");
    };

    t.run("Readiness Multiplexing: Read, Write, Error, Hangup") { sub =>
        net::register_socket(poller, 20, 2001, core::PollInterest.Read, core::PollTrigger.Level);
        net::register_socket(poller, 21, 2002, core::PollInterest.Write, core::PollTrigger.Level);
        net::register_socket(poller, 22, 2003, core::PollInterest.ReadWrite, core::PollTrigger.Level);

        // Simulate events
        net::simulate_read_ready(poller, 20, 512); // fd 20 has 512 bytes unread
        net::simulate_write_ready(poller, 21);      // fd 21 ready to write
        net::simulate_hangup(poller, 22);           // fd 22 hangup/EOF

        var events: core::PollReadyEvent[..64] = [];
        let count = net::poll_events(poller, 0, 1000000000, events);

        sub.assert_eq(count, 3, "3 readiness events harvested");

        // Validate fd 20 event
        var found_20 = false;
        var found_21 = false;
        var found_22 = false;

        for i in events.len {
            if events[i].tag == 2001 {
                found_20 = true;
                sub.assert_eq(events[i].fd, 20, "fd is 20");
                sub.assert_true((events[i].events & core::POLL_READ) != 0, "Event has POLL_READ");
                sub.assert_eq(events[i].bytes_available, 512, "Reported 512 bytes available");
                sub.assert_false(events[i].is_eof, "Not EOF");
            } else if events[i].tag == 2002 {
                found_21 = true;
                sub.assert_eq(events[i].fd, 21, "fd is 21");
                sub.assert_true((events[i].events & core::POLL_WRITE) != 0, "Event has POLL_WRITE");
            } else if events[i].tag == 2003 {
                found_22 = true;
                sub.assert_eq(events[i].fd, 22, "fd is 22");
                sub.assert_true((events[i].events & core::POLL_HANGUP) != 0, "Event has POLL_HANGUP");
                sub.assert_true(events[i].is_eof, "Event is EOF");
            }
        }

        sub.assert_true(found_20, "fd 20 event processed");
        sub.assert_true(found_21, "fd 21 event processed");
        sub.assert_true(found_22, "fd 22 event processed");

        net::deregister_socket(poller, 20);
        net::deregister_socket(poller, 21);
        net::deregister_socket(poller, 22);
    };

    net::close_poller(poller);
}

// ----------------------------------------------------------------------------
// 17. High-Resolution Timer Wheel
// ----------------------------------------------------------------------------
fn test_poller_timer_wheel(t: lit::T&) {
    var cfg = net_internal::auto_transport_driver_config();
    var poller = net::new_poller(cfg);

    t.run("One-shot Timer Expiration") { sub =>
        let now_ns: u64 = 1000000000; // 1.0s
        // Schedule one-shot timer for 50ms (deadline 1.05s)
        let ok_add = net::add_timer(poller, 101, 50, 9101, false, now_ns);
        sub.assert_true(ok_add, "Timer 101 added");
        sub.assert_eq(poller.active_timer_count, 1, "1 active timer");

        // Poll at 1.04s (40ms elapsed) -> timer should NOT fire
        var events40: core::PollReadyEvent[..64] = [];
        let c40 = net::poll_events(poller, 0, now_ns + 40000000, events40);
        sub.assert_eq(c40, 0, "Timer not yet expired at 40ms");

        // Poll at 1.06s (60ms elapsed) -> timer should fire!
        var events60: core::PollReadyEvent[..64] = [];
        let c60 = net::poll_events(poller, 0, now_ns + 60000000, events60);
        sub.assert_eq(c60, 1, "Timer fired at 60ms");
        sub.assert_eq(events60[0].tag, 9101, "Timer tag matches");
        sub.assert_true(events60[0].is_timer, "is_timer flag is true");
        sub.assert_true((events60[0].events & core::POLL_TIMER) != 0, "POLL_TIMER flag set");

        // One-shot timer is now deactivated
        sub.assert_eq(poller.active_timer_count, 0, "0 active timers left");

        // Subsequent poll should not fire
        var events70: core::PollReadyEvent[..64] = [];
        let c70 = net::poll_events(poller, 0, now_ns + 70000000, events70);
        sub.assert_eq(c70, 0, "No duplicate timer triggers");
    };

    t.run("Periodic Timer & Cancellation") { sub =>
        let now_ns: u64 = 1000000000;
        // Schedule periodic timer every 100ms
        net::add_timer(poller, 202, 100, 9202, true, now_ns);

        // 1st tick at 110ms
        var ev1: core::PollReadyEvent[..64] = [];
        let c1 = net::poll_events(poller, 0, now_ns + 110000000, ev1);
        sub.assert_eq(c1, 1, "1st tick fired");
        sub.assert_eq(ev1[0].tag, 9202, "Tag matches");

        // Timer still active (periodic)
        sub.assert_eq(poller.active_timer_count, 1, "Timer still active");

        // 2nd tick at 220ms
        var ev2: core::PollReadyEvent[..64] = [];
        let c2 = net::poll_events(poller, 0, now_ns + 220000000, ev2);
        sub.assert_eq(c2, 1, "2nd tick fired");

        // Cancel timer
        let ok_cancel = net::cancel_timer(poller, 202);
        sub.assert_true(ok_cancel, "Timer cancelled");
        sub.assert_eq(poller.active_timer_count, 0, "0 active timers");

        // 3rd tick should NOT fire after cancellation
        var ev3: core::PollReadyEvent[..64] = [];
        let c3 = net::poll_events(poller, 0, now_ns + 330000000, ev3);
        sub.assert_eq(c3, 0, "No tick after cancellation");
    };

    net::close_poller(poller);
}

// ----------------------------------------------------------------------------
// 18. Non-blocking EventLoop I/O
// ----------------------------------------------------------------------------
fn dummy_event_handler(tag: u64, ev: const core::PollReadyEvent&, el: net::EventLoop&) {
    if tag == 5001 {
        if (ev.events & core::POLL_READ) != 0 {
            var msg_buf: u8[..64] = [];
            net::consume_read(el, tag, msg_buf);
            // Echo back with prefix "ACK:"
            var reply: u8[..64] = "ACK:";
            reply.append(msg_buf[..]);
            net::queue_write(el, tag, reply[..]);
        }
    }
}

fn test_event_loop_io(t: lit::T&) {
    var cfg = net_internal::auto_transport_driver_config();
    var el = net::new_event_loop(cfg);

    t.run("Bind Connection, Queue Write, Feed Read & Consume") { sub =>
        let ok_bind = net::bind_connection(el, 30, 5001, core::PollInterest.ReadWrite);
        sub.assert_true(ok_bind, "Connection 5001 bound");

        // Feed incoming data
        let ok_feed = net::feed_read(el, 5001, "REQUEST_DATA_01");
        sub.assert_true(ok_feed, "Data fed into read buffer");

        // Run event loop once
        let dispatched = net::run_loop_once(el, 0, 1000000000, dummy_event_handler);
        sub.assert_eq(dispatched, 1, "1 event dispatched in loop");
        sub.assert_eq(el.iteration_count, 1, "Iteration count is 1");
        sub.assert_eq(el.events_dispatched_total, 1, "1 total dispatched event");

        // The handler consumed the read and queued an "ACK:REQUEST_DATA_01" response
        let b_idx = net::find_connection_buffer(el, 5001);
        sub.assert_true(b_idx >= 0, "Buffer found");
        sub.assert_bytes_eq(el.buffers[b_idx].write_buf[..], "ACK:REQUEST_DATA_01", "Outbound reply queued");

        // Flush writes
        let flushed = net::flush_writes(el, 5001);
        sub.assert_eq(flushed, 19, "Flushed 19 bytes");
        sub.assert_eq(el.buffers[b_idx].write_buf.len, 0, "Write buffer cleared");

        // Unbind
        sub.assert_true(net::unbind_connection(el, 5001), "Unbound");
    };

    net::close_event_loop(el);
}

// ----------------------------------------------------------------------------
// 19. Bidirectional Client-Server Mock Cycle over EventLoop
// ----------------------------------------------------------------------------
var g_server_received: u8[..64] = [];
var g_client_received: u8[..64] = [];

fn bidi_network_handler(tag: u64, ev: const core::PollReadyEvent&, el: net::EventLoop&) {
    if tag == 6001 { // Server connection
        if (ev.events & core::POLL_READ) != 0 {
            var buf: u8[..64] = [];
            net::consume_read(el, tag, buf);
            g_server_received.clear();
            g_server_received.append(buf[..]);

            // Server responds
            net::queue_write(el, tag, "SERVER_OK");
        }
    } else if tag == 6002 { // Client connection
        if (ev.events & core::POLL_READ) != 0 {
            var buf: u8[..64] = [];
            net::consume_read(el, tag, buf);
            g_client_received.clear();
            g_client_received.append(buf[..]);
        }
    }
}

fn test_bidi_client_server_cycle(t: lit::T&) {
    var cfg = net_internal::auto_transport_driver_config();
    var el = net::new_event_loop(cfg);

    t.run("Complete Non-blocking Bidi Request-Response Roundtrip") { sub =>
        g_server_received.clear();
        g_client_received.clear();

        net::bind_connection(el, 40, 6001, core::PollInterest.ReadWrite); // Server
        net::bind_connection(el, 41, 6002, core::PollInterest.ReadWrite); // Client

        // 1. Client sends request to Server
        net::feed_read(el, 6001, "PING_FROM_CLIENT");

        // 2. EventLoop Step 1: Server receives request and queues response
        net::run_loop_once(el, 0, 1000000000, bidi_network_handler);

        sub.assert_bytes_eq(g_server_received[..], "PING_FROM_CLIENT", "Server processed request");

        // 3. Network forwards Server's outbound response to Client's inbound buffer
        let s_idx = net::find_connection_buffer(el, 6001);
        let s_out = el.buffers[s_idx].write_buf[..];
        sub.assert_bytes_eq(s_out, "SERVER_OK", "Server queued reply");
        net::feed_read(el, 6002, s_out);
        net::flush_writes(el, 6001);

        // 4. EventLoop Step 2: Client receives Server's response
        net::run_loop_once(el, 0, 1000001000, bidi_network_handler);

        sub.assert_bytes_eq(g_client_received[..], "SERVER_OK", "Client received server reply");

        net::unbind_connection(el, 6001);
        net::unbind_connection(el, 6002);
    };

    net::close_event_loop(el);
}

// ----------------------------------------------------------------------------
// 20. 15-bit / 4-second Coarse Socket Timeouts (uWebSockets Pattern)
// ----------------------------------------------------------------------------
fn test_coarse_socket_timeouts(t: lit::T&) {
    var cfg = net_internal::auto_transport_driver_config();
    var poller = net::new_poller(cfg);

    t.run("Coarse 4-second Socket Timeout Expiry & Cancellation") { sub =>
        let now_ns: u64 = 1000000000; // 1.0s
        net::register_socket(poller, 50, 7001, core::PollInterest.Read, core::PollTrigger.Level);

        // Initial timeout is disabled (255)
        sub.assert_eq(net::get_socket_timeout(poller, 50), net::COARSE_TIMEOUT_DISABLED, "Timeout disabled initially");

        // Set 4-second timeout (1 tick ahead)
        let ok_set = net::set_socket_timeout(poller, 50, 4);
        sub.assert_true(ok_set, "Set 4s coarse timeout");
        sub.assert_true(net::get_socket_timeout(poller, 50) != net::COARSE_TIMEOUT_DISABLED, "Timeout tick armed");

        // First poll: initial anchor (delta 0s)
        var evs1: core::PollReadyEvent[..64] = [];
        let c1 = net::poll_events(poller, 0, now_ns, evs1);
        sub.assert_eq(c1, 0, "No events at initial poll");

        // Second poll: +2.0s (less than 4s threshold)
        var evs2: core::PollReadyEvent[..64] = [];
        let c2 = net::poll_events(poller, 0, now_ns + 2000000000, evs2);
        sub.assert_eq(c2, 0, "No timeout event before 4 seconds");

        // Third poll: +4.1s (4-second boundary crossed, tick matches)
        var evs3: core::PollReadyEvent[..64] = [];
        let c3 = net::poll_events(poller, 0, now_ns + 4100000000, evs3);
        sub.assert_eq(c3, 1, "Coarse timeout event fired at 4s boundary");
        sub.assert_true(evs3[0].is_timer, "Event is marked as timer");
        sub.assert_eq(evs3[0].tag, 7001, "Event tag matches socket 50 tag");
        sub.assert_eq(evs3[0].fd, 50, "Event fd matches socket 50");
        sub.assert_eq(net::get_socket_timeout(poller, 50), net::COARSE_TIMEOUT_DISABLED, "Timeout reset to disabled after firing");

        // Arm and cancel with seconds = 0
        net::set_socket_timeout(poller, 50, 16);
        sub.assert_true(net::get_socket_timeout(poller, 50) != net::COARSE_TIMEOUT_DISABLED, "Armed 16s timeout");
        net::set_socket_timeout(poller, 50, 0); // Disable
        sub.assert_eq(net::get_socket_timeout(poller, 50), net::COARSE_TIMEOUT_DISABLED, "Disabled via seconds=0");

        net::deregister_socket(poller, 50);
    };

    t.run("Multi-Tick Jump Expiry Without Skips (elapsed_ticks > 1)") { sub =>
        let now_ns: u64 = 10000000000; // 10.0s
        net::register_socket(poller, 60, 8001, core::PollInterest.Read, core::PollTrigger.Level);

        // Arm timeout for 4 seconds (target = current_tick + 1)
        net::set_socket_timeout(poller, 60, 4);

        // Advance poll by 12 seconds (elapsed_ticks = 3, skips over tick + 1)
        var evs: core::PollReadyEvent[..64] = [];
        let fired = net::poll_events(poller, 0, now_ns + 12000000000, evs);
        sub.assert_eq(fired, 1, "Coarse timeout fired even when time jumped 3 ticks ahead");
        sub.assert_true(evs[0].is_timer, "Event is marked as timer");
        sub.assert_eq(evs[0].fd, 60, "Event fd matches socket 60");

        net::deregister_socket(poller, 60);
    };

    net::close_poller(poller);
}

// --- Component: net_happy_eyeballs ---
// Verification suite for net/happy_eyeballs: RFC 8305 and HEv3 connection racing,
// CAD calculations, 50 ms Resolution Delay, candidate interleaving, and AttemptManager coordination.
// Defenses for Go #59494 / #35122 (Windows leaked dial timers) and RFC 8305 congestion collapse.

// ----------------------------------------------------------------------------
// 21. CAD Calculation & Absolute Floor
// ----------------------------------------------------------------------------
fn test_cad_calculation_and_absolute_floor(t: lit::T&) {
    t.run("CAD Clamping and Strict Absolute Floor >= 10 ms") { sub =>
        // Default when RTT is unknown: 250 ms
        let cad_default = net::compute_effective_cad_ms(0, false);
        sub.assert_eq(cad_default, 250, "Default CAD is 250 ms (RFC 8305)");

        // Observed RTT within normal window [100 ms, 2000 ms]
        let cad_normal = net::compute_effective_cad_ms(180, true);
        sub.assert_eq(cad_normal, 180, "Observed RTT 180 ms preserved");

        // Observed RTT below recommended minimum 100 ms
        let cad_clamped_min = net::compute_effective_cad_ms(45, true, 100, 2000);
        sub.assert_eq(cad_clamped_min, 100, "RTT 45 ms clamped to min 100 ms");

        // Observed RTT above max 2000 ms
        let cad_clamped_max = net::compute_effective_cad_ms(4500, true, 100, 2000);
        sub.assert_eq(cad_clamped_max, 2000, "RTT 4500 ms clamped to max 2000 ms");

        // Normative safety barrier: MUST NOT be less than 10 ms even with caller override
        let cad_floor1 = net::compute_effective_cad_ms(2, true, 4, 1000);
        sub.assert_eq(cad_floor1, 10, "CAD strictly clamped to absolute floor >= 10 ms");

        // 0 ms RTT (e.g. localhost or loopback)
        let cad_zero = net::compute_effective_cad_ms(0, true, 0, 1000);
        sub.assert_eq(cad_zero, 10, "0 ms RTT clamped to 10 ms absolute floor");

        // Negative RTT (clock jump backwards or uncalibrated timer)
        let cad_neg = net::compute_effective_cad_ms(-250, true, 0, 1000);
        sub.assert_eq(cad_neg, 10, "Negative RTT clamped safely to 10 ms absolute floor");

        // Custom bounds [500 ms, 1500 ms]
        let cad_custom = net::compute_effective_cad_ms(200, true, 500, 1500);
        sub.assert_eq(cad_custom, 500, "Custom min 500 ms applied");

        let cad_custom_high = net::compute_effective_cad_ms(1800, true, 500, 1500);
        sub.assert_eq(cad_custom_high, 1500, "Custom max 1500 ms applied");
    };
}

// ----------------------------------------------------------------------------
// 22. RFC 6724 & HEv3 Interleaving
// ----------------------------------------------------------------------------
fn test_rfc6724_and_hev3_interleaving(t: lit::T&) {
    t.run("First Address Family Count = 1 Interleaving Matrix") { sub =>
        var ipv6_list: net::DnsCandidate[..8] = [];
        ipv6_list.push(net::new_dns_candidate(net::AddressFamily.IPv6, "2001:db8::1", 443));
        ipv6_list.push(net::new_dns_candidate(net::AddressFamily.IPv6, "2001:db8::2", 443));

        var ipv4_list: net::DnsCandidate[..8] = [];
        ipv4_list.push(net::new_dns_candidate(net::AddressFamily.IPv4, "198.51.100.1", 443));
        ipv4_list.push(net::new_dns_candidate(net::AddressFamily.IPv4, "198.51.100.2", 443));

        var interleaved: net::DnsCandidate[..32] = [];
        net::interleave_candidates_he(ipv6_list[..], ipv4_list[..], interleaved, 1);

        sub.assert_eq(interleaved.len, 4, "4 candidates interleaved");
        sub.assert_true(interleaved[0].family == net::AddressFamily.IPv6, "Candidate 0 is IPv6_1");
        sub.assert_true(interleaved[1].family == net::AddressFamily.IPv4, "Candidate 1 is IPv4_1");
        sub.assert_true(interleaved[2].family == net::AddressFamily.IPv6, "Candidate 2 is IPv6_2");
        sub.assert_true(interleaved[3].family == net::AddressFamily.IPv4, "Candidate 3 is IPv4_2");
    };

    t.run("Asymmetric Candidate Interleaving (IPv6 Heavily Dominates)") { sub =>
        var ipv6_list: net::DnsCandidate[..8] = [];
        ipv6_list.push(net::new_dns_candidate(net::AddressFamily.IPv6, "2001:db8::1", 443));
        ipv6_list.push(net::new_dns_candidate(net::AddressFamily.IPv6, "2001:db8::2", 443));
        ipv6_list.push(net::new_dns_candidate(net::AddressFamily.IPv6, "2001:db8::3", 443));
        ipv6_list.push(net::new_dns_candidate(net::AddressFamily.IPv6, "2001:db8::4", 443));

        var ipv4_list: net::DnsCandidate[..8] = [];
        ipv4_list.push(net::new_dns_candidate(net::AddressFamily.IPv4, "198.51.100.1", 443));

        var interleaved: net::DnsCandidate[..32] = [];
        net::interleave_candidates_he(ipv6_list[..], ipv4_list[..], interleaved, 1);

        sub.assert_eq(interleaved.len, 5, "5 candidates total");
        sub.assert_true(interleaved[0].family == net::AddressFamily.IPv6, "0 is IPv6");
        sub.assert_true(interleaved[1].family == net::AddressFamily.IPv4, "1 is IPv4");
        sub.assert_true(interleaved[2].family == net::AddressFamily.IPv6, "2 is IPv6");
        sub.assert_true(interleaved[3].family == net::AddressFamily.IPv6, "3 is IPv6");
        sub.assert_true(interleaved[4].family == net::AddressFamily.IPv6, "4 is IPv6");
    };

    t.run("Asymmetric Candidate Interleaving (IPv4 Heavily Dominates)") { sub =>
        var ipv6_list: net::DnsCandidate[..8] = [];
        ipv6_list.push(net::new_dns_candidate(net::AddressFamily.IPv6, "2001:db8::1", 443));

        var ipv4_list: net::DnsCandidate[..8] = [];
        ipv4_list.push(net::new_dns_candidate(net::AddressFamily.IPv4, "198.51.100.1", 443));
        ipv4_list.push(net::new_dns_candidate(net::AddressFamily.IPv4, "198.51.100.2", 443));
        ipv4_list.push(net::new_dns_candidate(net::AddressFamily.IPv4, "198.51.100.3", 443));

        var interleaved: net::DnsCandidate[..32] = [];
        net::interleave_candidates_he(ipv6_list[..], ipv4_list[..], interleaved, 1);

        sub.assert_eq(interleaved.len, 4, "4 candidates total");
        sub.assert_true(interleaved[0].family == net::AddressFamily.IPv6, "0 is IPv6");
        sub.assert_true(interleaved[1].family == net::AddressFamily.IPv4, "1 is IPv4");
        sub.assert_true(interleaved[2].family == net::AddressFamily.IPv4, "2 is IPv4");
        sub.assert_true(interleaved[3].family == net::AddressFamily.IPv4, "3 is IPv4");
    };

    t.run("Single-Stack Fallbacks (0 IPv6 or 0 IPv4)") { sub =>
        var ipv6_only: net::DnsCandidate[..8] = [];
        ipv6_only.push(net::new_dns_candidate(net::AddressFamily.IPv6, "2001:db8::1", 443));
        ipv6_only.push(net::new_dns_candidate(net::AddressFamily.IPv6, "2001:db8::2", 443));
        var empty_ipv4: net::DnsCandidate[..8] = [];

        var res_v6: net::DnsCandidate[..32] = [];
        net::interleave_candidates_he(ipv6_only[..], empty_ipv4[..], res_v6, 1);
        sub.assert_eq(res_v6.len, 2, "IPv6-only preserved 2 candidates");
        sub.assert_true(res_v6[0].family == net::AddressFamily.IPv6, "Res 0 is IPv6");
        sub.assert_true(res_v6[1].family == net::AddressFamily.IPv6, "Res 1 is IPv6");

        var empty_ipv6: net::DnsCandidate[..8] = [];
        var ipv4_only:  net::DnsCandidate[..8] = [];
        ipv4_only.push(net::new_dns_candidate(net::AddressFamily.IPv4, "1.1.1.1", 80));
        var res_v4: net::DnsCandidate[..32] = [];
        net::interleave_candidates_he(empty_ipv6[..], ipv4_only[..], res_v4, 1);
        sub.assert_eq(res_v4.len, 1, "IPv4-only preserved 1 candidate");
        sub.assert_true(res_v4[0].family == net::AddressFamily.IPv4, "Res 0 is IPv4");
    };

    t.run("HEv3 Protocol Interleaving (QUIC vs TCP)") { sub =>
        var list: net::DnsCandidate[..8] = [];
        list.push(net::new_dns_candidate(net::AddressFamily.IPv6, "2001:db8::1", 443));
        list.push(net::new_dns_candidate(net::AddressFamily.IPv4, "198.51.100.1", 443));

        var proto_interleaved: net::DnsCandidate[..32] = [];
        net::interleave_protocols_hev3(list[..], proto_interleaved);

        sub.assert_eq(proto_interleaved.len, 4, "4 protocol attempts generated (QUIC + TCP for both)");
        sub.assert_true(proto_interleaved[0].l4_proto == net::L4Protocol.QuicUdp, "Attempt 0 is QUIC/UDP IPv6");
        sub.assert_true(proto_interleaved[1].l4_proto == net::L4Protocol.Tcp, "Attempt 1 is TCP IPv6");
        sub.assert_true(proto_interleaved[2].l4_proto == net::L4Protocol.QuicUdp, "Attempt 2 is QUIC/UDP IPv4");
        sub.assert_true(proto_interleaved[3].l4_proto == net::L4Protocol.Tcp, "Attempt 3 is TCP IPv4");
    };
}

// ----------------------------------------------------------------------------
// 23. DNS Race & Resolution Delay
// ----------------------------------------------------------------------------
fn test_dns_race_and_resolution_delay(t: lit::T&) {
    t.run("Asymmetric Priority: AAAA First Cancels Delay") { sub =>
        var task = net::new_dns_race_task();
        let ip6: const u8[:][1] = ["2001:db8::1"];
        net::on_dns_aaaa_response(task, ip6[..], 100);

        sub.assert_true(task.ready_to_connect, "Ready to connect immediately on AAAA");
        sub.assert_false(task.rd_timer_armed, "RD timer NOT armed when AAAA arrives first");
        sub.assert_eq(task.ipv6_candidates.len, 1, "IPv6 candidate ready");
    };

    t.run("A First Arms 50 ms Resolution Delay Timer") { sub =>
        var task = net::new_dns_race_task();
        let ip4: const u8[:][1] = ["198.51.100.1"];
        net::on_dns_a_response(task, ip4[..], 100);

        sub.assert_false(task.ready_to_connect, "Not ready immediately: waiting for AAAA in RD window");
        sub.assert_true(task.rd_timer_armed, "RD timer armed for 50 ms");
        sub.assert_eq(task.rd_deadline_ms, 150, "RD deadline set to now + 50 ms");

        // Positive AAAA arrives at t=120 (< 150)
        let ip6: const u8[:][1] = ["2001:db8::1"];
        net::on_dns_aaaa_response(task, ip6[..], 120);
        sub.assert_true(task.ready_to_connect, "Unblocked by late AAAA before RD deadline");
        sub.assert_false(task.rd_timer_armed, "RD timer cancelled on positive AAAA");
    };

    t.run("RD Expiration Unblocks IPv4") { sub =>
        var task = net::new_dns_race_task();
        let ip4: const u8[:][1] = ["198.51.100.1"];
        net::on_dns_a_response(task, ip4[..], 100);

        // Tick before deadline
        let unblocked_early = net::check_dns_resolution_delay_tick(task, 140);
        sub.assert_false(unblocked_early, "Not unblocked at t=140");

        // Tick at deadline (t=150)
        let unblocked = net::check_dns_resolution_delay_tick(task, 150);
        sub.assert_true(unblocked, "Unblocked at t=150 (50 ms RD expired)");
        sub.assert_true(task.ready_to_connect, "Ready to connect with IPv4");
    };

    t.run("Negative AAAA Immediately Unblocks IPv4") { sub =>
        var task = net::new_dns_race_task();
        let ip4: const u8[:][1] = ["198.51.100.1"];
        net::on_dns_a_response(task, ip4[..], 100);

        // Empty AAAA response (NODATA / negative)
        let empty_ip6: const u8[:][0] = [];
        net::on_dns_aaaa_response(task, empty_ip6[..], 110);
        sub.assert_true(task.ready_to_connect, "Negative AAAA immediately unblocks IPv4 without waiting for 50 ms");
        sub.assert_false(task.rd_timer_armed, "RD timer disarmed");
    };
}

// ----------------------------------------------------------------------------
// 24. AttemptManager Racing & Winner
// ----------------------------------------------------------------------------
fn test_attempt_manager_racing_and_winner(t: lit::T&) {
    t.run("Staggered Connection Racing, Winner Binding & Loser Cancellation (Go #59494)") { sub =>
        var mgr = net::new_attempt_manager(250); // CAD = 250 ms

        var candidates: net::DnsCandidate[..4] = [];
        candidates.push(net::new_dns_candidate(net::AddressFamily.IPv6, "2001:db8::1", 443));
        candidates.push(net::new_dns_candidate(net::AddressFamily.IPv4, "198.51.100.1", 443));
        candidates.push(net::new_dns_candidate(net::AddressFamily.IPv6, "2001:db8::2", 443));

        net::start_attempt_race(mgr, candidates[..], 0);

        sub.assert_eq(mgr.attempts.len, 1, "First attempt launched at t=0");
        sub.assert_eq(mgr.attempts[0].attempt_id, 1, "Attempt 1 launched");

        // Tick at t=100 (< CAD 250 ms) -> no new attempt
        let launched_early = net::tick_attempt_manager(mgr, 100);
        sub.assert_false(launched_early, "No attempt launched at t=100");
        sub.assert_eq(mgr.attempts.len, 1, "Still 1 attempt");

        // Tick at t=250 (= CAD) -> launches second attempt (IPv4)
        let launched_cad = net::tick_attempt_manager(mgr, 250);
        sub.assert_true(launched_cad, "Second attempt launched at t=250");
        sub.assert_eq(mgr.attempts.len, 2, "2 attempts now active");

        // Tick at t=500 (= 2*CAD) -> launches third attempt (IPv6_2)
        let launched_third = net::tick_attempt_manager(mgr, 500);
        sub.assert_true(launched_third, "Third attempt launched at t=500");
        sub.assert_eq(mgr.attempts.len, 3, "3 attempts now active");

        // Attempt 2 (IPv4) wins at t=550
        // Defense (Go #59494, #35122): All other attempts (1 and 3) must be cancelled immediately to prevent leaked dials on Windows!
        let won = net::bind_winner_attempt(mgr, 2);
        sub.assert_true(won, "Attempt 2 bound as winner");
        sub.assert_true(mgr.has_winner, "Manager marked has_winner");
        sub.assert_true(mgr.attempts[0].state == net::AttemptState.Cancelled, "Attempt 1 cancelled");
        sub.assert_true(mgr.attempts[1].state == net::AttemptState.Connected, "Attempt 2 connected");
        sub.assert_true(mgr.attempts[2].state == net::AttemptState.Cancelled, "Attempt 3 cancelled");

        // Attempting to tick after winner does not launch further attempts
        let tick_post_winner = net::tick_attempt_manager(mgr, 750);
        sub.assert_false(tick_post_winner, "No attempts launched after winner is bound");
    };

    t.run("Last Resort Local Synthesis Delay (2000 ms)") { sub =>
        var mgr = net::new_attempt_manager(250);
        var candidates: net::DnsCandidate[..2] = [];
        candidates.push(net::new_dns_candidate(net::AddressFamily.IPv6, "2001:db8::99", 443));

        net::start_attempt_race(mgr, candidates[..], 0);
        sub.assert_true(mgr.last_resort_armed, "Last resort synthesis armed for last IPv6 attempt");
        sub.assert_eq(mgr.last_resort_deadline_ms, 2000, "Deadline set to 2000 ms");

        // Tick at t=1999 -> not triggered
        net::tick_attempt_manager(mgr, 1999);
        sub.assert_false(mgr.last_resort_triggered, "Not triggered before 2000 ms");

        // Tick at t=2000 -> triggers RFC 7050 NAT64 synthesis
        net::tick_attempt_manager(mgr, 2000);
        sub.assert_true(mgr.last_resort_triggered, "Last resort synthesis triggered at 2000 ms");
        sub.assert_true(mgr.pending_candidates.len >= 2, "Synthesized NAT64 candidate injected into pending queue");

        // With an IPv4 candidate present, synthesizes 64:ff9b::<ipv4> with target port
        var mgr4 = net::new_attempt_manager(250);
        var cands4: net::DnsCandidate[..2] = [];
        cands4.push(net::new_dns_candidate(net::AddressFamily.IPv6, "2001:db8::1", 8443));
        cands4.push(net::new_dns_candidate(net::AddressFamily.IPv4, "192.0.2.33", 8443));
        net::start_attempt_race(mgr4, cands4[..], 0);
        net::tick_attempt_manager(mgr4, 2000);
        sub.assert_true(mgr4.last_resort_triggered, "Triggered for mixed list");
        let last_cand = mgr4.pending_candidates[mgr4.pending_candidates.len - 1];
        sub.assert_bytes_eq(last_cand.ip[..], "64:ff9b::192.0.2.33", "NAT64 synthesized from candidate IPv4");
        sub.assert_eq(last_cand.port, 8443, "Target port 8443 preserved");
    };

    t.run("Chromium JobController Creation Rules and Waiting Delay") { sub =>
        // dns_alpn_h3_job rules: HTTPS + QUIC + no proxy + no active QUIC session
        sub.assert_true(net::should_create_dns_alpn_h3_job(net::H3JobOptions { is_https: true, quic_enabled: true, uses_proxy: false, has_available_quic_session: false }), "Created on HTTPS, QUIC, direct, no active session");
        sub.assert_false(net::should_create_dns_alpn_h3_job(net::H3JobOptions { is_https: false, quic_enabled: true, uses_proxy: false, has_available_quic_session: false }), "Not created on plain HTTP");
        sub.assert_false(net::should_create_dns_alpn_h3_job(net::H3JobOptions { is_https: true, quic_enabled: false, uses_proxy: false, has_available_quic_session: false }), "Not created when QUIC disabled");
        sub.assert_false(net::should_create_dns_alpn_h3_job(net::H3JobOptions { is_https: true, quic_enabled: true, uses_proxy: true, has_available_quic_session: false }), "Not created when proxy is configured");
        sub.assert_false(net::should_create_dns_alpn_h3_job(net::H3JobOptions { is_https: true, quic_enabled: true, uses_proxy: false, has_available_quic_session: true }), "Not created when active QUIC session can be reused");

        // Waiting delay cancelled when open TCP socket already exists in pool
        let delay_open_tcp = net::compute_main_job_waiting_delay_ms(true, 200, false);
        sub.assert_eq(delay_open_tcp, 0, "Waiting delay cancelled (0 ms) when open TCP socket exists");

        // Waiting delay cancelled when DNS confirms no HTTP/3 ALPN support
        let delay_no_h3 = net::compute_main_job_waiting_delay_ms(false, 200, true);
        sub.assert_eq(delay_no_h3, 0, "Waiting delay cancelled (0 ms) when DNS confirms no HTTP/3");

        // Default waiting delay when cold
        let delay_cold = net::compute_main_job_waiting_delay_ms(false, 200, false);
        sub.assert_eq(delay_cold, 200, "Default waiting delay applied when cold");
    };
}

// --- Component: net_retry ---
// Verification suite for net/retry: Tier 1 zero-delay stale socket recovery,
// one-shot stream bug guards, QUIC protocol fallback, Full/Equal/Decorrelated Jitter,
// RFC 9110 Retry-After parser, circuit breaker, Google SRE adaptive retry budget,
// and Go #81671 (idempotent QUERY method).

// ----------------------------------------------------------------------------
// 25. Tier 1 Stale Socket & QUIC Fallback
// ----------------------------------------------------------------------------
fn test_tier1_stale_socket_and_quic_fallback(t: lit::T&) {
    t.run("Tier 1 4-Condition Invariant Evaluation") { sub =>
        // 1. Standard idempotent GET on reused Keep-Alive connection before headers
        var req_get = http::new_request("GET", "https://api.io/items");
        sub.assert_true(net::should_retry_tier1_stale_socket(true, req_get), "Reused GET before headers approved for immediate Tier 1 retry");

        // 2. Fresh dial connection failure: MUST NOT retry at Tier 1 (fails fast)
        sub.assert_false(net::should_retry_tier1_stale_socket(false, req_get), "Fresh connection failure rejected for Tier 1 retry");

        // 3. Response headers already received: MUST NOT retry at Tier 1
        sub.assert_false(net::should_retry_tier1_stale_socket(true, req_get, true), "Failure after response headers rejected for Tier 1 retry");

        // 4. Non-idempotent POST without Idempotency-Key: MUST NOT retry
        var req_post = http::new_request("POST", "https://api.io/payments");
        sub.assert_false(net::should_retry_tier1_stale_socket(true, req_post), "Non-idempotent POST without Idempotency-Key rejected");

        // 5. Non-idempotent POST WITH Idempotency-Key: approved for retry
        http::set_header(req_post, "Idempotency-Key", "uuid-v4-998811-aabbcc");
        sub.assert_true(net::should_retry_tier1_stale_socket(true, req_post), "POST with Idempotency-Key approved for Tier 1 retry");

        // 6. Non-idempotent PATCH without Idempotency-Key: rejected
        var req_patch = http::new_request("PATCH", "https://api.io/items/1");
        sub.assert_false(net::should_retry_tier1_stale_socket(true, req_patch), "PATCH without Idempotency-Key rejected");

        // 7. Non-idempotent PATCH WITH Idempotency-Key: approved
        http::set_header(req_patch, "Idempotency-Key", "patch-key-1");
        sub.assert_true(net::should_retry_tier1_stale_socket(true, req_patch), "PATCH with Idempotency-Key approved");

        // 8. Idempotent RFC methods sweep
        var req_head = http::new_request("HEAD", "https://api.io/items");
        sub.assert_true(net::should_retry_tier1_stale_socket(true, req_head), "HEAD is idempotent");

        var req_put = http::new_request("PUT", "https://api.io/items/1");
        sub.assert_true(net::should_retry_tier1_stale_socket(true, req_put), "PUT is idempotent");

        var req_del = http::new_request("DELETE", "https://api.io/items/1");
        sub.assert_true(net::should_retry_tier1_stale_socket(true, req_del), "DELETE is idempotent");

        var req_opt = http::new_request("OPTIONS", "https://api.io/items");
        sub.assert_true(net::should_retry_tier1_stale_socket(true, req_opt), "OPTIONS is idempotent");

        var req_trace = http::new_request("TRACE", "https://api.io/items");
        sub.assert_true(net::should_retry_tier1_stale_socket(true, req_trace), "TRACE is idempotent");
    };

    t.run("Go #81671 & RFC 9110: QUERY Method Safe & Replayable") { sub =>
        // RFC 9110 and draft-ietf-httpbis-safe-method-w-body:
        // QUERY method is safe and idempotent, and carries a request body.
        // It MUST be replayable on stale socket disconnections.
        var req_query = http::new_request("QUERY", "https://api.io/search");
        http::text(req_query, "SELECT id, name FROM users WHERE active = true");
        sub.assert_true(rfc::is_idempotent_method("QUERY"), "QUERY recognized as idempotent");
        sub.assert_true(net::should_retry_tier1_stale_socket(true, req_query), "QUERY with rewindable body replayable on stale socket drop");
    };

    t.run("Defense against One-Shot Stream Retry Bug (Go #41907 / #41913)") { sub =>
        // Request with non-empty body that is NOT rewindable (already consumed stream)
        var req_stream = http::new_request("PUT", "https://api.io/upload");
        req_stream.body.append("multipart-stream-chunk-data");
        req_stream.rewindable = false;
        req_stream.body_consumed = true;

        sub.assert_false(net::should_retry_tier1_stale_socket(true, req_stream), "Unrewindable consumed body stream rejected (prevents sending empty body)");

        // Non-empty body with rewindable = false but body_consumed = false
        var req_unrewind = http::new_request("PUT", "https://api.io/upload");
        req_unrewind.body.append("data");
        req_unrewind.rewindable = false;
        sub.assert_false(net::should_retry_tier1_stale_socket(true, req_unrewind), "Unrewindable body rejected");

        // Non-empty body with rewindable = true and body_consumed = true
        var req_consumed = http::new_request("PUT", "https://api.io/upload");
        req_consumed.body.append("data");
        req_consumed.rewindable = true;
        req_consumed.body_consumed = true;
        sub.assert_false(net::should_retry_tier1_stale_socket(true, req_consumed), "Already-consumed rewindable body rejected");

        // Request with rewindable body buffer (GetBody pattern)
        var req_rewindable = http::new_request("PUT", "https://api.io/upload");
        http::text(req_rewindable, "rewindable-payload-data");
        sub.assert_true(net::should_retry_tier1_stale_socket(true, req_rewindable), "Rewindable body approved for retry");
    };

    t.run("Chromium ERR_QUIC_PROTOCOL_ERROR Automatic TCP Fallback") { sub =>
        var req = http::new_request("GET", "https://quic.example.com");
        let dec = net::evaluate_tier1_retry(net::ERR_QUIC_PROTOCOL_ERROR, false, req);

        sub.assert_true(dec.retry_immediately, "Immediate retry on ERR_QUIC_PROTOCOL_ERROR");
        sub.assert_true(dec.disable_alternative_services, "disable_alternative_services flagged to force reliable TCP/TLS");

        // If headers were already received, cannot fallback immediately
        let dec_headers = net::evaluate_tier1_retry(net::ERR_QUIC_PROTOCOL_ERROR, false, req, true);
        sub.assert_false(dec_headers.retry_immediately, "QUIC error after headers received does not trigger blind retry");
    };
}

// ----------------------------------------------------------------------------
// 26. Tier 2 Backoff & Jitter Strategies
// ----------------------------------------------------------------------------
fn test_tier2_exponential_backoff_and_jitter(t: lit::T&) {
    t.run("Deterministic Backoff and 3 Jitter Strategies") { sub =>
        var seed:       u64 = 123456789;
        var prev_sleep: i64 = 0;

        let cfg_full = net::new_backoff_config(100, 5000, net::JitterStrategy.FullJitter);
        let cfg_equal = net::new_backoff_config(100, 5000, net::JitterStrategy.EqualJitter);
        let cfg_decorr = net::new_backoff_config(100, 5000, net::JitterStrategy.DecorrelatedJitter);
        let cfg_none = net::new_backoff_config(100, 5000, net::JitterStrategy.None);

        // Attempt 0: target 100 ms
        let t0 = net::compute_backoff_jitter_ms(cfg_none, 0, prev_sleep, seed);
        sub.assert_eq(t0, 100, "Attempt 0 deterministic delay is 100 ms");

        // Attempt 1: target 200 ms
        let t1 = net::compute_backoff_jitter_ms(cfg_none, 1, prev_sleep, seed);
        sub.assert_eq(t1, 200, "Attempt 1 deterministic delay is 200 ms");

        // Attempt 3: target 100 * 2^3 = 800 ms
        let t3 = net::compute_backoff_jitter_ms(cfg_none, 3, prev_sleep, seed);
        sub.assert_eq(t3, 800, "Attempt 3 deterministic delay is 800 ms");

        // Attempt 10: target 100 * 2^10 = 102400 ms -> clamped to cap 5000 ms
        let t10 = net::compute_backoff_jitter_ms(cfg_none, 10, prev_sleep, seed);
        sub.assert_eq(t10, 5000, "Attempt 10 clamped to cap 5000 ms");

        // Attempt 50: large attempt number must NOT overflow 64-bit integer
        let t50 = net::compute_backoff_jitter_ms(cfg_none, 50, prev_sleep, seed);
        sub.assert_eq(t50, 5000, "Attempt 50 clamped safely without integer overflow");

        // Full Jitter: in range [0, 800]
        for i in 20 {
            let fj = net::compute_backoff_jitter_ms(cfg_full, 3, prev_sleep, seed);
            sub.assert_true(fj >= 0 && fj <= 800, "Full Jitter within [0, 800]");
        }

        // Equal Jitter: in range [half, target] = [400, 800]
        for i in 20 {
            let ej = net::compute_backoff_jitter_ms(cfg_equal, 3, prev_sleep, seed);
            sub.assert_true(ej >= 400 && ej <= 800, "Equal Jitter maintains non-zero floor within [400, 800]");
        }

        // Decorrelated Jitter bounded by [base, cap]
        prev_sleep = 100;
        for i in 20 {
            let dj = net::compute_backoff_jitter_ms(cfg_decorr, 3, prev_sleep, seed);
            sub.assert_true(dj >= 100 && dj <= 5000, "Decorrelated Jitter bounded by [base, cap]");
        }
    };
}

// ----------------------------------------------------------------------------
// 27. RFC 9110 Retry-After Parser
// ----------------------------------------------------------------------------
fn test_rfc9110_retry_after_parser(t: lit::T&) {
    t.run("delay-seconds (1*DIGIT) Parsing") { sub =>
        let now_ms: i64 = 1700000000000;

        let ms0, ok0 = net::parse_retry_after_ms("0", now_ms);
        sub.assert_true(ok0, "Parsed delay-seconds '0'");
        sub.assert_eq(ms0, 0, "0 seconds is 0 ms");

        let ms1, ok1 = net::parse_retry_after_ms("1", now_ms);
        sub.assert_true(ok1, "Parsed delay-seconds '1'");
        sub.assert_eq(ms1, 1000, "1 second is 1000 ms");

        let ms120, ok120 = net::parse_retry_after_ms("120", now_ms);
        sub.assert_true(ok120, "Parsed delay-seconds '120'");
        sub.assert_eq(ms120, 120000, "120 seconds is 120,000 ms");

        let ms86400, ok86400 = net::parse_retry_after_ms("86400", now_ms);
        sub.assert_true(ok86400, "Parsed delay-seconds '86400'");
        sub.assert_eq(ms86400, 86400000, "86400 seconds is 86,400,000 ms (24h)");

        // Leading/trailing whitespace trimmed
        let ms_ws, ok_ws = net::parse_retry_after_ms("  45  ", now_ms);
        sub.assert_true(ok_ws, "Parsed delay-seconds with whitespace");
        sub.assert_eq(ms_ws, 45000, "45 seconds is 45,000 ms");

        // Invalid integer formats rejected
        let _, bad1 = net::parse_retry_after_ms("120s", now_ms);
        sub.assert_false(bad1, "Rejected unit suffix '120s'");

        let _, bad2 = net::parse_retry_after_ms("-10", now_ms);
        sub.assert_false(bad2, "Rejected negative delay-seconds '-10'");

        let _, bad3 = net::parse_retry_after_ms("+10", now_ms);
        sub.assert_false(bad3, "Rejected explicit positive sign '+10'");

        let _, bad4 = net::parse_retry_after_ms("12.5", now_ms);
        sub.assert_false(bad4, "Rejected decimal delay-seconds '12.5'");

        let _, bad5 = net::parse_retry_after_ms("abc", now_ms);
        sub.assert_false(bad5, "Rejected alphanumeric string");

        let _, bad6 = net::parse_retry_after_ms("", now_ms);
        sub.assert_false(bad6, "Rejected empty string");

        let _, bad7 = net::parse_retry_after_ms("   ", now_ms);
        sub.assert_false(bad7, "Rejected whitespace-only string");
    };

    t.run("IMF-fixdate Parsing and Exact UTC Round-Trip Validation") { sub =>
        // Wednesday, 21 Oct 2015 07:28:00 GMT = 1445412480000 ms
        let http_date = "Wed, 21 Oct 2015 07:28:00 GMT";

        // If current time is earlier (e.g. 1445412470000, 10s earlier)
        let delta_ms, ok_date = net::parse_retry_after_ms(http_date, 1445412470000);
        sub.assert_true(ok_date, "Parsed valid future IMF-fixdate");
        sub.assert_eq(delta_ms, 10000, "Calculated 10,000 ms delta");

        // If date is in the past: clamped to 0 ms
        let delta_past, ok_past = net::parse_retry_after_ms(http_date, 1500000000000);
        sub.assert_true(ok_past, "Parsed past IMF-fixdate");
        sub.assert_eq(delta_past, 0, "Past date clamped to 0 ms (never negative)");

        // Invalid calendar date: Feb 31 rejected by round-trip check
        let bad_date = "Wed, 31 Feb 2024 12:00:00 GMT";
        let _, ok_bad = net::parse_retry_after_ms(bad_date, 1700000000000);
        sub.assert_false(ok_bad, "Invalid calendar day 31 Feb rejected by round-trip validator");

        // Invalid month string
        let bad_month = "Wed, 21 Foo 2026 07:28:00 GMT";
        let _, ok_bm = net::parse_retry_after_ms(bad_month, 1700000000000);
        sub.assert_false(ok_bm, "Invalid month 'Foo' rejected");
    };
}

// ----------------------------------------------------------------------------
// 28. Circuit Breaker & Adaptive Retry Budget
// ----------------------------------------------------------------------------
fn test_circuit_breaker_and_adaptive_retry_budget(t: lit::T&) {
    t.run("Host Circuit Breaker on Excessive Retry-After") { sub =>
        var breaker = net::new_host_circuit_breaker(60000); // 60s max wait

        // Retry-After of 30s does not trip circuit breaker
        let tripped_small = net::trip_circuit_breaker_if_exceeded(breaker, "api.overloaded.com", 30000, 0);
        sub.assert_false(tripped_small, "30s does not trip circuit breaker");
        sub.assert_false(net::is_host_circuit_broken(breaker, "api.overloaded.com", 0), "Host not blocked");

        // Retry-After of 300s (> 60s) trips circuit breaker
        let tripped_large = net::trip_circuit_breaker_if_exceeded(breaker, "api.overloaded.com", 300000, 1000000000);
        sub.assert_true(tripped_large, "300s trips circuit breaker");
        sub.assert_true(net::is_host_circuit_broken(breaker, "api.overloaded.com", 2000000000), "Host blocked by circuit breaker");

        // Advance beyond unblock deadline (1s + 300s = 301s)
        sub.assert_false(net::is_host_circuit_broken(breaker, "api.overloaded.com", 302000000000), "Host unblocked after cool-down");

        // Different host is not blocked
        sub.assert_false(net::is_host_circuit_broken(breaker, "other.healthy.com", 2000000000), "Other host is not blocked");
    };

    t.run("Google SRE Adaptive Retry Budget") { sub =>
        // 20% max ratio, 2 retries/sec floor, 10s window (floor = 20 retries allowed)
        var budget = net::new_adaptive_retry_budget(20, 2, 10);

        // Record 100 primary requests
        for i in 100 {
            net::record_primary_request(budget, 1000000000);
        }

        // Allowed retries: max(100 * 20% = 20, 2 * 10 = 20) = 20 retries
        for i in 20 {
            let ok = net::allow_retry_budget(budget, 1000000000);
            sub.assert_true(ok, "Retry within budget allowed");
        }

        // 21st retry attempt exceeds budget during flood
        let blocked = net::allow_retry_budget(budget, 1000000000);
        sub.assert_false(blocked, "Retry exceeding 20% budget rejected to prevent retry storm");

        // After window advances (t = 12s, delta = 11s > 10s window), budget resets
        net::record_primary_request(budget, 12000000000);
        sub.assert_eq(budget.retried_requests, 0, "Retried requests reset in new window");
        let ok_new = net::allow_retry_budget(budget, 12000000000);
        sub.assert_true(ok_new, "Retry permitted after window resets");
    };
}

// --- Component: net_dns_svcb_ech ---
// tests/dns_svcb_ech_test.goose
// Verification Suite for RFC 9460 (HTTPS/SVCB DNS Resource Records),
// Encrypted Client Hello (ECH) parameter extraction, and DNS Cache Lifecycle.

// ----------------------------------------------------------------------------
// 29. RFC 9460 HTTPS/SVCB Parameter Parsing
// ----------------------------------------------------------------------------
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

        var rec = dns::HttpsRecord { .. };
        let ok = rec.parse_https_svc_params(raw_params[..]);
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
        var r1 = dns::HttpsRecord { .. };
        sub.assert_false(r1.parse_https_svc_params(out_of_order[..]), "Out-of-order keys rejected");

        // Reject duplicate keys: Key 3 twice
        var duplicate_key: u8[>..] = [];
        duplicate_key.append([0x00, 0x03, 0x00, 0x02, 0x01, 0xBB]);
        duplicate_key.append([0x00, 0x03, 0x00, 0x02, 0x01, 0xBB]);
        var r2 = dns::HttpsRecord { .. };
        sub.assert_false(r2.parse_https_svc_params(duplicate_key[..]), "Duplicate keys rejected");

        // Reject bad port length: 1 byte
        var bad_port: u8[>..] = [];
        bad_port.append([0x00, 0x03, 0x00, 0x01, 0x50]);
        var r3 = dns::HttpsRecord { .. };
        sub.assert_false(r3.parse_https_svc_params(bad_port[..]), "Port length != 2 rejected");

        // Reject bad IPv4 length: 6 bytes (not multiple of 4)
        var bad_ip4: u8[>..] = [];
        bad_ip4.append([0x00, 0x04, 0x00, 0x06, 0xC0, 0x00, 0x02, 0x01, 0x00, 0x01]);
        var r4 = dns::HttpsRecord { .. };
        sub.assert_false(r4.parse_https_svc_params(bad_ip4[..]), "IPv4 hint length not multiple of 4 rejected");

        // Reject truncated parameter value (stated length 4, actual bytes 2)
        var trunc_val: u8[>..] = [];
        trunc_val.append([0x00, 0x04, 0x00, 0x04, 0xC0, 0x00]);
        var r5 = dns::HttpsRecord { .. };
        sub.assert_false(r5.parse_https_svc_params(trunc_val[..]), "Truncated parameter value rejected");
    };
}

// ----------------------------------------------------------------------------
// 30. DoH Query Serialization
// ----------------------------------------------------------------------------
fn test_doh_query_generation(t: lit::T&) {
    t.run("1. DoH POST Body and GET URL Construction") { sub =>
        var post_body: u8[..512] = [];
        let ok_post = dns::build_doh_post_body("cloudflare.com", rfc::DNS_QTYPE_HTTPS, 0x1234, post_body);
        sub.assert_true(ok_post, "build_doh_post_body succeeds");
        sub.assert_true(post_body.len >= 12, "Post body at least DNS header size (12 bytes)");

        // Header check: tx_id 0x1234
        sub.assert_eq(post_body[0], 0x12, "Tx ID byte 0");
        sub.assert_eq(post_body[1], 0x34, "Tx ID byte 1");

        // GET URL with base64url query parameter
        var get_url: u8[..512] = [];
        let ok_get = dns::build_doh_get_url("https://1.1.1.1/dns-query", "cloudflare.com", rfc::DNS_QTYPE_HTTPS, get_url);
        sub.assert_true(ok_get, "build_doh_get_url succeeds");
        sub.assert_true(core::starts_with(get_url[..], "https://1.1.1.1/dns-query?dns="), "URL starts with endpoint and ?dns=");
    };
}

// ----------------------------------------------------------------------------
// 31. DNS Cache Lifecycle & Stale-While-Revalidate
// ----------------------------------------------------------------------------
fn test_dns_cache_lifecycle(t: lit::T&) {
    t.run("1. Freshness, Stale-While-Revalidate Window, and Expiration") { sub =>
        var cache = dns::Cache { .. };

        var entry = dns::CacheEntry { .. };
        entry.domain.append("api.example.com");
        entry.qtype = rfc::DNS_QTYPE_A;
        entry.ipv4_hints.push(0x7F000001); // 127.0.0.1
        entry.inserted_at_sec = 1000;
        entry.ttl_sec = 60;
        entry.stale_ttl_sec = 300; // Stale window: 1060 .. 1360
        entry.valid = true;

        cache.insert(entry);
        sub.assert_eq(cache.entries.len, 1, "Cache holds 1 entry");

        // Lookup at t = 1030 (Fresh, elapsed 30 < 60)
        let out1, st1 = cache.lookup("api.example.com", rfc::DNS_QTYPE_A, 1030);
        sub.assert_eq(st1, dns::CacheStatus.Fresh, "Lookup at t=1030 is Fresh");
        sub.assert_true(out1 != null, "Fresh lookup returns entry ref");
        if out1 {
            sub.assert_eq(out1.ipv4_hints.len, 1, "Output holds 1 IP");
            sub.assert_eq(out1.ipv4_hints[0], 0x7F000001, "IP matches");
        }

        // Lookup at t = 1100 (Stale, elapsed 100 >= 60 but < 360)
        let out2, st2 = cache.lookup("api.example.com", rfc::DNS_QTYPE_A, 1100);
        sub.assert_eq(st2, dns::CacheStatus.Stale, "Lookup at t=1100 is Stale");
        sub.assert_true(out2 != null, "Stale lookup returns entry ref");

        // Lookup at t = 1400 (Expired, elapsed 400 >= 360)
        let out3, st3 = cache.lookup("api.example.com", rfc::DNS_QTYPE_A, 1400);
        sub.assert_eq(st3, dns::CacheStatus.Expired, "Lookup at t=1400 is Expired");
        sub.assert_true(out3 == null, "Expired lookup returns null");

        // Overwrite existing entry with refreshed TTL
        var updated = entry;
        updated.inserted_at_sec = 1400;
        updated.ttl_sec = 120;
        cache.insert(updated);
        sub.assert_eq(cache.entries.len, 1, "Cache still holds 1 entry after update");

        let out4, st4 = cache.lookup("api.example.com", rfc::DNS_QTYPE_A, 1450);
        sub.assert_eq(st4, dns::CacheStatus.Fresh, "Lookup after refresh is Fresh");
        sub.assert_true(out4 != null, "Refreshed lookup returns entry ref");
    };
}

// ----------------------------------------------------------------------------
// 32. RFC 1035 §2.3.4 & §4.1.4: DNS Wire Decoding Label Length <= 63 and Reserved Bits
// ----------------------------------------------------------------------------
fn test_dns_decode_label_length_and_reserved_bits(t: lit::T&) {
    t.run("DNS wire decode MUST reject label length > 63") { sub =>
        // RFC 1035 Section 2.3.4: "labels: 63 octets or less"
        // Construct DNS wire name with an illegal label length byte of 64 (0x40) or 70.
        // But 0x40 has high bits 01 (reserved), while 0x46 is 70 with 00!
        // A label of 70 bytes: length byte 70 (0x46), followed by 70 'a' bytes, followed by 0x00.
        var wire: u8[..128] = [];
        wire.push(70 as u8); // Illegal: > 63 octets!
        for i in 70 { wire.push('a' as u8); }
        wire.push(0); // Zero root label

        var out_name: u8[..256] = [];
        var off:      i64       = 0;
        let ok = dns::decode_name(wire[..], off, out_name);
        sub.assert_false(ok, "dns::decode_name MUST reject label with length 70 (> 63)");
    };

    t.run("DNS wire decode MUST reject reserved high-order label bits (0x40 or 0x80)") { sub =>
        // RFC 1035 Section 4.1.4: "The 10 and 01 combinations are reserved for future use."
        // Only 00 (uncompressed label <= 63) and 11 (0xC0 compression pointer) are valid.
        var wire:     u8[..16]  = [0x44, 't', 'e', 's', 't', 0x00]; // 0x44 has bits 01_000100
        var out_name: u8[..256] = [];
        var off:      i64       = 0;
        let ok = dns::decode_name(wire[..], off, out_name);
        sub.assert_false(ok, "dns::decode_name MUST reject label starting with reserved bits 01 (0x40)");
    };
}

// ----------------------------------------------------------------------------
// 33. CVE-2026-94441 & Go #81656: Scheme Isolation in Connection Pool Keys
// ----------------------------------------------------------------------------
fn test_h2c_vs_https_connection_pool_isolation(t: lit::T&) {
    t.run("Connection pool key for H2c vs Https to same host:port MUST NOT match") { sub =>
        let dummy_proxy = net::ProxyChain { .. };
        let dummy_part = net::NetworkAnonymizationKey { .. };
        let dummy_policy = net::TlsAndDnsPolicy { .. };

        let h2c_key = net::new_pool_key(
            net::PoolScheme.H2c,
            "api.internal",
            80,
            dummy_proxy,
            dummy_part,
            dummy_policy,
        );

        let https_key = net::new_pool_key(
            net::PoolScheme.Https,
            "api.internal",
            80,
            dummy_proxy,
            dummy_part,
            dummy_policy,
        );

        sub.assert_false(net::pool_key_equals(h2c_key, https_key), "H2c and Https pool keys MUST NOT be equal");
        sub.assert_ne(net::pool_key_hash(h2c_key), net::pool_key_hash(https_key), "H2c and Https pool keys MUST produce different hashes");
    };
}

// ----------------------------------------------------------------------------
// 34. DNS Name Decoding Length Overflow
// ----------------------------------------------------------------------------
fn test_dns_name_length_overflow(t: lit::T&) {
    // Malformed pointer chain pointing beyond end of packet
    let bad_dns: u8[12] = [
        0x00, 0x01, 0x81, 0x80,
        0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ];
    let _, ok = dns::parse_response(bad_dns[..]);
    t.assert_false(ok, "Truncated DNS packet must return false without panic");
}

// ----------------------------------------------------------------------------
// 35. Per-Group & Per-Proxy Socket Quotas + WantQueue Handoff
// ----------------------------------------------------------------------------
fn test_group_and_proxy_quotas_with_waiter_handoff(t: lit::T&) {
    t.run("max_sockets_per_group evicts group idle or rejects when all active, and hands off to WantQueue waiter") { sub =>
        var pool = net::new_stream_pool();
        pool.max_sockets_per_group = 2;
        pool.max_sockets_per_proxy = 3;

        var proxy = net::ProxyChain { .. };
        proxy.is_direct = false;
        proxy.servers.push(net::new_proxy_server(net::ProxyScheme.Http, "proxy.corp.local", 8080));

        let nak = net::NetworkAnonymizationKey { .. };
        let pol = net::TlsAndDnsPolicy { .. };
        let key_a = net::new_pool_key(net::PoolScheme.Https, "a.example.com", 443, proxy, nak, pol);
        let key_b = net::new_pool_key(net::PoolScheme.Https, "b.example.com", 443, proxy, nak, pol);

        sub.assert_true(net::can_allocate_group_socket(pool, key_a), "Initial group quota available");

        let id1 = net::register_connection(pool, key_a, net::NegotiatedProtocol.Http11, "203.0.113.10", 443, 1000);
        let id2 = net::register_connection(pool, key_a, net::NegotiatedProtocol.Http11, "203.0.113.10", 443, 1001);
        sub.assert_gt(id1, 0, "Conn 1 allocated");
        sub.assert_gt(id2, 0, "Conn 2 allocated");
        sub.assert_false(net::can_allocate_group_socket(pool, key_a), "Group quota full with 2 active connections");

        // 3rd active connection in same group MUST be rejected (-1)
        let id3_blocked = net::register_connection(pool, key_a, net::NegotiatedProtocol.Http11, "203.0.113.10", 443, 1002);
        sub.assert_eq(id3_blocked, -1, "3rd active connection in group rejected by max_sockets_per_group");

        // Enqueue a waiter for group A and release id1 -> direct handoff to waiter!
        let enq_ok = net::enqueue_group_waiter(pool, key_a, 9001);
        sub.assert_true(enq_ok, "Waiter enqueued in group WantQueue");
        var handed_waiter = net::WantConn { .. };
        let rel_ok1, handed_off = net::release_connection_or_handoff(pool, id1, 1004, handed_waiter);
        sub.assert_true(rel_ok1 && handed_off, "Released connection handed off directly to queued waiter");
        sub.assert_eq(handed_waiter.req_id, 9001 as u64, "Handed off waiter req_id matches");

        // Release id1 again with no waiters -> becomes Idle
        var dummy_waiter = net::WantConn { .. };
        let rel_ok2, handed_off2 = net::release_connection_or_handoff(pool, id1, 1005, dummy_waiter);
        sub.assert_true(rel_ok2 && !handed_off2, "Released connection parks as Idle when WantQueue is empty");
        sub.assert_true(net::can_allocate_group_socket(pool, key_a), "Group quota available by evicting idle connection");

        // Allocating new connection in group A evicts idle id1 and succeeds
        let id3_ok = net::register_connection(pool, key_a, net::NegotiatedProtocol.Http11, "203.0.113.10", 443, 1006);
        sub.assert_gt(id3_ok, 0, "New connection in group A succeeds after evicting oldest idle in group");

        // Group B shares the same proxy (max_sockets_per_proxy = 3, currently 2 active in group A)
        let id_b1 = net::register_connection(pool, key_b, net::NegotiatedProtocol.Http11, "203.0.113.11", 443, 1007);
        sub.assert_gt(id_b1, 0, "3rd proxy connection across group B allowed");
        let id_b2_blocked = net::register_connection(pool, key_b, net::NegotiatedProtocol.Http11, "203.0.113.11", 443, 1008);
        sub.assert_eq(id_b2_blocked, -1, "4th active connection on same proxy rejected by max_sockets_per_proxy=3");
    };
}

// ----------------------------------------------------------------------------
// 36. HEv3 HTTPS/SVCB Metadata Extraction & AddressFamilyCache
// ----------------------------------------------------------------------------
fn test_hev3_https_svcb_and_address_family_cache(t: lit::T&) {
    t.run("extract_https_svcb_metadata extracts ALPN, ECH, port override, and IPv4/IPv6 hints") { sub =>
        var rec = dns::HttpsRecord {
            priority: 1,
            port:     8443,
            has_ech:  true,
            ..
        };
        rec.target_name.append("svc.example.com");
        rec.ech_config_list.append("ech-wire-bytes");
        rec.alpns.push("h3");
        rec.alpns.push("h2");
        rec.ipv4_hints.push(0x5DB8D822);
        rec.ipv6_hints.push([0x26, 0x06, 0x28, 0x00, 0x02, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x48]);

        let meta, eff_port = net::extract_https_svcb_metadata(rec, 443);
        sub.assert_eq(eff_port, 8443, "SVCB port override applied");
        sub.assert_true(meta.alpn_h3, "alpn_h3 extracted");
        sub.assert_true(meta.alpn_h2, "alpn_h2 extracted");
        sub.assert_true(meta.ech_config_present, "ech_config_present extracted");
        sub.assert_eq(meta.ipv4_hints.len, 1, "1 IPv4 hint extracted");
        sub.assert_bytes_eq(meta.ipv4_hints[0][..], "93.184.216.34", "IPv4 hint formatted");
        sub.assert_eq(meta.ipv6_hints.len, 1, "1 IPv6 hint extracted");
    };

    t.run("AddressFamilyCache records preferred winner family and reorders interleave") { sub =>
        var af_cache = net::AddressFamilyCache { .. };
        let _, found0 = net::lookup_preferred_family(af_cache, "dual.example.com", 100);
        sub.assert_false(found0, "Empty cache returns false");

        net::record_preferred_family(af_cache, "dual.example.com", net::AddressFamily.IPv4, 100);
        let pref, found1 = net::lookup_preferred_family(af_cache, "dual.example.com", 200);
        sub.assert_true(found1, "Cache hit within TTL");
        sub.assert_true(pref == net::AddressFamily.IPv4, "Preferred family is IPv4");

        let _, found_exp = net::lookup_preferred_family(af_cache, "dual.example.com", 800);
        sub.assert_false(found_exp, "Cache entry expires after 600s TTL");

        var v6: net::DnsCandidate[..2] = [];
        v6.push(net::new_dns_candidate(net::AddressFamily.IPv6, "2001:db8::1", 443, net::L4Protocol.Tcp, 50));
        var v4: net::DnsCandidate[..2] = [];
        v4.push(net::new_dns_candidate(net::AddressFamily.IPv4, "198.51.100.1", 443, net::L4Protocol.Tcp, 40));

        var out: net::DnsCandidate[..32] = [];
        net::interleave_candidates_by_preference(v6[..], v4[..], net::AddressFamily.IPv4, out);
        sub.assert_eq(out.len, 2, "2 candidates interleaved");
        sub.assert_true(out[0].family == net::AddressFamily.IPv4, "IPv4 placed first when preferred");
        sub.assert_true(out[1].family == net::AddressFamily.IPv6, "IPv6 placed second");
    };
}

// ----------------------------------------------------------------------------
// 37. Core Cross-Framework UFCS Async Reactor & Backpressure Contract
// ----------------------------------------------------------------------------
fn wake_echo_handler(tag: u64, ev: const core::PollReadyEvent&, el: net::EventLoop&) {
    if tag == 8800 && (ev.events & core::POLL_WAKE) != 0 {
        let _ = net::defer_task(el, tag, 1, 7);
    }
}

fn test_core_reactor_and_wake_contract(t: lit::T&) {
    t.run("core::Poller Generic Reactor & POLL_WAKE Delivery") { sub =>
        var cfg = net_internal::auto_transport_driver_config();
        var poller = net::new_poller(cfg);

        sub.assert_true(core::reactor_register(poller, 71, 3001, core::PollInterest.Read, core::PollTrigger.Level), "reactor_register");
        sub.assert_true(core::reactor_modify(poller, 71, 3001, core::PollInterest.ReadWrite, core::PollTrigger.Edge), "reactor_modify");
        sub.assert_true(core::reactor_wake(poller, 4444), "reactor_wake 4444");
        sub.assert_true(core::reactor_wake(poller, 4444), "reactor_wake dedups 4444");
        sub.assert_true(core::reactor_add_timer(poller, 55, 10, 5555, false, 1000000), "reactor_add_timer");
        let _ = net::simulate_read_ready(poller, 71, 128);

        var evs: core::PollReadyEvent[..64] = [];
        let n = core::reactor_poll(poller, 0, 20000000, evs);
        sub.assert_eq(n, 3, "Harvested wake + timer + socket read");
        sub.assert_eq(evs[0].tag, 4444, "First event is wake tag 4444");
        sub.assert_true((evs[0].events & core::POLL_WAKE) != 0, "Wake event has POLL_WAKE");
        sub.assert_true(core::reactor_deregister(poller, 71), "reactor_deregister");
        net::close_poller(poller);
    };

    t.run("EventLoop::wake_tag & Stopped Guard") { sub =>
        var cfg = net_internal::auto_transport_driver_config();
        var el = net::new_event_loop(cfg);
        sub.assert_true(net::wake_tag(el, 8800), "wake_tag queued on open loop");
        let cnt = net::run_loop_once(el, 0, 1000000, wake_echo_handler);
        sub.assert_eq(cnt, 1, "1 wake event dispatched");
        sub.assert_true(net::has_deferred_tasks(el), "wake_echo_handler deferred follow-up task");
        net::close_event_loop(el);
        sub.assert_false(net::wake_tag(el, 8801), "wake_tag rejected on stopped loop");
    };

    t.run("core::stream_try_send/recv Backpressure & net::TcpDialer") { sub =>
        var pipe = core::new_pipe_buffer();
        var rx: u8[16] = [0; 16];
        let r0, e0 = core::stream_try_recv(pipe, rx[..]);
        sub.assert_eq(r0, 0, "Empty pipe yields 0 bytes");
        sub.assert_eq(e0, core::IoError.WouldBlock, "Empty open pipe yields WouldBlock");

        let s1, se1 = core::stream_try_send(pipe, "ASYNC");
        sub.assert_eq(s1, 5, "Sent 5 bytes");
        sub.assert_eq(se1, core::IoError.None, "No error on send");

        core::stream_close(pipe);
        let r1, e1 = core::stream_try_recv(pipe, rx[..]);
        sub.assert_eq(r1, 5, "Read buffered 5 bytes after close");
        sub.assert_eq(e1, core::IoError.None, "No error while buffered bytes remain");

        let r2, e2 = core::stream_try_recv(pipe, rx[..]);
        sub.assert_eq(r2, 0, "0 bytes after drain");
        sub.assert_eq(e2, core::IoError.Eof, "Closed drained pipe yields Eof");

        var dialer = net::TcpDialer { default_timeout_ms: 100 };
        let fd, derr = core::reactor_dial(dialer, core::DialTarget { host: "", port: 0, .. });
        sub.assert_eq(fd, -1, "Invalid dial target returns -1");
        sub.assert_eq(derr, core::IoError.InvalidArgument, "Invalid dial target returns InvalidArgument");
    };
}

// ----------------------------------------------------------------------------
// 38. Live OS Loopback E2E + VirtualPipe Backpressure Parity
// ----------------------------------------------------------------------------
fn test_live_os_loopback_reactor_e2e(t: lit::T&) {
    t.run("Live OS Loopback: TcpDialer + EventLoop OS Multiplexing + Eof") { sub =>
        let srv = net::tcp_listen("127.0.0.1", 0);
        sub.assert_true(srv > 0, "tcp_listen ephemeral loopback");
        defer if srv > 0 { net::tcp_close(srv); };
        let port = net::tcp_getsockname_port(srv);
        sub.assert_true(port != 0, "getsockname returns bound port");

        var dialer = net::TcpDialer { default_timeout_ms: 2000 };
        let target = core::DialTarget { host: "127.0.0.1", port: port, timeout_ms: 2000, non_blocking: true };
        let cli_fd, derr = core::reactor_dial(dialer, target);
        sub.assert_true(cli_fd > 0 && derr == core::IoError.None, "reactor_dial non_blocking loopback");
        var cli_tr: net::Transport = net::Transport.Tcp { fd: cli_fd };
        defer core::stream_close(cli_tr);

        let acc_fd = net::tcp_accept(srv, 1000);
        sub.assert_true(acc_fd > 0, "tcp_accept loopback peer");
        var acc_tr: net::Transport = net::Transport.Tcp { fd: acc_fd };
        defer core::stream_close(acc_tr);

        var rx: u8[32] = [0; 32];
        let r0, e0 = core::stream_try_recv(cli_tr, rx[..]);
        sub.assert_eq(r0, 0, "Empty non-blocking Tcp recv yields 0");
        sub.assert_eq(e0, core::IoError.WouldBlock, "Empty non-blocking Tcp recv yields WouldBlock");

        var cfg = net_internal::auto_transport_driver_config();
        var el = net::new_event_loop(cfg);
        defer net::close_event_loop(el);
        sub.assert_true(net::enable_os_multiplexing(el), "EventLoop enable_os_multiplexing");
        sub.assert_true(core::reactor_register(el, cli_fd as i32, 7070, core::PollInterest.Read), "reactor_register");
        sub.assert_true(core::reactor_modify(el, cli_fd as i32, 7070, core::PollInterest.ReadWrite), "reactor_modify");
        sub.assert_true(core::reactor_add_timer(el, 91, 5000, 9191, false, 1000), "reactor_add_timer");
        sub.assert_true(core::reactor_cancel_timer(el, 91), "reactor_cancel_timer");
        sub.assert_true(core::reactor_modify(el, cli_fd as i32, 7070, core::PollInterest.Read), "restore Read interest");

        let s1, se1 = core::stream_try_send(acc_tr, "WING_REACTOR");
        sub.assert_eq(s1, 12, "Server sent 12 bytes");
        sub.assert_eq(se1, core::IoError.None, "Server send IoError.None");

        var evs: core::PollReadyEvent[..64] = [];
        let n_ready = core::reactor_poll(el, 500, 2000, evs);
        sub.assert_true(
            n_ready >= 1 && evs[0].tag == 7070 && (evs[0].events & core::POLL_READ) != 0,
            "EventLoop woke with POLL_READ",
        );

        let r1, e1 = core::stream_try_recv(cli_tr, rx[..]);
        sub.assert_eq(r1, 12, "Client read 12 bytes after POLL_READ");
        sub.assert_eq(e1, core::IoError.None, "Client read IoError.None");
        sub.assert_true(core::equal_short(rx[..r1], "WING_REACTOR"), "Payload matches WING_REACTOR");

        core::stream_close(acc_tr);
        let n_eof = core::reactor_poll(el, 500, 3000, evs);
        sub.assert_true(n_eof >= 1 && evs[0].tag == 7070, "EventLoop signaled readable on peer close");
        let r2, e2 = core::stream_try_recv(cli_tr, rx[..]);
        sub.assert_eq(r2, 0, "Client recv 0 after peer close");
        sub.assert_eq(e2, core::IoError.Eof, "Client recv IoError.Eof after peer close");
        sub.assert_true(core::reactor_deregister(el, cli_fd as i32), "reactor_deregister");
    };

    t.run("Transport.Virtual: Empty WouldBlock, Full WouldBlock, and Peer Close Eof") { sub =>
        let ran = net::with_virtual_pipe_pair() { end_a, end_b =>
            var rx: u8[512] = [0; 512];
            let r0, e0 = core::stream_try_recv(end_b, rx[..]);
            sub.assert_eq(r0, 0, "Empty virtual pipe recv yields 0");
            sub.assert_eq(e0, core::IoError.WouldBlock, "Empty open virtual pipe yields WouldBlock");

            var tx: u8[512] = [0x41; 512];
            var saw_backpressure = false;
            for _ in 128 {
                let _, se = core::stream_try_send(end_a, tx[..]);
                if se == core::IoError.WouldBlock {
                    saw_backpressure = true;
                    break;
                }
            }
            sub.assert_true(saw_backpressure, "Full virtual pipe returns IoError.WouldBlock");

            for _ in 128 {
                let _, re = core::stream_try_recv(end_b, rx[..]);
                if re == core::IoError.WouldBlock { break; }
            }
            core::stream_close(end_a);
            let r1, e1 = core::stream_try_recv(end_b, rx[..]);
            sub.assert_eq(r1, 0, "Drained peer-closed virtual pipe yields 0");
            sub.assert_eq(e1, core::IoError.Eof, "Drained peer-closed virtual pipe yields Eof");
        };
        sub.assert_true(ran, "Allocated virtual pipe pair");
    };
}

// ----------------------------------------------------------------------------
// 39. OS Shim Regression Guards (URING-5, KQUEUE-5, RIO-3/6, ACCEL-ABBA)
// ----------------------------------------------------------------------------
fn verify_live_windows_rio_guards(sub: lit::T&) {
    let cq = net_internal::native_rio_create_cq(64);
    sub.assert_true(cq != 0, "Create RIO CQ for timeout test");
    guard cq != 0 else { return; }
    defer net_internal::native_rio_close_cq(cq);

    for _ in 3 {
        let t0 = core::monotonic_now().nanos;
        let w = net_internal::rio_wait_cq(cq, 12);
        let elapsed = core::sub_sat_u64(core::monotonic_now().nanos, t0);
        sub.assert_true(w == 0 && elapsed >= 4000000, "Repeated RIONotify timeouts sleep cleanly without WSAEINVAL spin");
    }

    let lfd_v6 = net_internal::rio_listen("::1", 0, 16);
    sub.assert_gt(lfd_v6, 0, "RIO IPv6 ::1 listener opens");
    sub.assert_gt(net::tcp_getsockname_port(lfd_v6), 0, "IPv6 getsockname returns non-zero port");
    sub.assert_eq(net_internal::native_rio_is_listener(lfd_v6), 1, "IPv6 RIO listener recognized");
    net::tcp_close(lfd_v6);
}

fn test_os_shim_regression_guards(t: lit::T&) {
    t.run("Platform detection uses compile-time C host target") { sub =>
        let plat = net_internal::detect_target_platform();
        let code = net_internal::native_host_platform();
        sub.assert_true(code >= 0 && code <= 3, "Host platform code valid");
        if code == 0 { sub.assert_true(plat == net_internal::TargetPlatform.Windows, "Windows host"); }
        if code == 1 { sub.assert_true(plat == net_internal::TargetPlatform.Linux, "Linux host"); }
        if code == 2 { sub.assert_true(plat == net_internal::TargetPlatform.Darwin, "Darwin host"); }
    };

    t.run("URING-5 multishot ioprio and KQUEUE-5 EVFILT_WRITE / EV_EOF+fflags guards") { sub =>
        var sqe = net_internal::UringSqe { .. };
        net_internal::uring_prep_recv(sqe, 9, 0, 0, 42, true);
        sub.assert_eq(sqe.ioprio, net_internal::URING_RECV_MULTISHOT, "multishot sets URING_RECV_MULTISHOT");

        let kev_w = net_internal::Kevent {
            ident: 1, filter: net_internal::EVFILT_WRITE, flags: 0, fflags: 0, data: 4096, udata: 1,
        };
        sub.assert_eq(net_internal::kevent_bytes_available(kev_w), 0, "EVFILT_WRITE bytes_available is 0");

        let kev_eof_err = net_internal::Kevent {
            ident: 1, filter: net_internal::EVFILT_READ, flags: net_internal::EV_EOF, fflags: 104, data: 0, udata: 1,
        };
        let fl, is_eof = net::map_kevent_to_poll_flags(kev_eof_err);
        sub.assert_true(is_eof && (fl & core::POLL_HANGUP) != 0 && (fl & core::POLL_ERROR) != 0, "EV_EOF+fflags sets POLL_ERROR");
    };

    t.run("ReactorAccelRuntime slot generation rejects stale tokens across slot reuse") { sub =>
        var accel = net::ReactorAccelRuntime { mode: net::ReactorAccelMode.Rio, .. };
        accel.slot_accel[2] = true;
        let tok1 = net::reactor_accel_slot_token(accel, 2);
        let s1, ok1 = net::reactor_accel_match_token(accel, tok1);
        sub.assert_true(ok1 && s1 == 2, "Fresh token matches active slot");

        net::reactor_reset_accel_slot(accel, 2);
        accel.slot_accel[2] = true;
        let tok2 = net::reactor_accel_slot_token(accel, 2);
        let s2, ok2 = net::reactor_accel_match_token(accel, tok2);
        let _, ok_stale = net::reactor_accel_match_token(accel, tok1);
        sub.assert_true(ok2 && s2 == 2 && !ok_stale, "Stale generation token rejected after slot reuse");
    };

    t.run("Windows RIO repeated RIONotify timeout and IPv6 listener") { sub =>
        if net_internal::detect_target_platform() == net_internal::TargetPlatform.Windows &&
            net_internal::native_rio_available() == 1 {
            verify_live_windows_rio_guards(sub);
        }
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
    lit::run_case(runner, "32. RFC 1035 §2.3.4 & §4.1.4: DNS Wire Decoding Label Bounds", test_dns_decode_label_length_and_reserved_bits);
    lit::run_case(runner, "33. CVE-2026-94441 & Go #81656: Scheme Isolation in Connection Pool Keys", test_h2c_vs_https_connection_pool_isolation);
    lit::run_case(runner, "34. DNS Name Decoding Length Overflow", test_dns_name_length_overflow);
    lit::run_case(runner, "35. Per-Group & Per-Proxy Socket Quotas + WantQueue Handoff", test_group_and_proxy_quotas_with_waiter_handoff);
    lit::run_case(runner, "36. HEv3 HTTPS/SVCB Metadata Extraction & AddressFamilyCache", test_hev3_https_svcb_and_address_family_cache);
    lit::run_case(runner, "37. Core Cross-Framework UFCS Async Reactor & Backpressure Contract", test_core_reactor_and_wake_contract);
    lit::run_case(runner, "38. Live OS Loopback E2E & VirtualPipe Backpressure Parity", test_live_os_loopback_reactor_e2e);
    lit::run_case(runner, "39. OS Shim Regression Guards (URING-5, KQUEUE-5, RIO-3/6, ACCEL-ABBA)", test_os_shim_regression_guards);

    let ok = lit::finish(runner);
    assert(ok);
}
