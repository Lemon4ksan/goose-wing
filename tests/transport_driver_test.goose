// Verification suite for Layer 4 Transport Driver Architecture (net/driver.goose):
// - Platform probing across Windows, Linux, and macOS
// - Driver capability bitmasks (KernelBypass, ZeroCopy, RingCompletion, BatchIO, ExactBufMetrics)
// - Graceful auto-selection and fallback handling across the Big Three (RIO, io_uring, kqueue)
// - Windows RIO page-locked zero-copy buffer lifecycle
// - Linux io_uring SQE/CQE batch submission and ring state tracking
// - macOS / Darwin kqueue event multiplexing (struct kevent, byte-accurate accounting, EOF detection)
// - Diagnostic summary string formatting
import std;
import core from "..";
import wing from "..";

fn test_driver_probing(t: core::T&) {
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

fn test_driver_fallback_and_selection(t: core::T&) {
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
            preferred_kind: internal::TransportDriverKind.IoUring,
            enable_kernel_bypass: true,
            ..
        };
        sub.assert_true(internal::init_transport_driver_with_platform(cfg, internal::TargetPlatform.Windows), "Init ok");
        sub.assert_true(cfg.active_kind == internal::TransportDriverKind.WindowsRIO, "Auto-selected WindowsRIO");
        sub.assert_true(internal::driver_has_cap(cfg.capabilities, internal::CAP_KERNEL_BYPASS), "Has KernelBypass");
    };

    t.run("Windows Graceful Fallback: io_uring preferred without bypass") { sub =>
        var cfg = internal::TransportDriverConfig {
            preferred_kind: internal::TransportDriverKind.IoUring,
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

fn test_rio_buffer_lifecycle(t: core::T&) {
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

fn test_uring_sqe_cqe_batch(t: core::T&) {
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

fn test_kqueue_event_lifecycle(t: core::T&) {
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

fn test_driver_summary_formatter(t: core::T&) {
    t.run("Summary String Formatting") { sub =>
        var cfg_rio = internal::TransportDriverConfig {
            preferred_kind: internal::TransportDriverKind.WindowsRIO,
            ring_size: 2048,
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

fn test_af_xdp_and_dpdk_kernel_bypass(t: core::T&) {
    t.run("AF_XDP UMEM Descriptor Lifecycle") { sub =>
        var umem = internal::AfXdpUmem {
            addr: 0x10000000,
            len: 8388608, // 8 MB UMEM
            chunk_size: 2048,
            headroom: 0,
            is_registered: true,
        };
        sub.assert_true(umem.is_registered, "UMEM registered");
        sub.assert_eq(umem.chunk_size, 2048, "Chunk size is 2048 bytes");

        // Verify XdpDesc packet descriptor
        var desc = internal::XdpDesc {
            addr: 0x10000800,
            len: 1460, // MSS payload
            options: 0,
        };
        sub.assert_eq(desc.addr, 0x10000800, "Packet buffer offset mapped");
        sub.assert_eq(desc.len, 1460, "Packet length 1460 bytes");
    };

    t.run("DPDK Port and Mempool Interface") { sub =>
        var dev = internal::new_dpdk_device(0);
        sub.assert_false(dev.is_initialized, "starts uninitialized");

        var pcfg = internal::DpdkPortConfig {
            port_id: 0,
            rx_queues: 4,
            tx_queues: 4,
            rx_ring_size: 1024,
            tx_ring_size: 1024,
            promiscuous: true,
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

fn test_smartnic_ktls_offload(t: core::T&) {
    t.run("SmartNIC Hardware Model Identification") { sub =>
        sub.assert_contains(internal::smartnic_model_name(internal::SmartNicModel.MellanoxConnectX6Dx), "Mellanox ConnectX-6", "Identified CX-6 Dx");
        sub.assert_contains(internal::smartnic_model_name(internal::SmartNicModel.NvidiaBlueField3), "NVIDIA BlueField-3", "Identified BlueField-3 DPU");
        sub.assert_contains(internal::smartnic_model_name(internal::SmartNicModel.IntelMountEvans), "Intel Mount Evans", "Identified Mount Evans IPU");
    };

    t.run("SmartNIC AES-GCM-128 / 256 Key Offload Configuration") { sub =>
        let key128: u8[16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let iv: u8[4] = [0xA1, 0xB2, 0xC3, 0xD4];
        let salt: u8[4] = [0xE5, 0xF6, 0x07, 0x18];
        let seq: u8[8] = [0, 0, 0, 0, 0, 0, 0, 1];

        // Attach to socket (dummy fd = 100 for test)
        let sess, err = internal::smartnic_attach_hardware_tls(
            100,
            internal::SmartNicCipherSuite.AesGcm128,
            key128[..],
            iv[..],
            salt[..],
            seq[..]
        );
        sub.assert_eq(err, 0, "smartnic_attach_hardware_tls succeeded");
        sub.assert_true(sess.ktls_active, "kTLS active");
        sub.assert_eq(sess.fd, 100, "Target fd retained");
    };
}

fn main() {
    var runner = core::new_runner("Layer 4 Transport Driver Architecture Suite", core::Verbosity.Verbose);
    core::run_case(runner, "1. Transport Driver Probing", test_driver_probing);
    core::run_case(runner, "2. Driver Fallback and Auto-Selection", test_driver_fallback_and_selection);
    core::run_case(runner, "3. Windows RIO Buffer Lifecycle", test_rio_buffer_lifecycle);
    core::run_case(runner, "4. io_uring SQE/CQE Batch Submissions", test_uring_sqe_cqe_batch);
    core::run_case(runner, "5. macOS kqueue Event Lifecycle", test_kqueue_event_lifecycle);
    core::run_case(runner, "6. Driver Summary Formatter", test_driver_summary_formatter);
    core::run_case(runner, "7. AF_XDP & DPDK Kernel-Bypass Architecture", test_af_xdp_and_dpdk_kernel_bypass);
    core::run_case(runner, "8. SmartNIC & Hardware kTLS Crypto Offload", test_smartnic_ktls_offload);
    let ok = core::finish(runner);
    assert(ok);
}
