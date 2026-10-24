// Verification suite for Layer 4 Transport Driver Architecture (net/driver.goose):
// - Platform probing across Windows, Linux, and macOS
// - Driver capability bitmasks (KernelBypass, ZeroCopy, RingCompletion, BatchIO)
// - Graceful auto-selection and fallback handling
// - Windows RIO page-locked zero-copy buffer lifecycle
// - Linux io_uring SQE/CQE batch submission and ring state tracking
// - Diagnostic summary string formatting
import std;
import core from "..";
import wing from "..";

fn test_driver_probing(t: core::T&) {
    t.run("Standard Driver Probing (Universal)") { sub =>
        let p_win = wing::probe_transport_driver_for_platform(wing::TransportDriverKind.Standard, wing::TargetPlatform.Windows);
        sub.assert_true(p_win.available, "Standard available on Windows");
        sub.assert_eq(p_win.error_code, 0, "Standard error code 0 on Windows");

        let p_linux = wing::probe_transport_driver_for_platform(wing::TransportDriverKind.Standard, wing::TargetPlatform.Linux);
        sub.assert_true(p_linux.available, "Standard available on Linux");
        sub.assert_eq(p_linux.error_code, 0, "Standard error code 0 on Linux");

        let p_mac = wing::probe_transport_driver_for_platform(wing::TransportDriverKind.Standard, wing::TargetPlatform.Darwin);
        sub.assert_true(p_mac.available, "Standard available on macOS");
        sub.assert_eq(p_mac.error_code, 0, "Standard error code 0 on macOS");
    };

    t.run("Windows RIO Probing") { sub =>
        let p_win = wing::probe_transport_driver_for_platform(wing::TransportDriverKind.WindowsRIO, wing::TargetPlatform.Windows);
        sub.assert_true(p_win.available, "RIO available on Windows");
        sub.assert_eq(p_win.error_code, 0, "RIO error code 0 on Windows");
        sub.assert_true(wing::driver_has_cap(p_win.capabilities, wing::CAP_KERNEL_BYPASS), "RIO has KernelBypass");
        sub.assert_true(wing::driver_has_cap(p_win.capabilities, wing::CAP_ZERO_COPY), "RIO has ZeroCopy");
        sub.assert_true(wing::driver_has_cap(p_win.capabilities, wing::CAP_PAGE_LOCKED_BUFFERS), "RIO has PageLockedBuffers");
        sub.assert_true(wing::driver_has_cap(p_win.capabilities, wing::CAP_BATCH_IO), "RIO has BatchIO");

        let p_linux = wing::probe_transport_driver_for_platform(wing::TransportDriverKind.WindowsRIO, wing::TargetPlatform.Linux);
        sub.assert_false(p_linux.available, "RIO unavailable on Linux");
        sub.assert_eq(p_linux.error_code, -38, "RIO returns -ENOSYS on Linux");

        let p_mac = wing::probe_transport_driver_for_platform(wing::TransportDriverKind.WindowsRIO, wing::TargetPlatform.Darwin);
        sub.assert_false(p_mac.available, "RIO unavailable on macOS");
        sub.assert_eq(p_mac.error_code, -38, "RIO returns -ENOSYS on macOS");
    };

    t.run("Linux io_uring Probing") { sub =>
        let p_linux = wing::probe_transport_driver_for_platform(wing::TransportDriverKind.IoUring, wing::TargetPlatform.Linux);
        sub.assert_true(p_linux.available, "io_uring available on Linux");
        sub.assert_eq(p_linux.error_code, 0, "io_uring error code 0 on Linux");
        sub.assert_true(wing::driver_has_cap(p_linux.capabilities, wing::CAP_RING_COMPLETION), "io_uring has RingCompletion");
        sub.assert_true(wing::driver_has_cap(p_linux.capabilities, wing::CAP_ZERO_COPY), "io_uring has ZeroCopy");
        sub.assert_true(wing::driver_has_cap(p_linux.capabilities, wing::CAP_BATCH_IO), "io_uring has BatchIO");
        sub.assert_true(wing::driver_has_cap(p_linux.capabilities, wing::CAP_DIRECT_DESCRIPTORS), "io_uring has DirectDescriptors");
        sub.assert_true(wing::driver_has_cap(p_linux.capabilities, wing::CAP_MULTISHOT_RECV), "io_uring has MultishotRecv");

        let p_win = wing::probe_transport_driver_for_platform(wing::TransportDriverKind.IoUring, wing::TargetPlatform.Windows);
        sub.assert_false(p_win.available, "io_uring unavailable on Windows");
        sub.assert_eq(p_win.error_code, -38, "io_uring returns -ENOSYS on Windows");

        let p_mac = wing::probe_transport_driver_for_platform(wing::TransportDriverKind.IoUring, wing::TargetPlatform.Darwin);
        sub.assert_false(p_mac.available, "io_uring unavailable on macOS");
        sub.assert_eq(p_mac.error_code, -38, "io_uring returns -ENOSYS on macOS");
    };
}

fn test_driver_fallback_and_selection(t: core::T&) {
    t.run("Standard Selection Everywhere") { sub =>
        var cfg = wing::TransportDriverConfig {
            preferred_kind: wing::TransportDriverKind.Standard,
            ..
        };
        sub.assert_true(wing::init_transport_driver_with_platform(cfg, wing::TargetPlatform.Windows), "Init ok on Windows");
        sub.assert_true(cfg.active_kind == wing::TransportDriverKind.Standard, "Active is Standard");
        sub.assert_true(cfg.is_probed, "Is probed");
    };

    t.run("Windows Auto-Selection: io_uring preferred with kernel bypass") { sub =>
        var cfg = wing::TransportDriverConfig {
            preferred_kind: wing::TransportDriverKind.IoUring,
            enable_kernel_bypass: true,
            ..
        };
        sub.assert_true(wing::init_transport_driver_with_platform(cfg, wing::TargetPlatform.Windows), "Init ok");
        sub.assert_true(cfg.active_kind == wing::TransportDriverKind.WindowsRIO, "Auto-selected WindowsRIO");
        sub.assert_true(wing::driver_has_cap(cfg.capabilities, wing::CAP_KERNEL_BYPASS), "Has KernelBypass");
    };

    t.run("Windows Graceful Fallback: io_uring preferred without bypass") { sub =>
        var cfg = wing::TransportDriverConfig {
            preferred_kind: wing::TransportDriverKind.IoUring,
            enable_kernel_bypass: false,
            ..
        };
        sub.assert_true(wing::init_transport_driver_with_platform(cfg, wing::TargetPlatform.Windows), "Init ok");
        sub.assert_true(cfg.active_kind == wing::TransportDriverKind.Standard, "Fell back to Standard");
    };

    t.run("Linux Auto-Selection: WindowsRIO preferred") { sub =>
        var cfg = wing::TransportDriverConfig {
            preferred_kind: wing::TransportDriverKind.WindowsRIO,
            ..
        };
        sub.assert_true(wing::init_transport_driver_with_platform(cfg, wing::TargetPlatform.Linux), "Init ok");
        sub.assert_true(cfg.active_kind == wing::TransportDriverKind.IoUring, "Auto-selected io_uring");
        sub.assert_true(wing::driver_has_cap(cfg.capabilities, wing::CAP_RING_COMPLETION), "Has RingCompletion");
    };

    t.run("macOS Fallback: io_uring or WindowsRIO preferred") { sub =>
        var cfg = wing::TransportDriverConfig {
            preferred_kind: wing::TransportDriverKind.IoUring,
            ..
        };
        sub.assert_true(wing::init_transport_driver_with_platform(cfg, wing::TargetPlatform.Darwin), "Init ok");
        sub.assert_true(cfg.active_kind == wing::TransportDriverKind.Standard, "Fell back to Standard");
    };
}

fn test_rio_buffer_lifecycle(t: core::T&) {
    t.run("RIO Buffer Registration and Slicing") { sub =>
        var buf = wing::new_rio_buffer(1001, 65536);
        sub.assert_eq(buf.buffer_id, 1001, "Buffer ID matches");
        sub.assert_eq(buf.offset, 0, "Initial offset is 0");
        sub.assert_eq(buf.length, 65536, "Length is 65536");
        sub.assert_true(buf.is_registered, "Buffer is registered");
        sub.assert_true(buf.page_locked, "Buffer is page-locked");

        sub.assert_true(wing::rio_can_zero_copy(buf, 1024), "Can zero-copy 1024B");
        sub.assert_true(wing::rio_can_zero_copy(buf, 65536), "Can zero-copy 65536B");
        sub.assert_false(wing::rio_can_zero_copy(buf, 70000), "Cannot zero-copy 70000B");

        // Sub-slice
        let sub_buf = wing::rio_sub_buffer(buf, 4096, 2048);
        sub.assert_eq(sub_buf.buffer_id, 1001, "Sub-slice keeps buffer ID");
        sub.assert_eq(sub_buf.offset, 4096, "Sub-slice offset is 4096");
        sub.assert_eq(sub_buf.length, 2048, "Sub-slice length is 2048");
        sub.assert_true(sub_buf.is_registered, "Sub-slice is registered");

        // Out of bounds sub-slice
        let oob_buf = wing::rio_sub_buffer(buf, 60000, 10000);
        sub.assert_false(oob_buf.is_registered, "OOB slice fails safely");

        // Deregister
        wing::rio_deregister_buffer(buf);
        sub.assert_false(buf.is_registered, "Buffer deregistered");
        sub.assert_false(buf.page_locked, "Page lock released");
        sub.assert_false(wing::rio_can_zero_copy(buf, 100), "Cannot zero-copy after deregister");
    };

    t.run("Physical Windows RIO Kernel Registration") { sub =>
        if wing::detect_target_platform() == wing::TargetPlatform.Windows {
            let avail = wing::native_rio_available();
            sub.assert_eq(avail, 1, "Native RIO is available in mswsock.dll");
            let probe = wing::native_rio_probe();
            sub.assert_eq(probe, 0, "Native RIO probe succeeds");
        }
    };
}

fn test_uring_sqe_cqe_batch(t: core::T&) {
    t.run("io_uring SQE Preparation") { sub =>
        var sqe_send = wing::UringSqe { .. };
        wing::uring_prep_send(sqe_send, 42, 0x1000, 2048, 999, true);
        sub.assert_eq(sqe_send.opcode, wing::URING_OP_SEND_ZC, "Send opcode is SEND_ZC");
        sub.assert_eq(sqe_send.fd, 42, "FD matches");
        sub.assert_eq(sqe_send.addr, 0x1000, "Addr matches");
        sub.assert_eq(sqe_send.len, 2048, "Len matches");
        sub.assert_eq(sqe_send.user_data, 999, "Tag matches");

        var sqe_recv = wing::UringSqe { .. };
        wing::uring_prep_recv(sqe_recv, 42, 0x2000, 4096, 1000, true);
        sub.assert_eq(sqe_recv.opcode, wing::URING_OP_RECV, "Recv opcode is RECV");
        sub.assert_eq(sqe_recv.flags, wing::URING_SQE_BUFFER_SELECT, "Multishot buffer select set");

        var sqe_accept = wing::UringSqe { .. };
        wing::uring_prep_accept(sqe_accept, 5, 1001);
        sub.assert_eq(sqe_accept.opcode, wing::URING_OP_ACCEPT, "Accept opcode matches");

        var sqe_cancel = wing::UringSqe { .. };
        wing::uring_prep_cancel(sqe_cancel, 999);
        sub.assert_eq(sqe_cancel.opcode, wing::URING_OP_ASYNC_CANCEL, "Cancel opcode matches");
        sub.assert_eq(sqe_cancel.addr, 999, "Tag to cancel stored in addr");
    };

    t.run("io_uring Batch Submission and CQE Reaping") { sub =>
        var state = wing::new_ring_queue_state(128);
        var sqes: wing::UringSqe[4] = [
            wing::UringSqe { opcode: wing::URING_OP_SEND, len: 512, user_data: 101, .. },
            wing::UringSqe { opcode: wing::URING_OP_SEND_ZC, len: 1024, user_data: 102, .. },
            wing::UringSqe { opcode: wing::URING_OP_RECV, flags: wing::URING_SQE_BUFFER_SELECT, len: 4096, user_data: 103, .. },
            wing::UringSqe { opcode: wing::URING_OP_NOP, len: 0, user_data: 104, .. },
        ];

        var cqes: wing::UringCqe[..32] = [];
        let submitted = wing::uring_submit_batch(state, sqes[..], cqes);
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
        sub.assert_true((cqes[2].flags & wing::URING_CQE_F_MORE) != 0, "Multishot CQE has F_MORE flag");
    };
}

fn test_driver_summary_formatter(t: core::T&) {
    t.run("Summary String Formatting") { sub =>
        var cfg_rio = wing::TransportDriverConfig {
            preferred_kind: wing::TransportDriverKind.WindowsRIO,
            ring_size: 2048,
            registered_buffer_size: 131072,
            ..
        };
        wing::init_transport_driver_with_platform(cfg_rio, wing::TargetPlatform.Windows);

        var summary_buf: u8[>..] = [];
        wing::format_driver_summary(cfg_rio, summary_buf);

        sub.assert_true(summary_buf.len > 0, "Summary buffer is not empty");
        sub.assert_contains(summary_buf[..], "Windows RIO", "Contains Windows RIO");
        sub.assert_contains(summary_buf[..], "KernelBypass", "Contains KernelBypass");
        sub.assert_contains(summary_buf[..], "ZeroCopy", "Contains ZeroCopy");
        sub.assert_contains(summary_buf[..], "2048", "Contains ring size 2048");
        sub.assert_contains(summary_buf[..], "131072B", "Contains buffer size 131072B");

        var cfg_std = wing::TransportDriverConfig {
            preferred_kind: wing::TransportDriverKind.Standard,
            ..
        };
        wing::init_transport_driver_with_platform(cfg_std, wing::TargetPlatform.Linux);
        summary_buf.clear();
        wing::format_driver_summary(cfg_std, summary_buf);
        sub.assert_contains(summary_buf[..], "Standard", "Contains Standard");
        sub.assert_contains(summary_buf[..], "None (Standard Stream)", "Contains None");
    };
}

fn main() {
    var runner = core::new_runner("Layer 4 Transport Driver Architecture Suite", core::Verbosity.Verbose);
    core::run_case(runner, "1. Transport Driver Probing", test_driver_probing);
    core::run_case(runner, "2. Driver Fallback and Auto-Selection", test_driver_fallback_and_selection);
    core::run_case(runner, "3. Windows RIO Buffer Lifecycle", test_rio_buffer_lifecycle);
    core::run_case(runner, "4. io_uring SQE/CQE Batch Submissions", test_uring_sqe_cqe_batch);
    core::run_case(runner, "5. Driver Summary Formatter", test_driver_summary_formatter);
    let ok = core::finish(runner);
    assert(ok);
}
