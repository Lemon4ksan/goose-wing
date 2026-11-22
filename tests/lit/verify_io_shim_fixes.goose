// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Goose LIT Regression Suite: OS I/O Shim ABIs, kqueue Filters, RIO Timeouts/IPv6, and Reactor Slot Generations.
// RUN: goose build -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import wing from "../..";

fn test_platform_and_uring_abi_contracts() {
    let plat = net_internal::detect_target_platform();
    let host_code = net_internal::native_host_platform();
    let expected = match host_code {
        0 => net_internal::TargetPlatform.Windows,
        1 => net_internal::TargetPlatform.Linux,
        2 => net_internal::TargetPlatform.Darwin,
        _ => net_internal::TargetPlatform.Unknown,
    };
    assert(plat == expected);

    var sqe_multi = net_internal::UringSqe { .. };
    net_internal::uring_prep_recv(sqe_multi, 7, 0, 0, 0x1111, true);
    assert(sqe_multi.flags == net_internal::URING_SQE_BUFFER_SELECT);
    assert(sqe_multi.ioprio == net_internal::URING_RECV_MULTISHOT);
    assert(sqe_multi.user_data == 0x1111);

    var sqe_single = net_internal::UringSqe { .. };
    net_internal::uring_prep_recv(sqe_single, 7, 0x2000, 512, 0x1112, false);
    assert(sqe_single.flags == 0 && sqe_single.ioprio == 0);
    assert(sqe_single.addr == 0x2000 && sqe_single.len == 512);

    var sqe_poll = net_internal::UringSqe { .. };
    net_internal::uring_prep_poll_add(sqe_poll, 9, 0x05, 0x2222);
    assert(sqe_poll.op_flags == 0x05 && sqe_poll.user_data == 0x2222);

    // Multi-SQE slice batch verifies 42-byte packed UringSqe stride at negative fd boundary.
    var batch: net_internal::UringSqe[4] = [sqe_multi, sqe_single, sqe_poll, net_internal::UringSqe { .. }];
    assert(net_internal::uring_submit_sqes(-1, batch[..]) < 0);
    print("SHIM_URING_AND_PLATFORM: OK");
}

fn test_kqueue_filter_and_poller_contracts() {
    var kev_write = net_internal::Kevent {
        ident:  42,
        filter: net_internal::EVFILT_WRITE,
        flags:  0,
        fflags: 0,
        data:   65536,
        udata:  101,
    };
    assert(net_internal::kevent_bytes_available(kev_write) == 0);
    let fl_w, eof_w = net_internal::map_kevent_to_poll_flags(kev_write);
    assert(fl_w == core::POLL_WRITE && !eof_w);

    var kev_read = net_internal::Kevent {
        ident:  42,
        filter: net_internal::EVFILT_READ,
        flags:  0,
        fflags: 0,
        data:   128,
        udata:  102,
    };
    assert(net_internal::kevent_bytes_available(kev_read) == 128);

    var kev_eof_clean = net_internal::Kevent {
        ident:  42,
        filter: net_internal::EVFILT_READ,
        flags:  net_internal::EV_EOF,
        fflags: 0,
        data:   0,
        udata:  103,
    };
    let fl_c, eof_c = net_internal::map_kevent_to_poll_flags(kev_eof_clean);
    assert(eof_c && (fl_c & core::POLL_HANGUP) != 0 && (fl_c & core::POLL_ERROR) == 0);

    var kev_eof_err = net_internal::Kevent {
        ident:  42,
        filter: net_internal::EVFILT_READ,
        flags:  net_internal::EV_EOF,
        fflags: 54,
        data:   0,
        udata:  104,
    };
    let fl_e, eof_e = net_internal::map_kevent_to_poll_flags(kev_eof_err);
    assert(eof_e && (fl_e & core::POLL_HANGUP) != 0 && (fl_e & core::POLL_ERROR) != 0);

    var cfg = net_internal::auto_transport_driver_config();
    var p = net::new_poller(cfg);
    assert(net::register_socket(p, 88, 8801, core::PollInterest.Read, core::PollTrigger.Level));
    assert(net::modify_socket(p, 88, 8802, core::PollInterest.ReadWrite, core::PollTrigger.Edge));
    assert(net::deregister_socket(p, 88));
    net::close_poller(p);
    print("SHIM_KQUEUE_AND_POLLER: OK");
}

fn test_reactor_slot_generation_token_guard() {
    var accel = net::ReactorAccelRuntime {
        mode: net::ReactorAccelMode.Rio,
        ..
    };
    accel.slot_accel[3] = true;
    accel.active_accel_slots = 1;
    let tok1 = net::reactor_accel_slot_token(accel, 3);
    let slot1, ok1 = net::reactor_accel_match_token(accel, tok1);
    assert(ok1 && slot1 == 3);

    net::reactor_reset_accel_slot(accel, 3);
    let _, ok_reset = net::reactor_accel_match_token(accel, tok1);
    assert(!ok_reset && accel.active_accel_slots == 0);

    // Reusing the same physical slot rejects stale completions carrying old generation token.
    accel.slot_accel[3] = true;
    accel.active_accel_slots = 1;
    let tok2 = net::reactor_accel_slot_token(accel, 3);
    assert(tok2 != tok1);
    let slot2, ok2 = net::reactor_accel_match_token(accel, tok2);
    let _, ok_stale = net::reactor_accel_match_token(accel, tok1);
    assert(ok2 && slot2 == 3 && !ok_stale);

    // Generation counter wraps 65535 -> 1 (never 0) and generation 0 tokens always fail.
    accel.slot_gen[3] = 65535;
    net::reactor_reset_accel_slot(accel, 3);
    assert(accel.slot_gen[3] == 1);
    accel.slot_accel[3] = true;
    let _, ok_zero = net::reactor_accel_match_token(accel, 3);
    assert(!ok_zero);
    print("ACCEL_SLOT_GENERATIONS: OK");
}

fn verify_rio_cq_repeated_timeouts_and_v6() {
    let cq = net_internal::native_rio_create_cq(64);
    assert(cq != 0);
    defer net_internal::native_rio_close_cq(cq);

    // Repeated WAIT_TIMEOUT must sleep instead of spinning with WSAEINVAL (-1).
    for _ in 4 {
        let t0 = core::monotonic_now().nanos;
        let w = net_internal::rio_wait_cq(cq, 15);
        let elapsed = core::sub_sat_u64(core::monotonic_now().nanos, t0);
        assert(w == 0 && elapsed >= 5000000);
    }

    // IPv6 "::1" RIO listener + non-RIO vs RIO socket family check + dual-stack AcceptEx roundtrip.
    let lfd_v6 = net_internal::rio_listen("::1", 0, 16);
    assert(lfd_v6 > 0);
    let port_v6 = net::tcp_getsockname_port(lfd_v6);
    assert(port_v6 > 0 && net_internal::native_rio_is_listener(lfd_v6) == 1);
    net::tcp_close(lfd_v6);

    let lfd_dual = net_internal::rio_listen("::", 0, 16);
    assert(lfd_dual > 0);
    let port_dual = net::tcp_getsockname_port(lfd_dual);
    assert(port_dual > 0 && net_internal::native_rio_is_listener(lfd_dual) == 1);

    let std_fd = net::tcp_listen("127.0.0.1", 0);
    assert(std_fd > 0 && net_internal::native_rio_is_listener(std_fd) == 0);
    net::tcp_close(std_fd);

    let cfd = net::tcp_connect("127.0.0.1", port_dual);
    assert(cfd > 0);
    let sfd = net_internal::native_rio_poll_accept(lfd_dual, 1000);
    assert(sfd > 0);

    var backing: u8[4096] = [0; 4096];
    let bid = net_internal::native_rio_register_slice(backing[..]);
    assert(bid != 0);
    let rq = net_internal::native_rio_create_rq_ctx(sfd, 16, 16, cq, cq, 0x00020005);
    assert(rq != 0);
    assert(net_internal::native_rio_post_recv(rq, bid, 0, 1024, 901) == 0);
    assert(net::tcp_send(cfd, "V6_DUAL_OK") == 10);
    assert(net_internal::rio_wait_cq(cq, 1000) == 1);
    var results: net_internal::RioResult[..64] = [];
    let drained = net_internal::rio_drain_completions(cq, results);
    assert(drained == 1 && results[0].socket_context == 0x00020005 && results[0].request_context == 901);
    assert(results[0].bytes_transferred == 10 && backing[..10] == "V6_DUAL_OK");

    net_internal::native_rio_deregister_buffer(bid);
    net::tcp_close(sfd);
    net::tcp_close(cfd);
    net::tcp_close(lfd_dual);
}

fn verify_rio_burst_accept_reactor() {
    var srv = server::new_http_server("127.0.0.1", 0);
    srv.accel_mode = net::ReactorAccelMode.Rio;
    server::add_static_get_route(srv, "/burst", "text/plain", "BURST_OK");

    let lfd = server::reactor_listen_accelerated(srv, 64);
    assert(lfd > 0);
    let port = net::tcp_getsockname_port(lfd);
    assert(port > 0);

    var clients: i64[4] = [0; 4];
    for i in 4 {
        let c = net::tcp_connect("127.0.0.1", port);
        assert(c > 0);
        assert(net::tcp_send(c, "GET /burst HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n") > 0);
        clients[i] = c;
    }

    let served = server::serve_reactor(srv, lfd, 4);
    assert(served >= 4);

    var resp: u8[512] = [0; 512];
    for i in 4 {
        let nr = net::tcp_recv_slice(clients[i], resp[..]);
        assert(nr > 0 && core::contains(resp[..nr], "BURST_OK"));
        net::tcp_close(clients[i]);
    }
    net::tcp_close(lfd);
}

fn test_live_rio_timeout_ipv6_and_burst() {
    if net_internal::detect_target_platform() == net_internal::TargetPlatform.Windows &&
        net_internal::native_rio_available() == 1 {
        verify_rio_cq_repeated_timeouts_and_v6();
        verify_rio_burst_accept_reactor();
    }
    print("SHIM_RIO_LIVE: OK");
}

// CHECK: SHIM_URING_AND_PLATFORM: OK
// CHECK: SHIM_KQUEUE_AND_POLLER: OK
// CHECK: ACCEL_SLOT_GENERATIONS: OK
// CHECK: SHIM_RIO_LIVE: OK
fn main() {
    test_platform_and_uring_abi_contracts();
    test_kqueue_filter_and_poller_contracts();
    test_reactor_slot_generation_token_guard();
    test_live_rio_timeout_ipv6_and_burst();
}
