// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan
// RUN: goose build -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

fn test_driver_slice_abis() {
    var empty_res: internal::RioResult[..64] = [];
    assert(internal::rio_drain_completions(0, empty_res) == 0);

    var sqe = internal::UringSqe { .. };
    internal::uring_prep_poll_add(sqe, 5, 1, 0xABCD);
    assert(sqe.opcode == internal::URING_OP_POLL_ADD && sqe.fd == 5 && sqe.op_flags == 1 && sqe.user_data == 0xABCD);
    internal::uring_prep_poll_remove(sqe, 0xABCD, 0xABCE);
    assert(sqe.opcode == internal::URING_OP_POLL_REMOVE && sqe.addr == 0xABCD && sqe.user_data == 0xABCE);
    internal::uring_prep_sqe_recv_multishot(sqe, 7, 3, 0x9999);
    assert(sqe.opcode == internal::URING_OP_RECV && sqe.buf_index == 3 && sqe.ioprio == internal::URING_RECV_MULTISHOT);
    internal::uring_prep_recvmsg(sqe, 8, 0x1000, 2, 0x8888);
    assert(sqe.opcode == internal::URING_OP_RECVMSG && sqe.fd == 8 && sqe.op_flags == 2);

    var sqe_batch: internal::UringSqe[1] = [sqe];
    var cqe_batch: internal::UringCqe[4] = [internal::UringCqe { .. }; 4];
    assert(internal::uring_submit_sqes(-1, sqe_batch[..]) < 0);
    assert(internal::uring_wait_cqes(-1, cqe_batch[..], 1, 0) < 0);
    let bad_pb, ok_pb = internal::uring_alloc_pbuf_ring(-1, 1, 16, 4096);
    assert(!ok_pb && bad_pb == 0);
    var dummy_dst: u8[16] = [0; 16];
    assert(internal::uring_read_pbuf(0, 0, 8, dummy_dst[..]) < 0);
    internal::uring_recycle_pbuf(0, 0);
    internal::uring_free_pbuf_ring(0);

    var kev_in:  internal::Kevent[1] = [internal::Kevent { .. }];
    var kev_out: internal::Kevent[4] = [internal::Kevent { .. }; 4];
    let kq_rc = internal::kqueue_poll_slice(-1, kev_in[..], kev_out[..], 0);
    assert(kq_rc < 0);

    if internal::detect_target_platform() == internal::TargetPlatform.Windows &&
        internal::native_rio_available() == 1 {
        let lfd = internal::rio_listen("127.0.0.1", 0, 16);
        assert(lfd > 0);
        let port = wing::tcp_getsockname_port(lfd);
        assert(port > 0);
        let cfd = wing::tcp_connect("127.0.0.1", port);
        assert(cfd > 0);
        let sfd = internal::rio_accept(lfd);
        assert(sfd > 0);
        let cq = internal::native_rio_create_cq(64);
        assert(cq != 0);
        let rq = internal::native_rio_create_rq_ctx(sfd, 16, 16, cq, cq, 777);
        assert(rq != 0);
        var backing: u8[4096] = [0; 4096];
        let buf_id = internal::native_rio_register_slice(backing[..]);
        assert(buf_id != 0);
        assert(internal::native_rio_post_recv(rq, buf_id, 0, 1024, 888) == 0);
        assert(wing::tcp_send(cfd, "PING") == 4);
        assert(internal::rio_wait_cq(cq, 1000) >= 0);
        let drained = internal::rio_drain_completions(cq, empty_res);
        assert(drained == 1 && empty_res[0].bytes_transferred == 4);
        assert(empty_res[0].socket_context == 777 && empty_res[0].request_context == 888);
        assert(backing[..4] == "PING");

        backing[2048] = 'P';
        backing[2049] = 'O';
        backing[2050] = 'N';
        backing[2051] = 'G';
        assert(internal::native_rio_post_send(rq, buf_id, 2048, 4, 889) == 0);
        assert(internal::rio_wait_cq(cq, 1000) >= 0);
        let drained_tx = internal::rio_drain_completions(cq, empty_res);
        assert(drained_tx == 1 && empty_res[0].request_context == 889);
        var pong_rx: u8[8] = [0; 8];
        assert(wing::tcp_recv_slice(cfd, pong_rx[..]) == 4 && pong_rx[..4] == "PONG");

        internal::native_rio_deregister_buffer(buf_id);
        internal::native_rio_close_cq(cq);
        wing::tcp_close(sfd);
        wing::tcp_close(cfd);
        wing::tcp_close(lfd);
    }
    print("TASK1_DRIVER_ABIS: OK");
}

fn test_tls_slice_codecs_and_ktls_probe() {
    assert(internal::smartnic_model_name(internal::SmartNicModel.LinuxKtls).len > 0);
    let _ = internal::smartnic_probe_ktls();
    var dummy_rx: u8[16] = [0; 16];
    let bad_rx, bad_rt = internal::smartnic_recv_record(-1, dummy_rx[..]);
    assert(bad_rx < 0 && bad_rt == 0);
    assert(internal::smartnic_send_record(-1, "PING", rfc::TLS_CONTENT_APPLICATION_DATA) < 0);

    let slot_s = wing::alloc_tls_cipher_slot();
    let slot_c = wing::alloc_tls_cipher_slot();
    assert(slot_s != 0xFFFF && slot_c != 0xFFFF);
    let key: u8[16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let iv:  u8[12] = [9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 1, 2];
    wing::tls_init_cipher_slot_for_test(
        slot_s, rfc::TLS_CIPHER_AES_128_GCM_SHA256, key[..], iv, key[..], iv,
    );
    wing::tls_init_cipher_slot_for_test(
        slot_c, rfc::TLS_CIPHER_AES_128_GCM_SHA256, key[..], iv, key[..], iv,
    );

    // 1. App data roundtrip in memory
    var wire_buf: u8[..2048] = [];
    assert(wing::tls_cipher_slot_seal_app_data(slot_c, "GET / HTTP/1.1\r\n\r\n", wire_buf));
    var plain_out: u8[..2048] = [];
    let cons1, st1 = wing::tls_cipher_slot_unseal_records(slot_s, wire_buf[..10], plain_out);
    assert(cons1 == 0 && st1 == wing::TlsSliceUnsealStatus.NeedMore && plain_out.len == 0);
    let cons2, st2 = wing::tls_cipher_slot_unseal_records(slot_s, wire_buf[..], plain_out);
    assert(cons2 == wire_buf.len && st2 == wing::TlsSliceUnsealStatus.Ok);
    assert(plain_out[..] == "GET / HTTP/1.1\r\n\r\n");

    // 2. Review Focus #4: Post-handshake NewSessionTicket (0x04 inside 0x16) skipped, close_notify (0x15) closes
    var nst_msg: u8[8]  = [4, 0, 0, 4, 0, 0, 0, 1];
    var nst_rec: u8[64] = [0; 64];
    let nst_len, _, ok_nst = wing::tls_record_seal_into(
        rfc::TLS_CIPHER_AES_128_GCM_SHA256, key[..], iv, 1, rfc::TLS_CONTENT_HANDSHAKE, nst_msg[..], nst_rec[..],
    );
    assert(ok_nst);
    plain_out.clear();
    let cons_nst, st_nst = wing::tls_cipher_slot_unseal_records(slot_s, nst_rec[..nst_len], plain_out);
    assert(cons_nst == nst_len && st_nst == wing::TlsSliceUnsealStatus.ControlHandled && plain_out.len == 0);

    var alert_msg: u8[2]  = [1, 0];
    var alert_rec: u8[64] = [0; 64];
    let al_len, _, ok_al = wing::tls_record_seal_into(
        rfc::TLS_CIPHER_AES_128_GCM_SHA256, key[..], iv, 2, rfc::TLS_CONTENT_ALERT, alert_msg[..], alert_rec[..],
    );
    assert(ok_al);
    let cons_al, st_al = wing::tls_cipher_slot_unseal_records(slot_s, alert_rec[..al_len], plain_out);
    assert(cons_al == al_len && st_al == wing::TlsSliceUnsealStatus.Closed);

    let _, ktls_bad = wing::tls_try_enable_ktls(slot_s, -1);
    assert(!ktls_bad);

    wing::free_tls_cipher_slot(slot_s);
    wing::free_tls_cipher_slot(slot_c);
    print("TASK2_TLS_SLICE_AND_KTLS: OK");
}

fn test_poller_live_socket_and_synthetic_fds() {
    let cfg = internal::auto_transport_driver_config();
    var p = wing::new_poller(cfg);

    // Review Focus #2: synthetic FD 77 coexists with live sockets without POLLNVAL/EBADF failure
    assert(wing::register_socket(p, 77, 7700, core::PollInterest.Read, core::PollTrigger.Edge));
    assert(wing::simulate_read_ready(p, 77, 128));
    var evs: core::PollReadyEvent[..64] = [];
    let n_sim = wing::poll_events(p, 0, 1000, evs);
    assert(n_sim == 1 && evs[0].tag == 7700 && (evs[0].events & core::POLL_READ) != 0);

    // Real loopback TCP readiness through Poller without manual enable_os_multiplexing
    let lfd = wing::tcp_listen("127.0.0.1", 0);
    assert(lfd > 0);
    let port = wing::tcp_getsockname_port(lfd);
    let cfd = wing::tcp_connect("127.0.0.1", port);
    let sfd = wing::tcp_accept(lfd);
    assert(cfd > 0 && sfd > 0);
    let _ = wing::tcp_set_nonblocking(sfd, true);

    assert(wing::register_socket(p, sfd as i32, 9001, core::PollInterest.Read, core::PollTrigger.Level));
    assert(wing::tcp_send(cfd, "HELLO_POLLER") == 12);
    evs.clear();
    let n_live = wing::poll_events(p, 500, 2000, evs);
    assert(n_live == 1 && evs[0].tag == 9001 && (evs[0].events & core::POLL_READ) != 0);

    var rx: u8[32] = [0; 32];
    let nr = wing::tcp_recv_slice(sfd, rx[..]);
    assert(nr == 12 && rx[..12] == "HELLO_POLLER");

    // WireQueue batch submission with attached Poller readiness tag
    var wq = wire::WireQueue { fd: cfd, is_connected: true, .. };
    wire::queue_attach_poller(wq, 9002);
    var cb1 = wire::WireCommandBuffer { state: wire::WireCommandBufferState.Executable, .. };
    var cb2 = wire::WireCommandBuffer { state: wire::WireCommandBufferState.Executable, .. };
    assert(cb1.buf.try_append("BATCH_"));
    assert(cb2.buf.try_append("OK"));
    let cbs: wire::WireCommandBuffer[2] = [cb1, cb2];
    let s_info = wire::WireSubmitInfo { .. };
    var fence = wire::WireFence { is_valid: true, status: wire::WireFenceStatus.Unsignaled, .. };
    let b_sent, b_res = wire::queue_submit_batch(wq, cbs[..], s_info, fence);
    assert(b_res == wire::WireResult.Success && b_sent == 8);
    let nr2 = wing::tcp_recv_slice(sfd, rx[..]);
    assert(nr2 == 8 && rx[..8] == "BATCH_OK");

    assert(wing::deregister_socket(p, 77));
    assert(wing::deregister_socket(p, sfd as i32));
    wing::tcp_close(sfd);
    wing::tcp_close(cfd);
    wing::tcp_close(lfd);
    wing::close_poller(p);
    print("TASK3_POLLER_LIVE: OK");
}

// CHECK: TASK1_DRIVER_ABIS: OK
// CHECK: TASK2_TLS_SLICE_AND_KTLS: OK
// CHECK: TASK3_POLLER_LIVE: OK
fn main() {
    test_driver_slice_abis();
    test_tls_slice_codecs_and_ktls_probe();
    test_poller_live_socket_and_synthetic_fds();
}
