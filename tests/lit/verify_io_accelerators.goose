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

// CHECK: TASK1_DRIVER_ABIS: OK
fn main() {
    test_driver_slice_abis();
}
