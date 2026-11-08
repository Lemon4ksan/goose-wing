// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Verification of Virtual Duplex Transport (Transport.Virtual),
// Tunnel-in-Tunnel TLS 1.3 over virtual pipe descriptors (VIRTUAL_FD_TAG),
// and generic UFCS <Io> stream adapters.
// RUN: goose %s | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

struct CustomVsockTransport {
    loopback: core::RingBuffer = core::RingBuffer { .. },
    closed:   bool             = false,
}

fn wing::send(v: CustomVsockTransport&, data: const u8[:]) -> i32 {
    guard !v.closed && data.len > 0 else { return -1; }
    let n, _ = core::write(v.loopback, data);
    return (n & 0x7FFFFFFF) as i32;
}

fn wing::recv_slice(v: CustomVsockTransport&, dst: u8[:], timeout_ms: u32 = 5000) -> i32 {
    guard !v.closed && dst.len > 0 else { return 0; }
    let n, _ = core::read(v.loopback, dst);
    return (n & 0x7FFFFFFF) as i32;
}

fn wing::close(v: CustomVsockTransport&) {
    core::clear(v.loopback);
    v.closed = true;
}

fn test_virtual_pipe_pair_and_scoped_helper() {
    var end_a, end_b, ok_open = wing::open_virtual_pipe_pair();
    assert(ok_open);
    assert(wing::is_connected(end_a));
    assert(wing::is_connected(end_b));

    let msg_a = "PING_OVER_VIRTUAL_PIPE_A_TO_B";
    let sent_a = end_a.send(msg_a);
    assert(sent_a == (msg_a.len as i32));

    var rx_b: u8[64] = [0; 64];
    let recvd_b = end_b.recv_slice(rx_b[..]);
    assert(recvd_b == (msg_a.len as i32));
    assert(rx_b[..recvd_b as i64] == msg_a);

    let msg_b = "PONG_OVER_VIRTUAL_PIPE_B_TO_A";
    let sent_b = end_b.send(msg_b);
    assert(sent_b == (msg_b.len as i32));

    var rx_a: u8[64] = [0; 64];
    let recvd_a = end_a.recv_slice(rx_a[..]);
    assert(recvd_a == (msg_b.len as i32));
    assert(rx_a[..recvd_a as i64] == msg_b);

    end_a.close();
    end_b.close();
    assert(!wing::is_connected(end_a));
    assert(!wing::is_connected(end_b));

    let ok_scoped = wing::with_virtual_pipe_pair() { pipe_a, pipe_b =>
        let s1 = wing::stream_send(pipe_a, "SCOPED_FRAME");
        assert(s1 == 12);
        var buf: u8[32] = [0; 32];
        let r1 = wing::stream_recv(pipe_b, buf[..]);
        assert(r1 == 12);
        assert(buf[..12] == "SCOPED_FRAME");
        wing::stream_close(pipe_a);
        wing::stream_close(pipe_b);
    };
    assert(ok_scoped);
    print("VIRTUAL_PIPE_DUPLEX: OK");
}

fn test_tls13_over_virtual_pipe_fd() {
    let vslot, ok_slot = wing::alloc_virtual_pipe_slot();
    assert(ok_slot);

    let fd_client = wing::virtual_pipe_to_fd(vslot, false);
    let fd_server = wing::virtual_pipe_to_fd(vslot, true);
    assert(wing::is_virtual_pipe_fd(fd_client));
    assert(wing::is_virtual_pipe_fd(fd_server));

    let dec_slot, dec_b, ok_dec = wing::decode_virtual_pipe_fd(fd_server);
    assert(ok_dec);
    assert(dec_slot == vslot);
    assert(dec_b);

    let c_slot = wing::alloc_tls_cipher_slot();
    let s_slot = wing::alloc_tls_cipher_slot();
    assert(c_slot != 0xFFFF && s_slot != 0xFFFF);

    let c_idx = c_slot as i64;
    let s_idx = s_slot as i64;
    wing::g_tls_cipher_slots[c_idx].cipher_suite = rfc::TLS_CIPHER_AES_128_GCM_SHA256;
    wing::g_tls_cipher_slots[c_idx].key_len = 16;
    wing::g_tls_cipher_slots[s_idx].cipher_suite = rfc::TLS_CIPHER_AES_128_GCM_SHA256;
    wing::g_tls_cipher_slots[s_idx].key_len = 16;
    wing::g_tls_cipher_slots[s_idx].is_server = true;

    for i in 16 {
        wing::g_tls_cipher_slots[c_idx].tx_key[i] = (0x10 + i) as u8;
        wing::g_tls_cipher_slots[s_idx].rx_key[i] = (0x10 + i) as u8;
        wing::g_tls_cipher_slots[s_idx].tx_key[i] = (0x30 + i) as u8;
        wing::g_tls_cipher_slots[c_idx].rx_key[i] = (0x30 + i) as u8;
    }
    for i in 12 {
        wing::g_tls_cipher_slots[c_idx].tx_iv[i] = (0xA0 + i) as u8;
        wing::g_tls_cipher_slots[s_idx].rx_iv[i] = (0xA0 + i) as u8;
        wing::g_tls_cipher_slots[s_idx].tx_iv[i] = (0xB0 + i) as u8;
        wing::g_tls_cipher_slots[c_idx].rx_iv[i] = (0xB0 + i) as u8;
    }

    var tls_client = wing::Transport.Tls {
        fd:            fd_client,
        record_seq_rx: 0,
        record_seq_tx: 0,
        cipher_slot:   c_slot,
    };
    var tls_server = wing::Transport.Tls {
        fd:            fd_server,
        record_seq_rx: 0,
        record_seq_tx: 0,
        cipher_slot:   s_slot,
    };

    let req_plain = "GET /tunnel-in-tunnel HTTP/1.1\r\nHost: inner.example\r\n\r\n";
    let n_sent = tls_client.send(req_plain);
    assert(n_sent == (req_plain.len as i32));

    var srv_rx: u8[128] = [0; 128];
    let n_recvd = tls_server.recv_slice(srv_rx[..]);
    assert(n_recvd == (req_plain.len as i32));
    assert(srv_rx[..n_recvd as i64] == req_plain);

    let resp_plain = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
    let n_resp_sent = tls_server.send(resp_plain);
    assert(n_resp_sent == (resp_plain.len as i32));

    var cli_rx: u8[128] = [0; 128];
    let n_resp_recvd = tls_client.recv_slice(cli_rx[..]);
    assert(n_resp_recvd == (resp_plain.len as i32));
    assert(cli_rx[..n_resp_recvd as i64] == resp_plain);

    tls_client.close();
    let eof_after_alert = tls_server.recv_slice(srv_rx[..]);
    assert(eof_after_alert == 0);
    tls_server.close();
    print("TLS13_TUNNEL_IN_TUNNEL: OK");
}

fn test_custom_ufcs_stream_adapter() {
    var vsock = CustomVsockTransport { .. };
    let payload = "CUSTOM_AF_VSOCK_STREAM_FRAME";
    let n_w = wing::stream_send(vsock, payload);
    assert(n_w == (payload.len as i32));

    var out: u8[64] = [0; 64];
    let n_r = wing::stream_recv(vsock, out[..], 1000);
    assert(n_r == (payload.len as i32));
    assert(out[..n_r as i64] == payload);

    wing::stream_close(vsock);
    assert(vsock.closed);
    assert(wing::stream_recv(vsock, out[..], 1000) == 0);
    print("UFCS_CUSTOM_STREAM: OK");
}

// CHECK: VIRTUAL_PIPE_DUPLEX: OK
// CHECK: TLS13_TUNNEL_IN_TUNNEL: OK
// CHECK: UFCS_CUSTOM_STREAM: OK
fn main() {
    test_virtual_pipe_pair_and_scoped_helper();
    test_tls13_over_virtual_pipe_fd();
    test_custom_ufcs_stream_adapter();
}
