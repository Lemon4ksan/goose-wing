// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RUN: goose %s | %FileCheck %s
import std;

struct VirtualSocket {
    id: i32 = 0,
    port: i32 = 0,
    is_open: bool = false,
    is_listening: bool = false,
    peer_id: i32 = 0,
    buffer: u8[..256] = [],
}

struct SocketSubsystem {
    sockets: VirtualSocket[8] = [
        VirtualSocket {}, VirtualSocket {}, VirtualSocket {}, VirtualSocket {},
        VirtualSocket {}, VirtualSocket {}, VirtualSocket {}, VirtualSocket {},
    ],
    next_id: i32 = 1,
}

fn tcp_listen(sub: SocketSubsystem&, port: i32) -> i32 {
    let id = sub.next_id;
    sub.next_id += 1;
    sub.sockets[id].id = id;
    sub.sockets[id].port = port;
    sub.sockets[id].is_open = true;
    sub.sockets[id].is_listening = true;
    return id;
}

fn tcp_connect(sub: SocketSubsystem&, port: i32) -> i32 {
    let cli_id = sub.next_id;
    sub.next_id += 1;
    sub.sockets[cli_id].id = cli_id;
    sub.sockets[cli_id].port = port;
    sub.sockets[cli_id].is_open = true;
    return cli_id;
}

fn tcp_accept(sub: SocketSubsystem&, lis_id: i32) -> i32 {
    assert(sub.sockets[lis_id].is_listening);
    let srv_id = sub.next_id;
    sub.next_id += 1;
    sub.sockets[srv_id].id = srv_id;
    sub.sockets[srv_id].port = sub.sockets[lis_id].port;
    sub.sockets[srv_id].is_open = true;
    return srv_id;
}

fn tcp_send(sub: SocketSubsystem&, sock_id: i32, data: const u8[:]) -> i32 {
    assert(sub.sockets[sock_id].is_open);
    for b in data {
        sub.sockets[sock_id].buffer.push(b);
    }
    return data.len as! i32;
}

fn tcp_recv(sub: SocketSubsystem&, sock_id: i32, out: u8[:]) -> i32 {
    assert(sub.sockets[sock_id].is_open);
    let n = if out.len < sub.sockets[sock_id].buffer.len { out.len } else { sub.sockets[sock_id].buffer.len };
    for i in n {
        out[i] = sub.sockets[sock_id].buffer[i];
    }
    return n as! i32;
}

fn tcp_close(sub: SocketSubsystem&, sock_id: i32) {
    sub.sockets[sock_id].is_open = false;
}

fn main() {
    var sub = SocketSubsystem {};
    let lis = tcp_listen(sub, 9001);
    assert(lis > 0);
    print("LIS_SOCKET: ", lis);

    let cli = tcp_connect(sub, 9001);
    assert(cli > 0);
    print("CLI_SOCKET: ", cli);

    let srv = tcp_accept(sub, lis);
    assert(srv > 0);
    print("SRV_SOCKET: ", srv);

    let sent = tcp_send(sub, cli, "PING-PONG-TEST");
    assert(sent == 14);

    var rcv_buf: u8[14] = [0; 14];
    let rcvd = tcp_recv(sub, cli, rcv_buf[..]);
    assert(rcvd == 14);
    assert(rcv_buf[0] == 80 && rcv_buf[1] == 73 && rcv_buf[2] == 78 && rcv_buf[3] == 71); // "PING"
    assert(rcv_buf[13] == 84); // "T"
    print("RECV_CLIENT: ", rcvd, " BYTES");

    let reply_sent = tcp_send(sub, srv, "PONG-REPLY-OK!");
    assert(reply_sent == 14);

    var reply_buf: u8[14] = [0; 14];
    let reply_rcvd = tcp_recv(sub, srv, reply_buf[..]);
    assert(reply_rcvd == 14);
    assert(reply_buf[0] == 80 && reply_buf[1] == 79 && reply_buf[2] == 78 && reply_buf[3] == 71); // "PONG"
    print("RECV_REPLY: ", reply_rcvd, " BYTES");

    tcp_close(sub, cli);
    tcp_close(sub, srv);
    tcp_close(sub, lis);
    print("L4_SOCKETS: ALL CLOSED OK");
}

// CHECK: LIS_SOCKET: 1
// CHECK: CLI_SOCKET: 2
// CHECK: SRV_SOCKET: 3
// CHECK: RECV_CLIENT: 14 BYTES
// CHECK: RECV_REPLY: 14 BYTES
// CHECK: L4_SOCKETS: ALL CLOSED OK
