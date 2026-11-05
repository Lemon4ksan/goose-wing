// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

enum SocketState {
    Closed,
    Listening,
    Connected,
}

struct L4Socket {
    id:      i32              = 0,
    port:    u16              = 0,
    state:   SocketState      = SocketState.Closed,
    peer_id: i32              = 0,
    rx_ring: core::RingBuffer = core::RingBuffer { .. },
}

struct L4Subsystem {
    sockets: L4Socket[8] = [
        L4Socket {}, L4Socket {}, L4Socket {}, L4Socket {},
        L4Socket {}, L4Socket {}, L4Socket {}, L4Socket {},
    ],
    next_id: i32 = 1,
}

fn tcp_listen(sub: L4Subsystem&, port: u16) -> i32 {
    let id = sub.next_id;
    sub.next_id += 1;
    sub.sockets[id].id = id;
    sub.sockets[id].port = port;
    sub.sockets[id].state = SocketState.Listening;
    return id;
}

fn tcp_connect(sub: L4Subsystem&, port: u16) -> i32 {
    let cli_id = sub.next_id;
    sub.next_id += 1;
    sub.sockets[cli_id].id = cli_id;
    sub.sockets[cli_id].port = port;
    sub.sockets[cli_id].state = SocketState.Connected;
    return cli_id;
}

fn tcp_accept(sub: L4Subsystem&, lis_id: i32) -> i32 {
    assert(sub.sockets[lis_id].state == SocketState.Listening);
    let srv_id = sub.next_id;
    sub.next_id += 1;
    sub.sockets[srv_id].id = srv_id;
    sub.sockets[srv_id].port = sub.sockets[lis_id].port;
    sub.sockets[srv_id].state = SocketState.Connected;
    return srv_id;
}

fn tcp_send(sub: L4Subsystem&, sock_id: i32, data: const u8[:]) -> i32 {
    assert(sub.sockets[sock_id].state == SocketState.Connected);
    let n, err = core::write(sub.sockets[sock_id].rx_ring, data);
    assert(err == core::IoError.None);
    return n as! i32;
}

fn tcp_recv(sub: L4Subsystem&, sock_id: i32, out: u8[:]) -> i32 {
    assert(sub.sockets[sock_id].state == SocketState.Connected);
    let n, err = core::read(sub.sockets[sock_id].rx_ring, out);
    assert(err == core::IoError.None || err == core::IoError.Eof);
    return n as! i32;
}

fn tcp_close(sub: L4Subsystem&, sock_id: i32) {
    sub.sockets[sock_id].state = SocketState.Closed;
    core::clear(sub.sockets[sock_id].rx_ring);
}

fn test_proxy_protocol_wire_ingress() {
    // PROXY v1 text ingress
    let v1_wire = "PROXY TCP4 203.0.113.195 198.51.100.1 56324 443\r\nPING-PONG-TEST";
    var v1_hdr = wing::ProxyHeader { .. };
    let app_stream, ok1 = wing::detect_and_strip_proxy_header(v1_wire, v1_hdr);
    assert(ok1);
    assert(v1_hdr.version == wing::ProxyProtocolVersion.V1);
    assert(v1_hdr.family == wing::ProxyAddressFamily.Inet4);
    assert(v1_hdr.src_port == 56324);
    assert(v1_hdr.dst_port == 443);
    assert(app_stream == "PING-PONG-TEST");

    // PROXY v2 binary ingress
    var v2_hdr_orig = wing::ProxyHeader {
        version:   wing::ProxyProtocolVersion.V2,
        command:   wing::ProxyCommand.Proxy,
        family:    wing::ProxyAddressFamily.Inet4,
        transport: wing::ProxyTransportProtocol.Stream,
        src_ipv4:  [192, 168, 1, 50],
        dst_ipv4:  [10, 0, 0, 1],
        src_port:  8080,
        dst_port:  80,
    };
    var v2_wire: u8[..512] = [];
    assert(wing::format_proxy_v2(v2_hdr_orig, v2_wire));
    v2_wire.append("PONG-REPLY-OK!");

    var v2_hdr_parsed = wing::ProxyHeader { .. };
    let v2_app, ok2 = wing::detect_and_strip_proxy_header(v2_wire[..], v2_hdr_parsed);
    assert(ok2);
    assert(v2_hdr_parsed.version == wing::ProxyProtocolVersion.V2);
    assert(v2_hdr_parsed.src_port == 8080);
    assert(v2_hdr_parsed.dst_port == 80);
    assert(v2_app == "PONG-REPLY-OK!");
}

fn main() {
    test_proxy_protocol_wire_ingress();

    var sub = L4Subsystem {};
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
