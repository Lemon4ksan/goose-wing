// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RUN: goose %s | %FileCheck %s
// CHECK: DUALSTACK_UDP_V4_V6_OK
// CHECK: POLLER_UDP_TCP_MULTIPLEX_OK
import std;
import wing from "../..";

fn wait_udp_recv(
    p:             net::Poller&,
    sock_fd:       i64,
    out_buf:       u8[:],
    out_peer_ip:   u8[:],
    out_ip_len:    i32&,
    out_peer_port: u16&,
) -> i32 {
    var evs: core::PollReadyEvent[..64] = [];
    for _ in 10 {
        let nr = net::udp_recvfrom_dual(sock_fd, out_buf, out_peer_ip, out_ip_len, out_peer_port);
        if nr > 0 {
            return nr;
        }
        evs.clear();
        let _ = net::poll_events(p, 50, 1000, evs);
    }
    return -2;
}

fn test_dualstack_udp_v4_and_v6() {
    let srv = net::udp_open_dual("::", 0, 0);
    assert(srv > 0);
    let srv_port = net::tcp_getsockname_port(srv);
    assert(srv_port > 0);

    let c4 = net::udp_open_dual("127.0.0.1", 0, 0);
    let c6 = net::udp_open_dual("::1", 0, 0);
    assert(c4 > 0 && c6 > 0);
    let c4_port = net::tcp_getsockname_port(c4);
    let c6_port = net::tcp_getsockname_port(c6);
    assert(c4_port > 0 && c6_port > 0);

    // Explicit "::1" UDP socket must keep IPV6_V6ONLY=1 and not receive IPv4 traffic.
    let v6_only = net::udp_open_dual("::1", 0, 0);
    assert(v6_only > 0);
    let v6_port = net::tcp_getsockname_port(v6_only);
    assert(v6_port > 0);
    let _ = net::udp_sendto_dual(c4, "v4only", "127.0.0.1", v6_port);

    let cfg = net_internal::auto_transport_driver_config();
    var rx_poller = net::new_poller(cfg);
    assert(net::enable_os_multiplexing(rx_poller));
    assert(net::poller_register_fd(rx_poller, srv, core::POLL_READ, 11));
    assert(net::poller_register_fd(rx_poller, c4, core::POLL_READ, 12));
    assert(net::poller_register_fd(rx_poller, c6, core::POLL_READ, 13));

    var buf:       u8[64] = [0; 64];
    var peer_ip:   u8[64] = [0; 64];
    var ip_len:    i32    = 0;
    var peer_port: u16    = 0;

    // 1. IPv4 client -> dual-stack "::" server -> IPv4 reply
    assert(net::udp_sendto_dual(c4, "ping4", "127.0.0.1", srv_port) == 5);
    let r4 = wait_udp_recv(rx_poller, srv, buf[..], peer_ip[..], ip_len, peer_port);
    assert(r4 == 5 && buf[..5] == "ping4");
    assert(ip_len == 9 && peer_ip[..9] == "127.0.0.1");
    assert(peer_port == c4_port);

    assert(net::udp_sendto_dual(srv, "pong4", peer_ip[..ip_len], peer_port) == 5);
    let cr4 = wait_udp_recv(rx_poller, c4, buf[..], peer_ip[..], ip_len, peer_port);
    assert(cr4 == 5 && buf[..5] == "pong4");
    assert(ip_len == 9 && peer_ip[..9] == "127.0.0.1");
    assert(peer_port == srv_port);

    // 2. IPv6 client -> dual-stack "::" server -> IPv6 reply
    assert(net::udp_sendto_dual(c6, "ping6", "::1", srv_port) == 5);
    let r6 = wait_udp_recv(rx_poller, srv, buf[..], peer_ip[..], ip_len, peer_port);
    assert(r6 == 5 && buf[..5] == "ping6");
    assert(ip_len == 3 && peer_ip[..3] == "::1");
    assert(peer_port == c6_port);

    assert(net::udp_sendto_dual(srv, "pong6", "::1", peer_port) == 5);
    let cr6 = wait_udp_recv(rx_poller, c6, buf[..], peer_ip[..], ip_len, peer_port);
    assert(cr6 == 5 && buf[..5] == "pong6");
    assert(ip_len == 3 && peer_ip[..3] == "::1");
    assert(peer_port == srv_port);

    // Verify explicit "::1" did not receive the IPv4 datagram sent earlier.
    let v6_ignored = net::udp_recvfrom_dual(v6_only, buf[..], peer_ip[..], ip_len, peer_port);
    assert(v6_ignored == -2);

    assert(net::poller_deregister_fd(rx_poller, srv));
    assert(net::poller_deregister_fd(rx_poller, c4));
    assert(net::poller_deregister_fd(rx_poller, c6));
    net::close_poller(rx_poller);
    net::tcp_close(v6_only);
    net::tcp_close(c6);
    net::tcp_close(c4);
    net::tcp_close(srv);
    print("DUALSTACK_UDP_V4_V6_OK");
}

fn test_poller_udp_and_tcp_multiplex() {
    let tcp_lis = net::tcp_listen("::", 0, 16);
    assert(tcp_lis > 0);
    let tcp_port = net::tcp_getsockname_port(tcp_lis);
    assert(tcp_port > 0);

    let udp_srv = net::udp_open_dual("::", 0, 0);
    assert(udp_srv > 0);
    let udp_port = net::tcp_getsockname_port(udp_srv);
    assert(udp_port > 0);

    let c4 = net::udp_open_dual("127.0.0.1", 0, 0);
    assert(c4 > 0);

    let cfg = net_internal::auto_transport_driver_config();
    var p = net::new_poller(cfg);
    assert(net::enable_os_multiplexing(p));

    // Reject negative or > i32::MAX descriptors without truncation.
    assert(!net::poller_register_fd(p, -1, core::POLL_READ, 999));
    assert(!net::poller_register_fd(p, 0x80000000, core::POLL_READ, 999));
    assert(!net::poller_modify_fd(p, -1, core::POLL_READ, 999));
    assert(!net::poller_deregister_fd(p, -1));

    assert(net::poller_register_fd(p, tcp_lis, core::POLL_READ, 1001));
    assert(net::poller_register_fd(p, udp_srv, core::POLL_READ, 2002));

    // Inbound IPv4 UDP datagram wakes Poller on udp_srv.
    assert(net::udp_sendto_dual(c4, "wake_udp", "127.0.0.1", udp_port) == 8);
    var evs: core::PollReadyEvent[..64] = [];
    let n_udp = net::poll_events(p, 500, 1000, evs);
    assert(n_udp >= 1);
    var saw_udp = false;
    for i in n_udp {
        if evs[i].tag == 2002 && evs[i].fd == (udp_srv as i32) && (evs[i].events & core::POLL_READ) != 0 {
            saw_udp = true;
        }
    }
    assert(saw_udp);

    var buf:       u8[64] = [0; 64];
    var peer_ip:   u8[64] = [0; 64];
    var ip_len:    i32    = 0;
    var peer_port: u16    = 0;
    let nr = net::udp_recvfrom_dual(udp_srv, buf[..], peer_ip[..], ip_len, peer_port);
    assert(nr == 8 && buf[..8] == "wake_udp");
    assert(ip_len == 9 && peer_ip[..9] == "127.0.0.1");

    // Modify UDP registration to include POLL_WRITE and verify readiness.
    assert(net::poller_modify_fd(p, udp_srv, core::POLL_READ | core::POLL_WRITE, 2003));
    evs.clear();
    let n_w = net::poll_events(p, 500, 2000, evs);
    assert(n_w >= 1);
    var saw_write = false;
    for i in n_w {
        if evs[i].tag == 2003 && (evs[i].events & core::POLL_WRITE) != 0 {
            saw_write = true;
        }
    }
    assert(saw_write);
    assert(net::poller_modify_fd(p, udp_srv, core::POLL_READ, 2002));

    // TCP connect alongside UDP registration wakes TCP listener tag 1001.
    let tcp_cli = net::tcp_connect_ip("127.0.0.1", tcp_port, 2000, net::IpFamily.Ipv4Only);
    assert(tcp_cli > 0);
    evs.clear();
    let n_tcp = net::poll_events(p, 500, 3000, evs);
    assert(n_tcp >= 1);
    var saw_tcp = false;
    for i in n_tcp {
        if evs[i].tag == 1001 && evs[i].fd == (tcp_lis as i32) && (evs[i].events & core::POLL_READ) != 0 {
            saw_tcp = true;
        }
    }
    assert(saw_tcp);
    let tcp_srv = net::tcp_accept(tcp_lis, 500);
    assert(tcp_srv > 0);

    assert(net::poller_deregister_fd(p, tcp_lis));
    assert(net::poller_deregister_fd(p, udp_srv));
    net::close_poller(p);
    net::tcp_close(tcp_srv);
    net::tcp_close(tcp_cli);
    net::tcp_close(c4);
    net::tcp_close(udp_srv);
    net::tcp_close(tcp_lis);
    print("POLLER_UDP_TCP_MULTIPLEX_OK");
}

fn main() {
    assert(net::tcp_init());
    test_dualstack_udp_v4_and_v6();
    test_poller_udp_and_tcp_multiplex();
}
