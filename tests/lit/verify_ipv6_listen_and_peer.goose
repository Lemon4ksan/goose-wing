// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RUN: goose %s | %FileCheck %s
// CHECK: IPV6_LOOPBACK_PEER_OK
// CHECK: DUALSTACK_V4_MAPPED_OK
import std;
import wing from "../..";

fn main() {
    assert(net::tcp_init());
    let l6 = net::tcp_listen("::1", 0, 16);
    assert(l6 > 0);
    let p6 = net::tcp_getsockname_port(l6);
    assert(p6 > 0);
    let c6 = net::tcp_connect_ip("::1", p6, 2000, net::IpFamily.Ipv6Only);
    assert(c6 > 0);
    let a6 = net::tcp_accept(l6, 2000);
    assert(a6 > 0);
    var ip6: u8[..64] = [];
    net::tcp_get_peer_ip(a6, ip6);
    assert(ip6[..] == "::1");
    net::tcp_close(a6);
    net::tcp_close(c6);
    net::tcp_close(l6);
    print("IPV6_LOOPBACK_PEER_OK");

    let ld = net::tcp_listen("::", 0, 16);
    assert(ld > 0);
    let pd = net::tcp_getsockname_port(ld);
    assert(pd > 0);
    let c4 = net::tcp_connect_ip("127.0.0.1", pd, 2000, net::IpFamily.Ipv4Only);
    assert(c4 > 0);
    let a4 = net::tcp_accept(ld, 2000);
    assert(a4 > 0);
    var ip4: u8[..64] = [];
    net::tcp_get_peer_ip(a4, ip4);
    assert(ip4[..] == "127.0.0.1");
    net::tcp_close(a4);
    net::tcp_close(c4);
    net::tcp_close(ld);
    print("DUALSTACK_V4_MAPPED_OK");
}
