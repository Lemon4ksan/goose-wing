// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Module: ProxyChain — proxy scheme, node specification, and ordered forwarding chain.
namespace net;

import std;
import core;

enum ProxyScheme {
    Direct,
    Http,
    Https,
    Socks4,
    Socks4a,
    Socks5,
    Socks5h,
}

// Specification of a single proxy node.
struct ProxyServer {
    scheme:     ProxyScheme = ProxyScheme.Direct,
    host:       u8[..256]   = [],
    port:       u16         = 0,
    overflowed: bool        = false,
}

fn new_proxy_server(scheme_val: ProxyScheme, host_str: const u8[:], port_num: u16) -> ProxyServer {
    var ps = ProxyServer { scheme: scheme_val, port: port_num, .. };
    if ps.host.try_set(host_str) {
        to_lower(ps.host[..]);
    } else {
        ps.overflowed = true;
    }
    return ps;
}

fn proxy_server_equals(a: const ProxyServer&, b: const ProxyServer&) -> bool {
    guard !a.overflowed && !b.overflowed else { return false; }
    return a.scheme == b.scheme && a.port == b.port && a.host[..].eq_ascii_fold(b.host[..]);
}

// Ordered proxy chain (direct or multi-hop forwarding route).
struct ProxyChain {
    servers:   ProxyServer[..4] = [],
    is_direct: bool             = true,
}

fn new_direct_proxy_chain() -> ProxyChain {
    return ProxyChain { is_direct: true, .. };
}

fn new_single_proxy_chain(ps: ProxyServer) -> ProxyChain {
    var pc = ProxyChain { is_direct: (ps.scheme == ProxyScheme.Direct), .. };
    pc.servers.push(ps);
    return pc;
}

fn proxy_chain_equals(a: const ProxyChain&, b: const ProxyChain&) -> bool {
    if a.is_direct != b.is_direct { return false; }
    if a.is_direct && b.is_direct { return true; }
    if a.servers.len != b.servers.len { return false; }
    for &s_a, i in a.servers {
        if !s_a.proxy_server_equals(b.servers[i]) { return false; }
    }
    return true;
}
