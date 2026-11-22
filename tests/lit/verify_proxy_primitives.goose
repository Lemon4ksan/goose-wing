// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Verification suite for upstream proxy, CIDR, binary SSRF, SOCKS5/4a, and dual-stack L4 primitives.
// RUN: goose build -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import wing from "../..";

struct TestLineReq {
    method:    u8[..16]  = [],
    url:       u8[..512] = [],
    is_http10: bool      = false,
}

fn test_ip_cidr_and_ufcs() {
    let ip4, ok4 = core::parse_ip_addr("185.10.40.7");
    assert(ok4 && ip4.family == core::IpFamily.V4);
    assert(ip4.bytes[0] == 185 && ip4.bytes[3] == 7);

    let _, bad_lz = core::parse_ipv4_octets("192.168.01.1");
    assert(!bad_lz);
    let u32_lo, ok_lo = core::parse_ipv4_u32("127.0.0.1");
    assert(ok_lo && u32_lo == 0x7F000001);

    let ip6, ok6 = core::parse_ip_addr("[2001:db8::1]");
    assert(ok6 && ip6.family == core::IpFamily.V6);

    let c4, ok_c4 = core::parse_cidr("185.10.40.0/24");
    assert(ok_c4 && core::cidr_contains_ip(c4, ip4));
    let sub4, ok_sub4 = core::parse_cidr("185.10.40.0/25");
    assert(ok_sub4 && core::cidr_contains_cidr(c4, sub4));
    assert(!core::cidr_contains_cidr(sub4, c4));

    let c6, ok_c6 = core::parse_cidr("2001:db8::/32");
    assert(ok_c6 && core::cidr_contains_ip(c6, ip6));

    var fmt_buf: u8[..64] = [];
    assert(core::format_ip_addr(ip6, fmt_buf) && fmt_buf[..] == "2001:db8::1");
    assert(core::ip_addr_equals(ip4, ip4) && !core::ip_addr_equals(ip4, ip6));

    var dyn_buf: u8[>..] = [];
    assert(dyn_buf.try_push('a') && dyn_buf.try_push('/') && dyn_buf[..] == "a/");
    print("IP_CIDR_UFCS_OK\n");
    // CHECK: IP_CIDR_UFCS_OK
}

fn test_binary_ssrf_and_ports() {
    let pub_ip, _ = core::parse_ip_addr("93.184.216.34");
    let loop_ip, _ = core::parse_ip_addr("127.0.0.1");
    let cgnat_ip, _ = core::parse_ip_addr("100.64.1.2");
    let mapped_ip, _ = core::parse_ip_addr("::ffff:10.0.0.5");
    let ula_ip, _ = core::parse_ip_addr("fd00::1");

    assert(!security::is_reserved_ip_addr(pub_ip));
    assert(security::is_reserved_ip_addr(loop_ip));
    assert(security::is_reserved_ip_addr(cgnat_ip));
    assert(security::is_reserved_ip_addr(mapped_ip));
    assert(security::is_reserved_ip_addr(ula_ip));
    assert(security::is_forbidden_proxy_port(25));
    assert(security::is_forbidden_proxy_port(445));
    assert(!security::is_forbidden_proxy_port(443));
    assert(security::is_udp_amplification_port(123));
    assert(security::is_udp_amplification_port(5353));
    assert(!security::is_udp_amplification_port(53));
    print("SSRF_PORTS_OK\n");
    // CHECK: SSRF_PORTS_OK
}

fn test_socks_server_codecs() {
    let greet_wire: u8[4] = [0x05, 0x02, 0x00, 0x02];
    let gr, gr_st = net::parse_socks5_client_greeting(greet_wire[..]);
    assert(gr_st == net::SocksParseStatus.Ok && gr.has_no_auth && gr.has_userpass && gr.consumed == 4);

    let sel = net::encode_socks5_method_selection(0x02);
    assert(sel[0] == 0x05 && sel[1] == 0x02);

    var up_wire: u8[>..] = [0x01, 0x05];
    up_wire.append("alice");
    up_wire.push(0x06);
    up_wire.append("secret");
    var creds, up_st = net::parse_socks5_userpass_request(up_wire[..]);
    assert(up_st == net::SocksParseStatus.Ok);
    assert(creds.username[..] == "alice" && creds.password[..] == "secret");
    net::zeroize_socks5_creds(creds);
    assert(creds.password.len == 0);
    let up_rep = net::encode_socks5_userpass_reply(true);
    assert(up_rep[0] == 0x01 && up_rep[1] == 0x00);

    let bind_ip, _ = core::parse_ip_addr("127.0.0.1");
    var srv_rep: u8[..32] = [];
    assert(net::encode_socks5_server_reply(0x00, bind_ip, 1080, srv_rep) && srv_rep.len == 10);
    var udp_hdr_out: u8[..32] = [];
    assert(net::encode_socks5_udp_header(bind_ip, 5353, udp_hdr_out) && udp_hdr_out.len == 10);

    var req_wire: u8[>..] = [0x05, 0x01, 0x00, 0x03, 0x0B];
    req_wire.append("example.com");
    req_wire.append([0x01, 0xBB]);
    let tgt, tgt_st = net::parse_socks5_client_request(req_wire[..]);
    assert(tgt_st == net::SocksParseStatus.Ok && tgt.host[..] == "example.com" && tgt.port == 443);

    var udp_assoc_wire: u8[10] = [0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    let utgt, u_st = net::parse_socks5_client_request(udp_assoc_wire[..]);
    assert(u_st == net::SocksParseStatus.Ok && utgt.cmd == 0x03);

    let udp_pkt: u8[12] = [0x00, 0x00, 0x00, 0x01, 8, 8, 8, 8, 0x00, 0x35, 'o', 'k'];
    let uh, uh_st = net::parse_socks5_udp_header(udp_pkt[..]);
    assert(uh_st == net::SocksParseStatus.Ok && uh.header_len == 10 && uh.target.port == 53);

    let bad_frag: u8[10] = [0x00, 0x00, 0x01, 0x01, 8, 8, 8, 8, 0x00, 0x35];
    let _, frag_st = net::parse_socks5_udp_header(bad_frag[..]);
    assert(frag_st == net::SocksParseStatus.Unsupported);

    var s4a_wire: u8[>..] = [0x04, 0x01, 0x01, 0xBB, 0, 0, 0, 1];
    s4a_wire.append("bob");
    s4a_wire.push(0x00);
    s4a_wire.append("api.example.com");
    s4a_wire.push(0x00);
    let s4t, is4a, s4_st = net::parse_socks4_client_request(s4a_wire[..]);
    assert(s4_st == net::SocksParseStatus.Ok && is4a && s4t.host[..] == "api.example.com" && s4t.port == 443);
    let s4_rep = net::encode_socks4_server_reply(true);
    assert(s4_rep[1] == 0x5A);
    print("SOCKS_SERVER_CODECS_OK\n");
    // CHECK: SOCKS_SERVER_CODECS_OK
}

fn test_http_proxy_and_tls_chain() {
    let h, p, ok_hp = net::parse_authority_host_port("[2001:db8::1]:8443", 443, net::PortRequirement.Required);
    assert(ok_hp && h[..] == "2001:db8::1" && p == 8443);

    let h2, p2, ok_opt = net::parse_authority_host_port("proxy.local", 8080, net::PortRequirement.Optional);
    assert(ok_opt && h2[..] == "proxy.local" && p2 == 8080);

    var login: u8[..128] = [];
    var pwd:   u8[..256] = [];
    assert(net::decode_basic_proxy_auth("Basic dXNlcjpwYXNz", login, pwd));
    assert(login[..] == "user" && pwd[..] == "pass");
    assert(!net::decode_basic_proxy_auth("Bearer xyz", login, pwd));
    assert(pwd.len == 0);

    var r1 = TestLineReq { .. };
    assert(!server::parse_http1_request_line("GET http://example.com/a HTTP/1.1", r1));
    assert(server::parse_http1_request_line("GET http://example.com/a HTTP/1.1", r1, server::RequestTargetMode.AllowAbsoluteForm));
    assert(r1.url[..] == "http://example.com/a");

    var am = net::AttemptManager { enable_nat64_synthesis: false, .. };
    var cands: net::DnsCandidate[..4] = [];
    let _ = cands.try_push(net::new_dns_candidate(net::AddressFamily.IPv6, "2001:db8::1", 443));
    net::start_attempt_race(am, cands[..], 0);
    let _ = net::tick_attempt_manager(am, 5000);
    assert(!am.last_resort_armed && !am.last_resort_triggered && am.pending_candidates.len == 1);

    let leaf:     u8[3] = [0x30, 0x01, 0x01];
    let ca_bytes: u8[3] = [0x30, 0x01, 0x02];
    var ca_item: u8[..4096] = [];
    let _ = ca_item.try_append(ca_bytes[..]);
    let chain: u8[..4096][1] = [ca_item];
    var cert_out: u8[..1024] = [];
    assert(tls_internal::encode_client_certificate_chain(cert_out, "", leaf[..], chain[..]));
    assert(cert_out.len == 20);
    print("HTTP_PROXY_TLS_CHAIN_OK\n");
    // CHECK: HTTP_PROXY_TLS_CHAIN_OK
}

fn test_dual_stack_sockets_and_host_utils() {
    var ips_buf: u8[2048] = [0; 2048];
    let n_ips = net::net_get_local_ips(ips_buf[..]);
    assert(n_ips > 0);
    let pct = net::fs_disk_usage_percent(".");
    assert(pct >= 0 && pct <= 100);
    assert(net::fs_file_mtime("wing.goose") > 0);

    var up = net::UringPoller { .. };
    if net::uring_poll_open(up, 64) {
        let _ = net::uring_poll_mod(up, -1, net::EPOLL_READ, 1);
        let _ = net::uring_poll_del(up, -1);
        var ufds: i64[2] = [0; 2];
        var uud:  u64[2] = [0; 2];
        var uev:  u32[2] = [0; 2];
        let _ = net::uring_poll_wait_events(up, ufds[..], uud[..], uev[..], 0);
        net::uring_poll_close(up);
    } else {
        assert(!net::uring_poll_mod(up, 1, net::EPOLL_READ, 1));
        assert(!net::uring_poll_del(up, 1));
        var ufds: i64[2] = [0; 2];
        var uud:  u64[2] = [0; 2];
        var uev:  u32[2] = [0; 2];
        assert(net::uring_poll_wait_events(up, ufds[..], uud[..], uev[..], 0) == 0);
        net::uring_poll_close(up);
    }

    var pr:      i64 = -1;
    var pw:      i64 = -1;
    var in_pipe: i64 = 0;
    if net::pipe_create(pr, pw) {
        let _ = net::tcp_splice_chunk(-1, -1, pr, pw, 64, in_pipe);
        net::pipe_close(pr, pw);
    } else {
        assert(net::tcp_splice_chunk(-1, -1, pr, pw, 64, in_pipe) == -1);
        net::pipe_close(pr, pw);
    }

    let lis = net::tcp_listen_dual("127.0.0.1", 0, 16, 0);
    assert(lis > 0);
    let lport = net::tcp_getsockname_port(lis);
    assert(lport > 0);

    var st:  i32 = -1;
    var err: i32 = -1;
    let cfd = net::tcp_connect_bound_begin("127.0.0.1", "127.0.0.1", lport, 0, st, err);
    assert(cfd > 0);
    assert(net::tcp_connect_status(cfd) >= 0);
    assert(net::tcp_set_ttl(cfd, 64, false));

    var peer_ip: u8[64] = [0; 64];
    var dst_ip:  u8[64] = [0; 64];
    var plen:    i32    = 0;
    var dlen:    i32    = 0;
    var pport:   u16    = 0;
    var dport:   u16    = 0;
    var afd:     i64    = 0;
    let ep = net::epoll_create();
    defer net::epoll_close(ep);
    let _ = net::epoll_add(ep, lis, net::EPOLL_READ, 1);
    var efds: i64[4] = [0; 4];
    var eud:  u64[4] = [0; 4];
    for _ in 20 {
        let _ = net_internal::epoll_wait_direct(ep, efds[..], eud[..], 5);
        afd = net::tcp_accept_info(lis, 0, peer_ip[..], plen, pport, dst_ip[..], dlen, dport);
        if afd > 0 { break; }
    }
    assert(afd > 0 && plen > 0 && peer_ip[..plen] == "127.0.0.1" && dport == lport);
    let _ = net::tcp_send(cfd, "ping");
    let _ = net::epoll_add(ep, afd, net::EPOLL_READ, 2);
    var peek_buf: u8[16] = [0; 16];
    var pk:       i32    = -2;
    for _ in 20 {
        let _ = net_internal::epoll_wait_direct(ep, efds[..], eud[..], 5);
        pk = net::tcp_recv_peek(afd, peek_buf[..]);
        if pk > 0 { break; }
    }
    assert(pk == 4 && peek_buf[..4] == "ping");
    net::tcp_close(afd);
    net::tcp_close(cfd);
    net::tcp_close(lis);

    let u1 = net::udp_open_dual("127.0.0.1", 0, 0);
    let u2 = net::udp_open_dual("127.0.0.1", 0, 0);
    assert(u1 > 0 && u2 > 0);
    let p2 = net::tcp_getsockname_port(u2);
    assert(net::udp_sendto_dual(u1, "dgram", "127.0.0.1", p2) == 5);
    let _ = net::epoll_add(ep, u2, net::EPOLL_READ, 3);
    var ubuf:  u8[64] = [0; 64];
    var upip:  u8[64] = [0; 64];
    var uplen: i32    = 0;
    var upprt: u16    = 0;
    var ur:    i32    = -2;
    for _ in 20 {
        let _ = net_internal::epoll_wait_direct(ep, efds[..], eud[..], 5);
        ur = net::udp_recvfrom_dual(u2, ubuf[..], upip[..], uplen, upprt);
        if ur > 0 { break; }
    }
    assert(ur == 5 && ubuf[..5] == "dgram");
    var ex_buf: u8[32] = [0; 32];
    let _ = net::udp_exchange_dual("127.0.0.1", p2, "q", ex_buf[..], 10);
    net::tcp_close(u1);
    net::tcp_close(u2);
    print("DUAL_STACK_HOST_OK\n");
    // CHECK: DUAL_STACK_HOST_OK
}

fn main() {
    test_ip_cidr_and_ufcs();
    test_binary_ssrf_and_ports();
    test_socks_server_codecs();
    test_http_proxy_and_tls_chain();
    test_dual_stack_sockets_and_host_utils();
}
