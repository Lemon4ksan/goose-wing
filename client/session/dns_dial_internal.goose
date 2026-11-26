// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal DNS cache/SVCB/override/system resolution, SSRF IP sweep, proxy dialing, and pool establishment.
namespace client_internal;

import std;
import os;
import core;
import rfc.http;
import rfc.dns;
import dns.cache;
import http.response;
import http.altsvc;
import security.ssrf;
import net.pool;
import net.proxy;
import net.socks5;
import net.http_connect;
import net.tcp;
import net.happy_eyeballs;
import net.transport;
import client.redirect;
import client.client;
import .tls_hop_internal;

inline fn calc_effective_timeout_ms(session_timeout: i64, req_timeout: i64) -> u32 {
    let raw = if req_timeout > 0 { req_timeout } else { session_timeout };
    return min(max(raw, 1), 600000) as u32;
}

inline fn calc_phase_timeout_ms(phase_ms: i64, session_timeout: i64, req_timeout: i64) -> u32 {
    if phase_ms > 0 {
        let raw = if req_timeout > 0 { min(phase_ms, req_timeout) } else { phase_ms };
        return min(max(raw, 1), 600000) as u32;
    }
    return calc_effective_timeout_ms(session_timeout, req_timeout);
}

fn validate_resolved_ips_against_ssrf(
    ips:    const u8[:][:],
    policy: const security::SsrfGuardPolicy&,
) -> client::RedirectError {
    guard policy.enabled else { return client::RedirectError.None; }
    guard ips.len > 0 else { return client::RedirectError.SsrfBlockedIp; }
    for ip in ips {
        guard security::is_valid_resolved_ip_literal(ip) else {
            return client::RedirectError.SsrfBlockedIp;
        }
        let blocked = if policy.deny_local_network {
            security::is_private_or_reserved_ip(ip)
        } else {
            security::is_cloud_metadata_or_reserved_ip(ip)
        };
        if blocked {
            return client::RedirectError.SsrfBlockedIp;
        }
    }
    return client::RedirectError.None;
}

inline fn is_ssrf_blocked_ip(policy: const security::SsrfGuardPolicy&, ip: const u8[:]) -> bool {
    guard policy.enabled else { return false; }
    return if policy.deny_local_network {
        security::is_private_or_reserved_ip(ip)
    } else {
        security::is_cloud_metadata_or_reserved_ip(ip)
    };
}

fn lookup_resolve_override(
    session:  const client::Session&,
    host_str: const u8[:],
    port_num: u16,
    out_ip:   u8[..64]&,
) -> bool {
    let clean_host = host_str.trim_lws().trim_end_byte('.');
    guard clean_host.len > 0 else { return false; }
    var wild_idx: i64 = -1;
    for &ov, i in session.resolve_overrides {
        guard ov.host[..].eq_ascii_fold(clean_host) else { continue; }
        if ov.port == port_num {
            return out_ip.try_set(ov.ip[..]);
        }
        if ov.port == 0 && wild_idx < 0 {
            wild_idx = i;
        }
    }
    if wild_idx >= 0 {
        return out_ip.try_set(session.resolve_overrides[wild_idx].ip[..]);
    }
    return false;
}

fn try_resolve_override_candidate(
    session:        const client::Session&,
    host_str:       const u8[:],
    port_num:       u16,
    out_candidates: net::DnsCandidate[..32]&,
) -> bool, http::Error {
    var ov_ip: u8[..64] = [];
    guard lookup_resolve_override(session, host_str, port_num, ov_ip) else {
        return false, http::Error { .. };
    }
    if session.ssrf_guard.enabled {
        let blocked = if session.ssrf_guard.deny_local_network {
            security::is_private_or_reserved_ip(ov_ip[..])
        } else {
            security::is_cloud_metadata_or_reserved_ip(ov_ip[..])
        };
        if blocked {
            return true, http::make_error(
                rfc::STATUS_FORBIDDEN, "ssrf_guard", "SSRF: resolve override to private IP blocked",
            );
        }
    }
    let is_v6 = ov_ip[..].contains_byte(':');
    let fam_mismatch = (session.ip_family == net::IpFamily.Ipv4Only && is_v6) ||
        (session.ip_family == net::IpFamily.Ipv6Only && !is_v6);
    if fam_mismatch {
        return true, http::make_error(
            rfc::STATUS_BAD_GATEWAY, "transport", "IP family mismatch for resolve override",
        );
    }
    let fam = if is_v6 { net::AddressFamily.IPv6 } else { net::AddressFamily.IPv4 };
    let _ = out_candidates.try_push(net::new_dns_candidate(fam, ov_ip[..], port_num, net::L4Protocol.Tcp, 50));
    return true, http::Error { .. };
}

fn collect_ipv4_dns_candidates(
    ssrf_guard: const security::SsrfGuardPolicy&,
    a_entry:    const dns::CacheEntry&,
    port_num:   u16,
    out_list:   net::DnsCandidate[..8]&,
) -> bool {
    var ip4_buf: u8[..64] = [];
    for ip4 in a_entry.ipv4_hints {
        core::format_ipv4_u32(ip4, ip4_buf);
        guard !is_ssrf_blocked_ip(ssrf_guard, ip4_buf[..]) else { return false; }
        let _ = out_list.try_push(
            net::new_dns_candidate(net::AddressFamily.IPv4, ip4_buf[..], port_num, net::L4Protocol.Tcp, 40),
        );
    }
    return true;
}

fn collect_ipv6_dns_candidates(
    ssrf_guard: const security::SsrfGuardPolicy&,
    aaaa_entry: const dns::CacheEntry&,
    port_num:   u16,
    out_list:   net::DnsCandidate[..8]&,
) -> bool {
    var ip6_buf: u8[..64] = [];
    for &ip6 in aaaa_entry.ipv6_hints {
        core::format_ipv6_bytes(ip6, ip6_buf);
        guard !is_ssrf_blocked_ip(ssrf_guard, ip6_buf[..]) else { return false; }
        let _ = out_list.try_push(
            net::new_dns_candidate(net::AddressFamily.IPv6, ip6_buf[..], port_num, net::L4Protocol.Tcp, 50),
        );
    }
    return true;
}

inline fn is_ssrf_blocked_port(policy: const security::SsrfGuardPolicy&, port: u16) -> bool {
    guard policy.enabled else { return false; }
    let port_val = port as i32;
    if policy.denied_ports.contains(port_val) { return true; }
    if policy.allowed_ports.len > 0 {
        return !policy.allowed_ports.contains(port_val);
    }
    return policy.deny_local_network && security::is_dangerous_service_port(port_val);
}

fn append_svcb_hint_candidate(
    ssrf_guard: const security::SsrfGuardPolicy&,
    ip_str:     const u8[:],
    fam:        net::AddressFamily,
    eff_port:   u16,
    priority:   u8,
    out_list:   net::DnsCandidate[..8]&,
) -> bool {
    guard !is_ssrf_blocked_port(ssrf_guard, eff_port) && !is_ssrf_blocked_ip(ssrf_guard, ip_str) else {
        return false;
    }
    let _ = out_list.try_push(net::new_dns_candidate(fam, ip_str, eff_port, net::L4Protocol.Tcp, priority));
    return true;
}

fn collect_https_svcb_hint_candidates(
    ssrf_guard: const security::SsrfGuardPolicy&,
    meta:       const net::ConnectionEndpointMetadata&,
    eff_port:   u16,
    task:       net::DnsRaceTask&,
) -> bool {
    if task.ipv6_candidates.len == 0 {
        for &ip6_str in meta.ipv6_hints {
            guard append_svcb_hint_candidate(
                ssrf_guard, ip6_str[..], net::AddressFamily.IPv6, eff_port, 50, task.ipv6_candidates,
            ) else { return false; }
        }
    }
    if task.ipv4_candidates.len == 0 {
        for &ip4_str in meta.ipv4_hints {
            guard append_svcb_hint_candidate(
                ssrf_guard, ip4_str[..], net::AddressFamily.IPv4, eff_port, 40, task.ipv4_candidates,
            ) else { return false; }
        }
    }
    return true;
}

fn resolve_https_svcb_record<B>(
    session:      client::Session&,
    host_str:     const u8[:],
    port_num:     u16,
    now_sec:      i64,
    task:         net::DnsRaceTask&,
    out_ech_list: B&,
) -> bool {
    let https_entry, h_stat = session.dns_cache.lookup(host_str, rfc::DNS_QTYPE_HTTPS, now_sec);
    guard https_entry && h_stat != dns::CacheStatus.Expired && https_entry.https_records.len > 0 else {
        return true;
    }
    let meta, eff_port = net::extract_https_svcb_metadata(https_entry.https_records[0], port_num);
    guard !is_ssrf_blocked_port(session.ssrf_guard, eff_port) else { return false; }
    task.metadata = meta;
    task.https_status = net::DnsQueryStatus.Success;
    if (session.enable_ech || session.auto_ech_discovery) && https_entry.https_records[0].has_ech {
        let _ = out_ech_list.try_set(https_entry.https_records[0].ech_config_list[..]);
    }
    return collect_https_svcb_hint_candidates(session.ssrf_guard, meta, eff_port, task);
}

fn lookup_dns_https_h3_endpoint(
    dns_cache:    const dns::Cache&,
    host_str:     const u8[:],
    default_port: u16,
    now_sec:      i64,
) -> http::AltSvcEndpoint, bool {
    var ep = http::AltSvcEndpoint { .. };
    let https_entry, h_stat = dns_cache.lookup(host_str, rfc::DNS_QTYPE_HTTPS, now_sec);
    guard https_entry && h_stat != dns::CacheStatus.Expired && https_entry.https_records.len > 0 else {
        return ep, false;
    }
    let meta, eff_port = net::extract_https_svcb_metadata(https_entry.https_records[0], default_port);
    guard meta.alpn_h3 else { return ep, false; }
    ep.port = eff_port;
    ep.max_age_sec = 86400;
    ep.persist = false;
    let _ = ep.proto.try_set("h3");
    let target_h = if meta.target_name.len > 0 { meta.target_name[..] } else { host_str };
    let _ = ep.host.try_append(target_h);
    return ep, true;
}

fn resolve_system_dns_candidates(
    session:        const client::Session&,
    host_str:       const u8[:],
    port_num:       u16,
    now_sec:        i64,
    task:           net::DnsRaceTask&,
    out_candidates: net::DnsCandidate[..32]&,
) -> http::Error {
    var resolved_ips: u8[..64][..16] = [];
    guard net::resolve_host_ips(host_str, resolved_ips, session.ip_family) else {
        return http::make_error(rfc::STATUS_BAD_GATEWAY, "transport", "DNS resolution failed");
    }
    for &ip in resolved_ips {
        guard !is_ssrf_blocked_ip(session.ssrf_guard, ip[..]) else {
            return http::make_error(
                rfc::STATUS_FORBIDDEN, "ssrf_guard", "SSRF: DNS rebinding to private IP blocked",
            );
        }
        if ip[..].contains_byte(':') {
            let _ = task.ipv6_candidates.try_push(
                net::new_dns_candidate(net::AddressFamily.IPv6, ip[..], port_num, net::L4Protocol.Tcp, 50),
            );
        } else {
            let _ = task.ipv4_candidates.try_push(
                net::new_dns_candidate(net::AddressFamily.IPv4, ip[..], port_num, net::L4Protocol.Tcp, 40),
            );
        }
    }
    let pref_fam, _ = net::lookup_preferred_family(session.af_cache, host_str, now_sec);
    net::interleave_candidates_by_preference(
        task.ipv6_candidates[..], task.ipv4_candidates[..], pref_fam, out_candidates,
    );
    guard out_candidates.len > 0 else {
        return http::make_error(rfc::STATUS_BAD_GATEWAY, "transport", "DNS resolution returned no usable IP");
    }
    return http::Error { .. };
}

fn collect_cached_address_candidates(
    session:  const client::Session&,
    host_str: const u8[:],
    port_num: u16,
    now_sec:  i64,
    task:     net::DnsRaceTask&,
) -> bool {
    if session.ip_family != net::IpFamily.Ipv6Only {
        let a_entry, a_stat = session.dns_cache.lookup(host_str, rfc::DNS_QTYPE_A, now_sec);
        if a_entry && a_stat != dns::CacheStatus.Expired {
            guard collect_ipv4_dns_candidates(session.ssrf_guard, a_entry, port_num, task.ipv4_candidates) else {
                return false;
            }
            task.a_status = net::DnsQueryStatus.Success;
        }
    }
    if session.ip_family != net::IpFamily.Ipv4Only {
        let aaaa_entry, aaaa_stat = session.dns_cache.lookup(host_str, rfc::DNS_QTYPE_AAAA, now_sec);
        if aaaa_entry && aaaa_stat != dns::CacheStatus.Expired {
            guard collect_ipv6_dns_candidates(session.ssrf_guard, aaaa_entry, port_num, task.ipv6_candidates) else {
                return false;
            }
            task.aaaa_status = net::DnsQueryStatus.Success;
        }
    }
    return true;
}

fn resolve_and_validate_live_host<B>(
    session:        client::Session&,
    host_str:       const u8[:],
    port_num:       u16,
    now_sec:        i64,
    out_candidates: net::DnsCandidate[..32]&,
    out_ech_list:   B&,
) -> http::Error {
    var committed = false;
    defer if !committed { out_candidates.clear(); out_ech_list.clear(); };
    out_candidates.clear();
    out_ech_list.clear();

    let has_override, ov_err = try_resolve_override_candidate(session, host_str, port_num, out_candidates);
    if has_override {
        committed = http::ok(ov_err);
        return ov_err;
    }

    let now_ms = core::mul_sat_i64(now_sec, 1000);
    var task = net::new_dns_race_task(port_num);

    guard collect_cached_address_candidates(session, host_str, port_num, now_sec, task) else {
        return http::make_error(rfc::STATUS_FORBIDDEN, "ssrf_guard", "SSRF: DNS rebinding to private IP blocked");
    }
    guard resolve_https_svcb_record(session, host_str, port_num, now_sec, task, out_ech_list) else {
        return http::make_error(rfc::STATUS_FORBIDDEN, "ssrf_guard", "SSRF: HTTPS SVCB hint to private IP blocked");
    }
    if session.ip_family == net::IpFamily.Ipv6Only { task.ipv4_candidates.clear(); }
    if session.ip_family == net::IpFamily.Ipv4Only { task.ipv6_candidates.clear(); }

    let _ = task.check_dns_resolution_delay_tick(core::add_sat_i64(now_ms, rfc::HE_RESOLUTION_DELAY_MS));
    let pref_fam, _ = net::lookup_preferred_family(session.af_cache, host_str, now_sec);
    net::interleave_candidates_by_preference(
        task.ipv6_candidates[..], task.ipv4_candidates[..], pref_fam, out_candidates,
    );
    if out_candidates.len == 0 {
        let sys_err = resolve_system_dns_candidates(
            session, host_str, port_num, now_sec, task, out_candidates,
        );
        guard http::ok(sys_err) else { return sys_err; }
    }
    committed = true;
    return http::Error { .. };
}

// Strips ASCII whitespace, IPv6 brackets, optional `:port`, and trailing `.` from a host token.
//
// Example:
//   raw = "[::1]:8443" -> "::1"
//   raw = "Api.Example.COM.:443" -> "Api.Example.COM"
fn normalize_no_proxy_host(raw: const u8[:]) -> const u8[:] {
    var s = raw.trim_ascii_space();
    guard s.len > 0 else { return ""; }
    if s[0] == '[' {
        let rb = s.index_of_byte(']');
        if rb > 1 {
            s = s[1..rb];
        }
    } else {
        let c1 = s.index_of_byte(':');
        if c1 > 0 && c1 == s.last_index_of_byte(':') {
            s = s[..c1];
        }
    }
    return s.trim_end_byte('.');
}

fn match_no_proxy_domain_suffix(pat: const u8[:], norm_host: const u8[:]) -> bool {
    let dot_sfx = if core::starts_with(pat, "*.") { pat[1..] } else { pat };
    let clean_sfx = dot_sfx.trim_end_byte('.');
    guard clean_sfx.len > 1 else { return false; }
    return norm_host.ends_with_fold(clean_sfx) || norm_host.eq_ascii_fold(clean_sfx[1..]);
}

fn match_no_proxy_pattern(pattern: const u8[:], norm_host: const u8[:]) -> bool {
    let pat = pattern.trim_ascii_space();
    guard pat.len > 0 && norm_host.len > 0 else { return false; }
    if pat == "*" { return true; }
    if pat.eq_ascii_fold("localhost") { return security::is_localhost_name(norm_host); }
    if pat.contains_byte('/') {
        let cidr, ok_cidr = core::parse_cidr(pat);
        let hip, ok_hip = core::parse_ip_addr(norm_host);
        return ok_cidr && ok_hip && core::cidr_contains_ip(cidr, hip);
    }
    if core::starts_with(pat, ".") || core::starts_with(pat, "*.") {
        return match_no_proxy_domain_suffix(pat, norm_host);
    }
    let norm_pat = normalize_no_proxy_host(pat);
    guard norm_pat.len > 0 else { return false; }
    let pip, ok_pip = core::parse_ip_addr(norm_pat);
    if ok_pip {
        let hip, ok_hip = core::parse_ip_addr(norm_host);
        return ok_hip && core::ip_addr_equals(pip, hip);
    }
    return norm_host.eq_ascii_fold(norm_pat);
}

fn matches_env_no_proxy(norm_host: const u8[:]) -> bool {
    var raw: u8[>..] = [];
    if !env("NO_PROXY", raw) || raw.len == 0 {
        raw.clear();
        guard env("no_proxy", raw) && raw.len > 0 else { return false; }
    }
    var tokenizer = core::make_byte_tokenizer(raw[..], ',');
    while true {
        let tok, has_tok = core::token_next(tokenizer);
        guard has_tok else { break; }
        if match_no_proxy_pattern(tok, norm_host) {
            return true;
        }
    }
    return false;
}

fn read_first_non_empty_env(names: const u8[:][:], out: u8[..256]&) -> bool {
    var raw: u8[>..] = [];
    for name in names {
        raw.clear();
        guard env(name, raw) else { continue; }
        let trimmed = raw[..].trim_ascii_space();
        guard trimmed.len > 0 else { continue; }
        return out.try_set(trimmed);
    }
    return false;
}

fn resolve_env_proxy_url(is_https: bool, out_url: u8[..256]&) -> bool {
    let https_vars: const u8[:][4] = ["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"];
    let http_vars:  const u8[:][4] = ["HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"];
    if is_https {
        return read_first_non_empty_env(https_vars[..], out_url);
    }
    return read_first_non_empty_env(http_vars[..], out_url);
}

fn build_proxy_chain_from_url(proxy_url: const u8[:]) -> net::ProxyChain, bool {
    guard proxy_url.len > 0 else { return net::new_direct_proxy_chain(), true; }
    let p_url = core::new_url(proxy_url);
    guard p_url.valid && p_url.hostname().len > 0 else { return net::new_direct_proxy_chain(), false; }
    let sc = p_url.scheme();
    var p_scheme = net::ProxyScheme.Http;
    if sc == "https" {
        p_scheme = net::ProxyScheme.Https;
    } else if sc == "socks5h" {
        p_scheme = net::ProxyScheme.Socks5h;
    } else if sc == "socks5" {
        p_scheme = net::ProxyScheme.Socks5;
    } else if sc != "http" {
        return net::new_direct_proxy_chain(), false;
    }
    let raw_port = p_url.effective_port();
    let p_port: u16 = if raw_port > 0 {
        raw_port as u16
    } else if p_scheme == net::ProxyScheme.Socks5 || p_scheme == net::ProxyScheme.Socks5h {
        1080
    } else if p_scheme == net::ProxyScheme.Https {
        443
    } else {
        80
    };
    let ps = net::new_proxy_server(p_scheme, p_url.hostname(), p_port);
    guard !ps.overflowed else { return net::new_direct_proxy_chain(), false; }
    return net::new_single_proxy_chain(ps), true;
}

fn resolve_hop_proxy_chain(session: const client::Session&) -> net::ProxyChain, bool {
    if session.proxy_url.len == 0 {
        return net::new_direct_proxy_chain(), true;
    }
    let p_url = core::new_url(session.proxy_url[..]);
    guard p_url.valid && p_url.hostname().len > 0 else {
        return net::new_direct_proxy_chain(), false;
    }
    let sc = p_url.scheme();
    var p_scheme = net::ProxyScheme.Http;
    if sc == "https" {
        p_scheme = net::ProxyScheme.Https;
    } else if sc == "socks5h" {
        p_scheme = net::ProxyScheme.Socks5h;
    } else if sc == "socks5" {
        p_scheme = net::ProxyScheme.Socks5;
    } else if sc != "http" {
        return net::new_direct_proxy_chain(), false;
    }
    let raw_port = p_url.effective_port();
    let p_port: u16 = if raw_port > 0 {
        raw_port as u16
    } else if p_scheme == net::ProxyScheme.Socks5 || p_scheme == net::ProxyScheme.Socks5h {
        1080
    } else if p_scheme == net::ProxyScheme.Https {
        443
    } else {
        80
    };
    let ps = net::new_proxy_server(p_scheme, p_url.hostname(), p_port);
    guard !ps.overflowed else { return net::new_direct_proxy_chain(), false; }
    return net::new_single_proxy_chain(ps), true;
}

fn resolve_effective_hop_proxy(
    session:       const client::Session&,
    host_str:      const u8[:],
    is_https:      bool,
    out_proxy_url: u8[..256]&,
) -> net::ProxyChain, bool {
    out_proxy_url.clear();
    if client::is_no_proxy_host(session, host_str) {
        return net::new_direct_proxy_chain(), true;
    }
    if session.proxy_url.len > 0 {
        let _ = out_proxy_url.try_set(session.proxy_url[..]);
        return resolve_hop_proxy_chain(session);
    }
    if session.use_env_proxy && resolve_env_proxy_url(is_https, out_proxy_url) {
        return build_proxy_chain_from_url(out_proxy_url[..]);
    }
    return net::new_direct_proxy_chain(), true;
}

struct DialResult {
    sock: i64      = -1,
    ip:   u8[..64] = [],
}

fn build_proxy_basic_auth(p_user: const u8[:], p_pass: const u8[:], out_auth: u8[..256]&) -> bool {
    out_auth.clear();
    guard p_user.len > 0 else { return true; }
    var cred_raw: u8[..160] = [];
    defer core::secure_zeroize_slice(cred_raw[..]);
    guard cred_raw.try_append(p_user) && cred_raw.try_push(':') && cred_raw.try_append(p_pass) else {
        return false;
    }
    var cred_b64: u8[..224] = [];
    defer core::secure_zeroize_slice(cred_b64[..]);
    core::base64_encode(cred_raw[..], cred_b64);
    guard cred_b64.len > 0 && out_auth.try_append("Basic ") && out_auth.try_append(cred_b64[..]) else {
        core::secure_zeroize_slice(out_auth[..]);
        out_auth.clear();
        return false;
    }
    return true;
}

fn dial_https_proxy_tunnel(
    session:     const client::Session&,
    raw_sock:    i64,
    proxy_host:  const u8[:],
    host_str:    const u8[:],
    port_num:    u16,
    proxy_auth:  const u8[:],
    eff_timeout: u32,
    now_sec:     i64,
) -> i64, http::Error {
    var outer_t, tls_err = establish_https_proxy_transport(session, raw_sock, proxy_host, eff_timeout, now_sec);
    guard http::ok(tls_err) else {
        net::fd_close(raw_sock);
        return -1, tls_err;
    }
    let c_err = net::http_connect_transport_handshake(
        outer_t, host_str, port_num, proxy_auth, "goose-wing/1.0", eff_timeout,
    );
    guard c_err == net::ConnectTunnelError.None else {
        outer_t.close();
        return -1, http::make_error(rfc::STATUS_BAD_GATEWAY, "transport", "HTTPS CONNECT tunnel failed");
    }
    let tun_fd, ok_tun = net::alloc_tunnel_fd(outer_t);
    guard ok_tun else {
        outer_t.close();
        return -1, http::make_error(rfc::STATUS_BAD_GATEWAY, "transport", "TLS tunnel descriptor table full");
    }
    return tun_fd, http::Error { .. };
}

fn apply_session_tcp_opts(session: const client::Session&, sock: i64) {
    let _ = net::tcp_set_nodelay(sock, session.tcp_nodelay);
    if session.tcp_keepalive_idle_sec > 0 &&
        session.tcp_keepalive_intvl_sec > 0 &&
        session.tcp_keepalive_cnt > 0 {
        let _ = net::tcp_set_keepalive(
            sock,
            session.tcp_keepalive_idle_sec,
            session.tcp_keepalive_intvl_sec,
            session.tcp_keepalive_cnt,
        );
    }
}

fn dial_session_tcp(
    session:    const client::Session&,
    host:       const u8[:],
    port:       u16,
    timeout_ms: u32,
) -> i64 {
    let sock = net::tcp_connect_ex(host, port, timeout_ms, session.ip_family, session.local_bind_addr[..]);
    guard sock > 0 else { return -1; }
    apply_session_tcp_opts(session, sock);
    return sock;
}

fn dial_session_tcp_ip(
    session:    const client::Session&,
    ip:         const u8[:],
    port:       u16,
    timeout_ms: u32,
) -> i64 {
    let sock = net::tcp_connect_ip(ip, port, timeout_ms, session.ip_family, session.local_bind_addr[..]);
    guard sock > 0 else { return -1; }
    apply_session_tcp_opts(session, sock);
    return sock;
}

fn dial_proxy_hop(
    session:     const client::Session&,
    proxy_url:   const u8[:],
    ps:          const net::ProxyServer&,
    host_str:    const u8[:],
    port_num:    u16,
    candidates:  const net::DnsCandidate[:],
    eff_timeout: u32,
    now_sec:     i64,
) -> DialResult, http::Error {
    var res = DialResult { .. };
    let sock = dial_session_tcp(session, ps.host[..], ps.port, eff_timeout);
    guard sock > 0 else {
        return res, http::make_error(rfc::STATUS_BAD_GATEWAY, "transport", "Proxy TCP connect failed");
    }
    var proxy_ready = false;
    defer if !proxy_ready { net::fd_close(sock); };
    let p_url = core::new_url(proxy_url);
    let p_user = p_url.username();
    let p_pass = p_url.password();
    if ps.scheme == net::ProxyScheme.Socks5 || ps.scheme == net::ProxyScheme.Socks5h {
        let use_ip = ps.scheme == net::ProxyScheme.Socks5 && candidates.len > 0;
        let t_host = if use_ip { candidates[0].ip[..] } else { host_str };
        let s_err = net::socks5_client_handshake(sock, ps.scheme, t_host, port_num, p_user, p_pass, eff_timeout);
        guard s_err == net::Socks5Error.None else {
            return res, http::make_error(rfc::STATUS_BAD_GATEWAY, "transport", "SOCKS5 handshake failed");
        }
        proxy_ready = true;
        res.sock = sock;
        let _ = res.ip.try_set(ps.host[..]);
        return res, http::Error { .. };
    }
    var proxy_auth: u8[..256] = [];
    defer core::secure_zeroize_slice(proxy_auth[..]);
    guard build_proxy_basic_auth(p_user, p_pass, proxy_auth) else {
        return res, http::make_error(rfc::STATUS_BAD_REQUEST, "proxy", "Proxy credentials exceed capacity");
    }
    if ps.scheme == net::ProxyScheme.Https {
        proxy_ready = true;
        let tun_fd, h_err = dial_https_proxy_tunnel(
            session, sock, ps.host[..], host_str, port_num, proxy_auth[..], eff_timeout, now_sec,
        );
        guard http::ok(h_err) else { return res, h_err; }
        res.sock = tun_fd;
        let _ = res.ip.try_set(ps.host[..]);
        return res, http::Error { .. };
    }
    let c_err = net::http_connect_client_handshake(
        sock, host_str, port_num, proxy_auth[..], "goose-wing/1.0", eff_timeout,
    );
    guard c_err == net::ConnectTunnelError.None else {
        return res, http::make_error(rfc::STATUS_BAD_GATEWAY, "transport", "HTTP CONNECT tunnel failed");
    }
    proxy_ready = true;
    res.sock = sock;
    let _ = res.ip.try_set(ps.host[..]);
    return res, http::Error { .. };
}

fn dial_live_tcp_or_proxy(
    session:     const client::Session&,
    proxy_url:   const u8[:],
    proxy_chain: const net::ProxyChain&,
    host_str:    const u8[:],
    port_num:    u16,
    candidates:  const net::DnsCandidate[:],
    eff_timeout: u32,
    now_sec:     i64,
    now_ms:      i64,
) -> DialResult, http::Error {
    if !proxy_chain.is_direct && proxy_chain.servers.len > 0 {
        return dial_proxy_hop(
            session, proxy_url, proxy_chain.servers[0], host_str, port_num, candidates, eff_timeout, now_sec,
        );
    }
    var mgr = net::new_attempt_manager();
    mgr.start_attempt_race(candidates, now_ms);
    for &cand in candidates {
        let sock = dial_session_tcp_ip(session, cand.ip[..], cand.port, eff_timeout);
        if sock > 0 {
            if mgr.attempts.len > 0 {
                let win_id = mgr.attempts[core::sub_sat_i64(mgr.attempts.len, 1)].attempt_id;
                let _ = mgr.bind_winner_attempt(win_id, false);
            }
            var res = DialResult { sock: sock, .. };
            let _ = res.ip.try_set(cand.ip[..]);
            return res, http::Error { .. };
        }
        let _ = mgr.tick_attempt_manager(core::add_sat_i64(now_ms, mgr.effective_cad_ms));
    }
    return DialResult { .. }, http::make_error(rfc::STATUS_BAD_GATEWAY, "transport", "TCP connect failed");
}

fn establish_pooled_connection(
    session:            client::Session&,
    pool_key:           const net::PoolKey&,
    proxy_url:          const u8[:],
    proxy_chain:        const net::ProxyChain&,
    host_str:           const u8[:],
    port_num:           u16,
    is_https:           bool,
    dns_candidates:     const net::DnsCandidate[:],
    ech_list:           const u8[:],
    connect_timeout_ms: u32,
    tls_timeout_ms:     u32,
    now_sec:            i64,
    now_ms:             i64,
    now_ns:             i64,
) -> i32, http::Error {
    let dial_res, dial_err = dial_live_tcp_or_proxy(
        session, proxy_url, proxy_chain, host_str, port_num, dns_candidates, connect_timeout_ms, now_sec, now_ms,
    );
    guard http::ok(dial_err) else { return -1, dial_err; }
    let sock = dial_res.sock;
    if proxy_chain.is_direct {
        let win_fam = if dial_res.ip[..].contains_byte(':') {
            net::AddressFamily.IPv6
        } else {
            net::AddressFamily.IPv4
        };
        net::record_preferred_family(session.af_cache, host_str, win_fam, now_sec);
    }

    var t = net::Transport.Disconnected;
    var neg_proto = net::NegotiatedProtocol.Http11;
    if is_https {
        let https_t, https_proto, tls_err = establish_https_transport(
            session, sock, host_str, ech_list, tls_timeout_ms, now_sec,
        );
        guard http::ok(tls_err) else {
            net::fd_close(sock);
            return -1, tls_err;
        }
        t = https_t;
        neg_proto = https_proto;
    } else {
        if session.http2_prior_knowledge {
            neg_proto = net::NegotiatedProtocol.Http2;
        }
        t = net::Transport.Tcp { fd: sock };
    }
    let max_streams: i32 = if neg_proto == net::NegotiatedProtocol.Http2 { 100 } else { 1 };
    let conn_id = net::register_connection(session.pool, pool_key, neg_proto, t, dial_res.ip[..], max_streams, now_ns);
    guard conn_id > 0 else {
        t.close();
        return -1, http::make_error(rfc::STATUS_BAD_GATEWAY, "transport", "connection pool registration failed");
    }
    return conn_id, http::Error { .. };
}
