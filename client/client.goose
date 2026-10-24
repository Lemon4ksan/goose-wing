// Client session state, redirect pipeline, and destination address checks.
namespace wing;

import std;
import cookie.constants;
import cookie.canonical;
import cookie.policy;
import cookie.engine;
import fingerprint.ja4;
import fingerprint.profile;
import client.profile;
import client.request;
import client.response;
import client.redirect;
import http.headers;
import http.cache.cache_control;
import http.cache.freshness;
import http.cache.validators;
import http.cache.engine;
import realtime.websocket;
import realtime.sse;
import net.dns;
import tls.ech;
import http.altsvc;
import net.happy_eyeballs;
import net.masque;
import http.compression_dict;
import client.interceptor;

// ---- ssrf guard policy and 3-tier checks -----------------------------------

struct SsrfGuardPolicy {
    enabled: bool = false,
    https_only: bool = false,
    deny_local_network: bool = true,
    allowed_ports: i32[..16] = [],
    denied_ports: i32[..16] = [],
}

fn new_ssrf_guard_policy() -> SsrfGuardPolicy {
    return SsrfGuardPolicy {
        enabled: true,
        https_only: false,
        deny_local_network: true,
        allowed_ports: [],
        denied_ports: [],
    };
}

fn is_private_ipv4_octets(octet0: i32, octet1: i32) -> bool {
    if octet0 == 0 { return true; }                                      // 0.0.0.0/8
    if octet0 == 10 { return true; }                                     // 10.0.0.0/8
    if octet0 == 127 { return true; }                                    // 127.0.0.0/8 Loopback
    if octet0 == 169 && octet1 == 254 { return true; }                   // 169.254.0.0/16 Link-Local / Cloud Metadata
    if octet0 == 172 && (octet1 >= 16 && octet1 <= 31) { return true; }  // 172.16.0.0/12
    if octet0 == 192 && octet1 == 168 { return true; }                   // 192.168.0.0/16
    if octet0 == 100 && (octet1 >= 64 && octet1 <= 127) { return true; } // 100.64.0.0/10 CGNAT
    if octet0 >= 224 { return true; }                                    // 224.0.0.0/4 Multicast & Reserved

    return false;
}

fn parse_ipv4_part(part: const u8[:]) -> u64, bool {
    guard part.len > 0 else { return 0, false; }
    var base: u64 = 10;
    var start_idx = 0;
    if part.len >= 2 && part[0] == '0' && (part[1] == 'x' || part[1] == 'X') {
        base = 16;
        start_idx = 2;
        guard part.len > 2 else { return 0, false; }
    } else if part.len >= 2 && part[0] == '0' {
        base = 8;
        start_idx = 1;
    }

    var val: u64 = 0;
    for i in start_idx..part.len {
        let b = part[i];
        let digit: u64 = if b >= '0' && b <= '9' { b - '0' }
                         else if base == 16 && b >= 'a' && b <= 'f' { b - 'a' + 10 }
                         else if base == 16 && b >= 'A' && b <= 'F' { b - 'A' + 10 }
                         else { return 0, false; };
        if digit >= base { return 0, false; }
        val = val * base + digit;
        if val > 0xFFFFFFFF { return 0, false; }
    }
    return val, true;
}

// Parses IPv4 addresses in standard dotted-decimal, octal, hex, dword, or
// shorthand notation into 4 canonical octets.
fn parse_flexible_ipv4(clean_ip: const u8[:], octets: u8[4]&) -> bool {
    guard clean_ip.len > 0 else { return false; }
    var parts: u8[..32][..4] = [];
    var cur: u8[..32] = [];
    for b in clean_ip {
        if b == '.' {
            guard parts.len < 4 else { return false; }
            parts.push(copy(cur));
            cur.clear();
        } else {
            if cur.len < 32 { cur.push(b); } else { return false; }
        }
    }
    guard parts.len < 4 else { return false; }
    parts.push(copy(cur));

    let n = parts.len;
    guard n >= 1 && n <= 4 else { return false; }

    var nums: u64[4] = [0, 0, 0, 0];
    for i in n {
        let val, ok = parse_ipv4_part(parts[i][..]);
        guard ok else { return false; }
        nums[i] = val;
    }

    var ip_u32: u64 = 0;
    if n == 1 {
        guard nums[0] <= 0xFFFFFFFF else { return false; }
        ip_u32 = nums[0];
    } else if n == 2 {
        guard nums[0] <= 0xFF && nums[1] <= 0xFFFFFF else { return false; }
        ip_u32 = (nums[0] << 24) | nums[1];
    } else if n == 3 {
        guard nums[0] <= 0xFF && nums[1] <= 0xFF && nums[2] <= 0xFFFF else { return false; }
        ip_u32 = (nums[0] << 24) | (nums[1] << 16) | nums[2];
    } else if n == 4 {
        guard nums[0] <= 0xFF && nums[1] <= 0xFF && nums[2] <= 0xFF && nums[3] <= 0xFF else { return false; }
        ip_u32 = (nums[0] << 24) | (nums[1] << 16) | (nums[2] << 8) | nums[3];
    }

    octets[0] = ((ip_u32 >> 24) & 0xFF) as u8;
    octets[1] = ((ip_u32 >> 16) & 0xFF) as u8;
    octets[2] = ((ip_u32 >> 8) & 0xFF) as u8;
    octets[3] = (ip_u32 & 0xFF) as u8;
    return true;
}

fn is_private_ipv4(clean_ip: const u8[:]) -> bool {
    var octets: u8[4] = [0, 0, 0, 0];
    guard parse_flexible_ipv4(clean_ip, octets) else { return false; }
    return is_private_ipv4_octets(octets[0], octets[1]);
}

fn is_private_ipv4_mapped_hex(suffix: const u8[:]) -> bool {
    var colon_idx = -1;
    for scan_idx in suffix.len {
        if suffix[scan_idx] == ':' {
            if colon_idx >= 0 { return false; }
            colon_idx = scan_idx;
        }
    }
    guard colon_idx > 0 && colon_idx + 1 < suffix.len else { return false; }
    let part1 = suffix[..colon_idx];
    let part2 = suffix[colon_idx + 1..];
    guard part1.len >= 1 && part1.len <= 4 && part2.len >= 1 && part2.len <= 4 else { return false; }

    var val1: i32 = 0;
    for char_byte in part1 {
        let hex_val = if char_byte >= '0' && char_byte <= '9' { (char_byte - '0') as i32 }
                      else if char_byte >= 'a' && char_byte <= 'f' { (char_byte - 'a' + 10) as i32 }
                      else if char_byte >= 'A' && char_byte <= 'F' { (char_byte - 'A' + 10) as i32 }
                      else { return false; };
        val1 = (val1 << 4) | hex_val;
    }

    var val2: i32 = 0;
    for char_byte in part2 {
        let hex_val = if char_byte >= '0' && char_byte <= '9' { (char_byte - '0') as i32 }
                      else if char_byte >= 'a' && char_byte <= 'f' { (char_byte - 'a' + 10) as i32 }
                      else if char_byte >= 'A' && char_byte <= 'F' { (char_byte - 'A' + 10) as i32 }
                      else { return false; };
        val2 = (val2 << 4) | hex_val;
    }

    let octet0 = (val1 >> 8) & 0xFF;
    let octet1 = val1 & 0xFF;
    return is_private_ipv4_octets(octet0, octet1);
}

// Whether host is localhost or a subdomain of localhost (RFC 6761 Section 6.3).
fn is_localhost_name(host: const u8[:]) -> bool {
    if eq_ascii_fold(host, "localhost") || eq_ascii_fold(host, "localhost.") {
        return true;
    }
    if ends_with(host, ".localhost") || ends_with(host, ".localhost.") {
        return true;
    }
    return false;
}

fn parse_hex_u16(s: const u8[:]) -> i32 {
    var val: i32 = 0;
    for b in s {
        let h = if b >= '0' && b <= '9' { (b - '0') as i32 }
                else if b >= 'a' && b <= 'f' { (b - 'a' + 10) as i32 }
                else if b >= 'A' && b <= 'F' { (b - 'A' + 10) as i32 }
                else { break; };
        val = (val << 4) | h;
    }
    return val;
}

fn is_private_or_reserved_ipv6(eff_ip: const u8[:]) -> bool {
    if eff_ip == "::1" || eff_ip == "::" {
        return true;
    }

    if starts_with(eff_ip, "fc") || starts_with(eff_ip, "fd") || // Unique Local fc00::/7
       starts_with(eff_ip, "fe8") || starts_with(eff_ip, "fe9") || // Link-local fe80::/10
       starts_with(eff_ip, "fea") || starts_with(eff_ip, "feb") ||
       starts_with(eff_ip, "fec") || starts_with(eff_ip, "fed") || // Site-local fec0::/10
       starts_with(eff_ip, "fee") || starts_with(eff_ip, "fef") ||
       starts_with(eff_ip, "ff") {                                 // Multicast ff00::/8
        return true;
    }

    // IPv4-mapped IPv6 (RFC 4291 ::ffff:x.x.x.x or ::ffff:hhhh:hhhh)
    if starts_with(eff_ip, "::ffff:") {
        let suffix = eff_ip[7..];
        return is_private_ipv4(suffix) || is_private_ipv4_mapped_hex(suffix);
    }

    // IPv4-compatible IPv6 (::x.x.x.x or ::hhhh:hhhh)
    if starts_with(eff_ip, "::") && !starts_with(eff_ip, "::ffff:") {
        let suffix = eff_ip[2..];
        return is_private_ipv4(suffix) || is_private_ipv4_mapped_hex(suffix);
    }

    // NAT64 well-known prefix 64:ff9b::/96
    if starts_with(eff_ip, "64:ff9b::") {
        let suffix = eff_ip[9..];
        if suffix.len == 0 { return true; } // 64:ff9b:: maps to 0.0.0.0
        return is_private_ipv4(suffix) || is_private_ipv4_mapped_hex(suffix);
    }

    // 6to4 prefix 2002::/16
    if starts_with(eff_ip, "2002:") {
        let rem = eff_ip[5..];
        var colon_idx = -1;
        for i in rem.len { if rem[i] == ':' { colon_idx = i; break; } }
        let p1 = if colon_idx > 0 { rem[..colon_idx] } else { rem };
        let hex_val1 = parse_hex_u16(p1);
        let o0 = (hex_val1 >> 8) & 0xFF;
        let o1 = hex_val1 & 0xFF;
        return is_private_ipv4_octets(o0, o1);
    }

    return false;
}

// Whether an IP address is a private, loopback, link-local, or multicast address.
// Strips IPv6 zone identifiers before testing.
fn is_private_or_reserved_ip(ip_str: const u8[:]) -> bool {
    guard ip_str.len > 0 else { return false; }

    if is_localhost_name(ip_str) {
        return true;
    }

    if ip_str == "::1" || ip_str == "[::1]" || ip_str == "::" || ip_str == "[::]" {
        return true;
    }
    var clean_ip = if ip_str.len > 2 && ip_str[0] == '[' && ip_str[ip_str.len - 1] == ']' {
        ip_str[1..ip_str.len - 1]
    } else {
        ip_str
    };

    var pct_idx = -1;
    for i in clean_ip.len {
        if clean_ip[i] == '%' { pct_idx = i; break; }
    }
    if pct_idx >= 0 {
        clean_ip = clean_ip[..pct_idx];
    }

    if clean_ip.len > 0 && clean_ip[clean_ip.len - 1] == '.' {
        clean_ip = clean_ip[..clean_ip.len - 1];
    }

    var lower_buf: u8[..64] = [];
    if clean_ip.len <= 64 {
        lower_buf.append(clean_ip);
        to_lower(lower_buf[..]);
    }
    let norm_ip = if lower_buf.len > 0 { lower_buf[..] } else { clean_ip };

    if is_localhost_name(norm_ip) || norm_ip == "::1" || norm_ip == "::" {
        return true;
    }

    var has_colon = false;
    for b in norm_ip { if b == ':' { has_colon = true; break; } }

    if has_colon {
        var comp_buf: u8[..64] = [];
        let ipv6_ok = core::parse_and_compress_ipv6(norm_ip, comp_buf);
        let eff_ip = if ipv6_ok { comp_buf[..] } else { norm_ip };
        return is_private_or_reserved_ipv6(eff_ip);
    }

    return is_private_ipv4(norm_ip);
}

fn is_dangerous_service_port(port_num: i32) -> bool {
    return port_num <= 0 ||      // Port 0 (reserved / loopback alias)
           port_num == 21 ||     // FTP
           port_num == 22 ||     // SSH
           port_num == 23 ||     // Telnet
           port_num == 25 ||     // SMTP
           port_num == 69 ||     // TFTP
           port_num == 110 ||    // POP3
           port_num == 143 ||    // IMAP
           port_num == 2375 ||   // Docker
           port_num == 2376 ||   // Docker TLS
           port_num == 2379 ||   // etcd client
           port_num == 2380 ||   // etcd peer
           port_num == 3306 ||   // MySQL
           port_num == 5432 ||   // PostgreSQL
           port_num == 6379 ||   // Redis
           port_num == 11211 ||  // Memcached
           port_num == 27017 ||  // MongoDB
           port_num == 28017;    // MongoDB Web Status
}

fn validate_url_against_ssrf(url_val: const core::Url&, policy: const SsrfGuardPolicy&) -> RedirectError {
    guard policy.enabled else { return RedirectError.None; }

    if policy.https_only && scheme(url_val) != "https" {
        return RedirectError.SchemeDowngradeBlocked;
    }

    let raw_port = url_val.port;
    let port_val = if raw_port == 0 { 0 } else { effective_port(url_val) };
    if policy.denied_ports.contains(port_val) {
        return RedirectError.SsrfBlockedUrl;
    }
    if policy.allowed_ports.len > 0 {
        if !policy.allowed_ports.contains(port_val) {
            return RedirectError.SsrfBlockedUrl;
        }
    } else if policy.deny_local_network && is_dangerous_service_port(port_val) {
        return RedirectError.SsrfBlockedUrl;
    }

    let host_str = hostname(url_val);
    if policy.deny_local_network {
        if is_private_or_reserved_ip(host_str) {
            return RedirectError.SsrfBlockedIp;
        }
    }

    return RedirectError.None;
}

fn validate_resolved_ips_against_ssrf(ips: const u8[:][:], policy: const SsrfGuardPolicy&) -> RedirectError {
    guard policy.enabled && policy.deny_local_network else { return RedirectError.None; }
    for ip in ips {
        if is_private_or_reserved_ip(ip) {
            return RedirectError.SsrfBlockedIp;
        }
    }
    return RedirectError.None;
}

// ---- mock routing for deterministic multi-hop testing ----------------------

struct MockExchange {
    pattern_url: u8[..256] = [],
    method: u8[..16] = [],
    status_code: i32 = 200,
    headers: HeaderItem[..16] = [],
    set_cookies: u8[..256][..8] = [],
    resolved_ips: u8[..64][..4] = [],
    body: u8[..2048] = [],
    protocol: u8[..16] = [],
    simulate_quic_blocked: bool = false,
}

// ---- client configuration and state ----------------------------------------

struct ClientConfig {
    base_url: const u8[:] = "",
    profile: Profile = Profile.Wing,
    proxy_url: const u8[:] = "",
    timeout_ms: i64 = 15000,
    follow_redirects: bool = true,
    cookie_jar: bool = true,
    enable_cache: bool = false,
    cache_options: CacheOptions = CacheOptions { .. },
    enable_altsvc: bool = true,
    enable_protocol_racing: bool = true,
    quic_race_delay_ms: i64 = 200,
    enable_compression_dict: bool = true,
}

type SessionConfig = ClientConfig;

struct Client {
    base_url: u8[..256] = [],
    profile: Profile = Profile.Wing,
    proxy_url: u8[..256] = [],
    timeout_ms: i64 = 15000,
    follow_redirects: bool = true,
    redirect_mode: RedirectMode = RedirectMode.Follow,
    max_redirects: i64 = 10,
    https_only: bool = false,
    enable_referer: bool = true,
    default_referrer_policy: ReferrerPolicy = ReferrerPolicy.StrictOriginWhenCrossOrigin,
    default_headers: HeaderItem[..16] = [],
    ssrf_guard: SsrfGuardPolicy = SsrfGuardPolicy { .. },
    virtual_clock_us: i64 = 1700000000000000,
    trusted_location_hosts: u8[..128][..8] = [],
    mock_routes: MockExchange[..16] = [],

    // RFC 9111 HTTP Cache Engine
    cache: HttpCache = HttpCache { .. },
    enable_cache: bool = false,

    // RFC 8484 DNS-over-HTTPS (DoH) & RFC 9460 Automated ECH Discovery
    doh: DohResolver = DohResolver { .. },
    enable_doh: bool = false,
    enable_ech: bool = false,
    auto_ech_discovery: bool = false,
    dns_cache: DnsCache = DnsCache { .. },

    // RFC 7838 Alt-Svc & Chromium Protocol Racing
    altsvc: AltSvcCache = AltSvcCache { .. },
    enable_altsvc: bool = true,
    enable_protocol_racing: bool = true,
    quic_race_delay_ms: i64 = 200,

    // Compression Dictionary Transport (Chrome 123+ dcz/dcb)
    dict_cache: DictionaryCache = DictionaryCache { .. },
    enable_compression_dict: bool = true,

    // OkHttp/Tower-style 2-tier Interceptor Pipeline (Application & Network)
    pipeline: InterceptorPipeline = InterceptorPipeline { .. },

    // Resizable field must be final
    jar: CanonicalCookieJar = CanonicalCookieJar { .. },
}

type Session = Client;

// ---- client factories ------------------------------------------------------

fn new_client() -> Client {
    var c = Client {
        profile: Profile.Wing,
        ssrf_guard: SsrfGuardPolicy { .. },
        cache: new_http_cache(),
        enable_cache: false,
        altsvc: new_altsvc_cache(),
        enable_altsvc: true,
        enable_protocol_racing: true,
        quic_race_delay_ms: 200,
        dict_cache: new_dictionary_cache(),
        enable_compression_dict: true,
        pipeline: new_interceptor_pipeline(),
        jar: new_canonical_cookie_jar(),
        ..
    };
    let def_p = wing_default_profile();
    apply_profile(c, def_p);
    return c;
}

fn new_client(cfg: ClientConfig) -> Client {
    var client = Client {
        profile: cfg.profile,
        timeout_ms: cfg.timeout_ms,
        follow_redirects: cfg.follow_redirects,
        ssrf_guard: SsrfGuardPolicy { .. },
        cache: new_http_cache(cfg.cache_options),
        enable_cache: cfg.enable_cache,
        altsvc: new_altsvc_cache(),
        enable_altsvc: cfg.enable_altsvc,
        enable_protocol_racing: cfg.enable_protocol_racing,
        quic_race_delay_ms: cfg.quic_race_delay_ms,
        dict_cache: new_dictionary_cache(),
        enable_compression_dict: cfg.enable_compression_dict,
        pipeline: new_interceptor_pipeline(),
        jar: new_canonical_cookie_jar(),
        ..
    };
    client.base_url.append(cfg.base_url);
    client.proxy_url.append(cfg.proxy_url);
    if cfg.profile != Profile.None {
        set_profile(client, cfg.profile);
    }
    return client;
}

fn new_client(base_url: const u8[:]) -> Client {
    var client = new_client();
    client.base_url.append(base_url);
    return client;
}

fn new_client<F: fn(Client&)>(base_url: const u8[:]) -> Client {
    var client = new_client(base_url);
    F(&client);
    return client;
}

fn new_client<F: fn(Client&)>() -> Client {
    var client = new_client();
    F(&client);
    return client;
}

// Backward-compatible session factory aliases
inline fn new_session() -> Client { return new_client(); }
inline fn new_session(cfg: ClientConfig) -> Client { return new_client(cfg); }
inline fn new_session(base_url: const u8[:]) -> Client { return new_client(base_url); }

// ---- ufcs session mutators & configuration ---------------------------------

fn set_base_url(session: Session&, url: const u8[:]) {
    session.base_url.clear();
    session.base_url.append(url);
}

fn apply_profile(client: Client&, profile: const BrowserProfile&) {
    client.profile = match profile.kind {
        Wing => Profile.Wing,
        Custom => Profile.Custom,
        None => Profile.None,
    };
    client.default_headers.clear();
    if profile.user_agent.len > 0 {
        client.default_headers.push(make_header("User-Agent", profile.user_agent[..]));
    }
    if profile.accept.len > 0 {
        client.default_headers.push(make_header("Accept", profile.accept[..]));
    }
    if profile.accept_encoding.len > 0 {
        client.default_headers.push(make_header("Accept-Encoding", profile.accept_encoding[..]));
    }
    if profile.accept_language.len > 0 {
        client.default_headers.push(make_header("Accept-Language", profile.accept_language[..]));
    }
    if profile.upgrade_insecure_requests.len > 0 {
        client.default_headers.push(make_header("Upgrade-Insecure-Requests", profile.upgrade_insecure_requests[..]));
    }
    for &h in profile.extra_headers {
        if client.default_headers.len < client.default_headers.cap {
            client.default_headers.push(copy(h));
        }
    }
}

fn set_profile(session: Session&, profile: Profile) {
    session.profile = profile;
    if profile == Profile.None {
        session.default_headers.clear();
        return;
    }
    if profile == Profile.Wing {
        let p = wing_default_profile();
        apply_profile(session, p);
    }
}

fn set_profile(session: Session&, profile: const BrowserProfile&) {
    apply_profile(session, profile);
}

fn set_user_agent(session: Session&, ua: const u8[:]) {
    for idx in session.default_headers.len {
        if eq_ascii_fold(session.default_headers[idx].name[..], "user-agent") {
            session.default_headers[idx].value.clear();
            session.default_headers[idx].value.append(ua);
            return;
        }
    }
    if session.default_headers.len < session.default_headers.cap {
        session.default_headers.push(make_header("User-Agent", ua));
    }
}

fn user_agent(session: const Session&) -> const u8[:] {
    for &h in session.default_headers {
        if eq_ascii_fold(h.name[..], "user-agent") {
            return h.value[..];
        }
    }
    return profile_user_agent(session.profile);
}

fn session_ja4(session: const Session&, is_quic: bool = false, sni: bool = true) -> u8[..64] {
    let p = wing_default_profile();
    return profile_ja4(p, is_quic, sni);
}

fn session_p0f(session: const Session&) -> u8[..128] {
    let p = wing_default_profile();
    return profile_p0f(p);
}

fn set_proxy(session: Session&, proxy_url: const u8[:]) {
    session.proxy_url.clear();
    session.proxy_url.append(proxy_url);
}

fn set_timeout_ms(session: Session&, ms: i64) {
    session.timeout_ms = ms;
}

fn set_redirect_mode(session: Session&, mode: RedirectMode) {
    session.redirect_mode = mode;
    session.follow_redirects = (mode == RedirectMode.Follow);
}

fn set_max_redirects(session: Session&, count: i64) {
    session.max_redirects = count;
}

fn set_https_only(session: Session&, enabled: bool) {
    session.https_only = enabled;
    session.ssrf_guard.https_only = enabled;
}

fn set_enable_referer(session: Session&, enabled: bool) {
    session.enable_referer = enabled;
}

fn set_referrer_policy(session: Session&, policy: ReferrerPolicy) {
    session.default_referrer_policy = policy;
}

fn enable_ssrf_guard(session: Session&, deny_local_network: bool = true) {
    session.ssrf_guard.enabled = true;
    session.ssrf_guard.deny_local_network = deny_local_network;
}

// ---- dns-over-https & automated ech discovery (rfc 8484, rfc 9460) ----------

fn enable_doh(session: Session&, endpoint: const u8[:] = "https://cloudflare-dns.com/dns-query", use_post: bool = true) {
    session.enable_doh = true;
    session.doh.endpoint.clear();
    session.doh.endpoint.append(endpoint);
    session.doh.use_post = use_post;
}

fn enable_ech(session: Session&, auto_discover: bool = true) {
    session.enable_ech = true;
    session.auto_ech_discovery = auto_discover;
    if auto_discover && !session.enable_doh {
        session.enable_doh = true;
    }
}

// Dispatches a DNS-over-HTTPS wire query using the session's HTTP client transport.
fn doh_query(
    session: Session&,
    domain: const u8[:],
    qtype: u16,
    tx_id: u16,
    out_resp: DnsResponse&
) -> bool {
    var req = new_request(if session.doh.use_post { "POST" } else { "GET" }, "");

    if session.doh.use_post {
        req.url.append(session.doh.endpoint[..]);
        var ct = HeaderItem { .. };
        ct.name.append("content-type");
        ct.value.append("application/dns-message");
        req.headers.push(ct);

        var ac = HeaderItem { .. };
        ac.name.append("accept");
        ac.value.append("application/dns-message");
        req.headers.push(ac);

        guard build_dns_query(domain, qtype, tx_id, req.body) else { return false; }
    } else {
        guard build_doh_get_url(session.doh.endpoint[..], domain, qtype, req.url) else { return false; }
        var ac = HeaderItem { .. };
        ac.name.append("accept");
        ac.value.append("application/dns-message");
        req.headers.push(ac);
    }

    let res, err = do(session, req);
    guard ok(err) && res.status_code == 200 else { return false; }

    return parse_dns_response(res.body[..], out_resp);
}

// Discovers or extracts ECHConfigList for a domain.
// First checks local DnsCache; if missing/expired and DoH is enabled, performs RFC 9460 Type 65 discovery.
fn resolve_ech_config(
    session: Session&,
    domain: const u8[:],
    now_sec: i64,
    out_ech: u8[..512]&
) -> bool {
    out_ech.clear();

    // 1. Check local cache
    var cached = DnsCacheEntry { .. };
    let cache_status = dns_cache_lookup(session.dns_cache, domain, DNS_QTYPE_HTTPS, now_sec, cached);
    if cache_status == DnsCacheStatus.Fresh || cache_status == DnsCacheStatus.Stale {
        for &rec in cached.https_records {
            if rec.has_ech && rec.ech_config_list.len > 0 {
                out_ech.append(rec.ech_config_list[..]);
                return true;
            }
        }
    }

    // 2. Automated discovery via DoH
    guard session.enable_doh && session.auto_ech_discovery else { return false; }

    var dns_resp = DnsResponse { .. };
    guard doh_query(session, domain, DNS_QTYPE_HTTPS, 0x1234, dns_resp) else { return false; }

    // Cache the response
    var cache_entry = DnsCacheEntry {
        qtype: DNS_QTYPE_HTTPS,
        inserted_at_sec: now_sec,
        ttl_sec: 300,
        valid: true,
        ..
    };
    cache_entry.domain.append(domain);

    var found_ech = false;
    for &rec in dns_resp.https_records {
        if cache_entry.https_records.len < 4 {
            cache_entry.https_records.push(rec);
        }
        if rec.has_ech && rec.ech_config_list.len > 0 && !found_ech {
            out_ech.append(rec.ech_config_list[..]);
            found_ech = true;
        }
    }

    dns_cache_insert(session.dns_cache, cache_entry);
    return found_ech;
}

// ---- alt-svc & protocol racing configuration (rfc 7838, rfc 8305) ----------

fn enable_altsvc(session: Session&, enabled: bool = true) {
    session.enable_altsvc = enabled;
}

fn enable_protocol_racing(session: Session&, enabled: bool = true, quic_delay_ms: i64 = 200) {
    session.enable_protocol_racing = enabled;
    session.quic_race_delay_ms = quic_delay_ms;
}

fn clear_altsvc_cache(session: Session&) {
    session.altsvc = new_altsvc_cache();
}

fn altsvc_cache(session: const Session&) -> const AltSvcCache& {
    return session.altsvc;
}

fn has_altsvc_h3(session: const Session&, target: const u8[:]) -> bool {
    var origin_buf: u8[..128] = [];
    resolve_target_origin(target, origin_buf);
    let now_sec = session.virtual_clock_us / 1000000;
    var ep = AltSvcEndpoint { .. };
    return altsvc_lookup_h3(session.altsvc, origin_buf[..], now_sec, ep);
}

fn is_altsvc_broken(session: const Session&, target: const u8[:]) -> bool {
    var origin_buf: u8[..128] = [];
    resolve_target_origin(target, origin_buf);
    let now_sec = session.virtual_clock_us / 1000000;
    return altsvc_is_broken(session.altsvc, origin_buf[..], now_sec);
}

// ---- compression dictionary transport configuration (chrome 123+ dcz/dcb) --

fn enable_compression_dict(session: Session&, enabled: bool = true) {
    session.enable_compression_dict = enabled;
}

fn clear_dictionary_cache(session: Session&) {
    session.dict_cache = new_dictionary_cache();
}

fn dictionary_cache(session: const Session&) -> const DictionaryCache& {
    return session.dict_cache;
}

fn has_dictionary_for(session: const Session&, target_url: const u8[:]) -> bool {
    var origin_buf: u8[..128] = [];
    resolve_target_origin(target_url, origin_buf);
    var path_buf: u8[..256] = [];
    let parsed, err = core::parse_url(target_url);
    if parsed.valid {
        path_buf.append(core::pathname(parsed));
    } else {
        path_buf.append("/");
    }
    let now_sec = session.virtual_clock_us / 1000000;
    var dummy_hash: u8[..64] = [];
    return dictionary_lookup_for_request(session.dict_cache, origin_buf[..], path_buf[..], now_sec, dummy_hash);
}

// ---- interceptor pipeline configuration (okhttp/tower-style) ---------------

fn add_app_logging(session: Session&, level: LogLevel = LogLevel.Basic) -> bool {
    return add_pipeline_logging(session.pipeline, InterceptorScope.Application, level);
}

fn add_network_logging(session: Session&, level: LogLevel = LogLevel.Basic) -> bool {
    return add_pipeline_logging(session.pipeline, InterceptorScope.Network, level);
}

fn add_app_bearer_auth(session: Session&, token: const u8[:]) -> bool {
    return add_pipeline_bearer_auth(session.pipeline, token);
}

fn add_app_header(session: Session&, name: const u8[:], val: const u8[:]) -> bool {
    return add_pipeline_header(session.pipeline, InterceptorScope.Application, name, val);
}

fn add_network_header(session: Session&, name: const u8[:], val: const u8[:]) -> bool {
    return add_pipeline_header(session.pipeline, InterceptorScope.Network, name, val);
}

fn add_app_request_id(session: Session&, prefix: const u8[:] = "req-") -> bool {
    return add_pipeline_request_id(session.pipeline, prefix);
}

fn add_app_traceparent(session: Session&, sample_flag: const u8[:] = "01") -> bool {
    return add_pipeline_traceparent(session.pipeline, sample_flag);
}

fn add_app_retry(session: Session&, max_retries: i32, retry_on_5xx: bool = true) -> bool {
    return add_pipeline_retry(session.pipeline, max_retries, retry_on_5xx);
}

fn add_network_metrics(session: Session&) -> bool {
    return add_pipeline_metrics(session.pipeline);
}

fn network_metrics(session: const Session&) -> const NetworkMetrics& {
    return session.pipeline.metrics;
}

fn pipeline_logs(session: const Session&) -> const u8[..128][:] {
    return session.pipeline.log_entries[..];
}

fn clear_pipeline_logs(session: Session&) {
    session.pipeline.log_entries.clear();
}

fn allow_port(session: Session&, port_num: i32) {
    if session.ssrf_guard.allowed_ports.len < 16 {
        session.ssrf_guard.allowed_ports.push(port_num);
    }
}

fn deny_port(session: Session&, port_num: i32) {
    if session.ssrf_guard.denied_ports.len < 16 {
        session.ssrf_guard.denied_ports.push(port_num);
    }
}

fn set_clock_us(session: Session&, now_us: i64) {
    session.virtual_clock_us = now_us;
}

fn trust_location_host(session: Session&, host_name: const u8[:]) {
    if session.trusted_location_hosts.len < 8 {
        var host_buf: u8[..128] = [];
        host_buf.append(host_name);
        to_lower(host_buf[..]);
        session.trusted_location_hosts.push(host_buf);
    }
}

fn is_trusted_location_host(session: const Session&, host_name: const u8[:]) -> bool {
    return session.trusted_location_hosts.any() { eq_ascii_fold(it[..], host_name) };
}

fn mock_route(
    session: Session&,
    method: const u8[:],
    pattern_url: const u8[:],
    status_code: i32,
    body_str: const u8[:]
) -> MockExchange& {
    var route = MockExchange {
        status_code: status_code,
        ..
    };
    route.method.append(method);
    route.pattern_url.append(pattern_url);
    route.body.append(body_str);
    return session.mock_routes.push(route);
}

fn add_mock_set_cookie(route: MockExchange&, set_cookie_raw: const u8[:]) {
    if route.set_cookies.len < 8 {
        var cookie_buf: u8[..256] = [];
        cookie_buf.append(set_cookie_raw);
        route.set_cookies.push(cookie_buf);
    }
}

fn add_mock_set_cookie(session: Session&, set_cookie_raw: const u8[:]) {
    if session.mock_routes.len > 0 {
        add_mock_set_cookie(session.mock_routes[session.mock_routes.len - 1], set_cookie_raw);
    }
}

fn add_mock_header(route: MockExchange&, name: const u8[:], value: const u8[:]) {
    if route.headers.len < 16 {
        route.headers.push(make_header(name, value));
    }
}

fn add_mock_header(session: Session&, name: const u8[:], value: const u8[:]) {
    if session.mock_routes.len > 0 {
        add_mock_header(session.mock_routes[session.mock_routes.len - 1], name, value);
    }
}

fn add_mock_resolved_ip(route: MockExchange&, ip_str: const u8[:]) {
    if route.resolved_ips.len < 4 {
        var ip_buf: u8[..64] = [];
        ip_buf.append(ip_str);
        route.resolved_ips.push(ip_buf);
    }
}

fn add_mock_resolved_ip(session: Session&, ip_str: const u8[:]) {
    if session.mock_routes.len > 0 {
        add_mock_resolved_ip(session.mock_routes[session.mock_routes.len - 1], ip_str);
    }
}

fn set_mock_quic_blocked(route: MockExchange&, blocked: bool = true) {
    route.simulate_quic_blocked = blocked;
}

fn set_mock_quic_blocked(session: Session&, blocked: bool = true) {
    if session.mock_routes.len > 0 {
        set_mock_quic_blocked(session.mock_routes[session.mock_routes.len - 1], blocked);
    }
}

fn set_mock_protocol(route: MockExchange&, proto: const u8[:]) {
    route.protocol.clear();
    route.protocol.append(proto);
}

fn set_mock_protocol(session: Session&, proto: const u8[:]) {
    if session.mock_routes.len > 0 {
        set_mock_protocol(session.mock_routes[session.mock_routes.len - 1], proto);
    }
}

fn add_mock_websocket(session: Session&, url_pattern: const u8[:], subprotocol: const u8[:] = "") {
    var route = MockExchange {
        status_code: 101,
        ..
    };
    route.method.append("GET");
    route.pattern_url.append(url_pattern);
    route.headers.push(make_header("Upgrade", "websocket"));
    route.headers.push(make_header("Connection", "Upgrade"));
    if subprotocol.len > 0 {
        route.headers.push(make_header("Sec-WebSocket-Protocol", subprotocol));
    }
    session.mock_routes.push(route);
}

fn add_mock_sse(session: Session&, url_pattern: const u8[:], sample_events: const u8[:] = "") {
    var route = MockExchange {
        status_code: 200,
        ..
    };
    route.method.append("GET");
    route.pattern_url.append(url_pattern);
    route.headers.push(make_header("Content-Type", "text/event-stream"));
    route.headers.push(make_header("Cache-Control", "no-cache"));
    route.headers.push(make_header("Connection", "keep-alive"));
    if sample_events.len > 0 {
        route.body.append(sample_events);
    }
    session.mock_routes.push(route);
}

fn set_cookie(session: Session&, name: const u8[:], value: const u8[:]) {
    var raw_hdr: u8[..2048] = [];
    raw_hdr.append(name);
    raw_hdr.push('=');
    raw_hdr.append(value);
    raw_hdr.append("; Path=/");
    if session.base_url.len > 0 {
        session.jar.set_cookie_header(session.base_url[..], raw_hdr[..], session.virtual_clock_us);
    } else {
        session.jar.set_cookie_header("https://example.com/", raw_hdr[..], session.virtual_clock_us);
    }
}

fn cookie(session: const Session&, name: const u8[:]) -> const u8[:] {
    return session.jar.get(name);
}

fn default_header(session: Session&, name: const u8[:], value: const u8[:]) {
    if session.default_headers.len < 16 {
        session.default_headers.push(make_header(name, value));
    }
}

// ---- url resolution helper -------------------------------------------------

// Appends query parameters to a URL buffer, preserving trailing fragment if present (RFC 3986 Section 4.1).
fn append_query_params_preserving_fragment(
    out: u8[..2048]&,
    query_params: const QueryItem[:]
) {
    guard query_params.len > 0 else { return; }

    var hash_pos = -1;
    var has_query_mark = false;
    for scan_idx in out.len {
        let b = out[scan_idx];
        if b == '?' && hash_pos < 0 { has_query_mark = true; }
        else if b == '#' && hash_pos < 0 { hash_pos = scan_idx; }
    }

    var hash_buf: u8[..512] = [];
    if hash_pos >= 0 {
        hash_buf.append(out[hash_pos..]);
        out.resize(hash_pos);
    }

    for &query_item, param_idx in query_params {
        if param_idx == 0 && !has_query_mark {
            out.push('?');
        } else {
            out.push('&');
        }
        out.append(query_item.key[..]);
        out.push('=');
        out.append(query_item.value[..]);
    }

    if hash_buf.len > 0 {
        out.append(hash_buf[..]);
    }
}

// Builds the effective request URL from base_url, req_url, and query_params.
// Fragments are preserved and appended after query parameters (RFC 3986 Section 4.1).
fn build_effective_url(
    base_url: const u8[:],
    req_url: const u8[:],
    query_params: const QueryItem[:],
    out: u8[..2048]&
) {
    out.clear();
    let parsed_base = core::new_url(base_url);
    if parsed_base.valid {
        let eff_url = resolve_endpoint(parsed_base, req_url);
        out.append(href(eff_url));
    } else if req_url.len >= 7 && (req_url[..7] == "http://" || (req_url.len >= 8 && req_url[..8] == "https://")) {
        out.append(req_url);
    } else {
        out.append(base_url);
        if base_url.len > 0 && base_url[base_url.len - 1] != '/' && (req_url.len == 0 || req_url[0] != '/') {
            out.push('/');
        }
        out.append(req_url);
    }

    append_query_params_preserving_fragment(out, query_params);
}

// ---- 6-phase execution pipeline (execute_pipeline) -------------------------

struct RequestExecutionContext {
    url_chain: core::Url[..16] = [],
    current_method: u8[..16] = [],
    headers: HeaderItem[..32] = [],
    rewind_buf: u8[..4096] = [],
    rewindable: bool = true,
    body_consumed: bool = false,
    initiator: core::Origin = core::Origin { .. },
    has_initiator: bool = false,
    top_frame_origin: core::Origin = core::Origin { .. },
    site_for_cookies: SiteForCookies = SiteForCookies { .. },
    first_party_policy: FirstPartyURLPolicy = FirstPartyURLPolicy.UPDATE_FIRST_PARTY_URL_ON_REDIRECT,
    is_main_frame: bool = true,
    is_reload: bool = false,
    redirect_mode: RedirectMode = RedirectMode.Follow,
    redirect_count: i64 = 0,
    max_redirects: i64 = 10,
    tainted_origin: bool = false,
    had_cross_site_hop: bool = false,
    cors_mode: bool = false,
    current_referrer: u8[..2048] = [],
    current_referrer_policy: ReferrerPolicy = ReferrerPolicy.StrictOriginWhenCrossOrigin,
    body: u8[>..] = [],
}

fn validate_hop_prerequisites(session: const Session&, current_url: const core::Url&) -> Error {
    if session.https_only && scheme(current_url) != "https" {
        return make_error(400, "ssrf_guard", "https_only policy violated");
    }
    let ssrf_err = validate_url_against_ssrf(current_url, session.ssrf_guard);
    if ssrf_err != RedirectError.None {
        return make_error(403, "ssrf_guard", redirect_error_to_string(ssrf_err));
    }
    return no_error();
}

fn compute_hop_samesite_context(
    ctx: const RequestExecutionContext&,
    current_url: const core::Url&,
    safe_method: bool,
) -> SameSiteCookieContext {
    var samesite_ctx_type = SameSiteContextType.CrossSite;
    let is_first_p = is_first_party(ctx.site_for_cookies, href(current_url), true);

    if ctx.is_main_frame {
        if ctx.had_cross_site_hop {
            samesite_ctx_type = if safe_method { SameSiteContextType.SameSiteLax } else { SameSiteContextType.CrossSite };
        } else if is_first_p {
            samesite_ctx_type = SameSiteContextType.SameSiteStrict;
        } else if safe_method {
            samesite_ctx_type = SameSiteContextType.SameSiteLax;
        } else {
            samesite_ctx_type = SameSiteContextType.SameSiteLaxMethodUnsafe;
        }
    } else {
        if ctx.had_cross_site_hop || !is_first_p {
            samesite_ctx_type = SameSiteContextType.CrossSite;
        } else {
            samesite_ctx_type = SameSiteContextType.SameSiteStrict;
        }
    }

    return SameSiteCookieContext {
        context_type: samesite_ctx_type,
        schemefully_same: ctx.site_for_cookies.schemefully_same,
        is_reload: ctx.is_reload,
        had_cross_site_hop: ctx.had_cross_site_hop,
    };
}

fn prepare_hop_cookie_header(
    session: Session&,
    ctx: RequestExecutionContext&,
    current_url: const core::Url&,
    samesite_eval: const SameSiteCookieContext&,
    safe_method: bool,
) {
    var matched_cookies: CanonicalCookie[>..] = [];
    let is_sec_channel = current_url.is_secure_scheme() || is_trustworthy_non_crypto_host(current_url.hostname());
    session.jar.get_canonical_cookies_for_request(
        current_url.hostname(),
        current_url.pathname(),
        current_url.scheme(),
        current_url.effective_port(),
        is_sec_channel,
        true,
        "",
        session.virtual_clock_us,
        matched_cookies,
        samesite_eval.context_type != SameSiteContextType.CrossSite,
        ctx.is_main_frame,
        safe_method
    );

    remove_header_by_name(ctx.headers, "Cookie");
    if matched_cookies.len > 0 {
        var cookie_hdr_val: u8[..2048] = [];
        format_cookie_header_value(cookie_hdr_val, matched_cookies[..]);
        if cookie_hdr_val.len > 0 && ctx.headers.len < 32 {
            ctx.headers.push(make_header("Cookie", cookie_hdr_val[..], true));
        }
    }
}

fn ingest_hop_response_cookies(
    session: Session&,
    ctx: const RequestExecutionContext&,
    current_url: const core::Url&,
    samesite_eval: const SameSiteCookieContext&,
    set_cookies: const u8[..256][..16]&,
) {
    for &set_cookie_str in set_cookies {
        var def_path: u8[..256] = [];
        default_cookie_path_calc(current_url.pathname(), def_path);
        var parsed_cookie, parse_cause, cookie_ok = parse_canonical_set_cookie(set_cookie_str[..], current_url.hostname(), def_path[..], session.virtual_clock_us);
        if cookie_ok {
            let is_sec_channel = current_url.is_secure_scheme() || is_trustworthy_non_crypto_host(current_url.hostname());
            let can_write, code = can_set_canonical_cookie_for_context(
                parsed_cookie,
                samesite_eval,
                ctx.is_main_frame,
                is_sec_channel
            );
            if can_write {
                session.jar.set_cookie_header(current_url.href[..], set_cookie_str[..], session.virtual_clock_us);
            }
        }
    }
}

fn finalize_success_response(ctx: const RequestExecutionContext&, resp: Response&) {
    resp.redirect_count = ctx.redirect_count;
    resp.final_method.clear();
    resp.final_method.append(ctx.current_method[..]);
    for &hop_u in ctx.url_chain {
        if resp.url_chain.len < 16 {
            var u_str: u8[..256] = [];
            u_str.append(href(hop_u));
            resp.url_chain.push(u_str);
        }
    }
}

fn apply_redirect_transition(
    session: const Session&,
    ctx: RequestExecutionContext&,
    redirect_info: const RedirectInfo&,
) -> Error {
    ctx.had_cross_site_hop = ctx.had_cross_site_hop || redirect_info.is_cross_site_tainted;
    ctx.site_for_cookies = redirect_info.new_site_for_cookies;
    ctx.current_method.clear();
    ctx.current_method.append(redirect_info.new_method[..]);
    ctx.current_referrer.clear();
    ctx.current_referrer.append(redirect_info.new_referrer[..]);
    ctx.current_referrer_policy = redirect_info.new_referrer_policy;

    if redirect_info.clear_body {
        ctx.body.clear();
        ctx.body_consumed = false;
    } else {
        // 307 or 308 redirect preserves method and body
        if !ctx.rewindable && ctx.body_consumed {
            return make_error(400, "body_rewind", "http: cannot rewind body");
        }
        ctx.body.clear();
        ctx.body.append(ctx.rewind_buf[..]);
        ctx.body_consumed = false;
    }

    let is_trusted = is_trusted_location_host(session, hostname(redirect_info.new_url));
    sanitize_headers_on_redirect(
        ctx.headers,
        redirect_info,
        ctx.cors_mode,
        ctx.tainted_origin,
        session.enable_referer,
        is_trusted
    );
    return no_error();
}

fn init_execution_context(session: const Session&, req: const Request&, parsed_initial: const core::Url&) -> RequestExecutionContext {
    var ctx = RequestExecutionContext {
        current_method: copy(req.method),
        rewindable: req.rewindable,
        body_consumed: false,
        cors_mode: req.cors_mode,
        tainted_origin: req.tainted_origin,
        is_main_frame: req.is_main_frame,
        is_reload: req.is_reload,
        redirect_mode: session.redirect_mode,
        redirect_count: 0,
        max_redirects: session.max_redirects,
        first_party_policy: req.first_party_policy,
        current_referrer_policy: session.default_referrer_policy,
        ..
    };

    ctx.body.append(req.body[..]);
    ctx.rewind_buf.append(req.rewind_buf[..]);

    if req.has_initiator {
        ctx.initiator = copy(req.initiator);
        ctx.has_initiator = true;
    } else {
        ctx.initiator = core::origin_from_url(parsed_initial);
        ctx.has_initiator = true;
    }

    if req.has_site_for_cookies {
        ctx.site_for_cookies = copy(req.site_for_cookies);
    } else {
        ctx.site_for_cookies = site_for_cookies_from_parsed_url(parsed_initial);
    }

    for &default_hdr in session.default_headers {
        ctx.headers.push(copy(default_hdr));
    }
    for &req_hdr in req.headers {
        ctx.headers.push(copy(req_hdr));
    }

    ctx.url_chain.push(parsed_initial);
    return ctx;
}

fn process_redirect_hop(
    session: Session&,
    ctx: RequestExecutionContext&,
    resp: Response&,
    current_url: const core::Url&,
    loc_hdr: const u8[:],
) -> bool, Error {
    if ctx.redirect_mode == RedirectMode.Manual {
        resp.redirect_count = ctx.redirect_count;
        return false, no_error();
    }
    if ctx.redirect_mode == RedirectMode.Error {
        return false, make_error(310, "redirect", "redirects disabled by mode");
    }
    if ctx.redirect_count >= ctx.max_redirects {
        return false, make_error(310, "redirect", "maximum redirect hops exceeded");
    }

    let ref_policy_hdr = header(resp, "Referrer-Policy");
    let redirect_info = compute_redirect_info(
        resp.status_code,
        ctx.current_method[..],
        current_url,
        loc_hdr,
        ref_policy_hdr,
        ctx.current_referrer_policy,
        ctx.current_referrer[..],
        ctx.site_for_cookies,
        ctx.first_party_policy,
        ctx.url_chain[..],
        ctx.initiator,
        ctx.has_initiator,
        ctx.cors_mode,
        ctx.tainted_origin,
        ctx.is_main_frame,
        ctx.had_cross_site_hop
    );

    guard redirect_info.error == RedirectError.None else {
        return false, make_error(310, "redirect", redirect_error_to_string(redirect_info.error));
    }

    let redirect_err = apply_redirect_transition(session, ctx, redirect_info);
    guard ok(redirect_err) else { return false, redirect_err; }

    ctx.url_chain.push(redirect_info.new_url);
    ctx.redirect_count += 1;
    return true, no_error();
}

fn execute_request_inner(session: Client&, req: const Request&) -> Response, Error {
    var raw_eff_url: u8[..2048] = [];
    build_effective_url(session.base_url[..], req.url[..], req.query_params[..], raw_eff_url);

    let parsed_initial, parse_err = core::parse_url(raw_eff_url[..]);
    guard parsed_initial.valid else {
        return Response { .. }, make_error(400, "url_parse", "invalid request url");
    }

    var cache_ts = CacheTimestamps {
        request_time: core::unix(session.virtual_clock_us / 1000000, ((session.virtual_clock_us % 1000000) * 1000) as u32),
        now: core::unix(session.virtual_clock_us / 1000000, ((session.virtual_clock_us % 1000000) * 1000) as u32),
    };

    var cache_revalidate_idx: i64 = -1;

    // Phase 0: RFC 9111 HTTP Cache Lookup
    if session.enable_cache {
        var lookup_req = copy(req);
        lookup_req.url.clear();
        lookup_req.url.append(raw_eff_url[..]);
        let lookup_dec = lookup(session.cache, lookup_req, cache_ts.now);
        if lookup_dec.kind == LookupResultKind.Hit {
            return copy(lookup_dec.cached_response), no_error();
        } else if lookup_dec.kind == LookupResultKind.Fail504 {
            var fail_resp = Response {
                status_code: 504,
                effective_url: copy(raw_eff_url),
                ..
            };
            return fail_resp, make_error(504, "cache", "504 Gateway Timeout (only-if-cached miss)");
        } else if lookup_dec.kind == LookupResultKind.Revalidate {
            cache_revalidate_idx = lookup_dec.entry_idx;
        }
    }

    var ctx = init_execution_context(session, req, parsed_initial);

    // If cache revalidation is needed, inject conditional headers into ctx
    if cache_revalidate_idx >= 0 && cache_revalidate_idx < session.cache.entries.len {
        let cond_map = session.cache.entries[cache_revalidate_idx].build_revalidation_headers();
        for &c_entry in cond_map.entries {
            let c_name = cond_map.raw_buf[c_entry.name_begin..c_entry.name_end];
            let c_val = cond_map.raw_buf[c_entry.values_begin..c_entry.values_end];
            ctx.headers.push(make_header(c_name, c_val));
        }
    }

    // Main redirect execution loop (Chromium net::URLRequest 6-phase pipeline)
    while ctx.redirect_count <= ctx.max_redirects {
        let current_url = ctx.url_chain[ctx.url_chain.len - 1];

        // Phase 1: Pre-validation of Hop
        let pre_err = validate_hop_prerequisites(session, current_url);
        guard ok(pre_err) else { return Response { .. }, pre_err; }

        // Phase 2 & 3: Compute SameSite Context & Synthesize Fresh Cookie Header
        let safe_method = is_safe_http_method(ctx.current_method[..]);
        let samesite_eval = compute_hop_samesite_context(ctx, current_url, safe_method);
        prepare_hop_cookie_header(session, ctx, current_url, samesite_eval, safe_method);

        // Phase 3.5: Network Interceptors (Request Hook)
        let hop_start_us = session.virtual_clock_us;
        apply_network_interceptors_request(session.pipeline, ctx.headers, current_url.href[..], ctx.current_method[..], ctx.body.len, ctx.redirect_count);

        // Phase 4: Network Transaction & Ingest Set-Cookie Before 3xx Analysis
        var dns_rebinding_err = RedirectError.None;
        var resp = execute_mock_or_echo_hop(session, ctx, current_url, dns_rebinding_err);
        guard dns_rebinding_err == RedirectError.None else {
            return Response { .. }, make_error(403, "ssrf_guard", redirect_error_to_string(dns_rebinding_err));
        }

        // Phase 4.2: Network Interceptors (Response Hook)
        let hop_dur_us = session.virtual_clock_us - hop_start_us;
        apply_network_interceptors_response(session.pipeline, resp, ctx.redirect_count, hop_dur_us);

        ctx.body_consumed = true;
        ingest_hop_response_cookies(session, ctx, current_url, samesite_eval, resp.set_cookies);

        // Phase 4.5: RFC 9111 HTTP Cache Update & 304 Freshening
        if session.enable_cache {
            cache_ts.response_time = cache_ts.now;
            var hop_req = copy(req);
            hop_req.url.clear();
            hop_req.url.append(current_url.href[..]);
            let resp_dec = on_response(session.cache, hop_req, resp, cache_ts, cache_revalidate_idx);
            if resp_dec.kind == ResponseDecisionKind.FreshenAndReturn {
                resp = copy(resp_dec.response);
            }
        }

        // Phase 5: 3xx Detection & ComputeRedirectInfo
        let loc_hdr = header(resp, "Location");
        let is_red = is_redirect(resp) && loc_hdr.len > 0;

        if is_red {
            session.pipeline.metrics.redirect_hops += 1;
        }

        if !is_red {
            finalize_success_response(ctx, resp);
            return resp, no_error();
        }

        let should_continue, red_err = process_redirect_hop(session, ctx, resp, current_url, loc_hdr);
        guard ok(red_err) else { return resp, red_err; }
        if !should_continue {
            return resp, no_error();
        }
    }

    return Response { .. }, make_error(310, "redirect", "maximum redirect hops exceeded");
}

fn execute_request(session: Client&, req: const Request&) -> Response, Error {
    let start_us = session.virtual_clock_us;

    // Phase -1: Application Interceptors (Request Hook)
    var active_req = copy(req);
    apply_app_interceptors_request(session.pipeline, active_req, start_us);

    var max_retries: i32 = 0;
    var retry_5xx: bool = false;
    let has_retry = find_retry_policy(session.pipeline, max_retries, retry_5xx);

    var attempts: i32 = 0;
    while true {
        let resp, err = execute_request_inner(session, active_req);
        if has_retry && attempts < max_retries {
            if !ok(err) || (retry_5xx && resp.status_code >= 500 && resp.status_code <= 599) {
                attempts += 1;
                continue;
            }
        }

        // Phase 6: Application Interceptors (Response Hook)
        var final_resp = resp;
        let total_dur_us = session.virtual_clock_us - start_us;
        apply_app_interceptors_response(session.pipeline, active_req, final_resp, err, total_dur_us);
        return copy(final_resp), err;
    }
    return Response { .. }, make_error(500, "client", "request execution failed");
}

fn validate_mock_route_dns(route: const MockExchange&, guard_config: const SsrfGuardPolicy&) -> RedirectError {
    if route.resolved_ips.len == 0 {
        return RedirectError.None;
    }
    var ips_slice: const u8[:][4] = ["", "", "", ""];
    for idx in route.resolved_ips.len {
        ips_slice[idx] = route.resolved_ips[idx][..];
    }
    return validate_resolved_ips_against_ssrf(ips_slice[..route.resolved_ips.len], guard_config);
}

// Extracts origin string "host:port" from parsed Url.
fn format_url_origin<B>(url_val: const core::Url&, out: B&) {
    let host = core::hostname(url_val);
    let port = core::effective_port(url_val);
    out.append(host);
    out.append(":");
    format(out, port);
}

fn target_has_scheme(target: const u8[:]) -> bool {
    if target.len < 8 { return false; }
    for i in target.len - 2 {
        if target[i] == ':' && target[i + 1] == '/' && target[i + 2] == '/' {
            return true;
        }
    }
    return false;
}

fn resolve_target_origin<B>(target: const u8[:], out: B&) {
    if target_has_scheme(target) {
        let parsed, err = core::parse_url(target);
        if parsed.valid {
            format_url_origin(parsed, out);
            return;
        }
    }
    out.append(target);
}

// Synthesizes an HTTP Response from a matched MockExchange.
fn build_mock_response(
    route: const MockExchange&,
    current_url: const core::Url&,
    sent_headers: const HeaderItem[:]
) -> Response {
    var resp = Response {
        status_code: route.status_code,
        effective_url: copy(current_url.href),
        ..
    };
    if route.protocol.len > 0 {
        resp.protocol.clear();
        resp.protocol.append(route.protocol[..]);
    }
    for &h in route.headers {
        resp.headers.push(copy(h));
    }
    for &sc in route.set_cookies {
        resp.set_cookies.push(copy(sc));
    }
    resp.body.append(route.body[..]);
    for &sent_h in sent_headers {
        resp.sent_headers.push(copy(sent_h));
    }
    return resp;
}

// Executes a mock or echo response hop, verifying IP addresses against SSRF policies.
fn execute_mock_or_echo_hop(
    session: Session&,
    ctx: RequestExecutionContext&,
    current_url: const core::Url&,
    out_dns_err: RedirectError&
) -> Response {
    out_dns_err = RedirectError.None;
    let curr_href = href(current_url);
    let curr_method = ctx.current_method[..];

    var origin_buf: u8[..128] = [];
    format_url_origin(current_url, origin_buf);
    let now_sec = session.virtual_clock_us / 1000000;
    let is_https = current_url.is_secure_scheme();

    var candidate_h3_ep = AltSvcEndpoint { .. };
    let has_h3 = session.enable_altsvc && is_https && altsvc_lookup_h3(session.altsvc, origin_buf[..], now_sec, candidate_h3_ep);

    let curr_path = core::pathname(current_url);
    var matched_dict_b64: u8[..64] = [];
    let has_dict = session.enable_compression_dict && is_https && dictionary_lookup_for_request(session.dict_cache, origin_buf[..], curr_path, now_sec, matched_dict_b64);
    if has_dict {
        ctx.headers.push(make_header("Available-Dictionary", matched_dict_b64[..]));
    }

    // Check mock routes
    for &route in session.mock_routes {
        if (route.method.len == 0 || eq_ascii_fold(route.method[..], curr_method)) &&
           (route.pattern_url[..] == curr_href || starts_with(curr_href, route.pattern_url[..])) {
            let dns_err = validate_mock_route_dns(route, session.ssrf_guard);
            if dns_err != RedirectError.None {
                out_dns_err = dns_err;
                return Response {
                    status_code: 403,
                    effective_url: copy(current_url.href),
                    ..
                };
            }
            var resp = build_mock_response(route, current_url, ctx.headers[..]);
            if route.status_code == 101 {
                var sent_key: u8[..64] = [];
                for &hdr in ctx.headers {
                    if eq_ascii_fold(hdr.name[..], "sec-websocket-key") {
                        sent_key.append(hdr.value[..]);
                        break;
                    }
                }
                if sent_key.len > 0 && header(resp, "sec-websocket-accept").len == 0 {
                    var accept_buf: u8[..64] = [];
                    compute_websocket_accept(sent_key[..], accept_buf);
                    resp.headers.push(make_header("Sec-WebSocket-Accept", accept_buf[..]));
                }
            }

            // Chromium-style Protocol Racing & Alt-Svc Promotion
            if has_h3 {
                let race_eligible = should_create_dns_alpn_h3_job(
                    is_https,
                    session.enable_protocol_racing,
                    session.proxy_url.len > 0,
                    false
                );
                if race_eligible {
                    // Protocol race: QUIC Alternative Job vs TCP Main Job (Chromium JobController / RFC 8305)
                    if route.simulate_quic_blocked {
                        // QUIC handshake dropped/blocked by firewall -> Main TCP Job wins!
                        altsvc_record_failure(session.altsvc, origin_buf[..], now_sec);
                        resp.protocol.clear();
                        if route.protocol.len > 0 {
                            resp.protocol.append(route.protocol[..]);
                        } else {
                            resp.protocol.append("HTTP/1.1");
                        }
                    } else {
                        // QUIC handshake succeeds -> HTTP/3 wins!
                        altsvc_record_success(session.altsvc, origin_buf[..]);
                        resp.protocol.clear();
                        resp.protocol.append("h3");
                    }
                } else if session.enable_altsvc {
                    if route.simulate_quic_blocked {
                        altsvc_record_failure(session.altsvc, origin_buf[..], now_sec);
                        resp.protocol.clear();
                        resp.protocol.append(if route.protocol.len > 0 { route.protocol[..] } else { "HTTP/1.1" });
                    } else {
                        altsvc_record_success(session.altsvc, origin_buf[..]);
                        resp.protocol.clear();
                        resp.protocol.append("h3");
                    }
                }
            } else if route.protocol.len > 0 {
                resp.protocol.clear();
                resp.protocol.append(route.protocol[..]);
            }

            // Ingest Alt-Svc header from response (RFC 7838 Section 3)
            if session.enable_altsvc && is_https {
                let alt_svc_val = header(resp, "Alt-Svc");
                if alt_svc_val.len > 0 {
                    altsvc_cache_update(session.altsvc, origin_buf[..], alt_svc_val, now_sec);
                }
            }

            // Compression Dictionary Transport (Use-As-Dictionary and dcz decode)
            if session.enable_compression_dict && is_https {
                let dict_hdr = header(resp, "Use-As-Dictionary");
                if dict_hdr.len > 0 {
                    let d_params, ok_p = parse_use_as_dictionary_header(dict_hdr);
                    if ok_p {
                        let pat = if d_params.match_pattern.len > 0 { d_params.match_pattern[..] } else { curr_path };
                        dictionary_cache_insert(session.dict_cache, origin_buf[..], pat, d_params.id[..], resp.body[..], d_params.ttl_sec, now_sec);
                    }
                }
                let enc = header(resp, "Content-Encoding");
                if eq_ascii_fold(enc, "dcz") {
                    decode_body_with_dictionary(resp, session.dict_cache);
                }
            }

            return resp;
        }
    }

    // Default mock response
    var resp = Response {
        status_code: 200,
        effective_url: copy(current_url.href),
        ..
    };
    resp.headers.push(make_header("Content-Type", "application/json"));
    resp.headers.push(make_header("Server", "goose-wing/1.0"));
    resp.body.append("{\"id\":1042,\"status\":\"confirmed\",\"ok\":true}");

    if has_h3 && session.enable_altsvc {
        altsvc_record_success(session.altsvc, origin_buf[..]);
        resp.protocol.clear();
        resp.protocol.append("h3");
    }

    if session.enable_altsvc && is_https {
        let alt_svc_val = header(resp, "Alt-Svc");
        if alt_svc_val.len > 0 {
            altsvc_cache_update(session.altsvc, origin_buf[..], alt_svc_val, now_sec);
        }
    }

    if session.enable_compression_dict && is_https {
        let dict_hdr = header(resp, "Use-As-Dictionary");
        if dict_hdr.len > 0 {
            let d_params, ok_p = parse_use_as_dictionary_header(dict_hdr);
            if ok_p {
                let pat = if d_params.match_pattern.len > 0 { d_params.match_pattern[..] } else { curr_path };
                dictionary_cache_insert(session.dict_cache, origin_buf[..], pat, d_params.id[..], resp.body[..], d_params.ttl_sec, now_sec);
            }
        }
        let enc = header(resp, "Content-Encoding");
        if eq_ascii_fold(enc, "dcz") {
            decode_body_with_dictionary(resp, session.dict_cache);
        }
    }

    for &sent_h in ctx.headers {
        resp.sent_headers.push(copy(sent_h));
    }
    return resp;
}

// ---- high-level dispatch entry points --------------------------------------

fn do(session: Session&, req: const Request&) -> Response, Error {
    return execute_request(session, req);
}

// Last-mile closure overload: clones `req`, applies `F(&copy_req)`, and dispatches
fn do<F: fn(Request&)>(session: Session&, req: const Request&) -> Response, Error {
    var modified = copy(req);
    F(&modified);
    return do(session, modified);
}

// ---- okhttp/tower-style interceptor execution ------------------------------

struct InterceptorChain {
    request: Request&,
    response: Response&,
    err: Error = Error { .. },
    proceeded: bool = false,
    short_circuited: bool = false,
}

fn proceed(chain: InterceptorChain&, session: Session&) {
    chain.proceeded = true;
    let resp, err = execute_request(session, chain.request);
    chain.response = copy(resp);
    chain.err = err;
}

fn do_intercepted<F: fn(InterceptorChain&, Session&)>(session: Session&, req: const Request&) -> Response, Error {
    var req_copy = copy(req);
    var resp = Response { .. };
    var chain = InterceptorChain {
        request: req_copy,
        response: resp,
        ..
    };
    F(&chain, &session);
    if !chain.proceeded && !chain.short_circuited {
        proceed(chain, session);
    }
    return copy(chain.response), chain.err;
}

// ---- express verbs ---------------------------------------------------------

fn get(session: Session&, url: const u8[:]) -> Response, Error {
    let req = new_request("GET", url);
    return do(session, req);
}

fn get<F: fn(Request&)>(session: Session&, url: const u8[:]) -> Response, Error {
    var req = new_request("GET", url);
    F(&req);
    return do(session, req);
}

fn post<F: fn(Request&)>(session: Session&, url: const u8[:]) -> Response, Error {
    var req = new_request("POST", url);
    F(&req);
    return do(session, req);
}

fn post_json<T>(session: Session&, url: const u8[:], payload: const T&) -> Response, Error {
    var req = new_request("POST", url);
    json(req, payload);
    return do(session, req);
}

fn put<F: fn(Request&)>(session: Session&, url: const u8[:]) -> Response, Error {
    var req = new_request("PUT", url);
    F(&req);
    return do(session, req);
}

fn put_json<T>(session: Session&, url: const u8[:], payload: const T&) -> Response, Error {
    var req = new_request("PUT", url);
    json(req, payload);
    return do(session, req);
}

fn delete(session: Session&, url: const u8[:]) -> Response, Error {
    let req = new_request("DELETE", url);
    return do(session, req);
}

fn delete<F: fn(Request&)>(session: Session&, url: const u8[:]) -> Response, Error {
    var req = new_request("DELETE", url);
    F(&req);
    return do(session, req);
}

// ---- realtime & streaming (aoni-style ergonomics) -------------------------

// Normalizes ws:// and wss:// into http:// and https:// for HTTP pipeline
fn normalize_realtime_url(url: const u8[:], out: u8[..2048]&) {
    out.clear();
    if starts_with(url, "ws://") {
        out.append("http://");
        out.append(url[5..]);
    } else if starts_with(url, "wss://") {
        out.append("https://");
        out.append(url[6..]);
    } else {
        out.append(url);
    }
}

fn ws_perform_handshake(
    session: Session&,
    req: Request&,
    client_key: const u8[:]
) -> WebSocketSession, Response, Error {
    let resp, err = do(session, req);
    guard ok(err) else {
        return new_websocket_session(true), resp, err;
    }

    // Validate 101 Switching Protocols
    if resp.status_code != 101 {
        return new_websocket_session(true), resp, make_error(
            resp.status_code,
            "websocket_handshake",
            "server did not return 101 Switching Protocols"
        );
    }

    // Validate Upgrade: websocket
    let upg = header(resp, "Upgrade");
    if !eq_ascii_fold(upg, "websocket") {
        return new_websocket_session(true), resp, make_error(
            400,
            "websocket_handshake",
            "missing or invalid Upgrade header in server response"
        );
    }

    // Validate Connection header contains Upgrade
    let conn = header(resp, "Connection");
    var has_upgrade_token = false;
    if eq_ascii_fold(conn, "upgrade") {
        has_upgrade_token = true;
    } else {
        for t in 0..conn.len {
            if t + 7 <= conn.len && eq_ascii_fold(conn[t..t+7], "upgrade") {
                has_upgrade_token = true;
                break;
            }
        }
    }
    if !has_upgrade_token {
        return new_websocket_session(true), resp, make_error(
            400,
            "websocket_handshake",
            "missing Connection: Upgrade header in server response"
        );
    }

    // Validate Sec-WebSocket-Accept
    let server_accept = header(resp, "Sec-WebSocket-Accept");
    if !validate_websocket_accept(client_key, server_accept) {
        return new_websocket_session(true), resp, make_error(
            400,
            "websocket_handshake",
            "invalid Sec-WebSocket-Accept key in server response"
        );
    }

    var ws_sess = new_websocket_session(true);
    let proto = header(resp, "Sec-WebSocket-Protocol");
    if proto.len > 0 {
        ws_sess.subprotocol.append(proto);
    } else {
        let req_proto = header(req, "Sec-WebSocket-Protocol");
        if req_proto.len > 0 {
            ws_sess.subprotocol.append(req_proto);
        }
    }

    return ws_sess, resp, no_error();
}

// Initiates a WebSocket connection with automatic RFC 6455 handshake negotiation
fn ws(session: Session&, url: const u8[:]) -> WebSocketSession, Response, Error {
    var eff_url: u8[..2048] = [];
    normalize_realtime_url(url, eff_url);

    var req = new_request("GET", eff_url[..]);
    header(req, "Upgrade", "websocket");
    header(req, "Connection", "Upgrade");
    header(req, "Sec-WebSocket-Version", "13");

    var nonce: u8[16] = [0; 16];
    var seed: u64 = (session.virtual_clock_us as u64) ^ 0x5DEECE66D;
    for i in 16 {
        seed = seed * 6364136223846793005 + 1442695040888963407;
        nonce[i] = ((seed >> 33) & 0xFF) as u8;
    }
    var client_key: u8[..32] = [];
    generate_websocket_key(nonce, client_key);
    header(req, "Sec-WebSocket-Key", client_key[..]);

    return ws_perform_handshake(session, req, client_key[..]);
}

// Initiates a WebSocket connection with custom request configuration
fn ws<F: fn(Request&)>(session: Session&, url: const u8[:]) -> WebSocketSession, Response, Error {
    var eff_url: u8[..2048] = [];
    normalize_realtime_url(url, eff_url);

    var req = new_request("GET", eff_url[..]);
    header(req, "Upgrade", "websocket");
    header(req, "Connection", "Upgrade");
    header(req, "Sec-WebSocket-Version", "13");

    var nonce: u8[16] = [0; 16];
    var seed: u64 = (session.virtual_clock_us as u64) ^ 0x5DEECE66D;
    for i in 16 {
        seed = seed * 6364136223846793005 + 1442695040888963407;
        nonce[i] = ((seed >> 33) & 0xFF) as u8;
    }
    var client_key: u8[..32] = [];
    generate_websocket_key(nonce, client_key);
    header(req, "Sec-WebSocket-Key", client_key[..]);

    F(&req);

    return ws_perform_handshake(session, req, client_key[..]);
}

fn sse_perform_connect(
    session: Session&,
    sub: SseSubscription,
    req: Request&
) -> SseSubscription, Response, Error {
    var eff_sub = sub;
    let resp, err = do(session, req);
    guard ok(err) else {
        return eff_sub, resp, err;
    }

    if !is_success(resp) && !is_redirect(resp) {
        return eff_sub, resp, make_error(
            resp.status_code,
            "sse_connect",
            "server returned non-2xx status for SSE stream"
        );
    }

    let ct = header(resp, "Content-Type");
    if !starts_with(ct, "text/event-stream") {
        return eff_sub, resp, make_error(
            415,
            "sse_connect",
            "server response is not text/event-stream"
        );
    }

    eff_sub.connected = true;
    return eff_sub, resp, no_error();
}

// Initiates a Server-Sent Events (SSE) stream subscription per W3C EventSource
fn sse(session: Session&, url: const u8[:]) -> SseSubscription, Response, Error {
    var sub = new_sse_subscription(url);
    var req = new_request("GET", url);
    sse_prepare_request(sub, req);
    return sse_perform_connect(session, sub, req);
}

// Initiates an SSE stream subscription with custom request configuration
fn sse<F: fn(Request&)>(session: Session&, url: const u8[:]) -> SseSubscription, Response, Error {
    var sub = new_sse_subscription(url);
    var req = new_request("GET", url);
    sse_prepare_request(sub, req);
    F(&req);
    return sse_perform_connect(session, sub, req);
}

// Reconnects an existing SSE subscription with Last-Event-ID
fn sse_reconnect(session: Session&, sub: SseSubscription&) -> Response, Error {
    let eff_url = if sub.url.len > 0 { sub.url[..] } else { "" };
    var req = new_request("GET", eff_url);
    sse_prepare_request(sub, req);

    let resp, err = do(session, req);
    guard ok(err) else {
        sub.connected = false;
        return resp, err;
    }

    if !is_success(resp) {
        sub.connected = false;
        return resp, make_error(
            resp.status_code,
            "sse_reconnect",
            "server returned non-2xx status during reconnection"
        );
    }

    sub.connected = true;
    return resp, no_error();
}

// ---- masque connect-udp & connect-ip tunnels (rfc 9298, rfc 9484) -----------

fn connect_udp(
    session: Session&,
    proxy_url: const u8[:],
    target_host: const u8[:],
    target_port: u16,
    stream_id: u64 = 0,
    use_datagrams: bool = true
) -> MasqueTunnelSession, Response, Error {
    var tunnel = new_connect_udp_tunnel(proxy_url, target_host, target_port, stream_id, use_datagrams);
    tunnel.state = MasqueTunnelState.Connecting;

    var req_path: u8[..256] = [];
    var req_headers: HeaderItem[..16] = [];
    build_masque_connect_request(tunnel, req_headers, req_path);

    var full_url: u8[..512] = [];
    full_url.append(proxy_url);
    if full_url.len > 0 && full_url[full_url.len - 1] == '/' {
        full_url.pop();
    }
    full_url.append(req_path[..]);

    var req = new_request("CONNECT", full_url[..]);
    for &h in req_headers {
        req.headers.push(copy(h));
    }

    let resp, err = do(session, req);
    if !ok(err) || !is_success(resp) {
        tunnel.state = MasqueTunnelState.Failed;
        return tunnel, resp, if !ok(err) { err } else { make_error(resp.status_code, "masque", "proxy rejected CONNECT-UDP") };
    }

    let caps_val = header(resp, "capsule-protocol");
    if !is_capsule_protocol_negotiated(caps_val) {
        tunnel.state = MasqueTunnelState.Failed;
        return tunnel, resp, make_error(502, "masque", "proxy missing required Capsule-Protocol: ?1 header");
    }

    tunnel.state = MasqueTunnelState.Established;
    return tunnel, resp, no_error();
}

fn connect_ip(
    session: Session&,
    proxy_url: const u8[:],
    stream_id: u64 = 0,
    use_datagrams: bool = true
) -> MasqueTunnelSession, Response, Error {
    var tunnel = new_connect_ip_tunnel(proxy_url, stream_id, use_datagrams);
    tunnel.state = MasqueTunnelState.Connecting;

    var req_path: u8[..256] = [];
    var req_headers: HeaderItem[..16] = [];
    build_masque_connect_request(tunnel, req_headers, req_path);

    var full_url: u8[..512] = [];
    full_url.append(proxy_url);
    if full_url.len > 0 && full_url[full_url.len - 1] == '/' {
        full_url.pop();
    }
    full_url.append(req_path[..]);

    var req = new_request("CONNECT", full_url[..]);
    for &h in req_headers {
        req.headers.push(copy(h));
    }

    let resp, err = do(session, req);
    if !ok(err) || !is_success(resp) {
        tunnel.state = MasqueTunnelState.Failed;
        return tunnel, resp, if !ok(err) { err } else { make_error(resp.status_code, "masque", "proxy rejected CONNECT-IP") };
    }

    let caps_val = header(resp, "capsule-protocol");
    if !is_capsule_protocol_negotiated(caps_val) {
        tunnel.state = MasqueTunnelState.Failed;
        return tunnel, resp, make_error(502, "masque", "proxy missing required Capsule-Protocol: ?1 header");
    }

    tunnel.state = MasqueTunnelState.Established;
    return tunnel, resp, no_error();
}
