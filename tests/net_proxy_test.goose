// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Consolidated Verification Suite: Reverse Proxy, GCRA Rate Limiter, MASQUE, and Alt-Svc Suite
//
// RUN: goose build -o %t.exe %s
// RUN: %t.exe
import std;
import wing from "..";
import lit from "github.com/Lemon4ksan/goose-lit@v0.1.0";

// --- Component: net_proxy ---
// Verification suite for net/proxy: SOCKS5/SOCKS5h (RFC 1928 & RFC 1929),
// HTTP CONNECT tunneling, credential isolation, and 4-tier Slowloris defenses.
// CVE-2026-94439, CVE-2026-56866, CVE-2025-4673, and CVE-2021-33197 defenses.

// ----------------------------------------------------------------------------
// 1. SOCKS5 Greeting & RFC 1929
// ----------------------------------------------------------------------------
fn test_socks5_greeting_and_rfc1929(t: lit::T&) {
    t.run("SOCKS5 Phase 1 Greeting and Negotiation") { sub =>
        var greeting_buf: u8[..16] = [];
        net::build_socks5_greeting(net::Socks5GreetingOptions { has_credentials: true, enable_gssapi: true }, greeting_buf);

        sub.assert_eq(greeting_buf[0], 0x05, "Greeting version is 0x05");
        sub.assert_eq(greeting_buf[1], 3, "3 auth methods announced (None, UserPass, GSSAPI)");
        sub.assert_eq(greeting_buf[2], 0x00, "Method 0 is None");
        sub.assert_eq(greeting_buf[3], 0x02, "Method 1 is UserPass");
        sub.assert_eq(greeting_buf[4], 0x01, "Method 2 is GSSAPI");

        // Greeting without credentials and without GSSAPI (None only)
        var greet_none: u8[..16] = [];
        net::build_socks5_greeting(net::Socks5GreetingOptions { has_credentials: false, enable_gssapi: false }, greet_none);
        sub.assert_eq(greet_none.len, 3, "Greeting len == 3 (ver, nmethods=1, none)");
        sub.assert_eq(greet_none[1], 1, "1 auth method announced");
        sub.assert_eq(greet_none[2], 0x00, "Method is None");

        // Parse valid server selection [0x05, 0x02]
        let server_reply: u8[2] = [0x05, 0x02];
        let method, err = net::parse_socks5_greeting_reply(server_reply[..]);
        sub.assert_true(err == net::Socks5Error.None, "Greeting parsed cleanly");
        sub.assert_eq(method, 0x02, "UserPass method selected by server");

        // Server selects None [0x05, 0x00]
        let reply_none: u8[2] = [0x05, 0x00];
        let m_none, err_none = net::parse_socks5_greeting_reply(reply_none[..]);
        sub.assert_true(err_none == net::Socks5Error.None, "None auth parsed cleanly");
        sub.assert_eq(m_none, 0x00, "None selected");

        // Server rejects with 0xFF
        let reject_reply: u8[2] = [0x05, 0xFF];
        let m_rej, err_rej = net::parse_socks5_greeting_reply(reject_reply[..]);
        sub.assert_true(err_rej == net::Socks5Error.NoAcceptableAuth, "0xFF rejected as NoAcceptableAuth");

        // Server bad versions
        let bad_ver1: u8[2] = [0x04, 0x00];
        let m_bad1, err_bad1 = net::parse_socks5_greeting_reply(bad_ver1[..]);
        sub.assert_true(err_bad1 == net::Socks5Error.InvalidVersion, "Version 0x04 rejected");

        let bad_ver2: u8[2] = [0x06, 0x00];
        let m_bad2, err_bad2 = net::parse_socks5_greeting_reply(bad_ver2[..]);
        sub.assert_true(err_bad2 == net::Socks5Error.InvalidVersion, "Version 0x06 rejected");

        // Truncated greeting reply
        let trunc1: u8[1] = [0x05];
        let m_tr1, err_tr1 = net::parse_socks5_greeting_reply(trunc1[..]);
        sub.assert_true(err_tr1 == net::Socks5Error.BufferTruncated, "1-byte reply is truncated");

        let empty_reply: u8[0] = [];
        let m_emp, err_emp = net::parse_socks5_greeting_reply(empty_reply[..]);
        sub.assert_true(err_emp == net::Socks5Error.BufferTruncated, "0-byte reply is truncated");
    };

    t.run("RFC 1929 Subnegotiation Version 0x01 Invariant & Buffer Limits") { sub =>
        var auth_buf: u8[..520] = [];
        let auth_err = net::build_socks5_rfc1929_auth("testuser", "secretpass123", auth_buf);
        sub.assert_true(auth_err == net::Socks5Error.None, "RFC 1929 auth frame built");

        // Critical standard invariant: RFC 1929 version MUST be 0x01, NOT 0x05!
        sub.assert_eq(auth_buf[0], 0x01, "First byte is strictly RFC 1929 version 0x01");
        sub.assert_eq(auth_buf[1], 8, "Username length is 8");
        sub.assert_bytes_eq(auth_buf[2..10], "testuser", "Username matches");
        sub.assert_eq(auth_buf[10], 13, "Password length is 13");
        sub.assert_bytes_eq(auth_buf[11..24], "secretpass123", "Password matches");

        // Boundary: 0-length username is forbidden per RFC 1929
        var auth_buf_bad: u8[..520] = [];
        let err_empty_u = net::build_socks5_rfc1929_auth("", "secret", auth_buf_bad);
        sub.assert_true(err_empty_u == net::Socks5Error.AuthFailed, "0-length username rejected");

        // Boundary: 0-length password is forbidden per RFC 1929
        let err_empty_p = net::build_socks5_rfc1929_auth("user", "", auth_buf_bad);
        sub.assert_true(err_empty_p == net::Socks5Error.AuthFailed, "0-length password rejected");

        // Boundary: 1-char username and password
        let err_single = net::build_socks5_rfc1929_auth("u", "p", auth_buf_bad);
        sub.assert_true(err_single == net::Socks5Error.None, "Single-char user/pass accepted");
        sub.assert_eq(auth_buf_bad.len, 5, "Len is 1 (ver) + 1 (ulen) + 1 (u) + 1 (plen) + 1 (p) = 5");

        // Parse valid RFC 1929 reply [0x01, 0x00]
        let reply_ok: u8[2] = [0x01, 0x00];
        let rep_err = net::parse_socks5_rfc1929_reply(reply_ok[..]);
        sub.assert_true(rep_err == net::Socks5Error.None, "Status 0x00 authenticated successfully");

        // Parse rejected RFC 1929 reply [0x01, 0x01]
        let reply_fail: u8[2] = [0x01, 0x01];
        let fail_err = net::parse_socks5_rfc1929_reply(reply_fail[..]);
        sub.assert_true(fail_err == net::Socks5Error.AuthFailed, "Non-0x00 status rejected as AuthFailed");

        // Invalid version byte in RFC 1929 reply (e.g. 0x05)
        let reply_wrong_ver: u8[2] = [0x05, 0x00];
        let wrong_ver_err = net::parse_socks5_rfc1929_reply(reply_wrong_ver[..]);
        sub.assert_true(wrong_ver_err == net::Socks5Error.InvalidAuthResponse, "Wrong version byte in auth reply rejected");

        // Truncated RFC 1929 reply
        let reply_trunc: u8[1] = [0x01];
        let trunc_auth_err = net::parse_socks5_rfc1929_reply(reply_trunc[..]);
        sub.assert_true(trunc_auth_err == net::Socks5Error.BufferTruncated, "Truncated auth reply caught");
    };
}

// ----------------------------------------------------------------------------
// 2. SOCKS5 Command & Reply
// ----------------------------------------------------------------------------
fn test_socks5_command_and_reply_parsing(t: lit::T&) {
    t.run("socks5h vs socks5 ATYP and Port Serialization") { sub =>
        // socks5h:// MUST use ATYP = 0x03 to delegate DNS resolution to proxy node
        var req_socks5h: u8[..300] = [];
        let dummy_ip: u8[4] = [0, 0, 0, 0];
        let err_h = net::build_socks5_connect_request(net::ProxyScheme.Socks5h, "target.internal", dummy_ip, false, 443, req_socks5h);
        sub.assert_true(err_h == net::Socks5Error.None, "Socks5h request built");

        sub.assert_eq(req_socks5h[0], 0x05, "VER == 0x05");
        sub.assert_eq(req_socks5h[1], 0x01, "CMD == 0x01 (CONNECT)");
        sub.assert_eq(req_socks5h[2], 0x00, "RSV == 0x00");
        sub.assert_eq(req_socks5h[3], 0x03, "ATYP == 0x03 (Domain Name) prevents DNS leak");
        sub.assert_eq(req_socks5h[4], 15, "Domain length == 15");
        sub.assert_bytes_eq(req_socks5h[5..20], "target.internal", "Domain string preserved");
        sub.assert_eq(req_socks5h[20], 0x01, "Port high byte == 0x01 (443)");
        sub.assert_eq(req_socks5h[21], 0xBB, "Port low byte == 0xBB (443)");

        // socks5:// with local DNS resolution uses ATYP = 0x01
        var req_socks5: u8[..300] = [];
        let local_ip: u8[4] = [93, 184, 216, 34];
        let err_5 = net::build_socks5_connect_request(net::ProxyScheme.Socks5, "example.com", local_ip, true, 80, req_socks5);
        sub.assert_true(err_5 == net::Socks5Error.None, "Socks5 IPv4 request built");
        sub.assert_eq(req_socks5[3], 0x01, "ATYP == 0x01 (IPv4)");
        sub.assert_eq(req_socks5[4], 93, "IPv4 octet 0");
        sub.assert_eq(req_socks5[5], 184, "IPv4 octet 1");
        sub.assert_eq(req_socks5[6], 216, "IPv4 octet 2");
        sub.assert_eq(req_socks5[7], 34, "IPv4 octet 3");
        sub.assert_eq(req_socks5[8], 0x00, "Port high byte 0 for 80");
        sub.assert_eq(req_socks5[9], 80, "Port low byte 80");

        // socks5:// with IPv6 uses ATYP = 0x04
        var req_socks5_v6: u8[..300] = [];
        var ip6:           u8[16]    = [0; 16];
        ip6[15] = 1;
        let err_v6 = net::build_socks5_connect_request_v6(net::ProxyScheme.Socks5, "example.com", ip6, true, 80, req_socks5_v6);
        sub.assert_true(err_v6 == net::Socks5Error.None, "Socks5 IPv6 request built");
        sub.assert_eq(req_socks5_v6[3], 0x04, "ATYP == 0x04 (IPv6)");

        // High port boundary: 65535 (0xFFFF)
        var req_max_port: u8[..300] = [];
        let err_mp = net::build_socks5_connect_request(net::ProxyScheme.Socks5, "example.com", local_ip, true, 65535, req_max_port);
        sub.assert_true(err_mp == net::Socks5Error.None, "Max port 65535 built");
        sub.assert_eq(req_max_port[8], 0xFF, "Port hi == 0xFF");
        sub.assert_eq(req_max_port[9], 0xFF, "Port lo == 0xFF");
    };

    t.run("Parse SOCKS5 Reply Frames & All 9 Error Codes") { sub =>
        // Success reply: VER=0x05, REP=0x00, RSV=0x00, ATYP=0x01, BND.ADDR=127.0.0.1, BND.PORT=1080 (0x0438)
        let reply_ok: u8[10] = [0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x04, 0x38];
        let rep, err = net::parse_socks5_connect_reply(reply_ok[..]);
        sub.assert_true(err == net::Socks5Error.None, "Success reply parsed cleanly");
        sub.assert_eq(rep.bound_port, 1080, "Bound port 1080 parsed");
        sub.assert_eq(rep.bytes_consumed, 10, "Consumed exact 10 bytes");

        // Test all RFC 1928 failure codes:
        // REP = 0x01: GeneralFailure
        let reply_01: u8[10] = [0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        let _, err_01 = net::parse_socks5_connect_reply(reply_01[..]);
        sub.assert_true(err_01 == net::Socks5Error.ServerFailure, "0x01 is ServerFailure");

        // REP = 0x02: ConnectionNotAllowed
        let reply_02: u8[10] = [0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        let _, err_02 = net::parse_socks5_connect_reply(reply_02[..]);
        sub.assert_true(err_02 == net::Socks5Error.ConnectionNotAllowed, "0x02 is ConnectionNotAllowed");

        // REP = 0x03: NetworkUnreachable
        let reply_03: u8[10] = [0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        let _, err_03 = net::parse_socks5_connect_reply(reply_03[..]);
        sub.assert_true(err_03 == net::Socks5Error.NetworkUnreachable, "0x03 is NetworkUnreachable");

        // REP = 0x04: HostUnreachable
        let reply_04: u8[10] = [0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        let _, err_04 = net::parse_socks5_connect_reply(reply_04[..]);
        sub.assert_true(err_04 == net::Socks5Error.HostUnreachable, "0x04 is HostUnreachable");

        // REP = 0x05: ConnectionRefused
        let reply_05: u8[10] = [0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        let _, err_05 = net::parse_socks5_connect_reply(reply_05[..]);
        sub.assert_true(err_05 == net::Socks5Error.ConnectionRefused, "0x05 is ConnectionRefused");

        // REP = 0x06: TtlExpired
        let reply_06: u8[10] = [0x05, 0x06, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        let _, err_06 = net::parse_socks5_connect_reply(reply_06[..]);
        sub.assert_true(err_06 == net::Socks5Error.TtlExpired, "0x06 is TtlExpired");

        // REP = 0x07: CommandNotSupported
        let reply_07: u8[10] = [0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        let _, err_07 = net::parse_socks5_connect_reply(reply_07[..]);
        sub.assert_true(err_07 == net::Socks5Error.CommandNotSupported, "0x07 is CommandNotSupported");

        // REP = 0x08: AddressTypeNotSupported
        let reply_08: u8[10] = [0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        let _, err_08 = net::parse_socks5_connect_reply(reply_08[..]);
        sub.assert_true(err_08 == net::Socks5Error.AddressTypeNotSupported, "0x08 is AddressTypeNotSupported");

        // Domain bound reply: 4 + 1 + 10 ("proxy.node") + 2 = 17 bytes
        var rep_domain: u8[17] = [0x05, 0x00, 0x00, 0x03, 10, 'p', 'r', 'o', 'x', 'y', '.', 'n', 'o', 'd', 'e', 0x1F, 0x90];
        let rep_d, err_d = net::parse_socks5_connect_reply(rep_domain[..]);
        sub.assert_true(err_d == net::Socks5Error.None, "Domain reply parsed cleanly");
        sub.assert_eq(rep_d.bound_port, 8080, "Bound port 8080 parsed");
        sub.assert_eq(rep_d.bytes_consumed, 17, "Consumed exact 17 bytes");

        // IPv6 bound reply: 4 + 16 (addr) + 2 (port 443 = 0x01BB) = 22 bytes
        var rep_ipv6: u8[22] = [
            0x05, 0x00, 0x00, 0x04,
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x01, 0xBB,
        ];
        let rep_6, err_6 = net::parse_socks5_connect_reply(rep_ipv6[..]);
        sub.assert_true(err_6 == net::Socks5Error.None, "IPv6 reply parsed cleanly");
        sub.assert_eq(rep_6.bound_port, 443, "Bound port 443 parsed");
        sub.assert_eq(rep_6.bytes_consumed, 22, "Consumed exact 22 bytes");

        // Truncated replies
        let trunc_ipv4: u8[9] = [0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x04];
        let _, err_tr_4 = net::parse_socks5_connect_reply(trunc_ipv4[..]);
        sub.assert_true(err_tr_4 == net::Socks5Error.BufferTruncated, "Truncated IPv4 reply caught");

        let trunc_ipv6: u8[21] = [0x05, 0x00, 0x00, 0x04, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17];
        let _, err_tr_6 = net::parse_socks5_connect_reply(trunc_ipv6[..]);
        sub.assert_true(err_tr_6 == net::Socks5Error.BufferTruncated, "Truncated IPv6 reply caught");

        // Invalid ATYP (0x02)
        let reply_bad_atyp: u8[10] = [0x05, 0x00, 0x00, 0x02, 0, 0, 0, 0, 0, 0];
        let _, err_bad_atyp = net::parse_socks5_connect_reply(reply_bad_atyp[..]);
        sub.assert_true(err_bad_atyp == net::Socks5Error.AddressTypeNotSupported, "Invalid ATYP 0x02 rejected");
    };
}

// ----------------------------------------------------------------------------
// 3. HTTP CONNECT Tunnel & Buffer Hygiene
// ----------------------------------------------------------------------------
fn test_http_connect_tunnel_and_buffer_hygiene(t: lit::T&) {
    t.run("CONNECT Header Construction & Credential Isolation (CVE-2025-4673)") { sub =>
        var req_buf: u8[..1024] = [];
        net::build_http_connect_request("secure.bank.com", 443, "Basic dXNlcjpwYXNz", "goose-wing/1.0", req_buf);

        sub.assert_true(starts_with(req_buf[..], "CONNECT secure.bank.com:443 HTTP/1.1\r\n"), "CONNECT request line correct");
        sub.assert_contains(req_buf[..], "Proxy-Authorization: Basic dXNlcjpwYXNz\r\n", "Proxy auth header included");

        // Isolation barrier: sanitize_tunnel_headers_for_origin (CVE-2025-4673 & CVE-2021-33197)
        var origin_headers = http::HeaderMap { .. };
        http::append_header(origin_headers, "Host", "secure.bank.com");
        http::append_header(origin_headers, "Proxy-Authorization", "Basic dXNlcjpwYXNz");
        http::append_header(origin_headers, "PROXY-AUTHORIZATION", "Basic UPPERCASE_LEAK");
        http::append_header(origin_headers, "proxy-authorization", "Basic lowercase_leak");
        http::append_header(origin_headers, "Proxy-Authenticate", "Basic realm=corp");
        http::append_header(origin_headers, "Proxy-Connection", "Keep-Alive");
        http::append_header(origin_headers, "Authorization", "Bearer user_token_99");
        http::append_header(origin_headers, "Cookie", "session=secret_session");

        net::sanitize_tunnel_headers_for_origin(origin_headers);

        sub.assert_eq(origin_headers.entries.len, 3, "All 5 proxy header variations stripped from origin request");
        sub.assert_bytes_eq(http::entry_name(origin_headers, origin_headers.entries[0]), "Host", "Host header preserved");
        sub.assert_bytes_eq(http::entry_name(origin_headers, origin_headers.entries[1]), "Authorization", "Target origin bearer auth preserved");
        sub.assert_bytes_eq(http::entry_name(origin_headers, origin_headers.entries[2]), "Cookie", "Origin cookies preserved");

        // Edge case: empty headers list
        var empty_hdrs = http::HeaderMap { .. };
        net::sanitize_tunnel_headers_for_origin(empty_hdrs);
        sub.assert_eq(empty_hdrs.entries.len, 0, "Empty headers list remains empty");

        // Edge case: headers list with ONLY proxy headers
        var only_proxy = http::HeaderMap { .. };
        http::append_header(only_proxy, "Proxy-Authorization", "Basic xyz");
        http::append_header(only_proxy, "Proxy-Connection", "close");
        net::sanitize_tunnel_headers_for_origin(only_proxy);
        sub.assert_eq(only_proxy.entries.len, 0, "Headers list with only proxy headers reduced to 0");
    };

    t.run("OkHttp Leftover Buffer Defense: TLS Tunnel Buffered Too Many Bytes (CVE-2026-56866)") { sub =>
        // 1. Clean CONNECT response with no trailing bytes
        let clean_resp = "HTTP/1.1 200 Connection Established\r\nProxy-Agent: corporate-proxy\r\n\r\n";
        let err_clean = net::verify_connect_tunnel_response(clean_resp, 0);
        sub.assert_true(err_clean == net::ConnectTunnelError.None, "Clean 200 OK CONNECT approved");

        // 2. Data injection attack: Extra bytes after \r\n\r\n before TLS handshake
        let injected_resp = "HTTP/1.1 200 Connection Established\r\n\r\nINJECTED_TLS_PREFIX_DATA";
        let err_injected = net::verify_connect_tunnel_response(injected_resp, 0);
        sub.assert_true(err_injected == net::ConnectTunnelError.TunnelBufferedTooManyBytes, "Detected leftover buffer data injection");

        // 3. Single-byte smuggled prefix attack
        let single_byte_inj = "HTTP/1.1 200 Connection Established\r\n\r\nX";
        let err_single = net::verify_connect_tunnel_response(single_byte_inj, 0);
        sub.assert_true(err_single == net::ConnectTunnelError.TunnelBufferedTooManyBytes, "1-byte smuggled prefix caught");

        // 4. Sink has leftover unwritten bytes
        let err_sink = net::verify_connect_tunnel_response(clean_resp, 16);
        sub.assert_true(err_sink == net::ConnectTunnelError.TunnelBufferedTooManyBytes, "Detected non-empty sink buffer");

        // 5. Proxy Authentication Required (407)
        let auth_req_resp = "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\n\r\n";
        let err_407 = net::verify_connect_tunnel_response(auth_req_resp, 0);
        sub.assert_true(err_407 == net::ConnectTunnelError.ProxyAuthRequired, "407 status parsed correctly");

        // 6. Bad Gateway (502)
        let bad_gw = "HTTP/1.1 502 Bad Gateway\r\n\r\n";
        let err_502 = net::verify_connect_tunnel_response(bad_gw, 0);
        sub.assert_true(err_502 == net::ConnectTunnelError.ConnectFailed, "502 status mapped to ConnectFailed");

        // 7. Forbidden (403)
        let forbidden = "HTTP/1.1 403 Forbidden\r\n\r\n";
        let err_403 = net::verify_connect_tunnel_response(forbidden, 0);
        sub.assert_true(err_403 == net::ConnectTunnelError.ConnectFailed, "403 status mapped to ConnectFailed");

        // 8. Missing \r\n\r\n
        let no_end = "HTTP/1.1 200 OK\r\nHeader: value";
        let err_no_end = net::verify_connect_tunnel_response(no_end, 0);
        sub.assert_true(err_no_end == net::ConnectTunnelError.MalformedHeaders, "Missing header end separator caught");

        // 9. Short / Truncated response
        let short_resp = "HTTP/1.1 200";
        let err_short = net::verify_connect_tunnel_response(short_resp, 0);
        sub.assert_true(err_short == net::ConnectTunnelError.MalformedHeaders, "Truncated response caught");
    };
}

// ----------------------------------------------------------------------------
// 4. Slowloris Tarpit Defenses
// ----------------------------------------------------------------------------
fn test_slowloris_tarpit_defenses(t: lit::T&) {
    t.run("4-Tier Slowloris Defense Enforcement") { sub =>
        let cfg = net::SlowlorisDefenseConfig { .. };
        var reader = net::new_header_reader(cfg, 0);

        // Feed standard fast chunk at t=100ms
        let chunk1 = "GET /index.html HTTP/1.1\r\nHost: example.com\r\n";
        let v1 = net::feed_header_bytes(reader, chunk1, 100000000);
        sub.assert_true(v1 == net::SlowlorisViolation.None, "Valid chunk approved");

        // Barrier 1: Monotonic Cumulative Header Deadline (10s)
        let chunk2 = "User-Agent: test\r\n";
        let v_timeout = net::feed_header_bytes(reader, chunk2, 10500000000); // t=10.5s
        sub.assert_true(v_timeout == net::SlowlorisViolation.HeaderTimeoutExpired, "Header timeout triggered after 10s monotonic deadline");
        sub.assert_true(reader.poison_connection, "Poison connection flagged");

        // Barrier 3: Memory ceiling (64 KB)
        var reader_mem = net::new_header_reader(cfg, 0);
        reader_mem.cumulative_header_bytes = 65000;
        let big_chunk: u8[1000] = ['A'; 1000];
        let v_mem = net::feed_header_bytes(reader_mem, big_chunk[..], 500000000);
        sub.assert_true(v_mem == net::SlowlorisViolation.MaxHeaderBytesExceeded, "Hard memory ceiling triggered on 65 KB header block");
        sub.assert_true(reader_mem.poison_connection, "Memory ceiling poisons connection");

        // Barrier 4: Byte-Drip gate (< 256 B/s)
        var reader_drip = net::new_header_reader(cfg, 0);
        let drip_byte = "X";
        // 1 byte received over 2.0 seconds -> 0.5 B/s (< 256 B/s)
        let v_drip = net::feed_header_bytes(reader_drip, drip_byte, 2000000000);
        sub.assert_true(v_drip == net::SlowlorisViolation.MinIngressRateViolated, "Byte-drip tarpit caught by minimum ingress rate gate");
        sub.assert_true(reader_drip.poison_connection, "Byte-drip poisons connection");

        // Barrier 5: Header lines count ceiling (> 100 lines)
        var reader_lines = net::new_header_reader(cfg, 0);
        var many_lines: u8[..4096] = [];
        for i in 101 {
            many_lines.append("X-H: v\r\n");
        }
        let v_lines = net::feed_header_bytes(reader_lines, many_lines[..], 500000000);
        sub.assert_true(v_lines == net::SlowlorisViolation.MaxHeaderCountExceeded, "101 header lines exceeds max_header_count (100)");
        sub.assert_true(reader_lines.poison_connection, "Header count excess poisons connection");
    };
}

// --- Component: net_proxy_protocol ---
// tests/proxy_protocol_test.goose
// Verification test suite for HAProxy PROXY Protocol v1 (text) and v2 (binary).

// 5. PROXY Protocol v1 (Text) Conformance
fn test_proxy_v1_conformance(t: lit::T&) {
    t.run("PROXY-v1-01: Valid TCP4 line parsing") { sub =>
        let raw = "PROXY TCP4 192.168.0.1 10.0.0.1 56324 443\r\nGET / HTTP/1.1\r\n";
        let hdr, consumed, ok = net::parse_proxy_v1(raw);
        sub.assert_true(ok, "parse_proxy_v1 succeeds on valid TCP4");
        sub.assert_eq(consumed, 43, "consumed exact 43 bytes of PROXY v1 line");
        sub.assert_true(hdr.version == net::ProxyProtocolVersion.V1, "version is V1");
        sub.assert_true(hdr.command == net::ProxyCommand.Proxy, "command is Proxy");
        sub.assert_true(hdr.family == net::ProxyAddressFamily.Inet4, "family is Inet4");
        sub.assert_true(hdr.transport == net::ProxyTransportProtocol.Stream, "transport is Stream");
        sub.assert_bytes_eq(hdr.src_ip_str[..], "192.168.0.1", "src_ip_str matches");
        sub.assert_bytes_eq(hdr.dst_ip_str[..], "10.0.0.1", "dst_ip_str matches");
        sub.assert_eq(hdr.src_port, 56324, "src_port matches");
        sub.assert_eq(hdr.dst_port, 443, "dst_port matches");
        sub.assert_eq(hdr.src_ipv4[0], 192, "IPv4 octet 0 matches");
        sub.assert_eq(hdr.src_ipv4[3], 1, "IPv4 octet 3 matches");
    };

    t.run("PROXY-v1-02: Valid TCP6 line parsing") { sub =>
        let raw = "PROXY TCP6 2001:db8::1 2001:db8::2 56324 443\r\n";
        let hdr, consumed, ok = net::parse_proxy_v1(raw);
        sub.assert_true(ok, "parse_proxy_v1 succeeds on valid TCP6");
        sub.assert_eq(consumed, raw.len, "consumed full line");
        sub.assert_true(hdr.family == net::ProxyAddressFamily.Inet6, "family is Inet6");
        sub.assert_bytes_eq(hdr.src_ip_str[..], "2001:db8::1", "IPv6 src matches");
        sub.assert_bytes_eq(hdr.dst_ip_str[..], "2001:db8::2", "IPv6 dst matches");
        sub.assert_eq(hdr.src_port, 56324, "src port matches");
        sub.assert_eq(hdr.dst_port, 443, "dst port matches");
        sub.assert_eq(hdr.src_ipv6[0], 0x20, "IPv6 src byte 0 is 0x20");
        sub.assert_eq(hdr.src_ipv6[1], 0x01, "IPv6 src byte 1 is 0x01");
        sub.assert_eq(hdr.src_ipv6[2], 0x0d, "IPv6 src byte 2 is 0x0d");
        sub.assert_eq(hdr.src_ipv6[3], 0xb8, "IPv6 src byte 3 is 0xb8");
        sub.assert_eq(hdr.src_ipv6[15], 0x01, "IPv6 src byte 15 is 0x01");
        sub.assert_eq(hdr.dst_ipv6[15], 0x02, "IPv6 dst byte 15 is 0x02");
    };

    t.run("PROXY-v1-03: UNKNOWN protocol parsing") { sub =>
        let raw = "PROXY UNKNOWN\r\n";
        let hdr, consumed, ok = net::parse_proxy_v1(raw);
        sub.assert_true(ok, "parse_proxy_v1 succeeds on UNKNOWN");
        sub.assert_eq(consumed, 15, "consumed exact 15 bytes");
        sub.assert_true(hdr.command == net::ProxyCommand.Local, "command is Local for UNKNOWN");
        sub.assert_true(hdr.family == net::ProxyAddressFamily.Unspec, "family is Unspec");
    };

    t.run("PROXY-v1-04: Serialization round-trip") { sub =>
        var hdr = net::ProxyHeader {
            version:   net::ProxyProtocolVersion.V1,
            command:   net::ProxyCommand.Proxy,
            family:    net::ProxyAddressFamily.Inet4,
            transport: net::ProxyTransportProtocol.Stream,
            src_ipv4:  [172, 16, 1, 25],
            dst_ipv4:  [10, 0, 0, 2],
            src_port:  41234,
            dst_port:  8080,
            ..
        };
        hdr.src_ip_str.append("172.16.1.25");
        hdr.dst_ip_str.append("10.0.0.2");

        var out: u8[..128] = [];
        let ok_fmt = net::format_proxy_v1(hdr, out);
        sub.assert_true(ok_fmt, "format_proxy_v1 succeeds");
        sub.assert_bytes_eq(out[..], "PROXY TCP4 172.16.1.25 10.0.0.2 41234 8080\r\n", "serialized v1 format matches spec");

        // Parse back
        let back_hdr, consumed, ok_back = net::parse_proxy_v1(out[..]);
        sub.assert_true(ok_back, "parse back succeeds");
        sub.assert_eq(consumed, out.len, "consumed all bytes");
        sub.assert_eq(back_hdr.src_port, 41234, "round-trip port matches");
        sub.assert_bytes_eq(back_hdr.src_ip_str[..], "172.16.1.25", "round-trip IP matches");
    };

    t.run("PROXY-v1-05: Rejection of invalid and truncated lines") { sub =>
        // Missing CRLF
        let truncated = "PROXY TCP4 192.168.0.1 10.0.0.1 56324 443";
        let _, _, ok_trunc = net::parse_proxy_v1(truncated);
        sub.assert_false(ok_trunc, "truncated line without CRLF rejected");

        // Wrong prefix
        let wrong_prefix = "PROX2 TCP4 192.168.0.1 10.0.0.1 56324 443\r\n";
        let _, _, ok_pref = net::parse_proxy_v1(wrong_prefix);
        sub.assert_false(ok_pref, "wrong prefix rejected");

        // Invalid IP octet > 255
        let bad_ip = "PROXY TCP4 300.168.0.1 10.0.0.1 56324 443\r\n";
        let _, _, ok_bad_ip = net::parse_proxy_v1(bad_ip);
        sub.assert_false(ok_bad_ip, "octet > 255 rejected");

        // Invalid Port > 65535
        let bad_port = "PROXY TCP4 192.168.0.1 10.0.0.1 70000 443\r\n";
        let _, _, ok_bad_port = net::parse_proxy_v1(bad_port);
        sub.assert_false(ok_bad_port, "port > 65535 rejected");

        // Missing tokens
        let missing_tok = "PROXY TCP4 192.168.0.1 10.0.0.1 443\r\n";
        let _, _, ok_mis = net::parse_proxy_v1(missing_tok);
        sub.assert_false(ok_mis, "line with missing tokens rejected");
    };
}

// 6. PROXY Protocol v2 (Binary) Conformance
fn test_proxy_v2_conformance(t: lit::T&) {
    t.run("PROXY-v2-01: IPv4 TCP binary header parsing") { sub =>
        // Preamble (12) + 0x21 (v2, PROXY) + 0x11 (INET4, STREAM) + len 12 (0x000C)
        var wire: u8[..64] = [];
        for b in net_internal::PROXY_V2_PREAMBLE { wire.push(b); }
        wire.push(0x21); // version 2, PROXY command
        wire.push(0x11); // INET4, STREAM (TCP)
        wire.push(0x00); wire.push(12); // payload length = 12

        // IPv4 addresses: 192.168.1.10 -> 10.0.0.1
        wire.push(192); wire.push(168); wire.push(1); wire.push(10);
        wire.push(10); wire.push(0); wire.push(0); wire.push(1);
        // Ports: src 50000 (0xC350), dst 443 (0x01BB)
        wire.push(0xC3); wire.push(0x50);
        wire.push(0x01); wire.push(0xBB);

        let hdr, consumed, ok = net::parse_proxy_v2(wire[..]);
        sub.assert_true(ok, "parse_proxy_v2 succeeds on IPv4 TCP");
        sub.assert_eq(consumed, 28, "consumed exact 28 bytes (16 header + 12 addr)");
        sub.assert_true(hdr.version == net::ProxyProtocolVersion.V2, "version is V2");
        sub.assert_true(hdr.command == net::ProxyCommand.Proxy, "command is Proxy");
        sub.assert_true(hdr.family == net::ProxyAddressFamily.Inet4, "family is Inet4");
        sub.assert_true(hdr.transport == net::ProxyTransportProtocol.Stream, "transport is Stream");
        sub.assert_bytes_eq(hdr.src_ip_str[..], "192.168.1.10", "formatted src IPv4 matches");
        sub.assert_bytes_eq(hdr.dst_ip_str[..], "10.0.0.1", "formatted dst IPv4 matches");
        sub.assert_eq(hdr.src_port, 50000, "src port matches");
        sub.assert_eq(hdr.dst_port, 443, "dst port matches");
    };

    t.run("PROXY-v2-02: Command LOCAL (health checks)") { sub =>
        var wire: u8[..32] = [];
        for b in net_internal::PROXY_V2_PREAMBLE { wire.push(b); }
        wire.push(0x20); // version 2, LOCAL command
        wire.push(0x00); // UNSPEC, UNSPEC
        wire.push(0x00); wire.push(0x00); // payload length = 0

        let hdr, consumed, ok = net::parse_proxy_v2(wire[..]);
        sub.assert_true(ok, "parse_proxy_v2 succeeds on LOCAL");
        sub.assert_eq(consumed, 16, "consumed exact 16 bytes");
        sub.assert_true(hdr.command == net::ProxyCommand.Local, "command is Local");
        sub.assert_true(hdr.family == net::ProxyAddressFamily.Unspec, "family is Unspec");
    };

    t.run("PROXY-v2-03: IPv6 TCP binary header parsing") { sub =>
        var wire: u8[..64] = [];
        for b in net_internal::PROXY_V2_PREAMBLE { wire.push(b); }
        wire.push(0x21); // version 2, PROXY command
        wire.push(0x21); // INET6, STREAM (TCP)
        wire.push(0x00); wire.push(36); // payload length = 36

        // 16 bytes src IPv6
        for i in 16 { wire.push(i as u8); }
        // 16 bytes dst IPv6
        for i in 16 { wire.push((0x10 + i) as u8); }
        // Ports: 8080 (0x1F90), 443 (0x01BB)
        wire.push(0x1F); wire.push(0x90);
        wire.push(0x01); wire.push(0xBB);

        let hdr, consumed, ok = net::parse_proxy_v2(wire[..]);
        sub.assert_true(ok, "parse_proxy_v2 succeeds on IPv6");
        sub.assert_eq(consumed, 52, "consumed 16 header + 36 addr = 52 bytes");
        sub.assert_true(hdr.family == net::ProxyAddressFamily.Inet6, "family is Inet6");
        sub.assert_eq(hdr.src_port, 8080, "src port matches");
        sub.assert_eq(hdr.dst_port, 443, "dst port matches");
    };

    t.run("PROXY-v2-04: Rejection of invalid v2 headers") { sub =>
        // Corrupted preamble
        var bad_preamble: u8[16] = [0; 16];
        let _, _, ok_bad = net::parse_proxy_v2(bad_preamble[..]);
        sub.assert_false(ok_bad, "bad preamble rejected");

        // Wrong version (0x11 instead of 0x21)
        var bad_ver: u8[..32] = [];
        for b in net_internal::PROXY_V2_PREAMBLE { bad_ver.push(b); }
        bad_ver.push(0x11); bad_ver.push(0x11); bad_ver.push(0); bad_ver.push(0);
        let _, _, ok_ver = net::parse_proxy_v2(bad_ver[..]);
        sub.assert_false(ok_ver, "version != 2 rejected");

        // Truncated payload length claim
        var trunc_wire: u8[..32] = [];
        for b in net_internal::PROXY_V2_PREAMBLE { trunc_wire.push(b); }
        trunc_wire.push(0x21); trunc_wire.push(0x11);
        trunc_wire.push(0x00); trunc_wire.push(100); // claim 100 bytes but only 16 present
        let _, _, ok_len = net::parse_proxy_v2(trunc_wire[..]);
        sub.assert_false(ok_len, "truncated payload rejected");
    };
}

// 7. PROXY Protocol v2 TLV (Type-Length-Value) Metadata
fn test_proxy_v2_tlvs(t: lit::T&) {
    t.run("PROXY-v2-TLV-01: ALPN, Authority, and Unique ID") { sub =>
        var hdr = net::ProxyHeader {
            version:   net::ProxyProtocolVersion.V2,
            command:   net::ProxyCommand.Proxy,
            family:    net::ProxyAddressFamily.Inet4,
            transport: net::ProxyTransportProtocol.Stream,
            src_ipv4:  [192, 168, 1, 100],
            dst_ipv4:  [10, 0, 0, 1],
            src_port:  45678,
            dst_port:  443,
            ..
        };
        hdr.alpn.append("h2");
        hdr.authority.append("secure.api.internal");
        hdr.unique_id.append("trace-c0ffee-9988");
        hdr.netns.append("ns_customer_prod");

        var wire: u8[..256] = [];
        let ok_fmt = net::format_proxy_v2(hdr, wire);
        sub.assert_true(ok_fmt, "format_proxy_v2 with TLVs succeeds");

        // Parse back
        let back_hdr, consumed, ok_parse = net::parse_proxy_v2(wire[..]);
        sub.assert_true(ok_parse, "parse_proxy_v2 succeeds on serialized TLVs");
        sub.assert_eq(consumed, wire.len, "consumed full wire with TLVs");
        sub.assert_bytes_eq(back_hdr.alpn[..], "h2", "ALPN TLV matches");
        sub.assert_bytes_eq(back_hdr.authority[..], "secure.api.internal", "Authority/SNI TLV matches");
        sub.assert_bytes_eq(back_hdr.unique_id[..], "trace-c0ffee-9988", "Unique ID TLV matches");
        sub.assert_bytes_eq(back_hdr.netns[..], "ns_customer_prod", "Netns TLV matches");
    };

    t.run("PROXY-v2-TLV-02: SSL/TLS Metadata & Sub-TLVs") { sub =>
        var hdr = net::ProxyHeader {
            version:   net::ProxyProtocolVersion.V2,
            command:   net::ProxyCommand.Proxy,
            family:    net::ProxyAddressFamily.Inet4,
            transport: net::ProxyTransportProtocol.Stream,
            src_ipv4:  [10, 20, 30, 40],
            dst_ipv4:  [10, 0, 0, 2],
            src_port:  33445,
            dst_port:  8443,
            ..
        };
        hdr.ssl.has_ssl = true;
        hdr.ssl.client_flags = net_internal::PP2_CLIENT_SSL | net_internal::PP2_CLIENT_CERT_CONN;
        hdr.ssl.verify_result = 0; // successfully verified client cert
        hdr.ssl.version.append("TLSv1.3");
        hdr.ssl.cipher.append("rfc::TLS_CIPHER_AES_128_GCM_SHA256");
        hdr.ssl.sig_alg.append("SHA256");
        hdr.ssl.key_alg.append("RSA2048");
        hdr.ssl.client_cn.append("client.tenant42.prod");

        var wire: u8[..512] = [];
        let ok_fmt = net::format_proxy_v2(hdr, wire);
        sub.assert_true(ok_fmt, "format_proxy_v2 with SSL TLV succeeds");

        // Parse back
        let back_hdr, consumed, ok_parse = net::parse_proxy_v2(wire[..]);
        sub.assert_true(ok_parse, "parse_proxy_v2 parses SSL TLVs cleanly");
        sub.assert_eq(consumed, wire.len, "consumed entire buffer");
        sub.assert_true(back_hdr.ssl.has_ssl, "SSL flag set");
        sub.assert_eq(back_hdr.ssl.client_flags, net_internal::PP2_CLIENT_SSL | net_internal::PP2_CLIENT_CERT_CONN, "client flags preserved");
        sub.assert_eq(back_hdr.ssl.verify_result, 0, "verify_result is 0");
        sub.assert_bytes_eq(back_hdr.ssl.version[..], "TLSv1.3", "SSL version matches");
        sub.assert_bytes_eq(back_hdr.ssl.cipher[..], "rfc::TLS_CIPHER_AES_128_GCM_SHA256", "Cipher matches");
        sub.assert_bytes_eq(back_hdr.ssl.sig_alg[..], "SHA256", "Signature alg matches");
        sub.assert_bytes_eq(back_hdr.ssl.key_alg[..], "RSA2048", "Key alg matches");
        sub.assert_bytes_eq(back_hdr.ssl.client_cn[..], "client.tenant42.prod", "Client CN matches");
    };
}

// 8. Stream Stripping & Server Pipeline Integration
fn test_proxy_server_integration(t: lit::T&) {
    t.run("Auto-Detection and Stream Stripping") { sub =>
        let stream = "PROXY TCP4 203.0.113.195 10.0.0.1 54321 80\r\nGET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        var proxy_hdr = net::ProxyHeader { .. };
        let rest, has_proxy = net::detect_and_strip_proxy_header(stream, proxy_hdr);

        sub.assert_true(has_proxy, "PROXY header detected and stripped");
        sub.assert_bytes_eq(proxy_hdr.src_ip_str[..], "203.0.113.195", "Client IP extracted from PROXY v1");
        sub.assert_bytes_eq(rest[..15], "GET /index.html", "Remaining stream starts with HTTP request");

        // Non-proxy stream returns original stream unchanged
        let non_proxy = "GET /status HTTP/1.1\r\nHost: test.com\r\n\r\n";
        var empty_hdr = net::ProxyHeader { .. };
        let rest2, has_proxy2 = net::detect_and_strip_proxy_header(non_proxy, empty_hdr);
        sub.assert_false(has_proxy2, "No PROXY header detected on plain HTTP");
        sub.assert_bytes_eq(rest2, non_proxy, "Plain HTTP stream unchanged");
    };

    t.run("HttpServer with accept_proxy_protocol = true") { sub =>
        var server = server::new_http_server("127.0.0.1", 8080);
        server.accept_proxy_protocol = true;
        var trusted_cidr: u8[..64] = [];
        let _ = trusted_cidr.try_set("127.0.0.0/8");
        let _ = server.proxy_protocol_trusted_cidrs.try_push(trusted_cidr);
        server::add_get_route(server, "/api/hello", 101);

        // Prepend PROXY v1 header before HTTP/1.1 wire request
        let wire_in = "PROXY TCP4 198.51.100.77 10.0.0.1 61234 8080\r\nGET /api/hello HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
        var wire_out: u8[..512] = [];

        let outcome, ok = server::handle_connection_wire(server, "127.0.0.1", wire_in, 1700000000, wire_out);
        sub.assert_true(ok, "handle_connection_wire succeeds with PROXY header");
        sub.assert_true(outcome == server::PipelineOutcome.Handled, "Pipeline handled route");
        sub.assert_gt(wire_out.len, 0, "Response generated");
        sub.assert_bytes_eq(wire_out[..15], "HTTP/1.1 200 OK", "Server returned 200 OK");
        sub.assert_eq(server.requests_processed, 1, "Requests counter incremented");
    };
}

// --- Component: net_proxy_health_check ---
// Verification suite for proxy/health_check and load_balancer integration:
// Active background health check probing, state machine transitions (UP, DOWN, PROBING),
// consecutive success/failure thresholds, and circuit breaker interlock.

// ----------------------------------------------------------------------------
// 9. Health State Machine Transitions
// ----------------------------------------------------------------------------
fn test_health_state_transitions(t: lit::T&) {
    t.run("Up -> Down on Consecutive Failures") { sub =>
        let cfg = proxy::new_health_check_config(5000, 2000, 2, 3);
        var health = proxy::UpstreamHealth { .. };
        sub.assert_true(health.state == proxy::HealthState.Up, "Initial state is Up");

        // Fail 1 & 2: still Up
        proxy::record_probe_failure(health, cfg);
        sub.assert_true(health.state == proxy::HealthState.Up, "State remains Up after 1 failure");
        sub.assert_eq(health.consecutive_failures, 1, "Consecutive failures = 1");

        proxy::record_probe_failure(health, cfg);
        sub.assert_true(health.state == proxy::HealthState.Up, "State remains Up after 2 failures");

        // Fail 3: threshold reached -> transitions to Down
        proxy::record_probe_failure(health, cfg);
        sub.assert_true(health.state == proxy::HealthState.Down, "State transitioned to Down at 3 failures");
        sub.assert_eq(health.consecutive_failures, 3, "Consecutive failures = 3");
    };

    t.run("Down -> Probing -> Up on Consecutive Successes") { sub =>
        let cfg = proxy::new_health_check_config(5000, 2000, 2, 3);
        var health = proxy::UpstreamHealth { .. };
        health.state = proxy::HealthState.Down;
        health.consecutive_failures = 3;

        // Manual or probe entry to Probing
        let entered = proxy::enter_probing_state(health);
        sub.assert_true(entered, "Successfully entered Probing state from Down");
        sub.assert_true(health.state == proxy::HealthState.Probing, "State is Probing");

        // First success: not yet Up (threshold is 2)
        proxy::record_probe_success(health, 1500, cfg);
        sub.assert_true(health.state == proxy::HealthState.Probing, "Still Probing after 1 success");
        sub.assert_eq(health.consecutive_successes, 1, "Consecutive successes = 1");
        sub.assert_eq(health.consecutive_failures, 0, "Failures reset on success");

        // Second success: reaches threshold 2 -> transitions to Up
        proxy::record_probe_success(health, 1200, cfg);
        sub.assert_true(health.state == proxy::HealthState.Up, "State transitioned to Up at 2 successes");
        sub.assert_eq(health.consecutive_successes, 2, "Consecutive successes = 2");
    };

    t.run("Probing Failure Demotes to Down") { sub =>
        let cfg = proxy::new_health_check_config(5000, 2000, 2, 1);
        var health = proxy::UpstreamHealth { .. };
        health.state = proxy::HealthState.Probing;
        health.consecutive_successes = 1;

        // Failure during probing immediately drops back to Down
        proxy::record_probe_failure(health, cfg);
        sub.assert_true(health.state == proxy::HealthState.Down, "Failed probe in Probing drops to Down");
        sub.assert_eq(health.consecutive_successes, 0, "Successes reset to 0");
    };
}

// ----------------------------------------------------------------------------
// 10. Probe Wire Formatting and Response Evaluation
// ----------------------------------------------------------------------------
fn test_probe_wire_and_response_parsing(t: lit::T&) {
    t.run("Format Health Probe HTTP/1.1 Request") { sub =>
        var wire: u8[>..] = [];
        proxy::format_health_probe_request("api.internal:8080", "/healthz", wire);

        let s = wire[..];
        sub.assert_true(s.len > 0, "Wire buffer populated");
        sub.assert_eq(s[0..4], "GET ", "Begins with GET");
        sub.assert_true(core::contains(s, "Host: api.internal:8080"), "Contains Host header");
        sub.assert_true(core::contains(s, "User-Agent: wing-health-probe"), "Contains User-Agent");
        sub.assert_true(core::contains(s, "Connection: close"), "Contains Connection: close");
    };

    t.run("Parse HTTP Status Code from Wire Response") { sub =>
        let resp_200: u8[..64] = "HTTP/1.1 200 OK\r\nContent-Len: 0\r\n";
        let code200, ok200 = proxy::parse_probe_status_code(resp_200[..]);
        sub.assert_true(ok200, "Parsed 200 response");
        sub.assert_eq(code200, 200, "Code is 200");
        sub.assert_true(proxy::evaluate_probe_response(resp_200[..], 200), "Evaluate 200 matches expected");

        let resp_503: u8[..64] = "HTTP/1.1 503 Unavailable\r\n\r\n";
        let code503, ok503 = proxy::parse_probe_status_code(resp_503[..]);
        sub.assert_true(ok503, "Parsed 503 response");
        sub.assert_eq(code503, 503, "Code is 503");
        sub.assert_true(!proxy::evaluate_probe_response(resp_503[..], 200), "503 does not match 200");

        let resp_bad: u8[..16] = "GARBAGE DATA";
        let _, ok_bad = proxy::parse_probe_status_code(resp_bad[..]);
        sub.assert_true(!ok_bad, "Garbage data rejected cleanly");
    };
}

// ----------------------------------------------------------------------------
// 11. Cluster Health Checker Engine
// ----------------------------------------------------------------------------
fn test_cluster_health_checker_integration(t: lit::T&) {
    t.run("Cluster Active Health Check Engine") { sub =>
        var cluster = proxy::new_upstream_cluster(proxy::LbPolicy.RoundRobin, 2);
        proxy::add_upstream_target(cluster, "10.0.0.1", 8080);
        proxy::add_upstream_target(cluster, "10.0.0.2", 8080);

        let cfg = proxy::new_health_check_config(1000, 500, 2, 2);
        var checker = proxy::new_cluster_health_checker(cfg);
        proxy::register_target_for_probing(checker, 0);
        proxy::register_target_for_probing(checker, 1);

        // Fail target 0 via load balancer failures
        proxy::record_upstream_failure(cluster, 0);
        proxy::record_upstream_failure(cluster, 0);
        sub.assert_true(!cluster.targets[0].is_healthy, "Target 0 is marked unhealthy");
        sub.assert_true(cluster.targets[0].health_state == proxy::UpstreamHealthState.Down, "Target 0 state is Down");

        // Fail target 1 via health checker failure
        let state1 = proxy::on_probe_failure(checker, cluster, 1);
        sub.assert_true(state1 == proxy::HealthState.Up, "Target 1 remains Up on 1st fail");
        let state2 = proxy::on_probe_failure(checker, cluster, 1);
        sub.assert_true(state2 == proxy::HealthState.Down, "Target 1 Down on 2nd fail");
        sub.assert_true(cluster.circuit_open, "Cluster circuit tripped open when all targets are Down");

        // Recover target 0 via active probe successes
        proxy::on_probe_success(checker, cluster, 0, 800);
        sub.assert_true(cluster.targets[0].health_state == proxy::UpstreamHealthState.Probing, "Target 0 enters Probing");

        proxy::on_probe_success(checker, cluster, 0, 750);
        sub.assert_true(cluster.targets[0].health_state == proxy::UpstreamHealthState.Up, "Target 0 promoted to Up");
        sub.assert_true(cluster.targets[0].is_healthy, "Target 0 is healthy again");
        sub.assert_true(!cluster.circuit_open, "Cluster circuit breaker restored");

        // Verify upstream dispatch now succeeds and selects target 0
        let chosen, ok = proxy::select_upstream(cluster);
        sub.assert_true(ok, "Upstream selection succeeds");
        sub.assert_eq(chosen, 0, "Target 0 selected");
    };

    t.run("Probing State Hysteresis on Cluster Sync") { sub =>
        var cluster = proxy::new_upstream_cluster(proxy::LbPolicy.RoundRobin, 2);
        proxy::add_upstream_target(cluster, "10.0.0.1", 8080);

        let cfg = proxy::new_health_check_config(1000, 500, 2, 2);
        var checker = proxy::new_cluster_health_checker(cfg);
        proxy::register_target_for_probing(checker, 0);

        // Fail target 0 via load balancer failures
        proxy::record_upstream_failure(cluster, 0);
        proxy::record_upstream_failure(cluster, 0);
        sub.assert_true(cluster.targets[0].health_state == proxy::UpstreamHealthState.Down, "Target 0 state is Down");

        // Manually place in Probing mode
        proxy::set_upstream_probing(cluster, 0);
        sub.assert_true(cluster.targets[0].health_state == proxy::UpstreamHealthState.Probing, "Target 0 in Probing");

        // Reset checker slot to Up to simulate desync prior to probe
        checker.slots[0].health.state = proxy::HealthState.Up;

        // 1st probe success must NOT promote directly to Up; sync_slot_from_cluster must enforce Probing
        let st1 = proxy::on_probe_success(checker, cluster, 0, 500);
        sub.assert_true(st1 == proxy::HealthState.Probing, "Target 0 remains Probing after 1st success");
        sub.assert_true(!cluster.targets[0].is_healthy, "Target 0 remains unhealthy in cluster during Probing");

        // 2nd probe success reaches healthy_threshold (2) -> promoted to Up
        let st2 = proxy::on_probe_success(checker, cluster, 0, 500);
        sub.assert_true(st2 == proxy::HealthState.Up, "Target 0 promoted to Up after 2nd success");
        sub.assert_true(cluster.targets[0].is_healthy, "Target 0 is healthy again");
    };
}

// ----------------------------------------------------------------------------
// 12. Reverse Proxy Hardening & Backpressure
// ----------------------------------------------------------------------------
fn test_reverse_proxy_hardening(t: lit::T&) {
    t.run("Connection Leak Defense and Lifecycle") { sub =>
        var rp = proxy::new_reverse_proxy(proxy::LbPolicy.RoundRobin);
        proxy::add_upstream_target(rp.cluster, "upstream.local:8080", 8080);

        var in_headers = http::HeaderMap { .. };
        http::append_header(in_headers, "Host", "frontend.test");

        var wire: u8[>..] = [];
        let t_idx, ok = proxy::prepare_proxy_request(rp, "GET", "/api", in_headers, "127.0.0.1", "http", "", wire);
        sub.assert_true(ok, "Proxy request prepared");
        sub.assert_eq(t_idx, 0, "Dispatched to target 0");
        sub.assert_eq(rp.cluster.targets[0].active_conns, 1, "Target 0 active_conns = 1");

        // Complete successfully -> active_conns decremented
        proxy::finish_proxy_request(rp, t_idx, true);
        sub.assert_eq(rp.cluster.targets[0].active_conns, 0, "Active conns decremented to 0 upon finish");

        // Dispatched second time, then aborted -> active_conns decremented cleanly
        let t_idx2, ok2 = proxy::prepare_proxy_request(rp, "GET", "/api", in_headers, "127.0.0.1", "http", "", wire);
        sub.assert_true(ok2, "Second request prepared");
        sub.assert_eq(rp.cluster.targets[0].active_conns, 1, "Active conns is 1");

        proxy::abort_proxy_request(rp, t_idx2);
        sub.assert_eq(rp.cluster.targets[0].active_conns, 0, "Active conns decremented to 0 upon abort");
    };

    t.run("Concurrency Backpressure and Overload Defense") { sub =>
        var rp = proxy::new_reverse_proxy(proxy::LbPolicy.RoundRobin);
        proxy::add_upstream_target(rp.cluster, "backend.srv:8080", 8080);
        rp.config.max_active_conns_per_target = 2;

        var in_headers = http::HeaderMap { .. };
        http::append_header(in_headers, "Host", "test.example.com");

        var wire: u8[>..] = [];
        let idx1, ok1 = proxy::prepare_proxy_request(rp, "GET", "/", in_headers, "10.0.0.1", "http", "", wire);
        let idx2, ok2 = proxy::prepare_proxy_request(rp, "GET", "/", in_headers, "10.0.0.2", "http", "", wire);
        sub.assert_true(ok1 && ok2, "First 2 requests admitted up to concurrency ceiling");
        sub.assert_eq(rp.cluster.targets[0].active_conns, 2, "Active connections reached ceiling of 2");

        // 3rd request exceeds max_active_conns_per_target (2)
        let idx3, ok3 = proxy::prepare_proxy_request(rp, "GET", "/", in_headers, "10.0.0.3", "http", "", wire);
        sub.assert_true(!ok3, "3rd request rejected due to target concurrency overload");
        sub.assert_eq(rp.cluster.targets[0].active_conns, 2, "Active conns remains 2 (no connection leak!)");
        sub.assert_eq(rp.total_overloaded, 1, "total_overloaded recorded");
        sub.assert_eq(rp.total_dropped, 1, "total_dropped recorded");

        // Finishing request 1 frees slot
        proxy::finish_proxy_request(rp, idx1, true);
        sub.assert_eq(rp.cluster.targets[0].active_conns, 1, "Active conns decreased to 1");

        // Now next request succeeds
        let idx4, ok4 = proxy::prepare_proxy_request(rp, "GET", "/", in_headers, "10.0.0.4", "http", "", wire);
        sub.assert_true(ok4, "Admitted after connection freed");
        sub.assert_eq(rp.cluster.targets[0].active_conns, 2, "Active conns is back to 2");
    };

    t.run("Hop-by-hop and Metadata Spoofing Defense") { sub =>
        var rp = proxy::new_reverse_proxy(proxy::LbPolicy.RoundRobin);
        proxy::add_upstream_target(rp.cluster, "app.internal:80", 80);

        var in_headers = http::HeaderMap { .. };
        http::append_header(in_headers, "Host", "legit.example.com");
        http::append_header(in_headers, "Connection", "keep-alive, X-Secret-Internal");
        http::append_header(in_headers, "X-Secret-Internal", "should-be-stripped");
        http::append_header(in_headers, "X-Forwarded-Host", "evil-spoof.com");
        http::append_header(in_headers, "X-Forwarded-Proto", "gopher");
        http::append_header(in_headers, "X-Forwarded-Ssl", "on");

        var wire: u8[>..] = [];
        let _, ok = proxy::prepare_proxy_request(rp, "GET", "/secure", in_headers, "203.0.113.5", "https", "", wire);
        sub.assert_true(ok, "Request prepared");

        let s = wire[..];
        sub.assert_true(!core::contains(s, "evil-spoof.com"), "Spoofed X-Forwarded-Host stripped");
        sub.assert_true(!core::contains(s, "gopher"), "Spoofed X-Forwarded-Proto stripped");
        sub.assert_true(!core::contains(s, "should-be-stripped"), "Connection-listed token stripped");
        sub.assert_true(!core::contains(s, "X-Forwarded-Ssl"), "X-Forwarded-Ssl stripped");
        sub.assert_true(core::contains(s, "X-Forwarded-Proto: https"), "Valid proxy proto injected");
        sub.assert_true(core::contains(s, "X-Forwarded-Host: legit.example.com"), "Valid proxy host injected");
    };

    t.run("GCRA Rate Limiting Shield") { sub =>
        var rp = proxy::new_reverse_proxy(proxy::LbPolicy.RoundRobin);
        proxy::add_upstream_target(rp.cluster, "backend.internal:8080", 8080);
        rp.config.enable_rate_limiting = true;
        rp.rate_limiter = security::new_gateway_rate_limiter(10, 1); // 10 rps, burst 1

        var in_headers = http::HeaderMap { .. };
        http::append_header(in_headers, "Host", "test.example.com");

        var wire: u8[>..] = [];
        let client_ip: u8[..16] = "198.51.100.77";
        let now_ns:    u64      = 1000000000;

        let _, ok1 = proxy::prepare_proxy_request_at(rp, "GET", "/", in_headers, client_ip[..], "http", "", wire, now_ns);
        let _, ok2 = proxy::prepare_proxy_request_at(rp, "GET", "/", in_headers, client_ip[..], "http", "", wire, now_ns);
        sub.assert_true(ok1 && ok2, "Burst requests admitted");

        // 3rd request at same timestamp -> Rate limited!
        let _, ok3 = proxy::prepare_proxy_request_at(rp, "GET", "/", in_headers, client_ip[..], "http", "", wire, now_ns);
        sub.assert_true(!ok3, "3rd request rejected by GCRA rate limit");
        sub.assert_eq(rp.total_rate_limited, 1, "total_rate_limited recorded");
        sub.assert_eq(rp.cluster.targets[0].active_conns, 2, "Upstream active conns untouched by rejected request");
    };

    t.run("P2C Resilient Fallback on Degraded Cluster") { sub =>
        var cluster = proxy::new_upstream_cluster(proxy::LbPolicy.RandomTwoChoice, 2);
        proxy::add_upstream_target(cluster, "10.0.0.1", 8080);
        proxy::add_upstream_target(cluster, "10.0.0.2", 8080);
        proxy::add_upstream_target(cluster, "10.0.0.3", 8080);
        proxy::add_upstream_target(cluster, "10.0.0.4", 8080);

        // Mark nodes 1, 2, 3 as unhealthy; only node 0 remains UP
        cluster.targets[1].is_healthy = false;
        cluster.targets[2].is_healthy = false;
        cluster.targets[3].is_healthy = false;

        // Select 20 times: all 20 must succeed and select node 0 via least-connections fallback
        for _ in 20 {
            let chosen, ok = proxy::select_upstream(cluster);
            sub.assert_true(ok, "P2C gracefully falls back and finds healthy target");
            sub.assert_eq(chosen, 0, "Selected only healthy node 0");
            proxy::release_upstream_connection(cluster, chosen);
        }
    };

    t.run("X-Forwarded-For Edge Perimeter Spoofing vs Trust Chaining") { sub =>
        var rp = proxy::new_reverse_proxy(proxy::LbPolicy.RoundRobin);
        proxy::add_upstream_target(rp.cluster, "app.internal:80", 80);

        var in_headers = http::HeaderMap { .. };
        http::append_header(in_headers, "Host", "api.example.com");
        http::append_header(in_headers, "X-Forwarded-For", "127.0.0.1, 10.0.0.1");

        // 1. Default mode: trust_incoming_xff is false -> spoofed XFF dropped
        var wire_untrusted: u8[>..] = [];
        let _, ok1 = proxy::prepare_proxy_request(
            rp,
            "GET",
            "/api",
            in_headers,
            "203.0.113.195",
            "https",
            "",
            wire_untrusted,
        );
        sub.assert_true(ok1, "Untrusted XFF request prepared");
        sub.assert_true(!core::contains(wire_untrusted[..], "127.0.0.1"), "Spoofed 127.0.0.1 dropped at edge");
        sub.assert_true(!core::contains(wire_untrusted[..], "10.0.0.1"), "Spoofed 10.0.0.1 dropped at edge");
        sub.assert_true(core::contains(wire_untrusted[..], "X-Forwarded-For: 203.0.113.195"), "Real client IP injected");

        // 2. Internal proxy mode: trust_incoming_xff is true -> chained
        rp.config.trust_incoming_xff = true;
        var wire_trusted: u8[>..] = [];
        let _, ok2 = proxy::prepare_proxy_request(
            rp,
            "GET",
            "/api",
            in_headers,
            "203.0.113.195",
            "https",
            "",
            wire_trusted,
        );
        sub.assert_true(ok2, "Trusted XFF request prepared");
        sub.assert_true(core::contains(wire_trusted[..], "X-Forwarded-For: 127.0.0.1, 10.0.0.1, 203.0.113.195"), "Chained XFF forwarded");
    };

    t.run("Dynamic Rate Limiter Synchronization") { sub =>
        var rp = proxy::new_reverse_proxy(proxy::LbPolicy.RoundRobin);
        proxy::add_upstream_target(rp.cluster, "backend.internal:8080", 8080);

        // Configure rate limit dynamically via helper
        proxy::set_proxy_rate_limit(rp, 10, 1);
        sub.assert_true(rp.config.enable_rate_limiting, "Rate limit enabled");
        sub.assert_eq(rp.config.rate_limit_rps, 10, "Config RPS is 10");
        sub.assert_eq(rp.config.rate_limit_burst, 1, "Config burst is 1");

        var in_headers = http::HeaderMap { .. };
        http::append_header(in_headers, "Host", "test.example.com");

        var wire: u8[>..] = [];
        let client_ip: u8[..16] = "198.51.100.88";
        let now_ns:    u64      = 2000000000;

        let _, ok1 = proxy::prepare_proxy_request_at(rp, "GET", "/", in_headers, client_ip[..], "http", "", wire, now_ns);
        let _, ok2 = proxy::prepare_proxy_request_at(rp, "GET", "/", in_headers, client_ip[..], "http", "", wire, now_ns);
        sub.assert_true(ok1 && ok2, "Initial burst requests admitted");

        // 3rd request rejected by dynamically synchronized limiter
        let _, ok3 = proxy::prepare_proxy_request_at(rp, "GET", "/", in_headers, client_ip[..], "http", "", wire, now_ns);
        sub.assert_true(!ok3, "3rd request rejected by synced GCRA rate limit");
    };
}

// --- Component: net_proxy_gcra ---
// Verification suite for proxy/gcra: Zero-allocation GCRA rate limiting,
// burst tolerance (tau), emission interval (T), TAT tracking,
// clock drift protection, and bounded GatewayRateLimiter.

// ----------------------------------------------------------------------------
// 13. GCRA Core Algorithm & Conformance
// ----------------------------------------------------------------------------
fn test_gcra_core_algorithm(t: lit::T&) {
    t.run("GCRA Quota and Single-Cell Conformance") { sub =>
        // 10 rps -> T = 100ms (100,000,000 ns), burst = 2 -> tau = 200ms (200,000,000 ns)
        let cfg = security::new_gcra_config(10, 2);
        sub.assert_eq(cfg.emission_interval_ns, 100000000, "Emission interval T is 100ms");
        sub.assert_eq(cfg.tau_ns, 200000000, "Burst tolerance tau is 200ms");
        sub.assert_eq(cfg.max_burst, 2, "Max burst capacity is 2");

        var cell = security::GcraCell { tat_ns: 0 };
        let now_ns: u64 = 1000000000; // 1.0s

        // Cell 1: Initial arrival
        let dec1 = security::gcra_check(cfg, cell, 1, now_ns);
        sub.assert_true(dec1.allowed, "First cell is allowed");
        sub.assert_eq(dec1.remaining_burst, 2, "Burst capacity remains 2 on cold start");
        sub.assert_eq(cell.tat_ns, 1100000000, "TAT advanced to now + T");

        // Cell 2: Immediate burst arrival at same timestamp
        let dec2 = security::gcra_check(cfg, cell, 1, now_ns);
        sub.assert_true(dec2.allowed, "Burst cell 2 is allowed");
        sub.assert_eq(dec2.remaining_burst, 1, "Remaining burst decremented to 1");
        sub.assert_eq(cell.tat_ns, 1200000000, "TAT advanced to 1.2s");

        // Cell 3: Second burst arrival at same timestamp
        let dec3 = security::gcra_check(cfg, cell, 1, now_ns);
        sub.assert_true(dec3.allowed, "Burst cell 3 is allowed");
        sub.assert_eq(dec3.remaining_burst, 0, "Remaining burst exhausted (0)");
        sub.assert_eq(cell.tat_ns, 1300000000, "TAT advanced to 1.3s");

        // Cell 4: Over-burst arrival at same timestamp -> REJECT
        let dec4 = security::gcra_check(cfg, cell, 1, now_ns);
        sub.assert_true(!dec4.allowed, "Cell 4 rejected due to burst exhaustion");
        sub.assert_true(dec4.retry_after_ns > 0, "Retry-after is non-zero");
        sub.assert_eq(dec4.retry_after_ns, 100000000, "Retry-after is 100ms");
        sub.assert_eq(cell.tat_ns, 1300000000, "TAT unchanged on rejection");

        // Advance clock by 100ms -> Cell 5 admitted
        let now_later = now_ns + 100000000;
        let dec5 = security::gcra_check(cfg, cell, 1, now_later);
        sub.assert_true(dec5.allowed, "Cell 5 admitted after 100ms delay");
        sub.assert_eq(dec5.remaining_burst, 0, "Remaining burst is 0");
    };

    t.run("GCRA Peek, Penalize, and Reset Semantics") { sub =>
        let cfg = security::new_gcra_config(5, 1); // 200ms per cell
        var cell = security::GcraCell { tat_ns: 0 };
        let now_ns: u64 = 5000000000;

        // Peek should not alter TAT
        let peek_dec = security::gcra_peek(cfg, cell, 1, now_ns);
        sub.assert_true(peek_dec.allowed, "Peek shows cell is allowed");
        sub.assert_eq(cell.tat_ns, 0, "Cell TAT remains untouched after peek");

        // Check mutates TAT
        let check_dec = security::gcra_check(cfg, cell, 1, now_ns);
        sub.assert_true(check_dec.allowed, "Check allows request");
        sub.assert_eq(cell.tat_ns, 5200000000, "Check advances TAT by 200ms");

        // Penalize pushes TAT further into future
        security::gcra_penalize(cfg, cell, 1000000000, now_ns); // +1s penalty
        sub.assert_eq(cell.tat_ns, 6200000000, "Penalize pushed TAT by 1.0s");

        // Subsequent check at 5.1s should fail due to penalty
        let pen_check = security::gcra_check(cfg, cell, 1, 5100000000);
        sub.assert_true(!pen_check.allowed, "Request rejected under penalty delay");

        // Reset clears TAT
        security::gcra_reset(cell);
        sub.assert_eq(cell.tat_ns, 0, "Reset restores cell TAT to 0");
    };

    t.run("BUG-04 Defense: NTP Backward Jump Clamping Updates cell.tat_ns") { sub =>
        let cfg = security::new_gcra_config(10, 2); // limit_window = 300ms
        // Set TAT to distant future (50s in future due to corrupted clock)
        var cell = security::GcraCell { tat_ns: 50000000000 };
        let now_ns: u64 = 1000000000; // clock jumped back to 1.0s

        // BUG-04 fix verifies cell.tat_ns is clamped down even when request is rejected
        let dec = security::gcra_check(cfg, cell, 1, now_ns);
        sub.assert_true(!dec.allowed, "Rejected during clamped limit window");
        sub.assert_eq(cell.tat_ns, 1300000000, "TAT clamped to now + limit_window (1.3s)");

        // After limit window passes (at 1.4s), client recovers without permanent lockout
        let dec_rec = security::gcra_check(cfg, cell, 1, 1400000000);
        sub.assert_true(dec_rec.allowed, "Client successfully recovers after clamped window");
    };
}

// ----------------------------------------------------------------------------
// 14. Gateway Multi-Client Rate Limiter
// ----------------------------------------------------------------------------
fn test_gateway_rate_limiter(t: lit::T&) {
    t.run("Multi-Client Isolation and Limiting") { sub =>
        var limiter = security::new_gateway_rate_limiter(10, 2);
        let client_a: u8[..16] = "192.168.1.100";
        let client_b: u8[..16] = "10.0.0.1";
        let now_ns:   u64      = 1000000000;

        // Client A consumes all 3 burst tokens
        let da1 = security::check_gateway_rate_limit(limiter, client_a[..], 1, now_ns);
        let da2 = security::check_gateway_rate_limit(limiter, client_a[..], 1, now_ns);
        let da3 = security::check_gateway_rate_limit(limiter, client_a[..], 1, now_ns);
        sub.assert_true(da1.allowed && da2.allowed && da3.allowed, "Client A burst allowed");

        // 4th request from Client A rejected
        let da4 = security::check_gateway_rate_limit(limiter, client_a[..], 1, now_ns);
        sub.assert_true(!da4.allowed, "Client A over-burst rejected");

        // Client B is isolated and has full capacity
        let db1 = security::check_gateway_rate_limit(limiter, client_b[..], 1, now_ns);
        sub.assert_true(db1.allowed, "Client B allowed independently of Client A");

        sub.assert_eq(limiter.total_allowed, 4, "Global allowed count is 4");
        sub.assert_eq(limiter.total_rejected, 1, "Global rejected count is 1");
    };

    t.run("Idle Client Eviction and Table Reset") { sub =>
        var limiter = security::new_gateway_rate_limiter(5, 1);
        let client_old: u8[..16] = "172.16.0.5";
        let now_ns:     u64      = 1000000000;

        security::check_gateway_rate_limit(limiter, client_old[..], 1, now_ns);
        sub.assert_eq(limiter.entries.len, 1, "1 client slot registered");

        // Evict with 2s max_idle at now + 5s (idle time = 5s > 2s)
        let now_later = now_ns + 5000000000;
        let evicted = security::evict_idle_gateway_clients(limiter, 2000000000, now_later);
        sub.assert_eq(evicted, 1, "1 idle client entry evicted");

        // Reset clears all counters
        security::reset_gateway_rate_limiter(limiter);
        sub.assert_eq(limiter.total_allowed, 0, "Allowed reset to 0");
        sub.assert_eq(limiter.total_rejected, 0, "Rejected reset to 0");
    };
}

// --- Component: net_rate_limiter ---
// Tests for GCRA rate limiter, burst tolerance, and sharded storage.

// ----------------------------------------------------------------------------
// 15. Mathematical GCRA TAT Scheduling & Burst Tolerance
// ----------------------------------------------------------------------------
fn test_gcra_tat_and_burst(t: lit::T&) {
    t.run("Single-Cell Ingress & Burst Tolerance Exhaustion") { sub =>
        // Limit: 10 req/s (T = 100 ms), Burst: 2 (tau = 200 ms)
        let quota = security::new_gcra_quota(10, wing::secs(1), 2);
        sub.assert_eq(quota.emission_interval_ns, 100000000, "T = 100ms");
        sub.assert_eq(quota.delay_tolerance_ns, 200000000, "tau = 200ms");

        var cell = security::GcraCell { tat_ns: 0 };
        let t0: u64 = 1000000000; // t = 1.0s

        // Request 1 at t0: allowed, TAT becomes t0 + 100ms
        let d1 = security::gcra_check_n(quota, cell, 1, t0);
        sub.assert_true(security::is_allowed(d1), "req 1 allowed");
        sub.assert_eq(cell.tat_ns, t0 + 100000000, "TAT advanced by T");

        // Request 2 at t0: allowed, TAT becomes t0 + 200ms
        let d2 = security::gcra_check_n(quota, cell, 1, t0);
        sub.assert_true(security::is_allowed(d2), "req 2 allowed");
        sub.assert_eq(cell.tat_ns, t0 + 200000000, "TAT advanced to t0 + 200ms");

        // Request 3 at t0: allowed (burst limit = tau + T = 300ms)
        let d3 = security::gcra_check_n(quota, cell, 1, t0);
        sub.assert_true(security::is_allowed(d3), "req 3 allowed at burst threshold");
        sub.assert_eq(cell.tat_ns, t0 + 300000000, "TAT at max window limit");

        // Request 4 at t0: REJECTED! TAT would exceed limit window
        let d4 = security::gcra_check_n(quota, cell, 1, t0);
        sub.assert_false(security::is_allowed(d4), "req 4 rejected (burst exceeded)");
        let ok_rej = match d4 {
            Rejected r => r.retry_after_ns > 0,
            _ => false,
        };
        sub.assert_true(ok_rej, "retry_after_ns > 0 on rejection");
        sub.assert_eq(cell.tat_ns, t0 + 300000000, "TAT unchanged on rejection");

        // Advance clock by 100ms: quota for 1 cell recovers!
        let t1 = t0 + 100000000;
        let d5 = security::gcra_check_n(quota, cell, 1, t1);
        sub.assert_true(security::is_allowed(d5), "req 5 allowed after 100ms clock advance");
        sub.assert_eq(cell.tat_ns, t0 + 400000000, "TAT advanced to t0 + 400ms");
    };
}

// ----------------------------------------------------------------------------
// 16. Anti-Starvation Multi-Cell Priority Reservation (governor #16 Fix)
// ----------------------------------------------------------------------------
fn test_anti_starvation_reservation(t: lit::T&) {
    t.run("Priority Reservation Preempts Small Subsequent Requests") { sub =>
        // Limit: 1 req/sec (T = 1s), Burst: 0 (tau = 0)
        let quota = security::new_gcra_quota(1, wing::secs(1), 0);
        var cell = security::GcraCell { tat_ns: 0 };
        let now: u64 = 1000000000;

        // Ingress 1: cost 1 cell at now: allowed, TAT = now + 1s
        let d1 = security::gcra_check_n(quota, cell, 1, now);
        sub.assert_true(security::is_allowed(d1), "initial cell allowed");
        sub.assert_eq(cell.tat_ns, now + 1000000000, "TAT = now + 1s");

        // Heavy request requesting n=3 cells arrives immediately at now
        // Standard check would reject it. With gcra_reserve_n and max_wait = 5s:
        let d_res = security::gcra_reserve_n(quota, cell, 3, now, 5000000000);
        let ok_res = match d_res {
            Reserved r => r.wait_ns == 3000000000 && r.new_tat_ns == now + 4000000000,
            _ => false,
        };
        sub.assert_true(ok_res, "heavy request successfully reserved slot ahead of time");
        sub.assert_eq(cell.tat_ns, now + 4000000000, "TAT advanced by 3 cells to 4s");

        // Subsequent lighter request (n=1) arriving at now + 500ms tries to steal:
        let d_steal = security::gcra_check_n(quota, cell, 1, now + 500000000);
        sub.assert_false(security::is_allowed(d_steal), "lighter request cannot steal reserved heavy slot");

        // Heavy request completes reservation wait time and executes cleanly
        let now_after_wait = now + 3000000000;
        let d_after = security::gcra_check_n(quota, cell, 1, now_after_wait + 1000000000);
        sub.assert_true(security::is_allowed(d_after), "pipeline resumes after reservation window");
    };
}

// ----------------------------------------------------------------------------
// 17. 256-Micro-Shard Table & Per-Key Isolation
// ----------------------------------------------------------------------------
fn test_sharded_gcra_limiter(t: lit::T&) {
    t.run("Independent Client Quotas Across Shards") { sub =>
        // Limit: 2 req/s, Burst: 1 (allows 2 immediate requests at t0, 3rd rejected)
        let quota = security::new_gcra_quota(2, wing::secs(1), 1);
        var limiter = security::new_sharded_limiter(quota);
        let now: u64 = 2000000000;

        let ip_a = "192.168.1.10";
        let ip_b = "10.0.0.5";

        // IP A exhausts its quota (2 requests)
        let d_a1 = security::check_rate_limit(limiter, ip_a, 1, now);
        let d_a2 = security::check_rate_limit(limiter, ip_a, 1, now);
        let d_a3 = security::check_rate_limit(limiter, ip_a, 1, now);

        sub.assert_true(security::is_allowed(d_a1), "IP A req 1 allowed");
        sub.assert_true(security::is_allowed(d_a2), "IP A req 2 allowed");
        sub.assert_false(security::is_allowed(d_a3), "IP A req 3 rejected (exhausted)");

        // IP B must NOT be affected by IP A's exhaustion!
        let d_b1 = security::check_rate_limit(limiter, ip_b, 1, now);
        let d_b2 = security::check_rate_limit(limiter, ip_b, 1, now);
        sub.assert_true(security::is_allowed(d_b1), "IP B req 1 allowed independently");
        sub.assert_true(security::is_allowed(d_b2), "IP B req 2 allowed independently");
    };

    t.run("FNV-1a 256-Shard Uniform Key Distribution") { sub =>
        var seen_shards: bool[256] = [false; 256];
        var distinct_shards = 0;

        // Hash 100 distinct mock IP keys
        for i in 100 {
            var ip_buf: u8[..32] = [];
            ip_buf.append("192.168.");
            format(ip_buf, i);
            ip_buf.append(".1");

            let shard = (core::fnv1a_64(ip_buf[..]) & 0xFF) as i64;
            if !seen_shards[shard] {
                seen_shards[shard] = true;
                distinct_shards += 1;
            }
        }

        // 100 random keys should hit at least 25 distinct shards
        sub.assert_true(distinct_shards > 25, "FNV-1a uniformly distributes keys across 256 shards");
    };
}

// ----------------------------------------------------------------------------
// 18. Extreme DDoS Probabilistic Sampling (5%)
// ----------------------------------------------------------------------------
fn test_probabilistic_ddos_mitigation(t: lit::T&) {
    t.run("5% Statistical Sampling Under Extreme Load") { sub =>
        let quota = security::new_gcra_quota(1000, wing::secs(1), 100);
        var pgcra = security::new_probabilistic_gcra(quota, 20); // 1-in-20 = 5%

        var sampled_count = 0;
        var non_sampled_count = 0;
        let now: u64 = 1000000000;

        // Run 500 requests
        for i in 500 {
            let tat_before = pgcra.cell.tat_ns;
            let dec = security::check_rate_limit(pgcra, 1, now);
            if pgcra.cell.tat_ns != tat_before {
                sampled_count += 1;
            } else {
                non_sampled_count += 1;
            }
        }

        // Sampling rate is 1/20 = 5% (+/- random variance)
        sub.assert_true(sampled_count > 0, "sampled requests touched TAT cell");
        sub.assert_true(non_sampled_count > sampled_count, "majority of requests passed without lock/write");
    };
}

// ----------------------------------------------------------------------------
// 19. IETF RateLimit-* Header Synthesis
// ----------------------------------------------------------------------------
fn test_ietf_rate_limit_headers(t: lit::T&) {
    t.run("IETF Headers on Allowed Request") { sub =>
        let quota = security::new_gcra_quota(100, wing::secs(1), 10);
        let dec: security::RateLimitDecision = security::RateLimitDecision.Allowed {
            remaining_burst: 8,
            new_tat_ns:      1200000000,
            reset_after_ns:  200000000,
        };

        var res = http::Response { .. };
        security::apply_rate_limit_headers(res, quota, dec);

        sub.assert_true(res.has_header("RateLimit-Limit"), "RateLimit-Limit emitted");
        sub.assert_eq(res.header("RateLimit-Limit"), "100", "RateLimit-Limit = 100");
        sub.assert_true(res.has_header("RateLimit-Remaining"), "RateLimit-Remaining emitted");
        sub.assert_eq(res.header("RateLimit-Remaining"), "8", "RateLimit-Remaining = 8");
        sub.assert_true(res.has_header("RateLimit-Reset"), "RateLimit-Reset emitted");
        sub.assert_eq(res.header("RateLimit-Reset"), "1", "RateLimit-Reset ceiling ceil(0.2s) = 1s");
    };

    t.run("IETF Headers & 429 Status on Rejected Request") { sub =>
        let quota = security::new_gcra_quota(50, wing::secs(1), 0);
        let dec: security::RateLimitDecision = security::RateLimitDecision.Rejected {
            retry_after_ns: 2500000000, // 2.5 seconds
            current_tat_ns: 3500000000,
        };

        var res = http::Response { .. };
        security::apply_rate_limit_headers(res, quota, dec);

        sub.assert_eq(res.status_code, 429, "status set to 429 Too Many Requests");

        sub.assert_true(res.has_header("Retry-After"), "Retry-After emitted");
        sub.assert_eq(res.header("Retry-After"), "3", "Retry-After ceil(2.5s) = 3s");
        sub.assert_true(res.has_header("RateLimit-Remaining"), "RateLimit-Remaining is 0");
        sub.assert_eq(res.header("RateLimit-Remaining"), "0", "RateLimit-Remaining = 0 on rejection");
    };
}

// ----------------------------------------------------------------------------
// 20. GCRA Arithmetic, Overflow & Zero Emission Invariants
// ----------------------------------------------------------------------------
fn test_gcra_arithmetic_and_overflow(t: lit::T&) {
    t.run("Zero Emission Interval Handling & Division by Zero") { sub =>
        // Limit 2,000,000 req per 1 ms (p_ns = 1,000,000, l = 2,000,000 -> p_ns / l = 0)
        let quota = security::new_gcra_quota(2000000, wing::millis(1), 10);
        sub.assert_true(quota.emission_interval_ns >= 1, "emission interval floored to >= 1ns to prevent division by zero");

        var cell = security::GcraCell { tat_ns: 0 };
        let dec = security::gcra_check_n(quota, cell, 1, 1000000);
        sub.assert_true(security::is_allowed(dec), "admission succeeds without divide-by-zero panic");
    };

    t.run("Accurate Burst Remaining Calculation in Reservation") { sub =>
        // Limit: 1 req/s (T = 1s), Burst: 5 (tau = 5s)
        let quota = security::new_gcra_quota(1, wing::secs(1), 5);
        var cell = security::GcraCell { tat_ns: 0 };
        let now: u64 = 1000000000;

        // Immediate reservation consuming 3 tokens
        let dec = security::gcra_reserve_n(quota, cell, 3, now, 10000000000);
        sub.assert_true(security::is_allowed(dec), "reservation allowed immediately");
        let remaining = match dec {
            Allowed a => a.remaining_burst,
            _ => 999,
        };
        // After consuming 3 tokens from initial burst capacity of 5, remaining burst must decrement
        sub.assert_true(remaining < 5, "remaining_burst must decrement, not report static quota.burst");
        sub.assert_eq(remaining, 3, "remaining_burst decrements to 3 after cost 3");
    };

    t.run("U64 Nanosecond Overflow In Burst Calculation") { sub =>
        let quota = security::new_gcra_quota(1, wing::secs(1), 5); // T = 1s, tau = 5s
        let now: u64 = 18446744073709551615 - 30000000000; // 30s before u64::MAX
        var cell = security::GcraCell { tat_ns: now };

        // Consuming 3 tokens near u64 limit:
        let dec = security::gcra_check_n(quota, cell, 3, now);
        sub.assert_true(security::is_allowed(dec), "admission succeeds near u64 boundaries");
        let remaining = match dec {
            Allowed a => a.remaining_burst,
            _ => 999,
        };
        // After cost 3 from burst 5, remaining burst must decrement to 3
        sub.assert_eq(remaining, 3, "burst correctly decrements without u64 wrap-around");
    };

    t.run("Clock Drift & Backward NTP Jump Recovery") { sub =>
        let quota = security::new_gcra_quota(10, wing::secs(1), 2);
        var cell = security::GcraCell { tat_ns: 60000000000 }; // TAT at 60s
        let now_backward: u64 = 10000000000; // Clock jumped back to 10s (50s backward jump)
        let dec = security::gcra_check_n(quota, cell, 1, now_backward);
        let retry_after = match dec {
            Rejected r => r.retry_after_ns,
            Allowed _ => 0,
            _ => 999999999999,
        };
        sub.assert_true(retry_after <= 200000000, "retry_after bounded to emission interval under 50s clock jump");
    };

    t.run("Clock Drift & Backward NTP Jump Recovery in Reservation") { sub =>
        let quota = security::new_gcra_quota(1, wing::secs(1), 0);
        var cell = security::GcraCell { tat_ns: 70000000000 }; // TAT at 70s
        let now_backward: u64 = 10000000000; // Clock jumped back to 10s
        let dec = security::gcra_reserve_n(quota, cell, 1, now_backward, 5000000000);
        let wait_ns = match dec {
            Reserved r => r.wait_ns,
            Allowed _ => 0,
            Rejected r => r.retry_after_ns,
        };
        sub.assert_true(wait_ns <= 1000000000, "reservation wait_ns bounded under 60s clock jump");
    };
}

// --- Component: net_masque ---
// Verification suite for MASQUE protocols:
// - RFC 9297: HTTP Datagrams & Capsule Protocol
// - RFC 9298: Proxying UDP in HTTP (CONNECT-UDP)
// - RFC 9484: Proxying IP in HTTP (CONNECT-IP)
// - RFC 9221: An Unreliable Datagram Extension to QUIC

// ----------------------------------------------------------------------------
// 21. RFC 9297 Capsules & HTTP Datagrams
// ----------------------------------------------------------------------------
fn test_rfc9297_capsules_and_datagrams(t: lit::T&) {
    t.run("Capsule Protocol Framing & Zero-Copy Decode") { sub =>
        var wire: u8[..256] = [];
        let raw_payload = "test_capsule_payload_bytes";
        let enc_ok = net::encode_http_capsule(wire, rfc::CAPSULE_DATAGRAM, raw_payload);
        sub.assert_true(enc_ok, "encode_http_capsule succeeded");

        let c, dec_ok = net::parse_http_capsule(wire[..]);
        sub.assert_true(dec_ok, "parse_http_capsule succeeded");
        sub.assert_eq(c.capsule_type, rfc::CAPSULE_DATAGRAM, "Type is rfc::CAPSULE_DATAGRAM (0x00)");
        sub.assert_bytes_eq(c.payload, raw_payload, "Payload bytes match exactly");

        // Truncated capsule wire detection
        let short_wire = wire[..wire.len - 3];
        let _, trunc_ok = net::parse_http_capsule(short_wire);
        sub.assert_false(trunc_ok, "Truncated capsule detected and rejected");

        // Capsule-Protocol RFC 9297 Section 3.4 / RFC 8941 validation
        sub.assert_true(net::is_capsule_protocol_negotiated("?1"), "Standard ?1");
        sub.assert_true(net::is_capsule_protocol_negotiated(" ?1; param=value "), "Structured ?1 with params");
        sub.assert_false(net::is_capsule_protocol_negotiated("?0"), "?0 rejected");

        var mock_hdrs = http::HeaderMap { .. };
        http::append_header(mock_hdrs, "capsule-protocol", "?1");
        sub.assert_true(net::has_capsule_protocol(mock_hdrs), "has_capsule_protocol on HeaderMap");
    };

    t.run("HTTP Datagrams over QUIC (Quarter Stream ID + Context ID)") { sub =>
        var dgram_wire: u8[..256] = [];
        let udp_sample = "dns_query_udp_payload";
        let quarter_stream_id: u64 = 2; // Stream ID 8 / 4 = 2
        let context_id:        u64 = 0; // Default uncompressed context

        let enc_ok = net::encode_http_datagram(dgram_wire, quarter_stream_id, context_id, udp_sample);
        sub.assert_true(enc_ok, "encode_http_datagram ok");

        let q_id, ctx_id, payload, dec_ok = net::decode_http_datagram(dgram_wire[..]);
        sub.assert_true(dec_ok, "decode_http_datagram ok");
        sub.assert_eq(q_id, 2, "Quarter stream ID matches (2)");
        sub.assert_eq(ctx_id, 0, "Context ID matches (0)");
        sub.assert_bytes_eq(payload, udp_sample, "Payload matches");

        // QUIC DATAGRAM frame (RFC 9221 Type 0x31 with length)
        var quic_frame_wire: u8[..256] = [];
        let frame_ok = quic::encode_datagram_frame(dgram_wire[..], quic_frame_wire, true);
        sub.assert_true(frame_ok, "encode_quic_datagram_frame ok");

        let parsed_dgram, end_off, frame_dec_ok = quic::decode_datagram_frame(quic_frame_wire[..], 0);
        sub.assert_true(frame_dec_ok, "decode_quic_datagram_frame ok");
        sub.assert_bytes_eq(parsed_dgram, dgram_wire[..], "Datagram bytes match inside QUIC frame");
    };
}

// ----------------------------------------------------------------------------
// 22. RFC 9298 MASQUE CONNECT-UDP
// ----------------------------------------------------------------------------
fn test_rfc9298_connect_udp(t: lit::T&) {
    t.run("URI Template Formatting and Parsing") { sub =>
        var path_buf: u8[..256] = [];
        net::format_connect_udp_path(path_buf, "1.1.1.1", 53);
        sub.assert_bytes_eq(path_buf[..], "/.well-known/masque/udp/1.1.1.1/53/", "Format IPv4 53");

        let host, port, ok = net::parse_connect_udp_path(path_buf[..]);
        sub.assert_true(ok, "parse_connect_udp_path ok");
        sub.assert_bytes_eq(host[..], "1.1.1.1", "Host parsed correctly");
        sub.assert_eq(port, 53, "Port parsed correctly (53)");

        // Domain name target
        var domain_path: u8[..256] = [];
        net::format_connect_udp_path(domain_path, "dns.google", 853);
        let d_host, d_port, d_ok = net::parse_connect_udp_path(domain_path[..]);
        sub.assert_true(d_ok, "parse domain target ok");
        sub.assert_bytes_eq(d_host[..], "dns.google", "Domain target parsed");
        sub.assert_eq(d_port, 853, "Port 853 parsed");

        // Invalid paths
        let _, _, bad1 = net::parse_connect_udp_path("/random/path/foo");
        sub.assert_false(bad1, "Random path rejected");

        let _, _, bad2 = net::parse_connect_udp_path("/.well-known/masque/udp/1.1.1.1/notaport/");
        sub.assert_false(bad2, "Non-numeric port rejected");
    };

    t.run("In-Stream DATAGRAM Capsule Serialization") { sub =>
        var wire: u8[..256] = [];
        let udp_data = "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01";
        let enc_ok = net::encode_connect_udp_datagram_capsule(wire, 0, udp_data);
        sub.assert_true(enc_ok, "encode_connect_udp_datagram_capsule ok");

        let c, ok_c = net::parse_http_capsule(wire[..]);
        sub.assert_true(ok_c, "parse outer capsule ok");
        sub.assert_eq(c.capsule_type, rfc::CAPSULE_DATAGRAM, "Capsule type is 0x00");

        let ctx_id, parsed_udp, ok_udp = net::parse_connect_udp_datagram(c.payload);
        sub.assert_true(ok_udp, "parse_connect_udp_datagram ok");
        sub.assert_eq(ctx_id, 0, "Context ID is 0");
        sub.assert_bytes_eq(parsed_udp, udp_data, "UDP payload matches");
    };
}

// ----------------------------------------------------------------------------
// 23. RFC 9484 MASQUE CONNECT-IP
// ----------------------------------------------------------------------------
fn test_rfc9484_connect_ip(t: lit::T&) {
    t.run("ADDRESS_REQUEST & ADDRESS_ASSIGN Capsules") { sub =>
        // 1. Client creates Address Request
        var req = net::IpAddressRequest {
            request_id: 1,
            ip_version: 4,
            prefix_len: 32,
            ..
        };
        req.requested_ip.append([10, 0, 0, 42]);

        var req_wire: u8[..256] = [];
        let req_enc_ok = net::encode_address_request_capsule(req_wire, req);
        sub.assert_true(req_enc_ok, "encode_address_request_capsule ok");

        let c_req, c_req_ok = net::parse_http_capsule(req_wire[..]);
        sub.assert_true(c_req_ok, "parse request capsule ok");
        sub.assert_eq(c_req.capsule_type, rfc::CAPSULE_ADDRESS_REQUEST, "Type is ADDRESS_REQUEST (0x02)");

        let dec_req, dec_req_ok = net::decode_address_request_capsule(c_req.payload);
        sub.assert_true(dec_req_ok, "decode_address_request_capsule ok");
        sub.assert_eq(dec_req.request_id, 1, "Request ID matches (1)");
        sub.assert_eq(dec_req.ip_version, 4, "IPv4");
        sub.assert_eq(dec_req.prefix_len, 32, "Prefix len 32");
        sub.assert_bytes_eq(dec_req.requested_ip[..], [10, 0, 0, 42], "IP matches 10.0.0.42");

        // 2. Server creates Address Assign
        var assign = net::IpAddressAssign {
            request_id: 1,
            ip_version: 4,
            prefix_len: 24,
            ..
        };
        assign.assigned_ip.append([192, 168, 1, 0]);

        var assign_wire: u8[..256] = [];
        let assign_enc_ok = net::encode_address_assign_capsule(assign_wire, assign);
        sub.assert_true(assign_enc_ok, "encode_address_assign_capsule ok");

        let c_assign, c_assign_ok = net::parse_http_capsule(assign_wire[..]);
        sub.assert_true(c_assign_ok, "parse assign capsule ok");
        sub.assert_eq(c_assign.capsule_type, rfc::CAPSULE_ADDRESS_ASSIGN, "Type is ADDRESS_ASSIGN (0x01)");

        let dec_assign, dec_assign_ok = net::decode_address_assign_capsule(c_assign.payload);
        sub.assert_true(dec_assign_ok, "decode_address_assign_capsule ok");
        sub.assert_eq(dec_assign.request_id, 1, "Request ID matches (1)");
        sub.assert_eq(dec_assign.prefix_len, 24, "Prefix len 24");
        sub.assert_bytes_eq(dec_assign.assigned_ip[..], [192, 168, 1, 0], "Assigned IP matches 192.168.1.0/24");
    };

    t.run("ROUTE_ADVERTISEMENT Capsule") { sub =>
        var route = net::RouteAdvertisement {
            ip_version:  4,
            ip_protocol: 0,
            ..
        };
        route.start_ip.append([10, 0, 0, 0]);
        route.end_ip.append([10, 0, 0, 255]);

        var route_wire: u8[..256] = [];
        let enc_ok = net::encode_route_advertisement_capsule(route_wire, route);
        sub.assert_true(enc_ok, "encode_route_advertisement_capsule ok");

        let c, c_ok = net::parse_http_capsule(route_wire[..]);
        sub.assert_true(c_ok, "parse route capsule ok");
        sub.assert_eq(c.capsule_type, rfc::CAPSULE_ROUTE_ADVERTISEMENT, "Type is ROUTE_ADVERTISEMENT (0x03)");

        let dec_route, dec_route_ok = net::decode_route_advertisement_capsule(c.payload);
        sub.assert_true(dec_route_ok, "decode_route_advertisement_capsule ok");
        sub.assert_eq(dec_route.ip_version, 4, "IPv4");
        sub.assert_bytes_eq(dec_route.start_ip[..], [10, 0, 0, 0], "Start IP 10.0.0.0 matches");
        sub.assert_bytes_eq(dec_route.end_ip[..], [10, 0, 0, 255], "End IP 10.0.0.255 matches");
        sub.assert_eq(dec_route.ip_protocol, 0, "IP Protocol 0 (all)");
    };
}

// ----------------------------------------------------------------------------
// 24. MASQUE Client Sessions & Tunneling
// ----------------------------------------------------------------------------
fn test_masque_client_sessions_and_tunneling(t: lit::T&) {
    t.run("CONNECT-UDP Handshake & End-to-End Tunneling via Client") { sub =>
        var client = client::new_client();

        // Configure mock proxy accepting CONNECT-UDP
        client::mock_route(client, "CONNECT", "https://proxy.privacy.org/.well-known/masque/udp/1.1.1.1/53/", 200, "");
        client::add_mock_header(client, "Capsule-Protocol", "?1");

        // 1. Client connects via CONNECT-UDP
        let tunnel, resp, err = client::connect_udp(client, "https://proxy.privacy.org", "1.1.1.1", 53, 4, false);
        sub.assert_true(http::ok(err), "connect_udp handshake succeeded");
        sub.assert_eq(http::status(resp), 200, "200 OK");
        sub.assert_true(tunnel.state == net::MasqueTunnelState.Established, "Tunnel state is Established");

        // 2. Client sends UDP packet through tunnel (in-stream capsule mode via UFCS)
        var tunnel_mut = copy(tunnel);
        var wire_out: u8[..256] = [];
        let dns_query = "fake_dns_wire_query";
        let send_ok = tunnel_mut.send_packet(dns_query, wire_out);
        sub.assert_true(send_ok, "tunnel.send_packet UFCS succeeded");
        sub.assert_eq(tunnel_mut.packets_sent, 1, "1 packet sent recorded");
        sub.assert_eq(tunnel_mut.bytes_sent, dns_query.len as u64, "Bytes sent matches");

        // 3. Client receives UDP response packet from wire via UFCS
        var packet_in: u8[..256] = [];
        let recv_ok = tunnel_mut.receive_capsule(wire_out[..], packet_in);
        sub.assert_true(recv_ok, "tunnel.receive_capsule UFCS succeeded");
        sub.assert_bytes_eq(packet_in[..], dns_query, "Received packet content matches sent query");
        sub.assert_eq(tunnel_mut.packets_received, 1, "1 packet received recorded");
    };

    t.run("CONNECT-IP Handshake & Address Assignment via Client") { sub =>
        var client = client::new_client();

        // Configure mock VPN gateway accepting CONNECT-IP
        client::mock_route(client, "CONNECT", "https://vpn.corp.com/.well-known/masque/ip/", 200, "");
        client::add_mock_header(client, "Capsule-Protocol", "?1");

        // 1. Client connects via CONNECT-IP
        let tunnel, resp, err = client::connect_ip(client, "https://vpn.corp.com", 0, false);
        sub.assert_true(http::ok(err), "connect_ip handshake succeeded");
        sub.assert_true(tunnel.state == net::MasqueTunnelState.Established, "Tunnel is Established");

        // 2. Simulate server sending ADDRESS_ASSIGN capsule
        var tunnel_mut = copy(tunnel);
        var assign = net::IpAddressAssign {
            request_id: 10,
            ip_version: 4,
            prefix_len: 32,
            ..
        };
        assign.assigned_ip.append([10, 8, 0, 5]);

        var assign_capsule_wire: u8[..256] = [];
        net::encode_address_assign_capsule(assign_capsule_wire, assign);

        var dummy_pkt: u8[..256] = [];
        let recv_ok = net::receive_capsule(tunnel_mut, assign_capsule_wire[..], dummy_pkt);
        sub.assert_true(recv_ok, "ADDRESS_ASSIGN capsule ingested");
        sub.assert_bytes_eq(tunnel_mut.assigned_ip[..], [10, 8, 0, 5], "Tunnel assigned IP is 10.8.0.5");
        sub.assert_eq(tunnel_mut.assigned_prefix_len, 32, "Tunnel prefix length is /32");
    };

    t.run("Proxy Rejection (Missing Capsule-Protocol Header)") { sub =>
        var client = client::new_client();

        // Mock proxy returning 200 OK without Capsule-Protocol: ?1
        client::mock_route(client, "CONNECT", "https://bad-proxy.org/.well-known/masque/udp/8.8.8.8/53/", 200, "");

        let tunnel, resp, err = client::connect_udp(client, "https://bad-proxy.org", "8.8.8.8", 53);
        sub.assert_false(http::ok(err), "Failed due to missing Capsule-Protocol");
        sub.assert_eq(err.code, 502, "Error 502 Bad Gateway");
        sub.assert_true(tunnel.state == net::MasqueTunnelState.Failed, "Tunnel state is Failed");
    };
}

// --- Component: net_masque_dns_invariants ---
// Security invariant tests for MASQUE (RFC 9297, RFC 9298, RFC 9484) and DNS (RFC 1035, RFC 9460).

// ----------------------------------------------------------------------------
// 25. MASQUE CONNECT-UDP Path Parsing
// ----------------------------------------------------------------------------
fn test_masque_connect_udp_path_parsing(t: lit::T&) {
    // 1. Valid RFC 9298 paths
    let h1, p1, ok1 = net::parse_connect_udp_path("/.well-known/masque/udp/1.1.1.1/53/");
    t.assert_true(ok1, "valid template with trailing slash should pass");
    t.assert_eq(p1, 53, "port should be 53");
    t.assert_true(h1[..] == "1.1.1.1", "host should match");

    let h2, p2, ok2 = net::parse_connect_udp_path("/.well-known/masque/udp/example.com/443");
    t.assert_true(ok2, "valid template without trailing slash should pass");
    t.assert_eq(p2, 443, "port should be 443");
    t.assert_true(h2[..] == "example.com", "host should match");

    // 2. RFC 9298 Section 3: target_port MUST be 1..65535, port 0 strictly forbidden
    let _, _, ok_zero = net::parse_connect_udp_path("/.well-known/masque/udp/1.1.1.1/0/");
    t.assert_false(ok_zero, "port 0 must be rejected");

    let _, _, ok_big = net::parse_connect_udp_path("/.well-known/masque/udp/1.1.1.1/65536/");
    t.assert_false(ok_big, "port > 65535 must be rejected");

    // 3. Characters forbidden in host part
    let _, _, ok_bad1 = net::parse_connect_udp_path("/.well-known/masque/udp/bad?host/53/");
    t.assert_false(ok_bad1, "host with query delimiter must be rejected");

    let _, _, ok_bad2 = net::parse_connect_udp_path("/.well-known/masque/udp/bad#host/53/");
    t.assert_false(ok_bad2, "host with hash fragment delimiter must be rejected");

    let _, _, ok_bad3 = net::parse_connect_udp_path("/.well-known/masque/udp/bad host/53/");
    t.assert_false(ok_bad3, "host with space must be rejected");

    // 4. Extra path segments
    let _, _, ok_extra = net::parse_connect_udp_path("/.well-known/masque/udp/1.1.1.1/53/extra");
    t.assert_false(ok_extra, "extra segments after port must be rejected");
}

// ----------------------------------------------------------------------------
// 26. MASQUE Capsule Codecs
// ----------------------------------------------------------------------------
fn test_masque_capsule_codecs(t: lit::T&) {
    // 1. DATAGRAM capsule encode & decode
    var cap_out: u8[..128] = [];
    let enc_ok = net::encode_connect_udp_datagram_capsule(cap_out, 0, "ping");
    t.assert_true(enc_ok, "datagram capsule encode should succeed");

    let cap, parse_ok = net::parse_http_capsule(cap_out[..]);
    t.assert_true(parse_ok, "http capsule parse should succeed");
    t.assert_true(cap.capsule_type == rfc::CAPSULE_DATAGRAM, "capsule type should be DATAGRAM");

    let ctx_id, pkt, pkt_ok = net::parse_connect_udp_datagram(cap.payload);
    t.assert_true(pkt_ok, "connect udp datagram parse should succeed");
    t.assert_eq(ctx_id, 0, "context id should be 0");
    t.assert_true(pkt == "ping", "payload should match");

    // 2. CONNECT-IP ADDRESS_ASSIGN IPv4 (RFC 9484)
    var assign4 = net::IpAddressAssign { request_id: 42, ip_version: 4, prefix_len: 32, .. };
    assign4.assigned_ip.append([10, 0, 0, 1]);
    var wire4: u8[..128] = [];
    t.assert_true(net::encode_address_assign_capsule(wire4, assign4), "encode address assign v4");

    let cap4, cap4_ok = net::parse_http_capsule(wire4[..]);
    t.assert_true(cap4_ok, "parse assign capsule");
    t.assert_true(cap4.capsule_type == rfc::CAPSULE_ADDRESS_ASSIGN, "type matches address assign");

    let dec4, dec4_ok = net::decode_address_assign_capsule(cap4.payload);
    t.assert_true(dec4_ok, "decode address assign v4");
    t.assert_eq(dec4.request_id, 42, "req id matches");
    t.assert_eq(dec4.ip_version, 4, "version is 4");
    t.assert_eq(dec4.prefix_len, 32, "prefix is 32");
    t.assert_true(dec4.assigned_ip.len == 4 && dec4.assigned_ip[0] == 10 && dec4.assigned_ip[3] == 1, "assigned ip matches");

    // 3. CONNECT-IP ADDRESS_ASSIGN invalid versions / bounds
    // Invalid IP version 5
    let bad_ver_wire: u8[7] = [0x01, 0x05, 10, 0, 0, 1, 0x20];
    let _, bad_ver_ok = net::decode_address_assign_capsule(bad_ver_wire[..]);
    t.assert_false(bad_ver_ok, "invalid IP version 5 must be rejected");

    // IPv4 prefix length > 32
    let bad_pre_wire: u8[7] = [0x01, 0x04, 10, 0, 0, 1, 0x21];
    let _, bad_pre_wire_ok = net::decode_address_assign_capsule(bad_pre_wire[..]);
    t.assert_false(bad_pre_wire_ok, "IPv4 prefix length > 32 must be rejected");

    // IPv4 with wrong byte count (3 bytes instead of 4)
    let bad_len_wire: u8[6] = [0x01, 0x04, 10, 0, 1, 0x20];
    let _, bad_len_ok = net::decode_address_assign_capsule(bad_len_wire[..]);
    t.assert_false(bad_len_ok, "IPv4 address with rdlength != 4 must be rejected");
}

// ----------------------------------------------------------------------------
// 27. DNS Pointer Security
// ----------------------------------------------------------------------------
fn test_dns_pointer_security(t: lit::T&) {
    // Valid backward pointer response
    // Header 12B, Question 17B (example.com A IN), Answer 16B (pointer 0xC00C -> example.com)
    let valid_wire: const u8[45] = [
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
        0x00, 0x01, 0x00, 0x01,
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04,
        0x5d, 0xb8, 0xd8, 0x22,
    ];
    let resp1, ok1 = dns::parse_response(valid_wire[..]);
    t.assert_true(ok1, "valid backward pointer must succeed");
    t.assert_eq(resp1.a_records.len, 1, "parsed 1 A record");
    t.assert_true(resp1.a_records[0] == 0x5db8d822, "IP address matches");
    t.assert_eq(resp1.min_ttl_sec, 60, "min_ttl_sec parsed as 60 seconds");

    // Forward pointer rejected (RFC 1035 §4.1.4: ptr_off >= current_off)
    var fwd_wire = valid_wire;
    fwd_wire[29] = 0xc0;
    fwd_wire[30] = 0x23; // points to offset 35 > 29
    let _, ok2 = dns::parse_response(fwd_wire[..]);
    t.assert_false(ok2, "forward pointer must be rejected");

    // Pointer into header rejected (ptr_off < 12)
    var hdr_wire = valid_wire;
    hdr_wire[29] = 0xc0;
    hdr_wire[30] = 0x04; // points to offset 4 < 12
    let _, ok3 = dns::parse_response(hdr_wire[..]);
    t.assert_false(ok3, "pointer into header must be rejected");
}

// ----------------------------------------------------------------------------
// 28. DNS Record Bounds & HTTPS Target
// ----------------------------------------------------------------------------
fn test_dns_record_bounds_and_https_target(t: lit::T&) {
    // Malformed A record: rdlength != 4
    let bad_a_wire: const u8[44] = [
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
        0x00, 0x01, 0x00, 0x01,
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x03,
        0x5d, 0xb8, 0xd8,
    ];
    let _, ok_a = dns::parse_response(bad_a_wire[..]);
    t.assert_false(ok_a, "A record with rdlength != 4 must be rejected");

    // RFC 9460 §2.5.1: HTTPS TargetName containing compression pointer (0xC00C) must be rejected
    let bad_https_wire: const u8[45] = [
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
        0x00, 0x41, 0x00, 0x01,
        0xc0, 0x0c, 0x00, 0x41, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04,
        0x00, 0x01, 0xc0, 0x0c,
    ];
    let _, ok_h = dns::parse_response(bad_https_wire[..]);
    t.assert_false(ok_h, "HTTPS TargetName with compression pointer must be rejected");
}

// --- Component: net_altsvc_race ---
// Verification suite for RFC 7838 Alt-Svc upgrade and Chromium-style Speculative Protocol Racing.
// Verifies:
// 1. Zero-heap Alt-Svc header learning and origin caching.
// 2. Promotion of TCP (HTTP/1.1 / HTTP/2) connections to HTTP/3 (QUIC).
// 3. Speculative racing between Alternative Job (H3) and Main Job (TCP).
// 4. Firewall UDP drop simulation, fallback to TCP without user error.
// 5. Chromium-identical exponential failure backoff (5s, 10s, 20s... 320s).
// 6. Fast-path TCP bypass during backoff window.
// 7. Success recovery and failure counter reset.
// 8. RFC 7838 `clear` directive cache purging.
// 9. RFC 7838 Section 2.1 security invariant: Alt-Svc ignored on unencrypted HTTP.
// 10. Max-age (TTL) expiration.

// ----------------------------------------------------------------------------
// 29. Alt-Svc Learning & HTTP/3 Promotion
// ----------------------------------------------------------------------------
fn test_altsvc_learning_and_h3_promotion(t: lit::T&) {
    t.run("Cold Request Learns Alt-Svc and Next Request Upgrades to HTTP/3") { sub =>
        var client = client::new_client();
        client::set_clock_us(client, 1700000000000000); // t = 1700000000s

        // 1. Setup mock route returning Alt-Svc header
        client::mock_route(client, "GET", "https://api.example.com/v1/user", 200, "{\"id\":1}");
        client::add_mock_header(client, "Alt-Svc", "h3=\":443\"; ma=86400; persist=1");

        // Before request: cache has no entry
        sub.assert_false(client::has_altsvc_h3(client, "api.example.com:443"), "no prior Alt-Svc for api.example.com");

        // 2. Cold request: executed over standard TCP (HTTP/1.1)
        let resp1, err1 = client::get(client, "https://api.example.com/v1/user");
        sub.assert_true(http::ok(err1), "cold request succeeds");
        sub.assert_eq(http::status(resp1), 200, "200 OK");
        sub.assert_eq(http::protocol(resp1), "HTTP/1.1", "cold request served via HTTP/1.1");
        sub.assert_false(http::is_http3(resp1), "not HTTP/3 yet");

        // 3. Verify Alt-Svc was ingested into client cache
        sub.assert_true(client::has_altsvc_h3(client, "api.example.com:443"), "Alt-Svc cached for api.example.com:443");
        sub.assert_true(client::has_altsvc_h3(client, "https://api.example.com/v1/user"), "URL origin lookup works");

        // 4. Second request: Alt-Svc candidate found -> upgraded to HTTP/3!
        let resp2, err2 = client::get(client, "https://api.example.com/v1/user");
        sub.assert_true(http::ok(err2), "second request succeeds");
        sub.assert_eq(http::protocol(resp2), "h3", "second request upgraded to h3 via Alt-Svc!");
        sub.assert_true(http::is_http3(resp2), "is_http3 helper returns true");
    };
}

// ----------------------------------------------------------------------------
// 30. Protocol Racing & UDP Firewall Fallback
// ----------------------------------------------------------------------------
fn test_chromium_protocol_racing_and_udp_fallback(t: lit::T&) {
    t.run("UDP Firewall Block: TCP Wins Race, Zero Error, Backoff Recorded") { sub =>
        var client = client::new_client();
        client::set_clock_us(client, 1700000000000000); // t0 = 1700000000s (sec)

        // Seed Alt-Svc cache
        client::mock_route(client, "GET", "https://fast.edge.net/data", 200, "{\"ready\":true}");
        client::add_mock_header(client, "Alt-Svc", "h3=\":443\"; ma=3600");

        let resp_seed, err_seed = client::get(client, "https://fast.edge.net/data");
        sub.assert_true(http::ok(err_seed), "seed request ok");
        sub.assert_true(client::has_altsvc_h3(client, "fast.edge.net:443"), "Alt-Svc cached");

        // Now simulate corporate firewall blocking UDP/QUIC (e.g. timeout or packet drop)
        client::set_mock_quic_blocked(client, true);

        // Request during UDP blockage: Protocol Race starts
        // Alternative Job (H3) times out / blocked -> Main Job (TCP) wins the race!
        let resp_blocked, err_blocked = client::get(client, "https://fast.edge.net/data");
        sub.assert_true(http::ok(err_blocked), "request succeeds without user error");
        sub.assert_eq(http::status(resp_blocked), 200, "200 OK via TCP fallback");
        sub.assert_eq(http::protocol(resp_blocked), "HTTP/1.1", "served via TCP Main Job");

        // Check Chromium failure penalization: origin is now marked broken!
        sub.assert_true(client::is_altsvc_broken(client, "fast.edge.net:443"), "origin fast.edge.net marked broken");
        sub.assert_false(client::has_altsvc_h3(client, "fast.edge.net:443"), "has_altsvc_h3 suppressed during backoff");

        // Request 1 second later (within 5s initial backoff window):
        client::set_clock_us(client, 1700000001000000); // t0 + 1s
        let resp_cached_tcp, err_cached_tcp = client::get(client, "https://fast.edge.net/data");
        sub.assert_true(http::ok(err_cached_tcp), "fast-path TCP succeeds");
        sub.assert_eq(http::protocol(resp_cached_tcp), "HTTP/1.1", "bypassed QUIC race without delay");

        // Advance virtual clock past 5s backoff window (t0 + 6s)
        client::set_clock_us(client, 1700000006000000); // t0 + 6s
        sub.assert_false(client::is_altsvc_broken(client, "fast.edge.net:443"), "backoff expired after 5s");
        sub.assert_true(client::has_altsvc_h3(client, "fast.edge.net:443"), "H3 candidate available again");

        // Now firewall allows UDP again:
        client::set_mock_quic_blocked(client, false);
        let resp_recovered, err_recovered = client::get(client, "https://fast.edge.net/data");
        sub.assert_true(http::ok(err_recovered), "recovered request ok");
        sub.assert_eq(http::protocol(resp_recovered), "h3", "H3 race won after recovery!");
        sub.assert_false(client::is_altsvc_broken(client, "fast.edge.net:443"), "broken status cleared on success");
    };

    t.run("Exponential Failure Backoff Progression (5s -> 10s)") { sub =>
        var client = client::new_client();
        client::set_clock_us(client, 1700000000000000); // t0

        client::mock_route(client, "GET", "https://flaky.cdn.com/res", 200, "flaky");
        client::add_mock_header(client, "Alt-Svc", "h3=\":443\"; ma=86400");
        let _, _ = client::get(client, "https://flaky.cdn.com/res");

        // Failure 1: backoff is 5s
        client::set_mock_quic_blocked(client, true);
        let _, _ = client::get(client, "https://flaky.cdn.com/res");
        sub.assert_true(client::is_altsvc_broken(client, "flaky.cdn.com:443"), "broken attempt 1");

        // At t0 + 6s: backoff 1 has expired
        client::set_clock_us(client, 1700000006000000);
        sub.assert_false(client::is_altsvc_broken(client, "flaky.cdn.com:443"), "expired at t0+6s");

        // Failure 2: backoff doubles to 10s (broken until t0 + 6s + 10s = t0 + 16s)
        let _, _ = client::get(client, "https://flaky.cdn.com/res");
        sub.assert_true(client::is_altsvc_broken(client, "flaky.cdn.com:443"), "broken attempt 2");

        // At t0 + 12s: still broken (12 < 16)
        client::set_clock_us(client, 1700000012000000);
        sub.assert_true(client::is_altsvc_broken(client, "flaky.cdn.com:443"), "still broken at t0+12s");

        // At t0 + 17s: backoff 2 expired (17 >= 16)
        client::set_clock_us(client, 1700000017000000);
        sub.assert_false(client::is_altsvc_broken(client, "flaky.cdn.com:443"), "expired at t0+17s");
    };
}

// ----------------------------------------------------------------------------
// 31. Alt-Svc Clear Directive & TTL Expiration
// ----------------------------------------------------------------------------
fn test_altsvc_clear_and_ttl_expiration(t: lit::T&) {
    t.run("Alt-Svc: clear Purges Origin from Cache Immediately") { sub =>
        var client = client::new_client();
        client::set_clock_us(client, 1700000000000000);

        client::mock_route(client, "GET", "https://service.org/item", 200, "item");
        client::add_mock_header(client, "Alt-Svc", "h3=\":443\"; ma=86400");
        let _, _ = client::get(client, "https://service.org/item");
        sub.assert_true(client::has_altsvc_h3(client, "service.org:443"), "cached");

        // Server sends `Alt-Svc: clear` (RFC 7838 Section 3.1)
        client::mock_route(client, "POST", "https://service.org/logout", 200, "bye");
        client::add_mock_header(client, "Alt-Svc", "clear");
        let _, _ = client::post(client, "https://service.org/logout") { _ => };

        sub.assert_false(client::has_altsvc_h3(client, "service.org:443"), "origin purged after clear");

        // Subsequent request uses standard TCP
        let resp3, _ = client::get(client, "https://service.org/item");
        sub.assert_eq(http::protocol(resp3), "HTTP/1.1", "served via HTTP/1.1 after clear");
    };

    t.run("Max-Age (ma) Expiration") { sub =>
        var client = client::new_client();
        client::set_clock_us(client, 1700000000000000); // t0

        client::mock_route(client, "GET", "https://short-lived.com/status", 200, "ok");
        client::add_mock_header(client, "Alt-Svc", "h3=\":443\"; ma=3"); // TTL = 3 seconds
        let _, _ = client::get(client, "https://short-lived.com/status");
        sub.assert_true(client::has_altsvc_h3(client, "short-lived.com:443"), "cached at t0");

        // Advance 2 seconds (still valid)
        client::set_clock_us(client, 1700000002000000); // t0 + 2s
        sub.assert_true(client::has_altsvc_h3(client, "short-lived.com:443"), "valid at t0+2s (< 3s)");

        // Advance 4 seconds (expired)
        client::set_clock_us(client, 1700000004000000); // t0 + 4s
        sub.assert_false(client::has_altsvc_h3(client, "short-lived.com:443"), "expired at t0+4s (>= 3s)");
    };
}

// ----------------------------------------------------------------------------
// 32. RFC 7838 Insecure Transport Security & Toggles
// ----------------------------------------------------------------------------
fn test_rfc7838_security_and_options(t: lit::T&) {
    t.run("RFC 7838 Section 2.1: Alt-Svc MUST be Ignored on Insecure HTTP") { sub =>
        var client = client::new_client();
        client::set_clock_us(client, 1700000000000000);

        // Plain HTTP server attempts to send Alt-Svc
        client::mock_route(client, "GET", "http://insecure.site/api", 200, "insecure");
        client::add_mock_header(client, "Alt-Svc", "h3=\":443\"; ma=86400");

        let resp, err = client::get(client, "http://insecure.site/api");
        sub.assert_true(http::ok(err), "http request ok");

        // MUST NOT be cached because transport was unencrypted HTTP!
        sub.assert_false(client::has_altsvc_h3(client, "insecure.site:80"), "Alt-Svc ignored over insecure HTTP");
    };

    t.run("Manual Disabling of Alt-Svc or Protocol Racing") { sub =>
        var client = client::new_client();
        client::enable_altsvc(client, false); // Alt-Svc disabled

        client::mock_route(client, "GET", "https://disabled.com/data", 200, "data");
        client::add_mock_header(client, "Alt-Svc", "h3=\":443\"; ma=86400");

        let resp1, _ = client::get(client, "https://disabled.com/data");
        sub.assert_false(client::has_altsvc_h3(client, "disabled.com:443"), "not cached when disabled");

        let resp2, _ = client::get(client, "https://disabled.com/data");
        sub.assert_eq(http::protocol(resp2), "HTTP/1.1", "remains HTTP/1.1");
    };
}

// --- Component: http/client_cert (RFC 9440) ---
// Client-Cert / Client-Cert-Chain SFV Byte Sequence codec and TTRP sanitization.

// ----------------------------------------------------------------------------
// 33. RFC 9440 Client-Cert
// ----------------------------------------------------------------------------
fn test_client_cert_header(t: lit::T&) {
    t.run("Client-Cert Byte Sequence round-trip on 64-byte DER fixture") { sub =>
        var der: u8[..64] = [];
        for i in 64 {
            der.push((i as u8));
        }

        var field: u8[..8192] = [];
        let ok_enc = http::encode_client_cert(der[..], field);
        sub.assert_true(ok_enc, "encode succeeds for 64-byte DER");
        sub.assert_eq(field.len, 90, "encode writes 90 bytes for 64-byte DER");
        sub.assert_bytes_eq(
            field[..],
            ":AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+Pw==:",
            "encoded field matches SFV Byte Sequence form",
        );

        var out_der: u8[..4096] = [];
        let ok = http::parse_client_cert(field[..], out_der);
        sub.assert_true(ok, "parse_client_cert accepts encoded field");
        sub.assert_eq(out_der.len, 64, "decoded DER length is 64");
        sub.assert_bytes_eq(out_der[..], der[..], "round-trip preserves DER bytes");

        var reenc: u8[..8192] = [];
        let ok_re = http::encode_client_cert(out_der[..], reenc);
        sub.assert_true(ok_re, "re-encode succeeds");
        sub.assert_eq(reenc.len, field.len, "re-encode length matches");
        sub.assert_bytes_eq(reenc[..], field[..], "re-encode is byte-for-byte identical");
    };

    t.run("Client-Cert rejects trailing content, empty, and oversize DER") { sub =>
        var out_der: u8[..4096] = [];

        let trailing = ":AAECAw==:extra";
        sub.assert_false(http::parse_client_cert(trailing, out_der), "trailing content after colon rejected");
        sub.assert_eq(out_der.len, 0, "out_der cleared on trailing-content failure");

        let empty = "::";
        sub.assert_false(http::parse_client_cert(empty, out_der), "empty Byte Sequence rejected");

        let unclosed = ":AAECAw==";
        sub.assert_false(http::parse_client_cert(unclosed, out_der), "missing closing colon rejected");

        // 4097-byte DER fixture (enterprise cap is 4096)
        var big: u8[>..] = [];
        big.push(':');
        var der_src: u8[>..] = [];
        for _ in 4097 {
            der_src.push('X');
        }
        var b64_buf: u8[>..] = [];
        core::base64_encode(der_src[..], b64_buf);
        big.append(b64_buf[..]);
        big.push(':');
        sub.assert_false(http::parse_client_cert(big[..], out_der), "DER > 4096 bytes rejected");
        sub.assert_eq(out_der.len, 0, "out_der cleared on oversize failure");
    };

    t.run("Client-Cert-Chain list parse and malformed-item rejection") { sub =>
        var certs: u8[..4096][..4] = [];

        // SFV List of Byte Sequences with trailing comma (RFC 9110 §5.6.1 #rule)
        let ok2 = http::parse_client_cert_chain(":YQ==:, :Yg==:,", certs);
        sub.assert_true(ok2, "two-item list with trailing comma accepted");
        sub.assert_eq(certs.len, 2, "count == 2");
        sub.assert_eq(certs[0].len, 1, "item 0 length is 1");
        sub.assert_eq(certs[1].len, 1, "item 1 length is 1");
        sub.assert_bytes_eq(certs[0][..], "a", "item 0 decodes to a");
        sub.assert_bytes_eq(certs[1][..], "b", "item 1 decodes to b");

        certs.clear();
        let ok_bad = http::parse_client_cert_chain(":YQ==:, !!!, :Yg==:", certs);
        sub.assert_false(ok_bad, "malformed item rejects whole field (RFC 9440 §2.3)");
        sub.assert_eq(certs.len, 0, "certs cleared on malformed chain");

        certs.clear();
        let ok5 = http::parse_client_cert_chain(
            ":YQ==:, :Yg==:, :YQ==:, :Yg==:, :YQ==:",
            certs,
        );
        sub.assert_false(ok5, "more than 4 chain items rejected");
        sub.assert_eq(certs.len, 0, "certs cleared on oversize chain");
    };

    t.run("Spoofing strip via is_forwarded_metadata_header") { sub =>
        sub.assert_true(proxy::is_forwarded_metadata_header("client-cert"), "client-cert stripped");
        sub.assert_true(proxy::is_forwarded_metadata_header("Client-Cert-Chain"), "Client-Cert-Chain stripped");
        sub.assert_true(proxy::is_forwarded_metadata_header("CLIENT-CERT"), "CLIENT-CERT case-folded stripped");
    };

    t.run("filter_and_forward_headers strips spoofed Client-Cert when injection disabled") { sub =>
        var cfg = proxy::Config { .. };
        sub.assert_false(cfg.forward_client_cert, "forward_client_cert defaults to false");

        var in_headers = http::HeaderMap { .. };
        http::append_header(in_headers, "Host", "origin.example");
        http::append_header(in_headers, "Client-Cert", ":spoof:");

        var out_headers = http::HeaderMap { .. };
        let ok = proxy::filter_and_forward_headers(
            in_headers,
            out_headers,
            "203.0.113.9",
            "https",
            "origin.example",
            cfg,
        );
        sub.assert_true(ok, "filter_and_forward_headers succeeds");
        sub.assert_false(http::has_header(out_headers, "Client-Cert"), "spoofed Client-Cert stripped");
    };

    t.run("filter_and_forward_headers injects exactly one Client-Cert when enabled") { sub =>
        var cfg = proxy::Config { .. };
        cfg.forward_client_cert = true;
        for i in 64 {
            cfg.client_cert_der.push((i as u8));
        }
        cfg.client_cert_der_len = 64;

        var in_headers = http::HeaderMap { .. };
        http::append_header(in_headers, "Host", "origin.example");
        http::append_header(in_headers, "Client-Cert", ":spoof:");

        var out_headers = http::HeaderMap { .. };
        let ok = proxy::filter_and_forward_headers(
            in_headers,
            out_headers,
            "203.0.113.9",
            "https",
            "origin.example",
            cfg,
        );
        sub.assert_true(ok, "filter_and_forward_headers succeeds with injection");

        var client_cert_count = 0;
        for i in out_headers.entries.len {
            let entry = out_headers.entries[i];
            let name = out_headers.raw_buf[entry.name_begin..entry.name_end];
            if core::eq_ascii_fold(name, "client-cert") {
                client_cert_count++;
            }
        }
        sub.assert_eq(client_cert_count, 1, "exactly one Client-Cert header");

        var expected: u8[..8192] = [];
        let ok_enc = http::encode_client_cert(cfg.client_cert_der[..cfg.client_cert_der_len], expected);
        sub.assert_true(ok_enc && expected.len > 0, "expected encode produces output");
        let actual = http::get_header(out_headers, "Client-Cert");
        sub.assert_bytes_eq(actual, expected[..], "Client-Cert equals encode_client_cert(client_cert_der)");
    };
}

// ----------------------------------------------------------------------------
// 34. Load Balancer: Weights, PRNG, and State Transitions
// ----------------------------------------------------------------------------
fn test_load_balancer(t: lit::T&) {
    t.run("LeastConnections respects upstream weights") { sub =>
        var cluster = proxy::new_upstream_cluster(proxy::LbPolicy.LeastConnections, 3);
        sub.assert_true(proxy::add_upstream_target(cluster, "srv-weight-1", 80, 1), "add target 1");
        sub.assert_true(proxy::add_upstream_target(cluster, "srv-weight-2", 80, 2), "add target 2");

        // Both targets have 1 active connection.
        // Target 0 (weight 1): normalized load = 1 / 1 = 1.0
        // Target 1 (weight 2): normalized load = 1 / 2 = 0.5
        cluster.targets[0].active_conns = 1;
        cluster.targets[1].active_conns = 1;

        let chosen, ok = proxy::select_upstream(cluster);
        sub.assert_true(ok, "upstream selected");
        sub.assert_eq(chosen, 1, "target with weight 2 chosen over weight 1 with equal connections");
    };

    t.run("PowerOfTwoChoices respects target weights") { sub =>
        var t1 = proxy::UpstreamTarget { active_conns: 2, weight: 1, .. };
        var t2 = proxy::UpstreamTarget { active_conns: 3, weight: 2, .. };

        // t1: 2 conns * 2 weight2 = 4
        // t2: 3 conns * 1 weight1 = 3 -> t2 has lower weighted load
        let chosen = proxy::evaluate_two_choice(t1, 0, t2, 1);
        sub.assert_eq(chosen, 1, "P2C selects target 2 due to higher weight capacity");
    };

    t.run("PRNG preserves non-zero 64-bit entropy") { sub =>
        var state: u64 = 0x123456789abcdef0;
        let r1 = proxy::next_prng(state);
        let r2 = proxy::next_prng(state);
        let r3 = proxy::next_prng(state);

        sub.assert_ne(r1, r2, "PRNG values differ across steps");
        sub.assert_ne(r2, r3, "PRNG sequence continues");
        sub.assert_ne(state, 0, "PRNG state remains non-zero");
    };

    t.run("Probing target is selectable during recovery") { sub =>
        var cluster = proxy::new_upstream_cluster(proxy::LbPolicy.RoundRobin, 2);
        sub.assert_true(proxy::add_upstream_target(cluster, "srv-probe", 80, 1), "add target");
        cluster.targets[0].is_healthy = false;
        cluster.targets[0].health_state = proxy::UpstreamHealthState.Probing;

        let chosen, ok = proxy::select_upstream(cluster);
        sub.assert_true(ok, "probing target is selected for trial traffic");
        sub.assert_eq(chosen, 0, "target 0 selected");
    };
}

// ----------------------------------------------------------------------------
// 35. Active Health Check: Prober State Machine & Thresholds
// ----------------------------------------------------------------------------
fn test_health_check(t: lit::T&) {
    t.run("Probing failure immediately trips to Down") { sub =>
        let config = proxy::new_health_check_config(5000, 2000, 2, 3);
        var health = proxy::UpstreamHealth {
            state:                 proxy::HealthState.Probing,
            consecutive_successes: 1,
            consecutive_failures:  0,
            ..
        };

        let new_state = proxy::record_probe_failure(health, config);
        sub.assert_eq(new_state, proxy::HealthState.Down, "failure during Probing immediately trips Down");
        sub.assert_eq(health.consecutive_successes, 0, "success streak cleared on failure");
    };

    t.run("Consecutive successes transition Probing to Up") { sub =>
        let config = proxy::new_health_check_config(5000, 2000, 2, 3);
        var health = proxy::UpstreamHealth {
            state:                 proxy::HealthState.Down,
            consecutive_successes: 0,
            consecutive_failures:  3,
            ..
        };

        // First success transitions Down -> Probing
        let s1 = proxy::record_probe_success(health, 500, config);
        sub.assert_eq(s1, proxy::HealthState.Probing, "first success enters Probing");

        // Second success reaches healthy_threshold (2) -> transitions to Up
        let s2 = proxy::record_probe_success(health, 400, config);
        sub.assert_eq(s2, proxy::HealthState.Up, "second success reaches threshold and enters Up");
    };

    t.run("Probe HTTP status code parser") { sub =>
        let wire_200 = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        let code_200, ok_200 = proxy::parse_probe_status_code(wire_200);
        sub.assert_true(ok_200, "parse 200 ok");
        sub.assert_eq(code_200, 200, "status 200");

        let wire_503 = "HTTP/1.1 503 Service Unavailable\r\n\r\n";
        let code_503, ok_503 = proxy::parse_probe_status_code(wire_503);
        sub.assert_true(ok_503, "parse 503 ok");
        sub.assert_eq(code_503, 503, "status 503");

        let config = proxy::new_health_check_config(5000, 2000, 2, 3);
        sub.assert_true(proxy::evaluate_probe_response(wire_200, 200), "validate expected 200");
        sub.assert_false(proxy::evaluate_probe_response(wire_503, 200), "reject unexpected 503");
    };
}

// ----------------------------------------------------------------------------
// 36. GCRA Rate Limiter: Headroom, Burst Headroom, and Buffer Limits
// ----------------------------------------------------------------------------
fn test_gcra_rate_limiter(t: lit::T&) {
    t.run("Burst headroom derivation: tau = T * B") { sub =>
        // 10 req/sec -> T = 100,000,000 ns (100ms)
        // burst = 5 -> tau = 100ms * 5 = 500ms
        // window = tau + T = 600ms
        let config = security::new_gcra_config(10, 5);
        sub.assert_eq(config.emission_interval_ns, 100000000, "T is 100ms");
        sub.assert_eq(config.tau_ns, 500000000, "tau is 500ms");
        sub.assert_eq(config.limit_window_ns, 600000000, "limit window is 600ms");
    };

    t.run("Multi-cell burst allowance at t=0") { sub =>
        let config = security::new_gcra_config(10, 2); // T=100ms, tau=200ms, burst=2
        var cell = security::GcraCell { tat_ns: 0 };
        let now: u64 = 1000000000; // t=1.0s

        // 1st request admitted
        let d1 = security::gcra_check(config, cell, 1, now);
        sub.assert_true(d1.allowed, "1st request allowed");

        // 2nd request admitted
        let d2 = security::gcra_check(config, cell, 1, now);
        sub.assert_true(d2.allowed, "2nd request allowed");

        // 3rd request admitted
        let d3 = security::gcra_check(config, cell, 1, now);
        sub.assert_true(d3.allowed, "3rd request allowed");

        // 4th request rejected (burst capacity 2 exhausted at instant t=1.0s)
        let d4 = security::gcra_check(config, cell, 1, now);
        sub.assert_false(d4.allowed, "4th request rejected");
    };

    t.run("Client ID overflow rejected without truncation") { sub =>
        var limiter = security::new_gateway_rate_limiter(10, 5);
        let oversized_key = "012345678901234567890123456789012345678901234567890123456789012345"; // 66 bytes

        let _, found_slot = security::find_client_slot(limiter, oversized_key);
        sub.assert_false(found_slot, "oversized client ID rejected by find_client_slot");

        let dec = security::check_gateway_rate_limit(limiter, oversized_key, 1, 1000000000);
        sub.assert_true(dec.allowed, "fallback admission handled");
        sub.assert_eq(limiter.entries.len, 0, "oversized key was NOT inserted into entries table");
    };
}

// ----------------------------------------------------------------------------
// 37. Reverse Proxy: Stream Ring Buffer & Zero-Copy Forwarding
// ----------------------------------------------------------------------------
fn test_reverse_proxy_streaming(t: lit::T&) {
    t.run("Stream ring compacting and slice vending") { sub =>
        var ring = proxy::StreamRing { .. };
        sub.assert_true(proxy::feed_stream_chunk(ring, "Hello, World!"), "feed chunk");
        sub.assert_eq(ring.buf.len, 13, "buffered length");

        let slice1 = proxy::incoming_slice(ring);
        sub.assert_eq(slice1, "Hello, World!", "incoming slice");

        // Consume 7 bytes ("Hello, ")
        sub.assert_true(proxy::advance_read(ring, 7), "advance read 7 bytes");
        sub.assert_eq(ring.read_pos, 7, "read cursor at 7");

        let slice2 = proxy::incoming_slice(ring);
        sub.assert_eq(slice2, "World!", "incoming slice after advance");

        // Compact ring
        proxy::compact_stream_ring(ring);
        sub.assert_eq(ring.read_pos, 0, "read cursor reset to 0 after compaction");
        sub.assert_eq(ring.buf.len, 6, "compacted length is remaining 6 bytes");

        let slice3 = proxy::incoming_slice(ring);
        sub.assert_eq(slice3, "World!", "incoming slice after compaction");
    };

    t.run("WebSocket userspace streaming masking") { sub =>
        var src = proxy::StreamRing { .. };
        var dst = proxy::StreamRing { .. };

        sub.assert_true(proxy::feed_stream_chunk(src, "ping"), "feed plain payload");

        let mask: u8[4] = [0x12, 0x34, 0x56, 0x78];
        let n, ok = proxy::forward_userspace_stream_chunk(src, dst, proxy::TransportKind.WebSocket, mask);
        sub.assert_true(ok, "forward chunk ok");
        sub.assert_eq(n, 4, "forwarded 4 bytes");

        let masked_slice = proxy::incoming_slice(dst);
        sub.assert_eq(masked_slice[0], ('p' as u8) ^ 0x12, "byte 0 masked with key[0]");
        sub.assert_eq(masked_slice[1], ('i' as u8) ^ 0x34, "byte 1 masked with key[1]");
        sub.assert_eq(masked_slice[2], ('n' as u8) ^ 0x56, "byte 2 masked with key[2]");
        sub.assert_eq(masked_slice[3], ('g' as u8) ^ 0x78, "byte 3 masked with key[3]");
    };

    t.run("Live ReverseProxy exchange over StreamPool") { sub =>
        let listener = net::tcp_listen("127.0.0.1", 0, 16);
        guard listener > 0 else { return; }
        let port = net::tcp_getsockname_port(listener);
        sub.assert_gt(port as i64, 0, "ephemeral port allocated");

        let client_sock = net::tcp_connect("127.0.0.1", port, 2000);
        sub.assert_gt(client_sock, 0, "connected to upstream listener");
        let server_sock = net::tcp_accept(listener, 2000);
        sub.assert_gt(server_sock, 0, "accepted upstream socket");

        let canned_resp = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 13\r\n\r\nUpstream Pong";
        let _ = net::tcp_send(server_sock, canned_resp);

        var rp = proxy::new_reverse_proxy(proxy::LbPolicy.RoundRobin);
        sub.assert_true(proxy::add_upstream_target(rp.cluster, "127.0.0.1", port, 1), "added upstream");

        var pool = net::new_stream_pool();
        let pkey = net::new_pool_key(
            net::PoolScheme.Http,
            "127.0.0.1",
            port,
            net::new_direct_proxy_chain(),
            net::NetworkAnonymizationKey { .. },
            net::TlsAndDnsPolicy { .. },
        );
        let t = net::Transport.Tcp { fd: client_sock };
        let cid = net::register_connection(pool, pkey, net::NegotiatedProtocol.Http11, t, "127.0.0.1", 1, 1000);
        sub.assert_gt(cid as i64, 0, "registered warm connection in pool");
        let _ = net::release_connection(pool, cid, 1000);

        var in_hdrs = http::HeaderMap { .. };
        let _ = http::append_header(in_hdrs, "Host", "edge.example.com");
        var resp = http::Response { .. };
        let ok_ex = proxy::execute_proxy_exchange(
            rp, pool, "GET", "/v1/health", in_hdrs, "203.0.113.5", "https", "", resp, 2000, 2000,
        );
        sub.assert_true(ok_ex, "execute_proxy_exchange succeeded");
        sub.assert_eq(resp.status_code, 200, "upstream status 200");
        sub.assert_bytes_eq(resp.body[..], "Upstream Pong", "upstream body forwarded");
        sub.assert_eq(rp.cluster.targets[0].active_conns, 0, "active conns released after exchange");
        sub.assert_eq(rp.cluster.targets[0].successes, 1, "upstream success recorded");

        net::tcp_close(server_sock);
        net::tcp_close(listener);
        net::close_pooled_connection(pool, cid);
    };
}

// ----------------------------------------------------------------------------
// 38. HAProxy PROXY Protocol v2 §2.2 & uWS #1927 / #1948: PROXY v2 Malformed TLVs
// ----------------------------------------------------------------------------
fn test_proxy_v2_truncated_tlv_and_trailing_bytes(t: lit::T&) {
    t.run("PROXY v2 with 2 leftover trailing bytes after TLVs MUST be rejected") { sub =>
        // Preamble (12B) + ver_cmd (0x21: PROXY) + fam_trans (0x11: TCP4) + len (12B addr + 2B trailing = 14B)
        var wire: u8[..64] = [];
        for b in [0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A] {
            wire.push(b as u8);
        }
        wire.push(0x21); // v2, PROXY
        wire.push(0x11); // TCP4
        wire.push(0x00); wire.push(14 as u8); // len = 14 bytes (12 bytes IPv4 + 2 trailing bytes)

        // 12-byte IPv4 block: 1.2.3.4 -> 5.6.7.8, port 1000 -> 2000
        for b in [1, 2, 3, 4, 5, 6, 7, 8, 0x03, 0xE8, 0x07, 0xD0] {
            wire.push(b as u8);
        }
        // 2 trailing unparsed bytes (truncated TLV header)
        wire.push(0x01); // TLV type 1 (ALPN)
        wire.push(0x00); // Truncated length (missing second byte and value)

        let hdr, consumed, ok = net::parse_proxy_v2(wire[..]);
        sub.assert_false(ok, "PROXY v2 with trailing truncated TLV bytes MUST be rejected");
    };
}

// ----------------------------------------------------------------------------
// 39. Connection Pool & Proxies (net/pool.goose, net/proxy.goose)
// ----------------------------------------------------------------------------
fn test_pool_and_proxy_san_invariants(t: lit::T&) {
    t.run("matches_san_pattern rejects TLD wildcard *.com") { sub =>
        let matches_tld = net::matches_san_pattern("*.com", "example.com");
        sub.assert_false(matches_tld, "*.com wildcard MUST NOT match apex domain (RFC 6125 §6.4.3)");
    };

    t.run("matches_san_pattern rejects candidate hostname with literal wildcard") { sub =>
        let matches_wild = net::matches_san_pattern("*.example.com", "*.example.com");
        sub.assert_false(matches_wild, "Candidate hostname containing literal '*' MUST NOT match");
    };

    t.run("verify_connect_tunnel_response rejects non-HTTP or 4-digit status codes") { sub =>
        let err1 = net::verify_connect_tunnel_response("HTTP/1.1 2000 OK\r\n\r\n");
        sub.assert_true(err1 == net::ConnectTunnelError.InvalidStatusLine, "Status code '2000' must be InvalidStatusLine");

        let err2 = net::verify_connect_tunnel_response("UNKNOWN 200 OK\r\n\r\n");
        sub.assert_true(err2 == net::ConnectTunnelError.InvalidStatusLine, "Non-HTTP protocol must be InvalidStatusLine");
    };
}

// ----------------------------------------------------------------------------
// 40. PROXY Protocol v1 Token Capacity Guard
// ----------------------------------------------------------------------------
fn test_proxy_protocol_overflow(t: lit::T&) {
    // PROXY v1 with >8 space-separated tokens
    let bad_line: const u8[:] = "PROXY TCP4 1.1.1.1 2.2.2.2 80 80 EXTRA1 EXTRA2 EXTRA3 EXTRA4\r\n";
    let hdr, consumed, ok = net::parse_proxy_v1(bad_line);
    t.assert_false(ok, "PROXY v1 with >8 tokens must fail safely without buffer overflow");
}

// ----------------------------------------------------------------------------
// 41. MASQUE Address Request Capsule Bounds
// ----------------------------------------------------------------------------
fn test_masque_address_capsule_bounds(t: lit::T&) {
    // Address capsule with oversized IP bytes (>16 bytes) per RFC 9484 §4.7.2
    var payload: u8[..32] = [];
    payload.push(1);  // request_id = 1
    payload.push(4);  // ip_version = 4
    for i in 20 { payload.push(0xAA); } // 20 bytes (> 16 cap)
    payload.push(32); // prefix_len = 32

    let req, ok = net::decode_address_request_capsule(payload[..]);
    t.assert_false(ok, "Address request capsule with >16 IP bytes must fail without panic");
}

// ----------------------------------------------------------------------------
// 42. goose2rfc net/ RFC Audit Regressions
// ----------------------------------------------------------------------------
fn test_goose2rfc_net_audit_regressions(t: lit::T&) {
    // NET1_C01: RFC 9484 §4.7.2 ADDRESS_REQUEST rejects request_id == 0 and non-zero host bits
    var req_zero_id = net::IpAddressRequest { request_id: 0, ip_version: 4, prefix_len: 32, .. };
    req_zero_id.requested_ip.append([10, 0, 0, 1]);
    var out_wire: u8[..64] = [];
    t.assert_false(net::encode_address_request_capsule(out_wire, req_zero_id), "request_id == 0 rejected");
    let raw_req_zero: const u8[7] = [0x00, 4, 10, 0, 0, 1, 32];
    let _, ok_req_zero = net::decode_address_request_capsule(raw_req_zero[..]);
    t.assert_false(ok_req_zero, "decode ADDRESS_REQUEST with request_id == 0 rejected");

    let raw_req_host_bits: const u8[7] = [0x01, 4, 10, 0, 0, 1, 24];
    let _, ok_req_host = net::decode_address_request_capsule(raw_req_host_bits[..]);
    t.assert_false(ok_req_host, "decode ADDRESS_REQUEST with non-zero host bits under /24 rejected");

    // NET1_C02: RFC 9484 §4.7.1 ADDRESS_ASSIGN rejects non-zero host bits outside prefix_len
    var bad_assign = net::IpAddressAssign { request_id: 1, ip_version: 4, prefix_len: 24, .. };
    bad_assign.assigned_ip.append([192, 168, 1, 100]);
    t.assert_false(net::encode_address_assign_capsule(out_wire, bad_assign), "encode ADDRESS_ASSIGN non-zero host bits rejected");
    let raw_assign_host_bits: const u8[7] = [0x01, 4, 192, 168, 1, 100, 24];
    let _, ok_assign_host = net::decode_address_assign_capsule(raw_assign_host_bits[..]);
    t.assert_false(ok_assign_host, "decode ADDRESS_ASSIGN non-zero host bits rejected");

    // NET1_C03: RFC 9484 §4.7.3 decode_route_entry validates start_ip <= end_ip on every entry
    let two_routes_second_inv: const u8[20] = [
        4, 10, 0, 0, 0, 10, 0, 0, 255, 0,
        4, 10, 0, 1, 255, 10, 0, 1, 0, 0,
    ];
    let _, ok_two_routes = net::decode_route_advertisement_capsule(two_routes_second_inv[..]);
    t.assert_false(ok_two_routes, "multi-entry ROUTE_ADVERTISEMENT with inverted 2nd entry rejected");

    // NET1_C05: RFC 9298 §5 Context ID 0 UDP Proxying Payload > 65527 bytes rejected
    var huge_dgram: u8[>..] = [];
    huge_dgram.push(0x00); // Context ID = 0
    for _ in 65528 { huge_dgram.push(0x42); }
    let _, _, ok_huge_dgram = net::parse_connect_udp_datagram(huge_dgram[..]);
    t.assert_false(ok_huge_dgram, "Context ID 0 UDP payload > 65527 bytes rejected");

    // NET1_C08 & NET1_C10: Transactional rollback on parse_https_svc_params and parse_proxy_v2_ssl_tlv
    let bad_svc_rdata: const u8[10] = [0x00, 0x01, 0x00, 0x03, 0x02, 'h', '2', 0x00, 0x03, 0x00];
    var svc_rec = dns::HttpsRecord { .. };
    t.assert_false(svc_rec.parse_https_svc_params(bad_svc_rdata[..]), "truncated SvcParams rejected");
    t.assert_eq(svc_rec.alpns.len, 0, "HttpsRecord.alpns rolled back on error");

    let bad_ssl_tlv: const u8[7] = [0x01, 0x00, 0x00, 0x00, 0x00, 0x21, 0x00];
    var ssl_info = net::ProxySslInfo { .. };
    t.assert_false(net::parse_proxy_v2_ssl_tlv(bad_ssl_tlv[..], ssl_info), "truncated SSL TLV rejected");
    t.assert_false(ssl_info.has_ssl, "ProxySslInfo rolled back on error");

    // NET2_C03: StreamPool release_connection_or_handoff does not hand off or idle-pool draining connections
    var sp = net::new_stream_pool(6, 32, 4);
    var pk = net::PoolKey { scheme: net::PoolScheme.Https, .. };
    pk.origin_endpoint.host.append("api.example.com");
    pk.origin_endpoint.port = 443;
    let cid = net::register_connection(sp, pk, net::NegotiatedProtocol.Http2, "1.1.1.1", 100, 1000);
    t.assert_true(net::enqueue_group_waiter(sp, pk, 777), "waiter enqueued");
    sp.conns[0].no_new_exchanges = true;
    var waiter_out = net::WantConn { .. };
    let rel_ok, handed_off = net::release_connection_or_handoff(sp, cid, 2000, waiter_out);
    t.assert_true(rel_ok && !handed_off, "draining connection not handed off to waiter");
    let g_idx = net::find_group_index(sp, pk);
    t.assert_eq(sp.groups[g_idx].active_conns, 0, "active_conns decremented to 0");
    t.assert_eq(sp.groups[g_idx].idle_conns, 0, "draining connection closed rather than added to idle_conns");
}

fn test_warm_upstream_pool_and_slowloris_h1_guard(t: lit::T&) {
    t.run("ReverseProxy Warm UpstreamPool Reuse and EPOLLRDHUP Eviction") { sub =>
        let slot_idx, ok_pipe = net::alloc_virtual_pipe_slot();
        sub.assert_true(ok_pipe, "allocated virtual pipe slot");
        defer net::free_virtual_pipe_slot(slot_idx);

        let fd_client = (net::virtual_pipe_to_fd(slot_idx, false) & 0x7FFFFFFF) as i32;
        var backend_end: net::Transport = net::Transport.Virtual { pipe_slot: slot_idx, is_b_end: true };
        let canned_resp = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok";
        sub.assert_eq(backend_end.send(canned_resp), canned_resp.len as i32, "seeded backend response");

        var rp = proxy::new_reverse_proxy(proxy::LbPolicy.RoundRobin);
        proxy::add_upstream_target(rp.cluster, "backend.internal", 8080);
        sub.assert_true(
            proxy::park_proxy_upstream_conn(rp, fd_client, "backend.internal", 8080),
            "parked warm upstream socket",
        );

        var sp = net::new_stream_pool(6, 32, 4);
        var in_headers = http::HeaderMap { .. };
        http::append_header(in_headers, "Host", "edge.example.com");
        var out_resp = http::Response { .. };
        let ex_ok = proxy::execute_proxy_exchange(
            rp, sp, "GET", "/ready", in_headers, "203.0.113.10", "https", "", out_resp, 1000, 1000000,
        );
        sub.assert_true(ex_ok, "execute_proxy_exchange reused warm upstream connection");
        sub.assert_eq(out_resp.status_code, 200, "received 200 OK from warm upstream");
        sub.assert_bytes_eq(out_resp.body[..], "ok", "received body from warm upstream");
        sub.assert_false(rp.warm_upstreams.entries[0].in_use, "warm socket returned to idle pool");
        sub.assert_true(rp.warm_upstreams.entries[0].healthy, "warm socket remains healthy");

        sub.assert_true(
            net::notify_upstream_epoll_events(rp.warm_upstreams, fd_client, net::EPOLLRDHUP),
            "notified EPOLLRDHUP on warm socket",
        );
        sub.assert_eq(rp.warm_upstreams.evicted_rdhup, 1 as u64, "EPOLLRDHUP evicted idle warm socket");
        sub.assert_false(rp.warm_upstreams.entries[0].healthy, "warm socket marked unhealthy");
    };

    t.run("HTTP/1.1 read_response_headers Enforces Slowloris Header Line Cap") { sub =>
        var conn = net::PooledConnection { .. };
        let _ = conn.rx_buf.try_append("HTTP/1.1 200 OK\r\n");
        for i in 105 {
            let _ = conn.rx_buf.try_append("X-Pad: 1\r\n");
        }
        let _ = conn.rx_buf.try_append("\r\n");
        let _, ok_hdr = wing::read_response_headers(conn, 1000);
        sub.assert_false(ok_hdr, "read_response_headers rejects > 100 header lines via Slowloris guard");
    };
}

fn main() {
    var runner = lit::new_runner("Reverse Proxy, GCRA Rate Limiter, MASQUE, and Alt-Svc Suite", lit::Verbosity.Verbose);

    lit::run_case(runner, "1. SOCKS5 Greeting & RFC 1929", test_socks5_greeting_and_rfc1929);
    lit::run_case(runner, "2. SOCKS5 Command & Reply", test_socks5_command_and_reply_parsing);
    lit::run_case(runner, "3. HTTP CONNECT Tunnel & Buffer Hygiene", test_http_connect_tunnel_and_buffer_hygiene);
    lit::run_case(runner, "4. Slowloris Tarpit Defenses", test_slowloris_tarpit_defenses);
    lit::run_case(runner, "5. PROXY Protocol v1 (Text) Conformance", test_proxy_v1_conformance);
    lit::run_case(runner, "6. PROXY Protocol v2 (Binary) Conformance", test_proxy_v2_conformance);
    lit::run_case(runner, "7. PROXY Protocol v2 TLV Metadata", test_proxy_v2_tlvs);
    lit::run_case(runner, "8. Stream Stripping & Server Integration", test_proxy_server_integration);
    lit::run_case(runner, "9. Health State Machine Transitions", test_health_state_transitions);
    lit::run_case(runner, "10. Probe Wire Formatting and Response Evaluation", test_probe_wire_and_response_parsing);
    lit::run_case(runner, "11. Cluster Health Checker Engine", test_cluster_health_checker_integration);
    lit::run_case(runner, "12. Reverse Proxy Hardening & Backpressure", test_reverse_proxy_hardening);
    lit::run_case(runner, "13. GCRA Core Algorithm & Conformance", test_gcra_core_algorithm);
    lit::run_case(runner, "14. Gateway Multi-Client Rate Limiter", test_gateway_rate_limiter);
    lit::run_case(runner, "15. Mathematical GCRA TAT Scheduling & Burst Tolerance", test_gcra_tat_and_burst);
    lit::run_case(runner, "16. Anti-Starvation Multi-Cell Priority Reservation", test_anti_starvation_reservation);
    lit::run_case(runner, "17. 256-Micro-Shard Table & Per-Key Isolation", test_sharded_gcra_limiter);
    lit::run_case(runner, "18. Extreme DDoS Probabilistic Sampling (5%)", test_probabilistic_ddos_mitigation);
    lit::run_case(runner, "19. IETF RateLimit-* Header Synthesis", test_ietf_rate_limit_headers);
    lit::run_case(runner, "20. GCRA Arithmetic, Overflow & Zero Emission Invariants", test_gcra_arithmetic_and_overflow);
    lit::run_case(runner, "21. RFC 9297 Capsules & HTTP Datagrams", test_rfc9297_capsules_and_datagrams);
    lit::run_case(runner, "22. RFC 9298 MASQUE CONNECT-UDP", test_rfc9298_connect_udp);
    lit::run_case(runner, "23. RFC 9484 MASQUE CONNECT-IP", test_rfc9484_connect_ip);
    lit::run_case(runner, "24. MASQUE Client Sessions & Tunneling", test_masque_client_sessions_and_tunneling);
    lit::run_case(runner, "25. MASQUE CONNECT-UDP Path Parsing", test_masque_connect_udp_path_parsing);
    lit::run_case(runner, "26. MASQUE Capsule Codecs", test_masque_capsule_codecs);
    lit::run_case(runner, "27. DNS Pointer Security", test_dns_pointer_security);
    lit::run_case(runner, "28. DNS Record Bounds & HTTPS Target", test_dns_record_bounds_and_https_target);
    lit::run_case(runner, "29. Alt-Svc Learning & HTTP/3 Promotion", test_altsvc_learning_and_h3_promotion);
    lit::run_case(runner, "30. Protocol Racing & UDP Firewall Fallback", test_chromium_protocol_racing_and_udp_fallback);
    lit::run_case(runner, "31. Alt-Svc Clear Directive & TTL Expiration", test_altsvc_clear_and_ttl_expiration);
    lit::run_case(runner, "32. RFC 7838 Insecure Transport Security & Toggles", test_rfc7838_security_and_options);
    lit::run_case(runner, "33. RFC 9440 Client-Cert", test_client_cert_header);
    lit::run_case(runner, "34. Load Balancer: Weights, PRNG, and State Transitions", test_load_balancer);
    lit::run_case(runner, "35. Active Health Check: Prober State Machine & Thresholds", test_health_check);
    lit::run_case(runner, "36. GCRA Rate Limiter: Headroom, Burst Headroom, and Buffer Limits", test_gcra_rate_limiter);
    lit::run_case(runner, "37. Reverse Proxy: Stream Ring Buffer & Zero-Copy Forwarding", test_reverse_proxy_streaming);
    lit::run_case(runner, "38. HAProxy PROXY Protocol v2 §2.2: Truncated TLVs & Trailing Bytes", test_proxy_v2_truncated_tlv_and_trailing_bytes);
    lit::run_case(runner, "39. Pool & Proxy SAN invariants (net/pool.goose, net/proxy.goose)", test_pool_and_proxy_san_invariants);
    lit::run_case(runner, "40. PROXY Protocol v1 Token Capacity Guard", test_proxy_protocol_overflow);
    lit::run_case(runner, "41. MASQUE Address Request Capsule Bounds", test_masque_address_capsule_bounds);
    lit::run_case(runner, "42. goose2rfc net/ RFC Audit Regressions", test_goose2rfc_net_audit_regressions);
    lit::run_case(runner, "43. Warm UpstreamPool & Slowloris H1 Guard", test_warm_upstream_pool_and_slowloris_h1_guard);

    let ok = lit::finish(runner);
    assert(ok);
}
