// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Consolidated Verification Suite: Reverse Proxy, GCRA Rate Limiter, MASQUE, and Alt-Svc Suite
import std;
import core from "..";
import wing from "..";

// --- Component: net_proxy ---
// Verification suite for net/proxy: SOCKS5/SOCKS5h (RFC 1928 & RFC 1929),
// HTTP CONNECT tunneling, credential isolation, and 4-tier Slowloris defenses.
// CVE-2026-94439, CVE-2026-56866, CVE-2025-4673, and CVE-2021-33197 defenses.

fn test_socks5_greeting_and_rfc1929(t: core::T&) {
    t.run("SOCKS5 Phase 1 Greeting and Negotiation") { sub =>
        var greeting_buf: u8[..16] = [];
        wing::build_socks5_greeting(true, true, greeting_buf);

        sub.assert_eq(greeting_buf[0], 0x05, "Greeting version is 0x05");
        sub.assert_eq(greeting_buf[1], 3, "3 auth methods announced (None, UserPass, GSSAPI)");
        sub.assert_eq(greeting_buf[2], 0x00, "Method 0 is None");
        sub.assert_eq(greeting_buf[3], 0x02, "Method 1 is UserPass");
        sub.assert_eq(greeting_buf[4], 0x01, "Method 2 is GSSAPI");

        // Greeting without credentials and without GSSAPI (None only)
        var greet_none: u8[..16] = [];
        wing::build_socks5_greeting(false, false, greet_none);
        sub.assert_eq(greet_none.len, 3, "Greeting len == 3 (ver, nmethods=1, none)");
        sub.assert_eq(greet_none[1], 1, "1 auth method announced");
        sub.assert_eq(greet_none[2], 0x00, "Method is None");

        // Parse valid server selection [0x05, 0x02]
        let server_reply: u8[2] = [0x05, 0x02];
        let method, err = wing::parse_socks5_greeting_reply(server_reply[..]);
        sub.assert_true(err == wing::Socks5Error.None, "Greeting parsed cleanly");
        sub.assert_eq(method, 0x02, "UserPass method selected by server");

        // Server selects None [0x05, 0x00]
        let reply_none: u8[2] = [0x05, 0x00];
        let m_none, err_none = wing::parse_socks5_greeting_reply(reply_none[..]);
        sub.assert_true(err_none == wing::Socks5Error.None, "None auth parsed cleanly");
        sub.assert_eq(m_none, 0x00, "None selected");

        // Server rejects with 0xFF
        let reject_reply: u8[2] = [0x05, 0xFF];
        let m_rej, err_rej = wing::parse_socks5_greeting_reply(reject_reply[..]);
        sub.assert_true(err_rej == wing::Socks5Error.NoAcceptableAuth, "0xFF rejected as NoAcceptableAuth");

        // Server bad versions
        let bad_ver1: u8[2] = [0x04, 0x00];
        let m_bad1, err_bad1 = wing::parse_socks5_greeting_reply(bad_ver1[..]);
        sub.assert_true(err_bad1 == wing::Socks5Error.InvalidVersion, "Version 0x04 rejected");

        let bad_ver2: u8[2] = [0x06, 0x00];
        let m_bad2, err_bad2 = wing::parse_socks5_greeting_reply(bad_ver2[..]);
        sub.assert_true(err_bad2 == wing::Socks5Error.InvalidVersion, "Version 0x06 rejected");

        // Truncated greeting reply
        let trunc1: u8[1] = [0x05];
        let m_tr1, err_tr1 = wing::parse_socks5_greeting_reply(trunc1[..]);
        sub.assert_true(err_tr1 == wing::Socks5Error.BufferTruncated, "1-byte reply is truncated");

        let empty_reply: u8[0] = [];
        let m_emp, err_emp = wing::parse_socks5_greeting_reply(empty_reply[..]);
        sub.assert_true(err_emp == wing::Socks5Error.BufferTruncated, "0-byte reply is truncated");
    };

    t.run("RFC 1929 Subnegotiation Version 0x01 Invariant & Buffer Limits") { sub =>
        var auth_buf: u8[..520] = [];
        let auth_err = wing::build_socks5_rfc1929_auth("testuser", "secretpass123", auth_buf);
        sub.assert_true(auth_err == wing::Socks5Error.None, "RFC 1929 auth frame built");

        // Critical standard invariant: RFC 1929 version MUST be 0x01, NOT 0x05!
        sub.assert_eq(auth_buf[0], 0x01, "First byte is strictly RFC 1929 version 0x01");
        sub.assert_eq(auth_buf[1], 8, "Username length is 8");
        sub.assert_bytes_eq(auth_buf[2..10], "testuser", "Username matches");
        sub.assert_eq(auth_buf[10], 13, "Password length is 13");
        sub.assert_bytes_eq(auth_buf[11..24], "secretpass123", "Password matches");

        // Boundary: 0-length username is forbidden per RFC 1929
        var auth_buf_bad: u8[..520] = [];
        let err_empty_u = wing::build_socks5_rfc1929_auth("", "secret", auth_buf_bad);
        sub.assert_true(err_empty_u == wing::Socks5Error.AuthFailed, "0-length username rejected");

        // Boundary: 0-length password is forbidden per RFC 1929
        let err_empty_p = wing::build_socks5_rfc1929_auth("user", "", auth_buf_bad);
        sub.assert_true(err_empty_p == wing::Socks5Error.AuthFailed, "0-length password rejected");

        // Boundary: 1-char username and password
        let err_single = wing::build_socks5_rfc1929_auth("u", "p", auth_buf_bad);
        sub.assert_true(err_single == wing::Socks5Error.None, "Single-char user/pass accepted");
        sub.assert_eq(auth_buf_bad.len, 5, "Len is 1 (ver) + 1 (ulen) + 1 (u) + 1 (plen) + 1 (p) = 5");

        // Parse valid RFC 1929 reply [0x01, 0x00]
        let reply_ok: u8[2] = [0x01, 0x00];
        let rep_err = wing::parse_socks5_rfc1929_reply(reply_ok[..]);
        sub.assert_true(rep_err == wing::Socks5Error.None, "Status 0x00 authenticated successfully");

        // Parse rejected RFC 1929 reply [0x01, 0x01]
        let reply_fail: u8[2] = [0x01, 0x01];
        let fail_err = wing::parse_socks5_rfc1929_reply(reply_fail[..]);
        sub.assert_true(fail_err == wing::Socks5Error.AuthFailed, "Non-0x00 status rejected as AuthFailed");

        // Invalid version byte in RFC 1929 reply (e.g. 0x05)
        let reply_wrong_ver: u8[2] = [0x05, 0x00];
        let wrong_ver_err = wing::parse_socks5_rfc1929_reply(reply_wrong_ver[..]);
        sub.assert_true(wrong_ver_err == wing::Socks5Error.InvalidAuthResponse, "Wrong version byte in auth reply rejected");

        // Truncated RFC 1929 reply
        let reply_trunc: u8[1] = [0x01];
        let trunc_auth_err = wing::parse_socks5_rfc1929_reply(reply_trunc[..]);
        sub.assert_true(trunc_auth_err == wing::Socks5Error.BufferTruncated, "Truncated auth reply caught");
    };
}

fn test_socks5_command_and_reply_parsing(t: core::T&) {
    t.run("socks5h vs socks5 ATYP and Port Serialization") { sub =>
        // socks5h:// MUST use ATYP = 0x03 to delegate DNS resolution to proxy node
        var req_socks5h: u8[..300] = [];
        let dummy_ip: u8[4] = [0, 0, 0, 0];
        let err_h = wing::build_socks5_connect_request(wing::ProxyScheme.Socks5h, "target.internal", dummy_ip, false, 443, req_socks5h);
        sub.assert_true(err_h == wing::Socks5Error.None, "Socks5h request built");

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
        let err_5 = wing::build_socks5_connect_request(wing::ProxyScheme.Socks5, "example.com", local_ip, true, 80, req_socks5);
        sub.assert_true(err_5 == wing::Socks5Error.None, "Socks5 IPv4 request built");
        sub.assert_eq(req_socks5[3], 0x01, "ATYP == 0x01 (IPv4)");
        sub.assert_eq(req_socks5[4], 93, "IPv4 octet 0");
        sub.assert_eq(req_socks5[5], 184, "IPv4 octet 1");
        sub.assert_eq(req_socks5[6], 216, "IPv4 octet 2");
        sub.assert_eq(req_socks5[7], 34, "IPv4 octet 3");
        sub.assert_eq(req_socks5[8], 0x00, "Port high byte 0 for 80");
        sub.assert_eq(req_socks5[9], 80, "Port low byte 80");

        // High port boundary: 65535 (0xFFFF)
        var req_max_port: u8[..300] = [];
        let err_mp = wing::build_socks5_connect_request(wing::ProxyScheme.Socks5, "example.com", local_ip, true, 65535, req_max_port);
        sub.assert_true(err_mp == wing::Socks5Error.None, "Max port 65535 built");
        sub.assert_eq(req_max_port[8], 0xFF, "Port hi == 0xFF");
        sub.assert_eq(req_max_port[9], 0xFF, "Port lo == 0xFF");
    };

    t.run("Parse SOCKS5 Reply Frames & All 9 Error Codes") { sub =>
        // Success reply: VER=0x05, REP=0x00, RSV=0x00, ATYP=0x01, BND.ADDR=127.0.0.1, BND.PORT=1080 (0x0438)
        let reply_ok: u8[10] = [0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x04, 0x38];
        let rep, err = wing::parse_socks5_connect_reply(reply_ok[..]);
        sub.assert_true(err == wing::Socks5Error.None, "Success reply parsed cleanly");
        sub.assert_eq(rep.bound_port, 1080, "Bound port 1080 parsed");
        sub.assert_eq(rep.bytes_consumed, 10, "Consumed exact 10 bytes");

        // Test all RFC 1928 failure codes:
        // REP = 0x01: GeneralFailure
        let reply_01: u8[10] = [0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        let _, err_01 = wing::parse_socks5_connect_reply(reply_01[..]);
        sub.assert_true(err_01 == wing::Socks5Error.ServerFailure, "0x01 is ServerFailure");

        // REP = 0x02: ConnectionNotAllowed
        let reply_02: u8[10] = [0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        let _, err_02 = wing::parse_socks5_connect_reply(reply_02[..]);
        sub.assert_true(err_02 == wing::Socks5Error.ConnectionNotAllowed, "0x02 is ConnectionNotAllowed");

        // REP = 0x03: NetworkUnreachable
        let reply_03: u8[10] = [0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        let _, err_03 = wing::parse_socks5_connect_reply(reply_03[..]);
        sub.assert_true(err_03 == wing::Socks5Error.NetworkUnreachable, "0x03 is NetworkUnreachable");

        // REP = 0x04: HostUnreachable
        let reply_04: u8[10] = [0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        let _, err_04 = wing::parse_socks5_connect_reply(reply_04[..]);
        sub.assert_true(err_04 == wing::Socks5Error.HostUnreachable, "0x04 is HostUnreachable");

        // REP = 0x05: ConnectionRefused
        let reply_05: u8[10] = [0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        let _, err_05 = wing::parse_socks5_connect_reply(reply_05[..]);
        sub.assert_true(err_05 == wing::Socks5Error.ConnectionRefused, "0x05 is ConnectionRefused");

        // REP = 0x06: TtlExpired
        let reply_06: u8[10] = [0x05, 0x06, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        let _, err_06 = wing::parse_socks5_connect_reply(reply_06[..]);
        sub.assert_true(err_06 == wing::Socks5Error.TtlExpired, "0x06 is TtlExpired");

        // REP = 0x07: CommandNotSupported
        let reply_07: u8[10] = [0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        let _, err_07 = wing::parse_socks5_connect_reply(reply_07[..]);
        sub.assert_true(err_07 == wing::Socks5Error.CommandNotSupported, "0x07 is CommandNotSupported");

        // REP = 0x08: AddressTypeNotSupported
        let reply_08: u8[10] = [0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        let _, err_08 = wing::parse_socks5_connect_reply(reply_08[..]);
        sub.assert_true(err_08 == wing::Socks5Error.AddressTypeNotSupported, "0x08 is AddressTypeNotSupported");

        // Domain bound reply: 4 + 1 + 10 ("proxy.node") + 2 = 17 bytes
        var rep_domain: u8[17] = [0x05, 0x00, 0x00, 0x03, 10, 'p', 'r', 'o', 'x', 'y', '.', 'n', 'o', 'd', 'e', 0x1F, 0x90];
        let rep_d, err_d = wing::parse_socks5_connect_reply(rep_domain[..]);
        sub.assert_true(err_d == wing::Socks5Error.None, "Domain reply parsed cleanly");
        sub.assert_eq(rep_d.bound_port, 8080, "Bound port 8080 parsed");
        sub.assert_eq(rep_d.bytes_consumed, 17, "Consumed exact 17 bytes");

        // IPv6 bound reply: 4 + 16 (addr) + 2 (port 443 = 0x01BB) = 22 bytes
        var rep_ipv6: u8[22] = [
            0x05, 0x00, 0x00, 0x04,
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x01, 0xBB,
        ];
        let rep_6, err_6 = wing::parse_socks5_connect_reply(rep_ipv6[..]);
        sub.assert_true(err_6 == wing::Socks5Error.None, "IPv6 reply parsed cleanly");
        sub.assert_eq(rep_6.bound_port, 443, "Bound port 443 parsed");
        sub.assert_eq(rep_6.bytes_consumed, 22, "Consumed exact 22 bytes");

        // Truncated replies
        let trunc_ipv4: u8[9] = [0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x04];
        let _, err_tr_4 = wing::parse_socks5_connect_reply(trunc_ipv4[..]);
        sub.assert_true(err_tr_4 == wing::Socks5Error.BufferTruncated, "Truncated IPv4 reply caught");

        let trunc_ipv6: u8[21] = [0x05, 0x00, 0x00, 0x04, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17];
        let _, err_tr_6 = wing::parse_socks5_connect_reply(trunc_ipv6[..]);
        sub.assert_true(err_tr_6 == wing::Socks5Error.BufferTruncated, "Truncated IPv6 reply caught");

        // Invalid ATYP (0x02)
        let reply_bad_atyp: u8[10] = [0x05, 0x00, 0x00, 0x02, 0, 0, 0, 0, 0, 0];
        let _, err_bad_atyp = wing::parse_socks5_connect_reply(reply_bad_atyp[..]);
        sub.assert_true(err_bad_atyp == wing::Socks5Error.AddressTypeNotSupported, "Invalid ATYP 0x02 rejected");
    };
}

fn test_http_connect_tunnel_and_buffer_hygiene(t: core::T&) {
    t.run("CONNECT Header Construction & Credential Isolation (CVE-2025-4673)") { sub =>
        var req_buf: u8[..1024] = [];
        wing::build_http_connect_request("secure.bank.com", 443, "Basic dXNlcjpwYXNz", "goose-wing/1.0", req_buf);

        sub.assert_true(starts_with(req_buf[..], "CONNECT secure.bank.com:443 HTTP/1.1\r\n"), "CONNECT request line correct");
        sub.assert_contains(req_buf[..], "Proxy-Authorization: Basic dXNlcjpwYXNz\r\n", "Proxy auth header included");

        // Isolation barrier: sanitize_tunnel_headers_for_origin (CVE-2025-4673 & CVE-2021-33197)
        var origin_headers: wing::HeaderItem[..32] = [];
        origin_headers.push(wing::make_header("Host", "secure.bank.com"));
        origin_headers.push(wing::make_header("Proxy-Authorization", "Basic dXNlcjpwYXNz"));
        origin_headers.push(wing::make_header("PROXY-AUTHORIZATION", "Basic UPPERCASE_LEAK"));
        origin_headers.push(wing::make_header("proxy-authorization", "Basic lowercase_leak"));
        origin_headers.push(wing::make_header("Proxy-Authenticate", "Basic realm=corp"));
        origin_headers.push(wing::make_header("Proxy-Connection", "Keep-Alive"));
        origin_headers.push(wing::make_header("Authorization", "Bearer user_token_99"));
        origin_headers.push(wing::make_header("Cookie", "session=secret_session"));

        wing::sanitize_tunnel_headers_for_origin(origin_headers);

        sub.assert_eq(origin_headers.len, 3, "All 5 proxy header variations stripped from origin request");
        sub.assert_bytes_eq(origin_headers[0].name[..], "Host", "Host header preserved");
        sub.assert_bytes_eq(origin_headers[1].name[..], "Authorization", "Target origin bearer auth preserved");
        sub.assert_bytes_eq(origin_headers[2].name[..], "Cookie", "Origin cookies preserved");

        // Edge case: empty headers list
        var empty_hdrs: wing::HeaderItem[..32] = [];
        wing::sanitize_tunnel_headers_for_origin(empty_hdrs);
        sub.assert_eq(empty_hdrs.len, 0, "Empty headers list remains empty");

        // Edge case: headers list with ONLY proxy headers
        var only_proxy: wing::HeaderItem[..32] = [];
        only_proxy.push(wing::make_header("Proxy-Authorization", "Basic xyz"));
        only_proxy.push(wing::make_header("Proxy-Connection", "close"));
        wing::sanitize_tunnel_headers_for_origin(only_proxy);
        sub.assert_eq(only_proxy.len, 0, "Headers list with only proxy headers reduced to 0");
    };

    t.run("OkHttp Leftover Buffer Defense: TLS Tunnel Buffered Too Many Bytes (CVE-2026-56866)") { sub =>
        // 1. Clean CONNECT response with no trailing bytes
        let clean_resp = "HTTP/1.1 200 Connection Established\r\nProxy-Agent: corporate-proxy\r\n\r\n";
        let err_clean = wing::verify_connect_tunnel_response(clean_resp, 0);
        sub.assert_true(err_clean == wing::ConnectTunnelError.None, "Clean 200 OK CONNECT approved");

        // 2. Data injection attack: Extra bytes after \r\n\r\n before TLS handshake
        let injected_resp = "HTTP/1.1 200 Connection Established\r\n\r\nINJECTED_TLS_PREFIX_DATA";
        let err_injected = wing::verify_connect_tunnel_response(injected_resp, 0);
        sub.assert_true(err_injected == wing::ConnectTunnelError.TunnelBufferedTooManyBytes, "Detected leftover buffer data injection");

        // 3. Single-byte smuggled prefix attack
        let single_byte_inj = "HTTP/1.1 200 Connection Established\r\n\r\nX";
        let err_single = wing::verify_connect_tunnel_response(single_byte_inj, 0);
        sub.assert_true(err_single == wing::ConnectTunnelError.TunnelBufferedTooManyBytes, "1-byte smuggled prefix caught");

        // 4. Sink has leftover unwritten bytes
        let err_sink = wing::verify_connect_tunnel_response(clean_resp, 16);
        sub.assert_true(err_sink == wing::ConnectTunnelError.TunnelBufferedTooManyBytes, "Detected non-empty sink buffer");

        // 5. Proxy Authentication Required (407)
        let auth_req_resp = "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\n\r\n";
        let err_407 = wing::verify_connect_tunnel_response(auth_req_resp, 0);
        sub.assert_true(err_407 == wing::ConnectTunnelError.ProxyAuthRequired, "407 status parsed correctly");

        // 6. Bad Gateway (502)
        let bad_gw = "HTTP/1.1 502 Bad Gateway\r\n\r\n";
        let err_502 = wing::verify_connect_tunnel_response(bad_gw, 0);
        sub.assert_true(err_502 == wing::ConnectTunnelError.ConnectFailed, "502 status mapped to ConnectFailed");

        // 7. Forbidden (403)
        let forbidden = "HTTP/1.1 403 Forbidden\r\n\r\n";
        let err_403 = wing::verify_connect_tunnel_response(forbidden, 0);
        sub.assert_true(err_403 == wing::ConnectTunnelError.ConnectFailed, "403 status mapped to ConnectFailed");

        // 8. Missing \r\n\r\n
        let no_end = "HTTP/1.1 200 OK\r\nHeader: value";
        let err_no_end = wing::verify_connect_tunnel_response(no_end, 0);
        sub.assert_true(err_no_end == wing::ConnectTunnelError.MalformedHeaders, "Missing header end separator caught");

        // 9. Short / Truncated response
        let short_resp = "HTTP/1.1 200";
        let err_short = wing::verify_connect_tunnel_response(short_resp, 0);
        sub.assert_true(err_short == wing::ConnectTunnelError.MalformedHeaders, "Truncated response caught");
    };
}

fn test_slowloris_tarpit_defenses(t: core::T&) {
    t.run("4-Tier Slowloris Defense Enforcement") { sub =>
        let cfg = wing::new_slowloris_defense_config();
        var reader = wing::new_header_reader(cfg, 0);

        // Feed standard fast chunk at t=100ms
        let chunk1 = "GET /index.html HTTP/1.1\r\nHost: example.com\r\n";
        let v1 = wing::feed_header_bytes(reader, chunk1, 100000000);
        sub.assert_true(v1 == wing::SlowlorisViolation.None, "Valid chunk approved");

        // Barrier 1: Monotonic Cumulative Header Deadline (10s)
        let chunk2 = "User-Agent: test\r\n";
        let v_timeout = wing::feed_header_bytes(reader, chunk2, 10500000000); // t=10.5s
        sub.assert_true(v_timeout == wing::SlowlorisViolation.HeaderTimeoutExpired, "Header timeout triggered after 10s monotonic deadline");
        sub.assert_true(reader.poison_connection, "Poison connection flagged");

        // Barrier 3: Memory ceiling (64 KB)
        var reader_mem = wing::new_header_reader(cfg, 0);
        reader_mem.cumulative_header_bytes = 65000;
        let big_chunk: u8[1000] = ['A'; 1000];
        let v_mem = wing::feed_header_bytes(reader_mem, big_chunk[..], 500000000);
        sub.assert_true(v_mem == wing::SlowlorisViolation.MaxHeaderBytesExceeded, "Hard memory ceiling triggered on 65 KB header block");
        sub.assert_true(reader_mem.poison_connection, "Memory ceiling poisons connection");

        // Barrier 4: Byte-Drip gate (< 256 B/s)
        var reader_drip = wing::new_header_reader(cfg, 0);
        let drip_byte = "X";
        // 1 byte received over 2.0 seconds -> 0.5 B/s (< 256 B/s)
        let v_drip = wing::feed_header_bytes(reader_drip, drip_byte, 2000000000);
        sub.assert_true(v_drip == wing::SlowlorisViolation.MinIngressRateViolated, "Byte-drip tarpit caught by minimum ingress rate gate");
        sub.assert_true(reader_drip.poison_connection, "Byte-drip poisons connection");

        // Barrier 5: Header lines count ceiling (> 100 lines)
        var reader_lines = wing::new_header_reader(cfg, 0);
        var many_lines: u8[..4096] = [];
        for i in 101 {
            many_lines.append("X-H: v\r\n");
        }
        let v_lines = wing::feed_header_bytes(reader_lines, many_lines[..], 500000000);
        sub.assert_true(v_lines == wing::SlowlorisViolation.MaxHeaderCountExceeded, "101 header lines exceeds max_header_count (100)");
        sub.assert_true(reader_lines.poison_connection, "Header count excess poisons connection");
    };
}

// --- Component: net_proxy_protocol ---
// tests/proxy_protocol_test.goose
// Verification test suite for HAProxy PROXY Protocol v1 (text) and v2 (binary).

// 1. PROXY Protocol v1 (Text) Conformance
fn test_proxy_v1_conformance(t: core::T&) {
    t.run("PROXY-v1-01: Valid TCP4 line parsing") { sub =>
        let raw = "PROXY TCP4 192.168.0.1 10.0.0.1 56324 443\r\nGET / HTTP/1.1\r\n";
        let hdr, consumed, ok = wing::parse_proxy_v1(raw);
        sub.assert_true(ok, "parse_proxy_v1 succeeds on valid TCP4");
        sub.assert_eq(consumed, 43, "consumed exact 43 bytes of PROXY v1 line");
        sub.assert_true(hdr.version == wing::ProxyProtocolVersion.V1, "version is V1");
        sub.assert_true(hdr.command == wing::ProxyCommand.Proxy, "command is Proxy");
        sub.assert_true(hdr.family == wing::ProxyAddressFamily.Inet4, "family is Inet4");
        sub.assert_true(hdr.transport == wing::ProxyTransportProtocol.Stream, "transport is Stream");
        sub.assert_bytes_eq(hdr.src_ip_str[..], "192.168.0.1", "src_ip_str matches");
        sub.assert_bytes_eq(hdr.dst_ip_str[..], "10.0.0.1", "dst_ip_str matches");
        sub.assert_eq(hdr.src_port, 56324, "src_port matches");
        sub.assert_eq(hdr.dst_port, 443, "dst_port matches");
        sub.assert_eq(hdr.src_ipv4[0], 192, "IPv4 octet 0 matches");
        sub.assert_eq(hdr.src_ipv4[3], 1, "IPv4 octet 3 matches");
    };

    t.run("PROXY-v1-02: Valid TCP6 line parsing") { sub =>
        let raw = "PROXY TCP6 2001:db8::1 2001:db8::2 56324 443\r\n";
        let hdr, consumed, ok = wing::parse_proxy_v1(raw);
        sub.assert_true(ok, "parse_proxy_v1 succeeds on valid TCP6");
        sub.assert_eq(consumed, raw.len, "consumed full line");
        sub.assert_true(hdr.family == wing::ProxyAddressFamily.Inet6, "family is Inet6");
        sub.assert_bytes_eq(hdr.src_ip_str[..], "2001:db8::1", "IPv6 src matches");
        sub.assert_bytes_eq(hdr.dst_ip_str[..], "2001:db8::2", "IPv6 dst matches");
        sub.assert_eq(hdr.src_port, 56324, "src port matches");
        sub.assert_eq(hdr.dst_port, 443, "dst port matches");
    };

    t.run("PROXY-v1-03: UNKNOWN protocol parsing") { sub =>
        let raw = "PROXY UNKNOWN\r\n";
        let hdr, consumed, ok = wing::parse_proxy_v1(raw);
        sub.assert_true(ok, "parse_proxy_v1 succeeds on UNKNOWN");
        sub.assert_eq(consumed, 15, "consumed exact 15 bytes");
        sub.assert_true(hdr.command == wing::ProxyCommand.Local, "command is Local for UNKNOWN");
        sub.assert_true(hdr.family == wing::ProxyAddressFamily.Unspec, "family is Unspec");
    };

    t.run("PROXY-v1-04: Serialization round-trip") { sub =>
        var hdr = wing::ProxyHeader {
            version: wing::ProxyProtocolVersion.V1,
            command: wing::ProxyCommand.Proxy,
            family: wing::ProxyAddressFamily.Inet4,
            transport: wing::ProxyTransportProtocol.Stream,
            src_ipv4: [172, 16, 1, 25],
            dst_ipv4: [10, 0, 0, 2],
            src_port: 41234,
            dst_port: 8080,
            ..
        };
        hdr.src_ip_str.append("172.16.1.25");
        hdr.dst_ip_str.append("10.0.0.2");

        var out: u8[..128] = [];
        let ok_fmt = wing::format_proxy_v1(hdr, out);
        sub.assert_true(ok_fmt, "format_proxy_v1 succeeds");
        sub.assert_bytes_eq(out[..], "PROXY TCP4 172.16.1.25 10.0.0.2 41234 8080\r\n", "serialized v1 format matches spec");

        // Parse back
        let back_hdr, consumed, ok_back = wing::parse_proxy_v1(out[..]);
        sub.assert_true(ok_back, "parse back succeeds");
        sub.assert_eq(consumed, out.len, "consumed all bytes");
        sub.assert_eq(back_hdr.src_port, 41234, "round-trip port matches");
        sub.assert_bytes_eq(back_hdr.src_ip_str[..], "172.16.1.25", "round-trip IP matches");
    };

    t.run("PROXY-v1-05: Rejection of invalid and truncated lines") { sub =>
        // Missing CRLF
        let truncated = "PROXY TCP4 192.168.0.1 10.0.0.1 56324 443";
        let _, _, ok_trunc = wing::parse_proxy_v1(truncated);
        sub.assert_false(ok_trunc, "truncated line without CRLF rejected");

        // Wrong prefix
        let wrong_prefix = "PROX2 TCP4 192.168.0.1 10.0.0.1 56324 443\r\n";
        let _, _, ok_pref = wing::parse_proxy_v1(wrong_prefix);
        sub.assert_false(ok_pref, "wrong prefix rejected");

        // Invalid IP octet > 255
        let bad_ip = "PROXY TCP4 300.168.0.1 10.0.0.1 56324 443\r\n";
        let _, _, ok_bad_ip = wing::parse_proxy_v1(bad_ip);
        sub.assert_false(ok_bad_ip, "octet > 255 rejected");

        // Invalid Port > 65535
        let bad_port = "PROXY TCP4 192.168.0.1 10.0.0.1 70000 443\r\n";
        let _, _, ok_bad_port = wing::parse_proxy_v1(bad_port);
        sub.assert_false(ok_bad_port, "port > 65535 rejected");

        // Missing tokens
        let missing_tok = "PROXY TCP4 192.168.0.1 10.0.0.1 443\r\n";
        let _, _, ok_mis = wing::parse_proxy_v1(missing_tok);
        sub.assert_false(ok_mis, "line with missing tokens rejected");
    };
}

// 2. PROXY Protocol v2 (Binary) Conformance
fn test_proxy_v2_conformance(t: core::T&) {
    t.run("PROXY-v2-01: IPv4 TCP binary header parsing") { sub =>
        // Preamble (12) + 0x21 (v2, PROXY) + 0x11 (INET4, STREAM) + len 12 (0x000C)
        var wire: u8[..64] = [];
        for b in internal::PROXY_V2_PREAMBLE { wire.push(b); }
        wire.push(0x21); // version 2, PROXY command
        wire.push(0x11); // INET4, STREAM (TCP)
        wire.push(0x00); wire.push(12); // payload length = 12

        // IPv4 addresses: 192.168.1.10 -> 10.0.0.1
        wire.push(192); wire.push(168); wire.push(1); wire.push(10);
        wire.push(10); wire.push(0); wire.push(0); wire.push(1);
        // Ports: src 50000 (0xC350), dst 443 (0x01BB)
        wire.push(0xC3); wire.push(0x50);
        wire.push(0x01); wire.push(0xBB);

        let hdr, consumed, ok = wing::parse_proxy_v2(wire[..]);
        sub.assert_true(ok, "parse_proxy_v2 succeeds on IPv4 TCP");
        sub.assert_eq(consumed, 28, "consumed exact 28 bytes (16 header + 12 addr)");
        sub.assert_true(hdr.version == wing::ProxyProtocolVersion.V2, "version is V2");
        sub.assert_true(hdr.command == wing::ProxyCommand.Proxy, "command is Proxy");
        sub.assert_true(hdr.family == wing::ProxyAddressFamily.Inet4, "family is Inet4");
        sub.assert_true(hdr.transport == wing::ProxyTransportProtocol.Stream, "transport is Stream");
        sub.assert_bytes_eq(hdr.src_ip_str[..], "192.168.1.10", "formatted src IPv4 matches");
        sub.assert_bytes_eq(hdr.dst_ip_str[..], "10.0.0.1", "formatted dst IPv4 matches");
        sub.assert_eq(hdr.src_port, 50000, "src port matches");
        sub.assert_eq(hdr.dst_port, 443, "dst port matches");
    };

    t.run("PROXY-v2-02: Command LOCAL (health checks)") { sub =>
        var wire: u8[..32] = [];
        for b in internal::PROXY_V2_PREAMBLE { wire.push(b); }
        wire.push(0x20); // version 2, LOCAL command
        wire.push(0x00); // UNSPEC, UNSPEC
        wire.push(0x00); wire.push(0x00); // payload length = 0

        let hdr, consumed, ok = wing::parse_proxy_v2(wire[..]);
        sub.assert_true(ok, "parse_proxy_v2 succeeds on LOCAL");
        sub.assert_eq(consumed, 16, "consumed exact 16 bytes");
        sub.assert_true(hdr.command == wing::ProxyCommand.Local, "command is Local");
        sub.assert_true(hdr.family == wing::ProxyAddressFamily.Unspec, "family is Unspec");
    };

    t.run("PROXY-v2-03: IPv6 TCP binary header parsing") { sub =>
        var wire: u8[..64] = [];
        for b in internal::PROXY_V2_PREAMBLE { wire.push(b); }
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

        let hdr, consumed, ok = wing::parse_proxy_v2(wire[..]);
        sub.assert_true(ok, "parse_proxy_v2 succeeds on IPv6");
        sub.assert_eq(consumed, 52, "consumed 16 header + 36 addr = 52 bytes");
        sub.assert_true(hdr.family == wing::ProxyAddressFamily.Inet6, "family is Inet6");
        sub.assert_eq(hdr.src_port, 8080, "src port matches");
        sub.assert_eq(hdr.dst_port, 443, "dst port matches");
    };

    t.run("PROXY-v2-04: Rejection of invalid v2 headers") { sub =>
        // Corrupted preamble
        var bad_preamble: u8[16] = [0; 16];
        let _, _, ok_bad = wing::parse_proxy_v2(bad_preamble[..]);
        sub.assert_false(ok_bad, "bad preamble rejected");

        // Wrong version (0x11 instead of 0x21)
        var bad_ver: u8[..32] = [];
        for b in internal::PROXY_V2_PREAMBLE { bad_ver.push(b); }
        bad_ver.push(0x11); bad_ver.push(0x11); bad_ver.push(0); bad_ver.push(0);
        let _, _, ok_ver = wing::parse_proxy_v2(bad_ver[..]);
        sub.assert_false(ok_ver, "version != 2 rejected");

        // Truncated payload length claim
        var trunc_wire: u8[..32] = [];
        for b in internal::PROXY_V2_PREAMBLE { trunc_wire.push(b); }
        trunc_wire.push(0x21); trunc_wire.push(0x11);
        trunc_wire.push(0x00); trunc_wire.push(100); // claim 100 bytes but only 16 present
        let _, _, ok_len = wing::parse_proxy_v2(trunc_wire[..]);
        sub.assert_false(ok_len, "truncated payload rejected");
    };
}

// 3. PROXY Protocol v2 TLV (Type-Length-Value) Metadata
fn test_proxy_v2_tlvs(t: core::T&) {
    t.run("PROXY-v2-TLV-01: ALPN, Authority, and Unique ID") { sub =>
        var hdr = wing::ProxyHeader {
            version: wing::ProxyProtocolVersion.V2,
            command: wing::ProxyCommand.Proxy,
            family: wing::ProxyAddressFamily.Inet4,
            transport: wing::ProxyTransportProtocol.Stream,
            src_ipv4: [192, 168, 1, 100],
            dst_ipv4: [10, 0, 0, 1],
            src_port: 45678,
            dst_port: 443,
            ..
        };
        hdr.alpn.append("h2");
        hdr.authority.append("secure.api.internal");
        hdr.unique_id.append("trace-c0ffee-9988");

        var wire: u8[..256] = [];
        let ok_fmt = wing::format_proxy_v2(hdr, wire);
        sub.assert_true(ok_fmt, "format_proxy_v2 with TLVs succeeds");

        // Parse back
        let back_hdr, consumed, ok_parse = wing::parse_proxy_v2(wire[..]);
        sub.assert_true(ok_parse, "parse_proxy_v2 succeeds on serialized TLVs");
        sub.assert_eq(consumed, wire.len, "consumed full wire with TLVs");
        sub.assert_bytes_eq(back_hdr.alpn[..], "h2", "ALPN TLV matches");
        sub.assert_bytes_eq(back_hdr.authority[..], "secure.api.internal", "Authority/SNI TLV matches");
        sub.assert_bytes_eq(back_hdr.unique_id[..], "trace-c0ffee-9988", "Unique ID TLV matches");
    };

    t.run("PROXY-v2-TLV-02: SSL/TLS Metadata & Sub-TLVs") { sub =>
        var hdr = wing::ProxyHeader {
            version: wing::ProxyProtocolVersion.V2,
            command: wing::ProxyCommand.Proxy,
            family: wing::ProxyAddressFamily.Inet4,
            transport: wing::ProxyTransportProtocol.Stream,
            src_ipv4: [10, 20, 30, 40],
            dst_ipv4: [10, 0, 0, 2],
            src_port: 33445,
            dst_port: 8443,
            ..
        };
        hdr.ssl.has_ssl = true;
        hdr.ssl.client_flags = internal::PP2_CLIENT_SSL | internal::PP2_CLIENT_CERT_CONN;
        hdr.ssl.verify_result = 0; // successfully verified client cert
        hdr.ssl.version.append("TLSv1.3");
        hdr.ssl.cipher.append("TLS_AES_128_GCM_SHA256");
        hdr.ssl.client_cn.append("client.tenant42.prod");

        var wire: u8[..512] = [];
        let ok_fmt = wing::format_proxy_v2(hdr, wire);
        sub.assert_true(ok_fmt, "format_proxy_v2 with SSL TLV succeeds");

        // Parse back
        let back_hdr, consumed, ok_parse = wing::parse_proxy_v2(wire[..]);
        sub.assert_true(ok_parse, "parse_proxy_v2 parses SSL TLVs cleanly");
        sub.assert_eq(consumed, wire.len, "consumed entire buffer");
        sub.assert_true(back_hdr.ssl.has_ssl, "SSL flag set");
        sub.assert_eq(back_hdr.ssl.client_flags, internal::PP2_CLIENT_SSL | internal::PP2_CLIENT_CERT_CONN, "client flags preserved");
        sub.assert_eq(back_hdr.ssl.verify_result, 0, "verify_result is 0");
        sub.assert_bytes_eq(back_hdr.ssl.version[..], "TLSv1.3", "SSL version matches");
        sub.assert_bytes_eq(back_hdr.ssl.cipher[..], "TLS_AES_128_GCM_SHA256", "Cipher matches");
        sub.assert_bytes_eq(back_hdr.ssl.client_cn[..], "client.tenant42.prod", "Client CN matches");
    };
}

// 4. Stream Stripping & Server Pipeline Integration
fn test_proxy_server_integration(t: core::T&) {
    t.run("Auto-Detection and Stream Stripping") { sub =>
        let stream = "PROXY TCP4 203.0.113.195 10.0.0.1 54321 80\r\nGET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        var proxy_hdr = wing::ProxyHeader { .. };
        let rest, has_proxy = wing::detect_and_strip_proxy_header(stream, proxy_hdr);

        sub.assert_true(has_proxy, "PROXY header detected and stripped");
        sub.assert_bytes_eq(proxy_hdr.src_ip_str[..], "203.0.113.195", "Client IP extracted from PROXY v1");
        sub.assert_bytes_eq(rest[..15], "GET /index.html", "Remaining stream starts with HTTP request");

        // Non-proxy stream returns original stream unchanged
        let non_proxy = "GET /status HTTP/1.1\r\nHost: test.com\r\n\r\n";
        var empty_hdr = wing::ProxyHeader { .. };
        let rest2, has_proxy2 = wing::detect_and_strip_proxy_header(non_proxy, empty_hdr);
        sub.assert_false(has_proxy2, "No PROXY header detected on plain HTTP");
        sub.assert_bytes_eq(rest2, non_proxy, "Plain HTTP stream unchanged");
    };

    t.run("HttpServer with accept_proxy_protocol = true") { sub =>
        var server = wing::new_http_server("127.0.0.1", 8080);
        server.accept_proxy_protocol = true;
        wing::add_get_route(server, "/api/hello", 101);

        // Prepend PROXY v1 header before HTTP/1.1 wire request
        let wire_in = "PROXY TCP4 198.51.100.77 10.0.0.1 61234 8080\r\nGET /api/hello HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
        var wire_out: u8[..512] = [];

        let outcome, ok = wing::handle_connection_wire(server, "127.0.0.1", wire_in, 1700000000, wire_out);
        sub.assert_true(ok, "handle_connection_wire succeeds with PROXY header");
        sub.assert_true(outcome == wing::PipelineOutcome.Handled, "Pipeline handled route");
        sub.assert_gt(wire_out.len, 0, "Response generated");
        sub.assert_bytes_eq(wire_out[..15], "HTTP/1.1 200 OK", "Server returned 200 OK");
        sub.assert_eq(server.requests_processed, 1, "Requests counter incremented");
    };
}

// --- Component: net_proxy_health_check ---
// Verification suite for proxy/health_check and load_balancer integration:
// Active background health check probing, state machine transitions (UP, DOWN, PROBING),
// consecutive success/failure thresholds, and circuit breaker interlock.

fn test_health_state_transitions(t: core::T&) {
    t.run("Up -> Down on Consecutive Failures") { sub =>
        let cfg = wing::new_health_check_config(5000, 2000, 2, 3);
        var health = wing::new_upstream_health();
        sub.assert_true(health.state == wing::HealthState.Up, "Initial state is Up");

        // Fail 1 & 2: still Up
        wing::record_probe_failure(health, cfg);
        sub.assert_true(health.state == wing::HealthState.Up, "State remains Up after 1 failure");
        sub.assert_eq(health.consecutive_failures, 1, "Consecutive failures = 1");

        wing::record_probe_failure(health, cfg);
        sub.assert_true(health.state == wing::HealthState.Up, "State remains Up after 2 failures");

        // Fail 3: threshold reached -> transitions to Down
        wing::record_probe_failure(health, cfg);
        sub.assert_true(health.state == wing::HealthState.Down, "State transitioned to Down at 3 failures");
        sub.assert_eq(health.consecutive_failures, 3, "Consecutive failures = 3");
    };

    t.run("Down -> Probing -> Up on Consecutive Successes") { sub =>
        let cfg = wing::new_health_check_config(5000, 2000, 2, 3);
        var health = wing::new_upstream_health();
        health.state = wing::HealthState.Down;
        health.consecutive_failures = 3;

        // Manual or probe entry to Probing
        let entered = wing::enter_probing_state(health);
        sub.assert_true(entered, "Successfully entered Probing state from Down");
        sub.assert_true(health.state == wing::HealthState.Probing, "State is Probing");

        // First success: not yet Up (threshold is 2)
        wing::record_probe_success(health, 1500, cfg);
        sub.assert_true(health.state == wing::HealthState.Probing, "Still Probing after 1 success");
        sub.assert_eq(health.consecutive_successes, 1, "Consecutive successes = 1");
        sub.assert_eq(health.consecutive_failures, 0, "Failures reset on success");

        // Second success: reaches threshold 2 -> transitions to Up
        wing::record_probe_success(health, 1200, cfg);
        sub.assert_true(health.state == wing::HealthState.Up, "State transitioned to Up at 2 successes");
        sub.assert_eq(health.consecutive_successes, 2, "Consecutive successes = 2");
    };

    t.run("Probing Failure Demotes to Down") { sub =>
        let cfg = wing::new_health_check_config(5000, 2000, 2, 1);
        var health = wing::new_upstream_health();
        health.state = wing::HealthState.Probing;
        health.consecutive_successes = 1;

        // Failure during probing immediately drops back to Down
        wing::record_probe_failure(health, cfg);
        sub.assert_true(health.state == wing::HealthState.Down, "Failed probe in Probing drops to Down");
        sub.assert_eq(health.consecutive_successes, 0, "Successes reset to 0");
    };
}

fn test_probe_wire_and_response_parsing(t: core::T&) {
    t.run("Format Health Probe HTTP/1.1 Request") { sub =>
        var wire: u8[>..] = [];
        wing::format_health_probe_request("api.internal:8080", "/healthz", wire);

        let s = wire[..];
        sub.assert_true(s.len > 0, "Wire buffer populated");
        sub.assert_eq(s[0..4], "GET ", "Begins with GET");
        sub.assert_true(core::contains(s, "Host: api.internal:8080"), "Contains Host header");
        sub.assert_true(core::contains(s, "User-Agent: wing-health-probe"), "Contains User-Agent");
        sub.assert_true(core::contains(s, "Connection: close"), "Contains Connection: close");
    };

    t.run("Parse HTTP Status Code from Wire Response") { sub =>
        let resp_200: u8[..64] = "HTTP/1.1 200 OK\r\nContent-Len: 0\r\n";
        let code200, ok200 = wing::parse_probe_status_code(resp_200[..]);
        sub.assert_true(ok200, "Parsed 200 response");
        sub.assert_eq(code200, 200, "Code is 200");
        sub.assert_true(wing::evaluate_probe_response(resp_200[..], 200), "Evaluate 200 matches expected");

        let resp_503: u8[..64] = "HTTP/1.1 503 Unavailable\r\n\r\n";
        let code503, ok503 = wing::parse_probe_status_code(resp_503[..]);
        sub.assert_true(ok503, "Parsed 503 response");
        sub.assert_eq(code503, 503, "Code is 503");
        sub.assert_true(!wing::evaluate_probe_response(resp_503[..], 200), "503 does not match 200");

        let resp_bad: u8[..16] = "GARBAGE DATA";
        let _, ok_bad = wing::parse_probe_status_code(resp_bad[..]);
        sub.assert_true(!ok_bad, "Garbage data rejected cleanly");
    };
}

fn test_cluster_health_checker_integration(t: core::T&) {
    t.run("Cluster Active Health Check Engine") { sub =>
        var cluster = wing::new_upstream_cluster(wing::LbPolicy.RoundRobin, 2);
        wing::add_upstream_target(cluster, "10.0.0.1", 8080);
        wing::add_upstream_target(cluster, "10.0.0.2", 8080);

        let cfg = wing::new_health_check_config(1000, 500, 2, 2);
        var checker = wing::new_cluster_health_checker(cfg);
        wing::register_target_for_probing(checker, 0);
        wing::register_target_for_probing(checker, 1);

        // Fail target 0 via load balancer failures
        wing::record_upstream_failure(cluster, 0);
        wing::record_upstream_failure(cluster, 0);
        sub.assert_true(!cluster.targets[0].is_healthy, "Target 0 is marked unhealthy");
        sub.assert_true(cluster.targets[0].health_state == wing::UpstreamHealthState.Down, "Target 0 state is Down");

        // Fail target 1 via health checker failure
        let state1 = wing::on_probe_failure(checker, cluster, 1);
        sub.assert_true(state1 == wing::HealthState.Up, "Target 1 remains Up on 1st fail");
        let state2 = wing::on_probe_failure(checker, cluster, 1);
        sub.assert_true(state2 == wing::HealthState.Down, "Target 1 Down on 2nd fail");
        sub.assert_true(cluster.circuit_open, "Cluster circuit tripped open when all targets are Down");

        // Recover target 0 via active probe successes
        wing::on_probe_success(checker, cluster, 0, 800);
        sub.assert_true(cluster.targets[0].health_state == wing::UpstreamHealthState.Probing, "Target 0 enters Probing");

        wing::on_probe_success(checker, cluster, 0, 750);
        sub.assert_true(cluster.targets[0].health_state == wing::UpstreamHealthState.Up, "Target 0 promoted to Up");
        sub.assert_true(cluster.targets[0].is_healthy, "Target 0 is healthy again");
        sub.assert_true(!cluster.circuit_open, "Cluster circuit breaker restored");

        // Verify upstream dispatch now succeeds and selects target 0
        let chosen, ok = wing::select_upstream(cluster);
        sub.assert_true(ok, "Upstream selection succeeds");
        sub.assert_eq(chosen, 0, "Target 0 selected");
    };
}

fn test_reverse_proxy_hardening(t: core::T&) {
    t.run("Connection Leak Defense and Lifecycle") { sub =>
        var proxy = wing::new_reverse_proxy(wing::LbPolicy.RoundRobin);
        wing::add_upstream_target(proxy.cluster, "upstream.local:8080", 8080);

        var in_headers = wing::new_header_map();
        wing::append_header(in_headers, "Host", "frontend.test");

        var wire: u8[>..] = [];
        let t_idx, ok = wing::prepare_proxy_request(proxy, "GET", "/api", in_headers, "127.0.0.1", "http", "", wire);
        sub.assert_true(ok, "Proxy request prepared");
        sub.assert_eq(t_idx, 0, "Dispatched to target 0");
        sub.assert_eq(proxy.cluster.targets[0].active_conns, 1, "Target 0 active_conns = 1");

        // Complete successfully -> active_conns decremented
        wing::finish_proxy_request(proxy, t_idx, true);
        sub.assert_eq(proxy.cluster.targets[0].active_conns, 0, "Active conns decremented to 0 upon finish");

        // Dispatched second time, then aborted -> active_conns decremented cleanly
        let t_idx2, ok2 = wing::prepare_proxy_request(proxy, "GET", "/api", in_headers, "127.0.0.1", "http", "", wire);
        sub.assert_true(ok2, "Second request prepared");
        sub.assert_eq(proxy.cluster.targets[0].active_conns, 1, "Active conns is 1");

        wing::abort_proxy_request(proxy, t_idx2);
        sub.assert_eq(proxy.cluster.targets[0].active_conns, 0, "Active conns decremented to 0 upon abort");
    };

    t.run("Concurrency Backpressure and Overload Defense") { sub =>
        var proxy = wing::new_reverse_proxy(wing::LbPolicy.RoundRobin);
        wing::add_upstream_target(proxy.cluster, "backend.srv:8080", 8080);
        proxy.config.max_active_conns_per_target = 2;

        var in_headers = wing::new_header_map();
        wing::append_header(in_headers, "Host", "test.example.com");

        var wire: u8[>..] = [];
        let idx1, ok1 = wing::prepare_proxy_request(proxy, "GET", "/", in_headers, "10.0.0.1", "http", "", wire);
        let idx2, ok2 = wing::prepare_proxy_request(proxy, "GET", "/", in_headers, "10.0.0.2", "http", "", wire);
        sub.assert_true(ok1 && ok2, "First 2 requests admitted up to concurrency ceiling");
        sub.assert_eq(proxy.cluster.targets[0].active_conns, 2, "Active connections reached ceiling of 2");

        // 3rd request exceeds max_active_conns_per_target (2)
        let idx3, ok3 = wing::prepare_proxy_request(proxy, "GET", "/", in_headers, "10.0.0.3", "http", "", wire);
        sub.assert_true(!ok3, "3rd request rejected due to target concurrency overload");
        sub.assert_eq(proxy.cluster.targets[0].active_conns, 2, "Active conns remains 2 (no connection leak!)");
        sub.assert_eq(proxy.total_overloaded, 1, "total_overloaded recorded");
        sub.assert_eq(proxy.total_dropped, 1, "total_dropped recorded");

        // Finishing request 1 frees slot
        wing::finish_proxy_request(proxy, idx1, true);
        sub.assert_eq(proxy.cluster.targets[0].active_conns, 1, "Active conns decreased to 1");

        // Now next request succeeds
        let idx4, ok4 = wing::prepare_proxy_request(proxy, "GET", "/", in_headers, "10.0.0.4", "http", "", wire);
        sub.assert_true(ok4, "Admitted after connection freed");
        sub.assert_eq(proxy.cluster.targets[0].active_conns, 2, "Active conns is back to 2");
    };

    t.run("Hop-by-hop and Metadata Spoofing Defense") { sub =>
        var proxy = wing::new_reverse_proxy(wing::LbPolicy.RoundRobin);
        wing::add_upstream_target(proxy.cluster, "app.internal:80", 80);

        var in_headers = wing::new_header_map();
        wing::append_header(in_headers, "Host", "legit.example.com");
        wing::append_header(in_headers, "Connection", "keep-alive, X-Secret-Internal");
        wing::append_header(in_headers, "X-Secret-Internal", "should-be-stripped");
        wing::append_header(in_headers, "X-Forwarded-Host", "evil-spoof.com");
        wing::append_header(in_headers, "X-Forwarded-Proto", "gopher");
        wing::append_header(in_headers, "X-Forwarded-Ssl", "on");

        var wire: u8[>..] = [];
        let _, ok = wing::prepare_proxy_request(proxy, "GET", "/secure", in_headers, "203.0.113.5", "https", "", wire);
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
        var proxy = wing::new_reverse_proxy(wing::LbPolicy.RoundRobin);
        wing::add_upstream_target(proxy.cluster, "backend.internal:8080", 8080);
        proxy.config.enable_rate_limiting = true;
        proxy.rate_limiter = wing::new_gateway_rate_limiter(10, 1); // 10 rps, burst 1

        var in_headers = wing::new_header_map();
        wing::append_header(in_headers, "Host", "test.example.com");

        var wire: u8[>..] = [];
        let client_ip: u8[..16] = "198.51.100.77";
        let now_ns: u64 = 1000000000;

        let _, ok1 = wing::prepare_proxy_request_at(proxy, "GET", "/", in_headers, client_ip[..], "http", "", wire, now_ns);
        let _, ok2 = wing::prepare_proxy_request_at(proxy, "GET", "/", in_headers, client_ip[..], "http", "", wire, now_ns);
        sub.assert_true(ok1 && ok2, "Burst requests admitted");

        // 3rd request at same timestamp -> Rate limited!
        let _, ok3 = wing::prepare_proxy_request_at(proxy, "GET", "/", in_headers, client_ip[..], "http", "", wire, now_ns);
        sub.assert_true(!ok3, "3rd request rejected by GCRA rate limit");
        sub.assert_eq(proxy.total_rate_limited, 1, "total_rate_limited recorded");
        sub.assert_eq(proxy.cluster.targets[0].active_conns, 2, "Upstream active conns untouched by rejected request");
    };
}

// --- Component: net_proxy_gcra ---
// Verification suite for proxy/gcra: Zero-allocation GCRA rate limiting,
// burst tolerance (tau), emission interval (T), TAT tracking,
// clock drift protection, and bounded GatewayRateLimiter.

fn test_gcra_core_algorithm(t: core::T&) {
    t.run("GCRA Quota and Single-Cell Conformance") { sub =>
        // 10 rps -> T = 100ms (100,000,000 ns), burst = 2 -> tau = 200ms (200,000,000 ns)
        let cfg = wing::new_gcra_config(10, 2);
        sub.assert_eq(cfg.emission_interval_ns, 100000000, "Emission interval T is 100ms");
        sub.assert_eq(cfg.tau_ns, 200000000, "Burst tolerance tau is 200ms");
        sub.assert_eq(cfg.max_burst, 2, "Max burst capacity is 2");

        var cell = wing::GcraTatCell { tat_ns: 0 };
        let now_ns: u64 = 1000000000; // 1.0s

        // Cell 1: Initial arrival
        let dec1 = wing::gcra_check(cfg, cell, 1, now_ns);
        sub.assert_true(dec1.allowed, "First cell is allowed");
        sub.assert_eq(dec1.remaining_burst, 2, "Burst capacity remains 2 on cold start");
        sub.assert_eq(cell.tat_ns, 1100000000, "TAT advanced to now + T");

        // Cell 2: Immediate burst arrival at same timestamp
        let dec2 = wing::gcra_check(cfg, cell, 1, now_ns);
        sub.assert_true(dec2.allowed, "Burst cell 2 is allowed");
        sub.assert_eq(dec2.remaining_burst, 1, "Remaining burst decremented to 1");
        sub.assert_eq(cell.tat_ns, 1200000000, "TAT advanced to 1.2s");

        // Cell 3: Second burst arrival at same timestamp
        let dec3 = wing::gcra_check(cfg, cell, 1, now_ns);
        sub.assert_true(dec3.allowed, "Burst cell 3 is allowed");
        sub.assert_eq(dec3.remaining_burst, 0, "Remaining burst exhausted (0)");
        sub.assert_eq(cell.tat_ns, 1300000000, "TAT advanced to 1.3s");

        // Cell 4: Over-burst arrival at same timestamp -> REJECT
        let dec4 = wing::gcra_check(cfg, cell, 1, now_ns);
        sub.assert_true(!dec4.allowed, "Cell 4 rejected due to burst exhaustion");
        sub.assert_true(dec4.retry_after_ns > 0, "Retry-after is non-zero");
        sub.assert_eq(dec4.retry_after_ns, 100000000, "Retry-after is 100ms");
        sub.assert_eq(cell.tat_ns, 1300000000, "TAT unchanged on rejection");

        // Advance clock by 100ms -> Cell 5 admitted
        let now_later = now_ns + 100000000;
        let dec5 = wing::gcra_check(cfg, cell, 1, now_later);
        sub.assert_true(dec5.allowed, "Cell 5 admitted after 100ms delay");
        sub.assert_eq(dec5.remaining_burst, 0, "Remaining burst is 0");
    };

    t.run("GCRA Peek, Penalize, and Reset Semantics") { sub =>
        let cfg = wing::new_gcra_config(5, 1); // 200ms per cell
        var cell = wing::GcraTatCell { tat_ns: 0 };
        let now_ns: u64 = 5000000000;

        // Peek should not alter TAT
        let peek_dec = wing::gcra_peek(cfg, cell, 1, now_ns);
        sub.assert_true(peek_dec.allowed, "Peek shows cell is allowed");
        sub.assert_eq(cell.tat_ns, 0, "Cell TAT remains untouched after peek");

        // Check mutates TAT
        let check_dec = wing::gcra_check(cfg, cell, 1, now_ns);
        sub.assert_true(check_dec.allowed, "Check allows request");
        sub.assert_eq(cell.tat_ns, 5200000000, "Check advances TAT by 200ms");

        // Penalize pushes TAT further into future
        wing::gcra_penalize(cfg, cell, 1000000000, now_ns); // +1s penalty
        sub.assert_eq(cell.tat_ns, 6200000000, "Penalize pushed TAT by 1.0s");

        // Subsequent check at 5.1s should fail due to penalty
        let pen_check = wing::gcra_check(cfg, cell, 1, 5100000000);
        sub.assert_true(!pen_check.allowed, "Request rejected under penalty delay");

        // Reset clears TAT
        wing::gcra_reset(cell);
        sub.assert_eq(cell.tat_ns, 0, "Reset restores cell TAT to 0");
    };

    t.run("BUG-04 Defense: NTP Backward Jump Clamping Updates cell.tat_ns") { sub =>
        let cfg = wing::new_gcra_config(10, 2); // limit_window = 300ms
        // Set TAT to distant future (50s in future due to corrupted clock)
        var cell = wing::GcraTatCell { tat_ns: 50000000000 };
        let now_ns: u64 = 1000000000; // clock jumped back to 1.0s

        // BUG-04 fix verifies cell.tat_ns is clamped down even when request is rejected
        let dec = wing::gcra_check(cfg, cell, 1, now_ns);
        sub.assert_true(!dec.allowed, "Rejected during clamped limit window");
        sub.assert_eq(cell.tat_ns, 1300000000, "TAT clamped to now + limit_window (1.3s)");

        // After limit window passes (at 1.4s), client recovers without permanent lockout
        let dec_rec = wing::gcra_check(cfg, cell, 1, 1400000000);
        sub.assert_true(dec_rec.allowed, "Client successfully recovers after clamped window");
    };
}

fn test_gateway_rate_limiter(t: core::T&) {
    t.run("Multi-Client Isolation and Limiting") { sub =>
        var limiter = wing::new_gateway_rate_limiter(10, 2);
        let client_a: u8[..16] = "192.168.1.100";
        let client_b: u8[..16] = "10.0.0.1";
        let now_ns: u64 = 1000000000;

        // Client A consumes all 3 burst tokens
        let da1 = wing::check_gateway_rate_limit(limiter, client_a[..], 1, now_ns);
        let da2 = wing::check_gateway_rate_limit(limiter, client_a[..], 1, now_ns);
        let da3 = wing::check_gateway_rate_limit(limiter, client_a[..], 1, now_ns);
        sub.assert_true(da1.allowed && da2.allowed && da3.allowed, "Client A burst allowed");

        // 4th request from Client A rejected
        let da4 = wing::check_gateway_rate_limit(limiter, client_a[..], 1, now_ns);
        sub.assert_true(!da4.allowed, "Client A over-burst rejected");

        // Client B is isolated and has full capacity
        let db1 = wing::check_gateway_rate_limit(limiter, client_b[..], 1, now_ns);
        sub.assert_true(db1.allowed, "Client B allowed independently of Client A");

        sub.assert_eq(limiter.total_allowed, 4, "Global allowed count is 4");
        sub.assert_eq(limiter.total_rejected, 1, "Global rejected count is 1");
    };

    t.run("Idle Client Eviction and Table Reset") { sub =>
        var limiter = wing::new_gateway_rate_limiter(5, 1);
        let client_old: u8[..16] = "172.16.0.5";
        let now_ns: u64 = 1000000000;

        wing::check_gateway_rate_limit(limiter, client_old[..], 1, now_ns);
        sub.assert_eq(limiter.entries.len, 1, "1 client slot registered");

        // Evict with 2s max_idle at now + 5s (idle time = 5s > 2s)
        let now_later = now_ns + 5000000000;
        let evicted = wing::evict_idle_gateway_clients(limiter, 2000000000, now_later);
        sub.assert_eq(evicted, 1, "1 idle client entry evicted");

        // Reset clears all counters
        wing::reset_gateway_rate_limiter(limiter);
        sub.assert_eq(limiter.total_allowed, 0, "Allowed reset to 0");
        sub.assert_eq(limiter.total_rejected, 0, "Rejected reset to 0");
    };
}

// --- Component: net_rate_limiter ---
// Tests for GCRA rate limiter, burst tolerance, and sharded storage.

// ----------------------------------------------------------------------------
// 1. Mathematical GCRA TAT Scheduling & Burst Tolerance
// ----------------------------------------------------------------------------
fn test_gcra_tat_and_burst(t: core::T&) {
    t.run("Single-Cell Ingress & Burst Tolerance Exhaustion") { sub =>
        // Limit: 10 req/s (T = 100 ms), Burst: 2 (tau = 200 ms)
        let quota = wing::new_gcra_quota(10, core::secs(1), 2);
        sub.assert_eq(quota.emission_interval_ns, 100000000, "T = 100ms");
        sub.assert_eq(quota.delay_tolerance_ns, 200000000, "tau = 200ms");

        var cell = wing::GcraCell { tat_ns: 0 };
        let t0: u64 = 1000000000; // t = 1.0s

        // Request 1 at t0: allowed, TAT becomes t0 + 100ms
        let d1 = wing::gcra_check_n(quota, cell, 1, t0);
        sub.assert_true(wing::is_allowed(d1), "req 1 allowed");
        sub.assert_eq(cell.tat_ns, t0 + 100000000, "TAT advanced by T");

        // Request 2 at t0: allowed, TAT becomes t0 + 200ms
        let d2 = wing::gcra_check_n(quota, cell, 1, t0);
        sub.assert_true(wing::is_allowed(d2), "req 2 allowed");
        sub.assert_eq(cell.tat_ns, t0 + 200000000, "TAT advanced to t0 + 200ms");

        // Request 3 at t0: allowed (burst limit = tau + T = 300ms)
        let d3 = wing::gcra_check_n(quota, cell, 1, t0);
        sub.assert_true(wing::is_allowed(d3), "req 3 allowed at burst threshold");
        sub.assert_eq(cell.tat_ns, t0 + 300000000, "TAT at max window limit");

        // Request 4 at t0: REJECTED! TAT would exceed limit window
        let d4 = wing::gcra_check_n(quota, cell, 1, t0);
        sub.assert_false(wing::is_allowed(d4), "req 4 rejected (burst exceeded)");
        let ok_rej = match d4 {
            Rejected r => r.retry_after_ns > 0,
            _ => false,
        };
        sub.assert_true(ok_rej, "retry_after_ns > 0 on rejection");
        sub.assert_eq(cell.tat_ns, t0 + 300000000, "TAT unchanged on rejection");

        // Advance clock by 100ms: quota for 1 cell recovers!
        let t1 = t0 + 100000000;
        let d5 = wing::gcra_check_n(quota, cell, 1, t1);
        sub.assert_true(wing::is_allowed(d5), "req 5 allowed after 100ms clock advance");
        sub.assert_eq(cell.tat_ns, t0 + 400000000, "TAT advanced to t0 + 400ms");
    };
}

// ----------------------------------------------------------------------------
// 2. Anti-Starvation Multi-Cell Priority Reservation (governor #16 Fix)
// ----------------------------------------------------------------------------
fn test_anti_starvation_reservation(t: core::T&) {
    t.run("Priority Reservation Preempts Small Subsequent Requests") { sub =>
        // Limit: 1 req/sec (T = 1s), Burst: 0 (tau = 0)
        let quota = wing::new_gcra_quota(1, core::secs(1), 0);
        var cell = wing::GcraCell { tat_ns: 0 };
        let now: u64 = 1000000000;

        // Ingress 1: cost 1 cell at now: allowed, TAT = now + 1s
        let d1 = wing::gcra_check_n(quota, cell, 1, now);
        sub.assert_true(wing::is_allowed(d1), "initial cell allowed");
        sub.assert_eq(cell.tat_ns, now + 1000000000, "TAT = now + 1s");

        // Heavy request requesting n=3 cells arrives immediately at now
        // Standard check would reject it. With gcra_reserve_n and max_wait = 5s:
        let d_res = wing::gcra_reserve_n(quota, cell, 3, now, 5000000000);
        let ok_res = match d_res {
            Reserved r => r.wait_ns == 3000000000 && r.new_tat_ns == now + 4000000000,
            _ => false,
        };
        sub.assert_true(ok_res, "heavy request successfully reserved slot ahead of time");
        sub.assert_eq(cell.tat_ns, now + 4000000000, "TAT advanced by 3 cells to 4s");

        // Subsequent lighter request (n=1) arriving at now + 500ms tries to steal:
        let d_steal = wing::gcra_check_n(quota, cell, 1, now + 500000000);
        sub.assert_false(wing::is_allowed(d_steal), "lighter request cannot steal reserved heavy slot");

        // Heavy request completes reservation wait time and executes cleanly
        let now_after_wait = now + 3000000000;
        let d_after = wing::gcra_check_n(quota, cell, 1, now_after_wait + 1000000000);
        sub.assert_true(wing::is_allowed(d_after), "pipeline resumes after reservation window");
    };
}

// ----------------------------------------------------------------------------
// 3. 256-Micro-Shard Table & Per-Key Isolation
// ----------------------------------------------------------------------------
fn test_sharded_gcra_limiter(t: core::T&) {
    t.run("Independent Client Quotas Across Shards") { sub =>
        // Limit: 2 req/s, Burst: 1 (allows 2 immediate requests at t0, 3rd rejected)
        let quota = wing::new_gcra_quota(2, core::secs(1), 1);
        var limiter = wing::new_sharded_limiter(quota);
        let now: u64 = 2000000000;

        let ip_a = "192.168.1.10";
        let ip_b = "10.0.0.5";

        // IP A exhausts its quota (2 requests)
        let d_a1 = wing::check_rate_limit(limiter, ip_a, 1, now);
        let d_a2 = wing::check_rate_limit(limiter, ip_a, 1, now);
        let d_a3 = wing::check_rate_limit(limiter, ip_a, 1, now);

        sub.assert_true(wing::is_allowed(d_a1), "IP A req 1 allowed");
        sub.assert_true(wing::is_allowed(d_a2), "IP A req 2 allowed");
        sub.assert_false(wing::is_allowed(d_a3), "IP A req 3 rejected (exhausted)");

        // IP B must NOT be affected by IP A's exhaustion!
        let d_b1 = wing::check_rate_limit(limiter, ip_b, 1, now);
        let d_b2 = wing::check_rate_limit(limiter, ip_b, 1, now);
        sub.assert_true(wing::is_allowed(d_b1), "IP B req 1 allowed independently");
        sub.assert_true(wing::is_allowed(d_b2), "IP B req 2 allowed independently");
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
// 4. Extreme DDoS Probabilistic Sampling (5%)
// ----------------------------------------------------------------------------
fn test_probabilistic_ddos_mitigation(t: core::T&) {
    t.run("5% Statistical Sampling Under Extreme Load") { sub =>
        let quota = wing::new_gcra_quota(1000, core::secs(1), 100);
        var pgcra = wing::new_probabilistic_gcra(quota, 20); // 1-in-20 = 5%

        var sampled_count = 0;
        var non_sampled_count = 0;
        let now: u64 = 1000000000;

        // Run 500 requests
        for i in 500 {
            let tat_before = pgcra.cell.tat_ns;
            let dec = wing::check_rate_limit(pgcra, 1, now);
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
// 5. IETF RateLimit-* Header Synthesis
// ----------------------------------------------------------------------------
fn test_ietf_rate_limit_headers(t: core::T&) {
    t.run("IETF Headers on Allowed Request") { sub =>
        let quota = wing::new_gcra_quota(100, core::secs(1), 10);
        let dec: wing::RateLimitDecision = wing::RateLimitDecision.Allowed {
            remaining_burst: 8,
            new_tat_ns: 1200000000,
            reset_after_ns: 200000000,
        };

        var res = wing::new_response();
        wing::apply_rate_limit_headers(res, quota, dec);

        sub.assert_true(res.has_header("RateLimit-Limit"), "RateLimit-Limit emitted");
        sub.assert_eq(res.header("RateLimit-Limit"), "100", "RateLimit-Limit = 100");
        sub.assert_true(res.has_header("RateLimit-Remaining"), "RateLimit-Remaining emitted");
        sub.assert_eq(res.header("RateLimit-Remaining"), "8", "RateLimit-Remaining = 8");
        sub.assert_true(res.has_header("RateLimit-Reset"), "RateLimit-Reset emitted");
        sub.assert_eq(res.header("RateLimit-Reset"), "1", "RateLimit-Reset ceiling ceil(0.2s) = 1s");
    };

    t.run("IETF Headers & 429 Status on Rejected Request") { sub =>
        let quota = wing::new_gcra_quota(50, core::secs(1), 0);
        let dec: wing::RateLimitDecision = wing::RateLimitDecision.Rejected {
            retry_after_ns: 2500000000, // 2.5 seconds
            current_tat_ns: 3500000000,
        };

        var res = wing::new_response();
        wing::apply_rate_limit_headers(res, quota, dec);

        sub.assert_eq(res.status_code, 429, "status set to 429 Too Many Requests");

        sub.assert_true(res.has_header("Retry-After"), "Retry-After emitted");
        sub.assert_eq(res.header("Retry-After"), "3", "Retry-After ceil(2.5s) = 3s");
        sub.assert_true(res.has_header("RateLimit-Remaining"), "RateLimit-Remaining is 0");
        sub.assert_eq(res.header("RateLimit-Remaining"), "0", "RateLimit-Remaining = 0 on rejection");
    };
}

// ----------------------------------------------------------------------------
// 6. GCRA Arithmetic, Overflow & Zero Emission Invariants
// ----------------------------------------------------------------------------
fn test_gcra_arithmetic_and_overflow(t: core::T&) {
    t.run("Zero Emission Interval Handling & Division by Zero") { sub =>
        // Limit 2,000,000 req per 1 ms (p_ns = 1,000,000, l = 2,000,000 -> p_ns / l = 0)
        let quota = wing::new_gcra_quota(2000000, core::Duration { nanos: 1000000 }, 10);
        sub.assert_true(quota.emission_interval_ns >= 1, "emission interval floored to >= 1ns to prevent division by zero");

        var cell = wing::GcraCell { tat_ns: 0 };
        let dec = wing::gcra_check_n(quota, cell, 1, 1000000);
        sub.assert_true(wing::is_allowed(dec), "admission succeeds without divide-by-zero panic");
    };

    t.run("Accurate Burst Remaining Calculation in Reservation") { sub =>
        // Limit: 1 req/s (T = 1s), Burst: 5 (tau = 5s)
        let quota = wing::new_gcra_quota(1, core::secs(1), 5);
        var cell = wing::GcraCell { tat_ns: 0 };
        let now: u64 = 1000000000;

        // Immediate reservation consuming 3 tokens
        let dec = wing::gcra_reserve_n(quota, cell, 3, now, 10000000000);
        sub.assert_true(wing::is_allowed(dec), "reservation allowed immediately");
        let remaining = match dec {
            Allowed a => a.remaining_burst,
            _ => 999,
        };
        // After consuming 3 tokens from initial burst capacity of 5, remaining burst must decrement
        sub.assert_true(remaining < 5, "remaining_burst must decrement, not report static quota.burst");
        sub.assert_eq(remaining, 3, "remaining_burst decrements to 3 after cost 3");
    };

    t.run("U64 Nanosecond Overflow In Burst Calculation") { sub =>
        let quota = wing::new_gcra_quota(1, core::secs(1), 5); // T = 1s, tau = 5s
        let now: u64 = 18446744073709551615 - 30000000000; // 30s before u64::MAX
        var cell = wing::GcraCell { tat_ns: now };

        // Consuming 3 tokens near u64 limit:
        let dec = wing::gcra_check_n(quota, cell, 3, now);
        sub.assert_true(wing::is_allowed(dec), "admission succeeds near u64 boundaries");
        let remaining = match dec {
            Allowed a => a.remaining_burst,
            _ => 999,
        };
        // After cost 3 from burst 5, remaining burst must decrement to 3
        sub.assert_eq(remaining, 3, "burst correctly decrements without u64 wrap-around");
    };

    t.run("Clock Drift & Backward NTP Jump Recovery") { sub =>
        let quota = wing::new_gcra_quota(10, core::secs(1), 2);
        var cell = wing::GcraCell { tat_ns: 60000000000 }; // TAT at 60s
        let now_backward: u64 = 10000000000; // Clock jumped back to 10s (50s backward jump)
        let dec = wing::gcra_check_n(quota, cell, 1, now_backward);
        let retry_after = match dec {
            Rejected r => r.retry_after_ns,
            Allowed _ => 0,
            _ => 999999999999,
        };
        sub.assert_true(retry_after <= 200000000, "retry_after bounded to emission interval under 50s clock jump");
    };

    t.run("Clock Drift & Backward NTP Jump Recovery in Reservation") { sub =>
        let quota = wing::new_gcra_quota(1, core::secs(1), 0);
        var cell = wing::GcraCell { tat_ns: 70000000000 }; // TAT at 70s
        let now_backward: u64 = 10000000000; // Clock jumped back to 10s
        let dec = wing::gcra_reserve_n(quota, cell, 1, now_backward, 5000000000);
        let wait_ns = match dec {
            Reserved r => r.wait_ns,
            Allowed _ => 0,
            Rejected r => r.retry_after_ns,
        };
        sub.assert_true(wait_ns <= 1000000000, "reservation wait_ns bounded under 60s clock jump");
    };
}

// ----------------------------------------------------------------------------
// Suite Runner
// ----------------------------------------------------------------------------

// --- Component: net_masque ---
// Verification suite for MASQUE protocols:
// - RFC 9297: HTTP Datagrams & Capsule Protocol
// - RFC 9298: Proxying UDP in HTTP (CONNECT-UDP)
// - RFC 9484: Proxying IP in HTTP (CONNECT-IP)
// - RFC 9221: An Unreliable Datagram Extension to QUIC

fn test_rfc9297_capsules_and_datagrams(t: core::T&) {
    t.run("Capsule Protocol Framing & Zero-Copy Decode") { sub =>
        var wire: u8[>..] = [];
        let raw_payload = "test_capsule_payload_bytes";
        let enc_ok = wing::encode_http_capsule(wire, wing::CAPSULE_DATAGRAM, raw_payload);
        sub.assert_true(enc_ok, "encode_http_capsule succeeded");

        let c, dec_ok = wing::parse_http_capsule(wire[..]);
        sub.assert_true(dec_ok, "parse_http_capsule succeeded");
        sub.assert_eq(c.capsule_type, wing::CAPSULE_DATAGRAM, "Type is CAPSULE_DATAGRAM (0x00)");
        sub.assert_bytes_eq(c.payload, raw_payload, "Payload bytes match exactly");

        // Truncated capsule wire detection
        let short_wire = wire[..wire.len - 3];
        let _, trunc_ok = wing::parse_http_capsule(short_wire);
        sub.assert_false(trunc_ok, "Truncated capsule detected and rejected");

        // Capsule-Protocol RFC 9297 Section 3.4 / RFC 8941 validation
        sub.assert_true(wing::is_capsule_protocol_negotiated("?1"), "Standard ?1");
        sub.assert_true(wing::is_capsule_protocol_negotiated(" ?1; param=value "), "Structured ?1 with params");
        sub.assert_false(wing::is_capsule_protocol_negotiated("?0"), "?0 rejected");

        var mock_hdrs = wing::new_header_map();
        wing::append_header(mock_hdrs, "capsule-protocol", "?1");
        sub.assert_true(mock_hdrs.has_capsule_protocol(), "has_capsule_protocol on HeaderMap");
    };

    t.run("HTTP Datagrams over QUIC (Quarter Stream ID + Context ID)") { sub =>
        var dgram_wire: u8[>..] = [];
        let udp_sample = "dns_query_udp_payload";
        let quarter_stream_id: u64 = 2; // Stream ID 8 / 4 = 2
        let context_id: u64 = 0;        // Default uncompressed context

        let enc_ok = wing::encode_http_datagram(dgram_wire, quarter_stream_id, context_id, udp_sample);
        sub.assert_true(enc_ok, "encode_http_datagram ok");

        let q_id, ctx_id, payload, dec_ok = wing::decode_http_datagram(dgram_wire[..]);
        sub.assert_true(dec_ok, "decode_http_datagram ok");
        sub.assert_eq(q_id, 2, "Quarter stream ID matches (2)");
        sub.assert_eq(ctx_id, 0, "Context ID matches (0)");
        sub.assert_bytes_eq(payload, udp_sample, "Payload matches");

        // QUIC DATAGRAM frame (RFC 9221 Type 0x31 with length)
        var quic_frame_wire: u8[>..] = [];
        let frame_ok = wing::encode_quic_datagram_frame(quic_frame_wire, dgram_wire[..], true);
        sub.assert_true(frame_ok, "encode_quic_datagram_frame ok");

        let parsed_dgram, end_off, frame_dec_ok = wing::decode_quic_datagram_frame(quic_frame_wire[..], 0);
        sub.assert_true(frame_dec_ok, "decode_quic_datagram_frame ok");
        sub.assert_bytes_eq(parsed_dgram, dgram_wire[..], "Datagram bytes match inside QUIC frame");
    };
}

fn test_rfc9298_connect_udp(t: core::T&) {
    t.run("URI Template Formatting and Parsing") { sub =>
        var path_buf: u8[..256] = [];
        wing::format_connect_udp_path(path_buf, "1.1.1.1", 53);
        sub.assert_bytes_eq(path_buf[..], "/.well-known/masque/udp/1.1.1.1/53/", "Format IPv4 53");

        let host, port, ok = wing::parse_connect_udp_path(path_buf[..]);
        sub.assert_true(ok, "parse_connect_udp_path ok");
        sub.assert_bytes_eq(host[..], "1.1.1.1", "Host parsed correctly");
        sub.assert_eq(port, 53, "Port parsed correctly (53)");

        // Domain name target
        var domain_path: u8[..256] = [];
        wing::format_connect_udp_path(domain_path, "dns.google", 853);
        let d_host, d_port, d_ok = wing::parse_connect_udp_path(domain_path[..]);
        sub.assert_true(d_ok, "parse domain target ok");
        sub.assert_bytes_eq(d_host[..], "dns.google", "Domain target parsed");
        sub.assert_eq(d_port, 853, "Port 853 parsed");

        // Invalid paths
        let _, _, bad1 = wing::parse_connect_udp_path("/random/path/foo");
        sub.assert_false(bad1, "Random path rejected");

        let _, _, bad2 = wing::parse_connect_udp_path("/.well-known/masque/udp/1.1.1.1/notaport/");
        sub.assert_false(bad2, "Non-numeric port rejected");
    };

    t.run("In-Stream DATAGRAM Capsule Serialization") { sub =>
        var wire: u8[>..] = [];
        let udp_data = "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01";
        let enc_ok = wing::encode_connect_udp_datagram_capsule(wire, 0, udp_data);
        sub.assert_true(enc_ok, "encode_connect_udp_datagram_capsule ok");

        let c, ok_c = wing::parse_http_capsule(wire[..]);
        sub.assert_true(ok_c, "parse outer capsule ok");
        sub.assert_eq(c.capsule_type, wing::CAPSULE_DATAGRAM, "Capsule type is 0x00");

        let ctx_id, parsed_udp, ok_udp = wing::parse_connect_udp_datagram(c.payload);
        sub.assert_true(ok_udp, "parse_connect_udp_datagram ok");
        sub.assert_eq(ctx_id, 0, "Context ID is 0");
        sub.assert_bytes_eq(parsed_udp, udp_data, "UDP payload matches");
    };
}

fn test_rfc9484_connect_ip(t: core::T&) {
    t.run("ADDRESS_REQUEST & ADDRESS_ASSIGN Capsules") { sub =>
        // 1. Client creates Address Request
        var req = wing::IpAddressRequest {
            request_id: 1,
            ip_version: 4,
            prefix_len: 32,
            ..
        };
        req.requested_ip.append([10, 0, 0, 42]);

        var req_wire: u8[>..] = [];
        let req_enc_ok = wing::encode_address_request_capsule(req_wire, req);
        sub.assert_true(req_enc_ok, "encode_address_request_capsule ok");

        let c_req, c_req_ok = wing::parse_http_capsule(req_wire[..]);
        sub.assert_true(c_req_ok, "parse request capsule ok");
        sub.assert_eq(c_req.capsule_type, wing::CAPSULE_ADDRESS_REQUEST, "Type is ADDRESS_REQUEST (0x1F)");

        let dec_req, dec_req_ok = wing::decode_address_request_capsule(c_req.payload);
        sub.assert_true(dec_req_ok, "decode_address_request_capsule ok");
        sub.assert_eq(dec_req.request_id, 1, "Request ID matches (1)");
        sub.assert_eq(dec_req.ip_version, 4, "IPv4");
        sub.assert_eq(dec_req.prefix_len, 32, "Prefix len 32");
        sub.assert_bytes_eq(dec_req.requested_ip[..], [10, 0, 0, 42], "IP matches 10.0.0.42");

        // 2. Server creates Address Assign
        var assign = wing::IpAddressAssign {
            request_id: 1,
            ip_version: 4,
            prefix_len: 24,
            ..
        };
        assign.assigned_ip.append([192, 168, 1, 100]);

        var assign_wire: u8[>..] = [];
        let assign_enc_ok = wing::encode_address_assign_capsule(assign_wire, assign);
        sub.assert_true(assign_enc_ok, "encode_address_assign_capsule ok");

        let c_assign, c_assign_ok = wing::parse_http_capsule(assign_wire[..]);
        sub.assert_true(c_assign_ok, "parse assign capsule ok");
        sub.assert_eq(c_assign.capsule_type, wing::CAPSULE_ADDRESS_ASSIGN, "Type is ADDRESS_ASSIGN (0x1E)");

        let dec_assign, dec_assign_ok = wing::decode_address_assign_capsule(c_assign.payload);
        sub.assert_true(dec_assign_ok, "decode_address_assign_capsule ok");
        sub.assert_eq(dec_assign.request_id, 1, "Request ID matches (1)");
        sub.assert_eq(dec_assign.prefix_len, 24, "Prefix len 24");
        sub.assert_bytes_eq(dec_assign.assigned_ip[..], [192, 168, 1, 100], "Assigned IP matches 192.168.1.100");
    };

    t.run("ROUTE_ADVERTISEMENT Capsule") { sub =>
        var route = wing::RouteAdvertisement {
            ip_version: 4,
            prefix_len: 8,
            ..
        };
        route.ip_prefix.append([10, 0, 0, 0]);

        var route_wire: u8[>..] = [];
        let enc_ok = wing::encode_route_advertisement_capsule(route_wire, route);
        sub.assert_true(enc_ok, "encode_route_advertisement_capsule ok");

        let c, c_ok = wing::parse_http_capsule(route_wire[..]);
        sub.assert_true(c_ok, "parse route capsule ok");
        sub.assert_eq(c.capsule_type, wing::CAPSULE_ROUTE_ADVERTISEMENT, "Type is ROUTE_ADVERTISEMENT (0x20)");

        let dec_route, dec_route_ok = wing::decode_route_advertisement_capsule(c.payload);
        sub.assert_true(dec_route_ok, "decode_route_advertisement_capsule ok");
        sub.assert_eq(dec_route.ip_version, 4, "IPv4");
        sub.assert_eq(dec_route.prefix_len, 8, "Prefix len 8");
        sub.assert_bytes_eq(dec_route.ip_prefix[..], [10, 0, 0, 0], "Prefix 10.0.0.0/8 matches");
    };
}

fn test_masque_client_sessions_and_tunneling(t: core::T&) {
    t.run("CONNECT-UDP Handshake & End-to-End Tunneling via Client") { sub =>
        var client = wing::new_client();

        // Configure mock proxy accepting CONNECT-UDP
        wing::mock_route(client, "CONNECT", "https://proxy.privacy.org/.well-known/masque/udp/1.1.1.1/53/", 200, "");
        wing::add_mock_header(client, "Capsule-Protocol", "?1");

        // 1. Client connects via CONNECT-UDP
        let tunnel, resp, err = wing::connect_udp(client, "https://proxy.privacy.org", "1.1.1.1", 53, 4, false);
        sub.assert_true(wing::ok(err), "connect_udp handshake succeeded");
        sub.assert_eq(wing::status(resp), 200, "200 OK");
        sub.assert_true(tunnel.state == wing::MasqueTunnelState.Established, "Tunnel state is Established");

        // 2. Client sends UDP packet through tunnel (in-stream capsule mode via UFCS)
        var tunnel_mut = copy(tunnel);
        var wire_out: u8[>..] = [];
        let dns_query = "fake_dns_wire_query";
        let send_ok = tunnel_mut.send_packet(dns_query, wire_out);
        sub.assert_true(send_ok, "tunnel.send_packet UFCS succeeded");
        sub.assert_eq(tunnel_mut.packets_sent, 1, "1 packet sent recorded");
        sub.assert_eq(tunnel_mut.bytes_sent, dns_query.len as u64, "Bytes sent matches");

        // 3. Client receives UDP response packet from wire via UFCS
        var packet_in: u8[>..] = [];
        let recv_ok = tunnel_mut.receive_capsule(wire_out[..], packet_in);
        sub.assert_true(recv_ok, "tunnel.receive_capsule UFCS succeeded");
        sub.assert_bytes_eq(packet_in[..], dns_query, "Received packet content matches sent query");
        sub.assert_eq(tunnel_mut.packets_received, 1, "1 packet received recorded");
    };

    t.run("CONNECT-IP Handshake & Address Assignment via Client") { sub =>
        var client = wing::new_client();

        // Configure mock VPN gateway accepting CONNECT-IP
        wing::mock_route(client, "CONNECT", "https://vpn.corp.com/.well-known/masque/ip/", 200, "");
        wing::add_mock_header(client, "Capsule-Protocol", "?1");

        // 1. Client connects via CONNECT-IP
        let tunnel, resp, err = wing::connect_ip(client, "https://vpn.corp.com", 0, false);
        sub.assert_true(wing::ok(err), "connect_ip handshake succeeded");
        sub.assert_true(tunnel.state == wing::MasqueTunnelState.Established, "Tunnel is Established");

        // 2. Simulate server sending ADDRESS_ASSIGN capsule
        var tunnel_mut = copy(tunnel);
        var assign = wing::IpAddressAssign {
            request_id: 10,
            ip_version: 4,
            prefix_len: 24,
            ..
        };
        assign.assigned_ip.append([10, 8, 0, 5]);

        var assign_capsule_wire: u8[>..] = [];
        wing::encode_address_assign_capsule(assign_capsule_wire, assign);

        var dummy_pkt: u8[>..] = [];
        let recv_ok = wing::receive_capsule(tunnel_mut, assign_capsule_wire[..], dummy_pkt);
        sub.assert_true(recv_ok, "ADDRESS_ASSIGN capsule ingested");
        sub.assert_bytes_eq(tunnel_mut.assigned_ip[..], [10, 8, 0, 5], "Tunnel assigned IP is 10.8.0.5");
        sub.assert_eq(tunnel_mut.assigned_prefix_len, 24, "Tunnel prefix length is /24");
    };

    t.run("Proxy Rejection (Missing Capsule-Protocol Header)") { sub =>
        var client = wing::new_client();

        // Mock proxy returning 200 OK without Capsule-Protocol: ?1
        wing::mock_route(client, "CONNECT", "https://bad-proxy.org/.well-known/masque/udp/8.8.8.8/53/", 200, "");

        let tunnel, resp, err = wing::connect_udp(client, "https://bad-proxy.org", "8.8.8.8", 53);
        sub.assert_false(wing::ok(err), "Failed due to missing Capsule-Protocol");
        sub.assert_eq(err.code, 502, "Error 502 Bad Gateway");
        sub.assert_true(tunnel.state == wing::MasqueTunnelState.Failed, "Tunnel state is Failed");
    };
}

// --- Component: net_masque_dns_invariants ---
// Security invariant tests for MASQUE (RFC 9297, RFC 9298, RFC 9484) and DNS (RFC 1035, RFC 9460).

fn test_masque_connect_udp_path_parsing(t: core::T&) {
    // 1. Valid RFC 9298 paths
    let h1, p1, ok1 = wing::parse_connect_udp_path("/.well-known/masque/udp/1.1.1.1/53/");
    t.assert_true(ok1, "valid template with trailing slash should pass");
    t.assert_eq(p1, 53, "port should be 53");
    t.assert_true(h1[..] == "1.1.1.1", "host should match");

    let h2, p2, ok2 = wing::parse_connect_udp_path("/.well-known/masque/udp/example.com/443");
    t.assert_true(ok2, "valid template without trailing slash should pass");
    t.assert_eq(p2, 443, "port should be 443");
    t.assert_true(h2[..] == "example.com", "host should match");

    // 2. RFC 9298 Section 3: target_port MUST be 1..65535, port 0 strictly forbidden
    let _, _, ok_zero = wing::parse_connect_udp_path("/.well-known/masque/udp/1.1.1.1/0/");
    t.assert_false(ok_zero, "port 0 must be rejected");

    let _, _, ok_big = wing::parse_connect_udp_path("/.well-known/masque/udp/1.1.1.1/65536/");
    t.assert_false(ok_big, "port > 65535 must be rejected");

    // 3. Characters forbidden in host part
    let _, _, ok_bad1 = wing::parse_connect_udp_path("/.well-known/masque/udp/bad?host/53/");
    t.assert_false(ok_bad1, "host with query delimiter must be rejected");

    let _, _, ok_bad2 = wing::parse_connect_udp_path("/.well-known/masque/udp/bad#host/53/");
    t.assert_false(ok_bad2, "host with hash fragment delimiter must be rejected");

    let _, _, ok_bad3 = wing::parse_connect_udp_path("/.well-known/masque/udp/bad host/53/");
    t.assert_false(ok_bad3, "host with space must be rejected");

    // 4. Extra path segments
    let _, _, ok_extra = wing::parse_connect_udp_path("/.well-known/masque/udp/1.1.1.1/53/extra");
    t.assert_false(ok_extra, "extra segments after port must be rejected");
}

fn test_masque_capsule_codecs(t: core::T&) {
    // 1. DATAGRAM capsule encode & decode
    var cap_out: u8[..128] = [];
    let enc_ok = wing::encode_connect_udp_datagram_capsule(cap_out, 0, "ping");
    t.assert_true(enc_ok, "datagram capsule encode should succeed");

    let cap, parse_ok = wing::parse_http_capsule(cap_out[..]);
    t.assert_true(parse_ok, "http capsule parse should succeed");
    t.assert_true(cap.capsule_type == wing::CAPSULE_DATAGRAM, "capsule type should be DATAGRAM");

    let ctx_id, pkt, pkt_ok = wing::parse_connect_udp_datagram(cap.payload);
    t.assert_true(pkt_ok, "connect udp datagram parse should succeed");
    t.assert_eq(ctx_id, 0, "context id should be 0");
    t.assert_true(pkt == "ping", "payload should match");

    // 2. CONNECT-IP ADDRESS_ASSIGN IPv4 (RFC 9484)
    var assign4 = wing::IpAddressAssign { request_id: 42, ip_version: 4, prefix_len: 32, .. };
    assign4.assigned_ip.append([10, 0, 0, 1]);
    var wire4: u8[..128] = [];
    t.assert_true(wing::encode_address_assign_capsule(wire4, assign4), "encode address assign v4");

    let cap4, cap4_ok = wing::parse_http_capsule(wire4[..]);
    t.assert_true(cap4_ok, "parse assign capsule");
    t.assert_true(cap4.capsule_type == wing::CAPSULE_ADDRESS_ASSIGN, "type matches address assign");

    let dec4, dec4_ok = wing::decode_address_assign_capsule(cap4.payload);
    t.assert_true(dec4_ok, "decode address assign v4");
    t.assert_eq(dec4.request_id, 42, "req id matches");
    t.assert_eq(dec4.ip_version, 4, "version is 4");
    t.assert_eq(dec4.prefix_len, 32, "prefix is 32");
    t.assert_true(dec4.assigned_ip.len == 4 && dec4.assigned_ip[0] == 10 && dec4.assigned_ip[3] == 1, "assigned ip matches");

    // 3. CONNECT-IP ADDRESS_ASSIGN invalid versions / bounds
    // Invalid IP version 5
    let bad_ver_wire: u8[7] = [0x01, 0x05, 0x20, 10, 0, 0, 1];
    let _, bad_ver_ok = wing::decode_address_assign_capsule(bad_ver_wire[..]);
    t.assert_false(bad_ver_ok, "invalid IP version 5 must be rejected");

    // IPv4 prefix length > 32
    let bad_pre_wire: u8[7] = [0x01, 0x04, 0x21, 10, 0, 0, 1];
    let _, bad_pre_wire_ok = wing::decode_address_assign_capsule(bad_pre_wire[..]);
    t.assert_false(bad_pre_wire_ok, "IPv4 prefix length > 32 must be rejected");

    // IPv4 with wrong byte count (3 bytes instead of 4)
    let bad_len_wire: u8[6] = [0x01, 0x04, 0x20, 10, 0, 1];
    let _, bad_len_ok = wing::decode_address_assign_capsule(bad_len_wire[..]);
    t.assert_false(bad_len_ok, "IPv4 address with rdlength != 4 must be rejected");
}

fn test_dns_pointer_security(t: core::T&) {
    // Valid backward pointer response
    // Header 12B, Question 17B (example.com A IN), Answer 16B (pointer 0xC00C -> example.com)
    let valid_wire: const u8[45] = [
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
        0x00, 0x01, 0x00, 0x01,
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04,
        0x5d, 0xb8, 0xd8, 0x22,
    ];
    var resp1 = wing::DnsResponse { .. };
    let ok1 = wing::parse_dns_response(valid_wire[..], resp1);
    t.assert_true(ok1, "valid backward pointer must succeed");
    t.assert_eq(resp1.a_records.len, 1, "parsed 1 A record");
    t.assert_true(resp1.a_records[0] == 0x5db8d822, "IP address matches");

    // Forward pointer rejected (RFC 1035 §4.1.4: ptr_off >= current_off)
    var fwd_wire = valid_wire;
    fwd_wire[29] = 0xc0;
    fwd_wire[30] = 0x23; // points to offset 35 > 29
    var resp2 = wing::DnsResponse { .. };
    let ok2 = wing::parse_dns_response(fwd_wire[..], resp2);
    t.assert_false(ok2, "forward pointer must be rejected");

    // Pointer into header rejected (ptr_off < 12)
    var hdr_wire = valid_wire;
    hdr_wire[29] = 0xc0;
    hdr_wire[30] = 0x04; // points to offset 4 < 12
    var resp3 = wing::DnsResponse { .. };
    let ok3 = wing::parse_dns_response(hdr_wire[..], resp3);
    t.assert_false(ok3, "pointer into header must be rejected");
}

fn test_dns_record_bounds_and_https_target(t: core::T&) {
    // Malformed A record: rdlength != 4
    let bad_a_wire: const u8[44] = [
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
        0x00, 0x01, 0x00, 0x01,
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x03,
        0x5d, 0xb8, 0xd8,
    ];
    var resp_a = wing::DnsResponse { .. };
    let ok_a = wing::parse_dns_response(bad_a_wire[..], resp_a);
    t.assert_false(ok_a, "A record with rdlength != 4 must be rejected");

    // RFC 9460 §2.5.1: HTTPS TargetName containing compression pointer (0xC00C) must be rejected
    let bad_https_wire: const u8[45] = [
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
        0x00, 0x41, 0x00, 0x01,
        0xc0, 0x0c, 0x00, 0x41, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04,
        0x00, 0x01, 0xc0, 0x0c,
    ];
    var resp_h = wing::DnsResponse { .. };
    let ok_h = wing::parse_dns_response(bad_https_wire[..], resp_h);
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

fn test_altsvc_learning_and_h3_promotion(t: core::T&) {
    t.run("Cold Request Learns Alt-Svc and Next Request Upgrades to HTTP/3") { sub =>
        var client = wing::new_client();
        wing::set_clock_us(client, 1700000000000000); // t = 1700000000s

        // 1. Setup mock route returning Alt-Svc header
        wing::mock_route(client, "GET", "https://api.example.com/v1/user", 200, "{\"id\":1}");
        wing::add_mock_header(client, "Alt-Svc", "h3=\":443\"; ma=86400; persist=1");

        // Before request: cache has no entry
        sub.assert_false(wing::has_altsvc_h3(client, "api.example.com:443"), "no prior Alt-Svc for api.example.com");

        // 2. Cold request: executed over standard TCP (HTTP/1.1)
        let resp1, err1 = wing::get(client, "https://api.example.com/v1/user");
        sub.assert_true(wing::ok(err1), "cold request succeeds");
        sub.assert_eq(wing::status(resp1), 200, "200 OK");
        sub.assert_eq(wing::protocol(resp1), "HTTP/1.1", "cold request served via HTTP/1.1");
        sub.assert_false(wing::is_http3(resp1), "not HTTP/3 yet");

        // 3. Verify Alt-Svc was ingested into client cache
        sub.assert_true(wing::has_altsvc_h3(client, "api.example.com:443"), "Alt-Svc cached for api.example.com:443");
        sub.assert_true(wing::has_altsvc_h3(client, "https://api.example.com/v1/user"), "URL origin lookup works");

        // 4. Second request: Alt-Svc candidate found -> upgraded to HTTP/3!
        let resp2, err2 = wing::get(client, "https://api.example.com/v1/user");
        sub.assert_true(wing::ok(err2), "second request succeeds");
        sub.assert_eq(wing::protocol(resp2), "h3", "second request upgraded to h3 via Alt-Svc!");
        sub.assert_true(wing::is_http3(resp2), "is_http3 helper returns true");
    };
}

fn test_chromium_protocol_racing_and_udp_fallback(t: core::T&) {
    t.run("UDP Firewall Block: TCP Wins Race, Zero Error, Backoff Recorded") { sub =>
        var client = wing::new_client();
        wing::set_clock_us(client, 1700000000000000); // t0 = 1700000000s (sec)

        // Seed Alt-Svc cache
        wing::mock_route(client, "GET", "https://fast.edge.net/data", 200, "{\"ready\":true}");
        wing::add_mock_header(client, "Alt-Svc", "h3=\":443\"; ma=3600");

        let resp_seed, err_seed = wing::get(client, "https://fast.edge.net/data");
        sub.assert_true(wing::ok(err_seed), "seed request ok");
        sub.assert_true(wing::has_altsvc_h3(client, "fast.edge.net:443"), "Alt-Svc cached");

        // Now simulate corporate firewall blocking UDP/QUIC (e.g. timeout or packet drop)
        wing::set_mock_quic_blocked(client, true);

        // Request during UDP blockage: Protocol Race starts
        // Alternative Job (H3) times out / blocked -> Main Job (TCP) wins the race!
        let resp_blocked, err_blocked = wing::get(client, "https://fast.edge.net/data");
        sub.assert_true(wing::ok(err_blocked), "request succeeds without user error");
        sub.assert_eq(wing::status(resp_blocked), 200, "200 OK via TCP fallback");
        sub.assert_eq(wing::protocol(resp_blocked), "HTTP/1.1", "served via TCP Main Job");

        // Check Chromium failure penalization: origin is now marked broken!
        sub.assert_true(wing::is_altsvc_broken(client, "fast.edge.net:443"), "origin fast.edge.net marked broken");
        sub.assert_false(wing::has_altsvc_h3(client, "fast.edge.net:443"), "has_altsvc_h3 suppressed during backoff");

        // Request 1 second later (within 5s initial backoff window):
        wing::set_clock_us(client, 1700000001000000); // t0 + 1s
        let resp_cached_tcp, err_cached_tcp = wing::get(client, "https://fast.edge.net/data");
        sub.assert_true(wing::ok(err_cached_tcp), "fast-path TCP succeeds");
        sub.assert_eq(wing::protocol(resp_cached_tcp), "HTTP/1.1", "bypassed QUIC race without delay");

        // Advance virtual clock past 5s backoff window (t0 + 6s)
        wing::set_clock_us(client, 1700000006000000); // t0 + 6s
        sub.assert_false(wing::is_altsvc_broken(client, "fast.edge.net:443"), "backoff expired after 5s");
        sub.assert_true(wing::has_altsvc_h3(client, "fast.edge.net:443"), "H3 candidate available again");

        // Now firewall allows UDP again:
        wing::set_mock_quic_blocked(client, false);
        let resp_recovered, err_recovered = wing::get(client, "https://fast.edge.net/data");
        sub.assert_true(wing::ok(err_recovered), "recovered request ok");
        sub.assert_eq(wing::protocol(resp_recovered), "h3", "H3 race won after recovery!");
        sub.assert_false(wing::is_altsvc_broken(client, "fast.edge.net:443"), "broken status cleared on success");
    };

    t.run("Exponential Failure Backoff Progression (5s -> 10s)") { sub =>
        var client = wing::new_client();
        wing::set_clock_us(client, 1700000000000000); // t0

        wing::mock_route(client, "GET", "https://flaky.cdn.com/res", 200, "flaky");
        wing::add_mock_header(client, "Alt-Svc", "h3=\":443\"; ma=86400");
        let _, _ = wing::get(client, "https://flaky.cdn.com/res");

        // Failure 1: backoff is 5s
        wing::set_mock_quic_blocked(client, true);
        let _, _ = wing::get(client, "https://flaky.cdn.com/res");
        sub.assert_true(wing::is_altsvc_broken(client, "flaky.cdn.com:443"), "broken attempt 1");

        // At t0 + 6s: backoff 1 has expired
        wing::set_clock_us(client, 1700000006000000);
        sub.assert_false(wing::is_altsvc_broken(client, "flaky.cdn.com:443"), "expired at t0+6s");

        // Failure 2: backoff doubles to 10s (broken until t0 + 6s + 10s = t0 + 16s)
        let _, _ = wing::get(client, "https://flaky.cdn.com/res");
        sub.assert_true(wing::is_altsvc_broken(client, "flaky.cdn.com:443"), "broken attempt 2");

        // At t0 + 12s: still broken (12 < 16)
        wing::set_clock_us(client, 1700000012000000);
        sub.assert_true(wing::is_altsvc_broken(client, "flaky.cdn.com:443"), "still broken at t0+12s");

        // At t0 + 17s: backoff 2 expired (17 >= 16)
        wing::set_clock_us(client, 1700000017000000);
        sub.assert_false(wing::is_altsvc_broken(client, "flaky.cdn.com:443"), "expired at t0+17s");
    };
}

fn test_altsvc_clear_and_ttl_expiration(t: core::T&) {
    t.run("Alt-Svc: clear Purges Origin from Cache Immediately") { sub =>
        var client = wing::new_client();
        wing::set_clock_us(client, 1700000000000000);

        wing::mock_route(client, "GET", "https://service.org/item", 200, "item");
        wing::add_mock_header(client, "Alt-Svc", "h3=\":443\"; ma=86400");
        let _, _ = wing::get(client, "https://service.org/item");
        sub.assert_true(wing::has_altsvc_h3(client, "service.org:443"), "cached");

        // Server sends `Alt-Svc: clear` (RFC 7838 Section 3.1)
        wing::mock_route(client, "POST", "https://service.org/logout", 200, "bye");
        wing::add_mock_header(client, "Alt-Svc", "clear");
        let _, _ = wing::post(client, "https://service.org/logout") { _ => };

        sub.assert_false(wing::has_altsvc_h3(client, "service.org:443"), "origin purged after clear");

        // Subsequent request uses standard TCP
        let resp3, _ = wing::get(client, "https://service.org/item");
        sub.assert_eq(wing::protocol(resp3), "HTTP/1.1", "served via HTTP/1.1 after clear");
    };

    t.run("Max-Age (ma) Expiration") { sub =>
        var client = wing::new_client();
        wing::set_clock_us(client, 1700000000000000); // t0

        wing::mock_route(client, "GET", "https://short-lived.com/status", 200, "ok");
        wing::add_mock_header(client, "Alt-Svc", "h3=\":443\"; ma=3"); // TTL = 3 seconds
        let _, _ = wing::get(client, "https://short-lived.com/status");
        sub.assert_true(wing::has_altsvc_h3(client, "short-lived.com:443"), "cached at t0");

        // Advance 2 seconds (still valid)
        wing::set_clock_us(client, 1700000002000000); // t0 + 2s
        sub.assert_true(wing::has_altsvc_h3(client, "short-lived.com:443"), "valid at t0+2s (< 3s)");

        // Advance 4 seconds (expired)
        wing::set_clock_us(client, 1700000004000000); // t0 + 4s
        sub.assert_false(wing::has_altsvc_h3(client, "short-lived.com:443"), "expired at t0+4s (>= 3s)");
    };
}

fn test_rfc7838_security_and_options(t: core::T&) {
    t.run("RFC 7838 Section 2.1: Alt-Svc MUST be Ignored on Insecure HTTP") { sub =>
        var client = wing::new_client();
        wing::set_clock_us(client, 1700000000000000);

        // Plain HTTP server attempts to send Alt-Svc
        wing::mock_route(client, "GET", "http://insecure.site/api", 200, "insecure");
        wing::add_mock_header(client, "Alt-Svc", "h3=\":443\"; ma=86400");

        let resp, err = wing::get(client, "http://insecure.site/api");
        sub.assert_true(wing::ok(err), "http request ok");

        // MUST NOT be cached because transport was unencrypted HTTP!
        sub.assert_false(wing::has_altsvc_h3(client, "insecure.site:80"), "Alt-Svc ignored over insecure HTTP");
    };

    t.run("Manual Disabling of Alt-Svc or Protocol Racing") { sub =>
        var client = wing::new_client();
        wing::enable_altsvc(client, false); // Alt-Svc disabled

        wing::mock_route(client, "GET", "https://disabled.com/data", 200, "data");
        wing::add_mock_header(client, "Alt-Svc", "h3=\":443\"; ma=86400");

        let resp1, _ = wing::get(client, "https://disabled.com/data");
        sub.assert_false(wing::has_altsvc_h3(client, "disabled.com:443"), "not cached when disabled");

        let resp2, _ = wing::get(client, "https://disabled.com/data");
        sub.assert_eq(wing::protocol(resp2), "HTTP/1.1", "remains HTTP/1.1");
    };
}

fn main() {
    var runner = core::new_runner("Reverse Proxy, GCRA Rate Limiter, MASQUE, and Alt-Svc Suite", core::Verbosity.Verbose);

    core::run_case(runner, "1. SOCKS5 Greeting & RFC 1929", test_socks5_greeting_and_rfc1929);
    core::run_case(runner, "2. SOCKS5 Command & Reply", test_socks5_command_and_reply_parsing);
    core::run_case(runner, "3. HTTP CONNECT Tunnel & Buffer Hygiene", test_http_connect_tunnel_and_buffer_hygiene);
    core::run_case(runner, "4. Slowloris Tarpit Defenses", test_slowloris_tarpit_defenses);
    core::run_case(runner, "5. PROXY Protocol v1 (Text) Conformance", test_proxy_v1_conformance);
    core::run_case(runner, "6. PROXY Protocol v2 (Binary) Conformance", test_proxy_v2_conformance);
    core::run_case(runner, "7. PROXY Protocol v2 TLV Metadata", test_proxy_v2_tlvs);
    core::run_case(runner, "8. Stream Stripping & Server Integration", test_proxy_server_integration);
    core::run_case(runner, "9. Health State Machine Transitions", test_health_state_transitions);
    core::run_case(runner, "10. Probe Wire Formatting and Response Evaluation", test_probe_wire_and_response_parsing);
    core::run_case(runner, "11. Cluster Health Checker Engine", test_cluster_health_checker_integration);
    core::run_case(runner, "12. Reverse Proxy Hardening & Backpressure", test_reverse_proxy_hardening);
    core::run_case(runner, "13. GCRA Core Algorithm & Conformance", test_gcra_core_algorithm);
    core::run_case(runner, "14. Gateway Multi-Client Rate Limiter", test_gateway_rate_limiter);
    core::run_case(runner, "15. Mathematical GCRA TAT Scheduling & Burst Tolerance", test_gcra_tat_and_burst);
    core::run_case(runner, "16. Anti-Starvation Multi-Cell Priority Reservation", test_anti_starvation_reservation);
    core::run_case(runner, "17. 256-Micro-Shard Table & Per-Key Isolation", test_sharded_gcra_limiter);
    core::run_case(runner, "18. Extreme DDoS Probabilistic Sampling (5%)", test_probabilistic_ddos_mitigation);
    core::run_case(runner, "19. IETF RateLimit-* Header Synthesis", test_ietf_rate_limit_headers);
    core::run_case(runner, "20. GCRA Arithmetic, Overflow & Zero Emission Invariants", test_gcra_arithmetic_and_overflow);
    core::run_case(runner, "21. RFC 9297 Capsules & HTTP Datagrams", test_rfc9297_capsules_and_datagrams);
    core::run_case(runner, "22. RFC 9298 MASQUE CONNECT-UDP", test_rfc9298_connect_udp);
    core::run_case(runner, "23. RFC 9484 MASQUE CONNECT-IP", test_rfc9484_connect_ip);
    core::run_case(runner, "24. MASQUE Client Sessions & Tunneling", test_masque_client_sessions_and_tunneling);
    core::run_case(runner, "25. MASQUE CONNECT-UDP Path Parsing", test_masque_connect_udp_path_parsing);
    core::run_case(runner, "26. MASQUE Capsule Codecs", test_masque_capsule_codecs);
    core::run_case(runner, "27. DNS Pointer Security", test_dns_pointer_security);
    core::run_case(runner, "28. DNS Record Bounds & HTTPS Target", test_dns_record_bounds_and_https_target);
    core::run_case(runner, "29. Alt-Svc Learning & HTTP/3 Promotion", test_altsvc_learning_and_h3_promotion);
    core::run_case(runner, "30. Protocol Racing & UDP Firewall Fallback", test_chromium_protocol_racing_and_udp_fallback);
    core::run_case(runner, "31. Alt-Svc Clear Directive & TTL Expiration", test_altsvc_clear_and_ttl_expiration);
    core::run_case(runner, "32. RFC 7838 Insecure Transport Security & Toggles", test_rfc7838_security_and_options);

    let ok = core::finish(runner);
    assert(ok);
}
