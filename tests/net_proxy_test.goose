// Verification suite for net/proxy: SOCKS5/SOCKS5h (RFC 1928 & RFC 1929),
// HTTP CONNECT tunneling, credential isolation, and 4-tier Slowloris defenses.
// CVE-2026-94439, CVE-2026-56866, CVE-2025-4673, and CVE-2021-33197 defenses.
import std;
import core from "..";
import wing from "..";

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
            0x01, 0xBB
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

fn main() {
    var runner = core::new_runner("net/proxy SOCKS5 & Slowloris Defense Suite", core::Verbosity.Verbose);
    core::run_case(runner, "1. SOCKS5 Greeting & RFC 1929", test_socks5_greeting_and_rfc1929);
    core::run_case(runner, "2. SOCKS5 Command & Reply", test_socks5_command_and_reply_parsing);
    core::run_case(runner, "3. HTTP CONNECT Tunnel & Buffer Hygiene", test_http_connect_tunnel_and_buffer_hygiene);
    core::run_case(runner, "4. Slowloris Tarpit Defenses", test_slowloris_tarpit_defenses);
    let ok = core::finish(runner);
    assert(ok);
}
