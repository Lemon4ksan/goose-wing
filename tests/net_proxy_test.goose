// Verification suite for net/proxy: SOCKS5/SOCKS5h (RFC 1928 & RFC 1929),
// HTTP CONNECT tunneling, credential isolation, and 4-tier Slowloris defenses.
import std;
import wing from "..";

fn test_socks5_greeting_and_rfc1929(t: wing::T&) {
    t.run("SOCKS5 Phase 1 Greeting and Negotiation") { sub =>
        var greeting_buf: u8[..16] = [];
        wing::build_socks5_greeting(true, true, greeting_buf);

        sub.assert_eq(greeting_buf[0], 0x05, "Greeting version is 0x05");
        sub.assert_eq(greeting_buf[1], 3, "3 auth methods announced (None, UserPass, GSSAPI)");
        sub.assert_eq(greeting_buf[2], 0x00, "Method 0 is None");
        sub.assert_eq(greeting_buf[3], 0x02, "Method 1 is UserPass");
        sub.assert_eq(greeting_buf[4], 0x01, "Method 2 is GSSAPI");

        // Parse valid server selection [0x05, 0x02]
        let server_reply: u8[2] = [0x05, 0x02];
        let method, err = wing::parse_socks5_greeting_reply(server_reply[..]);
        sub.assert_true(err == wing::Socks5Error.None, "Greeting parsed cleanly");
        sub.assert_eq(method, 0x02, "UserPass method selected by server");

        // Server rejects with 0xFF
        let reject_reply: u8[2] = [0x05, 0xFF];
        let m_rej, err_rej = wing::parse_socks5_greeting_reply(reject_reply[..]);
        sub.assert_true(err_rej == wing::Socks5Error.NoAcceptableAuth, "0xFF rejected as NoAcceptableAuth");

        // Server bad version
        let bad_ver: u8[2] = [0x04, 0x00];
        let m_bad, err_bad = wing::parse_socks5_greeting_reply(bad_ver[..]);
        sub.assert_true(err_bad == wing::Socks5Error.InvalidVersion, "Non-0x05 version rejected");
    };

    t.run("RFC 1929 Subnegotiation Version 0x01 Invariant") { sub =>
        var auth_buf: u8[..520] = [];
        let auth_err = wing::build_socks5_rfc1929_auth("testuser", "secretpass123", auth_buf);
        sub.assert_true(auth_err == wing::Socks5Error.None, "RFC 1929 auth frame built");

        // Critical standard invariant: RFC 1929 version MUST be 0x01, NOT 0x05!
        sub.assert_eq(auth_buf[0], 0x01, "First byte is strictly RFC 1929 version 0x01");
        sub.assert_eq(auth_buf[1], 8, "Username length is 8");
        sub.assert_bytes_eq(auth_buf[2..10], "testuser", "Username matches");
        sub.assert_eq(auth_buf[10], 13, "Password length is 13");
        sub.assert_bytes_eq(auth_buf[11..24], "secretpass123", "Password matches");

        // Parse valid RFC 1929 reply [0x01, 0x00]
        let reply_ok: u8[2] = [0x01, 0x00];
        let rep_err = wing::parse_socks5_rfc1929_reply(reply_ok[..]);
        sub.assert_true(rep_err == wing::Socks5Error.None, "Status 0x00 authenticated successfully");

        // Parse rejected RFC 1929 reply [0x01, 0x01]
        let reply_fail: u8[2] = [0x01, 0x01];
        let fail_err = wing::parse_socks5_rfc1929_reply(reply_fail[..]);
        sub.assert_true(fail_err == wing::Socks5Error.AuthFailed, "Non-0x00 status rejected as AuthFailed");
    };
}

fn test_socks5_command_and_reply_parsing(t: wing::T&) {
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
    };

    t.run("Parse SOCKS5 Reply Frames & Error Codes") { sub =>
        // Success reply: VER=0x05, REP=0x00, RSV=0x00, ATYP=0x01, BND.ADDR=127.0.0.1, BND.PORT=1080 (0x0438)
        let reply_ok: u8[10] = [0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x04, 0x38];
        let rep, err = wing::parse_socks5_connect_reply(reply_ok[..]);
        sub.assert_true(err == wing::Socks5Error.None, "Success reply parsed cleanly");
        sub.assert_eq(rep.bound_port, 1080, "Bound port 1080 parsed");
        sub.assert_eq(rep.bytes_consumed, 10, "Consumed exact 10 bytes");

        // Connection refused reply (REP = 0x05)
        let reply_refused: u8[10] = [0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        let rep_ref, err_ref = wing::parse_socks5_connect_reply(reply_refused[..]);
        sub.assert_true(err_ref == wing::Socks5Error.ConnectionRefused, "REP=0x05 mapped to ConnectionRefused");

        // Domain bound reply: 4 + 1 + 10 ("proxy.node") + 2 = 17 bytes
        var rep_domain: u8[17] = [0x05, 0x00, 0x00, 0x03, 10, 'p', 'r', 'o', 'x', 'y', '.', 'n', 'o', 'd', 'e', 0x1F, 0x90];
        let rep_d, err_d = wing::parse_socks5_connect_reply(rep_domain[..]);
        sub.assert_true(err_d == wing::Socks5Error.None, "Domain reply parsed cleanly");
        sub.assert_eq(rep_d.bound_port, 8080, "Bound port 8080 parsed");
        sub.assert_eq(rep_d.bytes_consumed, 17, "Consumed exact 17 bytes");
    };
}

fn test_http_connect_tunnel_and_buffer_hygiene(t: wing::T&) {
    t.run("CONNECT Header Construction & Credential Isolation") { sub =>
        var req_buf: u8[..1024] = [];
        wing::build_http_connect_request("secure.bank.com", 443, "Basic dXNlcjpwYXNz", "goose-wing/1.0", req_buf);

        sub.assert_true(starts_with(req_buf[..], "CONNECT secure.bank.com:443 HTTP/1.1\r\n"), "CONNECT request line correct");
        sub.assert_contains(req_buf[..], "Proxy-Authorization: Basic dXNlcjpwYXNz\r\n", "Proxy auth header included");

        // Isolation barrier: sanitize_tunnel_headers_for_origin
        var origin_headers: wing::HeaderItem[..32] = [];
        origin_headers.push(wing::make_header("Host", "secure.bank.com"));
        origin_headers.push(wing::make_header("Proxy-Authorization", "Basic dXNlcjpwYXNz"));
        origin_headers.push(wing::make_header("Proxy-Connection", "Keep-Alive"));
        origin_headers.push(wing::make_header("Authorization", "Bearer user_token_99"));

        wing::sanitize_tunnel_headers_for_origin(origin_headers);

        sub.assert_eq(origin_headers.len, 2, "Proxy headers stripped from origin request");
        sub.assert_bytes_eq(origin_headers[0].name[..], "Host", "Host header preserved");
        sub.assert_bytes_eq(origin_headers[1].name[..], "Authorization", "Target origin bearer auth preserved");
    };

    t.run("OkHttp Leftover Buffer Defense: TLS Tunnel Buffered Too Many Bytes") { sub =>
        // 1. Clean CONNECT response with no trailing bytes
        let clean_resp = "HTTP/1.1 200 Connection Established\r\nProxy-Agent: corporate-proxy\r\n\r\n";
        let err_clean = wing::verify_connect_tunnel_response(clean_resp, 0);
        sub.assert_true(err_clean == wing::ConnectTunnelError.None, "Clean 200 OK CONNECT approved");

        // 2. Data injection attack: Extra bytes after \r\n\r\n before TLS handshake
        let injected_resp = "HTTP/1.1 200 Connection Established\r\n\r\nINJECTED_TLS_PREFIX_DATA";
        let err_injected = wing::verify_connect_tunnel_response(injected_resp, 0);
        sub.assert_true(err_injected == wing::ConnectTunnelError.TunnelBufferedTooManyBytes, "Detected leftover buffer data injection");

        // 3. Sink has leftover unwritten bytes
        let err_sink = wing::verify_connect_tunnel_response(clean_resp, 16);
        sub.assert_true(err_sink == wing::ConnectTunnelError.TunnelBufferedTooManyBytes, "Detected non-empty sink buffer");

        // 4. Proxy Authentication Required (407)
        let auth_req_resp = "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\n\r\n";
        let err_407 = wing::verify_connect_tunnel_response(auth_req_resp, 0);
        sub.assert_true(err_407 == wing::ConnectTunnelError.ProxyAuthRequired, "407 status parsed correctly");
    };
}

fn test_slowloris_tarpit_defenses(t: wing::T&) {
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

        // Barrier 4: Byte-Drip gate (< 256 B/s)
        var reader_drip = wing::new_header_reader(cfg, 0);
        let drip_byte = "X";
        // 1 byte received over 2.0 seconds -> 0.5 B/s (< 256 B/s)
        let v_drip = wing::feed_header_bytes(reader_drip, drip_byte, 2000000000);
        sub.assert_true(v_drip == wing::SlowlorisViolation.MinIngressRateViolated, "Byte-drip tarpit caught by minimum ingress rate gate");
    };
}

fn main() {
    var runner = wing::new_runner("net/proxy SOCKS5 & Slowloris Defense Suite", wing::Verbosity.Verbose);
    wing::run_case(runner, "1. SOCKS5 Greeting & RFC 1929", test_socks5_greeting_and_rfc1929);
    wing::run_case(runner, "2. SOCKS5 Command & Reply", test_socks5_command_and_reply_parsing);
    wing::run_case(runner, "3. HTTP CONNECT Tunnel & Buffer Hygiene", test_http_connect_tunnel_and_buffer_hygiene);
    wing::run_case(runner, "4. Slowloris Tarpit Defenses", test_slowloris_tarpit_defenses);
    let ok = wing::finish(runner);
    assert(ok);
}
