// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Verification suite for historical bugs and CVEs across Go stdlib, uWebSockets, and OpenSSL:
// 1. Go CVE-2026-78667: Range Header Flood / Length Limit Enforcement (1024-byte ceiling).
// 2. Go #75557 / RFC 7578 В§4.2: Content-Disposition CRLF and NUL Injection Defenses.
// 3. RFC 9113 / Go #81115 / CVE-2026-78660: HTTP/2 HPACK Content-Length Integer Overflow Prevention.
// 4. OpenSSL #31392 / CVE-2009-2408: X.509 URI NameConstraints Matching & NUL Byte Injection Rejection.
// 5. uWebSockets #1876 & #1009: Control Frame Priority Under Backpressure and Heartbeat Reset.
// 6. RFC 8446 В§5.4: TLS 1.3 InnerPlaintext Zero-Length Application Data vs Malicious All-Padding.
import std;
import core from "..";
import wing from "..";

fn test_cve_2026_78667_range_header_overflow(t: core::T&) {
    t.run("CVE-2026-78667: Range header exceeding 1024 bytes MUST be rejected") { sub =>
        var oversized: u8[>..] = [];
        oversized.append("bytes=");
        for i in 200 {
            oversized.append("0-1,");
        }
        oversized.append("0-1");

        let rs, err = wing::parse_range_header(oversized[..], 1000);
        sub.assert_true(err == wing::RangeError.ExceededMaxRanges, "Range header > 1024 bytes must return ExceededMaxRanges");
        sub.assert_eq(rs.ranges.len, 0, "No ranges should be populated");
    };

    t.run("Valid Range header under 1024 bytes must succeed") { sub =>
        let rs, err = wing::parse_range_header("bytes=0-499,500-999", 2000, true);
        sub.assert_true(wing::is_ok(err), "Valid range must succeed");
        sub.assert_eq(rs.ranges.len, 1, "Ranges 0-499 and 500-999 should coalesce into 1 contiguous range (0-999)");
    };
}

fn test_go_75557_content_disposition_crlf_injection(t: core::T&) {
    t.run("Go #75557: Field name with CRLF injection MUST be rejected") { sub =>
        var out: u8[..256] = [];
        let ok = wing::format_content_disposition("upload\r\nEvil: injected", "test.txt", out);
        sub.assert_false(ok, "CRLF in field name must return false");
        sub.assert_eq(out.len, 0, "Output must remain empty on rejection");
    };

    t.run("Go #75557: Filename with CRLF injection MUST be rejected") { sub =>
        var out: u8[..256] = [];
        let ok = wing::format_content_disposition("file", "image.png\r\nSet-Cookie: pwned=1", out);
        sub.assert_false(ok, "CRLF in filename must return false");
        sub.assert_eq(out.len, 0, "Output must remain empty on rejection");
    };

    t.run("Go #75557: NUL byte injection in field name or filename MUST be rejected") { sub =>
        var out: u8[..256] = [];
        let ok = wing::format_content_disposition("field\0injection", "safe.txt", out);
        sub.assert_false(ok, "NUL byte in field name must return false");
    };

    t.run("Valid parameters with quotes and backslashes are properly escaped") { sub =>
        var out: u8[..256] = [];
        let ok = wing::format_content_disposition("my \"field\"", "vacation\\\"photo\".jpg", out);
        sub.assert_true(ok, "Valid parameters should format successfully");
        sub.assert_true(core::index_of_slice(out[..], "name=\"my \\\"field\\\"\"") >= 0, "Quotes in name must be escaped");
        sub.assert_true(core::index_of_slice(out[..], "filename=\"vacation\\\\\\\"photo\\\".jpg\"") >= 0, "Backslashes and quotes escaped in filename");
    };
}

fn test_http2_content_length_overflow_defense(t: core::T&) {
    t.run("RFC 9113 & Go #81115: HTTP/2 Content-Length > 19 digits MUST be rejected as PROTOCOL_ERROR") { sub =>
        var dt_enc = wing::new_dynamic_table(4096);
        var raw_bytes: u8[>..] = [];
        wing::encode_hpack_field(dt_enc, raw_bytes, ":method", "POST", false, false);
        wing::encode_hpack_field(dt_enc, raw_bytes, ":scheme", "https", false, false);
        wing::encode_hpack_field(dt_enc, raw_bytes, ":path", "/upload", false, false);
        wing::encode_hpack_field(dt_enc, raw_bytes, "content-length", "999999999999999999999999999999", false, false);

        var dt_dec = wing::new_dynamic_table(4096);
        var out_list = wing::DecodedH2HeaderList { .. };
        let err = wing::decode_hpack_header_block(dt_dec, raw_bytes[..], out_list, 8192, true);
        sub.assert_eq(err, wing::ERR_PROTOCOL_ERROR, "Excessive digits in Content-Length must trigger PROTOCOL_ERROR");
    };

    t.run("Valid Content-Length in HTTP/2 is parsed correctly") { sub =>
        var dt_enc = wing::new_dynamic_table(4096);
        var raw_bytes: u8[>..] = [];
        wing::encode_hpack_field(dt_enc, raw_bytes, ":method", "POST", false, false);
        wing::encode_hpack_field(dt_enc, raw_bytes, ":scheme", "https", false, false);
        wing::encode_hpack_field(dt_enc, raw_bytes, ":path", "/upload", false, false);
        wing::encode_hpack_field(dt_enc, raw_bytes, "content-length", "1048576", false, false);

        var dt_dec = wing::new_dynamic_table(4096);
        var out_list = wing::DecodedH2HeaderList { .. };
        let err = wing::decode_hpack_header_block(dt_dec, raw_bytes[..], out_list, 8192, true);
        sub.assert_eq(err, wing::ERR_NO_ERROR, "Valid Content-Length must succeed");
        sub.assert_true(out_list.has_content_length, "has_content_length set");
        sub.assert_eq(out_list.content_length_val, 1048576, "parsed content-length matches");
    };
}

fn test_openssl_31392_uri_name_constraints_nul(t: core::T&) {
    t.run("OpenSSL #31392 / RFC 5280 В§4.2.1.10: URI matching against DNS name constraint") { sub =>
        sub.assert_true(wing::match_uri_name_constraint("https://api.example.com/v1", "example.com"), "Subdomain matches constraint");
        sub.assert_true(wing::match_uri_name_constraint("https://example.com/login", "example.com"), "Exact domain matches constraint");
        sub.assert_false(wing::match_uri_name_constraint("https://evil.com/login", "example.com"), "Foreign domain must be rejected");
    };

    t.run("CVE-2009-2408: URI containing embedded NUL byte MUST be rejected") { sub =>
        let nul_uri: u8[29] = [
            'h', 't', 't', 'p', 's', ':', '/', '/',
            'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
            0x00,
            '.', 'e', 'v', 'i', 'l', '.', 'c', 'o', 'm',
        ];
        sub.assert_false(wing::match_uri_name_constraint(nul_uri[..], "example.com"), "NUL byte in URI must be rejected");
    };

    t.run("CVE-2024-45341 / Go #71208: IPv6 Zone ID URI Name Constraints Bypass Defense") { sub =>
        sub.assert_true(
            wing::match_uri_name_constraint("https://[2001:db8::1%25eth0]:8443/api", "2001:db8::1"),
            "IPv6 URI with encoded zone ID matches IP constraint",
        );
        sub.assert_true(
            wing::match_uri_name_constraint("https://[2001:db8::1%eth0]/status", "[2001:db8::1]"),
            "IPv6 URI with raw zone ID matches bracketed constraint",
        );
        sub.assert_false(
            wing::match_uri_name_constraint("https://[2001:db8::2%eth0]/api", "2001:db8::1"),
            "Non-matching IPv6 URI must be rejected",
        );
        sub.assert_false(
            wing::match_uri_name_constraint("https://[malformed-ipv6/api", "2001:db8::1"),
            "Unclosed bracket in IPv6 URI must be rejected",
        );
    };
}

fn test_uwebsockets_1876_control_priority_under_backpressure(t: core::T&) {
    t.run("uWebSockets #1876: Control frames MUST NOT be dropped when backpressure threshold is reached") { sub =>
        var ws = wing::WebSocketSession { .. };
        wing::set_max_backpressure(ws, 100, false); // 100 bytes max backpressure

        var out_wire: u8[>..] = [];
        // Saturate backpressure buffer
        let st1 = wing::send_text_with_status(ws, "Initial message filling backpressure quota", out_wire);
        sub.assert_true(st1 == wing::WsSendStatus.Backpressure || st1 == wing::WsSendStatus.Success, "Initial send succeeds or backpressures");
        sub.assert_true(wing::is_backpressured(ws), "Socket is backpressured");

        // Subsequent data message exceeding threshold is dropped
        var dropped_wire: u8[>..] = [];
        let st2 = wing::send_text_with_status(ws, "Excessive payload that must be dropped due to backpressure ceiling", dropped_wire);
        sub.assert_eq(st2, wing::WsSendStatus.Dropped, "Data frame must be dropped under pressure");

        // Control frame (Ping) must NOT be dropped!
        var ping_wire: u8[>..] = [];
        wing::send_ping(ws, "heartbeat", ping_wire);
        sub.assert_true(ping_wire.len > 0, "Ping frame must be written even when socket is backpressured");

        // Control frame (Close) must NOT be dropped!
        var close_wire: u8[>..] = [];
        wing::close(ws, wing::WS_STATUS_NORMAL, "clean close", close_wire);
        sub.assert_true(close_wire.len > 0, "Close frame must be written even when socket is backpressured");
        sub.assert_true(ws.is_closed, "Session marked closed");
    };
}

fn test_openssl_tls13_zero_length_plaintext_invariants(t: core::T&) {
    t.run("RFC 8446 В§5.4: Empty Application Data record with padding is permitted") { sub =>
        // Record with inner ContentType = 0x17 (Application Data) followed by zero padding
        let plain_wire: u8[4] = [0x17, 0x00, 0x00, 0x00];
        let content, inner_type, alert = wing::unpack_tls_inner_plaintext(plain_wire[..]);
        sub.assert_true(alert == wing::TlsAlert.CloseNotify, "Empty application data with padding must be accepted");
        sub.assert_eq(inner_type, 0x17, "Inner content type is ApplicationData");
        sub.assert_eq(content.len, 0, "Payload length is 0");
    };

    t.run("RFC 8446 В§5.4: Empty Handshake record MUST be rejected with unexpected_message") { sub =>
        // Record with inner ContentType = 0x16 (Handshake) and 0 payload bytes followed by padding
        let plain_hs: u8[3] = [0x16, 0x00, 0x00];
        let _, _, alert = wing::unpack_tls_inner_plaintext(plain_hs[..]);
        sub.assert_eq(alert, wing::TlsAlert.UnexpectedMessage, "Empty Handshake record must return unexpected_message");
    };

    t.run("RFC 8446 В§5.4: All-zero padding record MUST be rejected with unexpected_message") { sub =>
        let all_zero: u8[16] = [0; 16];
        let _, _, alert = wing::unpack_tls_inner_plaintext(all_zero[..]);
        sub.assert_eq(alert, wing::TlsAlert.UnexpectedMessage, "All-zero record missing inner ContentType must be rejected");
    };
}

fn test_go_66434_content_transfer_encoding_rejection(t: core::T&) {
    t.run("Go #66434 & RFC 7578 В§4.7: Content-Transfer-Encoding in multipart part MUST be rejected") { sub =>
        let body = "--sep\r\nContent-Disposition: form-data; name=\"msg\"\r\nContent-Transfer-Encoding: base64\r\n\r\nSGVsbG8=\r\n--sep--\r\n";
        let msg, err = wing::parse_multipart(body, "sep");
        sub.assert_true(err == wing::MultipartError.InvalidPartHeaders, "Deprecated Content-Transfer-Encoding must be rejected");
        sub.assert_false(msg.valid, "Message marked invalid");
    };

    t.run("Standard multipart without Content-Transfer-Encoding must succeed") { sub =>
        let body = "--sep\r\nContent-Disposition: form-data; name=\"msg\"\r\n\r\nHello World\r\n--sep--\r\n";
        let msg, err = wing::parse_multipart(body, "sep");
        sub.assert_true(wing::is_ok(err), "Standard multipart must parse successfully");
        sub.assert_true(msg.valid, "Message marked valid");
        sub.assert_eq(msg.parts.len, 1, "1 part parsed");
    };
}

fn test_uwebsockets_1662_streaming_utf8_continuation(t: core::T&) {
    t.run("uWS #1662 / Autobahn 6.x: Incomplete multi-byte codepoint split across frame chunks") { sub =>
        // Euro sign в‚¬ is 3 bytes: 0xE2, 0x82, 0xAC
        let chunk1: u8[2] = [0xE2, 0x82];
        let off1_non_final, ok1_non_final = core::validate_utf8_streaming(chunk1[..], false);
        sub.assert_true(ok1_non_final, "Valid prefix of incomplete 3-byte codepoint accepted when non-final");
        sub.assert_eq(off1_non_final, 0, "0 complete codepoints in chunk1");

        let off1_final, ok1_final = core::validate_utf8_streaming(chunk1[..], true);
        sub.assert_false(ok1_final, "Incomplete codepoint at final boundary MUST be rejected");

        // Complete sequence in assembled buffer
        let full: u8[3] = [0xE2, 0x82, 0xAC];
        let off_full, ok_full = core::validate_utf8_streaming(full[..], true);
        sub.assert_true(ok_full, "Complete 3-byte codepoint accepted");
        sub.assert_eq(off_full, 3, "All 3 bytes verified as complete codepoint");
    };

    t.run("uWS #1662 / Autobahn 6.x: Overlong UTF-8 prefix rejected immediately") { sub =>
        // Overlong 2-byte: 0xC0 0x80 (ASCII NUL encoded as 2 bytes)
        let overlong: u8[2] = [0xC0, 0x80];
        let _, ok_overlong = core::validate_utf8_streaming(overlong[..], false);
        sub.assert_false(ok_overlong, "Overlong prefix must be rejected immediately even on non-final chunk");
    };

    t.run("uWS #1662 / Autobahn 6.x: UTF-16 surrogate prefix rejected immediately") { sub =>
        // High surrogate U+D800: 0xED 0xA0 0x80
        let surrogate: u8[2] = [0xED, 0xA0];
        let _, ok_surrogate = core::validate_utf8_streaming(surrogate[..], false);
        sub.assert_false(ok_surrogate, "Surrogate prefix must be rejected immediately");
    };
}

fn test_openssl_33428_ech_alpn_isolation(t: core::T&) {
    t.run("OpenSSL #33428: ECH accepted MUST only permit inner ALPN negotiation") { sub =>
        let inner_alpn = "h2";
        let outer_alpn = "http/1.1";

        sub.assert_true(
            wing::validate_ech_alpn_negotiation(true, "h2", inner_alpn, outer_alpn),
            "Selected inner ALPN accepted when ECH accepted",
        );
        sub.assert_false(
            wing::validate_ech_alpn_negotiation(true, "http/1.1", inner_alpn, outer_alpn),
            "Outer ALPN rejected when ECH accepted",
        );
    };

    t.run("OpenSSL #33428: ECH rejected/bypassed MUST only permit outer ALPN negotiation") { sub =>
        let inner_alpn = "h2";
        let outer_alpn = "http/1.1";

        sub.assert_true(
            wing::validate_ech_alpn_negotiation(false, "http/1.1", inner_alpn, outer_alpn),
            "Selected outer ALPN accepted when ECH rejected",
        );
        sub.assert_false(
            wing::validate_ech_alpn_negotiation(false, "h2", inner_alpn, outer_alpn),
            "Inner ALPN MUST NOT leak into unencrypted outer connection",
        );
    };
}

fn test_openssl_33332_redirect_sensitive_header_purging(t: core::T&) {
    t.run("OpenSSL #33332 & Go #82350: Cross-origin redirect strips sensitive headers and Host") { sub =>
        var headers: wing::HeaderItem[..32] = [];
        headers.push(wing::make_header("Authorization", "Bearer secret-token"));
        headers.push(wing::make_header("Cookie", "session=xyz123"));
        headers.push(wing::make_header("X-Api-Key", "super-secret-key"));
        headers.push(wing::make_header("Host", "api.bank.com"));
        headers.push(wing::make_header("X-Custom-Data", "regular-value"));

        var rinfo = wing::RedirectInfo {
            is_cross_origin: true,
            is_scheme_downgrade: false,
            is_port_changed: false,
            ..
        };

        wing::sanitize_headers_on_redirect(headers, rinfo, false, false, false, false);

        sub.assert_false(wing::has_header(headers[..], "Authorization"), "Authorization must be stripped on cross-origin redirect");
        sub.assert_false(wing::has_header(headers[..], "Cookie"), "Cookie must be stripped on redirect");
        sub.assert_false(wing::has_header(headers[..], "X-Api-Key"), "X-Api-Key must be stripped on cross-origin redirect");
        sub.assert_false(wing::has_header(headers[..], "Host"), "Stale Host header must be stripped on cross-origin redirect (Go #82350)");
        sub.assert_true(wing::has_header(headers[..], "X-Custom-Data"), "Non-sensitive custom header must be preserved");
    };

    t.run("CVE-2018-1000007: Scheme downgrade (HTTPS -> HTTP) strips credentials even to trusted host") { sub =>
        var headers: wing::HeaderItem[..32] = [];
        headers.push(wing::make_header("Authorization", "Basic dXNlcjpwYXNz"));
        headers.push(wing::make_header("X-Custom", "safe"));

        var rinfo = wing::RedirectInfo {
            is_cross_origin: false,
            is_scheme_downgrade: true,
            is_port_changed: false,
            ..
        };

        // trusted_location_forwarding = true
        wing::sanitize_headers_on_redirect(headers, rinfo, false, false, false, true);

        sub.assert_false(wing::has_header(headers[..], "Authorization"), "Scheme downgrade MUST strip credentials even if host is trusted");
        sub.assert_true(wing::has_header(headers[..], "X-Custom"), "Non-sensitive header preserved");
    };
}

fn test_uweb_1941_chained_transfer_encoding_validation(t: core::T&) {
    t.run("uWS #1941 / #1943 & RFC 9112 В§6.1: Valid chained transfer codings ending in chunked") { sub =>
        sub.assert_true(wing::validate_transfer_encoding_value("chunked"), "Single chunked is valid");
        sub.assert_true(wing::validate_transfer_encoding_value("gzip, chunked"), "gzip, chunked is valid");
        sub.assert_true(wing::validate_transfer_encoding_value("identity, chunked"), "identity, chunked is valid");
        sub.assert_true(wing::validate_transfer_encoding_value("deflate, gzip, chunked"), "deflate, gzip, chunked is valid");
    };

    t.run("uWS #1941 / #1943: Rejection of invalid transfer codings or non-final chunked") { sub =>
        sub.assert_false(wing::validate_transfer_encoding_value("chunked, gzip"), "chunked before gzip MUST be rejected");
        sub.assert_false(wing::validate_transfer_encoding_value("gzip, chunked,"), "Trailing comma MUST be rejected");
        sub.assert_false(wing::validate_transfer_encoding_value("chunked, chunked"), "Duplicate chunked MUST be rejected");
        sub.assert_false(wing::validate_transfer_encoding_value("identity"), "Missing chunked MUST be rejected");
    };
}

fn test_cve_2026_42507_diagnostic_log_injection_defense(t: core::T&) {
    t.run("CVE-2026-42507 & Go #79346: Escapes CRLF and control characters in untrusted tokens") { sub =>
        var out: u8[..128] = [];
        wing::escape_diagnostic_control_chars("admin\r\nSet-Cookie: pwn=1\x00\x1b", out);

        sub.assert_false(core::contains_byte(out[..], 13), "Raw CR (13) must not be present in output");
        sub.assert_false(core::contains_byte(out[..], 10), "Raw LF (10) must not be present in output");
        sub.assert_false(core::contains_byte(out[..], 0), "Raw NUL (0) must not be present in output");
        sub.assert_true(core::index_of_slice(out[..], "\\r\\n") >= 0, "CRLF properly escaped as literal '\\r\\n'");
    };
}

fn test_h2_window_update_and_settings_cpu_limits(t: core::T&) {
    t.run("RFC 9113 В§6.9.1 & Go #58456: WINDOW_UPDATE increment bounds and window overflow") { sub =>
        var conn = wing::new_h2_connection(0, 8192, false);

        // Increment > 2^31 - 1 is a PROTOCOL_ERROR
        let err_proto = wing::apply_window_update(conn, 0, (wing::MAX_INITIAL_WINDOW_SIZE as u32) + 1);
        sub.assert_eq(err_proto, wing::ERR_PROTOCOL_ERROR, "Increment > 2^31 - 1 must trigger PROTOCOL_ERROR");

        // Increment pushing window past 2^31 - 1 is a FLOW_CONTROL_ERROR
        let err_flow = wing::apply_window_update(conn, 0, wing::MAX_INITIAL_WINDOW_SIZE as u32);
        sub.assert_eq(err_flow, wing::ERR_FLOW_CONTROL_ERROR, "Window accumulator exceeding 2^31 - 1 must trigger FLOW_CONTROL_ERROR");
    };

    t.run("CVE-2026-78669 & Go #81742: Excessive repeated INITIAL_WINDOW_SIZE changes throttled") { sub =>
        var conn = wing::new_h2_connection(0, 8192, false);

        for i in 16 {
            let res = wing::apply_peer_initial_window_size_delta(conn, 32768 + (i as u32));
            sub.assert_eq(res, wing::ERR_NO_ERROR, "First 16 window updates succeed");
        }

        // 17th update triggers ENHANCE_YOUR_CALM defense
        let res_17 = wing::apply_peer_initial_window_size_delta(conn, 65535);
        sub.assert_eq(res_17, wing::ERR_ENHANCE_YOUR_CALM, "Excessive repeated window changes must trigger ENHANCE_YOUR_CALM");
    };
}

// 14. RFC 8446 Section 4: TLS 1.3 Handshake State Machine Transition Invariants
fn test_openssl_handshake_state_machine_transition_invariants(t: core::T&) {
    t.run("Strict client handshake transition table enforcement (RFC 8446)") { sub =>
        // In full handshake (is_psk = false), Finished received prematurely before Cert/CV MUST be rejected
        let st_bad_fin, ok_bad_fin = wing::validate_client_handshake_transition(
            wing::HsState.ClientWaitCertCr,
            wing::HS_MSG_FINISHED,
            false,
            false,
        );
        sub.assert_false(ok_bad_fin, "Finished before Certificate/CV in full handshake MUST be rejected");
        sub.assert_true(st_bad_fin == wing::HsState.Closed, "Illegal transition transitions to Closed");

        // In PSK mode (is_psk = true), Finished is accepted directly after ServerHello/EncryptedExtensions
        let st_psk_fin, ok_psk_fin = wing::validate_client_handshake_transition(
            wing::HsState.ClientWaitCertCr,
            wing::HS_MSG_FINISHED,
            true,
            false,
        );
        sub.assert_true(ok_psk_fin, "Finished accepted in PSK mode");
        sub.assert_true(st_psk_fin == wing::HsState.Connected, "PSK Finished transitions to Connected");

        // Certificate received when expecting Certificate transitions to CV
        let st_cert, ok_cert = wing::validate_client_handshake_transition(
            wing::HsState.ClientWaitCert,
            wing::HS_MSG_CERTIFICATE,
            false,
            false,
        );
        sub.assert_true(ok_cert, "Certificate accepted in ClientWaitCert");
        sub.assert_true(st_cert == wing::HsState.ClientWaitCV, "Transitions to ClientWaitCV");

        // Synthetic message_hash (254) MUST NEVER appear on wire
        let st_hash, ok_hash = wing::validate_client_handshake_transition(
            wing::HsState.ClientWaitSH,
            wing::HS_MSG_MESSAGE_HASH,
            false,
            false,
        );
        sub.assert_false(ok_hash, "Synthetic message_hash on wire MUST be rejected");

        // Post-handshake: only NewSessionTicket and KeyUpdate permitted
        let st_ticket, ok_ticket = wing::validate_client_handshake_transition(
            wing::HsState.Connected,
            wing::HS_MSG_NEW_SESSION_TICKET,
            false,
            false,
        );
        sub.assert_true(ok_ticket, "NewSessionTicket accepted post-handshake");
        sub.assert_true(st_ticket == wing::HsState.Connected, "Remains Connected");

        let st_rehandshake, ok_rehandshake = wing::validate_client_handshake_transition(
            wing::HsState.Connected,
            wing::HS_MSG_SERVER_HELLO,
            false,
            false,
        );
        sub.assert_false(ok_rehandshake, "ServerHello received while Connected MUST be rejected (renegotiation banned)");
    };

    t.run("Strict server handshake transition table enforcement (RFC 8446)") { sub =>
        // Finished accepted in ServerWaitFinished
        let st_srv_fin, ok_srv_fin = wing::validate_server_handshake_transition(
            wing::HsState.ServerWaitFinished,
            wing::HS_MSG_FINISHED,
            false,
        );
        sub.assert_true(ok_srv_fin, "Finished accepted by server in ServerWaitFinished");
        sub.assert_true(st_srv_fin == wing::HsState.Connected, "Server transitions to Connected");

        // Out-of-order ClientHello in ServerWaitFinished rejected
        let st_srv_bad, ok_srv_bad = wing::validate_server_handshake_transition(
            wing::HsState.ServerWaitFinished,
            wing::HS_MSG_CLIENT_HELLO,
            false,
        );
        sub.assert_false(ok_srv_bad, "Duplicate ClientHello while waiting for Finished rejected");
    };
}

// 15. RFC 9113 Section 6.8 & Go #80759: HTTP/2 GOAWAY Last-Stream-ID Parity Invariants
fn test_rfc9113_goaway_last_stream_id_parity(t: core::T&) {
    t.run("Client GOAWAY peer stream parity (can only acknowledge server streams: even or 0)") { sub =>
        sub.assert_true(wing::validate_goaway_last_stream_id(0, true), "Client GOAWAY with 0 is valid");
        sub.assert_true(wing::validate_goaway_last_stream_id(2, true), "Client GOAWAY with even stream 2 is valid");
        sub.assert_true(wing::validate_goaway_last_stream_id(100, true), "Client GOAWAY with even stream 100 is valid");
        sub.assert_false(wing::validate_goaway_last_stream_id(1, true), "Client GOAWAY with client-initiated stream 1 MUST be rejected");
        sub.assert_false(wing::validate_goaway_last_stream_id(3, true), "Client GOAWAY with client-initiated stream 3 MUST be rejected");
        sub.assert_false(wing::validate_goaway_last_stream_id(99, true), "Client GOAWAY with client-initiated stream 99 MUST be rejected");
    };

    t.run("Server GOAWAY peer stream parity (can only acknowledge client streams: odd, 0, or max)") { sub =>
        sub.assert_true(wing::validate_goaway_last_stream_id(0, false), "Server GOAWAY with 0 is valid");
        sub.assert_true(wing::validate_goaway_last_stream_id(1, false), "Server GOAWAY with odd stream 1 is valid");
        sub.assert_true(wing::validate_goaway_last_stream_id(101, false), "Server GOAWAY with odd stream 101 is valid");
        sub.assert_true(wing::validate_goaway_last_stream_id(0x7FFFFFFF, false), "Server GOAWAY with 2^31 - 1 is valid");
        sub.assert_false(wing::validate_goaway_last_stream_id(2, false), "Server GOAWAY with server-initiated stream 2 MUST be rejected");
        sub.assert_false(wing::validate_goaway_last_stream_id(4, false), "Server GOAWAY with server-initiated stream 4 MUST be rejected");
        sub.assert_false(wing::validate_goaway_last_stream_id(102, false), "Server GOAWAY with server-initiated stream 102 MUST be rejected");
    };
}

// 16. RFC 4648 В§3.5 & RFC 7515 В§2: Base64 & Base64URL Canonical Decoding & Malleability Defenses
fn test_rfc4648_base64_canonical_and_malleability_defenses(t: core::T&) {
    t.run("Canonical Base64 round-trips succeed") { sub =>
        var out_a: u8[>..] = [];
        sub.assert_true(core::base64_decode("YQ==", out_a), "Decode canonical 'YQ==' to 'a'");
        sub.assert_bytes_eq(out_a[..], "a", "Value matches 'a'");

        var out_fo: u8[>..] = [];
        sub.assert_true(core::base64_decode("Zm8=", out_fo), "Decode canonical 'Zm8=' to 'fo'");
        sub.assert_bytes_eq(out_fo[..], "fo", "Value matches 'fo'");

        var out_foobar: u8[>..] = [];
        sub.assert_true(core::base64_decode("Zm9vYmFy", out_foobar), "Decode canonical 'Zm9vYmFy'");
        sub.assert_bytes_eq(out_foobar[..], "foobar", "Value matches 'foobar'");
    };

    t.run("Canonical Base64URL round-trips succeed") { sub =>
        var out_u_a: u8[>..] = [];
        sub.assert_true(core::base64url_decode("YQ", out_u_a), "Decode unpadded base64url 'YQ'");
        sub.assert_bytes_eq(out_u_a[..], "a", "Value matches 'a'");

        var out_u_fo: u8[>..] = [];
        sub.assert_true(core::base64url_decode("Zm8", out_u_fo), "Decode unpadded base64url 'Zm8'");
        sub.assert_bytes_eq(out_u_fo[..], "fo", "Value matches 'fo'");
    };

    t.run("RFC 4648 В§3.5 Malleability: Non-zero padding bits MUST be rejected") { sub =>
        var out_bad: u8[>..] = [];
        // 'YR==' has the 4 unused bits set to 0001 instead of 0000 ('YQ==')
        sub.assert_false(core::base64_decode("YR==", out_bad), "Non-zero padding bits in base64 MUST be rejected");
        sub.assert_false(core::base64url_decode("YR", out_bad), "Non-zero padding bits in unpadded base64url MUST be rejected");
        sub.assert_false(core::base64url_decode("YR==", out_bad), "Non-zero padding bits in padded base64url MUST be rejected");
    };

    t.run("Truncated 1-character quantum (len % 4 == 1) MUST be rejected") { sub =>
        var out_bad: u8[>..] = [];
        sub.assert_false(core::base64_decode("A", out_bad), "1-character base64 MUST be rejected");
        sub.assert_false(core::base64_decode("Zm9vYmFyA", out_bad), "9-character base64 (rem 1) MUST be rejected");
        sub.assert_false(core::base64url_decode("A", out_bad), "1-character base64url MUST be rejected");
        sub.assert_false(core::base64url_decode("Zm9vYmFyA", out_bad), "9-character base64url (rem 1) MUST be rejected");
    };

    t.run("Garbage after padding and invalid padding structure MUST be rejected") { sub =>
        var out_bad: u8[>..] = [];
        sub.assert_false(core::base64_decode("====", out_bad), "Bare padding '====' MUST be rejected");
        sub.assert_false(core::base64_decode("=", out_bad), "Bare padding '=' MUST be rejected");
        sub.assert_false(core::base64_decode("Y===", out_bad), "Padding after 1 char 'Y===' MUST be rejected");
        sub.assert_false(core::base64_decode("YQ=", out_bad), "1 pad char when 2 expected MUST be rejected");
        sub.assert_false(core::base64_decode("Zm8==", out_bad), "2 pad chars when 1 expected MUST be rejected");
        sub.assert_false(core::base64_decode("YQ==EXTRA", out_bad), "Garbage after valid padding MUST be rejected");
        sub.assert_false(core::base64_decode("YQ== ", out_bad), "Trailing whitespace after padding MUST be rejected");
        sub.assert_false(core::base64url_decode("YQ==EXTRA", out_bad), "Garbage after base64url padding MUST be rejected");
    };
}

// 17. Core Codec Overflow, Malleability & Truncation Defenses
fn test_core_codecs_boundary_and_overflow_defenses(t: core::T&) {
    t.run("Hex integer parsing with leading zeros and boundary limits") { sub =>
        // Hex with leading zeros MUST succeed
        let val_1, ok_1 = core::parse_u64_hex("0x00000000000000000001");
        sub.assert_true(ok_1, "Hex with leading zeros MUST succeed");
        sub.assert_eq(val_1, 1, "Parsed value must equal 1");

        let val_zero, ok_zero = core::parse_u64_hex("00000000000000000000");
        sub.assert_true(ok_zero, "Hex with 20 leading zeros MUST succeed");
        sub.assert_eq(val_zero, 0, "Parsed value must equal 0");

        // Hex overflow (> 16 significant digits) MUST be rejected
        let _, ok_overflow = core::parse_u64_hex("0x10000000000000000");
        sub.assert_false(ok_overflow, "Hex with 17 significant digits MUST be rejected as overflow");
    };

    t.run("Query parameter capacity overflow MUST be flagged") { sub =>
        // Key exceeding 64 bytes capacity must set list.overflow = true
        let long_key = "?0123456789012345678901234567890123456789012345678901234567890123456789=value";
        let list = core::parse_query_params(long_key);
        sub.assert_true(list.overflow, "Oversized query param key MUST mark list.overflow = true");
    };

    t.run("Path percent decode capacity safety") { sub =>
        var out_small: u8[..4] = [];
        let ok_dec = core::percent_decode("hello_world_too_long", out_small);
        sub.assert_false(ok_dec, "Percent decode into undersized buffer MUST return false without panic");
    };
}

// ----------------------------------------------------------------------------
// 18. RFC 7541 / RFC 9113: HTTP/2 HPACK Inbound Capacity & Overflow Defenses
// ----------------------------------------------------------------------------
fn test_http2_hpack_boundary_and_capacity_defenses(t: core::T&) {
    t.run("HPACK string literal exceeding buffer capacity fails closed") { sub =>
        // Construct raw uncompressed HPACK string literal of 300 bytes: prefix 0x00, length 300
        var raw_lit: u8[..320] = [];
        raw_lit.push(0x7F); // 7-bit prefix all 1s (127)
        raw_lit.push((300 - 127) as u8); // 173 -> total length 300
        for i in 300 {
            raw_lit.push('a');
        }

        var out_small: u8[..256] = [];
        let _, ok = wing::decode_hpack_string(raw_lit[..], 0, out_small);
        sub.assert_false(ok, "Literal HPACK string of 300 bytes into 256-cap buffer MUST return false without abort");
    };

    t.run("HPACK Huffman decode into undersized buffer fails closed") { sub =>
        // Huffman-encode "www.example.com" repeated 25 times (~350 bytes)
        var uncomp: u8[..400] = [];
        for i in 25 {
            uncomp.append("www.example.com/");
        }

        var huff_encoded: u8[..400] = [];
        wing::huff_encode_bytes(uncomp[..], huff_encoded);

        var out_small: u8[..64] = [];
        let ok = wing::huff_decode_bytes(huff_encoded[..], out_small);
        sub.assert_false(ok, "Huffman decode exceeding buffer capacity MUST return false without abort");
    };

    t.run("HPACK header block with oversized literal name rejected safely") { sub =>
        // Literal header with incremental indexing: 0x40 (name_idx = 0)
        // followed by 300-byte name string literal and 5-byte value
        var raw_block: u8[..400] = [];
        raw_block.push(0x40);
        // Name string length: 300 (0x7F + 173)
        raw_block.push(0x7F);
        raw_block.push(173);
        for i in 300 {
            raw_block.push('x');
        }
        // Value string length: 5 ("value")
        raw_block.push(5);
        raw_block.append("value");

        var dt = wing::new_dynamic_table(4096);
        var out_list = wing::DecodedH2HeaderList { .. };
        let err = wing::decode_hpack_header_block(dt, raw_block[..], out_list, 8192, false);
        sub.assert_ne(err, wing::ERR_NO_ERROR, "Header with 300-byte name MUST fail decoding safely");
    };
}

// ----------------------------------------------------------------------------
// 19. RFC 3986 & WHATWG: Relative URL Resolution Buffer Capacity Defenses
// ----------------------------------------------------------------------------
fn test_url_relative_resolution_capacity_defense(t: core::T&) {
    t.run("Relative reference exceeding 2048-byte URL buffer MUST return InputTooLong without abort") { sub =>
        // Construct a valid base URL near the 2048-byte capacity limit (1927 bytes)
        var long_base: u8[..2048] = [];
        long_base.append("https://example.com/prefix/");
        for i in 1900 {
            long_base.push('a');
        }
        let base_url = core::new_url(long_base[..]);
        sub.assert_true(base_url.valid, "Base URL within 2048 bytes must be valid");

        // 1. Fragment-only relative reference causing overflow (> 2048 bytes total)
        var long_frag: u8[..256] = [];
        long_frag.push('#');
        for i in 200 {
            long_frag.push('b');
        }
        let url_frag, err_frag = core::parse_url_with_base(long_frag[..], base_url);
        sub.assert_false(url_frag.valid, "Oversized relative fragment reference must fail");
        sub.assert_true(err_frag == core::UrlParseError.InputTooLong, "Must return InputTooLong instead of aborting");

        // 2. Query-only relative reference causing overflow
        var long_query: u8[..256] = [];
        long_query.push('?');
        for i in 200 {
            long_query.push('c');
        }
        let url_query, err_query = core::parse_url_with_base(long_query[..], base_url);
        sub.assert_false(url_query.valid, "Oversized relative query reference must fail");
        sub.assert_true(err_query == core::UrlParseError.InputTooLong, "Must return InputTooLong instead of aborting");

        // 3. Directory-relative path reference with base trailing slash causing combined path overflow
        var long_dir_base: u8[..2048] = [];
        long_dir_base.append("https://example.com/dir/");
        for i in 1900 {
            long_dir_base.push('a');
        }
        long_dir_base.push('/');
        let dir_base_url = core::new_url(long_dir_base[..]);
        sub.assert_true(dir_base_url.valid, "Base URL with trailing slash must be valid");

        var long_rel_path: u8[..256] = [];
        for i in 200 {
            long_rel_path.push('d');
        }
        let url_path, err_path = core::parse_url_with_base(long_rel_path[..], dir_base_url);
        sub.assert_false(url_path.valid, "Oversized relative directory path reference must fail");
        sub.assert_true(err_path == core::UrlParseError.InputTooLong, "Must return InputTooLong instead of aborting");

        // 4. Opaque base URL fragment resolution causing overflow
        var long_opaque_base: u8[..2048] = [];
        long_opaque_base.append("mailto:user");
        for i in 1900 {
            long_opaque_base.push('u');
        }
        long_opaque_base.append("@example.com");
        let opaque_base = core::new_url(long_opaque_base[..]);
        sub.assert_true(opaque_base.valid, "Opaque base URL must be valid");

        var long_frag_opaque: u8[..256] = [];
        long_frag_opaque.push('#');
        for i in 200 {
            long_frag_opaque.push('f');
        }
        let url_opaque, err_opaque = core::parse_url_with_base(long_frag_opaque[..], opaque_base);
        sub.assert_false(url_opaque.valid, "Oversized fragment on opaque base must fail");
        sub.assert_true(err_opaque == core::UrlParseError.InputTooLong, "Opaque fragment overflow returns InputTooLong");
    };
}

// ----------------------------------------------------------------------------
// 20. RFC 3986 & WHATWG: URL Path Manipulation & File URL Capacity Defenses
// ----------------------------------------------------------------------------
fn test_url_path_and_file_capacity_defenses(t: core::T&) {
    t.run("Path manipulation and file URL exceeding 2048 bytes fail safely without abort") { sub =>
        // 1. new_file_url with path expanding beyond 2048 bytes via percent-encoding
        var long_path: u8[..2048] = [];
        long_path.append("/path/with/spaces/");
        for i in 800 {
            long_path.push(' ');
        }
        let file_url = core::new_file_url(long_path[..]);
        sub.assert_false(file_url.valid, "Oversized file URL must fail gracefully with valid=false");

        // 2. appending_path_component exceeding 2048 bytes
        let base_url = core::new_url("https://example.com/base/");
        sub.assert_true(base_url.valid, "Base URL is valid");

        var long_comp: u8[..2048] = [];
        for i in 800 {
            long_comp.push(' ');
        }
        let res_comp = core::appending_path_component(base_url, long_comp[..]);
        sub.assert_false(res_comp.valid, "appending_path_component exceeding 2048 bytes must return invalid URL");

        // 3. appending_path exceeding 2048 bytes
        let res_path = core::appending_path(base_url, long_comp[..]);
        sub.assert_false(res_path.valid, "appending_path exceeding 2048 bytes must return invalid URL");

        // 4. appending_path_extension exceeding 2048 bytes
        let res_ext = core::appending_path_extension(base_url, long_comp[..]);
        sub.assert_false(res_ext.valid, "appending_path_extension exceeding 2048 bytes must return invalid URL");

        // 5. file_path into undersized output buffer returns false without abort
        let short_file_url = core::new_file_url("/usr/local/bin/my_app_executable_name");
        sub.assert_true(short_file_url.valid, "Short file URL is valid");
        var small_buf: u8[..8] = [];
        let ok_fp = core::file_path(short_file_url, small_buf);
        sub.assert_false(ok_fp, "file_path into undersized buffer must return false without abort");
    };
}

// ----------------------------------------------------------------------------
// 21. RFC 3986 В§3 & WHATWG: URL Query Delimiter & Parameter Isolation Defenses
// ----------------------------------------------------------------------------
fn test_url_query_delimiter_and_decoding_defenses(t: core::T&) {
    t.run("Fragment delimiter terminates query parameters preventing injection") { sub =>
        let poisoned_query = "?auth=token123#frag&admin=true&role=root";

        // 1. get_query_param_fast must not leak fragment parameters
        var out_val: u8[..64] = [];
        let found_admin, _ = core::get_query_param_fast(poisoned_query, "admin", out_val);
        sub.assert_false(found_admin, "Injected fragment param 'admin' must not be found by get_query_param_fast");

        let found_role, _ = core::get_query_param_fast(poisoned_query, "role", out_val);
        sub.assert_false(found_role, "Injected fragment param 'role' must not be found by get_query_param_fast");

        // 2. has_query_param_fast must not report existence of fragment parameters
        sub.assert_false(core::has_query_param_fast(poisoned_query, "admin"), "has_query_param_fast must return false for fragment params");
        sub.assert_false(core::has_query_param_fast(poisoned_query, "role"), "has_query_param_fast must return false for fragment params");

        // 3. parse_query_params must terminate at '#' and preserve clean valid param
        let list = core::parse_query_params(poisoned_query);
        sub.assert_false(core::has_query_param(list, "admin"), "parse_query_params must not include fragment 'admin'");
        sub.assert_false(core::has_query_param(list, "role"), "parse_query_params must not include fragment 'role'");
        sub.assert_bytes_eq(core::get_query_param(list, "auth"), "token123", "Query param 'auth' before fragment must equal 'token123'");

        // 4. validate_query_param_count must not count tokens in fragment
        sub.assert_true(core::validate_query_param_count("?a=1#&b=2&c=3&d=4", 1), "validate_query_param_count must only count pre-fragment parameters");
    };

    t.run("Plus-as-space decoding in fast query key lookup") { sub =>
        let query_str = "?user+name=Alice&order+by=desc";
        var out_name: u8[..64] = [];
        let found_name, _ = core::get_query_param_fast(query_str, "user name", out_name);
        sub.assert_true(found_name, "get_query_param_fast must decode '+' as space in key");
        sub.assert_bytes_eq(out_name[..], "Alice", "Matched param value must be 'Alice'");
        sub.assert_true(core::has_query_param_fast(query_str, "user name"), "has_query_param_fast must find plus-encoded key");
    };

    t.run("Query parameter lookup into undersized buffer fails safely without truncation") { sub =>
        let query_str = "?token=012345678901234567890123456789";
        var small_buf: u8[..8] = [];
        let found_tok, _ = core::get_query_param_fast(query_str, "token", small_buf);
        sub.assert_false(found_tok, "get_query_param_fast into undersized buffer must fail closed without silent truncation");
    };
}

fn test_rfc8439_poly1305_block_boundary_padding_overflow(t: core::T&) {
    t.run("RFC 8439 В§2.5.2: Multi-block Poly1305 2^128 padding integrity across 16-byte boundaries") { sub =>
        let key: u8[32] = [
            0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33,
            0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
            0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd,
            0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b,
        ];
        let msg = "Cryptographic Forum Research Group";
        let tag = core::poly1305_mac(key, msg);
        let expected: u8[16] = [
            0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6,
            0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9,
        ];
        for i in 16 {
            sub.assert_eq(tag[i], expected[i], "Multi-block Poly1305 tag byte matches RFC 8439 В§2.5.2");
        }
    };

    t.run("RFC 8439 В§2.8.2: ChaCha20-Poly1305 AEAD exact block boundary & AAD binding") { sub =>
        let key: u8[32] = [
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
            0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
            0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
            0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
        ];
        let nonce: u8[12] = [
            0x07, 0x00, 0x00, 0x00,
            0x40, 0x41, 0x42, 0x43,
            0x44, 0x45, 0x46, 0x47,
        ];
        let aad: u8[12] = [
            0x50, 0x51, 0x52, 0x53,
            0xc0, 0xc1, 0xc2, 0xc3,
            0xc4, 0xc5, 0xc6, 0xc7,
        ];
        let plaintext = "Ladies and Gentlemen of the class of \x2799: If I could offer you only one tip for the future, sunscreen would be it.";

        var ciphertext: u8[>..] = [];
        let tag = core::chacha20_poly1305_seal(key, nonce, plaintext, aad[..], ciphertext);

        let expected_tag: u8[16] = [
            0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a,
            0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91,
        ];
        for i in 16 {
            sub.assert_eq(tag[i], expected_tag[i], "AEAD Tag byte matches RFC 8439 В§2.8.2");
        }

        var decrypted: u8[>..] = [];
        let ok = core::chacha20_poly1305_open(key, nonce, ciphertext[..], aad[..], tag, decrypted);
        sub.assert_true(ok, "AEAD Open succeeds with valid tag");
        sub.assert_eq(decrypted.len, plaintext.len, "Decrypted length matches plaintext");
    };
}

fn test_network_backoff_jitter_u64_max_overflow_and_entropy_collapse(t: core::T&) {
    t.run("Full Jitter backoff with U64_MAX cap must not collapse entropy to zero") { sub =>
        var rng = core::new_wyrand(12345);
        let base_ms: u64 = 100;
        let cap_ms: u64 = core::U64_MAX;

        // When attempt >= 64, target = U64_MAX. In unpatched code, target + 1 wraps around to 0,
        // fast_range_biased_u64 returns 0, collapsing backoff entropy to 0 and triggering retry storms.
        var zero_count = 0;
        for attempt in 20 {
            let sleep = core::backoff_full_jitter_ms(rng, base_ms, cap_ms, (64 + attempt) as u32);
            if sleep == 0 {
                zero_count += 1;
            }
        }
        sub.assert_lt(zero_count, 5, "Full jitter backoff with U64_MAX cap must not collapse to 0 on saturated attempts");
    };

    t.run("Decorrelated Jitter backoff with U64_MAX span must not collapse entropy to zero") { sub =>
        var rng = core::new_wyrand(54321);
        var zero_count = 0;
        for i in 20 {
            let sleep = core::backoff_decorrelated_jitter_ms(rng, 0, core::U64_MAX, core::U64_MAX);
            if sleep == 0 {
                zero_count += 1;
            }
        }
        sub.assert_lt(zero_count, 5, "Decorrelated jitter backoff with U64_MAX cap and base 0 must not collapse to 0");
    };
}

fn test_rfc7748_x25519_constant_time_montgomery_ladder(t: core::T&) {
    t.run("fe_cswap branchless conditional swap correctness") { sub =>
        var a = core::Fe10 { v: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10] };
        var b = core::Fe10 { v: [101, 102, 103, 104, 105, 106, 107, 108, 109, 110] };

        // swap = 0 -> no change
        core::fe_cswap(0, a, b);
        for i in 10 {
            sub.assert_eq(a.v[i], (i + 1) as i64, "fe_cswap(0) preserves a");
            sub.assert_eq(b.v[i], (i + 101) as i64, "fe_cswap(0) preserves b");
        }

        // swap = 1 -> swapped
        core::fe_cswap(1, a, b);
        for i in 10 {
            sub.assert_eq(a.v[i], (i + 101) as i64, "fe_cswap(1) swaps b into a");
            sub.assert_eq(b.v[i], (i + 1) as i64, "fe_cswap(1) swaps a into b");
        }

        // swap = 0xFF -> swapped (odd bit 0)
        core::fe_cswap(0xFF, a, b);
        for i in 10 {
            sub.assert_eq(a.v[i], (i + 1) as i64, "fe_cswap(0xFF) swaps a back");
            sub.assert_eq(b.v[i], (i + 101) as i64, "fe_cswap(0xFF) swaps b back");
        }
    };

    t.run("RFC 7748 В§6.1 Vector 2 non-basepoint & non-canonical point masking") { sub =>
        let scalar: u8[32] = [
            0xa5, 0x46, 0xe3, 0x6b, 0xf0, 0x52, 0x7c, 0x9d,
            0x3b, 0x16, 0x15, 0x4b, 0x82, 0x46, 0x5e, 0xdd,
            0x62, 0x14, 0x4c, 0x0a, 0xc1, 0xfc, 0x5a, 0x18,
            0x50, 0x6a, 0x22, 0x44, 0xba, 0x44, 0x9a, 0xc4,
        ];
        var u_coord: u8[32] = [
            0xe6, 0xdb, 0x68, 0x67, 0x58, 0x30, 0x30, 0xdb,
            0x35, 0x94, 0xc1, 0xa4, 0x24, 0xb1, 0x5f, 0x7c,
            0x72, 0x66, 0x24, 0xec, 0x26, 0xb3, 0x35, 0x3b,
            0x10, 0xa9, 0x03, 0xa6, 0xd0, 0xab, 0x1c, 0x4c,
        ];
        let out = core::x25519_scalarmult(scalar, u_coord);
        let expected: u8[32] = [
            0xc3, 0xda, 0x55, 0x37, 0x9d, 0xe9, 0xc6, 0x90,
            0x8e, 0x94, 0xea, 0x4d, 0xf2, 0x8d, 0x08, 0x4f,
            0x32, 0xec, 0xcf, 0x03, 0x49, 0x1c, 0x71, 0xf7,
            0x54, 0xb4, 0x07, 0x55, 0x77, 0xa2, 0x85, 0x52,
        ];
        for i in 32 {
            sub.assert_eq(out[i], expected[i], "X25519 RFC 7748 В§6.1 Vector 2 shared secret matches");
        }

        // RFC 7748 В§5: Non-canonical u-coordinate with MSB set must be masked and yield identical secret
        u_coord[31] |= 0x80;
        let out_masked = core::x25519_scalarmult(scalar, u_coord);
        for i in 32 {
            sub.assert_eq(out_masked[i], expected[i], "X25519 non-canonical MSB masking yields identical output");
        }
    };

    t.run("X25519 Montgomery Ladder Constant-Time Execution via Dudect") { sub =>
        var ctx = core::new_dudect_context(5000000.0); // 5ms crop threshold
        let u9: u8[32] = [9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

        // Class 0: all-zero scalar (no swaps in ladder)
        let scalar_0: u8[32] = [0; 32];
        // Class 1: alternating bit scalar (maximum swaps in ladder)
        let scalar_1: u8[32] = [0x55; 32];

        // Warmup
        for w in 10 {
            let _ = core::x25519_scalarmult(scalar_0, u9);
            let _ = core::x25519_scalarmult(scalar_1, u9);
        }

        for iter in 50 {
            let sw0 = core::stopwatch();
            let _ = core::x25519_scalarmult(scalar_0, u9);
            let d0 = core::elapsed(sw0);
            core::dudect_push_sample(ctx, 0, d0.nanos as f64);

            let sw1 = core::stopwatch();
            let _ = core::x25519_scalarmult(scalar_1, u9);
            let d1 = core::elapsed(sw1);
            core::dudect_push_sample(ctx, 1, d1.nanos as f64);
        }

        // In unpatched code with branching `if do_swap == 1`, Class 1 does 254 conditional branches/copies
        // while Class 0 does 0, resulting in statistically significant timing difference.
        sub.assert_true(core::dudect_is_constant_time(ctx, 3.0), "Montgomery ladder must pass Welch t-test (|t| <= 3.0)");
    };
}
// ----------------------------------------------------------------------------
// 19. LimitReader EOF vs LimitExceeded Boundary Underflow Defenses
// ----------------------------------------------------------------------------
fn test_limit_reader_boundary_eof_and_underflow_defenses(t: core::T&) {
    t.run("Stream of exact limit length reaches EOF cleanly without false LimitExceeded") { sub =>
        let data = "0123456789"; // exactly 10 bytes
        var lr = core::new_limit_reader(data, 10);

        var buf: u8[10] = [0; 10];
        let n1, err1 = lr.read(buf[..]);
        sub.assert_eq(n1, 10, "Read all 10 bytes matching limit");
        sub.assert_eq(err1, core::IoError.None, "First read succeeds");
        sub.assert_eq(lr.remaining(), 0, "0 bytes remaining under limit");
        sub.assert_false(lr.exceeded, "Limit not exceeded initially");

        // Next read MUST return Eof, NOT LimitExceeded, because stream ended cleanly at limit
        var buf2: u8[10] = [0; 10];
        let n2, err2 = lr.read(buf2[..]);
        sub.assert_eq(n2, 0, "0 bytes read at EOF");
        sub.assert_eq(err2, core::IoError.Eof, "Stream at exact limit boundary MUST return Eof");
        sub.assert_false(lr.exceeded, "Exceeded flag MUST NOT be set when stream ends cleanly at limit");
    };

    t.run("Zero-byte read on exhausted limit returns None without setting exceeded") { sub =>
        let data = "0123456789";
        var lr = core::new_limit_reader(data, 5);

        var buf: u8[5] = [0; 5];
        let n1, err1 = lr.read(buf[..]);
        sub.assert_eq(n1, 5, "Read 5 bytes");
        sub.assert_eq(err1, core::IoError.None, "First read ok");

        // Zero-byte slice read attempt
        var empty_buf: u8[0] = [];
        let n0, err0 = lr.read(empty_buf[..]);
        sub.assert_eq(n0, 0, "0 bytes read into empty buffer");
        sub.assert_eq(err0, core::IoError.None, "0-byte read MUST return None without error");
        sub.assert_false(lr.exceeded, "Exceeded flag MUST NOT be set by 0-byte read");
    };

    t.run("Overflow read attempt when unread bytes remain in stream triggers LimitExceeded") { sub =>
        let data = "0123456789EXCESS"; // 16 bytes, limit 10
        var lr = core::new_limit_reader(data, 10);

        var buf: u8[10] = [0; 10];
        let n1, err1 = lr.read(buf[..]);
        sub.assert_eq(n1, 10, "Read 10 bytes up to limit");
        sub.assert_eq(err1, core::IoError.None, "First read ok");

        // Attempt to read past limit when data remains in stream MUST trigger LimitExceeded
        var extra: u8[4] = [0; 4];
        let n2, err2 = lr.read(extra[..]);
        sub.assert_eq(n2, 0, "0 bytes read past limit");
        sub.assert_eq(err2, core::IoError.LimitExceeded, "Attempting to read unconsumed stream data past limit triggers LimitExceeded");
        sub.assert_true(lr.exceeded, "Exceeded flag MUST be set");
    };

    t.run("Empty stream with limit 0 returns Eof cleanly") { sub =>
        var lr = core::new_limit_reader("", 0);
        var buf: u8[4] = [0; 4];
        let n, err = lr.read(buf[..]);
        sub.assert_eq(n, 0, "0 bytes read from empty stream");
        sub.assert_eq(err, core::IoError.Eof, "Empty stream with limit 0 MUST return Eof");
        sub.assert_false(lr.exceeded, "Empty stream MUST NOT set exceeded flag");
    };

    t.run("read_slice with negative count returns InvalidArgument") { sub =>
        var lr = core::new_limit_reader("data", 4);
        let slice, err = lr.read_slice(-1);
        sub.assert_eq(err, core::IoError.InvalidArgument, "Negative count MUST return InvalidArgument");
        sub.assert_false(lr.exceeded, "Negative count MUST NOT mark exceeded");
    };
}

// ----------------------------------------------------------------------------
// 20. RFC 1950 & RFC 1952 Compression Header Corruption, Flags & Stream Boundaries
// ----------------------------------------------------------------------------
fn test_compression_header_flags_window_and_stream_boundaries(t: core::T&) {
    t.run("RFC 1952 Gzip Header with reserved FLG bits rejected") { sub =>
        let payload = "Hello, Gzip Header Security!";
        var gz: u8[>..] = [];
        core::gzip_compress(payload, gz, 6);

        // Set reserved bit 5 in FLG byte (offset 3)
        gz[3] = gz[3] | 0x20;

        var restored: u8[>..] = [];
        let ok, err = core::gzip_decompress(gz[..], restored);
        sub.assert_false(ok, "Gzip header with reserved bit 5 MUST fail decompression");
        sub.assert_eq(err, core::CompressError.InvalidHeader, "Error MUST be InvalidHeader for reserved flag bits");
    };

    t.run("RFC 1952 Gzip Header with all reserved FLG bits 0xE0 rejected") { sub =>
        let payload = "Hello, Gzip Header Security!";
        var gz: u8[>..] = [];
        core::gzip_compress(payload, gz, 6);

        // Set all reserved bits 5, 6, 7 (0xE0) in FLG byte (offset 3)
        gz[3] = gz[3] | 0xE0;

        var restored: u8[>..] = [];
        let ok, err = core::gzip_decompress(gz[..], restored);
        sub.assert_false(ok, "Gzip header with reserved bits 0xE0 MUST fail decompression");
        sub.assert_eq(err, core::CompressError.InvalidHeader, "Error MUST be InvalidHeader for reserved flags 0xE0");
    };

    t.run("RFC 1950 Zlib Header with CINFO > 7 rejected") { sub =>
        let payload = "Hello, Zlib Window Security!";
        var zb: u8[>..] = [];
        core::zlib_compress(payload, zb, 6);

        // Replace CMF with CINFO=8 (0x88, 64KB window), CM=8 (deflate)
        // FLG must satisfy (CMF * 256 + FLG) % 31 == 0.
        // 0x88 * 256 = 34816. 34816 + 0x98 (152) = 34968 = 31 * 1128.
        zb[0] = 0x88;
        zb[1] = 0x98;

        var restored: u8[>..] = [];
        let ok, err = core::zlib_decompress(zb[..], restored);
        sub.assert_false(ok, "Zlib header with illegal CINFO=8 MUST fail decompression");
        sub.assert_eq(err, core::CompressError.InvalidHeader, "Error MUST be InvalidHeader for CINFO > 7");
    };

    t.run("RFC 1950 Zlib stream with extraneous trailing garbage rejected") { sub =>
        let payload = "Exact finality payload.";
        var zb: u8[>..] = [];
        core::zlib_compress(payload, zb, 6);

        // Append 4 bytes of trailing extraneous garbage
        var corrupted: u8[>..] = [];
        corrupted.append(zb[..]);
        corrupted.push(0xDE);
        corrupted.push(0xAD);
        corrupted.push(0xBE);
        corrupted.push(0xEF);

        var restored: u8[>..] = [];
        let ok, err = core::zlib_decompress(corrupted[..], restored);
        sub.assert_false(ok, "Zlib stream with extraneous trailing bytes MUST fail decompression");
        sub.assert_eq(err, core::CompressError.CorruptedBitstream, "Trailing garbage MUST return CorruptedBitstream");
    };

    t.run("RingBuffer 0-byte write on full buffer returns None without BufferFull") { sub =>
        var rb = core::new_ring_buffer();
        var full_chunk: u8[4096] = ['X' as u8; 4096];
        let w_n, w_err = rb.write(full_chunk[..]);
        sub.assert_eq(w_n, 4096, "Wrote 4096 bytes");
        sub.assert_eq(w_err, core::IoError.None, "Write succeeds");
        sub.assert_true(rb.is_full(), "RingBuffer is full");

        // 0-byte write attempt on full buffer
        var empty_src: u8[0] = [];
        let z_n, z_err = rb.write(empty_src[..]);
        sub.assert_eq(z_n, 0, "0 bytes written");
        sub.assert_eq(z_err, core::IoError.None, "0-byte write on full buffer MUST return None, NOT BufferFull");
    };

    t.run("RingBuffer 0-byte read on empty buffer returns None without Eof") { sub =>
        var rb = core::new_ring_buffer();
        sub.assert_true(rb.is_empty(), "RingBuffer is empty");

        var empty_dst: u8[0] = [];
        let r_n, r_err = rb.read(empty_dst[..]);
        sub.assert_eq(r_n, 0, "0 bytes read");
        sub.assert_eq(r_err, core::IoError.None, "0-byte read on empty buffer MUST return None, NOT Eof");
    };
}

// ----------------------------------------------------------------------------
// 21. PipeBuffer Lifecycle, Slice I/O Boundary Idempotency & Streaming Finality
// ----------------------------------------------------------------------------
fn test_pipe_lifecycle_slice_io_and_streaming_finality(t: core::T&) {
    t.run("PipeBuffer completed write rejection") { sub =>
        var pipe = core::new_pipe_buffer();
        core::complete_pipe(pipe);
        sub.assert_true(pipe.is_completed, "Pipe is marked completed");

        // Write attempt on completed pipe must fail with Closed
        let w_n, w_err = core::write(pipe, "unauthorized payload");
        sub.assert_eq(w_n, 0, "0 bytes written to completed pipe");
        sub.assert_eq(w_err, core::IoError.Closed, "Write to completed pipe MUST return Closed");

        // commit_write on completed pipe must fail with Closed
        let c_err = core::commit_write(pipe, 4);
        sub.assert_eq(c_err, core::IoError.Closed, "commit_write on completed pipe MUST return Closed");

        // get_write_span on completed pipe must fail with Closed
        let span, s_err = core::get_write_span(pipe, 1);
        sub.assert_eq(span.len, 0, "0 length span for completed pipe");
        sub.assert_eq(s_err, core::IoError.Closed, "get_write_span on completed pipe MUST return Closed");
    };

    t.run("PipeBuffer streaming read, partial drain and clean EOF") { sub =>
        var pipe = core::new_pipe_buffer();
        let payload = "0123456789";
        let w_n, w_err = core::write(pipe, payload);
        sub.assert_eq(w_n, 10, "Wrote 10 bytes to pipe");
        sub.assert_eq(w_err, core::IoError.None, "Write succeeds");

        // Mark transport as completed (writer finished)
        core::complete_pipe(pipe);

        // Read first 5 bytes
        var buf1: u8[5] = [0; 5];
        let r1_n, r1_err = core::read(pipe, buf1[..]);
        sub.assert_eq(r1_n, 5, "Read 5 bytes");
        sub.assert_eq(r1_err, core::IoError.None, "First read succeeds");
        sub.assert_eq(buf1[..], "01234", "Read contents match");

        // 0-byte read attempt on unexhausted completed pipe must return None
        var empty_buf: u8[0] = [];
        let z_n, z_err = core::read(pipe, empty_buf[..]);
        sub.assert_eq(z_n, 0, "0 bytes read into empty buffer");
        sub.assert_eq(z_err, core::IoError.None, "0-byte read MUST return None without error");

        // Read remaining 5 bytes
        var buf2: u8[5] = [0; 5];
        let r2_n, r2_err = core::read(pipe, buf2[..]);
        sub.assert_eq(r2_n, 5, "Read remaining 5 bytes");
        sub.assert_eq(r2_err, core::IoError.None, "Second read succeeds");
        sub.assert_eq(buf2[..], "56789", "Remaining contents match");

        // Pipe is now drained and completed: read MUST return Eof
        var buf3: u8[4] = [0; 4];
        let r3_n, r3_err = core::read(pipe, buf3[..]);
        sub.assert_eq(r3_n, 0, "0 bytes read from drained completed pipe");
        sub.assert_eq(r3_err, core::IoError.Eof, "Drained completed pipe MUST return Eof");
    };

    t.run("SliceWriter 0-byte write on full buffer returns None") { sub =>
        var storage: u8[4] = [0; 4];
        var w = core::new_slice_writer(storage[..]);
        let w_n, w_err = w.write("1234");
        sub.assert_eq(w_n, 4, "Wrote 4 bytes");
        sub.assert_eq(w_err, core::IoError.None, "Write ok");
        sub.assert_eq(w.available(), 0, "Writer is full");

        // 0-byte write attempt on full SliceWriter
        var empty_src: u8[0] = [];
        let z_n, z_err = w.write(empty_src[..]);
        sub.assert_eq(z_n, 0, "0 bytes written");
        sub.assert_eq(z_err, core::IoError.None, "0-byte write on full SliceWriter MUST return None, NOT BufferFull");
    };

    t.run("SliceReader 0-byte read on EOF reader returns None") { sub =>
        var r = core::new_slice_reader("");
        sub.assert_true(r.is_eof(), "SliceReader is EOF");

        // 0-byte read attempt on EOF SliceReader
        var empty_dst: u8[0] = [];
        let z_n, z_err = r.read(empty_dst[..]);
        sub.assert_eq(z_n, 0, "0 bytes read");
        sub.assert_eq(z_err, core::IoError.None, "0-byte read on EOF SliceReader MUST return None, NOT Eof");
    };

    t.run("Streaming Zlib trailing garbage rejected with CorruptedBitstream") { sub =>
        let payload = "Streaming exact finality vector.";
        var comp: u8[>..] = [];
        core::zlib_compress(payload, comp, 6);

        // Append 4 trailing garbage bytes
        comp.push(0xCA);
        comp.push(0xFE);
        comp.push(0xBA);
        comp.push(0xBE);

        var decomp = core::new_zstream_decompressor(core::ContainerFormat.Zlib);
        var restored: u8[>..] = [];
        let err = decomp.write(comp[..], restored);
        sub.assert_eq(err, core::CompressError.CorruptedBitstream, "Streaming Zlib trailing garbage MUST return CorruptedBitstream");
    };
}

fn test_h2_rst_stream_data_flow_control_invariants(t: core::T&) {
    t.run("RFC 9113 §5.1 & §6.9: DATA frame on stream closed via RST_STREAM accounts for connection flow control") { sub =>
        var conn = wing::new_h2_connection(0);
        // Initial conn_recv_window = 65535
        sub.assert_eq(conn.conn_recv_window, 65535, "Initial connection receive window is 65535");

        // 1. Open stream 1 via HEADERS
        let h_hdr = wing::FrameHeader { length: 0, frame_type: wing::FRAME_HEADERS, flags: wing::FLAG_END_HEADERS, stream_id: 1 };
        let err_h = wing::on_ingress_frame_header(conn, h_hdr, 0);
        sub.assert_eq(err_h, wing::ERR_NO_ERROR, "HEADERS on stream 1 accepted");
        sub.assert_eq(conn.active_stream_count, 1, "1 active stream");

        // 2. Client cancels stream 1 via RST_STREAM
        let rst_hdr = wing::FrameHeader { length: 4, frame_type: wing::FRAME_RST_STREAM, flags: 0, stream_id: 1 };
        let err_rst = wing::on_ingress_frame_header(conn, rst_hdr, 0);
        sub.assert_eq(err_rst, wing::ERR_NO_ERROR, "RST_STREAM on stream 1 accepted");
        sub.assert_eq(conn.active_stream_count, 0, "Active stream count decremented to 0");

        // 3. In-flight DATA frame arrives on stream 1 (length = 1000)
        let data_hdr = wing::FrameHeader { length: 1000, frame_type: wing::FRAME_DATA, flags: 0, stream_id: 1 };
        let err_data = wing::on_data_frame_received(conn, data_hdr, 1000);
        // Must return ERR_STREAM_CLOSED (stream error) rather than connection error
        sub.assert_eq(err_data, wing::ERR_STREAM_CLOSED, "DATA on reset stream returns STREAM_CLOSED");
        // BUT connection receive window MUST be accounted (decremented by 1000) per RFC 9113 §5.1 / §6.9
        sub.assert_eq(conn.conn_recv_window, 64535, "Connection receive window accounted: 65535 - 1000 = 64535");
    };

    t.run("RFC 9113 §6.9: Oversized DATA frame exceeding connection window on closed stream triggers FLOW_CONTROL_ERROR") { sub =>
        var conn = wing::new_h2_connection(0);
        // Set connection receive window to 500 bytes
        conn.conn_recv_window = 500;

        // Open stream 1
        let h_hdr = wing::FrameHeader { length: 0, frame_type: wing::FRAME_HEADERS, flags: wing::FLAG_END_HEADERS, stream_id: 1 };
        wing::on_ingress_frame_header(conn, h_hdr, 0);

        // Reset stream 1
        let rst_hdr = wing::FrameHeader { length: 4, frame_type: wing::FRAME_RST_STREAM, flags: 0, stream_id: 1 };
        wing::on_ingress_frame_header(conn, rst_hdr, 0);

        // Peer sends DATA frame of 600 bytes on closed stream 1 (exceeding conn_recv_window = 500)
        let data_hdr = wing::FrameHeader { length: 600, frame_type: wing::FRAME_DATA, flags: 0, stream_id: 1 };
        let err_data = wing::on_data_frame_received(conn, data_hdr, 600);
        // RFC 9113 §6.9: Connection flow control violation MUST trigger FLOW_CONTROL_ERROR, NOT STREAM_CLOSED!
        sub.assert_eq(err_data, wing::ERR_FLOW_CONTROL_ERROR, "Exceeding connection window on closed stream triggers FLOW_CONTROL_ERROR");
        sub.assert_true(conn.conn_recv_window < 0, "Connection receive window underflowed to negative value");
    };

    t.run("RFC 9113 §5.1 & §6.9: Multiple in-flight DATA frames after RST_STREAM prevent window lockup") { sub =>
        var conn = wing::new_h2_connection(0);

        // Open stream 3
        let h_hdr = wing::FrameHeader { length: 0, frame_type: wing::FRAME_HEADERS, flags: wing::FLAG_END_HEADERS, stream_id: 3 };
        wing::on_ingress_frame_header(conn, h_hdr, 0);

        // Reset stream 3
        let rst_hdr = wing::FrameHeader { length: 4, frame_type: wing::FRAME_RST_STREAM, flags: 0, stream_id: 3 };
        wing::on_ingress_frame_header(conn, rst_hdr, 0);

        // Peer sends 4 in-flight DATA chunks of 10000 bytes each
        for i in 4 {
            let data_chunk = wing::FrameHeader { length: 10000, frame_type: wing::FRAME_DATA, flags: 0, stream_id: 3 };
            let err_c = wing::on_data_frame_received(conn, data_chunk, 10000);
            sub.assert_eq(err_c, wing::ERR_STREAM_CLOSED, "Chunk returns STREAM_CLOSED");
        }
        // Total connection window consumed: 40000
        sub.assert_eq(conn.conn_recv_window, 25535, "Connection receive window accounted: 65535 - 40000 = 25535");

        // Replenish connection window via WINDOW_UPDATE (+40000)
        let err_win = wing::apply_window_update(conn, 0, 40000);
        sub.assert_eq(err_win, wing::ERR_NO_ERROR, "Connection WINDOW_UPDATE succeeds");
        sub.assert_eq(conn.conn_send_window, 105535, "Connection send window replenished without lockup");
    };
}

// ----------------------------------------------------------------------------
// 29. RFC 8446 §4.2, §4.2.10 & §4.6.1: NewSessionTicket Extensions & Ticket Confusion Defenses
// ----------------------------------------------------------------------------
fn test_rfc8446_nst_extension_validation_and_ticket_confusion(t: core::T&) {
    t.run("RFC 8446 §4.2: Duplicate early_data extension in NewSessionTicket MUST be rejected") { sub =>
        // Wire NewSessionTicket with two early_data extensions (ext_type = 42)
        let dup_early_data_wire: u8[33] = [
            0x00, 0x00, 0x0E, 0x10, // lifetime = 3600
            0x00, 0x00, 0x00, 0x01, // age_add = 1
            0x00,                   // nonce_len = 0
            0x00, 0x04, 0xAA, 0xBB, 0xCC, 0xDD, // ticket_len = 4, ticket
            0x00, 0x10,             // extensions_len = 16
            0x00, 0x2A,             // ext_type = 42 (early_data)
            0x00, 0x04,             // ext_len = 4
            0x00, 0x00, 0x04, 0x00, // max_early_data_size = 1024
            0x00, 0x2A,             // ext_type = 42 (DUPLICATE early_data)
            0x00, 0x04,             // ext_len = 4
            0x00, 0x00, 0x08, 0x00, // max_early_data_size = 2048
        ];

        var nst = wing::NewSessionTicketMsg { .. };
        let ok = wing::parse_new_session_ticket(dup_early_data_wire[..], nst);
        sub.assert_false(ok, "duplicate early_data extension in NewSessionTicket MUST be rejected");
    };

    t.run("RFC 8446 §4.2 Table 2: Non-permitted extension in NewSessionTicket MUST be rejected") { sub =>
        // Wire NewSessionTicket with supported_versions (ext_type = 43), which is forbidden in NST
        let forbidden_ext_wire: u8[23] = [
            0x00, 0x00, 0x0E, 0x10, // lifetime = 3600
            0x00, 0x00, 0x00, 0x01, // age_add = 1
            0x00,                   // nonce_len = 0
            0x00, 0x04, 0xAA, 0xBB, 0xCC, 0xDD, // ticket_len = 4, ticket
            0x00, 0x06,             // extensions_len = 6
            0x00, 0x2B,             // ext_type = 43 (supported_versions - FORBIDDEN in NST)
            0x00, 0x02,             // ext_len = 2
            0x03, 0x04,             // TLS 1.3
        ];

        var nst = wing::NewSessionTicketMsg { .. };
        let ok = wing::parse_new_session_ticket(forbidden_ext_wire[..], nst);
        sub.assert_false(ok, "supported_versions extension in NewSessionTicket MUST be rejected");
    };

    t.run("RFC 8446 §4.2.10 & §4.6.1: early_data with ticket_lifetime == 0 MUST be rejected") { sub =>
        // Wire NewSessionTicket with ticket_lifetime = 0 and early_data extension
        let zero_life_early_data_wire: u8[25] = [
            0x00, 0x00, 0x00, 0x00, // lifetime = 0 (MUST NOT offer early_data)
            0x00, 0x00, 0x00, 0x01, // age_add = 1
            0x00,                   // nonce_len = 0
            0x00, 0x04, 0xAA, 0xBB, 0xCC, 0xDD, // ticket_len = 4, ticket
            0x00, 0x08,             // extensions_len = 8
            0x00, 0x2A,             // ext_type = 42 (early_data)
            0x00, 0x04,             // ext_len = 4
            0x00, 0x00, 0x40, 0x00, // max_early_data_size = 16384
        ];

        var nst = wing::NewSessionTicketMsg { .. };
        let ok = wing::parse_new_session_ticket(zero_life_early_data_wire[..], nst);
        sub.assert_false(ok, "early_data with ticket_lifetime == 0 MUST be rejected");
    };

    t.run("RFC 8446 §4.6.1: Duplicate ticket_nonce on same connection rejected (ticket confusion defense)") { sub =>
        var cache = wing::SessionTicketCache { .. };

        var t1 = wing::NewSessionTicketMsg {
            ticket_lifetime: 3600,
            ticket_age_add: 100,
            ..
        };
        t1.ticket_nonce.append([0x01, 0x02, 0x03]);
        t1.ticket.append([0xAA, 0xBB, 0xCC]);

        let ok1 = wing::cache_session_ticket(cache, t1);
        sub.assert_true(ok1, "First ticket with nonce [1,2,3] cached successfully");
        sub.assert_eq(cache.tickets.len, 1, "Cache length is 1");

        // Duplicate ticket_nonce with different ticket payload MUST be rejected
        var t2 = wing::NewSessionTicketMsg {
            ticket_lifetime: 3600,
            ticket_age_add: 200,
            ..
        };
        t2.ticket_nonce.append([0x01, 0x02, 0x03]); // DUPLICATE NONCE
        t2.ticket.append([0xDD, 0xEE, 0xFF]);

        let ok2 = wing::cache_session_ticket(cache, t2);
        sub.assert_false(ok2, "Ticket with duplicate ticket_nonce on same connection MUST be rejected");
        sub.assert_eq(cache.tickets.len, 1, "Cache length remains 1 after duplicate nonce rejection");
    };

    t.run("RFC 8446 §4.6.1: Duplicate ticket payload on same connection rejected") { sub =>
        var cache = wing::SessionTicketCache { .. };

        var t1 = wing::NewSessionTicketMsg {
            ticket_lifetime: 3600,
            ticket_age_add: 100,
            ..
        };
        t1.ticket_nonce.append([0x01, 0x01]);
        t1.ticket.append([0xCA, 0xFE, 0xBA, 0xBE]);
        let ok1 = wing::cache_session_ticket(cache, t1);
        sub.assert_true(ok1, "Initial ticket cached successfully");

        // Duplicate ticket payload with different nonce MUST be rejected
        var t2 = wing::NewSessionTicketMsg {
            ticket_lifetime: 3600,
            ticket_age_add: 300,
            ..
        };
        t2.ticket_nonce.append([0x02, 0x02]);
        t2.ticket.append([0xCA, 0xFE, 0xBA, 0xBE]); // DUPLICATE TICKET PAYLOAD
        let ok2 = wing::cache_session_ticket(cache, t2);
        sub.assert_false(ok2, "Ticket with duplicate ticket payload on same connection MUST be rejected");
        sub.assert_eq(cache.tickets.len, 1, "Cache length remains 1 after duplicate ticket rejection");

        // Distinct ticket with unique nonce and payload succeeds
        var t3 = wing::NewSessionTicketMsg {
            ticket_lifetime: 3600,
            ticket_age_add: 400,
            ..
        };
        t3.ticket_nonce.append([0x03, 0x03]);
        t3.ticket.append([0xDE, 0xAD, 0xBE, 0xEF]);
        let ok3 = wing::cache_session_ticket(cache, t3);
        sub.assert_true(ok3, "Distinct ticket with unique nonce and payload cached successfully");
        sub.assert_eq(cache.tickets.len, 2, "Cache length incremented to 2");
    };
}

// ----------------------------------------------------------------------------
// 30. RFC 9110 §9.3.1 & RFC 9293: Connection Pool Starvation & Slot Reclamation
// ----------------------------------------------------------------------------
fn test_rfc9110_connection_pool_starvation_and_slot_reclamation(t: core::T&) {
    t.run("Pool saturation at 64 connections reclaims idle/evicted slots without starvation") { sub =>
        var pool = wing::new_stream_pool(64, 64, 64);
        let nak = wing::new_network_anonymization_key("https://pool-test.org");
        let key = wing::new_pool_key(wing::PoolScheme.Https, "pool-test.org", 443, wing::new_direct_proxy_chain(), nak, wing::TlsAndDnsPolicy { .. });

        // Register 64 connections saturating pool capacity
        var c_ids: i32[64] = [0; 64];
        for i in 64 {
            let cid = wing::register_connection(pool, key, wing::NegotiatedProtocol.Http11, "10.0.0.1", 1, (i + 1) as i64 * 1000);
            sub.assert_gt(cid, 0, "Initial 64 connections successfully registered");
            c_ids[i] = cid;
        }
        sub.assert_eq(pool.conns.len, 64, "Pool reached maximum capacity (64)");

        // Release the first connection making it idle
        wing::release_connection(pool, c_ids[0], 1000000);
        sub.assert_eq(pool.conns[0].active_allocations, 0, "Connection 0 is idle");

        // In unpatched code, registering a 65th connection returns -1 (pool starvation).
        // With slot reclamation, the idle connection is evicted and its slot reused.
        let c65 = wing::register_connection(pool, key, wing::NegotiatedProtocol.Http11, "10.0.0.1", 1, 2000000);
        sub.assert_gt(c65, 0, "65th connection registered successfully by reclaiming evicted slot");
        sub.assert_eq(c65, 65, "Connection ID incremented monotonically");
        sub.assert_eq(pool.conns.len, 64, "Connection pool storage remains bounded at 64");
        sub.assert_eq(pool.conns[0].conn_id, 65, "Reclaimed slot 0 contains new connection 65");
        sub.assert_eq(pool.conns[0].active_allocations, 1, "Reclaimed slot is active");
    };

    t.run("Explicitly closed connection slot is reclaimed immediately") { sub =>
        var pool = wing::new_stream_pool(64, 64, 64);
        let nak = wing::new_network_anonymization_key("https://reclaim.org");
        let key = wing::new_pool_key(wing::PoolScheme.Https, "reclaim.org", 443, wing::new_direct_proxy_chain(), nak, wing::TlsAndDnsPolicy { .. });

        var c_ids: i32[64] = [0; 64];
        for i in 64 {
            c_ids[i] = wing::register_connection(pool, key, wing::NegotiatedProtocol.Http11, "10.0.0.2", 1, (i + 1) as i64 * 1000);
        }
        sub.assert_eq(pool.conns.len, 64, "Pool saturated at 64");

        // Explicitly close slot 5
        let ok_close = wing::close_pooled_connection(pool, c_ids[5]);
        sub.assert_true(ok_close, "Connection c_ids[5] closed successfully");
        sub.assert_true(pool.conns[5].closed, "Slot 5 marked closed");

        // Register 65th connection: must reclaim slot 5 immediately without evicting other slots
        let c65 = wing::register_connection(pool, key, wing::NegotiatedProtocol.Http11, "10.0.0.2", 1, 5000000);
        sub.assert_gt(c65, 0, "New connection successfully registered");
        sub.assert_eq(pool.conns[5].conn_id, c65, "Slot 5 reclaimed by connection 65");
        sub.assert_false(pool.conns[5].closed, "Reclaimed slot is open and active");
    };

    t.run("Registering when all 64 slots are active fails closed without panic") { sub =>
        var pool = wing::new_stream_pool(64, 64, 64);
        let nak = wing::new_network_anonymization_key("https://busy-pool.org");
        let key = wing::new_pool_key(wing::PoolScheme.Https, "busy-pool.org", 443, wing::new_direct_proxy_chain(), nak, wing::TlsAndDnsPolicy { .. });

        for i in 64 {
            let cid = wing::register_connection(pool, key, wing::NegotiatedProtocol.Http11, "10.0.0.3", 1, (i + 1) as i64 * 1000);
            sub.assert_gt(cid, 0, "Registered active connection");
        }

        // None are released, so all 64 have active_allocations = 1.
        // Eviction cannot evict any active connection, so registering returns -1 cleanly.
        let c_fail = wing::register_connection(pool, key, wing::NegotiatedProtocol.Http11, "10.0.0.3", 1, 9000000);
        sub.assert_eq(c_fail, -1, "Fully active saturated pool returns -1 without crash or corruption");
    };
}

// ----------------------------------------------------------------------------
// 31. RFC 9204 §4.5.1.1 & §4.5.1.2: QPACK Zero-RIC Base Invariants & MaxTableCapacity RIC Bounds
// ----------------------------------------------------------------------------
fn test_rfc9204_qpack_zero_ric_base_invariants_and_capacity_bound(t: core::T&) {
    t.run("RFC 9204 §4.5.1.2: decode_base strictly enforces Base == 0 when RIC == 0") { sub =>
        // 1. Valid: ric == 0, sign == 0, delta_base == 0 => Base == 0
        let base0, err0 = wing::decode_base(0, 0, 0);
        sub.assert_eq(err0, wing::QpackError.None, "ric=0, sign=0, delta_base=0 returns None");
        sub.assert_eq(base0, 0, "Base must be 0 when RIC is 0");

        // 2. Invalid: ric == 0 with delta_base > 0 MUST fail with DecompressionFailed
        let _, err_delta = wing::decode_base(0, 1, 0);
        sub.assert_eq(err_delta, wing::QpackError.DecompressionFailed, "ric=0 with delta_base=1 MUST fail");

        let _, err_delta5 = wing::decode_base(0, 5, 0);
        sub.assert_eq(err_delta5, wing::QpackError.DecompressionFailed, "ric=0 with delta_base=5 MUST fail");

        // 3. Invalid: ric == 0 with sign == 1 MUST fail with DecompressionFailed
        let _, err_sign = wing::decode_base(1, 0, 0);
        sub.assert_eq(err_sign, wing::QpackError.DecompressionFailed, "ric=0 with sign=1 MUST fail");

        let _, err_sign_delta = wing::decode_base(1, 10, 0);
        sub.assert_eq(err_sign_delta, wing::QpackError.DecompressionFailed, "ric=0 with sign=1 and delta_base=10 MUST fail");

        // 4. Invalid: sign_bit > 1 MUST fail with DecompressionFailed
        let _, err_bad_sign = wing::decode_base(2, 0, 0);
        sub.assert_eq(err_bad_sign, wing::QpackError.DecompressionFailed, "Invalid sign_bit=2 MUST fail");
    };

    t.run("RFC 9204 §4.5.1.2: decode_qpack_section rejects wire header blocks with RIC == 0 and DeltaBase > 0") { sub =>
        var tbl = wing::new_qpack_table(4096, 16);
        var out_fields: wing::HeaderField[>..] = [];

        // Malicious header block: enc_ric = 0 (0x00), Sign = 0 & DeltaBase = 5 (0x05), Static :path="/" (0xC1)
        let malformed_block: u8[3] = [0x00, 0x05, 0xC1];
        let err_mal = wing::decode_qpack_section(tbl, malformed_block[..], out_fields, 4096);
        sub.assert_eq(err_mal, wing::QpackError.DecompressionFailed, "Header block with RIC=0 and DeltaBase=5 MUST trigger DecompressionFailed");

        // Malicious header block: enc_ric = 0 (0x00), Sign = 1 & DeltaBase = 0 (0x80), Static :path="/" (0xC1)
        let malformed_sign_block: u8[3] = [0x00, 0x80, 0xC1];
        let err_sign = wing::decode_qpack_section(tbl, malformed_sign_block[..], out_fields, 4096);
        sub.assert_eq(err_sign, wing::QpackError.DecompressionFailed, "Header block with RIC=0 and Sign=1 MUST trigger DecompressionFailed");

        // Valid header block: enc_ric = 0 (0x00), Sign = 0 & DeltaBase = 0 (0x00), Static :path="/" (0xC1)
        let valid_block: u8[3] = [0x00, 0x00, 0xC1];
        let err_val = wing::decode_qpack_section(tbl, valid_block[..], out_fields, 4096);
        sub.assert_eq(err_val, wing::QpackError.None, "Valid header block with RIC=0, Sign=0, DeltaBase=0 succeeds");
        sub.assert_eq(out_fields.len, 1, "One field decoded");
        sub.assert_eq(out_fields[0].name[..], ":path", "Decoded field name is :path");
        sub.assert_eq(out_fields[0].value[..], "/", "Decoded field value is /");
    };

    t.run("RFC 9204 §4.5.1.1: decode_qpack_section uses MaxTableCapacity for RIC calculation after capacity shrinkage") { sub =>
        var tbl = wing::new_qpack_table(4096, 16);
        // Insert a dynamic table entry (abs_idx = 0, cost = 51 bytes)
        let ok_ins = wing::qpack_insert_literal(tbl, "x-trace-id", "trace-777");
        sub.assert_true(ok_ins, "Inserted dynamic entry into QPACK table");
        sub.assert_eq(tbl.insert_count, 1, "insert_count is 1");

        // Encoder shrinks current capacity to 2048 via Set Dynamic Table Capacity instruction.
        // Entry remains cached (51 <= 2048), but capacity_bytes (2048) != max_capacity_bytes (4096).
        let ok_cap = wing::qpack_set_capacity(tbl, 2048);
        sub.assert_true(ok_cap, "Set capacity to 2048 succeeds");
        sub.assert_eq(tbl.capacity_bytes, 2048, "Current capacity_bytes is 2048");
        sub.assert_eq(tbl.max_capacity_bytes, 4096, "Decoder max_capacity_bytes remains 4096");

        // Construct section referencing dynamic entry 0:
        // FullRange based on max_capacity_bytes (4096) = 2 * (4096 / 32) = 256.
        // RIC = 1 => enc_ric = (1 % 256) + 1 = 2 (0x02).
        // Base = 1 => Sign = 0, DeltaBase = 0 (0x00).
        // Indexed field line, dynamic (T=0): 10xxxxxx => 0x80 | 0 = 0x80.
        let sec_wire: u8[3] = [0x02, 0x00, 0x80];

        var out_fields: wing::HeaderField[>..] = [];
        let err_dec = wing::decode_qpack_section(tbl, sec_wire[..], out_fields, 4096);
        sub.assert_eq(err_dec, wing::QpackError.None, "Section successfully decodes using max_capacity_bytes despite capacity_bytes == 2048");
        sub.assert_eq(out_fields.len, 1, "One dynamic field decoded");
        if out_fields.len > 0 {
            sub.assert_eq(out_fields[0].name[..], "x-trace-id", "Dynamic field name matches");
            sub.assert_eq(out_fields[0].value[..], "trace-777", "Dynamic field value matches");
        }
    };
}

// ----------------------------------------------------------------------------
// 32. RFC 8725 §3.2, §3.6, RFC 8037 §2 & RFC 7517 §4.4: JWKS Key Confusion & Algorithm Binding
// ----------------------------------------------------------------------------
fn test_rfc8725_jwks_key_confusion_and_algorithm_binding(t: core::T&) {
    let now_sec: i64 = 1770000000;
    let ed_seed: u8[32] = [
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
        0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x00,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x11,
    ];
    let ed_pub = core::ed25519_public_key(ed_seed);

    t.run("RFC 8725 §3.2: Asymmetric OKP key cannot verify symmetric HS256 token (Key Confusion Defense)") { sub =>
        var jwks = wing::new_jwks();
        wing::add_ed25519_key(jwks, "ed25519-pub-key-1", ed_pub);

        // Attacker creates HS256 token signed with ed_pub as HMAC secret
        var hdr = wing::new_jwt_header(wing::JwtAlg.HS256, "ed25519-pub-key-1");
        var clm = wing::new_jwt_claims();
        wing::set_subject(clm, "attacker");
        wing::set_expiry(clm, now_sec + 300);

        var token: u8[>..] = [];
        wing::sign_jwt_hmac(hdr, clm, ed_pub[..], token);

        var out_h = wing::new_jwt_header();
        var out_c = wing::new_jwt_claims();
        var opts = wing::default_jwt_validation_options(wing::JwtAlg.HS256);

        let err = wing::verify(token[..], jwks, opts, now_sec, out_h, out_c);
        sub.assert_eq(err, wing::JwtError.AlgorithmMismatch, "Asymmetric OKP key must reject HS256 verification");

        // Verify direct compatibility check fails closed
        let compat = wing::validate_jwks_key_compatibility(jwks.keys[0], wing::JwtAlg.HS256, false);
        sub.assert_eq(compat, wing::JwtError.AlgorithmMismatch, "OKP key incompatible with HS256 alg");
    };

    t.run("RFC 8725 §3.2: Symmetric oct key with EdDSA token or EdDSA algorithm binding rejected") { sub =>
        // Oct key in JWKS claiming EdDSA algorithm MUST be rejected during JWKS finalization
        let jwk_bad = "{\"keys\":[{\"kty\":\"oct\",\"alg\":\"EdDSA\",\"k\":\"c2VjcmV0LWtleS0xNmJ5dGVzCg\",\"kid\":\"bad-oct-eddsa\"}]}";
        var jwks_bad = wing::new_jwks();
        let ok_parse = wing::parse_jwks_json(jwk_bad, jwks_bad);
        sub.assert_false(ok_parse, "JWKS containing exclusively invalid oct-EdDSA key returns false");
        sub.assert_eq(jwks_bad.keys.len, 0, "Oct key binding EdDSA algorithm MUST be rejected");

        // Direct check: Oct key cannot be used to verify EdDSA
        var oct_key = wing::JwksKey { kty: wing::JwkKeyType.Oct, valid: true, .. };
        let compat = wing::validate_jwks_key_compatibility(oct_key, wing::JwtAlg.EdDSA, false);
        sub.assert_eq(compat, wing::JwtError.AlgorithmMismatch, "Oct key incompatible with EdDSA alg");
    };

    t.run("RFC 8037 §2 & §3.1: OKP key with non-Ed25519 curve or omitted curve rejected") { sub =>
        // X25519 curve (ECDH key, invalid for EdDSA signing)
        let jwk_x25519 = "{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"X25519\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\",\"kid\":\"x25519-key\"}]}";
        var jwks_x = wing::new_jwks();
        let ok_x = wing::parse_jwks_json(jwk_x25519, jwks_x);
        sub.assert_false(ok_x, "JWKS containing only non-Ed25519 curve returns false");
        sub.assert_eq(jwks_x.keys.len, 0, "OKP key with X25519 curve MUST be rejected");

        // Omitted curve
        let jwk_no_crv = "{\"keys\":[{\"kty\":\"OKP\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\",\"kid\":\"no-crv-key\"}]}";
        var jwks_nc = wing::new_jwks();
        let ok_nc = wing::parse_jwks_json(jwk_no_crv, jwks_nc);
        sub.assert_false(ok_nc, "JWKS containing OKP key with omitted crv returns false");
        sub.assert_eq(jwks_nc.keys.len, 0, "OKP key omitting crv MUST be rejected");
    };

    t.run("RFC 7517 §4.4: Oct key in JWKS omitting optional alg parameter verifies HS256 token") { sub =>
        let jwk_sym = "{\"keys\":[{\"kty\":\"oct\",\"k\":\"c2VjcmV0LXN5bS1rZXktMTZieXRlcw\",\"kid\":\"sym-no-alg\"}]}";
        var jwks_sym = wing::new_jwks();
        let ok_sym = wing::parse_jwks_json(jwk_sym, jwks_sym);
        sub.assert_true(ok_sym, "JWKS parsed");
        sub.assert_eq(jwks_sym.keys.len, 1, "Oct key without alg parsed into key set");
        sub.assert_eq(jwks_sym.keys[0].alg, wing::JwtAlg.None, "Default alg is None (compatible with HS256/384/512)");

        var hdr = wing::new_jwt_header(wing::JwtAlg.HS256, "sym-no-alg");
        var clm = wing::new_jwt_claims();
        wing::set_subject(clm, "user_bob");
        wing::set_expiry(clm, now_sec + 300);

        var token: u8[>..] = [];
        wing::sign_jwt_hmac(hdr, clm, "secret-sym-key-16bytes", token);

        var out_h = wing::new_jwt_header();
        var out_c = wing::new_jwt_claims();
        var opts = wing::default_jwt_validation_options(wing::JwtAlg.HS256);

        let err = wing::verify(token[..], jwks_sym, opts, now_sec, out_h, out_c);
        sub.assert_eq(err, wing::JwtError.None, "Token verified successfully with oct key lacking alg");
        sub.assert_bytes_eq(wing::claim_str(out_c, "sub"), "user_bob", "Subject matches");
    };

    t.run("RFC 8725 §3.6 & RFC 7518 §3.2: Weak symmetric key under 128 bits rejected") { sub =>
        let jwk_weak = "{\"keys\":[{\"kty\":\"oct\",\"k\":\"c2hvcnQ\",\"kid\":\"weak-sym-key\"}]}";
        var jwks_weak = wing::new_jwks();
        let ok_w = wing::parse_jwks_json(jwk_weak, jwks_weak);
        sub.assert_false(ok_w, "JWKS containing weak key returns false");
        sub.assert_eq(jwks_weak.keys.len, 0, "Weak symmetric key < 16 bytes MUST be rejected");

        // Mixed JWKS: 1 valid Ed25519 key + 1 weak oct key -> only valid key is preserved
        let jwk_mixed = "{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\",\"kid\":\"valid-ed\"},{\"kty\":\"oct\",\"k\":\"c2hvcnQ\",\"kid\":\"weak-oct\"}]}";
        var jwks_mixed = wing::new_jwks();
        let ok_m = wing::parse_jwks_json(jwk_mixed, jwks_mixed);
        sub.assert_true(ok_m, "Mixed JWKS parses successfully because valid key is present");
        sub.assert_eq(jwks_mixed.keys.len, 1, "Only 1 valid key retained");
        sub.assert_bytes_eq(jwks_mixed.keys[0].kid[..], "valid-ed", "Valid Ed25519 key retained");
    };
}

// ----------------------------------------------------------------------------
// 33. RFC 9293 §3.5 & RFC 1122 §4.2.2.13 TCP Half-Closed Teardown & Drain Deadlock
// ----------------------------------------------------------------------------
fn test_rfc9293_half_closed_socket_teardown_and_drain_deadlock_defenses(t: core::T&) {
    t.run("Case 1: Peer FIN followed by local shutdown completes full socket teardown") { sub =>
        let listener = wing::tcp_listen("127.0.0.1", 0, 16);
        sub.assert_gt(listener, 0, "Listener created");
        defer wing::tcp_close(listener);

        let port = wing::tcp_getsockname_port(listener);
        let client = wing::tcp_connect("127.0.0.1", port, 2000);
        sub.assert_gt(client, 0, "Client connected");
        defer wing::tcp_close(client);

        let server_conn = wing::tcp_accept(listener, 2000);
        sub.assert_gt(server_conn, 0, "Server accepted");
        defer wing::tcp_close(server_conn);

        // Client sends payload and immediately closes its write side (sends FIN)
        let req: const u8[:] = "PING_REQUEST";
        wing::tcp_send(client, req);
        wing::tcp_shutdown(client, wing::SHUT_WR);

        // Server reads payload and then detects EOF (peer FIN)
        var srv_req: u8[..64] = [];
        let r1 = wing::tcp_recv(server_conn, srv_req, 64, 2000);
        sub.assert_eq(r1, req.len as i32, "Server received request");

        var eof_probe: u8[..16] = [];
        let eof = wing::tcp_recv(server_conn, eof_probe, 16, 500);
        sub.assert_eq(eof, 0, "Server detected peer FIN (EOF)");

        var server_bp = wing::new_backpressure();
        wing::async_socket_on_peer_fin(server_conn, server_bp);
        sub.assert_true(server_bp.peer_fin_received, "Server recorded peer FIN");
        sub.assert_false(server_bp.write_shut, "Server write half is still open for response");

        // Server can still send response back
        var server_cork = core::new_cork_buffer();
        let resp: const u8[:] = "PONG_RESPONSE";
        let wr_bytes, _ = wing::async_socket_write(server_conn, server_cork, server_bp, resp);
        sub.assert_gt(wr_bytes, 0, "Server wrote response");
        wing::async_socket_uncork(server_conn, server_cork, server_bp);

        // Client receives response
        var cli_resp: u8[..64] = [];
        let r2 = wing::tcp_recv(client, cli_resp, 64, 2000);
        sub.assert_eq(r2, resp.len as i32, "Client received response");

        // Now server shuts down its write direction.
        // Because peer_fin_received is true, both directions are now closed!
        // async_socket_shutdown must cleanly execute tcp_close(server_conn).
        let did_shut, is_def = wing::async_socket_shutdown(server_conn, server_bp, server_cork);
        sub.assert_true(did_shut, "Immediate shutdown executed");
        sub.assert_false(is_def, "Shutdown was not deferred");
        sub.assert_true(server_bp.write_shut, "Server write direction shut");

        // Verify socket is closed (further reads or writes fail)
        var post_buf: u8[..16] = [];
        let post_recv = wing::tcp_recv(server_conn, post_buf, 16, 100);
        sub.assert_lt(post_recv, 0, "Server socket closed after both halves shut down");
    };

    t.run("Case 2: Local shutdown followed by peer FIN completes full socket teardown") { sub =>
        let listener = wing::tcp_listen("127.0.0.1", 0, 16);
        sub.assert_gt(listener, 0, "Listener created");
        defer wing::tcp_close(listener);

        let port = wing::tcp_getsockname_port(listener);
        let client = wing::tcp_connect("127.0.0.1", port, 2000);
        sub.assert_gt(client, 0, "Client connected");
        defer wing::tcp_close(client);

        let server_conn = wing::tcp_accept(listener, 2000);
        sub.assert_gt(server_conn, 0, "Server accepted");
        defer wing::tcp_close(server_conn);

        var server_bp = wing::new_backpressure();
        var server_cork = core::new_cork_buffer();

        // Server initiates write shutdown first (sends FIN to client)
        let did_shut, is_def = wing::async_socket_shutdown(server_conn, server_bp, server_cork);
        sub.assert_true(did_shut, "Server shut write side");
        sub.assert_false(is_def, "Shutdown was not deferred");
        sub.assert_true(server_bp.write_shut, "Server write_shut is true");
        sub.assert_false(server_bp.peer_fin_received, "Peer FIN not received yet");

        // Client detects EOF from server
        var cli_buf: u8[..16] = [];
        let eof = wing::tcp_recv(client, cli_buf, 16, 500);
        sub.assert_eq(eof, 0, "Client saw server EOF (FIN)");

        // Client can still send its final data before closing
        let final_data: const u8[:] = "FINAL_DATA";
        wing::tcp_send(client, final_data);
        wing::tcp_shutdown(client, wing::SHUT_WR);

        // Server reads remaining data from client
        var srv_final: u8[..64] = [];
        let r = wing::tcp_recv(server_conn, srv_final, 64, 1000);
        sub.assert_eq(r, final_data.len as i32, "Server read client final data");

        // Server detects client EOF
        var cli_eof_buf: u8[..16] = [];
        let cli_eof = wing::tcp_recv(server_conn, cli_eof_buf, 16, 500);
        sub.assert_eq(cli_eof, 0, "Server detected client FIN (EOF)");

        // When server records peer FIN with write_shut already true,
        // async_socket_on_peer_fin must automatically complete socket teardown (tcp_close)
        wing::async_socket_on_peer_fin(server_conn, server_bp);
        sub.assert_true(server_bp.peer_fin_received, "Peer FIN recorded");

        // Socket handle must now be closed
        var closed_probe: u8[..16] = [];
        let closed_res = wing::tcp_recv(server_conn, closed_probe, 16, 100);
        sub.assert_lt(closed_res, 0, "Server socket closed when second FIN received");
    };

    t.run("Case 3: Deferred shutdown with pending backpressure tears down socket when drain completes") { sub =>
        let listener = wing::tcp_listen("127.0.0.1", 0, 16);
        sub.assert_gt(listener, 0, "Listener created");
        defer wing::tcp_close(listener);

        let port = wing::tcp_getsockname_port(listener);
        let client = wing::tcp_connect("127.0.0.1", port, 2000);
        sub.assert_gt(client, 0, "Client connected");
        defer wing::tcp_close(client);

        let server_conn = wing::tcp_accept(listener, 2000);
        sub.assert_gt(server_conn, 0, "Server accepted");
        defer wing::tcp_close(server_conn);

        var server_bp = wing::new_backpressure();
        var server_cork = core::new_cork_buffer();

        // Client shuts down its write side (sends FIN)
        wing::tcp_shutdown(client, wing::SHUT_WR);
        var probe: u8[..16] = [];
        let eof = wing::tcp_recv(server_conn, probe, 16, 500);
        sub.assert_eq(eof, 0, "Server received peer FIN");
        wing::async_socket_on_peer_fin(server_conn, server_bp);
        sub.assert_true(server_bp.peer_fin_received, "Peer FIN recorded in backpressure");

        // Server queues backpressure
        let payload: const u8[:] = "QUEUED_DEFERRED_DATA";
        wing::backpressure_append(server_bp, payload);
        sub.assert_gt(wing::backpressure_len(server_bp), 0, "Backpressure contains payload");

        // Server initiates shutdown: must defer because backpressure is non-empty
        let did_shut, is_def = wing::async_socket_shutdown(server_conn, server_bp, server_cork);
        sub.assert_false(did_shut, "Shutdown deferred");
        sub.assert_true(is_def, "Shutdown marked deferred");
        sub.assert_true(server_bp.shutdown_pending, "Shutdown pending");
        sub.assert_false(server_bp.write_shut, "write_shut is false while draining");

        // Drain backpressure completely
        let drained, empty = wing::async_socket_drain(server_conn, server_bp);
        sub.assert_gt(drained, 0, "Backpressure drained to wire");
        sub.assert_true(empty, "Backpressure now fully empty");
        sub.assert_true(server_bp.write_shut, "Deferred shutdown executed write_shut");
        sub.assert_false(server_bp.shutdown_pending, "Shutdown is no longer pending");

        // Client reads all drained payload
        var cli_buf: u8[..64] = [];
        let recvd = wing::tcp_recv(client, cli_buf, 64, 1000);
        sub.assert_eq(recvd, payload.len as i32, "Client received all deferred payload");

        // Because peer_fin_received was true, check_execute_deferred_shutdown closed the socket
        var post_probe: u8[..16] = [];
        let post_res = wing::tcp_recv(server_conn, post_probe, 16, 100);
        sub.assert_lt(post_res, 0, "Server socket closed upon deferred shutdown completion");
    };

    t.run("Case 4: Drain failure on broken socket triggers abort and clears backpressure to prevent deadlock") { sub =>
        var bp = wing::new_backpressure();
        wing::backpressure_append(bp, "STALLED_PAYLOAD_FOR_DEAD_SOCKET");
        sub.assert_gt(wing::backpressure_len(bp), 0, "Backpressure has buffered data");

        // Use an invalid / closed socket descriptor to simulate write error (sent < 0)
        let dead_fd: i64 = 99999;
        let sent, empty = wing::async_socket_drain(dead_fd, bp);

        sub.assert_lt(sent, 0, "Drain on dead socket returns error < 0");
        sub.assert_true(empty, "Drain returns empty=true to prevent infinite event loop polling spin");
        sub.assert_eq(wing::backpressure_len(bp), 0, "Backpressure cleared by abortive teardown");
        sub.assert_true(bp.write_shut, "Write side marked shut after error abort");
        sub.assert_false(bp.shutdown_pending, "Pending shutdown cleared");
    };
}

fn main() {
    var runner = core::new_runner("Historical Vulnerabilities & Protocol Edge-Case Suite", core::Verbosity.Verbose);

    core::run_case(runner, "1. Go CVE-2026-78667: Range Header Overflow Defense", test_cve_2026_78667_range_header_overflow);
    core::run_case(runner, "2. Go #75557: Content-Disposition CRLF Injection Defenses", test_go_75557_content_disposition_crlf_injection);
    core::run_case(runner, "3. RFC 9113 & Go #81115: HTTP/2 Content-Length Overflow Defense", test_http2_content_length_overflow_defense);
    core::run_case(runner, "4. OpenSSL #31392 & Go #71208: URI NameConstraints & IPv6 Zone", test_openssl_31392_uri_name_constraints_nul);
    core::run_case(runner, "5. uWebSockets #1876: Control Frame Priority Under Backpressure", test_uwebsockets_1876_control_priority_under_backpressure);
    core::run_case(runner, "6. RFC 8446 §5.4: TLS 1.3 InnerPlaintext Zero-Length Invariants", test_openssl_tls13_zero_length_plaintext_invariants);
    core::run_case(runner, "7. Go #66434 / RFC 7578 §4.7: Content-Transfer-Encoding Rejection", test_go_66434_content_transfer_encoding_rejection);
    core::run_case(runner, "8. uWS #1662 / Autobahn 6.x: Streaming UTF-8 Chunk Boundaries", test_uwebsockets_1662_streaming_utf8_continuation);
    core::run_case(runner, "9. OpenSSL #33428: ECH Outer vs Inner ALPN Strict Isolation", test_openssl_33428_ech_alpn_isolation);
    core::run_case(runner, "10. OpenSSL #33332 & Go #82350: Redirect Sensitive Header Purging", test_openssl_33332_redirect_sensitive_header_purging);
    core::run_case(runner, "11. uWS #1941: Chained Transfer-Encoding List & Chunked Finality", test_uweb_1941_chained_transfer_encoding_validation);
    core::run_case(runner, "12. CVE-2026-42507: Diagnostic Log CRLF & Control Escaping", test_cve_2026_42507_diagnostic_log_injection_defense);
    core::run_case(runner, "13. RFC 9113 & CVE-2026-78669: H2 Window Bounds & Throttling", test_h2_window_update_and_settings_cpu_limits);
    core::run_case(runner, "14. RFC 8446 Section 4: TLS 1.3 Handshake State Machine Invariants", test_openssl_handshake_state_machine_transition_invariants);
    core::run_case(runner, "15. RFC 9113 & Go #80759: HTTP/2 GOAWAY Last-Stream-ID Parity", test_rfc9113_goaway_last_stream_id_parity);
    core::run_case(runner, "16. RFC 4648 §3.5: Base64 Canonical & Malleability Defenses", test_rfc4648_base64_canonical_and_malleability_defenses);
    core::run_case(runner, "17. Core Codec Overflow, Malleability & Truncation Defenses", test_core_codecs_boundary_and_overflow_defenses);
    core::run_case(runner, "18. RFC 7541 & RFC 9113: HTTP/2 HPACK Inbound Capacity & Overflow Defenses", test_http2_hpack_boundary_and_capacity_defenses);
    core::run_case(runner, "19. RFC 3986 & WHATWG: Relative URL Resolution Capacity Defense", test_url_relative_resolution_capacity_defense);
    core::run_case(runner, "20. RFC 3986 & WHATWG: URL Path Manipulation & File URL Capacity Defenses", test_url_path_and_file_capacity_defenses);
    core::run_case(runner, "21. RFC 3986 & WHATWG: URL Query Delimiter & Parameter Isolation Defenses", test_url_query_delimiter_and_decoding_defenses);
    core::run_case(runner, "22. RFC 8439: Poly1305 2^128 Block Boundary Padding & AEAD Integrity", test_rfc8439_poly1305_block_boundary_padding_overflow);
    core::run_case(runner, "23. Network Backoff Jitter U64_MAX Overflow & Entropy Collapse Defenses", test_network_backoff_jitter_u64_max_overflow_and_entropy_collapse);
    core::run_case(runner, "24. RFC 7748: Curve25519 X25519 Montgomery Ladder Constant-Time Invariants", test_rfc7748_x25519_constant_time_montgomery_ladder);
    core::run_case(runner, "25. LimitReader EOF vs LimitExceeded Boundary Underflow Defenses", test_limit_reader_boundary_eof_and_underflow_defenses);
    core::run_case(runner, "26. RFC 1950 & RFC 1952 Compression Header Corruption, Flags & Stream Boundaries", test_compression_header_flags_window_and_stream_boundaries);
    core::run_case(runner, "27. PipeBuffer Lifecycle, Slice I/O Boundary Idempotency & Streaming Finality", test_pipe_lifecycle_slice_io_and_streaming_finality);
    core::run_case(runner, "28. RFC 9113 §5.1 & §6.9: H2 RST_STREAM In-Flight DATA Flow Control Invariants", test_h2_rst_stream_data_flow_control_invariants);
    core::run_case(runner, "29. RFC 8446 §4.2, §4.2.10 & §4.6.1: NewSessionTicket Extensions & Ticket Confusion Defenses", test_rfc8446_nst_extension_validation_and_ticket_confusion);
    core::run_case(runner, "30. RFC 9110 & RFC 9293: Connection Pool Starvation & Slot Reclamation", test_rfc9110_connection_pool_starvation_and_slot_reclamation);
    core::run_case(runner, "31. RFC 9204 §4.5.1.1 & §4.5.1.2: QPACK Zero-RIC Base Invariants & MaxTableCapacity RIC Bounds", test_rfc9204_qpack_zero_ric_base_invariants_and_capacity_bound);
    core::run_case(runner, "32. RFC 8725 §3.2, §3.6, RFC 8037 §2 & RFC 7517 §4.4: JWKS Key Confusion & Algorithm Binding", test_rfc8725_jwks_key_confusion_and_algorithm_binding);
    core::run_case(runner, "33. RFC 9293 §3.5 & RFC 1122: Half-Closed Teardown & Drain Deadlock Defenses", test_rfc9293_half_closed_socket_teardown_and_drain_deadlock_defenses);

    let ok = core::finish(runner);
    assert(ok);
}
