// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Red regression test suite based on uWebSockets & uSockets issue tracker.
// Tracks verified fixes for vulnerabilities, RFC non-conformances, and edge cases.
import std;
import core from "..";
import wing from "..";

fn test_uweb_1951_non_ascii_url_rejection(t: core::T&) {
    // uWebSockets Issue #1951 / RFC 9112 Section 3.2:
    // Request target must only consist of visible ASCII characters (0x21..0x7E).
    // Raw UTF-8 bytes (e.g. 0xD1, 0x82) or raw binary bytes (>= 0x80) MUST be rejected with HTTP 400.

    var req = wing::new_request("GET", "");
    let bad_utf8: const u8[:] = "GET /тест HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let ok1, _ = wing::parse_http1_wire_request(bad_utf8, req);
    t.assert_false(ok1, "Raw UTF-8 in request target must be rejected per uWS #1951 / RFC 9112 §3.2");

    let bad_bin: const u8[:] = "GET /\xFF\xFE/resource HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let ok2, _ = wing::parse_http1_wire_request(bad_bin, req);
    t.assert_false(ok2, "High-bit raw binary bytes in request target must be rejected");

    let valid_ascii: const u8[:] = "GET /test/path?foo=bar%20baz HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let ok3, _ = wing::parse_http1_wire_request(valid_ascii, req);
    t.assert_true(ok3, "Valid visible ASCII path must be accepted");
}

fn test_uweb_1855_head_content_length_duplicate(t: core::T&) {
    // uWebSockets Issue #1855 / RFC 9110 Section 8.6:
    // When responding to HEAD or providing a manual Content-Length on empty body,
    // the server MUST NOT serialize two conflicting Content-Length headers (e.g. 0 and 1024).

    var res = wing::new_response();
    res.status_code = 200;
    wing::set_header(res, "Content-Length", "1024");
    // Body is intentionally empty (HEAD response)

    var wire_out: u8[..1024] = [];
    wing::serialize_http1_response(res, "GooseWing", wire_out);
    let wire_str = wire_out[..];

    t.assert_true(core::index_of_slice(wire_str, "Content-Length: 1024\r\n") >= 0, "Must contain Content-Length: 1024");
    t.assert_false(core::index_of_slice(wire_str, "Content-Length: 0\r\n") >= 0, "Must NOT contain conflicting Content-Length: 0");

    // Count occurrences of 'Content-Length:'
    var count: i64 = 0;
    var cursor: i64 = 0;
    while cursor < wire_str.len {
        let idx = core::index_of_slice(wire_str[cursor..], "Content-Length:");
        if idx < 0 { break; }
        count++;
        cursor += idx + 15;
    }
    t.assert_eq(count, 1, "Exactly one Content-Length header must be emitted");
}

fn test_uweb_1927_proxy_enforcement_and_no_fallthrough(t: core::T&) {
    // uWebSockets Issue #1927 & #1948 / HAProxy PROXY Protocol Specification:
    // When accept_proxy_protocol is enabled, the connection MUST begin with a valid PROXY header.
    // If a client sends plain HTTP without PROXY, it MUST be rejected immediately (NO fallthrough!).

    var srv = wing::new_http_server("127.0.0.1", 8080);
    srv.accept_proxy_protocol = true;

    var wire_out: u8[..1024] = [];
    let plain_http: const u8[:] = "GET /admin HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let outcome, ok = wing::handle_connection_wire(srv, "192.168.1.50", plain_http, 123456789, wire_out);

    t.assert_false(ok, "Direct plain HTTP connection when PROXY is enforced must be rejected");
    t.assert_true(core::index_of_slice(wire_out[..], "400 Bad Request") >= 0, "Must return 400 Bad Request on missing PROXY header");
}

fn test_uweb_1407_control_frame_protocol_error(t: core::T&) {
    // uWebSockets Issue #1407 / RFC 6455 Section 5.5:
    // Malformed control frames (payload > 125, fragmented control frame with FIN=0)
    // MUST trigger WS_STATUS_PROTOCOL_ERROR (1002) and close the WebSocket connection.

    var ws = wing::new_websocket_session(false); // Server-side session
    var msg = wing::WsMessage {};
    var reply: u8[..256] = [];

    // 1. Fragmented Ping frame (FIN = 0, opcode = 0x09) with 4-byte mask
    let frag_ping: u8[6] = [
        0x09, // FIN=0, opcode=Ping
        0x80, // Masked, len=0
        0x01, 0x02, 0x03, 0x04, // Mask key
    ];
    let ok1 = wing::receive(ws, frag_ping[..], msg, reply);
    t.assert_true(ok1, "receive must handle protocol error");
    t.assert_true(ws.is_closed, "WebSocket must be marked closed on fragmented control frame");
    t.assert_eq(ws.close_code, wing::WS_STATUS_PROTOCOL_ERROR, "Must close with WS_STATUS_PROTOCOL_ERROR (1002)");

    // 2. Control frame with payload length > 125 (len = 126)
    var ws2 = wing::new_websocket_session(false);
    var reply2: u8[..256] = [];
    let oversize_ping: u8[8] = [
        0x89, // FIN=1, opcode=Ping
        0xFE, // Masked, len=126 (0x7E)
        0x00, 0x7E, // 126 bytes extended length
        0x01, 0x02, 0x03, 0x04, // Mask key
    ];
    let ok2 = wing::receive(ws2, oversize_ping[..], msg, reply2);
    t.assert_true(ok2, "receive must handle protocol error");
    t.assert_true(ws2.is_closed, "WebSocket must be closed on oversized control frame");
    t.assert_eq(ws2.close_code, wing::WS_STATUS_PROTOCOL_ERROR, "Must close with WS_STATUS_PROTOCOL_ERROR (1002)");
}

fn test_uweb_1933_topictree_trailing_wildcard(t: core::T&) {
    // uWebSockets Issue #1933 & OASIS MQTT v5.0 §4.7.1.3:
    // 'sport/+' MUST match 'sport/' (trailing slash level).
    t.assert_true(wing::match_topic("sport/+", "sport/"), "'sport/+' must match 'sport/' with trailing slash");
    t.assert_true(wing::match_topic("sport/#", "sport/"), "'sport/#' must match 'sport/'");
    t.assert_true(wing::match_topic("sport/#", "sport"), "'sport/#' must match 'sport'");

    // uWebSockets Issue #1924 / #1933:
    // Publishing to empty TopicTree or querying non-existent topic must return 0 without panicking.
    var tree = wing::new_topic_tree();
    t.assert_eq(wing::subscriber_count(tree, "non/existent"), 0, "Subscriber count on non-existent topic must be 0");
    var out_fds: i64[..512] = [];
    let count = wing::find_subscribers(tree, "test/topic", out_fds);
    t.assert_eq(count, 0, "Finding subscribers in empty tree must return 0");
}

fn test_usock_263_socket_lifecycle_and_non_blocking_clean(t: core::T&) {
    let listener = wing::tcp_listen("127.0.0.1", 0, 16);
    t.assert_true(listener > 0, "Listener created with non-inheritable handle");
    let port = wing::tcp_getsockname_port(listener);
    t.assert_true(port > 0, "Port allocated");

    let client = wing::tcp_connect("127.0.0.1", port, 2000);
    t.assert_true(client > 0, "Client connected without handle inheritance");

    let server_sock = wing::tcp_accept(listener, 2000);
    t.assert_true(server_sock > 0, "Server accepted connection");

    let msg = "PING_USOCKETS_263";
    let sent = wing::tcp_send(client, msg);
    t.assert_eq(sent, msg.len as i32, "Sent test payload");

    var buf: u8[128] = [0; 128];
    let recvd = wing::tcp_recv_slice(server_sock, buf[..], 2000);
    t.assert_eq(recvd, msg.len as i32, "Received payload on accepted socket");

    wing::tcp_close(client);
    wing::tcp_close(server_sock);
    wing::tcp_close(listener);
}

fn test_uweb_1949_host_header_validation(t: core::T&) {
    // uWebSockets Issue #1949 / RFC 9112 Section 3.2:
    // 1. Missing Host header in HTTP/1.1 must be rejected with 400.
    // 2. Multiple Host headers must be rejected with 400.
    // 3. Host containing path ('/'), query ('?'), fragment ('#'), or userinfo ('@') must be rejected with 400.
    var req = wing::new_request("GET", "");

    // 1. Missing Host in HTTP/1.1
    let no_host: const u8[:] = "GET / HTTP/1.1\r\nConnection: close\r\n\r\n";
    let ok1, _ = wing::parse_http1_wire_request(no_host, req);
    t.assert_false(ok1, "HTTP/1.1 request without Host header must be rejected");

    // 2. Host with path slash '/'
    let slash_host: const u8[:] = "GET / HTTP/1.1\r\nHost: localhost:8080/path\r\n\r\n";
    let ok2, _ = wing::parse_http1_wire_request(slash_host, req);
    t.assert_false(ok2, "Host header with slash '/path' must be rejected");

    // 3. Host with query '?'
    let query_host: const u8[:] = "GET / HTTP/1.1\r\nHost: localhost?query=1\r\n\r\n";
    let ok3, _ = wing::parse_http1_wire_request(query_host, req);
    t.assert_false(ok3, "Host header with query '?' must be rejected");

    // 4. Host with userinfo '@'
    let user_host: const u8[:] = "GET / HTTP/1.1\r\nHost: admin@localhost\r\n\r\n";
    let ok4, _ = wing::parse_http1_wire_request(user_host, req);
    t.assert_false(ok4, "Host header with userinfo '@' must be rejected");

    // 5. Multiple conflicting Host headers
    let multi_host: const u8[:] = "GET / HTTP/1.1\r\nHost: alpha.com\r\nHost: beta.com\r\n\r\n";
    let ok5, _ = wing::parse_http1_wire_request(multi_host, req);
    t.assert_false(ok5, "Multiple Host headers must be rejected");

    // 6. Valid Host header
    let valid_host: const u8[:] = "GET / HTTP/1.1\r\nHost: localhost:8080\r\n\r\n";
    let ok6, _ = wing::parse_http1_wire_request(valid_host, req);
    t.assert_true(ok6, "Valid Host header must be accepted");
}

fn test_uweb_1370_204_no_content_length(t: core::T&) {
    // uWebSockets Issue #1370 / RFC 9110 Section 8.6:
    // A server MUST NOT send a Content-Length header field in any response
    // with status code 204 (No Content).
    var res = wing::new_response();
    res.status_code = 204;
    wing::set_header(res, "Content-Length", "0"); // User handler mistakenly sets Content-Length

    var wire_out: u8[..1024] = [];
    wing::serialize_http1_response(res, "GooseWing", wire_out);
    let wire_str = wire_out[..];

    t.assert_false(core::index_of_slice(wire_str, "Content-Length") >= 0, "204 No Content response must NOT contain Content-Length header");
}

fn test_rfc_6455_1005_empty_close_payload(t: core::T&) {
    // RFC 6455 Section 7.4.1 / Autobahn 7.1.x:
    // Status code 1005 (No Status Received) is designated for internal use
    // and MUST NOT be serialized onto the wire in a Close frame!
    // A close with WS_STATUS_NO_STATUS must produce an empty 0-byte payload.

    var ws = wing::new_websocket_session(false);
    var wire_out: u8[..256] = [];
    wing::close(ws, wing::WS_STATUS_NO_STATUS, "", wire_out);

    let hdr, ok = wing::parse_ws_frame_header(wire_out[..]);
    t.assert_true(ok, "Close frame must parse");
    t.assert_eq(hdr.opcode, wing::WS_OPCODE_CLOSE, "Opcode is Close");
    t.assert_eq(hdr.payload_len, 0, "1005 close frame payload length must be 0 bytes on wire");
}

fn test_uweb_1952_options_asterisk_and_get_asterisk_rejection(t: core::T&) {
    // uWebSockets Issue #1952 / RFC 9112 Section 3.2.4:
    // Asterisk-form ('*') request target is ONLY valid for OPTIONS.
    // GET *, POST *, or any non-OPTIONS method with '*' MUST be rejected with 400.
    // Normal origin-form targets for GET/POST must begin with '/'.
    var req = wing::new_request("GET", "");

    let opt_star: const u8[:] = "OPTIONS * HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let ok1, _ = wing::parse_http1_wire_request(opt_star, req);
    t.assert_true(ok1, "OPTIONS * HTTP/1.1 must be accepted per RFC 9112 §3.2.4");

    let get_star: const u8[:] = "GET * HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let ok2, _ = wing::parse_http1_wire_request(get_star, req);
    t.assert_false(ok2, "GET * HTTP/1.1 must be rejected per uWS #1952 / RFC 9112 §3.2.4");

    let post_star: const u8[:] = "POST * HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let ok3, _ = wing::parse_http1_wire_request(post_star, req);
    t.assert_false(ok3, "POST * HTTP/1.1 must be rejected");
}

fn test_uweb_1932_ws_send_blocked_when_closed(t: core::T&) {
    // uWebSockets Issue #1932 / RFC 6455 Section 5.5.1:
    // Once a WebSocket session is closed (or closing after backpressure/close frame),
    // all subsequent sends (text, binary, ping) MUST be dropped without writing frames.
    var ws = wing::new_websocket_session(false);
    var close_wire: u8[..128] = [];
    wing::close(ws, wing::WS_STATUS_NORMAL, "bye", close_wire);
    t.assert_true(ws.is_closed, "Session is closed");

    var wire_out: u8[..256] = [];
    wing::send_text(ws, "should be dropped", wire_out);
    t.assert_eq(wire_out.len, 0, "send_text must emit 0 bytes after session is closed");

    wing::send_binary(ws, "binary drop", wire_out);
    t.assert_eq(wire_out.len, 0, "send_binary must emit 0 bytes after session is closed");

    wing::send_ping(ws, "ping drop", wire_out);
    t.assert_eq(wire_out.len, 0, "send_ping must emit 0 bytes after session is closed");
}

fn test_mqtt_invalid_multilevel_wildcard_rejection(t: core::T&) {
    // OASIS MQTT v5.0 §4.7.1.2 & TopicTree Validation:
    // Multi-level wildcard '#' MUST be the last character in the topic pattern,
    // and MUST be either alone ("#") or preceded by '/' ("sport/#").
    // Patterns like "sport/#/tennis" or "sport#" or "sport+foo" are syntactically illegal!
    var tree = wing::new_topic_tree();

    t.assert_false(wing::subscribe(tree, 10, "sport/#/tennis"), "'#' in middle of topic pattern must be rejected");
    t.assert_false(wing::subscribe(tree, 10, "sport#"), "'#' not preceded by '/' must be rejected");
    t.assert_false(wing::subscribe(tree, 10, "sport+"), "'+' not occupying entire segment must be rejected");
    t.assert_true(wing::subscribe(tree, 10, "sport/#"), "Valid 'sport/#' must be accepted");
    t.assert_true(wing::subscribe(tree, 10, "#"), "Valid '#' must be accepted");
    t.assert_true(wing::subscribe(tree, 10, "sport/+/tennis"), "Valid 'sport/+/tennis' must be accepted");
}

fn test_uweb_1090_mqtt_wildcard_publish_rejection(t: core::T&) {
    // uWebSockets Issue #1090 / OASIS MQTT v5.0 §3.3.2.1:
    // "The Topic Name in the PUBLISH packet MUST NOT contain wildcard characters [MQTT-3.3.2-1]."
    // Publishing to wildcard topics ("sport/+", "sport/#", "+", "#") is illegal and MUST be rejected.
    var tree = wing::new_topic_tree();
    t.assert_true(wing::subscribe(tree, 10, "sport/+"), "Subscribe to 'sport/+'");
    t.assert_true(wing::subscribe(tree, 20, "sport/#"), "Subscribe to 'sport/#'");

    var fds: i64[..512] = [];
    // Legitimate publish to concrete topic: matches both
    let count1 = wing::find_subscribers(tree, "sport/tennis", fds);
    t.assert_eq(count1, 2, "Concrete topic 'sport/tennis' matches 2 subscribers");

    // Illegal publish containing '+' wildcard: must return 0
    let count2 = wing::find_subscribers(tree, "sport/+", fds);
    t.assert_eq(count2, 0, "Publish to wildcard topic 'sport/+' MUST be rejected (0 subscribers)");

    // Illegal publish containing '#' wildcard: must return 0
    let count3 = wing::find_subscribers(tree, "sport/#", fds);
    t.assert_eq(count3, 0, "Publish to wildcard topic 'sport/#' MUST be rejected (0 subscribers)");

    // Standalone wildcard publish: must return 0
    let count4 = wing::find_subscribers(tree, "#", fds);
    t.assert_eq(count4, 0, "Publish to wildcard topic '#' MUST be rejected (0 subscribers)");
}

fn test_uweb_1944_query_lookup_encoded_and_valueless(t: core::T&) {
    // uWebSockets Issue #1944 / WHATWG URL:
    // Query parameter fast lookup must handle percent-encoded keys and valueless parameters.
    let query_str: const u8[:] = "?user%20id=42&flag&category%2Ftag=news";

    t.assert_true(core::has_query_param_fast(query_str, "user id"), "Must find percent-encoded key 'user id'");

    var user_id_val: u8[..64] = [];
    let found1, is_valueless1 = core::get_query_param_fast(query_str, "user id", user_id_val);
    t.assert_true(found1, "Found 'user id'");
    t.assert_false(is_valueless1, "'user id' has value");
    t.assert_eq(user_id_val[..], "42", "Decoded value of 'user id' is '42'");

    var flag_val: u8[..64] = [];
    let found2, is_valueless2 = core::get_query_param_fast(query_str, "flag", flag_val);
    t.assert_true(found2, "Found valueless 'flag'");
    t.assert_true(is_valueless2, "'flag' is valueless");

    var cat_val: u8[..64] = [];
    let found3, is_valueless3 = core::get_query_param_fast(query_str, "category/tag", cat_val);
    t.assert_true(found3, "Found 'category/tag'");
    t.assert_false(is_valueless3, "'category/tag' has value");
    t.assert_eq(cat_val[..], "news", "Decoded value of 'category/tag' is 'news'");
}

fn test_uweb_1898_extra_bytes_connection_poisoning(t: core::T&) {
    // uWebSockets Issue #1898 / RFC 9112 Section 9.3:
    // Extra bytes sent beyond Content-Length must not be ignored or allowed to poison keep-alive.
    // If a request stream contains unparseable trailing junk after a request, the connection handler
    // must reject it with 400 Bad Request and fail the stream (return ok = false), rather than silently breaking.
    var server = wing::new_http_server();
    wing::add_route(server.pipeline.router, "POST", "/submit", 1);

    let poisoned_stream: const u8[:] =
        "POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nHELLOPOISON_EXTRA_BYTES_LINGERING";

    var wire_out: u8[..4096] = [];
    let handled, ok = wing::handle_connection_wire_pipelined(server, "127.0.0.1", poisoned_stream, 0, wire_out);
    t.assert_false(ok, "Trailing unparseable bytes after Content-Length must invalidate the stream (ok = false)");
    t.assert_true(core::index_of_slice(wire_out[..], "400 Bad Request") >= 0, "Must serialize 400 Bad Request for poisoned connection");
}

fn test_rfc_6455_non_minimal_length_protocol_error(t: core::T&) {
    // RFC 6455 §5.2 & Autobahn Cases 3.1, 3.2, 3.3, 3.4 / uWS #1407:
    // Non-minimal length encodings (e.g. 16-bit length < 126 or 64-bit length <= 65535)
    // and high-bit violations in 64-bit length MUST fail the connection with Protocol Error (1002).
    var ws = wing::new_websocket_session(false); // server session
    var reply: u8[..256] = [];
    var view = wing::WsMessageView { .. };

    // 1. Non-minimal 16-bit encoding: raw_len = 126, but length is 10 (< 126).
    // Wire: 0x81 (FIN+text), 0xFE (Masked + 126), 0x00, 0x0A (len=10), mask: 4 bytes, payload: 10 bytes
    var wire_non_minimal_16: u8[..32] = [
        0x81, 0xFE, 0x00, 0x0A,
        0x11, 0x22, 0x33, 0x44,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let handled1 = wing::receive_view(ws, wire_non_minimal_16[..], view, reply);
    t.assert_true(handled1, "Handled non-minimal 16-bit length frame");
    t.assert_true(ws.is_closed, "Session must be closed on non-minimal length");
    t.assert_eq(ws.close_code, wing::WS_STATUS_PROTOCOL_ERROR, "Must close with 1002 (PROTOCOL_ERROR)");

    // 2. High-bit set in 64-bit length: byte 2 has 0x80 set
    var ws2 = wing::new_websocket_session(false);
    var wire_high_bit_64: u8[..32] = [
        0x81, 0xFF, 0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x11, 0x22, 0x33, 0x44,
    ];
    let handled2 = wing::receive_view(ws2, wire_high_bit_64[..], view, reply);
    t.assert_true(handled2, "Handled high-bit 64-bit length frame");
    t.assert_true(ws2.is_closed, "Session must be closed on high-bit in 64-bit length");
    t.assert_eq(ws2.close_code, wing::WS_STATUS_PROTOCOL_ERROR, "Must close with 1002 (PROTOCOL_ERROR)");
}

fn test_uweb_1658_max_header_size_rejection(t: core::T&) {
    // uWebSockets #1658 / RFC 9112 §2.1:
    // Total header block size must be bounded (e.g. 8192 bytes).
    // Incoming requests exceeding 8192 bytes of headers must be rejected.
    var req = wing::new_request("GET", "");
    var huge_wire: u8[>..] = [];
    huge_wire.append("GET /large-headers HTTP/1.1\r\nHost: example.com\r\n");
    for i in 26 {
        huge_wire.append("X-Large-Header-Padding: 01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789\r\n");
    }
    huge_wire.append("\r\n");
    t.assert_true(huge_wire.len > 8192, "Total wire headers exceed 8192 bytes");

    let ok, _ = wing::parse_http1_wire_request(huge_wire[..], req);
    t.assert_false(ok, "Headers exceeding 8KB must be rejected per uWS #1658 / RFC 9112 §2.1");
}

fn test_usock_101_windows_exclusive_port_defense(t: core::T&) {
    // uSockets Issue #101 / #167:
    // On Windows, listening sockets MUST set SO_EXCLUSIVEADDRUSE rather than SO_REUSEADDR.
    // SO_REUSEADDR on Windows permits rogue processes to forcibly bind to the same port and steal connections (port hijacking).
    // With SO_EXCLUSIVEADDRUSE, a second bind to the same local IP and port MUST fail.
    let s1 = wing::native_tcp_listen("127.0.0.1", 0, 128);
    t.assert_true(s1 > 0, "First listener created successfully");
    let port = wing::native_tcp_getsockname_port(s1);
    t.assert_true(port > 0, "Listener bound to dynamic port");

    // Second bind attempt on the same address & port: MUST be rejected
    let s2 = wing::native_tcp_listen("127.0.0.1", port, 128);
    t.assert_eq(s2, -1, "Second listener on exact same port MUST fail (-1)");

    wing::native_tcp_close(s1);
    if s2 > 0 {
        wing::native_tcp_close(s2);
    }
}

fn test_rfc_6455_sec_websocket_key_validation(t: core::T&) {
    // RFC 6455 Section 4.2.1:
    // "The |Sec-WebSocket-Key| MUST be a base64-encoded value that, when decoded, is 16 bytes in length."
    // Handshake request with malformed, short, or non-base64 key MUST be rejected with HTTP 400.
    var req_bad = wing::new_request("GET", "/ws");
    wing::set_header(req_bad, "Host", "example.com");
    wing::set_header(req_bad, "Upgrade", "websocket");
    wing::set_header(req_bad, "Connection", "Upgrade");
    wing::set_header(req_bad, "Sec-WebSocket-Version", "13");
    wing::set_header(req_bad, "Sec-WebSocket-Key", "short_invalid_key");

    var res_bad = wing::new_response();
    let sess_bad, ok_bad = wing::ws_upgrade_request(req_bad, res_bad);
    t.assert_false(ok_bad, "Upgrade with non-16-byte key must fail");
    t.assert_eq(res_bad.status_code, 400, "Must return HTTP 400 Bad Request for malformed Sec-WebSocket-Key");

    // Valid 16-byte nonce base64-encoded (RFC 6455 example)
    var req_good = wing::new_request("GET", "/ws");
    wing::set_header(req_good, "Host", "example.com");
    wing::set_header(req_good, "Upgrade", "websocket");
    wing::set_header(req_good, "Connection", "Upgrade");
    wing::set_header(req_good, "Sec-WebSocket-Version", "13");
    wing::set_header(req_good, "Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==");

    var res_good = wing::new_response();
    let sess_good, ok_good = wing::ws_upgrade_request(req_good, res_good);
    t.assert_true(ok_good, "Upgrade with valid Sec-WebSocket-Key must succeed");
    t.assert_eq(res_good.status_code, 101, "Must return HTTP 101 Switching Protocols");
    let accept_val = wing::header(res_good, "Sec-WebSocket-Accept");
    t.assert_eq(accept_val, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", "Correct RFC 6455 Sec-WebSocket-Accept header");
}

fn test_uweb_1948_proxy_v2_command_and_family_validation(t: core::T&) {
    // uWebSockets Issue #1948 / HAProxy PROXY Protocol v2 Specification §2.2:
    // 1. Only exact family/transport combinations 0x00, 0x11, 0x12, 0x21, 0x22, 0x31, 0x32 are valid.
    //    Unspecified combinations like 0x01 (UNSPEC+STREAM) or 0x10 (INET4+UNSPEC) MUST be rejected.
    // 2. Command LOCAL (0x20) MUST NOT expose proxied addresses; native endpoint address MUST be preserved.

    let preamble: const u8[12] = [
        0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
    ];

    // Case 1: fam_trans = 0x01 (UNSPEC + STREAM) - MUST FAIL
    var bad_wire1: u8[..16] = [];
    bad_wire1.append(preamble[..]);
    bad_wire1.push(0x21); // PROXY command
    bad_wire1.push(0x01); // Invalid UNSPEC+STREAM
    bad_wire1.push(0x00); // len hi
    bad_wire1.push(0x00); // len lo
    let hdr1, c1, ok1 = wing::parse_proxy_v2(bad_wire1[..]);
    t.assert_false(ok1, "PROXY v2 with invalid fam_trans 0x01 (UNSPEC+STREAM) MUST be rejected");

    // Case 2: fam_trans = 0x10 (INET4 + UNSPEC) - MUST FAIL
    var bad_wire2: u8[..16] = [];
    bad_wire2.append(preamble[..]);
    bad_wire2.push(0x21); // PROXY command
    bad_wire2.push(0x10); // Invalid INET4+UNSPEC
    bad_wire2.push(0x00); // len hi
    bad_wire2.push(0x00); // len lo
    let hdr2, c2, ok2 = wing::parse_proxy_v2(bad_wire2[..]);
    t.assert_false(ok2, "PROXY v2 with invalid fam_trans 0x10 (INET4+UNSPEC) MUST be rejected");

    // Case 3: Command LOCAL (0x20) with IPv4 address payload - MUST NOT expose proxied address
    var local_wire: u8[..32] = [];
    local_wire.append(preamble[..]);
    local_wire.push(0x20); // LOCAL command
    local_wire.push(0x11); // INET4 + STREAM
    local_wire.push(0x00); // len hi
    local_wire.push(0x0C); // len = 12
    // 12 bytes address block: src 10.0.0.1, dst 10.0.0.2, sport 1234, dport 80
    let addr_bytes: u8[12] = [10, 0, 0, 1, 10, 0, 0, 2, 0x04, 0xD2, 0x00, 0x50];
    local_wire.append(addr_bytes[..]);

    let hdr3, c3, ok3 = wing::parse_proxy_v2(local_wire[..]);
    t.assert_true(ok3, "LOCAL command header syntax is valid");
    t.assert_eq(hdr3.src_ip_str.len, 0, "LOCAL command MUST NOT expose proxied client IP");
}

fn test_usock_258_windows_connect_rst_immediate_failure(t: core::T&) {
    // uSockets Issue #258 / #259 & Winsock2 Specification:
    // On Windows, when a non-blocking connect fails (RST / ECONNREFUSED), Winsock2
    // signals the socket via exceptfds or writefds with SO_ERROR set.
    // In uSockets #258, libuv/WSAPoll reported writable, and because uSockets
    // omitted getsockopt(SO_ERROR), it incorrectly treated connection failure as success (calling on_open).
    // In wing, native_tcp_connect guards via exceptfds, SO_ERROR inspection, and bounded timeout:
    // 1) Connection to unlistening port with 50ms timeout MUST return -1 (never treated as open).
    // 2) Elapsed time MUST be bounded (< 300ms) without hanging.

    let sw = core::stopwatch();
    let s = wing::native_tcp_connect("127.0.0.1", 59999, 50);
    let dur_ms = sw.elapsed().as_millis();

    t.assert_eq(s, -1, "Connect to closed port MUST return -1 (never call on_open)");
    t.assert_true(dur_ms < 300, "Connect with 50ms timeout must return within bounded time");
}

fn test_uweb_1941_transfer_encoding_list_and_final_chunked(t: core::T&) {
    // uWebSockets Issue #1941 / PR #1943 & RFC 9112 Section 6.1 & 7:
    // Transfer-Encoding can be a comma-separated list of transfer codings (e.g. gzip, identity, br, deflate),
    // but MUST end with 'chunked' (case-insensitive) as the final transfer coding.
    // In uWS #1941, uWS compared whole string against exact literal "chunked", causing 400 Bad Request
    // on valid list forms like "gzip, chunked", "identity, chunked", "CHUNKED".
    // goose-wing must accept any valid coding sequence ending in chunked, and reject:
    // 1) non-chunked endings (e.g. "chunked, gzip" or "identity")
    // 2) multiple chunked encodings (e.g. "chunked, chunked")

    // 1. Valid list forms ending in chunked
    t.assert_true(wing::validate_transfer_encoding_value("chunked"), "Single chunked is valid");
    t.assert_true(wing::validate_transfer_encoding_value("CHUNKED"), "Case-insensitive CHUNKED is valid");
    t.assert_true(wing::validate_transfer_encoding_value("gzip, chunked"), "gzip, chunked list is valid");
    t.assert_true(wing::validate_transfer_encoding_value("identity, chunked"), "identity, chunked list is valid");
    t.assert_true(wing::validate_transfer_encoding_value("deflate, gzip, chunked"), "deflate, gzip, chunked list is valid");
    t.assert_true(wing::validate_transfer_encoding_value("br, chunked"), "br, chunked list is valid");
    t.assert_true(wing::validate_transfer_encoding_value("gzip;q=1.0, chunked"), "parameterized coding is valid");

    // 2. Invalid forms (chunked not final or duplicate chunked)
    t.assert_false(wing::validate_transfer_encoding_value("chunked, gzip"), "chunked before gzip must be rejected");
    t.assert_false(wing::validate_transfer_encoding_value("chunked, identity"), "chunked before identity must be rejected");
    t.assert_false(wing::validate_transfer_encoding_value("identity"), "Missing chunked must be rejected");
    t.assert_false(wing::validate_transfer_encoding_value("chunked, chunked"), "Duplicate chunked must be rejected");

    // 3. End-to-end server wire handling with identity, chunked
    var server = wing::new_http_server("test-server");
    wing::add_post_route(server, "/upload", 1);
    var wire_out: u8[..512] = [];
    let raw_req: const u8[:] = "POST /upload HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: identity, chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
    let _, ok = wing::handle_connection_wire(server, "127.0.0.1", raw_req, 1000000000, wire_out);
    t.assert_true(ok, "Server must accept and process request with Transfer-Encoding: identity, chunked");
    t.assert_contains(wire_out[..], "200 OK", "Server responds 200 OK to valid chunked list form");
}

fn test_uweb_1936_chunk_extension_and_size_whitespace_validation(t: core::T&) {
    // uWebSockets Issue #1936 / Http11Probe & RFC 9112 Section 7.1.1:
    // chunk = chunk-size [ chunk-ext ] CRLF
    // chunk-size = 1*HEXDIG
    // chunk-ext = *( BWS ";" BWS chunk-ext-name [ BWS "=" BWS chunk-ext-val ] )
    // chunk-ext-name = token
    // chunk-ext-val = token / quoted-string
    //
    // In uWS #1936 / Http11Probe, uWebSockets failed 5+ compliance and smuggling checks:
    // 1) Whitespace before chunk-size (" 5\r\n") MUST be rejected.
    // 2) Whitespace after chunk-size without extension ("5 \r\n") MUST be rejected.
    // 3) Empty extension name after semicolon ("5;\r\n" or "5;;foo\r\n" or "5;=val\r\n") MUST be rejected.
    // 4) Unclosed quoted string in extension value ("5;foo=\"bar\r\n") MUST be rejected.
    // 5) Non-token characters in extension name ("5;foo@bar=1\r\n") MUST be rejected.
    // 6) Legitimate extensions ("5;name=value;flag\r\n" and "5;name=\"quoted val\"\r\n") MUST succeed.

    var body: u8[>..] = [];
    var trailers: wing::HeaderItem[..16] = [];

    // 1. Valid extensions
    body.clear(); trailers.clear();
    let err1, _ = wing::decode_chunked_body_with_trailers("5;name=value;flag\r\nHello\r\n0\r\n\r\n", body, trailers);
    t.assert_eq(err1, wing::ChunkedDecodeError.None, "Valid chunk extension accepted");

    body.clear(); trailers.clear();
    let err2, _ = wing::decode_chunked_body_with_trailers("5;name=\"quoted val\"\r\nHello\r\n0\r\n\r\n", body, trailers);
    t.assert_eq(err2, wing::ChunkedDecodeError.None, "Valid quoted extension accepted");

    // 2. Illegal whitespace around chunk-size (smuggling vector)
    body.clear(); trailers.clear();
    let err_ws1, _ = wing::decode_chunked_body_with_trailers(" 5\r\nHello\r\n0\r\n\r\n", body, trailers);
    t.assert_ne(err_ws1, wing::ChunkedDecodeError.None, "Leading whitespace before chunk size MUST be rejected");

    body.clear(); trailers.clear();
    let err_ws2, _ = wing::decode_chunked_body_with_trailers("5 \r\nHello\r\n0\r\n\r\n", body, trailers);
    t.assert_ne(err_ws2, wing::ChunkedDecodeError.None, "Trailing whitespace after chunk size without ';' MUST be rejected");

    // 3. Illegal empty extension names
    body.clear(); trailers.clear();
    let err_ext1, _ = wing::decode_chunked_body_with_trailers("5;\r\nHello\r\n0\r\n\r\n", body, trailers);
    t.assert_ne(err_ext1, wing::ChunkedDecodeError.None, "Empty extension name after ';' MUST be rejected");

    body.clear(); trailers.clear();
    let err_ext2, _ = wing::decode_chunked_body_with_trailers("5;=val\r\nHello\r\n0\r\n\r\n", body, trailers);
    t.assert_ne(err_ext2, wing::ChunkedDecodeError.None, "Extension with missing name before '=' MUST be rejected");

    body.clear(); trailers.clear();
    let err_ext3, _ = wing::decode_chunked_body_with_trailers("5;;foo=bar\r\nHello\r\n0\r\n\r\n", body, trailers);
    t.assert_ne(err_ext3, wing::ChunkedDecodeError.None, "Double semicolon in extension MUST be rejected");

    // 4. Unclosed quoted-string in extension value
    body.clear(); trailers.clear();
    let err_quote, _ = wing::decode_chunked_body_with_trailers("5;foo=\"unclosed\r\nHello\r\n0\r\n\r\n", body, trailers);
    t.assert_ne(err_quote, wing::ChunkedDecodeError.None, "Unclosed quoted string in extension MUST be rejected");

    // 5. Invalid token character in extension name
    body.clear(); trailers.clear();
    let err_tok, _ = wing::decode_chunked_body_with_trailers("5;foo@bar=1\r\nHello\r\n0\r\n\r\n", body, trailers);
    t.assert_ne(err_tok, wing::ChunkedDecodeError.None, "Invalid token character '@' in extension name MUST be rejected");
}

fn main() {
    var runner = core::new_runner("uWebSockets Bug Tracker Red-to-Green Regression Suite", core::Verbosity.Verbose);

    core::run_case(runner, "1. uWS #1951 Non-ASCII / UTF-8 Request Target Rejection", test_uweb_1951_non_ascii_url_rejection);
    core::run_case(runner, "2. uWS #1855 Duplicate Content-Length in HEAD Responses", test_uweb_1855_head_content_length_duplicate);
    core::run_case(runner, "3. uWS #1927 PROXY Protocol Enforcement Without Fallthrough", test_uweb_1927_proxy_enforcement_and_no_fallthrough);
    core::run_case(runner, "4. uWS #1407 WebSocket Control Frame Protocol Error (1002)", test_uweb_1407_control_frame_protocol_error);
    core::run_case(runner, "5. uWS #1933 TopicTree Trailing Wildcard & Safe Zero Publish", test_uweb_1933_topictree_trailing_wildcard);
    core::run_case(runner, "6. uSockets #263 Socket Handle Lifecycle & Inheritance Defense", test_usock_263_socket_lifecycle_and_non_blocking_clean);
    core::run_case(runner, "7. uWS #1949 Host Header Invariant Enforcement (RFC 9112 §3.2)", test_uweb_1949_host_header_validation);
    core::run_case(runner, "8. uWS #1370 Status 204 No Content Strip Content-Length", test_uweb_1370_204_no_content_length);
    core::run_case(runner, "9. RFC 6455 §7.4.1 Omit 1005 on Wire in Empty Close Frames", test_rfc_6455_1005_empty_close_payload);
    core::run_case(runner, "10. uWS #1952 OPTIONS * Acceptance & GET/POST * Rejection", test_uweb_1952_options_asterisk_and_get_asterisk_rejection);
    core::run_case(runner, "11. uWS #1932 Block Outbound WebSocket Sends After Close", test_uweb_1932_ws_send_blocked_when_closed);
    core::run_case(runner, "12. MQTT §4.7.1.2 TopicTree Wildcard Syntax Validation", test_mqtt_invalid_multilevel_wildcard_rejection);
    core::run_case(runner, "13. uWS #1090 TopicTree Wildcard Publish Rejection", test_uweb_1090_mqtt_wildcard_publish_rejection);
    core::run_case(runner, "14. uWS #1944 Query Lookup with Encoded Keys & Valueless", test_uweb_1944_query_lookup_encoded_and_valueless);
    core::run_case(runner, "15. uWS #1898 Extra Trailing Bytes Connection Poisoning Defense", test_uweb_1898_extra_bytes_connection_poisoning);
    core::run_case(runner, "16. RFC 6455 §5.2 Non-Minimal WebSocket Length Protocol Error", test_rfc_6455_non_minimal_length_protocol_error);
    core::run_case(runner, "17. uWS #1658 HTTP Header Block 8KB Limit Enforcement", test_uweb_1658_max_header_size_rejection);
    core::run_case(runner, "18. uSockets #101 Windows SO_EXCLUSIVEADDRUSE Port Hijack Defense", test_usock_101_windows_exclusive_port_defense);
    core::run_case(runner, "19. RFC 6455 §4.2.1 Sec-WebSocket-Key Nonce Validation", test_rfc_6455_sec_websocket_key_validation);
    core::run_case(runner, "20. uWS #1948 PROXY v2 Family & LOCAL Command Address Validation", test_uweb_1948_proxy_v2_command_and_family_validation);
    core::run_case(runner, "21. uSockets #258 Windows Connect RST Immediate Failure via exceptfds", test_usock_258_windows_connect_rst_immediate_failure);
    core::run_case(runner, "22. uWS #1941 Transfer-Encoding List & Final Chunked Requirement", test_uweb_1941_transfer_encoding_list_and_final_chunked);
    core::run_case(runner, "23. uWS #1936 Chunk Extension & Size Whitespace Validation (RFC 9112 §7.1.1)", test_uweb_1936_chunk_extension_and_size_whitespace_validation);

    let ok = core::finish(runner);
    assert(ok);
}
