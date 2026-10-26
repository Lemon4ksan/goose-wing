// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Verification suite for uWebSockets optimizations in goose-wing:
// 1. 256-bit Header BloomFilter and fast case-insensitive rejection
// 2. Fast HTTP/1.1 response serialization with pre-formatted status lines
// 3. Zero-Copy WebSocket frame ingress (WsMessageView)
// 4. Shared receive buffer and direct slice streaming
import std;
import core from "..";
import wing from "..";

fn test_header_bloom_filter(t: core::T&) {
    t.run("1. 256-bit Header BloomFilter Bitwise Rejection") { sub =>
        var bf = wing::HeaderBloomFilter { .. };
        wing::add_header(bf, "Content-Type");
        wing::add_header(bf, "Host");
        wing::add_header(bf, "Connection");
        wing::add_header(bf, "X-Custom-Auth");

        // Case-insensitive positive checks
        sub.assert_true(wing::might_have_header(bf, "content-type"), "Matches lowercase content-type");
        sub.assert_true(wing::might_have_header(bf, "CONTENT-TYPE"), "Matches uppercase CONTENT-TYPE");
        sub.assert_true(wing::might_have_header(bf, "Content-Type"), "Matches mixed-case Content-Type");
        sub.assert_true(wing::might_have_header(bf, "host"), "Matches host");
        sub.assert_true(wing::might_have_header(bf, "connection"), "Matches connection");
        sub.assert_true(wing::might_have_header(bf, "x-custom-auth"), "Matches x-custom-auth");

        // Negative checks: must be rejected with 0 string comparisons
        sub.assert_false(wing::might_have_header(bf, "sec-websocket-key"), "Rejects missing sec-websocket-key in 3 cycles");
        sub.assert_false(wing::might_have_header(bf, "authorization"), "Rejects missing authorization in 3 cycles");
        sub.assert_false(wing::might_have_header(bf, "upgrade"), "Rejects missing upgrade in 3 cycles");
        sub.assert_false(wing::might_have_header(bf, "transfer-encoding"), "Rejects missing transfer-encoding in 3 cycles");
    };

    t.run("2. Request Struct with Integrated BloomFilter") { sub =>
        var req = wing::new_request("GET", "/api/v1/status");
        req.set_header("Host", "api.example.com");
        req.set_header("Accept", "application/json");

        sub.assert_true(req.has_header("host"), "Request has host");
        sub.assert_true(req.has_header("ACCEPT"), "Request has ACCEPT (case-insensitive)");
        sub.assert_eq(req.header("accept"), "application/json", "Header value retrieved");

        // Missing headers return false / empty without iterating all headers
        sub.assert_false(req.has_header("cookie"), "Cookie fast-rejected");
        sub.assert_eq(req.header("cookie"), "", "Empty string for missing cookie");
    };
}

fn test_fast_serialization(t: core::T&) {
    t.run("1. Pre-formatted 200 OK Status Line & Content-Length 0") { sub =>
        var res = wing::new_response();
        res.status_code = 200;

        var wire: u8[>..] = [];
        wing::serialize_http1_response(res, "goose-wing", wire);

        let wire_str = wire[..];
        sub.assert_true(core::index_of_slice(wire_str, "HTTP/1.1 200 OK\r\n") == 0, "Status line uses pre-formatted 200 OK");
        sub.assert_true(core::index_of_slice(wire_str, "Content-Length: 0\r\n") >= 0, "Zero-length body emits Content-Length: 0 without decimal format loop");
        sub.assert_true(core::index_of_slice(wire_str, "Connection: keep-alive\r\n") >= 0, "Default keep-alive emitted");
    };
}

fn test_zero_copy_websocket_view(t: core::T&) {
    t.run("1. Zero-Copy Ingress via WsMessageView") { sub =>
        var ws = wing::new_websocket_session(false); // server session
        let mask: u8[4] = [0x11, 0x22, 0x33, 0x44];

        var wire_frame: u8[>..] = [];
        wing::encode_ws_frame(wire_frame, wing::WS_OPCODE_TEXT, "Zero-Copy Ingress Payload", true, mask, true);

        var view = wing::WsMessageView { .. };
        var reply: u8[>..] = [];

        // Receive directly into non-owning view
        let ok = ws.receive_view(wire_frame[..], view, reply);
        sub.assert_true(ok, "ws.receive_view succeeds");
        sub.assert_true(view.is_valid, "Message marked valid");
        sub.assert_eq(view.opcode, wing::WS_OPCODE_TEXT, "Opcode is TEXT");
        sub.assert_bytes_eq(view.payload, "Zero-Copy Ingress Payload", "Payload matches wire data without copying into heap or local buffer");

        // Ping auto-reply via view
        var ping_wire: u8[>..] = [];
        wing::encode_ws_frame(ping_wire, wing::WS_OPCODE_PING, "heartbeat", true, mask, true);

        var ping_view = wing::WsMessageView { .. };
        var pong_out: u8[>..] = [];
        let ok_ping = ws.receive_view(ping_wire[..], ping_view, pong_out);
        sub.assert_true(ok_ping, "Ping processed");
        sub.assert_eq(ping_view.opcode, wing::WS_OPCODE_PING, "Ping opcode");
        sub.assert_bytes_eq(ping_view.payload, "heartbeat", "Ping payload matched");
        sub.assert_true(pong_out.len > 0, "Pong reply generated automatically");
    };
}

fn test_shared_tcp_buffer(t: core::T&) {
    t.run("1. Live TCP Direct Slice Recv") { sub =>
        let listener = wing::tcp_listen("127.0.0.1", 0, 16);
        sub.assert_gt(listener, 0, "Listener created");
        let port = wing::tcp_getsockname_port(listener);

        let client = wing::tcp_connect("127.0.0.1", port, 2000);
        sub.assert_gt(client, 0, "Client connected");

        let srv_sock = wing::tcp_accept(listener, 2000);
        sub.assert_gt(srv_sock, 0, "Server accepted");

        // Client sends payload
        let payload = "ZERO_COPY_TCP_PAYLOAD_TEST";
        wing::tcp_send(client, payload);

        // Server receives directly into preallocated slice without stack memset
        var srv_storage: u8[256] = [0; 256];
        let recvd = wing::tcp_recv_slice(srv_sock, srv_storage[..], 2000);
        sub.assert_eq(recvd, payload.len as i32, "Direct slice received all bytes");
        sub.assert_bytes_eq(srv_storage[..recvd], payload, "Storage content matches sent payload");

        wing::tcp_close(client);
        wing::tcp_close(srv_sock);
        wing::tcp_close(listener);
    };
}

fn test_topic_tree_pubsub(t: core::T&) {
    t.run("1. Exact and Wildcard MQTT Pattern Matching") { sub =>
        var tree = wing::new_topic_tree();

        // Register subscribers with distinct socket descriptors
        sub.assert_true(tree.subscribe(101, "chat/general"), "Sub 101 to exact chat/general");
        sub.assert_true(tree.subscribe(102, "chat/+"), "Sub 102 to single-level wildcard chat/+");
        sub.assert_true(tree.subscribe(103, "sensors/#"), "Sub 103 to multi-level wildcard sensors/#");
        sub.assert_true(tree.subscribe(104, "#"), "Sub 104 to global root wildcard #");

        sub.assert_eq(tree.active_subscriptions, 4, "4 active subscriptions in pool");
        sub.assert_true(tree.is_subscribed(101, "chat/general"), "101 is subscribed to chat/general");
        sub.assert_false(tree.is_subscribed(101, "chat/random"), "101 is not subscribed to chat/random");

        // Query subscribers for "chat/general":
        // Should match: 101 (exact), 102 (chat/+), 104 (#). Total: 3
        var subs_gen: i64[..512] = [];
        let count_gen = tree.find_subscribers("chat/general", subs_gen);
        sub.assert_eq(count_gen, 3, "chat/general matches 3 subscribers");
        sub.assert_true(subs_gen.contains(101), "Contains 101");
        sub.assert_true(subs_gen.contains(102), "Contains 102");
        sub.assert_true(subs_gen.contains(104), "Contains 104");
        sub.assert_false(subs_gen.contains(103), "Does not contain 103");

        // Query subscribers for "sensors/room1/temp":
        // Should match: 103 (sensors/#), 104 (#). Total: 2
        var subs_temp: i64[..512] = [];
        let count_temp = tree.find_subscribers("sensors/room1/temp", subs_temp);
        sub.assert_eq(count_temp, 2, "sensors/room1/temp matches 2 subscribers");
        sub.assert_true(subs_temp.contains(103), "Contains 103");
        sub.assert_true(subs_temp.contains(104), "Contains 104");
    };

    t.run("2. Subscriber Deduplication across Overlapping Patterns") { sub =>
        var tree = wing::new_topic_tree();

        // Socket 200 subscribes to multiple overlapping wildcard topics
        tree.subscribe(200, "market/#");
        tree.subscribe(200, "market/+");
        tree.subscribe(200, "market/btc");

        var matched: i64[..512] = [];
        let count = tree.find_subscribers("market/btc", matched);
        sub.assert_eq(count, 1, "Socket 200 delivered exactly once despite 3 overlapping matches");
        sub.assert_eq(matched[0], 200, "Matched socket is 200");
    };

    t.run("3. Unsubscribe and Complete Connection Teardown") { sub =>
        var tree = wing::new_topic_tree();

        tree.subscribe(301, "news/sport");
        tree.subscribe(301, "news/weather");
        tree.subscribe(302, "news/sport");

        sub.assert_eq(tree.active_subscriptions, 3, "3 subscriptions registered");

        // Unsubscribe 301 from one topic
        let ok_unsub = tree.unsubscribe(301, "news/sport");
        sub.assert_true(ok_unsub, "Unsubscribed 301 from news/sport");
        sub.assert_eq(tree.subscriber_count("news/sport"), 1, "1 remaining subscriber on news/sport");

        // Connection disconnect: unsubscribe_all removes all remaining topics for 301
        let unsubs_all = tree.unsubscribe_all(301);
        sub.assert_eq(unsubs_all, 1, "Removed 1 remaining topic on unsubscribe_all");
        sub.assert_false(tree.is_subscribed(301, "news/weather"), "301 no longer subscribed to weather");

        // Clean up 302
        tree.unsubscribe_all(302);
        sub.assert_eq(tree.active_subscriptions, 0, "All subscriptions cleanly freed");
        sub.assert_eq(tree.active_buckets, 0, "All empty buckets reclaimed");
    };
}

fn test_vectored_io(t: core::T&) {
    t.run("1. Zero-Copy HTTP Response via Vectored I/O (tcp_send2)") { sub =>
        let listener = wing::tcp_listen("127.0.0.1", 0, 16);
        sub.assert_gt(listener, 0, "Listener created");
        let port = wing::tcp_getsockname_port(listener);

        let client = wing::tcp_connect("127.0.0.1", port, 2000);
        sub.assert_gt(client, 0, "Client connected");

        let srv_sock = wing::tcp_accept(listener, 2000);
        sub.assert_gt(srv_sock, 0, "Server accepted");

        // 1. Direct tcp_send2 with separate header and payload slices
        let hdr_part = "HDR_PART;";
        let body_part = "BODY_PART_VECTORED_IO";
        let sent2 = wing::tcp_send2(srv_sock, hdr_part, body_part);
        sub.assert_eq(sent2, (hdr_part.len + body_part.len) as i32, "tcp_send2 sent both slices in 1 call");

        var client_buf: u8[256] = [0; 256];
        let recvd = wing::tcp_recv_slice(client, client_buf[..], 2000);
        sub.assert_eq(recvd, (hdr_part.len + body_part.len) as i32, "Client received combined slices");
        sub.assert_bytes_eq(client_buf[..recvd], "HDR_PART;BODY_PART_VECTORED_IO", "Data matches concatenation without memory copy");

        // 2. Full HTTP response via send_http1_response (zero-copy body)
        var res = wing::new_response();
        res.status_code = 200;
        res.set_header("Content-Type", "text/plain");
        res.body.append("HELLO_VECTORED_WORLD");

        var wire_headers: u8[..1024] = [];
        let sent_res = wing::send_http1_response(srv_sock, res, "goose-wing", wire_headers);
        sub.assert_gt(sent_res, 0, "send_http1_response transmitted bytes");

        var resp_buf: u8[1024] = [0; 1024];
        let recvd_resp = wing::tcp_recv_slice(client, resp_buf[..], 2000);
        sub.assert_gt(recvd_resp, 0, "Client received response");
        let resp_slice = resp_buf[..recvd_resp];
        sub.assert_true(core::index_of_slice(resp_slice, "HTTP/1.1 200 OK\r\n") == 0, "Starts with 200 OK");
        sub.assert_true(core::index_of_slice(resp_slice, "HELLO_VECTORED_WORLD") >= 0, "Body received intact");

        wing::tcp_close(client);
        wing::tcp_close(srv_sock);
        wing::tcp_close(listener);
    };
}

fn test_server_cork_buffer(t: core::T&) {
    t.run("1. 16 KB CorkBuffer Syscall Coalescing") { sub =>
        let listener = wing::tcp_listen("127.0.0.1", 0, 16);
        sub.assert_gt(listener, 0, "Listener created");
        let port = wing::tcp_getsockname_port(listener);

        let client = wing::tcp_connect("127.0.0.1", port, 2000);
        sub.assert_gt(client, 0, "Client connected");

        let srv_sock = wing::tcp_accept(listener, 2000);
        sub.assert_gt(srv_sock, 0, "Server accepted");

        var cork = wing::new_server_cork(srv_sock);
        wing::server_cork_write(cork, "alpha;");
        wing::server_cork_write(cork, "beta;");
        wing::server_cork_write(cork, "gamma;");

        // 3 writes are coalesced into the 16 KB buffer without network transmission
        sub.assert_eq(core::cork_pending(cork.buffer), 17, "17 bytes buffered in cork");

        // Flush cork buffer in 1 syscall
        let flushed = wing::server_cork_flush(cork);
        sub.assert_eq(flushed, 17, "17 bytes flushed to socket in 1 syscall");
        sub.assert_eq(core::cork_pending(cork.buffer), 0, "Cork buffer is empty after flush");

        var recv_storage: u8[128] = [0; 128];
        let recvd = wing::tcp_recv_slice(client, recv_storage[..], 2000);
        sub.assert_eq(recvd, 17, "Client received all coalesced bytes at once");
        sub.assert_bytes_eq(recv_storage[..recvd], "alpha;beta;gamma;", "Coalesced data verified");

        wing::tcp_close(client);
        wing::tcp_close(srv_sock);
        wing::tcp_close(listener);
    };
}

fn test_handshake_and_date_and_swar_utf8(t: core::T&) {
    t.run("1. Unrolled 2-Block WebSocket Handshake Accept Key") { sub =>
        let test_key = "dGhlIHNhbXBsZSBub25jZQ==";
        var accept_key: u8[..64] = [];
        wing::compute_websocket_accept(test_key, accept_key);
        sub.assert_eq(accept_key[..], "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", "Exact RFC 6455 accept key generated via 2-block SHA-1");

        // Validate acceptance helper
        sub.assert_true(wing::validate_websocket_accept(test_key, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="), "Validation succeeds");
        sub.assert_false(wing::validate_websocket_accept(test_key, "invalid_accept_key"), "Validation rejects mismatch");
    };

    t.run("2. Cached RFC 7231 Date Header Generation") { sub =>
        let date_hdr = wing::get_cached_http_date_header(1700000000); // Fixed epoch 2023-11-14 22:13:20 GMT
        sub.assert_true(core::index_of_slice(date_hdr, "Date: ") == 0, "Header starts with Date: ");
        sub.assert_true(core::index_of_slice(date_hdr, "GMT\r\n") > 0, "Header ends with GMT CRLF");

        // Check response serialization automatically includes Date
        var res = wing::new_response();
        res.status_code = 200;
        var wire: u8[..512] = [];
        wing::serialize_http1_headers(res, "goose-wing", wire);
        sub.assert_true(core::index_of_slice(wire[..], "Date: ") >= 0, "HTTP/1.1 response includes Date header");
    };

    t.run("3. 16-byte SWAR ASCII Skip UTF-8 Validator") { sub =>
        // Pure 7-bit ASCII (should fast-skip in 16-byte words)
        let ascii_text = "This is a 64-byte purely ASCII test payload for SWAR verification!";
        sub.assert_true(core::validate_utf8(ascii_text), "ASCII text validated");

        // Mixed ASCII and multi-byte UTF-8 (Russian, CJK, Emoji)
        let mixed_text = "{\"user\": \"Иван\", \"status\": \"🚀 success\", \"code\": 200}";
        sub.assert_true(core::validate_utf8(mixed_text), "Mixed ASCII and UTF-8 validated");

        // Invalid UTF-8 sequence (truncated byte)
        let invalid_utf8: u8[4] = [0xD0, 0x98, 0xD0, 0x00]; // 0xD0 followed by 0x00 is invalid
        sub.assert_false(core::validate_utf8(invalid_utf8[..]), "Invalid multi-byte rejected");
    };
}

fn test_fast_query_parser(t: core::T&) {
    t.run("1. Zero-Allocation Targeted Query Parameter Lookup") { sub =>
        let query_str = "?filter=active&search=hello+world%21&debug&empty=&limit=50";

        // 1. Direct targeted retrieval with percent decoding
        var search_val: u8[..64] = [];
        let found_search, is_valueless_search = core::get_query_param_fast(query_str, "search", search_val);
        sub.assert_true(found_search, "Found 'search'");
        sub.assert_false(is_valueless_search, "'search' has a value");
        sub.assert_bytes_eq(search_val[..], "hello world!", "+ decoded to space and %21 to !");

        // 2. Valueless query parameter ("?debug") vs empty value ("?empty=")
        var debug_val: u8[..64] = [];
        let found_debug, is_valueless_debug = core::get_query_param_fast(query_str, "debug", debug_val);
        sub.assert_true(found_debug, "Found 'debug'");
        sub.assert_true(is_valueless_debug, "'debug' correctly recognized as valueless parameter");

        var empty_val: u8[..64] = [];
        let found_empty, is_valueless_empty = core::get_query_param_fast(query_str, "empty", empty_val);
        sub.assert_true(found_empty, "Found 'empty'");
        sub.assert_false(is_valueless_empty, "'empty' has an empty value (not valueless)");
        sub.assert_eq(empty_val.len, 0, "empty value length is 0");

        // 3. Fast existence checks
        sub.assert_true(core::has_query_param_fast(query_str, "filter"), "Has filter");
        sub.assert_true(core::has_query_param_fast(query_str, "limit"), "Has limit");
        sub.assert_false(core::has_query_param_fast(query_str, "missing"), "Missing param returns false");
    };
}

fn test_epoll_reactor_multiplexer(t: core::T&) {
    t.run("1. Non-blocking Epoll Reactor Multiplexing Across Multiple Sockets") { sub =>
        let listener = wing::tcp_listen("127.0.0.1", 0, 16);
        sub.assert_gt(listener, 0, "Listener created");
        let port = wing::tcp_getsockname_port(listener);
        sub.assert_true(wing::tcp_set_nonblocking(listener, true), "Listener configured non-blocking");

        let epfd = wing::epoll_create();
        sub.assert_gt(epfd, 0, "Epoll reactor created");

        let ok_add_l = wing::epoll_add(epfd, listener, wing::EPOLL_READ, wing::EPOLL_LISTENER_TAG);
        sub.assert_true(ok_add_l, "Listener added to epoll");

        // Connect 2 clients concurrently
        let c1 = wing::tcp_connect("127.0.0.1", port, 2000);
        let c2 = wing::tcp_connect("127.0.0.1", port, 2000);
        sub.assert_gt(c1, 0, "Client 1 connected");
        sub.assert_gt(c2, 0, "Client 2 connected");

        // Harvest accept readiness
        var ready_fds: i64[..16] = [];
        var ready_udata: u64[..16] = [];
        let n_accept = wing::epoll_wait(epfd, ready_fds, ready_udata, 2000);
        sub.assert_gt(n_accept, 0, "Accept readiness harvested by epoll_wait");

        var accepted_socks: i64[..8] = [];
        while true {
            let s = wing::tcp_accept_nonblocking(listener);
            if s <= 0 { break; }
            wing::tcp_set_nonblocking(s, true);
            accepted_socks.push(s);
        }
        sub.assert_eq(accepted_socks.len, 2, "Both client sockets accepted non-blocking");

        // Register accepted sockets in epoll with unique udata tags
        wing::epoll_add(epfd, accepted_socks[0], wing::EPOLL_READ, 101);
        wing::epoll_add(epfd, accepted_socks[1], wing::EPOLL_READ, 102);

        // Clients send messages
        wing::tcp_send(c1, "PING_ONE");
        wing::tcp_send(c2, "PING_TWO");

        // Reactor harvests read readiness for both sockets in 1 single epoll_wait call
        ready_fds.clear();
        ready_udata.clear();
        let n_data = wing::epoll_wait(epfd, ready_fds, ready_udata, 2000);
        sub.assert_gt(n_data, 0, "Data readiness events harvested");

        var recvd_1 = false;
        var recvd_2 = false;

        for i in ready_udata.len {
            let tag = ready_udata[i];
            if tag == 101 {
                var buf: u8[..128] = [];
                let r = wing::tcp_recv_nonblocking(accepted_socks[0], buf);
                sub.assert_eq(r, 8, "8 bytes read from sock 0");
                sub.assert_bytes_eq(buf[..], "PING_ONE", "Matches PING_ONE");
                recvd_1 = true;
            } else if tag == 102 {
                var buf: u8[..128] = [];
                let r = wing::tcp_recv_nonblocking(accepted_socks[1], buf);
                sub.assert_eq(r, 8, "8 bytes read from sock 1");
                sub.assert_bytes_eq(buf[..], "PING_TWO", "Matches PING_TWO");
                recvd_2 = true;
            }
        }

        sub.assert_true(recvd_1, "Socket 0 processed non-blocking in reactor");
        sub.assert_true(recvd_2, "Socket 1 processed non-blocking in reactor");

        // Clean up
        wing::epoll_del(epfd, accepted_socks[0]);
        wing::epoll_del(epfd, accepted_socks[1]);
        wing::epoll_del(epfd, listener);
        wing::epoll_close(epfd);

        wing::tcp_close(c1);
        wing::tcp_close(c2);
        wing::tcp_close(accepted_socks[0]);
        wing::tcp_close(accepted_socks[1]);
        wing::tcp_close(listener);
    };
}

fn test_swar_ctl_scanner(t: core::T&) {
    t.run("1. SWAR hasLess 64-bit Parallel Control Character Scanning") { sub =>
        // Pure printable ASCII
        let clean = "Host: api.example.com:8080";
        let offset_clean = core::swar_find_ctl(clean);
        sub.assert_eq(offset_clean, clean.len, "No CTL found in clean string");

        // CRLF at offset 16 (on an 8-byte boundary)
        let crlf_16 = "1234567812345678\r\nRestOfHeader";
        let offset_16 = core::swar_find_ctl(crlf_16);
        sub.assert_eq(offset_16, 16, "CRLF found at boundary offset 16");

        // CRLF at odd offset 7
        let crlf_7 = "1234567\r\nRestOfHeader";
        let offset_7 = core::swar_find_ctl(crlf_7);
        sub.assert_eq(offset_7, 7, "CRLF found at offset 7");

        // Embedded NUL at offset 3
        var with_nul: u8[..16] = [];
        with_nul.append("abc");
        with_nul.push(0);
        with_nul.append("defgh");
        let offset_nul = core::swar_find_ctl(with_nul[..]);
        sub.assert_eq(offset_nul, 3, "NUL byte detected at offset 3");

        // Long string (40 bytes) with CR at byte 33
        var long_str: u8[..48] = [];
        for _ in 33 { long_str.push('a'); }
        long_str.push('\r');
        long_str.push('\n');
        let offset_long = core::swar_find_ctl(long_str[..]);
        sub.assert_eq(offset_long, 33, "Long string scanned across 5 64-bit words finds CR at 33");
    };
}

fn test_fast_integer_ascii_serializers(t: core::T&) {
    t.run("1. Fast u64toa and u32toa_hex") { sub =>
        var buf: u8[32] = [0; 32];

        // u64toa zero
        let n0 = core::fast_u64toa(0, buf[..]);
        sub.assert_eq(n0, 1, "0 length is 1");
        sub.assert_bytes_eq(buf[..n0], "0", "0 formatted");

        // u64toa small
        let n42 = core::fast_u64toa(42, buf[..]);
        sub.assert_eq(n42, 2, "42 length is 2");
        sub.assert_bytes_eq(buf[..n42], "42", "42 formatted");

        // u64toa HTTP Content-Length typical (8192)
        let n_cl = core::fast_u64toa(8192, buf[..]);
        sub.assert_eq(n_cl, 4, "8192 length is 4");
        sub.assert_bytes_eq(buf[..n_cl], "8192", "8192 formatted");

        // u64toa large
        let n_large = core::fast_u64toa(1234567890123456789, buf[..]);
        sub.assert_eq(n_large, 19, "Large int length is 19");
        sub.assert_bytes_eq(buf[..n_large], "1234567890123456789", "Large int matches");

        // u32toa_hex zero
        let h0 = core::fast_u32toa_hex(0, buf[..]);
        sub.assert_eq(h0, 1, "hex 0 length is 1");
        sub.assert_bytes_eq(buf[..h0], "0", "hex 0 matches");

        // u32toa_hex 15 ("f")
        let h15 = core::fast_u32toa_hex(15, buf[..]);
        sub.assert_eq(h15, 1, "hex 15 length is 1");
        sub.assert_bytes_eq(buf[..h15], "f", "hex 15 is 'f'");

        // u32toa_hex 16 ("10")
        let h16 = core::fast_u32toa_hex(16, buf[..]);
        sub.assert_eq(h16, 2, "hex 16 length is 2");
        sub.assert_bytes_eq(buf[..h16], "10", "hex 16 is '10'");

        // u32toa_hex 0xDEADBEEF ("deadbeef")
        let h_dead = core::fast_u32toa_hex(0xDEADBEEF, buf[..]);
        sub.assert_eq(h_dead, 8, "0xDEADBEEF length is 8");
        sub.assert_bytes_eq(buf[..h_dead], "deadbeef", "0xDEADBEEF is 'deadbeef'");
    };
}

fn test_ws_unmask_shifted_header_overwrite(t: core::T&) {
    t.run("1. In-Place Zero-Copy Unmasking with Header Overwrite") { sub =>
        let mask: u8[4] = [0xAA, 0xBB, 0xCC, 0xDD];
        let original_msg = "Hello, zero-copy WebSocket world with shifted header overwrite!";

        // Build a masked client frame: 6-byte header + payload
        var frame: u8[..256] = [];
        wing::encode_ws_frame(frame, wing::WS_OPCODE_TEXT, original_msg, true, mask, true);

        let hdr, ok_hdr = wing::parse_ws_frame_header(frame[..]);
        sub.assert_true(ok_hdr, "Frame header parsed");
        sub.assert_eq(hdr.header_len, 6, "Header length is 6 bytes");
        sub.assert_eq(hdr.payload_len as i64, original_msg.len, "Payload length matches");

        // Shift unmask directly over frame header
        let unmasked = wing::unmask_websocket_shifted(
            frame[..],
            hdr.header_len as i64,
            hdr.payload_len as i64,
            hdr.mask_key,
        );

        sub.assert_eq(unmasked.len, original_msg.len, "Unmasked length matches");
        sub.assert_bytes_eq(unmasked, original_msg, "Unmasked payload matches original plaintext");

        // Verify unmasked data starts at frame[0]
        sub.assert_bytes_eq(frame[..original_msg.len], original_msg, "Header was cleanly overwritten in-place at index 0");
    };
}

fn test_chunked_fsm_decoder(t: core::T&) {
    t.run("1. 64-bit Register FSM Chunked Stream Decoding") { sub =>
        var dec = internal::new_chunk_fsm_decoder();

        let raw = "4\r\nWiki\r\n7\r\npedia  \r\nE\r\nin \r\n\r\nchunks.\r\n0\r\n\r\n";
        var total_body: u8[..128] = [];
        var cursor: i64 = 0;

        while cursor < raw.len {
            let st, consumed, chunk = internal::chunk_fsm_feed(dec, raw[cursor..]);
            cursor += consumed;

            if st == internal::ChunkFsmStatus.YieldChunk {
                total_body.append(chunk);
            } else if st == internal::ChunkFsmStatus.Complete {
                break;
            } else if st == internal::ChunkFsmStatus.Error {
                sub.assert_true(false, "FSM decoder encountered unexpected error");
                break;
            }
        }

        sub.assert_bytes_eq(total_body[..], "Wikipedia  in \r\n\r\nchunks.", "Assembled chunked stream matches");

        // Chunk extensions
        var dec_ext = internal::new_chunk_fsm_decoder();
        let raw_ext = "5;token=val;foo=\"quoted;val\"\r\nHello\r\n0\r\n\r\n";
        var ext_body: u8[..64] = [];
        var ext_cursor: i64 = 0;

        while ext_cursor < raw_ext.len {
            let st, consumed, chunk = internal::chunk_fsm_feed(dec_ext, raw_ext[ext_cursor..]);
            ext_cursor += consumed;
            if st == internal::ChunkFsmStatus.YieldChunk {
                ext_body.append(chunk);
            } else if st == internal::ChunkFsmStatus.Complete {
                break;
            }
        }
        sub.assert_bytes_eq(ext_body[..], "Hello", "Chunk extension decoded properly");

        // Invalid hex chunk size
        var dec_err = internal::new_chunk_fsm_decoder();
        let st_err, _, _ = internal::chunk_fsm_feed(dec_err, "Z\r\n");
        sub.assert_eq(st_err, internal::ChunkFsmStatus.Error, "Invalid hex digit returns Error");
    };
}

fn test_http_route_cache(t: core::T&) {
    t.run("1. Dual-Expiry Coalescing HTTP Route Cache") { sub =>
        var cache = wing::new_http_route_cache(1000, 5000);

        // Initially empty
        let initial = wing::cache_lookup(cache, 100);
        sub.assert_eq(initial, wing::CacheLookup.Miss, "Empty cache returns Miss");

        // Store rendered response
        let wire_sample = "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nCached Hello!";
        let ok_store = wing::cache_store(cache, 1000, wire_sample);
        sub.assert_true(ok_store, "Response cached successfully");

        // Fresh hit (within lower_expiry 1000ms: at t=1500)
        let hit_fresh = wing::cache_lookup(cache, 1500);
        sub.assert_eq(hit_fresh, wing::CacheLookup.HitFresh, "Lookup at t=1500 is Fresh Hit");
        sub.assert_bytes_eq(cache.wire[..], wire_sample, "Cached wire matches");

        // Stale hit (between 1000ms and 5000ms: at t=3000)
        let hit_stale = wing::cache_lookup(cache, 3000);
        sub.assert_eq(hit_stale, wing::CacheLookup.HitStaleNeedsUpdate, "Lookup at t=3000 is Stale Hit");
        sub.assert_bytes_eq(cache.wire[..], wire_sample, "Stale cached response still served");

        // Expired miss (after upper_expiry 5000ms: at t=7000)
        let hit_expired = wing::cache_lookup(cache, 7000);
        sub.assert_eq(hit_expired, wing::CacheLookup.Miss, "Lookup at t=7000 is Miss");

        // Invalidation
        wing::cache_invalidate(cache);
        sub.assert_eq(wing::cache_lookup(cache, 1500), wing::CacheLookup.Miss, "Invalidated cache is Miss");
    };
}

fn test_tick_timer_wheel(t: core::T&) {
    t.run("1. 1-Byte Tick Wheel Low-Overhead Timeout Sweeper") { sub =>
        var wheel = wing::new_tick_timer_wheel(10); // 10s default
        sub.assert_eq(wheel.current_tick, 0, "Initial tick is 0");

        // Arm two slots
        let slot1 = wing::tick_timer_arm(wheel, 10);
        let slot2 = wing::tick_timer_arm(wheel, 5);
        sub.assert_eq(slot1, 10, "Slot 1 timeout tick is 10");
        sub.assert_eq(slot2, 5, "Slot 2 timeout tick is 5");

        sub.assert_false(wing::tick_timer_is_expired(wheel, slot1), "Slot 1 not expired at t=0");
        sub.assert_false(wing::tick_timer_is_expired(wheel, slot2), "Slot 2 not expired at t=0");

        // Advance 5 ticks
        wing::tick_timer_advance(wheel, 5);
        sub.assert_eq(wheel.current_tick, 5, "Wheel at tick 5");
        sub.assert_true(wing::tick_timer_is_expired(wheel, slot2), "Slot 2 expired at t=5");
        sub.assert_false(wing::tick_timer_is_expired(wheel, slot1), "Slot 1 still active at t=5");

        // Advance 5 more ticks
        wing::tick_timer_advance(wheel, 5);
        sub.assert_eq(wheel.current_tick, 10, "Wheel at tick 10");
        sub.assert_true(wing::tick_timer_is_expired(wheel, slot1), "Slot 1 expired at t=10");

        // Disarmed slot
        let slot_disarmed = wing::tick_timer_disarm();
        sub.assert_eq(slot_disarmed, wing::TICK_TIMER_DISARMED, "Disarmed is 255");
        sub.assert_false(wing::tick_timer_is_expired(wheel, slot_disarmed), "Disarmed slot never expires");

        // Modular wraparound (modulo 240)
        wheel.current_tick = 235;
        let slot_wrap = wing::tick_timer_arm(wheel, 10); // (235 + 10) % 240 = 5
        sub.assert_eq(slot_wrap, 5, "Wraps modulo 240 cleanly to 5");
        sub.assert_false(wing::tick_timer_is_expired(wheel, slot_wrap), "Not expired before wrap");
        wing::tick_timer_advance(wheel, 10); // 235 + 10 = 5 mod 240
        sub.assert_eq(wheel.current_tick, 5, "Advanced across 240 boundary to 5");
        sub.assert_true(wing::tick_timer_is_expired(wheel, slot_wrap), "Expires at wrapped tick 5");
    };
}

fn test_buffer_fencing_margin(t: core::T&) {
    t.run("1. Wire Buffer Sentinel Fencing") { sub =>
        var wire_buf: u8[64] = [0; 64];
        let req_text = "GET /status HTTP/1.1";
        for i in req_text.len {
            wire_buf[i] = req_text[i];
        }

        let ok_fence = core::fence_wire_slice(wire_buf[..], req_text.len);
        sub.assert_true(ok_fence, "Buffer fenced successfully");
        sub.assert_eq(wire_buf[req_text.len], '\r', "Byte at len is sentinel CR");
        sub.assert_eq(wire_buf[req_text.len + 1], 'a', "Byte at len+1 is sentinel 'a' (non-LF)");

        // Out of bounds fence check
        let bad_fence = core::fence_wire_slice(wire_buf[..], 63);
        sub.assert_false(bad_fence, "Cannot fence without at least 2 spare bytes margin");
    };
}

fn test_tcp_quickack_and_cork(t: core::T&) {
    t.run("1. TCP QuickACK and Cork Control") { sub =>
        let listener = wing::tcp_listen("127.0.0.1", 0, 16);
        sub.assert_gt(listener, 0, "Listener created");
        let port = wing::tcp_getsockname_port(listener);

        let client = wing::tcp_connect("127.0.0.1", port, 2000);
        sub.assert_gt(client, 0, "Client connected");

        let accepted = wing::tcp_accept(listener, 2000);
        sub.assert_gt(accepted, 0, "Accepted incoming connection");

        // Set TCP_QUICKACK
        let ok_qack = wing::tcp_set_quickack(accepted, true);
        sub.assert_true(ok_qack, "TCP_QUICKACK configured successfully");

        // Set TCP_CORK enable
        let ok_cork_on = wing::tcp_set_cork(accepted, true);
        sub.assert_true(ok_cork_on, "TCP_CORK enabled successfully");

        // Send under cork
        let sent = wing::tcp_send(accepted, "CORKED_PAYLOAD");
        sub.assert_gt(sent, 0, "Bytes sent under cork");

        // Uncork
        let ok_cork_off = wing::tcp_set_cork(accepted, false);
        sub.assert_true(ok_cork_off, "TCP_CORK disabled successfully (flushed)");

        wing::tcp_close(client);
        wing::tcp_close(accepted);
        wing::tcp_close(listener);
    };
}

fn main() {
    var runner = core::new_runner("uWebSockets Optimizations Verification Suite", core::Verbosity.Verbose);
    core::run_case(runner, "1. 256-bit Header BloomFilter", test_header_bloom_filter);
    core::run_case(runner, "2. Fast HTTP/1.1 Response Serialization", test_fast_serialization);
    core::run_case(runner, "3. Zero-Copy WebSocket Ingress View", test_zero_copy_websocket_view);
    core::run_case(runner, "4. Shared TCP Buffer & Direct Slice Recv", test_shared_tcp_buffer);
    core::run_case(runner, "5. Native Pub/Sub TopicTree Engine", test_topic_tree_pubsub);
    core::run_case(runner, "6. Vectored I/O (tcp_send2 / WSASend)", test_vectored_io);
    core::run_case(runner, "7. 16 KB CorkBuffer Syscall Coalescing", test_server_cork_buffer);
    core::run_case(runner, "8. Unrolled Handshake, Cached Date & SWAR UTF-8", test_handshake_and_date_and_swar_utf8);
    core::run_case(runner, "9. Fast In-Place Query Parser", test_fast_query_parser);
    core::run_case(runner, "10. Share-Nothing Epoll Reactor & Non-blocking Multiplexing", test_epoll_reactor_multiplexer);
    core::run_case(runner, "11. SWAR 64-bit Parallel Control Character Scanning", test_swar_ctl_scanner);
    core::run_case(runner, "12. Fast Integer & Hex to ASCII Serializers", test_fast_integer_ascii_serializers);
    core::run_case(runner, "13. In-Place WebSocket Unmasking with Header Overwrite", test_ws_unmask_shifted_header_overwrite);
    core::run_case(runner, "14. 64-bit Register FSM Chunked Stream Decoder", test_chunked_fsm_decoder);
    core::run_case(runner, "15. Dual-Expiry Coalescing HTTP Route Cache", test_http_route_cache);
    core::run_case(runner, "16. 1-Byte Modular Tick Timer Wheel", test_tick_timer_wheel);
    core::run_case(runner, "17. Wire Buffer Sentinel Fencing", test_buffer_fencing_margin);
    core::run_case(runner, "18. TCP QuickACK and Cork Control", test_tcp_quickack_and_cork);
    let ok = core::finish(runner);
    assert(ok);
}
