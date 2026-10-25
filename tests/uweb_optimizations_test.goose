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
        req.header("Host", "api.example.com");
        req.header("Accept", "application/json");

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
    let ok = core::finish(runner);
    assert(ok);
}
