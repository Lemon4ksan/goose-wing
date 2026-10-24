// Verification Suite for Advanced Protocol Systems:
// - RFC 7838 Alt-Svc & H3 Promotion Engine
// - RFC 8297 103 Early Hints & RFC 8470 0-RTT Anti-Replay Guard
// - W3C No-Vary-Search Cache Normalization
// - RFC 9297 HTTP Capsules & RFC 9298 MASQUE CONNECT-UDP
// - HAR 1.2 Telemetry & Microsecond Waterfall Timing
// - Network Isolation Keys (NIK) State Partitioning
import std;
import core from "..";
import wing from "..";

fn test_altsvc_and_h3_promotion(t: core::T&) {
    t.run("1. RFC 7838 Alt-Svc Parsing & Format") { sub =>
        let raw = "h3=\":443\"; ma=86400; persist=1, h2=\"alt.example.com:8443\"; ma=3600";
        var endpoints: wing::AltSvcEndpoint[..4] = [];
        let ok, is_clear = wing::parse_altsvc_header(raw, endpoints);

        sub.assert_true(ok, "Parse valid Alt-Svc header");
        sub.assert_false(is_clear, "Not a clear directive");
        sub.assert_eq(endpoints.len, 2, "2 endpoints parsed");

        // Endpoint 1: h3
        sub.assert_bytes_eq(endpoints[0].proto[..], "h3", "Endpoint 1 proto is h3");
        sub.assert_eq(endpoints[0].port, 443, "Endpoint 1 port is 443");
        sub.assert_eq(endpoints[0].max_age_sec as i64, 86400, "Endpoint 1 max-age is 86400");
        sub.assert_true(endpoints[0].persist, "Endpoint 1 persist flag is true");

        // Endpoint 2: h2
        sub.assert_bytes_eq(endpoints[1].proto[..], "h2", "Endpoint 2 proto is h2");
        sub.assert_bytes_eq(endpoints[1].host[..], "alt.example.com", "Endpoint 2 alternate host");
        sub.assert_eq(endpoints[1].port, 8443, "Endpoint 2 port is 8443");
        sub.assert_eq(endpoints[1].max_age_sec as i64, 3600, "Endpoint 2 max-age is 3600");

        // Clear directive
        var empty_eps: wing::AltSvcEndpoint[..4] = [];
        let ok_clr, is_clr = wing::parse_altsvc_header("clear", empty_eps);
        sub.assert_true(ok_clr, "Parse clear succeeds");
        sub.assert_true(is_clr, "Is clear flag true");

        // Server-side format
        var server_hdr: u8[>..] = [];
        wing::format_altsvc_header(server_hdr, "h3", 443, 86400, true);
        sub.assert_bytes_eq(server_hdr[..], "h3=\":443\"; ma=86400; persist=1", "Server Alt-Svc formatted");
    };

    t.run("2. Alt-Svc Cache Promotion & Backoff on Failure") { sub =>
        var cache = wing::new_altsvc_cache();
        let origin = "example.com:443";
        let raw = "h3=\":443\"; ma=1000";

        // Insert at t = 1000
        wing::altsvc_cache_update(cache, origin, raw, 1000);

        // Lookup at t = 1500 (500s elapsed < 1000s max-age)
        var promoted_ep = wing::AltSvcEndpoint { .. };
        let has_h3 = wing::altsvc_lookup_h3(cache, origin, 1500, promoted_ep);
        sub.assert_true(has_h3, "Lookup succeeds and promotes to HTTP/3");
        sub.assert_bytes_eq(promoted_ep.proto[..], "h3", "Promoted proto is h3");
        sub.assert_eq(promoted_ep.port, 443, "Promoted port is 443");

        // Simulate connection failure (e.g. UDP blocked by firewall)
        wing::altsvc_record_failure(cache, origin, 1501);

        // Immediate subsequent lookup at t = 1502 must fail (broken_until_sec active)
        var fail_ep = wing::AltSvcEndpoint { .. };
        let is_broken = wing::altsvc_lookup_h3(cache, origin, 1502, fail_ep);
        sub.assert_false(is_broken, "Immediate lookup after failure returns false (backoff active)");

        // Clear directive invalidation
        wing::altsvc_cache_update(cache, origin, "clear", 1600);
        let cleared = wing::altsvc_lookup_h3(cache, origin, 1600, fail_ep);
        sub.assert_false(cleared, "Clear directive purged origin from cache");
    };
}

fn test_early_hints_and_replay_guard(t: core::T&) {
    t.run("1. RFC 8297 103 Early Hints Link Preload / Preconnect") { sub =>
        let link_hdr = "</style.css>; rel=preload; as=style, <https://cdn.example.com>; rel=preconnect";
        let hints, ok = wing::parse_early_hints(103, link_hdr);

        sub.assert_true(ok, "Parse 103 Early Hints response");
        sub.assert_eq(hints.links.len, 2, "2 links parsed");

        // Link 1: preload
        sub.assert_bytes_eq(hints.links[0].uri[..], "/style.css", "Link 1 URI");
        sub.assert_true(wing::early_hint_is_preload(hints.links[0]), "Link 1 is preload");
        sub.assert_bytes_eq(hints.links[0].as_type[..], "style", "Link 1 as=style");

        // Link 2: preconnect
        sub.assert_bytes_eq(hints.links[1].uri[..], "https://cdn.example.com", "Link 2 URI");
        sub.assert_true(wing::early_hint_is_preconnect(hints.links[1]), "Link 2 is preconnect");
    };

    t.run("2. RFC 8470 0-RTT Anti-Replay & 425 Too Early Recovery") { sub =>
        // Safe methods allowed in 0-RTT
        sub.assert_true(wing::is_safe_for_early_data("GET"), "GET is safe for 0-RTT");
        sub.assert_true(wing::is_safe_for_early_data("HEAD"), "HEAD is safe for 0-RTT");

        // Mutating methods forbidden by default
        sub.assert_false(wing::is_safe_for_early_data("POST"), "POST is mutating, forbidden in 0-RTT");
        sub.assert_false(wing::is_safe_for_early_data("DELETE"), "DELETE is mutating, forbidden in 0-RTT");

        let dec_post = wing::evaluate_early_data_request("POST", false);
        sub.assert_eq(dec_post, wing::EarlyDataDecision.RejectMutating, "POST evaluated as RejectMutating");

        // Server returns 425 Too Early
        let dec_425 = wing::evaluate_early_data_response(425, true);
        sub.assert_eq(dec_425, wing::EarlyDataDecision.RetryOn1Rtt, "425 triggers transparent 1-RTT retry");

        // Header format
        var req_hdr: u8[>..] = [];
        wing::append_early_data_header(req_hdr);
        sub.assert_bytes_eq(req_hdr[..], "Early-Data: 1\r\n", "Early-Data header appended");
    };
}

fn test_no_vary_search_cache(t: core::T&) {
    t.run("1. W3C No-Vary-Search Header Parser") { sub =>
        let raw = "params, except=(\"id\" \"page\"), key-order";
        let nvs, ok = wing::parse_no_vary_search(raw);

        sub.assert_true(ok, "Parse No-Vary-Search header");
        sub.assert_true(nvs.ignore_all_params, "params flag ignores all params by default");
        sub.assert_eq(nvs.except_params.len, 2, "2 excepted params");
        sub.assert_bytes_eq(nvs.except_params[0][..], "id", "Excepted param 0 is id");
        sub.assert_bytes_eq(nvs.except_params[1][..], "page", "Excepted param 1 is page");
        sub.assert_false(nvs.key_order_matters, "key-order flag means order does not matter");
    };

    t.run("2. Query Parameter Normalization for Cache Hits") { sub =>
        let raw = "params, except=(\"id\")";
        let nvs, _ = wing::parse_no_vary_search(raw);

        // Input URL with marketing tracking tags and id in between
        let input_query = "utm_source=twitter&id=42&utm_medium=social&fbclid=XYZ123";
        var normalized: u8[>..] = [];
        wing::normalize_query_for_cache(input_query, nvs, normalized);

        sub.assert_bytes_eq(normalized[..], "id=42", "Tracking parameters stripped, only excepted id preserved");

        // Parameter order sorting
        let unordered = "b=2&a=1&c=3";
        let nvs_order, _ = wing::parse_no_vary_search("key-order");
        var sorted_q: u8[>..] = [];
        wing::normalize_query_for_cache(unordered, nvs_order, sorted_q);
        sub.assert_bytes_eq(sorted_q[..], "a=1&b=2&c=3", "Parameters sorted alphabetically by key");
    };
}

fn test_masque_capsules_and_datagrams(t: core::T&) {
    t.run("1. RFC 9297 Capsule Codec") { sub =>
        var wire: u8[>..] = [];
        let payload = "capsule_data_payload";
        sub.assert_true(wing::encode_http_capsule(wire, wing::CAPSULE_DATAGRAM, payload), "encode capsule");

        let c, ok = wing::parse_http_capsule(wire[..]);
        sub.assert_true(ok, "parse capsule");
        sub.assert_eq(c.capsule_type, wing::CAPSULE_DATAGRAM, "Capsule type is DATAGRAM (0x00)");
        sub.assert_bytes_eq(c.payload, payload, "Payload matches original");
    };

    t.run("2. MASQUE CONNECT-UDP (RFC 9298) Tunneling") { sub =>
        var path: u8[>..] = [];
        wing::format_connect_udp_path(path, "1.1.1.1", 53);
        sub.assert_bytes_eq(path[..], "/.well-known/masque/udp/1.1.1.1/53/", "MASQUE URI template path");

        // UDP packet datagram capsule
        var datagram_capsule: u8[>..] = [];
        let fake_dns_query = "dns_packet_bytes";
        sub.assert_true(
            wing::encode_connect_udp_datagram_capsule(datagram_capsule, 0, fake_dns_query),
            "encode datagram capsule"
        );

        let parsed_capsule, ok_c = wing::parse_http_capsule(datagram_capsule[..]);
        sub.assert_true(ok_c, "parse datagram capsule");
        sub.assert_eq(parsed_capsule.capsule_type, wing::CAPSULE_DATAGRAM, "Type is DATAGRAM");

        let ctx_id, udp_packet, ok_udp = wing::parse_connect_udp_datagram(parsed_capsule.payload);
        sub.assert_true(ok_udp, "parse connect-udp datagram");
        sub.assert_eq(ctx_id, 0, "Context ID is 0");
        sub.assert_bytes_eq(udp_packet, fake_dns_query, "Decapsulated UDP packet matches");
    };
}

fn test_har_telemetry_and_isolation(t: core::T&) {
    t.run("1. HAR 1.2 Telemetry & Timing Waterfall Serializer") { sub =>
        let timings = wing::RequestTimings {
            blocked_us: 100,
            dns_us: 1250,
            connect_us: 8400,
            ssl_us: 15200,
            send_us: 150,
            wait_us: 25400,
            receive_us: 3200,
        };
        let total_us = wing::compute_total_timing_us(timings);
        sub.assert_eq(total_us, 53700, "Total duration 53.7 ms = 53700 us");

        var entry = wing::HarEntry {
            status: 200,
            request_bytes: 450,
            response_bytes: 12500,
            timings: timings,
            ..
        };
        entry.started_iso8601.append("2026-10-24T18:00:00.000Z");
        entry.method.append("GET");
        entry.url.append("https://api.example.com/v1/data");
        entry.http_version.append("HTTP/3");
        entry.status_text.append("OK");

        var json_buf: u8[>..] = [];
        wing::serialize_har_entry_json(entry, json_buf);

        sub.assert_contains(json_buf[..], "\"time\":53.70", "HAR entry includes total time");
        sub.assert_contains(json_buf[..], "\"url\":\"https://api.example.com/v1/data\"", "HAR entry includes URL");
        sub.assert_contains(json_buf[..], "\"httpVersion\":\"HTTP/3\"", "HAR entry includes HTTP version");
        sub.assert_contains(json_buf[..], "\"ssl\":15.20", "HAR entry includes SSL handshake time");
    };

    t.run("2. Network Isolation Keys (NIK) State Partitioning") { sub =>
        let nik = wing::new_network_isolation_key("https://site-a.com", "https://site-b.com");
        sub.assert_false(nik.is_empty, "NIK is not empty");
        sub.assert_true(nik.is_cross_site, "Cross-site NIK detected");

        var partitioned_key: u8[>..] = [];
        wing::format_partitioned_key("example.com:443", nik, partitioned_key);
        sub.assert_bytes_eq(
            partitioned_key[..],
            "example.com:443{https://site-a.com,https://site-b.com}",
            "Partitioned socket/cache key includes NIK tuple"
        );

        // Empty NIK fallback
        let empty_nik = wing::empty_network_isolation_key();
        var raw_key: u8[>..] = [];
        wing::format_partitioned_key("example.com:443", empty_nik, raw_key);
        sub.assert_bytes_eq(raw_key[..], "example.com:443", "Empty NIK leaves key unpartitioned");
    };
}

fn main() {
    var runner = core::new_runner("Advanced Ecosystem Protocol Systems Suite", core::Verbosity.Verbose);

    core::run_case(runner, "1. RFC 7838 Alt-Svc & H3 Promotion Engine", test_altsvc_and_h3_promotion);
    core::run_case(runner, "2. RFC 8297 Early Hints & RFC 8470 0-RTT Anti-Replay", test_early_hints_and_replay_guard);
    core::run_case(runner, "3. W3C No-Vary-Search Cache Normalization", test_no_vary_search_cache);
    core::run_case(runner, "4. RFC 9297 HTTP Capsules & MASQUE CONNECT-UDP", test_masque_capsules_and_datagrams);
    core::run_case(runner, "5. HAR 1.2 Telemetry Waterfall & Network Isolation Keys", test_har_telemetry_and_isolation);

    let ok = core::finish(runner);
    assert(ok);
}
