// Verification suite for Compression Dictionary Transport (IETF / Chrome 123+ dcz/dcb):
// - `Use-As-Dictionary` response header parsing & dictionary caching
// - `Available-Dictionary` RFC 8941 Structured Fields byte sequence generation
// - `dcz` (Dictionary-Compressed Zstandard) frame encoding & decoding
// - Client automatic dictionary discovery, Available-Dictionary injection & transparent dcz decompression
// - Origin scoping, pattern matching, TTL expiration, and insecure HTTP rejection
import std;
import core from "..";
import wing from "..";

fn test_dictionary_header_parsing_and_matching(t: core::T&) {
    t.run("Use-As-Dictionary Parser: match, id, ttl") { sub =>
        let raw = "match=\"/assets/*\", id=\"v1\", ttl=3600, type=\"raw\"";
        let p, ok = wing::parse_use_as_dictionary_header(raw);
        sub.assert_true(ok, "parse_use_as_dictionary_header succeeded");
        sub.assert_bytes_eq(p.match_pattern[..], "/assets/*", "match_pattern is /assets/*");
        sub.assert_bytes_eq(p.id[..], "v1", "id is v1");
        sub.assert_eq(p.ttl_sec, 3600, "ttl is 3600");
        sub.assert_bytes_eq(p.dict_type[..], "raw", "type is raw");

        // Semicolon separated format
        let raw_semi = "match=\"/api/*\"; ttl=7200";
        let p2, ok2 = wing::parse_use_as_dictionary_header(raw_semi);
        sub.assert_true(ok2, "semicolon format parsed");
        sub.assert_bytes_eq(p2.match_pattern[..], "/api/*", "match is /api/*");
        sub.assert_eq(p2.ttl_sec, 7200, "ttl is 7200");
    };

    t.run("URL Pattern Matching") { sub =>
        sub.assert_true(wing::url_path_matches_pattern("/assets/app.js", "/assets/*"), "/assets/app.js matches /assets/*");
        sub.assert_true(wing::url_path_matches_pattern("/assets/vendor/chunk.js", "/assets/*"), "subpath matches /assets/*");
        sub.assert_false(wing::url_path_matches_pattern("/api/users", "/assets/*"), "/api/users does NOT match /assets/*");
        sub.assert_true(wing::url_path_matches_pattern("/exact.js", "/exact.js"), "exact match works");
        sub.assert_false(wing::url_path_matches_pattern("/other.js", "/exact.js"), "mismatch works");
    };
}

fn test_dcz_frame_codec(t: core::T&) {
    t.run("DCZ Magic, 32-Byte Hash & Payload Codec") { sub =>
        let dict_data = "dictionary_shared_context_v1";
        let hash = wing::sha256(dict_data);

        let uncompressed_target = "Hello World! This is target data to compress with dcz.";
        var dcz_wire: u8[>..] = [];
        let enc_ok = wing::encode_dcz_response(dcz_wire, hash, uncompressed_target);
        sub.assert_true(enc_ok, "encode_dcz_response ok");

        // Verify wire format:
        // Byte 0..3: 0xFF, 'D', 'C', 'Z'
        sub.assert_true(dcz_wire.len >= 36, "dcz frame is at least 36 bytes");
        sub.assert_eq(dcz_wire[0], 0xFF, "Magic byte 0 is 0xFF");
        sub.assert_eq(dcz_wire[1], 'D' as u8, "Magic byte 1 is 'D'");
        sub.assert_eq(dcz_wire[2], 'C' as u8, "Magic byte 2 is 'C'");
        sub.assert_eq(dcz_wire[3], 'Z' as u8, "Magic byte 3 is 'Z'");

        // Decode DCZ header
        var decoded_hash: u8[32] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let p_slice, dec_ok = wing::decode_dcz_header(dcz_wire[..], decoded_hash);
        sub.assert_true(dec_ok, "decode_dcz_header ok");
        sub.assert_bytes_eq(decoded_hash[..], hash[..], "Decoded 32-byte dict hash matches");

        // Decompress payload using dictionary
        var decompressed: u8[>..] = [];
        let dec_body_ok = wing::decompress_dcz_payload(p_slice, dict_data, decompressed);
        sub.assert_true(dec_body_ok, "decompress_dcz_payload ok");
        sub.assert_bytes_eq(decompressed[..], uncompressed_target, "Decompressed payload matches original target data!");
    };
}

fn test_client_dictionary_lifecycle(t: core::T&) {
    t.run("Request 1 Learns Dictionary, Request 2 Sends Available-Dictionary & Decodes dcz") { sub =>
        var client = wing::new_client();
        wing::set_clock_us(client, 1700000000000000); // t0

        let dict_body = "function sharedCommonUtils() { return 42; }";
        let dict_hash = wing::sha256(dict_body);

        // 1. Mock dictionary endpoint returning Use-As-Dictionary header
        wing::mock_route(client, "GET", "https://cdn.site.com/assets/dict.js", 200, dict_body);
        wing::add_mock_header(client, "Use-As-Dictionary", "match=\"/assets/*\", id=\"v1\", ttl=86400");

        sub.assert_false(wing::has_dictionary_for(client, "https://cdn.site.com/assets/app.js"), "no dictionary before request");

        // Fetch dictionary
        let resp1, err1 = wing::get(client, "https://cdn.site.com/assets/dict.js");
        sub.assert_true(wing::ok(err1), "fetch dict ok");
        sub.assert_eq(wing::status(resp1), 200, "200 OK");

        // Client has now ingested dictionary
        sub.assert_true(wing::has_dictionary_for(client, "https://cdn.site.com/assets/app.js"), "dictionary available for /assets/app.js");
        sub.assert_false(wing::has_dictionary_for(client, "https://cdn.site.com/api/user"), "not available for non-matching path");
        sub.assert_false(wing::has_dictionary_for(client, "https://other.com/assets/app.js"), "not available for different origin");

        // 2. Mock app endpoint returning DCZ compressed response
        let original_app_js = "console.log('App started with shared utils'); sharedCommonUtils();";
        var dcz_payload: u8[>..] = [];
        wing::encode_dcz_response(dcz_payload, dict_hash, original_app_js);

        wing::mock_route(client, "GET", "https://cdn.site.com/assets/app.js", 200, dcz_payload[..]);
        wing::add_mock_header(client, "Content-Encoding", "dcz");

        // Fetch app.js: Client automatically adds Available-Dictionary and decompresses dcz!
        let resp2, err2 = wing::get(client, "https://cdn.site.com/assets/app.js");
        sub.assert_true(wing::ok(err2), "fetch app.js ok");
        sub.assert_eq(wing::status(resp2), 200, "200 OK");

        // Verify client sent Available-Dictionary header
        let sent_avail = wing::sent_header(resp2, "Available-Dictionary");
        sub.assert_true(sent_avail.len > 0, "Available-Dictionary sent in request");
        sub.assert_eq(sent_avail[0], ':' as u8, "Starts with colon (Structured Fields byte sequence)");
        sub.assert_eq(sent_avail[sent_avail.len - 1], ':' as u8, "Ends with colon");

        // Verify transparent dcz decompression!
        sub.assert_bytes_eq(resp2.body[..], original_app_js, "Body was transparently decompressed from dcz!");
    };

    t.run("Dictionary TTL Expiration") { sub =>
        var client = wing::new_client();
        wing::set_clock_us(client, 1700000000000000); // t0

        wing::mock_route(client, "GET", "https://api.site.com/dict", 200, "short_lived_dictionary");
        wing::add_mock_header(client, "Use-As-Dictionary", "match=\"/api/*\", id=\"temp\", ttl=3");

        let _, _ = wing::get(client, "https://api.site.com/dict");
        sub.assert_true(wing::has_dictionary_for(client, "https://api.site.com/api/v1"), "valid at t0");

        // Advance 2s: still valid
        wing::set_clock_us(client, 1700000002000000);
        sub.assert_true(wing::has_dictionary_for(client, "https://api.site.com/api/v1"), "valid at t0+2s (< 3s)");

        // Advance 4s: expired
        wing::set_clock_us(client, 1700000004000000);
        sub.assert_false(wing::has_dictionary_for(client, "https://api.site.com/api/v1"), "expired at t0+4s (>= 3s)");
    };

    t.run("Insecure Transport Security Invariant") { sub =>
        var client = wing::new_client();
        wing::set_clock_us(client, 1700000000000000);

        // Plain HTTP server tries to declare a dictionary
        wing::mock_route(client, "GET", "http://insecure.site.com/dict", 200, "insecure_dict");
        wing::add_mock_header(client, "Use-As-Dictionary", "match=\"/*\"");

        let _, _ = wing::get(client, "http://insecure.site.com/dict");
        sub.assert_false(wing::has_dictionary_for(client, "http://insecure.site.com/page"), "Use-As-Dictionary ignored over insecure HTTP");
    };
}

fn main() {
    var runner = core::new_runner("Compression Dictionary Transport Suite (Chrome 123+ dcz)", core::Verbosity.Verbose);
    core::run_case(runner, "1. Dictionary Header Parsing & Pattern Matching", test_dictionary_header_parsing_and_matching);
    core::run_case(runner, "2. DCZ Wire Format Codec & Decompression", test_dcz_frame_codec);
    core::run_case(runner, "3. Client Dictionary Lifecycle & dcz Decompression", test_client_dictionary_lifecycle);
    let ok = core::finish(runner);
    assert(ok);
}
