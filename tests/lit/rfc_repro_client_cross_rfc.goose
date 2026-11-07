// RUN: goose %s | %FileCheck %s

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Cross-component & RFC edge-case regression suite for `client` and `client/session`.
import std;
import core from "../..";
import headers from "../../http";
import wing from "../..";

// F001: RFC 9112 Section 7.1 - Truncated `Transfer-Encoding: chunked` body without
// terminating `0\r\n\r\n` must return `StreamReadStatus.Error` on the next `read_chunk`
// (instead of spinning in an infinite loop in `read_chunk` / `download_stream`) and
// roll back partial output in `read_all`.
fn test_f001_truncated_chunked_stream_terminates() {
    var resp = wing::Response { status_code: 200, .. };
    wing::set_header(resp.headers, "Transfer-Encoding", "chunked");
    wing::update_response_presence(resp, "Transfer-Encoding");
    // Missing terminating "0\r\n\r\n" chunk
    resp.body.append("5\r\nhello\r\n");

    var reader = wing::new_stream_reader(resp);
    var chunk_buf: u8[>..] = [];
    let st1, eof1 = wing::read_chunk(reader, 16, chunk_buf);
    assert(st1 == wing::StreamReadStatus.Data);
    assert(chunk_buf[..] == "hello");
    assert(!eof1);

    // Next read_chunk sees cursor at end of raw_data while chunk decoder is still in ChunkSize state.
    let st2, _ = wing::read_chunk(reader, 16, chunk_buf);
    assert(st2 == wing::StreamReadStatus.Error);
    assert(reader.finished);

    // Also verify `download_stream` terminates with ErrorKind.Stream instead of hanging
    var c = wing::new_client();
    wing::mock_route(c, "GET", "https://example.com/trunc-chunked", 200, "5\r\nhello\r\n");
    wing::add_mock_header(c, "Transfer-Encoding", "chunked");
    var downloaded: u8[>..] = [];
    let _, dl_err = wing::download_stream(c, "https://example.com/trunc-chunked", 16, downloaded) {};
    assert(!wing::ok(dl_err));
    assert(dl_err.kind == wing::ErrorKind.Stream);
    assert(downloaded.len == 0);

    // Also verify `read_all` rejects truncated chunked stream and rolls back `out`
    var reader2 = wing::new_stream_reader(resp);
    var all_out: u8[>..] = [];
    let emitted = wing::read_all(reader2, all_out);
    assert(emitted == 0);
    assert(all_out.len == 0);
    assert(wing::has_error(reader2.chunk_decoder));
    print("PASS: F001 truncated chunked stream terminates with Error");
}

// F002: RFC 9842 Section 2.1 & Section 2.3 - Compression Dictionary (`dcz`) delta update
// (`Content-Encoding: dcz` + `Use-As-Dictionary` replacing same pattern) must decompress
// the current response with the previous dictionary before updating `dict_cache`, and
// `stage_client_dict_negotiate` must send `Dictionary-ID` when the stored dictionary has `id`.
fn test_f002_compression_dict_id_and_delta_replace() {
    var c = wing::new_client();
    wing::enable_compression_dict(c, true);
    wing::set_clock_us(c, 1000000000);

    // Step 1: Seed initial dictionary v1 with id="dict-v1"
    let dict_v1: const u8[:] = "shared_dictionary_prefix_v1_0123456789abcdef";
    wing::mock_route(c, "GET", "https://cdn.example.com/app/v1.js", 200, dict_v1);
    wing::add_mock_header(c, "Use-As-Dictionary", "match=\"/app/*\", id=\"dict-v1\", ttl=3600");
    let r1, e1 = wing::get(c, "https://cdn.example.com/app/v1.js");
    assert(wing::ok(e1));
    assert(wing::text(r1) == dict_v1);

    // Step 2: Build a dcz-compressed v2 response using dict_v1 that ALSO carries Use-As-Dictionary
    // for the same match="/app/*" pattern (delta update to dict_v2).
    let dict_v2: const u8[:] = "shared_dictionary_prefix_v1_0123456789abcdef_UPDATED_V2";
    var dcz_wire: u8[..512] = [];
    assert(wing::encode_dcz_response(dcz_wire, c.dict_cache.entries[0].sha256_hash, dict_v2));

    wing::mock_route(c, "GET", "https://cdn.example.com/app/v2.js", 200, dcz_wire[..]);
    wing::add_mock_header(c, "Content-Encoding", "dcz");
    wing::add_mock_header(c, "Use-As-Dictionary", "match=\"/app/*\", id=\"dict-v2\", ttl=3600");

    let r2, e2 = wing::get(c, "https://cdn.example.com/app/v2.js");
    assert(wing::ok(e2));
    // RFC 9842 §2.3: Request for v2.js MUST carry Dictionary-ID: "dict-v1"
    assert(wing::sent_header(r2, "Dictionary-ID") == "\"dict-v1\"");
    // Response v2.js MUST be decompressed to dict_v2 before Use-As-Dictionary overwrites dict_v1!
    assert(wing::text(r2) == dict_v2);
    assert(wing::header(r2, "Content-Encoding") == "");

    // Step 3: Next request to /app/v3.js must advertise Dictionary-ID: "dict-v2"
    wing::mock_route(c, "GET", "https://cdn.example.com/app/v3.js", 200, "v3-plain");
    let r3, e3 = wing::get(c, "https://cdn.example.com/app/v3.js");
    assert(wing::ok(e3));
    assert(wing::sent_header(r3, "Dictionary-ID") == "\"dict-v2\"");
    print("PASS: F002 compression dict Dictionary-ID and delta replacement");
}

// F003: RFC 9111 Section 4.1 & Section 4.3.4 - `HttpCache` (`stage_client_cache_lookup` &
// `stage_client_cache_store`) must evaluate `Vary` against effective hop headers (`ctx.headers`
// including `Cookie` from `session.jar`) rather than bare `req.headers`, and populate
// `resp.presence_mask` on cache hits so `has_header(resp, ...)` works on cached responses.
fn test_f003_cache_vary_cookie_and_presence_mask() {
    var c = wing::new_client();
    c.enable_cache = true;
    wing::set_clock_us(c, 1000000000);

    // Seed cookie for Alice in session.jar
    c.jar.set_cookie_header("https://api.example.com/profile", "session_user=alice; Path=/; Secure", c.virtual_clock_us);

    wing::mock_route(c, "GET", "https://api.example.com/profile", 200, "profile:alice");
    wing::add_mock_header(c, "Cache-Control", "max-age=60");
    wing::add_mock_header(c, "Vary", "Cookie");
    wing::add_mock_header(c, "Content-Type", "text/plain");
    wing::add_mock_header(c, "ETag", "\"v1-alice\"");

    let r1, e1 = wing::get(c, "https://api.example.com/profile");
    assert(wing::ok(e1));
    assert(wing::text(r1) == "profile:alice");

    // Same cookie -> cache hit; `has_header(r_hit, "Content-Type")` must be true!
    c.mock_routes.clear();
    let r_hit, e_hit = wing::get(c, "https://api.example.com/profile");
    assert(wing::ok(e_hit));
    assert(wing::text(r_hit) == "profile:alice");
    assert(wing::has_header(r_hit, "Content-Type"));
    assert(wing::has_header(r_hit, "ETag"));

    // Change cookie in jar to Bob -> `Vary: Cookie` MUST miss cache and fetch from origin!
    c.jar.set_cookie_header("https://api.example.com/profile", "session_user=bob; Path=/; Secure", c.virtual_clock_us);
    wing::mock_route(c, "GET", "https://api.example.com/profile", 200, "profile:bob");
    wing::add_mock_header(c, "Cache-Control", "max-age=60");
    wing::add_mock_header(c, "Vary", "Cookie");
    let r_bob, e_bob = wing::get(c, "https://api.example.com/profile");
    assert(wing::ok(e_bob));
    assert(wing::text(r_bob) == "profile:bob");
    print("PASS: F003 HttpCache Vary: Cookie and cached response presence_mask");
}

// F004: RFC 6797 Section 8.3 & RFC 9110 Section 15.4 - Redirect to an `http://` URL on an HSTS
// host must upgrade to `https://` BEFORE computing scheme-downgrade / cross-origin / SameSite
// transitions, and conflicting multiple `Location` headers must be rejected.
fn test_f004_redirect_hsts_pre_upgrade_and_multiple_location() {
    var c = wing::new_client();
    wing::set_clock_us(c, 1000000000);
    c.jar.set_cookie_header("https://secure.example.com/", "strict_sid=s1; Path=/; Secure; SameSite=Strict", c.virtual_clock_us);

    // Hop 0 sets HSTS and redirects to http://secure.example.com/step2
    wing::mock_route(c, "GET", "https://secure.example.com/step1", 302, "");
    wing::add_mock_header(c, "Strict-Transport-Security", "max-age=31536000");
    wing::add_mock_header(c, "Location", "http://secure.example.com/step2");

    wing::mock_route(c, "GET", "https://secure.example.com/step2", 200, "ok-hsts-redirect");

    var req = wing::new_request("GET", "https://secure.example.com/step1");
    wing::bearer(req, "same-origin-secret");
    let r1, e1 = wing::do(c, req);
    assert(wing::ok(e1));
    assert(wing::text(r1) == "ok-hsts-redirect");
    // Because HSTS upgraded http://secure.example.com/step2 -> https://secure.example.com/step2
    // prior to redirect policy evaluation (RFC 6797 §8.3), it is NOT a scheme downgrade or cross-origin hop:
    assert(wing::sent_header(r1, "Referer") == "https://secure.example.com/step1");
    assert(wing::sent_header(r1, "Authorization") == "Bearer same-origin-secret");
    assert(wing::sent_header(r1, "Cookie") == "strict_sid=s1");

    // Conflicting multiple Location headers on 302 must be rejected (RedirectError.MultipleLocationHeaders)
    var c2 = wing::new_client();
    wing::mock_route(c2, "GET", "https://example.com/multi-loc", 302, "");
    wing::add_mock_header(c2, "Location", "https://example.com/dest-a");
    wing::add_mock_header(c2, "Location", "https://evil.example/dest-b");
    let _, e2 = wing::get(c2, "https://example.com/multi-loc");
    assert(!wing::ok(e2));
    print("PASS: F004 HSTS pre-redirect upgrade and conflicting Location rejection");
}

// F005: RFC 7617 Section 2 & RFC 9110 Section 11.6.1 - 401 Basic Auth must support full
// 128-byte username + 128-byte password capacity, reject non-Basic prefix schemes like
// `BasicCustom`, and allow 401 authentication on a redirect target after an earlier hop.
fn test_f005_auth_401_bounds_scheme_boundary_and_redirect_reset() {
    var c = wing::new_client();
    let long_user: const u8[:] = "uuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuu"; // 80B
    let long_pass: const u8[:] = "pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp"; // 80B
    assert(wing::set_credentials(c, long_user, long_pass));

    // 1. Non-Basic scheme `BasicCustom` must NOT trigger Basic credential transmission
    wing::mock_route(c, "GET", "https://example.com/custom-scheme", 401, "unauth");
    wing::add_mock_header(c, "WWW-Authenticate", "BasicCustom realm=\"app\"");
    let r_custom, _ = wing::get(c, "https://example.com/custom-scheme");
    assert(r_custom.status_code == 401);
    assert(wing::sent_header(r_custom, "Authorization") == "");

    // 2. Valid `Basic realm="app"` with 80B+80B (161B > old 140B buffer) must succeed on retry
    wing::mock_route(c, "GET", "https://example.com/long-basic", 401, "");
    wing::add_mock_header(c, "WWW-Authenticate", "Basic realm=\"app\"");
    let r_basic, e_basic = wing::get(c, "https://example.com/long-basic");
    assert(wing::ok(e_basic));
    assert(core::starts_with_fold(wing::sent_header(r_basic, "Authorization"), "Basic "));

    // 3. Redirect target that challenges with 401 after an earlier hop must also be allowed to retry auth
    var c_red = wing::new_client();
    assert(wing::set_credentials(c_red, "admin", "secret"));
    wing::mock_route(c_red, "GET", "https://example.com/entry", 302, "");
    wing::add_mock_header(c_red, "Location", "https://other.example.com/protected");
    wing::mock_route(c_red, "GET", "https://other.example.com/protected", 401, "");
    wing::add_mock_header(c_red, "WWW-Authenticate", "Basic realm=\"other\"");
    let r_red, e_red = wing::get(c_red, "https://example.com/entry");
    assert(wing::ok(e_red));
    assert(core::starts_with_fold(wing::sent_header(r_red, "Authorization"), "Basic "));
    print("PASS: F005 401 Basic capacity, scheme token boundary, and redirect auth");
}

fn main() {
    // Note: F002..F005 run first so we can observe their failure before F001 even if F001 would hang
    test_f002_compression_dict_id_and_delta_replace();
    test_f003_cache_vary_cookie_and_presence_mask();
    test_f004_redirect_hsts_pre_upgrade_and_multiple_location();
    test_f005_auth_401_bounds_scheme_boundary_and_redirect_reset();
    test_f001_truncated_chunked_stream_terminates();
}

// CHECK: PASS: F002 compression dict Dictionary-ID and delta replacement
// CHECK: PASS: F003 HttpCache Vary: Cookie and cached response presence_mask
// CHECK: PASS: F004 HSTS pre-redirect upgrade and conflicting Location rejection
// CHECK: PASS: F005 401 Basic capacity, scheme token boundary, and redirect auth
// CHECK: PASS: F001 truncated chunked stream terminates with Error
