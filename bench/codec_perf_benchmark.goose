// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Engine Codec Microbenchmark Suite:
// 1. HTTP/1.1 Parser (http::parse_request_headers, http::parse_response_headers)
// 2. HeaderMap & Bloom Filter (http::append_header, set_header, get_header, has_header, add_header, might_have_header)
// 3. URL Parser (core::parse_url, core::parse_url_view)
// 4. HPACK Codec (http2::encode_hpack_field, http2::decode_hpack_to_map with Huffman + dynamic table)
// 5. AEAD Ciphers (AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305 inplace seal/open on 1 KB records)
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe --iters 5000
import std;
import wing from "..";

const DEFAULT_BENCH_ITERS: i64 = 10000;
const AEAD_RECORD_SIZE:    i64 = 1024;

// Prints a non-negative integer scaled by 100 as `whole.frac` (2 decimal places).
fn format_fixed_x100<B>(scaled: u64, out: B&) {
    let clamped = min(scaled, 9000000000000000000) as i64;
    let whole = core::div_euclid_i64(clamped, 100) as u64;
    let frac = core::rem_euclid_i64(clamped, 100) as u64;
    whole.format_u64_dec(out);
    let _ = out.try_push('.');
    if frac < 10 {
        let _ = out.try_push('0');
    }
    frac.format_u64_dec(out);
}

// Emits one structured machine-readable benchmark line and checks non-zero checksum.
fn report_bench(
    name:        const u8[:],
    iters:       i64,
    elapsed_ns:  i64,
    bytes_total: u64,
    checksum:    u64,
) {
    assert(checksum != 0);
    let eff_ns = max(elapsed_ns, 1) as u64;
    let u_iters = max(iters, 1) as u64;
    let num_ns = core::add_sat_u64(core::mul_sat_u64(eff_ns, 100), u_iters >> 1);
    let num_mb = core::add_sat_u64(core::mul_sat_u64(bytes_total, 100000), eff_ns >> 1);
    let ns_op_x100 = core::div_euclid_i64(min(num_ns, 9000000000000000000) as i64, u_iters as i64) as u64;
    let mb_s_x100 = core::div_euclid_i64(min(num_mb, 9000000000000000000) as i64, eff_ns as i64) as u64;

    var ns_buf: u8[..32] = [];
    var mb_buf: u8[..32] = [];
    format_fixed_x100(ns_op_x100, ns_buf);
    format_fixed_x100(mb_s_x100, mb_buf);

    print(
        "BENCH ", name,
        " iters=", iters,
        " ns_op=", ns_buf[..],
        " mb_s=", mb_buf[..],
        " checksum=", checksum,
    );
}

// Parses `--iters <N>` or positional `<N>` from CLI arguments, falling back to DEFAULT_BENCH_ITERS.
//
// Example:
//   argv = ["codec_perf_benchmark.exe", "--iters", "5000"]
//   returns: 5000
fn parse_iters_arg<S>(argv: const S[:]) -> i64 {
    var i: u64 = 1;
    let argc = argv.len as u64;
    while i < argc {
        let arg = argv[i];
        let next_i = core::add_sat_u64(i, 1);
        if arg == "--iters" && next_i < argc {
            let parsed, ok = argv[next_i].parse_i64_dec();
            if ok && parsed > 0 {
                return parsed;
            }
        }
        let pos_val, pos_ok = arg.parse_i64_dec();
        if pos_ok && pos_val > 0 {
            return pos_val;
        }
        i = next_i;
    }
    return DEFAULT_BENCH_ITERS;
}

inline fn calc_warmup_iters(iters: i64) -> i64 {
    let tenth = max(iters, 0) >> 3;
    return min(max(tenth, 64), 2000);
}

fn append_sample_h1_request<B>(out: B&) {
    out.clear();
    assert(out.try_append("GET /api/v1/orders?page=2&limit=50 HTTP/1.1\r\n"));
    assert(out.try_append("Host: api.example.com\r\n"));
    assert(out.try_append("User-Agent: goose-wing/2.0\r\n"));
    assert(out.try_append("Accept: application/json\r\n"));
    assert(out.try_append("Accept-Encoding: gzip, br\r\n"));
    assert(out.try_append("Authorization: Bearer tok_bench_0123456789abcdef\r\n"));
    assert(out.try_append("Content-Type: application/json\r\n"));
    assert(out.try_append("Cookie: sid=abc123; theme=dark\r\n"));
    assert(out.try_append("X-Request-Id: req-9f3d2a1b-4c5e\r\n"));
    assert(out.try_append("Connection: keep-alive\r\n\r\n"));
}

fn bench_h1_request(iters: i64) -> u64 {
    var req_buf: u8[..512] = [];
    append_sample_h1_request(req_buf);
    let req_wire = req_buf[..];

    var map = http::HeaderMap { .. };
    let warmup = calc_warmup_iters(iters);
    var checksum: u64 = 0;

    for _ in warmup {
        let err = http::parse_request_headers(req_wire, map);
        assert(http::is_ok(err));
        checksum = core::add_sat_u64(checksum, map.entries.len as u64);
    }

    let watch = core::stopwatch();
    for _ in iters {
        let err = http::parse_request_headers(req_wire, map);
        assert(http::is_ok(err) && map.entries.len == 9);
        let req_id = http::get_header(map, "x-request-id");
        checksum = core::add_sat_u64(checksum, core::add_sat_u64(map.entries.len as u64, req_id.len as u64));
    }
    let dt = core::elapsed(watch);
    let total_bytes = core::mul_sat_u64(iters as u64, req_wire.len as u64);
    report_bench("h1_parse_request", iters, dt.as_nanos(), total_bytes, checksum);
    return checksum;
}

fn append_sample_h1_response<B>(out: B&) {
    out.clear();
    assert(out.try_append("HTTP/1.1 200 OK\r\n"));
    assert(out.try_append("Date: Thu, 13 Nov 2026 14:00:00 GMT\r\n"));
    assert(out.try_append("Server: goose-wing/2.0\r\n"));
    assert(out.try_append("Content-Type: application/json; charset=utf-8\r\n"));
    assert(out.try_append("Content-Length: 1024\r\n"));
    assert(out.try_append("Cache-Control: max-age=60, stale-while-revalidate=30\r\n"));
    assert(out.try_append("ETag: \"v1-8a9b0c1d\"\r\n"));
    assert(out.try_append("X-Trace-Id: trace-001122334455\r\n"));
    assert(out.try_append("Connection: keep-alive\r\n\r\n"));
}

fn bench_h1_response(iters: i64) -> u64 {
    var resp_buf: u8[..512] = [];
    append_sample_h1_response(resp_buf);
    let resp_wire = resp_buf[..];

    var map = http::HeaderMap { .. };
    let warmup = calc_warmup_iters(iters);
    var checksum: u64 = 0;

    for _ in warmup {
        let err = http::parse_response_headers(resp_wire, map);
        assert(http::is_ok(err));
        checksum = core::add_sat_u64(checksum, map.status_code as u64);
    }

    let watch = core::stopwatch();
    for _ in iters {
        let err = http::parse_response_headers(resp_wire, map);
        assert(http::is_ok(err) && map.status_code == 200);
        let etag = http::get_header(map, "etag");
        checksum = core::add_sat_u64(checksum, core::add_sat_u64(map.status_code as u64, etag.len as u64));
    }
    let dt = core::elapsed(watch);
    let total_bytes = core::mul_sat_u64(iters as u64, resp_wire.len as u64);
    report_bench("h1_parse_response", iters, dt.as_nanos(), total_bytes, checksum);
    return checksum;
}

fn populate_sample_headermap(map: http::HeaderMap&) -> i64 {
    http::clear(map);
    assert(http::append_header(map, "Host", "api.example.com"));
    assert(http::append_header(map, "Content-Type", "application/json"));
    assert(http::append_header(map, "Authorization", "Bearer tok_bench_0123456789abcdef"));
    assert(http::append_header(map, "Accept-Encoding", "gzip, br"));
    assert(http::append_header(map, "Connection", "keep-alive"));
    assert(http::append_header(map, "X-Trace-B3", "80f198ee56343ba864fe8b2a57d3eff7"));
    http::set_header(map, "X-Request-Id", "req-9f3d2a1b-4c5e");
    return map.raw_buf.len;
}

fn bench_headermap_write(iters: i64) -> u64 {
    var map = http::HeaderMap { .. };
    let warmup = calc_warmup_iters(iters);
    var checksum: u64 = 0;

    for _ in warmup {
        checksum = core::add_sat_u64(checksum, populate_sample_headermap(map) as u64);
    }

    var bytes_per_op: i64 = 0;
    let watch = core::stopwatch();
    for _ in iters {
        bytes_per_op = populate_sample_headermap(map);
        checksum = core::add_sat_u64(checksum, core::add_sat_u64(bytes_per_op as u64, map.entries.len as u64));
    }
    let dt = core::elapsed(watch);
    let total_bytes = core::mul_sat_u64(iters as u64, bytes_per_op as u64);
    report_bench("headermap_append_set", iters, dt.as_nanos(), total_bytes, checksum);
    return checksum;
}

fn bench_headermap_lookup(iters: i64) -> u64 {
    var map = http::HeaderMap { .. };
    let _ = populate_sample_headermap(map);
    let keys:      const u8[:][4] = ["Host", "content-type", "X-Request-Id", "x-trace-b3"];
    let avg_bytes: u64            = 29;
    let warmup = calc_warmup_iters(iters);
    var checksum: u64 = 0;

    for k in warmup {
        let key = keys[k & 3];
        assert(http::has_header(map, key));
        checksum = core::add_sat_u64(checksum, http::get_header(map, key).len as u64);
    }

    let watch = core::stopwatch();
    for k in iters {
        let key = keys[k & 3];
        let present = http::has_header(map, key);
        let val = http::get_header(map, key);
        assert(present && val.len > 0);
        checksum = core::add_sat_u64(checksum, core::add_sat_u64(val.len as u64, val[0]));
    }
    let dt = core::elapsed(watch);
    let total_bytes = core::mul_sat_u64(iters as u64, avg_bytes);
    report_bench("headermap_get_has_hit", iters, dt.as_nanos(), total_bytes, checksum);
    return checksum;
}

fn bench_bloom_filter(iters: i64) -> u64 {
    var bf = http::HeaderBloomFilter { .. };
    let present_keys: const u8[:][8] = [
        "Host",
        "Content-Type",
        "Authorization",
        "Accept-Encoding",
        "Connection",
        "X-Trace-B3",
        "X-Request-Id",
        "User-Agent",
    ];
    for key in present_keys {
        http::add_header(bf, key);
        assert(http::might_have_header(bf, key));
    }

    let miss_keys: const u8[:][4] = [
        "Sec-WebSocket-Key",
        "Proxy-Authenticate",
        "X-Forwarded-Proto",
        "Transfer-Encoding",
    ];
    for mkey in miss_keys {
        assert(!http::might_have_header(bf, mkey));
    }

    let warmup = calc_warmup_iters(iters);
    var checksum: u64 = 0;
    for k in warmup {
        let mk = miss_keys[k & 3];
        let hit = http::might_have_header(bf, mk);
        assert(!hit);
        checksum = core::add_sat_u64(checksum, mk.len as u64);
    }

    let watch = core::stopwatch();
    for k in iters {
        let mk = miss_keys[k & 3];
        let hit = http::might_have_header(bf, mk);
        assert(!hit);
        checksum = core::add_sat_u64(checksum, mk.len as u64);
    }
    let dt = core::elapsed(watch);
    let total_bytes = core::mul_sat_u64(iters as u64, 18);
    report_bench("bloom_fast_miss", iters, dt.as_nanos(), total_bytes, checksum);
    return checksum;
}

fn bench_url_parse(iters: i64) -> u64 {
    let urls: const u8[:][4] = [
        "https://api.example.com:8443/api/v1/../v2/users/42/orders?status=active&limit=50&sort=desc",
        "http://svc.internal:8080/v1/catalog/items/9876/./details?currency=USD&include=inventory",
        "https://cdn.assets.example.org/static/2026/11/../12/bundle.min.js?v=42&cache=1",
        "https://auth.example.net:9443/oauth2/authorize?client_id=gw_app&response_type=code&scope=read",
    ];

    let warmup = calc_warmup_iters(iters);
    var checksum: u64 = 0;
    for k in warmup {
        let u, err = core::parse_url(urls[k & 3]);
        assert(core::is_ok(err) && u.valid);
        checksum = core::add_sat_u64(checksum, u.href.len as u64);
    }

    var total_bytes: u64 = 0;
    let watch = core::stopwatch();
    for k in iters {
        let raw = urls[k & 3];
        total_bytes = core::add_sat_u64(total_bytes, raw.len as u64);
        let u, err = core::parse_url(raw);
        assert(core::is_ok(err) && u.valid);
        let path_len = core::sub_sat_i64(u.pathname_end, u.pathname_start) as u64;
        checksum = core::add_sat_u64(checksum, core::add_sat_u64(u.href.len as u64, path_len));
    }
    let dt = core::elapsed(watch);
    report_bench("url_parse", iters, dt.as_nanos(), total_bytes, checksum);
    return checksum;
}

fn bench_url_parse_view(iters: i64) -> u64 {
    let urls: const u8[:][4] = [
        "https://api.example.com:8443/api/v1/../v2/users/42/orders?status=active&limit=50&sort=desc",
        "http://svc.internal:8080/v1/catalog/items/9876/./details?currency=USD&include=inventory",
        "https://cdn.assets.example.org/static/2026/11/../12/bundle.min.js?v=42&cache=1",
        "https://auth.example.net:9443/oauth2/authorize?client_id=gw_app&response_type=code&scope=read",
    ];

    let warmup = calc_warmup_iters(iters);
    var checksum: u64 = 0;
    for k in warmup {
        let v, err = core::parse_url_view(urls[k & 3]);
        assert(core::is_ok(err) && v.valid);
        checksum = core::add_sat_u64(checksum, v.host.len as u64);
    }

    var total_bytes: u64 = 0;
    let watch = core::stopwatch();
    for k in iters {
        let raw = urls[k & 3];
        total_bytes = core::add_sat_u64(total_bytes, raw.len as u64);
        let v, err = core::parse_url_view(raw);
        assert(core::is_ok(err) && v.valid);
        let sum_parts = core::add_sat_u64(v.host.len as u64, core::add_sat_u64(v.pathname.len as u64, v.search.len as u64));
        checksum = core::add_sat_u64(checksum, sum_parts);
    }
    let dt = core::elapsed(watch);
    report_bench("url_parse_view", iters, dt.as_nanos(), total_bytes, checksum);
    return checksum;
}

fn encode_sample_hpack_block<B>(
    dt:       http2::DynamicTable&,
    out:      B&,
    path_val: const u8[:],
    req_id:   const u8[:],
) -> u64 {
    out.clear();
    let inc = http2::HpackIndexing.Incremental;
    let lit_none = http2::HpackIndexing.None;
    assert(http2::encode_hpack_field(dt, out, ":method", "GET", inc, true));
    assert(http2::encode_hpack_field(dt, out, ":scheme", "https", inc, true));
    assert(http2::encode_hpack_field(dt, out, ":authority", "api.example.com", inc, true));
    assert(http2::encode_hpack_field(dt, out, ":path", path_val, inc, true));
    assert(http2::encode_hpack_field(dt, out, "accept", "application/json", inc, true));
    assert(http2::encode_hpack_field(dt, out, "user-agent", "goose-wing/2.0", inc, true));
    assert(http2::encode_hpack_field(dt, out, "content-type", "application/json", inc, true));
    assert(http2::encode_hpack_field(dt, out, "x-request-id", req_id, lit_none, true));
    let fixed_bytes: u64 = 138;
    return core::add_sat_u64(fixed_bytes, core::add_sat_u64(path_val.len as u64, req_id.len as u64));
}

fn bench_hpack_encode(iters: i64) -> u64 {
    var dt = http2::new_dynamic_table();
    var out: u8[..1024] = [];
    let paths:   const u8[:][2] = ["/api/v1/orders?page=1", "/api/v1/orders?page=2"];
    let req_ids: const u8[:][2] = ["req-9f3d2a1b-0001", "req-9f3d2a1b-0002"];

    let warmup = calc_warmup_iters(iters);
    var checksum: u64 = 0;
    for k in warmup {
        let _ = encode_sample_hpack_block(dt, out, paths[k & 1], req_ids[k & 1]);
        checksum = core::add_sat_u64(checksum, out.len as u64);
    }

    var total_bytes: u64 = 0;
    let watch = core::stopwatch();
    for k in iters {
        total_bytes = core::add_sat_u64(total_bytes, encode_sample_hpack_block(dt, out, paths[k & 1], req_ids[k & 1]));
        checksum = core::add_sat_u64(checksum, core::add_sat_u64(out.len as u64, out[0]));
    }
    let dt_elapsed = core::elapsed(watch);
    report_bench("hpack_encode_huffman", iters, dt_elapsed.as_nanos(), total_bytes, checksum);
    return checksum;
}

fn bench_hpack_decode(iters: i64) -> u64 {
    var enc_dt = http2::new_dynamic_table();
    var wire_block: u8[..1024] = [];
    let raw_bytes = encode_sample_hpack_block(
        enc_dt, wire_block, "/api/v1/orders?page=1", "req-9f3d2a1b-0001",
    );

    var dec_dt = http2::new_dynamic_table();
    var pseudo = http2::PseudoHeaders { .. };
    var hdrs = http::HeaderMap { .. };
    let warmup = calc_warmup_iters(iters);
    var checksum: u64 = 0;

    for _ in warmup {
        let err = http2::decode_hpack_to_map(dec_dt, wire_block[..], pseudo, hdrs);
        assert(err == 0 && pseudo.has_method && hdrs.entries.len == 4);
        checksum = core::add_sat_u64(checksum, pseudo.path.len as u64);
    }

    let watch = core::stopwatch();
    for _ in iters {
        let err = http2::decode_hpack_to_map(dec_dt, wire_block[..], pseudo, hdrs);
        assert(err == 0 && pseudo.has_method && hdrs.entries.len == 4);
        let req_id = http::get_header(hdrs, "x-request-id");
        checksum = core::add_sat_u64(checksum, core::add_sat_u64(pseudo.path.len as u64, req_id.len as u64));
    }
    let dt_elapsed = core::elapsed(watch);
    let total_bytes = core::mul_sat_u64(iters as u64, raw_bytes);
    report_bench("hpack_decode_huffman", iters, dt_elapsed.as_nanos(), total_bytes, checksum);

    var name_buf: u8[..256]  = [];
    var val_buf:  u8[..8192] = [];
    let w_scratch = core::stopwatch();
    for _ in iters {
        let err = http2::decode_hpack_to_map_with_scratch(
            dec_dt, wire_block[..], pseudo, hdrs, name_buf, val_buf,
        );
        assert(err == 0 && pseudo.has_method && hdrs.entries.len == 4);
        let req_id = http::get_header(hdrs, "x-request-id");
        checksum = core::add_sat_u64(checksum, core::add_sat_u64(pseudo.path.len as u64, req_id.len as u64));
    }
    let dt_scratch = core::elapsed(w_scratch);
    report_bench("hpack_decode_huffman_scratch", iters, dt_scratch.as_nanos(), total_bytes, checksum);
    return checksum;
}

fn fill_aead_fixtures(
    pt:    u8[1024]&,
    aad:   u8[13]&,
    key16: u8[16]&,
    key32: u8[32]&,
    nonce: u8[12]&,
) {
    for i in AEAD_RECORD_SIZE {
        let val = core::add_sat_u64(core::mul_sat_u64(i as u64, 131), 17);
        pt[i] = (val & 0xFF) as u8;
    }
    for i in 13 {
        aad[i] = core::add_sat_u64(0xA0, i as u64) as u8;
    }
    for i in 16 {
        key16[i] = core::add_sat_u64(0x10, i as u64) as u8;
    }
    for i in 32 {
        key32[i] = core::add_sat_u64(0x30, i as u64) as u8;
    }
    for i in 12 {
        nonce[i] = core::add_sat_u64(0x50, i as u64) as u8;
    }
}

fn bench_aes128_gcm(
    iters: i64,
    pt:    const u8[1024]&,
    aad:   const u8[13]&,
    key16: const u8[16]&,
    nonce: const u8[12]&,
) -> u64 {
    var work: u8[1024] = pt;
    let warmup = calc_warmup_iters(iters);
    var checksum: u64 = 0;

    for _ in warmup {
        let tag, ok = core::aes128_gcm_seal_inplace(key16, nonce, work[..], aad[..]);
        assert(ok);
        checksum = core::add_sat_u64(checksum, tag[0]);
    }

    let w_seal = core::stopwatch();
    for _ in iters {
        let tag, ok = core::aes128_gcm_seal_inplace(key16, nonce, work[..], aad[..]);
        assert(ok);
        checksum = core::add_sat_u64(checksum, core::add_sat_u64(tag[0], work[0]));
    }
    let dt_seal = core::elapsed(w_seal);
    let total_bytes = core::mul_sat_u64(iters as u64, AEAD_RECORD_SIZE as u64);
    report_bench("aes128_gcm_seal_1kb", iters, dt_seal.as_nanos(), total_bytes, checksum);

    var ct: u8[1024] = pt;
    let open_tag, seal_ok = core::aes128_gcm_seal_inplace(key16, nonce, ct[..], aad[..]);
    assert(seal_ok);

    let w_open = core::stopwatch();
    for _ in iters {
        work = ct;
        let dec_len, ok = core::aes128_gcm_open_inplace(
            key16, nonce, work[..], aad[..], open_tag,
        );
        assert(ok && dec_len == AEAD_RECORD_SIZE && work[0] == pt[0] && work[1023] == pt[1023]);
        checksum = core::add_sat_u64(checksum, work[512]);
    }
    let dt_open = core::elapsed(w_open);
    report_bench("aes128_gcm_open_1kb", iters, dt_open.as_nanos(), total_bytes, checksum);
    return checksum;
}

fn bench_aes256_gcm(
    iters: i64,
    pt:    const u8[1024]&,
    aad:   const u8[13]&,
    key32: const u8[32]&,
    nonce: const u8[12]&,
) -> u64 {
    var work: u8[1024] = pt;
    let warmup = calc_warmup_iters(iters);
    var checksum: u64 = 0;

    for _ in warmup {
        let tag, ok = core::aes256_gcm_seal_inplace(key32, nonce, work[..], aad[..]);
        assert(ok);
        checksum = core::add_sat_u64(checksum, tag[0]);
    }

    let w_seal = core::stopwatch();
    for _ in iters {
        let tag, ok = core::aes256_gcm_seal_inplace(key32, nonce, work[..], aad[..]);
        assert(ok);
        checksum = core::add_sat_u64(checksum, core::add_sat_u64(tag[0], work[0]));
    }
    let dt_seal = core::elapsed(w_seal);
    let total_bytes = core::mul_sat_u64(iters as u64, AEAD_RECORD_SIZE as u64);
    report_bench("aes256_gcm_seal_1kb", iters, dt_seal.as_nanos(), total_bytes, checksum);

    var ct: u8[1024] = pt;
    let open_tag, seal_ok = core::aes256_gcm_seal_inplace(key32, nonce, ct[..], aad[..]);
    assert(seal_ok);

    let w_open = core::stopwatch();
    for _ in iters {
        work = ct;
        let dec_len, ok = core::aes256_gcm_open_inplace(
            key32, nonce, work[..], aad[..], open_tag,
        );
        assert(ok && dec_len == AEAD_RECORD_SIZE && work[0] == pt[0] && work[1023] == pt[1023]);
        checksum = core::add_sat_u64(checksum, work[512]);
    }
    let dt_open = core::elapsed(w_open);
    report_bench("aes256_gcm_open_1kb", iters, dt_open.as_nanos(), total_bytes, checksum);
    return checksum;
}

fn bench_chacha20_poly1305(
    iters: i64,
    pt:    const u8[1024]&,
    aad:   const u8[13]&,
    key32: const u8[32]&,
    nonce: const u8[12]&,
) -> u64 {
    var work: u8[1024] = pt;
    let warmup = calc_warmup_iters(iters);
    var checksum: u64 = 0;

    for _ in warmup {
        let tag, ok = core::chacha20_poly1305_seal_inplace(key32, nonce, work[..], aad[..]);
        assert(ok);
        checksum = core::add_sat_u64(checksum, tag[0]);
    }

    let w_seal = core::stopwatch();
    for _ in iters {
        let tag, ok = core::chacha20_poly1305_seal_inplace(key32, nonce, work[..], aad[..]);
        assert(ok);
        checksum = core::add_sat_u64(checksum, core::add_sat_u64(tag[0], work[0]));
    }
    let dt_seal = core::elapsed(w_seal);
    let total_bytes = core::mul_sat_u64(iters as u64, AEAD_RECORD_SIZE as u64);
    report_bench("chacha20_poly1305_seal_1kb", iters, dt_seal.as_nanos(), total_bytes, checksum);

    var ct: u8[1024] = pt;
    let open_tag, seal_ok = core::chacha20_poly1305_seal_inplace(key32, nonce, ct[..], aad[..]);
    assert(seal_ok);

    let w_open = core::stopwatch();
    for _ in iters {
        work = ct;
        let dec_len, ok = core::chacha20_poly1305_open_inplace(
            key32, nonce, work[..], aad[..], open_tag,
        );
        assert(ok && dec_len == AEAD_RECORD_SIZE && work[0] == pt[0] && work[1023] == pt[1023]);
        checksum = core::add_sat_u64(checksum, work[512]);
    }
    let dt_open = core::elapsed(w_open);
    report_bench("chacha20_poly1305_open_1kb", iters, dt_open.as_nanos(), total_bytes, checksum);
    return checksum;
}

fn bench_url_parse_into(iters: i64) -> u64 {
    let urls: const u8[:][4] = [
        "https://api.example.com:8443/api/v1/../v2/users/42/orders?status=active&limit=50&sort=desc",
        "http://svc.internal:8080/v1/catalog/items/9876/./details?currency=USD&include=inventory",
        "https://cdn.assets.example.org/static/2026/11/../12/bundle.min.js?v=42&cache=1",
        "https://auth.example.net:9443/oauth2/authorize?client_id=gw_app&response_type=code&scope=read",
    ];

    let warmup = calc_warmup_iters(iters);
    var checksum: u64 = 0;
    for k in warmup {
        let u, err = core::parse_url(urls[k & 3]);
        assert(core::is_ok(err) && u.valid);
        checksum = core::add_sat_u64(checksum, u.href.len as u64);
    }

    var total_bytes: u64 = 0;
    let watch = core::stopwatch();
    for k in iters {
        let raw = urls[k & 3];
        total_bytes = core::add_sat_u64(total_bytes, raw.len as u64);
        let u, err = core::parse_url(raw);
        assert(core::is_ok(err) && u.valid);
        let path_len = core::sub_sat_i64(u.pathname_end, u.pathname_start) as u64;
        checksum = core::add_sat_u64(checksum, core::add_sat_u64(u.href.len as u64, path_len));
    }
    let dt = core::elapsed(watch);
    report_bench("url_parse_into", iters, dt.as_nanos(), total_bytes, checksum);
    return checksum;
}

fn bench_aes_gcm_prepared(
    iters:     i64,
    seal_name: const u8[:],
    open_name: const u8[:],
    key:       const u8[:],
    pt:        const u8[1024]&,
    aad:       const u8[13]&,
    nonce:     const u8[12]&,
) -> u64 {
    var ctx = core::AesGcmKey { .. };
    defer core::zeroize_aes_gcm_key(ctx);
    assert(core::aes_gcm_prepare_key(key, ctx));

    var work: u8[1024] = pt;
    let warmup = calc_warmup_iters(iters);
    var checksum: u64 = 0;

    for _ in warmup {
        let tag, n, ok = core::aes_gcm_seal_prepared_inplace(ctx, nonce, work[..], aad[..]);
        assert(ok && n == AEAD_RECORD_SIZE);
        checksum = core::add_sat_u64(checksum, tag[0]);
    }

    let w_seal = core::stopwatch();
    for _ in iters {
        let tag, n, ok = core::aes_gcm_seal_prepared_inplace(ctx, nonce, work[..], aad[..]);
        assert(ok && n == AEAD_RECORD_SIZE);
        checksum = core::add_sat_u64(checksum, core::add_sat_u64(tag[0], work[0]));
    }
    let dt_seal = core::elapsed(w_seal);
    let total_bytes = core::mul_sat_u64(iters as u64, AEAD_RECORD_SIZE as u64);
    report_bench(seal_name, iters, dt_seal.as_nanos(), total_bytes, checksum);

    var ct: u8[1024] = pt;
    let open_tag, ct_n, seal_ok = core::aes_gcm_seal_prepared_inplace(ctx, nonce, ct[..], aad[..]);
    assert(seal_ok && ct_n == AEAD_RECORD_SIZE);

    let w_open = core::stopwatch();
    for _ in iters {
        let dec_len, ok = core::aes_gcm_open_prepared_into(
            ctx, nonce, ct[..], aad[..], open_tag, work[..],
        );
        assert(ok && dec_len == AEAD_RECORD_SIZE && work[0] == pt[0] && work[1023] == pt[1023]);
        checksum = core::add_sat_u64(checksum, work[512]);
    }
    let dt_open = core::elapsed(w_open);
    report_bench(open_name, iters, dt_open.as_nanos(), total_bytes, checksum);
    return checksum;
}

fn fill_compression_payload(buf: u8[1024]&) {
    let parts: const u8[:][5] = [
        "{\"status\":200,\"message\":\"ok\",\"service\":\"goose-wing-gateway\",\"timestamp\":1710000000,",
        "\"user\":{\"id\":1001,\"username\":\"gopher_goose\",\"roles\":[\"admin\",\"operator\"],\"active\":true},",
        "\"metrics\":{\"requests\":1054320,\"p99_latency_ms\":1.42,\"error_rate\":0.0001,\"cpu\":0.15},",
        "\"config\":{\"max_connections\":4096,\"keepalive\":true,\"timeout_sec\":30,\"features\":[\"h2\",\"tls13\",\"zstd\",\"br\"]},",
        "\"description\":\"Zero-allocation high performance network engine compression fixture.\"}\n",
    ];
    var idx = 0;
    while idx < 1024 {
        for part in parts {
            let rem = 1024 - idx;
            if rem <= 0 {
                break;
            }
            let c_len = min(part.len, rem);
            for j in c_len {
                buf[idx + j] = part[j];
            }
            idx = idx + c_len;
        }
    }
}

fn bench_deflate_compress(
    iters: i64,
    pt:    const u8[1024]&,
    level: i32,
    name:  const u8[:],
) -> u64 {
    var comp: u8[..2048] = [];
    let warmup = calc_warmup_iters(iters);
    var checksum: u64 = 0;

    for _ in warmup {
        comp.clear();
        let ok = core::deflate(pt[..], comp, level);
        assert(ok && comp.len > 0);
        checksum = core::add_sat_u64(checksum, comp[0]);
    }

    let watch = core::stopwatch();
    for _ in iters {
        comp.clear();
        let ok = core::deflate(pt[..], comp, level);
        assert(ok && comp.len > 0);
        checksum = core::add_sat_u64(checksum, core::add_sat_u64(comp.len as u64, comp[0]));
    }
    let dt = core::elapsed(watch);
    let total_bytes = core::mul_sat_u64(iters as u64, pt.len as u64);
    report_bench(name, iters, dt.as_nanos(), total_bytes, checksum);
    return checksum;
}

fn bench_deflate_decompress(
    iters:      i64,
    compressed: const u8[:],
    raw_len:    i64,
    name:       const u8[:],
) -> u64 {
    var decomp: u8[..2048] = [];
    let warmup = calc_warmup_iters(iters);
    var checksum: u64 = 0;

    for _ in warmup {
        decomp.clear();
        let ok, err = core::inflate(compressed, decomp);
        assert(ok && decomp.len == raw_len);
        checksum = core::add_sat_u64(checksum, decomp[0]);
    }

    let watch = core::stopwatch();
    for _ in iters {
        decomp.clear();
        let ok, err = core::inflate(compressed, decomp);
        assert(ok && decomp.len == raw_len);
        checksum = core::add_sat_u64(checksum, core::add_sat_u64(decomp.len as u64, decomp[0]));
    }
    let dt = core::elapsed(watch);
    let total_bytes = core::mul_sat_u64(iters as u64, raw_len as u64);
    report_bench(name, iters, dt.as_nanos(), total_bytes, checksum);
    return checksum;
}

fn bench_zstd_compress(
    iters: i64,
    pt:    const u8[1024]&,
    name:  const u8[:],
) -> u64 {
    var comp: u8[..2048] = [];
    let warmup = calc_warmup_iters(iters);
    var checksum: u64 = 0;

    for _ in warmup {
        comp.clear();
        let ok = core::zstd_compress(pt[..], comp, true);
        assert(ok && comp.len > 0);
        checksum = core::add_sat_u64(checksum, comp[0]);
    }

    let watch = core::stopwatch();
    for _ in iters {
        comp.clear();
        let ok = core::zstd_compress(pt[..], comp, true);
        assert(ok && comp.len > 0);
        checksum = core::add_sat_u64(checksum, core::add_sat_u64(comp.len as u64, comp[0]));
    }
    let dt = core::elapsed(watch);
    let total_bytes = core::mul_sat_u64(iters as u64, pt.len as u64);
    report_bench(name, iters, dt.as_nanos(), total_bytes, checksum);
    return checksum;
}

fn bench_zstd_decompress(
    iters:      i64,
    compressed: const u8[:],
    raw_len:    i64,
    name:       const u8[:],
) -> u64 {
    var decomp: u8[..2048] = [];
    let warmup = calc_warmup_iters(iters);
    var checksum: u64 = 0;

    for _ in warmup {
        decomp.clear();
        let ok, err = core::zstd_decompress(compressed, decomp);
        assert(ok && decomp.len == raw_len);
        checksum = core::add_sat_u64(checksum, decomp[0]);
    }

    let watch = core::stopwatch();
    for _ in iters {
        decomp.clear();
        let ok, err = core::zstd_decompress(compressed, decomp);
        assert(ok && decomp.len == raw_len);
        checksum = core::add_sat_u64(checksum, core::add_sat_u64(decomp.len as u64, decomp[0]));
    }
    let dt = core::elapsed(watch);
    let total_bytes = core::mul_sat_u64(iters as u64, raw_len as u64);
    report_bench(name, iters, dt.as_nanos(), total_bytes, checksum);
    return checksum;
}

fn bench_brotli_compress(
    iters: i64,
    pt:    const u8[1024]&,
    level: i32,
    name:  const u8[:],
) -> u64 {
    var comp: u8[..2048] = [];
    let warmup = calc_warmup_iters(iters);
    var checksum: u64 = 0;

    for _ in warmup {
        comp.clear();
        let ok = core::brotli_compress(pt[..], comp, level);
        assert(ok && comp.len > 0);
        checksum = core::add_sat_u64(checksum, comp[0]);
    }

    let watch = core::stopwatch();
    for _ in iters {
        comp.clear();
        let ok = core::brotli_compress(pt[..], comp, level);
        assert(ok && comp.len > 0);
        checksum = core::add_sat_u64(checksum, core::add_sat_u64(comp.len as u64, comp[0]));
    }
    let dt = core::elapsed(watch);
    let total_bytes = core::mul_sat_u64(iters as u64, pt.len as u64);
    report_bench(name, iters, dt.as_nanos(), total_bytes, checksum);
    return checksum;
}

fn bench_brotli_decompress(
    iters:      i64,
    compressed: const u8[:],
    raw_len:    i64,
    name:       const u8[:],
) -> u64 {
    var decomp: u8[..2048] = [];
    let warmup = calc_warmup_iters(iters);
    var checksum: u64 = 0;

    for _ in warmup {
        decomp.clear();
        let ok, err = core::brotli_decompress(compressed, decomp);
        assert(ok && decomp.len == raw_len);
        checksum = core::add_sat_u64(checksum, decomp[0]);
    }

    let watch = core::stopwatch();
    for _ in iters {
        decomp.clear();
        let ok, err = core::brotli_decompress(compressed, decomp);
        assert(ok && decomp.len == raw_len);
        checksum = core::add_sat_u64(checksum, core::add_sat_u64(decomp.len as u64, decomp[0]));
    }
    let dt = core::elapsed(watch);
    let total_bytes = core::mul_sat_u64(iters as u64, raw_len as u64);
    report_bench(name, iters, dt.as_nanos(), total_bytes, checksum);
    return checksum;
}

fn main() {
    let argv = args();
    let iters = parse_iters_arg(argv[..]);
    var total_checksum: u64 = 0;

    total_checksum = core::add_sat_u64(total_checksum, bench_h1_request(iters));
    total_checksum = core::add_sat_u64(total_checksum, bench_h1_response(iters));
    total_checksum = core::add_sat_u64(total_checksum, bench_headermap_write(iters));
    total_checksum = core::add_sat_u64(total_checksum, bench_headermap_lookup(iters));
    total_checksum = core::add_sat_u64(total_checksum, bench_bloom_filter(iters));
    total_checksum = core::add_sat_u64(total_checksum, bench_url_parse(iters));
    total_checksum = core::add_sat_u64(total_checksum, bench_url_parse_into(iters));
    total_checksum = core::add_sat_u64(total_checksum, bench_url_parse_view(iters));
    total_checksum = core::add_sat_u64(total_checksum, bench_hpack_encode(iters));
    total_checksum = core::add_sat_u64(total_checksum, bench_hpack_decode(iters));

    var pt:    u8[1024] = [0; 1024];
    var aad:   u8[13]   = [0; 13];
    var key16: u8[16]   = [0; 16];
    var key32: u8[32]   = [0; 32];
    var nonce: u8[12]   = [0; 12];
    fill_aead_fixtures(pt, aad, key16, key32, nonce);

    total_checksum = core::add_sat_u64(total_checksum, bench_aes128_gcm(iters, pt, aad, key16, nonce));
    total_checksum = core::add_sat_u64(
        total_checksum,
        bench_aes_gcm_prepared(
            iters,
            "aes128_gcm_prepared_seal_1kb",
            "aes128_gcm_prepared_open_1kb",
            key16[..],
            pt,
            aad,
            nonce,
        ),
    );
    total_checksum = core::add_sat_u64(total_checksum, bench_aes256_gcm(iters, pt, aad, key32, nonce));
    total_checksum = core::add_sat_u64(
        total_checksum,
        bench_aes_gcm_prepared(
            iters,
            "aes256_gcm_prepared_seal_1kb",
            "aes256_gcm_prepared_open_1kb",
            key32[..],
            pt,
            aad,
            nonce,
        ),
    );
    total_checksum = core::add_sat_u64(total_checksum, bench_chacha20_poly1305(iters, pt, aad, key32, nonce));

    var comp_pt: u8[1024] = [0; 1024];
    fill_compression_payload(comp_pt);

    var def_l1_wire: u8[..2048] = [];
    assert(core::deflate(comp_pt[..], def_l1_wire, 1));
    var def_l6_wire: u8[..2048] = [];
    assert(core::deflate(comp_pt[..], def_l6_wire, 6));

    var zstd_wire: u8[..2048] = [];
    assert(core::zstd_compress(comp_pt[..], zstd_wire, true));

    var br_l0_wire: u8[..2048] = [];
    assert(core::brotli_compress(comp_pt[..], br_l0_wire, 0));
    var br_l1_wire: u8[..2048] = [];
    assert(core::brotli_compress(comp_pt[..], br_l1_wire, 1));

    total_checksum = core::add_sat_u64(
        total_checksum,
        bench_deflate_compress(iters, comp_pt, 1, "deflate_l1_compress_1kb"),
    );
    total_checksum = core::add_sat_u64(
        total_checksum,
        bench_deflate_decompress(iters, def_l1_wire[..], 1024, "deflate_l1_decompress_1kb"),
    );
    total_checksum = core::add_sat_u64(
        total_checksum,
        bench_deflate_compress(iters, comp_pt, 6, "deflate_compress_1kb"),
    );
    total_checksum = core::add_sat_u64(
        total_checksum,
        bench_deflate_decompress(iters, def_l6_wire[..], 1024, "deflate_decompress_1kb"),
    );
    total_checksum = core::add_sat_u64(
        total_checksum,
        bench_zstd_compress(iters, comp_pt, "zstd_compress_1kb"),
    );
    total_checksum = core::add_sat_u64(
        total_checksum,
        bench_zstd_decompress(iters, zstd_wire[..], 1024, "zstd_decompress_1kb"),
    );
    total_checksum = core::add_sat_u64(
        total_checksum,
        bench_brotli_compress(iters, comp_pt, 0, "brotli_compress_1kb"),
    );
    total_checksum = core::add_sat_u64(
        total_checksum,
        bench_brotli_decompress(iters, br_l0_wire[..], 1024, "brotli_decompress_1kb"),
    );
    total_checksum = core::add_sat_u64(
        total_checksum,
        bench_brotli_compress(iters, comp_pt, 1, "brotli_l1_compress_1kb"),
    );
    total_checksum = core::add_sat_u64(
        total_checksum,
        bench_brotli_decompress(iters, br_l1_wire[..], 1024, "brotli_l1_decompress_1kb"),
    );

    assert(total_checksum != 0);
    print("CODEC_BENCH_DONE total_checksum=", total_checksum);
}
