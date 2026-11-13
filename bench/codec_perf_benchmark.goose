// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Engine Codec Microbenchmark Suite:
// 1. HTTP/1.1 Parser (wing::parse_request_headers, wing::parse_response_headers)
// 2. HeaderMap & Bloom Filter (wing::append_header, set_header, get_header, has_header, add_header, might_have_header)
// 3. URL Parser (core::parse_url, core::parse_url_view)
// 4. HPACK Codec (internal::encode_hpack_field, internal::decode_hpack_to_map with Huffman + dynamic table)
// 5. AEAD Ciphers (AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305 inplace seal/open on 1 KB records)
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe --iters 5000
import std;
import core from "..";
import wing from "..";

const DEFAULT_BENCH_ITERS: i64 = 10000;
const AEAD_RECORD_SIZE:    i64 = 1024;

// Prints a non-negative integer scaled by 100 as `whole.frac` (2 decimal places).
fn format_fixed_x100<B>(scaled: i64, out: B&) {
    let clamped = max(scaled, 0);
    let whole = clamped / 100;
    let frac = clamped % 100;
    whole.format_i64_dec(out);
    let _ = out.try_push('.');
    if frac < 10 {
        let _ = out.try_push('0');
    }
    frac.format_i64_dec(out);
}

// Emits one structured machine-readable benchmark line and checks non-zero checksum.
fn report_bench(
    name:        const u8[:],
    iters:       i64,
    elapsed_ns:  i64,
    bytes_total: i64,
    checksum:    u64,
) {
    assert(checksum != 0);
    let eff_ns = max(elapsed_ns, 1);
    let ns_op_f = (eff_ns * 100.0) / iters;
    let mb_s_f = (bytes_total * 100000.0) / eff_ns;
    let ns_op_x100 = (ns_op_f + 0.5) as i64;
    let mb_s_x100 = (mb_s_f + 0.5) as i64;

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
    var i: i64 = 1;
    while i < argv.len {
        let arg = argv[i];
        if arg == "--iters" && (i + 1) < argv.len {
            let parsed, ok = argv[i + 1].parse_i64_dec();
            if ok && parsed > 0 {
                return parsed;
            }
        }
        let pos_val, pos_ok = arg.parse_i64_dec();
        if pos_ok && pos_val > 0 {
            return pos_val;
        }
        i += 1;
    }
    return DEFAULT_BENCH_ITERS;
}

inline fn calc_warmup_iters(iters: i64) -> i64 {
    return min(max(iters / 10, 64), 2000);
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

    var map = wing::HeaderMap { .. };
    let warmup = calc_warmup_iters(iters);
    var checksum: u64 = 0;

    for _ in warmup {
        let err = wing::parse_request_headers(req_wire, map);
        assert(wing::is_ok(err));
        checksum += map.entries.len as u64;
    }

    let watch = core::stopwatch();
    for _ in iters {
        let err = wing::parse_request_headers(req_wire, map);
        assert(wing::is_ok(err) && map.entries.len == 9);
        let req_id = wing::get_header(map, "x-request-id");
        checksum += (map.entries.len as u64) + (req_id.len as u64);
    }
    let dt = core::elapsed(watch);
    report_bench("h1_parse_request", iters, dt.as_nanos(), iters * req_wire.len, checksum);
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

    var map = wing::HeaderMap { .. };
    let warmup = calc_warmup_iters(iters);
    var checksum: u64 = 0;

    for _ in warmup {
        let err = wing::parse_response_headers(resp_wire, map);
        assert(wing::is_ok(err));
        checksum += map.status_code as u64;
    }

    let watch = core::stopwatch();
    for _ in iters {
        let err = wing::parse_response_headers(resp_wire, map);
        assert(wing::is_ok(err) && map.status_code == 200);
        let etag = wing::get_header(map, "etag");
        checksum += (map.status_code as u64) + (etag.len as u64);
    }
    let dt = core::elapsed(watch);
    report_bench("h1_parse_response", iters, dt.as_nanos(), iters * resp_wire.len, checksum);
    return checksum;
}

fn populate_sample_headermap(map: wing::HeaderMap&) -> i64 {
    wing::clear(map);
    assert(wing::append_header(map, "Host", "api.example.com"));
    assert(wing::append_header(map, "Content-Type", "application/json"));
    assert(wing::append_header(map, "Authorization", "Bearer tok_bench_0123456789abcdef"));
    assert(wing::append_header(map, "Accept-Encoding", "gzip, br"));
    assert(wing::append_header(map, "Connection", "keep-alive"));
    assert(wing::append_header(map, "X-Trace-B3", "80f198ee56343ba864fe8b2a57d3eff7"));
    wing::set_header(map, "X-Request-Id", "req-9f3d2a1b-4c5e");
    return map.raw_buf.len;
}

fn bench_headermap_write(iters: i64) -> u64 {
    var map = wing::HeaderMap { .. };
    let warmup = calc_warmup_iters(iters);
    var checksum: u64 = 0;

    for _ in warmup {
        checksum += populate_sample_headermap(map) as u64;
    }

    var bytes_per_op: i64 = 0;
    let watch = core::stopwatch();
    for _ in iters {
        bytes_per_op = populate_sample_headermap(map);
        checksum += (bytes_per_op as u64) + (map.entries.len as u64);
    }
    let dt = core::elapsed(watch);
    report_bench("headermap_append_set", iters, dt.as_nanos(), iters * bytes_per_op, checksum);
    return checksum;
}

fn bench_headermap_lookup(iters: i64) -> u64 {
    var map = wing::HeaderMap { .. };
    let _ = populate_sample_headermap(map);
    let keys:         const u8[:][4] = ["Host", "content-type", "X-Request-Id", "x-trace-b3"];
    let bytes_per_op: i64            = 4 + 12 + 12 + 10 + 15 + 16 + 15 + 32;
    let warmup = calc_warmup_iters(iters);
    var checksum: u64 = 0;

    for k in warmup {
        let key = keys[k & 3];
        assert(wing::has_header(map, key));
        checksum += wing::get_header(map, key).len as u64;
    }

    let watch = core::stopwatch();
    for k in iters {
        let key = keys[k & 3];
        let present = wing::has_header(map, key);
        let val = wing::get_header(map, key);
        assert(present && val.len > 0);
        checksum += (val.len as u64) + val[0];
    }
    let dt = core::elapsed(watch);
    let avg_bytes = bytes_per_op / 4;
    report_bench("headermap_get_has_hit", iters, dt.as_nanos(), iters * avg_bytes, checksum);
    return checksum;
}

fn bench_bloom_filter(iters: i64) -> u64 {
    var bf = wing::HeaderBloomFilter { .. };
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
        wing::add_header(bf, key);
        assert(wing::might_have_header(bf, key));
    }

    let miss_keys: const u8[:][4] = [
        "Sec-WebSocket-Key",
        "Proxy-Authenticate",
        "X-Forwarded-Proto",
        "Transfer-Encoding",
    ];
    for mkey in miss_keys {
        assert(!wing::might_have_header(bf, mkey));
    }

    let warmup = calc_warmup_iters(iters);
    var checksum: u64 = 0;
    for k in warmup {
        let mk = miss_keys[k & 3];
        let hit = wing::might_have_header(bf, mk);
        assert(!hit);
        checksum += mk.len as u64;
    }

    let watch = core::stopwatch();
    for k in iters {
        let mk = miss_keys[k & 3];
        let hit = wing::might_have_header(bf, mk);
        assert(!hit);
        checksum += mk.len as u64;
    }
    let dt = core::elapsed(watch);
    report_bench("bloom_fast_miss", iters, dt.as_nanos(), iters * 18, checksum);
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
        checksum += u.href.len as u64;
    }

    var total_bytes: i64 = 0;
    let watch = core::stopwatch();
    for k in iters {
        let raw = urls[k & 3];
        total_bytes += raw.len;
        let u, err = core::parse_url(raw);
        assert(core::is_ok(err) && u.valid);
        checksum += (u.href.len as u64) + ((u.pathname_end - u.pathname_start) as u64);
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
        checksum += v.host.len as u64;
    }

    var total_bytes: i64 = 0;
    let watch = core::stopwatch();
    for k in iters {
        let raw = urls[k & 3];
        total_bytes += raw.len;
        let v, err = core::parse_url_view(raw);
        assert(core::is_ok(err) && v.valid);
        checksum += (v.host.len as u64) + (v.pathname.len as u64) + (v.search.len as u64);
    }
    let dt = core::elapsed(watch);
    report_bench("url_parse_view", iters, dt.as_nanos(), total_bytes, checksum);
    return checksum;
}

fn encode_sample_hpack_block<B>(
    dt:       internal::DynamicTable&,
    out:      B&,
    path_val: const u8[:],
    req_id:   const u8[:],
) -> i64 {
    out.clear();
    let inc = internal::HpackIndexing.Incremental;
    let lit_none = internal::HpackIndexing.None;
    assert(internal::encode_hpack_field(dt, out, ":method", "GET", inc, true));
    assert(internal::encode_hpack_field(dt, out, ":scheme", "https", inc, true));
    assert(internal::encode_hpack_field(dt, out, ":authority", "api.example.com", inc, true));
    assert(internal::encode_hpack_field(dt, out, ":path", path_val, inc, true));
    assert(internal::encode_hpack_field(dt, out, "accept", "application/json", inc, true));
    assert(internal::encode_hpack_field(dt, out, "user-agent", "goose-wing/2.0", inc, true));
    assert(internal::encode_hpack_field(dt, out, "content-type", "application/json", inc, true));
    assert(internal::encode_hpack_field(dt, out, "x-request-id", req_id, lit_none, true));
    return 10 + 12 + 25 + 5 + path_val.len + 22 + 24 + 28 + 12 + req_id.len;
}

fn bench_hpack_encode(iters: i64) -> u64 {
    var dt = internal::new_dynamic_table();
    var out: u8[..1024] = [];
    let paths:   const u8[:][2] = ["/api/v1/orders?page=1", "/api/v1/orders?page=2"];
    let req_ids: const u8[:][2] = ["req-9f3d2a1b-0001", "req-9f3d2a1b-0002"];

    let warmup = calc_warmup_iters(iters);
    var checksum: u64 = 0;
    for k in warmup {
        let _ = encode_sample_hpack_block(dt, out, paths[k & 1], req_ids[k & 1]);
        checksum += out.len as u64;
    }

    var total_bytes: i64 = 0;
    let watch = core::stopwatch();
    for k in iters {
        total_bytes += encode_sample_hpack_block(dt, out, paths[k & 1], req_ids[k & 1]);
        checksum += (out.len as u64) + out[0];
    }
    let dt_elapsed = core::elapsed(watch);
    report_bench("hpack_encode_huffman", iters, dt_elapsed.as_nanos(), total_bytes, checksum);
    return checksum;
}

fn bench_hpack_decode(iters: i64) -> u64 {
    var enc_dt = internal::new_dynamic_table();
    var wire_block: u8[..1024] = [];
    let raw_bytes = encode_sample_hpack_block(
        enc_dt, wire_block, "/api/v1/orders?page=1", "req-9f3d2a1b-0001",
    );

    var dec_dt = internal::new_dynamic_table();
    var pseudo = internal::H2PseudoHeaders { .. };
    var hdrs = wing::HeaderMap { .. };
    let warmup = calc_warmup_iters(iters);
    var checksum: u64 = 0;

    for _ in warmup {
        let err = internal::decode_hpack_to_map(dec_dt, wire_block[..], pseudo, hdrs);
        assert(err == 0 && pseudo.has_method && hdrs.entries.len == 4);
        checksum += pseudo.path.len as u64;
    }

    let watch = core::stopwatch();
    for _ in iters {
        let err = internal::decode_hpack_to_map(dec_dt, wire_block[..], pseudo, hdrs);
        assert(err == 0 && pseudo.has_method && hdrs.entries.len == 4);
        let req_id = wing::get_header(hdrs, "x-request-id");
        checksum += (pseudo.path.len as u64) + (req_id.len as u64);
    }
    let dt_elapsed = core::elapsed(watch);
    report_bench("hpack_decode_huffman", iters, dt_elapsed.as_nanos(), iters * raw_bytes, checksum);
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
        pt[i] = ((i * 131 + 17) & 0xFF) as u8;
    }
    for i in 13 {
        aad[i] = (0xA0 + i) as u8;
    }
    for i in 16 {
        key16[i] = (0x10 + i) as u8;
    }
    for i in 32 {
        key32[i] = (0x30 + i) as u8;
    }
    for i in 12 {
        nonce[i] = (0x50 + i) as u8;
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
        checksum += tag[0];
    }

    let w_seal = core::stopwatch();
    for _ in iters {
        let tag, ok = core::aes128_gcm_seal_inplace(key16, nonce, work[..], aad[..]);
        assert(ok);
        checksum += tag[0] + work[0];
    }
    let dt_seal = core::elapsed(w_seal);
    report_bench(
        "aes128_gcm_seal_1kb", iters, dt_seal.as_nanos(), iters * AEAD_RECORD_SIZE, checksum,
    );

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
        checksum += work[512];
    }
    let dt_open = core::elapsed(w_open);
    report_bench(
        "aes128_gcm_open_1kb", iters, dt_open.as_nanos(), iters * AEAD_RECORD_SIZE, checksum,
    );
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
        checksum += tag[0];
    }

    let w_seal = core::stopwatch();
    for _ in iters {
        let tag, ok = core::aes256_gcm_seal_inplace(key32, nonce, work[..], aad[..]);
        assert(ok);
        checksum += tag[0] + work[0];
    }
    let dt_seal = core::elapsed(w_seal);
    report_bench(
        "aes256_gcm_seal_1kb", iters, dt_seal.as_nanos(), iters * AEAD_RECORD_SIZE, checksum,
    );

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
        checksum += work[512];
    }
    let dt_open = core::elapsed(w_open);
    report_bench(
        "aes256_gcm_open_1kb", iters, dt_open.as_nanos(), iters * AEAD_RECORD_SIZE, checksum,
    );
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
        checksum += tag[0];
    }

    let w_seal = core::stopwatch();
    for _ in iters {
        let tag, ok = core::chacha20_poly1305_seal_inplace(key32, nonce, work[..], aad[..]);
        assert(ok);
        checksum += tag[0] + work[0];
    }
    let dt_seal = core::elapsed(w_seal);
    report_bench(
        "chacha20_poly1305_seal_1kb", iters, dt_seal.as_nanos(), iters * AEAD_RECORD_SIZE, checksum,
    );

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
        checksum += work[512];
    }
    let dt_open = core::elapsed(w_open);
    report_bench(
        "chacha20_poly1305_open_1kb", iters, dt_open.as_nanos(), iters * AEAD_RECORD_SIZE, checksum,
    );
    return checksum;
}

fn main() {
    let argv = args();
    let iters = parse_iters_arg(argv[..]);
    var total_checksum: u64 = 0;

    total_checksum += bench_h1_request(iters);
    total_checksum += bench_h1_response(iters);
    total_checksum += bench_headermap_write(iters);
    total_checksum += bench_headermap_lookup(iters);
    total_checksum += bench_bloom_filter(iters);
    total_checksum += bench_url_parse(iters);
    total_checksum += bench_url_parse_view(iters);
    total_checksum += bench_hpack_encode(iters);
    total_checksum += bench_hpack_decode(iters);

    var pt:    u8[1024] = [0; 1024];
    var aad:   u8[13]   = [0; 13];
    var key16: u8[16]   = [0; 16];
    var key32: u8[32]   = [0; 32];
    var nonce: u8[12]   = [0; 12];
    fill_aead_fixtures(pt, aad, key16, key32, nonce);

    total_checksum += bench_aes128_gcm(iters, pt, aad, key16, nonce);
    total_checksum += bench_aes256_gcm(iters, pt, aad, key32, nonce);
    total_checksum += bench_chacha20_poly1305(iters, pt, aad, key32, nonce);

    assert(total_checksum != 0);
    print("CODEC_BENCH_DONE total_checksum=", total_checksum);
}
