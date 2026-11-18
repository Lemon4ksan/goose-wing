// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RUN: goose %s | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

fn append_feed_post(out: u8[>..]&, post_idx: i64) {
    if post_idx > 0 {
        out.push(',');
    }
    out.append("{\"id\":");
    (post_idx + 1).format_i64_dec(out);
    out.append(",\"author\":\"member_");
    (post_idx + 1).format_i64_dec(out);
    out.append("\",\"ts\":");
    (1700000000 + post_idx).format_i64_dec(out);
    out.append(",\"sig\":\"");
    for salt in 6 {
        var seed_buf: u8[..16] = [];
        let mix = (post_idx as u64) * 0x9E3779B97F4A7C15 + (salt as u64) * 0xBF58476D1CE4E5B9;
        core::append_u64_be(seed_buf, mix);
        let h = core::xxh64(seed_buf[..], (salt as u64) + 1);
        core::format_u64_hex_fixed(h, 16, out, false);
    }
    out.append("\",\"body\":\"goose-wing simd gzip pipeline verification item\"}");
}

// Builds a valid JSON feed object `{"posts":[...],"pad":"..."}` of exact byte length `target_len`.
fn build_json_feed(num_posts: i64, target_len: i64) -> u8[>..] {
    var out: u8[>..] = [];
    out.append("{\"posts\":[");
    for i in num_posts {
        append_feed_post(out, i);
    }
    out.append("],\"pad\":\"");
    let closing = "\"}";
    var pad_idx: u64 = 1;
    while out.len + closing.len < target_len {
        var hex_tmp: u8[..16] = [];
        let h = core::xxh64("pad-entropy", pad_idx);
        core::format_u64_hex_fixed(h, 16, hex_tmp, false);
        let rem = target_len - (out.len + closing.len);
        let take = min(rem, hex_tmp.len);
        out.append(hex_tmp[..take]);
        pad_idx += 1;
    }
    out.append(closing);
    assert(out.len == target_len);
    return out;
}

fn verify_gzip_roundtrip(compressed: const u8[:], expected: const u8[:]) {
    var decoded: u8[>..] = [];
    let ok, _ = core::gzip_decompress(compressed, decoded);
    assert(ok);
    assert(decoded.len == expected.len);
    assert(decoded[..] == expected);
}

fn test_dynamic_level_selection() {
    let l0 = wing::select_dynamic_gzip_level(0);
    let l64 = wing::select_dynamic_gzip_level(64);
    let l127 = wing::select_dynamic_gzip_level(127);
    let l128 = wing::select_dynamic_gzip_level(128);
    let l500 = wing::select_dynamic_gzip_level(500);
    let l6000 = wing::select_dynamic_gzip_level(6000);
    let l6_custom = wing::select_dynamic_gzip_level(500, 6);
    let l6_tiny = wing::select_dynamic_gzip_level(64, 6);
    let l_fallback = wing::select_dynamic_gzip_level(500, 0);

    assert(l0 == 0 && l64 == 0 && l127 == 0);
    assert(l128 == 1 && l500 == 1 && l6000 == 1);
    assert(l6_custom == 6 && l6_tiny == 0 && l_fallback == 1);

    // CHECK: LEVEL_SELECT: lt128=0 eq128=1 gt128=1 custom6=6
    print(
        "LEVEL_SELECT: lt128=", l127,
        " eq128=", l128,
        " gt128=", l6000,
        " custom6=", l6_custom,
    );
}

fn test_small_500b_memoized_gzip() {
    let json_500 = build_json_feed(2, 500);
    var memo = wing::ServerCompressAndEtagMemo { .. };
    var req = wing::new_request("GET", "/api/small");
    wing::set_header(req, "Accept-Encoding", "gzip");

    var res1 = wing::Response { status_code: 200, .. };
    wing::set_header(res1, "Content-Type", "application/json");
    wing::set_header(res1, "ETag", "\"small-v1\"");
    let _ = res1.body.try_set(json_500[..]);

    let _ = wing::stage_server_compress(req, res1, wing::STAGE_EGRESS_COMPRESS_GZIP, memo);
    assert(wing::header(res1, "Content-Encoding") == "gzip");
    assert(wing::header(res1, "Vary") == "Accept-Encoding");
    assert(wing::header(res1, "ETag") == "\"small-v1-gzip\"");
    assert(res1.body.len > 18 && res1.body.len < 500);
    assert(res1.body[8] == 4); // RFC 1952 XFL=4 for level 1 fast deflate
    verify_gzip_roundtrip(res1.body[..], json_500[..]);

    assert(memo.gzip_src[..] == json_500[..]);
    assert(memo.gzip_dst[..] == res1.body[..]);
    assert(memo.gzip_level == 1);

    var res2 = wing::Response { status_code: 200, .. };
    wing::set_header(res2, "Content-Type", "application/json");
    wing::set_header(res2, "ETag", "\"small-v1\"");
    let _ = res2.body.try_set(json_500[..]);

    let _ = wing::stage_server_compress(req, res2, wing::STAGE_EGRESS_COMPRESS_GZIP, memo);
    assert(res2.body[..] == res1.body[..]);
    assert(wing::header(res2, "Content-Encoding") == "gzip");
    assert(wing::header(res2, "Vary") == "Accept-Encoding");
    assert(wing::header(res2, "ETag") == "\"small-v1-gzip\"");
    verify_gzip_roundtrip(res2.body[..], json_500[..]);

    // CHECK-NEXT: GZIP_500B_MEMO: OK enc=gzip vary=Accept-Encoding etag="small-v1-gzip"
    print(
        "GZIP_500B_MEMO: OK enc=", wing::header(res2, "Content-Encoding"),
        " vary=", wing::header(res2, "Vary"),
        " etag=", wing::header(res2, "ETag"),
    );
}

fn test_feed_6000b_and_24000b_payloads() {
    let feed_6k = build_json_feed(20, 6000);
    var memo = wing::ServerCompressAndEtagMemo { .. };
    var req = wing::new_request("GET", "/feed");
    wing::set_header(req, "Accept-Encoding", "gzip");

    var res_6k = wing::Response { status_code: 200, .. };
    wing::set_header(res_6k, "Content-Type", "application/json");
    wing::set_header(res_6k, "ETag", "\"feed20\"");
    let _ = res_6k.body.try_set(feed_6k[..]);

    let _ = wing::stage_server_compress(req, res_6k, wing::STAGE_EGRESS_COMPRESS_GZIP, memo);
    assert(wing::header(res_6k, "Content-Encoding") == "gzip");
    assert(wing::header(res_6k, "Vary") == "Accept-Encoding");
    assert(wing::header(res_6k, "ETag") == "\"feed20-gzip\"");
    assert(res_6k.body.len > 2048 && res_6k.body.len < 6000);
    assert(res_6k.body[8] == 4);
    verify_gzip_roundtrip(res_6k.body[..], feed_6k[..]);

    let feed_24k = build_json_feed(80, 24000);
    var res_24k = wing::Response { status_code: 200, .. };
    wing::set_header(res_24k, "Content-Type", "application/json");
    wing::set_header(res_24k, "ETag", "\"feed80\"");
    let _ = res_24k.body.try_set(feed_24k[..]);

    let _ = wing::stage_server_compress(req, res_24k, wing::STAGE_EGRESS_COMPRESS_GZIP, memo);
    assert(wing::header(res_24k, "Content-Encoding") == "gzip");
    assert(wing::header(res_24k, "Vary") == "Accept-Encoding");
    assert(wing::header(res_24k, "ETag") == "\"feed80-gzip\"");
    assert(res_24k.body.len > 8192 && res_24k.body.len < 24000);
    assert(res_24k.body[8] == 4);
    verify_gzip_roundtrip(res_24k.body[..], feed_24k[..]);

    // CHECK-NEXT: GZIP_LARGE_FEEDS: OK gt2k_6k=true gt8k_24k=true
    print(
        "GZIP_LARGE_FEEDS: OK gt2k_6k=", res_6k.body.len > 2048,
        " gt8k_24k=", res_24k.body.len > 8192,
    );
}

fn test_zstd_and_brotli_large_feeds() {
    let feed_6k = build_json_feed(20, 6000);
    let feed_24k = build_json_feed(80, 24000);
    var memo = wing::ServerCompressAndEtagMemo { .. };

    var req_zstd = wing::new_request("GET", "/feed");
    wing::set_header(req_zstd, "Accept-Encoding", "zstd");
    var res_zstd = wing::Response { status_code: 200, .. };
    wing::set_header(res_zstd, "ETag", "\"z24\"");
    let _ = res_zstd.body.try_set(feed_24k[..]);
    let _ = wing::stage_server_compress(req_zstd, res_zstd, wing::STAGE_EGRESS_COMPRESS_ZSTD, memo);
    assert(wing::header(res_zstd, "Content-Encoding") == "zstd");
    assert(wing::header(res_zstd, "ETag") == "\"z24-zstd\"");
    var z_dec: u8[>..] = [];
    let ok_z, _ = core::zstd_decompress(res_zstd.body[..], z_dec);
    assert(ok_z && z_dec[..] == feed_24k[..]);

    var req_br = wing::new_request("GET", "/feed");
    wing::set_header(req_br, "Accept-Encoding", "br");
    var res_br = wing::Response { status_code: 200, .. };
    wing::set_header(res_br, "ETag", "\"b6\"");
    let _ = res_br.body.try_set(feed_6k[..]);
    let _ = wing::stage_server_compress(req_br, res_br, wing::STAGE_EGRESS_COMPRESS_BROTLI, memo);
    assert(wing::header(res_br, "Content-Encoding") == "br");
    assert(wing::header(res_br, "ETag") == "\"b6-br\"");
    var b_dec: u8[>..] = [];
    let ok_b, _ = core::brotli_decompress(res_br.body[..], b_dec);
    assert(ok_b && b_dec[..] == feed_6k[..]);

    // CHECK-NEXT: ZSTD_BR_FEEDS: OK zstd=zstd br=br
    print(
        "ZSTD_BR_FEEDS: OK zstd=", wing::header(res_zstd, "Content-Encoding"),
        " br=", wing::header(res_br, "Content-Encoding"),
    );
}

fn test_pipeline_config_gzip_level_override() {
    let feed_6k = build_json_feed(20, 6000);
    let json_500 = build_json_feed(2, 500);
    var cfg = wing::new_default_server_pipeline_config("example.com");
    assert(cfg.gzip_level == 1);

    var req = wing::new_request("GET", "/feed");
    wing::set_header(req, "Accept-Encoding", "gzip");
    let pso_gz = wing::STAGE_EGRESS_COMPRESS_GZIP;

    var res_l1 = wing::Response { status_code: 200, .. };
    wing::set_header(res_l1, "ETag", "\"cfg-l1\"");
    let _ = res_l1.body.try_set(json_500[..]);
    wing::dispatch_egress_pipeline(cfg, req, res_l1, pso_gz, 1000, -1);
    assert(res_l1.body[8] == 4);
    verify_gzip_roundtrip(res_l1.body[..], json_500[..]);

    cfg.gzip_level = 6;
    var res_500_l6 = wing::Response { status_code: 200, .. };
    wing::set_header(res_500_l6, "ETag", "\"cfg-l6-small\"");
    let _ = res_500_l6.body.try_set(json_500[..]);
    wing::dispatch_egress_pipeline(cfg, req, res_500_l6, pso_gz, 1000, -1);
    assert(res_500_l6.body[8] == 2); // RFC 1952 XFL=2 for level >= 6
    assert(wing::header(res_500_l6, "Content-Encoding") == "gzip");
    assert(wing::header(res_500_l6, "Vary") == "Accept-Encoding");
    assert(wing::header(res_500_l6, "ETag") == "\"cfg-l6-small-gzip\"");
    verify_gzip_roundtrip(res_500_l6.body[..], json_500[..]);

    var res_6k_l6 = wing::Response { status_code: 200, .. };
    wing::set_header(res_6k_l6, "ETag", "\"cfg-l6-feed\"");
    let _ = res_6k_l6.body.try_set(feed_6k[..]);
    wing::dispatch_egress_pipeline(cfg, req, res_6k_l6, pso_gz, 1000, -1);
    assert(res_6k_l6.body[8] == 2);
    assert(wing::header(res_6k_l6, "Content-Encoding") == "gzip");
    assert(wing::header(res_6k_l6, "Vary") == "Accept-Encoding");
    assert(wing::header(res_6k_l6, "ETag") == "\"cfg-l6-feed-gzip\"");
    verify_gzip_roundtrip(res_6k_l6.body[..], feed_6k[..]);

    // CHECK-NEXT: GZIP_CFG_OVERRIDE: OK xfl_l1=4 xfl_l6=2
    print(
        "GZIP_CFG_OVERRIDE: OK xfl_l1=", res_l1.body[8],
        " xfl_l6=", res_6k_l6.body[8],
    );
}

fn main() {
    test_dynamic_level_selection();
    test_small_500b_memoized_gzip();
    test_feed_6000b_and_24000b_payloads();
    test_zstd_and_brotli_large_feeds();
    test_pipeline_config_gzip_level_override();
}
