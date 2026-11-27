// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Focused Gap-Closing Suite: core/url & core/compress edge, error, and RFC branches.
//
// RUN: goose build -o %t.exe %s
// RUN: %t.exe
import std;
import core from "..";
import lit from "github.com/Lemon4ksan/goose-lit@v0.1.0";

fn test_url_deep_edges(t: lit::T&) {
    t.run("URL parser userinfo, IPv6/zone, relative resolution, file://, IDNA, IP/CIDR, PSL, Query") { sub =>
        // Userinfo (@, :@, user:pass, empty), special schemes, outgoing host & origins
        let u_info, e_info = core::parse_url("https://alice@foo:p@ss@Example.COM:443/a/b?k=v#frag");
        sub.assert_true(e_info == core::UrlParseError.None);
        let u_empty_ui, e_eui = core::parse_url("http://:@host.test/p");
        sub.assert_true(e_eui == core::UrlParseError.None);
        let u_v6z, e_v6z = core::parse_url("http://[fe80::1%25eth0]:8080/x");
        sub.assert_true(e_v6z == core::UrlParseError.None);
        var host_hdr: u8[..128] = [];
        core::format_outgoing_host(u_v6z, host_hdr);
        sub.assert_bytes_eq(host_hdr[..], "[fe80::1]:8080");
        let inv_u = core::new_url("");
        core::format_outgoing_host(inv_u, host_hdr);
        sub.assert_eq(host_hdr.len, 0);

        let u_bad_v6z1 = core::new_url("http://[2001:db8::1%25eth0]/"); // global IPv6 with zone rejected
        let u_bad_v6z2 = core::new_url("http://[fe80::1%25]/");
        let u_bad_v6p = core::new_url("http://[::1]:99999/");
        let u_bad_file_port = core::new_url("file://localhost:80/a");
        let u_file_local = core::new_url("file://localhost/tmp/file%20name.txt");
        let u_nohost = core::new_url("https:///onlypath");
        sub.assert_false(u_bad_v6z1.valid || u_bad_v6z2.valid || u_bad_v6p.valid || u_bad_file_port.valid || u_nohost.valid);
        sub.assert_true(u_file_local.valid && core::hostname(u_file_local) == "");

        // Origins: blob, file, data, ws/wss
        let u_blob = core::new_url("blob:https://app.github.io/123");
        let u_blob_bad = core::new_url("blob:not-a-url");
        let u_blob_data = core::new_url("blob:data:text/plain,hi");
        let u_data = core::new_url("data:text/plain,hello");
        let u_ws = core::new_url("wss://ws.example/chat");
        let o_blob = core::origin_from_url(u_blob);
        let o_blob_bad = core::origin_from_url(u_blob_bad);
        let o_blob_data = core::origin_from_url(u_blob_data);
        let o_file = core::origin_from_url(u_file_local);
        let o_data = core::origin_from_url(u_data);
        let o_ws = core::origin_from_url(u_ws);
        sub.assert_true(o_blob.kind == core::OriginKind.Tuple && o_ws.kind == core::OriginKind.Tuple);
        sub.assert_true(o_blob_bad.kind == core::OriginKind.Opaque);
        sub.assert_true(o_blob_data.kind == core::OriginKind.Opaque);
        sub.assert_true(o_file.kind == core::OriginKind.Opaque);
        sub.assert_true(o_data.kind == core::OriginKind.Opaque);

        // Relative endpoint resolution & UrlView
        let base_h = core::new_url("https://example.com/dir/sub/page.html?old=1#h");
        let r_view, ok_rv = core::parse_url_view("wss://user@h.test:9443/p?x=1#z");
        sub.assert_true(ok_rv == core::UrlParseError.None && r_view.scheme == "wss" && r_view.port == 9443);

        var tiny_dec: u8[..4] = [];
        sub.assert_true(core::percent_decode("", tiny_dec));
        let ep_abs, _ = core::parse_endpoint(base_h, "/v2/users");
        let ep_hash, _ = core::parse_endpoint(base_h, "#sec");
        sub.assert_bytes_eq(core::pathname(ep_abs), "/dir/sub/page.html/v2/users");
        sub.assert_bytes_eq(core::hash(ep_hash), "#sec");

        // IDNA / Punycode: CJK, Cyrillic+hyphen ("тест-1.рф" -> "xn---1-..."), overlong, invalid ACE bodies
        var ace: u8[..256] = [];
        sub.assert_true(core::punycode_encode_domain("example.中国", ace), "idna_cn");
        sub.assert_bytes_eq(ace[..], "example.xn--fiqs8s");
        ace.clear();
        sub.assert_true(core::punycode_encode_domain("тест-1.рф", ace), "idna_ru_enc");
        sub.assert_true(core::validate_idna_domain_bounds(ace[..]), "idna_ru_bounds");
        sub.assert_true(core::validate_host_punycode_labels(ace[..]), "idna_ru_host");
        var huge_dom: u8[260] = ['a'; 260];
        sub.assert_false(core::punycode_encode_domain(huge_dom[..], ace));
        sub.assert_false(core::validate_idna_domain_bounds("a..b.com"));
        sub.assert_false(core::validate_idna_domain_bounds("-bad.com"));
        sub.assert_false(core::validate_host_punycode_labels("xn--.com"));
        sub.assert_false(core::validate_host_punycode_labels("xn--bad_score.com"));
        sub.assert_false(core::validate_host_punycode_labels("xn--abc.com."));
        sub.assert_false(core::is_valid_punycode_ace_body("-abc"));
        sub.assert_false(core::is_valid_punycode_ace_body("abc-"));

        // IP/CIDR formatting & v6 parsing + PSL exceptions & wildcards
        let ip4, ok4 = core::parse_ip_addr("10.20.30.40");
        let ip6_z, ok6z = core::parse_ip_addr("0:0:0:0:0:0:0:1");
        let ip6_m, ok6m = core::parse_ip_addr("::ffff:192.0.2.128");
        var ip_str: u8[..64] = [];
        sub.assert_true(ok4 && ok6z && ok6m);
        sub.assert_true(core::format_ip_addr(ip4, ip_str) && ip_str[..] == "10.20.30.40");
        sub.assert_true(core::format_ip_addr(ip6_z, ip_str) && ip_str[..] == "::1");
        sub.assert_true(core::format_ip_addr(ip6_m, ip_str));
        var tiny_ip: u8[..2] = [];
        sub.assert_false(core::format_ip_addr(ip4, tiny_ip));
        sub.assert_false(core::format_ip_addr(ip6_z, tiny_ip));
        let ip_unk = core::IpAddr {};
        sub.assert_false(core::format_ip_addr(ip_unk, ip_str));
        let c6, okc6 = core::parse_cidr("2001:db8:1:2::/64");
        let ip6_in, _ = core::parse_ip_addr("2001:db8:1:2::99");
        let ip6_out, _ = core::parse_ip_addr("2001:db8:1:3::1");
        sub.assert_true(okc6 && core::cidr_contains_ip(c6, ip6_in) && !core::cidr_contains_ip(c6, ip6_out));
        sub.assert_false(core::cidr_contains_ip(c6, ip4));

        // Query encoders/decoders
        var qe: u8[..128] = [];
        sub.assert_true(core::append_query_component("a&b=c +%", qe));
        sub.assert_bytes_eq(qe[..], "a%26b%3Dc%20%2B%25");
        var qe_tiny: u8[..2] = [];
        sub.assert_false(core::append_query_component("a&b", qe_tiny));
        var fq: u8[..1024] = [];
        sub.assert_true(core::append_form_urlencoded("hello world!", fq));
        sub.assert_bytes_eq(fq[..], "hello+world%21");
        var fq_val: u8[..64] = [];
        let qs_dec = "k=hello%20world%21&flag&a%20b=ok";
        sub.assert_true(core::get_query_param_fast(qs_dec, "k", fq_val) == core::QueryParamMatch.Value, "q_dec_k");
        sub.assert_bytes_eq(fq_val[..], "hello world!");
        sub.assert_true(core::get_query_param_fast(qs_dec, "flag", fq_val) == core::QueryParamMatch.Valueless && fq_val.len == 0);
        sub.assert_true(core::has_query_param_fast("&&a=1&b&c=x%20y&&", "b"));
        sub.assert_true(core::get_query_param_fast("&&a=1&b&c=x%20y&&", "c", fq_val) == core::QueryParamMatch.Value && fq_val[..] == "x y");
    };
}

fn test_compress_stream_and_error_edges(t: lit::T&) {
    t.run("ZStream Auto/Zlib-dict/Gzip/Zstd trickle + Zlib/Gzip/Deflate/Brotli edge paths") { sub =>
        // 1. ZStreamCompressor + ZStreamDecompressor for Zlib with dict + SyncFlush + FullFlush
        let dict = "shared_dictionary_prefix_alpha_beta_gamma_0123456789";
        var zsc = core::new_zstream_compressor(core::ContainerFormat.Zlib, 6);
        zsc.dict = dict;
        var z_wire: u8[>..] = [];
        sub.assert_true(core::zstream_write(zsc, "shared_dictionary_prefix_alpha ", z_wire, core::FlushMode.NoFlush));
        sub.assert_true(core::zstream_write(zsc, "", z_wire, core::FlushMode.SyncFlush));
        sub.assert_true(core::zstream_write(zsc, "", z_wire, core::FlushMode.FullFlush));
        sub.assert_true(core::zstream_write(zsc, "beta_gamma_0123456789 end!", z_wire, core::FlushMode.NoFlush));
        sub.assert_true(core::zstream_finish(zsc, z_wire));
        sub.assert_false(core::zstream_finish(zsc, z_wire)); // already finished

        // Byte-by-byte trickle decompression with ContainerFormat.Auto
        var zsd = core::new_zstream_decompressor(core::ContainerFormat.Auto, dict);
        var z_out: u8[>..] = [];
        for i in z_wire.len {
            let err = core::zstream_decompress_write(zsd, z_wire[i..i + 1], z_out);
            sub.assert_true(err == core::CompressError.None);
        }
        sub.assert_true(zsd.is_finished, "zlib_zstream_fin");
        sub.assert_bytes_eq(z_out[..], "shared_dictionary_prefix_alpha beta_gamma_0123456789 end!");

        // 2. ZStream Gzip multi-member concatenation in Auto mode (trickle 3B chunks)
        var gz1: u8[>..] = [];
        var gz2: u8[>..] = [];
        sub.assert_true(core::gzip_compress_with_header("member-one-", gz1, 6, "one.txt", "", true), "gz1_c");
        sub.assert_true(core::gzip_compress_with_header("member-two", gz2, 1, "", "two-comment", false), "gz2_c");
        gz1.append(gz2[..]);
        var gz_d = core::new_zstream_decompressor(core::ContainerFormat.Auto);
        var gz_out: u8[>..] = [];
        var off:    i64     = 0;
        while off < gz1.len {
            let end = min(off + 3, gz1.len);
            let err = core::zstream_decompress_write(gz_d, gz1[off..end], gz_out);
            sub.assert_true(err == core::CompressError.None, "gz_step");
            off = end;
        }
        sub.assert_bytes_eq(gz_out[..], "member-one-member-two");

        // 3. ZStream Zstd in Auto mode (trickle) + error cases (bad header, wrong dict, checksum mismatch, limit overflow)
        var zs_wire: u8[>..] = [];
        sub.assert_true(core::zstd_compress_level("zstd auto trickle payload repeating repeating!", zs_wire, 3, true), "zstd_c");
        var zstd_d = core::new_zstream_decompressor(core::ContainerFormat.Auto);
        var zstd_out: u8[>..] = [];
        for i in zs_wire.len {
            let err = core::zstream_decompress_write(zstd_d, zs_wire[i..i + 1], zstd_out);
            sub.assert_true(err == core::CompressError.None, "zstd_step");
        }
        sub.assert_true(zstd_d.is_finished, "zstd_fin");
        sub.assert_bytes_eq(zstd_out[..], "zstd auto trickle payload repeating repeating!");

        var bad_zd = core::new_zstream_decompressor(core::ContainerFormat.Zlib);
        let bad_zhdr: u8[4] = [0x01, 0x02, 0x03, 0x04];
        sub.assert_true(core::zstream_decompress_write(bad_zd, bad_zhdr[..], zstd_out) == core::CompressError.InvalidHeader, "bad_zhdr");

        // 4. Zlib error paths: truncated, invalid FCHECK, missing dict, wrong dict, corrupted checksum, trailing bytes
        var z_comp: u8[>..] = [];
        sub.assert_true(core::zlib_compress_with_dict("shared_dictionary_prefix_alpha hello", z_comp, 6, dict), "z_dict_c");
        var d_tmp: u8[>..] = [];
        let _, ez1 = core::zlib_decompress(z_comp[..3], d_tmp);
        let _, ez2 = core::zlib_decompress_with_dict(z_comp[..], d_tmp, "");
        let _, ez3 = core::zlib_decompress_with_dict(z_comp[..], d_tmp, "wrong_dict");
        var z_bad_chk = copy(z_comp);
        z_bad_chk[z_bad_chk.len - 1] ^= 0xFF;
        let _, ez4 = core::zlib_decompress_with_dict(z_bad_chk[..], d_tmp, dict);
        var z_trail = copy(z_comp);
        z_trail.push(0x99);
        let _, ez5 = core::zlib_decompress_with_dict(z_trail[..], d_tmp, dict);
        sub.assert_true(ez1 == core::CompressError.InputBufferTruncated, "ez1");
        sub.assert_true(ez2 == core::CompressError.NeedDictionary, "ez2");
        sub.assert_true(ez3 == core::CompressError.DictionaryMismatch, "ez3");
        sub.assert_true(ez4 == core::CompressError.ChecksumMismatch, "ez4");
        sub.assert_true(ez5 == core::CompressError.CorruptedBitstream, "ez5");

        // 5. Deflate levels 0 (stored), 1 (fast), 6, 9 + sync flush + overflow + inflate errors
        var big_txt: u8[>..] = [];
        for i in 4096 { big_txt.push(('a' + (i % 13)) as u8); }
        var df0:    u8[>..] = [];
        var df1:    u8[>..] = [];
        var df9:    u8[>..] = [];
        var df_out: u8[>..] = [];
        sub.assert_true(core::deflate(big_txt[..200], df0, 0), "df0");
        sub.assert_true(core::deflate(big_txt[..], df1, 1), "df1");
        sub.assert_true(core::deflate(big_txt[..], df9, 9), "df9");
        let ok_i0, _ = core::inflate(df0[..], df_out);
        sub.assert_true(ok_i0 && df_out[..] == big_txt[..200], "inf0");
        df_out.clear();
        let ok_i1, _ = core::inflate(df1[..], df_out);
        sub.assert_true(ok_i1 && df_out[..] == big_txt[..], "inf1");
        df_out.clear();
        let ok_i9, _ = core::inflate(df9[..], df_out);
        sub.assert_true(ok_i9 && df_out[..] == big_txt[..], "inf9");
        var tiny_d: u8[..4] = [];
        let ok_ovf, err_ovf = core::inflate(df0[..], tiny_d);
        sub.assert_false(ok_ovf || err_ovf == core::CompressError.None);

        // 6. Brotli transform word omit-last / invalid / tiny buffer overflow
        var tb: u8[..64] = [];
        sub.assert_true(core::brotli_transform_word("testing", 1 as u8, tb), "br_t1");  // omit last 1
        sub.assert_true(core::brotli_transform_word("testing", 45 as u8, tb), "br_t45"); // omit first 2 / compound
        var tb_tiny: u8[..2] = [];
        sub.assert_false(core::brotli_transform_word("testing", 44 as u8, tb_tiny));
    };
}

fn main() {
    let runner = lit::new_runner("Core URL and Compress Gap-Closing Suite");
    lit::run_case(runner, "1. URL Deep Edge & RFC Paths", test_url_deep_edges);
    lit::run_case(runner, "2. Compress Stream & Error Paths", test_compress_stream_and_error_edges);
    assert(lit::finish(runner));
}
