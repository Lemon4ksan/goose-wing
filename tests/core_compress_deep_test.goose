// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Consolidated Deep Compression Verification Suite: Zstd, Brotli (+ dictionary transforms),
// Deflate/Inflate (Stored, Fixed, Dynamic, Dict, SyncFlush), Gzip Headers, Zlib Dict, and ZStream.
//
// RUN: goose build -o %t.exe %s
// RUN: %t.exe
import std;
import core from "..";
import lit from "github.com/Lemon4ksan/goose-lit@v0.1.0";

const ZSTD_DICT: const u8[176] = [
    0x37, 0xA4, 0x30, 0xEC, 0x17, 0xDC, 0xFB, 0x7C, 0x09, 0x10, 0x10, 0xDF, 0x30, 0x33, 0x33, 0xB3,
    0x77, 0x0A, 0x73, 0x70, 0x70, 0x38, 0x1C, 0xD2, 0x72, 0xC7, 0x71, 0xCE, 0x39, 0xE7, 0xDC, 0x1D,
    0x74, 0xE0, 0xC0, 0xC1, 0xC1, 0xC1, 0xC1, 0xC1, 0xC1, 0xC1, 0xC1, 0xC1, 0xC1, 0xC1, 0xC1, 0xC1,
    0xC1, 0xC1, 0xC1, 0xC1, 0xC1, 0xC1, 0xC1, 0xC1, 0xC1, 0xC1, 0xC1, 0xC1, 0xC1, 0xC1, 0xC1, 0xC1,
    0xC1, 0xC1, 0xC1, 0xC1, 0xC1, 0xD5, 0x01, 0xE8, 0x70, 0x38, 0x1C, 0x92, 0xE7, 0x9C, 0x73, 0xCE,
    0xDD, 0x01, 0x94, 0x2E, 0x21, 0x21, 0x21, 0x21, 0x21, 0x91, 0x48, 0x24, 0x12, 0x89, 0x44, 0x22,
    0x91, 0x48, 0x24, 0x12, 0x89, 0x44, 0x22, 0x49, 0x92, 0x24, 0x49, 0x92, 0x24, 0xA5, 0x94, 0xF2,
    0x01, 0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x74, 0x68, 0x65,
    0x20, 0x71, 0x75, 0x69, 0x63, 0x6B, 0x20, 0x62, 0x72, 0x6F, 0x77, 0x6E, 0x20, 0x66, 0x6F, 0x78,
    0x20, 0x6A, 0x75, 0x6D, 0x70, 0x73, 0x20, 0x6F, 0x76, 0x65, 0x72, 0x20, 0x74, 0x68, 0x65, 0x20,
    0x6C, 0x61, 0x7A, 0x79, 0x20, 0x64, 0x6F, 0x67, 0x20, 0x74, 0x68, 0x65, 0x20, 0x71, 0x75, 0x69,
];

const ZSTD_DICT_FRAME: const u8[40] = [
    0x28, 0xB5, 0x2F, 0xFD, 0x27, 0x17, 0xDC, 0xFB, 0x7C, 0xB7, 0xBD, 0x00, 0x00, 0x58, 0x61, 0x67,
    0x61, 0x69, 0x6E, 0x20, 0x61, 0x6E, 0x64, 0x21, 0x20, 0x03, 0xFC, 0x17, 0x68, 0xD2, 0xD4, 0x9D,
    0x1D, 0xB2, 0x8A, 0x28, 0x5E, 0xC6, 0x17, 0x1B,
];

const ZSTD_HUF_FRAME: const u8[254] = [
    0x28, 0xB5, 0x2F, 0xFD, 0x64, 0x0A, 0x08, 0x85, 0x07, 0x00, 0x22, 0x4E, 0x36, 0x1C, 0x10, 0xB0,
    0xD5, 0x03, 0x50, 0xB7, 0xE9, 0x25, 0xFB, 0x88, 0x79, 0x21, 0x92, 0x96, 0x6B, 0xBB, 0x58, 0xED,
    0x93, 0x9A, 0x66, 0x0E, 0xCD, 0x61, 0x80, 0xC6, 0x12, 0x03, 0xAD, 0xCC, 0x44, 0x93, 0x01, 0xF5,
    0x93, 0x0F, 0x6C, 0x31, 0x16, 0x5F, 0x56, 0x42, 0xB0, 0xE4, 0x32, 0xE1, 0x14, 0x13, 0x09, 0x40,
    0x62, 0x81, 0xE0, 0x3A, 0x1F, 0x57, 0x45, 0x29, 0x0D, 0x4D, 0x38, 0x2D, 0xAA, 0xA1, 0xF0, 0x9E,
    0xE3, 0xC6, 0xAE, 0xF4, 0xEC, 0x9E, 0xC1, 0x78, 0xF2, 0x39, 0x31, 0xA8, 0xC1, 0x54, 0xAC, 0x3D,
    0x24, 0x03, 0x4A, 0xA2, 0x84, 0x87, 0x85, 0x00, 0x1C, 0xAD, 0x3C, 0xA8, 0xA4, 0x87, 0x15, 0xD1,
    0x8B, 0x01, 0x77, 0x83, 0xA7, 0x84, 0x40, 0x05, 0xB3, 0x46, 0x23, 0x0A, 0xC8, 0x85, 0x70, 0x93,
    0xB9, 0xD0, 0xCD, 0x4C, 0x0A, 0xF4, 0x0B, 0x45, 0x8E, 0x67, 0x44, 0x20, 0xA9, 0x25, 0xA2, 0xEF,
    0x80, 0xB0, 0x8C, 0x54, 0x1C, 0xD2, 0x9C, 0x8E, 0x2A, 0x1A, 0xCA, 0x02, 0x6A, 0xC3, 0x21, 0x15,
    0xF4, 0x25, 0xD8, 0x6B, 0xAF, 0x56, 0x55, 0x6D, 0x66, 0xFD, 0x77, 0x2D, 0xEB, 0xD3, 0xA7, 0x1A,
    0x8B, 0xB9, 0x7D, 0xD3, 0x9B, 0xCC, 0x6A, 0xFF, 0xAB, 0x6E, 0xCC, 0x34, 0x7B, 0xC3, 0x17, 0x16,
    0xCF, 0x6F, 0xF2, 0x1D, 0xE3, 0x7D, 0xC5, 0x79, 0xBC, 0xA3, 0x5F, 0xDB, 0xD0, 0xD4, 0x7B, 0x8D,
    0xC5, 0xED, 0x77, 0x65, 0xFE, 0x7C, 0x7F, 0xDE, 0x47, 0x7B, 0x61, 0x32, 0xFC, 0x7D, 0x21, 0x06,
    0x5D, 0xA0, 0x37, 0x2B, 0x4B, 0x32, 0x05, 0x00, 0x73, 0x45, 0xA9, 0x42, 0x13, 0xB9, 0x8F, 0x13,
    0x09, 0xB1, 0x42, 0x07, 0xEF, 0xCB, 0x0F, 0x58, 0x95, 0x01, 0x2E, 0x2B, 0x19, 0xDE,
];

const ZSTD_RLE_FRAME: const u8[23] = [
    0x28, 0xB5, 0x2F, 0xFD, 0x64, 0x00, 0x01, 0x4D, 0x00, 0x00, 0x10, 0x5A, 0x5A, 0x01, 0x00, 0xFB,
    0x2A, 0xC0, 0x02, 0x4A, 0x28, 0xB3, 0x5F,
];

const ZSTD_MULTI_FRAME: const u8[41] = [
    0x50, 0x2A, 0x4D, 0x18, 0x04, 0x00, 0x00, 0x00, 0x73, 0x6B, 0x69, 0x70, 0x28, 0xB5, 0x2F, 0xFD,
    0x20, 0x06, 0x31, 0x00, 0x00, 0x70, 0x61, 0x72, 0x74, 0x31, 0x2D, 0x28, 0xB5, 0x2F, 0xFD, 0x20,
    0x05, 0x29, 0x00, 0x00, 0x70, 0x61, 0x72, 0x74, 0x32,
];

const BR_Q9: const u8[161] = [
    0x1B, 0x79, 0x04, 0x00, 0x04, 0x04, 0x58, 0x57, 0xAA, 0x4B, 0xF5, 0x00, 0x34, 0xF3, 0xA9, 0xC3,
    0x03, 0xF6, 0x55, 0xB2, 0x04, 0xB3, 0xB2, 0x62, 0x89, 0xF8, 0xA2, 0x07, 0xC1, 0xF3, 0x41, 0x0F,
    0x56, 0xDA, 0xCD, 0x03, 0xDA, 0x83, 0x78, 0x8D, 0x1D, 0x3D, 0x0F, 0xA9, 0xEF, 0xE3, 0xBB, 0xD3,
    0x1F, 0x3F, 0xE6, 0xF7, 0x76, 0x3E, 0x1C, 0x9F, 0xEE, 0x46, 0x22, 0xD2, 0xC6, 0x59, 0x0D, 0x1D,
    0xA5, 0x04, 0x40, 0x30, 0x04, 0x36, 0x98, 0xDF, 0xCF, 0x8B, 0x11, 0x04, 0x1E, 0x15, 0x73, 0xE1,
    0xD5, 0xFD, 0x5E, 0xC4, 0x0E, 0x94, 0x94, 0xF5, 0xD1, 0xFE, 0xB1, 0xE0, 0x6C, 0x98, 0x44, 0x10,
    0x56, 0xCE, 0xB5, 0xFA, 0xF3, 0xB7, 0x62, 0xAD, 0xD3, 0xDE, 0x91, 0x1C, 0xF9, 0x7B, 0x30, 0x74,
    0x29, 0xD6, 0x15, 0x82, 0xC4, 0x90, 0x2C, 0xC4, 0xD0, 0xCB, 0x5C, 0x54, 0x2F, 0xC7, 0x4C, 0x1C,
    0x5F, 0x91, 0xF1, 0x52, 0x25, 0x24, 0x14, 0x5C, 0xD9, 0x73, 0x8A, 0xC4, 0xF7, 0x95, 0x50, 0x12,
    0x22, 0xA5, 0xC8, 0xBC, 0x50, 0x8E, 0xEC, 0xE1, 0x00, 0x38, 0xEB, 0x6D, 0x5F, 0xD3, 0x3D, 0x0E,
    0x0E,
];

fn test_zstd_full_suite(t: lit::T&) {
    t.run("RFC 8878 Zstd vectors (dict, 4-stream Huf+FSE+checksum, RLE, multi+skippable)") { sub =>
        var out: u8[>..] = [];
        let ok_d, err_d = core::zstd_decompress_with_dict(ZSTD_DICT_FRAME[..], ZSTD_DICT[..], out);
        sub.assert_true(ok_d && core::ok(err_d));
        sub.assert_true(core::starts_with(out[..], "the quick brown fox"));

        out.clear();
        let ok_h, err_h = core::zstd_decompress(ZSTD_HUF_FRAME[..], out);
        sub.assert_true(ok_h && core::ok(err_h) && out.len > 1900);

        out.clear();
        let ok_r, err_r = core::zstd_decompress(ZSTD_RLE_FRAME[..], out);
        sub.assert_true(ok_r && core::ok(err_r) && out.len == 512 && out[0] == 'Z');

        out.clear();
        let ok_m, err_m = core::zstd_decompress(ZSTD_MULTI_FRAME[..], out);
        sub.assert_true(ok_m && core::ok(err_m));
        sub.assert_bytes_eq(out[..], "part1-part2");

        // Bomb limit, bad checksum, bad dict magic & compress levels (small, medium, multi-block, dict)
        var bomb_out: u8[>..] = [];
        let ok_b, err_b = core::zstd_decompress_with_limit(ZSTD_RLE_FRAME[..], bomb_out, 100);
        sub.assert_false(ok_b);
        sub.assert_true(err_b == core::CompressError.OutputBufferOverflow);

        var bad_chk = ZSTD_RLE_FRAME;
        bad_chk[22] ^= 0xFF;
        let ok_c, err_c = core::zstd_decompress(bad_chk[..], bomb_out);
        sub.assert_false(ok_c && core::ok(err_c));

        var pdict = core::ParsedZstdDict {};
        let bad_dict: u8[6] = [0x37, 0xA4, 0x30, 0xEC, 0x00, 0x00];
        sub.assert_true(core::parse_zstd_dictionary(bad_dict[..], pdict) != core::CompressError.None);
        let zero_id: u8[8] = [0x37, 0xA4, 0x30, 0xEC, 0, 0, 0, 0];
        sub.assert_true(core::parse_zstd_dictionary(zero_id[..], pdict) != core::CompressError.None);

        var payload: u8[>..] = [];
        for i in 1200 { payload.push(('A' + (i % 26)) as u8); }
        var zc: u8[>..] = [];
        sub.assert_true(core::zstd_compress_level(payload[..48], zc, 0, true));
        sub.assert_true(core::zstd_compress_level(payload[..], zc, 3, true));
        out.clear();
        let ok_rt, _ = core::zstd_decompress(zc[..], out);
        sub.assert_true(ok_rt);

        zc.clear();
        let d_src = "the quick brown fox jumps over the lazy dog tail";
        sub.assert_true(core::zstd_compress_with_dict(d_src, ZSTD_DICT[..], zc, 3, true));
        out.clear();
        let ok_zd, _ = core::zstd_decompress_with_dict(zc[..], ZSTD_DICT[..], out);
        sub.assert_true(ok_zd && out[..] == d_src);
    };
}

fn test_brotli_and_dict_transforms(t: lit::T&) {
    t.run("RFC 7932 Brotli compressed blocks, dict transforms & compress/decompress") { sub =>
        var out: u8[>..] = [];
        let ok_br, err_br = core::brotli_decompress(BR_Q9[..], out);
        sub.assert_true(ok_br && core::ok(err_br));
        sub.assert_true(core::contains(out[..], "RANDOM_UPPERCASE_WORDS"));

        let ok_bomb, err_bomb = core::brotli_decompress_with_limit(BR_Q9[..], out, 16);
        sub.assert_false(ok_bomb);
        sub.assert_true(err_bomb == core::CompressError.OutputBufferOverflow);

        // Compress level 0 (uncompressed) and level 1 (LZ77 + flat) across >4KB chunk
        var big: u8[>..] = [];
        for i in 5000 { big.push(('a' + (i % 20)) as u8); }
        var c0: u8[>..] = [];
        var c1: u8[>..] = [];
        sub.assert_true(core::brotli_compress(big[..100], c0, 0));
        sub.assert_true(core::brotli_compress(big[..], c1, 1));
        out.clear();
        let ok0, _ = core::brotli_decompress(c0[..], out);
        sub.assert_true(ok0 && out[..] == big[..100]);
        out.clear();
        let ok1, _ = core::brotli_decompress(c1[..], out);
        sub.assert_true(ok1 && out[..] == big[..]);

        // Transform word edges (upper first, upper all, omit first/last, invalid id)
        var tb: u8[..64] = [];
        sub.assert_true(core::brotli_transform_word("word", 44 as u8, tb)); // uppercase first
        sub.assert_true(core::brotli_transform_word("word", 11 as u8, tb)); // uppercase all
        sub.assert_true(core::brotli_transform_word("word", 23 as u8, tb)); // omit first 1
        sub.assert_false(core::brotli_transform_word("word", 122 as u8, tb));
        sub.assert_false(core::is_valid_brotli_dict_word(1, 0, 3));
        var d_bad: u8[..32] = [];
        sub.assert_false(core::brotli_lookup_dictionary_word(1, 0, 3, d_bad));
    };
}

fn test_gzip_zlib_deflate_and_zstream(t: lit::T&) {
    t.run("Gzip rich headers, Zlib preset dict, Deflate levels & errors, ZStream") { sub =>
        // Gzip with FEXTRA, FNAME, FCOMMENT, FHCRC + bomb + truncation
        var gz: u8[>..] = [];
        let ok_g = core::gzip_compress_with_header(
            "hello gzip headers", gz, 6, "file.txt", "comment", true,
        );
        sub.assert_true(ok_g);
        var gout: u8[>..] = [];
        let ok_gd, err_gd = core::gzip_decompress(gz[..], gout);
        sub.assert_true(ok_gd && core::ok(err_gd) && gout[..] == "hello gzip headers");
        let _, err_gb = core::gzip_decompress_with_limit(gz[..], gout, 5);
        sub.assert_true(err_gb == core::CompressError.OutputBufferOverflow);
        let _, err_gt = core::gzip_decompress(gz[..14], gout);
        sub.assert_false(core::ok(err_gt));

        // Zlib preset dict compress/decompress, missing dict, wrong dict, bomb
        let dict = "common_prefix_dictionary_token_alpha_beta_gamma";
        let z_src = "common_prefix_dictionary_token_alpha_beta_gamma payload!";
        var z_buf: u8[>..] = [];
        sub.assert_true(core::zlib_compress_with_dict(z_src, z_buf, 6, dict));
        var z_out: u8[>..] = [];
        let ok_zn, err_zn = core::zlib_decompress_with_dict(z_buf[..], z_out, "");
        sub.assert_false(ok_zn);
        sub.assert_true(err_zn == core::CompressError.NeedDictionary);
        let ok_zm, err_zm = core::zlib_decompress_with_dict(z_buf[..], z_out, "wrong_dict");
        sub.assert_false(ok_zm);
        sub.assert_true(err_zm == core::CompressError.DictionaryMismatch);
        z_out.clear();
        let ok_zo, _ = core::zlib_decompress_with_dict(z_buf[..], z_out, dict);
        sub.assert_true(ok_zo && z_out[..] == z_src);

        // Deflate stored (level 0), L1 (>32KB SIMD + tiny), dynamic (level 9), dict sync flush
        var big35: u8[>..] = [];
        for i in 35000 { big35.push(('A' + (i % 26)) as u8); }
        var df0: u8[>..] = [];
        var df1: u8[>..] = [];
        var df9: u8[>..] = [];
        sub.assert_true(core::deflate(big35[..100], df0, 0));
        sub.assert_true(core::deflate(big35[..], df1, 1));
        sub.assert_true(core::deflate(big35[..1200], df9, 9));
        var inf: u8[>..] = [];
        let ok_i0, _ = core::inflate(df0[..], inf);
        sub.assert_true(ok_i0 && inf[..] == big35[..100]);
        inf.clear();
        let ok_i1, _ = core::inflate(df1[..], inf);
        sub.assert_true(ok_i1 && inf[..] == big35[..]);
        inf.clear();
        let ok_i9, _ = core::inflate(df9[..], inf);
        sub.assert_true(ok_i9 && inf[..] == big35[..1200]);

        // ZStreamCompressor + ZStreamDecompressor (Zlib dict, Gzip multi-member & big chunk, Auto Zstd)
        var comp = core::new_zstream_compressor(core::ContainerFormat.Zlib, 6);
        comp.dict = dict;
        var wire: u8[>..] = [];
        sub.assert_true(comp.write(z_src[..20], wire, core::FlushMode.NoFlush));
        sub.assert_true(comp.write("", wire, core::FlushMode.SyncFlush));
        sub.assert_true(comp.write(z_src[20..], wire, core::FlushMode.Finish));
        sub.assert_false(comp.write("after_finish", wire));

        var decomp = core::new_zstream_decompressor(core::ContainerFormat.Auto, dict);
        var res: u8[>..] = [];
        for b in wire {
            let b_slice: u8[1] = [b];
            sub.assert_true(core::ok(decomp.write(b_slice[..], res)));
        }
        sub.assert_true(res[..] == z_src);

        // ZStream Gzip >32KB sliding window & concatenated Gzip & Auto Zstd
        var gcomp = core::new_zstream_compressor(core::ContainerFormat.Gzip, 1);
        var gwire: u8[>..] = [];
        sub.assert_true(gcomp.write(big35[..], gwire));
        sub.assert_true(gcomp.finish(gwire));
        var gdec = core::new_zstream_decompressor(core::ContainerFormat.Auto);
        var gres: u8[>..] = [];
        sub.assert_true(core::ok(gdec.write(gwire[..], gres)));
        sub.assert_true(gres[..] == big35[..]);

        var gz2: u8[>..] = [];
        sub.assert_true(core::gzip_compress("partA", gz2));
        sub.assert_true(core::gzip_compress("partB", gz2));
        var gdec2 = core::new_zstream_decompressor(core::ContainerFormat.Gzip);
        gres.clear();
        sub.assert_true(core::ok(gdec2.write(gz2[..], gres)) && gres[..] == "partApartB");

        var zst_auto = core::new_zstream_decompressor(core::ContainerFormat.Auto);
        gres.clear();
        sub.assert_true(core::ok(zst_auto.write(ZSTD_RLE_FRAME[..], gres)) && gres.len == 512);
    };
}

fn main() {
    let runner = lit::new_runner("Core Compress Deep Verification Suite");
    lit::run_case(runner, "1. Zstandard Frames, Dict & Checksums", test_zstd_full_suite);
    lit::run_case(runner, "2. Brotli Trees, Transforms & Levels", test_brotli_and_dict_transforms);
    lit::run_case(runner, "3. Gzip, Zlib Dict, Deflate & ZStream", test_gzip_zlib_deflate_and_zstream);
    assert(lit::finish(runner));
}
