// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Verification suite for RFC 7932 Brotli Compression & Decompression Engine:
// 1. Bit-level framing and empty stream handling
// 2. Uncompressed meta-blocks (Level 0 encoder & decoder) with roundtrip
// 3. Official Google Brotli compressed test vectors (uncompressed & compressed)
// 4. Repetitive LZ77 matching & backward copy decoding
// 5. Built-in Static Dictionary (122 KB) & Word Transformations (Appendix B)
// 6. Output limit protection (decompression bomb defense)
// 7. Error handling on corrupted/truncated bitstreams
// 8. HTTP Client Response auto-decompression (`Content-Encoding: br`)
import std;
import core from "..";
import wing from "..";

// ---- Official Google Brotli Test Vectors -------------------------------------

// empty raw_len=0 c_len=1
const VEC_EMPTY_RAW: const u8[0] = [];
const VEC_EMPTY_COMP: const u8[1] = [59];

// hello raw_len=23 c_len=27
const VEC_HELLO_RAW: const u8[23] = [
    72, 101, 108, 108, 111, 44, 32, 66, 114, 111, 116, 108, 105, 32, 105, 110, 32, 71, 111, 111, 115, 101, 33,
];
const VEC_HELLO_COMP: const u8[27] = [
    11, 11, 128, 72, 101, 108, 108, 111, 44, 32, 66, 114, 111, 116, 108, 105, 32, 105, 110, 32, 71, 111, 111, 115, 101, 33, 3,
];

// json raw_len=26 c_len=30
const VEC_JSON_RAW: const u8[26] = [
    123, 34, 115, 116, 97, 116, 117, 115, 34, 58, 34, 111, 107, 34, 44, 34, 99, 111, 100, 101, 34, 58, 50, 48, 48, 125,
];
const VEC_JSON_COMP: const u8[30] = [
    139, 12, 128, 123, 34, 115, 116, 97, 116, 117, 115, 34, 58, 34, 111, 107, 34, 44, 34, 99, 111, 100, 101, 34, 58, 50, 48, 48, 125, 3,
];

// repeat raw_len=100 c_len=20 (LZ77 compressed)
const VEC_REPEAT_COMP: const u8[20] = [
    139, 49, 0, 0, 32, 130, 216, 0, 14, 92, 195, 9, 113, 54, 128, 11, 112, 88, 222, 6,
];

// ---- Test Cases -------------------------------------------------------------

fn test_brotli_empty_and_uncompressed(t: core::T&) {
    t.run("Empty stream and Google Brotli uncompressed vectors") { sub =>
        // 1. Empty stream: Google Brotli vector [59]
        var dec_empty: u8[>..] = [];
        let ok_e, err_e = core::brotli_decompress(VEC_EMPTY_COMP[..], dec_empty);
        sub.assert_true(ok_e, "Decompress empty vector succeeds");
        sub.assert_true(err_e == core::CompressError.None, "No error on empty vector");
        sub.assert_eq(dec_empty.len, 0, "Decoded empty length is 0");

        // 2. Hello World vector
        var dec_hello: u8[>..] = [];
        let ok_h, err_h = core::brotli_decompress(VEC_HELLO_COMP[..], dec_hello);
        sub.assert_true(ok_h, "Decompress hello vector succeeds");
        sub.assert_true(err_h == core::CompressError.None, "No error on hello vector");
        sub.assert_eq(dec_hello.len, VEC_HELLO_RAW.len, "Hello length matches");
        sub.assert_eq(dec_hello[..], VEC_HELLO_RAW[..], "Hello payload matches 100%");

        // 3. JSON vector
        var dec_json: u8[>..] = [];
        let ok_j, err_j = core::brotli_decompress(VEC_JSON_COMP[..], dec_json);
        sub.assert_true(ok_j, "Decompress JSON vector succeeds");
        sub.assert_true(err_j == core::CompressError.None, "No error on JSON vector");
        sub.assert_eq(dec_json.len, VEC_JSON_RAW.len, "JSON length matches");
        sub.assert_eq(dec_json[..], VEC_JSON_RAW[..], "JSON payload matches 100%");
    };
}

fn test_brotli_level0_roundtrip(t: core::T&) {
    t.run("Level 0 uncompressed encoder and decoder round-trip") { sub =>
        // 1. Short text roundtrip
        let text = "Brotli zero-heap compression running natively inside Goose-Wing!";
        var comp: u8[>..] = [];
        let ok_c = core::brotli_compress(text, comp, 0);
        sub.assert_true(ok_c, "Level 0 compression succeeds");
        sub.assert_true(comp.len > 0, "Compressed output not empty");

        var decomp: u8[>..] = [];
        let ok_d, err_d = core::brotli_decompress(comp[..], decomp);
        sub.assert_true(ok_d, "Decompression succeeds");
        sub.assert_true(err_d == core::CompressError.None, "No decompression error");
        sub.assert_eq(decomp.len, text.len, "Decompressed length matches original");
        sub.assert_eq(decomp[..], text, "Decompressed content matches exactly");

        // 2. Empty string roundtrip
        var comp_empty: u8[>..] = [];
        let ok_ce = core::brotli_compress("", comp_empty, 0);
        sub.assert_true(ok_ce, "Empty string compression succeeds");

        var decomp_empty: u8[>..] = [];
        let ok_de, err_de = core::brotli_decompress(comp_empty[..], decomp_empty);
        sub.assert_true(ok_de, "Empty string decompression succeeds");
        sub.assert_eq(decomp_empty.len, 0, "Empty string roundtrips to 0 bytes");
    };
}

fn test_brotli_compressed_meta_blocks(t: core::T&) {
    t.run("Google Brotli LZ77 compressed meta-block decoding") { sub =>
        // VEC_REPEAT_COMP compresses 100 'A's into 20 bytes
        var decomp: u8[>..] = [];
        let ok, err = core::brotli_decompress(VEC_REPEAT_COMP[..], decomp);
        sub.assert_true(ok, "Decompress LZ77 vector succeeds");
        sub.assert_true(err == core::CompressError.None, "No error on repeat vector");
        sub.assert_eq(decomp.len, 100, "Decompressed length is 100");

        var all_a = true;
        for b in decomp {
            if b != ('A' as u8) {
                all_a = false;
                break;
            }
        }
        sub.assert_true(all_a, "All 100 bytes are correctly decompressed 'A's");
    };
}

fn test_brotli_static_dictionary_transforms(t: core::T&) {
    t.run("Static built-in dictionary and word transformations") { sub =>
        // 1. Verify static dictionary is present and non-empty
        sub.assert_eq(core::BROTLI_DICTIONARY.len, 122784, "Dictionary size is exactly 122,784 bytes");

        // 2. Test word transformations directly
        var word_out1: u8[>..] = [];
        // Transform 0: Identity
        let ok1 = core::brotli_transform_word("world", 0, word_out1);
        sub.assert_true(ok1, "Transform 0 succeeds");
        sub.assert_eq(word_out1[..], "world", "Transform 0 is Identity");

        // Transform 1: Add trailing space
        var word_out2: u8[>..] = [];
        let ok2 = core::brotli_transform_word("hello", 1, word_out2);
        sub.assert_true(ok2, "Transform 1 succeeds");
        sub.assert_eq(word_out2[..], "hello ", "Transform 1 adds trailing space");

        // Transform 2: Add leading and trailing space
        var word_out3: u8[>..] = [];
        let ok3 = core::brotli_transform_word("test", 2, word_out3);
        sub.assert_true(ok3, "Transform 2 succeeds");
        sub.assert_eq(word_out3[..], " test ", "Transform 2 adds leading & trailing space");

        // Transform 4: Uppercase first and add space
        var word_out4: u8[>..] = [];
        let ok4 = core::brotli_transform_word("google", 4, word_out4);
        sub.assert_true(ok4, "Transform 4 succeeds");
        sub.assert_eq(word_out4[..], "Google ", "Transform 4 capitalizes first letter and adds space");

        // Transform 5: Add suffix " the "
        var word_out5: u8[>..] = [];
        let ok5 = core::brotli_transform_word("all", 5, word_out5);
        sub.assert_true(ok5, "Transform 5 succeeds");
        sub.assert_eq(word_out5[..], "all the ", "Transform 5 appends ' the '");

        // 3. Test static dictionary word lookup
        var dict_out: u8[>..] = [];
        // Look up 4-letter word at index 0 (distance = max_dist + 1)
        // Offset for length 4, index 0 is 0..4
        let ok_lookup = core::brotli_lookup_dictionary_word(1001, 1000, 4, dict_out);
        sub.assert_true(ok_lookup, "Dictionary lookup succeeds");
        sub.assert_true(dict_out.len >= 4, "Dictionary word length >= 4");
    };
}

fn test_brotli_quota_and_error_handling(t: core::T&) {
    t.run("Decompression bomb protection and corrupted streams") { sub =>
        // 1. Quota limit exceeded guard
        var out_limited: u8[>..] = [];
        // VEC_HELLO_COMP has 23 bytes uncompressed. Limit to 10 bytes:
        let ok_q, err_q = core::brotli_decompress_with_limit(VEC_HELLO_COMP[..], out_limited, 10);
        sub.assert_false(ok_q, "Decompression quota limit triggers failure");
        sub.assert_true(err_q == core::CompressError.OutputBufferOverflow, "Returns OutputBufferOverflow");

        // 2. Empty input buffer
        var out_empty: u8[>..] = [];
        let ok_trunc, err_trunc = core::brotli_decompress(VEC_EMPTY_RAW[..], out_empty);
        sub.assert_false(ok_trunc, "Empty buffer rejected");
        sub.assert_true(err_trunc == core::CompressError.InputBufferTruncated, "Returns InputBufferTruncated");

        // 3. Corrupted header
        var bad_bytes: u8[4] = [0xFF, 0xFF, 0xFF, 0xFF];
        var out_bad: u8[>..] = [];
        let ok_bad, _ = core::brotli_decompress(bad_bytes[..], out_bad);
        sub.assert_false(ok_bad, "Corrupted header is rejected");

        // 4. RFC 7932 Section 3.4: Duplicate symbols in simple prefix code must be rejected
        var dup_simple_bytes: u8[10] = [2, 0, 0, 0, 84, 80, 80, 32, 16, 0];
        var out_dup: u8[>..] = [];
        let ok_dup, err_dup = core::brotli_decompress(dup_simple_bytes[..], out_dup);
        sub.assert_false(ok_dup, "Simple prefix code with duplicate symbols is rejected");
        sub.assert_true(err_dup == core::CompressError.InvalidHuffmanCode, "Returns InvalidHuffmanCode");

        // 5. RFC 7932 Section 8 & Section 9.2: Static dictionary transformed word length exceeding MLEN must be rejected
        var dict_overflow_bytes: u8[10] = [98, 0, 0, 0, 4, 64, 8, 18, 32, 1];
        var out_dict_overflow: u8[>..] = [];
        let ok_do, err_do = core::brotli_decompress(dict_overflow_bytes[..], out_dict_overflow);
        sub.assert_false(ok_do, "Dictionary transformed word exceeding MLEN is rejected");
        sub.assert_true(err_do == core::CompressError.CorruptedBitstream, "Returns CorruptedBitstream on MLEN overflow");

        // 6. Decompression bomb quota: dictionary transform expansion exceeding max_output_bytes must be rejected
        var out_quota_dict: u8[>..] = [];
        let ok_qd, _ = core::brotli_decompress_with_limit(dict_overflow_bytes[..], out_quota_dict, 4);
        sub.assert_false(ok_qd, "Decompression quota defense rejects dictionary word exceeding limit");

        // 7. RFC 7932 Section 9.2: Metadata meta-blocks must be parsed and skipped cleanly without corrupting stream
        var metadata_stream: u8[15] = [172, 1, 77, 69, 84, 65, 32, 0, 8, 71, 111, 111, 115, 101, 3];
        var out_meta: u8[>..] = [];
        let ok_meta, err_meta = core::brotli_decompress(metadata_stream[..], out_meta);
        sub.assert_true(ok_meta, "Metadata meta-block decompress succeeded");
        sub.assert_eq(out_meta[..], "Goose", "Payload decompressed matches 'Goose'");
    };
}

fn test_brotli_http_client_integration(t: core::T&) {
    t.run("HTTP Client Response auto-decompression for Content-Encoding: br") { sub =>
        // 1. Compress payload with Level 0 Brotli
        let original_body = "{\"user\":\"admin\",\"authenticated\":true,\"stack\":\"wing-brotli\"}";
        var comp_body: u8[>..] = [];
        let ok_c = core::brotli_compress(original_body, comp_body, 0);
        sub.assert_true(ok_c, "Compressed test payload");

        // 2. Response with Content-Encoding: br
        var res = wing::new_response();
        res.status_code = 200;
        res.headers.push(wing::make_header("Content-Encoding", "br"));
        res.headers.push(wing::make_header("Content-Type", "application/json"));
        res.body.append(comp_body[..]);

        // 3. Transparent auto-decompression via wing::decode_body
        let ok_dec = wing::decode_body(res);
        sub.assert_true(ok_dec, "decode_body succeeded for Content-Encoding: br");
        sub.assert_eq(res.body[..], original_body, "Body was automatically decompressed from Brotli");
    };
}

fn main() {
    var runner = core::new_runner("RFC 7932 Brotli Compression Engine Suite", core::Verbosity.Verbose);
    core::run_case(runner, "1. Empty Stream and Google Brotli Vectors", test_brotli_empty_and_uncompressed);
    core::run_case(runner, "2. Level 0 Uncompressed Round-Trip", test_brotli_level0_roundtrip);
    core::run_case(runner, "3. Compressed Meta-Block Decoding", test_brotli_compressed_meta_blocks);
    core::run_case(runner, "4. Static Built-in Dictionary and Word Transforms", test_brotli_static_dictionary_transforms);
    core::run_case(runner, "5. Decompression Bomb Quota Protection & Errors", test_brotli_quota_and_error_handling);
    core::run_case(runner, "6. HTTP Client Response Content-Encoding: br", test_brotli_http_client_integration);
    let ok = core::finish(runner);
    assert(ok);
}
