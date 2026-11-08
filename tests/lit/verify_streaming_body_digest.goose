// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Verification of RFC 9530 Incremental Streaming Digest Verifier and Composable Push-Streaming Sinks.
// RUN: goose %s | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

fn test_streaming_digest_sha256_and_sha512() {
    print("=== 1. RFC 9530 Streaming Digest SHA-256 & SHA-512 ===");
    // CHECK: === 1. RFC 9530 Streaming Digest SHA-256 & SHA-512 ===

    // RFC 9530 Section 2 vector for "hello world"
    // SHA-256("hello world") base64 = uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=
    var hdr_sha256: u8[..128] = [];
    assert(wing::format_digest_field_value("sha-256", "hello world", hdr_sha256));

    var v256, ok256 = wing::begin_streaming_digest(hdr_sha256[..]);
    assert(ok256);
    assert(v256.algo == wing::StreamingDigestAlgo.Sha256);
    assert(wing::update_streaming_digest(v256, "hello "));
    assert(wing::update_streaming_digest(v256, "world"));
    assert(v256.bytes_fed == 11);
    let match256 = wing::finish_streaming_digest(v256);
    print("sha256_chunks_ok: ", match256);
    // CHECK: sha256_chunks_ok: true

    // Second finish must fail after finalization
    assert(!wing::finish_streaming_digest(v256));
    assert(!wing::update_streaming_digest(v256, "!"));

    // Negative tamper detection on SHA-256
    var v256_bad, ok256_bad = wing::begin_streaming_digest(hdr_sha256[..]);
    assert(ok256_bad);
    assert(wing::update_streaming_digest(v256_bad, "hello "));
    assert(wing::update_streaming_digest(v256_bad, "world!"));
    let match256_bad = wing::finish_streaming_digest(v256_bad);
    print("sha256_tamper_rejected: ", !match256_bad);
    // CHECK: sha256_tamper_rejected: true

    // SHA-512 incremental multi-chunk verification
    var hdr_sha512: u8[..256] = [];
    assert(wing::format_digest_field_value("sha-512", "Wikipedia in chunks", hdr_sha512));

    var v512, ok512 = wing::begin_streaming_digest(hdr_sha512[..]);
    assert(ok512);
    assert(v512.algo == wing::StreamingDigestAlgo.Sha512);
    assert(wing::update_streaming_digest(v512, "Wiki"));
    assert(wing::update_streaming_digest(v512, "pedia"));
    assert(wing::update_streaming_digest(v512, " in "));
    assert(wing::update_streaming_digest(v512, "chunks"));
    assert(v512.bytes_fed == 19);
    let match512 = wing::finish_streaming_digest(v512);
    print("sha512_chunks_ok: ", match512);
    // CHECK: sha512_chunks_ok: true

    // Negative tests for malformed / unsupported / wrong-length headers
    let _, ok_empty = wing::begin_streaming_digest("");
    assert(!ok_empty);
    let _, ok_unknown = wing::begin_streaming_digest("md5=:X48E9qOokqqrvdts8nOJR==:");
    assert(!ok_unknown);
    let _, ok_short_hash = wing::begin_streaming_digest("sha-256=:YWJj:");
    assert(!ok_short_hash);
}

fn test_request_streaming_digest() {
    print("=== 2. Request Streaming Digest Initialization ===");
    // CHECK: === 2. Request Streaming Digest Initialization ===

    var req = wing::new_post("https://example.com/upload");
    req.body.append("streamed payload data");
    assert(wing::set_content_digest(req, "sha-256"));

    var v_req, ok_req = wing::begin_request_streaming_digest(req);
    assert(ok_req);
    assert(wing::update_streaming_digest(v_req, "streamed "));
    assert(wing::update_streaming_digest(v_req, "payload "));
    assert(wing::update_streaming_digest(v_req, "data"));
    let req_ok = wing::finish_streaming_digest(v_req);
    print("request_content_digest_ok: ", req_ok);
    // CHECK: request_content_digest_ok: true

    var req_repr = wing::new_post("https://example.com/repr");
    req_repr.body.append("representation body");
    assert(wing::set_repr_digest(req_repr, "sha-512"));

    var v_repr, ok_repr = wing::begin_request_streaming_digest(req_repr);
    assert(ok_repr);
    assert(wing::update_streaming_digest(v_repr, "representation "));
    assert(wing::update_streaming_digest(v_repr, "body"));
    let repr_ok = wing::finish_streaming_digest(v_repr);
    print("request_repr_digest_ok: ", repr_ok);
    // CHECK: request_repr_digest_ok: true

    let req_none = wing::new_get("https://example.com/none");
    let _, ok_none = wing::begin_request_streaming_digest(req_none);
    assert(!ok_none);
}

fn test_hashing_sink_and_zero_copy_streaming_fsm() {
    print("=== 3. HashingSink & Zero-Copy pump_chunk_fsm_streaming ===");
    // CHECK: === 3. HashingSink & Zero-Copy pump_chunk_fsm_streaming ===

    let chunked_wire: const u8[:] = "4\r\nWiki\r\n5\r\npedia\r\n6\r\n rocks\r\n0\r\n\r\n";
    var dec = internal::new_chunk_fsm_decoder();
    var hsink = wing::new_hashing_sink(wing::ArenaSink { max_bytes: 65536 });
    var out_body: u8[>..] = [];

    let st, consumed = wing::pump_chunk_fsm(dec, chunked_wire, hsink, out_body);
    assert(st == internal::ChunkFsmStatus.Complete);
    assert(consumed == chunked_wire.len);
    assert(hsink.total_len == 15);
    assert(core::equal_short(out_body[..], "Wikipedia rocks"));

    let sink_hash = wing::finish_hashing_sink(hsink);
    let expected_hash = core::sha256("Wikipedia rocks");
    let hash_matches = core::ct_eq_bytes(sink_hash[..], expected_hash[..]);
    print("hashing_sink_match: ", hash_matches);
    // CHECK: hashing_sink_match: true

    // Verify pump_chunk_fsm_streaming with constant 4 KB RingBuffer + StreamingDigestVerifier
    var hdr_wiki: u8[..128] = [];
    assert(wing::format_digest_field_value("sha-256", "Wikipedia rocks", hdr_wiki));
    var stream_ver, ok_sv = wing::begin_streaming_digest(hdr_wiki[..]);
    assert(ok_sv);

    var dec_stream = internal::new_chunk_fsm_decoder();
    var ring = core::new_ring_buffer();
    var total_streamed: u64 = 0;

    let st_stream, consumed_stream = wing::pump_chunk_fsm_streaming(dec_stream, chunked_wire) { chunk =>
        let written, err = core::write(ring, chunk);
        assert(err == core::IoError.None && written == chunk.len);
        let readable = core::contiguous_readable_slice(ring);
        assert(wing::update_streaming_digest(stream_ver, readable));
        total_streamed = core::add_sat_u64(total_streamed, readable.len as! u64);
        core::clear(ring);
    };
    assert(st_stream == internal::ChunkFsmStatus.Complete);
    assert(consumed_stream == chunked_wire.len);
    assert(total_streamed == 15);
    let stream_digest_ok = wing::finish_streaming_digest(stream_ver);
    print("zero_alloc_stream_digest_ok: ", stream_digest_ok);
    // CHECK: zero_alloc_stream_digest_ok: true
}

fn main() {
    test_streaming_digest_sha256_and_sha512();
    test_request_streaming_digest();
    test_hashing_sink_and_zero_copy_streaming_fsm();
    print("=== ALL STREAMING DIGEST & SINK TESTS PASSED ===");
    // CHECK: === ALL STREAMING DIGEST & SINK TESTS PASSED ===
}
