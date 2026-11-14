// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 9530 Digest Fields for HTTP (obsoleting RFC 3230 and RFC 5843).
// Defines Content-Digest and Repr-Digest headers using RFC 8941 Structured Fields
// Dictionary syntax with byte sequences (:base64:) for sha-256 and sha-512.
namespace wing;

import std;
import core from "..";
import client.request;
import client.response;
import http.headers.chunked_fsm;
import .sfv;

// ---- RFC 9530 Constants --------------------------------------------------

inline fn compute_sha256_digest(data: const u8[:]) -> u8[..64] {
    var out: u8[..64] = [];
    let hash = core::sha256(data);
    out.append(hash[..]);
    return out;
}

inline fn compute_sha512_digest(data: const u8[:]) -> u8[..64] {
    var out: u8[..64] = [];
    let hash = core::sha512(data);
    out.append(hash[..]);
    return out;
}

// Computes raw RFC 9530 digest bytes (SHA-256 or SHA-512) returning bounded array via RVO.
//
// Example:
//   data = "hello world", alg = "sha-256"
//   returns: [185, 91, 154, ...], ok = true
fn compute_digest_bytes(data: const u8[:], alg: const u8[:]) -> u8[..64], bool {
    if alg.eq_ascii_fold(rfc::DIGEST_ALG_SHA256) {
        return compute_sha256_digest(data), true;
    }
    if alg.eq_ascii_fold(rfc::DIGEST_ALG_SHA512) {
        return compute_sha512_digest(data), true;
    }
    var empty: u8[..64] = [];
    return empty, false;
}

// Formats an RFC 9530 Structured Field dictionary value: e.g. "sha-256=:X48E9...=:"
//
// Example:
//   alg = "sha-256", data = "hello world"
//   returns: true, out = "sha-256=:uU0nuZ...=:"
fn format_digest_field_value<B>(alg: const u8[:], data: const u8[:], out: B&) -> bool {
    out.clear();
    let hash_bytes, ok_hash = compute_digest_bytes(data, alg);
    guard ok_hash else { return false; }

    out.append(if alg.eq_ascii_fold(rfc::DIGEST_ALG_SHA512) { "sha-512=:" } else { "sha-256=:" });
    core::base64_encode(hash_bytes[..], out);
    out.push(':' as u8);
    return true;
}

// ---- Content-Digest & Repr-Digest Generators -----------------------------

// Computes and attaches RFC 9530 Content-Digest header to Request.
fn set_content_digest(req: Request&, alg: const u8[:] = "sha-256") -> bool {
    var field_val: u8[..128] = [];
    guard format_digest_field_value(alg, req.body[..], field_val) else { return false; }
    set_header(req, rfc::HEADER_CONTENT_DIGEST, field_val[..]);
    return true;
}

// Computes and attaches RFC 9530 Repr-Digest header to Request.
fn set_repr_digest(req: Request&, alg: const u8[:] = "sha-256") -> bool {
    var field_val: u8[..128] = [];
    guard format_digest_field_value(alg, req.body[..], field_val) else { return false; }
    set_header(req, rfc::HEADER_REPR_DIGEST, field_val[..]);
    return true;
}

// Attaches RFC 9530 Want-Content-Digest header to Request.
fn set_want_content_digest(req: Request&, want_algorithms: const u8[:] = "sha-256=10") {
    set_header(req, rfc::HEADER_WANT_CONTENT_DIGEST, want_algorithms);
}

// Attaches RFC 9530 Want-Repr-Digest header to Request.
fn set_want_repr_digest(req: Request&, want_algorithms: const u8[:] = "sha-256=10") {
    set_header(req, rfc::HEADER_WANT_REPR_DIGEST, want_algorithms);
}

// Computes and attaches RFC 9530 Content-Digest header to Response.
fn set_response_content_digest(res: Response&, alg: const u8[:] = "sha-256") -> bool {
    var field_val: u8[..128] = [];
    guard format_digest_field_value(alg, res.body[..], field_val) else { return false; }
    res.set_header(rfc::HEADER_CONTENT_DIGEST, field_val[..]);
    return true;
}

// Computes and attaches RFC 9530 Content-Digest, Repr-Digest, and Want-*-Digest headers to Request.
fn apply_request_digest_headers(
    req:             Request&,
    alg:             const u8[:],
    include_repr:    bool,
    want_algorithms: const u8[:] = "sha-256=10",
) -> bool {
    var cd_val: u8[..128] = [];
    guard format_digest_field_value(alg, req.body[..], cd_val) else { return false; }
    var rd_val: u8[..128] = [];
    if include_repr {
        guard format_digest_field_value(alg, req.body[..], rd_val) else { return false; }
    }
    set_header(req, rfc::HEADER_CONTENT_DIGEST, cd_val[..]);
    if include_repr {
        set_header(req, rfc::HEADER_REPR_DIGEST, rd_val[..]);
    }
    if want_algorithms.len > 0 {
        set_want_content_digest(req, want_algorithms);
        set_want_repr_digest(req, want_algorithms);
    }
    return true;
}

fn apply_request_digest_headers(req: Request&, alg: const u8[:] = "sha-256") -> bool {
    return apply_request_digest_headers(req, alg, true, "sha-256=10");
}

// ---- Verification Logic --------------------------------------------------

fn check_digest_match(expected_b64: const u8[:], alg: const u8[:], data: const u8[:]) -> bool {
    var expected_hash: u8[..64] = [];
    guard core::base64_decode(expected_b64, expected_hash) else { return false; }
    let computed_hash, ok_hash = compute_digest_bytes(data, alg);
    guard ok_hash else { return false; }
    guard computed_hash.len == expected_hash.len else { return false; }
    return core::ct_eq_bytes(computed_hash[..], expected_hash[..]);
}

fn verify_single_digest_entry(entry: const SfDictEntry&, data: const u8[:]) -> bool {
    guard entry.item.kind == SfType.Binary else { return false; }
    return check_digest_match(entry.item.str_val[..], entry.key[..], data);
}

// Verifies a raw RFC 9530 Content-Digest or Repr-Digest header value against message data.
// Returns true if at least one supported digest matches.
fn verify_digest_field(header_val: const u8[:], data: const u8[:]) -> bool {
    guard header_val.len > 0 else { return false; }

    var entries: SfDictEntry[..16] = [];
    guard parse_sf_dict(header_val, entries) else { return false; }

    var matched_any = false;
    for &entry in entries {
        let is_sha256 = entry.key[..].eq_ascii_fold(rfc::DIGEST_ALG_SHA256);
        let is_sha512 = entry.key[..].eq_ascii_fold(rfc::DIGEST_ALG_SHA512);
        if is_sha256 || is_sha512 {
            guard verify_single_digest_entry(entry, data) else { return false; }
            matched_any = true;
        }
    }
    return matched_any;
}

// Verifies Request Content-Digest header against req.body.
fn verify_request_content_digest(req: const Request&) -> bool {
    var combined: u8[..4096] = [];
    guard req.headers.get_combined(rfc::HEADER_CONTENT_DIGEST, combined, 4096) else { return false; }
    return verify_digest_field(combined[..], req.body[..]);
}

// Verifies Request Repr-Digest header against req.body.
fn verify_request_repr_digest(req: const Request&) -> bool {
    var combined: u8[..4096] = [];
    guard req.headers.get_combined(rfc::HEADER_REPR_DIGEST, combined, 4096) else { return false; }
    return verify_digest_field(combined[..], req.body[..]);
}

// Verifies Response Content-Digest header against res.body.
fn verify_response_content_digest(res: const Response&) -> bool {
    var combined: u8[..4096] = [];
    guard res.headers.get_combined(rfc::HEADER_CONTENT_DIGEST, combined, 4096) else { return false; }
    return verify_digest_field(combined[..], res.body[..]);
}

// Verifies Response Repr-Digest header against res.body.
fn verify_response_repr_digest(res: const Response&) -> bool {
    var combined: u8[..4096] = [];
    guard res.headers.get_combined(rfc::HEADER_REPR_DIGEST, combined, 4096) else { return false; }
    return verify_digest_field(combined[..], res.body[..]);
}

// RFC 9530 Section 4: Integrity Preference Fields - Parse Want-*-Digest SF Dictionary weights (0..10).
fn accumulate_want_digest_weights(
    raw:   const u8[:],
    w_256: i64&,
    w_512: i64&,
) -> bool {
    guard raw.len > 0 else { return true; }
    var entries: SfDictEntry[..16] = [];
    guard parse_sf_dict(raw, entries) else { return false; }
    for &e in entries {
        guard !e.is_inner_list && e.item.kind == SfType.Integer &&
              e.item.int_val >= 0 && e.item.int_val <= 10 else {
            return false;
        }
        if e.key.eq_ascii_fold(rfc::DIGEST_ALG_SHA256) {
            w_256 = e.item.int_val;
        } else if e.key.eq_ascii_fold(rfc::DIGEST_ALG_SHA512) {
            w_512 = e.item.int_val;
        }
    }
    return true;
}

// Verifies request Repr-Digest if present and attaches Response Content-Digest when requested via Want-*-Digest.
fn apply_response_digest_if_wanted(
    req:         const Request&,
    res:         Response&,
    default_alg: const u8[:],
) -> bool {
    if req.has_header(rfc::HEADER_REPR_DIGEST) {
        guard verify_request_repr_digest(req) else { return false; }
    }
    let has_wcd = req.has_header(rfc::HEADER_WANT_CONTENT_DIGEST);
    let has_wrd = req.has_header(rfc::HEADER_WANT_REPR_DIGEST);
    if !has_wcd && !has_wrd {
        return true;
    }

    var w_256: i64 = -1;
    var w_512: i64 = -1;
    if has_wcd {
        var comb_cd: u8[..1024] = [];
        guard req.headers.get_combined(rfc::HEADER_WANT_CONTENT_DIGEST, comb_cd, 1024) &&
              accumulate_want_digest_weights(comb_cd[..], w_256, w_512) else {
            return true;
        }
    }
    if has_wrd {
        var comb_rd: u8[..1024] = [];
        guard req.headers.get_combined(rfc::HEADER_WANT_REPR_DIGEST, comb_rd, 1024) &&
              accumulate_want_digest_weights(comb_rd[..], w_256, w_512) else {
            return true;
        }
    }

    if w_512 == 0 && w_256 == 0 {
        return true;
    }
    if w_512 > 0 && w_512 >= w_256 {
        return set_response_content_digest(res, rfc::DIGEST_ALG_SHA512);
    }
    if w_256 > 0 {
        return set_response_content_digest(res, rfc::DIGEST_ALG_SHA256);
    }
    if w_256 == 0 || w_512 == 0 {
        return true;
    }
    return set_response_content_digest(res, default_alg);
}

fn apply_response_digest_if_wanted(req: const Request&, res: Response&) -> bool {
    return apply_response_digest_if_wanted(req, res, rfc::DIGEST_ALG_SHA256);
}

// ---- Incremental Streaming Digest Verification (RFC 9530) ----------------

enum StreamingDigestAlgo {
    None,
    Sha256,
    Sha512,
}

struct StreamingDigestVerifier {
    algo:          StreamingDigestAlgo = StreamingDigestAlgo.None,
    sha256_ctx:    core::Sha256Ctx     = core::Sha256Ctx { .. },
    sha512_ctx:    core::Sha512Ctx     = core::Sha512Ctx { .. },
    expected_hash: u8[..64]            = [],
    bytes_fed:     u64                 = 0,
    is_valid_init: bool                = false,
}

inline fn apply_streaming_digest_entry(v: StreamingDigestVerifier&, entry: const SfDictEntry&) -> bool {
    let is_sha256 = entry.key[..].eq_ascii_fold(rfc::DIGEST_ALG_SHA256);
    let is_sha512 = entry.key[..].eq_ascii_fold(rfc::DIGEST_ALG_SHA512);
    guard is_sha256 || is_sha512 else { return true; }
    guard entry.item.kind == SfType.Binary else { return false; }

    var decoded: u8[..64] = [];
    guard core::base64_decode(entry.item.str_val[..], decoded) else { return false; }
    let req_len: i64 = if is_sha512 { 64 } else { 32 };
    guard decoded.len == req_len else { return false; }

    if !v.is_valid_init || is_sha512 {
        v.algo = if is_sha512 { StreamingDigestAlgo.Sha512 } else { StreamingDigestAlgo.Sha256 };
        v.expected_hash.clear();
        v.expected_hash.append(decoded[..]);
        v.is_valid_init = true;
    }
    return true;
}

// Parses an RFC 9530 Content-Digest or Repr-Digest dictionary field and initializes
// an incremental SHA-256 or SHA-512 streaming verifier.
fn begin_streaming_digest(header_val: const u8[:]) -> StreamingDigestVerifier, bool {
    var v = StreamingDigestVerifier { .. };
    guard header_val.len > 0 else { return v, false; }

    var entries: SfDictEntry[..16] = [];
    guard parse_sf_dict(header_val, entries) else { return v, false; }

    for &entry in entries {
        guard apply_streaming_digest_entry(v, entry) else { return v, false; }
    }
    guard v.is_valid_init else { return v, false; }
    return v, true;
}

// Feeds a payload chunk into the incremental RFC 9530 digest verifier.
fn update_streaming_digest(v: StreamingDigestVerifier&, chunk: const u8[:]) -> bool {
    guard v.is_valid_init else { return false; }
    if v.algo == StreamingDigestAlgo.Sha256 {
        core::sha256_update(v.sha256_ctx, chunk);
        v.bytes_fed = core::add_sat_u64(v.bytes_fed, chunk.len as u64);
        return true;
    }
    if v.algo == StreamingDigestAlgo.Sha512 {
        core::sha512_update(v.sha512_ctx, chunk);
        v.bytes_fed = core::add_sat_u64(v.bytes_fed, chunk.len as u64);
        return true;
    }
    return false;
}

// Finalizes the incremental digest and verifies it in constant time against expected_hash.
fn finish_streaming_digest(v: StreamingDigestVerifier&) -> bool {
    guard v.is_valid_init else { return false; }
    v.is_valid_init = false;
    if v.algo == StreamingDigestAlgo.Sha256 {
        guard v.expected_hash.len == 32 else { return false; }
        let computed = core::sha256_final(v.sha256_ctx);
        return core::ct_eq_bytes(computed[..], v.expected_hash[..]);
    }
    if v.algo == StreamingDigestAlgo.Sha512 {
        guard v.expected_hash.len == 64 else { return false; }
        let computed = core::sha512_final(v.sha512_ctx);
        return core::ct_eq_bytes(computed[..], v.expected_hash[..]);
    }
    return false;
}

// Initializes an incremental RFC 9530 streaming digest verifier from a Request's Content-Digest or Repr-Digest header.
fn begin_request_streaming_digest(req: const Request&) -> StreamingDigestVerifier, bool {
    var combined: u8[..4096] = [];
    if req.has_header(rfc::HEADER_CONTENT_DIGEST) {
        guard req.headers.get_combined(rfc::HEADER_CONTENT_DIGEST, combined, 4096) else {
            return StreamingDigestVerifier { .. }, false;
        }
        return begin_streaming_digest(combined[..]);
    }
    guard req.headers.get_combined(rfc::HEADER_REPR_DIGEST, combined, 4096) else {
        return StreamingDigestVerifier { .. }, false;
    }
    return begin_streaming_digest(combined[..]);
}

// ---- Push-Streaming Sinks & Monomorphized Decorators ---------------------

// Zero-allocation push sink appending directly into caller-owned byte buffer.
struct ArenaSink {
    max_bytes: i64 = 16777216,
}

inline fn emit<B>(sink: ArenaSink, chunk: const u8[:], out: B&) -> bool {
    guard core::add_sat_i64(out.len, chunk.len) <= sink.max_bytes else { return false; }
    out.append(chunk);
    return true;
}

// Composable push-streaming sink decorator that computes an incremental SHA-256 digest
// across all emitted chunks while forwarding payload slices to the inner sink.
struct HashingSink<Inner> {
    inner:      Inner,
    sha256_ctx: core::Sha256Ctx = core::Sha256Ctx { .. },
    total_len:  u64             = 0,
}

fn new_hashing_sink<Inner>(inner: Inner) -> HashingSink<Inner> {
    return HashingSink<Inner> {
        inner:      inner,
        sha256_ctx: core::Sha256Ctx { .. },
        total_len:  0,
    };
}

inline fn emit<Inner, B>(sink: HashingSink<Inner>&, chunk: const u8[:], out: B&) -> bool {
    guard sink.inner.emit(chunk, out) else { return false; }
    core::sha256_update(sink.sha256_ctx, chunk);
    sink.total_len = core::add_sat_u64(sink.total_len, chunk.len as u64);
    return true;
}

fn finish_hashing_sink<Inner>(sink: HashingSink<Inner>&) -> u8[32] {
    return core::sha256_final(sink.sha256_ctx);
}

// Feeds incoming wire slice through 64-bit ChunkFsmDecoder and emits clean slices into sink.
fn pump_chunk_fsm<Sink, B>(
    dec:  internal::ChunkFsmDecoder&,
    wire: const u8[:],
    sink: Sink&,
    out:  B&,
) -> internal::ChunkFsmStatus, i64 {
    var total_consumed: i64 = 0;
    var cursor:         i64 = 0;
    while cursor < wire.len {
        let st, consumed, chunk = internal::chunk_fsm_feed(dec, wire[cursor..]);
        cursor = core::add_sat_i64(cursor, consumed);
        total_consumed = core::add_sat_i64(total_consumed, consumed);
        if chunk.len > 0 {
            guard sink.emit(chunk, out) else {
                return internal::ChunkFsmStatus.Error, total_consumed;
            }
        }
        if st == internal::ChunkFsmStatus.Complete || st == internal::ChunkFsmStatus.Error {
            return st, total_consumed;
        }
    }
    return internal::ChunkFsmStatus.NeedMore, total_consumed;
}

// Feeds incoming wire slice through 64-bit ChunkFsmDecoder and invokes callback F(chunk)
// on each zero-copy decoded slice in constant stack RAM without growing an output buffer.
fn pump_chunk_fsm_streaming<F>(
    dec:  internal::ChunkFsmDecoder&,
    wire: const u8[:],
) -> internal::ChunkFsmStatus, i64 {
    var total_consumed: i64 = 0;
    var cursor:         i64 = 0;
    while cursor < wire.len {
        let st, consumed, chunk = internal::chunk_fsm_feed(dec, wire[cursor..]);
        cursor = core::add_sat_i64(cursor, consumed);
        total_consumed = core::add_sat_i64(total_consumed, consumed);
        if chunk.len > 0 {
            F(chunk);
        }
        if st == internal::ChunkFsmStatus.Complete || st == internal::ChunkFsmStatus.Error {
            return st, total_consumed;
        }
    }
    return internal::ChunkFsmStatus.NeedMore, total_consumed;
}

// Decodes an HTTP/1.1 chunked body from wire bytes into `out_body` while verifying
// the request's RFC 9530 Content-Digest or Repr-Digest header.
fn verify_chunked_wire_digest<B>(
    req:         const Request&,
    wire_chunks: const u8[:],
    out_body:    B&,
    max_bytes:   i64,
) -> bool {
    out_body.clear();
    var ver, ok_v = begin_request_streaming_digest(req);
    guard ok_v else { return false; }

    var dec_stream = internal::new_chunk_fsm_decoder();
    var feed_ok = true;
    let st_stream, consumed_stream = pump_chunk_fsm_streaming(dec_stream, wire_chunks) { chunk =>
        if !update_streaming_digest(ver, chunk) {
            feed_ok = false;
        }
    };
    guard feed_ok && st_stream == internal::ChunkFsmStatus.Complete && consumed_stream == wire_chunks.len else {
        return false;
    }
    guard finish_streaming_digest(ver) else { return false; }

    var dec = internal::new_chunk_fsm_decoder();
    var hsink = new_hashing_sink(ArenaSink { max_bytes: max_bytes });
    let st, consumed = pump_chunk_fsm(dec, wire_chunks, hsink, out_body);
    guard st == internal::ChunkFsmStatus.Complete && consumed == wire_chunks.len else {
        out_body.clear();
        return false;
    }
    let sink_hash = finish_hashing_sink(hsink);
    if ver.algo == StreamingDigestAlgo.Sha256 {
        guard core::ct_eq_bytes(sink_hash[..], ver.expected_hash[..]) else {
            out_body.clear();
            return false;
        }
    }
    return true;
}

fn verify_chunked_wire_digest<B>(
    req:         const Request&,
    wire_chunks: const u8[:],
    out_body:    B&,
) -> bool {
    return verify_chunked_wire_digest(req, wire_chunks, out_body, 16777216);
}
