// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 9530 Digest Fields for HTTP (obsoleting RFC 3230 and RFC 5843).
// Defines Content-Digest and Repr-Digest headers using RFC 8941 Structured Fields
// Dictionary syntax with byte sequences (:base64:) for sha-256 and sha-512.
namespace http;

import std;
import core;
import .request;
import .response;
import http.headers.chunked_fsm;
import .sfv;
import http.codec_internal;

// ---- RFC 9530 Constants --------------------------------------------------

// Formats an RFC 9530 Structured Field dictionary value: e.g. "sha-256=:X48E9...=:"
//
// Example:
//   alg = "sha-256", data = "hello world"
//   returns: true, out = "sha-256=:uU0nuZ...=:"
fn format_digest_field_value<B>(alg: const u8[:], data: const u8[:], out: B&) -> bool {
    let hash_bytes, ok_hash = http_internal::compute_digest_bytes(data, alg);
    guard ok_hash else { return false; }

    out.clear();
    var committed = false;
    defer if !committed { out.clear(); };

    let prefix = if alg.eq_ascii_fold(rfc::DIGEST_ALG_SHA512) { "sha-512=:" } else { "sha-256=:" };
    guard out.try_append(prefix) else { return false; }
    let b64_len = ((hash_bytes.len + 2) / 3) * 4;
    guard out.len + b64_len + 1 <= out.cap else { return false; }
    core::base64_encode(hash_bytes[..], out);
    guard out.try_push(':' as u8) else { return false; }
    committed = true;
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

// ---- Verification Logic --------------------------------------------------

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
            guard http_internal::verify_single_digest_entry(entry, data) else { return false; }
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
              http_internal::accumulate_want_digest_weights(comb_cd[..], w_256, w_512) else {
            return true;
        }
    }
    if has_wrd {
        var comb_rd: u8[..1024] = [];
        guard req.headers.get_combined(rfc::HEADER_WANT_REPR_DIGEST, comb_rd, 1024) &&
              http_internal::accumulate_want_digest_weights(comb_rd[..], w_256, w_512) else {
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

// Parses an RFC 9530 Content-Digest or Repr-Digest dictionary field and initializes
// an incremental SHA-256 or SHA-512 streaming verifier.
fn begin_streaming_digest(header_val: const u8[:]) -> StreamingDigestVerifier, bool {
    var v = StreamingDigestVerifier { .. };
    guard header_val.len > 0 else { return v, false; }

    var entries: SfDictEntry[..16] = [];
    guard parse_sf_dict(header_val, entries) else { return v, false; }

    for &entry in entries {
        guard http_internal::apply_streaming_digest_entry(v, entry) else { return v, false; }
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
    dec:  http_internal::ChunkFsmDecoder&,
    wire: const u8[:],
    sink: Sink&,
    out:  B&,
) -> http_internal::ChunkFsmStatus, i64 {
    var total_consumed: i64 = 0;
    var cursor:         i64 = 0;
    while cursor < wire.len {
        let st, consumed, chunk = http_internal::chunk_fsm_feed(dec, wire[cursor..]);
        cursor = core::add_sat_i64(cursor, consumed);
        total_consumed = core::add_sat_i64(total_consumed, consumed);
        if chunk.len > 0 {
            guard sink.emit(chunk, out) else {
                return http_internal::ChunkFsmStatus.Error, total_consumed;
            }
        }
        if st == http_internal::ChunkFsmStatus.Complete || st == http_internal::ChunkFsmStatus.Error {
            return st, total_consumed;
        }
    }
    return http_internal::ChunkFsmStatus.NeedMore, total_consumed;
}

// Feeds incoming wire slice through 64-bit ChunkFsmDecoder and invokes callback F(chunk)
// on each zero-copy decoded slice in constant stack RAM without growing an output buffer.
fn pump_chunk_fsm_streaming<F>(
    dec:  http_internal::ChunkFsmDecoder&,
    wire: const u8[:],
) -> http_internal::ChunkFsmStatus, i64 {
    var total_consumed: i64 = 0;
    var cursor:         i64 = 0;
    while cursor < wire.len {
        let st, consumed, chunk = http_internal::chunk_fsm_feed(dec, wire[cursor..]);
        cursor = core::add_sat_i64(cursor, consumed);
        total_consumed = core::add_sat_i64(total_consumed, consumed);
        if chunk.len > 0 {
            F(chunk);
        }
        if st == http_internal::ChunkFsmStatus.Complete || st == http_internal::ChunkFsmStatus.Error {
            return st, total_consumed;
        }
    }
    return http_internal::ChunkFsmStatus.NeedMore, total_consumed;
}
