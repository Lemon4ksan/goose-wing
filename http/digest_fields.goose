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
    if eq_ascii_fold(alg, rfc::DIGEST_ALG_SHA256) {
        return compute_sha256_digest(data), true;
    }
    if eq_ascii_fold(alg, rfc::DIGEST_ALG_SHA512) {
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

    out.append(if eq_ascii_fold(alg, rfc::DIGEST_ALG_SHA512) { "sha-512=:" } else { "sha-256=:" });
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

// Formats an RFC 9530 Section 4 Want-Content-Digest or Want-Repr-Digest header value.
fn format_want_digest_header<B>(out: B&, want_algorithms: const u8[:] = "sha-256=10") {
    out.append(want_algorithms);
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

// Computes and attaches RFC 9530 Repr-Digest header to Response.
fn set_response_repr_digest(res: Response&, alg: const u8[:] = "sha-256") -> bool {
    var field_val: u8[..128] = [];
    guard format_digest_field_value(alg, res.body[..], field_val) else { return false; }
    res.set_header(rfc::HEADER_REPR_DIGEST, field_val[..]);
    return true;
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
        let is_sha256 = eq_ascii_fold(entry.key[..], rfc::DIGEST_ALG_SHA256);
        let is_sha512 = eq_ascii_fold(entry.key[..], rfc::DIGEST_ALG_SHA512);
        if is_sha256 || is_sha512 {
            guard verify_single_digest_entry(entry, data) else { return false; }
            matched_any = true;
        }
    }
    return matched_any;
}

// Verifies Request Content-Digest header against req.body.
fn verify_request_content_digest(req: const Request&) -> bool {
    var combined: u8[..512] = [];
    let ok = req.headers.get_combined(rfc::HEADER_CONTENT_DIGEST, combined);
    let hdr = if ok { combined[..] } else { req.header(rfc::HEADER_CONTENT_DIGEST) };
    guard hdr.len > 0 else { return false; }
    return verify_digest_field(hdr, req.body[..]);
}

// Verifies Request Repr-Digest header against req.body.
fn verify_request_repr_digest(req: const Request&) -> bool {
    var combined: u8[..512] = [];
    let ok = req.headers.get_combined(rfc::HEADER_REPR_DIGEST, combined);
    let hdr = if ok { combined[..] } else { req.header(rfc::HEADER_REPR_DIGEST) };
    guard hdr.len > 0 else { return false; }
    return verify_digest_field(hdr, req.body[..]);
}

// Verifies Response Content-Digest header against res.body.
fn verify_response_content_digest(res: const Response&) -> bool {
    var combined: u8[..512] = [];
    let ok = res.headers.get_combined(rfc::HEADER_CONTENT_DIGEST, combined);
    let hdr = if ok { combined[..] } else { res.header(rfc::HEADER_CONTENT_DIGEST) };
    guard hdr.len > 0 else { return false; }
    return verify_digest_field(hdr, res.body[..]);
}

// Verifies Response Repr-Digest header against res.body.
fn verify_response_repr_digest(res: const Response&) -> bool {
    var combined: u8[..512] = [];
    let ok = res.headers.get_combined(rfc::HEADER_REPR_DIGEST, combined);
    let hdr = if ok { combined[..] } else { res.header(rfc::HEADER_REPR_DIGEST) };
    guard hdr.len > 0 else { return false; }
    return verify_digest_field(hdr, res.body[..]);
}
