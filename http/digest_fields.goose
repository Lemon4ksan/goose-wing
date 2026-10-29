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

// ---- 1. RFC 9530 Constants --------------------------------------------------

const HEADER_CONTENT_DIGEST: const u8[:] = "Content-Digest";
const HEADER_REPR_DIGEST: const u8[:] = "Repr-Digest";

const DIGEST_ALG_SHA256: const u8[:] = "sha-256";
const DIGEST_ALG_SHA512: const u8[:] = "sha-512";

// ---- 2. Digest Computation --------------------------------------------------

fn compute_digest_bytes(data: const u8[:], alg: const u8[:], out: u8[>..]&) -> bool {
    out.clear();
    if eq_ascii_fold(alg, DIGEST_ALG_SHA256) {
        let hash = core::sha256(data);
        for b in hash { out.push(b); }
        return true;
    } else if eq_ascii_fold(alg, DIGEST_ALG_SHA512) {
        let hash = core::sha512(data);
        for b in hash { out.push(b); }
        return true;
    }
    return false;
}

// Formats an RFC 9530 Structured Field dictionary value: e.g. "sha-256=:X48E9...=:"
fn format_digest_field_value<B>(alg: const u8[:], data: const u8[:], out: B&) -> bool {
    out.clear();
    var hash_bytes: u8[>..] = [];
    guard compute_digest_bytes(data, alg, hash_bytes) else { return false; }

    out.append(if eq_ascii_fold(alg, DIGEST_ALG_SHA512) { "sha-512=:" } else { "sha-256=:" });
    core::base64_encode(hash_bytes[..], out);
    out.push(':' as u8);
    return true;
}

// ---- 3. Content-Digest & Repr-Digest Generators -----------------------------

// Computes and attaches RFC 9530 Content-Digest header to Request.
fn set_content_digest(req: Request&, alg: const u8[:] = "sha-256") -> bool {
    var field_val: u8[>..] = [];
    guard format_digest_field_value(alg, req.body[..], field_val) else { return false; }
    set_header(req, HEADER_CONTENT_DIGEST, field_val[..]);
    return true;
}

// Computes and attaches RFC 9530 Repr-Digest header to Request.
fn set_repr_digest(req: Request&, alg: const u8[:] = "sha-256") -> bool {
    var field_val: u8[>..] = [];
    guard format_digest_field_value(alg, req.body[..], field_val) else { return false; }
    set_header(req, HEADER_REPR_DIGEST, field_val[..]);
    return true;
}

// Computes and attaches RFC 9530 Content-Digest header to Response.
fn set_response_content_digest(res: Response&, alg: const u8[:] = "sha-256") -> bool {
    var field_val: u8[>..] = [];
    guard format_digest_field_value(alg, res.body[..], field_val) else { return false; }
    res.set_header(HEADER_CONTENT_DIGEST, field_val[..]);
    return true;
}

// Computes and attaches RFC 9530 Repr-Digest header to Response.
fn set_response_repr_digest(res: Response&, alg: const u8[:] = "sha-256") -> bool {
    var field_val: u8[>..] = [];
    guard format_digest_field_value(alg, res.body[..], field_val) else { return false; }
    res.set_header(HEADER_REPR_DIGEST, field_val[..]);
    return true;
}

// ---- 4. Verification Logic --------------------------------------------------

fn check_digest_match(expected_b64: const u8[:], alg: const u8[:], data: const u8[:]) -> bool {
    var expected_hash: u8[>..] = [];
    guard core::base64_decode(expected_b64, expected_hash) else { return false; }
    var computed_hash: u8[>..] = [];
    guard compute_digest_bytes(data, alg, computed_hash) else { return false; }
    guard computed_hash.len == expected_hash.len else { return false; }
    return core::ct_eq_bytes(computed_hash[..], expected_hash[..]);
}

fn verify_single_digest_entry(entry: const SfDictEntry&, data: const u8[:]) -> bool, u8[>..] {
    var alg_out: u8[>..] = [];
    guard entry.item.kind == SfType.Binary else { return false, alg_out; }
    guard check_digest_match(entry.item.str_val[..], entry.key[..], data) else { return false, alg_out; }
    alg_out.append(entry.key[..]);
    return true, alg_out;
}

// Verifies a raw RFC 9530 Content-Digest or Repr-Digest header value against message data.
// Returns true and the verified algorithm name if at least one supported digest matches.
fn verify_digest_field(header_val: const u8[:], data: const u8[:]) -> bool, u8[>..] {
    var matched_alg: u8[>..] = [];
    guard header_val.len > 0 else { return false, matched_alg; }

    var entries: SfDictEntry[..16] = [];
    guard parse_sf_dict(header_val, entries) else { return false, matched_alg; }

    for &entry in entries {
        if eq_ascii_fold(entry.key[..], DIGEST_ALG_SHA256) || eq_ascii_fold(entry.key[..], DIGEST_ALG_SHA512) {
            let ok, alg = verify_single_digest_entry(entry, data);
            if ok {
                return true, alg;
            }
        }
    }
    return false, matched_alg;
}

// Verifies Request Content-Digest header against req.body.
fn verify_request_content_digest(req: const Request&) -> bool {
    let hdr = req.header(HEADER_CONTENT_DIGEST);
    guard hdr.len > 0 else { return false; }
    let ok, _ = verify_digest_field(hdr, req.body[..]);
    return ok;
}

// Verifies Request Repr-Digest header against req.body.
fn verify_request_repr_digest(req: const Request&) -> bool {
    let hdr = req.header(HEADER_REPR_DIGEST);
    guard hdr.len > 0 else { return false; }
    let ok, _ = verify_digest_field(hdr, req.body[..]);
    return ok;
}

// Verifies Response Content-Digest header against res.body.
fn verify_response_content_digest(res: const Response&) -> bool {
    let hdr = res.header(HEADER_CONTENT_DIGEST);
    guard hdr.len > 0 else { return false; }
    let ok, _ = verify_digest_field(hdr, res.body[..]);
    return ok;
}

// Verifies Response Repr-Digest header against res.body.
fn verify_response_repr_digest(res: const Response&) -> bool {
    let hdr = res.header(HEADER_REPR_DIGEST);
    guard hdr.len > 0 else { return false; }
    let ok, _ = verify_digest_field(hdr, res.body[..]);
    return ok;
}
