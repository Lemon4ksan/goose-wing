// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal Digest header serialization and challenge resolution helpers.
namespace auth_internal;

import std;
import core;
import rfc.http;
import .types;
import .internal;
import .digest_core;

fn serialize_digest_core_kv<B>(
    out:            B&,
    effective_user: const u8[:],
    realm:          const u8[:],
    nonce:          const u8[:],
    uri:            const u8[:],
    algo:           const u8[:],
    response_hex:   const u8[:],
) -> bool {
    guard out.try_append("Digest username=\"") && append_escaped_digest_param(out, effective_user) else {
        return false;
    }
    guard out.try_append("\", realm=\"") && append_escaped_digest_param(out, realm) else { return false; }
    guard out.try_append("\", nonce=\"") && append_escaped_digest_param(out, nonce) else { return false; }
    guard out.try_append("\", uri=\"") && auth::append_digest_uri(out, uri) else { return false; }
    guard out.try_append("\", algorithm=") && out.try_append(algo) else { return false; }
    guard out.try_append(", response=\"") && append_escaped_digest_param(out, response_hex) else {
        return false;
    }
    return out.try_push('"' as u8);
}

fn resolve_digest_user(
    username: const u8[:],
    realm:    const u8[:],
    userhash: bool,
    algo:     const u8[:],
) -> u8[..128] {
    var effective: u8[..128] = [];
    if userhash {
        let hashed = auth::resolve_userhash(username, realm, algo);
        let _ = effective.try_set(hashed[..]);
        return effective;
    }
    let _ = effective.try_set(username);
    return effective;
}

// Selects preferred RFC 7616 protection quality ("auth" over "auth-int"; empty in legacy RFC 2069 mode).
inline fn resolve_active_qop(raw_qop: const u8[:]) -> const u8[:] {
    guard raw_qop.len > 0 else { return ""; }
    if auth::qop_list_has_token(raw_qop, rfc::DIGEST_QOP_AUTH) {
        return rfc::DIGEST_QOP_AUTH;
    }
    if auth::qop_list_has_token(raw_qop, rfc::DIGEST_QOP_AUTH_INT) {
        return rfc::DIGEST_QOP_AUTH_INT;
    }
    return "";
}
