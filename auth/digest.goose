// RFC 7616 HTTP Digest Access Authentication (obsoleting RFC 2617).
// Supports SHA-256 (mandatory by RFC 7616 Section 3.4) and MD5 legacy fallback.
// Handles challenge parsing, HA1/HA2 derivation, qop=auth/auth-int, and Authorization header generation.
namespace wing;

import std;
import core from "..";

// ---- 1. Digest Models -------------------------------------------------------

struct DigestChallenge {
    realm: u8[..128] = [],
    nonce: u8[..128] = [],
    algorithm: u8[..32] = "SHA-256",
    qop: u8[..32] = "auth",
    opaque: u8[..128] = [],
    domain: u8[..128] = [],
    stale: bool = false,
    userhash: bool = false,
    valid: bool = false,
}

struct DigestCredentials {
    username: u8[..128] = [],
    password: u8[..128] = [],
}

// ---- 2. Challenge Parsing (RFC 7616 Section 3.3) -----------------------------

fn skip_whitespace_and_commas(raw: const u8[:], idx: i64&) {
    while idx < raw.len && (raw[idx] == ' ' || raw[idx] == '\t' || raw[idx] == ',' || raw[idx] == '\r' || raw[idx] == '\n') {
        idx += 1;
    }
}

fn parse_digest_param_key(raw: const u8[:], idx: i64&, out_key: u8[..32]&) -> bool {
    out_key.clear();
    while idx < raw.len && raw[idx] != '=' && raw[idx] != ' ' && raw[idx] != '\t' {
        out_key.push(raw[idx]);
        idx += 1;
    }
    return out_key.len > 0;
}

fn parse_digest_param_val<B>(raw: const u8[:], idx: i64&, out_val: B&) -> bool {
    out_val.clear();
    while idx < raw.len && (raw[idx] == ' ' || raw[idx] == '\t' || raw[idx] == '=') {
        idx += 1;
    }
    guard idx < raw.len else { return false; }

    if raw[idx] == '"' {
        // Quoted string
        idx += 1; // skip opening quote
        while idx < raw.len && raw[idx] != '"' {
            if raw[idx] == '\\' && idx + 1 < raw.len {
                idx += 1;
            }
            out_val.push(raw[idx]);
            idx += 1;
        }
        if idx < raw.len && raw[idx] == '"' {
            idx += 1; // skip closing quote
        }
        return true;
    }

    // Token
    while idx < raw.len && raw[idx] != ',' && raw[idx] != ' ' && raw[idx] != '\t' && raw[idx] != '\r' && raw[idx] != '\n' {
        out_val.push(raw[idx]);
        idx += 1;
    }
    return true;
}

// Parses a `WWW-Authenticate: Digest ...` challenge header into structured fields
fn parse_digest_challenge(raw_header: const u8[:]) -> DigestChallenge, bool {
    var chal = DigestChallenge { .. };
    var idx: i64 = 0;

    // Optional leading scheme "Digest "
    skip_whitespace_and_commas(raw_header, idx);
    if idx + 7 <= raw_header.len {
        let scheme = raw_header[idx..idx + 6];
        if eq_ascii_fold(scheme, "digest") && (raw_header[idx + 6] == ' ' || raw_header[idx + 6] == '\t') {
            idx += 7;
        }
    }

    while idx < raw_header.len {
        skip_whitespace_and_commas(raw_header, idx);
        guard idx < raw_header.len else { break; }

        var key: u8[..32] = [];
        guard parse_digest_param_key(raw_header, idx, key) else { break; }

        var val: u8[..128] = [];
        guard parse_digest_param_val(raw_header, idx, val) else { break; }

        if eq_ascii_fold(key[..], "realm") {
            chal.realm.clear();
            chal.realm.append(val[..]);
        } else if eq_ascii_fold(key[..], "nonce") {
            chal.nonce.clear();
            chal.nonce.append(val[..]);
        } else if eq_ascii_fold(key[..], "algorithm") {
            chal.algorithm.clear();
            chal.algorithm.append(val[..]);
        } else if eq_ascii_fold(key[..], "qop") {
            chal.qop.clear();
            chal.qop.append(val[..]);
        } else if eq_ascii_fold(key[..], "opaque") {
            chal.opaque.clear();
            chal.opaque.append(val[..]);
        } else if eq_ascii_fold(key[..], "domain") {
            chal.domain.clear();
            chal.domain.append(val[..]);
        } else if eq_ascii_fold(key[..], "stale") {
            chal.stale = eq_ascii_fold(val[..], "true");
        } else if eq_ascii_fold(key[..], "userhash") {
            chal.userhash = eq_ascii_fold(val[..], "true");
        }
    }

    chal.valid = (chal.realm.len > 0 && chal.nonce.len > 0);
    return chal, chal.valid;
}

// ---- 3. Digest Calculation (RFC 7616 Section 3.4 & 3.5) ---------------------

fn digest_hash_hex<B>(algorithm: const u8[:], data: const u8[:], out_hex: B&) {
    out_hex.clear();
    if eq_ascii_fold(algorithm, "md5") || eq_ascii_fold(algorithm, "md5-sess") {
        let md = core::md5(data);
        for b in md {
            core::format_u8_hex(b, out_hex);
        }
    } else {
        // Default to SHA-256 (RFC 7616 standard)
        let sh = core::sha256(data);
        for b in sh {
            core::format_u8_hex(b, out_hex);
        }
    }
}

// Computes RFC 7616 Digest response and outputs the full Authorization header
fn compute_digest_response(
    challenge: const DigestChallenge&,
    creds: const DigestCredentials&,
    method: const u8[:],
    uri: const u8[:],
    nc: u32,
    cnonce: const u8[:],
    body: const u8[:],
    out_header: u8[..512]&
) -> bool {
    guard challenge.valid else { return false; }

    let algo = challenge.algorithm[..];

    // 1. Calculate HA1 = H(username:realm:password)
    var a1: u8[>..] = [];
    a1.append(creds.username[..]);
    a1.push(':');
    a1.append(challenge.realm[..]);
    a1.push(':');
    a1.append(creds.password[..]);

    var ha1_hex: u8[..64] = [];
    digest_hash_hex(algo, a1[..], ha1_hex);

    // If algorithm is *-sess: HA1 = H(H(username:realm:password):nonce:cnonce)
    if eq_ascii_fold(algo, "sha-256-sess") || eq_ascii_fold(algo, "md5-sess") {
        var a1_sess: u8[>..] = [];
        a1_sess.append(ha1_hex[..]);
        a1_sess.push(':');
        a1_sess.append(challenge.nonce[..]);
        a1_sess.push(':');
        a1_sess.append(cnonce);
        digest_hash_hex(algo, a1_sess[..], ha1_hex);
    }

    // 2. Calculate HA2 = H(method:uri) [or H(method:uri:H(entity-body)) if qop=auth-int]
    var a2: u8[>..] = [];
    a2.append(method);
    a2.push(':');
    a2.append(uri);

    let is_auth_int = eq_ascii_fold(challenge.qop[..], "auth-int");
    if is_auth_int {
        var h_body_hex: u8[..64] = [];
        digest_hash_hex(algo, body, h_body_hex);
        a2.push(':');
        a2.append(h_body_hex[..]);
    }

    var ha2_hex: u8[..64] = [];
    digest_hash_hex(algo, a2[..], ha2_hex);

    // 3. Format nc (8-digit hex)
    var nc_str: u8[..16] = [];
    core::format_u64_hex_fixed(nc, 8, nc_str, false);

    // 4. Calculate response = H(HA1:nonce:nc:cnonce:qop:HA2)
    var a3: u8[>..] = [];
    a3.append(ha1_hex[..]);
    a3.push(':');
    a3.append(challenge.nonce[..]);

    let has_qop = (challenge.qop.len > 0);
    if has_qop {
        let active_qop = if is_auth_int { "auth-int" } else { "auth" };
        a3.push(':');
        a3.append(nc_str[..]);
        a3.push(':');
        a3.append(cnonce);
        a3.push(':');
        a3.append(active_qop);
    }

    a3.push(':');
    a3.append(ha2_hex[..]);

    var response_hex: u8[..64] = [];
    digest_hash_hex(algo, a3[..], response_hex);

    // 5. Assemble formatted `Authorization: Digest ...` header
    out_header.clear();
    out_header.append("Digest username=\"");
    out_header.append(creds.username[..]);
    out_header.append("\", realm=\"");
    out_header.append(challenge.realm[..]);
    out_header.append("\", nonce=\"");
    out_header.append(challenge.nonce[..]);
    out_header.append("\", uri=\"");
    out_header.append(uri);
    out_header.append("\", algorithm=");
    out_header.append(algo);
    out_header.append(", response=\"");
    out_header.append(response_hex[..]);
    out_header.append("\"");

    if has_qop {
        let active_qop = if is_auth_int { "auth-int" } else { "auth" };
        out_header.append(", qop=");
        out_header.append(active_qop);
        out_header.append(", nc=");
        out_header.append(nc_str[..]);
        out_header.append(", cnonce=\"");
        out_header.append(cnonce);
        out_header.append("\"");
    }

    if challenge.opaque.len > 0 {
        out_header.append(", opaque=\"");
        out_header.append(challenge.opaque[..]);
        out_header.append("\"");
    }

    return true;
}
