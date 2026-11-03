// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Oblivious HTTP (RFC 9458): key configuration parsing and request/response
// encapsulation over HPKE (RFC 9180), protecting binary HTTP (RFC 9292).
// Suite support is restricted to DHKEM(X25519, HKDF-SHA256) with AES-128-GCM
// or ChaCha20-Poly1305 (the suites provided by tls/hpke.goose for OHTTP).
namespace wing;

import std;
import core from "..";
import tls.hpke;

// ---- RFC 9458 constants ----------------------------------------------------

const OHTTP_MAX_KEY_CONFIGS: i64 = 4;

// ---- structures -------------------------------------------------------------

// Single key configuration (RFC 9458 Section 3.1). Only the first KDF/AEAD
// pair is selected; it must name a supported suite or parsing is rejected.
struct OhttpKeyConfig {
    key_id:         u8       = 0,
    kem_id:         u16      = rfc::HPKE_KEM_DHKEM_X25519_HKDF_SHA256,
    kdf_id:         u16      = rfc::HPKE_KDF_HKDF_SHA256,
    aead_id:        u16      = rfc::HPKE_AEAD_AES_128_GCM,
    public_key:     u8[..32] = [],
    public_key_len: i32      = 0,
}

// Retained per-exchange state: the HPKE context plus `enc` from enc_request,
// which serves as the response KDF salt (RFC 9458 Section 4.3 step 4,
// Section 4.4 step 3).
struct OhttpSession {
    ctx:     HpkeContext = HpkeContext { .. },
    enc:     u8[..32]    = [],
    enc_len: i32         = 0,
}

// ---- shared helpers ---------------------------------------------------------

// Suite restriction for this engine: DHKEM(X25519, HKDF-SHA256) paired with
// AES-128-GCM or ChaCha20-Poly1305 (RFC 9458 Section 4.3 selection rules).
fn ohttp_suite_supported(kem_id: u16, kdf_id: u16, aead_id: u16) -> bool {
    if kem_id != rfc::HPKE_KEM_DHKEM_X25519_HKDF_SHA256 {
        return false;
    }
    if kdf_id != rfc::HPKE_KDF_HKDF_SHA256 {
        return false;
    }
    return aead_id == rfc::HPKE_AEAD_AES_128_GCM || aead_id == rfc::HPKE_AEAD_CHACHA20_POLY1305;
}

// Builds the 7-byte message header hdr = key_id || kem_id || kdf_id || aead_id
// in network byte order (RFC 9458 Section 4.3 step 1).
fn ohttp_build_hdr(cfg: const OhttpKeyConfig&, out: u8[7]&) {
    out[0] = cfg.key_id;
    out[1] = ((cfg.kem_id >> 8) & 0xFF) as u8;
    out[2] = (cfg.kem_id & 0xFF) as u8;
    out[3] = ((cfg.kdf_id >> 8) & 0xFF) as u8;
    out[4] = (cfg.kdf_id & 0xFF) as u8;
    out[5] = ((cfg.aead_id >> 8) & 0xFF) as u8;
    out[6] = (cfg.aead_id & 0xFF) as u8;
}

// Builds info = "message/bhttp request" || 0x00 || hdr (RFC 9458 Section 4.3 step 2):
// 21-byte label + 1 zero byte + 7-byte hdr = 29 bytes (Appendix A info vector).
fn ohttp_request_info(hdr: const u8[:], out: u8[..30]&) -> bool {
    out.clear();
    out.append(rfc::OHTTP_INFO_REQUEST);
    out.push(0);
    out.append(hdr);
    return out.len == 29;
}

// Derives the response AEAD key and nonce (RFC 9458 Section 4.4 steps 1-5):
// secret = context.Export("message/bhttp response", max(Nn, Nk));
// prk = Extract(salt = enc || response_nonce, ikm = secret);
// key = Expand(prk, "key", Nk); nonce = Expand(prk, "nonce", Nn).
// Raw HKDF from RFC 5869, not TLS-style labeled expand.
fn ohttp_derive_response_aead(
    session:        const OhttpSession&,
    response_nonce: const u8[:],
    out_key:        u8[32]&,
    out_nonce:      u8[12]&,
) -> bool {
    let nk = session.ctx.key_len;
    let nn = session.ctx.nonce_len;
    let exp_len = if nk > nn { nk } else { nn };
    guard response_nonce.len == exp_len else { return false; }
    guard session.enc_len == 32 && session.enc.len == 32 else { return false; }

    var secret: u8[32] = [0; 32];
    guard hpke_export(session.ctx, rfc::OHTTP_INFO_RESPONSE, secret[..exp_len]) else { return false; }

    var salt: u8[..64] = [];
    salt.append(session.enc[..]);
    salt.append(response_nonce);
    let prk = core::hkdf_extract(salt[..], secret[..exp_len]);

    guard core::hkdf_expand_bytes_256(prk[..], "key", nk, out_key[..nk]) else { return false; }
    guard core::hkdf_expand_bytes_256(prk[..], "nonce", nn, out_nonce[..nn]) else { return false; }
    return true;
}

// ---- key configuration parsing (RFC 9458 Sections 3.1-3.2) ------------------

// Parses one key configuration: Key Identifier (8), KEM ID (16), Public Key
// (Npk*8, Npk = 32 for X25519), Symmetric Algorithms Length (16) = 4..65532,
// then repeated 4-byte (KDF ID, AEAD ID) pairs. Unsupported suites are rejected.
//
// Example:
//   raw = 01 00 20 <32-byte pk> 00 04 00 01 00 01, out = OhttpKeyConfig { .. }
//   returns: ok = true, out.key_id = 1, out.kem_id = 0x0020, first pair 0x0001/0x0001
fn parse_ohttp_key_config(raw: const u8[:], out: OhttpKeyConfig&) -> bool {
    guard raw.len >= rfc::OHTTP_MIN_KEY_CONFIG_LEN else { return false; }
    let kem_id = ((raw[1] as u16) << 8) | raw[2];
    guard kem_id == rfc::HPKE_KEM_DHKEM_X25519_HKDF_SHA256 else { return false; }
    let sym_len = ((raw[35] as u16) << 8) | raw[36];
    guard sym_len >= 4 && (sym_len % 4) == 0 else { return false; }
    guard 37 + sym_len == raw.len else { return false; }
    let kdf_id = ((raw[37] as u16) << 8) | raw[38];
    let aead_id = ((raw[39] as u16) << 8) | raw[40];
    guard ohttp_suite_supported(kem_id, kdf_id, aead_id) else { return false; }

    out.key_id = raw[0];
    out.kem_id = kem_id;
    out.kdf_id = kdf_id;
    out.aead_id = aead_id;
    out.public_key.clear();
    out.public_key.append(raw[3..35]);
    out.public_key_len = 32;
    return true;
}

// Parses an "application/ohttp-keys" collection: u16be length-prefixed configs
// concatenated (RFC 9458 Section 3.2). ANY malformed element discards the whole
// collection: ok == false and out_count == 0 (MUST discard).
//
// Example:
//   raw = 00 2D <45-byte config> 00 2D <45-byte config>, out_count = 99
//   returns: ok = true, out_count = 2, out[0..2] filled
fn parse_ohttp_key_configs(raw: const u8[:], out: OhttpKeyConfig[..4]&, out_count: i32&) -> bool {
    out_count = 0;
    guard raw.len >= 2 else { return false; }
    var idx:   i64 = 0;
    var count: i64 = 0;
    while idx < raw.len {
        guard (raw.len - idx) >= 2 else { return false; }
        let elen = ((raw[idx] as i64) << 8) | raw[idx + 1];
        idx += 2;
        guard elen > 0 && elen <= (raw.len - idx) else { return false; }
        guard count < OHTTP_MAX_KEY_CONFIGS else { return false; }
        var elem = OhttpKeyConfig { .. };
        guard parse_ohttp_key_config(raw[idx..idx + elen], elem) else { return false; }
        out[count] = elem;
        count += 1;
        idx += elen;
    }
    out_count = count as i32;
    return true;
}

// ---- request encapsulation (RFC 9458 Sections 4.1, 4.3) ---------------------

// Seals a binary HTTP request into an Encapsulated Request:
// enc_request = hdr || enc || ct (RFC 9458 Section 4.1). The ephemeral HPKE
// secret key is caller-supplied so the engine does not own entropy; fills
// `session` with the sending context and `enc` for later response sealing.
//
// Example:
//   cfg = { key_id: 1, ... }, inner_bhttp = <bhttp request>, out = []
//   returns: ok = true, out[0..7] = hdr, out_len = 7 + 32 + len(inner) + 16
fn ohttp_seal_request(
    cfg:          const OhttpKeyConfig&,
    ephemeral_sk: const u8[32]&,
    inner_bhttp:  const u8[:],
    out:          u8[..8192]&,
    out_len:      i32&,
    session:      OhttpSession&,
) -> bool {
    guard ohttp_suite_supported(cfg.kem_id, cfg.kdf_id, cfg.aead_id) else { return false; }
    guard cfg.public_key_len == 32 && cfg.public_key.len == 32 else { return false; }

    var hdr: u8[7] = [0; 7];
    ohttp_build_hdr(cfg, hdr);
    var info: u8[..30] = [];
    guard ohttp_request_info(hdr[..], info) else { return false; }

    var pk: u8[32] = [0; 32];
    for i in 32 { pk[i] = cfg.public_key[i]; }
    var enc: u8[32] = [0; 32];
    guard hpke_setup_base_s(
        pk,
        info[..],
        cfg.kem_id,
        cfg.kdf_id,
        cfg.aead_id,
        ephemeral_sk,
        enc,
        session.ctx,
    ) else {
        return false;
    }

    var ct: u8[>..] = [];
    guard hpke_seal(session.ctx, [], inner_bhttp, ct) else { return false; }
    guard rfc::OHTTP_HDR_LEN + 32 + ct.len <= out.cap else { return false; }

    out.clear();
    out.append(hdr[..]);
    out.append(enc[..]);
    out.append(ct[..]);

    session.enc.clear();
    session.enc.append(enc[..]);
    session.enc_len = 32;
    out_len = out.len as i32;
    return true;
}

// Opens an Encapsulated Request at the Oblivious Gateway Resource:
// SetupBaseR + Open (RFC 9458 Section 4.3). Fills `session` with the
// receiving context and `enc` so a response can be sealed afterwards.
//
// Example:
//   enc_request = <7-byte hdr> || <32-byte enc> || <ct>, out = []
//   returns: ok = true with out = original bhttp request, out_len = len(out)
fn ohttp_open_request(
    skR:         const u8[:],
    enc_request: const u8[:],
    out:         u8[..8192]&,
    out_len:     i32&,
    session:     OhttpSession&,
) -> bool {
    guard skR.len == 32 else { return false; }
    guard enc_request.len >= rfc::OHTTP_HDR_LEN + 32 + rfc::OHTTP_AEAD_TAG_LEN else { return false; }
    let kem_id = ((enc_request[1] as u16) << 8) | enc_request[2];
    let kdf_id = ((enc_request[3] as u16) << 8) | enc_request[4];
    let aead_id = ((enc_request[5] as u16) << 8) | enc_request[6];
    guard ohttp_suite_supported(kem_id, kdf_id, aead_id) else { return false; }

    var hdr: u8[7] = [0; 7];
    for i in 7 { hdr[i] = enc_request[i]; }
    var info: u8[..30] = [];
    guard ohttp_request_info(hdr[..], info) else { return false; }

    var enc: u8[32] = [0; 32];
    for i in 32 { enc[i] = enc_request[rfc::OHTTP_HDR_LEN + i]; }
    let ct = enc_request[rfc::OHTTP_HDR_LEN + 32..];

    var sk: u8[32] = [0; 32];
    for i in 32 { sk[i] = skR[i]; }
    guard hpke_setup_base_r(enc, sk, info[..], kem_id, kdf_id, aead_id, session.ctx) else { return false; }

    var pt: u8[>..] = [];
    guard hpke_open(session.ctx, [], ct, pt) else { return false; }
    guard pt.len <= out.cap else { return false; }

    out.clear();
    out.append(pt[..]);
    session.enc.clear();
    session.enc.append(enc[..]);
    session.enc_len = 32;
    out_len = pt.len as i32;
    return true;
}

// ---- response encapsulation (RFC 9458 Section 4.4) -------------------------

// Seals a binary HTTP response into an Encapsulated Response:
// enc_response = response_nonce || ct. Uses Export + HKDF re-derivation
// (RFC 9458 Section 4.4), NOT a plain HPKE Seal; response_nonce is
// caller-supplied with length max(Nn, Nk) (engine does not own entropy).
//
// Example:
//   session = gateway session from ohttp_open_request, response_nonce = <16 bytes>
//   returns: ok = true, out[0..16] = response_nonce, out_len = 16 + len(response) + 16
fn ohttp_seal_response(
    session:        const OhttpSession&,
    response_nonce: const u8[:],
    response:       const u8[:],
    out:            u8[..8192]&,
    out_len:        i32&,
) -> bool {
    var key:   u8[32] = [0; 32];
    var nonce: u8[12] = [0; 12];
    guard ohttp_derive_response_aead(session, response_nonce, key, nonce) else { return false; }

    var ct: u8[>..] = [];
    for i in response.len { ct.push(0); }
    if session.ctx.aead_id == rfc::HPKE_AEAD_AES_128_GCM {
        var key16: u8[16] = [0; 16];
        for i in 16 { key16[i] = key[i]; }
        let tag, _, ok = core::aes128_gcm_seal(key16, nonce, response, [], ct[..]);
        guard ok else { return false; }
        for i in 16 { ct.push(tag[i]); }
    } else if session.ctx.aead_id == rfc::HPKE_AEAD_CHACHA20_POLY1305 {
        let tag, _, ok = core::chacha20_poly1305_seal(key, nonce, response, [], ct[..]);
        guard ok else { return false; }
        for i in 16 { ct.push(tag[i]); }
    } else {
        return false;
    }

    guard response_nonce.len + ct.len <= out.cap else { return false; }
    out.clear();
    out.append(response_nonce);
    out.append(ct[..]);
    out_len = out.len as i32;
    return true;
}

// Opens an Encapsulated Response at the client (RFC 9458 Section 4.4):
// same Export + HKDF derivation using the retained sending context.
//
// Example:
//   enc_response = <max(Nn,Nk)-byte nonce> || <ct>, session = client session
//   returns: ok = true with out = original bhttp response
fn ohttp_open_response(
    session:      const OhttpSession&,
    enc_response: const u8[:],
    out:          u8[..8192]&,
    out_len:      i32&,
) -> bool {
    let nk = session.ctx.key_len;
    let nn = session.ctx.nonce_len;
    let exp_len = if nk > nn { nk } else { nn };
    guard enc_response.len >= exp_len + rfc::OHTTP_AEAD_TAG_LEN else { return false; }

    let response_nonce = enc_response[..exp_len];
    let ct = enc_response[exp_len..];

    var key:   u8[32] = [0; 32];
    var nonce: u8[12] = [0; 12];
    guard ohttp_derive_response_aead(session, response_nonce, key, nonce) else { return false; }

    var tag: u8[16] = [0; 16];
    for i in 16 { tag[i] = ct[ct.len - 16 + i]; }
    let body = ct[..ct.len - 16];

    var pt: u8[>..] = [];
    if session.ctx.aead_id == rfc::HPKE_AEAD_AES_128_GCM {
        var key16: u8[16] = [0; 16];
        for i in 16 { key16[i] = key[i]; }
        guard core::aes128_gcm_open(key16, nonce, body, [], tag, pt) else { return false; }
    } else if session.ctx.aead_id == rfc::HPKE_AEAD_CHACHA20_POLY1305 {
        guard core::chacha20_poly1305_open(key, nonce, body, [], tag, pt) else { return false; }
    } else {
        return false;
    }

    guard pt.len <= out.cap else { return false; }
    out.clear();
    out.append(pt[..]);
    out_len = pt.len as i32;
    return true;
}
