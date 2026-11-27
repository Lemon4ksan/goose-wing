// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Oblivious HTTP (RFC 9458): key configuration parsing and request/response
// encapsulation over HPKE (RFC 9180), protecting binary HTTP (RFC 9292).
// Suite support is restricted to DHKEM(X25519, HKDF-SHA256) with AES-128-GCM
// or ChaCha20-Poly1305 (the suites provided by tls/hpke.goose for OHTTP).
namespace http;

import std;
import core;
import security.hpke;
import .bhttp;
import http.codec_internal;

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
    ctx:             security::HpkeContext = security::HpkeContext { .. },
    enc:             u8[..32]              = [],
    enc_len:         i32                   = 0,
    response_sealed: bool                  = false,
}

const OHTTP_REPLAY_CACHE_CAP: i64 = 64;

// Bounded ring-buffer replay cache of SHA-256(`enc`) digests with TTL (RFC 9458 §6.5.2).
struct OhttpReplayCache {
    enc_hashes: u8[32][64] = [[0; 32]; 64],
    timestamps: i64[64]    = [0; 64],
    occupied:   bool[64]   = [false; 64],
    head:       i64        = 0,
    ttl_sec:    i64        = 300,
}

// ---- shared helpers ---------------------------------------------------------

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
    let kem_id = core::read_be_u16(raw, 1);
    guard kem_id == rfc::HPKE_KEM_DHKEM_X25519_HKDF_SHA256 else { return false; }
    let sym_len = core::read_be_u16(raw, 35);
    guard sym_len >= 4 && (sym_len & 3) == 0 else { return false; }
    guard 37 + (sym_len as i64) == raw.len else { return false; }

    var kdf_id:  u16 = 0;
    var aead_id: u16 = 0;
    guard http_internal::scan_supported_ohttp_sym_suite(raw, kem_id, sym_len, kdf_id, aead_id) else {
        return false;
    }

    out.key_id = raw[0];
    out.kem_id = kem_id;
    out.kdf_id = kdf_id;
    out.aead_id = aead_id;
    let _ = out.public_key.try_set(raw[3..35]);
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
    out.clear();
    guard raw.len >= 2 else { return false; }
    var committed = false;
    defer if !committed {
        out.clear();
        out_count = 0;
    };
    var cur = core::cursor_from(raw);
    while cur.buf.len > 0 {
        let elem_raw, ok_elem = cur.read_u16_prefixed();
        guard ok_elem && elem_raw.len > 0 else { return false; }
        var elem = OhttpKeyConfig { .. };
        if parse_ohttp_key_config(elem_raw, elem) {
            guard out.len < OHTTP_MAX_KEY_CONFIGS && out.try_push(elem) else {
                return false;
            }
        } else {
            guard http_internal::is_skippable_ohttp_key_config(elem_raw) else { return false; }
        }
    }
    guard out.len > 0 else { return false; }
    out_count = out.len as i32;
    committed = true;
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
    guard http_internal::ohttp_suite_supported(cfg.kem_id, cfg.kdf_id, cfg.aead_id) else { return false; }
    guard cfg.public_key_len == 32 && cfg.public_key.len == 32 else { return false; }

    var hdr: u8[7] = [0; 7];
    http_internal::ohttp_build_hdr(cfg, hdr);
    var info: u8[..30] = [];
    guard http_internal::ohttp_request_info(hdr[..], info) else { return false; }

    var pk: u8[32] = [0; 32];
    for i in 32 { pk[i] = cfg.public_key[i]; }
    var enc: u8[32] = [0; 32];
    guard security::hpke_setup_base_s(
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

    guard rfc::OHTTP_HDR_LEN + 32 + inner_bhttp.len + 16 <= out.cap else {
        security::zeroize_hpke_context(session.ctx);
        return false;
    }

    out.clear();
    out.append(hdr[..]);
    out.append(enc[..]);
    guard security::hpke_seal(session.ctx, [], inner_bhttp, out) else {
        security::zeroize_hpke_context(session.ctx);
        out.clear();
        return false;
    }

    let _ = session.enc.try_set(enc[..]);
    session.enc_len = 32;
    session.response_sealed = false;
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
    out_len = 0;
    guard skR.len == 32 else { return false; }
    guard enc_request.len >= rfc::OHTTP_HDR_LEN + 32 + rfc::OHTTP_AEAD_TAG_LEN else { return false; }
    let kem_id = ((enc_request[1] as u16) << 8) | enc_request[2];
    let kdf_id = ((enc_request[3] as u16) << 8) | enc_request[4];
    let aead_id = ((enc_request[5] as u16) << 8) | enc_request[6];
    guard http_internal::ohttp_suite_supported(kem_id, kdf_id, aead_id) else { return false; }

    var hdr: u8[7] = [0; 7];
    for i in 7 { hdr[i] = enc_request[i]; }
    var info: u8[..30] = [];
    guard http_internal::ohttp_request_info(hdr[..], info) else { return false; }

    var enc: u8[32] = [0; 32];
    for i in 32 { enc[i] = enc_request[rfc::OHTTP_HDR_LEN + i]; }
    let ct = enc_request[rfc::OHTTP_HDR_LEN + 32..];
    guard ct.len - rfc::OHTTP_AEAD_TAG_LEN <= out.cap else { return false; }

    var sk: u8[32] = [0; 32];
    for i in 32 { sk[i] = skR[i]; }
    let ok_setup = security::hpke_setup_base_r(enc, sk, info[..], kem_id, kdf_id, aead_id, session.ctx);
    core::secure_zeroize_32(sk);
    guard ok_setup else { return false; }

    out.clear();
    guard security::hpke_open(session.ctx, [], ct, out) else {
        security::zeroize_hpke_context(session.ctx);
        session.enc.clear();
        session.enc_len = 0;
        session.response_sealed = false;
        return false;
    }
    let _ = session.enc.try_set(enc[..]);
    session.enc_len = 32;
    session.response_sealed = false;
    out_len = out.len as i32;
    return true;
}

// Opens an Encapsulated Request at the Oblivious Gateway Resource and rejects
// replayed `enc` values within `cache.ttl_sec` (RFC 9458 Section 6.5.2).
//
// Example:
//   cache = OhttpReplayCache { ttl_sec: 300, .. }, now_sec = 1700000000
//   returns: ok = true on first `enc`; ok = false on duplicate `enc` within TTL
fn ohttp_open_request_checked(
    cache:       OhttpReplayCache&,
    skR:         const u8[:],
    enc_request: const u8[:],
    now_sec:     i64,
    out:         u8[..8192]&,
    out_len:     i32&,
    session:     OhttpSession&,
) -> bool {
    out_len = 0;
    guard now_sec >= 0 && cache.ttl_sec > 0 else { return false; }
    guard enc_request.len >= rfc::OHTTP_HDR_LEN + 32 + rfc::OHTTP_AEAD_TAG_LEN else { return false; }
    let enc_slice = enc_request[rfc::OHTTP_HDR_LEN..rfc::OHTTP_HDR_LEN + 32];
    let enc_hash = core::sha256(enc_slice);
    guard !http_internal::ohttp_replay_cache_has(cache, enc_hash, now_sec) else { return false; }
    guard ohttp_open_request(skR, enc_request, out, out_len, session) else { return false; }
    http_internal::ohttp_replay_cache_insert(cache, enc_hash, now_sec);
    return true;
}

// ---- response encapsulation (RFC 9458 Section 4.4) -------------------------

// Zeroizes retained HPKE context secrets and `enc` in `session`.
fn zeroize_ohttp_session(session: OhttpSession&) {
    security::zeroize_hpke_context(session.ctx);
    core::secure_zeroize_slice(session.enc[..]);
    session.enc.clear();
    session.enc_len = 0;
    session.response_sealed = false;
}

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
    out_len = 0;
    guard session.ctx.role == security::HpkeRole.Recipient && !session.response_sealed else { return false; }
    guard response_nonce.len + response.len + rfc::OHTTP_AEAD_TAG_LEN <= out.cap else { return false; }

    var key:   u8[32] = [0; 32];
    var nonce: u8[12] = [0; 12];
    defer core::secure_zeroize_32(key);
    defer core::secure_zeroize_slice(nonce[..]);
    guard http_internal::ohttp_derive_response_aead(session, response_nonce, key, nonce) else { return false; }

    var ct: u8[..8192] = [];
    for i in response.len { ct.push(0); }
    var seal_ok = false;
    if session.ctx.aead_id == rfc::HPKE_AEAD_AES_128_GCM {
        var key16: u8[16] = [0; 16];
        defer core::secure_zeroize_16(key16);
        for i in 16 { key16[i] = key[i]; }
        let tag, _, ok = core::aes128_gcm_seal(key16, nonce, response, [], ct[..]);
        if ok {
            for i in 16 { ct.push(tag[i]); }
            seal_ok = true;
        }
    } else if session.ctx.aead_id == rfc::HPKE_AEAD_CHACHA20_POLY1305 {
        let tag, _, ok = core::chacha20_poly1305_seal(key, nonce, response, [], ct[..]);
        if ok {
            for i in 16 { ct.push(tag[i]); }
            seal_ok = true;
        }
    }
    guard seal_ok else { return false; }

    out.clear();
    out.append(response_nonce);
    out.append(ct[..]);
    out_len = out.len as i32;
    return true;
}

// Seals a single response on a gateway `OhttpSession` and marks `session.response_sealed`
// so the same `enc` / exported secret cannot be reused with a second response_nonce.
fn ohttp_seal_response_once(
    session:        OhttpSession&,
    response_nonce: const u8[:],
    response:       const u8[:],
    out:            u8[..8192]&,
    out_len:        i32&,
) -> bool {
    guard ohttp_seal_response(session, response_nonce, response, out, out_len) else { return false; }
    session.response_sealed = true;
    return true;
}

// Seals a single response using a fresh CSPRNG-generated `response_nonce` of length `max(Nn, Nk)`.
fn ohttp_seal_response_random(
    session:  OhttpSession&,
    response: const u8[:],
    out:      u8[..8192]&,
    out_len:  i32&,
) -> bool {
    out_len = 0;
    guard session.ctx.role == security::HpkeRole.Recipient && !session.response_sealed else { return false; }
    let exp_len = max(session.ctx.key_len, session.ctx.nonce_len) as i64;
    guard exp_len > 0 && exp_len <= 32 else { return false; }
    var nonce_buf: u8[32] = [0; 32];
    defer core::secure_zeroize_32(nonce_buf);
    guard core::csprng_fill(nonce_buf[..exp_len]) else { return false; }
    return ohttp_seal_response_once(session, nonce_buf[..exp_len], response, out, out_len);
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
    out_len = 0;
    guard session.ctx.role == security::HpkeRole.Sender else { return false; }
    let nk = session.ctx.key_len;
    let nn = session.ctx.nonce_len;
    let exp_len = max(nk, nn);
    guard enc_response.len >= exp_len + rfc::OHTTP_AEAD_TAG_LEN else { return false; }

    let response_nonce = enc_response[..exp_len];
    let ct = enc_response[exp_len..];
    guard ct.len - rfc::OHTTP_AEAD_TAG_LEN <= out.cap else { return false; }

    var key:   u8[32] = [0; 32];
    var nonce: u8[12] = [0; 12];
    defer core::secure_zeroize_32(key);
    defer core::secure_zeroize_slice(nonce[..]);
    guard http_internal::ohttp_derive_response_aead(session, response_nonce, key, nonce) else { return false; }

    var tag: u8[16] = [0; 16];
    for i in 16 { tag[i] = ct[ct.len - 16 + i]; }
    let body = ct[..^16];

    out.clear();
    var open_ok = false;
    if session.ctx.aead_id == rfc::HPKE_AEAD_AES_128_GCM {
        var key16: u8[16] = [0; 16];
        defer core::secure_zeroize_16(key16);
        for i in 16 { key16[i] = key[i]; }
        open_ok = core::aes128_gcm_open(key16, nonce, body, [], tag, out);
    } else if session.ctx.aead_id == rfc::HPKE_AEAD_CHACHA20_POLY1305 {
        open_ok = core::chacha20_poly1305_open(key, nonce, body, [], tag, out);
    }
    guard open_ok else {
        out.clear();
        return false;
    }

    out_len = out.len as i32;
    return true;
}

// Encodes a `BhttpRequest` (RFC 9292) and seals it into an Oblivious HTTP Encapsulated Request (RFC 9458 §4.1).
fn ohttp_seal_bhttp_request(
    cfg:          const OhttpKeyConfig&,
    ephemeral_sk: const u8[32]&,
    req:          const BhttpRequest&,
    out:          u8[..8192]&,
    out_len:      i32&,
    session:      OhttpSession&,
) -> bool {
    var bhttp_buf: u8[..8192] = [];
    let blen = bhttp_encode_request(req, bhttp_buf);
    guard blen > 0 else { return false; }
    return ohttp_seal_request(cfg, ephemeral_sk, bhttp_buf[..], out, out_len, session);
}

// Opens an Oblivious HTTP Encapsulated Request and decodes the inner `BhttpRequest` (RFC 9458 §4.3, RFC 9292).
fn ohttp_open_bhttp_request(
    skR:         const u8[:],
    enc_request: const u8[:],
    out_req:     BhttpRequest&,
    session:     OhttpSession&,
) -> bool {
    var bhttp_buf: u8[..8192] = [];
    var bhttp_len: i32        = 0;
    guard ohttp_open_request(skR, enc_request, bhttp_buf, bhttp_len, session) else { return false; }
    return bhttp_decode_request(bhttp_buf[..(bhttp_len as i64)], out_req);
}

// Encodes a `BhttpResponse` (RFC 9292) and seals it into an Oblivious HTTP Encapsulated Response (RFC 9458 §4.4).
fn ohttp_seal_bhttp_response(
    session:        const OhttpSession&,
    response_nonce: const u8[:],
    res:            const BhttpResponse&,
    out:            u8[..8192]&,
    out_len:        i32&,
) -> bool {
    var bhttp_buf: u8[..8192] = [];
    let blen = bhttp_encode_response(res, bhttp_buf);
    guard blen > 0 else { return false; }
    return ohttp_seal_response(session, response_nonce, bhttp_buf[..], out, out_len);
}

// Opens an Oblivious HTTP Encapsulated Response and decodes the inner `BhttpResponse` (RFC 9458 §4.4, RFC 9292).
fn ohttp_open_bhttp_response(
    session:      const OhttpSession&,
    enc_response: const u8[:],
    out_res:      BhttpResponse&,
) -> bool {
    var bhttp_buf: u8[..8192] = [];
    var bhttp_len: i32        = 0;
    guard ohttp_open_response(session, enc_response, bhttp_buf, bhttp_len) else { return false; }
    return bhttp_decode_response(bhttp_buf[..(bhttp_len as i64)], out_res);
}
