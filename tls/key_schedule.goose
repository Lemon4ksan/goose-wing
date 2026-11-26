// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Deterministic zero-allocation TLS 1.3 Key Schedule and RFC 9001 QUIC Key Derivation.
// Conforms to RFC 8446 Section 7.1, RFC 9001 Section 5.1-5.4, and BoringSSL HKDF layout.
namespace tls_internal;

import std;
import core;
import rfc.h3_quic;
import rfc.tls;

// ---- Constants and Supported Cipher Suites -------------------------------

const HASH_SHA256: u8 = 1;
const HASH_SHA384: u8 = 2;

const KS_STAGE_UNINIT:     u8 = 0;
const KS_STAGE_EARLY:      u8 = 1;
const KS_STAGE_HANDSHAKE:  u8 = 2;
const KS_STAGE_MASTER:     u8 = 3;
const KS_STAGE_RESUMPTION: u8 = 4;

// ---- HKDF-Expand-Label and Derive-Secret (RFC 8446 Section 7.1) ----------

// Encodes HkdfLabel structure:
// struct {
//     uint16 length = Length;
//     opaque label<7..255> = "tls13 " + Label;
//     opaque context<0..255> = Context;
// } HkdfLabel;
inline fn is_all_zero_slice(data: const u8[:]) -> bool {
    return core::ct_declassify_u8(core::ct_is_zero_bit(data)) == 1;
}

fn hkdf_expand_label(
    hash_id: u8,
    secret:  const u8[:],
    label:   const u8[:],
    context: const u8[:],
    length:  u16,
    out:     u8[:],
) -> bool {
    let full_label_len = 6 + label.len;
    guard full_label_len >= 7 && full_label_len <= 255 else { return false; }
    guard context.len <= 255 else { return false; }
    guard length > 0 else { return false; }
    guard out.len >= length else { return false; }

    if hash_id == HASH_SHA256 {
        guard secret.len >= 32 else { return false; }
        guard (length as i64) <= 255 * 32 else { return false; }
    } else if hash_id == HASH_SHA384 {
        guard secret.len >= 48 else { return false; }
        guard (length as i64) <= 255 * 48 else { return false; }
    } else {
        return false;
    }

    let total_info_len = 2 + 1 + full_label_len + 1 + context.len;
    guard total_info_len <= 516 else { return false; }

    var info: u8[..516] = [];
    // uint16 length
    info.append_u16_be(length);
    // opaque label<7..255> = "tls13 " + Label
    info.push(full_label_len as u8);
    info.append("tls13 ");
    info.append(label);
    // opaque context<0..255>
    info.push(context.len as u8);
    info.append(context);

    if hash_id == HASH_SHA256 {
        return core::hkdf_expand_bytes_256(secret, info[..], length, out);
    } else if hash_id == HASH_SHA384 {
        return core::hkdf_expand_bytes_384(secret, info[..], length, out);
    }
    return false;
}

// Derive-Secret(Secret, Label, Messages) = HKDF-Expand-Label(Secret, Label, Transcript-Hash(Messages), Hash.length)
// When messages are empty (""), context is Hash("").
fn derive_secret(
    hash_id:         u8,
    hash_len:        u8,
    secret:          const u8[:],
    label:           const u8[:],
    transcript_hash: const u8[:],
    out:             u8[:],
) -> bool {
    guard out.len >= hash_len else { return false; }
    guard secret.len >= hash_len else { return false; }
    guard transcript_hash.len == 0 || transcript_hash.len == hash_len else { return false; }

    if transcript_hash.len == 0 {
        if hash_id == HASH_SHA256 {
            let empty_h = core::sha256([]);
            return hkdf_expand_label(hash_id, secret, label, empty_h[..], hash_len, out);
        } else if hash_id == HASH_SHA384 {
            let empty_h = core::sha384([]);
            return hkdf_expand_label(hash_id, secret, label, empty_h[..], hash_len, out);
        }
        return false;
    }

    return hkdf_expand_label(hash_id, secret, label, transcript_hash, hash_len, out);
}

// ---- KeySchedule Struct and Lifecycle Transitions ------------------------

struct KeySchedule {
    cipher_suite:          u16      = 0,
    hash_id:               u8       = 1,
    hash_len:              u8       = 32,
    stage:                 u8       = 0,
    current_secret:        u8[48]   = [0; 48],
    client_early_traffic:  u8[48]   = [0; 48],
    early_exporter_secret: u8[..48] = [],
    client_hs_traffic:     u8[48]   = [0; 48],
    server_hs_traffic:     u8[48]   = [0; 48],
    client_ap_traffic:     u8[48]   = [0; 48],
    server_ap_traffic:     u8[48]   = [0; 48],
    exporter_secret:       u8[48]   = [0; 48],
    resumption_secret:     u8[48]   = [0; 48],
    binder_key:            u8[48]   = [0; 48],
}

fn ks_init(cipher_suite: u16) -> KeySchedule, bool {
    var ks = KeySchedule { cipher_suite: cipher_suite };
    if cipher_suite == rfc::TLS_CIPHER_AES_128_GCM_SHA256 || cipher_suite == rfc::TLS_CIPHER_CHACHA20_POLY1305_SHA256 {
        ks.hash_id = HASH_SHA256;
        ks.hash_len = rfc::tls13_cipher_suite_hash_len(cipher_suite);
        return ks, true;
    } else if cipher_suite == rfc::TLS_CIPHER_AES_256_GCM_SHA384 {
        ks.hash_id = HASH_SHA384;
        ks.hash_len = rfc::tls13_cipher_suite_hash_len(cipher_suite);
        return ks, true;
    }
    return ks, false;
}

// Initializes Early Secret from either zero-filled secret (no PSK) or external/resumption PSK (RFC 8446 §7.1).
// For external PSK: derives "ext binder"
// For resumption PSK / no PSK: derives "res binder"
fn ks_init_early_secret_with_mode(ks: KeySchedule&, psk: const u8[:], is_external: bool) -> bool {
    var committed = false;
    defer if !committed { ks_zeroize(ks); };
    let zeros: u8[48] = [0; 48];
    let zero_salt = zeros[..ks.hash_len];
    let ikm = if psk.len > 0 { psk } else { zero_salt };

    if ks.hash_id == HASH_SHA256 {
        var es = core::hkdf_extract(zero_salt, ikm);
        for i in 32 { ks.current_secret[i] = es[i]; }
        core::secure_zeroize_32(es);
    } else if ks.hash_id == HASH_SHA384 {
        var es = core::hkdf_extract_384(zero_salt, ikm);
        for i in 48 { ks.current_secret[i] = es[i]; }
        core::secure_zeroize_48(es);
    } else {
        return false;
    }

    let binder_label = if is_external { "ext binder" } else { "res binder" };
    guard derive_secret(
        ks.hash_id,
        ks.hash_len,
        ks.current_secret[..ks.hash_len],
        binder_label,
        [],
        ks.binder_key[..ks.hash_len],
    ) else {
        return false;
    }
    ks.stage = KS_STAGE_EARLY;
    committed = true;
    return true;
}

// Early Secret = HKDF-Extract(0, PSK) defaulting to resumption PSK or 0-filled secret
fn ks_init_early_secret(ks: KeySchedule&, psk: const u8[:]) -> bool {
    return ks_init_early_secret_with_mode(ks, psk, false);
}

// client_early_traffic_secret = Derive-Secret(Early Secret, "c e traffic", ClientHello)
// early_exporter_master_secret = Derive-Secret(Early Secret, "e exp master", ClientHello)
fn ks_derive_early_traffic(ks: KeySchedule&, client_hello_hash: const u8[:]) -> bool {
    guard ks.stage == KS_STAGE_EARLY else { return false; }
    guard client_hello_hash.len == ks.hash_len else { return false; }
    let ok_ce = derive_secret(
        ks.hash_id,
        ks.hash_len,
        ks.current_secret[..ks.hash_len],
        "c e traffic",
        client_hello_hash,
        ks.client_early_traffic[..ks.hash_len],
    );
    var ee_sec: u8[48] = [0; 48];
    defer core::secure_zeroize_48(ee_sec);
    let ok_ee = derive_secret(
        ks.hash_id,
        ks.hash_len,
        ks.current_secret[..ks.hash_len],
        "e exp master",
        client_hello_hash,
        ee_sec[..ks.hash_len],
    );
    let ok_set = ks.early_exporter_secret.try_set(ee_sec[..ks.hash_len]);
    return ok_ce && ok_ee && ok_set;
}

// Handshake Secret = HKDF-Extract(Derive-Secret(Early Secret, "derived", ""), (EC)DHE)
fn ks_advance_to_handshake(ks: KeySchedule&, ecdhe_shared_secret: const u8[:]) -> bool {
    guard ks.stage == KS_STAGE_EARLY else { return false; }
    guard ecdhe_shared_secret.len > 0 else { return false; }
    guard !is_all_zero_slice(ecdhe_shared_secret) else { return false; }

    var derived: u8[48] = [0; 48];
    defer core::secure_zeroize_48(derived);
    if !derive_secret(
        ks.hash_id,
        ks.hash_len,
        ks.current_secret[..ks.hash_len],
        "derived",
        [],
        derived[..ks.hash_len],
    ) {
        return false;
    }

    if ks.hash_id == HASH_SHA256 {
        var hs = core::hkdf_extract(derived[..32], ecdhe_shared_secret);
        for i in 32 { ks.current_secret[i] = hs[i]; }
        core::secure_zeroize_32(hs);
    } else if ks.hash_id == HASH_SHA384 {
        var hs = core::hkdf_extract_384(derived[..48], ecdhe_shared_secret);
        for i in 48 { ks.current_secret[i] = hs[i]; }
        core::secure_zeroize_48(hs);
    } else {
        return false;
    }

    ks.stage = KS_STAGE_HANDSHAKE;
    return true;
}

// Derives client and server handshake traffic secrets:
// c hs traffic = Derive-Secret(Handshake Secret, "c hs traffic", CH...SH)
// s hs traffic = Derive-Secret(Handshake Secret, "s hs traffic", CH...SH)
fn ks_derive_handshake_traffic(ks: KeySchedule&, ch_sh_hash: const u8[:]) -> bool {
    guard ks.stage == KS_STAGE_HANDSHAKE else { return false; }
    guard ch_sh_hash.len == ks.hash_len else { return false; }

    let ok_c = derive_secret(
        ks.hash_id,
        ks.hash_len,
        ks.current_secret[..ks.hash_len],
        "c hs traffic",
        ch_sh_hash,
        ks.client_hs_traffic[..ks.hash_len],
    );
    let ok_s = derive_secret(
        ks.hash_id,
        ks.hash_len,
        ks.current_secret[..ks.hash_len],
        "s hs traffic",
        ch_sh_hash,
        ks.server_hs_traffic[..ks.hash_len],
    );
    return ok_c && ok_s;
}

// Master Secret = HKDF-Extract(Derive-Secret(Handshake Secret, "derived", ""), 0)
// c ap traffic = Derive-Secret(Master Secret, "c ap traffic", Transcript)
// s ap traffic = Derive-Secret(Master Secret, "s ap traffic", Transcript)
// exp master = Derive-Secret(Master Secret, "exp master", Transcript)
fn ks_advance_to_master(ks: KeySchedule&, transcript_hash: const u8[:]) -> bool {
    guard ks.stage == KS_STAGE_HANDSHAKE else { return false; }
    guard transcript_hash.len == ks.hash_len else { return false; }

    var committed = false;
    defer if !committed { ks_zeroize(ks); };

    var derived: u8[48] = [0; 48];
    defer core::secure_zeroize_48(derived);
    if !derive_secret(
        ks.hash_id,
        ks.hash_len,
        ks.current_secret[..ks.hash_len],
        "derived",
        [],
        derived[..ks.hash_len],
    ) {
        return false;
    }

    let zeros: u8[48] = [0; 48];
    let zero_ikm = zeros[..ks.hash_len];

    if ks.hash_id == HASH_SHA256 {
        var ms = core::hkdf_extract(derived[..32], zero_ikm);
        for i in 32 { ks.current_secret[i] = ms[i]; }
        core::secure_zeroize_32(ms);
    } else if ks.hash_id == HASH_SHA384 {
        var ms = core::hkdf_extract_384(derived[..48], zero_ikm);
        for i in 48 { ks.current_secret[i] = ms[i]; }
        core::secure_zeroize_48(ms);
    } else {
        return false;
    }

    let ok_c = derive_secret(
        ks.hash_id,
        ks.hash_len,
        ks.current_secret[..ks.hash_len],
        "c ap traffic",
        transcript_hash,
        ks.client_ap_traffic[..ks.hash_len],
    );
    let ok_s = derive_secret(
        ks.hash_id,
        ks.hash_len,
        ks.current_secret[..ks.hash_len],
        "s ap traffic",
        transcript_hash,
        ks.server_ap_traffic[..ks.hash_len],
    );
    let ok_exp = derive_secret(
        ks.hash_id,
        ks.hash_len,
        ks.current_secret[..ks.hash_len],
        "exp master",
        transcript_hash,
        ks.exporter_secret[..ks.hash_len],
    );
    guard ok_c && ok_s && ok_exp else { return false; }
    ks.stage = KS_STAGE_MASTER;
    committed = true;
    return true;
}

// Resumption Master Secret = Derive-Secret(Master Secret, "res master", ClientHello...server Finished)
fn ks_advance_to_resumption(ks: KeySchedule&, finished_transcript_hash: const u8[:]) -> bool {
    guard ks.stage == KS_STAGE_MASTER else { return false; }
    guard finished_transcript_hash.len == ks.hash_len else { return false; }

    let ok = derive_secret(
        ks.hash_id,
        ks.hash_len,
        ks.current_secret[..ks.hash_len],
        "res master",
        finished_transcript_hash,
        ks.resumption_secret[..ks.hash_len],
    );
    if ok {
        ks.stage = KS_STAGE_RESUMPTION;
    }
    return ok;
}

// Exports key material according to RFC 8446 Section 7.5 (TLS-Exporter).
// TLS-Exporter(label, context_value, key_length) =
//     HKDF-Expand-Label(Derive-Secret(Secret, label, ""),
//                       "exporter", Hash(context_value), key_length)
// Arbitrary-length context_value is hashed via SHA-256/SHA-384 before entering HkdfLabel (RFC 8446 §7.5).
// When context is empty (""), Hash("") is used.
fn ks_export_keying_material(
    ks:         const KeySchedule&,
    label:      const u8[:],
    context:    const u8[:],
    key_length: u16,
    out:        u8[:],
) -> bool {
    guard ks.stage >= KS_STAGE_MASTER else { return false; }
    guard label.len > 0 && label.len <= 245 else { return false; }
    guard key_length > 0 else { return false; }
    guard out.len >= key_length else { return false; }

    var intermediate: u8[48] = [0; 48];
    defer core::secure_zeroize_48(intermediate);
    if !derive_secret(
        ks.hash_id,
        ks.hash_len,
        ks.exporter_secret[..ks.hash_len],
        label,
        [],
        intermediate[..ks.hash_len],
    ) {
        return false;
    }

    var ctx_hash: u8[48] = [0; 48];
    defer core::secure_zeroize_48(ctx_hash);
    if ks.hash_id == HASH_SHA256 {
        let h = core::sha256(context);
        for i in 32 { ctx_hash[i] = h[i]; }
    } else if ks.hash_id == HASH_SHA384 {
        let h = core::sha384(context);
        for i in 48 { ctx_hash[i] = h[i]; }
    } else {
        return false;
    }

    return hkdf_expand_label(
        ks.hash_id,
        intermediate[..ks.hash_len],
        "exporter",
        ctx_hash[..ks.hash_len],
        key_length,
        out,
    );
}

// Derives the resumption PSK for a NewSessionTicket from resumption_master_secret
// and ticket_nonce (RFC 8446 §4.6.1).
// PSK = HKDF-Expand-Label(resumption_master_secret, "resumption", ticket_nonce, Hash.length)
fn ks_derive_resumption_psk(
    ks:           const KeySchedule&,
    ticket_nonce: const u8[:],
    out_psk:      u8[:],
) -> bool {
    guard ks.stage == KS_STAGE_RESUMPTION else { return false; }
    guard ticket_nonce.len <= 255 else { return false; }
    guard out_psk.len >= ks.hash_len else { return false; }
    return hkdf_expand_label(
        ks.hash_id,
        ks.resumption_secret[..ks.hash_len],
        "resumption",
        ticket_nonce,
        ks.hash_len,
        out_psk,
    );
}

// Derives symmetric AEAD key and 12-byte IV from traffic secret (RFC 8446 Section 7.3).
fn ks_derive_key_iv(
    hash_id: u8,
    secret:  const u8[:],
    key_len: u16,
    out_key: u8[:],
    out_iv:  u8[12]&,
) -> bool {
    let ok_k = hkdf_expand_label(hash_id, secret, "key", [], key_len, out_key);
    let ok_iv = hkdf_expand_label(hash_id, secret, "iv", [], 12, out_iv[..]);
    return ok_k && ok_iv;
}

// Derives QUIC Header Protection key (RFC 9001 Section 5.4).
// `version` selects the label prefix: "quic hp" for v1, "quicv2 hp" for v2
// (RFC 9369 §3.3.2). Unknown versions yield an empty prefix and fail closed.
fn ks_derive_quic_hp_key(
    hash_id:    u8,
    secret:     const u8[:],
    hp_key_len: u16,
    out_hp_key: u8[:],
    version:    u32 = rfc::QUIC_VERSION_1,
) -> bool {
    let prefix = rfc::quic_hkdf_label_prefix(version);
    guard prefix.len > 0 else { return false; }
    var lbl: u8[..16] = [];
    lbl.append(prefix);
    lbl.append("hp");
    return hkdf_expand_label(hash_id, secret, lbl[..], [], hp_key_len, out_hp_key);
}

// Computes Finished verify_data = HMAC(finished_key, Transcript-Hash) (RFC 8446 Section 4.4.4).
fn ks_compute_finished_verify_data(
    hash_id:         u8,
    hash_len:        u8,
    base_key:        const u8[:],
    transcript_hash: const u8[:],
    out_verify_data: u8[:],
) -> bool {
    guard (hash_id == HASH_SHA256 && hash_len == 32) || (hash_id == HASH_SHA384 && hash_len == 48) else {
        return false;
    }
    guard out_verify_data.len >= hash_len else { return false; }
    guard base_key.len >= hash_len else { return false; }
    guard transcript_hash.len == hash_len else { return false; }

    var finished_key: u8[48] = [0; 48];
    defer core::secure_zeroize_48(finished_key);
    if !hkdf_expand_label(hash_id, base_key, "finished", [], hash_len, finished_key[..hash_len]) {
        return false;
    }

    if hash_id == HASH_SHA256 {
        var vd = core::hmac_sha256(finished_key[..32], transcript_hash);
        for i in 32 { out_verify_data[i] = vd[i]; }
        core::secure_zeroize_32(vd);
        return true;
    } else if hash_id == HASH_SHA384 {
        var vd = core::hmac_sha384(finished_key[..48], transcript_hash);
        for i in 48 { out_verify_data[i] = vd[i]; }
        core::secure_zeroize_48(vd);
        return true;
    }
    return false;
}

// Updates application traffic secret:
// next_secret = HKDF-Expand-Label(current, "traffic upd", "", Hash.length) (RFC 8446 §7.2).
fn ks_update_traffic_secret(hash_id: u8, hash_len: u8, traffic_secret: u8[:]) -> bool {
    guard (hash_id == HASH_SHA256 && hash_len == 32) || (hash_id == HASH_SHA384 && hash_len == 48) else {
        return false;
    }
    guard traffic_secret.len >= hash_len else { return false; }
    var next_secret: u8[48] = [0; 48];
    defer core::secure_zeroize_48(next_secret);
    if !hkdf_expand_label(
        hash_id,
        traffic_secret[..hash_len],
        "traffic upd",
        [],
        hash_len,
        next_secret[..hash_len],
    ) {
        return false;
    }
    for i in hash_len {
        traffic_secret[i] = next_secret[i];
    }
    return true;
}

// Securely wipes all secrets from the KeySchedule.
fn ks_zeroize(ks: KeySchedule&) {
    core::secure_zeroize_48(ks.current_secret);
    core::secure_zeroize_48(ks.client_early_traffic);
    core::secure_zeroize_slice(ks.early_exporter_secret[..]);
    ks.early_exporter_secret.clear();
    core::secure_zeroize_48(ks.client_hs_traffic);
    core::secure_zeroize_48(ks.server_hs_traffic);
    core::secure_zeroize_48(ks.client_ap_traffic);
    core::secure_zeroize_48(ks.server_ap_traffic);
    core::secure_zeroize_48(ks.exporter_secret);
    core::secure_zeroize_48(ks.resumption_secret);
    core::secure_zeroize_48(ks.binder_key);
    ks.stage = KS_STAGE_UNINIT;
}

// ---- PSK Binders Verification (RFC 8446 Section 4.2.11.2) ----------------

// Verifies PSK binder tag against a pre-computed truncated ClientHello transcript hash.
fn verify_psk_binder_hash(
    hash_id:         u8,
    hash_len:        u8,
    binder_key:      const u8[:],
    ch_hash:         const u8[:],
    expected_binder: const u8[:],
) -> bool {
    guard (hash_id == HASH_SHA256 && hash_len == 32) || (hash_id == HASH_SHA384 && hash_len == 48) else {
        return false;
    }
    guard expected_binder.len == hash_len else { return false; }
    guard binder_key.len >= hash_len else { return false; }
    guard ch_hash.len == hash_len else { return false; }

    var finished_key: u8[48] = [0; 48];
    defer core::secure_zeroize_48(finished_key);
    if !hkdf_expand_label(hash_id, binder_key, "finished", [], hash_len, finished_key[..hash_len]) {
        return false;
    }

    if hash_id == HASH_SHA256 {
        var calc_binder = core::hmac_sha256(finished_key[..32], ch_hash);
        defer core::secure_zeroize_32(calc_binder);
        var exp: u8[32] = [0; 32];
        for i in 32 { exp[i] = expected_binder[i]; }
        return core::ct_eq_tag32(calc_binder, exp);
    }
    var calc_binder = core::hmac_sha384(finished_key[..48], ch_hash);
    defer core::secure_zeroize_48(calc_binder);
    var exp: u8[48] = [0; 48];
    for i in 48 { exp[i] = expected_binder[i]; }
    return core::ct_eq_tag48(calc_binder, exp);
}

// Verifies PSK binder tag on truncated ClientHello in constant time.
fn verify_psk_binder(
    hash_id:         u8,
    hash_len:        u8,
    binder_key:      const u8[:],
    truncated_ch:    const u8[:],
    expected_binder: const u8[:],
) -> bool {
    guard truncated_ch.len > 0 else { return false; }
    if hash_id == HASH_SHA256 && hash_len == 32 {
        let ch_hash = core::sha256(truncated_ch);
        return verify_psk_binder_hash(hash_id, hash_len, binder_key, ch_hash[..], expected_binder);
    }
    if hash_id == HASH_SHA384 && hash_len == 48 {
        let ch_hash = core::sha384(truncated_ch);
        return verify_psk_binder_hash(hash_id, hash_len, binder_key, ch_hash[..], expected_binder);
    }
    return false;
}

// ---- ZeroRttStrikeRegister: Two-Epoch Bloom Filter Anti-Replay -----------

struct ZeroRttStrikeRegister {
    epoch_window_ms:      i64     = 10000,
    max_age_tolerance_ms: i64     = 2000,
    current_epoch:        i64     = 0,
    bitmap_current:       u64[64] = [0; 64],
    bitmap_previous:      u64[64] = [0; 64],
    hash_key:             u8[32]  = [0; 32],
    keyed:                bool    = false,
}

fn strike_register_init(epoch_window_ms: i64 = 10000, max_age_tolerance_ms: i64 = 2000) -> ZeroRttStrikeRegister {
    var reg = ZeroRttStrikeRegister {
        epoch_window_ms:      epoch_window_ms,
        max_age_tolerance_ms: max_age_tolerance_ms,
        current_epoch:        0,
        bitmap_current:       [0; 64],
        bitmap_previous:      [0; 64],
        hash_key:             [0; 32],
        keyed:                false,
    };
    reg.keyed = core::csprng_fill(reg.hash_key[..]);
    return reg;
}

// Computes k=4 independent 12-bit Bloom indices via per-instance keyed HMAC-SHA256
// to prevent algorithmic complexity saturation attacks (RFC 8446 Section 8.2).
inline fn strike_reg_hash_bits(hash_key: const u8[32]&, data: const u8[:]) -> u32[4] {
    let mac = core::hmac_sha256(hash_key[..], data);
    var bits: u32[4] = [0; 4];
    for i in 4 {
        let off = core::add_sat_i64(i, i);
        bits[i] = (core::read_be_u16(mac[..], off) as u32) & 4095;
    }
    return bits;
}

// Rotates epoch bitmaps when epoch_window_ms has elapsed.
fn strike_register_rotate(reg: ZeroRttStrikeRegister&, now_ms: i64) {
    if reg.epoch_window_ms <= 0 { return; }
    let epoch = now_ms / reg.epoch_window_ms;
    if epoch > reg.current_epoch {
        if epoch == reg.current_epoch + 1 {
            for i in 64 {
                reg.bitmap_previous[i] = reg.bitmap_current[i];
                reg.bitmap_current[i] = 0;
            }
        } else {
            for i in 64 {
                reg.bitmap_previous[i] = 0;
                reg.bitmap_current[i] = 0;
            }
        }
        reg.current_epoch = epoch;
    }
}

fn strike_register_insert_bits(bitmap: u64[64]&, bits: const u32[4]&) {
    for i in 4 {
        let bit = bits[i];
        let word_idx = ((bit >> 6) & 63) as i64;
        let bit_mask: u64 = (1 as u64) << (bit & 63);
        bitmap[word_idx] |= bit_mask;
    }
}

// Checks if ticket_id was already accepted; if not, registers it and returns true.
// Returns false on replay detection, invalid arguments, CSPRNG failure, or backward clock skew.
fn strike_register_check_and_insert(reg: ZeroRttStrikeRegister&, ticket_id: const u8[:], now_ms: i64) -> bool {
    guard now_ms >= 0 && ticket_id.len > 0 && reg.epoch_window_ms > 0 else { return false; }
    if !reg.keyed {
        guard core::csprng_fill(reg.hash_key[..]) else { return false; }
        reg.keyed = true;
    }

    let epoch = now_ms / reg.epoch_window_ms;
    guard epoch >= reg.current_epoch - 1 else { return false; }

    strike_register_rotate(reg, now_ms);

    let bits = strike_reg_hash_bits(reg.hash_key, ticket_id);
    var in_current = true;
    var in_previous = true;

    for i in 4 {
        let bit = bits[i];
        let word_idx = ((bit >> 6) & 63) as i64;
        let bit_mask: u64 = (1 as u64) << (bit & 63);

        if (reg.bitmap_current[word_idx] & bit_mask) == 0 {
            in_current = false;
        }
        if (reg.bitmap_previous[word_idx] & bit_mask) == 0 {
            in_previous = false;
        }
    }

    if in_current || in_previous {
        return false;
    }

    if epoch == reg.current_epoch - 1 {
        strike_register_insert_bits(reg.bitmap_previous, bits);
    }
    strike_register_insert_bits(reg.bitmap_current, bits);

    return true;
}

// Validates ticket age freshness according to RFC 8446 Section 4.2.10 and 4.6.1.
inline fn validate_ticket_age(
    obfuscated_ticket_age: u32,
    ticket_age_add:        u32,
    expected_age_ms:       i64,
    tolerance_ms:          i64,
) -> bool {
    guard expected_age_ms >= 0 && tolerance_ms >= 0 else { return false; }
    guard expected_age_ms <= rfc::MAX_TICKET_LIFETIME_MS else { return false; }

    // RFC 8446 Section 4.2.11.1: ticket age is obfuscated via wrapping addition mod 2^32.
    // Unobfuscation performs wrapping unsigned subtraction mod 2^32.
    let raw_age_u32: u32 = obfuscated_ticket_age - ticket_age_add;
    let raw_age = raw_age_u32 as i64;
    guard raw_age <= rfc::MAX_TICKET_LIFETIME_MS else { return false; }

    let diff = if raw_age > expected_age_ms {
        raw_age - expected_age_ms
    } else {
        expected_age_ms - raw_age
    };
    return diff <= tolerance_ms;
}

// Truncates ClientHello to exclude the PSK binders list for binder computation (RFC 8446 §4.2.11.2).
// The PSK extension is the last extension in ClientHello. The binders list starts with a 2-byte
// vector length field followed by binders_len bytes.
// Returns the truncated ClientHello slice and true on success, or empty slice and false on error.
inline fn truncate_client_hello_for_binder(client_hello: const u8[:], binders_len: u16) -> const u8[:], bool {
    let binders_overhead = 2 + (binders_len as i64);
    guard binders_len > 0 else { return client_hello[..0], false; }
    guard client_hello.len > binders_overhead else { return client_hello[..0], false; }
    let truncated_len = client_hello.len - binders_overhead;
    return client_hello[..truncated_len], true;
}

// Validates that the number of PSK identities equals the number of PSK binders (RFC 8446 §4.2.11).
// "The identities and binders lists MUST have the same number of elements;
// if they do not, the server MUST terminate the handshake with an illegal_parameter alert."
inline fn validate_psk_identities_and_binders_count(identities_count: i64, binders_count: i64) -> bool {
    guard identities_count > 0 && binders_count > 0 else { return false; }
    return identities_count == binders_count;
}
