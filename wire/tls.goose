// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Zero-allocation TLS 1.3 key schedule and stateful record framing facade (RFC 8446).
namespace wire;

import std;
import core from "..";
import rfc.tls;
import tls.key_schedule;
import tls.record;

// RFC 8446 Section 5.2: 5-byte record header + 1-byte inner content type + 16-byte AEAD tag.
const TLS13_RECORD_OVERHEAD_LEN: i64 = rfc::TLS_RECORD_HEADER_LEN + 1 + rfc::TLS_AEAD_TAG_LEN;
// RFC 8446 Section 5.2: Minimum TLSCiphertext.encrypted_record length (1-byte type + 16-byte tag).
const TLS13_MIN_CIPHERTEXT_PAYLOAD: i64 = rfc::TLS_AEAD_TAG_LEN + 1;

// Directional TLS 1.3 AEAD record protection state (RFC 8446 Sections 5.2-5.3, 7.3).
struct WireTlsRecordState {
    cipher_suite: u16    = 0,
    hash_id:      u8     = 0,
    hash_len:     u8     = 0,
    key_len:      u16    = 0,
    secret:       u8[48] = [0; 48],
    key:          u8[32] = [0; 32],
    iv:           u8[12] = [0; 12],
    seq_num:      u64    = 0,
    active:       bool   = false,
}

// Bidirectional TLS 1.3 client/server traffic secrets and derived AEAD record states.
struct WireTlsTrafficKeys {
    cipher_suite:    u16                = 0,
    hash_id:         u8                 = 0,
    hash_len:        u8                 = 0,
    client:          WireTlsRecordState = WireTlsRecordState {},
    server:          WireTlsRecordState = WireTlsRecordState {},
    exporter_secret: u8[48]             = [0; 48],
}

// Securely wipes secret, key, and IV material in `state` and marks it inactive.
fn zeroize_tls_record_state(state: WireTlsRecordState&) {
    core::secure_zeroize_48(state.secret);
    core::secure_zeroize_32(state.key);
    core::secure_zeroize_slice(state.iv[..]);
    state.seq_num = 0;
    state.key_len = 0;
    state.hash_id = 0;
    state.hash_len = 0;
    state.cipher_suite = 0;
    state.active = false;
}

// Securely wipes both client and server record states and the exporter secret in `keys`.
fn zeroize_tls_traffic_keys(keys: WireTlsTrafficKeys&) {
    zeroize_tls_record_state(keys.client);
    zeroize_tls_record_state(keys.server);
    core::secure_zeroize_48(keys.exporter_secret);
    keys.cipher_suite = 0;
    keys.hash_id = 0;
    keys.hash_len = 0;
}

// Initializes a directional TLS 1.3 AEAD record state from a raw traffic secret
// using HKDF-Expand-Label("key" / "iv") (RFC 8446 Section 7.3).
//
// Example:
//   let st, ok = wire::init_tls13_record_state(rfc::TLS_CIPHER_AES_128_GCM_SHA256, secret[..32]);
//   returns: initialized WireTlsRecordState with seq_num = 0, ok = true
fn init_tls13_record_state(cipher_suite: u16, traffic_secret: const u8[:]) -> WireTlsRecordState, bool {
    var st = WireTlsRecordState {};
    var committed = false;
    defer if !committed { zeroize_tls_record_state(st); };

    let ks, ok_ks = internal::ks_init(cipher_suite);
    guard ok_ks else { return st, false; }

    let key_len = rfc::tls13_cipher_suite_key_len(cipher_suite);
    guard key_len > 0 && (key_len as i64) <= 32 else { return st, false; }
    guard traffic_secret.len == ks.hash_len else { return st, false; }

    st.cipher_suite = cipher_suite;
    st.hash_id = ks.hash_id;
    st.hash_len = ks.hash_len;
    st.key_len = key_len;
    for i in ks.hash_len {
        st.secret[i] = traffic_secret[i];
    }
    guard internal::ks_derive_key_iv(
        st.hash_id,
        st.secret[..st.hash_len],
        st.key_len,
        st.key[..st.key_len],
        st.iv,
    ) else {
        return st, false;
    }

    st.seq_num = 0;
    st.active = true;
    committed = true;
    return st, true;
}

fn advance_ks_to_handshake(
    cipher_suite:          u16,
    ecdhe_shared_secret:   const u8[:],
    ch_sh_transcript_hash: const u8[:],
    psk:                   const u8[:],
) -> internal::KeySchedule, bool {
    var ks, ok_init = internal::ks_init(cipher_suite);
    guard ok_init else { return ks, false; }
    var committed = false;
    defer if !committed { internal::ks_zeroize(ks); };

    guard internal::ks_init_early_secret(ks, psk) else { return ks, false; }
    guard internal::ks_advance_to_handshake(ks, ecdhe_shared_secret) else { return ks, false; }
    guard internal::ks_derive_handshake_traffic(ks, ch_sh_transcript_hash) else {
        return ks, false;
    }
    committed = true;
    return ks, true;
}

// Derives TLS 1.3 client and server handshake record states from the ECDHE shared
// secret and ClientHello..ServerHello transcript hash (RFC 8446 Section 7.1).
//
// Example:
//   let hs, ok = wire::derive_tls13_handshake_keys(cs, shared, ch_sh_hash);
//   returns: hs.client and hs.server ready for handshake record protection, ok = true
fn derive_tls13_handshake_keys(
    cipher_suite:          u16,
    ecdhe_shared_secret:   const u8[:],
    ch_sh_transcript_hash: const u8[:],
    psk:                   const u8[:] = [],
) -> WireTlsTrafficKeys, bool {
    var keys = WireTlsTrafficKeys {};
    var committed = false;
    defer if !committed { zeroize_tls_traffic_keys(keys); };

    var ks, ok_ks = advance_ks_to_handshake(
        cipher_suite,
        ecdhe_shared_secret,
        ch_sh_transcript_hash,
        psk,
    );
    defer internal::ks_zeroize(ks);
    guard ok_ks else { return keys, false; }

    let cl, ok_c = init_tls13_record_state(cipher_suite, ks.client_hs_traffic[..ks.hash_len]);
    guard ok_c else { return keys, false; }
    let sv, ok_s = init_tls13_record_state(cipher_suite, ks.server_hs_traffic[..ks.hash_len]);
    guard ok_s else { return keys, false; }

    keys.cipher_suite = cipher_suite;
    keys.hash_id = ks.hash_id;
    keys.hash_len = ks.hash_len;
    keys.client = cl;
    keys.server = sv;
    committed = true;
    return keys, true;
}

// Derives TLS 1.3 client and server application traffic record states and the
// exporter master secret from handshake inputs and the ServerHello..ServerFinished
// transcript hash (RFC 8446 Section 7.1).
//
// Example:
//   let app, ok = wire::derive_tls13_app_keys(cs, shared, ch_sh_hash, ch_sf_hash);
//   returns: app.client and app.server ready for application records, ok = true
fn derive_tls13_app_keys(
    cipher_suite:          u16,
    ecdhe_shared_secret:   const u8[:],
    ch_sh_transcript_hash: const u8[:],
    ch_sf_transcript_hash: const u8[:],
    psk:                   const u8[:] = [],
) -> WireTlsTrafficKeys, bool {
    var keys = WireTlsTrafficKeys {};
    var committed = false;
    defer if !committed { zeroize_tls_traffic_keys(keys); };

    var ks, ok_ks = advance_ks_to_handshake(
        cipher_suite,
        ecdhe_shared_secret,
        ch_sh_transcript_hash,
        psk,
    );
    defer internal::ks_zeroize(ks);
    guard ok_ks else { return keys, false; }
    guard internal::ks_advance_to_master(ks, ch_sf_transcript_hash) else {
        return keys, false;
    }

    let cl, ok_c = init_tls13_record_state(cipher_suite, ks.client_ap_traffic[..ks.hash_len]);
    guard ok_c else { return keys, false; }
    let sv, ok_s = init_tls13_record_state(cipher_suite, ks.server_ap_traffic[..ks.hash_len]);
    guard ok_s else { return keys, false; }

    keys.cipher_suite = cipher_suite;
    keys.hash_id = ks.hash_id;
    keys.hash_len = ks.hash_len;
    keys.client = cl;
    keys.server = sv;
    for i in ks.hash_len {
        keys.exporter_secret[i] = ks.exporter_secret[i];
    }
    committed = true;
    return keys, true;
}

// Computes TLS 1.3 Finished verify_data = HMAC(finished_key, transcript_hash)
// from a directional handshake record state (RFC 8446 Section 4.4.4).
//
// Example:
//   let verify_data, ok = wire::compute_tls13_finished_verify_data(hs.server, ch_cv_hash);
//   returns: 32 or 48 byte verify_data buffer, ok = true
fn compute_tls13_finished_verify_data(
    state:           const WireTlsRecordState&,
    transcript_hash: const u8[:],
) -> u8[..48], bool {
    var out_verify: u8[..48] = [];
    guard state.active else { return out_verify, false; }
    guard state.hash_len == 32 || state.hash_len == 48 else { return out_verify, false; }
    out_verify.resize(state.hash_len as i64, 0);
    guard internal::ks_compute_finished_verify_data(
        state.hash_id,
        state.hash_len,
        state.secret[..state.hash_len],
        transcript_hash,
        out_verify[..],
    ) else {
        core::secure_zeroize_slice(out_verify[..]);
        out_verify.clear();
        return out_verify, false;
    }
    return out_verify, true;
}

// Advances a directional TLS 1.3 application traffic state via KeyUpdate
// (`traffic upd` secret expansion, key/iv re-derivation, and seq_num = 0)
// (RFC 8446 Sections 4.6.3, 7.2). Rolls back to previous state on error.
//
// Example:
//   let ok = wire::update_tls13_traffic_keys(app.client);
//   returns: true with updated secret/key/iv and seq_num = 0
fn update_tls13_traffic_keys(state: WireTlsRecordState&) -> bool {
    guard state.active else { return false; }
    guard state.key_len > 0 && (state.key_len as i64) <= 32 else { return false; }
    guard state.hash_len == 32 || state.hash_len == 48 else { return false; }

    var saved = state;
    var committed = false;
    defer {
        if !committed {
            state = saved;
        }
        zeroize_tls_record_state(saved);
    };

    guard internal::ks_update_traffic_secret(
        state.hash_id,
        state.hash_len,
        state.secret[..state.hash_len],
    ) else {
        return false;
    }
    guard internal::ks_derive_key_iv(
        state.hash_id,
        state.secret[..state.hash_len],
        state.key_len,
        state.key[..state.key_len],
        state.iv,
    ) else {
        return false;
    }
    state.seq_num = 0;
    committed = true;
    return true;
}

// Encrypts a TLS 1.3 TLSCiphertext record into `out`, managing the sequence-number
// nonce and incrementing `state.seq_num` on success. Rolls back `out` and
// `state.seq_num` cleanly on error (RFC 8446 Sections 5.2-5.3).
//
// Example:
//   let alert, ok = wire::seal_tls13_record(app.client, rfc::TLS_CONTENT_APPLICATION_DATA, "ping", out);
//   returns: alert = TlsAlert.CloseNotify, ok = true; increments app.client.seq_num
fn seal_tls13_record<B>(
    state:      WireTlsRecordState&,
    inner_type: u8,
    plaintext:  const u8[:],
    out:        B&,
) -> wing::TlsAlert, bool {
    guard state.active else { return wing::TlsAlert.InternalError, false; }
    guard state.key_len > 0 && (state.key_len as i64) <= 32 else {
        return wing::TlsAlert.InternalError, false;
    }
    guard plaintext.len >= 0 && plaintext.len <= rfc::TLS_MAX_RECORD_PLAINTEXT_LEN else {
        return wing::TlsAlert.RecordOverflow, false;
    }
    // RFC 8446 Section 5.4: Record Padding - zero-length handshake or alert records MUST NOT be sent.
    guard plaintext.len > 0 || inner_type == rfc::TLS_CONTENT_APPLICATION_DATA else {
        return wing::TlsAlert.UnexpectedMessage, false;
    }

    let start_len = out.len;
    let saved_seq = state.seq_num;
    var committed = false;
    defer if !committed {
        out.resize(start_len);
        state.seq_num = saved_seq;
    };

    let needed = core::add_sat_i64(plaintext.len, TLS13_RECORD_OVERHEAD_LEN);
    var rec_buf: u8[16406] = [0; 16406];
    let written, alert, ok_seal = wing::tls_record_seal_into(
        state.cipher_suite,
        state.key[..state.key_len],
        state.iv,
        state.seq_num,
        inner_type,
        plaintext,
        rec_buf[..needed],
    );
    guard ok_seal else { return alert, false; }
    guard out.try_append(rec_buf[..written]) else { return wing::TlsAlert.InternalError, false; }
    guard wing::increment_record_seq_num(state.seq_num) else {
        return wing::TlsAlert.UnexpectedMessage, false;
    }

    committed = true;
    return wing::TlsAlert.CloseNotify, true;
}

// Parses and decrypts one TLS 1.3 TLSCiphertext record at `raw[cursor..]`, appending
// the decrypted plaintext to `out` and advancing `cursor` and `state.seq_num`.
// Rolls back `cursor`, `out`, and `state.seq_num` on any failure (RFC 8446 Section 5.2).
//
// Example:
//   var cur: i64 = 0;
//   let inner_type, alert, ok = wire::open_tls13_record_at(app.server, raw, cur, pt_out);
//   returns: inner_type = 0x17, alert = TlsAlert.CloseNotify, ok = true
fn open_tls13_record_at<B>(
    state:  WireTlsRecordState&,
    raw:    const u8[:],
    cursor: i64&,
    out:    B&,
) -> u8, wing::TlsAlert, bool {
    guard state.active else { return 0, wing::TlsAlert.InternalError, false; }
    guard state.key_len > 0 && (state.key_len as i64) <= 32 else {
        return 0, wing::TlsAlert.InternalError, false;
    }

    let saved_cursor = cursor;
    let saved_seq = state.seq_num;
    let start_len = out.len;
    var committed = false;
    defer if !committed {
        cursor = saved_cursor;
        state.seq_num = saved_seq;
        out.resize(start_len);
    };

    let rec_type, _ver, rec_len, hdr_alert, ok_hdr = wing::parse_tls_record_header_at(raw, cursor);
    guard ok_hdr else { return 0, hdr_alert, false; }
    guard rec_type == rfc::TLS_CONTENT_APPLICATION_DATA else {
        return 0, wing::TlsAlert.UnexpectedMessage, false;
    }

    let payload_len = rec_len as i64;
    guard payload_len >= TLS13_MIN_CIPHERTEXT_PAYLOAD &&
          payload_len <= rfc::TLS_MAX_RECORD_CIPHERTEXT_LEN else {
        return 0, wing::TlsAlert.DecodeError, false;
    }
    let payload_end = core::add_sat_i64(cursor, payload_len);
    guard payload_end <= raw.len else {
        return 0, wing::TlsAlert.DecodeError, false;
    }

    let hdr_end = core::add_sat_i64(saved_cursor, rfc::TLS_RECORD_HEADER_LEN);
    let hdr_slice = raw[saved_cursor..hdr_end];
    let payload_slice = raw[cursor..payload_end];
    cursor = payload_end;

    let ct_len = core::sub_sat_i64(payload_len, rfc::TLS_AEAD_TAG_LEN);
    var pt_buf: u8[16624] = [0; 16624];
    defer core::secure_zeroize_slice(pt_buf[..ct_len]);

    let pt_len, inner_type, dec_alert, ok_dec = wing::tls_record_decrypt_into(
        state.cipher_suite,
        state.key[..state.key_len],
        state.iv,
        state.seq_num,
        hdr_slice,
        payload_slice,
        pt_buf[..ct_len],
    );
    guard ok_dec else { return 0, dec_alert, false; }
    guard out.try_append(pt_buf[..pt_len]) else { return 0, wing::TlsAlert.InternalError, false; }
    guard wing::increment_record_seq_num(state.seq_num) else {
        return 0, wing::TlsAlert.UnexpectedMessage, false;
    }

    committed = true;
    return inner_type, wing::TlsAlert.CloseNotify, true;
}

// Decrypts a complete single TLS 1.3 TLSCiphertext record `record_bytes` into `out`,
// rejecting trailing bytes and rolling back `out` and `state.seq_num` on error.
//
// Example:
//   let inner_type, alert, ok = wire::open_tls13_record(app.server, record_bytes, pt_out);
//   returns: inner_type = 0x17, alert = TlsAlert.CloseNotify, ok = true
fn open_tls13_record<B>(
    state:        WireTlsRecordState&,
    record_bytes: const u8[:],
    out:          B&,
) -> u8, wing::TlsAlert, bool {
    var cursor: i64 = 0;
    let saved_seq = state.seq_num;
    let start_len = out.len;
    let inner_type, alert, ok = open_tls13_record_at(state, record_bytes, cursor, out);
    guard ok else { return 0, alert, false; }
    guard cursor == record_bytes.len else {
        state.seq_num = saved_seq;
        out.resize(start_len);
        return 0, wing::TlsAlert.DecodeError, false;
    }
    return inner_type, alert, true;
}
