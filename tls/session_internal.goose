// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal TLS 1.3 session locks, CSPRNG, socket I/O, handshake framing, and revocation checks.
namespace tls_internal;

import std;
import core;
import .internal;
import .record;
import .record_internal;
import .key_schedule;
import .handshake;
import .handshake_internal;
import .asn1;
import .types;
import .sct;
import .x509;
import .pem;
import .ocsp;
import .crl;
import .ticket;
import .ticket_internal;
import .pq_ntt_internal;
import .pq_mlkem_internal;
import .cert_compression;
import .ech;
import .pki_sig_internal;
import .pki_x509_ext_internal;
import .pki_nc_san_internal;
import .pki_ocsp_internal;
import .pki_crl_internal;
import net.tcp;
import net.transport;
import .handshake_wire_internal;
import .session_wire_internal;

const TLS_LOCK_CIPHER_SLOTS: i32 = 0;

const TLS_LOCK_ENTROPY_POOL: i32 = 1;

const TLS_LOCK_TICKET_CACHE: i32 = 2;

extern fn native_tls_state_lock(lock_id: i32) = "wing_tls_state_lock";

extern fn native_tls_state_unlock(lock_id: i32) = "wing_tls_state_unlock";

extern fn raw_tls_csprng_bytes(out: u8[:]) -> i32 = "wing_crypto_random_bytes";

var g_tls_sim_last_epoch: u64 = 0;

var g_tls_csprng_fault_for_test: bool = false;

// Enables or disables simulated OS CSPRNG failure for fail-closed tests.
fn tls_set_csprng_fault_for_test(enabled: bool) {
    native_tls_state_lock(TLS_LOCK_ENTROPY_POOL);
    defer native_tls_state_unlock(TLS_LOCK_ENTROPY_POOL);
    g_tls_csprng_fault_for_test = enabled;
}

// Fills `out` from deterministic simulation entropy when active, or OS CSPRNG otherwise.
fn native_tls_csprng_bytes(out: u8[:]) -> i32 {
    if core::sim_rng_is_active() {
        let epoch = core::sim_rng_epoch();
        if g_tls_sim_last_epoch != epoch {
            g_tls_sim_last_epoch = epoch;
            core::secure_zeroize_32(tls::g_tls_entropy_pool);
            tls::g_tls_entropy_counter = 0;
        }
        let _ = core::sim_rng_fill(out);
        return 0;
    }
    if g_tls_csprng_fault_for_test {
        core::secure_zeroize_slice(out);
        return -1;
    }
    return raw_tls_csprng_bytes(out);
}

// Wipes all cryptographic keys, IVs, traffic secrets, ticket cache material, and buffered
// plaintext in `slot` and resets metadata fields to inactive defaults (Invariant 11).
fn wipe_and_reset_tls_cipher_slot(slot: tls::CipherSlot&) {
    core::secure_zeroize_32(slot.rx_key);
    core::secure_zeroize_32(slot.tx_key);
    core::zeroize_aes_gcm_key(slot.rx_aes_key);
    core::zeroize_aes_gcm_key(slot.tx_aes_key);
    core::secure_zeroize_slice(slot.rx_iv[..]);
    core::secure_zeroize_slice(slot.tx_iv[..]);
    core::secure_zeroize_48(slot.rx_traffic_secret);
    core::secure_zeroize_48(slot.tx_traffic_secret);
    core::secure_zeroize_48(slot.exporter_secret);
    core::secure_zeroize_48(slot.resumption_secret);
    core::secure_zeroize_slice(slot.rx_plain_buf[..]);
    for &t in slot.ticket_cache.tickets {
        core::secure_zeroize_slice(t.ticket_nonce[..]);
        core::secure_zeroize_slice(t.ticket[..]);
    }
    slot.in_use = false;
    slot.is_server = false;
    slot.ktls_tx_active = false;
    slot.ktls_rx_active = false;
    slot.cipher_suite = 0;
    slot.hash_id = 1;
    slot.hash_len = 32;
    slot.key_len = 16;
    slot.rx_seq = 0;
    slot.tx_seq = 0;
    slot.peer_closed = false;
    slot.resumed = false;
    slot.enable_session_tickets = true;
    slot.negotiated_alpn.clear();
    slot.server_name.clear();
    slot.san_hosts.clear();
    slot.rx_plain_buf.clear();
    slot.rx_plain_pos = 0;
    slot.bytes_sent = 0;
    slot.empty_app_records = 0;
    slot.warning_alerts = 0;
    slot.key_update_tracker = tls::KeyUpdateTracker { .. };
    slot.ticket_cache = tls::SessionTicketCache { .. };
}

inline fn peek_ciphertext_record_len(rem: const u8[:]) -> i64, tls::SliceUnsealStatus {
    if rem.len < rfc::TLS_RECORD_HEADER_LEN {
        return 0, tls::SliceUnsealStatus.NeedMore;
    }
    let ct, _, rec_len_u16, _, ok_hdr = tls::parse_record_header(rem[..rfc::TLS_RECORD_HEADER_LEN]);
    let rec_len = rec_len_u16 as i64;
    guard ok_hdr && ct == rfc::TLS_CONTENT_APPLICATION_DATA &&
        rec_len <= rfc::TLS_MAX_RECORD_CIPHERTEXT_LEN else {
        return 0, tls::SliceUnsealStatus.Error;
    }
    let total_rec = core::add_sat_i64(rfc::TLS_RECORD_HEADER_LEN, rec_len);
    if rem.len < total_rec {
        return 0, tls::SliceUnsealStatus.NeedMore;
    }
    return total_rec, tls::SliceUnsealStatus.Ok;
}

// Reads exactly dst.len bytes from socket, returning:
//    1 : full read succeeded
//    0 : clean EOF before any byte was read
//   -2 : timeout / WouldBlock before any byte was read
//   -1 : socket error or mid-record truncation
recursive fn tls_read_exact_status(fd: i64, dst: u8[:], timeout_ms: u32) -> i32 {
    guard fd > 0 && dst.len > 0 else { return -1; }
    var total_read: i64 = 0;
    while total_read < dst.len {
        let recvd = net::fd_recv(fd, dst[total_read..], timeout_ms);
        if recvd > 0 {
            total_read = core::add_sat_i64(total_read, recvd);
            continue;
        }
        if total_read == 0 && (recvd == 0 || recvd == -2) {
            return recvd;
        }
        return -1;
    }
    return 1;
}

// Reads exactly dst.len bytes from socket, returning false on error, timeout, or EOF before full read.
recursive fn tls_read_exact(fd: i64, dst: u8[:], timeout_ms: u32) -> bool {
    return tls_read_exact_status(fd, dst, timeout_ms) == 1;
}

// Writes entire data buffer to socket, retrying transient WouldBlock (-2) on non-blocking FDs.
recursive fn tls_write_all(fd: i64, data: const u8[:]) -> bool {
    guard fd > 0 && data.len > 0 else { return false; }
    var total_sent: i64 = 0;
    var retries:    i32 = 0;
    while total_sent < data.len {
        let sent = net::fd_send(fd, data[total_sent..]);
        if sent > 0 {
            total_sent = core::add_sat_i64(total_sent, sent);
            retries = 0;
            continue;
        }
        guard sent == -2 && retries < 2000 else { return false; }
        retries = core::add_sat_i64(retries, 1) as i32;
        if retries > 64 {
            sleep_ms(1);
        }
    }
    return true;
}

inline fn select_tls_outbound_chunk_len(rem: i64, bytes_sent: u64) -> i64, u64 {
    let max_rec_len = if bytes_sent < tls::DYNAMIC_RESIZE_THRESHOLD_BYTES {
        tls::SINGLE_MSS_PLAINTEXT_LEN
    } else {
        rfc::TLS_MAX_RECORD_PLAINTEXT_LEN
    };
    let chunk_len = min(rem, max_rec_len);
    let cur_i64 = (bytes_sent & 0x7FFFFFFFFFFFFFFF) as i64;
    let next_i64 = core::add_sat_i64(cur_i64, chunk_len);
    let next_bytes = (next_i64 & 0x7FFFFFFFFFFFFFFF) as u64;
    return chunk_len, next_bytes;
}

fn tls_drain_rx_buf(idx: i64, dst: u8[:]) -> i32 {
    guard idx >= 0 && idx < tls::g_tls_cipher_slots.len && tls::g_tls_cipher_slots[idx].in_use else { return 0; }
    let slot .= tls::g_tls_cipher_slots[idx];
    let rem_buf = core::sub_sat_i64(slot.rx_plain_buf.len, slot.rx_plain_pos);
    if rem_buf <= 0 { return 0; }
    let to_copy = min(rem_buf, dst.len);
    let start = tls::g_tls_cipher_slots[idx].rx_plain_pos;
    for i in to_copy {
        let src_idx = core::add_sat_i64(start, i);
        dst[i] = tls::g_tls_cipher_slots[idx].rx_plain_buf[src_idx];
    }
    tls::g_tls_cipher_slots[idx].rx_plain_pos = core::add_sat_i64(start, to_copy);
    if tls::g_tls_cipher_slots[idx].rx_plain_pos >= tls::g_tls_cipher_slots[idx].rx_plain_buf.len {
        core::secure_zeroize_slice(tls::g_tls_cipher_slots[idx].rx_plain_buf[..]);
        tls::g_tls_cipher_slots[idx].rx_plain_buf.clear();
        tls::g_tls_cipher_slots[idx].rx_plain_pos = 0;
    }
    return (to_copy & 0x7FFFFFFF) as i32;
}

fn try_read_handshake_msg<OutBuf>(
    r:            tls::HandshakeRecordReader&,
    msg_type:     u8&,
    out_msg_body: OutBuf&,
) -> bool {
    let remaining_plain = r.current_record_plain.len - r.current_offset;
    guard remaining_plain >= 4 else { return false; }
    let slice = r.current_record_plain[r.current_offset..];
    let mt, m_len, ok_hdr = tls::parse_handshake_header(slice);
    guard ok_hdr else { return false; }
    let total_len = 4 + (m_len as i64);
    guard remaining_plain >= total_len && out_msg_body.try_set(slice[4..total_len]) else { return false; }
    msg_type = mt;
    r.current_offset += total_len;
    return true;
}

fn compact_handshake_reader(r: tls::HandshakeRecordReader&) {
    let remaining_plain = core::sub_sat_i64(r.current_record_plain.len, r.current_offset);
    if remaining_plain > 0 && r.current_offset > 0 {
        var k: i64 = 0;
        while k < remaining_plain {
            let src_idx = core::add_sat_i64(r.current_offset, k);
            r.current_record_plain[k] = r.current_record_plain[src_idx];
            k = core::add_sat_i64(k, 1);
        }
        while r.current_record_plain.len > remaining_plain {
            r.current_record_plain.pop();
        }
    } else if remaining_plain <= 0 {
        r.current_record_plain.clear();
    }
    r.current_offset = 0;
}

// Sends a plaintext RFC 8446 Section 6.2 fatal alert before handshake keys are active.
fn send_plaintext_fatal_alert(fd: i64, alert: tls::Alert) {
    guard fd > 0 && alert != tls::Alert.CloseNotify else { return; }
    let rec: u8[7] = [
        rfc::TLS_CONTENT_ALERT,
        0x03,
        0x03,
        0x00,
        0x02,
        0x02,
        tls::alert_to_u8(alert),
    ];
    let _ = tls_write_all(fd, rec[..]);
}

// Seals and sends an encrypted RFC 8446 Section 6.2 fatal alert under handshake traffic keys.
fn send_hs_fatal_alert(
    fd:           i64,
    cipher_suite: u16,
    tx_key:       const u8[:],
    tx_iv:        const u8[12]&,
    alert:        tls::Alert,
) {
    guard fd > 0 && tx_key.len > 0 && alert != tls::Alert.CloseNotify else { return; }
    let alert_data: u8[2] = [2, tls::alert_to_u8(alert)];
    var rec_buf: u8[64] = [0; 64];
    let sealed_len, _, ok = tls::record_seal_into(
        cipher_suite, tx_key, tx_iv, 0, rfc::TLS_CONTENT_ALERT, alert_data[..], rec_buf[..],
    );
    if ok && sealed_len > 0 {
        let _ = tls_write_all(fd, rec_buf[..sealed_len]);
    }
}

fn unseal_hs_record_step(
    r:            tls::HandshakeRecordReader&,
    fd:           i64,
    cipher_suite: u16,
    key:          const u8[:],
    iv:           const u8[12]&,
    timeout_ms:   u32,
) -> bool {
    var hdr_buf: u8[5] = [0; 5];
    guard tls_read_exact(fd, hdr_buf[..], timeout_ms) else { return false; }

    let ct, ver, payload_len_u16, alert, ok_p = tls::parse_record_header(hdr_buf[..]);
    guard ok_p else { r.last_alert = alert; return false; }
    let payload_len = payload_len_u16 as i64;
    guard payload_len <= rfc::TLS_MAX_RECORD_CIPHERTEXT_LEN else {
        r.last_alert = tls::Alert.RecordOverflow;
        return false;
    }

    var ct_payload: u8[16640] = [0; 16640];
    guard tls_read_exact(fd, ct_payload[..payload_len], timeout_ms) else { return false; }

    if ct == rfc::TLS_CONTENT_CHANGE_CIPHER_SPEC {
        guard r.ccs_count < 1 &&
            r.current_offset == r.current_record_plain.len &&
            ver == rfc::TLS_LEGACY_VERSION_1_2 &&
            tls::validate_change_cipher_spec_record(ct_payload[..payload_len]) == tls::Alert.CloseNotify else {
            r.last_alert = tls::Alert.UnexpectedMessage;
            return false;
        }
        r.ccs_count = core::add_sat_u32(r.ccs_count, 1);
        return true;
    }
    guard ct == rfc::TLS_CONTENT_APPLICATION_DATA else {
        r.last_alert = tls::Alert.UnexpectedMessage;
        return false;
    }

    compact_handshake_reader(r);
    var plain_dec: u8[16640] = [0; 16640];
    defer core::secure_zeroize_slice(plain_dec[..payload_len]);
    let dec_len, inner_type, alert_dec, ok_dec = tls::record_decrypt_into(
        cipher_suite, key, iv, r.seq_num, hdr_buf[..], ct_payload[..payload_len], plain_dec[..payload_len],
    );
    guard ok_dec else { r.last_alert = alert_dec; return false; }
    guard inner_type == rfc::TLS_CONTENT_HANDSHAKE && dec_len > 0 else {
        r.last_alert = tls::Alert.UnexpectedMessage;
        return false;
    }
    tls::increment_record_seq_num(r.seq_num);
    guard r.current_record_plain.try_append(plain_dec[..dec_len]) else {
        r.last_alert = tls::Alert.DecodeError;
        return false;
    }
    return true;
}

// Reads the next encrypted handshake message from the TLS 1.3 handshake record stream.
// Records `r.last_alert` on protocol/decryption errors for RFC 8446 Section 6.2 alert reporting.
//
// Example:
//   r.current_record_plain = [0x08, 0x00, 0x00, 0x02, 0x00, 0x00], r.current_offset = 0
//   returns: true, msg_type = 8, out_msg_body = [0x00, 0x00]
fn next_handshake_message<OutBuf>(
    r:            tls::HandshakeRecordReader&,
    fd:           i64,
    cipher_suite: u16,
    key:          const u8[:],
    iv:           const u8[12]&,
    msg_type:     u8&,
    out_msg_body: OutBuf&,
    timeout_ms:   u32,
) -> bool {
    r.last_alert = tls::Alert.CloseNotify;
    loop {
        if try_read_handshake_msg(r, msg_type, out_msg_body) {
            return true;
        }
        guard unseal_hs_record_step(r, fd, cipher_suite, key, iv, timeout_ms) else {
            return false;
        }
    }
    return false;
}

// Sends a plaintext TLS record containing a handshake message (RFC 8446 §5.1).
// Initial ClientHello MAY use 0x0301; ServerHello and post-HRR ClientHello2 MUST use 0x0303.
fn send_plaintext_handshake_record(
    fd:         i64,
    hs_msg:     const u8[:],
    legacy_ver: u16 = rfc::TLS_LEGACY_VERSION_1_0,
) -> bool {
    guard hs_msg.len > 0 && hs_msg.len <= rfc::TLS_MAX_RECORD_PLAINTEXT_LEN else { return false; }
    var rec_buf: u8[..16640] = [];
    rec_buf.push(rfc::TLS_CONTENT_HANDSHAKE);
    rec_buf.append_u16_be(legacy_ver);
    rec_buf.append_u16_be(hs_msg.len as u16);
    rec_buf.append(hs_msg);
    return tls_write_all(fd, rec_buf[..]);
}

fn verify_ocsp_against_trust_store(
    leaf_ocsp:   const u8[:],
    leaf_cert:   const tls::ParsedCert&,
    leaf_raw:    const u8[:],
    eff_clock:   i64,
    trust_store: const tls::TrustAnchorStore&,
) -> bool, bool {
    let leaf_issuer_dn = tls::span_slice(leaf_raw, leaf_cert.issuer_raw);
    guard leaf_issuer_dn.len > 0 else { return false, false; }
    var matched_idx: i64 = -1;
    for i in trust_store.anchors.len {
        let a .= trust_store.anchors[i];
        if a.is_valid && a.has_pub_material && a.subject_raw[..] == leaf_issuer_dn {
            matched_idx = i;
            break;
        }
    }
    guard matched_idx >= 0 else { return false, false; }
    let a .= trust_store.anchors[matched_idx];
    let alert = tls::validate_ocsp_stapling(leaf_ocsp, leaf_cert, leaf_raw, eff_clock);
    guard alert == tls::Alert.CloseNotify else { return true, false; }
    var ocsp_parsed = tls::ParsedOcspResponse { .. };
    guard tls::parse_ocsp_response(leaf_ocsp, ocsp_parsed) else { return true, false; }
    guard x509_verify_ocsp_cert_id_material(
        ocsp_parsed, leaf_ocsp, a.subject_raw[..], a.spki_pubkey[..],
    ) else { return true, false; }
    let sig_alert = x509_verify_ocsp_signature_with_pubkey(
        ocsp_parsed, leaf_ocsp, a.spki_pubkey[..],
    );
    return true, sig_alert == tls::Alert.CloseNotify;
}

fn verify_stapled_ocsp_for_chain(
    leaf_ocsp:             const u8[:],
    chain_parsed:          const tls::ParsedCert[..8]&,
    chain_slices:          const (const u8[:])[..8]&,
    eff_clock:             i64,
    trust_store:           const tls::TrustAnchorStore&,
    require_ocsp_stapling: bool = false,
) -> bool {
    guard leaf_ocsp.len > 0 else {
        return !require_ocsp_stapling && !chain_parsed[0].has_must_staple;
    }
    if chain_parsed.len >= 2 {
        return tls::validate_ocsp_stapling(
            leaf_ocsp, chain_parsed[0], chain_slices[0], eff_clock, chain_slices[1],
        ) == tls::Alert.CloseNotify;
    }
    let anchor_matched, anchor_ok = verify_ocsp_against_trust_store(
        leaf_ocsp, chain_parsed[0], chain_slices[0], eff_clock, trust_store,
    );
    if anchor_matched {
        return anchor_ok;
    }
    let leaf_subj = tls::span_slice(chain_slices[0], chain_parsed[0].subject_raw);
    let leaf_iss = tls::span_slice(chain_slices[0], chain_parsed[0].issuer_raw);
    guard leaf_subj.len > 0 && leaf_subj == leaf_iss else { return false; }
    return tls::validate_ocsp_stapling(
        leaf_ocsp, chain_parsed[0], chain_slices[0], eff_clock, chain_slices[0],
    ) == tls::Alert.CloseNotify;
}

// RFC 5280 Section 6.3.3: CRL Processing - Resolves the CRL issuer certificate or trust anchor and verifies cRLSign key usage and signature.
fn verify_crl_signer_for_cert(
    crl_parsed:   const tls::ParsedCrl&,
    crl_der:      const u8[:],
    cert_idx:     i64,
    chain_parsed: const tls::ParsedCert[..8]&,
    chain_slices: const (const u8[:])[..8]&,
    trust_store:  const tls::TrustAnchorStore&,
) -> bool {
    let next_idx = core::add_sat_i64(cert_idx, 1);
    if next_idx < chain_parsed.len {
        let iss .= chain_parsed[next_idx];
        guard !iss.has_key_usage || (iss.key_usage & rfc::KEY_USAGE_CRL_SIGN) != 0 else { return false; }
        let sig_alert = tls::x509_verify_crl_signature(crl_parsed, crl_der, iss, chain_slices[next_idx]);
        return sig_alert == tls::Alert.CloseNotify;
    }
    var matched_anchor: i64 = -1;
    for j in trust_store.anchors.len {
        let a .= trust_store.anchors[j];
        if a.is_valid && a.has_pub_material && a.subject_raw[..] == crl_parsed.issuer {
            matched_anchor = j;
            break;
        }
    }
    if matched_anchor >= 0 {
        let a .= trust_store.anchors[matched_anchor];
        guard !a.has_key_usage || (a.key_usage & rfc::KEY_USAGE_CRL_SIGN) != 0 else { return false; }
        let alert = x509_verify_crl_signature_with_pubkey(crl_parsed, crl_der, a.spki_pubkey[..]);
        return alert == tls::Alert.CloseNotify;
    }
    let self_cert .= chain_parsed[cert_idx];
    let self_subj = tls::span_slice(chain_slices[cert_idx], self_cert.subject_raw);
    guard self_subj.len > 0 && self_subj == crl_parsed.issuer else { return false; }
    guard !self_cert.has_key_usage || (self_cert.key_usage & rfc::KEY_USAGE_CRL_SIGN) != 0 else { return false; }
    let self_alert = tls::x509_verify_crl_signature(crl_parsed, crl_der, self_cert, chain_slices[cert_idx]);
    return self_alert == tls::Alert.CloseNotify;
}

// RFC 5280 Section 6.3.3: CRL Processing - Verifies CRL freshness, issuer signature, and revocation status across matching chain certificates.
fn verify_crl_for_chain_with_store(
    crl_der:      const u8[:],
    chain_parsed: const tls::ParsedCert[..8]&,
    chain_slices: const (const u8[:])[..8]&,
    now_unix:     i64,
    trust_store:  const tls::TrustAnchorStore&,
) -> bool {
    guard crl_der.len > 0 else { return true; }
    guard chain_parsed.len > 0 && chain_slices.len == chain_parsed.len else { return false; }
    var crl_parsed = tls::ParsedCrl { .. };
    guard tls::parse_x509_crl(crl_der, crl_parsed) else { return false; }
    let now_sec = if now_unix > 0 { now_unix } else { core::unix(core::now()) };
    guard crl_parsed.this_update <= now_sec else { return false; }
    if crl_parsed.next_update > 0 {
        guard now_sec <= crl_parsed.next_update else { return false; }
    }
    var matched_any = false;
    for i in chain_parsed.len {
        let cert_issuer = tls::span_slice(chain_slices[i], chain_parsed[i].issuer_raw);
        if cert_issuer == crl_parsed.issuer {
            matched_any = true;
            guard verify_crl_signer_for_cert(
                crl_parsed, crl_der, i, chain_parsed, chain_slices, trust_store,
            ) else { return false; }
            let ser_bytes = tls::span_slice(chain_slices[i], chain_parsed[i].serial_number);
            let ser_u64, ok_ser = tls::parse_asn1_serial_u64(ser_bytes);
            guard ok_ser && !tls::crl_is_revoked(crl_parsed, ser_u64) else { return false; }
        }
    }
    return matched_any;
}

// Seals and sends an encrypted handshake record, advancing sequence number.
fn tls_seal_and_send_hs(
    fd:           i64,
    cipher_suite: u16,
    key:          const u8[:],
    iv:           const u8[12]&,
    seq:          u64,
    hs_msg:       const u8[:],
) -> bool {
    var ct_buf: u8[..4096] = [];
    let needed = hs_msg.len + 32;
    guard needed <= ct_buf.cap else { return false; }
    ct_buf.resize(needed, 0);
    let s_len, _, ok_seal = tls::record_seal_into(
        cipher_suite, key, iv, seq,
        rfc::TLS_CONTENT_HANDSHAKE, hs_msg, ct_buf[..],
    );
    guard ok_seal && tls_write_all(fd, ct_buf[..s_len]) else { return false; }
    return true;
}

fn transcript_update(t: tls::Transcript&, data: const u8[:]) {
    core::sha256_update(t.sha256_ctx, data);
    core::sha384_update(t.sha384_ctx, data);
}

fn transcript_update_msg(t: tls::Transcript&, msg_type: u8, body: const u8[:]) {
    var hdr: u8[4] = [0; 4];
    hdr[0] = msg_type;
    hdr[1] = ((body.len >> 16) & 0xFF) as u8;
    hdr[2] = ((body.len >> 8) & 0xFF) as u8;
    hdr[3] = (body.len & 0xFF) as u8;
    transcript_update(t, hdr[..]);
    transcript_update(t, body);
}

fn transcript_current_hash(t: const tls::Transcript&, hash_id: u8, out_hash: u8[..48]&) {
    out_hash.clear();
    if hash_id == HASH_SHA384 {
        var ctx = t.sha384_ctx;
        let h = core::sha384_final(ctx);
        out_hash.append(h[..]);
    } else {
        var ctx = t.sha256_ctx;
        let h = core::sha256_final(ctx);
        out_hash.append(h[..]);
    }
}

// Replaces transcript state with synthetic message_hash after HelloRetryRequest (RFC 8446 §4.4.1).
fn transcript_replace_with_message_hash(t: tls::Transcript&, hash_id: u8, hash_len: u8) -> bool {
    var ch1_hash: u8[..48] = [];
    transcript_current_hash(t, hash_id, ch1_hash);
    var synth: u8[64] = [0; 64];
    let synth_len, ok_s = compress_hrr_transcript(hash_len, ch1_hash[..], synth[..]);
    guard ok_s else { return false; }
    t.sha256_ctx = core::Sha256Ctx { .. };
    t.sha384_ctx = core::Sha384Ctx { .. };
    transcript_update(t, synth[..synth_len]);
    return true;
}

// Fills `out` with 32 cryptographically secure random bytes by mixing OS kernel CSPRNG
// (`BCryptGenRandom` / `RtlGenRandom` / `getrandom`), monotonic timer, wall clock,
// entropy pool, and sequence counter via Fast-Key-Erasure SHA-256 ratcheting (Invariant 16).
// Returns deterministic `core::sim_rng_fill` bytes directly when DST simulation entropy is active.
// Fails closed on OS CSPRNG error by wiping `out` and `g_tls_entropy_pool` and returning `false`.
fn random_bytes_32_checked(out: u8[32]&) -> bool {
    if core::sim_rng_is_active() {
        guard core::sim_rng_fill(out[..]) else {
            core::secure_zeroize_32(out);
            return false;
        }
        return true;
    }
    native_tls_state_lock(TLS_LOCK_ENTROPY_POOL);
    defer native_tls_state_unlock(TLS_LOCK_ENTROPY_POOL);

    var os_seed: u8[32] = [0; 32];
    defer core::secure_zeroize_32(os_seed);
    guard native_tls_csprng_bytes(os_seed[..]) == 0 else {
        core::secure_zeroize_32(tls::g_tls_entropy_pool);
        tls::g_tls_entropy_counter = 0;
        core::secure_zeroize_32(out);
        return false;
    }
    for i in 32 {
        tls::g_tls_entropy_pool[i] ^= os_seed[i];
    }

    tls::g_tls_entropy_counter = core::add_sat_u64(tls::g_tls_entropy_counter, 1);
    let mono_ns = core::monotonic_now().nanos;
    let wall_now = core::now();
    let wall_sec = (max(0, wall_now.wall_sec) & 0x7FFFFFFFFFFFFFFF) as u64;
    let wall_nsec = (max(0, wall_now.nsec) & 0x7FFFFFFF) as u32;

    var mix: u8[64] = [0; 64];
    defer core::secure_zeroize_64(mix);
    core::ct_copy_bytes(mix[0..32], tls::g_tls_entropy_pool[..]);
    core::write_le_u64_at(mix[..], 32, tls::g_tls_entropy_counter);
    core::write_le_u64_at(mix[..], 40, mono_ns);
    core::write_le_u64_at(mix[..], 48, wall_sec);
    core::write_le_u32_at(mix[..], 56, wall_nsec);
    mix[60] = 0x01;
    let out_bytes = core::sha256(mix[..]);

    core::ct_copy_bytes(mix[0..32], tls::g_tls_entropy_pool[..]);
    mix[60] = 0x02;
    for i in 32 {
        let off = core::add_sat_i64(32, i);
        mix[off] ^= out_bytes[i];
    }
    tls::g_tls_entropy_pool = core::sha256(mix[..]);
    out = out_bytes;
    return true;
}

// Returns 32 cryptographically secure random bytes, failing closed with zeroed output
// and a wiped entropy pool if the OS CSPRNG fails.
fn random_bytes_32() -> u8[32] {
    var out: u8[32] = [0; 32];
    if !random_bytes_32_checked(out) {
        core::secure_zeroize_32(out);
    }
    return out;
}

fn read_plaintext_handshake_record(
    fd:          i64,
    out_payload: u8[..16384]&,
    timeout_ms:  u32 = 5000,
) -> bool {
    var raw_msg:   u8[..16384] = [];
    var ccs_count: u32         = 0;
    var found = false;
    while !found {
        var hdr: u8[5] = [0; 5];
        guard tls_read_exact(fd, hdr[..], timeout_ms) else { return false; }
        let ct, ver, p_len_u16, alert, ok_hdr = tls::parse_record_header(hdr[..]);
        guard ok_hdr else { return false; }
        let p_len = p_len_u16 as i64;
        guard p_len <= rfc::TLS_MAX_RECORD_PLAINTEXT_LEN else { return false; }

        var body: u8[..16384] = [];
        while body.len < p_len { body.push(0); }
        guard tls_read_exact(fd, body[..p_len], timeout_ms) else { return false; }

        if ct == rfc::TLS_CONTENT_CHANGE_CIPHER_SPEC {
            guard ccs_count < 1 &&
                raw_msg.len == 0 &&
                ver == rfc::TLS_LEGACY_VERSION_1_2 &&
                tls::validate_change_cipher_spec_record(body[..p_len]) == tls::Alert.CloseNotify else {
                return false;
            }
            ccs_count = core::add_sat_u32(ccs_count, 1);
            continue;
        }
        guard ct == rfc::TLS_CONTENT_HANDSHAKE && raw_msg.try_append(body[..p_len]) else { return false; }
        found = has_complete_plaintext_handshake_msg(raw_msg[..]);
    }
    guard found else { return false; }
    return out_payload.try_set(raw_msg[..]);
}

fn verify_chain_ocsp_and_crl(
    chain_parsed: const tls::ParsedCert[..8]&,
    chain_slices: const (const u8[:])[..8]&,
    leaf_ocsp:    const u8[:],
    config:       const tls::ClientHandshakeConfig&,
    eff_clock:    i64,
) -> bool {
    if config.trust_store.anchors.len > 0 || !config.use_system_roots {
        let alert = tls::verify_certificate_chain(
            chain_parsed, chain_slices, config.trust_store, eff_clock, tls::CertValidationRole.Server,
        );
        guard alert == tls::Alert.CloseNotify else { return false; }
        guard verify_stapled_ocsp_for_chain(
            leaf_ocsp, chain_parsed, chain_slices, eff_clock, config.trust_store, config.require_ocsp_stapling,
        ) else {
            return false;
        }
        return verify_crl_for_chain_with_store(
            config.crl_der[..], chain_parsed, chain_slices, eff_clock, config.trust_store,
        );
    }

    guard chain_parsed.len > 0 && chain_slices.len == chain_parsed.len else { return false; }

    var sys_store = tls::TrustAnchorStore { .. };
    let top_idx = core::sub_sat_i64(chain_parsed.len, 1);
    let top_issuer = tls::span_slice(chain_slices[top_idx], chain_parsed[top_idx].issuer_raw);
    let _ = tls::load_system_roots_for_issuer(sys_store, top_issuer);
    let top_subj = tls::span_slice(chain_slices[top_idx], chain_parsed[top_idx].subject_raw);
    if top_subj != top_issuer {
        let _ = tls::load_system_roots_for_issuer(sys_store, top_subj);
    }
    let alert = tls::verify_certificate_chain(
        chain_parsed, chain_slices, sys_store, eff_clock, tls::CertValidationRole.Server,
    );
    guard alert == tls::Alert.CloseNotify else { return false; }
    guard verify_stapled_ocsp_for_chain(
        leaf_ocsp, chain_parsed, chain_slices, eff_clock, sys_store, config.require_ocsp_stapling,
    ) else {
        return false;
    }
    return verify_crl_for_chain_with_store(
        config.crl_der[..], chain_parsed, chain_slices, eff_clock, sys_store,
    );
}

inline fn verify_cv_sig_with_min_rsa(
    sig_scheme: u16,
    sig_bytes:  const u8[:],
    leaf_pub:   const u8[:],
    cv_msg:     const u8[:],
) -> bool {
    if sig_scheme == rfc::SIG_SCHEME_RSA_PSS_RSAE_SHA256 ||
        sig_scheme == rfc::SIG_SCHEME_RSA_PSS_RSAE_SHA384 {
        guard is_valid_rsa_pubkey_min_bits(leaf_pub) else { return false; }
    }
    return verify_certificate_verify_sig(sig_scheme, sig_bytes, leaf_pub, cv_msg);
}
