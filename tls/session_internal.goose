// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal TLS 1.3 session I/O, handshake framing, PSK binder, and certificate helper routines.
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
import .ocsp;
import .crl;
import .ticket;
import .ticket_internal;
import .post_quantum;
import .cert_compression;
import .ech;
import .pki_internal;
import net.tcp;
import net.transport;

const TLS_LOCK_CIPHER_SLOTS: i32 = 0;
const TLS_LOCK_ENTROPY_POOL: i32 = 1;
const TLS_LOCK_TICKET_CACHE: i32 = 2;

extern fn native_tls_state_lock(lock_id: i32) = "wing_tls_state_lock";
extern fn native_tls_state_unlock(lock_id: i32) = "wing_tls_state_unlock";
extern fn raw_tls_csprng_bytes(out: u8[:]) -> i32 = "wing_crypto_random_bytes";

var g_tls_sim_last_epoch:        u64  = 0;
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

fn try_read_handshake_msg(
    r:            tls::HandshakeRecordReader&,
    msg_type:     u8&,
    out_msg_body: u8[..16384]&,
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
fn next_handshake_message(
    r:            tls::HandshakeRecordReader&,
    fd:           i64,
    cipher_suite: u16,
    key:          const u8[:],
    iv:           const u8[12]&,
    msg_type:     u8&,
    out_msg_body: u8[..16384]&,
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

// Encodes an ALPN extension (RFC 7301 §3.1) supporting single or comma-separated protocol names (e.g. "h2,http/1.1").
fn encode_alpn_extension_from_csv<B>(out: B&, alpn_csv: const u8[:]) {
    guard alpn_csv.len > 0 && alpn_csv.len <= 255 else { return; }
    var proto_list: u8[..256] = [];
    var cursor:     i64       = 0;
    while cursor < alpn_csv.len {
        var comma_idx = cursor;
        while comma_idx < alpn_csv.len && alpn_csv[comma_idx] != ',' {
            comma_idx++;
        }
        let item = alpn_csv[cursor..comma_idx];
        if item.len > 0 && item.len <= 255 {
            proto_list.push(item.len as u8);
            proto_list.append(item);
        }
        cursor = comma_idx + 1;
    }
    guard proto_list.len >= 2 else { return; }
    out.append_u16_be(rfc::TLS_EXT_ALPN);
    out.append_u16_be((proto_list.len + 2) as u16);
    out.append_u16_be(proto_list.len as u16);
    out.append(proto_list[..]);
}

// Computes a TLS 1.3 PSK binder tag (SHA-256 or SHA-384) over a truncated ClientHello (RFC 8446 Section 4.2.11.2).
fn compute_tls13_psk_binder_for_hash(
    hash_id:      u8,
    binder_key:   const u8[:],
    truncated_ch: const u8[:],
    out_binder:   u8[..48]&,
) -> bool {
    out_binder.clear();
    if hash_id == tls_internal::HASH_SHA256 {
        guard binder_key.len >= 32 else { return false; }
        let ch_hash = core::sha256(truncated_ch);
        var mac: u8[32] = [0; 32];
        defer core::secure_zeroize_32(mac);
        guard tls_internal::ks_compute_finished_verify_data(
            tls_internal::HASH_SHA256, 32, binder_key[..32], ch_hash[..], mac[..],
        ) else { return false; }
        return out_binder.try_set(mac[..]);
    }
    if hash_id == tls_internal::HASH_SHA384 {
        guard binder_key.len >= 48 else { return false; }
        let ch_hash = core::sha384(truncated_ch);
        var mac: u8[48] = [0; 48];
        defer core::secure_zeroize_48(mac);
        guard tls_internal::ks_compute_finished_verify_data(
            tls_internal::HASH_SHA384, 48, binder_key[..48], ch_hash[..], mac[..],
        ) else { return false; }
        return out_binder.try_set(mac[..]);
    }
    return false;
}

// Encodes psk_key_exchange_modes (RFC 8446 §4.2.9) and pre_shared_key (RFC 8446 §4.2.11) extensions.
fn encode_psk_client_extensions<B>(
    out:         B&,
    psk_ticket:  const u8[:],
    psk_age_add: u32,
    binder_len:  u8 = 32,
) {
    guard psk_ticket.len > 0 && psk_ticket.len <= 1536 && (binder_len == 32 || binder_len == 48) else { return; }
    out.append_u16_be(rfc::TLS_EXT_PSK_KEY_EXCHANGE_MODES);
    out.append_u16_be(2);
    out.push(1);
    out.push(1);

    let id_entry_len = core::add_sat_i64(psk_ticket.len, 6) as u16;
    let binders_entry_len: u16 = if binder_len == 48 { 49 } else { 33 };
    let psk_ext_len = core::add_sat_i64(id_entry_len as i64, core::add_sat_i64(binders_entry_len as i64, 4)) as u16;
    out.append_u16_be(rfc::TLS_EXT_PRE_SHARED_KEY);
    out.append_u16_be(psk_ext_len);
    out.append_u16_be(id_entry_len);
    out.append_u16_be(psk_ticket.len as u16);
    out.append(psk_ticket);
    out.append_u32_be(psk_age_add);
    out.append_u16_be(binders_entry_len);
    out.push(binder_len);
    for i in (binder_len as i64) { out.push(0); }
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

inline fn alpn_csv_contains_proto(alpn_csv: const u8[:], target: const u8[:]) -> bool {
    if alpn_csv == "*" {
        return true;
    }
    guard alpn_csv.len > 0 && target.len > 0 else { return false; }
    var tok = core::make_byte_tokenizer(alpn_csv, ',');
    while true {
        let item, ok = core::token_next(tok);
        if !ok { break; }
        if item == target { return true; }
    }
    return false;
}

fn validate_ee_solicited_extensions(
    entries:          const tls::ExtensionEntry[..32]&,
    offered_alpn_csv: const u8[:],
    sni_state:        tls::SniOfferState,
    allow_ech_retry:  bool,
) -> bool {
    for &e in entries {
        if e.ext_type == rfc::TLS_EXT_SERVER_NAME {
            guard sni_state == tls::SniOfferState.Offered && e.data.len == 0 else { return false; }
        } else if e.ext_type == rfc::TLS_EXT_SUPPORTED_GROUPS {
            // RFC 8446 Section 4.2.7: Supported Groups - Server may echo NamedGroupList in EncryptedExtensions.
            guard e.data.len >= 4 else { return false; }
            let list_len = core::read_be_u16(e.data, 0) as i64;
            guard list_len >= 2 && (list_len & 1) == 0 && core::add_sat_i64(list_len, 2) == e.data.len else {
                return false;
            }
        } else if e.ext_type == rfc::TLS_EXT_ALPN {
            guard offered_alpn_csv.len > 0 else { return false; }
        } else if e.ext_type == rfc::EXT_ENCRYPTED_CLIENT_HELLO {
            guard allow_ech_retry && e.data.len >= 2 else { return false; }
        } else {
            return false;
        }
    }
    return true;
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

// Detects the TLS 1.3 SignatureScheme (`SIG_SCHEME_ECDSA_SECP256R1_SHA256` or `SIG_SCHEME_ED25519`)
// from the leaf certificate's SubjectPublicKeyInfo OID (RFC 8446 Section 4.4.3).
fn detect_cert_sig_scheme(cert_der: const u8[:]) -> u16 {
    var cert = tls::ParsedCert { .. };
    if cert_der.len > 0 && tls::parse_x509_certificate(cert_der, cert) {
        let spki_oid = tls::span_slice(cert_der, cert.spki_alg_oid);
        if spki_oid == rfc::OID_SECP256R1[..] {
            return rfc::SIG_SCHEME_ECDSA_SECP256R1_SHA256;
        }
    }
    return rfc::SIG_SCHEME_ED25519;
}

inline fn is_client_offered_tls13_suite(cs: u16) -> bool {
    return cs == rfc::TLS_CIPHER_AES_128_GCM_SHA256 ||
        cs == rfc::TLS_CIPHER_AES_256_GCM_SHA384 ||
        cs == rfc::TLS_CIPHER_CHACHA20_POLY1305_SHA256;
}

// RFC 8446 Section 4.1.3: Server Hello - Verify legacy_session_id_echo, offered cipher suite, and key_share.
fn validate_live_client_sh(sh: const tls::ParsedServerHello&, client_random: const u8[32]&) -> bool {
    guard sh.session_id_echo.len == 32 &&
        core::ct_eq_bytes(sh.session_id_echo[..], client_random[..]) &&
        is_client_offered_tls13_suite(sh.cipher_suite) else {
        return false;
    }
    return sh.is_hrr || sh.server_share.len > 0;
}

fn frame_handshake_msg_4k(msg_type: u8, payload: const u8[:], out_msg: u8[..4096]&) -> bool {
    out_msg.clear();
    let payload_u32 = (payload.len & 0xFFFFFF) as u32;
    let total_len = core::add_sat_i64(payload.len, 4);
    guard payload.len >= 0 && total_len <= out_msg.cap else { return false; }
    var hdr: u8[4] = [0; 4];
    guard tls::encode_handshake_header(msg_type, payload_u32, hdr) else { return false; }
    out_msg.append(hdr[..]);
    out_msg.append(payload);
    return true;
}

fn try_match_single_psk_binder(
    ticket_id:    const u8[:],
    binder_slice: const u8[:],
    ch_msg:       const u8[:],
    binders_len:  u16,
    selected_cs:  u16,
    out_psk:      u8[..48]&,
) -> bool, bool {
    out_psk.clear();
    var full_psk: u8[..48] = [];
    defer core::secure_zeroize_slice(full_psk[..]);
    var cs: u16 = 0;
    if !lookup_ticket_by_identity_full(ticket_id, full_psk, cs) ||
        (full_psk.len != 32 && full_psk.len != 48) {
        return false, true;
    }
    let suite = if cs != 0 { cs } else { rfc::TLS_CIPHER_AES_128_GCM_SHA256 };
    if selected_cs != 0 && rfc::tls13_cipher_suite_hash_len(suite) != rfc::tls13_cipher_suite_hash_len(selected_cs) {
        return false, true;
    }
    var ks_early, ok_kse = tls_internal::ks_init(suite);
    defer tls_internal::ks_zeroize(ks_early);
    guard ok_kse && tls_internal::ks_init_early_secret(ks_early, full_psk[..]) else { return false, false; }
    let hlen = ks_early.hash_len as i64;
    guard binder_slice.len == hlen else { return false, false; }

    let trunc_ch, ok_tr = tls_internal::truncate_client_hello_for_binder(ch_msg, binders_len);
    guard ok_tr else { return false, false; }
    guard tls_internal::verify_psk_binder(
        ks_early.hash_id, ks_early.hash_len, ks_early.binder_key[..hlen], trunc_ch, binder_slice,
    ) else { return false, false; }
    guard out_psk.try_set(full_psk[..]) else { return false, false; }
    return true, true;
}

// Reads one PskIdentity and matching PskBinderEntry from OfferedPsks cursors (RFC 8446 Section 4.2.11).
//
// Example:
//   ic = [0x00, 0x04, 'T', 'K', 'T', '1', 0, 0, 0, 0], bc = [0x20, ...32 bytes...]
//   returns: ticket_id = "TKT1", binder_slice = [32 bytes], ok = true
inline fn read_psk_identity_and_binder(
    ic: core::ByteCursor&,
    bc: core::ByteCursor&,
) -> const u8[:], const u8[:], bool {
    let ticket_id, ok_t = ic.read_u16_prefixed();
    let _, ok_age = ic.read_u32();
    let binder_slice, ok_bs = bc.read_u8_prefixed();
    guard ok_t && ticket_id.len > 0 && ok_age && ok_bs else { return "", "", false; }
    guard binder_slice.len == 32 || binder_slice.len == 48 else { return "", "", false; }
    return ticket_id, binder_slice, true;
}

// Splits a TLS 1.3 pre_shared_key ClientHello extension into identities and binders slices.
//
// Example:
//   psk_ext = <2B ids_len><ids...><2B binders_len><binders...>
//   returns: ids, binders, ok = true
inline fn parse_psk_extension_lists(psk_ext: const u8[:]) -> const u8[:], const u8[:], bool {
    var c = core::cursor_from(psk_ext);
    let ids_bytes, ok_ids = c.read_u16_prefixed();
    let binders_bytes, ok_b = c.read_u16_prefixed();
    let ok = ok_ids && ids_bytes.len >= 7 && ok_b && c.buf.len == 0 && binders_bytes.len >= 33;
    return ids_bytes, binders_bytes, ok;
}

fn eval_client_hello_psk_binders(
    ch_msg:          const u8[:],
    psk_ext:         const u8[:],
    selected_cs:     u16,
    out_psk:         u8[..48]&,
    out_selected_id: u16&,
) -> bool, bool {
    core::secure_zeroize_slice(out_psk[..]);
    out_psk.clear();
    out_selected_id = 0;

    let ids_bytes, binders_bytes, ok_lists = parse_psk_extension_lists(psk_ext);
    guard ok_lists else { return false, false; }

    var ic = core::cursor_from(ids_bytes);
    var bc = core::cursor_from(binders_bytes);
    var matched_psk: u8[..48] = [];
    defer core::secure_zeroize_slice(matched_psk[..]);
    var matched = false;
    var cur_idx:   u16 = 0;
    var chosen_id: u16 = 0;

    while ic.buf.len > 0 && bc.buf.len > 0 {
        let ticket_id, binder_slice, ok_entry = read_psk_identity_and_binder(ic, bc);
        guard ok_entry && cur_idx < 0xFFFF else { return false, false; }
        if !matched {
            let entry_matched, entry_ok = try_match_single_psk_binder(
                ticket_id, binder_slice, ch_msg, binders_bytes.len as u16, selected_cs, matched_psk,
            );
            guard entry_ok else { return false, false; }
            if entry_matched {
                matched = true;
                chosen_id = cur_idx;
            }
        }
        cur_idx = core::add_sat_u64(cur_idx, 1) as u16;
    }
    guard ic.buf.len == 0 && bc.buf.len == 0 else { return false, false; }
    if !matched {
        return false, true;
    }
    guard out_psk.try_set(matched_psk[..]) else { return false, false; }
    out_selected_id = chosen_id;
    return true, true;
}

fn has_valid_psk_dhe_ke_mode(modes_ext: const u8[:]) -> bool {
    var c = core::cursor_from(modes_ext);
    let modes, ok = c.read_u8_prefixed();
    guard ok && c.buf.len == 0 && modes.len >= 1 else { return false; }
    var has_dhe = false;
    for m in modes {
        guard m == 0 || m == 1 else { return false; }
        if m == 1 { has_dhe = true; }
    }
    return has_dhe;
}

fn eval_client_hello_psk_entry(
    entries:         const tls::ExtensionEntry[..32]&,
    payload:         const u8[:],
    psk_ext:         const u8[:],
    selected_cs:     u16,
    out_psk:         u8[..48]&,
    out_selected_id: u16&,
) -> bool, bool {
    let last_idx = core::sub_sat_i64(entries.len, 1);
    guard entries.len > 0 && last_idx >= 0 && last_idx < entries.len else { return false, false; }
    guard entries[last_idx].ext_type == rfc::TLS_EXT_PRE_SHARED_KEY else { return false, false; }
    let modes_ext, has_modes = tls::find_extension(entries, rfc::TLS_EXT_PSK_KEY_EXCHANGE_MODES);
    guard has_modes && has_valid_psk_dhe_ke_mode(modes_ext) else { return false, false; }
    return eval_client_hello_psk_binders(payload, psk_ext, selected_cs, out_psk, out_selected_id);
}

// Extracts the 32-byte X25519 key share from a parsed KeyShareEntry list.
//
// Example:
//   shares = [0x00, 0x1D, 0x00, 0x20, ...32 bytes...]
//   returns: true, out_client_pub = [32 bytes]
fn extract_x25519_client_share(shares: const u8[:], out_client_pub: u8[32]&) -> bool {
    guard validate_client_key_share_entries(shares) else { return false; }
    var sc = core::cursor_from(shares);
    var found = false;
    while sc.buf.len > 0 {
        let group, ok_g = sc.read_u16();
        let kex_bytes, ok_k = sc.read_u16_prefixed();
        guard ok_g && ok_k else { return false; }
        if group == rfc::GROUP_X25519 {
            guard kex_bytes.len == 32 else { return false; }
            for i in 32 { out_client_pub[i] = kex_bytes[i]; }
            found = true;
        }
    }
    return found;
}

fn ch_cipher_suites_slice(raw: const u8[:]) -> const u8[:] {
    guard raw.len > 38 && raw[0] == rfc::TLS_HS_CLIENT_HELLO else { return raw; }
    var c = core::cursor_from(raw);
    let _, _ = c.read_u8();
    let body, ok_b = c.read_u24_prefixed();
    guard ok_b && c.buf.len == 0 else { return raw; }
    var bc = core::cursor_from(body);
    let ver, ok_v = bc.read_u16();
    let _, ok_r = bc.read_bytes(32);
    let sid, ok_sid = bc.read_u8_prefixed();
    let cs_bytes, ok_cs = bc.read_u16_prefixed();
    let comp, ok_cm = bc.read_u8_prefixed();
    let _, ok_ext = bc.read_u16_prefixed();
    guard ok_v && ver == rfc::TLS_LEGACY_VERSION_1_2 && ok_r && ok_sid && sid.len <= 32 &&
        ok_cs && ok_cm && comp.len >= 1 && ok_ext && bc.buf.len == 0 else {
        return raw;
    }
    return cs_bytes;
}

fn select_cipher_suite_from_list(cs_bytes: const u8[:]) -> u16, bool {
    guard cs_bytes.len >= 2 && (cs_bytes.len & 1) == 0 else { return 0, false; }
    var c = core::cursor_from(cs_bytes);
    while c.buf.len >= 2 {
        let cs, ok = c.read_u16();
        guard ok else { return 0, false; }
        if is_client_offered_tls13_suite(cs) {
            return cs, true;
        }
    }
    return 0, false;
}

fn has_forbidden_extension(entries: const tls::ExtensionEntry[..32]&) -> bool {
    for &e in entries {
        if rfc::is_forbidden_ch_extension(e.ext_type) { return true; }
    }
    return false;
}

// RFC 8446 Section 4.2.3: Signature Algorithms - Validates SignatureSchemeList syntax and required server scheme.
fn validate_ch_sig_algorithms(sig_ext: const u8[:], required_scheme: u16) -> bool {
    var c = core::cursor_from(sig_ext);
    let list_bytes, ok = c.read_u16_prefixed();
    guard ok && c.buf.len == 0 && list_bytes.len >= 2 && (list_bytes.len & 1) == 0 else { return false; }
    var lc = core::cursor_from(list_bytes);
    var has_supported = false;
    while lc.buf.len >= 2 {
        let scheme, ok_s = lc.read_u16();
        guard ok_s else { return false; }
        if required_scheme != 0 {
            if scheme == required_scheme { has_supported = true; }
        } else if scheme == rfc::SIG_SCHEME_ED25519 || scheme == rfc::SIG_SCHEME_ECDSA_SECP256R1_SHA256 {
            has_supported = true;
        }
    }
    return has_supported;
}

inline fn group_bytes_contains(grp_bytes: const u8[:], target: u16) -> bool {
    var gc = core::cursor_from(grp_bytes);
    while gc.buf.len >= 2 {
        let g, ok = gc.read_u16();
        if ok && g == target { return true; }
    }
    return false;
}

// RFC 8446 Section 4.2.8: Key Share - Every KeyShareEntry group must appear in supported_groups in the same order.
fn validate_ch_groups_and_shares(grp_ext: const u8[:], shares: const u8[:]) -> bool {
    var c = core::cursor_from(grp_ext);
    let grp_bytes, ok = c.read_u16_prefixed();
    guard ok && c.buf.len == 0 && grp_bytes.len >= 2 && (grp_bytes.len & 1) == 0 else { return false; }
    guard group_bytes_contains(grp_bytes, rfc::GROUP_X25519) else { return false; }

    var sc = core::cursor_from(shares);
    var gc = core::cursor_from(grp_bytes);
    while sc.buf.len > 0 {
        let ks_grp, ok_g = sc.read_u16();
        let _, ok_k = sc.read_u16_prefixed();
        guard ok_g && ok_k else { return false; }
        var matched = false;
        while gc.buf.len >= 2 && !matched {
            let g, ok_grp = gc.read_u16();
            matched = ok_grp && g == ks_grp;
        }
        guard matched else { return false; }
    }
    return true;
}

// Reads and validates ClientHello legacy version, random, session_id, cipher_suites, and compression_methods.
//
// Example:
//   bc = [0x03, 0x03, ...32B random..., 0x00, 0x00, 0x02, 0x13, 0x01, 0x01, 0x00]
//   returns: cs_bytes = [0x13, 0x01], ok = true
fn decode_ch_legacy_preamble(bc: core::ByteCursor&, out_sid: u8[..32]&) -> const u8[:], bool {
    out_sid.clear();
    let ver, ok_v = bc.read_u16();
    let _, ok_r = bc.read_bytes(32);
    let sid, ok_sid = bc.read_u8_prefixed();
    let cs_bytes, ok_cs = bc.read_u16_prefixed();
    let comp_bytes, ok_cm = bc.read_u8_prefixed();
    guard ok_v && ver == rfc::TLS_LEGACY_VERSION_1_2 && ok_r else { return "", false; }
    guard ok_cs && ok_cm && comp_bytes.len == 1 && comp_bytes[0] == 0 else { return "", false; }
    guard ok_sid && sid.len <= 32 && out_sid.try_set(sid) else { return "", false; }
    return cs_bytes, true;
}

// Decodes ClientHello handshake framing, legacy preamble, selected cipher suite, and extension table.
//
// Example:
//   payload = [0x01, 0x00, 0x00, 0x46, 0x03, 0x03, ...0x13, 0x01...]
//   returns: sel_cs = 0x1301, ok = true
fn decode_ch_server_preamble(
    payload:     const u8[:],
    out_sid:     u8[..32]&,
    out_entries: tls::ExtensionEntry[..32]&,
) -> u16, bool {
    out_sid.clear();
    out_entries.clear();
    var committed = false;
    defer if !committed {
        out_sid.clear();
        out_entries.clear();
    };
    var c = core::cursor_from(payload);
    let hs_type, ok_t = c.read_u8();
    let body, ok_b = c.read_u24_prefixed();
    guard ok_t && hs_type == rfc::TLS_HS_CLIENT_HELLO && ok_b && c.buf.len == 0 else {
        return 0, false;
    }
    var bc = core::cursor_from(body);
    let cs_bytes, ok_leg = decode_ch_legacy_preamble(bc, out_sid);
    guard ok_leg else { return 0, false; }
    let sel_cs, ok_sel = select_cipher_suite_from_list(cs_bytes);
    guard ok_sel && tls::parse_extensions_block(bc.buf, out_entries) && !has_forbidden_extension(out_entries) else {
        return 0, false;
    }
    committed = true;
    return sel_cs, true;
}

// Validates mandatory TLS 1.3 ClientHello extensions and extracts the client X25519 share and sig_algs slice.
//
// Example:
//   entries = [supported_versions, signature_algorithms, supported_groups, key_share]
//   returns: sig_ext, ok = true, out_client_pub = [32 bytes]
fn extract_ch_mandatory_exts(
    entries:        const tls::ExtensionEntry[..32]&,
    out_client_pub: u8[32]&,
) -> const u8[:], bool {
    core::secure_zeroize_32(out_client_pub);
    let sv_ext, has_sv = tls::find_extension(entries, rfc::TLS_EXT_SUPPORTED_VERSIONS);
    guard has_sv else { return "", false; }
    let supports_13, ok_sv = tls::parse_client_supported_versions(sv_ext);
    guard ok_sv && supports_13 else { return "", false; }

    let sig_ext, has_sig = tls::find_extension(entries, rfc::TLS_EXT_SIGNATURE_ALGORITHMS);
    guard has_sig && validate_ch_sig_algorithms(sig_ext, 0) else { return "", false; }

    let grp_ext, has_grp = tls::find_extension(entries, rfc::TLS_EXT_SUPPORTED_GROUPS);
    let ks_data, has_ks = tls::find_extension(entries, rfc::TLS_EXT_KEY_SHARE);
    guard has_grp && has_ks else { return "", false; }
    var shares: u8[..4096] = [];
    guard tls::parse_key_share_client_extension(ks_data, shares) &&
        validate_ch_groups_and_shares(grp_ext, shares[..]) &&
        extract_x25519_client_share(shares[..], out_client_pub) else {
        core::secure_zeroize_32(out_client_pub);
        return "", false;
    }
    return sig_ext, true;
}

fn build_compressed_cert_payload(
    algo:             u16,
    uncompressed_len: i64,
    compressed_data:  const u8[:],
    out_payload:      u8[..4096]&,
) -> bool {
    let uncomp_u32 = (uncompressed_len & 0xFFFFFF) as u32;
    guard uncompressed_len > 0 && uncompressed_len <= rfc::MAX_UNCOMPRESSED_CERT_SIZE else {
        return false;
    }
    var comp_msg = tls_internal::CompressedCertificate {
        algorithm:                      algo,
        uncompressed_length:            uncomp_u32,
        compressed_certificate_message: compressed_data,
    };
    return tls_internal::encode_compressed_certificate(comp_msg, out_payload);
}

// Extracts the 32-byte ClientHello.random field from a framed ClientHello handshake message (RFC 8446 Section 4.1.2).
//
// Example:
//   ch_msg = [0x01, 0x00, 0x00, 0x22, 0x03, 0x03, ...32 random bytes...]
//   returns: true, out_random = [32 random bytes]
fn extract_ch_client_random(ch_msg: const u8[:], out_random: u8[32]&) -> bool {
    core::secure_zeroize_32(out_random);
    guard ch_msg.len >= 38 && ch_msg[0] == rfc::TLS_HS_CLIENT_HELLO else { return false; }
    core::ct_copy_bytes(out_random[..], ch_msg[6..38]);
    return true;
}

// Formats one NSS Key Log Format line (`<LABEL> <client_random_hex> <secret_hex>\n`) into `out`.
fn append_keylog_secret_line(
    out:           u8[..1024]&,
    label:         const u8[:],
    client_random: const u8[32]&,
    secret:        const u8[:],
) -> bool {
    let saved = out.len;
    var committed = false;
    defer if !committed { out.resize(saved); };
    guard label.len > 0 && (secret.len == 32 || secret.len == 48) else { return false; }
    let hex_secret_len = core::add_sat_i64(secret.len, secret.len);
    let line_len = core::add_sat_i64(core::add_sat_i64(label.len, 67), hex_secret_len);
    guard core::sub_sat_i64(out.cap, out.len) >= line_len else { return false; }
    guard out.try_append(label) && out.try_push(' ') else { return false; }
    for b in client_random {
        core::format_u8_hex(b, out, false);
    }
    guard out.try_push(' ') else { return false; }
    for b in secret {
        core::format_u8_hex(b, out, false);
    }
    guard out.try_push('\n') else { return false; }
    committed = true;
    return true;
}

// Appends TLS 1.3 handshake traffic secrets in NSS Key Log Format to `keylog_path`.
// No-op when `keylog_path` is empty.
fn emit_tls13_hs_keylog(
    keylog_path:   const u8[:],
    client_random: const u8[32]&,
    ks:            const KeySchedule&,
) {
    guard keylog_path.len > 0 else { return; }
    let hlen = ks.hash_len as i64;
    guard hlen == 32 || hlen == 48 else { return; }
    var buf: u8[..1024] = [];
    defer core::secure_zeroize_slice(buf[..]);
    guard append_keylog_secret_line(
        buf, "CLIENT_HANDSHAKE_TRAFFIC_SECRET", client_random, ks.client_hs_traffic[..hlen],
    ) && append_keylog_secret_line(
        buf, "SERVER_HANDSHAKE_TRAFFIC_SECRET", client_random, ks.server_hs_traffic[..hlen],
    ) else { return; }
    let _ = append_file(keylog_path, buf[..]);
}

// Appends TLS 1.3 application traffic and exporter secrets in NSS Key Log Format to `keylog_path`.
// No-op when `keylog_path` is empty.
fn emit_tls13_app_keylog(
    keylog_path:   const u8[:],
    client_random: const u8[32]&,
    ks:            const KeySchedule&,
) {
    guard keylog_path.len > 0 else { return; }
    let hlen = ks.hash_len as i64;
    guard hlen == 32 || hlen == 48 else { return; }
    var buf: u8[..1024] = [];
    defer core::secure_zeroize_slice(buf[..]);
    guard append_keylog_secret_line(
        buf, "CLIENT_TRAFFIC_SECRET_0", client_random, ks.client_ap_traffic[..hlen],
    ) && append_keylog_secret_line(
        buf, "SERVER_TRAFFIC_SECRET_0", client_random, ks.server_ap_traffic[..hlen],
    ) && append_keylog_secret_line(
        buf, "EXPORTER_SECRET", client_random, ks.exporter_secret[..hlen],
    ) else { return; }
    let _ = append_file(keylog_path, buf[..]);
}
