// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal TLS 1.3 handshake wire-codec, extension, HRR, KeyUpdate, and certificate helpers.
namespace tls_internal;

import std;
import core;
import .internal;
import .record;
import .key_schedule;
import .asn1;
import .types;
import .sct;
import .x509;
import .ocsp;
import .crl;
import .pq_ntt_internal;
import .pq_mlkem_internal;
import .cert_compression;
import .handshake_internal;
import .handshake;

// Server state transition validator with client authentication enforcement.
fn validate_server_handshake_transition_auth(
    current:              tls::HsState,
    incoming_msg_type:    u8,
    client_auth:          tls::ClientAuthMode,
    client_cert_is_empty: bool,
    early_data_accepted:  tls::EarlyDataAccepted    = tls::EarlyDataAccepted.Rejected,
    cert_comp:            tls::CertCompressionOffer = tls::CertCompressionOffer.NotOffered,
) -> tls::HsState, bool {
    guard incoming_msg_type != rfc::TLS_HS_MESSAGE_HASH else { return tls::HsState.Closed, false; }
    if current == tls::HsState.ServerWaitCH || current == tls::HsState.ServerWaitEOED {
        return server_wait_initial_transition(
            current, incoming_msg_type, client_auth == tls::ClientAuthMode.Requested, early_data_accepted,
        );
    }
    if current == tls::HsState.ServerWaitCert {
        return server_wait_cert_step(incoming_msg_type, client_cert_is_empty, cert_comp);
    }
    if current == tls::HsState.ServerWaitCV {
        return server_wait_cv_step(incoming_msg_type, client_cert_is_empty);
    }
    return server_wait_done_transition(
        current, incoming_msg_type, client_auth, client_cert_is_empty, cert_comp,
    );
}

// Validates a handshake message header against an explicit record boundary.
// RFC 8446 Section 5.1: Handshake fragment length <= 2^24 - 1 and must match the record payload length.
// RFC 8446 Section 4: message_hash (254 / 0xFE) is synthetic and MUST NOT appear on wire.
fn validate_handshake_record_boundary(data: const u8[:], record_payload_len: i64) -> u8, u32, bool {
    guard record_payload_len >= 4 else { return 0, 0, false; }
    let msg_type, msg_len, ok_hdr = tls::parse_handshake_header(data);
    guard ok_hdr else { return 0, 0, false; }
    let total_msg_len = core::add_sat_i64(msg_len, 4);
    guard total_msg_len <= record_payload_len && data.len >= total_msg_len else { return 0, 0, false; }
    return msg_type, msg_len, true;
}

fn encode_handshake_header(msg_type: u8, msg_len: u32, out: u8[4]&) -> bool {
    guard msg_len <= rfc::MAX_HANDSHAKE_MSG_LEN else { return false; }
    out[0] = msg_type;
    out[1] = ((msg_len >> 16) & 0xFF) as u8;
    out[2] = ((msg_len >> 8) & 0xFF) as u8;
    out[3] = (msg_len & 0xFF) as u8;
    return true;
}

// Generates synthetic message_hash handshake message (RFC 8446 Section 4.4.1):
// struct {
//     HandshakeType msg_type = message_hash (254);
//     uint24 length = Hash.length;
//     opaque hash[Hash.length];
// }
// Output buffer must have capacity >= 4 + hash_len (36 for SHA-256, 52 for SHA-384).
fn compress_hrr_transcript(
    hash_len: u8,
    ch1_hash: const u8[:],
    out:      u8[:],
) -> i64, bool {
    // RFC 8446 Section 4.4.1: TLS 1.3 only permits SHA-256 (32) and SHA-384 (48) transcript hashes
    guard hash_len == 32 || hash_len == 48 else { return 0, false; }
    guard ch1_hash.len == hash_len else { return 0, false; }
    let total_len = core::add_sat_i64(4, hash_len);
    guard out.len >= total_len else { return 0, false; }

    out[0] = rfc::TLS_HS_MESSAGE_HASH;
    out[1] = 0x00;
    out[2] = 0x00;
    out[3] = hash_len;
    core::ct_copy_bytes(out[4..total_len], ch1_hash);
    return total_len, true;
}

// Computes synthetic message_hash directly from raw ClientHello1 bytes (RFC 8446 Section 4.4.1).
fn build_synthetic_message_hash(
    raw_ch1:  const u8[:],
    hash_len: u8,
    out:      u8[:],
) -> i64, bool {
    guard hash_len == 32 || hash_len == 48 else { return 0, false; }
    if hash_len == 32 {
        let h = core::sha256(raw_ch1);
        return compress_hrr_transcript(32, h[..], out);
    } else {
        let h = core::sha384(raw_ch1);
        return compress_hrr_transcript(48, h[..], out);
    }
}

// RFC 8446 Section 4.1.4: Strictly only ONE HelloRetryRequest allowed per handshake.
// Second HRR MUST trigger fatal unexpected_message alert.
inline fn validate_hrr_count(current_hrr_count: u8) -> bool {
    return current_hrr_count == 0;
}

// RFC 8446 Section 4.1.4: ServerHello cipher suite MUST strictly match HRR cipher suite.
inline fn validate_hrr_cipher_suite(hrr_cipher: u16, sh_cipher: u16) -> bool {
    return hrr_cipher != 0 && hrr_cipher == sh_cipher;
}

// RFC 8446 Section 4.1.4: HRR selected_group must be in client's supported_groups
// and MUST NOT be in client's initial key_shares.
fn validate_hrr_selected_group(
    selected_group:          u16,
    client_supported_groups: const u16[:],
    client_initial_shares:   const u16[:],
) -> bool {
    // 1. Must be in supported_groups
    guard client_supported_groups.contains(selected_group) else { return false; }

    // 2. MUST NOT be among the groups for which client already provided a key_share
    guard !client_initial_shares.contains(selected_group) else { return false; }
    return true;
}

// Returns true if the last 8 bytes of server_random match DOWNGRD\x01 or DOWNGRD\x00
inline fn has_downgrade_sentinel(server_random: const u8[32]&) -> bool {
    let last8 = server_random[24..32];
    return core::equal_short(last8, rfc::DOWNGRADE_SENTINEL_TLS12) ||
           core::equal_short(last8, rfc::DOWNGRADE_SENTINEL_TLS11);
}

// Validates server-selected cipher suite against client-offered cipher suites and TLS 1.3 rules (RFC 8446 §4.1.3).
fn validate_server_cipher_suite(
    selected_cs:           u16,
    client_offered_suites: const u16[:],
) -> bool {
    guard rfc::is_supported_tls13_cipher_suite(selected_cs) else { return false; }
    return client_offered_suites.contains(selected_cs);
}

// Validates an ALPN extension per RFC 7301 Section 3.1.
// Checks list bounds (2..2^16-1), non-empty protocol names (1..255), no NUL bytes,
// and no trailing unparsed data.
fn validate_alpn_extension(alpn_ext_bytes: const u8[:]) -> bool {
    var cursor = core::cursor_from(alpn_ext_bytes);
    var list_cursor, ok_l = cursor.read_u16_sub_cursor();
    // RFC 7301 Section 3.1: ProtocolName protocol_name_list<2..2^16-1>;
    guard ok_l && list_cursor.cursor_len() >= 2 && cursor.cursor_len() == 0 else { return false; }

    var count = 0;
    while list_cursor.cursor_len() > 0 {
        let proto_cursor, ok_p = list_cursor.read_u8_sub_cursor();
        guard ok_p else { return false; }
        let proto = proto_cursor.buf;
        guard proto.len >= 1 && proto.len <= 255 && !proto.contains_byte(0) else { return false; }
        count = core::add_sat_i64(count, 1);
    }
    return count > 0 && list_cursor.cursor_len() == 0;
}

// Parses and validates a TLS 1.3 Cookie extension (RFC 8446 Section 4.2.2 & OpenSSL #30868).
// cookie<1..2^16-1> strictly forbids zero-length values.
// Example:
//   ext_bytes = [0x00, 0x04, 0x01, 0x02, 0x03, 0x04]
//   returns: ok = true, out_cookie = [0x01, 0x02, 0x03, 0x04]
fn parse_cookie_extension<B>(ext_bytes: const u8[:], out_cookie: B&) -> bool {
    var committed = false;
    defer if !committed { out_cookie.clear(); };
    // RFC 8446 Section 4.2.2 & OpenSSL #30868: cookie<1..2^16-1> forbids zero-length values.
    guard ext_bytes.len >= 3 else { return false; }
    var cursor = core::cursor_from(ext_bytes);
    let cookie_c, ok = cursor.read_u16_sub_cursor();
    guard ok && cookie_c.buf.len >= 1 && cursor.buf.len == 0 else { return false; }
    guard out_cookie.try_set(cookie_c.buf) else { return false; }
    committed = true;
    return true;
}

// Serializes a TLS 1.3 Cookie extension (RFC 8446 Section 4.2.2) into `out`.
// cookie<1..2^16-1> strictly forbids zero-length values.
fn serialize_cookie_extension<B>(out: B&, cookie: const u8[:]) -> bool {
    guard cookie.len >= 1 && cookie.len <= 65533 else { return false; }
    var b = core::builder_init();
    b.put_u16(rfc::TLS_EXT_COOKIE);
    guard b.start_u16_prefix() && b.start_u16_prefix() else { return false; }
    b.put_bytes(cookie);
    guard b.finish_u16_prefix() && b.finish_u16_prefix() else { return false; }
    return out.try_append(b.buf[..]);
}

// Validates a TLS 1.3 certificate_authorities extension (RFC 8446 Section 4.2.4 & OpenSSL #32211).
// authorities<3..2^16-1> strictly forbids vectors smaller than 3 octets.
fn validate_certificate_authorities_extension(ext_bytes: const u8[:]) -> bool {
    // RFC 8446 Section 4.2.4 & OpenSSL #32211: authorities<3..2^16-1> strictly forbids vectors < 3 bytes.
    guard ext_bytes.len >= 5 else { return false; }
    var cursor = core::cursor_from(ext_bytes);
    let authorities_len, ok_len = cursor.read_u16();
    guard ok_len && authorities_len >= 3 else { return false; }
    var auth_cursor, ok_sub = cursor.read_sub_cursor(authorities_len);
    guard ok_sub && cursor.cursor_len() == 0 else { return false; }

    while auth_cursor.cursor_len() > 0 {
        let dn_cursor, ok_dn = auth_cursor.read_u16_sub_cursor();
        // Each DistinguishedName<1..2^16-1> must be at least 1 byte
        guard ok_dn && dn_cursor.cursor_len() >= 1 else { return false; }
    }
    return auth_cursor.cursor_len() == 0;
}

// Parses and validates the ClientHello supported_versions extension (RFC 8446 Section 4.2.1).
// Returns (supports_tls13: bool, ok: bool).
// Rejects malformed lengths, odd byte lengths, empty lists, duplicate versions,
// and trailing garbage.
// Example:
//   ext_bytes = [0x02, 0x03, 0x04]
//   returns: supports_tls13 = true, ok = true
fn parse_client_supported_versions(ext_bytes: const u8[:]) -> bool, bool {
    var cursor = core::cursor_from(ext_bytes);
    var list_cursor, ok_l = cursor.read_u8_sub_cursor();
    guard ok_l && cursor.cursor_len() == 0 else { return false, false; }

    let list_len = list_cursor.cursor_len();
    // RFC 8446 Section 4.2.1: versions<2..254>, must be even length
    guard list_len >= 2 && list_len <= 254 && (list_len & 1) == 0 else { return false, false; }

    var seen_versions: u16[..127] = [];
    var has_tls13 = false;

    while list_cursor.cursor_len() > 0 {
        var ver: u16 = 0;
        guard list_cursor.get_u16(ver) else { return false, false; }
        guard check_and_add_version(seen_versions, ver) else { return false, false; }

        if ver == rfc::TLS_VERSION_1_3 {
            has_tls13 = true;
        }
    }

    return has_tls13, true;
}

// Parses and validates the ServerHello / HRR supported_versions extension (RFC 8446 Section 4.2.1).
// Returns (selected_version: u16, ok: bool).
// Must be exactly 2 bytes. In TLS 1.3, selected_version MUST be 0x0304.
// Legacy versions (0x0303, 0x0302, 0x0301, 0x0300, 0x0200) are strictly rejected.
// Example:
//   ext_bytes = [0x03, 0x04]
//   returns: selected_version = 0x0304, ok = true
fn parse_server_supported_versions(ext_bytes: const u8[:]) -> u16, bool {
    guard ext_bytes.len == 2 else { return 0, false; }
    var cursor = core::cursor_from(ext_bytes);
    var selected_ver: u16 = 0;
    guard cursor.get_u16(selected_ver) else { return 0, false; }
    guard cursor.cursor_len() == 0 else { return 0, false; }

    // Strict TLS 1.3 requirement: ServerHello MUST only negotiate TLS 1.3 (0x0304)
    guard selected_ver == rfc::TLS_VERSION_1_3 else { return 0, false; }
    return selected_ver, true;
}

// Encodes the client's `compress_certificate` extension (RFC 8879 Section 3)
fn encode_compress_certificate_extension<B>(out: B&, algorithms: const u16[:]) {
    // RFC 8879 Section 3: algorithms<2..2^8-2>, meaning 1 to 127 algorithms
    guard algorithms.len >= 1 && algorithms.len <= 127 else { return; }
    var b = core::builder_init();
    b.put_u16(rfc::TLS_EXT_COMPRESS_CERTIFICATE);
    guard b.start_u16_prefix() && b.start_u8_prefix() else { return; }
    for algo in algorithms {
        b.put_u16(algo);
    }
    guard b.finish_u8_prefix() && b.finish_u16_prefix() else { return; }
    out.append(b.buf[..]);
}

// Parses a CompressedCertificate handshake message payload (RFC 8879 Section 4)
// Example:
//   payload = [0x00, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x04, 0x28, 0xB5, 0x2F, 0xFD]
//   returns: msg with algorithm = CERT_COMPRESS_ZSTD, uncompressed_len = 256, ok = true
fn parse_compressed_certificate(
    payload:       const u8[:],
    offered_algos: const u16[:] = [],
) -> tls::CompressedCertMsg, bool {
    var msg = tls::CompressedCertMsg { compressed_data: payload[..0], .. };
    var ic = CompressedCertificate { .. };
    guard parse_compressed_certificate_msg(payload, ic) else { return msg, false; }
    // RFC 8879 Section 4: Compressed Certificate Message - Selected algorithm MUST belong to the advertised offer list.
    guard offered_algos.len == 0 || offered_algos.contains(ic.algorithm) else { return msg, false; }
    msg.algorithm = ic.algorithm;
    msg.uncompressed_len = ic.uncompressed_length;
    msg.compressed_data = ic.compressed_certificate_message;
    return msg, true;
}

// RFC 8879 Section 4: Compressed Certificate Message - Encodes CompressedCertificate payload and propagates validation failure.
fn encode_compressed_certificate_payload<B>(
    out:              B&,
    algorithm:        u16,
    uncompressed_len: u32,
    compressed_data:  const u8[:],
) -> bool {
    let saved_len = out.len;
    let ic = CompressedCertificate {
        algorithm:                      algorithm,
        uncompressed_length:            uncompressed_len,
        compressed_certificate_message: compressed_data,
    };
    if !encode_compressed_certificate(ic, out) {
        out.resize(saved_len);
        return false;
    }
    return true;
}

// RFC 8879 Section 4: Compressed Certificate Message - Unified decompressor enforcing offered algorithm membership.
fn decompress_incoming_certificate<B>(
    payload:       const u8[:],
    out_cert:      B&,
    offered_algos: const u16[:] = [],
) -> bool {
    var committed = false;
    defer if !committed { out_cert.clear(); };
    var comp_msg = CompressedCertificate { .. };
    guard parse_compressed_certificate_msg(payload, comp_msg) else { return false; }
    guard offered_algos.len == 0 || offered_algos.contains(comp_msg.algorithm) else { return false; }
    guard comp_msg.uncompressed_length <= rfc::MAX_UNCOMPRESSED_CERT_SIZE else { return false; }
    guard decompress_certificate_payload(
        comp_msg.compressed_certificate_message,
        comp_msg.algorithm,
        comp_msg.uncompressed_length,
        out_cert,
    ) else {
        return false;
    }
    committed = true;
    return true;
}

// RFC 8446 Section 4.2.7: Supported Groups - Encodes supported_groups extension (type 10)
fn encode_supported_groups_extension<B>(out: B&, groups: const u16[:]) {
    guard groups.len >= 1 && groups.len <= 127 else { return; }
    out.append_u16_be(rfc::TLS_EXT_SUPPORTED_GROUPS);
    let list_len = core::shl_sat_u64(groups.len as u64, 1) as u16;
    out.append_u16_be(core::add_sat_u64(list_len as u64, 2) as u16);
    out.append_u16_be(list_len);
    for g in groups {
        out.append_u16_be(g);
    }
}

// RFC 8446 Section 4.2.7: Supported Groups - Parses supported_groups extension payload into bounded buffer.
//
// Example:
//   data = [0x00, 0x04, 0x11, 0xEB, 0x11, 0xED]
//   returns: ok = true, out_groups[0..2] = [0x11EB, 0x11ED]
fn parse_supported_groups_extension<G>(
    data:       const u8[:],
    out_groups: G&,
) -> bool {
    var committed = false;
    defer if !committed { out_groups.clear(); };
    var c = core::cursor_from(data);
    var lc, ok_l = c.read_u16_sub_cursor();
    guard ok_l && c.buf.len == 0 && lc.buf.len >= 2 && (lc.buf.len & 1) == 0 else { return false; }
    let count = lc.buf.len >> 1;
    guard count <= out_groups.cap else { return false; }
    out_groups.clear();
    while lc.buf.len > 0 {
        let g, ok_g = lc.read_u16();
        guard ok_g && out_groups.try_push(g) else { return false; }
    }
    committed = true;
    return true;
}

// RFC 8446 Section 4.2.8: Key Share - Parses ClientHello key_share extension payload
//
// Example:
//   data = [0x04, 0xC5, 0x11, 0xEB, 0x04, 0xC1, ... (1221 bytes)]
//   returns: ok = true, out_shares = [0x11, 0xEB, 0x04, 0xC1, ...]
fn parse_key_share_client_extension(
    data:        const u8[:],
    out_shares:  u8[..4096]&,
    allow_empty: bool = false,
) -> bool {
    var committed = false;
    defer if !committed { out_shares.clear(); };
    var c = core::cursor_from(data);
    let shares_c, ok = c.read_u16_sub_cursor();
    guard ok && c.buf.len == 0 && validate_client_key_share_entries(shares_c.buf, allow_empty) else {
        return false;
    }
    guard out_shares.try_set(shares_c.buf) else { return false; }
    committed = true;
    return true;
}

fn apply_hrr_server_hello_exts(
    entries: const tls::ExtensionEntry[..32]&,
    out:     tls::ParsedServerHello&,
) -> bool {
    let ks_data, has_ks = tls::find_extension(entries, rfc::TLS_EXT_KEY_SHARE);
    if has_ks {
        guard ks_data.len == 2 else { return false; }
        out.selected_group = core::read_be_u16(ks_data, 0);
    }
    let cookie_data, has_cookie = tls::find_extension(entries, rfc::TLS_EXT_COOKIE);
    if has_cookie {
        guard parse_cookie_extension(cookie_data, out.hrr_cookie) else { return false; }
    }
    let ech_data, has_ech = tls::find_extension(entries, rfc::EXT_ENCRYPTED_CLIENT_HELLO);
    if has_ech {
        guard ech_data.len == rfc::ECH_ACCEPT_CONFIRM_LEN && out.ech_ext_data.try_set(ech_data) else {
            return false;
        }
        out.has_ech_ext = true;
    }
    return has_ks || has_cookie;
}

fn apply_regular_server_hello_exts(
    entries:  const tls::ExtensionEntry[..32]&,
    rand_arr: const u8[32]&,
    out:      tls::ParsedServerHello&,
) -> bool {
    guard tls::validate_server_random_downgrade(rand_arr, rfc::TLS_VERSION_1_3, true) else { return false; }
    let ks_data, has_ks = tls::find_extension(entries, rfc::TLS_EXT_KEY_SHARE);
    guard has_ks && parse_key_share_server_extension(ks_data, out.selected_group, out.server_share) else {
        return false;
    }
    let psk_data, has_psk = tls::find_extension(entries, rfc::TLS_EXT_PRE_SHARED_KEY);
    if has_psk {
        guard psk_data.len == 2 && core::read_be_u16(psk_data, 0) == 0 else { return false; }
        out.psk_resumed = true;
    }
    return true;
}

fn read_server_hello_preamble(
    payload:  const u8[:],
    rand_arr: u8[32]&,
    out:      tls::ParsedServerHello&,
) -> const u8[:], bool {
    var c = core::cursor_from(payload);
    let hs_type, ok_t = c.read_u8();
    guard ok_t && hs_type == rfc::TLS_HS_SERVER_HELLO else { return "", false; }
    var bc, ok_b = c.read_u24_sub_cursor();
    guard ok_b && c.buf.len == 0 else { return "", false; }

    let ver, ok_v = bc.read_u16();
    guard ok_v && ver == rfc::TLS_LEGACY_VERSION_1_2 else { return "", false; }
    let srv_rand, ok_r = bc.read_sub_cursor(32);
    guard ok_r else { return "", false; }
    core::ct_copy_bytes(rand_arr[..], srv_rand.buf);
    out.is_hrr = tls::is_hello_retry_request(rand_arr);

    let sid_c, ok_sid = bc.read_u8_sub_cursor();
    let cs, ok_cs = bc.read_u16();
    let comp, ok_cm = bc.read_u8();
    guard ok_sid && out.session_id_echo.try_set(sid_c.buf) &&
        ok_cs && rfc::is_supported_tls13_cipher_suite(cs) && ok_cm && comp == 0 else {
        return "", false;
    }
    out.cipher_suite = cs;
    return bc.buf, true;
}

// Splits a TLS ClientHello into multiple TLS records (RFC 8446 Section 5.1).
// This evades naive Middlebox / DPI SNI filtering by splitting the ClientHello record
// across two or more records without altering cryptographic validity.
// Enforces that handshake message headers (4 bytes) MUST NOT be split across records,
// and individual record payloads must not exceed MAX_RECORD_PLAINTEXT_LEN (16384 bytes).
fn fragment_client_hello<B>(
    raw_ch:           const u8[:],
    first_record_len: i64,
    out_records:      B&,
) -> bool {
    // RFC 8446 Section 5.1: Handshake message headers MUST NOT be split across records.
    guard first_record_len >= 4 && first_record_len <= rfc::TLS_MAX_RECORD_PLAINTEXT_LEN else { return false; }
    guard first_record_len < raw_ch.len else { return false; }

    let rem_len = core::sub_sat_i64(raw_ch.len, first_record_len);
    guard rem_len > 0 && rem_len <= rfc::TLS_MAX_RECORD_PLAINTEXT_LEN else { return false; }

    // Record 1: type 22 (handshake), legacy version 0x0301 (TLS 1.0)
    out_records.push(22);
    out_records.append_u16_be(0x0301);
    out_records.append_u16_be(first_record_len as u16);
    out_records.append(raw_ch[..first_record_len]);

    // Record 2: type 22 (handshake), legacy version 0x0301 (TLS 1.0)
    out_records.push(22);
    out_records.append_u16_be(0x0301);
    out_records.append_u16_be(rem_len as u16);
    out_records.append(raw_ch[first_record_len..]);

    return true;
}

// Encodes a NewSessionTicket handshake message payload (RFC 8446 Section 4.6.1).
fn encode_new_session_ticket<B>(
    out:                 B&,
    ticket_lifetime:     u32,
    ticket_age_add:      u32,
    ticket_nonce:        const u8[:],
    ticket:              const u8[:],
    max_early_data_size: u32,
) -> bool {
    guard ticket_lifetime <= rfc::MAX_TICKET_LIFETIME_SECS else { return false; }
    guard ticket_nonce.len <= 255 && ticket.len >= 1 && ticket.len <= 65535 else { return false; }
    // RFC 8446 Section 4.2.10: Early Data Indication - early_data MUST NOT be offered when ticket_lifetime is 0.
    guard !(ticket_lifetime == 0 && max_early_data_size > 0) else { return false; }

    var b = core::builder_init();
    b.put_u32(ticket_lifetime);
    b.put_u32(ticket_age_add);
    guard b.start_u8_prefix() else { return false; }
    b.put_bytes(ticket_nonce);
    guard b.finish_u8_prefix() && b.start_u16_prefix() else { return false; }
    b.put_bytes(ticket);
    guard b.finish_u16_prefix() && b.start_u16_prefix() else { return false; }
    if max_early_data_size > 0 {
        b.put_u16(rfc::TLS_EXT_EARLY_DATA);
        guard b.start_u16_prefix() else { return false; }
        b.put_u32(max_early_data_size);
        guard b.finish_u16_prefix() else { return false; }
    }
    guard b.finish_u16_prefix() else { return false; }
    return out.try_append(b.buf[..]);
}

// Validates state for KeyUpdate (RFC 8446 Section 4.6.3).
// KeyUpdate is ONLY permitted post-handshake in Connected state.
inline fn validate_key_update_state(state: tls::HsState) -> bool {
    return state == tls::HsState.Connected;
}

// Tracks received KeyUpdate, enforces DoS rate limiting, and returns whether an
// update_not_requested response is required.
// Returns (needs_response: bool, ok: bool).
fn track_received_key_update(
    tracker: tls::KeyUpdateTracker&,
    state:   tls::HsState,
    payload: const u8[:],
) -> bool, bool {
    guard validate_key_update_state(state) else { return false, false; }
    let req, ok = tls::parse_key_update(payload);
    guard ok else { return false, false; }

    // DoS Protection: Limit consecutive KeyUpdates without intervening application data
    guard tracker.consecutive_updates < MAX_CONSECUTIVE_KEY_UPDATES else { return false, false; }

    tracker.consecutive_updates = core::add_sat_u32(tracker.consecutive_updates, 1);
    tracker.total_updates = core::add_sat_u32(tracker.total_updates, 1);

    if req == rfc::KEY_UPDATE_REQUESTED {
        tracker.pending_response = true;
        return true, true;
    }
    return false, true;
}

// Resets consecutive KeyUpdate counter when application data record is sent or received.
inline fn on_key_update_app_data(tracker: tls::KeyUpdateTracker&) {
    tracker.consecutive_updates = 0;
}

// Encodes KeyUpdate payload (1 byte).
fn encode_key_update<B>(out: B&, request_update: u8) -> bool {
    let is_valid = request_update == rfc::KEY_UPDATE_NOT_REQUESTED || request_update == rfc::KEY_UPDATE_REQUESTED;
    guard is_valid else { return false; }
    return out.try_push(request_update);
}

// Encodes the client's `post_handshake_auth` extension (RFC 8446 Section 4.2.6).
// The extension_data field of the "post_handshake_auth" extension is zero length.
fn encode_post_handshake_auth_extension<B>(out: B&) {
    out.append_u16_be(rfc::TLS_EXT_POST_HANDSHAKE_AUTH);
    out.append_u16_be(0);
}

fn read_cert_req_extensions(ext_cursor: core::ByteCursor&, out: tls::CertificateRequestMsg&) -> bool {
    var seen_types: u16[..16] = [];
    while ext_cursor.cursor_len() > 0 {
        let ext_type, ok_t = ext_cursor.read_u16();
        var ext_data, ok_d = ext_cursor.read_u16_sub_cursor();
        guard ok_t && ok_d else { return false; }

        // RFC 8446 Section 4.2: Extensions - There MUST NOT be more than one extension
        // of the same type in a given extension block.
        guard !seen_types.contains(ext_type) else { return false; }
        guard seen_types.try_push(ext_type) else { return false; }

        // RFC 8446 Section 4.2: Extensions - If an implementation receives a recognized extension
        // not specified for the message, it MUST abort with an "illegal_parameter" alert.
        guard !rfc::is_forbidden_cert_req_extension(ext_type) else { return false; }

        if ext_type == rfc::TLS_EXT_SIGNATURE_ALGORITHMS {
            guard read_cert_req_sig_algs(ext_data, out) else { return false; }
        } else if ext_type == rfc::TLS_EXT_CERTIFICATE_AUTHORITIES {
            // RFC 8446 Section 4.2.4: Certificate Authorities - authorities<3..2^16-1> lower bound validation
            guard validate_certificate_authorities_extension(ext_data.buf) else { return false; }
        }
    }
    return ext_cursor.cursor_len() == 0;
}

// Parses Certificate message header to inspect certificate_list length (RFC 8446 Section 4.4.2).
// Returns (is_empty: bool, ok: bool).
// Example:
//   payload = [0x00, 0x00, 0x00, 0x00]
//   returns: is_empty = true, ok = true
fn parse_certificate_header_is_empty(payload: const u8[:]) -> bool, bool {
    var c = core::cursor_from(payload);
    let ctx, ok_ctx = c.read_u8_sub_cursor();
    var list_c = core::cursor_from("");
    let ok_list = c.get_u24_length_prefixed(list_c);
    guard ok_ctx && ctx.buf.len <= 255 && ok_list && c.buf.len == 0 else { return false, false; }
    return list_c.buf.len == 0, true;
}

// RFC 8446 Section 4.2.10 & OpenSSL Bug #31406:
// Server MUST verify that the negotiated cipher suite exactly matches the PSK cipher suite before accepting early data.
inline fn validate_server_early_data_cipher(psk_cipher: u16, negotiated_cipher: u16) -> bool {
    return psk_cipher != 0 && negotiated_cipher != 0 && psk_cipher == negotiated_cipher;
}

// Evaluates server EncryptedExtensions for early_data acceptance or rejection (RFC 8446 Section 4.2.10).
// If rejected, discards 0-RTT keys and transitions state cleanly without sending EndOfEarlyData.
fn early_data_on_encrypted_extensions(
    ctrl:              tls::EarlyDataController&,
    ee_has_early_data: bool,
) -> bool {
    guard ctrl.state == tls::EarlyDataState.Offered else { return false; }
    if ee_has_early_data {
        if !validate_server_early_data_cipher(ctrl.psk_cipher_suite, ctrl.negotiated_cipher_suite) {
            // OpenSSL Bug #31406 & RFC 8446 §4.2.10: Mismatched or missing cipher suite
            // between PSK and server selection invalidates early_data.
            ctrl.state = tls::EarlyDataState.Rejected;
            ctrl.keys_discarded = true;
            return false;
        }
        ctrl.state = tls::EarlyDataState.Accepted;
        return true;
    } else {
        // RFC 8446 Section 4.2.10: Server rejected early_data; client MUST discard 0-RTT traffic keys
        ctrl.state = tls::EarlyDataState.Rejected;
        ctrl.keys_discarded = true;
        return true;
    }
}

// Returns true if client is permitted to send EndOfEarlyData (RFC 8446 Section 4.2.10).
// Only permitted when early_data was accepted.
inline fn early_data_can_send_eoed(ctrl: const tls::EarlyDataController&) -> bool {
    return ctrl.state == tls::EarlyDataState.Accepted;
}

// Records an early data record transmission and enforces max_early_data_size bounds.
fn early_data_record_sent(ctrl: tls::EarlyDataController&, record_len: u32) -> bool {
    guard ctrl.state == tls::EarlyDataState.Offered else { return false; }
    let new_total = core::add_sat_u64(ctrl.bytes_sent, record_len);
    guard new_total <= ctrl.max_early_data_size else { return false; }
    ctrl.bytes_sent = new_total as u32;
    return true;
}

// Encodes a single TLS 1.3 CertificateEntry (3-byte length + DER bytes + 0 extensions).
inline fn encode_cert_chain_entry(b: core::ByteBuilder&, cert_der: const u8[:]) -> bool {
    guard b.start_u24_prefix() else { return false; }
    b.put_bytes(cert_der);
    guard b.finish_u24_prefix() else { return false; }
    b.put_u16(0);
    return true;
}

// Encodes a client Certificate message (RFC 8446 §4.4.2) with leaf and optional intermediate certs.
// When leaf_der is empty, an empty certificate_list is encoded.
fn encode_client_certificate_chain<B>(
    out:          B&,
    cert_context: const u8[:],
    leaf_der:     const u8[:],
    chain_ders:   const u8[..4096][:],
) -> bool {
    guard cert_context.len <= 255 else { return false; }

    var b = core::builder_init();
    b.put_u8(cert_context.len as u8);
    b.put_bytes(cert_context);
    guard b.start_u24_prefix() else { return false; }
    if leaf_der.len > 0 {
        guard encode_cert_chain_entry(b, leaf_der) else { return false; }
        for &icert in chain_ders {
            guard icert.len > 0 else { continue; }
            guard encode_cert_chain_entry(b, icert[..]) else { return false; }
        }
    }
    guard b.finish_u24_prefix() else { return false; }
    guard b.buf.len <= (rfc::MAX_HANDSHAKE_MSG_LEN as i64) else { return false; }
    return out.try_append(b.buf[..]);
}

// Verifies a TLS 1.3 digital signature in CertificateVerify (RFC 8446 §4.4.3).
fn verify_certificate_verify_sig(
    sig_scheme: u16,
    signature:  const u8[:],
    pubkey:     const u8[:],
    msg:        const u8[:],
) -> bool {
    if sig_scheme == rfc::SIG_SCHEME_ED25519 {
        guard pubkey.len == 32 && signature.len == 64 else { return false; }
        var pub_arr: u8[32] = [0; 32];
        for i in 32 { pub_arr[i] = pubkey[i]; }
        var sig_arr: u8[64] = [0; 64];
        for i in 64 { sig_arr[i] = signature[i]; }
        return core::ed25519_verify(pub_arr, msg, sig_arr);
    }
    if sig_scheme == rfc::SIG_SCHEME_ECDSA_SECP256R1_SHA256 {
        return core::ecdsa_p256_verify_der(pubkey, msg, signature);
    }
    if sig_scheme == rfc::SIG_SCHEME_ECDSA_SECP384R1_SHA384 {
        return core::ecdsa_p384_verify_der(pubkey, msg, signature);
    }
    if sig_scheme == rfc::SIG_SCHEME_RSA_PSS_RSAE_SHA256 {
        guard is_valid_rsa_pubkey_min_bits(pubkey) else { return false; }
        return core::rsa_pss_sha256_verify_der(pubkey, msg, signature);
    }
    if sig_scheme == rfc::SIG_SCHEME_RSA_PSS_RSAE_SHA384 {
        guard is_valid_rsa_pubkey_min_bits(pubkey) else { return false; }
        return core::rsa_pss_sha384_verify_der(pubkey, msg, signature);
    }
    return false;
}

// Verifies a client's digital signature in CertificateVerify (RFC 8446 §4.4.3).
fn verify_client_certificate_verify(
    sig_scheme:      u16,
    signature:       const u8[:],
    client_pubkey:   const u8[:],
    transcript_hash: const u8[:],
) -> bool {
    var msg_buf: u8[160] = [0; 160];
    let msg_len, ok_m = tls::build_certificate_verify_message(false, transcript_hash, msg_buf[..]);
    guard ok_m else { return false; }
    return verify_certificate_verify_sig(sig_scheme, signature, client_pubkey, msg_buf[..msg_len]);
}

// Encodes the TLS quic_transport_parameters extension `0x0039` (RFC 9001 Section 8.2).
//
// Example:
//   tp_bytes = [0x01, 0x01, 0x00], out = []
//   returns: true, out = [0x00, 0x39, 0x00, 0x03, 0x01, 0x01, 0x00]
fn encode_quic_tp_extension<B>(out: B&, tp_bytes: const u8[:]) -> bool {
    guard tp_bytes.len <= 2048 else { return false; }
    let mark = out.len;
    var committed = false;
    defer if !committed { out.resize(mark); };
    let hdr: u8[4] = [
        ((rfc::TLS_EXT_QUIC_TRANSPORT_PARAMETERS >> 8) & 0xFF) as u8,
        (rfc::TLS_EXT_QUIC_TRANSPORT_PARAMETERS & 0xFF) as u8,
        ((tp_bytes.len >> 8) & 0xFF) as u8,
        (tp_bytes.len & 0xFF) as u8,
    ];
    guard out.try_append(hdr[..]) && out.try_append(tp_bytes) else { return false; }
    committed = true;
    return true;
}
