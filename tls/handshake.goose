// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Deterministic zero-allocation TLS 1.3 Handshake State Machine and Extensions.
// Conforms to RFC 8446 Sections 4 and 4.4, RFC 9001 (QUIC), RFC 6066 (SNI), and RFC 7301 (ALPN).
namespace wing;

import std;
import core from "..";
import .record;
import .key_schedule;
import .asn1;
import .sct;
import .x509;
import .ocsp;
import .crl;
import .post_quantum;
import .cert_compression;

// ---- Handshake State ADT and Transitions ---------------------------------

enum HandshakeMode {
    Full,
    Psk,
}

enum ClientAuthMode {
    Disabled,
    Requested,
}

enum HsState {
    ClientStart,
    ClientWaitSH,
    ClientWaitEE,
    ClientWaitCertCr,
    ClientWaitCert,
    ClientWaitCV,
    ClientWaitFinished,
    ServerWaitCH,
    ServerWaitEOED,
    ServerWaitCert,
    ServerWaitCV,
    ServerWaitFinished,
    Connected,
    Closed,
}

enum EarlyDataAccepted {
    Rejected,
    Accepted,
}

enum PostHandshakeAuth {
    Disabled,
    Offered,
}

enum CertCompressionOffer {
    NotOffered,
    Offered,
}

fn client_wait_pre_transition(current: HsState, incoming_msg_type: u8, is_hrr: bool) -> HsState, bool {
    if current == HsState.ClientWaitSH {
        if incoming_msg_type == rfc::TLS_HS_SERVER_HELLO {
            if is_hrr {
                // RFC 8446 Section 4.1.4: On HRR, client sends ClientHello2 and awaits ServerHello2
                return HsState.ClientWaitSH, true;
            }
            return HsState.ClientWaitEE, true;
        }
    } else if current == HsState.ClientWaitEE {
        if incoming_msg_type == rfc::TLS_HS_ENCRYPTED_EXTENSIONS {
            return HsState.ClientWaitCertCr, true;
        }
    }
    return HsState.Closed, false;
}

// RFC 8879 Section 4: Compressed Certificate Message - Accept CompressedCertificate only when compress_certificate was advertised.
fn client_wait_cert_cr_transition(
    incoming_msg_type: u8,
    is_psk:            bool,
    cert_comp:         CertCompressionOffer = CertCompressionOffer.NotOffered,
) -> HsState, bool {
    if is_psk {
        // In PSK mode: Certificate and CertificateVerify are omitted; Finished transitions directly to Connected
        if incoming_msg_type == rfc::TLS_HS_FINISHED {
            return HsState.Connected, true;
        }
        return HsState.Closed, false;
    }
    if incoming_msg_type == rfc::TLS_HS_CERTIFICATE_REQUEST {
        return HsState.ClientWaitCert, true;
    }
    if incoming_msg_type == rfc::TLS_HS_CERTIFICATE {
        return HsState.ClientWaitCV, true;
    }
    if incoming_msg_type == rfc::TLS_HS_COMPRESSED_CERTIFICATE && cert_comp == CertCompressionOffer.Offered {
        return HsState.ClientWaitCV, true;
    }
    // Strict RFC 8446 Invariant: Finished received before Certificate/CertificateVerify MUST be rejected
    return HsState.Closed, false;
}

fn client_wait_cert_or_cv_transition(
    current:           HsState,
    incoming_msg_type: u8,
    cert_comp:         CertCompressionOffer = CertCompressionOffer.NotOffered,
) -> HsState, bool {
    if current == HsState.ClientWaitCert {
        if incoming_msg_type == rfc::TLS_HS_CERTIFICATE {
            return HsState.ClientWaitCV, true;
        }
        if incoming_msg_type == rfc::TLS_HS_COMPRESSED_CERTIFICATE && cert_comp == CertCompressionOffer.Offered {
            return HsState.ClientWaitCV, true;
        }
    } else if current == HsState.ClientWaitCV {
        if incoming_msg_type == rfc::TLS_HS_CERTIFICATE_VERIFY {
            return HsState.ClientWaitFinished, true;
        }
    }
    return HsState.Closed, false;
}

// RFC 8446 Section 4.2.6: Post-Handshake Client Authentication - Reject post-handshake CertificateRequest unless post_handshake_auth was offered.
fn client_wait_post_transition(
    current:           HsState,
    incoming_msg_type: u8,
    pha:               PostHandshakeAuth = PostHandshakeAuth.Disabled,
) -> HsState, bool {
    if current == HsState.ClientWaitFinished {
        if incoming_msg_type == rfc::TLS_HS_FINISHED {
            return HsState.Connected, true;
        }
    } else if current == HsState.Connected {
        if incoming_msg_type == rfc::TLS_HS_NEW_SESSION_TICKET || incoming_msg_type == rfc::TLS_HS_KEY_UPDATE {
            return HsState.Connected, true;
        }
        if incoming_msg_type == rfc::TLS_HS_CERTIFICATE_REQUEST && pha == PostHandshakeAuth.Offered {
            return HsState.Connected, true;
        }
    }
    return HsState.Closed, false;
}

// Context-aware client state transition validator (RFC 8446 Section 4).
// Enforces:
// - Unexpected messages in wrong state (e.g. Finished before Certificate/CertificateVerify rejected in full handshake).
// - EncryptedExtensions strictly rejected outside ClientWaitEE.
// - Post-handshake: NewSessionTicket and KeyUpdate accepted; CertificateRequest requires PostHandshakeAuth.Offered.
// - HelloRetryRequest: client transitions to ClientWaitSH waiting for ServerHello2 (not ClientWaitEE).
// - Synthetic message_hash (254) strictly rejected from wire.
fn validate_client_handshake_transition(
    current:           HsState,
    incoming_msg_type: u8,
    mode:              HandshakeMode,
    is_hrr:            bool,
    pha:               PostHandshakeAuth    = PostHandshakeAuth.Disabled,
    cert_comp:         CertCompressionOffer = CertCompressionOffer.NotOffered,
) -> HsState, bool {
    guard incoming_msg_type != rfc::TLS_HS_MESSAGE_HASH else { return HsState.Closed, false; }
    if current == HsState.ClientWaitSH || current == HsState.ClientWaitEE {
        return client_wait_pre_transition(current, incoming_msg_type, is_hrr);
    }
    if current == HsState.ClientWaitCertCr {
        return client_wait_cert_cr_transition(incoming_msg_type, mode == HandshakeMode.Psk, cert_comp);
    }
    if current == HsState.ClientWaitCert || current == HsState.ClientWaitCV {
        return client_wait_cert_or_cv_transition(current, incoming_msg_type, cert_comp);
    }
    return client_wait_post_transition(current, incoming_msg_type, pha);
}

fn server_wait_initial_transition(
    current:               HsState,
    incoming_msg_type:     u8,
    client_auth_requested: bool,
    early_data_accepted:   EarlyDataAccepted = EarlyDataAccepted.Rejected,
) -> HsState, bool {
    if current == HsState.ServerWaitCH && incoming_msg_type == rfc::TLS_HS_CLIENT_HELLO {
        if early_data_accepted == EarlyDataAccepted.Accepted {
            return HsState.ServerWaitEOED, true;
        }
        if client_auth_requested { return HsState.ServerWaitCert, true; }
        return HsState.ServerWaitFinished, true;
    }
    if current == HsState.ServerWaitEOED && incoming_msg_type == rfc::TLS_HS_END_OF_EARLY_DATA {
        if client_auth_requested { return HsState.ServerWaitCert, true; }
        return HsState.ServerWaitFinished, true;
    }
    return HsState.Closed, false;
}

fn server_wait_cert_step(
    incoming_msg_type:    u8,
    client_cert_is_empty: bool,
    cert_comp:            CertCompressionOffer = CertCompressionOffer.NotOffered,
) -> HsState, bool {
    let is_cert = incoming_msg_type == rfc::TLS_HS_CERTIFICATE
        || (incoming_msg_type == rfc::TLS_HS_COMPRESSED_CERTIFICATE && cert_comp == CertCompressionOffer.Offered);
    if is_cert {
        if client_cert_is_empty {
            // RFC 8446 Section 4.4.2: If client has no certificates, CertificateVerify is omitted
            return HsState.ServerWaitFinished, true;
        }
        return HsState.ServerWaitCV, true;
    }
    return HsState.Closed, false;
}

fn server_wait_cv_step(incoming_msg_type: u8, client_cert_is_empty: bool) -> HsState, bool {
    if client_cert_is_empty {
        // RFC 8446 Section 4.4.2: Client MUST NOT send CertificateVerify if certificate was empty
        return HsState.Closed, false;
    }
    if incoming_msg_type == rfc::TLS_HS_CERTIFICATE_VERIFY {
        return HsState.ServerWaitFinished, true;
    }
    return HsState.Closed, false;
}

fn server_wait_done_transition(
    current:              HsState,
    incoming_msg_type:    u8,
    client_auth:          ClientAuthMode       = ClientAuthMode.Disabled,
    client_cert_is_empty: bool                 = false,
    cert_comp:            CertCompressionOffer = CertCompressionOffer.NotOffered,
) -> HsState, bool {
    if current == HsState.ServerWaitFinished {
        guard incoming_msg_type == rfc::TLS_HS_FINISHED else { return HsState.Closed, false; }
        return HsState.Connected, true;
    }
    guard current == HsState.Connected else { return HsState.Closed, false; }
    if incoming_msg_type == rfc::TLS_HS_KEY_UPDATE {
        return HsState.Connected, true;
    }
    // RFC 8446 Section 4.4.2: Certificate - Accept post-handshake Certificate only when client auth was requested.
    let is_post_cert = incoming_msg_type == rfc::TLS_HS_CERTIFICATE
        || (incoming_msg_type == rfc::TLS_HS_COMPRESSED_CERTIFICATE && cert_comp == CertCompressionOffer.Offered);
    if is_post_cert && client_auth == ClientAuthMode.Requested {
        let next = if client_cert_is_empty { HsState.ServerWaitFinished } else { HsState.ServerWaitCV };
        return next, true;
    }
    return HsState.Closed, false;
}

// Server state transition validator with client authentication enforcement.
fn validate_server_handshake_transition_auth(
    current:              HsState,
    incoming_msg_type:    u8,
    client_auth:          ClientAuthMode,
    client_cert_is_empty: bool,
    early_data_accepted:  EarlyDataAccepted    = EarlyDataAccepted.Rejected,
    cert_comp:            CertCompressionOffer = CertCompressionOffer.NotOffered,
) -> HsState, bool {
    guard incoming_msg_type != rfc::TLS_HS_MESSAGE_HASH else { return HsState.Closed, false; }
    if current == HsState.ServerWaitCH || current == HsState.ServerWaitEOED {
        return server_wait_initial_transition(
            current, incoming_msg_type, client_auth == ClientAuthMode.Requested, early_data_accepted,
        );
    }
    if current == HsState.ServerWaitCert {
        return server_wait_cert_step(incoming_msg_type, client_cert_is_empty, cert_comp);
    }
    if current == HsState.ServerWaitCV {
        return server_wait_cv_step(incoming_msg_type, client_cert_is_empty);
    }
    return server_wait_done_transition(current, incoming_msg_type, client_auth, client_cert_is_empty, cert_comp);
}

fn validate_server_handshake_transition(
    current:               HsState,
    incoming_msg_type:     u8,
    client_auth_requested: bool,
    early_data_accepted:   EarlyDataAccepted = EarlyDataAccepted.Rejected,
    client_cert_is_empty:  bool              = false,
) -> HsState, bool {
    let c_auth = if client_auth_requested { ClientAuthMode.Requested } else { ClientAuthMode.Disabled };
    return validate_server_handshake_transition_auth(
        current,
        incoming_msg_type,
        c_auth,
        client_cert_is_empty,
        early_data_accepted,
    );
}

fn can_client_transition(current: HsState, incoming_msg_type: u8) -> HsState, bool {
    return validate_client_handshake_transition(current, incoming_msg_type, HandshakeMode.Full, false);
}

fn can_server_transition(current: HsState, incoming_msg_type: u8) -> HsState, bool {
    return validate_server_handshake_transition(current, incoming_msg_type, false);
}

// ---- Framing: Handshake Message Header -----------------------------------

// Handshake message header is 4 bytes: [msg_type: 1 byte] || [msg_len: 3 bytes (u24)].

// Validates that fragment length <= 2^24-1 and fits within data buffer.
// RFC 8446 Section 4: message_hash (254 / 0xFE) is synthetic and MUST NOT appear on wire.
// Example:
//   data = [0x01, 0x00, 0x00, 0x04, 0xAA, 0xBB, 0xCC, 0xDD]
//   returns: msg_type = 1, msg_len = 4, ok = true
fn parse_handshake_header(data: const u8[:]) -> u8, u32, bool {
    guard data.len >= 4 else { return 0, 0, false; }
    var br = core::make_bit_reader(data[..4]);
    let msg_type_bits, ok_t = br.read_bits(8);
    let msg_len_bits, ok_l = br.read_bits(24);
    guard ok_t && ok_l else { return 0, 0, false; }
    let msg_type = msg_type_bits as u8;
    guard msg_type != rfc::TLS_HS_MESSAGE_HASH else { return 0, 0, false; }
    let msg_len = msg_len_bits as u32;
    guard msg_len <= rfc::MAX_HANDSHAKE_MSG_LEN else { return 0, 0, false; }
    guard core::sub_sat_i64(data.len, 4) >= msg_len else { return 0, 0, false; }
    return msg_type, msg_len, true;
}

// Validates a handshake message header against an explicit record boundary.
// RFC 8446 Section 5.1: Handshake fragment length <= 2^24 - 1 and must match the record payload length.
// RFC 8446 Section 4: message_hash (254 / 0xFE) is synthetic and MUST NOT appear on wire.
fn validate_handshake_record_boundary(data: const u8[:], record_payload_len: i64) -> u8, u32, bool {
    guard record_payload_len >= 4 else { return 0, 0, false; }
    let msg_type, msg_len, ok_hdr = parse_handshake_header(data);
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

// ---- HelloRetryRequest & Synthetic message_hash Compression --------------

// RFC 8446 Section 4.1.3 HelloRetryRequest special random value:
// CF 21 AD 74 7E 00 7E 27 9F 7F 07 E0 EB 10 DC 03 BE 3D 68 A8 63 FE 95 D6 53 0E 32 30 79 28 8A 2D
inline fn is_hello_retry_request(server_random: const u8[32]&) -> bool {
    return core::ct_eq_tag32(server_random, rfc::HRR_RANDOM);
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
    let total_len = 4 + (hash_len as i64);
    guard out.len >= total_len else { return 0, false; }

    out[0] = rfc::TLS_HS_MESSAGE_HASH;
    out[1] = 0x00;
    out[2] = 0x00;
    out[3] = hash_len;

    for i in hash_len {
        out[4 + i] = ch1_hash[i];
    }
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

// ---- Downgrade Sentinel Protection (RFC 8446 Section 4.1.3) --------------

// RFC 8446 Section 4.1.3 Downgrade Sentinel values

// Returns true if the last 8 bytes of server_random match DOWNGRD\x01 or DOWNGRD\x00
inline fn has_downgrade_sentinel(server_random: const u8[32]&) -> bool {
    let last8 = server_random[24..32];
    return core::equal_short(last8, rfc::DOWNGRADE_SENTINEL_TLS12) ||
           core::equal_short(last8, rfc::DOWNGRADE_SENTINEL_TLS11);
}

// Validates ServerHello.random downgrade protection (RFC 8446 Section 4.1.3).
// If negotiating TLS 1.3, ServerHello.random MUST NOT contain a downgrade sentinel.
// If a TLS 1.3-capable client negotiates TLS 1.2 or below and observes a sentinel,
// it detects an active MITM downgrade attack and MUST abort.
fn validate_server_random_downgrade(
    server_random:         const u8[32]&,
    negotiated_version:    u16,
    client_supports_tls13: bool,
) -> bool {
    let sentinel_present = has_downgrade_sentinel(server_random);
    if negotiated_version == rfc::TLS_VERSION_1_3 {
        // In TLS 1.3, sentinel MUST NOT be present
        return !sentinel_present;
    } else if negotiated_version <= rfc::TLS_LEGACY_VERSION_1_2 {
        // In TLS 1.2 or below, if client offered TLS 1.3 and sees sentinel, abort!
        if client_supports_tls13 && sentinel_present {
            return false;
        }
    }
    return true;
}

// ---- Cipher Suite Restrictions (RFC 8446 Section 4.1.2 & Appendix B.4) ---

// Validates server-selected cipher suite against client-offered cipher suites and TLS 1.3 rules (RFC 8446 §4.1.3).
fn validate_server_cipher_suite(
    selected_cs:           u16,
    client_offered_suites: const u16[:],
) -> bool {
    guard rfc::is_supported_tls13_cipher_suite(selected_cs) else { return false; }
    return client_offered_suites.contains(selected_cs);
}

// ---- SNI Extension Parser (RFC 6066 Section 3) ---------------------------

// Parses server_name extension:
// struct {
//     ServerName server_name_list<1..2^16-1>;
// } ServerNameList;
// struct {
//     NameType name_type; // 0 = host_name
//     opaque host_name<1..2^16-1>;
// } ServerName;
//
// Validation rules:
// - name_type must be 0 (host_name)
// - host_name length must be 1..255
// - no NUL bytes permitted
// - IPv4 and IPv6 address literals strictly forbidden in host_name (RFC 6066 Section 3)
// - Normalized to ASCII lowercase
fn has_consecutive_dots(raw: const u8[:]) -> bool {
    for i in raw.len - 1 {
        if raw[i] == '.' && raw[i + 1] == '.' { return true; }
    }
    return false;
}

inline fn is_sni_digit_or_dot(b: u8) -> bool {
    return (b >= '0' && b <= '9') || b == '.';
}

fn is_ip_literal_or_invalid(raw: const u8[:]) -> bool {
    guard raw.len > 0 else { return false; }
    var has_colon = false;
    var is_digits_dots = true;
    for b in raw {
        if b == 0 { return true; }
        if b == ':' { has_colon = true; }
        if !is_sni_digit_or_dot(b) {
            is_digits_dots = false;
        }
    }
    return has_colon || is_digits_dots;
}

// RFC 1035 Section 2.3.4: Size limits - Enforces 1..63 byte LDH labels without leading or trailing hyphens.
fn is_valid_sni_ldh_labels(raw: const u8[:]) -> bool {
    var label_len:   u64  = 0;
    var prev_hyphen: bool = false;
    for b in raw {
        if b == '.' {
            guard label_len >= 1 && !prev_hyphen else { return false; }
            label_len = 0;
            prev_hyphen = false;
        } else {
            guard core::is_ascii_alphanumeric(b) || b == '-' else { return false; }
            guard label_len > 0 || b != '-' else { return false; }
            label_len = core::add_sat_u64(label_len, 1);
            guard label_len <= 63 else { return false; }
            prev_hyphen = b == '-';
        }
    }
    return label_len >= 1 && !prev_hyphen;
}

// RFC 6066 Section 3: Server Name Indication - Requires ASCII DNS HostName <= 253 octets without trailing dot.
fn validate_sni_host_bytes(raw: const u8[:]) -> bool {
    guard raw.len >= 1 && raw.len <= 253 else { return false; }
    guard raw[0] != '.' && raw[raw.len - 1] != '.' else { return false; }
    guard !has_consecutive_dots(raw) else { return false; }
    guard !is_ip_literal_or_invalid(raw) else { return false; }
    return is_valid_sni_ldh_labels(raw);
}

fn read_sni_entry(list_cursor: ByteCursor&, found_host_name: bool&, out_sni: u8[..255]&) -> bool {
    let name_type, ok_t = list_cursor.read_u8();
    let name_bytes, ok_n = list_cursor.read_u16_sub_cursor();
    guard ok_t && ok_n else { return false; }

    if name_type == 0 { // host_name
        guard !found_host_name else { return false; }
        guard validate_sni_host_bytes(name_bytes.buf) else { return false; }
        out_sni.clear();
        for b in name_bytes.buf {
            out_sni.push(core::to_lower_ascii_byte(b));
        }
        found_host_name = true;
    }
    return true;
}

// Example:
//   ext_bytes = 0x00 0x0E 0x00 0x00 0x0B "example.com"
//   returns: ok = true, out_sni = "example.com"
fn parse_sni_extension(ext_bytes: const u8[:], out_sni: u8[..255]&) -> bool {
    var cursor = core::cursor_from(ext_bytes);
    var list_cursor, ok_l = cursor.read_u16_sub_cursor();
    guard ok_l && list_cursor.cursor_len() > 0 && cursor.cursor_len() == 0 else { return false; }

    var found_host_name = false;

    while list_cursor.cursor_len() > 0 {
        guard read_sni_entry(list_cursor, found_host_name, out_sni) else { return false; }
    }
    return found_host_name;
}

// ---- ALPN Negotiation (RFC 7301) -----------------------------------------

enum NegotiatedAlpn {
    None,
    H3,
    H2,
    Http11,
    Other,
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
        count++;
    }
    return count > 0 && list_cursor.cursor_len() == 0;
}

inline fn is_valid_alpn_proto(proto: const u8[:]) -> bool {
    return proto.len >= 1 && proto.len <= 255 && !proto.contains_byte(0);
}

inline fn is_http11_name(proto: const u8[:]) -> bool {
    return core::equal_short(proto, "http/1.1");
}

fn match_alpn_protocol(proto: const u8[:], has_h3: bool&, has_h2: bool&, has_http11: bool&) -> bool {
    guard is_valid_alpn_proto(proto) else { return false; }
    if proto.len == 2 && proto[0] == 'h' {
        if proto[1] == '3' { has_h3 = true; return true; }
        if proto[1] == '2' { has_h2 = true; return true; }
    }
    if is_http11_name(proto) {
        has_http11 = true;
    }
    return true;
}

struct AlpnCandidates {
    is_quic:    bool = false,
    has_h3:     bool = false,
    has_h2:     bool = false,
    has_http11: bool = false,
    has_any:    bool = false,
}

fn select_alpn_result(c: AlpnCandidates) -> NegotiatedAlpn {
    if c.is_quic {
        if c.has_h3 { return NegotiatedAlpn.H3; }
        return NegotiatedAlpn.None;
    }
    if c.has_h2 { return NegotiatedAlpn.H2; }
    if c.has_http11 { return NegotiatedAlpn.Http11; }
    if c.has_any { return NegotiatedAlpn.Other; }
    return NegotiatedAlpn.None;
}

// Parses ALPN ProtocolNameList and negotiates best matching protocol.
// For QUIC (is_quic == true): strictly requires "h3" (RFC 9001 Section 8.1).
// For TCP (is_quic == false): prefers "h2", then "http/1.1".
fn negotiate_alpn(alpn_ext_bytes: const u8[:], is_quic: bool) -> NegotiatedAlpn {
    var cursor = core::cursor_from(alpn_ext_bytes);
    var list_cursor, ok_l = cursor.read_u16_sub_cursor();
    // RFC 7301 Section 3.1: ProtocolName protocol_name_list<2..2^16-1>;
    guard ok_l && list_cursor.cursor_len() >= 2 && cursor.cursor_len() == 0 else {
        return NegotiatedAlpn.None;
    }

    var has_h3 = false;
    var has_h2 = false;
    var has_http11 = false;
    var has_any = false;

    while list_cursor.cursor_len() > 0 {
        let proto_cursor, ok_p = list_cursor.read_u8_sub_cursor();
        guard ok_p && match_alpn_protocol(proto_cursor.buf, has_h3, has_h2, has_http11) else {
            return NegotiatedAlpn.None;
        }
        has_any = true;
    }

    guard list_cursor.cursor_len() == 0 else { return NegotiatedAlpn.None; }
    return select_alpn_result(AlpnCandidates {
        is_quic:    is_quic,
        has_h3:     has_h3,
        has_h2:     has_h2,
        has_http11: has_http11,
        has_any:    has_any,
    });
}

// Parses and validates a TLS 1.3 Cookie extension (RFC 8446 Section 4.2.2 & OpenSSL #30868).
// cookie<1..2^16-1> strictly forbids zero-length values.
// Example:
//   ext_bytes = [0x00, 0x04, 0x01, 0x02, 0x03, 0x04]
//   returns: ok = true, out_cookie = [0x01, 0x02, 0x03, 0x04]
fn parse_tls_cookie_extension<B>(ext_bytes: const u8[:], out_cookie: B&) -> bool {
    out_cookie.clear();
    // RFC 8446 Section 4.2.2 & OpenSSL #30868: cookie<1..2^16-1> forbids zero-length values.
    guard ext_bytes.len >= 3 else { return false; }
    var cursor = core::cursor_from(ext_bytes);
    let cookie_c, ok = cursor.read_u16_sub_cursor();
    guard ok && cookie_c.buf.len >= 1 && cursor.buf.len == 0 else { return false; }
    return out_cookie.try_set(cookie_c.buf);
}

// Serializes a TLS 1.3 Cookie extension (RFC 8446 Section 4.2.2) into `out`.
// cookie<1..2^16-1> strictly forbids zero-length values.
fn serialize_tls_cookie_extension<B>(out: B&, cookie: const u8[:]) -> bool {
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

// ---- Extensions Parser Combinator ----------------------------------------

struct TlsExtensionEntry {
    ext_type: u16         = 0,
    data:     const u8[:] = [],
}

fn check_and_add_extension(entries: TlsExtensionEntry[..32]&, ext_type: u16, data: const u8[:]) -> bool {
    for i in entries.len {
        if entries[i].ext_type == ext_type {
            return false;
        }
    }
    return entries.try_push(TlsExtensionEntry {
        ext_type: ext_type,
        data:     data,
    });
}

// Parses extension block into static array of entries without heap allocation.
// RFC 8446 Section 4.2: Endpoints MUST NOT send duplicate extensions in a single message.
// Rejects duplicate extensions, unparsed trailing bytes, and capacity overflow.
// Example:
//   ext_block_bytes = [0x00, 0x08, 0x00, 0x2B, 0x00, 0x04, 0x03, 0x04, 0x03, 0x03]
//   returns: ok = true, entries populated
fn parse_extensions_block(
    ext_block_bytes: const u8[:],
    entries:         TlsExtensionEntry[..32]&,
) -> bool {
    entries.clear();
    var cursor = core::cursor_from(ext_block_bytes);
    var extensions_cursor, ok_ext = cursor.read_u16_sub_cursor();
    // Trailing bytes after extensions block strictly forbidden
    guard ok_ext && cursor.cursor_len() == 0 else { return false; }

    while extensions_cursor.cursor_len() > 0 {
        let ext_type, ok_t = extensions_cursor.read_u16();
        let ext_data, ok_d = extensions_cursor.read_u16_sub_cursor();
        guard ok_t && ok_d && check_and_add_extension(entries, ext_type, ext_data.buf) else {
            return false;
        }
    }
    return extensions_cursor.cursor_len() == 0;
}

// Finds an extension by type in the parsed entries array.
fn find_extension(entries: const TlsExtensionEntry[..32]&, ext_type: u16) -> const u8[:], bool {
    for i in entries.len {
        if entries[i].ext_type == ext_type {
            return entries[i].data, true;
        }
    }
    return "", false;
}

// ---- Supported Versions Extension (RFC 8446 Section 4.2.1) ---------------

fn check_and_add_version(seen_versions: u16[..127]&, ver: u16) -> bool {
    for i in seen_versions.len {
        if seen_versions[i] == ver {
            return false;
        }
    }
    return seen_versions.try_push(ver);
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

// ---- Certificate Compression (RFC 8879) ----------------------------------

struct CompressedCertMsg {
    algorithm:        u16 = rfc::CERT_COMPRESSION_ZSTD,
    uncompressed_len: u32 = 0,
    compressed_data:  const u8[:],
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

// RFC 8879 Section 3: Negotiating Certificate Compression - Parses up to 127 algorithm IDs with rollback.
//
// Example:
//   ext_bytes = [0x04, 0x00, 0x02, 0x00, 0x03]
//   returns: ok = true, out_algos = [2, 3]
fn parse_compress_certificate_ext<A>(ext_bytes: const u8[:], out_algos: A&) -> bool {
    out_algos.clear();
    var committed = false;
    defer if !committed { out_algos.clear(); };
    var c = core::cursor_from(ext_bytes);
    var lc, ok_l = c.read_u8_sub_cursor();
    guard ok_l && c.buf.len == 0 && lc.buf.len >= 2 && (lc.buf.len & 1) == 0 else { return false; }
    while lc.buf.len > 0 {
        let algo, ok_a = lc.read_u16();
        guard ok_a && out_algos.try_push(algo) else { return false; }
    }
    committed = true;
    return true;
}

// Parses a CompressedCertificate handshake message payload (RFC 8879 Section 4)
// Example:
//   payload = [0x00, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x04, 0x28, 0xB5, 0x2F, 0xFD]
//   returns: msg with algorithm = CERT_COMPRESS_ZSTD, uncompressed_len = 256, ok = true
fn parse_compressed_certificate(
    payload:       const u8[:],
    offered_algos: const u16[:] = [],
) -> CompressedCertMsg, bool {
    var msg = CompressedCertMsg { compressed_data: payload[..0], .. };
    var ic = internal::CompressedCertificate { .. };
    guard internal::parse_compressed_certificate_msg(payload, ic) else { return msg, false; }
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
    let ic = internal::CompressedCertificate {
        algorithm:                      algorithm,
        uncompressed_length:            uncompressed_len,
        compressed_certificate_message: compressed_data,
    };
    if !internal::encode_compressed_certificate(ic, out) {
        out.resize(saved_len);
        return false;
    }
    return true;
}

// Decompresses a CompressedCertificate using Wing's pure RFC 8878 Zstandard engine
fn decompress_certificate_zstd<B>(compressed_data: const u8[:], uncompressed_len: u32, out_cert: B&) -> bool {
    guard uncompressed_len > 0 else { return false; }
    return internal::decompress_certificate_zstd(compressed_data, uncompressed_len, out_cert);
}

// RFC 8879 Section 4: Compressed Certificate Message - Unified decompressor enforcing offered algorithm membership.
fn decompress_incoming_certificate<B>(
    payload:       const u8[:],
    out_cert:      B&,
    offered_algos: const u16[:] = [],
) -> bool {
    out_cert.clear();
    var comp_msg = internal::CompressedCertificate { .. };
    guard internal::parse_compressed_certificate_msg(payload, comp_msg) else { return false; }
    guard offered_algos.len == 0 || offered_algos.contains(comp_msg.algorithm) else { return false; }
    guard comp_msg.uncompressed_length <= rfc::MAX_UNCOMPRESSED_CERT_SIZE else { return false; }
    if !internal::decompress_certificate_payload(
        comp_msg.compressed_certificate_message,
        comp_msg.algorithm,
        comp_msg.uncompressed_length,
        out_cert,
    ) {
        out_cert.clear();
        return false;
    }
    return true;
}

// ---- Supported Groups & Key Share Extensions (RFC 8446 Section 4.2.7-8) --

// RFC 8446 Section 4.2.7: Supported Groups - Encodes supported_groups extension (type 10)
fn encode_supported_groups_extension<B>(out: B&, groups: const u16[:]) {
    guard groups.len >= 1 && groups.len <= 127 else { return; }
    out.append_u16_be(rfc::TLS_EXT_SUPPORTED_GROUPS);
    let list_len = (groups.len as u16) << 1;
    out.append_u16_be(list_len + 2);
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
    out_groups.clear();
    var committed = false;
    defer if !committed { out_groups.clear(); };
    var c = core::cursor_from(data);
    var lc, ok_l = c.read_u16_sub_cursor();
    guard ok_l && c.buf.len == 0 && lc.buf.len >= 2 && (lc.buf.len & 1) == 0 else { return false; }
    let count = lc.buf.len >> 1;
    guard count <= out_groups.cap else { return false; }
    while lc.buf.len > 0 {
        let g, ok_g = lc.read_u16();
        guard ok_g && out_groups.try_push(g) else { return false; }
    }
    committed = true;
    return true;
}

// RFC 8446 Section 4.2.8: Key Share - Encodes ClientHello key_share extension (type 51)
fn encode_key_share_client_extension<B>(out: B&, client_shares_raw: const u8[:]) {
    guard client_shares_raw.len >= 4 && client_shares_raw.len <= 65533 else { return; }
    out.append_u16_be(rfc::TLS_EXT_KEY_SHARE);
    let list_len = client_shares_raw.len as u16;
    out.append_u16_be(list_len + 2);
    out.append_u16_be(list_len);
    out.append(client_shares_raw);
}

fn validate_client_key_share_entries(shares: const u8[:]) -> bool {
    guard shares.len >= 5 else { return false; }
    var sc = core::cursor_from(shares);
    var seen_groups: u16[..32] = [];
    while sc.buf.len > 0 {
        let grp, ok_g = sc.read_u16();
        let kex, ok_k = sc.read_u16_prefixed();
        guard ok_g && ok_k && kex.len >= 1 else { return false; }
        guard !seen_groups.contains(grp) && seen_groups.try_push(grp) else { return false; }
    }
    return true;
}

// RFC 8446 Section 4.2.8: Key Share - Parses ClientHello key_share extension payload
//
// Example:
//   data = [0x04, 0xC5, 0x11, 0xEB, 0x04, 0xC1, ... (1221 bytes)]
//   returns: ok = true, out_shares = [0x11, 0xEB, 0x04, 0xC1, ...]
fn parse_key_share_client_extension(
    data:       const u8[:],
    out_shares: u8[..4096]&,
) -> bool {
    out_shares.clear();
    var c = core::cursor_from(data);
    let shares_c, ok = c.read_u16_sub_cursor();
    guard ok && c.buf.len == 0 && validate_client_key_share_entries(shares_c.buf) else {
        return false;
    }
    return out_shares.try_set(shares_c.buf);
}

// RFC 8446 Section 4.2.8: Key Share - Encodes ServerHello key_share extension (type 51)
fn encode_key_share_server_extension<B>(out: B&, group: u16, key_exchange: const u8[:]) {
    guard key_exchange.len >= 1 && key_exchange.len <= 65531 else { return; }
    out.append_u16_be(rfc::TLS_EXT_KEY_SHARE);
    let kex_len = key_exchange.len as u16;
    out.append_u16_be(kex_len + 4);
    out.append_u16_be(group);
    out.append_u16_be(kex_len);
    out.append(key_exchange);
}

// RFC 8446 Section 4.2.8: Key Share - Parses ServerHello key_share extension payload
//
// Example:
//   data = [0x11, 0xEB, 0x04, 0x81, 0x04, ... (1153 bytes)]
//   returns: ok = true, out_group = 0x11EB, out_key_exchange = slice
fn parse_key_share_server_extension(
    data:             const u8[:],
    out_group:        u16&,
    out_key_exchange: u8[..2048]&,
) -> bool {
    var c = core::cursor_from(data);
    let grp, ok_g = c.read_u16();
    let kex_c, ok_k = c.read_u16_sub_cursor();
    guard ok_g && ok_k && c.buf.len == 0 && kex_c.buf.len >= 1 else { return false; }
    guard out_key_exchange.try_set(kex_c.buf) else { return false; }
    out_group = grp;
    return true;
}

// ---- ServerHello & HelloRetryRequest Parser (RFC 8446 Section 4.1.3-4) ---

struct ParsedServerHello {
    cipher_suite:    u16        = 0,
    is_hrr:          bool       = false,
    selected_group:  u16        = 0,
    server_share:    u8[..2048] = [],
    hrr_cookie:      u8[..256]  = [],
    psk_resumed:     bool       = false,
    session_id_echo: u8[..32]   = [],
}

fn validate_sh_or_hrr_extensions(entries: const TlsExtensionEntry[:], is_hrr: bool) -> bool {
    for e in entries {
        if is_hrr {
            guard !rfc::is_forbidden_hrr_extension(e.ext_type) else { return false; }
        } else {
            guard !rfc::is_forbidden_sh_extension(e.ext_type) else { return false; }
        }
    }
    return true;
}

fn apply_hrr_server_hello_exts(
    entries: const TlsExtensionEntry[..32]&,
    out:     ParsedServerHello&,
) -> bool {
    let ks_data, has_ks = find_extension(entries, rfc::TLS_EXT_KEY_SHARE);
    if has_ks {
        guard ks_data.len == 2 else { return false; }
        out.selected_group = core::read_be_u16(ks_data, 0);
    }
    let cookie_data, has_cookie = find_extension(entries, rfc::TLS_EXT_COOKIE);
    if has_cookie {
        guard parse_tls_cookie_extension(cookie_data, out.hrr_cookie) else { return false; }
    }
    return has_ks || has_cookie;
}

fn apply_regular_server_hello_exts(
    entries:  const TlsExtensionEntry[..32]&,
    rand_arr: const u8[32]&,
    out:      ParsedServerHello&,
) -> bool {
    guard validate_server_random_downgrade(rand_arr, rfc::TLS_VERSION_1_3, true) else { return false; }
    let ks_data, has_ks = find_extension(entries, rfc::TLS_EXT_KEY_SHARE);
    guard has_ks && parse_key_share_server_extension(ks_data, out.selected_group, out.server_share) else {
        return false;
    }
    let psk_data, has_psk = find_extension(entries, rfc::TLS_EXT_PRE_SHARED_KEY);
    if has_psk {
        guard psk_data.len == 2 && core::read_be_u16(psk_data, 0) == 0 else { return false; }
        out.psk_resumed = true;
    }
    return true;
}

fn read_server_hello_preamble(
    payload:  const u8[:],
    rand_arr: u8[32]&,
    out:      ParsedServerHello&,
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
    out.is_hrr = is_hello_retry_request(rand_arr);

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

// Parses a live ServerHello or HelloRetryRequest handshake message (RFC 8446 §4.1.3, §4.1.4),
// extracting key_share (or 2-byte HRR selected_group), cookie, and pre_shared_key extensions.
//
// Example:
//   payload = [0x02, 0x00, 0x00, 0x46, 0x03, 0x03, ...32B random..., 0x00, 0x13, 0x01, 0x00, ...]
//   returns: ok = true, out.cipher_suite = 0x1301, out.is_hrr = false
fn parse_live_server_hello(payload: const u8[:], out: ParsedServerHello&) -> bool {
    out = ParsedServerHello { .. };
    var tmp = ParsedServerHello { .. };

    var rand_arr: u8[32] = [0; 32];
    let ext_bytes, ok_pre = read_server_hello_preamble(payload, rand_arr, tmp);
    guard ok_pre else { return false; }

    var entries: TlsExtensionEntry[..32] = [];
    guard parse_extensions_block(ext_bytes, entries) else { return false; }
    guard validate_sh_or_hrr_extensions(entries, tmp.is_hrr) else { return false; }

    let ver_data, has_ver = find_extension(entries, rfc::TLS_EXT_SUPPORTED_VERSIONS);
    guard has_ver else { return false; }
    let negotiated_ver, ok_ver = parse_server_supported_versions(ver_data);
    guard ok_ver && negotiated_ver == rfc::TLS_VERSION_1_3 else { return false; }

    let ok_ext = if tmp.is_hrr {
        apply_hrr_server_hello_exts(entries, tmp)
    } else {
        apply_regular_server_hello_exts(entries, rand_arr, tmp)
    };
    guard ok_ext else { return false; }
    out = tmp;
    return true;
}

// ---- ClientHello Record Fragmentation (RFC 8446 Section 5.1) -------------

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

    let rem_len = raw_ch.len - first_record_len;
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

// ---- Post-Handshake NewSessionTicket (RFC 8446 Section 4.6.1) -----------

struct NewSessionTicketMsg {
    ticket_lifetime:     u32       = 0,
    ticket_age_add:      u32       = 0,
    ticket_nonce:        u8[..255] = [],
    ticket:              u8[..256] = [],
    has_early_data:      bool      = false,
    max_early_data_size: u32       = 0,
}

struct SessionTicketCache {
    tickets:        NewSessionTicketMsg[..8] = [],
    total_received: u32                      = 0,
}

// RFC 8446 Section 4.2: Extensions - Table 2 indicates recognized TLS 1.3 extensions.
fn read_ticket_early_data(ext_data: ByteCursor&, out: NewSessionTicketMsg&) -> bool {
    // RFC 8446 Section 4.2.10: In NewSessionTicket, early_data MUST be uint32 max_early_data_size
    guard ext_data.cursor_len() == 4 else { return false; }
    var max_size: u32 = 0;
    guard ext_data.get_u32(max_size) else { return false; }
    // RFC 8446 Section 4.2.10: Servers MUST NOT offer early_data with max_early_data_size = 0.
    // Client receiving this MUST terminate connection with illegal_parameter.
    guard max_size > 0 else { return false; }
    guard !out.has_early_data else { return false; }
    out.has_early_data = true;
    out.max_early_data_size = max_size;
    return true;
}

fn read_ticket_extensions(ext_cursor: ByteCursor&, out: NewSessionTicketMsg&) -> bool {
    var seen_types: u16[..16] = [];
    while ext_cursor.cursor_len() > 0 {
        let ext_type, ok_t = ext_cursor.read_u16();
        var ext_data, ok_d = ext_cursor.read_u16_sub_cursor();
        guard ok_t && ok_d else { return false; }

        // RFC 8446 Section 4.2: Extensions MUST NOT contain duplicates
        guard !seen_types.contains(ext_type) else { return false; }
        guard seen_types.try_push(ext_type) else { return false; }

        // RFC 8446 Section 4.2 Table 2: Extensions not permitted in NST MUST be rejected
        guard !rfc::is_forbidden_nst_extension(ext_type) else { return false; }

        if ext_type == rfc::TLS_EXT_EARLY_DATA {
            guard read_ticket_early_data(ext_data, out) else { return false; }
        }
    }
    return ext_cursor.cursor_len() == 0;
}

fn read_ticket_nonce(c: ByteCursor&, out: NewSessionTicketMsg&) -> bool {
    let nonce_c, ok = c.read_u8_sub_cursor();
    guard ok else { return false; }
    return out.ticket_nonce.try_set(nonce_c.buf);
}

fn read_ticket_bytes(c: ByteCursor&, out: NewSessionTicketMsg&) -> bool {
    let ticket_c, ok = c.read_u16_sub_cursor();
    guard ok && ticket_c.buf.len > 0 else { return false; }
    return out.ticket.try_set(ticket_c.buf);
}

// Parses and validates a NewSessionTicket handshake message payload (RFC 8446 Section 4.6.1).
// Rejects ticket_lifetime > 604800s, empty tickets, nonce length overflow, and malformed early_data.
// Example:
//   payload = [0x00, 0x01, 0x00, 0x00]
//   returns: ok = true, out populated
fn parse_new_session_ticket(payload: const u8[:], out: NewSessionTicketMsg&) -> bool {
    let saved = out;
    out = NewSessionTicketMsg { .. };
    var committed = false;
    defer if !committed { out = saved; };

    var c = core::cursor_from(payload);
    guard c.get_u32(out.ticket_lifetime) else { return false; }
    // RFC 8446 Section 4.6.1: Servers MUST NOT use lifetime > 7 days (604800s)
    guard out.ticket_lifetime <= rfc::MAX_TICKET_LIFETIME_SECS else { return false; }

    guard c.get_u32(out.ticket_age_add) else { return false; }
    guard read_ticket_nonce(c, out) else { return false; }
    guard read_ticket_bytes(c, out) else { return false; }

    var ext_cursor, ok_ext = c.read_u16_sub_cursor();
    guard ok_ext && c.cursor_len() == 0 else { return false; }

    guard read_ticket_extensions(ext_cursor, out) else { return false; }

    // RFC 8446 Section 4.2.10 & 4.6.1: early_data MUST NOT be offered when ticket_lifetime is 0
    guard !(out.ticket_lifetime == 0 && out.has_early_data) else { return false; }

    committed = true;
    return true;
}

fn has_conflicting_ticket(cache: const SessionTicketCache&, ticket: const NewSessionTicketMsg&) -> bool {
    for i in cache.tickets.len {
        let existing = cache.tickets[i];
        if ticket.ticket_nonce.len > 0 && existing.ticket_nonce.len == ticket.ticket_nonce.len {
            if core::ct_eq_bytes(existing.ticket_nonce[..], ticket.ticket_nonce[..]) {
                return true;
            }
        }
        if ticket.ticket.len > 0 && existing.ticket.len == ticket.ticket.len {
            if core::ct_eq_bytes(existing.ticket[..], ticket.ticket[..]) {
                return true;
            }
        }
    }
    return false;
}

// Stores a validated NewSessionTicket into bounded SessionTicketCache using circular eviction.
// Handles multiple NewSessionTickets without heap allocation or state corruption.
fn cache_session_ticket(cache: SessionTicketCache&, ticket: const NewSessionTicketMsg&) -> bool {
    // RFC 8446 Section 4.6.1: ticket_lifetime == 0 indicates ticket should be discarded immediately
    guard ticket.ticket_lifetime > 0 else { return true; }
    guard ticket.ticket_lifetime <= rfc::MAX_TICKET_LIFETIME_SECS else { return false; }

    // RFC 8446 Section 4.6.1: Each ticket MUST have a unique ticket_nonce on this connection.
    // Reject duplicate nonce or duplicate ticket bytes to prevent post-handshake ticket confusion
    // and resumption PSK collisions in ks_derive_resumption_psk.
    guard !has_conflicting_ticket(cache, ticket) else { return false; }

    cache.total_received++;
    if cache.tickets.len < cache.tickets.cap {
        cache.tickets.push(ticket);
        return true;
    }
    // Shift oldest ticket out
    for i in cache.tickets.len - 1 {
        cache.tickets[i] = cache.tickets[i + 1];
    }
    cache.tickets[cache.tickets.len - 1] = ticket;
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

// ---- KeyUpdate Handshake Protocol (RFC 8446 Section 4.6.3) ---------------

const MAX_CONSECUTIVE_KEY_UPDATES: u32 = 32;

struct KeyUpdateTracker {
    consecutive_updates: u32  = 0,
    pending_response:    bool = false,
    total_updates:       u32  = 0,
}

// Parses and validates a KeyUpdate handshake payload (RFC 8446 Section 4.6.3).
// Payload MUST be exactly 1 byte. Values 2..255 MUST be rejected with illegal_parameter.
// Example:
//   payload = [0x00]
//   returns: req = 0, ok = true
fn parse_key_update(payload: const u8[:]) -> u8, bool {
    guard payload.len == 1 else { return 0, false; }
    let req = payload[0];
    guard req == rfc::KEY_UPDATE_NOT_REQUESTED || req == rfc::KEY_UPDATE_REQUESTED else { return 0, false; }
    return req, true;
}

// Validates state for KeyUpdate (RFC 8446 Section 4.6.3).
// KeyUpdate is ONLY permitted post-handshake in Connected state.
inline fn validate_key_update_state(state: HsState) -> bool {
    return state == HsState.Connected;
}

// Tracks received KeyUpdate, enforces DoS rate limiting, and returns whether an
// update_not_requested response is required.
// Returns (needs_response: bool, ok: bool).
fn track_received_key_update(
    tracker: KeyUpdateTracker&,
    state:   HsState,
    payload: const u8[:],
) -> bool, bool {
    guard validate_key_update_state(state) else { return false, false; }
    let req, ok = parse_key_update(payload);
    guard ok else { return false, false; }

    // DoS Protection: Limit consecutive KeyUpdates without intervening application data
    guard tracker.consecutive_updates < MAX_CONSECUTIVE_KEY_UPDATES else { return false, false; }

    tracker.consecutive_updates++;
    tracker.total_updates++;

    if req == rfc::KEY_UPDATE_REQUESTED {
        tracker.pending_response = true;
        return true, true;
    }
    return false, true;
}

// Resets consecutive KeyUpdate counter when application data record is sent or received.
inline fn on_key_update_app_data(tracker: KeyUpdateTracker&) {
    tracker.consecutive_updates = 0;
}

// Encodes KeyUpdate payload (1 byte).
fn encode_key_update<B>(out: B&, request_update: u8) -> bool {
    let is_valid = request_update == rfc::KEY_UPDATE_NOT_REQUESTED || request_update == rfc::KEY_UPDATE_REQUESTED;
    guard is_valid else { return false; }
    return out.try_push(request_update);
}

// ---- CertificateRequest & Client Authentication (RFC 8446 Section 4.3.2) -

struct CertificateRequestMsg {
    context:                  u8[..255] = [],
    has_signature_algorithms: bool      = false,
    sig_algorithms:           u16[..64] = [],
}

fn read_cert_req_sig_algs(ext_data: ByteCursor&, out: CertificateRequestMsg&) -> bool {
    out.has_signature_algorithms = true;
    var alg_cursor, ok_l = ext_data.read_u16_sub_cursor();
    guard ok_l && ext_data.buf.len == 0 && alg_cursor.buf.len >= 2 && (alg_cursor.buf.len & 1) == 0 else {
        return false;
    }
    while alg_cursor.buf.len > 0 {
        let alg, ok_a = alg_cursor.read_u16();
        guard ok_a && out.sig_algorithms.try_push(alg) else { return false; }
    }
    return true;
}

// Parses and validates CertificateRequest message (RFC 8446 Section 4.3.2).
// In initial handshake: context MUST be 0 length. In post-handshake: context MUST be non-empty and <= 32 bytes.
// signature_algorithms extension is mandatory; absence MUST cause rejection.
fn read_cert_req_context(c: ByteCursor&, is_post_handshake: bool, out: CertificateRequestMsg&) -> bool {
    let ctx_c, ok = c.read_u8_sub_cursor();
    guard ok else { return false; }
    if is_post_handshake {
        // RFC 8446 Section 4.3.2: A post-handshake CertificateRequest context MUST be non-empty
        guard ctx_c.buf.len > 0 else { return false; }
    } else {
        // RFC 8446 Section 4.3.2: In initial handshake, context MUST be 0 length
        guard ctx_c.buf.len == 0 else { return false; }
    }
    return out.context.try_set(ctx_c.buf);
}

// Encodes the client's `post_handshake_auth` extension (RFC 8446 Section 4.2.6).
// The extension_data field of the "post_handshake_auth" extension is zero length.
fn encode_post_handshake_auth_extension<B>(out: B&) {
    out.append_u16_be(rfc::TLS_EXT_POST_HANDSHAKE_AUTH);
    out.append_u16_be(0);
}

fn read_cert_req_extensions(ext_cursor: ByteCursor&, out: CertificateRequestMsg&) -> bool {
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

// Parses and validates CertificateRequest message (RFC 8446 Section 4.3.2).
// In initial handshake: context MUST be 0 length. In post-handshake: context MUST be <= 255 bytes.
// signature_algorithms extension is mandatory; absence MUST cause rejection.
// Example:
//   payload = [0x00, 0x00, 0x08, 0x00, 0x0D, 0x00, 0x04, 0x00, 0x02, 0x04, 0x03]
//   returns: ok = true, out contains sig_algorithms
fn parse_certificate_request(
    payload:           const u8[:],
    is_post_handshake: bool,
    out:               CertificateRequestMsg&,
) -> bool {
    out = CertificateRequestMsg { .. };
    var committed = false;
    defer if !committed { out = CertificateRequestMsg { .. }; };

    var c = core::cursor_from(payload);
    guard read_cert_req_context(c, is_post_handshake, out) else { return false; }

    var ext_cursor, ok_ext = c.read_u16_sub_cursor();
    // RFC 8446 Section 4.3.2: extensions<2..2^16-1>
    guard ok_ext && ext_cursor.cursor_len() >= 2 && c.cursor_len() == 0 else { return false; }

    guard read_cert_req_extensions(ext_cursor, out) else { return false; }

    // RFC 8446 Section 4.3.2: signature_algorithms MUST be present
    guard out.has_signature_algorithms && out.sig_algorithms.len > 0 else { return false; }
    committed = true;
    return true;
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

// ---- 0-RTT Early Data State Machine & Recovery (RFC 8446 Section 4.2.10) --

enum EarlyDataState {
    None,
    Offered,
    Accepted,
    Rejected,
}

struct EarlyDataController {
    state:                   EarlyDataState = EarlyDataState.None,
    keys_discarded:          bool           = false,
    bytes_sent:              u32            = 0,
    max_early_data_size:     u32            = 0,
    psk_cipher_suite:        u16            = 0,
    negotiated_cipher_suite: u16            = 0,
}

// RFC 8446 Section 4.2.10 & OpenSSL Bug #31406:
// Server MUST verify that the negotiated cipher suite exactly matches the PSK cipher suite before accepting early data.
inline fn validate_server_early_data_cipher(psk_cipher: u16, negotiated_cipher: u16) -> bool {
    return psk_cipher != 0 && negotiated_cipher != 0 && psk_cipher == negotiated_cipher;
}

// Evaluates server EncryptedExtensions for early_data acceptance or rejection (RFC 8446 Section 4.2.10).
// If rejected, discards 0-RTT keys and transitions state cleanly without sending EndOfEarlyData.
fn early_data_on_encrypted_extensions(
    ctrl:              EarlyDataController&,
    ee_has_early_data: bool,
) -> bool {
    guard ctrl.state == EarlyDataState.Offered else { return false; }
    if ee_has_early_data {
        if !validate_server_early_data_cipher(ctrl.psk_cipher_suite, ctrl.negotiated_cipher_suite) {
            // OpenSSL Bug #31406 & RFC 8446 §4.2.10: Mismatched or missing cipher suite
            // between PSK and server selection invalidates early_data.
            ctrl.state = EarlyDataState.Rejected;
            ctrl.keys_discarded = true;
            return false;
        }
        ctrl.state = EarlyDataState.Accepted;
        return true;
    } else {
        // RFC 8446 Section 4.2.10: Server rejected early_data; client MUST discard 0-RTT traffic keys
        ctrl.state = EarlyDataState.Rejected;
        ctrl.keys_discarded = true;
        return true;
    }
}

// Returns true if client is permitted to send EndOfEarlyData (RFC 8446 Section 4.2.10).
// Only permitted when early_data was accepted.
inline fn early_data_can_send_eoed(ctrl: const EarlyDataController&) -> bool {
    return ctrl.state == EarlyDataState.Accepted;
}

// Records an early data record transmission and enforces max_early_data_size bounds.
fn early_data_record_sent(ctrl: EarlyDataController&, record_len: u32) -> bool {
    guard ctrl.state == EarlyDataState.Offered else { return false; }
    let new_total = ctrl.bytes_sent + record_len;
    guard new_total >= ctrl.bytes_sent && new_total <= ctrl.max_early_data_size else { return false; }
    ctrl.bytes_sent = new_total;
    return true;
}

// ---- Mutual TLS (mTLS) Client Authentication (RFC 8446 Section 4.4.2) ---

fn encode_cert_req_ext_sig_algs<B>(out: B&, sig_algorithms: const u16[:]) {
    guard sig_algorithms.len >= 1 && sig_algorithms.len <= 64 else { return; }
    out.append_u16_be(rfc::TLS_EXT_SIGNATURE_ALGORITHMS);
    let algs_bytes_len = (sig_algorithms.len * 2) as u16;
    out.append_u16_be(algs_bytes_len + 2);
    out.append_u16_be(algs_bytes_len);
    for alg in sig_algorithms {
        out.append_u16_be(alg);
    }
}

// RFC 8446 Section 4.3.2: Certificate Request - Encodes context<0..2^8-1> and signature_algorithms.
fn encode_certificate_request<B>(out: B&, context: const u8[:], sig_algorithms: const u16[:]) -> bool {
    guard context.len >= 0 && context.len <= 255 else { return false; }
    guard sig_algorithms.len >= 1 && sig_algorithms.len <= 64 else { return false; }
    var ext_buf: u8[..256] = [];
    encode_cert_req_ext_sig_algs(ext_buf, sig_algorithms);
    let req_len = core::add_sat_i64(3, core::add_sat_i64(context.len, ext_buf.len));
    guard core::add_sat_i64(out.len, req_len) <= out.cap else { return false; }

    out.push(context.len as u8);
    out.append(context);
    out.append_u16_be(ext_buf.len as u16);
    out.append(ext_buf[..]);
    return true;
}

// Encodes a client Certificate message (RFC 8446 §4.4.2).
// When cert_der is empty, an empty certificate_list is encoded.
fn encode_client_certificate<B>(out: B&, cert_context: const u8[:], cert_der: const u8[:]) -> bool {
    let max_cert_len = core::sub_sat_i64((rfc::MAX_HANDSHAKE_MSG_LEN as i64) - 4, cert_context.len);
    guard cert_context.len <= 255 && cert_der.len <= max_cert_len else { return false; }

    var b = core::builder_init();
    b.put_u8(cert_context.len as u8);
    b.put_bytes(cert_context);
    guard b.start_u24_prefix() else { return false; }
    if cert_der.len > 0 {
        guard b.start_u24_prefix() else { return false; }
        b.put_bytes(cert_der);
        guard b.finish_u24_prefix() else { return false; }
        b.put_u16(0); // 0 extensions for client cert entry
    }
    guard b.finish_u24_prefix() else { return false; }
    return out.try_append(b.buf[..]);
}

// RFC 8446 Section 4.4.3: Certificate Verify - Rejects forbidden TLS 1.3 signature schemes before encoding.
fn encode_client_certificate_verify<B>(out: B&, sig_scheme: u16, signature: const u8[:]) -> bool {
    guard !rfc::is_forbidden_tls13_sig_scheme(sig_scheme) else { return false; }
    guard signature.len > 0 && signature.len <= 1024 else { return false; }
    guard core::add_sat_i64(out.len, core::add_sat_i64(4, signature.len)) <= out.cap else { return false; }
    out.append_u16_be(sig_scheme);
    out.append_u16_be(signature.len as u16);
    out.append(signature);
    return true;
}

// Parses CertificateVerify handshake message payload (RFC 8446 §4.4.3).
// Returns (sig_scheme, signature_slice, ok).
// Example:
//   payload = [0x08, 0x07, 0x00, 0x04, 0xAA, 0xBB, 0xCC, 0xDD]
//   returns: sig_scheme = 0x0807, sig = [0xAA, 0xBB, 0xCC, 0xDD], ok = true
fn parse_certificate_verify(payload: const u8[:]) -> u16, const u8[:], bool {
    var c = core::cursor_from(payload);
    let sig_scheme, ok_s = c.read_u16();
    let sig, ok_sig = c.read_u16_prefixed();
    guard ok_s && ok_sig && sig.len > 0 &&
        !rfc::is_forbidden_tls13_sig_scheme(sig_scheme) && c.buf.len == 0 else {
        return 0, "", false;
    }
    return sig_scheme, sig, true;
}

// Verifies a TLS 1.3 digital signature in CertificateVerify (RFC 8446 §4.4.3).
fn verify_tls13_certificate_verify_sig(
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
        return core::rsa_pss_sha256_verify_der(pubkey, msg, signature);
    }
    if sig_scheme == rfc::SIG_SCHEME_RSA_PSS_RSAE_SHA384 {
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
    let msg_len, ok_m = build_certificate_verify_message(false, transcript_hash, msg_buf[..]);
    guard ok_m else { return false; }
    return verify_tls13_certificate_verify_sig(sig_scheme, signature, client_pubkey, msg_buf[..msg_len]);
}
