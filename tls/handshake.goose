// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Deterministic zero-allocation TLS 1.3 Handshake State Machine and Extensions.
// Conforms to RFC 8446 Sections 4 and 4.4, RFC 9001 (QUIC), RFC 6066 (SNI), and RFC 7301 (ALPN).
namespace wing;

import std;
import core from "..";
import .record;
import .key_schedule;
import .x509;
import .post_quantum;
import .cert_compression;

// ---- 1. Handshake Message Types (RFC 8446 Section 4) ------------------------

const HS_MSG_CLIENT_HELLO:           u8 = 1;
const HS_MSG_SERVER_HELLO:           u8 = 2;
const HS_MSG_NEW_SESSION_TICKET:     u8 = 4;
const HS_MSG_END_OF_EARLY_DATA:      u8 = 5;
const HS_MSG_ENCRYPTED_EXTENSIONS:   u8 = 8;
const HS_MSG_CERTIFICATE:            u8 = 11;
const HS_MSG_CERTIFICATE_REQUEST:    u8 = 13;
const HS_MSG_CERTIFICATE_VERIFY:     u8 = 15;
const HS_MSG_FINISHED:               u8 = 20;
const HS_MSG_KEY_UPDATE:             u8 = 24;
const HS_MSG_COMPRESSED_CERTIFICATE: u8 = 25; // RFC 8879 Section 4
const HS_MSG_MESSAGE_HASH:           u8 = 254; // 0xFE synthetic HRR message

// ---- 2. Extension Type Identifiers ------------------------------------------

const EXT_SERVER_NAME:               u16 = 0; // RFC 6066
const EXT_STATUS_REQUEST:            u16 = 5; // OCSP stapling
const EXT_SUPPORTED_GROUPS:          u16 = 10;
const EXT_SIGNATURE_ALGORITHMS:      u16 = 13;
const EXT_ALPN:                      u16 = 16; // RFC 7301
const EXT_COMPRESS_CERTIFICATE:      u16 = 27; // RFC 8879 Section 3
const EXT_PRE_SHARED_KEY:            u16 = 41;
const EXT_EARLY_DATA:                u16 = 42;
const EXT_SUPPORTED_VERSIONS:        u16 = 43;
const EXT_COOKIE:                    u16 = 44;
const EXT_PSK_KEY_EXCHANGE_MODES:    u16 = 45;
const EXT_CERTIFICATE_AUTHORITIES:   u16 = 47; // RFC 8446 Section 4.2.4
const EXT_KEY_SHARE:                 u16 = 51;
const EXT_QUIC_TRANSPORT_PARAMETERS: u16 = 0x39; // RFC 9001 Section 8.2

// ---- 3. Handshake State ADT and Transitions ---------------------------------

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

fn client_wait_pre_transition(current: HsState, incoming_msg_type: u8, is_hrr: bool) -> HsState, bool {
    if current == HsState.ClientWaitSH {
        if incoming_msg_type == HS_MSG_SERVER_HELLO {
            if is_hrr {
                // RFC 8446 Section 4.1.4: On HRR, client sends ClientHello2 and awaits ServerHello2
                return HsState.ClientWaitSH, true;
            }
            return HsState.ClientWaitEE, true;
        }
    } else if current == HsState.ClientWaitEE {
        if incoming_msg_type == HS_MSG_ENCRYPTED_EXTENSIONS {
            return HsState.ClientWaitCertCr, true;
        }
    }
    return HsState.Closed, false;
}

fn client_wait_cert_cr_transition(incoming_msg_type: u8, is_psk: bool) -> HsState, bool {
    if is_psk {
        // In PSK mode: Certificate and CertificateVerify are omitted; Finished transitions directly to Connected
        if incoming_msg_type == HS_MSG_FINISHED {
            return HsState.Connected, true;
        }
        return HsState.Closed, false;
    }
    if incoming_msg_type == HS_MSG_CERTIFICATE_REQUEST {
        return HsState.ClientWaitCert, true;
    }
    if incoming_msg_type == HS_MSG_CERTIFICATE || incoming_msg_type == HS_MSG_COMPRESSED_CERTIFICATE {
        return HsState.ClientWaitCV, true;
    }
    // Strict RFC 8446 Invariant: Finished received before Certificate/CertificateVerify MUST be rejected
    return HsState.Closed, false;
}

fn client_wait_cert_or_cv_transition(current: HsState, incoming_msg_type: u8) -> HsState, bool {
    if current == HsState.ClientWaitCert {
        if incoming_msg_type == HS_MSG_CERTIFICATE || incoming_msg_type == HS_MSG_COMPRESSED_CERTIFICATE {
            return HsState.ClientWaitCV, true;
        }
    } else if current == HsState.ClientWaitCV {
        if incoming_msg_type == HS_MSG_CERTIFICATE_VERIFY {
            return HsState.ClientWaitFinished, true;
        }
    }
    return HsState.Closed, false;
}

fn client_wait_post_transition(current: HsState, incoming_msg_type: u8) -> HsState, bool {
    if current == HsState.ClientWaitFinished {
        if incoming_msg_type == HS_MSG_FINISHED {
            return HsState.Connected, true;
        }
    } else if current == HsState.Connected {
        // RFC 8446 Section 4.6: Post-handshake messages from server
        if incoming_msg_type == HS_MSG_NEW_SESSION_TICKET || incoming_msg_type == HS_MSG_KEY_UPDATE {
            return HsState.Connected, true;
        }
    }
    return HsState.Closed, false;
}

// Context-aware client state transition validator (RFC 8446 Section 4).
// Enforces:
// - Unexpected messages in wrong state (e.g. Finished before Certificate/CertificateVerify rejected in full handshake).
// - EncryptedExtensions strictly rejected outside ClientWaitEE.
// - Post-handshake: only NewSessionTicket and KeyUpdate accepted from server.
// - HelloRetryRequest: client transitions to ClientWaitSH waiting for ServerHello2 (not ClientWaitEE).
// - Synthetic message_hash (254) strictly rejected from wire.
fn validate_client_handshake_transition(
    current:           HsState,
    incoming_msg_type: u8,
    mode:              HandshakeMode,
    is_hrr:            bool,
) -> HsState, bool {
    guard incoming_msg_type != HS_MSG_MESSAGE_HASH else { return HsState.Closed, false; }
    if current == HsState.ClientWaitSH || current == HsState.ClientWaitEE {
        return client_wait_pre_transition(current, incoming_msg_type, is_hrr);
    }
    if current == HsState.ClientWaitCertCr {
        return client_wait_cert_cr_transition(incoming_msg_type, mode == HandshakeMode.Psk);
    }
    if current == HsState.ClientWaitCert || current == HsState.ClientWaitCV {
        return client_wait_cert_or_cv_transition(current, incoming_msg_type);
    }
    return client_wait_post_transition(current, incoming_msg_type);
}

fn server_wait_initial_transition(
    current:               HsState,
    incoming_msg_type:     u8,
    client_auth_requested: bool,
    early_data_accepted:   EarlyDataAccepted = EarlyDataAccepted.Rejected,
) -> HsState, bool {
    if current == HsState.ServerWaitCH && incoming_msg_type == HS_MSG_CLIENT_HELLO {
        if early_data_accepted == EarlyDataAccepted.Accepted {
            return HsState.ServerWaitEOED, true;
        }
        if client_auth_requested { return HsState.ServerWaitCert, true; }
        return HsState.ServerWaitFinished, true;
    }
    if current == HsState.ServerWaitEOED && incoming_msg_type == HS_MSG_END_OF_EARLY_DATA {
        if client_auth_requested { return HsState.ServerWaitCert, true; }
        return HsState.ServerWaitFinished, true;
    }
    return HsState.Closed, false;
}

fn server_wait_cert_step(incoming_msg_type: u8, client_cert_is_empty: bool) -> HsState, bool {
    if incoming_msg_type == HS_MSG_CERTIFICATE || incoming_msg_type == HS_MSG_COMPRESSED_CERTIFICATE {
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
    if incoming_msg_type == HS_MSG_CERTIFICATE_VERIFY {
        return HsState.ServerWaitFinished, true;
    }
    return HsState.Closed, false;
}

fn server_wait_done_transition(current: HsState, incoming_msg_type: u8) -> HsState, bool {
    if current == HsState.ServerWaitFinished {
        if incoming_msg_type == HS_MSG_FINISHED {
            return HsState.Connected, true;
        }
    } else if current == HsState.Connected {
        // Post-handshake: client MUST NOT send Finished, Certificate, etc. Only KeyUpdate permitted.
        if incoming_msg_type == HS_MSG_KEY_UPDATE {
            return HsState.Connected, true;
        }
    }
    return HsState.Closed, false;
}

// Server state transition validator with client authentication enforcement.
fn validate_server_handshake_transition_auth(
    current:              HsState,
    incoming_msg_type:    u8,
    client_auth:          ClientAuthMode,
    client_cert_is_empty: bool,
) -> HsState, bool {
    guard incoming_msg_type != HS_MSG_MESSAGE_HASH else { return HsState.Closed, false; }
    if current == HsState.ServerWaitCH || current == HsState.ServerWaitEOED {
        return server_wait_initial_transition(
            current, incoming_msg_type, client_auth == ClientAuthMode.Requested,
        );
    }
    if current == HsState.ServerWaitCert {
        return server_wait_cert_step(incoming_msg_type, client_cert_is_empty);
    }
    if current == HsState.ServerWaitCV {
        return server_wait_cv_step(incoming_msg_type, client_cert_is_empty);
    }
    return server_wait_done_transition(current, incoming_msg_type);
}

fn validate_server_handshake_transition(
    current:               HsState,
    incoming_msg_type:     u8,
    client_auth_requested: bool,
    early_data_accepted:   EarlyDataAccepted = EarlyDataAccepted.Rejected,
) -> HsState, bool {
    if current == HsState.ServerWaitCH || current == HsState.ServerWaitEOED {
        return server_wait_initial_transition(
            current,
            incoming_msg_type,
            client_auth_requested,
            early_data_accepted,
        );
    }
    let c_auth = if client_auth_requested { ClientAuthMode.Requested } else { ClientAuthMode.Disabled };
    return validate_server_handshake_transition_auth(
        current,
        incoming_msg_type,
        c_auth,
        false,
    );
}

fn can_client_transition(current: HsState, incoming_msg_type: u8) -> HsState, bool {
    return validate_client_handshake_transition(current, incoming_msg_type, HandshakeMode.Full, false);
}

fn can_server_transition(current: HsState, incoming_msg_type: u8) -> HsState, bool {
    return validate_server_handshake_transition(current, incoming_msg_type, false);
}

// ---- 4. Framing: Handshake Message Header -----------------------------------

// Handshake message header is 4 bytes: [msg_type: 1 byte] || [msg_len: 3 bytes (u24)].
const MAX_HANDSHAKE_MSG_LEN: u32 = 16777215; // 2^24 - 1 (RFC 8446 Section 5.1)

// Validates that fragment length <= 2^24-1 and fits within data buffer.
// RFC 8446 Section 4: message_hash (254 / 0xFE) is synthetic and MUST NOT appear on wire.
// Example:
//   data = [0x01, 0x00, 0x00, 0x04, 0xAA, 0xBB, 0xCC, 0xDD]
//   returns: msg_type = 1, msg_len = 4, ok = true
fn parse_handshake_header(data: const u8[:]) -> u8, u32, bool {
    guard data.len >= 4 else { return 0, 0, false; }
    let msg_type = data[0];
    guard msg_type != HS_MSG_MESSAGE_HASH else { return 0, 0, false; }
    let msg_len = ((data[1] as u32) << 16) | ((data[2] as u32) << 8) | data[3];
    guard msg_len <= MAX_HANDSHAKE_MSG_LEN else { return 0, 0, false; }
    guard (data.len - 4) as u32 >= msg_len else { return 0, 0, false; }
    return msg_type, msg_len, true;
}

// Validates a handshake message header against an explicit record boundary.
// RFC 8446 Section 5.1: Handshake fragment length <= 2^24 - 1 and must match the record payload length.
// RFC 8446 Section 4: message_hash (254 / 0xFE) is synthetic and MUST NOT appear on wire.
fn validate_handshake_record_boundary(data: const u8[:], record_payload_len: i64) -> u8, u32, bool {
    guard data.len >= 4 else { return 0, 0, false; }
    let msg_type = data[0];
    guard msg_type != HS_MSG_MESSAGE_HASH else { return 0, 0, false; }
    let msg_len = ((data[1] as u32) << 16) | ((data[2] as u32) << 8) | data[3];
    guard msg_len <= MAX_HANDSHAKE_MSG_LEN else { return 0, 0, false; }
    guard record_payload_len >= 4 else { return 0, 0, false; }
    guard (record_payload_len - 4) as u32 == msg_len else { return 0, 0, false; }
    guard (data.len - 4) as u32 >= msg_len else { return 0, 0, false; }
    return msg_type, msg_len, true;
}

fn encode_handshake_header(msg_type: u8, msg_len: u32, out: u8[4]&) -> bool {
    guard msg_len <= MAX_HANDSHAKE_MSG_LEN else { return false; }
    out[0] = msg_type;
    out[1] = ((msg_len >> 16) & 0xFF) as u8;
    out[2] = ((msg_len >> 8) & 0xFF) as u8;
    out[3] = (msg_len & 0xFF) as u8;
    return true;
}

// ---- 5. HelloRetryRequest & Synthetic message_hash Compression --------------

// RFC 8446 Section 4.1.3 HelloRetryRequest special random value:
// CF 21 AD 74 7E 00 7E 27 9F 7F 07 E0 EB 10 DC 03 BE 3D 68 A8 63 FE 95 D6 53 0E 32 30 79 28 8A 2D
const HRR_RANDOM: u8[32] = [
    0xCF, 0x21, 0xAD, 0x74, 0x7E, 0x00, 0x7E, 0x27,
    0x9F, 0x7F, 0x07, 0xE0, 0xEB, 0x10, 0xDC, 0x03,
    0xBE, 0x3D, 0x68, 0xA8, 0x63, 0xFE, 0x95, 0xD6,
    0x53, 0x0E, 0x32, 0x30, 0x79, 0x28, 0x8A, 0x2D,
];

fn is_hello_retry_request(server_random: const u8[32]&) -> bool {
    return core::ct_eq_tag32(server_random, HRR_RANDOM);
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

    out[0] = HS_MSG_MESSAGE_HASH;
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
fn validate_hrr_count(current_hrr_count: u8) -> bool {
    return current_hrr_count == 0;
}

// RFC 8446 Section 4.1.4: ServerHello cipher suite MUST strictly match HRR cipher suite.
fn validate_hrr_cipher_suite(hrr_cipher: u16, sh_cipher: u16) -> bool {
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

// ---- Downgrade Sentinel Protection (RFC 8446 Section 4.1.3) -----------------

// RFC 8446 Section 4.1.3 Downgrade Sentinel values
const DOWNGRADE_SENTINEL_TLS12: u8[8] = [0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01]; // "DOWNGRD\x01"
const DOWNGRADE_SENTINEL_TLS11: u8[8] = [0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x00]; // "DOWNGRD\x00"

// Returns true if the last 8 bytes of server_random match DOWNGRD\x01 or DOWNGRD\x00
fn has_downgrade_sentinel(server_random: const u8[32]&) -> bool {
    let last8 = server_random[24..32];
    var is_tls12 = true;
    var is_tls11 = true;
    for i in 8 {
        if last8[i] != DOWNGRADE_SENTINEL_TLS12[i] { is_tls12 = false; }
        if last8[i] != DOWNGRADE_SENTINEL_TLS11[i] { is_tls11 = false; }
    }
    return is_tls12 || is_tls11;
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
    if negotiated_version == TLS13_VERSION {
        // In TLS 1.3, sentinel MUST NOT be present
        return !sentinel_present;
    } else if negotiated_version <= 0x0303 {
        // In TLS 1.2 or below, if client offered TLS 1.3 and sees sentinel, abort!
        if client_supports_tls13 && sentinel_present {
            return false;
        }
    }
    return true;
}

// ---- Cipher Suite Restrictions (RFC 8446 Section 4.1.2 & Appendix B.4) ------

const TLS_CIPHER_AES_128_GCM_SHA256:       u16 = 0x1301;
const TLS_CIPHER_AES_256_GCM_SHA384:       u16 = 0x1302;
const TLS_CIPHER_CHACHA20_POLY1305_SHA256: u16 = 0x1303;
const TLS_CIPHER_AES_128_CCM_SHA256:       u16 = 0x1304;
const TLS_CIPHER_AES_128_CCM_8_SHA256:     u16 = 0x1305;

// Validates that a cipher suite is a recognized TLS 1.3 cipher suite (RFC 8446 Appendix B.4).
fn is_supported_tls13_cipher_suite(cs: u16) -> bool {
    return cs == TLS_CIPHER_AES_128_GCM_SHA256 ||
           cs == TLS_CIPHER_AES_256_GCM_SHA384 ||
           cs == TLS_CIPHER_CHACHA20_POLY1305_SHA256 ||
           cs == TLS_CIPHER_AES_128_CCM_SHA256 ||
           cs == TLS_CIPHER_AES_128_CCM_8_SHA256;
}

// Validates server-selected cipher suite against client-offered cipher suites and TLS 1.3 rules (RFC 8446 §4.1.3).
fn validate_server_cipher_suite(
    selected_cs:           u16,
    client_offered_suites: const u16[:],
) -> bool {
    guard is_supported_tls13_cipher_suite(selected_cs) else { return false; }
    return client_offered_suites.contains(selected_cs);
}

// ---- 6. SNI Extension Parser (RFC 6066 Section 3) ---------------------------

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

fn is_sni_digit_or_dot(b: u8) -> bool {
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

fn validate_sni_host_bytes(raw: const u8[:]) -> bool {
    guard raw.len >= 1 && raw.len <= 255 else { return false; }
    guard raw[0] != '.' && raw[raw.len - 1] != '.' else { return false; }
    guard !has_consecutive_dots(raw) else { return false; }
    return !is_ip_literal_or_invalid(raw);
}

fn read_sni_entry(list_cursor: ByteCursor&, found_host_name: bool&, out_sni: u8[..255]&) -> bool {
    var name_type: u8 = 0;
    guard get_u8(list_cursor, name_type) else { return false; }

    var name_bytes = cursor_from(list_cursor.buf[..0]);
    guard get_u16_length_prefixed(list_cursor, name_bytes) else { return false; }

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
    var cursor = cursor_from(ext_bytes);
    var list_cursor = cursor_from(ext_bytes[..0]);
    guard get_u16_length_prefixed(cursor, list_cursor) else { return false; }
    guard cursor_len(list_cursor) > 0 && cursor_len(cursor) == 0 else { return false; }

    var found_host_name = false;

    while cursor_len(list_cursor) > 0 {
        guard read_sni_entry(list_cursor, found_host_name, out_sni) else { return false; }
    }
    return found_host_name;
}

// ---- 7. ALPN Negotiation (RFC 7301) -----------------------------------------

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
    var cursor = cursor_from(alpn_ext_bytes);
    var list_cursor = cursor_from(alpn_ext_bytes[..0]);
    guard get_u16_length_prefixed(cursor, list_cursor) else { return false; }
    // RFC 7301 Section 3.1: ProtocolName protocol_name_list<2..2^16-1>;
    guard cursor_len(list_cursor) >= 2 else { return false; }
    guard cursor_len(cursor) == 0 else { return false; }

    var count = 0;
    while cursor_len(list_cursor) > 0 {
        var proto_cursor = cursor_from(alpn_ext_bytes[..0]);
        guard get_u8_length_prefixed(list_cursor, proto_cursor) else { return false; }
        let proto = proto_cursor.buf;
        guard proto.len >= 1 && proto.len <= 255 else { return false; }
        for b in proto {
            guard b != 0 else { return false; }
        }
        count++;
    }
    return count > 0 && cursor_len(list_cursor) == 0;
}

fn is_valid_alpn_proto(proto: const u8[:]) -> bool {
    guard proto.len >= 1 && proto.len <= 255 else { return false; }
    for b in proto {
        guard b != 0 else { return false; }
    }
    return true;
}

fn is_http11_name(proto: const u8[:]) -> bool {
    guard proto.len == 8 else { return false; }
    return proto[0] == 'h' && proto[1] == 't' && proto[2] == 't' && proto[3] == 'p' &&
           proto[4] == '/' && proto[5] == '1' && proto[6] == '.' && proto[7] == '1';
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
    var cursor = cursor_from(alpn_ext_bytes);
    var list_cursor = cursor_from(alpn_ext_bytes[..0]);
    if !get_u16_length_prefixed(cursor, list_cursor) {
        return NegotiatedAlpn.None;
    }
    // RFC 7301 Section 3.1: ProtocolName protocol_name_list<2..2^16-1>;
    guard cursor_len(list_cursor) >= 2 else { return NegotiatedAlpn.None; }
    // Reject trailing data in extension
    guard cursor_len(cursor) == 0 else { return NegotiatedAlpn.None; }

    var has_h3 = false;
    var has_h2 = false;
    var has_http11 = false;
    var has_any = false;

    while cursor_len(list_cursor) > 0 {
        var proto_cursor = cursor_from(alpn_ext_bytes[..0]);
        if !get_u8_length_prefixed(list_cursor, proto_cursor) {
            return NegotiatedAlpn.None;
        }
        if !match_alpn_protocol(proto_cursor.buf, has_h3, has_h2, has_http11) {
            return NegotiatedAlpn.None;
        }
        has_any = true;
    }

    guard cursor_len(list_cursor) == 0 else { return NegotiatedAlpn.None; }
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
    var cursor = cursor_from(ext_bytes);
    var cookie_len: u16 = 0;
    guard get_u16(cursor, cookie_len) else { return false; }
    guard cookie_len >= 1 else { return false; }
    guard (cursor_len(cursor) as u16) == cookie_len else { return false; }
    guard cookie_len <= out_cookie.cap else { return false; }
    for i in cookie_len {
        out_cookie.push(cursor.buf[i]);
    }
    return true;
}

// Validates a TLS 1.3 certificate_authorities extension (RFC 8446 Section 4.2.4 & OpenSSL #32211).
// authorities<3..2^16-1> strictly forbids vectors smaller than 3 octets.
fn validate_certificate_authorities_extension(ext_bytes: const u8[:]) -> bool {
    // RFC 8446 Section 4.2.4 & OpenSSL #32211: authorities<3..2^16-1> strictly forbids vectors < 3 bytes.
    guard ext_bytes.len >= 5 else { return false; }
    var cursor = cursor_from(ext_bytes);
    var authorities_len: u16 = 0;
    guard get_u16(cursor, authorities_len) else { return false; }
    guard authorities_len >= 3 else { return false; }
    guard (cursor_len(cursor) as u16) == authorities_len else { return false; }

    var auth_cursor = cursor_from(cursor.buf);
    while cursor_len(auth_cursor) > 0 {
        var dn_len: u16 = 0;
        guard get_u16(auth_cursor, dn_len) else { return false; }
        // Each DistinguishedName<1..2^16-1> must be at least 1 byte
        guard dn_len >= 1 else { return false; }
        guard cursor_len(auth_cursor) >= dn_len else { return false; }
        auth_cursor.buf = auth_cursor.buf[dn_len..];
    }
    return cursor_len(auth_cursor) == 0;
}

// ---- 8. Extensions Parser Combinator ----------------------------------------

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
    guard entries.len < entries.cap else { return false; }
    entries.push(TlsExtensionEntry {
        ext_type: ext_type,
        data:     data,
    });
    return true;
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
    var cursor = cursor_from(ext_block_bytes);
    var extensions_cursor = cursor_from(ext_block_bytes[..0]);

    if !get_u16_length_prefixed(cursor, extensions_cursor) {
        return false;
    }
    // Trailing bytes after extensions block strictly forbidden
    guard cursor_len(cursor) == 0 else { return false; }

    while cursor_len(extensions_cursor) > 0 {
        var ext_type: u16 = 0;
        if !get_u16(extensions_cursor, ext_type) { return false; }

        var ext_data = cursor_from(ext_block_bytes[..0]);
        if !get_u16_length_prefixed(extensions_cursor, ext_data) { return false; }

        guard check_and_add_extension(entries, ext_type, ext_data.buf) else { return false; }
    }
    guard cursor_len(extensions_cursor) == 0 else { return false; }
    return true;
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

// ---- Supported Versions Extension (RFC 8446 Section 4.2.1) -------------------

fn check_and_add_version(seen_versions: u16[..127]&, ver: u16) -> bool {
    for i in seen_versions.len {
        if seen_versions[i] == ver {
            return false;
        }
    }
    guard seen_versions.len < seen_versions.cap else { return false; }
    seen_versions.push(ver);
    return true;
}

// Parses and validates the ClientHello supported_versions extension (RFC 8446 Section 4.2.1).
// Returns (supports_tls13: bool, ok: bool).
// Rejects malformed lengths, odd byte lengths, empty lists, duplicate versions,
// and trailing garbage.
// Example:
//   ext_bytes = [0x02, 0x03, 0x04]
//   returns: supports_tls13 = true, ok = true
fn parse_client_supported_versions(ext_bytes: const u8[:]) -> bool, bool {
    var cursor = cursor_from(ext_bytes);
    var list_cursor = cursor_from(ext_bytes[..0]);
    guard get_u8_length_prefixed(cursor, list_cursor) else { return false, false; }
    guard cursor_len(cursor) == 0 else { return false, false; }

    let list_len = cursor_len(list_cursor);
    // RFC 8446 Section 4.2.1: versions<2..254>, must be even length
    guard list_len >= 2 && list_len <= 254 && (list_len % 2) == 0 else { return false, false; }

    var seen_versions: u16[..127] = [];
    var has_tls13 = false;

    while cursor_len(list_cursor) > 0 {
        var ver: u16 = 0;
        guard get_u16(list_cursor, ver) else { return false, false; }
        guard check_and_add_version(seen_versions, ver) else { return false, false; }

        if ver == TLS13_VERSION {
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
    var cursor = cursor_from(ext_bytes);
    var selected_ver: u16 = 0;
    guard get_u16(cursor, selected_ver) else { return 0, false; }
    guard cursor_len(cursor) == 0 else { return 0, false; }

    // Strict TLS 1.3 requirement: ServerHello MUST only negotiate TLS 1.3 (0x0304)
    guard selected_ver == TLS13_VERSION else { return 0, false; }
    return selected_ver, true;
}

// ---- 9. RFC 8879 Certificate Compression & ClientHello Fragmentation --------

const CERT_COMPRESS_ZLIB:   u16 = 1;
const CERT_COMPRESS_BROTLI: u16 = 2;
const CERT_COMPRESS_ZSTD:   u16 = 3; // RFC 8879 Section 3 (Zstandard)

struct CompressedCertMsg {
    algorithm:        u16 = CERT_COMPRESS_ZSTD,
    uncompressed_len: u32 = 0,
    compressed_data:  const u8[:],
}

// Encodes the client's `compress_certificate` extension (RFC 8879 Section 3)
fn encode_compress_certificate_extension<B>(out: B&, algorithms: const u16[:]) {
    // RFC 8879 Section 3: algorithms<2..2^8-2>, meaning 1 to 127 algorithms
    guard algorithms.len >= 1 && algorithms.len <= 127 else { return; }

    out.push(((EXT_COMPRESS_CERTIFICATE >> 8) & 0xFF) as u8);
    out.push((EXT_COMPRESS_CERTIFICATE & 0xFF) as u8);

    let ext_len = 1 + algorithms.len * 2;
    out.push(((ext_len >> 8) & 0xFF) as u8);
    out.push((ext_len & 0xFF) as u8);

    let list_len = (algorithms.len * 2) as u8;
    out.push(list_len);
    for algo in algorithms {
        out.push(((algo >> 8) & 0xFF) as u8);
        out.push((algo & 0xFF) as u8);
    }
}

const MAX_UNCOMPRESSED_CERT_LEN: u32 = 65536; // 64 KB decompression ceiling (RFC 8879 DoS / bomb defense)

// Parses a CompressedCertificate handshake message payload (RFC 8879 Section 4)
// Example:
//   payload = [0x00, 0x03, 0x00, 0x01, 0x00, 0x28, 0xB5, 0x2F, 0xFD]
//   returns: msg with algorithm = CERT_COMPRESS_ZSTD, uncompressed_len = 256, ok = true
fn parse_compressed_certificate(payload: const u8[:]) -> CompressedCertMsg, bool {
    var msg = CompressedCertMsg { compressed_data: payload[..0], .. };
    // RFC 8879 Section 4: algorithm (2B) + uncompressed_length (3B) + compressed_data (>= 1B)
    guard payload.len >= 6 else { return msg, false; }

    let algo = ((payload[0] as u16) << 8) | payload[1];
    let is_valid_algo = algo == CERT_COMPRESS_ZLIB || algo == CERT_COMPRESS_BROTLI || algo == CERT_COMPRESS_ZSTD;
    guard is_valid_algo else { return msg, false; }

    let ulen = ((payload[2] as u32) << 16) | ((payload[3] as u32) << 8) | payload[4];
    // RFC 8879 Section 4: uncompressed_length MUST NOT be 0 and MUST NOT exceed bounded buffer ceiling
    guard ulen > 0 && ulen <= MAX_UNCOMPRESSED_CERT_LEN else { return msg, false; }

    let comp_len = (payload.len - 5) as u32;
    // Decompression bomb ratio sanity check (reject expansion ratio > 1024x)
    guard ulen <= comp_len * 1024 else { return msg, false; }

    msg.algorithm = algo;
    msg.uncompressed_len = ulen;
    msg.compressed_data = payload[5..];
    return msg, true;
}

// Encodes a CompressedCertificate handshake message payload (RFC 8879 Section 4)
fn encode_compressed_certificate_payload<B>(
    out:              B&,
    algorithm:        u16,
    uncompressed_len: u32,
    compressed_data:  const u8[:],
) {
    out.push(((algorithm >> 8) & 0xFF) as u8);
    out.push((algorithm & 0xFF) as u8);
    out.push(((uncompressed_len >> 16) & 0xFF) as u8);
    out.push(((uncompressed_len >> 8) & 0xFF) as u8);
    out.push((uncompressed_len & 0xFF) as u8);
    out.append(compressed_data);
}

// Decompresses a CompressedCertificate using Wing's pure RFC 8878 Zstandard engine
fn decompress_certificate_zstd<B>(compressed_data: const u8[:], uncompressed_len: u32, out_cert: B&) -> bool {
    guard uncompressed_len > 0 && uncompressed_len <= MAX_UNCOMPRESSED_CERT_LEN else { return false; }
    let ok, _ = core::zstd_decompress(compressed_data, out_cert);
    guard ok else { return false; }
    guard (out_cert.len as u32) == uncompressed_len else { return false; }
    return true;
}

// RFC 8879 Section 4: Compressed Certificate Handshake Message - Unified decompressor
fn decompress_incoming_certificate<B>(payload: const u8[:], out_cert: B&) -> bool {
    var comp_msg = internal::CompressedCertificate { .. };
    guard internal::parse_compressed_certificate_msg(payload, comp_msg) else { return false; }
    guard comp_msg.uncompressed_length <= MAX_UNCOMPRESSED_CERT_LEN else { return false; }
    return internal::decompress_certificate_payload(
        comp_msg.compressed_certificate_message,
        comp_msg.algorithm,
        comp_msg.uncompressed_length,
        out_cert,
    );
}

// RFC 8446 Section 4.2.7: Supported Groups - Encodes supported_groups extension (type 10)
fn encode_supported_groups_extension<B>(out: B&, groups: const u16[:]) {
    guard groups.len >= 1 && groups.len <= 127 else { return; }
    core::write_be_u16(out, EXT_SUPPORTED_GROUPS);
    let list_len = (groups.len as u16) << 1;
    core::write_be_u16(out, list_len + 2);
    core::write_be_u16(out, list_len);
    for g in groups {
        core::write_be_u16(out, g);
    }
}

// RFC 8446 Section 4.2.7: Supported Groups - Parses supported_groups extension payload
//
// Example:
//   data = [0x00, 0x04, 0x11, 0xEB, 0x11, 0xED]
//   returns: ok = true, out_groups[0..2] = [0x11EB, 0x11ED]
fn parse_supported_groups_extension(
    data:       const u8[:],
    out_groups: u16[..32]&,
) -> bool {
    guard data.len >= 4 else { return false; }
    let list_len = core::read_be_u16(data, 0) as i64;
    guard (list_len & 1) == 0 && data.len == 2 + list_len else { return false; }
    let count = list_len >> 1;
    guard count <= out_groups.cap else { return false; }
    out_groups.clear();
    var offset: i64 = 2;
    for i in count {
        out_groups.push(core::read_be_u16(data, offset));
        offset += 2;
    }
    return true;
}

// RFC 8446 Section 4.2.8: Key Share - Encodes ClientHello key_share extension (type 51)
fn encode_key_share_client_extension<B>(out: B&, client_shares_raw: const u8[:]) {
    guard client_shares_raw.len >= 4 && client_shares_raw.len <= 65535 else { return; }
    core::write_be_u16(out, EXT_KEY_SHARE);
    let list_len = client_shares_raw.len as u16;
    core::write_be_u16(out, list_len + 2);
    core::write_be_u16(out, list_len);
    out.append(client_shares_raw);
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
    guard data.len >= 6 else { return false; }
    let list_len = core::read_be_u16(data, 0) as i64;
    guard list_len >= 4 && data.len == 2 + list_len else { return false; }
    guard list_len <= out_shares.cap else { return false; }
    out_shares.clear();
    out_shares.append(data[2..]);
    return true;
}

// RFC 8446 Section 4.2.8: Key Share - Encodes ServerHello key_share extension (type 51)
fn encode_key_share_server_extension<B>(out: B&, group: u16, key_exchange: const u8[:]) {
    guard key_exchange.len >= 1 && key_exchange.len <= 65535 else { return; }
    core::write_be_u16(out, EXT_KEY_SHARE);
    let kex_len = key_exchange.len as u16;
    core::write_be_u16(out, kex_len + 4);
    core::write_be_u16(out, group);
    core::write_be_u16(out, kex_len);
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
    guard data.len >= 5 else { return false; }
    out_group = core::read_be_u16(data, 0);
    let kex_len = core::read_be_u16(data, 2) as i64;
    guard kex_len >= 1 && data.len == 4 + kex_len else { return false; }
    guard kex_len <= out_key_exchange.cap else { return false; }
    out_key_exchange.clear();
    out_key_exchange.append(data[4..]);
    return true;
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
    guard first_record_len >= 4 && first_record_len <= MAX_RECORD_PLAINTEXT_LEN else { return false; }
    guard first_record_len < raw_ch.len else { return false; }

    let rem_len = raw_ch.len - first_record_len;
    guard rem_len > 0 && rem_len <= MAX_RECORD_PLAINTEXT_LEN else { return false; }

    // Record 1: type 22 (handshake), legacy version 0x0301 (TLS 1.0)
    out_records.push(22);
    out_records.push(0x03); out_records.push(0x01);
    out_records.push(((first_record_len >> 8) & 0xFF) as u8);
    out_records.push((first_record_len & 0xFF) as u8);
    out_records.append(raw_ch[..first_record_len]);

    // Record 2: type 22 (handshake), legacy version 0x0301 (TLS 1.0)
    out_records.push(22);
    out_records.push(0x03); out_records.push(0x01);
    out_records.push(((rem_len >> 8) & 0xFF) as u8);
    out_records.push((rem_len & 0xFF) as u8);
    out_records.append(raw_ch[first_record_len..]);

    return true;
}

// ---- 10. Post-Handshake NewSessionTicket (RFC 8446 Section 4.6.1) -----------

const MAX_TICKET_LIFETIME_SECS: u32 = 604800; // 7 days (RFC 8446 Section 4.6.1)

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

fn is_forbidden_nst_extension(ext_type: u16) -> bool {
    return match ext_type {
        EXT_SERVER_NAME => true,
        EXT_STATUS_REQUEST => true,
        EXT_SUPPORTED_GROUPS => true,
        EXT_SIGNATURE_ALGORITHMS => true,
        EXT_ALPN => true,
        EXT_COMPRESS_CERTIFICATE => true,
        EXT_PRE_SHARED_KEY => true,
        EXT_SUPPORTED_VERSIONS => true,
        EXT_COOKIE => true,
        EXT_PSK_KEY_EXCHANGE_MODES => true,
        EXT_KEY_SHARE => true,
        EXT_QUIC_TRANSPORT_PARAMETERS => true,
        _ => false,
    };
}

fn read_ticket_early_data(ext_data: ByteCursor&, out: NewSessionTicketMsg&) -> bool {
    // RFC 8446 Section 4.2.10: In NewSessionTicket, early_data MUST be uint32 max_early_data_size
    guard cursor_len(ext_data) == 4 else { return false; }
    var max_size: u32 = 0;
    guard get_u32(ext_data, max_size) else { return false; }
    // RFC 8446 Section 4.2.10: Servers MUST NOT offer early_data with max_early_data_size = 0.
    // Client receiving this MUST terminate connection with illegal_parameter.
    guard max_size > 0 else { return false; }
    guard !out.has_early_data else { return false; }
    out.has_early_data = true;
    out.max_early_data_size = max_size;
    return true;
}

fn read_ticket_extensions(ext_cursor: ByteCursor&, payload: const u8[:], out: NewSessionTicketMsg&) -> bool {
    var seen_types: u16[..16] = [];
    while cursor_len(ext_cursor) > 0 {
        var ext_type: u16 = 0;
        guard get_u16(ext_cursor, ext_type) else { return false; }

        var ext_data = cursor_from(payload[..0]);
        guard get_u16_length_prefixed(ext_cursor, ext_data) else { return false; }

        // RFC 8446 Section 4.2: Extensions MUST NOT contain duplicates
        guard !seen_types.contains(ext_type) else { return false; }
        guard seen_types.len < seen_types.cap else { return false; }
        seen_types.push(ext_type);

        // RFC 8446 Section 4.2 Table 2: Extensions not permitted in NST MUST be rejected
        guard !is_forbidden_nst_extension(ext_type) else { return false; }

        if ext_type == EXT_EARLY_DATA {
            guard read_ticket_early_data(ext_data, out) else { return false; }
        }
    }
    return cursor_len(ext_cursor) == 0;
}

fn read_ticket_nonce(c: ByteCursor&, out: NewSessionTicketMsg&) -> bool {
    var nonce_cursor = cursor_from(c.buf[..0]);
    guard get_u8_length_prefixed(c, nonce_cursor) else { return false; }
    let nonce_len = cursor_len(nonce_cursor);
    guard nonce_len <= 255 && nonce_len <= out.ticket_nonce.cap else { return false; }
    for i in nonce_len {
        out.ticket_nonce.push(nonce_cursor.buf[i]);
    }
    return true;
}

fn read_ticket_bytes(c: ByteCursor&, out: NewSessionTicketMsg&) -> bool {
    var ticket_cursor = cursor_from(c.buf[..0]);
    guard get_u16_length_prefixed(c, ticket_cursor) else { return false; }
    let ticket_len = cursor_len(ticket_cursor);
    guard ticket_len > 0 && ticket_len <= out.ticket.cap else { return false; }
    for i in ticket_len {
        out.ticket.push(ticket_cursor.buf[i]);
    }
    return true;
}

// Parses and validates a NewSessionTicket handshake message payload (RFC 8446 Section 4.6.1).
// Rejects ticket_lifetime > 604800s, empty tickets, nonce length overflow, and malformed early_data.
// Example:
//   payload = [0x00, 0x01, 0x00, 0x00]
//   returns: ok = true, out populated
fn parse_new_session_ticket(payload: const u8[:], out: NewSessionTicketMsg&) -> bool {
    out.ticket_nonce.clear();
    out.ticket.clear();
    out.has_early_data = false;
    out.max_early_data_size = 0;

    var c = cursor_from(payload);
    guard get_u32(c, out.ticket_lifetime) else { return false; }
    // RFC 8446 Section 4.6.1: Servers MUST NOT use lifetime > 7 days (604800s)
    guard out.ticket_lifetime <= MAX_TICKET_LIFETIME_SECS else { return false; }

    guard get_u32(c, out.ticket_age_add) else { return false; }
    guard read_ticket_nonce(c, out) else { return false; }
    guard read_ticket_bytes(c, out) else { return false; }

    var ext_cursor = cursor_from(payload[..0]);
    guard get_u16_length_prefixed(c, ext_cursor) else { return false; }
    guard cursor_len(c) == 0 else { return false; }

    guard read_ticket_extensions(ext_cursor, payload, out) else { return false; }

    // RFC 8446 Section 4.2.10 & 4.6.1: early_data MUST NOT be offered when ticket_lifetime is 0
    guard !(out.ticket_lifetime == 0 && out.has_early_data) else { return false; }

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
    guard ticket.ticket_lifetime <= MAX_TICKET_LIFETIME_SECS else { return false; }

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
    guard ticket_lifetime <= MAX_TICKET_LIFETIME_SECS else { return false; }
    guard ticket_nonce.len <= 255 else { return false; }
    guard ticket.len >= 1 && ticket.len <= 65535 else { return false; }

    // ticket_lifetime
    out.push(((ticket_lifetime >> 24) & 0xFF) as u8);
    out.push(((ticket_lifetime >> 16) & 0xFF) as u8);
    out.push(((ticket_lifetime >> 8) & 0xFF) as u8);
    out.push((ticket_lifetime & 0xFF) as u8);

    // ticket_age_add
    out.push(((ticket_age_add >> 24) & 0xFF) as u8);
    out.push(((ticket_age_add >> 16) & 0xFF) as u8);
    out.push(((ticket_age_add >> 8) & 0xFF) as u8);
    out.push((ticket_age_add & 0xFF) as u8);

    // ticket_nonce<0..255>
    out.push(ticket_nonce.len as u8);
    out.append(ticket_nonce);

    // ticket<1..2^16-1>
    out.push(((ticket.len >> 8) & 0xFF) as u8);
    out.push((ticket.len & 0xFF) as u8);
    out.append(ticket);

    // extensions<0..2^16-2>
    if max_early_data_size > 0 {
        // extension_type: 42 (2B) + ext_len: 4 (2B) + max_early_data_size (4B) = 8 bytes
        out.push(0x00); out.push(0x08); // extensions length = 8
        out.push(((EXT_EARLY_DATA >> 8) & 0xFF) as u8);
        out.push((EXT_EARLY_DATA & 0xFF) as u8);
        out.push(0x00); out.push(0x04);
        out.push(((max_early_data_size >> 24) & 0xFF) as u8);
        out.push(((max_early_data_size >> 16) & 0xFF) as u8);
        out.push(((max_early_data_size >> 8) & 0xFF) as u8);
        out.push((max_early_data_size & 0xFF) as u8);
    } else {
        out.push(0x00); out.push(0x00); // 0 extensions length
    }
    return true;
}

// ---- 11. KeyUpdate Handshake Protocol (RFC 8446 Section 4.6.3) ---------------

const KEY_UPDATE_NOT_REQUESTED:    u8  = 0;
const KEY_UPDATE_REQUESTED:        u8  = 1;
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
    guard req == KEY_UPDATE_NOT_REQUESTED || req == KEY_UPDATE_REQUESTED else { return 0, false; }
    return req, true;
}

// Validates state for KeyUpdate (RFC 8446 Section 4.6.3).
// KeyUpdate is ONLY permitted post-handshake in Connected state.
fn validate_key_update_state(state: HsState) -> bool {
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

    if req == KEY_UPDATE_REQUESTED {
        tracker.pending_response = true;
        return true, true;
    }
    return false, true;
}

// Resets consecutive KeyUpdate counter when application data record is sent or received.
fn on_key_update_app_data(tracker: KeyUpdateTracker&) {
    tracker.consecutive_updates = 0;
}

// Encodes KeyUpdate payload (1 byte).
fn encode_key_update<B>(out: B&, request_update: u8) -> bool {
    guard request_update == KEY_UPDATE_NOT_REQUESTED || request_update == KEY_UPDATE_REQUESTED else { return false; }
    out.push(request_update);
    return true;
}

// ---- 12. CertificateRequest & Client Authentication (RFC 8446 Section 4.3.2) -

struct CertificateRequestMsg {
    context:                  u8[..32]  = [],
    has_signature_algorithms: bool      = false,
    sig_algorithms:           u16[..16] = [],
}

fn read_cert_req_sig_algs(ext_data: ByteCursor&, out: CertificateRequestMsg&) -> bool {
    out.has_signature_algorithms = true;
    var alg_cursor = cursor_from(ext_data.buf[..0]);
    guard get_u16_length_prefixed(ext_data, alg_cursor) else { return false; }
    let bytes_len = cursor_len(alg_cursor);
    guard bytes_len >= 2 && (bytes_len % 2) == 0 else { return false; }
    while cursor_len(alg_cursor) > 0 {
        var alg: u16 = 0;
        guard get_u16(alg_cursor, alg) else { return false; }
        guard out.sig_algorithms.len < out.sig_algorithms.cap else { return false; }
        out.sig_algorithms.push(alg);
    }
    return true;
}

// Parses and validates CertificateRequest message (RFC 8446 Section 4.3.2).
// In initial handshake: context MUST be 0 length. In post-handshake: context MUST be <= 32 bytes.
// signature_algorithms extension is mandatory; absence MUST cause rejection.
fn read_cert_req_context(c: ByteCursor&, is_post_handshake: bool, out: CertificateRequestMsg&) -> bool {
    var ctx_cursor = cursor_from(c.buf[..0]);
    guard get_u8_length_prefixed(c, ctx_cursor) else { return false; }

    let ctx_len = cursor_len(ctx_cursor);
    // RFC 8446 Section 4.3.2: context MUST be <= 32 bytes
    guard ctx_len <= 32 && ctx_len <= out.context.cap else { return false; }
    if !is_post_handshake {
        // RFC 8446 Section 4.3.2: In initial handshake, context MUST be 0 length
        guard ctx_len == 0 else { return false; }
    }
    for i in ctx_len {
        out.context.push(ctx_cursor.buf[i]);
    }
    return true;
}

fn read_cert_req_extensions(ext_cursor: ByteCursor&, payload: const u8[:], out: CertificateRequestMsg&) -> bool {
    while cursor_len(ext_cursor) > 0 {
        var ext_type: u16 = 0;
        guard get_u16(ext_cursor, ext_type) else { return false; }

        var ext_data = cursor_from(payload[..0]);
        guard get_u16_length_prefixed(ext_cursor, ext_data) else { return false; }

        if ext_type == EXT_SIGNATURE_ALGORITHMS {
            guard read_cert_req_sig_algs(ext_data, out) else { return false; }
        } else if ext_type == EXT_CERTIFICATE_AUTHORITIES {
            // RFC 8446 §4.2.4 & OpenSSL #32211: authorities<3..2^16-1> lower bound validation
            guard validate_certificate_authorities_extension(ext_data.buf) else { return false; }
        }
    }
    return cursor_len(ext_cursor) == 0;
}

// Parses and validates CertificateRequest message (RFC 8446 Section 4.3.2).
// In initial handshake: context MUST be 0 length. In post-handshake: context MUST be <= 32 bytes.
// signature_algorithms extension is mandatory; absence MUST cause rejection.
// Example:
//   payload = [0x00, 0x00, 0x08, 0x00, 0x0D, 0x00, 0x04, 0x00, 0x02, 0x04, 0x03]
//   returns: ok = true, out contains sig_algorithms
fn parse_certificate_request(
    payload:           const u8[:],
    is_post_handshake: bool,
    out:               CertificateRequestMsg&,
) -> bool {
    out.context.clear();
    out.has_signature_algorithms = false;
    out.sig_algorithms.clear();

    var c = cursor_from(payload);
    guard read_cert_req_context(c, is_post_handshake, out) else { return false; }

    var ext_cursor = cursor_from(payload[..0]);
    guard get_u16_length_prefixed(c, ext_cursor) else { return false; }
    // RFC 8446 Section 4.3.2: extensions<2..2^16-1>
    guard cursor_len(ext_cursor) >= 2 && cursor_len(c) == 0 else { return false; }

    guard read_cert_req_extensions(ext_cursor, payload, out) else { return false; }

    // RFC 8446 Section 4.3.2: signature_algorithms MUST be present
    guard out.has_signature_algorithms && out.sig_algorithms.len > 0 else { return false; }
    return true;
}

// Parses Certificate message header to inspect certificate_list length (RFC 8446 Section 4.4.2).
// Returns (is_empty: bool, ok: bool).
// Example:
//   payload = [0x00, 0x00, 0x00, 0x00]
//   returns: is_empty = true, ok = true
fn parse_certificate_header_is_empty(payload: const u8[:]) -> bool, bool {
    var c = cursor_from(payload);
    var ctx_cursor = cursor_from(payload[..0]);
    guard get_u8_length_prefixed(c, ctx_cursor) else { return false, false; }
    guard cursor_len(ctx_cursor) <= 32 else { return false, false; }

    guard cursor_len(c) >= 3 else { return false, false; }
    var b0: u8 = 0; var b1: u8 = 0; var b2: u8 = 0;
    guard get_u8(c, b0) && get_u8(c, b1) && get_u8(c, b2) else { return false, false; }
    let list_len = ((b0 as u32) << 16) | ((b1 as u32) << 8) | b2;
    guard (cursor_len(c) as u32) == list_len else { return false, false; }
    return list_len == 0, true;
}

// ---- 13. 0-RTT Early Data State Machine & Recovery (RFC 8446 Section 4.2.10) --

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
fn validate_server_early_data_cipher(psk_cipher: u16, negotiated_cipher: u16) -> bool {
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
        let has_ciphers = ctrl.psk_cipher_suite != 0 && ctrl.negotiated_cipher_suite != 0;
        if has_ciphers && ctrl.psk_cipher_suite != ctrl.negotiated_cipher_suite {
            // OpenSSL Bug #31406 & RFC 8446 §4.2.10: Mismatched cipher suite between PSK and server selection
            // strictly invalidates early_data; client MUST reject and abort.
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
fn early_data_can_send_eoed(ctrl: const EarlyDataController&) -> bool {
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

// ---- 14. Mutual TLS (mTLS) Client Authentication (RFC 8446 Section 4.4.2) ---

fn encode_cert_req_ext_sig_algs<B>(out: B&, sig_algorithms: const u16[:]) {
    core::append_u16_be(out, EXT_SIGNATURE_ALGORITHMS);
    let algs_bytes_len = (sig_algorithms.len * 2) as u16;
    core::append_u16_be(out, algs_bytes_len + 2);
    core::append_u16_be(out, algs_bytes_len);
    for alg in sig_algorithms {
        core::append_u16_be(out, alg);
    }
}

// Encodes a CertificateRequest handshake message (RFC 8446 §4.3.2).
fn encode_certificate_request<B>(out: B&, context: const u8[:], sig_algorithms: const u16[:]) -> bool {
    guard context.len <= 32 else { return false; }
    out.push(context.len as u8);
    out.append(context);

    var ext_buf: u8[..64] = [];
    encode_cert_req_ext_sig_algs(ext_buf, sig_algorithms);
    core::append_u16_be(out, ext_buf.len as u16);
    out.append(ext_buf[..]);
    return true;
}

// Encodes a client Certificate message (RFC 8446 §4.4.2).
// When cert_der is empty, an empty certificate_list is encoded.
fn encode_client_certificate<B>(out: B&, cert_context: const u8[:], cert_der: const u8[:]) -> bool {
    guard cert_context.len <= 32 else { return false; }
    out.push(cert_context.len as u8);
    out.append(cert_context);

    if cert_der.len == 0 {
        // Empty certificate list (3 zero bytes for u24 length)
        core::append_u24_be(out, 0);
        return true;
    }

    // List length = 3 bytes cert_data len + cert_der.len + 2 bytes extensions len
    let list_len = (cert_der.len + 5) as u32;
    core::append_u24_be(out, list_len);
    core::append_u24_be(out, cert_der.len as u32);
    out.append(cert_der);
    core::append_u16_be(out, 0); // 0 extensions for client cert entry
    return true;
}

// Encodes a client CertificateVerify message (RFC 8446 §4.4.3).
fn encode_client_certificate_verify<B>(out: B&, sig_scheme: u16, signature: const u8[:]) -> bool {
    guard signature.len > 0 && signature.len <= 512 else { return false; }
    core::append_u16_be(out, sig_scheme);
    core::append_u16_be(out, signature.len as u16);
    out.append(signature);
    return true;
}

// Parses CertificateVerify handshake message payload (RFC 8446 §4.4.3).
// Returns (sig_scheme, signature_slice, ok).
// Example:
//   payload = [0x08, 0x07, 0x00, 0x04, 0xAA, 0xBB, 0xCC, 0xDD]
//   returns: sig_scheme = 0x0807, sig = [0xAA, 0xBB, 0xCC, 0xDD], ok = true
fn parse_certificate_verify(payload: const u8[:]) -> u16, const u8[:], bool {
    guard payload.len >= 4 else { return 0, "", false; }
    let sig_scheme = ((payload[0] as u16) << 8) | payload[1];
    let sig_len = (((payload[2] as u16) << 8) | payload[3]) as i64;
    let expected_total = 4 + sig_len;
    guard payload.len == expected_total else { return 0, "", false; }
    return sig_scheme, payload[4..], true;
}

// Verifies a client's digital signature in CertificateVerify (RFC 8446 §4.4.3).
fn verify_client_certificate_verify(
    sig_scheme:      u16,
    signature:       const u8[:],
    client_pubkey:   const u8[:],
    transcript_hash: const u8[:],
) -> bool {
    guard sig_scheme == SIG_SCHEME_ED25519 else { return false; }
    guard client_pubkey.len == 32 && signature.len == 64 else { return false; }

    var pub_arr: u8[32] = [0; 32];
    for i in 32 { pub_arr[i] = client_pubkey[i]; }

    var sig_arr: u8[64] = [0; 64];
    for i in 64 { sig_arr[i] = signature[i]; }

    var msg_buf: u8[160] = [0; 160];
    let msg_len, ok_m = build_certificate_verify_message(false, transcript_hash, msg_buf[..]);
    guard ok_m else { return false; }
    return core::ed25519_verify(pub_arr, msg_buf[..msg_len], sig_arr);
}
