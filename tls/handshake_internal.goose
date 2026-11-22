// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal TLS 1.3 handshake state-machine, extension, and ECH parsing helpers.
namespace tls_internal;

import std;
import core;
import .internal;
import .record;
import .key_schedule;
import .asn1;
import .types;
import .post_quantum;
import .cert_compression;
import security.hpke;

enum EchEntryStatus {
    Accepted,
    SkippedUnsupported,
    Invalid,
}

struct AlpnCandidates {
    is_quic:    bool = false,
    has_h3:     bool = false,
    has_h2:     bool = false,
    has_http11: bool = false,
    has_any:    bool = false,
}

// Reads cipher suites list from ECH contents cursor.
//
// Example:
//   contents = [0x00, 0x04, 0x00, 0x01, 0x00, 0x01], out = EchConfig { .. }
//   returns: ok = true, out.cipher_suites populated
fn read_ech_cipher_suites(contents: core::ByteCursor&, out: tls::EchConfig&) -> bool {
    var cs_cursor = core::ByteCursor { buf: contents.buf[..0] };
    guard contents.get_u16_length_prefixed(cs_cursor) else { return false; }
    guard cs_cursor.cursor_len() >= 4 && (cs_cursor.cursor_len() & 3) == 0 else { return false; }

    out.cipher_suites.clear();
    while cs_cursor.cursor_len() >= 4 {
        var kdf:  u16 = 0;
        var aead: u16 = 0;
        guard cs_cursor.get_u16(kdf) && cs_cursor.get_u16(aead) else { return false; }
        guard out.cipher_suites.try_push(tls::EchCipherSuite { kdf_id: kdf, aead_id: aead }) else { return false; }
    }
    guard cs_cursor.cursor_len() == 0 else { return false; }
    return out.cipher_suites.len > 0;
}

inline fn is_valid_dns_char(b: u8) -> bool {
    return core::is_ascii_alphanumeric(b) || b == '-' || b == '.';
}

// RFC 9849 Section 4: Encrypted ClientHello Configuration - Rejects IPv4 decimal or hex final DNS labels while permitting digit-leading labels like "3m".
inline fn is_ipv4_numeric_label(label: const u8[:]) -> bool {
    guard label.len > 0 else { return false; }
    if label.len >= 2 && label[0] == '0' && (label[1] == 'x' || label[1] == 'X') {
        for i in 2..label.len {
            if !core::is_ascii_hexdigit(label[i]) { return false; }
        }
        return true;
    }
    for b in label {
        if !core::is_ascii_digit(b) { return false; }
    }
    return true;
}

fn validate_ech_public_name_bytes(pub_raw: const u8[:]) -> bool {
    guard pub_raw.len >= 1 && pub_raw.len <= 253 else { return false; }
    var first_b:          u8  = 0;
    var last_b:           u8  = 0;
    var last_label_start: i64 = 0;
    var label_len:        i64 = 0;
    for i in pub_raw.len {
        let b = pub_raw[i];
        if first_b == 0 { first_b = b; }
        guard is_valid_dns_char(b) else { return false; }
        if b == '.' {
            guard last_b != '.' && last_b != '-' else { return false; }
            label_len = 0;
            last_label_start = core::add_sat_i64(i, 1);
        } else {
            guard b != '-' || last_b != '.' else { return false; }
            label_len = core::add_sat_i64(label_len, 1);
            guard label_len <= 63 else { return false; }
        }
        last_b = b;
    }
    guard first_b != '.' && first_b != '-' else { return false; }
    guard last_b != '.' && last_b != '-' else { return false; }
    return !is_ipv4_numeric_label(pub_raw[last_label_start..]);
}

// Reads public name from ECH contents cursor.
//
// Example:
//   contents = [0x09, 'c', 'l', 'o', 'u', 'd', '.', 'c', 'o', 'm'], out = EchConfig { .. }
//   returns: ok = true, out.public_name populated
fn read_ech_public_name(contents: core::ByteCursor&, out: tls::EchConfig&) -> bool {
    var pub_cursor = core::ByteCursor { buf: contents.buf[..0] };
    guard contents.get_u8_length_prefixed(pub_cursor) else { return false; }
    let pub_len = pub_cursor.cursor_len();
    guard pub_len >= 1 && pub_len <= 255 else { return false; }

    guard validate_ech_public_name_bytes(pub_cursor.buf) else { return false; }

    return out.public_name.try_set(pub_cursor.buf);
}

// Reads key config from ECH contents cursor.
//
// Example:
//   contents = [0x01, 0x00, 0x20, ...], out = EchConfig { .. }
//   returns: ok = true, out.config_id and out.public_key populated
fn read_ech_key_config(contents: core::ByteCursor&, out: tls::EchConfig&) -> bool {
    guard contents.get_u8(out.config_id) && contents.get_u16(out.kem_id) else { return false; }
    var pk_cursor = core::ByteCursor { buf: contents.buf[..0] };
    guard contents.get_u16_length_prefixed(pk_cursor) && pk_cursor.cursor_len() >= 1 else { return false; }
    if out.kem_id == rfc::HPKE_KEM_DHKEM_X25519_HKDF_SHA256 {
        guard pk_cursor.cursor_len() == 32 else { return false; }
        for i in 32 { out.public_key[i] = pk_cursor.buf[i]; }
    } else {
        core::secure_zeroize_32(out.public_key);
    }
    return read_ech_cipher_suites(contents, out);
}

// RFC 9849 Section 4.2: Configuration Extensions - Rejects malformed or duplicate extensions and marks unknown critical extensions unsupported.
fn check_ech_config_extensions(ext_cursor: core::ByteCursor&) -> EchEntryStatus {
    var seen_types: u16[..16] = [];
    var has_unknown_critical = false;
    while ext_cursor.cursor_len() > 0 {
        var ext_type: u16 = 0;
        var ext_data = core::ByteCursor { buf: ext_cursor.buf[..0] };
        guard ext_cursor.get_u16(ext_type) && ext_cursor.get_u16_length_prefixed(ext_data) else {
            return EchEntryStatus.Invalid;
        }
        guard !seen_types.contains(ext_type) && seen_types.try_push(ext_type) else {
            return EchEntryStatus.Invalid;
        }
        if (ext_type & 0x8000) != 0 {
            has_unknown_critical = true;
        }
    }
    if has_unknown_critical {
        return EchEntryStatus.SkippedUnsupported;
    }
    return EchEntryStatus.Accepted;
}

// Parses a single RFC 9849 ECHConfig entry and classifies syntax errors vs unsupported critical extensions.
//
// Example:
//   raw = [0xFE, 0x0D, 0x00, 0x30, ...], out = EchConfig { .. }
//   returns: EchEntryStatus.Accepted
fn parse_ech_config_entry(raw: const u8[:], out: tls::EchConfig&) -> EchEntryStatus {
    out = tls::EchConfig { .. };
    var committed = false;
    defer if !committed { out = tls::EchConfig { .. }; };

    guard raw.len >= 4 else { return EchEntryStatus.Invalid; }
    var c = core::cursor_from(raw);

    guard c.get_u16(out.version) && c.get_u16(out.length) && out.length <= c.cursor_len() else {
        return EchEntryStatus.Invalid;
    }
    let total_len = core::add_sat_i64(4, out.length);
    guard total_len == raw.len else { return EchEntryStatus.Invalid; }
    guard out.version == rfc::ECH_VERSION_RFC9849 else { return EchEntryStatus.SkippedUnsupported; }
    guard out.raw_bytes.try_set(raw) else { return EchEntryStatus.Invalid; }

    var contents = core::ByteCursor { buf: raw[..0] };
    guard c.get_bytes(contents, out.length) else { return EchEntryStatus.Invalid; }
    guard read_ech_key_config(contents, out) &&
        contents.get_u8(out.maximum_name_length) &&
        read_ech_public_name(contents, out) else {
        return EchEntryStatus.Invalid;
    }

    var ext_cursor = core::ByteCursor { buf: raw[..0] };
    guard contents.get_u16_length_prefixed(ext_cursor) && contents.cursor_len() == 0 else {
        return EchEntryStatus.Invalid;
    }
    let ext_status = check_ech_config_extensions(ext_cursor);
    if ext_status == EchEntryStatus.Accepted {
        committed = true;
    }
    return ext_status;
}

// Reads a single ECHConfig entry from list cursor.
//
// Example:
//   list_cursor = [0xFE, 0x0D, 0x00, 0x30, ...], out = EchConfigList { .. }
//   returns: ok = true, advance list_cursor
fn read_ech_config_entry(list_cursor: core::ByteCursor&, out: tls::EchConfigList&) -> bool {
    let entry_start = list_cursor.buf;
    var probe = core::cursor_from(entry_start);
    var ver:  u16 = 0;
    var elen: u16 = 0;
    guard probe.get_u16(ver) && probe.get_u16(elen) else { return false; }

    let total_entry = core::add_sat_i64(4, elen);
    guard total_entry <= list_cursor.cursor_len() else { return false; }

    if ver == rfc::ECH_VERSION_RFC9849 {
        var cfg = tls::EchConfig { .. };
        let st = parse_ech_config_entry(entry_start[..total_entry], cfg);
        guard st != EchEntryStatus.Invalid else { return false; }
        if st == EchEntryStatus.Accepted {
            guard out.configs.try_push(cfg) else { return false; }
        }
    }
    list_cursor.buf = list_cursor.buf[total_entry..];
    return true;
}

// RFC 9849 Section 4: Encrypted ClientHello Configuration - Validates ECHConfigList wire syntax while ignoring unsupported versions.
//
// Example:
//   raw = [0x00, 0x06, 0x0A, 0x0A, 0x00, 0x02, 0x00, 0x00], out = EchConfigList { .. }
//   returns: ok = true, out.configs.len = 0
fn parse_ech_config_list_syntax(raw: const u8[:], out: tls::EchConfigList&) -> bool {
    out.configs.clear();
    var committed = false;
    defer if !committed { out.configs.clear(); };

    guard raw.len >= 4 else { return false; }
    var c = core::cursor_from(raw);
    var list_cursor = core::ByteCursor { buf: raw[..0] };
    guard c.get_u16_length_prefixed(list_cursor) else { return false; }
    guard c.cursor_len() == 0 && list_cursor.cursor_len() >= 4 else { return false; }

    while list_cursor.cursor_len() >= 4 {
        guard read_ech_config_entry(list_cursor, out) else { return false; }
    }
    guard list_cursor.cursor_len() == 0 else { return false; }
    committed = true;
    return true;
}

inline fn is_supported_ech_cipher(cs: const tls::EchCipherSuite&) -> bool {
    guard cs.kdf_id == rfc::HPKE_KDF_HKDF_SHA256 else { return false; }
    return cs.aead_id == rfc::HPKE_AEAD_AES_128_GCM || cs.aead_id == rfc::HPKE_AEAD_CHACHA20_POLY1305;
}

inline fn calc_ech_padding_len(max_name_len: u8, real_sni_len: i64) -> i64 {
    if real_sni_len == 0 {
        return (max_name_len as i64) + 9;
    }
    return max(0, max_name_len - real_sni_len);
}

fn append_ech_inner_sni_and_alpn<B>(ext_buf: B&, inner_sni: const u8[:], inner_alpn: const u8[:]) -> bool {
    if inner_sni.len > 0 {
        guard inner_sni.len <= 255 else { return false; }
        let sni_entry_len = core::add_sat_i64(inner_sni.len, 3) as u16;
        ext_buf.append_u16_be(rfc::TLS_EXT_SERVER_NAME);
        ext_buf.append_u16_be(core::add_sat_i64(inner_sni.len, 5) as u16);
        ext_buf.append_u16_be(sni_entry_len);
        ext_buf.push(0);
        ext_buf.append_u16_be(inner_sni.len as u16);
        ext_buf.append(inner_sni);
    }
    if inner_alpn.len > 0 {
        guard inner_alpn.len <= 255 else { return false; }
        let alpn_list_len = core::add_sat_i64(inner_alpn.len, 1) as u16;
        ext_buf.append_u16_be(rfc::TLS_EXT_ALPN);
        ext_buf.append_u16_be(core::add_sat_i64(inner_alpn.len, 3) as u16);
        ext_buf.append_u16_be(alpn_list_len);
        ext_buf.push(inner_alpn.len as u8);
        ext_buf.append(inner_alpn);
    }
    return true;
}

// RFC 9849 Section 5: The "encrypted_client_hello" Extension - Extracts the 8-byte HelloRetryRequest confirmation payload.
//
// Example:
//   ext_data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08], out_confirm = [0; 8]
//   returns: ok = true, out_confirm = [1, 2, 3, 4, 5, 6, 7, 8]
fn parse_ech_hrr_confirmation(ext_data: const u8[:], out_confirm: u8[8]&) -> bool {
    guard ext_data.len == rfc::ECH_ACCEPT_CONFIRM_LEN else {
        core::secure_zeroize_slice(out_confirm[..]);
        return false;
    }
    core::ct_copy_bytes(out_confirm[..], ext_data);
    return true;
}

fn ech_fsm_on_hrr(
    fsm:              tls::EchFsm&,
    has_ech_ext:      bool,
    ech_ext_data:     const u8[:],
    expected_confirm: const u8[8]&,
) -> bool {
    guard !fsm.has_hrr else { return false; }
    fsm.has_hrr = true;
    if fsm.mode != tls::EchHandshakeMode.Offered {
        return !has_ech_ext;
    }
    if !has_ech_ext {
        fsm.mode = tls::EchHandshakeMode.Bypassed;
        return true;
    }
    var hrr_conf: u8[8] = [0; 8];
    guard parse_ech_hrr_confirmation(ech_ext_data, hrr_conf) else { return false; }
    fsm.mode = if core::ct_eq_bytes(hrr_conf[..], expected_confirm[..]) {
        tls::EchHandshakeMode.Offered
    } else {
        tls::EchHandshakeMode.Bypassed
    };
    return true;
}

fn alpn_offer_contains(offer_list: const u8[:], selected: const u8[:]) -> bool {
    guard offer_list.len > 0 && selected.len > 0 else { return false; }
    var matched = false;
    var tok = core::make_byte_tokenizer(offer_list, ',');
    while true {
        let item, has_next = core::token_next(tok);
        if !has_next { break; }
        let trimmed = item.trim_lws();
        guard trimmed.len >= 1 && trimmed.len <= 255 else { return false; }
        if trimmed == selected {
            matched = true;
        }
    }
    return matched;
}

fn client_wait_pre_transition(current: tls::HsState, incoming_msg_type: u8, is_hrr: bool) -> tls::HsState, bool {
    if current == tls::HsState.ClientWaitSH {
        if incoming_msg_type == rfc::TLS_HS_SERVER_HELLO {
            if is_hrr {
                // RFC 8446 Section 4.1.4: On HRR, client sends ClientHello2 and awaits ServerHello2
                return tls::HsState.ClientWaitSH, true;
            }
            return tls::HsState.ClientWaitEE, true;
        }
    } else if current == tls::HsState.ClientWaitEE {
        if incoming_msg_type == rfc::TLS_HS_ENCRYPTED_EXTENSIONS {
            return tls::HsState.ClientWaitCertCr, true;
        }
    }
    return tls::HsState.Closed, false;
}

// RFC 8879 Section 4: Compressed Certificate Message - Accept CompressedCertificate only when compress_certificate was advertised.
fn client_wait_cert_cr_transition(
    incoming_msg_type: u8,
    is_psk:            bool,
    cert_comp:         tls::CertCompressionOffer = tls::CertCompressionOffer.NotOffered,
) -> tls::HsState, bool {
    if is_psk {
        // In PSK mode: Certificate and CertificateVerify are omitted; Finished transitions directly to Connected
        if incoming_msg_type == rfc::TLS_HS_FINISHED {
            return tls::HsState.Connected, true;
        }
        return tls::HsState.Closed, false;
    }
    if incoming_msg_type == rfc::TLS_HS_CERTIFICATE_REQUEST {
        return tls::HsState.ClientWaitCert, true;
    }
    if incoming_msg_type == rfc::TLS_HS_CERTIFICATE {
        return tls::HsState.ClientWaitCV, true;
    }
    if incoming_msg_type == rfc::TLS_HS_COMPRESSED_CERTIFICATE && cert_comp == tls::CertCompressionOffer.Offered {
        return tls::HsState.ClientWaitCV, true;
    }
    // Strict RFC 8446 Invariant: Finished received before Certificate/CertificateVerify MUST be rejected
    return tls::HsState.Closed, false;
}

fn client_wait_cert_or_cv_transition(
    current:           tls::HsState,
    incoming_msg_type: u8,
    cert_comp:         tls::CertCompressionOffer = tls::CertCompressionOffer.NotOffered,
) -> tls::HsState, bool {
    if current == tls::HsState.ClientWaitCert {
        if incoming_msg_type == rfc::TLS_HS_CERTIFICATE {
            return tls::HsState.ClientWaitCV, true;
        }
        if incoming_msg_type == rfc::TLS_HS_COMPRESSED_CERTIFICATE && cert_comp == tls::CertCompressionOffer.Offered {
            return tls::HsState.ClientWaitCV, true;
        }
    } else if current == tls::HsState.ClientWaitCV {
        if incoming_msg_type == rfc::TLS_HS_CERTIFICATE_VERIFY {
            return tls::HsState.ClientWaitFinished, true;
        }
    }
    return tls::HsState.Closed, false;
}

// RFC 8446 Section 4.2.6: Post-Handshake Client Authentication - Reject post-handshake CertificateRequest unless post_handshake_auth was offered.
fn client_wait_post_transition(
    current:           tls::HsState,
    incoming_msg_type: u8,
    pha:               tls::PostHandshakeAuth = tls::PostHandshakeAuth.Disabled,
) -> tls::HsState, bool {
    if current == tls::HsState.ClientWaitFinished {
        if incoming_msg_type == rfc::TLS_HS_FINISHED {
            return tls::HsState.Connected, true;
        }
    } else if current == tls::HsState.Connected {
        if incoming_msg_type == rfc::TLS_HS_NEW_SESSION_TICKET || incoming_msg_type == rfc::TLS_HS_KEY_UPDATE {
            return tls::HsState.Connected, true;
        }
        if incoming_msg_type == rfc::TLS_HS_CERTIFICATE_REQUEST && pha == tls::PostHandshakeAuth.Offered {
            return tls::HsState.Connected, true;
        }
    }
    return tls::HsState.Closed, false;
}

fn server_wait_initial_transition(
    current:               tls::HsState,
    incoming_msg_type:     u8,
    client_auth_requested: bool,
    early_data_accepted:   tls::EarlyDataAccepted = tls::EarlyDataAccepted.Rejected,
) -> tls::HsState, bool {
    if current == tls::HsState.ServerWaitCH && incoming_msg_type == rfc::TLS_HS_CLIENT_HELLO {
        if early_data_accepted == tls::EarlyDataAccepted.Accepted {
            return tls::HsState.ServerWaitEOED, true;
        }
        if client_auth_requested { return tls::HsState.ServerWaitCert, true; }
        return tls::HsState.ServerWaitFinished, true;
    }
    if current == tls::HsState.ServerWaitEOED && incoming_msg_type == rfc::TLS_HS_END_OF_EARLY_DATA {
        if client_auth_requested { return tls::HsState.ServerWaitCert, true; }
        return tls::HsState.ServerWaitFinished, true;
    }
    return tls::HsState.Closed, false;
}

fn server_wait_cert_step(
    incoming_msg_type:    u8,
    client_cert_is_empty: bool,
    cert_comp:            tls::CertCompressionOffer = tls::CertCompressionOffer.NotOffered,
) -> tls::HsState, bool {
    let is_cert = incoming_msg_type == rfc::TLS_HS_CERTIFICATE
        || (incoming_msg_type == rfc::TLS_HS_COMPRESSED_CERTIFICATE && cert_comp == tls::CertCompressionOffer.Offered);
    if is_cert {
        if client_cert_is_empty {
            // RFC 8446 Section 4.4.2: If client has no certificates, CertificateVerify is omitted
            return tls::HsState.ServerWaitFinished, true;
        }
        return tls::HsState.ServerWaitCV, true;
    }
    return tls::HsState.Closed, false;
}

fn server_wait_cv_step(incoming_msg_type: u8, client_cert_is_empty: bool) -> tls::HsState, bool {
    if client_cert_is_empty {
        // RFC 8446 Section 4.4.2: Client MUST NOT send CertificateVerify if certificate was empty
        return tls::HsState.Closed, false;
    }
    if incoming_msg_type == rfc::TLS_HS_CERTIFICATE_VERIFY {
        return tls::HsState.ServerWaitFinished, true;
    }
    return tls::HsState.Closed, false;
}

fn server_wait_done_transition(
    current:              tls::HsState,
    incoming_msg_type:    u8,
    client_auth:          tls::ClientAuthMode       = tls::ClientAuthMode.Disabled,
    client_cert_is_empty: bool                      = false,
    cert_comp:            tls::CertCompressionOffer = tls::CertCompressionOffer.NotOffered,
) -> tls::HsState, bool {
    if current == tls::HsState.ServerWaitFinished {
        guard incoming_msg_type == rfc::TLS_HS_FINISHED else { return tls::HsState.Closed, false; }
        return tls::HsState.Connected, true;
    }
    guard current == tls::HsState.Connected else { return tls::HsState.Closed, false; }
    if incoming_msg_type == rfc::TLS_HS_KEY_UPDATE {
        return tls::HsState.Connected, true;
    }
    // RFC 8446 Section 4.4.2: Certificate - Accept post-handshake Certificate only when client auth was requested.
    let is_post_cert = incoming_msg_type == rfc::TLS_HS_CERTIFICATE
        || (incoming_msg_type == rfc::TLS_HS_COMPRESSED_CERTIFICATE && cert_comp == tls::CertCompressionOffer.Offered);
    if is_post_cert && client_auth == tls::ClientAuthMode.Requested {
        let next = if client_cert_is_empty { tls::HsState.ServerWaitFinished } else { tls::HsState.ServerWaitCV };
        return next, true;
    }
    return tls::HsState.Closed, false;
}

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
    return core::is_ascii_digit(b) || b == '.';
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

fn read_sni_entry(list_cursor: core::ByteCursor&, found_host_name: bool&, out_sni: u8[..255]&) -> bool {
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

fn select_alpn_result(c: AlpnCandidates) -> tls::NegotiatedAlpn {
    if c.is_quic {
        if c.has_h3 { return tls::NegotiatedAlpn.H3; }
        return tls::NegotiatedAlpn.None;
    }
    if c.has_h2 { return tls::NegotiatedAlpn.H2; }
    if c.has_http11 { return tls::NegotiatedAlpn.Http11; }
    if c.has_any { return tls::NegotiatedAlpn.Other; }
    return tls::NegotiatedAlpn.None;
}

fn check_and_add_extension(entries: tls::ExtensionEntry[..32]&, ext_type: u16, data: const u8[:]) -> bool {
    for i in entries.len {
        if entries[i].ext_type == ext_type {
            return false;
        }
    }
    return entries.try_push(tls::ExtensionEntry {
        ext_type: ext_type,
        data:     data,
    });
}

fn check_and_add_version(seen_versions: u16[..127]&, ver: u16) -> bool {
    for i in seen_versions.len {
        if seen_versions[i] == ver {
            return false;
        }
    }
    return seen_versions.try_push(ver);
}

// RFC 8879 Section 3: Negotiating Certificate Compression - Parses up to 127 algorithm IDs with rollback.
//
// Example:
//   ext_bytes = [0x04, 0x00, 0x02, 0x00, 0x03]
//   returns: ok = true, out_algos = [2, 3]
fn parse_compress_certificate_ext<A>(ext_bytes: const u8[:], out_algos: A&) -> bool {
    var committed = false;
    defer if !committed { out_algos.clear(); };
    var c = core::cursor_from(ext_bytes);
    var lc, ok_l = c.read_u8_sub_cursor();
    guard ok_l && c.buf.len == 0 && lc.buf.len >= 2 && (lc.buf.len & 1) == 0 else { return false; }
    out_algos.clear();
    while lc.buf.len > 0 {
        let algo, ok_a = lc.read_u16();
        guard ok_a && out_algos.try_push(algo) else { return false; }
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

// RFC 8446 Section 4.1.3: Server Hello - Reject any extension not permitted in TLS 1.3 ServerHello or HRR.
fn validate_sh_or_hrr_extensions(entries: const tls::ExtensionEntry[:], is_hrr: bool) -> bool {
    for &e in entries {
        let t = e.ext_type;
        if is_hrr {
            let allowed_hrr = t == rfc::TLS_EXT_SUPPORTED_VERSIONS ||
                t == rfc::TLS_EXT_KEY_SHARE ||
                t == rfc::TLS_EXT_COOKIE;
            guard allowed_hrr else { return false; }
        } else {
            let allowed_sh = t == rfc::TLS_EXT_SUPPORTED_VERSIONS ||
                t == rfc::TLS_EXT_KEY_SHARE ||
                t == rfc::TLS_EXT_PRE_SHARED_KEY;
            guard allowed_sh else { return false; }
        }
    }
    return true;
}

// RFC 8446 Section 4.2: Extensions - Table 2 indicates recognized TLS 1.3 extensions.
fn read_ticket_early_data(ext_data: core::ByteCursor&, out: tls::NewSessionTicketMsg&) -> bool {
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

// Validates the TLS 1.3 `tls_flags` extension payload (IANA ExtensionType 62).
// Rejects empty flag vectors with DecodeError and trailing zero octets with IllegalParameter.
fn validate_ticket_tls_flags(ext_data: core::ByteCursor&) -> tls::Alert {
    let flags_c, ok_f = ext_data.read_u8_sub_cursor();
    guard ok_f && ext_data.cursor_len() == 0 && flags_c.cursor_len() >= 1 else {
        return tls::Alert.DecodeError;
    }
    let last_idx = core::sub_sat_i64(flags_c.buf.len, 1);
    guard flags_c.buf[last_idx] != 0 else {
        return tls::Alert.IllegalParameter;
    }
    return tls::Alert.CloseNotify;
}

fn read_ticket_extensions(ext_cursor: core::ByteCursor&, out: tls::NewSessionTicketMsg&) -> bool {
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
        } else if ext_type == rfc::TLS_EXT_TLS_FLAGS {
            guard validate_ticket_tls_flags(ext_data) == tls::Alert.CloseNotify else { return false; }
        }
    }
    return ext_cursor.cursor_len() == 0;
}

// Classifies a malformed NewSessionTicket payload into the RFC-prescribed fatal alert.
fn classify_nst_failure_alert(payload: const u8[:]) -> tls::Alert {
    var c = core::cursor_from(payload);
    let _, ok_lt = c.read_u32();
    let _, ok_aa = c.read_u32();
    let _, ok_nc = c.read_u8_prefixed();
    let _, ok_tk = c.read_u16_prefixed();
    var ext_c, ok_ext = c.read_u16_sub_cursor();
    guard ok_lt && ok_aa && ok_nc && ok_tk && ok_ext && c.cursor_len() == 0 else {
        return tls::Alert.DecodeError;
    }
    while ext_c.cursor_len() > 0 {
        let et, ok_t = ext_c.read_u16();
        var ed, ok_d = ext_c.read_u16_sub_cursor();
        guard ok_t && ok_d else { return tls::Alert.DecodeError; }
        if et == rfc::TLS_EXT_TLS_FLAGS {
            let flg_alert = validate_ticket_tls_flags(ed);
            if flg_alert != tls::Alert.CloseNotify { return flg_alert; }
        }
    }
    return tls::Alert.DecodeError;
}

fn read_ticket_nonce(c: core::ByteCursor&, out: tls::NewSessionTicketMsg&) -> bool {
    let nonce_c, ok = c.read_u8_sub_cursor();
    guard ok else { return false; }
    return out.ticket_nonce.try_set(nonce_c.buf);
}

fn read_ticket_bytes(c: core::ByteCursor&, out: tls::NewSessionTicketMsg&) -> bool {
    let ticket_c, ok = c.read_u16_sub_cursor();
    guard ok && ticket_c.buf.len > 0 else { return false; }
    return out.ticket.try_set(ticket_c.buf);
}

fn has_conflicting_ticket(cache: const tls::SessionTicketCache&, ticket: const tls::NewSessionTicketMsg&) -> bool {
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

fn read_cert_req_sig_algs(ext_data: core::ByteCursor&, out: tls::CertificateRequestMsg&) -> bool {
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
fn read_cert_req_context(c: core::ByteCursor&, is_post_handshake: bool, out: tls::CertificateRequestMsg&) -> bool {
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
