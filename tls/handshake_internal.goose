// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal TLS 1.3 handshake state-machine and extension parsing helpers.
namespace tls_internal;

import std;
import core;
import .internal;
import .record;
import .key_schedule;
import .asn1;
import .types;
import .pq_ntt_internal;
import .pq_mlkem_internal;
import .cert_compression;

struct AlpnCandidates {
    is_quic:    bool = false,
    has_h3:     bool = false,
    has_h2:     bool = false,
    has_http11: bool = false,
    has_any:    bool = false,
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

fn validate_client_key_share_entries(shares: const u8[:], allow_empty: bool = false) -> bool {
    if shares.len == 0 {
        return allow_empty;
    }
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
        if is_hrr {
            guard rfc::is_permitted_hrr_extension(e.ext_type) else { return false; }
        } else {
            guard rfc::is_permitted_sh_extension(e.ext_type) else { return false; }
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
