// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Deterministic zero-allocation TLS 1.3 Handshake State Machine and Extensions.
// Conforms to RFC 8446 Sections 4 and 4.4, RFC 9001 (QUIC), RFC 6066 (SNI), and RFC 7301 (ALPN).
namespace tls;

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
import .handshake_wire_internal;

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
        return tls_internal::client_wait_pre_transition(current, incoming_msg_type, is_hrr);
    }
    if current == HsState.ClientWaitCertCr {
        return tls_internal::client_wait_cert_cr_transition(incoming_msg_type, mode == HandshakeMode.Psk, cert_comp);
    }
    if current == HsState.ClientWaitCert || current == HsState.ClientWaitCV {
        return tls_internal::client_wait_cert_or_cv_transition(current, incoming_msg_type, cert_comp);
    }
    return tls_internal::client_wait_post_transition(current, incoming_msg_type, pha);
}

fn validate_server_handshake_transition(
    current:               HsState,
    incoming_msg_type:     u8,
    client_auth_requested: bool,
    early_data_accepted:   EarlyDataAccepted = EarlyDataAccepted.Rejected,
    client_cert_is_empty:  bool              = false,
) -> HsState, bool {
    let c_auth = if client_auth_requested { ClientAuthMode.Requested } else { ClientAuthMode.Disabled };
    return tls_internal::validate_server_handshake_transition_auth(
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

// RFC 8446 Section 4.1.3 HelloRetryRequest special random value.
inline fn is_hello_retry_request(server_random: const u8[32]&) -> bool {
    return core::ct_eq_tag32(server_random, rfc::HRR_RANDOM);
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
    let sentinel_present = tls_internal::has_downgrade_sentinel(server_random);
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

// Example:
//   ext_bytes = 0x00 0x0E 0x00 0x00 0x0B "example.com"
//   returns: ok = true, out_sni = "example.com"
fn parse_sni_extension(ext_bytes: const u8[:], out_sni: u8[..255]&) -> bool {
    var cursor = core::cursor_from(ext_bytes);
    var list_cursor, ok_l = cursor.read_u16_sub_cursor();
    guard ok_l && list_cursor.cursor_len() > 0 && cursor.cursor_len() == 0 else { return false; }

    var found_host_name = false;

    while list_cursor.cursor_len() > 0 {
        guard tls_internal::read_sni_entry(list_cursor, found_host_name, out_sni) else { return false; }
    }
    return found_host_name;
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
        guard ok_p && tls_internal::match_alpn_protocol(proto_cursor.buf, has_h3, has_h2, has_http11) else {
            return NegotiatedAlpn.None;
        }
        has_any = true;
    }

    guard list_cursor.cursor_len() == 0 else { return NegotiatedAlpn.None; }
    return tls_internal::select_alpn_result(tls_internal::AlpnCandidates {
        is_quic:    is_quic,
        has_h3:     has_h3,
        has_h2:     has_h2,
        has_http11: has_http11,
        has_any:    has_any,
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
    entries:         ExtensionEntry[..32]&,
) -> bool {
    entries.clear();
    var cursor = core::cursor_from(ext_block_bytes);
    var extensions_cursor, ok_ext = cursor.read_u16_sub_cursor();
    // Trailing bytes after extensions block strictly forbidden
    guard ok_ext && cursor.cursor_len() == 0 else { return false; }

    while extensions_cursor.cursor_len() > 0 {
        let ext_type, ok_t = extensions_cursor.read_u16();
        let ext_data, ok_d = extensions_cursor.read_u16_sub_cursor();
        guard ok_t && ok_d && tls_internal::check_and_add_extension(entries, ext_type, ext_data.buf) else {
            return false;
        }
    }
    return extensions_cursor.cursor_len() == 0;
}

// Finds an extension by type in the parsed entries array.
fn find_extension(entries: const ExtensionEntry[..32]&, ext_type: u16) -> const u8[:], bool {
    for i in entries.len {
        if entries[i].ext_type == ext_type {
            return entries[i].data, true;
        }
    }
    return "", false;
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
    let ext_bytes, ok_pre = tls_internal::read_server_hello_preamble(payload, rand_arr, tmp);
    guard ok_pre else { return false; }

    var entries: ExtensionEntry[..32] = [];
    guard parse_extensions_block(ext_bytes, entries) else { return false; }
    guard tls_internal::validate_sh_or_hrr_extensions(entries, tmp.is_hrr) else { return false; }

    let ver_data, has_ver = find_extension(entries, rfc::TLS_EXT_SUPPORTED_VERSIONS);
    guard has_ver else { return false; }
    let negotiated_ver, ok_ver = tls_internal::parse_server_supported_versions(ver_data);
    guard ok_ver && negotiated_ver == rfc::TLS_VERSION_1_3 else { return false; }

    let ok_ext = if tmp.is_hrr {
        tls_internal::apply_hrr_server_hello_exts(entries, tmp)
    } else {
        tls_internal::apply_regular_server_hello_exts(entries, rand_arr, tmp)
    };
    guard ok_ext else { return false; }
    out = tmp;
    return true;
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
    guard tls_internal::read_ticket_nonce(c, out) else { return false; }
    guard tls_internal::read_ticket_bytes(c, out) else { return false; }

    var ext_cursor, ok_ext = c.read_u16_sub_cursor();
    guard ok_ext && c.cursor_len() == 0 else { return false; }

    guard tls_internal::read_ticket_extensions(ext_cursor, out) else { return false; }

    // RFC 8446 Section 4.2.10 & 4.6.1: early_data MUST NOT be offered when ticket_lifetime is 0
    guard !(out.ticket_lifetime == 0 && out.has_early_data) else { return false; }

    committed = true;
    return true;
}

const MAX_SESSION_TICKETS_PER_CONN: u32 = 64;

// Stores a validated NewSessionTicket into bounded SessionTicketCache using circular eviction.
// Enforces a per-connection NewSessionTicket flood ceiling including zero-lifetime tickets.
fn cache_session_ticket(cache: SessionTicketCache&, ticket: const NewSessionTicketMsg&) -> bool {
    guard cache.total_received < MAX_SESSION_TICKETS_PER_CONN else { return false; }
    guard ticket.ticket_lifetime <= rfc::MAX_TICKET_LIFETIME_SECS else { return false; }
    // RFC 8446 Section 4.6.1: ticket_lifetime == 0 indicates ticket should be discarded immediately,
    // while still counting toward the connection-wide post-handshake NST DoS budget.
    if ticket.ticket_lifetime == 0 {
        cache.total_received = core::add_sat_u32(cache.total_received, 1);
        return true;
    }

    // RFC 8446 Section 4.6.1: Each ticket MUST have a unique ticket_nonce on this connection.
    // Reject duplicate nonce or duplicate ticket bytes to prevent post-handshake ticket confusion
    // and resumption PSK collisions in ks_derive_resumption_psk.
    guard !tls_internal::has_conflicting_ticket(cache, ticket) else { return false; }

    cache.total_received = core::add_sat_u32(cache.total_received, 1);
    if cache.tickets.len < cache.tickets.cap {
        cache.tickets.push(ticket);
        return true;
    }
    for i in cache.tickets.len - 1 {
        cache.tickets[i] = cache.tickets[i + 1];
    }
    cache.tickets[cache.tickets.len - 1] = ticket;
    return true;
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
    guard tls_internal::read_cert_req_context(c, is_post_handshake, out) else { return false; }

    var ext_cursor, ok_ext = c.read_u16_sub_cursor();
    // RFC 8446 Section 4.3.2: extensions<2..2^16-1>
    guard ok_ext && ext_cursor.cursor_len() >= 2 && c.cursor_len() == 0 else { return false; }

    guard tls_internal::read_cert_req_extensions(ext_cursor, out) else { return false; }

    // RFC 8446 Section 4.3.2: signature_algorithms MUST be present
    guard out.has_signature_algorithms && out.sig_algorithms.len > 0 else { return false; }
    committed = true;
    return true;
}

// RFC 8446 Section 4.3.2: Certificate Request - Encodes context<0..2^8-1> and signature_algorithms.
fn encode_certificate_request<B>(out: B&, context: const u8[:], sig_algorithms: const u16[:]) -> bool {
    guard context.len >= 0 && context.len <= 255 else { return false; }
    guard sig_algorithms.len >= 1 && sig_algorithms.len <= 64 else { return false; }
    var ext_buf: u8[..256] = [];
    tls_internal::encode_cert_req_ext_sig_algs(ext_buf, sig_algorithms);
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
