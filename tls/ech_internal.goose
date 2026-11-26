// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal Encrypted Client Hello (ECH, RFC 9849) config parsing and FSM helpers.
namespace tls_internal;

import std;
import core;
import .internal;
import .record;
import .key_schedule;
import .types;
import security.hpke;

enum EchEntryStatus {
    Accepted,
    SkippedUnsupported,
    Invalid,
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

fn validate_ech_dns_label(label: const u8[:]) -> bool {
    guard label.len >= 1 && label.len <= 63 else { return false; }
    let last_idx = core::sub_sat_i64(label.len, 1);
    guard label[0] != '-' && label[last_idx] != '-' else { return false; }
    for b in label {
        guard is_valid_dns_char(b) else { return false; }
    }
    return true;
}

fn validate_ech_public_name_bytes(pub_raw: const u8[:]) -> bool {
    guard pub_raw.len >= 1 && pub_raw.len <= 253 else { return false; }
    var start:      i64 = 0;
    var last_start: i64 = 0;
    for i in pub_raw.len {
        if pub_raw[i] == '.' {
            guard validate_ech_dns_label(pub_raw[start..i]) else { return false; }
            start = core::add_sat_i64(i, 1);
            last_start = start;
        }
    }
    guard validate_ech_dns_label(pub_raw[start..]) else { return false; }
    return !is_ipv4_numeric_label(pub_raw[last_start..]);
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
        return core::add_sat_i64(max_name_len, 9);
    }
    return max(0, core::sub_sat_i64(max_name_len, real_sni_len));
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
        var wire_list: u8[..256] = [];
        var tok = core::make_byte_tokenizer(inner_alpn, ',');
        loop {
            let raw_proto, has_tok = core::token_next(tok);
            guard has_tok else { break; }
            let proto = raw_proto.trim_lws();
            guard proto.len > 0 && proto.len <= 255 else { return false; }
            guard wire_list.try_push(proto.len as u8) && wire_list.try_append(proto) else {
                return false;
            }
        }
        guard wire_list.len > 0 && wire_list.len <= 255 else { return false; }
        ext_buf.append_u16_be(rfc::TLS_EXT_ALPN);
        ext_buf.append_u16_be(core::add_sat_i64(wire_list.len, 2) as u16);
        ext_buf.append_u16_be(wire_list.len as u16);
        guard ext_buf.try_append(wire_list[..]) else { return false; }
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

fn validate_ech_config_extensions(ext_cursor: core::ByteCursor&) -> bool {
    return check_ech_config_extensions(ext_cursor) == EchEntryStatus.Accepted;
}

// Computes RFC 9849 Section 6.1.3 padding for ClientHelloInner.
// Pads inner ClientHello to hide exact length of real SNI and extensions.
fn pad_ech_inner<B>(inner_bytes: const u8[:], max_name_len: u8, real_sni_len: i64, out_padded: B&) -> bool {
    guard inner_bytes.len > 0 else { return false; }
    guard real_sni_len >= 0 else { return false; }

    let pad_len = calc_ech_padding_len(max_name_len, real_sni_len);

    // Standard 32-byte alignment padding
    let current_total = core::add_sat_i64(inner_bytes.len, pad_len);
    let rem = current_total & 31;
    let align_pad = if rem != 0 { core::sub_sat_i64(32, rem) } else { 0 };
    let total_padding = core::add_sat_i64(pad_len, align_pad);
    let needed = core::add_sat_i64(inner_bytes.len, total_padding);
    guard core::add_sat_i64(out_padded.len, needed) <= out_padded.cap else { return false; }

    out_padded.append(inner_bytes);
    for i in total_padding {
        out_padded.push(0);
    }
    return true;
}

// Builds the ECH extension wire bytes for ClientHelloOuter (RFC 9849 Section 5).
// Set `include_enc = false` for ClientHelloOuter2 after HelloRetryRequest (empty `enc`).
fn build_ech_outer_extension<B>(
    config_id:   u8,
    cs:          const tls::EchCipherSuite&,
    enc:         const u8[32]&,
    ciphertext:  const u8[:],
    out:         B&,
    include_enc: bool = true,
) -> bool {
    let ct_len = ciphertext.len;
    guard ct_len >= 1 && ct_len <= 65535 else { return false; }
    let enc_len: i64 = if include_enc { 32 } else { 0 };
    let needed = core::add_sat_i64(core::add_sat_i64(10, enc_len), ct_len);
    guard core::add_sat_i64(out.len, needed) <= out.cap else { return false; }

    out.push(rfc::ECH_CLIENT_OUTER);
    out.push(((cs.kdf_id >> 8) & 0xFF) as u8);
    out.push((cs.kdf_id & 0xFF) as u8);
    out.push(((cs.aead_id >> 8) & 0xFF) as u8);
    out.push((cs.aead_id & 0xFF) as u8);
    out.push(config_id);

    // enc: opaque<0..2^16-1> (32 bytes on CH1, 0 bytes on CH2 after HRR)
    out.push(0x00);
    out.push(enc_len as u8);
    if include_enc {
        for i in 32 { out.push(enc[i]); }
    }

    // payload: opaque<1..2^16-1>
    out.push(((ct_len >> 8) & 0xFF) as u8);
    out.push((ct_len & 0xFF) as u8);
    out.append(ciphertext);

    return true;
}

// RFC 9849 Section 5: Builds the ECH extension wire bytes for ClientHelloInner.
// Type = 0x01 (inner), empty payload.
fn build_ech_inner_extension<B>(out: B&) {
    out.push(rfc::ECH_CLIENT_INNER);
}

// Encodes the RFC 9849 §5.1 `ech_outer_extensions` (`0xFD00`) TLS extension entry.
// Rejects empty lists, lists > 127 entries, duplicate entries, or forbidden ECH/outer_extensions types.
//
// Example:
//   ext_types = [0x000A, 0x000D, 0x0033], out = []
//   returns: ok = true, out = [0xFD, 0x00, 0x00, 0x07, 0x06, 0x00, 0x0A, 0x00, 0x0D, 0x00, 0x33]
fn encode_ech_outer_extensions<B>(out: B&, ext_types: const u16[:]) -> bool {
    guard ext_types.len >= 1 && ext_types.len <= 127 else { return false; }
    for i in ext_types.len {
        let t = ext_types[i];
        guard t != rfc::EXT_ENCRYPTED_CLIENT_HELLO && t != rfc::TLS_EXT_ECH_OUTER_EXTENSIONS else { return false; }
        for j in i {
            guard ext_types[j] != t else { return false; }
        }
    }
    let vec_bytes = core::add_sat_i64(ext_types.len, ext_types.len);
    let total_needed = core::add_sat_i64(5, vec_bytes);
    guard core::add_sat_i64(out.len, total_needed) <= out.cap else { return false; }

    out.append_u16_be(rfc::TLS_EXT_ECH_OUTER_EXTENSIONS);
    out.append_u16_be(core::add_sat_i64(1, vec_bytes) as u16);
    out.push(vec_bytes as u8);
    for t in ext_types {
        out.append_u16_be(t);
    }
    return true;
}

// Constructs a deterministic RFC 9849 §5.1 `EncodedClientHelloInner` payload padded per RFC 9849 §6.1.3.
//
// Example:
//   inner_random = [0x11; 32], inner_sni = "secret.example.com", inner_alpn = "h2",
//   outer_ext_types = [0x000A, 0x0033], max_name_len = 64
//   returns: ok = true, out populated with 32-byte aligned EncodedClientHelloInner
fn build_encoded_client_hello_inner<B>(
    out:             B&,
    inner_random:    const u8[32]&,
    inner_sni:       const u8[:],
    inner_alpn:      const u8[:],
    outer_ext_types: const u16[:],
    max_name_len:    u8,
) -> bool {
    var ext_buf: u8[..768] = [];
    guard append_ech_inner_sni_and_alpn(ext_buf, inner_sni, inner_alpn) else { return false; }

    // supported_versions (0x002B): strictly TLS 1.3 (0x0304) in ClientHelloInner (RFC 9849 §5.1)
    ext_buf.append_u16_be(rfc::TLS_EXT_SUPPORTED_VERSIONS);
    ext_buf.append_u16_be(3);
    ext_buf.push(2);
    ext_buf.append_u16_be(rfc::TLS_VERSION_1_3);

    // encrypted_client_hello (0xFE0D): inner marker (type = 1)
    ext_buf.append_u16_be(rfc::EXT_ENCRYPTED_CLIENT_HELLO);
    ext_buf.append_u16_be(1);
    build_ech_inner_extension(ext_buf);

    if outer_ext_types.len > 0 {
        guard encode_ech_outer_extensions(ext_buf, outer_ext_types) else { return false; }
    }

    var raw_inner: u8[..1024] = [];
    raw_inner.append_u16_be(rfc::TLS_LEGACY_VERSION_1_2);
    raw_inner.append(inner_random[..]);
    raw_inner.push(0); // legacy_session_id MUST be empty in EncodedClientHelloInner (RFC 9849 §5.1)
    raw_inner.append_u16_be(6);
    raw_inner.append_u16_be(rfc::TLS_CIPHER_AES_128_GCM_SHA256);
    raw_inner.append_u16_be(rfc::TLS_CIPHER_AES_256_GCM_SHA384);
    raw_inner.append_u16_be(rfc::TLS_CIPHER_CHACHA20_POLY1305_SHA256);
    raw_inner.push(1);
    raw_inner.push(0);
    raw_inner.append_u16_be(ext_buf.len as u16);
    raw_inner.append(ext_buf[..]);

    return pad_ech_inner(raw_inner[..], max_name_len, inner_sni.len, out);
}

struct EchClientState {
    active:        bool                  = false,
    fsm:           tls::EchFsm           = tls::EchFsm { .. },
    cfg:           tls::EchConfig        = tls::EchConfig { .. },
    cs:            tls::EchCipherSuite   = tls::EchCipherSuite { .. },
    hpke_ctx:      security::HpkeContext = security::HpkeContext { .. },
    inner_random:  u8[32]                = [0; 32],
    ch_inner_msg:  u8[..4096]            = [],
    inner_tr:      tls::Transcript       = tls::Transcript { .. },
    retry_configs: tls::EchConfigList    = tls::EchConfigList { .. },
}

fn zeroize_ech_client_state(st: EchClientState&) {
    core::secure_zeroize_32(st.hpke_ctx.key);
    core::secure_zeroize_slice(st.hpke_ctx.base_nonce[..]);
    core::secure_zeroize_32(st.hpke_ctx.exporter_secret);
    st.hpke_ctx.seq = 0;
    core::secure_zeroize_32(st.inner_random);
    core::secure_zeroize_slice(st.ch_inner_msg[..]);
    st.ch_inner_msg.clear();
}

// Locates the 8-byte confirmation payload offset inside an HRR `encrypted_client_hello`
// extension (`0xFE0D`) per RFC 9849 Section 7.2.1.
//
// Example:
//   hrr_msg = [0x02, ..., 0xFE, 0x0D, 0x00, 0x08, <8B confirm>]
//   returns: offset pointing to <8B confirm>, ok = true
fn find_hrr_ech_confirm_offset(hrr_msg: const u8[:]) -> i64, bool {
    guard hrr_msg.len >= rfc::ECH_SH_MIN_HEADER_LEN && hrr_msg[0] == rfc::TLS_HS_SERVER_HELLO else {
        return 0, false;
    }
    var c = core::cursor_from(hrr_msg);
    let _, ok_h = c.read_bytes(4);
    let _, ok_v = c.read_u16();
    let _, ok_r = c.read_bytes(32);
    let _, ok_s = c.read_u8_prefixed();
    let _, ok_c = c.read_bytes(3);
    guard ok_h && ok_v && ok_r && ok_s && ok_c else { return 0, false; }
    var exts, ok_e = c.read_u16_sub_cursor();
    guard ok_e && c.buf.len == 0 else { return 0, false; }

    var ext_base = core::sub_sat_i64(hrr_msg.len, exts.buf.len);
    while exts.buf.len > 0 {
        let et, ok_t = exts.read_u16();
        let data, ok_d = exts.read_u16_prefixed();
        guard ok_t && ok_d else { return 0, false; }
        let data_off = core::add_sat_i64(ext_base, 4);
        if et == rfc::EXT_ENCRYPTED_CLIENT_HELLO {
            guard data.len == rfc::ECH_ACCEPT_CONFIRM_LEN &&
                core::add_sat_i64(data_off, rfc::ECH_ACCEPT_CONFIRM_LEN) <= hrr_msg.len else {
                return 0, false;
            }
            return data_off, true;
        }
        ext_base = core::add_sat_i64(data_off, data.len);
    }
    return 0, false;
}

fn hash_ech_confirm_transcript(
    base_tr:         const tls::Transcript&,
    sh_msg_with_hdr: const u8[:],
    zero_start:      i64,
    hash_id:         u8,
    out_hash:        u8[..48]&,
) -> bool {
    out_hash.clear();
    let zero_end = core::add_sat_i64(zero_start, rfc::ECH_ACCEPT_CONFIRM_LEN);
    guard zero_start >= 0 && zero_end <= sh_msg_with_hdr.len else { return false; }
    let zero8: u8[8] = [0; 8];
    if hash_id == HASH_SHA256 {
        var sha_ctx = base_tr.sha256_ctx;
        core::sha256_update(sha_ctx, sh_msg_with_hdr[0..zero_start]);
        core::sha256_update(sha_ctx, zero8[..]);
        if zero_end < sh_msg_with_hdr.len {
            core::sha256_update(sha_ctx, sh_msg_with_hdr[zero_end..]);
        }
        let digest = core::sha256_final(sha_ctx);
        return out_hash.try_set(digest[..]);
    }
    if hash_id == HASH_SHA384 {
        var sha_ctx = base_tr.sha384_ctx;
        core::sha384_update(sha_ctx, sh_msg_with_hdr[0..zero_start]);
        core::sha384_update(sha_ctx, zero8[..]);
        if zero_end < sh_msg_with_hdr.len {
            core::sha384_update(sha_ctx, sh_msg_with_hdr[zero_end..]);
        }
        let digest = core::sha384_final(sha_ctx);
        return out_hash.try_set(digest[..]);
    }
    return false;
}

fn expand_ech_accept_confirm(
    inner_random:    const u8[32]&,
    transcript_hash: const u8[:],
    is_hrr:          bool,
    hash_id:         u8,
) -> u8[8], bool {
    var confirm: u8[8] = [0; 8];
    let label = if is_hrr { "hrr ech accept confirmation" } else { "ech accept confirmation" };
    if hash_id == HASH_SHA256 {
        let zero_salt: u8[32] = [0; 32];
        var prk = core::hkdf_extract(zero_salt[..], inner_random[..]);
        defer core::secure_zeroize_32(prk);
        let ok = hkdf_expand_label(
            HASH_SHA256, prk[..], label, transcript_hash, rfc::ECH_ACCEPT_CONFIRM_LEN, confirm[..],
        );
        return confirm, ok;
    }
    if hash_id == HASH_SHA384 {
        let zero_salt: u8[48] = [0; 48];
        var prk = core::hkdf_extract_384(zero_salt[..], inner_random[..]);
        defer core::secure_zeroize_48(prk);
        let ok = hkdf_expand_label(
            HASH_SHA384, prk[..], label, transcript_hash, rfc::ECH_ACCEPT_CONFIRM_LEN, confirm[..],
        );
        return confirm, ok;
    }
    return confirm, false;
}

// Computes the 8-byte RFC 9849 §7.2 / §7.2.1 ECH acceptance confirmation signal from an active
// inner transcript (`ClientHelloInner`, or `message_hash || HRR || ClientHelloInner2`).
fn compute_ech_confirm_from_transcript(
    inner_random:    const u8[32]&,
    inner_tr:        const tls::Transcript&,
    sh_msg_with_hdr: const u8[:],
    is_hrr:          bool,
    hash_id:         u8 = HASH_SHA256,
) -> u8[8], bool {
    var zero_start: i64 = rfc::ECH_SH_CONFIRM_START;
    if is_hrr {
        let off, ok_off = find_hrr_ech_confirm_offset(sh_msg_with_hdr);
        guard ok_off else { return [0; 8], false; }
        zero_start = off;
    } else {
        guard sh_msg_with_hdr.len >= rfc::ECH_SH_MIN_HEADER_LEN else { return [0; 8], false; }
    }
    var th: u8[..48] = [];
    guard hash_ech_confirm_transcript(inner_tr, sh_msg_with_hdr, zero_start, hash_id, th) else {
        return [0; 8], false;
    }
    return expand_ech_accept_confirm(inner_random, th[..], is_hrr, hash_id);
}

// Computes the 8-byte RFC 9849 §7.2 / §7.2.1 ECH transcript acceptance confirmation signal.
// For ServerHello (`is_hrr == false`), zeroes bytes [30..38] (last 8 bytes of ServerHello.random).
// For HelloRetryRequest (`is_hrr == true`), zeroes the 8-byte payload of the HRR ECH extension.
// Supports both SHA-256 (`HASH_SHA256`) and SHA-384 (`HASH_SHA384`) cipher suites.
//
// Example:
//   inner_random = [0x22; 32], ch_inner_bytes = [0x01, ...],
//   sh_msg_with_hdr = [0x02, 0x00, 0x00, 0x26, ...], is_hrr = false
//   returns: confirm = [8 bytes], ok = true
fn compute_ech_accept_confirmation(
    inner_random:    const u8[32]&,
    ch_inner_bytes:  const u8[:],
    sh_msg_with_hdr: const u8[:],
    is_hrr:          bool,
    hash_id:         u8 = HASH_SHA256,
) -> u8[8], bool {
    guard ch_inner_bytes.len > 0 else { return [0; 8], false; }
    var tr = tls::Transcript { .. };
    core::sha256_update(tr.sha256_ctx, ch_inner_bytes);
    core::sha384_update(tr.sha384_ctx, ch_inner_bytes);
    return compute_ech_confirm_from_transcript(inner_random, tr, sh_msg_with_hdr, is_hrr, hash_id);
}

// RFC 9849 Section 6.1.4: Determining ECH Acceptance - Advances ECH state machine on HelloRetryRequest extension or ServerHello.random[24..32].
fn ech_fsm_on_server_hello(
    fsm:               tls::EchFsm&,
    sh_type:           tls::EchServerHelloType,
    has_ech_ext:       bool,
    sh_confirm_or_ext: const u8[:],
    expected_confirm:  const u8[8]&,
    out_retry_configs: tls::EchConfigList&,
) -> bool {
    out_retry_configs.configs.clear();
    if sh_type == tls::EchServerHelloType.HelloRetryRequest {
        return ech_fsm_on_hrr(fsm, has_ech_ext, sh_confirm_or_ext, expected_confirm);
    }
    // RFC 9849 Section 5: The "encrypted_client_hello" Extension - Non-HRR ServerHello MUST NOT contain an ECH extension.
    guard !has_ech_ext else { return false; }
    if fsm.mode != tls::EchHandshakeMode.Offered {
        return true;
    }
    guard sh_confirm_or_ext.len == rfc::ECH_ACCEPT_CONFIRM_LEN else { return false; }
    if tls::verify_ech_acceptance_confirmation(sh_confirm_or_ext, expected_confirm) {
        fsm.mode = tls::EchHandshakeMode.Accepted;
        return true;
    }
    // RFC 9849 Section 6.1.5: Handshaking with ClientHelloInner - ServerHello omitting ECH acceptance after HRR acceptance MUST abort.
    guard !fsm.has_hrr else { return false; }
    fsm.mode = tls::EchHandshakeMode.Bypassed;
    return true;
}
