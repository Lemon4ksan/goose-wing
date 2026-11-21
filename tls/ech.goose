// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Deterministic zero-allocation Encrypted Client Hello (ECH, RFC 9849).
// Provides privacy-preserving SNI encryption via HPKE (RFC 9180) and DNS HTTPS RR (Type 65).
namespace tls;

import std;
import core;
import .internal;
import .record;
import .key_schedule;
import .types;
import .handshake_internal;
import security.hpke;

// RFC 9849 Section 4.2: Configuration Extensions - Validates that all ECHConfig extensions are well-formed, unique, and recognized.
fn validate_ech_config_extensions(ext_cursor: core::ByteCursor&) -> bool {
    return tls_internal::check_ech_config_extensions(ext_cursor) == tls_internal::EchEntryStatus.Accepted;
}

// Parses a single ECHConfig from raw wire bytes.
//
// Example:
//   raw = [0xFE, 0x0D, 0x00, 0x30, ...], out = EchConfig { .. }
//   returns: ok = true, out populated with version, kem_id, public_key, etc.
fn parse_ech_config(raw: const u8[:], out: EchConfig&) -> bool {
    guard raw.len >= 4 else {
        out = EchConfig { .. };
        return false;
    }
    let declared_len = core::read_be_u16(raw, 2);
    let total_len = core::add_sat_i64(4, declared_len);
    guard total_len <= raw.len else {
        out = EchConfig { .. };
        return false;
    }
    return tls_internal::parse_ech_config_entry(raw[..total_len], out) == tls_internal::EchEntryStatus.Accepted;
}

// Parses an ECHConfigList: opaque<2..2^16-1> sequence of ECHConfig.
// RFC 9849 Section 4: Clients MUST ignore any ECHConfig with an unsupported version.
// Rejects trailing unparsed bytes, empty lists, and truncated records.
//
// Example:
//   raw = [0x00, 0x34, 0xFE, 0x0D, 0x00, 0x30, ...], out = EchConfigList { .. }
//   returns: ok = true, out populated with supported configs
fn parse_ech_config_list(raw: const u8[:], out: EchConfigList&) -> bool {
    guard tls_internal::parse_ech_config_list_syntax(raw, out) else { return false; }
    guard out.configs.len > 0 else {
        out.configs.clear();
        return false;
    }
    return true;
}

// Selects the first compatible ECHConfig and cipher suite supporting X25519 & HKDF-SHA256.
fn select_ech_config(list: const EchConfigList&, out_cfg: EchConfig&, out_cs: EchCipherSuite&) -> bool {
    for &cfg in list.configs {
        guard cfg.version == rfc::ECH_VERSION_RFC9849 else { continue; }
        guard cfg.kem_id == rfc::HPKE_KEM_DHKEM_X25519_HKDF_SHA256 else { continue; }

        for &cs in cfg.cipher_suites {
            if tls_internal::is_supported_ech_cipher(cs) {
                out_cfg = copy(cfg);
                out_cs = cs;
                return true;
            }
        }
    }
    return false;
}

// Computes RFC 9849 Section 6.1.3 padding for ClientHelloInner.
// Pads inner ClientHello to hide exact length of real SNI and extensions.
fn pad_ech_inner<B>(inner_bytes: const u8[:], max_name_len: u8, real_sni_len: i64, out_padded: B&) -> bool {
    guard inner_bytes.len > 0 else { return false; }
    guard real_sni_len >= 0 else { return false; }

    let pad_len = tls_internal::calc_ech_padding_len(max_name_len, real_sni_len);

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

// Builds the ECH extension wire bytes for ClientHelloOuter.
// wire format:
//   type (1B) = 0x00 (outer)
//   cipher_suite (4B) = kdf_id (2B) || aead_id (2B)
//   config_id (1B)
//   enc (opaque<1..2^16-1>)
//   payload (opaque<1..2^16-1>)
fn build_ech_outer_extension<B>(
    config_id:  u8,
    cs:         const EchCipherSuite&,
    enc:        const u8[32]&,
    ciphertext: const u8[:],
    out:        B&,
) -> bool {
    let ct_len = ciphertext.len;
    guard ct_len >= 1 && ct_len <= 65535 else { return false; }
    guard core::add_sat_i64(out.len, core::add_sat_i64(42, ct_len)) <= out.cap else { return false; }

    out.push(rfc::ECH_CLIENT_OUTER);
    out.push(((cs.kdf_id >> 8) & 0xFF) as u8);
    out.push((cs.kdf_id & 0xFF) as u8);
    out.push(((cs.aead_id >> 8) & 0xFF) as u8);
    out.push((cs.aead_id & 0xFF) as u8);
    out.push(config_id);

    // enc: opaque<1..2^16-1>
    out.push(0x00);
    out.push(32);
    for i in 32 { out.push(enc[i]); }

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
    guard tls_internal::append_ech_inner_sni_and_alpn(ext_buf, inner_sni, inner_alpn) else { return false; }

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

// Computes the 8-byte RFC 9849 §7.2 ECH transcript acceptance confirmation signal.
// Zeroes bytes [30..38] (the last 8 bytes of ServerHello.random) in the transcript hash,
// extracts PRK = HKDF-Extract(0, ClientHelloInner.random), and expands with label
// "ech accept confirmation" (or "hrr ech accept confirmation" when `is_hrr == true`).
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
) -> u8[8], bool {
    var confirm: u8[8] = [0; 8];
    guard ch_inner_bytes.len > 0 else { return confirm, false; }
    guard sh_msg_with_hdr.len >= rfc::ECH_SH_MIN_HEADER_LEN else { return confirm, false; }

    var sha_ctx = core::Sha256Ctx { .. };
    core::sha256_update(sha_ctx, ch_inner_bytes);
    core::sha256_update(sha_ctx, sh_msg_with_hdr[0..rfc::ECH_SH_CONFIRM_START]);
    let zero8: u8[8] = [0; 8];
    core::sha256_update(sha_ctx, zero8[..]);
    if sh_msg_with_hdr.len > rfc::ECH_SH_MIN_HEADER_LEN {
        core::sha256_update(sha_ctx, sh_msg_with_hdr[rfc::ECH_SH_MIN_HEADER_LEN..]);
    }
    let transcript_hash = core::sha256_final(sha_ctx);

    let zero_salt: u8[32] = [0; 32];
    var prk = core::hkdf_extract(zero_salt[..], inner_random[..]);
    defer core::secure_zeroize_32(prk);
    let label = if is_hrr { "hrr ech accept confirmation" } else { "ech accept confirmation" };
    let ok = tls_internal::hkdf_expand_label(
        tls_internal::HASH_SHA256,
        prk[..],
        label,
        transcript_hash[..],
        rfc::ECH_ACCEPT_CONFIRM_LEN,
        confirm[..],
    );
    return confirm, ok;
}

// Seals the padded ClientHelloInner using HPKE and the selected ECHConfig.
// Info string: "tls ech\x00" || ECHConfig
fn seal_ech_inner<B>(
    config:       const EchConfig&,
    cs:           const EchCipherSuite&,
    outer_aad:    const u8[:],
    inner_padded: const u8[:],
    ephemeral_sk: const u8[32]&,
    out_enc:      u8[32]&,
    out_ct:       B&,
) -> bool {
    var info: u8[..2064] = [];
    info.append("tls ech");
    info.push(0x00);
    guard info.try_append(config.raw_bytes[..]) else { return false; }

    return security::hpke_seal_base(
        config.public_key,
        info[..],
        outer_aad,
        inner_padded,
        ephemeral_sk,
        cs.aead_id,
        out_enc,
        out_ct,
    );
}

// RFC 9849 Section 6.1.6: Handshaking with ClientHelloOuter - Validates EncryptedExtensions retry_configs syntax including GREASE-only lists.
//
// Example:
//   ext_data = [0x00, 0x24, 0xFE, 0x0D, ...], out_config_list = EchConfigList { .. }
//   returns: ok = true
fn parse_and_validate_ech_retry_configs(
    ext_data:        const u8[:],
    out_config_list: EchConfigList&,
) -> bool {
    guard ext_data.len >= 4 else {
        out_config_list.configs.clear();
        return false;
    }
    return tls_internal::parse_ech_config_list_syntax(ext_data, out_config_list);
}

// Verifies the 8-byte ECH acceptance confirmation in ServerHello (RFC 9849 Section 7.2).
// Constant-time comparison against expected confirmation derived from transcript.
fn verify_ech_acceptance_confirmation(
    ext_data:              const u8[:],
    expected_confirmation: const u8[8]&,
) -> bool {
    guard ext_data.len == 8 else { return false; }
    return core::ct_eq_bytes(ext_data, expected_confirmation[..]);
}

// RFC 9849 Section 6.1.4: Determining ECH Acceptance - Advances ECH state machine on HelloRetryRequest extension or ServerHello.random[24..32].
fn ech_fsm_on_server_hello(
    fsm:               EchFsm&,
    sh_type:           EchServerHelloType,
    has_ech_ext:       bool,
    sh_confirm_or_ext: const u8[:],
    expected_confirm:  const u8[8]&,
    out_retry_configs: EchConfigList&,
) -> bool {
    out_retry_configs.configs.clear();
    if sh_type == EchServerHelloType.HelloRetryRequest {
        return tls_internal::ech_fsm_on_hrr(fsm, has_ech_ext, sh_confirm_or_ext, expected_confirm);
    }
    // RFC 9849 Section 5: The "encrypted_client_hello" Extension - Non-HRR ServerHello MUST NOT contain an ECH extension.
    guard !has_ech_ext else { return false; }
    if fsm.mode != EchHandshakeMode.Offered {
        return true;
    }
    guard sh_confirm_or_ext.len == rfc::ECH_ACCEPT_CONFIRM_LEN else { return false; }
    if verify_ech_acceptance_confirmation(sh_confirm_or_ext, expected_confirm) {
        fsm.mode = EchHandshakeMode.Accepted;
        return true;
    }
    // RFC 9849 Section 6.1.5: Handshaking with ClientHelloInner - ServerHello omitting ECH acceptance after HRR acceptance MUST abort.
    guard !fsm.has_hrr else { return false; }
    fsm.mode = EchHandshakeMode.Bypassed;
    return true;
}

// RFC 9849 Section 6.1.6: Handshaking with ClientHelloOuter - Processes EncryptedExtensions retry_configs and rejects unsolicited ECH extensions.
fn ech_fsm_on_encrypted_extensions(
    fsm:               EchFsm&,
    has_ech_ext:       bool,
    ech_ext_data:      const u8[:],
    out_retry_configs: EchConfigList&,
) -> bool {
    out_retry_configs.configs.clear();
    if fsm.mode != EchHandshakeMode.Bypassed {
        return !has_ech_ext;
    }
    if !has_ech_ext {
        return true;
    }
    guard parse_and_validate_ech_retry_configs(ech_ext_data, out_retry_configs) else {
        return false;
    }
    if out_retry_configs.configs.len > 0 {
        fsm.mode = EchHandshakeMode.RejectedWithRetry;
    }
    return true;
}

// RFC 9849 Section 6.1 & Section 10.8: ECH Early Data (0-RTT) Placement Validation.
// Validates that unencrypted outer ClientHello messages do not expose early_data without inner ECH protection.
inline fn validate_ech_early_data_placement(ch_type: EchClientHelloType, has_early_data: bool) -> bool {
    if ch_type == EchClientHelloType.Outer && has_early_data {
        return false;
    }
    return true;
}

// ECH Outer ALPN Separation (rule from OpenSSL #33428; ECH context per RFC 9849)
// When ECH is accepted, the selected ALPN must match an inner ALPN offer.
// When ECH is bypassed or rejected, the selected ALPN must match an outer ALPN offer.
fn validate_ech_alpn_negotiation(
    is_ech_accepted: bool,
    selected_alpn:   const u8[:],
    inner_alpn:      const u8[:],
    outer_alpn:      const u8[:],
) -> bool {
    let active_offer = if is_ech_accepted { inner_alpn } else { outer_alpn };
    if selected_alpn.len == 0 {
        return active_offer.len == 0;
    }
    return tls_internal::alpn_offer_contains(active_offer, selected_alpn);
}
