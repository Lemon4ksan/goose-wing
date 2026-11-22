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
import .ech_internal;
import security.hpke;

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
