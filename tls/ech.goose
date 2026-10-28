// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Deterministic zero-allocation Encrypted Client Hello (ECH, RFC 9460 & draft-ietf-tls-esni-13+).
// Provides privacy-preserving SNI encryption via HPKE (RFC 9180) and DNS HTTPS RR (Type 65).
namespace wing;

import std;
import core from "..";
import .record;
import .hpke;

// ---- 1. ECH Constants & Identifiers -----------------------------------------

const EXT_ENCRYPTED_CLIENT_HELLO: u16 = 0xFE0D; // RFC 9460 & ECH draft-13/14+

const ECH_CLIENT_OUTER: u8 = 0;
const ECH_CLIENT_INNER: u8 = 1;

// Supported ECH version (draft-ietf-tls-esni-13 / RFC 9460)
const ECH_VERSION_DRAFT13: u16 = 0xFE0D;

// ---- 2. Data Structures ----------------------------------------------------

struct EchCipherSuite {
    kdf_id: u16 = HPKE_KDF_HKDF_SHA256,
    aead_id: u16 = HPKE_AEAD_AES_128_GCM,
}

struct EchConfig {
    version: u16 = ECH_VERSION_DRAFT13,
    length: u16 = 0,
    config_id: u8 = 0,
    kem_id: u16 = HPKE_KEM_DHKEM_X25519_HKDF_SHA256,
    public_key: u8[32] = [0; 32],
    cipher_suites: EchCipherSuite[..4] = [],
    maximum_name_length: u8 = 0,
    public_name: u8[..255] = [],
    raw_bytes: u8[..512] = [], // Complete wire bytes of ECHConfig
}

struct EchConfigList {
    configs: EchConfig[..4] = [],
}

struct EchClientState {
    enabled: bool = false,
    selected_config: EchConfig = EchConfig { .. },
    selected_cipher: EchCipherSuite = EchCipherSuite { .. },
    inner_sni: u8[..255] = [],
    outer_sni: u8[..255] = [],
    enc: u8[32] = [0; 32],
    retry_configs: u8[..512] = [],
}

// ---- 3. ECHConfig Parser (RFC 9460 Section 4) ------------------------------

// Parses a single ECHConfig from raw wire bytes.
fn parse_ech_config(raw: const u8[:], out: EchConfig&) -> bool {
    guard raw.len >= 4 else { return false; }
    var c = cursor_from(raw);

    guard get_u16(c, out.version) else { return false; }
    // Only draft-13 / RFC 9460 (0xFE0D) format is supported by this parser
    guard out.version == ECH_VERSION_DRAFT13 else { return false; }

    guard get_u16(c, out.length) else { return false; }
    guard out.length <= cursor_len(c) else { return false; }

    // Preserve raw bytes of this ECHConfig for HPKE info binding
    let total_len = 4 + (out.length as i64);
    guard total_len <= raw.len else { return false; }
    // Guard against silent truncation in raw_bytes buffer
    guard total_len <= out.raw_bytes.cap else { return false; }

    out.raw_bytes.clear();
    for i in total_len {
        out.raw_bytes.push(raw[i]);
    }

    var contents = ByteCursor { buf: raw[..0] };
    guard get_bytes(c, contents, out.length) else { return false; }

    // KeyConfig: config_id (u8) || kem_id (u16) || public_key<1..2^16-1> || cipher_suites
    guard get_u8(contents, out.config_id) else { return false; }
    guard get_u16(contents, out.kem_id) else { return false; }

    var pk_cursor = ByteCursor { buf: raw[..0] };
    guard get_u16_length_prefixed(contents, pk_cursor) else { return false; }
    guard cursor_len(pk_cursor) == 32 else { return false; }
    for i in 32 { out.public_key[i] = pk_cursor.buf[i]; }

    var cs_cursor = ByteCursor { buf: raw[..0] };
    guard get_u16_length_prefixed(contents, cs_cursor) else { return false; }
    guard cursor_len(cs_cursor) >= 4 && (cursor_len(cs_cursor) % 4) == 0 else { return false; }

    out.cipher_suites.clear();
    while cursor_len(cs_cursor) >= 4 {
        var kdf: u16 = 0;
        var aead: u16 = 0;
        guard get_u16(cs_cursor, kdf) && get_u16(cs_cursor, aead) else { return false; }
        if out.cipher_suites.len < out.cipher_suites.cap {
            out.cipher_suites.push(EchCipherSuite { kdf_id: kdf, aead_id: aead });
        }
    }
    guard cursor_len(cs_cursor) == 0 else { return false; }
    guard out.cipher_suites.len > 0 else { return false; }

    // maximum_name_length (u8)
    guard get_u8(contents, out.maximum_name_length) else { return false; }

    // public_name: opaque<1..255> (RFC 9460: MUST NOT be empty or an IP literal)
    var pub_cursor = ByteCursor { buf: raw[..0] };
    guard get_u8_length_prefixed(contents, pub_cursor) else { return false; }
    let pub_len = cursor_len(pub_cursor);
    guard pub_len >= 1 && pub_len <= 255 && pub_len <= out.public_name.cap else { return false; }

    let pub_raw = pub_cursor.buf;
    var has_colon = false;
    var is_all_digits_and_dots = true;
    for b in pub_raw {
        guard b != 0 else { return false; }
        if b == ':' { has_colon = true; }
        if !(b >= '0' && b <= '9') && b != '.' {
            is_all_digits_and_dots = false;
        }
    }
    if has_colon || (is_all_digits_and_dots && pub_raw.len > 0) {
        return false;
    }

    out.public_name.clear();
    for i in pub_len {
        out.public_name.push(pub_cursor.buf[i]);
    }

    // extensions: Extension<0..2^16-1>
    var ext_cursor = ByteCursor { buf: raw[..0] };
    guard get_u16_length_prefixed(contents, ext_cursor) else { return false; }

    // Trailing unparsed bytes inside contents are strictly rejected
    guard cursor_len(contents) == 0 else { return false; }

    return true;
}

// Parses an ECHConfigList: opaque<2..2^16-1> sequence of ECHConfig.
// RFC 9460 Section 4: Clients MUST ignore any ECHConfig with an unsupported version.
// Rejects trailing unparsed bytes, empty lists, and truncated records.
fn parse_ech_config_list(raw: const u8[:], out: EchConfigList&) -> bool {
    guard raw.len >= 4 else { return false; }
    var c = cursor_from(raw);

    var list_cursor = ByteCursor { buf: raw[..0] };
    guard get_u16_length_prefixed(c, list_cursor) else { return false; }
    guard cursor_len(c) == 0 else { return false; }
    guard cursor_len(list_cursor) >= 4 else { return false; }

    out.configs.clear();
    while cursor_len(list_cursor) >= 4 {
        let entry_start = list_cursor.buf;
        var probe = cursor_from(entry_start);
        var ver: u16 = 0;
        var elen: u16 = 0;
        guard get_u16(probe, ver) && get_u16(probe, elen) else { return false; }

        let total_entry = 4 + (elen as i64);
        guard total_entry <= cursor_len(list_cursor) else { return false; }

        if ver != ECH_VERSION_DRAFT13 {
            // RFC 9460 Section 4: Ignore unsupported versions and advance to next entry
            list_cursor.buf = list_cursor.buf[total_entry..];
            continue;
        }

        var cfg = EchConfig { .. };
        guard parse_ech_config(entry_start[..total_entry], cfg) else { return false; }

        if out.configs.len < out.configs.cap {
            out.configs.push(cfg);
        }
        list_cursor.buf = list_cursor.buf[total_entry..];
    }

    // Must have fully consumed list_cursor without trailing fragments
    guard cursor_len(list_cursor) == 0 else { return false; }
    return out.configs.len > 0;
}

// ---- 4. Selection and Matching ----------------------------------------------

// Selects the first compatible ECHConfig and cipher suite supporting X25519 & HKDF-SHA256.
fn select_ech_config(list: const EchConfigList&, out_cfg: EchConfig&, out_cs: EchCipherSuite&) -> bool {
    for i in list.configs.len {
        let cfg = list.configs[i];
        if cfg.version != ECH_VERSION_DRAFT13 { continue; }
        if cfg.kem_id != HPKE_KEM_DHKEM_X25519_HKDF_SHA256 { continue; }

        for j in cfg.cipher_suites.len {
            let cs = cfg.cipher_suites[j];
            if cs.kdf_id == HPKE_KDF_HKDF_SHA256 &&
               (cs.aead_id == HPKE_AEAD_AES_128_GCM || cs.aead_id == HPKE_AEAD_CHACHA20_POLY1305) {
                out_cfg = cfg;
                out_cs = cs;
                return true;
            }
        }
    }
    return false;
}

// ---- 5. ClientHelloInner Padding & Encryption ------------------------------

// Computes RFC 9460 / ECH draft-13 padding for ClientHelloInner.
// Pads inner ClientHello to hide exact length of real SNI and extensions.
fn pad_ech_inner<B>(inner_bytes: const u8[:], max_name_len: u8, real_sni_len: i64, out_padded: B&) -> bool {
    guard inner_bytes.len > 0 else { return false; }
    guard real_sni_len >= 0 else { return false; }
    out_padded.append(inner_bytes);

    let max_len = max_name_len as i64;
    let pad_len = if real_sni_len < max_len { max_len - real_sni_len } else { 0 };

    // Standard 32-byte alignment padding
    let current_total = inner_bytes.len + pad_len;
    let align_pad = if (current_total % 32) != 0 { 32 - (current_total % 32) } else { 0 };
    let total_padding = pad_len + align_pad;

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
    config_id: u8,
    cs: const EchCipherSuite&,
    enc: const u8[32]&,
    ciphertext: const u8[:],
    out: B&,
) -> bool {
    out.push(ECH_CLIENT_OUTER);
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
    let ct_len = ciphertext.len;
    out.push(((ct_len >> 8) & 0xFF) as u8);
    out.push((ct_len & 0xFF) as u8);
    out.append(ciphertext);

    return true;
}

// Builds the ECH extension wire bytes for ClientHelloInner (RFC 9460 Section 6.1).
// Type = 0x01 (inner), empty payload.
fn build_ech_inner_extension<B>(out: B&) {
    out.push(ECH_CLIENT_INNER);
}

// Seals the padded ClientHelloInner using HPKE and the selected ECHConfig.
// Info string: "tls ech\x00" || ECHConfig
fn seal_ech_inner(
    config: const EchConfig&,
    cs: const EchCipherSuite&,
    outer_aad: const u8[:],
    inner_padded: const u8[:],
    ephemeral_sk: const u8[32]&,
    out_enc: u8[32]&,
    out_ct: u8[>..]&,
) -> bool {
    var info: u8[..600] = [];
    info.append("tls ech");
    info.push(0x00);
    for i in config.raw_bytes.len {
        info.push(config.raw_bytes[i]);
    }

    return hpke_seal_base(
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

// Parses and validates retry_configs from Server HelloRetryRequest ECH extension (RFC 9460 Section 5).
// Must contain a valid, parseable ECHConfigList.
fn parse_and_validate_ech_retry_configs(
    ext_data: const u8[:],
    out_config_list: EchConfigList&,
) -> bool {
    guard ext_data.len >= 4 else { return false; }
    return parse_ech_config_list(ext_data, out_config_list);
}

// Parses retry_configs from Server HelloRetryRequest ECH extension.
// Enforces that the payload is a valid RFC 9460 ECHConfigList before copying.
fn parse_ech_hrr_retry_configs(ext_data: const u8[:], out_configs: u8[>..]&) -> bool {
    guard ext_data.len >= 4 else { return false; }
    var parsed_list = EchConfigList { .. };
    guard parse_ech_config_list(ext_data, parsed_list) else { return false; }
    out_configs.clear();
    out_configs.append(ext_data);
    return true;
}

// Verifies the 8-byte ECH acceptance confirmation in ServerHello (RFC 9460 Section 7.2).
// Constant-time comparison against expected confirmation derived from transcript.
fn verify_ech_acceptance_confirmation(
    ext_data: const u8[:],
    expected_confirmation: const u8[8]&,
) -> bool {
    guard ext_data.len == 8 else { return false; }
    var diff: u8 = 0;
    for i in 8 {
        diff |= ext_data[i] ^ expected_confirmation[i];
    }
    return diff == 0;
}

enum EchHandshakeMode {
    Disabled,
    Offered,
    Accepted,
    RejectedWithRetry,
    Bypassed,
}

struct EchFsm {
    mode: EchHandshakeMode = EchHandshakeMode.Disabled,
    has_hrr: bool = false,
    offered_config_id: u8 = 0,
}

// Handles ECH state machine progression on receiving ServerHello or HRR (RFC 9460 Section 6 & 7).
fn ech_fsm_on_server_hello(
    fsm: EchFsm&,
    is_hrr: bool,
    has_ech_ext: bool,
    ech_ext_data: const u8[:],
    expected_confirm: const u8[8]&,
    out_retry_configs: EchConfigList&,
) -> bool {
    if fsm.mode != EchHandshakeMode.Offered {
        // If ECH was not offered, server MUST NOT send ECH extension
        return !has_ech_ext;
    }

    if is_hrr {
        guard !fsm.has_hrr else { return false; } // Strictly only ONE HRR allowed
        fsm.has_hrr = true;
        if has_ech_ext {
            // ECH rejected with retry_configs
            guard parse_and_validate_ech_retry_configs(ech_ext_data, out_retry_configs) else { return false; }
            fsm.mode = EchHandshakeMode.RejectedWithRetry;
            return true;
        } else {
            // ECH accepted in HRR; client continues ECH with ClientHello2
            fsm.mode = EchHandshakeMode.Offered;
            return true;
        }
    } else {
        // Regular ServerHello
        if has_ech_ext {
            // Must verify acceptance confirmation
            guard verify_ech_acceptance_confirmation(ech_ext_data, expected_confirm) else { return false; }
            fsm.mode = EchHandshakeMode.Accepted;
            return true;
        } else {
            // ECH rejected / bypassed by server
            fsm.mode = EchHandshakeMode.Bypassed;
            return true;
        }
    }
}

// RFC 9460 Section 6.1: When ECH is used with 0-RTT, early_data MUST be in ClientHelloInner,
// and MUST NOT appear in ClientHelloOuter.
// A server observing early_data in ClientHelloOuter MUST reject it with illegal_parameter.
fn validate_ech_early_data_placement(is_inner: bool, has_early_data: bool) -> bool {
    if !is_inner && has_early_data {
        return false;
    }
    return true;
}
