// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 7468 PEM textual encoding decoder and PKCS#8 / SEC 1 private key DER loaders.
namespace tls;

import std;
import core;
import rfc.tls;
import .internal;
import .asn1;
import .types;
import .x509;
import .pki_internal;

// Scans `raw` starting at `idx` for the next PEM-encapsulated block (RFC 7468).
// Extracts the encapsulation label and decodes the Base64 payload into `out_der`.
// On failure, restores `idx` and clears `out_label` and `out_der`.
//
// Example:
//   raw = "-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n", idx = 0
//   returns: ok = true, out_label = "CERTIFICATE", out_der = [0x01, 0x02, 0x03], idx = 59
fn pem_next_block(
    raw:       const u8[:],
    idx:       i64&,
    out_label: u8[..64]&,
    out_der:   u8[..4096]&,
) -> bool {
    let saved_idx = idx;
    var committed = false;
    defer if !committed {
        idx = saved_idx;
        out_label.clear();
        out_der.clear();
    };

    var body_start: i64 = 0;
    guard tls_internal::pem_find_begin_line(raw, idx, out_label, body_start) else { return false; }
    var body_end: i64 = 0;
    var next_idx: i64 = 0;
    guard tls_internal::pem_find_end_line(raw, body_start, out_label[..], body_end, next_idx) else {
        return false;
    }
    guard tls_internal::pem_decode_body(raw[body_start..body_end], out_der) else { return false; }

    idx = next_idx;
    committed = true;
    return true;
}

// Parses all "CERTIFICATE" PEM blocks in `pem_bundle` into `store`.
// Returns `(added_count, ok)` where `ok` is true if at least one certificate was added
// and no malformed PEM block was encountered.
//
// Example:
//   pem_bundle = "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n"
//   returns: added_count = 1, ok = true
fn add_trust_anchors_pem(store: TrustAnchorStore&, pem_bundle: const u8[:]) -> i64, bool {
    var idx:   i64        = 0;
    var count: i64        = 0;
    var label: u8[..64]   = [];
    var der:   u8[..4096] = [];

    while idx < pem_bundle.len {
        let rel_begin = core::find(pem_bundle[idx..], tls_internal::PEM_PRE_EB);
        if rel_begin < 0 { break; }
        guard pem_next_block(pem_bundle, idx, label, der) else { return count, false; }
        if label[..] == "CERTIFICATE" {
            guard add_trust_anchor_cert_der(store, der[..]) else { return count, false; }
            count = core::add_sat_i64(count, 1);
        }
    }
    return count, count > 0;
}

// Reads a PEM CA bundle file from `path`, validates size bounds, and loads all
// "CERTIFICATE" blocks into `store`. Zeroizes the temporary buffer and rolls back
// `store.anchors` on any read, size, or parse error.
//
// Example:
//   load_trust_anchors_pem_file(store, "ca-bundle.pem")
//   returns: added_count = 1, ok = true
fn load_trust_anchors_pem_file(store: TrustAnchorStore&, path: const u8[:]) -> i64, bool {
    guard path.len > 0 && path.len <= 4096 else { return 0, false; }
    var raw_pem: u8[>..] = [];
    defer core::secure_zeroize_slice(raw_pem[..]);
    guard read_file(path, raw_pem) else { return 0, false; }
    guard raw_pem.len > 0 && raw_pem.len <= tls_internal::PEM_MAX_BUNDLE_BYTES else { return 0, false; }

    let saved_len = store.anchors.len;
    let added, ok_pem = add_trust_anchors_pem(store, raw_pem[..]);
    guard ok_pem else {
        store.anchors.resize(saved_len);
        return 0, false;
    }
    return added, true;
}

// Parses a PEM-encoded unencrypted private key ("PRIVATE KEY" PKCS#8 or "EC PRIVATE KEY" SEC 1).
// Zeroizes temporary DER buffers and `out_key` on failure.
//
// Example:
//   pem = "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n"
//   returns: kind = PrivateKeyKind.Ed25519, ok = true
fn parse_private_key_pem(pem: const u8[:], out_key: u8[32]&) -> PrivateKeyKind, bool {
    var idx:   i64        = 0;
    var label: u8[..64]   = [];
    var der:   u8[..4096] = [];
    defer core::secure_zeroize_slice(der[..]);

    guard pem_next_block(pem, idx, label, der) else {
        core::secure_zeroize_32(out_key);
        return PrivateKeyKind.Unknown, false;
    }
    if label[..] == "PRIVATE KEY" {
        return tls_internal::parse_pkcs8_private_key_der(der[..], out_key);
    }
    if label[..] == "EC PRIVATE KEY" {
        guard tls_internal::parse_sec1_ec_private_key_der(der[..], out_key) else {
            return PrivateKeyKind.Unknown, false;
        }
        return PrivateKeyKind.EcdsaP256, true;
    }
    core::secure_zeroize_32(out_key);
    return PrivateKeyKind.Unknown, false;
}

// Loads a PEM certificate and matching PEM private key into `TlsServerHandshakeConfig`.
// Validates X.509 DER structure and ensures the private key algorithm matches the certificate SPKI.
// On failure, clears `out_cfg.cert_der` and zeroizes `out_cfg.priv_seed`.
//
// Example:
//   load_server_credentials_pem(cert_pem, key_pem, cfg) -> true
fn load_server_credentials_pem(
    cert_pem: const u8[:],
    key_pem:  const u8[:],
    out_cfg:  ServerHandshakeConfig&,
) -> bool {
    var committed = false;
    defer if !committed {
        out_cfg.cert_der.clear();
        core::secure_zeroize_32(out_cfg.priv_seed);
    };

    var idx:   i64        = 0;
    var label: u8[..64]   = [];
    var der:   u8[..4096] = [];
    guard pem_next_block(cert_pem, idx, label, der) && label[..] == "CERTIFICATE" else {
        return false;
    }
    var parsed_cert = ParsedCert { .. };
    guard parse_x509_certificate(der[..], parsed_cert) else { return false; }
    guard out_cfg.cert_der.try_set(der[..]) else { return false; }

    let key_kind, ok_key = parse_private_key_pem(key_pem, out_cfg.priv_seed);
    guard ok_key else { return false; }

    let spki_oid = span_slice(der[..], parsed_cert.spki_alg_oid);
    if key_kind == PrivateKeyKind.Ed25519 {
        guard spki_oid == rfc::OID_ED25519[..] else { return false; }
    } else if key_kind == PrivateKeyKind.EcdsaP256 {
        guard spki_oid == rfc::OID_SECP256R1[..] else { return false; }
    } else {
        return false;
    }

    committed = true;
    return true;
}
