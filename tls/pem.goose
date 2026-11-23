// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 7468 PEM textual encoding decoder and PKCS#8 / SEC 1 private key DER loaders.
namespace tls;

import std;
import os;
import core;
import rfc.tls;
import .internal;
import .asn1;
import .types;
import .x509;
import .pki_sig_internal;
import .pki_x509_ext_internal;
import .pki_nc_san_internal;
import .pki_ocsp_internal;
import .pki_crl_internal;

// Scans `raw` starting at `idx` for the next PEM-encapsulated block (RFC 7468).
// Extracts the encapsulation label and decodes the Base64 payload into `out_der`.
// On failure, restores `idx` and clears `out_label` and `out_der`.
//
// Example:
//   raw = "-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n", idx = 0
//   returns: ok = true, out_label = "CERTIFICATE", out_der = [0x01, 0x02, 0x03], idx = 59
fn pem_next_block<B>(
    raw:       const u8[:],
    idx:       i64&,
    out_label: u8[..64]&,
    out_der:   B&,
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
    var der:   u8[..8192] = [];

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

fn bind_server_rsa_key(
    n_be:     const u8[:],
    e_be:     const u8[:],
    d_be:     const u8[:],
    spki_oid: const u8[:],
    cert_pub: const u8[:],
    out_cfg:  ServerHandshakeConfig&,
) -> bool {
    guard spki_oid == rfc::OID_RSA_ENCRYPTION[..] else { return false; }
    let cert_n, cert_e, ok_pub = core::parse_rsa_public_key_der(cert_pub);
    guard ok_pub && core::ct_eq_bytes(n_be, cert_n) && core::ct_eq_bytes(e_be, cert_e) else {
        return false;
    }
    let slot = alloc_rsa_key_slot(n_be, e_be, d_be);
    guard slot >= 0 else { return false; }
    out_cfg.rsa_key_slot = slot;
    out_cfg.key_kind = PrivateKeyKind.Rsa;
    return true;
}

fn bind_server_seed_key(
    key_kind: PrivateKeyKind,
    spki_oid: const u8[:],
    cert_pub: const u8[:],
    out_cfg:  ServerHandshakeConfig&,
) -> bool {
    if key_kind == PrivateKeyKind.Ed25519 {
        let derived_ed = core::ed25519_public_key(out_cfg.priv_seed);
        guard spki_oid == rfc::OID_ED25519[..] && core::ct_eq_bytes(derived_ed[..], cert_pub) else {
            return false;
        }
        out_cfg.key_kind = PrivateKeyKind.Ed25519;
        return true;
    }
    if key_kind == PrivateKeyKind.EcdsaP256 {
        let derived_p256 = core::ecdsa_p256_public_key(out_cfg.priv_seed);
        guard spki_oid == rfc::OID_SECP256R1[..] && core::ct_eq_bytes(derived_p256[..], cert_pub) else {
            return false;
        }
        out_cfg.key_kind = PrivateKeyKind.EcdsaP256;
        return true;
    }
    return false;
}

fn bind_server_pem_key(
    key_label: const u8[:],
    key_der:   const u8[:],
    spki_oid:  const u8[:],
    cert_pub:  const u8[:],
    out_cfg:   ServerHandshakeConfig&,
) -> bool {
    if key_label == "RSA PRIVATE KEY" {
        let n_be, e_be, d_be, ok_r = tls_internal::parse_rsa_pkcs1_private_key_der(key_der);
        guard ok_r else { return false; }
        return bind_server_rsa_key(n_be, e_be, d_be, spki_oid, cert_pub, out_cfg);
    }
    if key_label == "EC PRIVATE KEY" {
        guard tls_internal::parse_sec1_ec_private_key_der(key_der, out_cfg.priv_seed) else { return false; }
        return bind_server_seed_key(PrivateKeyKind.EcdsaP256, spki_oid, cert_pub, out_cfg);
    }
    if key_label == "PRIVATE KEY" {
        let key_kind, ok_ec = tls_internal::parse_pkcs8_private_key_der(key_der, out_cfg.priv_seed);
        if ok_ec {
            return bind_server_seed_key(key_kind, spki_oid, cert_pub, out_cfg);
        }
        let n_be, e_be, d_be, ok_r = tls_internal::parse_pkcs8_rsa_private_key_der(key_der);
        guard ok_r else { return false; }
        return bind_server_rsa_key(n_be, e_be, d_be, spki_oid, cert_pub, out_cfg);
    }
    return false;
}

fn pem_load_extra_certs(
    cert_pem:  const u8[:],
    start_idx: i64,
    out_cfg:   ServerHandshakeConfig&,
) -> bool {
    var idx = start_idx;
    var label: u8[..64]   = [];
    var der:   u8[..4096] = [];
    var parsed = ParsedCert { .. };
    while idx < cert_pem.len {
        let rel_begin = core::find(cert_pem[idx..], tls_internal::PEM_PRE_EB);
        if rel_begin < 0 { break; }
        guard pem_next_block(cert_pem, idx, label, der) else { return false; }
        if label[..] == "CERTIFICATE" {
            guard parse_x509_certificate(der[..], parsed) else { return false; }
            guard out_cfg.extra_certs_der.try_push(copy(der)) else { return false; }
        }
    }
    return true;
}

// Loads a leaf PEM certificate (plus up to 3 intermediate certs) and matching PEM private key
// (Ed25519, ECDSA P-256, or PKCS#1/PKCS#8 RSA) into `ServerHandshakeConfig`.
// On failure, clears certificate buffers, frees any RSA key slot, and zeroizes key material.
//
// Example:
//   load_server_credentials_pem(cert_pem, key_pem, cfg) -> true
fn load_server_credentials_pem(
    cert_pem: const u8[:],
    key_pem:  const u8[:],
    out_cfg:  ServerHandshakeConfig&,
) -> bool {
    release_server_credentials(out_cfg);
    var committed = false;
    defer if !committed {
        release_server_credentials(out_cfg);
    };

    var idx:   i64        = 0;
    var label: u8[..64]   = [];
    var der:   u8[..4096] = [];
    guard pem_next_block(cert_pem, idx, label, der) && label[..] == "CERTIFICATE" else {
        return false;
    }
    var parsed_leaf = ParsedCert { .. };
    guard parse_x509_certificate(der[..], parsed_leaf) else { return false; }
    guard out_cfg.cert_der.try_set(der[..]) else { return false; }
    guard pem_load_extra_certs(cert_pem, idx, out_cfg) else { return false; }

    var key_idx:   i64        = 0;
    var key_label: u8[..64]   = [];
    var key_der:   u8[..4096] = [];
    defer core::secure_zeroize_slice(key_der[..]);
    guard pem_next_block(key_pem, key_idx, key_label, key_der) else { return false; }

    let spki_oid = span_slice(out_cfg.cert_der[..], parsed_leaf.spki_alg_oid);
    var cert_pub = span_slice(out_cfg.cert_der[..], parsed_leaf.spki_pubkey);
    if cert_pub.len >= 2 && cert_pub[0] == 0 {
        cert_pub = cert_pub[1..];
    }
    guard bind_server_pem_key(key_label[..], key_der[..], spki_oid, cert_pub, out_cfg) else {
        return false;
    }
    committed = true;
    return true;
}

// Returns true when the leaf certificate in `cert_pem` expires within `renew_before_sec`
// seconds of `now_unix` or when `cert_pem` cannot be decoded (RFC 5280 Section 4.1.2.5: Validity).
//
// Example:
//   cert_expires_within_sec(cert_pem, now_unix, 86400) -> false
fn cert_expires_within_sec(
    cert_pem:         const u8[:],
    now_unix:         i64,
    renew_before_sec: i64,
) -> bool {
    var idx:   i64        = 0;
    var label: u8[..64]   = [];
    var der:   u8[..4096] = [];
    while idx < cert_pem.len {
        let rel = core::find(cert_pem[idx..], tls_internal::PEM_PRE_EB);
        if rel < 0 { break; }
        guard pem_next_block(cert_pem, idx, label, der) else { return true; }
        if label[..] == "CERTIFICATE" {
            var parsed = ParsedCert { .. };
            guard parse_x509_certificate(der[..], parsed) else { return true; }
            return core::sub_sat_i64(parsed.validity_not_after, now_unix) <= renew_before_sec;
        }
    }
    return true;
}

extern fn native_tls_system_roots_by_subject(
    subject_der_tlv: const u8[:],
    out_buf:         u8[:],
    out_written:     i32&,
) -> i32 = "wing_tls_system_roots_by_subject";

const SYSTEM_PEM_BUNDLE_PATHS: const u8[:][4] = [
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/ca-bundle.pem",
    "/etc/ssl/cert.pem",
];

fn try_add_matching_pem_cert(
    store:      TrustAnchorStore&,
    label:      const u8[:],
    der:        const u8[:],
    issuer_raw: const u8[:],
    parsed:     ParsedCert&,
) -> bool {
    guard label == "CERTIFICATE" && parse_x509_certificate(der, parsed) else { return false; }
    guard span_slice(der, parsed.subject_raw) == issuer_raw else { return false; }
    return add_trust_anchor_cert_der(store, der);
}

// Scans a PEM CA bundle file and appends only certificates whose Subject DN equals `issuer_raw`.
//
// Example:
//   load_matching_roots_from_pem_file(store, "/etc/ssl/cert.pem", issuer_dn_inner) -> 1
fn load_matching_roots_from_pem_file(
    store:      TrustAnchorStore&,
    path:       const u8[:],
    issuer_raw: const u8[:],
) -> i64 {
    guard path.len > 0 && issuer_raw.len > 0 else { return 0; }
    var raw_pem: u8[>..] = [];
    guard read_file(path, raw_pem) && raw_pem.len > 0 && raw_pem.len <= tls_internal::PEM_MAX_BUNDLE_BYTES else {
        return 0;
    }

    var idx:   i64        = 0;
    var added: i64        = 0;
    var label: u8[..64]   = [];
    var der:   u8[..8192] = [];
    var parsed = ParsedCert { .. };
    while idx < raw_pem.len && store.anchors.len < store.anchors.cap {
        let rel = core::find(raw_pem[idx..], tls_internal::PEM_PRE_EB);
        if rel < 0 { break; }
        if !pem_next_block(raw_pem[..], idx, label, der) {
            idx = core::add_sat_i64(idx, core::add_sat_i64(rel, tls_internal::PEM_PRE_EB.len));
            continue;
        }
        if try_add_matching_pem_cert(store, label[..], der[..], issuer_raw, parsed) {
            added = core::add_sat_i64(added, 1);
        }
    }
    return added;
}

fn ingest_packed_der_roots(store: TrustAnchorStore&, packed: const u8[:]) -> i64 {
    var cur = core::cursor_from(packed);
    var added: i64 = 0;
    while cur.buf.len >= 4 && store.anchors.len < store.anchors.cap {
        let der_len, ok_l = cur.read_u32();
        guard ok_l && der_len > 0 && der_len <= 4096 else { break; }
        let der, ok_d = cur.read_bytes(der_len);
        guard ok_d else { break; }
        if add_trust_anchor_cert_der(store, der) {
            added = core::add_sat_i64(added, 1);
        }
    }
    return added;
}

// Loads matching root CAs from `SSL_CERT_FILE` (if set), else the OS trust store
// (Windows Crypt32 ROOT store excluding Disallowed/non-ServerAuth roots, or Unix/macOS
// standard PEM CA bundle paths) into `store` for `issuer_raw`.
//
// Example:
//   load_system_roots_for_issuer(store, top_cert_issuer_inner) -> 1
fn load_system_roots_for_issuer(store: TrustAnchorStore&, issuer_raw: const u8[:]) -> i64 {
    guard issuer_raw.len > 0 && store.anchors.len < store.anchors.cap else { return 0; }

    var env_path: u8[>..] = [];
    if env("SSL_CERT_FILE", env_path) && env_path.len > 0 {
        return load_matching_roots_from_pem_file(store, env_path[..], issuer_raw);
    }

    var issuer_tlv: u8[..1024] = [];
    guard tls_internal::encode_der_name_tlv(issuer_raw, issuer_tlv) else { return 0; }

    var packed:  u8[16384] = [0; 16384];
    var written: i32       = 0;
    let rc = native_tls_system_roots_by_subject(issuer_tlv[..], packed[..], written);
    if rc >= 0 {
        guard written > 0 && written <= packed.len else { return 0; }
        return ingest_packed_der_roots(store, packed[..written]);
    }

    for path in SYSTEM_PEM_BUNDLE_PATHS {
        let n = load_matching_roots_from_pem_file(store, path, issuer_raw);
        if n > 0 { return n; }
    }
    return 0;
}
