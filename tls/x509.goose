// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Deterministic zero-allocation X.509 PKI certificate parser and RFC 5280 chain validator.
// Conforms to RFC 5280, RFC 6125 (SAN matching), and RFC 8446 Section 4.4.3 (CertificateVerify).
namespace tls;

import std;
import core from "..";
import .internal;
import .record;
import .asn1;
import .types;
import .sct;
import .pki_internal;
import .x509_san;
import .x509_chain_internal;

// Parses raw X.509 certificate DER into zero-allocation ParsedCert descriptor (RFC 5280 Section 4.1).
// Extracts spans for tbsCertificate, serial, issuer, validity, subject, SPKI, and signature.
//
// Example:
//   raw_cert = "\x30\x82\x01\x20\x30\x81\xC8..." (valid X.509 DER Certificate)
//   returns: true, out.raw_len = 292, out.signature_value.length = 64
fn parse_x509_certificate(raw_cert: const u8[:], out: ParsedCert&) -> bool {
    out = ParsedCert { .. };
    var committed = false;
    defer if !committed { out = ParsedCert { .. }; };

    out.raw_len = raw_cert.len as u32;
    var cert_seq = core::cursor_from(raw_cert[..0]);
    guard tls_internal::x509_read_outer_sequence(raw_cert, cert_seq) else { return false; }

    // TBSCertificate SEQUENCE
    let tbs_raw_start = cert_seq.buf;
    var tbs_seq = core::cursor_from(raw_cert[..0]);
    if !get_asn1_element(cert_seq, rfc::ASN1_TAG_SEQUENCE, tbs_seq) { return false; }
    let tbs_tlv_len = core::sub_sat_i64(tbs_raw_start.len, cert_seq.buf.len);
    out.tbs_cert = make_span(raw_cert, tbs_raw_start[..tbs_tlv_len]);

    let inner_sig_span, ok_tbs = tls_internal::x509_read_tbs_components(raw_cert, tbs_seq, out);
    guard ok_tbs else { return false; }
    let inner_sig_alg = span_slice(raw_cert, inner_sig_span);
    guard tls_internal::x509_read_outer_signature(raw_cert, cert_seq, inner_sig_alg, out) else { return false; }
    committed = true;
    return true;
}

fn add_trust_anchor(store: TrustAnchorStore&, subject_raw: const u8[:], spki_raw: const u8[:]) -> bool {
    var anchor = TrustAnchor {
        subject_dn_sha256: core::sha256(subject_raw),
        spki_sha256:       core::sha256(spki_raw),
        is_valid:          true,
    };
    let subj_ok = anchor.subject_raw.try_set(subject_raw);
    let pk_ok = tls_internal::extract_spki_pubkey_material(spki_raw, anchor.spki_pubkey);
    anchor.has_pub_material = subj_ok && pk_ok;
    if !anchor.has_pub_material {
        anchor.subject_raw.clear();
        anchor.spki_pubkey.clear();
    }
    return store.anchors.try_push(anchor);
}

// Parses a DER-encoded X.509 certificate and adds its Subject DN and SPKI to the trust anchor store.
fn add_trust_anchor_cert_der(store: TrustAnchorStore&, raw_cert_der: const u8[:]) -> bool {
    var cert = ParsedCert { .. };
    guard parse_x509_certificate(raw_cert_der, cert) else { return false; }
    let subj = span_slice(raw_cert_der, cert.subject_raw);
    let spki = span_slice(raw_cert_der, cert.spki_raw);
    guard subj.len > 0 && spki.len > 0 else { return false; }

    var anchor = TrustAnchor {
        subject_dn_sha256:     core::sha256(subj),
        spki_sha256:           core::sha256(spki),
        key_usage:             cert.key_usage,
        has_key_usage:         cert.has_key_usage,
        has_basic_constraints: cert.has_basic_constraints,
        is_ca:                 cert.is_ca,
        path_len_constraint:   cert.path_len_constraint,
        validity_not_before:   cert.validity_not_before,
        validity_not_after:    cert.validity_not_after,
        has_validity:          true,
        is_valid:              true,
    };
    var pk = span_slice(raw_cert_der, cert.spki_pubkey);
    if pk.len >= 2 && pk[0] == 0 {
        pk = pk[1..];
    }
    let subj_ok = anchor.subject_raw.try_set(subj);
    let pk_ok = anchor.spki_pubkey.try_set(pk);
    anchor.has_pub_material = subj_ok && pk_ok;
    if cert.has_skid {
        anchor.has_skid = anchor.skid_key_id.try_set(span_slice(raw_cert_der, cert.skid_key_id));
    }
    if !anchor.has_pub_material {
        anchor.subject_raw.clear();
        anchor.spki_pubkey.clear();
    }
    return store.anchors.try_push(anchor);
}

// RFC 5280 Certificate Chain Validation.
// Returns TlsAlert.CloseNotify (0) on success, or appropriate fatal alert.
fn verify_certificate_chain(
    chain_certs: const ParsedCert[..8]&,
    raw_certs:   const u8[:][..8]&,
    trust_store: const TrustAnchorStore&,
    now_unix:    i64,
) -> Alert {
    guard chain_certs.len > 0 && chain_certs.len <= tls_internal::MAX_CHAIN_DEPTH else { return Alert.BadCertificate; }
    guard raw_certs.len > 0 && raw_certs.len == chain_certs.len else { return Alert.BadCertificate; }

    if tls_internal::x509_detect_chain_cycles(chain_certs, raw_certs) {
        return Alert.BadCertificate;
    }

    let is_direct_trust_anchor = chain_certs.len == 1 &&
        matches_trust_anchor(trust_store, chain_certs[0], raw_certs[0]);

    if chain_certs.len == 1 && chain_certs[0].is_ca && !is_direct_trust_anchor {
        return Alert.UnknownCa;
    }

    let nodes_alert = tls_internal::x509_validate_chain_nodes(
        chain_certs, raw_certs, trust_store, is_direct_trust_anchor, now_unix,
    );
    guard nodes_alert == Alert.CloseNotify else { return nodes_alert; }

    return tls_internal::x509_enforce_chain_name_constraints(chain_certs, raw_certs);
}

// Verifies that signature scheme is strictly bound to the public key curve/algorithm.
// Enforces that legacy PKCS#1 v1.5 RSA schemes are rejected in TLS 1.3.
fn verify_signature_scheme_curve_binding(
    sig_scheme: u16,
    spki_oid:   const u8[:],
) -> bool {
    if rfc::is_forbidden_tls13_sig_scheme(sig_scheme) {
        return false;
    }
    if sig_scheme == rfc::SIG_SCHEME_ECDSA_SECP256R1_SHA256 {
        return spki_oid == rfc::OID_SECP256R1[..];
    } else if sig_scheme == rfc::SIG_SCHEME_ECDSA_SECP384R1_SHA384 {
        return spki_oid == rfc::OID_SECP384R1[..];
    } else if sig_scheme == rfc::SIG_SCHEME_ED25519 {
        return spki_oid == rfc::OID_ED25519[..];
    } else if sig_scheme == rfc::SIG_SCHEME_RSA_PSS_RSAE_SHA256 || sig_scheme == rfc::SIG_SCHEME_RSA_PSS_RSAE_SHA384 {
        return spki_oid == rfc::OID_RSA_ENCRYPTION[..];
    }
    return false; // Rejects legacy PKCS#1 (0x0401, 0x0501) and unknown schemes
}

// Builds the CertificateVerify signed message input (RFC 8446 Section 4.4.3):
// 64 spaces (0x20) || "TLS 1.3, " || context_string || 0x00 || Transcript-Hash
// Total length: 64 + 33 + 1 + hash_len = 98 + hash_len.
fn build_certificate_verify_message(
    is_server:       bool,
    transcript_hash: const u8[:],
    out:             u8[:],
) -> i64, bool {
    var buf: u8[..256] = [];
    for _ in 64 { buf.push(0x20); }
    let ctx = if is_server {
        "TLS 1.3, server CertificateVerify\x00"
    } else {
        "TLS 1.3, client CertificateVerify\x00"
    };
    guard buf.try_append(ctx) && buf.try_append(transcript_hash) else { return 0, false; }
    guard out.len >= buf.len else { return 0, false; }
    core::ct_copy_bytes(out[..buf.len], buf[..]);
    return buf.len, true;
}
