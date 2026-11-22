// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal X.509 certificate chain validation, linkage, and cycle-detection helpers (RFC 5280 §6).
namespace tls_internal;

import std;
import core;
import .internal;
import .asn1;
import .record;
import .types;
import .pki_internal;
import .x509_san;

fn validate_chain_cert_validity(cert: const tls::ParsedCert&, now_unix: i64) -> tls::Alert {
    // RFC 5280 §4.1.2.5: Inversion check (notBefore <= notAfter)
    if cert.validity_not_before > cert.validity_not_after {
        return tls::Alert.BadCertificate;
    }
    if now_unix < cert.validity_not_before || now_unix > cert.validity_not_after {
        return tls::Alert.CertificateExpired;
    }
    return tls::Alert.CloseNotify;
}

inline fn required_eku_mask_for_role(role: tls::CertValidationRole) -> u8 {
    if role == tls::CertValidationRole.Server {
        return rfc::EKU_SERVER_AUTH | rfc::EKU_ANY;
    }
    if role == tls::CertValidationRole.Client {
        return rfc::EKU_CLIENT_AUTH | rfc::EKU_ANY;
    }
    return rfc::EKU_SERVER_AUTH | rfc::EKU_CLIENT_AUTH | rfc::EKU_ANY;
}

fn validate_end_entity_constraints(
    cert: const tls::ParsedCert&,
    role: tls::CertValidationRole = tls::CertValidationRole.Server,
) -> tls::Alert {
    // RFC 5280 / RFC 8446 §4.4.2: End-entity certificate MUST NOT be a CA
    if cert.is_ca {
        return tls::Alert.BadCertificate;
    }
    // End-entity MUST NOT assert keyCertSign
    if cert.has_key_usage && (cert.key_usage & rfc::KEY_USAGE_KEY_CERT_SIGN) != 0 {
        return tls::Alert.UnsupportedCertificate;
    }
    // RFC 5280 Section 4.2.1.12: Extended Key Usage - End-entity EKU must permit the TLS peer role.
    if cert.has_eku && (cert.eku_mask & required_eku_mask_for_role(role)) == 0 {
        return tls::Alert.UnsupportedCertificate;
    }
    // RFC 5280 §4.2.1.10: Name constraints MUST NOT be used in end-entity certificates
    if cert.has_name_constraints {
        return tls::Alert.BadCertificate;
    }
    return tls::Alert.CloseNotify;
}

fn validate_intermediate_ca_constraints(cert: const tls::ParsedCert&, depth: i64) -> tls::Alert {
    // Intermediate CA MUST have basicConstraints asserted with cA: TRUE
    if !cert.has_basic_constraints || !cert.is_ca {
        return tls::Alert.BadCertificate;
    }
    // Intermediate CA MUST assert keyCertSign if KeyUsage is present
    if cert.has_key_usage && (cert.key_usage & rfc::KEY_USAGE_KEY_CERT_SIGN) == 0 {
        return tls::Alert.UnsupportedCertificate;
    }
    // RFC 5280 Section 4.2.1.9: Basic Constraints - max non-self-issued intermediate certs following this cert.
    if cert.path_len_constraint >= 0 && (depth - 1) > cert.path_len_constraint {
        return tls::Alert.BadCertificate;
    }
    return tls::Alert.CloseNotify;
}

fn x509_is_cert_duplicate(
    raw_j:  const u8[:],
    cert_j: const tls::ParsedCert&,
    raw_k:  const u8[:],
    cert_k: const tls::ParsedCert&,
) -> bool {
    let s_j = tls::span_slice(raw_j, cert_j.subject_raw);
    let spki_j = tls::span_slice(raw_j, cert_j.spki_raw);
    let s_k = tls::span_slice(raw_k, cert_k.subject_raw);
    let spki_k = tls::span_slice(raw_k, cert_k.spki_raw);
    return s_j.len > 0 && s_j == s_k && spki_j.len > 0 && spki_j == spki_k;
}

inline fn x509_is_self_issued(cert: const tls::ParsedCert&, raw_cert: const u8[:]) -> bool {
    let iss = tls::span_slice(raw_cert, cert.issuer_raw);
    let sub = tls::span_slice(raw_cert, cert.subject_raw);
    return iss.len > 0 && iss == sub;
}

fn x509_count_non_self_issued_below(
    chain_certs: const tls::ParsedCert[..8]&,
    raw_certs:   const u8[:][..8]&,
    up_to_idx:   i64,
) -> i64 {
    var count: i64 = 0;
    var j:     i64 = 1;
    while j < up_to_idx {
        if !x509_is_self_issued(chain_certs[j], raw_certs[j]) {
            count = core::add_sat_i64(count, 1);
        }
        j = core::add_sat_i64(j, 1);
    }
    return count;
}

// RFC 5280 Certificate Chain Validation.
// Returns TlsAlert.CloseNotify (0) on success, or appropriate fatal alert.
fn x509_detect_chain_cycles(chain_certs: const tls::ParsedCert[..8]&, raw_certs: const u8[:][..8]&) -> bool {
    for j in chain_certs.len {
        for k in chain_certs.len {
            if j < k && x509_is_cert_duplicate(raw_certs[j], chain_certs[j], raw_certs[k], chain_certs[k]) {
                return true;
            }
        }
    }
    return false;
}

inline fn x509_check_cert_rsa_min_bits(cert: const tls::ParsedCert&, raw_cert: const u8[:]) -> bool {
    let spki_oid = tls::span_slice(raw_cert, cert.spki_alg_oid);
    guard spki_oid == rfc::OID_RSA_ENCRYPTION[..] else { return true; }
    var spki_pk = tls::span_slice(raw_cert, cert.spki_pubkey);
    if spki_pk.len >= 2 && spki_pk[0] == 0 {
        spki_pk = spki_pk[1..];
    }
    return is_valid_rsa_pubkey_min_bits(spki_pk);
}

fn x509_verify_cert_sig_with_pss(
    child_cert:  const tls::ParsedCert&,
    child_raw:   const u8[:],
    parent_cert: const tls::ParsedCert&,
    parent_raw:  const u8[:],
) -> tls::Alert {
    guard child_cert.signature_value.length > 0 && child_cert.tbs_cert.length > 0 else {
        return tls::Alert.BadCertificate;
    }
    let sig_oid = tls::span_slice(child_raw, child_cert.sig_alg_oid);
    let tbs_data = tls::span_slice(child_raw, child_cert.tbs_cert);
    let sig_bytes = tls::span_slice(child_raw, child_cert.signature_value);
    var parent_pubkey = tls::span_slice(parent_raw, parent_cert.spki_pubkey);
    if parent_pubkey.len >= 2 && parent_pubkey[0] == 0 {
        parent_pubkey = parent_pubkey[1..];
    }
    return x509_verify_signature_by_oid(
        sig_oid, tbs_data, sig_bytes, parent_pubkey, tls::Alert.BadCertificate, child_cert.pss_hash_id,
    );
}

fn x509_validate_single_chain_cert(
    cert:                   const tls::ParsedCert&,
    raw_cert:               const u8[:],
    i:                      i64,
    non_self_issued_below:  i64,
    is_direct_trust_anchor: bool,
    now_unix:               i64,
    role:                   tls::CertValidationRole = tls::CertValidationRole.Server,
) -> tls::Alert {
    if cert.has_unsupported_critical {
        return tls::Alert.UnsupportedExtension;
    }
    if cert.has_malformed_policy_constraints {
        return tls::Alert.BadCertificate;
    }
    guard x509_check_cert_rsa_min_bits(cert, raw_cert) else {
        return tls::Alert.BadCertificate;
    }
    if cert.has_san {
        var sans: tls::SanEntry[..64] = [];
        guard tls::get_cert_san_extension(cert, raw_cert, sans) else {
            return tls::Alert.BadCertificate;
        }
    }

    let val_alert = validate_chain_cert_validity(cert, now_unix);
    guard val_alert == tls::Alert.CloseNotify else { return val_alert; }

    let sig_oid = tls::span_slice(raw_cert, cert.sig_alg_oid);
    if rfc::is_forbidden_cert_signature_algorithm(sig_oid) {
        return tls::Alert.UnsupportedCertificate;
    }

    if i == 0 && !is_direct_trust_anchor {
        return validate_end_entity_constraints(cert, role);
    } else if i > 0 {
        return validate_intermediate_ca_constraints(cert, core::add_sat_i64(non_self_issued_below, 1));
    }
    return tls::Alert.CloseNotify;
}

fn x509_validate_chain_linkage(
    child_cert:  const tls::ParsedCert&,
    child_raw:   const u8[:],
    parent_cert: const tls::ParsedCert&,
    parent_raw:  const u8[:],
) -> tls::Alert {
    let issuer_slice = tls::span_slice(child_raw, child_cert.issuer_raw);
    let next_subject_slice = tls::span_slice(parent_raw, parent_cert.subject_raw);
    if issuer_slice != next_subject_slice {
        return tls::Alert.UnknownCa;
    }

    if child_cert.has_akid && parent_cert.has_skid {
        let child_akid = tls::span_slice(child_raw, child_cert.akid_key_id);
        let parent_skid = tls::span_slice(parent_raw, parent_cert.skid_key_id);
        if child_akid != parent_skid {
            return tls::Alert.UnknownCa;
        }
    }
    if child_cert.signature_value.length > 0 {
        return x509_verify_cert_sig_with_pss(child_cert, child_raw, parent_cert, parent_raw);
    }
    return tls::Alert.CloseNotify;
}

fn x509_check_child_sans_against_nc(
    nc_entries: const tls::NameConstraintEntry[..16]&,
    child_cert: const tls::ParsedCert&,
    child_raw:  const u8[:],
) -> bool {
    guard child_cert.has_san else { return true; }
    var child_sans: tls::SanEntry[..64] = [];
    guard tls::get_cert_san_extension(child_cert, child_raw, child_sans) else { return false; }
    for s_idx in child_sans.len {
        if !tls::check_name_constraints(nc_entries, child_sans[s_idx]) {
            return false;
        }
    }
    return true;
}

fn x509_enforce_single_cert_nc(
    chain_certs: const tls::ParsedCert[..8]&,
    raw_certs:   const u8[:][..8]&,
    k:           i64,
) -> bool {
    guard chain_certs[k].has_name_constraints else { return true; }
    var nc_entries: tls::NameConstraintEntry[..16] = [];
    let nc_bytes = tls::span_slice(raw_certs[k], chain_certs[k].name_constraints_raw);
    guard tls::parse_name_constraints(nc_bytes, nc_entries) else { return false; }
    for j in k {
        guard x509_check_child_sans_against_nc(nc_entries, chain_certs[j], raw_certs[j]) else {
            return false;
        }
    }
    return true;
}

fn x509_enforce_chain_name_constraints(
    chain_certs: const tls::ParsedCert[..8]&,
    raw_certs:   const u8[:][..8]&,
) -> tls::Alert {
    for k in chain_certs.len {
        guard x509_enforce_single_cert_nc(chain_certs, raw_certs, k) else {
            return tls::Alert.BadCertificate;
        }
    }
    return tls::Alert.CloseNotify;
}

fn x509_find_matching_trust_anchor(
    store:    const tls::TrustAnchorStore&,
    cert:     const tls::ParsedCert&,
    raw_cert: const u8[:],
) -> i64 {
    let s_hash = core::sha256(tls::span_slice(raw_cert, cert.subject_raw));
    let spki_hash = core::sha256(tls::span_slice(raw_cert, cert.spki_raw));
    for i in store.anchors.len {
        let a .= store.anchors[i];
        if a.is_valid &&
            core::ct_eq_tag32(a.subject_dn_sha256, s_hash) &&
            core::ct_eq_tag32(a.spki_sha256, spki_hash) {
            return i;
        }
    }
    return -1;
}

fn x509_enforce_anchor_name_constraints(
    anchor:      const tls::TrustAnchor&,
    chain_certs: const tls::ParsedCert[..8]&,
    raw_certs:   const u8[:][..8]&,
    child_count: i64,
) -> tls::Alert {
    guard anchor.has_name_constraints else { return tls::Alert.CloseNotify; }
    var nc_entries: tls::NameConstraintEntry[..16] = [];
    guard tls::parse_name_constraints(anchor.name_constraints_raw[..], nc_entries) else {
        return tls::Alert.BadCertificate;
    }
    for j in child_count {
        guard x509_check_child_sans_against_nc(nc_entries, chain_certs[j], raw_certs[j]) else {
            return tls::Alert.BadCertificate;
        }
    }
    return tls::Alert.CloseNotify;
}

fn x509_verify_cert_against_anchor(
    cert:                  const tls::ParsedCert&,
    raw_cert:              const u8[:],
    anchor:                const tls::TrustAnchor&,
    non_self_issued_count: i64,
    now_unix:              i64,
) -> tls::Alert {
    if anchor.has_basic_constraints && !anchor.is_ca {
        return tls::Alert.BadCertificate;
    }
    if anchor.has_key_usage && (anchor.key_usage & rfc::KEY_USAGE_KEY_CERT_SIGN) == 0 {
        return tls::Alert.UnsupportedCertificate;
    }
    if anchor.path_len_constraint >= 0 && non_self_issued_count > anchor.path_len_constraint {
        return tls::Alert.BadCertificate;
    }
    if anchor.has_validity {
        if anchor.validity_not_before > anchor.validity_not_after {
            return tls::Alert.BadCertificate;
        }
        if now_unix < anchor.validity_not_before || now_unix > anchor.validity_not_after {
            return tls::Alert.CertificateExpired;
        }
    }
    let sig_oid = tls::span_slice(raw_cert, cert.sig_alg_oid);
    let tbs_data = tls::span_slice(raw_cert, cert.tbs_cert);
    let sig_bytes = tls::span_slice(raw_cert, cert.signature_value);
    return x509_verify_signature_by_oid(
        sig_oid, tbs_data, sig_bytes, anchor.spki_pubkey[..], tls::Alert.BadCertificate, cert.pss_hash_id,
    );
}

fn x509_validate_trust_anchor_node(
    chain_certs:           const tls::ParsedCert[..8]&,
    raw_certs:             const u8[:][..8]&,
    top_idx:               i64,
    trust_store:           const tls::TrustAnchorStore&,
    non_self_issued_count: i64,
    now_unix:              i64,
) -> tls::Alert {
    let cert .= chain_certs[top_idx];
    let raw_cert = raw_certs[top_idx];
    let direct_idx = x509_find_matching_trust_anchor(trust_store, cert, raw_cert);
    if direct_idx >= 0 {
        let issuer_slice = tls::span_slice(raw_cert, cert.issuer_raw);
        let subject_slice = tls::span_slice(raw_cert, cert.subject_raw);
        if issuer_slice == subject_slice && cert.signature_value.length > 0 {
            let self_alert = x509_verify_cert_sig_with_pss(cert, raw_cert, cert, raw_cert);
            guard self_alert == tls::Alert.CloseNotify else { return self_alert; }
        }
        return x509_enforce_anchor_name_constraints(
            trust_store.anchors[direct_idx], chain_certs, raw_certs, top_idx,
        );
    }

    guard cert.signature_value.length > 0 && cert.tbs_cert.length > 0 else {
        return tls::Alert.BadCertificate;
    }

    let issuer_slice = tls::span_slice(raw_cert, cert.issuer_raw);
    let child_count = core::add_sat_i64(top_idx, 1);
    var saw_candidate = false;
    var last_alert = tls::Alert.UnknownCa;
    for i in trust_store.anchors.len {
        let anchor .= trust_store.anchors[i];
        guard anchor.is_valid && anchor.has_pub_material else { continue; }
        guard anchor.subject_raw[..] == issuer_slice else { continue; }
        if cert.has_akid && anchor.has_skid {
            guard tls::span_slice(raw_cert, cert.akid_key_id) == anchor.skid_key_id[..] else { continue; }
        }
        saw_candidate = true;
        var alert = x509_verify_cert_against_anchor(cert, raw_cert, anchor, non_self_issued_count, now_unix);
        if alert == tls::Alert.CloseNotify {
            alert = x509_enforce_anchor_name_constraints(anchor, chain_certs, raw_certs, child_count);
        }
        if alert == tls::Alert.CloseNotify {
            return tls::Alert.CloseNotify;
        }
        last_alert = alert;
    }
    return if saw_candidate { last_alert } else { tls::Alert.UnknownCa };
}

fn x509_validate_chain_nodes(
    chain_certs:            const tls::ParsedCert[..8]&,
    raw_certs:              const u8[:][..8]&,
    trust_store:            const tls::TrustAnchorStore&,
    is_direct_trust_anchor: bool,
    now_unix:               i64,
    role:                   tls::CertValidationRole = tls::CertValidationRole.Server,
) -> tls::Alert {
    let n = min(chain_certs.len, raw_certs.len);
    for i in n {
        let non_si_below = x509_count_non_self_issued_below(chain_certs, raw_certs, i);
        let cert_alert = x509_validate_single_chain_cert(
            chain_certs[i], raw_certs[i], i, non_si_below, is_direct_trust_anchor, now_unix, role,
        );
        guard cert_alert == tls::Alert.CloseNotify else { return cert_alert; }
        if i + 1 == n {
            let total_non_si = x509_count_non_self_issued_below(chain_certs, raw_certs, n);
            let ta_alert = x509_validate_trust_anchor_node(
                chain_certs, raw_certs, i, trust_store, total_non_si, now_unix,
            );
            guard ta_alert == tls::Alert.CloseNotify else { return ta_alert; }
        }
    }
    if n > 1 {
        for i in n - 1 {
            let link_alert = x509_validate_chain_linkage(
                chain_certs[i], raw_certs[i], chain_certs[i + 1], raw_certs[i + 1],
            );
            guard link_alert == tls::Alert.CloseNotify else { return link_alert; }
        }
    }
    return tls::Alert.CloseNotify;
}
