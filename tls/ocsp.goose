// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 6066 §8 & RFC 6960 Online Certificate Status Protocol (OCSP) Stapling parser and validator.
namespace tls;

import std;
import core from "..";
import .internal;
import .record;
import .asn1;
import .types;
import .x509;
import .pki_internal;

// RFC 6960 Section 4.2.1: ASN.1 Specification of the OCSP Response - Parses DER OCSPResponse with rollback.
//
// Example:
//   raw_ocsp = 0x30 ... (DER encoded OCSPResponse)
//   returns: ok = true, out filled with status and cert status
fn parse_ocsp_response(raw_ocsp: const u8[:], out: ParsedOcspResponse&) -> bool {
    return tls_internal::parse_ocsp_response_for_serial(raw_ocsp, "", out);
}

// Validates an OCSP stapled response against the leaf certificate (RFC 6066 §8, RFC 6960).
fn validate_ocsp_stapling(
    raw_ocsp:       const u8[:],
    leaf_cert:      const ParsedCert&,
    leaf_raw:       const u8[:],
    now_unix:       i64,
    issuer_raw_der: const u8[:] = "",
) -> Alert {
    let leaf_serial = span_slice(leaf_raw, leaf_cert.serial_number);
    guard leaf_serial.len > 0 else {
        return Alert.BadCertificateStatusResponse;
    }
    var resp = ParsedOcspResponse {};
    guard tls_internal::parse_ocsp_response_for_serial(raw_ocsp, leaf_serial, resp) &&
        resp.status == OcspResponseStatus.Successful &&
        resp.signature.length > 0 &&
        resp.sig_alg_oid.length > 0 else {
        return Alert.BadCertificateStatusResponse;
    }
    if resp.cert_status == OcspCertStatus.Revoked {
        return Alert.BadCertificate;
    }
    guard resp.cert_status == OcspCertStatus.Good else {
        return Alert.BadCertificateStatusResponse;
    }

    let ocsp_serial = span_slice(raw_ocsp, resp.serial_number);
    guard ocsp_serial.len > 0 && ocsp_serial == leaf_serial else {
        return Alert.BadCertificateStatusResponse;
    }
    guard tls_internal::x509_validate_ocsp_cert_id_alg(resp, raw_ocsp) else {
        return Alert.BadCertificateStatusResponse;
    }

    if issuer_raw_der.len > 0 {
        var issuer_cert = ParsedCert { .. };
        guard parse_x509_certificate(issuer_raw_der, issuer_cert) else {
            return Alert.BadCertificateStatusResponse;
        }
        guard tls_internal::x509_verify_ocsp_cert_id_with_issuer(
            resp, raw_ocsp, leaf_cert, leaf_raw, issuer_cert, issuer_raw_der,
        ) else {
            return Alert.BadCertificateStatusResponse;
        }
        let sig_alert = x509_verify_ocsp_signature(resp, raw_ocsp, issuer_cert, issuer_raw_der);
        guard sig_alert == Alert.CloseNotify else {
            return sig_alert;
        }
    } else if leaf_cert.issuer_raw.length > 0 {
        let alg_oid = span_slice(raw_ocsp, resp.hash_alg_oid);
        let ocsp_nh = span_slice(raw_ocsp, resp.issuer_name_hash);
        let issuer_dn = span_slice(leaf_raw, leaf_cert.issuer_raw);
        guard tls_internal::x509_verify_ocsp_issuer_name_hash(alg_oid, ocsp_nh, issuer_dn) else {
            return Alert.BadCertificateStatusResponse;
        }
    }

    return tls_internal::x509_validate_ocsp_temporal(resp, now_unix);
}

fn x509_verify_ocsp_signature(
    resp:        const ParsedOcspResponse&,
    raw_ocsp:    const u8[:],
    issuer_cert: const ParsedCert&,
    issuer_raw:  const u8[:],
) -> Alert {
    var parent_pubkey = span_slice(issuer_raw, issuer_cert.spki_pubkey);
    if parent_pubkey.len >= 2 && parent_pubkey[0] == 0 {
        parent_pubkey = parent_pubkey[1..];
    }
    return tls_internal::x509_verify_ocsp_signature_with_pubkey(resp, raw_ocsp, parent_pubkey);
}

// RFC 6066 Section 8: Certificate Status Request - Unwraps CertificateStatus (status_type = ocsp(1) + u24 OCSPResponse).
//
// Example:
//   ext_data = [0x01, 0x00, 0x00, 0x04, 'O', 'C', 'S', 'P']
//   returns: "OCSP", ok = true
fn unwrap_ocsp_response(ext_data: const u8[:]) -> const u8[:], bool {
    var c = core::cursor_from(ext_data);
    var status_type: u8 = 0;
    guard c.get_u8(status_type) && status_type == tls_internal::CERT_STATUS_TYPE_OCSP else { return "", false; }
    var resp_len: u32 = 0;
    if !c.get_u24(resp_len) { return "", false; }
    guard resp_len > 0 && resp_len == c.cursor_len() else { return "", false; }
    return c.buf, true;
}
