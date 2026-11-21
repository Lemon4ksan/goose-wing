// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 9116: A File Format to Aid in Security Vulnerability Disclosure (security.txt).
// Zero-heap parser, validator, and formatter for /.well-known/security.txt.
namespace http;

import std;
import core from "..";
import http.meta_internal;

// ---- canonical locations and media type ------------------------------------

// ---- error codes -----------------------------------------------------------

const SEC_TXT_OK:                    i32 = 0;
const SEC_TXT_ERR_MISSING_CONTACT:   i32 = 1;
const SEC_TXT_ERR_MISSING_EXPIRES:   i32 = 2;
const SEC_TXT_ERR_DUPLICATE_EXPIRES: i32 = 3;
const SEC_TXT_ERR_INVALID_EXPIRES:   i32 = 4;
const SEC_TXT_ERR_EXPIRED:           i32 = 5;
const SEC_TXT_ERR_INVALID_CANONICAL: i32 = 6;
const SEC_TXT_ERR_EMPTY_VALUE:       i32 = 7;
const SEC_TXT_ERR_INVALID_FIELD:     i32 = 8;

// ---- data structures -------------------------------------------------------

struct SecurityTxt {
    contact:             u8[..256][..8] = [],
    expires:             u8[..64]       = "",
    expires_unix:        i64            = 0,
    encryption:          u8[..256][..4] = [],
    canonical:           u8[..256][..4] = [],
    acknowledgments:     u8[..256][..4] = [],
    policy:              u8[..256][..4] = [],
    hiring:              u8[..256][..4] = [],
    preferred_languages: u8[..64]       = "",
    is_valid:            bool           = false,
    has_contact:         bool           = false,
    has_expires:         bool           = false,
    is_expired:          bool           = false,
    status:              i32            = 0,
}

// Constructs a zero-initialized SecurityTxt structure.
// Returns whether the request URI path matches the RFC 9116 security.txt location.
fn is_security_txt_path(path: const u8[:]) -> bool {
    return path == rfc::SECURITY_TXT_WELL_KNOWN_PATH || path == rfc::SECURITY_TXT_LEGACY_PATH;
}

// ---- line classification helper --------------------------------------------

// ---- line field parser helpers ---------------------------------------------

// ---- parser implementation -------------------------------------------------

// Parses and validates a security.txt buffer per RFC 9116.
//
// Example:
//   content = "Contact: mailto:sec@example.com\nExpires: 2027-01-01T00:00:00Z\n"
//   returns: sec with status=SEC_TXT_OK, is_valid=true
fn parse_security_txt(content: const u8[:], now_epoch: i64 = 0) -> SecurityTxt {
    var sec = SecurityTxt { .. };
    var tok = core::make_byte_tokenizer(content, '\n');

    loop {
        let line, ok = tok.token_next();
        guard ok else { break; }

        let line_ok = http_internal::parse_security_txt_line(line, now_epoch, sec);
        guard line_ok else { return sec; }
    }

    http_internal::validate_mandatory_security_fields(sec);
    return sec;
}

// ---- formatter implementation ----------------------------------------------

// Formats a valid SecurityTxt object into wire text format per RFC 9116.
fn format_security_txt<B>(sec: const SecurityTxt&, out: B&) {
    for c in sec.contact {
        out.append("Contact: ");
        out.append(c[..]);
        out.append("\r\n");
    }

    if sec.expires.len > 0 {
        out.append("Expires: ");
        out.append(sec.expires[..]);
        out.append("\r\n");
    }

    for enc in sec.encryption {
        out.append("Encryption: ");
        out.append(enc[..]);
        out.append("\r\n");
    }

    for can in sec.canonical {
        out.append("Canonical: ");
        out.append(can[..]);
        out.append("\r\n");
    }

    for ack in sec.acknowledgments {
        out.append("Acknowledgments: ");
        out.append(ack[..]);
        out.append("\r\n");
    }

    for pol in sec.policy {
        out.append("Policy: ");
        out.append(pol[..]);
        out.append("\r\n");
    }

    for hir in sec.hiring {
        out.append("Hiring: ");
        out.append(hir[..]);
        out.append("\r\n");
    }

    if sec.preferred_languages.len > 0 {
        out.append("Preferred-Languages: ");
        out.append(sec.preferred_languages[..]);
        out.append("\r\n");
    }
}
