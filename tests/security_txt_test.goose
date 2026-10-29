// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Verification Suite for RFC 9116 (A File Format to Aid in Security Vulnerability Disclosure - security.txt).
import std;
import core from "..";
import wing from "..";

fn test_security_txt_valid_matrix(t: core::T&) {
    t.run("1. Valid security.txt Parsing with Comments and PGP Armor") { sub =>
        let valid_payload = "# RFC 9116 security.txt disclosure policy\n-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nContact: mailto:security@example.com\nContact: https://example.com/security\nExpires: 2030-12-31T23:59:59Z\nEncryption: https://example.com/pgp-key.txt\nCanonical: https://example.com/.well-known/security.txt\nAcknowledgments: https://example.com/hall-of-fame\nPolicy: https://example.com/disclosure-policy\nHiring: https://example.com/security-jobs\nPreferred-Languages: en, ru, de\n\n-----BEGIN PGP SIGNATURE-----\nVersion: OpenPrivacy\n...\n";

        let now_epoch: i64 = 1700000000; // Nov 2023
        let sec = wing::parse_security_txt(valid_payload, now_epoch);

        sub.assert_true(sec.is_valid, "Valid security.txt marked valid");
        sub.assert_eq(sec.status, wing::SEC_TXT_OK, "Status is SEC_TXT_OK");
        sub.assert_eq(sec.contact.len, 2, "2 contacts parsed");
        sub.assert_bytes_eq(sec.contact[0][..], "mailto:security@example.com", "Contact 1 matches");
        sub.assert_bytes_eq(sec.contact[1][..], "https://example.com/security", "Contact 2 matches");
        sub.assert_bytes_eq(sec.expires[..], "2030-12-31T23:59:59Z", "Expires matches");
        sub.assert_true(sec.expires_unix > now_epoch, "Expires timestamp is in future");
        sub.assert_eq(sec.encryption.len, 1, "1 encryption URI");
        sub.assert_bytes_eq(sec.canonical[0][..], "https://example.com/.well-known/security.txt", "Canonical matches");
        sub.assert_bytes_eq(sec.preferred_languages[..], "en, ru, de", "Preferred-Languages matches");
    };

    t.run("2. Mandatory Contact Field Enforcement (RFC 9116 §2.5.3)") { sub =>
        let missing_contact = "Expires: 2030-12-31T23:59:59Z\nCanonical: https://example.com/.well-known/security.txt\n";

        let sec = wing::parse_security_txt(missing_contact, 0);
        sub.assert_false(sec.is_valid, "Missing contact must not be valid");
        sub.assert_eq(sec.status, wing::SEC_TXT_ERR_MISSING_CONTACT, "Status indicates missing contact");
    };

    t.run("3. Mandatory Expires Field Enforcement (RFC 9116 §2.5.5)") { sub =>
        let missing_expires = "Contact: mailto:security@example.com\n";

        let sec = wing::parse_security_txt(missing_expires, 0);
        sub.assert_false(sec.is_valid, "Missing expires must not be valid");
        sub.assert_eq(sec.status, wing::SEC_TXT_ERR_MISSING_EXPIRES, "Status indicates missing expires");
    };

    t.run("4. Duplicate Expires Rejection") { sub =>
        let dup_expires = "Contact: mailto:security@example.com\nExpires: 2030-12-31T23:59:59Z\nExpires: 2031-12-31T23:59:59Z\n";

        let sec = wing::parse_security_txt(dup_expires, 0);
        sub.assert_false(sec.is_valid, "Duplicate expires must be rejected");
        sub.assert_eq(sec.status, wing::SEC_TXT_ERR_DUPLICATE_EXPIRES, "Status indicates duplicate expires");
    };

    t.run("5. Expired / Stale Timestamp Rejection") { sub =>
        let stale_txt = "Contact: mailto:security@example.com\nExpires: 2021-01-01T00:00:00Z\n";

        let now_epoch: i64 = 1700000000; // Nov 2023
        let sec = wing::parse_security_txt(stale_txt, now_epoch);
        sub.assert_false(sec.is_valid, "Stale file must not be valid");
        sub.assert_true(sec.is_expired, "is_expired flag set");
        sub.assert_eq(sec.status, wing::SEC_TXT_ERR_EXPIRED, "Status indicates expired file");
    };

    t.run("6. Canonical HTTPS Requirement (RFC 9116 §2.5.2)") { sub =>
        let insecure_canonical = "Contact: mailto:security@example.com\nExpires: 2030-12-31T23:59:59Z\nCanonical: http://example.com/.well-known/security.txt\n";

        let sec = wing::parse_security_txt(insecure_canonical, 0);
        sub.assert_false(sec.is_valid, "Non-HTTPS canonical must fail");
        sub.assert_eq(sec.status, wing::SEC_TXT_ERR_INVALID_CANONICAL, "Status indicates invalid canonical");
    };

    t.run("7. Roundtrip Format and Parse") { sub =>
        var orig = wing::new_security_txt();
        orig.contact.push("mailto:cert@company.org");
        orig.expires.append("2032-06-30T12:00:00Z");
        orig.canonical.push("https://company.org/.well-known/security.txt");
        orig.policy.push("https://company.org/security-policy");
        orig.preferred_languages.append("en");

        var wire: u8[>..] = [];
        wing::format_security_txt(orig, wire);

        let parsed = wing::parse_security_txt(wire[..], 0);
        sub.assert_true(parsed.is_valid, "Formatted wire text re-parses as valid");
        sub.assert_bytes_eq(parsed.contact[0][..], "mailto:cert@company.org", "Roundtrip contact matches");
        sub.assert_bytes_eq(parsed.expires[..], "2032-06-30T12:00:00Z", "Roundtrip expires matches");
        sub.assert_bytes_eq(parsed.canonical[0][..], "https://company.org/.well-known/security.txt", "Roundtrip canonical matches");
        sub.assert_bytes_eq(parsed.policy[0][..], "https://company.org/security-policy", "Roundtrip policy matches");
        sub.assert_bytes_eq(parsed.preferred_languages[..], "en", "Roundtrip languages match");
    };

    t.run("8. Path Validation Helpers") { sub =>
        sub.assert_true(wing::is_security_txt_path("/.well-known/security.txt"), "Standard well-known path matches");
        sub.assert_true(wing::is_security_txt_path("/security.txt"), "Legacy root path matches");
        sub.assert_false(wing::is_security_txt_path("/security"), "Non-matching path rejected");
        sub.assert_false(wing::is_security_txt_path("/.well-known/other"), "Other well-known path rejected");
    };
}

fn main() {
    var runner = core::new_runner("RFC 9116 security.txt Verification Suite", core::Verbosity.Verbose);
    core::run_case(runner, "1. RFC 9116 security.txt Validation Matrix", test_security_txt_valid_matrix);
    let ok = core::finish(runner);
    assert(ok);
}
