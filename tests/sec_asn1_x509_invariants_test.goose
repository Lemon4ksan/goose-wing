// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Hardening & Security Invariants Suite for ASN.1 DER & X.509 Certificate Decoders (ITU-T X.690 & RFC 5280):
// 1. ASN.1 DER length canonicality, indefinite length bans, and integer overflow guards.
// 2. ASN.1 INTEGER canonical padding, negative serial number bans, and 20-octet limits.
// 3. SAN dNSName validation (null bytes, label lengths, hyphen boundaries).
// 4. ASN.1 UTCTime & GeneralizedTime strict DER canonical parsing.
import std;
import core from "..";
import wing from "..";

fn test_asn1_der_length_canonicality(t: core::T&) {
    t.run("ASN1-SEC-01: Short Form and Long Form Valid Lengths") { sub =>
        // Short form: 0x42 = 66
        let short_der: u8[1] = [0x42];
        var c1 = wing::cursor_from(short_der[..]);
        var out_len1: i64 = 0;
        let ok1 = wing::get_asn1_length(c1, out_len1);
        sub.assert_true(ok1, "short form length succeeds");
        sub.assert_eq(out_len1, 66, "out_len matches 66");

        // Long form: 2 bytes: 0x82 0x01 0x00 = 256
        let long_der: u8[3] = [0x82, 0x01, 0x00];
        var c2 = wing::cursor_from(long_der[..]);
        var out_len2: i64 = 0;
        let ok2 = wing::get_asn1_length(c2, out_len2);
        sub.assert_true(ok2, "long form length succeeds");
        sub.assert_eq(out_len2, 256, "out_len matches 256");
    };

    t.run("ASN1-SEC-02: BER Indefinite Length (0x80) strictly forbidden in DER") { sub =>
        let indef_der: u8[1] = [0x80];
        var c = wing::cursor_from(indef_der[..]);
        var out_len: i64 = 0;
        let ok = wing::get_asn1_length(c, out_len);
        sub.assert_false(ok, "indefinite length 0x80 must fail in DER per X.690 §8.1.3.6");
    };

    t.run("ASN1-SEC-03: Redundant Leading Zero in Long Form Length Rejected") { sub =>
        // 0x82 0x00 0x80 (2-byte length where first length byte is 0x00)
        let red_der: u8[3] = [0x82, 0x00, 0x80];
        var c = wing::cursor_from(red_der[..]);
        var out_len: i64 = 0;
        let ok = wing::get_asn1_length(c, out_len);
        sub.assert_false(ok, "redundant leading zero in long form length must be rejected");
    };

    t.run("ASN1-SEC-04: Reserved Initial Octet 0xFF and Truncated Lengths Rejected") { sub =>
        let ff_der: u8[1] = [0xFF];
        var c1 = wing::cursor_from(ff_der[..]);
        var out_len1: i64 = 0;
        let ok1 = wing::get_asn1_length(c1, out_len1);
        sub.assert_false(ok1, "reserved initial octet 0xFF must be rejected");

        // Declares 3 length bytes (0x83), but only 1 byte follows
        let trunc_der: u8[2] = [0x83, 0x01];
        var c2 = wing::cursor_from(trunc_der[..]);
        var out_len2: i64 = 0;
        let ok2 = wing::get_asn1_length(c2, out_len2);
        sub.assert_false(ok2, "truncated long form length must be rejected");
    };
}

fn test_asn1_der_integer_and_serial_invariants(t: core::T&) {
    t.run("ASN1-SEC-05: Empty Integer and Redundant Zero Padding") { sub =>
        let empty_buf: u8[0] = [];
        sub.assert_false(wing::validate_asn1_integer(empty_buf[..], false), "empty integer is forbidden");

        // 0x00 0x7F: redundant leading zero (0x7F has bit 7 clear, so 0x00 was unnecessary)
        let red_zero: u8[2] = [0x00, 0x7F];
        sub.assert_false(wing::validate_asn1_integer(red_zero[..], false), "redundant zero padding must be rejected");

        // 0x00 0x80: valid canonical padding (0x80 has bit 7 set, so 0x00 is required to remain positive)
        let canon_pos: u8[2] = [0x00, 0x80];
        sub.assert_true(wing::validate_asn1_integer(canon_pos[..], false), "valid zero prefix for positive int accepted");
    };

    t.run("ASN1-SEC-06: Negative Serial Number and Zero Serial Number Rejection") { sub =>
        // 0x80: negative integer (-128)
        let neg_serial: u8[1] = [0x80];
        sub.assert_true(wing::validate_asn1_integer(neg_serial[..], false), "general integer can be negative");
        sub.assert_false(wing::validate_asn1_integer(neg_serial[..], true), "serial number MUST be positive per RFC 5280 §4.1.2.2");

        // 0x00: zero serial number (RFC 5280 requires strictly positive serial numbers)
        let zero_serial: u8[1] = [0x00];
        sub.assert_false(wing::validate_asn1_integer(zero_serial[..], true), "serial number 0 is forbidden per RFC 5280");
    };

    t.run("ASN1-SEC-07: Serial Number 20-Octet Limit (RFC 5280 §4.1.2.2)") { sub =>
        // 20-byte serial number (valid)
        let valid_20: u8[20] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
            0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14,
        ];
        sub.assert_true(wing::validate_asn1_integer(valid_20[..], true), "20-byte serial number accepted");

        // 22-byte serial number (forbidden)
        let bad_22: u8[22] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
            0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14,
            0x15, 0x16,
        ];
        sub.assert_false(wing::validate_asn1_integer(bad_22[..], true), "serial number > 20 octets must be rejected");
    };
}

fn test_x509_san_dns_name_validation(t: core::T&) {
    t.run("ASN1-SEC-08: Valid DNS Names in SAN") { sub =>
        sub.assert_true(wing::validate_san_dns_name("example.com"), "standard domain name valid");
        sub.assert_true(wing::validate_san_dns_name("api.sub.domain.co.uk"), "multilevel domain valid");
        sub.assert_true(wing::validate_san_dns_name("host-with-dash.com"), "embedded hyphen valid");
    };

    t.run("ASN1-SEC-09: Embedded Null Byte in DNS Name (CVE-2009-2408)") { sub =>
        let null_dns: u8[21] = [
            'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 0x00,
            '.', 'e', 'v', 'i', 'l', '.', 'c', 'o', 'm',
        ];
        sub.assert_false(wing::validate_san_dns_name(null_dns[..]), "embedded null byte in SAN DNS must be rejected");
    };

    t.run("ASN1-SEC-10: Leading/Trailing Dots, Empty Labels and Hyphen Violations") { sub =>
        sub.assert_false(wing::validate_san_dns_name(".example.com"), "leading dot invalid");
        sub.assert_false(wing::validate_san_dns_name("example.com."), "trailing dot invalid in SAN");
        sub.assert_false(wing::validate_san_dns_name("example..com"), "empty label (consecutive dots) invalid");
        sub.assert_false(wing::validate_san_dns_name("-example.com"), "leading hyphen in label invalid");
        sub.assert_false(wing::validate_san_dns_name("example-.com"), "trailing hyphen in label invalid");
    };

    t.run("ASN1-SEC-11: DNS Name and Label Length Limits (RFC 5280 / RFC 1035)") { sub =>
        // Empty DNS name
        sub.assert_false(wing::validate_san_dns_name(""), "empty DNS name invalid");

        // Label > 63 octets
        var long_label: u8[..128] = [];
        for i in 64 { long_label.push('a'); }
        long_label.append(".com");
        sub.assert_false(wing::validate_san_dns_name(long_label[..]), "label > 63 octets invalid");
    };
}

fn test_x509_asn1_time_parsing(t: core::T&) {
    t.run("ASN1-SEC-12: Valid UTCTime and GeneralizedTime Canonical DER") { sub =>
        // UTCTime: "261028120000Z" (2026-10-28 12:00:00 UTC)
        let utc_valid = "261028120000Z";
        let ts_utc, ok_utc = wing::parse_asn1_time(wing::ASN1_TAG_UTC_TIME, utc_valid);
        sub.assert_true(ok_utc, "valid UTCTime parses successfully");
        sub.assert_true(ts_utc > 0, "timestamp > 0");

        // GeneralizedTime: "20261028120000Z"
        let gen_valid = "20261028120000Z";
        let ts_gen, ok_gen = wing::parse_asn1_time(wing::ASN1_TAG_GENERALIZED_TIME, gen_valid);
        sub.assert_true(ok_gen, "valid GeneralizedTime parses successfully");
        sub.assert_true(ts_gen > 0, "timestamp > 0");
    };

    t.run("ASN1-SEC-13: Out-of-Bounds Calendar Values and Non-UTC Suffix Rejection") { sub =>
        // Month 13
        let bad_month = "261328120000Z";
        let _, ok_m = wing::parse_asn1_time(wing::ASN1_TAG_UTC_TIME, bad_month);
        sub.assert_false(ok_m, "month 13 must be rejected");

        // Day 32
        let bad_day = "261032120000Z";
        let _, ok_d = wing::parse_asn1_time(wing::ASN1_TAG_UTC_TIME, bad_day);
        sub.assert_false(ok_d, "day 32 must be rejected");

        // Hour 25
        let bad_hour = "261028250000Z";
        let _, ok_h = wing::parse_asn1_time(wing::ASN1_TAG_UTC_TIME, bad_hour);
        sub.assert_false(ok_h, "hour 25 must be rejected");

        // Non-UTC suffix: local time without 'Z' (strictly forbidden in DER per X.690 §11.7)
        let no_z = "261028120000";
        let _, ok_z = wing::parse_asn1_time(wing::ASN1_TAG_UTC_TIME, no_z);
        sub.assert_false(ok_z, "missing 'Z' timezone must be rejected in DER");
    };
}

fn main() {
    var runner = core::new_runner("ASN.1 DER & X.509 Security Invariants Suite", core::Verbosity.Verbose);

    core::run_case(runner, "1. ASN.1 DER Length Canonicality & Bounds", test_asn1_der_length_canonicality);
    core::run_case(runner, "2. ASN.1 INTEGER Canonical Rules & Serial Invariants", test_asn1_der_integer_and_serial_invariants);
    core::run_case(runner, "3. X.509 SAN dNSName Hostname Validation", test_x509_san_dns_name_validation);
    core::run_case(runner, "4. ASN.1 Time (UTCTime & GeneralizedTime) Canonical DER Parsing", test_x509_asn1_time_parsing);

    let ok = core::finish(runner);
    assert(ok);
}
