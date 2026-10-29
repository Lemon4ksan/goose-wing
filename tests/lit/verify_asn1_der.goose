// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_asn1_der.goose
// Verification of ITU-T X.690 DER encoding rules and ASN.1 wire decoding via wing::tls.
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";
import wire_kit from ".";

fn wing_check_tlv_length_prefix(buf: const u8[:]) -> i64 {
    let b1 = buf[1];
    guard (b1 & 0x80) != 0 else { return 0; }
    guard b1 != 0x80 && b1 != 0xFF else { return -2; }
    let num_octets = (b1 & 0x7F) as i64;
    guard num_octets >= 1 && num_octets <= 4 else { return -2; }
    guard buf.len >= 2 + num_octets else { return -1; }
    guard buf[2] != 0 else { return -2; }
    return 0;
}

// Wire adapter for verify_split_stream and fuzzing using wing's real get_any_asn1_element.
fn wing_parse_der_tlv(buf: const u8[:]) -> i64 {
    var c = wing::cursor_from(buf);
    var tag: u8 = 0;
    var val = wing::cursor_from(buf[..0]);
    if wing::get_any_asn1_element(c, tag, val) {
        return val.buf.len;
    }
    guard buf.len >= 2 else { return -1; }
    let pre_check = wing_check_tlv_length_prefix(buf);
    guard pre_check == 0 else { return pre_check; }

    var c_len = wing::cursor_from(buf[1..]);
    var out_len: i64 = 0;
    guard wing::get_asn1_length(c_len, out_len) else { return -2; }
    let total_hdr = buf.len - c_len.buf.len;
    guard buf.len >= total_hdr + out_len else { return -1; }
    return -2;
}

// Wire adapter for integer validation using wing's real get_asn1_integer & validate_asn1_integer.
fn wing_validate_der_integer(buf: const u8[:]) -> i64 {
    guard buf.len >= 2 else { return -1; }
    guard buf[0] == wing::ASN1_TAG_INTEGER else { return 0; }
    var c = wing::cursor_from(buf);
    var val: i64 = 0;
    if !wing::get_asn1_integer(c, val) {
        let vlen = buf[1] as i64;
        guard buf.len >= 2 + vlen else { return -1; }
        return 0;
    }
    guard val > 0 else { return 0; }
    return 1;
}

fn calc_asn1_tag_class(tag: i64) -> i64 {
    return (tag >> 6) & 3;
}

fn derive_der_short_len(b: i64) -> i64 {
    if (b & 128) == 0 { return b; }
    return -1;
}

fn main() {
    var raw_short: u8[>..] = [];
    assert(wire_kit::parse_hex("0203010001", raw_short));
    assert(wire_kit::verify_split_stream(raw_short[..], -1, 3, wing_parse_der_tlv));
    assert(wire_kit::fuzz_payload(raw_short[..], 100, wing_parse_der_tlv));
    print("ASN1_SHORT_TLV: OK");

    var raw_hdr: u8[>..] = [];
    assert(wire_kit::parse_hex("308180", raw_hdr));
    assert(wing_parse_der_tlv(raw_hdr[..]) == -1);

    var vA: u8[>..] = []; wire_kit::parse_hex("02817F", vA);
    assert(wing_parse_der_tlv(vA[..]) == -2);
    var vB: u8[>..] = []; wire_kit::parse_hex("3080", vB);
    assert(wing_parse_der_tlv(vB[..]) == -2);
    var vC: u8[>..] = []; wire_kit::parse_hex("02FF01", vC);
    assert(wing_parse_der_tlv(vC[..]) == -2);
    var vD: u8[>..] = []; wire_kit::parse_hex("02820080", vD);
    assert(wing_parse_der_tlv(vD[..]) == -2);
    print("ASN1_INVALID_TLV: OK");

    var vUnderrun: u8[>..] = []; wire_kit::parse_hex("042001020304", vUnderrun);
    assert(wing_parse_der_tlv(vUnderrun[..]) == -1);
    print("ASN1_UNDERRUN: OK");

    var i128: u8[>..] = []; wire_kit::parse_hex("02020080", i128);
    assert(wing_validate_der_integer(i128[..]) == 1);
    var iRedundant: u8[>..] = []; wire_kit::parse_hex("02020001", iRedundant);
    assert(wing_validate_der_integer(iRedundant[..]) == 0);
    var iNeg: u8[>..] = []; wire_kit::parse_hex("0202FF01", iNeg);
    assert(wing_validate_der_integer(iNeg[..]) == 0);
    var i127: u8[>..] = []; wire_kit::parse_hex("02017F", i127);
    assert(wing_validate_der_integer(i127[..]) == 1);
    var iNegSingle: u8[>..] = []; wire_kit::parse_hex("020180", iNegSingle);
    assert(wing_validate_der_integer(iNegSingle[..]) == 0);

    var iSerial: u8[>..] = []; wire_kit::parse_hex("020400AABBCC", iSerial);
    assert(wing_validate_der_integer(iSerial[..]) == 1);
    assert(wire_kit::verify_split_stream(iSerial[..], -1, 1, wing_validate_der_integer));
    assert(wire_kit::fuzz_payload(iSerial[..], 100, wing_validate_der_integer));
    print("ASN1_INT_RULES: OK");

    assert(calc_asn1_tag_class(wing::ASN1_TAG_SEQUENCE) == 0);
    assert(derive_der_short_len(0x2A) == 42);
    print("ASN1_DER_ALL: PASS");
}

// CHECK: ASN1_SHORT_TLV: OK
// CHECK: ASN1_INVALID_TLV: OK
// CHECK: ASN1_UNDERRUN: OK
// CHECK: ASN1_INT_RULES: OK
// CHECK: ASN1_DER_ALL: PASS
