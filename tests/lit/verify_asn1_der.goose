// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RUN: goose %s | %FileCheck %s
import std;
import wire_kit from ".";

fn parse_der_tlv(buf: const u8[:]) -> i64 {
    if buf.len < 2 { return -1; }
    let _ = buf[0];
    let b1 = buf[1];
    var hdr_len: i64 = 2;
    var val_len: i64 = 0;

    if (b1 & 128) == 0 {
        val_len = b1;
    } else {
        if b1 == 128 || b1 == 255 {
            return -2;
        }
        let num_octets = b1 & 127;
        if num_octets < 1 || num_octets > 4 {
            return -2;
        }
        hdr_len += num_octets;
        if buf.len < hdr_len {
            return -1;
        }

        var l_acc: i64 = 0;
        var j: i64 = 0;
        while j < num_octets {
            let oct = buf[2 + j] as i64;
            if j == 0 && oct == 0 {
                return -2;
            }
            l_acc = (l_acc << 8) | oct;
            j += 1;
        }

        if l_acc < 128 || l_acc < 0 {
            return -2;
        }
        val_len = l_acc;
    }

    if buf.len < hdr_len + val_len {
        return -1;
    }

    return val_len;
}

fn validate_der_integer_elem(buf: const u8[:]) -> i64 {
    if buf.len < 2 { return -1; }
    let tag = buf[0];
    if tag != 2 { return 0; }

    let vlen = buf[1] as i64;
    if vlen > 127 { return 0; }
    if buf.len < 2 + vlen { return -1; }
    if vlen == 0 { return 0; }

    let b0 = buf[2];
    if vlen == 1 {
        if (b0 & 128) != 0 { return 0; }
        return 1;
    }

    let b1 = buf[3];
    if (b0 & 128) != 0 { return 0; }
    if b0 == 0 && (b1 & 128) == 0 {
        return 0;
    }

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
    assert(wire_kit::verify_split_stream(raw_short[..], -1, 3, parse_der_tlv));
    assert(wire_kit::fuzz_payload(raw_short[..], 100, parse_der_tlv));
    print("ASN1_SHORT_TLV: OK");

    var raw_hdr: u8[>..] = [];
    assert(wire_kit::parse_hex("308180", raw_hdr));
    assert(parse_der_tlv(raw_hdr[..]) == -1);

    var vA: u8[>..] = []; wire_kit::parse_hex("02817F", vA);
    assert(parse_der_tlv(vA[..]) == -2);
    var vB: u8[>..] = []; wire_kit::parse_hex("3080", vB);
    assert(parse_der_tlv(vB[..]) == -2);
    var vC: u8[>..] = []; wire_kit::parse_hex("02FF01", vC);
    assert(parse_der_tlv(vC[..]) == -2);
    var vD: u8[>..] = []; wire_kit::parse_hex("02820080", vD);
    assert(parse_der_tlv(vD[..]) == -2);
    print("ASN1_INVALID_TLV: OK");

    var vUnderrun: u8[>..] = []; wire_kit::parse_hex("042001020304", vUnderrun);
    assert(parse_der_tlv(vUnderrun[..]) == -1);
    print("ASN1_UNDERRUN: OK");

    var i128: u8[>..] = []; wire_kit::parse_hex("02020080", i128);
    assert(validate_der_integer_elem(i128[..]) == 1);
    var iRedundant: u8[>..] = []; wire_kit::parse_hex("02020001", iRedundant);
    assert(validate_der_integer_elem(iRedundant[..]) == 0);
    var iNeg: u8[>..] = []; wire_kit::parse_hex("0202FF01", iNeg);
    assert(validate_der_integer_elem(iNeg[..]) == 0);
    var i127: u8[>..] = []; wire_kit::parse_hex("02017F", i127);
    assert(validate_der_integer_elem(i127[..]) == 1);
    var iNegSingle: u8[>..] = []; wire_kit::parse_hex("020180", iNegSingle);
    assert(validate_der_integer_elem(iNegSingle[..]) == 0);

    var iSerial: u8[>..] = []; wire_kit::parse_hex("020400AABBCC", iSerial);
    assert(validate_der_integer_elem(iSerial[..]) == 1);
    assert(wire_kit::verify_split_stream(iSerial[..], -1, 1, validate_der_integer_elem));
    assert(wire_kit::fuzz_payload(iSerial[..], 100, validate_der_integer_elem));
    print("ASN1_INT_RULES: OK");

    assert(calc_asn1_tag_class(0x30) == 0);
    assert(derive_der_short_len(0x2A) == 42);
    print("ASN1_DER_ALL: PASS");
}

// CHECK: ASN1_SHORT_TLV: OK
// CHECK: ASN1_INVALID_TLV: OK
// CHECK: ASN1_UNDERRUN: OK
// CHECK: ASN1_INT_RULES: OK
// CHECK: ASN1_DER_ALL: PASS
