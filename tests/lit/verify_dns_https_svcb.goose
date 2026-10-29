// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_dns_https_svcb.goose
// Verification of RFC 9460 HTTPS/SVCB DNS wire parameter decoding,
// strictly ascending SvcParamKeys ordering, and uncompressed target names.
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";
import wire_kit from ".";

// Wire bridge to RFC 9460 SvcParams decoder
fn decode_svc_params_wire(buf: const u8[:]) -> i64 {
    if buf.len < 24 { return -1; }
    var rec = wing::HttpsRecord { .. };
    let ok = wing::parse_https_svc_params(buf, rec);
    if !ok { return -2; }
    return rec.port;
}

fn test_valid_svc_params() {
    var params_pkt: u8[>..] = [];
    // Key 1 (ALPN, len 6: "h2", "h3"), Key 3 (Port, len 2: 8443), Key 4 (IPv4Hint, len 4: 192.0.2.1)
    assert(wire_kit::parse_hex("000100060268320268330003000220FB00040004C0000201", params_pkt));

    var rec = wing::HttpsRecord { .. };
    let ok = wing::parse_https_svc_params(params_pkt[..], rec);
    assert(ok);
    assert(rec.alpns.len == 2);
    assert(rec.alpns[0] == "h2");
    assert(rec.alpns[1] == "h3");
    assert(rec.port == 8443);
    assert(rec.ipv4_hints.len == 1);
    assert(rec.ipv4_hints[0] == 0xC0000201);

    assert(wire_kit::verify_split_stream(params_pkt[..], -1, 8443, decode_svc_params_wire));
    assert(wire_kit::fuzz_payload(params_pkt[..], 100, decode_svc_params_wire));
    print("SVC_PARAMS_VALID: OK");
}

fn test_invalid_svc_params() {
    // 1. Out of order keys: Key 3 (Port) followed by Key 1 (ALPN)
    var out_of_order: u8[>..] = [];
    assert(wire_kit::parse_hex("0003000201BB00010003026832", out_of_order));
    var rec1 = wing::HttpsRecord { .. };
    assert(!wing::parse_https_svc_params(out_of_order[..], rec1));

    // 2. Duplicate key: Key 1 followed by Key 1
    var dup_keys: u8[>..] = [];
    assert(wire_kit::parse_hex("0001000302683200010003026833", dup_keys));
    var rec2 = wing::HttpsRecord { .. };
    assert(!wing::parse_https_svc_params(dup_keys[..], rec2));

    // 3. Invalid port length: 3 bytes instead of 2
    var bad_port_len: u8[>..] = [];
    assert(wire_kit::parse_hex("0003000301BB00", bad_port_len));
    var rec3 = wing::HttpsRecord { .. };
    assert(!wing::parse_https_svc_params(bad_port_len[..], rec3));

    // 4. Invalid IPv4 hint length: 3 bytes (not multiple of 4)
    var bad_ip4_len: u8[>..] = [];
    assert(wire_kit::parse_hex("00040003C00002", bad_ip4_len));
    var rec4 = wing::HttpsRecord { .. };
    assert(!wing::parse_https_svc_params(bad_ip4_len[..], rec4));

    // 5. Invalid no_default_alpn length: 1 byte instead of 0
    var bad_no_default: u8[>..] = [];
    assert(wire_kit::parse_hex("0002000100", bad_no_default));
    var rec5 = wing::HttpsRecord { .. };
    assert(!wing::parse_https_svc_params(bad_no_default[..], rec5));

    print("SVC_PARAMS_INVALID_REJECTED: OK");
}

fn test_full_dns_https_response() {
    // DNS response packet with 1 HTTPS record:
    // Header 12B: ID=0x5678, QR=1 (response), AA=1, RCODE=0, QDCOUNT=1, ANCOUNT=1
    // Question: example.com, Type=HTTPS (65 = 0x0041), Class=IN (1)
    // Answer: pointer 0xC00C -> example.com, Type=HTTPS, Class=IN, TTL=60, RDLENGTH=9
    // RDATA: Priority=1, TargetName="." (0x00, root), SvcParams=(Port=443)
    var resp_pkt: u8[>..] = [];
    assert(wire_kit::parse_hex("567881800001000100000000076578616d706c6503636f6d0000410001C00C004100010000003C00090001000003000201BB", resp_pkt));

    var resp = wing::DnsResponse { .. };
    let ok = wing::parse_dns_response(resp_pkt[..], resp);
    assert(ok);
    assert(resp.https_records.len == 1);
    assert(resp.https_records[0].priority == 1);
    assert(resp.https_records[0].port == 443);
    assert(resp.https_records[0].target_name == "");

    // RFC 9460 §2.5.1: HTTPS TargetName containing compression pointer must be rejected
    var bad_https_wire: u8[>..] = [];
    assert(wire_kit::parse_hex("567881800001000100000000076578616d706c6503636f6d0000410001C00C004100010000003C00040001C00C", bad_https_wire));
    var resp_bad = wing::DnsResponse { .. };
    assert(!wing::parse_dns_response(bad_https_wire[..], resp_bad));

    print("DNS_HTTPS_RESPONSE: OK");
}

fn main() {
    test_valid_svc_params();
    test_invalid_svc_params();
    test_full_dns_https_response();
    print("DNS_HTTPS_SVCB: ALL INVARIANTS PASS");
}

// CHECK: SVC_PARAMS_VALID: OK
// CHECK: SVC_PARAMS_INVALID_REJECTED: OK
// CHECK: DNS_HTTPS_RESPONSE: OK
// CHECK: DNS_HTTPS_SVCB: ALL INVARIANTS PASS
