// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RUN: goose %s | %FileCheck %s
import std;
import wire_kit from ".";

// Section 1: HTTP/1 chunked parser
fn parse_chunk_size(buf: const u8[:]) -> i64 {
    let len = buf.len;
    if len < 3 { return -1; }
    var size: i64 = 0;
    var i: i64 = 0;
    var seen_digits: i64 = 0;

    while i < len {
        let b = buf[i];
        if b == 13 || b == 59 { break; }
        if b == 10 { return -2; }

        var digit: i64 = -1;
        if b >= 48 && b <= 57 { digit = b - 48; }
        else if b >= 97 && b <= 102 { digit = b - 87; }
        else if b >= 65 && b <= 70 { digit = b - 55; }
        else { return -2; }

        if seen_digits >= 8 { return -2; }
        size = (size << 4) | digit;
        seen_digits += 1;
        i += 1;
    }

    if seen_digits == 0 { return -2; }

    while i < len && buf[i] != 13 {
        if buf[i] == 10 { return -2; }
        i += 1;
    }

    if i + 1 >= len { return -1; }
    if buf[i] != 13 || buf[i + 1] != 10 { return -2; }
    i += 2;

    let total_needed = i + size + 2;
    if len < total_needed { return -1; }
    if buf[i + size] != 13 || buf[i + size + 1] != 10 { return -2; }
    return size;
}

// Section 2: DNS wire question parser
fn parse_dns_question(buf: const u8[:]) -> i64 {
    let len = buf.len;
    if len < 12 { return -1; }
    let qdcount = ((buf[4] as i64) << 8) | buf[5];
    if qdcount == 0 { return -2; }
    var offset: i64 = 12;
    var labels: i64 = 0;

    while offset < len {
        let label_len = buf[offset];
        if label_len == 0 {
            offset += 1;
            break;
        }
        if (label_len & 0xC0) != 0 { return -2; }
        if label_len > 63 { return -2; }
        offset += 1 + (label_len as i64);
        labels += 1;
        if labels > 128 || offset > len {
            if offset > len { return -1; }
            return -2;
        }
    }

    if offset + 4 > len { return -1; }
    let qtype = ((buf[offset] as i64) << 8) | buf[offset + 1];
    let qclass = ((buf[offset + 2] as i64) << 8) | buf[offset + 3];
    if qclass != 1 && qclass != 255 { return -2; }
    return qtype;
}

// Section 3: TLS 1.3 record header parser
fn parse_tls_record_header(buf: const u8[:]) -> i64 {
    let len = buf.len;
    if len < 5 { return -1; }
    let ctype = buf[0] as i64;
    if ctype < 20 || ctype > 23 { return -2; }
    let v_maj = buf[1];
    let v_min = buf[2];
    if v_maj != 3 || (v_min != 1 && v_min != 3) { return -2; }
    let rlen = ((buf[3] as i64) << 8) | buf[4];
    if rlen > 16640 { return -2; }
    if ctype == 23 && rlen == 0 { return -2; }
    return rlen;
}

// Section 4: WebSocket extended header parser
fn parse_ws_extended_header(buf: const u8[:]) -> i64 {
    let len = buf.len;
    if len < 2 { return -1; }
    let b0 = buf[0];
    let b1 = buf[1];
    let rsv = (b0 >> 4) & 7;
    if rsv != 0 { return -2; }
    let opcode = b0 & 15;
    if opcode > 10 { return -2; }

    let masked = (b1 & 128) != 0;
    var plen = (b1 & 127) as i64;
    var hdr_len: i64 = 2;

    if plen == 126 {
        hdr_len += 2;
        if len < hdr_len { return -1; }
        plen = ((buf[2] as i64) << 8) | buf[3];
        if plen < 126 { return -2; }
    } else if plen == 127 {
        hdr_len += 8;
        if len < hdr_len { return -1; }
        let msb = ((buf[2] as i64) << 24) | ((buf[3] as i64) << 16) | ((buf[4] as i64) << 8) | buf[5];
        if (msb & 0x80000000) != 0 { return -2; }
        plen = ((buf[6] as i64) << 24) | ((buf[7] as i64) << 16) | ((buf[8] as i64) << 8) | buf[9];
        if msb == 0 && plen < 65536 { return -2; }
    }

    if masked {
        hdr_len += 4;
        if len < hdr_len { return -1; }
    }

    return plen;
}

fn main() {
    var chunk_pkt: u8[>..] = [];
    assert(wire_kit::parse_hex("31410d0a30313233343536373839616263646566303132333435363738390d0a", chunk_pkt));
    assert(wire_kit::verify_split_stream(chunk_pkt[..], -1, 26, parse_chunk_size));
    assert(wire_kit::fuzz_payload(chunk_pkt[..], 100, parse_chunk_size));
    print("CHAOS_CHUNKED: OK");

    var dns_pkt: u8[>..] = [];
    assert(wire_kit::parse_hex("123401000001000000000000076578616d706c6503636f6d0000010001", dns_pkt));
    assert(wire_kit::verify_split_stream(dns_pkt[..], -1, 1, parse_dns_question));
    assert(wire_kit::fuzz_payload(dns_pkt[..], 100, parse_dns_question));
    print("CHAOS_DNS: OK");

    var tls_pkt: u8[>..] = [];
    assert(wire_kit::parse_hex("1703030080", tls_pkt));
    assert(wire_kit::verify_split_stream(tls_pkt[..], -1, 128, parse_tls_record_header));
    assert(wire_kit::fuzz_payload(tls_pkt[..], 100, parse_tls_record_header));
    print("CHAOS_TLS: OK");

    var ws_pkt: u8[>..] = [];
    assert(wire_kit::parse_hex("81fe0100a1b2c3d4", ws_pkt));
    assert(wire_kit::verify_split_stream(ws_pkt[..], -1, 256, parse_ws_extended_header));
    assert(wire_kit::fuzz_payload(ws_pkt[..], 100, parse_ws_extended_header));
    print("CHAOS_WS: OK");
}

// CHECK: CHAOS_CHUNKED: OK
// CHECK: CHAOS_DNS: OK
// CHECK: CHAOS_TLS: OK
// CHECK: CHAOS_WS: OK
