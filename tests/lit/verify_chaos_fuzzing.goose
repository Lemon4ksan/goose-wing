// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";
import wire_kit from ".";

// Section 1: HTTP/1 chunked parser wired to wing FSM
fn parse_chunk_size(buf: const u8[:]) -> i64 {
    var dec = internal::new_chunk_fsm_decoder();
    let st, consumed, chunk = internal::chunk_fsm_feed(dec, buf);
    match st {
        YieldChunk => {
            if dec.state == internal::CHUNK_STATE_IS_CHUNKED && consumed == buf.len {
                return chunk.len;
            }
            return -1;
        },
        Complete => {
            if consumed == buf.len {
                return 0;
            }
            return -1;
        },
        NeedMore => {
            return -1;
        },
        Error => {
            return -2;
        },
    }
}

// Section 2: DNS wire question parser wired to wing DNS decoder
fn parse_dns_question(buf: const u8[:]) -> i64 {
    if buf.len < 12 { return -1; }
    let qdcount = core::read_be_u16(buf, 4);
    if qdcount == 0 { return -2; }

    var off: i64 = 12;
    var saw_end = false;
    while off < buf.len {
        let b = buf[off];
        if b == 0 {
            off += 1;
            saw_end = true;
            break;
        }
        if (b & 0xC0) == 0xC0 {
            if off + 2 > buf.len { return -1; }
            off += 2;
            saw_end = true;
            break;
        }
        if (b & 0xC0) != 0 || b > 63 { return -2; }
        let label_len = b as i64;
        off += 1 + label_len;
        if off > buf.len { return -1; }
    }
    if !saw_end { return -1; }

    var decode_off: i64       = 12;
    var name_out:   u8[..256] = [];
    if !wing::dns_decode_name(buf, decode_off, name_out) {
        return -2;
    }
    if buf.len < decode_off + 4 { return -1; }
    let qtype = core::read_be_u16(buf, decode_off);
    let qclass = core::read_be_u16(buf, decode_off + 2);
    if qclass != 1 && qclass != 255 { return -2; }
    return qtype;
}

// Section 3: TLS 1.3 record header parser wired to wing TLS record decoder
fn parse_tls_record_header(buf: const u8[:]) -> i64 {
    if buf.len < 5 { return -1; }
    let _, _, rlen, _, ok = wing::parse_tls_record_header(buf);
    if !ok { return -2; }
    return rlen;
}

// Section 4: WebSocket extended header parser wired to wing WebSocket decoder
fn parse_ws_extended_header(buf: const u8[:]) -> i64 {
    if buf.len < 2 { return -1; }
    let opcode = buf[0] & 0x0F;
    if !wing::is_valid_ws_opcode(opcode) { return -2; }
    let masked = (buf[1] & 0x80) != 0;
    let raw_len = buf[1] & 0x7F;
    var min_hdr: i64 = 2;
    if raw_len == 126 { min_hdr += 2; }
    else if raw_len == 127 { min_hdr += 8; }
    if masked { min_hdr += 4; }
    if buf.len < min_hdr { return -1; }

    let hdr, ok = wing::parse_ws_frame_header(buf);
    if !ok { return -2; }
    return hdr.payload_len as! i64;
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
