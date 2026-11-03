// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Consolidated Verification Suite: QUIC Protocol, Framing, Flow Control & ACK Verification Suite
//
// RUN: goose build -o %t.exe %s
// RUN: %t.exe
import std;
import core from "..";
import wing from "..";
import lit from "github.com/Lemon4ksan/goose-lit@v0.1.0";

// --- Component: quic ---
// QUIC Transport & HTTP/3 Echelon 7 Conformance Suite (RFC 9000, RFC 9001, RFC 9002, RFC 9114, RFC 9204).
// Tests QPACK Static/Dynamic tables, Header Accordion DoS Defenses, VarInt codec,
// AES/ChaCha Header Protection, Packet Number Reconstruction, Anti-Amplification 3x,
// ReassemblyBuffer, ACK Framing, OACK Defense, 5-Priority PTO, BBRv2/v3, CUBIC & Pacer.

// 1. QPACK Static Table, Dynamic Table & Codecs (RFC 9204)
fn test_qpack_table_and_codecs(t: lit::T&) {
    t.run("QPACK-01: RFC 9204 Appendix A Static Table Lookups") { sub =>
        // Index 0: :authority
        let ent0, ok0 = internal::get_qpack_static_field(0);
        sub.assert_true(ok0, "static lookup index 0 ok");
        sub.assert_eq(ent0.name, ":authority", "index 0 name is :authority");
        sub.assert_eq(ent0.val, "", "index 0 value is empty");

        // Index 1: :path /
        let ent1, ok1 = internal::get_qpack_static_field(1);
        sub.assert_true(ok1, "static lookup index 1 ok");
        sub.assert_eq(ent1.name, ":path", "index 1 name is :path");
        sub.assert_eq(ent1.val, "/", "index 1 value is /");

        // Index 17: :method GET
        let ent17, ok17 = internal::get_qpack_static_field(17);
        sub.assert_true(ok17, "static lookup index 17 ok");
        sub.assert_eq(ent17.name, ":method", "index 17 name is :method");
        sub.assert_eq(ent17.val, "GET", "index 17 value is GET");

        // Index 25: :status 200
        let ent25, ok25 = internal::get_qpack_static_field(25);
        sub.assert_true(ok25, "static lookup index 25 ok");
        sub.assert_eq(ent25.name, ":status", "index 25 name is :status");
        sub.assert_eq(ent25.val, "200", "index 25 value is 200");

        // Out of bounds: index 99
        let _, ok99 = internal::get_qpack_static_field(99);
        sub.assert_false(ok99, "index 99 is out of bounds for 99-entry static table");
    };

    t.run("QPACK-02: Zero-Allocation Dynamic Table Ring Buffer & Eviction") { sub =>
        var tbl = internal::new_qpack_table(128, 16); // 128 bytes max capacity
        // Each entry size = name.len + value.len + 32
        // Entry 1: custom-header (13) + value1 (6) + 32 = 51 bytes
        let ok1 = internal::qpack_insert_literal(tbl, "custom-header", "value1");
        sub.assert_true(ok1, "insert entry 1 ok");
        sub.assert_eq(tbl.insert_count, 1, "inserted count is 1");
        sub.assert_eq(tbl.used_bytes, 51, "used 51 bytes");

        // Entry 2: custom-header (13) + value2 (6) + 32 = 51 bytes. Total = 102 <= 128
        let ok2 = internal::qpack_insert_literal(tbl, "custom-header", "value2");
        sub.assert_true(ok2, "insert entry 2 ok");
        sub.assert_eq(tbl.insert_count, 2, "inserted count is 2");
        sub.assert_eq(tbl.used_bytes, 102, "used 102 bytes");

        // Entry 3: custom-header (13) + value3 (6) + 32 = 51 bytes.
        // 102 + 51 = 153 > 128 -> Must evict entry 1 (oldest)!
        let ok3 = internal::qpack_insert_literal(tbl, "custom-header", "value3");
        sub.assert_true(ok3, "insert entry 3 ok with eviction");
        sub.assert_eq(tbl.insert_count, 3, "total inserted count is 3");
        sub.assert_eq(tbl.used_bytes, 102, "used bytes remains 102 after eviction");

        // Absolute index 0 was evicted
        var n0: u8[..256]  = [];
        var v0: u8[..4096] = [];
        let ok_evicted = internal::qpack_lookup_absolute(tbl, 0, n0, v0);
        sub.assert_false(ok_evicted, "evicted entry 0 cannot be looked up");

        // Absolute index 2 (latest) is active
        var n2: u8[..256]  = [];
        var v2: u8[..4096] = [];
        let ok_act = internal::qpack_lookup_absolute(tbl, 2, n2, v2);
        sub.assert_true(ok_act, "active entry 2 looked up");
        sub.assert_eq(v2[..], "value3", "entry 2 value is value3");
    };

    t.run("QPACK-03: RIC and Delta Base Prefix Codecs") { sub =>
        // Test RIC encode/decode
        let enc_ric = internal::encode_ric(15, 128);
        let ric, err_ric = internal::decode_ric(enc_ric, 15, 128);
        sub.assert_eq(err_ric, internal::QpackError.None, "decode RIC no error");
        sub.assert_eq(ric, 15, "decoded RIC matches original");

        // Test Delta Base encode/decode
        let sign_bit, delta_base = internal::encode_base(20, 25); // base < ric -> sign = 1, delta = 4
        let base, err_base = internal::decode_base(sign_bit, delta_base, 25);
        sub.assert_eq(err_base, internal::QpackError.None, "decode base no error");
        sub.assert_eq(base, 20, "decoded base matches original");
    };
}

// 2. QPACK Header Accordion DoS Defense & Post-Decode RIC Validation
fn test_qpack_security_defenses(t: lit::T&) {
    t.run("QPACK-DOS-01: Header Accordion 32-Byte Overhead Enforcement") { sub =>
        var fields:      internal::HeaderField[>..] = [];
        var budget_left: u64                        = 100; // 100 bytes budget

        // Entry: "a": "b" -> length 2. Plus 32 overhead = 34 bytes!
        let err1 = internal::emit_field_checked(fields, budget_left, "a", "b", false);
        sub.assert_eq(err1, internal::QpackError.None, "first field accepted");
        sub.assert_eq(budget_left, 66, "budget left is 66 (100 - 34)");

        // Second entry: "c": "d" -> 34 bytes. Budget left = 32 <= 100
        let err2 = internal::emit_field_checked(fields, budget_left, "c", "d", false);
        sub.assert_eq(err2, internal::QpackError.None, "second field accepted");
        sub.assert_eq(budget_left, 32, "budget left is 32");

        // Third entry: "e": "f" -> 34 bytes. 32 < 34 -> Must reject with HeaderListTooLarge!
        let err3 = internal::emit_field_checked(fields, budget_left, "e", "f", false);
        sub.assert_eq(err3, internal::QpackError.HeaderListTooLarge, "third field rejected to prevent 33x memory amplification DoS");
    };

    t.run("QPACK-DOS-02: Post-Decode RIC Validation (RFC 9204 Section 4.5.1)") { sub =>
        var tbl = internal::new_qpack_table(4096, 16);
        // Wire block with static-only reference (:status 200, static idx 25)
        // Header block prefix: RIC=5 (encoded as 6 with max_cap=4096), DeltaBase=0
        // But block only uses static headers -> RFC 9204 Section 4.5.1 mandates RIC MUST BE 0!
        var malicious_block: u8[..16] = [];
        // enc_ric = 6
        malicious_block.push(0x06);
        // delta_base = 0 (sign = 0, delta = 0)
        malicious_block.push(0x00);
        // static field line: 11011001 (1T idx=25) -> 0xD9
        malicious_block.push(0xD9);

        var out_fields: internal::HeaderField[>..] = [];
        let err = internal::decode_qpack_section(tbl, malicious_block[..], out_fields, 16384);
        sub.assert_eq(err, internal::QpackError.DecompressionFailed, "malicious non-zero RIC on static-only block rejected");
    };
}

// 3. QUIC VarInt Codec & Packet Framing (RFC 9000, RFC 9001)
fn test_quic_varint_and_framing(t: lit::T&) {
    t.run("VARINT-01: 1, 2, 4, 8-Byte Boundary Roundtrips") { sub =>
        // 1-byte boundary: 0, 63
        var buf1: u8[..16] = [];
        sub.assert_true(internal::quic_encode_varint(buf1, 63), "encode 63");
        sub.assert_eq(buf1.len, 1, "63 encoded in 1 byte");
        let v1, _, ok1 = internal::quic_decode_varint(buf1[..], 0);
        sub.assert_true(ok1, "decode 63");
        sub.assert_eq(v1, 63, "value 63 matches");

        // 2-byte boundary: 64, 16383
        var buf2: u8[..16] = [];
        sub.assert_true(internal::quic_encode_varint(buf2, 16383), "encode 16383");
        sub.assert_eq(buf2.len, 2, "16383 encoded in 2 bytes");
        let v2, _, ok2 = internal::quic_decode_varint(buf2[..], 0);
        sub.assert_true(ok2, "decode 16383");
        sub.assert_eq(v2, 16383, "value 16383 matches");

        // 4-byte boundary: 1073741823
        var buf4: u8[..16] = [];
        sub.assert_true(internal::quic_encode_varint(buf4, 1073741823), "encode 1073741823");
        sub.assert_eq(buf4.len, 4, "1073741823 encoded in 4 bytes");
        let v4, _, ok4 = internal::quic_decode_varint(buf4[..], 0);
        sub.assert_true(ok4, "decode 1073741823");
        sub.assert_eq(v4, 1073741823, "value 1073741823 matches");

        // 8-byte boundary: 0x3FFFFFFFFFFFFFFF
        var buf8: u8[..16] = [];
        sub.assert_true(internal::quic_encode_varint(buf8, 0x3FFFFFFFFFFFFFFF), "encode max varint");
        sub.assert_eq(buf8.len, 8, "max varint encoded in 8 bytes");
        let v8, _, ok8 = internal::quic_decode_varint(buf8[..], 0);
        sub.assert_true(ok8, "decode max varint");
        sub.assert_eq(v8, 0x3FFFFFFFFFFFFFFF, "value max varint matches");
    };

    t.run("FRAMING-01: Long & Short Header Encode / Decode Roundtrip") { sub =>
        // Initial Header
        var orig_hdr = internal::QuicHeader {
            header_type:    internal::QuicHeaderType.Initial,
            version:        rfc::QUIC_VERSION_1,
            payload_length: 1200,
            packet_number:  42,
            ..
        };
        orig_hdr.dcid.append([1, 2, 3, 4, 5, 6, 7, 8]);
        orig_hdr.scid.append([9, 10, 11, 12]);

        var wire: u8[..128] = [];
        let ok_enc = internal::encode_quic_header(wire, orig_hdr, 2);
        sub.assert_true(ok_enc, "encode Initial header ok");

        let parsed, ok_dec = internal::parse_quic_header(wire[..], 0);
        sub.assert_true(ok_dec, "parse Initial header ok");
        sub.assert_eq(parsed.header_type, internal::QuicHeaderType.Initial, "header type Initial");
        sub.assert_eq(parsed.version, rfc::QUIC_VERSION_1, "version QUIC v1");
        sub.assert_eq(parsed.dcid[..], orig_hdr.dcid[..], "dcid matches");
        sub.assert_eq(parsed.scid[..], orig_hdr.scid[..], "scid matches");
        sub.assert_eq(parsed.payload_length, 1200, "payload length matches");
    };

    t.run("STREAM-01: Stream Identifier Classification (RFC 9000 Section 2.1)") { sub =>
        // Client Bidirectional: 0, 4, 8
        sub.assert_true(internal::quic_is_client_stream(0), "stream 0 is client");
        sub.assert_true(internal::quic_is_bidi_stream(0), "stream 0 is bidi");

        // Server Bidirectional: 1, 5, 9
        sub.assert_true(internal::quic_is_server_stream(1), "stream 1 is server");
        sub.assert_true(internal::quic_is_bidi_stream(1), "stream 1 is bidi");

        // Client Unidirectional: 2, 6, 10
        sub.assert_true(internal::quic_is_client_stream(2), "stream 2 is client");
        sub.assert_true(internal::quic_is_uni_stream(2), "stream 2 is uni");

        // Server Unidirectional: 3, 7, 11
        sub.assert_true(internal::quic_is_server_stream(3), "stream 3 is server");
        sub.assert_true(internal::quic_is_uni_stream(3), "stream 3 is uni");
    };

    t.run("DATAGRAM-01: RFC 9221 Unreliable Datagram Framing") { sub =>
        var buf1: u8[..64] = [];
        sub.assert_true(internal::encode_quic_datagram_frame(buf1, "telemetry-payload", true), "encode datagram with length");
        let d1, next1, ok1 = internal::decode_quic_datagram_frame(buf1[..], 0);
        sub.assert_true(ok1, "decode datagram with length");
        sub.assert_eq(d1, "telemetry-payload", "payload matches with length");
        sub.assert_eq(next1, buf1.len as u64, "consumed all bytes");

        var buf2: u8[..64] = [];
        sub.assert_true(internal::encode_quic_datagram_frame(buf2, "raw-stream-end", false), "encode datagram without length");
        let d2, next2, ok2 = internal::decode_quic_datagram_frame(buf2[..], 0, buf2.len as u64);
        sub.assert_true(ok2, "decode datagram without length");
        sub.assert_eq(d2, "raw-stream-end", "payload matches without length");
        sub.assert_eq(next2, buf2.len as u64, "consumed all bytes");
    };
}

// 4. Header Protection & Packet Number Reconstruction (RFC 9001, RFC 9000)
fn test_header_protection_and_pn(t: lit::T&) {
    t.run("HP-01: RFC 9001 Appendix A.2 Header Protection Vector") { sub =>
        let hp_key: u8[16] = [
            0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10,
            0x28, 0x3a, 0x1e, 0x99, 0x33, 0xad, 0xed, 0xd2,
        ];
        let sample: u8[16] = [
            0xd1, 0xb1, 0xc9, 0x8d, 0xd7, 0x68, 0x9f, 0xb8,
            0xec, 0x11, 0xd2, 0x42, 0xb1, 0x23, 0xdc, 0x9b,
        ];
        let mask = internal::aes128_header_protect_mask(hp_key, sample);
        let expected_mask: u8[5] = [0x43, 0x7b, 0x9a, 0xec, 0x36];
        sub.assert_eq(mask[..], expected_mask[..], "AES-128 HP mask matches RFC 9001 Appendix A.2");
    };

    t.run("HP-02: Header Protection Mask Application & In-Place Removal") { sub =>
        // Simulated 1-RTT short header with 2-byte packet number (PN = 0x1234)
        var pkt: u8[8] = [0x41, 0x12, 0x34, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
        let mask: u8[5] = [0x1A, 0x55, 0xAA, 0x00, 0x00];

        internal::apply_header_protection(pkt[..], 1, 2, mask);
        // Header first byte and PN fields are now masked
        sub.assert_true(pkt[0] != 0x41, "header first byte is masked");
        sub.assert_true(pkt[1] != 0x12, "PN byte 0 is masked");

        // Remove protection in-place
        let pn_len, trunc_pn = internal::remove_header_protection(pkt[..], 1, mask);
        sub.assert_eq(pn_len, 2, "recovered PN length is 2");
        sub.assert_eq(trunc_pn, 0x1234, "recovered truncated PN is 0x1234");
        sub.assert_eq(pkt[0], 0x41, "first byte unmasked to 0x41");
    };

    t.run("PN-01: RFC 9000 Appendix A.3 Packet Number Reconstruction") { sub =>
        // Normal sequential packet numbers
        let pn1 = internal::decode_packet_number(0, 1, 1);
        sub.assert_eq(pn1, 1, "pn 1 decoded from largest_acked 0");

        let pn64 = internal::decode_packet_number(63, 64, 1);
        sub.assert_eq(pn64, 64, "pn 64 decoded from largest_acked 63");

        // Window wrap across 1-byte truncated boundary (255 -> 256)
        let pn256 = internal::decode_packet_number(255, 0, 1);
        sub.assert_eq(pn256, 256, "pn 256 decoded from wrap 0 with largest_acked 255");

        // Out-of-order packet in the past (e.g. pn 254 arriving when largest acked is 256)
        let pn_past = internal::decode_packet_number(256, 254, 1);
        sub.assert_eq(pn_past, 254, "out-of-order past pn 254 correctly reconstructed");
    };

    t.run("HP-03: ChaCha20 & AES-256 Header Protection") { sub =>
        let hp_key: u8[32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        ];
        let sample: u8[16] = [
            0xd1, 0xb1, 0xc9, 0x8d, 0xd7, 0x68, 0x9f, 0xb8,
            0xec, 0x11, 0xd2, 0x42, 0xb1, 0x23, 0xdc, 0x9b,
        ];
        let chacha_mask = internal::chacha20_header_protect_mask(hp_key, sample);
        sub.assert_true(chacha_mask.len == 5, "chacha20 mask is 5 bytes");

        let aes256_mask = internal::aes256_header_protect_mask(hp_key, sample);
        sub.assert_true(aes256_mask.len == 5, "aes256 mask is 5 bytes");

        // Protect & unprotect with ChaCha20 mask on long header
        var pkt: u8[16] = [
            0xC3, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x05, 0x12, 0x34, 0x56, 0x78, 0xAA, 0xBB, 0xCC,
        ];
        let orig_b0 = pkt[0];
        internal::apply_header_protection(pkt[..], 9, 4, chacha_mask);
        sub.assert_true(pkt[0] != orig_b0, "first byte masked");

        let pn_len, trunc_pn = internal::remove_header_protection(pkt[..], 9, chacha_mask);
        sub.assert_eq(pn_len, 4, "recovered 4-byte PN");
        sub.assert_eq(trunc_pn, 0x12345678, "recovered truncated PN matches");
        sub.assert_eq(pkt[0], orig_b0, "first byte restored");
    };

    t.run("HDR-02: QUIC Header Parsing Across All Packet Types") { sub =>
        // 1. Handshake Packet Header
        var h_hdr = internal::QuicHeader {
            header_type:    internal::QuicHeaderType.Handshake,
            version:        rfc::QUIC_VERSION_1,
            payload_length: 120,
            packet_number:  42,
            ..
        };
        h_hdr.dcid.append("dcid1234");
        h_hdr.scid.append("scid5678");

        var h_buf: u8[..128] = [];
        sub.assert_true(internal::encode_quic_header(h_buf, h_hdr, 2), "encode Handshake header");
        let parsed_h, ok_h = internal::parse_quic_header(h_buf[..], 0);
        sub.assert_true(ok_h, "parse Handshake header");
        sub.assert_eq(parsed_h.header_type, internal::QuicHeaderType.Handshake, "type is Handshake");
        sub.assert_eq(parsed_h.dcid[..], "dcid1234", "dcid matches");
        sub.assert_eq(parsed_h.scid[..], "scid5678", "scid matches");
        sub.assert_eq(parsed_h.payload_length, 120, "payload length matches");

        // 2. 0-RTT Packet Header
        var z_hdr = internal::QuicHeader {
            header_type:    internal::QuicHeaderType.ZeroRtt,
            version:        rfc::QUIC_VERSION_1,
            payload_length: 50,
            packet_number:  1,
            ..
        };
        z_hdr.dcid.append("zero-dcid");
        var z_buf: u8[..128] = [];
        sub.assert_true(internal::encode_quic_header(z_buf, z_hdr, 1), "encode 0-RTT header");
        let parsed_z, ok_z = internal::parse_quic_header(z_buf[..], 0);
        sub.assert_true(ok_z, "parse 0-RTT header");
        sub.assert_eq(parsed_z.header_type, internal::QuicHeaderType.ZeroRtt, "type is ZeroRtt");

        // 3. Retry Packet Header
        var r_hdr = internal::QuicHeader {
            header_type: internal::QuicHeaderType.Retry,
            version:     rfc::QUIC_VERSION_1,
            ..
        };
        r_hdr.dcid.append("retry-dcid");
        r_hdr.scid.append("retry-scid");
        var r_buf: u8[..128] = [];
        sub.assert_true(internal::encode_quic_header(r_buf, r_hdr, 1), "encode Retry header");
        r_buf.append("retry-token-data-16bytes");
        let parsed_r, ok_r = internal::parse_quic_header(r_buf[..], 0);
        sub.assert_true(ok_r, "parse Retry header");
        sub.assert_eq(parsed_r.header_type, internal::QuicHeaderType.Retry, "type is Retry");

        // 4. Version Negotiation Packet Header (version = 0)
        var vn_buf: u8[..64] = [];
        vn_buf.push(0x80); // Long header, ver=0
        vn_buf.push(0x00);
        vn_buf.push(0x00);
        vn_buf.push(0x00);
        vn_buf.push(0x00);
        vn_buf.push(4); // dcid len
        vn_buf.append("dcid");
        vn_buf.push(4); // scid len
        vn_buf.append("scid");
        vn_buf.push(0x00); vn_buf.push(0x00); vn_buf.push(0x00); vn_buf.push(0x01);

        let parsed_vn, ok_vn = internal::parse_quic_header(vn_buf[..], 0);
        sub.assert_true(ok_vn, "parse Version Negotiation header");
        sub.assert_eq(parsed_vn.header_type, internal::QuicHeaderType.VersionNegotiation, "type is VersionNegotiation");
        sub.assert_eq(parsed_vn.dcid[..], "dcid", "VN dcid matches");
        sub.assert_eq(parsed_vn.scid[..], "scid", "VN scid matches");
    };
}

// 5. Anti-Amplification 3x Limit & Zero-Heap Reassembly (RFC 9000)
fn test_anti_amplification_and_reassembly(t: lit::T&) {
    t.run("PATH-01: Server Anti-Amplification 3x Credit Tracking") { sub =>
        let ip: u8[16] = [0; 16];
        var path = internal::new_path_state(ip, 443, false); // unvalidated client path

        // Client sends 1200 bytes Initial packet
        internal::on_path_bytes_received(path, 1200);
        // Total credit = 3 * 1200 = 3600 bytes

        sub.assert_true(internal::can_send_on_path(path, 1200), "can send 1st 1200B packet");
        internal::on_path_bytes_sent(path, 1200);

        sub.assert_true(internal::can_send_on_path(path, 1200), "can send 2nd 1200B packet");
        internal::on_path_bytes_sent(path, 1200);

        sub.assert_true(internal::can_send_on_path(path, 1200), "can send 3rd 1200B packet");
        internal::on_path_bytes_sent(path, 1200);
        // Total sent = 3600 = 3 * 1200. Further packets must be blocked!

        sub.assert_false(internal::can_send_on_path(path, 1), "4th packet blocked by 3x limit");

        // Validate path -> credit limit lifted
        internal::validate_path(path);
        sub.assert_true(internal::can_send_on_path(path, 1200), "sending allowed on validated path");
    };

    t.run("REASSEMBLY-01: Out-of-Order & Overlapping Stream Fragments") { sub =>
        var rbuf = internal::new_reassembly_buffer(65536);

        // Fragment 2 arrives first: offset 5..10 ("WORLD")
        let ok2 = internal::insert_fragment(rbuf, 5, "WORLD", false);
        sub.assert_true(ok2, "insert fragment 2 ok");
        sub.assert_eq(rbuf.consumed_offset, 0, "consumed remains 0 while waiting for head");

        // Fragment 1 arrives: offset 0..5 ("HELLO")
        let ok1 = internal::insert_fragment(rbuf, 0, "HELLO", false);
        sub.assert_true(ok1, "insert fragment 1 ok");

        // Contiguous read
        var out: u8[..64] = [];
        let n = internal::read_contiguous(rbuf, out);
        sub.assert_eq(n, 10, "read 10 contiguous bytes");
        sub.assert_eq(out[..], "HELLOWORLD", "assembled payload is HELLOWORLD");
        sub.assert_eq(rbuf.consumed_offset, 10, "consumed offset advanced to 10");
    };

    t.run("REASSEMBLY-02: Flow Control & Final Size Guard") { sub =>
        var rbuf = internal::new_reassembly_buffer(100); // 100 bytes max limit

        // Fragment exceeding flow control limit
        let ok_overflow = internal::insert_fragment(rbuf, 90, "0123456789ABCDEF", false); // end 106 > 100
        sub.assert_false(ok_overflow, "flow control overflow rejected");

        // Consistent FIN
        let ok_fin1 = internal::insert_fragment(rbuf, 0, "DATA", true);
        sub.assert_true(ok_fin1, "FIN set at offset 4");
        sub.assert_eq(rbuf.final_size, 4, "final size is 4");

        // Conflicting FIN -> QUIC_ERR_FINAL_SIZE
        let ok_fin2 = internal::insert_fragment(rbuf, 0, "DATA123", true);
        sub.assert_false(ok_fin2, "mismatched final size rejected");
    };
}

// 6. ACK Framing, OACK Defense & 5-Priority PTO (RFC 9000, RFC 9002, ANRW 2025)
fn test_ack_and_pto_engine(t: lit::T&) {
    t.run("ACK-01: ACK & ACK_ECN Encode / Decode Roundtrip") { sub =>
        var orig_ack = internal::AckFrame {
            is_ecn:          true,
            largest_acked:   100,
            ack_delay:       250,
            first_ack_range: 10, // packets 90..100
            ect0_count:      5,
            ect1_count:      0,
            ecn_ce_count:    2,
            ..
        };
        // Gap 2 (packets 87..89 unacked), ACK range 5 (packets 81..86 acked)
        orig_ack.ranges.push(internal::AckRange { gap: 2, ack_range: 5 });

        var wire: u8[..64] = [];
        sub.assert_true(internal::encode_ack_frame(wire, orig_ack), "encode ACK_ECN");

        let dec_ack, consumed, ok_dec = internal::decode_ack_frame(wire[..], 0);
        sub.assert_true(ok_dec, "decode ACK_ECN");
        sub.assert_true(consumed > 0, "consumed > 0");
        sub.assert_true(dec_ack.is_ecn, "is ECN frame");
        sub.assert_eq(dec_ack.largest_acked, 100, "largest acked matches");
        sub.assert_eq(dec_ack.ack_delay, 250, "ack delay matches");
        sub.assert_eq(dec_ack.first_ack_range, 10, "first range matches");
        sub.assert_eq(dec_ack.ranges.len, 1, "ranges len is 1");
        sub.assert_eq(dec_ack.ranges[0].gap, 2, "gap matches");
        sub.assert_eq(dec_ack.ranges[0].ack_range, 5, "range matches");
        sub.assert_eq(dec_ack.ecn_ce_count, 2, "ECN CE count matches");
    };

    t.run("PNSpace: Install Keys and Validate Key State") { sub =>
        var space = internal::PnSpaceState { space_id: internal::PnSpaceId.Handshake, .. };
        var hp:   u8[16] = [1; 16];
        var aead: u8[32] = [2; 32];
        var iv:   u8[12] = [3; 12];
        let ok = internal::quic_install_pn_space_keys(space, hp[..], aead[..], iv[..], 0x1301);
        sub.assert_true(ok, "keys installed");
        sub.assert_true(space.keys_installed, "keys_installed flag set");
        sub.assert_eq(space.hp_key.len, 16, "hp_key len 16");
    };

    t.run("ACK-02: Optimistic ACK (OACK) Forward-Dated Attack Rejection") { sub =>
        var space = internal::PnSpaceState {
            space_id:         internal::PnSpaceId.ApplicationData,
            largest_sent_pn:  50, // Sender only sent up to PN 50!
            has_sent_packets: true,
            ..
        };

        // Malicious peer sends ACK for PN 60 > largest_sent_pn
        let malicious_ack = internal::AckFrame {
            largest_acked:   60,
            ack_delay:       0,
            first_ack_range: 0,
            ..
        };

        var intervals: internal::AckInterval[..64] = [];
        let ok_valid = internal::parse_and_validate_ack(space, malicious_ack, intervals);
        sub.assert_false(ok_valid, "OACK attack claiming unsent PN 60 rejected");
    };

    t.run("RTT-01: RTT Estimators & Max ACK Delay Clamping (RFC 9002 Sec 5.3)") { sub =>
        var rtt = internal::RttState {};
        sub.assert_eq(rtt.smoothed_rtt_us, 333000, "initial smoothed_rtt is 333 ms");

        // First sample: 40 ms
        internal::update_rtt(rtt, 40000, 2000, true, 1000000);
        sub.assert_eq(rtt.min_rtt_us, 40000, "min_rtt updated to 40 ms");
        sub.assert_eq(rtt.smoothed_rtt_us, 40000, "smoothed_rtt initialized to 40 ms");
        sub.assert_eq(rtt.rttvar_us, 20000, "rttvar initialized to 20 ms");

        // Second sample: 48 ms with 5 ms delay -> adjusted 43 ms
        internal::update_rtt(rtt, 48000, 5000, true, 2000000);
        sub.assert_eq(rtt.min_rtt_us, 40000, "min_rtt remains 40 ms");
        // smoothed_rtt = (7 * 40000 + 43000) / 8 = 40375 us
        sub.assert_eq(rtt.smoothed_rtt_us, 40375, "smoothed_rtt weighted average updated");
    };

    t.run("PTO-01: 5-Priority PTO State Machine Decisions") { sub =>
        var spaces: internal::PnSpaceState[3] = [
            internal::PnSpaceState { space_id: internal::PnSpaceId.Initial, .. },
            internal::PnSpaceState { space_id: internal::PnSpaceId.Handshake, .. },
            internal::PnSpaceState { space_id: internal::PnSpaceId.ApplicationData, .. },
        ];
        var rtt = internal::RttState { smoothed_rtt_us: 50000, rttvar_us: 10000, .. };

        // Priority 2: Server at anti-amplification limit
        let dec_amp = internal::evaluate_pto_timer(
            spaces, rtt, 0, 1000000, internal::PtoContext {
                is_server:                true,
                is_amplification_limited: true,
            },
        );
        sub.assert_eq(dec_amp.mode, internal::PtoTimerMode.AntiAmplification, "server at amp limit returns AntiAmplification");

        // Priority 3: Client Anti-deadlock PTO when no packets in flight
        let dec_deadlock = internal::evaluate_pto_timer(
            spaces, rtt, 0, 1000000, internal::PtoContext {
                is_server:                      false,
                is_amplification_limited:       false,
                peer_completed_addr_validation: false,
                handshake_confirmed:            false,
            },
        );
        sub.assert_eq(dec_deadlock.mode, internal::PtoTimerMode.AntiDeadlock, "client anti-deadlock armed");

        // Priority 5: Standard PTO when packets in flight
        spaces[0].sent_packets.push(internal::SentPacketMeta {
            pn: 1, time_sent_us: 1000000, ack_eliciting: true, in_flight: true,
        });
        spaces[0].time_of_last_ack_eliciting_us = 1000000;
        let dec_std = internal::evaluate_pto_timer(
            spaces, rtt, 0, 1000000, internal::PtoContext {
                is_server:                      true,
                peer_completed_addr_validation: true,
            },
        );
        sub.assert_eq(dec_std.mode, internal::PtoTimerMode.StandardPto, "standard PTO scheduled");

        // Priority 1: Time threshold loss detection takes precedence over PTO
        spaces[0].loss_time_us = 1010000;
        let dec_loss = internal::evaluate_pto_timer(
            spaces, rtt, 0, 1000000, internal::PtoContext {
                is_server:                      true,
                peer_completed_addr_validation: true,
            },
        );
        sub.assert_eq(dec_loss.mode, internal::PtoTimerMode.LossTime, "loss time timer takes Priority 1");
    };

    t.run("ACK-03: Descending Interval Tracking & Frame Construction") { sub =>
        var ranges: internal::AckInterval[..64] = [];

        // Record PN 10
        internal::record_received_pn(ranges, 10);
        sub.assert_eq(ranges.len, 1, "1 range recorded");
        sub.assert_eq(ranges[0].smallest, 10, "smallest is 10");
        sub.assert_eq(ranges[0].largest, 10, "largest is 10");

        // Record PN 11 -> merges into [10..11]
        internal::record_received_pn(ranges, 11);
        sub.assert_eq(ranges.len, 1, "still 1 range after contiguous PN 11");
        sub.assert_eq(ranges[0].smallest, 10, "smallest is 10");
        sub.assert_eq(ranges[0].largest, 11, "largest is 11");

        // Record PN 13 -> creates new range: [13..13], [10..11]
        internal::record_received_pn(ranges, 13);
        sub.assert_eq(ranges.len, 2, "2 ranges after gap");
        sub.assert_eq(ranges[0].largest, 13, "range 0 largest is 13");
        sub.assert_eq(ranges[1].largest, 11, "range 1 largest is 11");

        // Record duplicate PN 10 -> ignored
        internal::record_received_pn(ranges, 10);
        sub.assert_eq(ranges.len, 2, "duplicate PN 10 ignored");

        // Record PN 12 -> bridges the gap, merging into [10..13]
        internal::record_received_pn(ranges, 12);
        sub.assert_eq(ranges.len, 1, "gap bridged into 1 range [10..13]");
        sub.assert_eq(ranges[0].smallest, 10, "smallest is 10");
        sub.assert_eq(ranges[0].largest, 13, "largest is 13");

        // Build ACK frame from interval set
        let ack, ok_ack = internal::build_ack_frame(ranges, 150, false);
        sub.assert_true(ok_ack, "build_ack_frame succeeds");
        sub.assert_eq(ack.largest_acked, 13, "largest acked is 13");
        sub.assert_eq(ack.first_ack_range, 3, "first ack range is 13 - 10 = 3");
        sub.assert_eq(ack.ranges.len, 0, "no extra ranges");
        sub.assert_eq(ack.ack_delay, 150, "ack delay is 150");
    };

    t.run("LOSS-01: Packet and Time Threshold Loss Detection (RFC 9002)") { sub =>
        var space = internal::PnSpaceState {
            space_id:          internal::PnSpaceId.ApplicationData,
            has_acked_packets: true,
            largest_acked_pn:  10,
            ..
        };
        // Sent packets: PN 5 (t=1000), PN 6 (t=1000), PN 8 (t=1000)
        space.sent_packets.push(internal::SentPacketMeta {
            pn: 5, time_sent_us: 1000, ack_eliciting: true, in_flight: true,
        });
        space.sent_packets.push(internal::SentPacketMeta {
            pn: 6, time_sent_us: 1000, ack_eliciting: true, in_flight: true,
        });
        space.sent_packets.push(internal::SentPacketMeta {
            pn: 8, time_sent_us: 1000, ack_eliciting: true, in_flight: true,
        });

        var rtt = internal::RttState {
            smoothed_rtt_us: 40000,
            latest_rtt_us:   40000,
            ..
        };

        var lost: internal::SentPacketMeta[..64] = [];
        internal::detect_lost_packets(space, rtt, 100000, lost);

        // Packets 5 and 6 meet packet threshold (10 >= 5 + 3 and 10 >= 6 + 3)
        sub.assert_true(lost.len >= 2, "at least 2 lost packets detected");
        sub.assert_eq(lost[0].pn, 5, "packet 5 detected as lost");
        sub.assert_eq(lost[1].pn, 6, "packet 6 detected as lost");
    };
}

// 7. BBRv2/v3, CUBIC & Pacing Engine (draft-ietf-ccwg-bbr-06, RFC 9438)
fn test_bbr_cubic_and_pacing(t: lit::T&) {
    t.run("PACER-01: User-Space Leaky Bucket Token Tracking") { sub =>
        var pacer = internal::new_pacer(8000000); // 8 Mbps -> 1 byte per microsecond

        // Transmit 1000 bytes at t = 1000000 us -> takes 1000 us
        let ok1, _ = internal::pacer_can_send(pacer, 1000000, 1000);
        sub.assert_true(ok1, "first packet sent immediately");

        // Next packet at t = 1000100 us (only 100 us later) -> bucket in deficit (-900 us)
        let ok2, delay = internal::pacer_can_send(pacer, 1000100, 1000);
        sub.assert_false(ok2, "second packet paced / held in bucket");
        sub.assert_true(delay > 0, "pacer returns non-zero pacing delay");

        // At t = 1002000 us (1900 us later) -> deficit repaid
        let ok3, _ = internal::pacer_can_send(pacer, 1002000, 1000);
        sub.assert_true(ok3, "packet permitted after pacing interval elapsed");
    };

    t.run("BBR-01: 7-State Phase Transitions & Dual-Envelope Congestion") { sub =>
        var bbr = internal::new_bbr_state();
        bbr.bw_hi_bps = 100000000; // 100 Mbps
        bbr.min_rtt_us = 40000;    // 40 ms -> BDP = 500 KB

        sub.assert_eq(bbr.mode, internal::BbrMode.Startup, "initial mode is Startup");

        // Cycle through phases: Startup -> Drain -> Cruise -> Refill -> Up -> Down
        internal::bbr_advance_cycle(bbr, true);
        sub.assert_eq(bbr.mode, internal::BbrMode.Drain, "advanced to Drain");

        internal::bbr_advance_cycle(bbr, true);
        sub.assert_eq(bbr.mode, internal::BbrMode.ProbeBwCruise, "advanced to ProbeBwCruise");

        // Congestion signal: loss rate 5% (> 2%)
        internal::bbr_on_congestion_signal(bbr, 500000, 5000, 100000, 0, 100);
        sub.assert_eq(bbr.mode, internal::BbrMode.ProbeBwDown, "dropped to ProbeBwDown on >2% loss");
        // inflight_hi reduced to 70% of 500,000 = 350,000 bytes
        sub.assert_eq(bbr.inflight_hi_bytes, 350000, "inflight_hi reduced by 70% beta");
    };

    t.run("BBR-02: 5-Second ProbeRTT Trigger & 0.5 BDP Floor") { sub =>
        var bbr = internal::new_bbr_state();
        bbr.bw_hi_bps = 80000000; // 80 Mbps
        bbr.min_rtt_us = 50000;   // 50 ms -> BDP = 500,000 bytes
        bbr.min_rtt_stamp_us = 1000000;
        bbr.mode = internal::BbrMode.ProbeBwCruise;

        // Check at t = 2s (within 5s window) -> remains in Cruise
        internal::bbr_check_probe_rtt(bbr, 2000000, 52000);
        sub.assert_eq(bbr.mode, internal::BbrMode.ProbeBwCruise, "remains in Cruise before 5s expiration");

        // Check at t = 6.1s (> 5s window) -> triggers ProbeRtt!
        internal::bbr_check_probe_rtt(bbr, 6100000, 51000);
        sub.assert_eq(bbr.mode, internal::BbrMode.ProbeRtt, "switched to ProbeRtt after 5s");
        // cwnd in ProbeRtt = max(0.5 * BDP, 4800) = 250,000 bytes
        sub.assert_eq(bbr.cwnd_bytes, 250000, "ProbeRtt cwnd set to 0.5 BDP floor");
    };

    t.run("CUBIC-01: Integer Cube Root & Application-Limited Freeze") { sub =>
        // Test int_cbrt exact values
        sub.assert_eq(internal::int_cbrt(0), 0, "cbrt(0) = 0");
        sub.assert_eq(internal::int_cbrt(1), 1, "cbrt(1) = 1");
        sub.assert_eq(internal::int_cbrt(8), 2, "cbrt(8) = 2");
        sub.assert_eq(internal::int_cbrt(27), 3, "cbrt(27) = 3");
        sub.assert_eq(internal::int_cbrt(1000), 10, "cbrt(1000) = 10");
        sub.assert_eq(internal::int_cbrt(1000000), 100, "cbrt(1000000) = 100");

        var cubic = internal::CubicState { .. };
        cubic.cwnd_segments = 20; // 20 * 1200 = 24000 bytes
        cubic.epoch_start_us = 1000000;
        cubic.last_update_us = 1000000;

        // Inflight = 10000 bytes (< 75% of 24000 = 18000) -> Application Limited!
        let cwnd1 = internal::cubic_on_ack(cubic, 2000000, 40000, 10000, 1200);
        sub.assert_true(cubic.app_limited, "sender detected as application-limited");
        sub.assert_eq(cwnd1, 24000, "cwnd frozen during application-limited period");
        // Epoch start advanced by 1s idle time (from 1000000 to 2000000)
        sub.assert_eq(cubic.epoch_start_us, 2000000, "epoch start frozen/advanced by elapsed idle time");
    };

    t.run("CUBIC-02: Loss Multiplicative Window Reduction (RFC 9438)") { sub =>
        var cubic = internal::CubicState { .. };
        cubic.cwnd_segments = 100;
        internal::cubic_on_loss(cubic, 5000000);
        sub.assert_eq(cubic.w_max_segments, 100, "w_max saved as 100");
        sub.assert_eq(cubic.cwnd_segments, 70, "cwnd reduced to 70 (beta 0.7)");
        sub.assert_eq(cubic.epoch_start_us, 5000000, "epoch start reset to now");
    };
}

// Main Conformance Runner

// --- Component: quic_frames ---
// Test suite for QUIC Transport RFC 9000 Section 19 Frame Codecs,
// Demuxer, and Section 3 Stream State Machine Invariants.

fn test_quic_stream_frame_codec(t: lit::T&) {
    // 1. STREAM frame: Base (stream_id=4, offset=0, no FIN, with length)
    var wire1: u8[..128] = [];
    let flags1 = internal::QuicStreamFlags { fin: false, with_len: true };
    let ok_enc1 = internal::encode_stream_frame(wire1, 4, 0, "hello quic", flags1);
    t.assert_true(ok_enc1, "encode basic stream frame");

    var cur1: i64 = 0;
    let frame1, ok_dec1 = internal::decode_quic_frame_cursor(wire1[..], cur1);
    t.assert_true(ok_dec1, "decode basic stream frame");
    t.assert_eq(frame1.stream_id, 4, "stream id matches");
    t.assert_eq(frame1.offset, 0, "offset is 0");
    t.assert_false(frame1.fin, "fin flag is false");
    t.assert_eq(frame1.payload, "hello quic", "payload matches");

    // 2. STREAM frame with Offset and FIN
    var wire2: u8[..128] = [];
    let flags2 = internal::QuicStreamFlags { fin: true, with_len: true };
    let ok_enc2 = internal::encode_stream_frame(wire2, 8, 1024, "world", flags2);
    t.assert_true(ok_enc2, "encode stream frame with off and fin");

    var cur2: i64 = 0;
    let frame2, ok_dec2 = internal::decode_quic_frame_cursor(wire2[..], cur2);
    t.assert_true(ok_dec2, "decode stream frame with off and fin");
    t.assert_eq(frame2.stream_id, 8, "stream id matches");
    t.assert_eq(frame2.offset, 1024, "offset matches");
    t.assert_true(frame2.fin, "fin flag is true");
    t.assert_eq(frame2.payload, "world", "payload matches");

    // 3. STREAM frame without length (consumes remainder of buffer)
    var wire3: u8[..128] = [];
    let flags3 = internal::QuicStreamFlags { fin: false, with_len: false };
    let ok_enc3 = internal::encode_stream_frame(wire3, 12, 2048, "rest-of-packet", flags3);
    t.assert_true(ok_enc3, "encode stream frame without length");

    var cur3: i64 = 0;
    let frame3, ok_dec3 = internal::decode_quic_frame_cursor(wire3[..], cur3);
    t.assert_true(ok_dec3, "decode stream frame without length");
    t.assert_eq(frame3.stream_id, 12, "stream id matches");
    t.assert_eq(frame3.offset, 2048, "offset matches");
    t.assert_eq(frame3.payload, "rest-of-packet", "payload matches");

    // 4. Zero-length payload STREAM with FIN
    var wire4: u8[..64] = [];
    let flags4 = internal::QuicStreamFlags { fin: true, with_len: true };
    let ok_enc4 = internal::encode_stream_frame(wire4, 16, 5000, "", flags4);
    t.assert_true(ok_enc4, "encode empty fin stream frame");

    var cur4: i64 = 0;
    let frame4, ok_dec4 = internal::decode_quic_frame_cursor(wire4[..], cur4);
    t.assert_true(ok_dec4, "decode empty fin stream frame");
    t.assert_eq(frame4.stream_id, 16, "stream id matches");
    t.assert_eq(frame4.offset, 5000, "offset matches");
    t.assert_true(frame4.fin, "fin is true");
    t.assert_eq(frame4.length, 0, "length is 0");

    // 5. RFC 9000 §19.8 bounds check: offset + length > 2^62 - 1 rejected
    var wire_bad: u8[..64] = [];
    let flags_bad = internal::QuicStreamFlags { fin: false, with_len: true };
    let ok_bad_enc = internal::encode_stream_frame(wire_bad, 4, 0x3FFFFFFFFFFFFFFF, "overflow", flags_bad);
    t.assert_false(ok_bad_enc, "offset + len exceeding 2^62-1 rejected during encoding");
}

fn test_quic_crypto_frame_codec(t: lit::T&) {
    var wire: u8[..256] = [];
    let tls_data: const u8[6] = [0x01, 0x00, 0x00, 0x02, 0x03, 0x03];
    let ok_enc = internal::encode_crypto_frame(wire, 500, tls_data[..]);
    t.assert_true(ok_enc, "encode crypto frame");

    var cur: i64 = 0;
    let frame, ok_dec = internal::decode_quic_frame_cursor(wire[..], cur);
    t.assert_true(ok_dec, "decode crypto frame");
    t.assert_eq(frame.raw_type, rfc::QUIC_FRAME_CRYPTO, "frame type is crypto");
    t.assert_eq(frame.offset, 500, "crypto offset matches");
    t.assert_eq(frame.length, 6, "crypto length matches");
    t.assert_eq(frame.payload.len, 6, "crypto payload slice matches");
    t.assert_eq(frame.payload[0], 0x01, "first payload byte matches");

    // RFC 9000 §19.6 bounds: offset + len > 2^62 - 1
    var wire_bad: u8[..64] = [];
    let ok_bad = internal::encode_crypto_frame(wire_bad, 0x3FFFFFFFFFFFFFFF, tls_data[..]);
    t.assert_false(ok_bad, "crypto offset overflow rejected");
}

fn test_quic_control_frames_codec(t: lit::T&) {
    // 1. RESET_STREAM
    var wire_rst: u8[..64] = [];
    let ok_rst_enc = internal::encode_reset_stream_frame(wire_rst, 4, 0x101, 4096);
    t.assert_true(ok_rst_enc, "encode reset stream frame");

    var cur_rst: i64 = 0;
    let f_rst, ok_rst_dec = internal::decode_quic_frame_cursor(wire_rst[..], cur_rst);
    t.assert_true(ok_rst_dec, "decode reset stream frame");
    t.assert_eq(f_rst.stream_id, 4, "reset stream id matches");
    t.assert_eq(f_rst.error_code, 0x101, "reset error code matches");
    t.assert_eq(f_rst.final_size, 4096, "reset final size matches");

    // 2. STOP_SENDING
    var wire_ss: u8[..64] = [];
    let ok_ss_enc = internal::encode_stop_sending_frame(wire_ss, 8, 0x102);
    t.assert_true(ok_ss_enc, "encode stop sending frame");

    var cur_ss: i64 = 0;
    let f_ss, ok_ss_dec = internal::decode_quic_frame_cursor(wire_ss[..], cur_ss);
    t.assert_true(ok_ss_dec, "decode stop sending frame");
    t.assert_eq(f_ss.stream_id, 8, "stop sending stream id matches");
    t.assert_eq(f_ss.error_code, 0x102, "stop sending error code matches");

    // 3. MAX_DATA
    var wire_md: u8[..64] = [];
    let ok_md_enc = internal::encode_max_data_frame(wire_md, 1048576);
    t.assert_true(ok_md_enc, "encode max data frame");

    var cur_md: i64 = 0;
    let f_md, ok_md_dec = internal::decode_quic_frame_cursor(wire_md[..], cur_md);
    t.assert_true(ok_md_dec, "decode max data frame");
    t.assert_eq(f_md.max_data, 1048576, "max data limit matches");

    // 4. MAX_STREAM_DATA
    var wire_msd: u8[..64] = [];
    let ok_msd_enc = internal::encode_max_stream_data_frame(wire_msd, 12, 262144);
    t.assert_true(ok_msd_enc, "encode max stream data frame");

    var cur_msd: i64 = 0;
    let f_msd, ok_msd_dec = internal::decode_quic_frame_cursor(wire_msd[..], cur_msd);
    t.assert_true(ok_msd_dec, "decode max stream data frame");
    t.assert_eq(f_msd.stream_id, 12, "max stream data stream id matches");
    t.assert_eq(f_msd.max_data, 262144, "max stream data limit matches");

    // 5. PING and PADDING
    var wire_ping: u8[..16] = [];
    t.assert_true(internal::encode_ping_frame(wire_ping), "encode ping");
    t.assert_eq(wire_ping.len, 1, "ping length 1");
    t.assert_eq(wire_ping[0], 0x01, "ping byte 0x01");

    var wire_pad: u8[..16] = [];
    t.assert_true(internal::encode_padding_frame(wire_pad, 5), "encode padding x5");
    t.assert_eq(wire_pad.len, 5, "padding length 5");
    for i in 5 {
        t.assert_eq(wire_pad[i], 0x00, "padding byte 0x00");
    }
}

fn test_quic_frame_demuxer(t: lit::T&) {
    // Pack multiple distinct frames into a single datagram payload buffer
    var packet_wire: u8[..512] = [];

    // Frame 1: PADDING
    internal::encode_padding_frame(packet_wire, 1);
    // Frame 2: PING
    internal::encode_ping_frame(packet_wire);
    // Frame 3: MAX_DATA
    internal::encode_max_data_frame(packet_wire, 2000000);
    // Frame 4: STREAM (id=0, offset=0, fin=false)
    internal::encode_stream_frame(packet_wire, 0, 0, "demux-part-1", internal::QuicStreamFlags { fin: false, with_len: true });
    // Frame 5: STOP_SENDING (id=4, err=0x99)
    internal::encode_stop_sending_frame(packet_wire, 4, 0x99);
    // Frame 6: STREAM (id=0, offset=12, fin=true)
    internal::encode_stream_frame(packet_wire, 0, 12, "-part-2", internal::QuicStreamFlags { fin: true, with_len: true });

    // Iteratively demux packet frames using zero-alloc slice cursor
    var p_cur: i64 = 0;

    // 1. PADDING
    let f1, ok1 = internal::decode_quic_frame_cursor(packet_wire[..], p_cur);
    t.assert_true(ok1, "demux f1 padding ok");
    t.assert_eq(f1.raw_type, rfc::QUIC_FRAME_PADDING, "f1 is padding");

    // 2. PING
    let f2, ok2 = internal::decode_quic_frame_cursor(packet_wire[..], p_cur);
    t.assert_true(ok2, "demux f2 ping ok");
    t.assert_eq(f2.raw_type, rfc::QUIC_FRAME_PING, "f2 is ping");

    // 3. MAX_DATA
    let f3, ok3 = internal::decode_quic_frame_cursor(packet_wire[..], p_cur);
    t.assert_true(ok3, "demux f3 max_data ok");
    t.assert_eq(f3.raw_type, rfc::QUIC_FRAME_MAX_DATA, "f3 is max_data");
    t.assert_eq(f3.max_data, 2000000, "f3 limit matches");

    // 4. STREAM part 1
    let f4, ok4 = internal::decode_quic_frame_cursor(packet_wire[..], p_cur);
    t.assert_true(ok4, "demux f4 stream ok");
    t.assert_eq(f4.stream_id, 0, "f4 stream_id is 0");
    t.assert_eq(f4.payload, "demux-part-1", "f4 payload matches");
    t.assert_false(f4.fin, "f4 fin is false");

    // 5. STOP_SENDING
    let f5, ok5 = internal::decode_quic_frame_cursor(packet_wire[..], p_cur);
    t.assert_true(ok5, "demux f5 stop_sending ok");
    t.assert_eq(f5.stream_id, 4, "f5 stream_id is 4");
    t.assert_eq(f5.error_code, 0x99, "f5 err code matches");

    // 6. STREAM part 2 with FIN
    let f6, ok6 = internal::decode_quic_frame_cursor(packet_wire[..], p_cur);
    t.assert_true(ok6, "demux f6 stream fin ok");
    t.assert_eq(f6.stream_id, 0, "f6 stream_id is 0");
    t.assert_eq(f6.offset, 12, "f6 offset is 12");
    t.assert_eq(f6.payload, "-part-2", "f6 payload matches");
    t.assert_true(f6.fin, "f6 fin is true");

    // Reached end of datagram
    t.assert_eq(p_cur, packet_wire.len, "slice cursor reached end of packet");

    // Test offset-based decode_quic_frame API
    var off: u64 = 0;
    let frame_from_off, next_off, ok_off = internal::decode_quic_frame(packet_wire[..], off);
    t.assert_true(ok_off, "decode from offset 0 ok");
    t.assert_eq(frame_from_off.raw_type, rfc::QUIC_FRAME_PADDING, "offset 0 is padding");
    t.assert_eq(next_off, 1, "next offset is 1");
}

fn test_quic_stream_state_machine_send(t: lit::T&) {
    var s = internal::new_quic_stream(0, 10000); // Bidi client stream, max recv 10000
    s.send_max_data = 5000;

    t.assert_eq(s.send_state, internal::QuicSendState.Ready, "initial state is ready");

    // 1. Ready -> Send: send first data fragment
    let ok1, err1 = internal::quic_stream_on_send_data(s, 0, 1000, false);
    t.assert_true(ok1, "send 1000 bytes ok");
    t.assert_eq(err1, rfc::QUIC_ERR_NO_ERROR, "no error");
    t.assert_eq(s.send_state, internal::QuicSendState.Send, "state is Send");
    t.assert_eq(s.bytes_sent, 1000, "bytes sent is 1000");

    // 2. Flow control violation: send beyond send_max_data (5000)
    let ok_fc, err_fc = internal::quic_stream_on_send_data(s, 4500, 1000, false); // 5500 > 5000
    t.assert_false(ok_fc, "sending beyond max_stream_data fails");
    t.assert_eq(err_fc, rfc::QUIC_ERR_FLOW_CONTROL, "error is flow control");

    // 3. Send -> DataSent: send FIN
    let ok2, err2 = internal::quic_stream_on_send_data(s, 1000, 500, true);
    t.assert_true(ok2, "send fin fragment ok");
    t.assert_eq(s.send_state, internal::QuicSendState.DataSent, "state is DataSent");
    t.assert_true(s.has_send_final_size, "has final size");
    t.assert_eq(s.send_final_size, 1500, "final size is 1500");

    // 4. DataSent -> DataRecvd (peer acknowledged all data)
    let ack_ok = internal::quic_stream_on_send_ack(s, true);
    t.assert_true(ack_ok, "ack all data accepted");
    t.assert_eq(s.send_state, internal::QuicSendState.DataRecvd, "state is DataRecvd (terminal)");
    t.assert_true(internal::quic_stream_is_send_closed(s), "sender is closed");

    // 5. Reset sending path
    var s2 = internal::new_quic_stream(4, 10000);
    let ok_rst, _ = internal::quic_stream_on_send_reset(s2, 0x404, 300);
    t.assert_true(ok_rst, "send reset ok");
    t.assert_eq(s2.send_state, internal::QuicSendState.ResetSent, "state is ResetSent");
    t.assert_eq(s2.send_error_code, 0x404, "error code is 0x404");

    let ok_rst_ack = internal::quic_stream_on_send_ack(s2, false);
    t.assert_true(ok_rst_ack, "ack reset accepted");
    t.assert_eq(s2.send_state, internal::QuicSendState.ResetRecvd, "state is ResetRecvd (terminal)");
    t.assert_true(internal::quic_stream_is_send_closed(s2), "sender is closed");
}

fn test_quic_stream_state_machine_recv(t: lit::T&) {
    var s = internal::new_quic_stream(0, 10000); // Recv limit = 10000
    t.assert_eq(s.recv_state, internal::QuicRecvState.Receive, "initial state is Receive");

    // 1. Receive data fragment [0, 500)
    let ok1, err1 = internal::quic_stream_on_recv_stream_frame(s, 0, 500, false);
    t.assert_true(ok1, "recv 500 bytes ok");
    t.assert_eq(err1, rfc::QUIC_ERR_NO_ERROR, "no error");
    t.assert_eq(s.bytes_recv, 500, "bytes_recv is 500");

    // 2. Receive FIN fragment [500, 1000)
    let ok2, err2 = internal::quic_stream_on_recv_stream_frame(s, 500, 500, true);
    t.assert_true(ok2, "recv fin fragment ok");
    t.assert_true(s.has_recv_final_size, "final size known");
    t.assert_eq(s.recv_final_size, 1000, "final size is 1000");
    t.assert_eq(s.recv_state, internal::QuicRecvState.DataRecvd, "state is DataRecvd");

    // 3. Final size violation (RFC 9000 §4.5): frame exceeding declared final size
    let ok_bad_fs, err_bad_fs = internal::quic_stream_on_recv_stream_frame(s, 1000, 10, false);
    t.assert_false(ok_bad_fs, "data exceeding final size rejected");
    t.assert_eq(err_bad_fs, rfc::QUIC_ERR_FINAL_SIZE, "error is FINAL_SIZE_ERROR");

    // 4. Application reads all data -> transitions to DataRead
    internal::quic_stream_on_app_read(s, 1000);
    t.assert_eq(s.recv_state, internal::QuicRecvState.DataRead, "state is DataRead (terminal)");
    t.assert_true(internal::quic_stream_is_recv_closed(s), "recv is closed");

    // 5. RFC 9000 §3.2: RESET_STREAM arriving after DataRecvd / DataRead is ignored
    let ok_rst_ign, err_rst_ign = internal::quic_stream_on_recv_reset(s, 0x123, 1000);
    t.assert_true(ok_rst_ign, "reset on DataRead ignored");
    t.assert_eq(err_rst_ign, rfc::QUIC_ERR_NO_ERROR, "no error");
    t.assert_eq(s.recv_state, internal::QuicRecvState.DataRead, "state remains DataRead");

    // 5b. RFC 9000 §3.2: Duplicate RESET_STREAM arriving on ResetRead state MUST NOT reopen stream
    var s_rst = internal::new_quic_stream(0, 10000);
    let ok_r1, _ = internal::quic_stream_on_recv_reset(s_rst, 0x123, 500);
    t.assert_true(ok_r1, "first reset stream accepted");
    t.assert_eq(s_rst.recv_state, internal::QuicRecvState.ResetRecvd, "state is ResetRecvd");
    internal::quic_stream_on_app_read_reset(s_rst);
    t.assert_eq(s_rst.recv_state, internal::QuicRecvState.ResetRead, "state is ResetRead (terminal)");
    t.assert_true(internal::quic_stream_is_recv_closed(s_rst), "recv is closed");
    let ok_r2, err_r2 = internal::quic_stream_on_recv_reset(s_rst, 0x123, 500);
    t.assert_true(ok_r2, "duplicate reset stream accepted without error");
    t.assert_eq(err_r2, rfc::QUIC_ERR_NO_ERROR, "no error on duplicate reset");
    t.assert_eq(s_rst.recv_state, internal::QuicRecvState.ResetRead, "stream remains ResetRead, does NOT reopen");
    t.assert_true(internal::quic_stream_is_recv_closed(s_rst), "stream remains closed");

    // 6. Receiving STOP_SENDING on send-capable stream
    var s_bidi = internal::new_quic_stream(0, 10000);
    let ok_ss, _ = internal::quic_stream_on_recv_stop_sending(s_bidi, 0x55, internal::QuicRole.Server);
    t.assert_true(ok_ss, "stop sending accepted on bidi stream");
    t.assert_eq(s_bidi.send_state, internal::QuicSendState.ResetSent, "sender transitioned to ResetSent");

    // 7. RFC 9000 §19.5: Receiving STOP_SENDING on receive-only stream -> STREAM_STATE_ERROR
    // Stream ID 2 is ClientUni: Server can ONLY receive on stream 2, cannot send!
    var s_uni = internal::new_quic_stream(2, 10000);
    let ok_ss_bad, err_ss_bad = internal::quic_stream_on_recv_stop_sending(s_uni, 0x55, internal::QuicRole.Server);
    t.assert_false(ok_ss_bad, "stop sending on receive-only stream rejected");
    t.assert_eq(err_ss_bad, rfc::QUIC_ERR_STREAM_STATE, "error is STREAM_STATE_ERROR");
}

fn test_quic_stream_table(t: lit::T&) {
    var tbl = internal::new_quic_stream_table(internal::QuicRole.Client);

    // Open first local client bidi stream (ID 0)
    let id0, idx0, ok0 = internal::quic_table_open_local_stream(tbl, true);
    t.assert_true(ok0, "open client bidi stream 0 ok");
    t.assert_eq(id0, 0, "first client bidi stream id is 0");
    t.assert_eq(idx0, 0, "index is 0");

    // Open second local client bidi stream (ID 4)
    let id4, idx4, ok4 = internal::quic_table_open_local_stream(tbl, true);
    t.assert_true(ok4, "open client bidi stream 4 ok");
    t.assert_eq(id4, 4, "second client bidi stream id is 4");
    t.assert_eq(idx4, 1, "index is 1");

    // Open client unidirectional stream (ID 2)
    let id2, idx2, ok2 = internal::quic_table_open_local_stream(tbl, false);
    t.assert_true(ok2, "open client uni stream 2 ok");
    t.assert_eq(id2, 2, "first client uni stream id is 2");
    t.assert_eq(idx2, 2, "index is 2");

    // Lookup existing stream
    let found0 = internal::quic_table_find_stream(tbl, 0);
    t.assert_eq(found0, 0, "found stream 0 at index 0");
    let found4 = internal::quic_table_find_stream(tbl, 4);
    t.assert_eq(found4, 1, "found stream 4 at index 1");

    // Peer stream opening (Server bidi stream ID 1)
    let idx_peer, ok_peer = internal::quic_table_get_or_open_stream(tbl, 1);
    t.assert_true(ok_peer, "open peer stream id 1 ok");
    t.assert_eq(idx_peer, 3, "peer stream added at index 3");
    t.assert_eq(tbl.streams.len, 4, "table has 4 streams");
}

// --- Component: quic_flow_control ---
// QUIC Flow Control & RFC 9000 Hardening Test Suite.
// Covers connection-level MAX_DATA, stream-level MAX_STREAM_DATA, credit exhaustion,
// monotonic updates, FLOW_CONTROL_ERROR violations, RESET_STREAM accounting,
// auto-window update thresholds, Appendix A packet number reconstruction,
// and QuicConnection inbound frame demuxing.

fn test_connection_flow_control_budget(t: lit::T&) {
    var fc = internal::new_quic_flow_control(1000, 65536); // Remote limit 1000
    var s0 = internal::new_quic_stream(0, 65536);
    s0.send_max_data = 10000; // Unlimited stream credit

    t.assert_eq(internal::quic_fc_remaining_conn_credit(fc), 1000, "initial conn credit 1000");

    // Send 600 bytes on stream 0
    let can_send1, blk_s1, blk_c1 = internal::quic_fc_can_send(fc, s0, 0, 600);
    t.assert_true(can_send1, "can send 600 bytes");
    t.assert_false(blk_s1, "not blocked on stream");
    t.assert_false(blk_c1, "not blocked on conn");

    let ok_send1 = internal::quic_fc_record_send(fc, s0, 0, 600);
    t.assert_true(ok_send1, "record send 600 ok");
    t.assert_eq(fc.bytes_sent_total, 600, "bytes_sent_total 600");
    t.assert_eq(internal::quic_fc_remaining_conn_credit(fc), 400, "conn credit remaining 400");
    t.assert_false(fc.is_data_blocked, "not blocked yet");

    // Send remaining 400 bytes on stream 4
    var s4 = internal::new_quic_stream(4, 65536);
    s4.send_max_data = 10000;

    let ok_send2 = internal::quic_fc_record_send(fc, s4, 0, 400);
    t.assert_true(ok_send2, "record send 400 on s4 ok");
    t.assert_eq(fc.bytes_sent_total, 1000, "bytes_sent_total 1000");
    t.assert_eq(internal::quic_fc_remaining_conn_credit(fc), 0, "conn credit exhausted");
    t.assert_true(fc.is_data_blocked, "marked data blocked");

    // Attempt to send 1 additional byte on stream 0
    let can_send3, blk_s3, blk_c3 = internal::quic_fc_can_send(fc, s0, 600, 1);
    t.assert_false(can_send3, "cannot send when conn credit is 0");
    t.assert_false(blk_s3, "stream has credit");
    t.assert_true(blk_c3, "blocked on conn credit");

    let ok_send3 = internal::quic_fc_record_send(fc, s0, 600, 1);
    t.assert_false(ok_send3, "record send fails when conn budget exceeded");
}

fn test_monotonic_remote_max_data(t: lit::T&) {
    var fc = internal::new_quic_flow_control(500, 65536);
    var s = internal::new_quic_stream(0, 65536);
    s.send_max_data = 5000;

    let _ = internal::quic_fc_record_send(fc, s, 0, 500);
    t.assert_true(fc.is_data_blocked, "connection is blocked at 500");

    // Non-monotonic / decreasing update MUST be rejected
    let rej_down = internal::quic_fc_update_remote_max_data(fc, 400);
    t.assert_false(rej_down, "reject lower MAX_DATA 400");
    t.assert_eq(fc.max_data_remote, 500, "limit remains 500");
    t.assert_true(fc.is_data_blocked, "remains blocked");

    // Stale identical update MUST be rejected
    let rej_same = internal::quic_fc_update_remote_max_data(fc, 500);
    t.assert_false(rej_same, "reject identical MAX_DATA 500");

    // Monotonic increase unblocks connection
    let ok_up = internal::quic_fc_update_remote_max_data(fc, 1200);
    t.assert_true(ok_up, "accept higher MAX_DATA 1200");
    t.assert_eq(fc.max_data_remote, 1200, "limit updated to 1200");
    t.assert_false(fc.is_data_blocked, "connection unblocked");
    t.assert_eq(internal::quic_fc_remaining_conn_credit(fc), 700, "remaining credit 700");

    // Sending now succeeds
    let can_send, _, _ = internal::quic_fc_can_send(fc, s, 500, 200);
    t.assert_true(can_send, "send 200 succeeds after unblocking");
}

fn test_stream_flow_control_budget(t: lit::T&) {
    var fc = internal::new_quic_flow_control(100000, 65536); // Unlimited conn credit
    var s = internal::new_quic_stream(0, 65536);
    s.send_max_data = 300; // 300 bytes stream budget

    t.assert_eq(internal::quic_fc_remaining_stream_credit(s), 300, "stream credit 300");

    // Send 200 bytes
    let ok1 = internal::quic_fc_record_send(fc, s, 0, 200);
    t.assert_true(ok1, "send 200 bytes ok");
    t.assert_eq(s.bytes_sent, 200, "stream bytes sent 200");
    t.assert_eq(internal::quic_fc_remaining_stream_credit(s), 100, "stream remaining credit 100");

    // Attempting to send 150 bytes exceeds stream budget (200 + 150 = 350 > 300)
    let can_send_excess, blk_s, blk_c = internal::quic_fc_can_send(fc, s, 200, 150);
    t.assert_false(can_send_excess, "cannot exceed stream limit");
    t.assert_true(blk_s, "blocked on stream limit");
    t.assert_false(blk_c, "connection not blocked");

    let ok_excess = internal::quic_fc_record_send(fc, s, 200, 150);
    t.assert_false(ok_excess, "record send exceeds stream budget fails");

    // Receive MAX_STREAM_DATA increasing limit to 800
    let ok_update = internal::quic_fc_update_stream_send_max_data(s, 800);
    t.assert_true(ok_update, "stream limit updated to 800");
    t.assert_eq(s.send_max_data, 800, "s.send_max_data is 800");
    t.assert_eq(internal::quic_fc_remaining_stream_credit(s), 600, "stream credit now 600");

    // Now sending 150 bytes succeeds
    let ok2 = internal::quic_fc_record_send(fc, s, 200, 150);
    t.assert_true(ok2, "send 150 succeeds after MAX_STREAM_DATA");
    t.assert_eq(s.bytes_sent, 350, "stream bytes sent 350");
}

fn test_ingress_flow_control_and_errors(t: lit::T&) {
    var fc = internal::new_quic_flow_control(10000, 1000); // Local conn limit 1000
    var s = internal::new_quic_stream(0, 500); // Local stream limit 500

    // Ingress 400 bytes at offset 0
    let ok1, err1 = internal::quic_fc_record_recv_stream(fc, s, 0, 400);
    t.assert_true(ok1, "recv 400 bytes ok");
    t.assert_eq(err1, rfc::QUIC_ERR_NO_ERROR, "no error");
    t.assert_eq(s.bytes_recv, 400, "stream bytes_recv 400");
    t.assert_eq(fc.bytes_recv_total, 400, "conn bytes_recv_total 400");

    // Re-transmission / duplicate interval (offset 100, len 100) MUST NOT inflate conn total
    let ok_dup, _ = internal::quic_fc_record_recv_stream(fc, s, 100, 100);
    t.assert_true(ok_dup, "duplicate interval accepted");
    t.assert_eq(s.bytes_recv, 400, "bytes_recv still 400");
    t.assert_eq(fc.bytes_recv_total, 400, "conn total not inflated by retransmission");

    // Ingress exceeding stream limit (offset 400, len 150 -> end 550 > 500)
    let ok_stream_violation, err_stream_violation = internal::quic_fc_record_recv_stream(fc, s, 400, 150);
    t.assert_false(ok_stream_violation, "stream flow control violation rejected");
    t.assert_eq(err_stream_violation, rfc::QUIC_ERR_FLOW_CONTROL, "returns FLOW_CONTROL_ERROR (0x03)");

    // Now test connection-level ingress violation with another stream
    var s4 = internal::new_quic_stream(4, 2000); // Large stream limit
    // Current conn total is 400. Conn limit is 1000.
    // Ingress 500 bytes on s4 -> conn total = 900 <= 1000 (ok)
    let ok2, _ = internal::quic_fc_record_recv_stream(fc, s4, 0, 500);
    t.assert_true(ok2, "recv 500 bytes on s4 ok");
    t.assert_eq(fc.bytes_recv_total, 900, "conn total 900");

    // Ingress 200 bytes on s4 -> 900 + 200 = 1100 > 1000 -> Connection FLOW_CONTROL_ERROR
    let ok_conn_violation, err_conn_violation = internal::quic_fc_record_recv_stream(fc, s4, 500, 200);
    t.assert_false(ok_conn_violation, "connection flow control violation rejected");
    t.assert_eq(err_conn_violation, rfc::QUIC_ERR_FLOW_CONTROL, "returns FLOW_CONTROL_ERROR (0x03)");
}

fn test_reset_stream_flow_control_accounting(t: lit::T&) {
    var fc = internal::new_quic_flow_control(10000, 1000);
    var s = internal::new_quic_stream(0, 800);

    // Stream had received 200 bytes
    let _ = internal::quic_fc_record_recv_stream(fc, s, 0, 200);
    t.assert_eq(fc.bytes_recv_total, 200, "conn total 200");

    // RESET_STREAM arrives with final_size = 500.
    // Additional 300 bytes committed to connection total.
    let ok_rst, err_rst = internal::quic_fc_record_recv_reset(fc, s, 500);
    t.assert_true(ok_rst, "reset final size 500 accepted");
    t.assert_eq(err_rst, rfc::QUIC_ERR_NO_ERROR, "no error");
    t.assert_eq(s.bytes_recv, 500, "stream bytes_recv set to final size 500");
    t.assert_eq(fc.bytes_recv_total, 500, "conn total advanced to 500");

    // RESET_STREAM with final size exceeding connection limit (e.g. 1200 > 1000)
    var s4 = internal::new_quic_stream(4, 2000);
    let ok_rst_exceed, err_rst_exceed = internal::quic_fc_record_recv_reset(fc, s4, 1200);
    t.assert_false(ok_rst_exceed, "reset exceeding conn limit rejected");
    t.assert_eq(err_rst_exceed, rfc::QUIC_ERR_FLOW_CONTROL, "returns FLOW_CONTROL_ERROR");
}

fn test_window_update_thresholds(t: lit::T&) {
    // Configure local window of 64KB (65536)
    var fc = internal::new_quic_flow_control(65536, 65536);
    var s = internal::new_quic_stream(0, 65536);

    // App reads 20000 bytes. Available credit: 65536 - 20000 = 45536 > 32768 (half window)
    internal::quic_fc_on_app_read(fc, s, 20000);
    let need_update1, _ = internal::quic_fc_check_conn_window_update(fc);
    t.assert_false(need_update1, "no MAX_DATA update before threshold (credit > half)");

    // App reads another 15000 bytes. Total read = 35000.
    // Available credit: 65536 - 35000 = 30536 < 32768 (credit < half window)
    internal::quic_fc_on_app_read(fc, s, 15000);
    let need_update2, new_max_data = internal::quic_fc_check_conn_window_update(fc);
    t.assert_true(need_update2, "MAX_DATA update triggered when available < half window");
    t.assert_eq(new_max_data, 100536, "new MAX_DATA is consumed (35000) + window (65536) = 100536");
    t.assert_eq(fc.max_data_local, 100536, "local max data updated");

    // Immediately checking again returns false (already advertised)
    let need_update3, _ = internal::quic_fc_check_conn_window_update(fc);
    t.assert_false(need_update3, "subsequent check does not re-trigger without more reads");

    // RFC 9000 §4.1: Received bytes trigger MAX_DATA update preventing deadlock without app reads
    var fc_rx = internal::new_quic_flow_control(65536, 65536);
    var s_rx = internal::new_quic_stream(0, 65536);
    let ok_rx, _ = internal::quic_fc_record_recv_stream(fc_rx, s_rx, 0, 35000);
    t.assert_true(ok_rx, "record receive 35000 bytes ok");
    let need_update_rx, new_max_rx = internal::quic_fc_check_conn_window_update(fc_rx);
    t.assert_true(need_update_rx, "MAX_DATA update triggered by received bytes preventing deadlock");
    t.assert_eq(new_max_rx, 100536, "new MAX_DATA calculated from received bytes (35000 + 65536)");

    // Stream window update threshold test
    var s_up = internal::new_quic_stream(0, 1000);
    s_up.recv_consumed = 600; // Read 600 bytes out of 1000. Available = 400 < 500 (half)
    let s_need, s_new_limit = internal::quic_fc_check_stream_window_update(s_up, 1000);
    t.assert_true(s_need, "MAX_STREAM_DATA triggered");
    t.assert_eq(s_new_limit, 1600, "new stream limit is 600 + 1000 = 1600");
}

fn test_rfc9000_packet_number_decoding(t: lit::T&) {
    // Vector 1 from RFC 9000 Appendix A:
    // largest_pn = 0xABE8B, truncated_pn = 0xACEB, pn_nbits = 16 (2 bytes)
    // expected reconstructed PN = 0x0AACEB (699627)
    let pn1 = internal::decode_packet_number(0xABE8B, 0xACEB, 2);
    t.assert_eq(pn1, 0x0AACEB, "RFC 9000 Appendix A Vector 1 decoded correctly");

    let pn1_chk, ok1 = internal::decode_packet_number_checked(0xABE8B, 0xACEB, 2);
    t.assert_true(ok1, "checked decode vector 1 ok");
    t.assert_eq(pn1_chk, 0x0AACEB, "checked decode vector 1 matches");

    // 1-byte packet number (8 bits, window 256):
    // largest_pn = 100, truncated = 105 -> 105
    let pn_1b = internal::decode_packet_number(100, 105, 1);
    t.assert_eq(pn_1b, 105, "1-byte PN near largest");

    // 1-byte wrapping around window:
    // largest_pn = 250, truncated = 5 -> candidate = 250 - 250 + 5 = 5.
    // candidate + 256 = 261. Diff |261 - 250| = 11 < |5 - 250| = 245.
    // Decoded PN = 261!
    let pn_wrap = internal::decode_packet_number(250, 5, 1);
    t.assert_eq(pn_wrap, 261, "1-byte PN wrapping around 256");

    // 3-byte packet number (24 bits, window 0x1000000):
    let pn_3b = internal::decode_packet_number(0x1000000, 0x000010, 3);
    t.assert_eq(pn_3b, 0x1000010, "3-byte PN window reconstruction");

    // 4-byte packet number (32 bits, window 0x100000000):
    let pn_4b = internal::decode_packet_number(0x200000000, 0x00000005, 4);
    t.assert_eq(pn_4b, 0x200000005, "4-byte PN window reconstruction");

    // Invalid length (0 or > 4) MUST fail in checked version
    let _, ok_inv0 = internal::decode_packet_number_checked(100, 10, 0);
    t.assert_false(ok_inv0, "0-byte length rejected");

    let _, ok_inv5 = internal::decode_packet_number_checked(100, 10, 5);
    t.assert_false(ok_inv5, "5-byte length rejected");
}

fn test_connection_datagram_demuxing(t: lit::T&) {
    let scid: u8[4] = [0x01, 0x02, 0x03, 0x04];
    var conn = internal::new_quic_server_connection(scid[..]);

    // Construct a synthetic 1-RTT packet:
    // Byte 0: 0x40 (Short header, 1-RTT, 1-byte PN)
    // Bytes 1..4: DCID (same as conn.scid)
    // Byte 5: Packet Number (0x01)
    // Bytes 6..: STREAM frame (Type 0x08 = OFF=0, LEN=0, FIN=0), Stream ID = 0, Payload = "WING"
    var dgram: u8[..128] = [];
    dgram.push(0x40); // Short header
    dgram.append(scid[..]); // 4-byte DCID
    dgram.push(0x01); // PN = 1

    // Encode STREAM frame into dgram: Stream ID 0 (Client Bidi), offset 0, len 4, fin false
    let ok_enc = internal::encode_stream_frame(dgram, 0, 0, "WING", internal::QuicStreamFlags { fin: true, with_len: false });
    t.assert_true(ok_enc, "stream frame encoded into datagram");

    var out_ack = internal::AckFrame { .. };
    let handled, needs_ack = internal::quic_conn_process_datagram(conn, dgram[..], 1000, out_ack);
    t.assert_true(handled, "datagram handled successfully");
    t.assert_true(needs_ack, "STREAM frame is ack-eliciting, needs_ack is true");

    // Verify stream state in connection
    t.assert_eq(conn.stream_table.streams.len, 1, "stream table has 1 stream");
    t.assert_eq(conn.stream_table.streams[0].stream_id, 0, "stream 0 registered");
    t.assert_eq(conn.stream_table.streams[0].bytes_recv, 4, "stream 0 received 4 bytes");
    t.assert_eq(conn.flow_ctrl.bytes_recv_total, 4, "flow control recorded 4 bytes received");

    // Now test connection-level ingress violation with exceeding payload
    let scid2: u8[4] = [0x05, 0x06, 0x07, 0x08];
    var conn2 = internal::new_quic_server_connection(scid2[..]);
    conn2.flow_ctrl.max_data_local = 10; // Low limit

    var dgram2: u8[..128] = [];
    dgram2.push(0x40);
    dgram2.append(scid2[..]);
    dgram2.push(0x02);

    let _ = internal::encode_stream_frame(
        dgram2, 0, 0, "0123456789ABCDEFGHIJ",
        internal::QuicStreamFlags { fin: true, with_len: false },
    ); // 20 bytes > 10

    var out_ack2 = internal::AckFrame { .. };
    let handled2, _ = internal::quic_conn_process_datagram(conn2, dgram2[..], 2000, out_ack2);
    t.assert_false(handled2, "violating datagram returns handled=false");
    t.assert_eq(conn2.state, internal::QuicConnState.Closing, "connection transitioned to Closing");
    t.assert_eq(conn2.close_code, rfc::QUIC_ERR_FLOW_CONTROL, "closed with FLOW_CONTROL_ERROR (0x03)");
}

// --- Component: quic_ack_invariants ---
// Security invariant tests for QUIC Transport (RFC 9000, RFC 9002):
// 1. ACK Frame encoding, decoding, and RFC 9000 §19.3.1 underflow defense.
// 2. Optimistic ACK (OACK) attack prevention.
// 3. QUIC packet header fixed and reserved bits validation.

fn test_quic_ack_frame_decoding_invariants(t: lit::T&) {
    // 1. Valid ACK Frame
    var ack = internal::AckFrame {
        is_ecn:          false,
        largest_acked:   100,
        ack_delay:       25,
        first_ack_range: 10,
        ..
    };
    var wire: u8[..64] = [];
    t.assert_true(internal::encode_ack_frame(wire, ack), "encode ack frame");

    let dec_ack, read_len, ok = internal::decode_ack_frame(wire[..], 0);
    t.assert_true(ok, "decode valid ack frame");
    t.assert_eq(dec_ack.largest_acked, 100, "largest acked matches");
    t.assert_eq(dec_ack.first_ack_range, 10, "first range matches");
    t.assert_eq(dec_ack.ack_delay, 25, "delay matches");

    // 2. RFC 9000 §19.3.1: Largest Acknowledged < First ACK Range must be rejected
    // Type 0x02, Largest Acked = 5, Delay = 0, Range Count = 0, First Range = 10
    let bad_wire: const u8[5] = [0x02, 0x05, 0x00, 0x00, 0x0A];
    let _, _, bad_ok = internal::decode_ack_frame(bad_wire[..], 0);
    t.assert_false(bad_ok, "largest_acked < first_ack_range must be rejected");

    // 3. Range gap underflow: subsequent range underflows packet number space
    // Type 0x02, Largest = 10, Delay = 0, Range Count = 1, First Range = 5 (smallest = 5),
    // Gap = 10 (needs 5 - 10 - 2, underflow!)
    let bad_gap_wire: const u8[7] = [0x02, 0x0A, 0x00, 0x01, 0x05, 0x0A, 0x01];
    let _, _, bad_gap_ok = internal::decode_ack_frame(bad_gap_wire[..], 0);
    t.assert_false(bad_gap_ok, "range gap underflowing PN space must be rejected");
}

fn test_quic_oack_defense(t: lit::T&) {
    var space = internal::PnSpaceState {
        has_sent_packets: true,
        largest_sent_pn:  50,
        ..
    };

    // Forward-dated ACK (largest_acked = 60 > largest_sent_pn = 50)
    var fwd_ack = internal::AckFrame {
        largest_acked:   60,
        first_ack_range: 0,
        ..
    };
    var intervals: internal::AckInterval[..64] = [];
    let ok_fwd = internal::parse_and_validate_ack(space, fwd_ack, intervals);
    t.assert_false(ok_fwd, "OACK forward-dated packet number must be rejected");

    // Valid ACK within sent range
    var valid_ack = internal::AckFrame {
        largest_acked:   50,
        first_ack_range: 5,
        ..
    };
    let ok_valid = internal::parse_and_validate_ack(space, valid_ack, intervals);
    t.assert_true(ok_valid, "valid ack within sent range passes");
    t.assert_eq(intervals.len, 1, "1 interval extracted");
    t.assert_eq(intervals[0].smallest, 45, "smallest is 45");
    t.assert_eq(intervals[0].largest, 50, "largest is 50");
}

fn test_quic_header_security_bits(t: lit::T&) {
    // 1. Long Header Fixed Bit (0x40) check: byte 0 = 0x80 (Long=1, Fixed=0)
    let bad_fixed_long: const u8[12] = [0x80, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let _, ok_fixed = internal::parse_quic_header(bad_fixed_long[..]);
    t.assert_false(ok_fixed, "long header with fixed bit cleared must be rejected");

    // 2. Long Header Initial Reserved Bits (0x0C) check: byte 0 = 0xC4 (Reserved bit set)
    let bad_res_long: const u8[12] = [0xC4, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let _, ok_res = internal::parse_quic_header(bad_res_long[..]);
    t.assert_false(ok_res, "long header with reserved bits set must be rejected");

    // 3. Short Header Fixed Bit (0x40) check: byte 0 = 0x00 (Fixed=0)
    let bad_fixed_short: const u8[8] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    let _, ok_short_fix = internal::parse_quic_header(bad_fixed_short[..], 4);
    t.assert_false(ok_short_fix, "short header with fixed bit cleared must be rejected");

    // 4. Short Header Reserved Bits (0x18) check: byte 0 = 0x58 (Fixed=1, Reserved bit 4 set)
    let bad_res_short: const u8[8] = [0x58, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    let _, ok_short_res = internal::parse_quic_header(bad_res_short[..], 4);
    t.assert_false(ok_short_res, "short header with reserved bits set must be rejected");
}

// RFC 9000 Section 19.17: PATH_CHALLENGE Frames - 8-byte payload test
// RFC 9000 Section 19.18: PATH_RESPONSE Frames - 8-byte payload test
fn test_quic_path_frames(t: lit::T&) {
    t.run("PATH-01: PATH_CHALLENGE frame serialization and parsing") { sub =>
        let challenge_token: u8[8] = [1, 2, 3, 4, 5, 6, 7, 8];
        var out_wire: u8[>..] = [];
        let enc_ok = internal::encode_path_challenge_frame(out_wire, challenge_token);
        sub.assert_true(enc_ok, "encode_path_challenge_frame succeeded");
        sub.assert_eq(out_wire.len, 9, "wire buffer has 9 bytes (1 type + 8 payload)");
        sub.assert_eq(out_wire[0], 0x1A as u8, "frame type byte is 0x1A");

        var idx: i64 = 1;
        let decoded, dec_ok = internal::decode_path_challenge_frame(out_wire[..], idx);
        sub.assert_true(dec_ok, "decode_path_challenge_frame succeeded");
        sub.assert_eq(idx, 9, "cursor advanced to end of frame (9)");
        for i in 8 {
            sub.assert_eq(decoded.data[i], challenge_token[i], "challenge data byte matched");
        }
    };

    t.run("PATH-02: PATH_RESPONSE frame serialization and parsing") { sub =>
        let response_token: u8[8] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22];
        var out_wire: u8[>..] = [];
        let enc_ok = internal::encode_path_response_frame(out_wire, response_token);
        sub.assert_true(enc_ok, "encode_path_response_frame succeeded");
        sub.assert_eq(out_wire.len, 9, "wire buffer has 9 bytes (1 type + 8 payload)");
        sub.assert_eq(out_wire[0], 0x1B as u8, "frame type byte is 0x1B");

        var idx: i64 = 1;
        let decoded, dec_ok = internal::decode_path_response_frame(out_wire[..], idx);
        sub.assert_true(dec_ok, "decode_path_response_frame succeeded");
        sub.assert_eq(idx, 9, "cursor advanced to end of frame (9)");
        for i in 8 {
            sub.assert_eq(decoded.data[i], response_token[i], "response data byte matched");
        }
    };

    t.run("PATH-03: Unified QUIC frame demuxer dispatches PATH frames") { sub =>
        let token: u8[8] = [10, 20, 30, 40, 50, 60, 70, 80];
        var wire: u8[>..] = [];
        internal::encode_path_challenge_frame(wire, token);
        internal::encode_path_response_frame(wire, token);

        let f1, next_off1, ok1 = internal::decode_quic_frame(wire[..], 0);
        sub.assert_true(ok1, "demuxed PATH_CHALLENGE frame");
        sub.assert_true(f1.frame_type == internal::QuicFrameType.PathChallenge, "type is PathChallenge");
        sub.assert_eq(f1.length, 8, "length is 8");
        sub.assert_eq(next_off1, 9, "next offset is 9");

        let f2, next_off2, ok2 = internal::decode_quic_frame(wire[..], next_off1);
        sub.assert_true(ok2, "demuxed PATH_RESPONSE frame");
        sub.assert_true(f2.frame_type == internal::QuicFrameType.PathResponse, "type is PathResponse");
        sub.assert_eq(f2.length, 8, "length is 8");
        sub.assert_eq(next_off2, 18, "next offset is 18");
    };

    t.run("PATH-04: Truncated PATH payload rejection") { sub =>
        let truncated: u8[5] = [0x1A, 1, 2, 3, 4];
        var idx: i64 = 1;
        let _, ok = internal::decode_path_challenge_frame(truncated[..], idx);
        sub.assert_false(ok, "truncated PATH_CHALLENGE payload rejected");
    };
}

// RFC 9000 Section 9: Connection Migration - State machine test
// RFC 9000 Section 8.2: Path Validation - Token verification and anti-amplification
fn test_connection_migration(t: lit::T&) {
    t.run("MIG-01: Path validation lifecycle (Initiated -> Validating -> Validated)") { sub =>
        let initial_addr = internal::new_quic_endpoint_addr("198.51.100.1", 4433);
        var mgr = internal::new_quic_migration_manager(initial_addr);

        let active_addr = mgr.active_path.remote_addr;
        sub.assert_eq(active_addr.port, 4433, "initial port is 4433");
        sub.assert_true(internal::quic_endpoint_addr_eq(active_addr, initial_addr), "initial addr matched");

        var seed: u64 = 0xDEADBEEFCAFE;
        let token = internal::generate_path_challenge_token(seed);

        let new_addr = internal::new_quic_endpoint_addr("203.0.113.50", 9000);
        internal::quic_migration_start_probing(mgr, new_addr, token);
        sub.assert_true(mgr.has_probing_path, "probing path active");
        sub.assert_true(mgr.probing_path.state == internal::PathValidationState.Validating, "state is Validating");

        // Response mismatch: must reject and stay Validating
        let wrong_token: u8[8] = [0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8];
        let rej_ok = internal::quic_migration_on_path_response(mgr, wrong_token[..]);
        sub.assert_false(rej_ok, "mismatched response token rejected");
        sub.assert_true(mgr.probing_path.state == internal::PathValidationState.Validating, "still Validating");

        // Response match: succeeds and transitions to Validated
        let match_ok = internal::quic_migration_on_path_response(mgr, token[..]);
        sub.assert_true(match_ok, "matching response token accepted");
        sub.assert_true(mgr.probing_path.state == internal::PathValidationState.Validated, "state is Validated");

        // Migration completion: moves active path to new address
        let mig_ok = internal::quic_migration_complete(mgr);
        sub.assert_true(mig_ok, "migration completed successfully");
        sub.assert_false(mgr.has_probing_path, "probing path cleared");

        let current_addr = mgr.active_path.remote_addr;
        sub.assert_true(internal::quic_endpoint_addr_eq(current_addr, new_addr), "active address updated to new endpoint");
    };

    t.run("MIG-02: Anti-amplification 3x limit on unvalidated paths") { sub =>
        let addr = internal::new_quic_endpoint_addr("192.0.2.1", 443);
        var mgr = internal::new_quic_migration_manager(addr);

        let token: u8[8] = [1, 2, 3, 4, 5, 6, 7, 8];
        let candidate_addr = internal::new_quic_endpoint_addr("192.0.2.200", 5000);
        internal::quic_migration_start_probing(mgr, candidate_addr, token);

        // Before receiving any bytes on candidate path: limit = 0
        sub.assert_false(internal::path_can_send(mgr.probing_path, 1), "cannot send before receiving bytes");

        // Receive 1200 bytes -> limit is 3600 bytes (3x)
        mgr.probing_path.bytes_received += 1200;
        sub.assert_true(internal::path_can_send(mgr.probing_path, 3600), "can send up to 3600 bytes");
        sub.assert_false(internal::path_can_send(mgr.probing_path, 3601), "cannot exceed 3x budget");

        // Send 2000 bytes
        mgr.probing_path.bytes_sent += 2000;
        sub.assert_true(internal::path_can_send(mgr.probing_path, 1600), "can send remaining 1600 bytes");
        sub.assert_false(internal::path_can_send(mgr.probing_path, 1601), "budget exceeded after partial send");

        // Validate path: limit is lifted completely
        let ok = internal::quic_migration_on_path_response(mgr, token[..]);
        sub.assert_true(ok, "path validated");
        sub.assert_true(internal::path_can_send(mgr.probing_path, 100000), "unlimited sending once path validated");
    };

    t.run("MIG-03: Probe retry counter exhaustion transitions to Failed") { sub =>
        let addr = internal::new_quic_endpoint_addr("192.0.2.1", 443);
        var mgr = internal::new_quic_migration_manager(addr);

        let token: u8[8] = [9, 8, 7, 6, 5, 4, 3, 2];
        let candidate = internal::new_quic_endpoint_addr("192.0.2.99", 6000);
        internal::quic_migration_start_probing(mgr, candidate, token);

        sub.assert_true(internal::quic_migration_retry_probe(mgr), "retry 1 succeeded");
        sub.assert_true(internal::quic_migration_retry_probe(mgr), "retry 2 succeeded");
        sub.assert_false(internal::quic_migration_retry_probe(mgr), "retry 3 exhausted (max 3)");
        sub.assert_false(mgr.has_probing_path, "probing path removed after failure");
    };

    t.run("MIG-04: Constant-time token verification") { sub =>
        let tok_a: u8[8] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let tok_b: u8[8] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let tok_c: u8[8] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x89];

        sub.assert_true(internal::verify_path_response_token(tok_a, tok_b[..]), "identical tokens match");
        sub.assert_false(internal::verify_path_response_token(tok_a, tok_c[..]), "1-bit differing tokens mismatch");
        sub.assert_false(internal::verify_path_response_token(tok_a, tok_a[..7]), "truncated token rejected");
    };

    t.run("MIG-05: QuicConnection integrated migration and DPLPMTUD") { sub =>
        let scid: u8[4] = [0x01, 0x02, 0x03, 0x04];
        var conn = internal::new_quic_server_connection(scid[..]);
        let cand_addr = internal::new_quic_endpoint_addr("198.51.100.99", 8443);
        let token: u8[8] = [1, 2, 3, 4, 5, 6, 7, 8];

        internal::quic_conn_migrate(conn, cand_addr, token);
        sub.assert_true(conn.migration.has_probing_path, "conn migration probing path initiated");

        // Simulate incoming PathResponse frame dispatch
        let resp_frame = internal::QuicFrame {
            frame_type: internal::QuicFrameType.PathResponse,
            length:     8,
            payload:    token[..],
            ..
        };
        let ok_disp, _ = internal::dispatch_inbound_frame(conn, resp_frame);
        sub.assert_true(ok_disp, "PathResponse dispatched to connection migration");
        sub.assert_true(conn.validated_address, "connection address marked validated after migration");

        // DPLPMTUD integration on connection
        sub.assert_eq(conn.dplpmtud.current_pmtu, 1200, "initial connection PMTU is 1200");
        sub.assert_true(internal::quic_conn_on_probe_acked(conn, 1200), "conn probe 1200 acked");
        sub.assert_eq(conn.dplpmtud.current_pmtu, 1200, "PMTU verified after ack");
        sub.assert_eq(conn.dplpmtud.probed_size, 1280, "target probe size progressed to 1280");
    };
}

// RFC 8899 Section 3: Probe Packets - Padded probe generation
// RFC 8899 Section 5.1: State Machine - DPLPMTUD state transitions
fn test_dplpmtud(t: lit::T&) {
    t.run("DPL-01: Padded PING probe generation across target sizes") { sub =>
        let sizes: u32[4] = [1200, 1280, 1420, 1500];
        for sz in sizes {
            var buf: u8[>..] = [];
            let ok = internal::generate_ping_probe(buf, sz);
            sub.assert_true(ok, "generate_ping_probe succeeded");
            sub.assert_eq(buf.len as u32, sz, "probe buffer length matches target size exactly");
            sub.assert_eq(buf[0], 0x01 as u8, "first byte is PING frame (0x01)");
            sub.assert_eq(buf[buf.len - 1], 0x00 as u8, "trailing byte is PADDING frame (0x00)");
        }
    };

    t.run("DPL-02: Padded PATH_CHALLENGE probe generation across target sizes") { sub =>
        let challenge: u8[8]  = [0xCA, 0xFE, 0xBA, 0xBE, 0x01, 0x02, 0x03, 0x04];
        let sizes:     u32[4] = [1200, 1280, 1420, 1500];
        for sz in sizes {
            var buf: u8[>..] = [];
            let ok = internal::generate_path_challenge_probe(buf, challenge, sz);
            sub.assert_true(ok, "generate_path_challenge_probe succeeded");
            sub.assert_eq(buf.len as u32, sz, "probe buffer length matches target size exactly");
            sub.assert_eq(buf[0], 0x1A as u8, "first byte is PATH_CHALLENGE frame (0x1A)");
            for i in 8 {
                sub.assert_eq(buf[1 + i], challenge[i], "challenge byte in probe matched");
            }
            sub.assert_eq(buf[buf.len - 1], 0x00 as u8, "trailing byte is PADDING frame (0x00)");
        }
    };

    t.run("DPL-03: DPLPMTUD State Transitions (Base -> Search -> SearchComplete)") { sub =>
        var d = internal::Dplpmtud { .. };
        sub.assert_true(d.state == internal::DplpmtudState.Base, "initial state is Base");
        sub.assert_eq(d.current_pmtu, 1200, "initial confirmed PMTU is 1200");
        sub.assert_eq(d.probed_size, 1200, "initial target probe size is 1200");

        // Base probe 1200 acknowledged -> Transitions to Search, probes 1280
        sub.assert_true(internal::dplpmtud_on_probe_acked(d, 1200), "ack 1200 ok");
        sub.assert_true(d.state == internal::DplpmtudState.Search, "state is Search");
        sub.assert_eq(d.probed_size, 1280, "probing 1280");

        // Probe 1280 acknowledged -> probes 1420
        sub.assert_true(internal::dplpmtud_on_probe_acked(d, 1280), "ack 1280 ok");
        sub.assert_eq(d.current_pmtu, 1280, "confirmed PMTU is 1280");
        sub.assert_eq(d.probed_size, 1420, "probing 1420");

        // Probe 1420 acknowledged -> probes 1500
        sub.assert_true(internal::dplpmtud_on_probe_acked(d, 1420), "ack 1420 ok");
        sub.assert_eq(d.current_pmtu, 1420, "confirmed PMTU is 1420");
        sub.assert_eq(d.probed_size, 1500, "probing 1500");

        // Probe 1500 acknowledged -> SearchComplete (ceiling reached)
        sub.assert_true(internal::dplpmtud_on_probe_acked(d, 1500), "ack 1500 ok");
        sub.assert_true(d.state == internal::DplpmtudState.SearchComplete, "state is SearchComplete");
        sub.assert_eq(d.current_pmtu, 1500, "final confirmed PMTU is 1500");
    };

    t.run("DPL-04: Probe loss and search ceiling discovery") { sub =>
        var d = internal::Dplpmtud { .. };
        internal::dplpmtud_on_probe_acked(d, 1200); // Now in Search, probing 1280
        internal::dplpmtud_on_probe_acked(d, 1280); // Now probing 1420

        // Lose 1420 probe 3 times -> stops search, remains SearchComplete with 1280 PMTU
        sub.assert_true(internal::dplpmtud_on_probe_lost(d, 1420), "loss 1 recorded");
        sub.assert_true(internal::dplpmtud_on_probe_lost(d, 1420), "loss 2 recorded");
        sub.assert_false(internal::dplpmtud_on_probe_lost(d, 1420), "loss 3 reaches max probes");

        sub.assert_true(d.state == internal::DplpmtudState.SearchComplete, "search completed on loss");
        sub.assert_eq(d.current_pmtu, 1280, "PMTU established at last confirmed size (1280)");
    };

    t.run("DPL-05: Base probe failure leads to Error state") { sub =>
        var d = internal::Dplpmtud { .. };
        internal::dplpmtud_on_probe_lost(d, 1200);
        internal::dplpmtud_on_probe_lost(d, 1200);
        internal::dplpmtud_on_probe_lost(d, 1200);
        sub.assert_true(d.state == internal::DplpmtudState.Error, "state transitioned to Error");
    };
}

fn test_quic_cross_module_bug_fixes(t: lit::T&) {
    t.run("FIX-01: Flow Control & ResetStream field mapping (RFC 9000)") { sub =>
        let scid: u8[4] = [0x11, 0x22, 0x33, 0x44];
        var conn = internal::new_quic_server_connection(scid[..]);

        // 1. MAX_DATA datagram updates conn.flow_ctrl.max_data_remote
        var dgram_md: u8[..64] = [];
        dgram_md.push(0x40);
        dgram_md.append(scid[..]);
        dgram_md.push(0x01);
        internal::encode_max_data_frame(dgram_md, 750000);

        var ack_out = internal::AckFrame { .. };
        let handled_md, _ = internal::quic_conn_process_datagram(conn, dgram_md[..], 1000, ack_out);
        sub.assert_true(handled_md, "max_data datagram handled");
        sub.assert_eq(conn.flow_ctrl.max_data_remote, 750000, "remote max_data updated to 750000");

        // 2. Open stream 0 first
        var dgram_st: u8[..64] = [];
        dgram_st.push(0x40);
        dgram_st.append(scid[..]);
        dgram_st.push(0x02);
        internal::encode_stream_frame(dgram_st, 0, 0, "ping", internal::QuicStreamFlags { fin: false, with_len: true });
        let handled_st, _ = internal::quic_conn_process_datagram(conn, dgram_st[..], 1001, ack_out);
        sub.assert_true(handled_st, "stream 0 created");

        // 3. MAX_STREAM_DATA datagram updates stream.flow_ctrl.max_data_remote
        var dgram_msd: u8[..64] = [];
        dgram_msd.push(0x40);
        dgram_msd.append(scid[..]);
        dgram_msd.push(0x03);
        internal::encode_max_stream_data_frame(dgram_msd, 0, 350000);
        let handled_msd, _ = internal::quic_conn_process_datagram(conn, dgram_msd[..], 1002, ack_out);
        sub.assert_true(handled_msd, "max_stream_data datagram handled");
        let st_idx = internal::quic_table_find_stream(conn.stream_table, 0);
        sub.assert_true(st_idx >= 0, "found stream 0");
        sub.assert_eq(
            conn.stream_table.streams[st_idx as i64].send_max_data,
            350000,
            "stream send_max_data updated to 350000",
        );

        // 4. RESET_STREAM updates final_size and bytes_recv_total
        var dgram_rst: u8[..64] = [];
        dgram_rst.push(0x40);
        dgram_rst.append(scid[..]);
        dgram_rst.push(0x04);
        internal::encode_reset_stream_frame(dgram_rst, 0, 0x99, 1200);
        let handled_rst, _ = internal::quic_conn_process_datagram(conn, dgram_rst[..], 1003, ack_out);
        sub.assert_true(handled_rst, "reset_stream datagram handled");
        sub.assert_eq(conn.stream_table.streams[st_idx as i64].recv_final_size, 1200, "stream recv_final_size set to 1200");
        sub.assert_eq(conn.flow_ctrl.bytes_recv_total, 1200, "flow control bytes_recv_total reflects final_size");
    };

    t.run("FIX-02: Multiplexed ACK and STREAM payload processing & Frame Error") { sub =>
        let scid: u8[4] = [0x21, 0x22, 0x23, 0x24];
        var conn = internal::new_quic_server_connection(scid[..]);

        // Synthesize datagram containing ACK frame followed by STREAM frame
        var dgram: u8[..128] = [];
        dgram.push(0x40);
        dgram.append(scid[..]);
        dgram.push(0x01); // PN = 1

        let ack = internal::AckFrame {
            is_ecn:          false,
            largest_acked:   0,
            ack_delay:       5,
            first_ack_range: 0,
            ..
        };
        internal::encode_ack_frame(dgram, ack);
        internal::encode_stream_frame(dgram, 0, 0, "ACK+STREAM", internal::QuicStreamFlags { fin: true, with_len: true });

        var ack_out = internal::AckFrame { .. };
        let handled, needs_ack = internal::quic_conn_process_datagram(conn, dgram[..], 2000, ack_out);
        sub.assert_true(handled, "multiplexed ACK+STREAM datagram handled successfully");
        sub.assert_true(needs_ack, "trailing STREAM frame elicited ACK requirement");
        let idx = internal::quic_table_find_stream(conn.stream_table, 0);
        sub.assert_true(idx >= 0, "stream 0 found and populated from trailing frame");
        sub.assert_eq(conn.stream_table.streams[idx as i64].bytes_recv, 10, "stream 0 received payload after ACK");

        // Corrupt frame: truncated varint inside payload
        var bad_dgram: u8[..32] = [];
        bad_dgram.push(0x40);
        bad_dgram.append(scid[..]);
        bad_dgram.push(0x02);
        // Varint with 2-bit prefix 11 (requires 8 bytes) but only 1 byte present
        bad_dgram.push(0xC0);

        let bad_handled, _ = internal::quic_conn_process_datagram(conn, bad_dgram[..], 2001, ack_out);
        sub.assert_false(bad_handled, "corrupt frame payload rejected");
        sub.assert_true(conn.state == internal::QuicConnState.Closing, "connection moved to Closing on corrupt frame");
        sub.assert_eq(conn.close_code, rfc::QUIC_ERR_FRAME_ENCODING, "closed with FRAME_ENCODING_ERROR (0x07)");
    };

    t.run("FIX-03: Peer Stream Limit Enforcement (RFC 9000 §4.6)") { sub =>
        let scid: u8[4] = [0x31, 0x32, 0x33, 0x34];
        var conn = internal::new_quic_server_connection(scid[..]);
        conn.stream_table.max_streams_bidi = 5; // Allow streams 0, 4, 8, 12, 16 (stream_idx 0..4)

        // Stream ID 20 corresponds to stream_idx 5 -> exceeds limit 5!
        var dgram: u8[..64] = [];
        dgram.push(0x40);
        dgram.append(scid[..]);
        dgram.push(0x01);
        internal::encode_stream_frame(dgram, 20, 0, "limit-exceeded", internal::QuicStreamFlags { fin: false, with_len: true });

        var ack_out = internal::AckFrame { .. };
        let handled, _ = internal::quic_conn_process_datagram(conn, dgram[..], 3000, ack_out);
        sub.assert_false(handled, "stream ID exceeding max_streams_bidi rejected");
        sub.assert_true(conn.state == internal::QuicConnState.Closing, "connection in Closing state");
        sub.assert_eq(conn.close_code, rfc::QUIC_ERR_STREAM_LIMIT, "closed with STREAM_LIMIT_ERROR (0x04)");
    };

    t.run("FIX-04: HANDSHAKE_DONE server rejection and PATH_CHALLENGE accounting") { sub =>
        let scid: u8[4] = [0x41, 0x42, 0x43, 0x44];
        var conn = internal::new_quic_server_connection(scid[..]);

        // Server receives HANDSHAKE_DONE frame (0x1E)
        var dgram_hd: u8[..32] = [];
        dgram_hd.push(0x40);
        dgram_hd.append(scid[..]);
        dgram_hd.push(0x01);
        internal::encode_handshake_done_frame(dgram_hd);

        var ack_out = internal::AckFrame { .. };
        let handled_hd, _ = internal::quic_conn_process_datagram(conn, dgram_hd[..], 4000, ack_out);
        sub.assert_false(handled_hd, "server rejects HANDSHAKE_DONE");
        sub.assert_true(conn.state == internal::QuicConnState.Closing, "connection Closing");
        sub.assert_eq(conn.close_code, rfc::QUIC_ERR_PROTOCOL_VIOLATION, "closed with PROTOCOL_VIOLATION (0x0A)");

        // Fresh connection: PATH_CHALLENGE byte accounting
        var conn2 = internal::new_quic_server_connection(scid[..]);
        var dgram_pc: u8[..32] = [];
        dgram_pc.push(0x40);
        dgram_pc.append(scid[..]);
        dgram_pc.push(0x02);
        let challenge_data: const u8[8] = [1, 2, 3, 4, 5, 6, 7, 8];
        internal::encode_path_challenge_frame(dgram_pc, challenge_data);

        let initial_bytes = conn2.bytes_received;
        let handled_pc, _ = internal::quic_conn_process_datagram(conn2, dgram_pc[..], 4001, ack_out);
        sub.assert_true(handled_pc, "path challenge processed");
        sub.assert_eq(
            conn2.bytes_received - initial_bytes,
            dgram_pc.len as u64,
            "bytes_received incremented exactly once by datagram len",
        );
    };

    t.run("FIX-05: BBR inflight_hi clamp & CUBIC millisecond scaling") { sub =>
        var bbr = internal::new_bbr_state();
        bbr.bw_hi_bps = 800000000; // 800 Mbps -> high BDP
        bbr.min_rtt_us = 100000;    // 100 ms
        bbr.mode = internal::BbrMode.ProbeBwCruise;
        bbr.inflight_hi_bytes = 15000; // low cap
        internal::bbr_update_pacing_and_cwnd(bbr);
        sub.assert_eq(bbr.cwnd_bytes, 15000, "cwnd clamped to inflight_hi_bytes");

        // CUBIC millisecond scaling:
        // 1. Verify K precision: for w_max = 100, K = cbrt(75) s = 4217 ms (old code truncated to 4s)
        let k_ms = internal::cubic_compute_k(100);
        sub.assert_eq(k_ms, 4217, "cubic_compute_k achieves millisecond precision (exactly 4217ms)");

        // 2. Verify sub-second growth: at t = 1400ms (1.4s), delta = 1 segment
        // Old integer-seconds code stayed flat at delta = 0 until t = 2s
        var cubic = internal::CubicState { .. };
        cubic.cwnd_segments = 50;
        cubic.w_max_segments = 50;
        cubic.epoch_start_us = 1000000;
        cubic.last_update_us = 1000000;

        let cwnd_1400ms = internal::cubic_on_ack(cubic, 2400000, 50000, 60000, 1200);
        sub.assert_eq(cubic.cwnd_segments, 51, "cubic cwnd incremented by 1 segment at 1.4s");
        sub.assert_eq(cwnd_1400ms, 51 * 1200, "cubic window grew at 1.4s without waiting for 2s integer floor");
    };

    t.run("FIX-06: DPLPMTUD IP overheads and payload size calculation") { sub =>
        let p_v4 = internal::calc_dplpmtud_probe_payload_size(1500, internal::DPLPMTUD_OVERHEAD_IPV4);
        sub.assert_eq(p_v4, 1500 - internal::DPLPMTUD_OVERHEAD_IPV4, "IPv4 payload equals 1500 - 49 = 1451");

        let p_v6 = internal::calc_dplpmtud_probe_payload_size(1500, internal::DPLPMTUD_OVERHEAD_IPV6);
        sub.assert_eq(p_v6, 1500 - internal::DPLPMTUD_OVERHEAD_IPV6, "IPv6 payload equals 1500 - 69 = 1431");
    };
}

// 30. RFC 9369 QUIC Version 2
fn test_quic_version2(t: lit::T&) {
    t.run("V2-01: Version constant and initial salt (RFC 9369 §3.1, §3.3.1)") { sub =>
        sub.assert_eq(rfc::QUIC_VERSION_2, 0x6b3343cf, "QUIC_VERSION_2 is 0x6b3343cf");

        let salt_v2 = internal::quic_initial_salt(rfc::QUIC_VERSION_2);
        let salt_v1 = internal::quic_initial_salt(rfc::QUIC_VERSION_1);
        let exp_v2: u8[20] = [
            0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
            0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
        ];
        sub.assert_eq(salt_v2.len, 20, "v2 salt is 20 bytes");
        sub.assert_eq(salt_v2[..], exp_v2[..], "v2 salt matches RFC 9369 §3.3.1 bytes");
        sub.assert_eq(salt_v1.len, 20, "v1 salt is 20 bytes");
        sub.assert_false(salt_v1[..] == salt_v2[..], "v1 and v2 initial salts differ");

        let salt_bad = internal::quic_initial_salt(0x0A0A0A0A);
        sub.assert_eq(salt_bad.len, 0, "unknown version yields empty salt");
    };

    t.run("V2-02: HKDF label prefixes and HP key divergence (RFC 9369 §3.3.2)") { sub =>
        sub.assert_eq(internal::quic_hkdf_label_prefix(rfc::QUIC_VERSION_1), "quic ", "v1 prefix is 'quic '");
        sub.assert_eq(
            internal::quic_hkdf_label_prefix(rfc::QUIC_VERSION_2),
            "quicv2 ",
            "v2 prefix is 'quicv2 '",
        );
        sub.assert_eq(internal::quic_hkdf_label_prefix(0x0A0A0A0A), "", "unknown version yields empty prefix");

        // Same secret must derive different HP keys under v1 vs v2 labels.
        let secret: u8[32] = [0x42; 32];
        var hp1: u8[16] = [0; 16];
        var hp2: u8[16] = [0; 16];
        let ok1 = internal::ks_derive_quic_hp_key(
            internal::HASH_SHA256,
            secret[..],
            16,
            hp1[..],
            rfc::QUIC_VERSION_1,
        );
        let ok2 = internal::ks_derive_quic_hp_key(
            internal::HASH_SHA256,
            secret[..],
            16,
            hp2[..],
            rfc::QUIC_VERSION_2,
        );
        sub.assert_true(ok1, "v1 HP key derivation ok");
        sub.assert_true(ok2, "v2 HP key derivation ok");
        sub.assert_false(hp1[..] == hp2[..], "same secret yields different HP keys per version");
    };

    t.run("V2-03: Long header type remap (RFC 9369 §3.2)") { sub =>
        let t1, ok1 = internal::quic_long_header_type(rfc::QUIC_VERSION_1, 0);
        sub.assert_true(ok1, "v1 type bits known");
        sub.assert_eq(t1, internal::QuicHeaderType.Initial, "v1 0b00 = Initial");

        let t2, ok2 = internal::quic_long_header_type(rfc::QUIC_VERSION_2, 1);
        sub.assert_true(ok2, "v2 type bits known");
        sub.assert_eq(t2, internal::QuicHeaderType.Initial, "v2 0b01 = Initial");

        let t3, ok3 = internal::quic_long_header_type(rfc::QUIC_VERSION_2, 0);
        sub.assert_true(ok3, "v2 type bits known (Retry)");
        sub.assert_eq(t3, internal::QuicHeaderType.Retry, "v2 0b00 = Retry");

        let t4, _ = internal::quic_long_header_type(rfc::QUIC_VERSION_2, 2);
        sub.assert_eq(t4, internal::QuicHeaderType.ZeroRtt, "v2 0b10 = 0-RTT");
        let t5, _ = internal::quic_long_header_type(rfc::QUIC_VERSION_2, 3);
        sub.assert_eq(t5, internal::QuicHeaderType.Handshake, "v2 0b11 = Handshake");

        let _, ok_unk = internal::quic_long_header_type(0x0A0A0A0A, 0);
        sub.assert_false(ok_unk, "unknown version has no type mapping");
    };

    t.run("V2-04: Version Negotiation listing QUIC v2 (RFC 9369 §4)") { sub =>
        // A v2-only peer answers VN with exactly 0x6b3343cf in its supported list.
        var vn_buf: u8[..64] = [];
        vn_buf.push(0xC0);
        core::append_u32_be(vn_buf, rfc::QUIC_VERSION_NEGOTIATION);
        vn_buf.push(4);
        vn_buf.append("dcid");
        vn_buf.push(0);
        core::append_u32_be(vn_buf, rfc::QUIC_VERSION_2);

        let hdr, ok = internal::parse_quic_header(vn_buf[..], 0);
        sub.assert_true(ok, "VN packet with v2 entry parses");
        sub.assert_eq(hdr.header_type, internal::QuicHeaderType.VersionNegotiation, "type is VersionNegotiation");
        let vl = hdr.header_len as i64;
        let listed = ((vn_buf[vl] as u32) << 24) | ((vn_buf[vl + 1] as u32) << 16) |
                     ((vn_buf[vl + 2] as u32) << 8) | (vn_buf[vl + 3] as u32);
        sub.assert_eq(listed, rfc::QUIC_VERSION_2, "supported list contains 0x6b3343cf");
    };

    t.run("V2-05: v2 long header parses with remapped Initial type (RFC 9369 §3.2)") { sub =>
        // first byte 0xD1: long form, fixed bit, Type=0b01 (v2 Initial), pn_len=2
        var v2_init: u8[..64] = [];
        v2_init.push(0xD1);
        core::append_u32_be(v2_init, rfc::QUIC_VERSION_2);
        v2_init.push(4);
        v2_init.append("dcid");
        v2_init.push(0);
        v2_init.push(0);
        v2_init.push(4);
        v2_init.push(0x12);
        v2_init.push(0x34);
        v2_init.push(0xAA);
        v2_init.push(0xBB);

        let hdr, ok = internal::parse_quic_header(v2_init[..], 0);
        sub.assert_true(ok, "v2 Initial long header parses");
        sub.assert_eq(hdr.header_type, internal::QuicHeaderType.Initial, "v2 Type 0b01 decodes as Initial");
        sub.assert_eq(hdr.version, rfc::QUIC_VERSION_2, "version field is 0x6b3343cf");
    };
}

fn main() {
    var runner = lit::new_runner("QUIC Protocol, Framing, Flow Control & ACK Verification Suite", lit::Verbosity.Verbose);

    lit::run_case(runner, "1. QPACK Static Table, Dynamic Table & Codecs (RFC 9204)", test_qpack_table_and_codecs);
    lit::run_case(runner, "2. QPACK Header Accordion DoS Defenses & Post-Decode RIC", test_qpack_security_defenses);
    lit::run_case(runner, "3. QUIC VarInt Codec & Packet Framing (RFC 9000)", test_quic_varint_and_framing);
    lit::run_case(runner, "4. Header Protection & Packet Number Reconstruction (RFC 9001)", test_header_protection_and_pn);
    lit::run_case(runner, "5. Anti-Amplification 3x & Zero-Heap Reassembly (RFC 9000)", test_anti_amplification_and_reassembly);
    lit::run_case(runner, "6. ACK Framing, OACK Defense & 5-Priority PTO (RFC 9002)", test_ack_and_pto_engine);
    lit::run_case(runner, "7. BBRv2/v3, CUBIC & Pacing Engine (RFC 9438)", test_bbr_cubic_and_pacing);
    lit::run_case(runner, "8. RFC 9000 §19.8 STREAM Frame Codec", test_quic_stream_frame_codec);
    lit::run_case(runner, "9. RFC 9000 §19.6 CRYPTO Frame Codec", test_quic_crypto_frame_codec);
    lit::run_case(runner, "10. RFC 9000 §19 Control Frames Codec", test_quic_control_frames_codec);
    lit::run_case(runner, "11. RFC 9000 Zero-Alloc Frame Demuxer", test_quic_frame_demuxer);
    lit::run_case(runner, "12. RFC 9000 §3.1 Sending Stream State Machine", test_quic_stream_state_machine_send);
    lit::run_case(runner, "13. RFC 9000 §3.2 & §4.5 Receiving Stream State Machine", test_quic_stream_state_machine_recv);
    lit::run_case(runner, "14. RFC 9000 Zero-Alloc Stream Table", test_quic_stream_table);
    lit::run_case(runner, "15. Connection Flow Control Budget (RFC 9000 §4.1)", test_connection_flow_control_budget);
    lit::run_case(runner, "16. Monotonic MAX_DATA Limit Updates", test_monotonic_remote_max_data);
    lit::run_case(runner, "17. Stream Flow Control Budget (RFC 9000 §4.1)", test_stream_flow_control_budget);
    lit::run_case(runner, "18. Ingress Flow Control & FLOW_CONTROL_ERROR", test_ingress_flow_control_and_errors);
    lit::run_case(runner, "19. RESET_STREAM Final Size Accounting (RFC 9000 §4.5)", test_reset_stream_flow_control_accounting);
    lit::run_case(runner, "20. Window Update Auto-Generation (RFC 9000 §4.2)", test_window_update_thresholds);
    lit::run_case(runner, "21. RFC 9000 Appendix A Packet Number Decoding", test_rfc9000_packet_number_decoding);
    lit::run_case(runner, "22. QuicConnection Inbound Frame Demuxing", test_connection_datagram_demuxing);
    lit::run_case(runner, "23. QUIC ACK Frame Decoding Invariants", test_quic_ack_frame_decoding_invariants);
    lit::run_case(runner, "24. QUIC OACK Attack Prevention", test_quic_oack_defense);
    lit::run_case(runner, "25. QUIC Header Security Bits", test_quic_header_security_bits);
    lit::run_case(runner, "26. QUIC PATH_CHALLENGE & PATH_RESPONSE Codecs (RFC 9000)", test_quic_path_frames);
    lit::run_case(runner, "27. Connection Migration FSM & Anti-Amplification (RFC 9000)", test_connection_migration);
    lit::run_case(runner, "28. DPLPMTUD Probe Generator & State Machine (RFC 8899)", test_dplpmtud);
    lit::run_case(runner, "29. Cross-Module QUIC Integration & RFC Conformance Fixes", test_quic_cross_module_bug_fixes);
    lit::run_case(runner, "30. RFC 9369 QUIC v2", test_quic_version2);

    let ok = lit::finish(runner);
    assert(ok);
}
