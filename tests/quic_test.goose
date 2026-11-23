// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Consolidated Verification Suite: QUIC Protocol, Framing, Flow Control & ACK Verification Suite
//
// RUN: goose build -o %t.exe %s
// RUN: %t.exe
import std;
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
        let ent0, ok0 = http3::get_qpack_static_field(0);
        sub.assert_true(ok0, "static lookup index 0 ok");
        sub.assert_eq(ent0.name, ":authority", "index 0 name is :authority");
        sub.assert_eq(ent0.val, "", "index 0 value is empty");

        // Index 1: :path /
        let ent1, ok1 = http3::get_qpack_static_field(1);
        sub.assert_true(ok1, "static lookup index 1 ok");
        sub.assert_eq(ent1.name, ":path", "index 1 name is :path");
        sub.assert_eq(ent1.val, "/", "index 1 value is /");

        // Index 17: :method GET
        let ent17, ok17 = http3::get_qpack_static_field(17);
        sub.assert_true(ok17, "static lookup index 17 ok");
        sub.assert_eq(ent17.name, ":method", "index 17 name is :method");
        sub.assert_eq(ent17.val, "GET", "index 17 value is GET");

        // Index 25: :status 200
        let ent25, ok25 = http3::get_qpack_static_field(25);
        sub.assert_true(ok25, "static lookup index 25 ok");
        sub.assert_eq(ent25.name, ":status", "index 25 name is :status");
        sub.assert_eq(ent25.val, "200", "index 25 value is 200");

        // Out of bounds: index 99
        let _, ok99 = http3::get_qpack_static_field(99);
        sub.assert_false(ok99, "index 99 is out of bounds for 99-entry static table");
    };

    t.run("QPACK-02: Zero-Allocation Dynamic Table Ring Buffer & Eviction") { sub =>
        var tbl = http3::new_qpack_table(128, 16); // 128 bytes max capacity
        // Each entry size = name.len + value.len + 32
        // Entry 1: custom-header (13) + value1 (6) + 32 = 51 bytes
        let ok1 = http3::qpack_insert_literal(tbl, "custom-header", "value1");
        sub.assert_true(ok1, "insert entry 1 ok");
        sub.assert_eq(tbl.insert_count, 1, "inserted count is 1");
        sub.assert_eq(tbl.used_bytes, 51, "used 51 bytes");

        // Entry 2: custom-header (13) + value2 (6) + 32 = 51 bytes. Total = 102 <= 128
        let ok2 = http3::qpack_insert_literal(tbl, "custom-header", "value2");
        sub.assert_true(ok2, "insert entry 2 ok");
        sub.assert_eq(tbl.insert_count, 2, "inserted count is 2");
        sub.assert_eq(tbl.used_bytes, 102, "used 102 bytes");

        // Entry 3: custom-header (13) + value3 (6) + 32 = 51 bytes.
        // 102 + 51 = 153 > 128 -> Must evict entry 1 (oldest)!
        let ok3 = http3::qpack_insert_literal(tbl, "custom-header", "value3");
        sub.assert_true(ok3, "insert entry 3 ok with eviction");
        sub.assert_eq(tbl.insert_count, 3, "total inserted count is 3");
        sub.assert_eq(tbl.used_bytes, 102, "used bytes remains 102 after eviction");

        // Absolute index 0 was evicted
        let _, _, ok_evicted = http3::qpack_lookup_absolute(tbl, 0);
        sub.assert_false(ok_evicted, "evicted entry 0 cannot be looked up");

        // Absolute index 2 (latest) is active
        let _, v2, ok_act = http3::qpack_lookup_absolute(tbl, 2);
        sub.assert_true(ok_act, "active entry 2 looked up");
        sub.assert_eq(v2, "value3", "entry 2 value is value3");
    };

    t.run("QPACK-03: RIC and Delta Base Prefix Codecs") { sub =>
        // Test RIC encode/decode
        let enc_ric = http3::encode_ric(15, 128);
        let ric, err_ric = http3::decode_ric(enc_ric, 15, 128);
        sub.assert_eq(err_ric, http3::QpackError.None, "decode RIC no error");
        sub.assert_eq(ric, 15, "decoded RIC matches original");

        // Test Delta Base encode/decode
        let sign_bit, delta_base = http3::encode_base(20, 25); // base < ric -> sign = 1, delta = 4
        let base, err_base = http3::decode_base(sign_bit, delta_base, 25);
        sub.assert_eq(err_base, http3::QpackError.None, "decode base no error");
        sub.assert_eq(base, 20, "decoded base matches original");
    };
}

// 2. QPACK Header Accordion DoS Defense & Post-Decode RIC Validation
fn test_qpack_security_defenses(t: lit::T&) {
    t.run("QPACK-DOS-01: Header Accordion 32-Byte Overhead Enforcement") { sub =>
        var fields:      http3::HeaderField[>..] = [];
        var budget_left: u64                     = 100; // 100 bytes budget

        // Entry: "a": "b" -> length 2. Plus 32 overhead = 34 bytes!
        let err1 = http3::emit_field_checked(fields, budget_left, "a", "b", false);
        sub.assert_eq(err1, http3::QpackError.None, "first field accepted");
        sub.assert_eq(budget_left, 66, "budget left is 66 (100 - 34)");

        // Second entry: "c": "d" -> 34 bytes. Budget left = 32 <= 100
        let err2 = http3::emit_field_checked(fields, budget_left, "c", "d", false);
        sub.assert_eq(err2, http3::QpackError.None, "second field accepted");
        sub.assert_eq(budget_left, 32, "budget left is 32");

        // Third entry: "e": "f" -> 34 bytes. 32 < 34 -> Must reject with HeaderListTooLarge!
        let err3 = http3::emit_field_checked(fields, budget_left, "e", "f", false);
        sub.assert_eq(err3, http3::QpackError.HeaderListTooLarge, "third field rejected to prevent 33x memory amplification DoS");
    };

    t.run("QPACK-DOS-02: Post-Decode RIC Validation (RFC 9204 Section 4.5.1)") { sub =>
        var tbl = http3::new_qpack_table(4096, 16);
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

        var out_fields: http3::HeaderField[>..] = [];
        let err = http3::decode_qpack_section(tbl, malicious_block[..], out_fields, 16384);
        sub.assert_eq(err, http3::QpackError.DecompressionFailed, "malicious non-zero RIC on static-only block rejected");
    };
}

// 3. QUIC VarInt Codec & Packet Framing (RFC 9000, RFC 9001)
fn test_quic_varint_and_framing(t: lit::T&) {
    t.run("VARINT-01: 1, 2, 4, 8-Byte Boundary Roundtrips") { sub =>
        // 1-byte boundary: 0, 63
        var buf1: u8[..16] = [];
        sub.assert_true(quic::encode_varint(63, buf1), "encode 63");
        sub.assert_eq(buf1.len, 1, "63 encoded in 1 byte");
        let v1, _, ok1 = quic::decode_varint(buf1[..], 0);
        sub.assert_true(ok1, "decode 63");
        sub.assert_eq(v1, 63, "value 63 matches");

        // 2-byte boundary: 64, 16383
        var buf2: u8[..16] = [];
        sub.assert_true(quic::encode_varint(16383, buf2), "encode 16383");
        sub.assert_eq(buf2.len, 2, "16383 encoded in 2 bytes");
        let v2, _, ok2 = quic::decode_varint(buf2[..], 0);
        sub.assert_true(ok2, "decode 16383");
        sub.assert_eq(v2, 16383, "value 16383 matches");

        // 4-byte boundary: 1073741823
        var buf4: u8[..16] = [];
        sub.assert_true(quic::encode_varint(1073741823, buf4), "encode 1073741823");
        sub.assert_eq(buf4.len, 4, "1073741823 encoded in 4 bytes");
        let v4, _, ok4 = quic::decode_varint(buf4[..], 0);
        sub.assert_true(ok4, "decode 1073741823");
        sub.assert_eq(v4, 1073741823, "value 1073741823 matches");

        // 8-byte boundary: 0x3FFFFFFFFFFFFFFF
        var buf8: u8[..16] = [];
        sub.assert_true(quic::encode_varint(0x3FFFFFFFFFFFFFFF, buf8), "encode max varint");
        sub.assert_eq(buf8.len, 8, "max varint encoded in 8 bytes");
        let v8, _, ok8 = quic::decode_varint(buf8[..], 0);
        sub.assert_true(ok8, "decode max varint");
        sub.assert_eq(v8, 0x3FFFFFFFFFFFFFFF, "value max varint matches");
    };

    t.run("FRAMING-01: Long & Short Header Encode / Decode Roundtrip") { sub =>
        // Initial Header
        var orig_hdr = quic::QuicHeader {
            header_type:    quic::QuicHeaderType.Initial,
            version:        rfc::QUIC_VERSION_1,
            payload_length: 1200,
            packet_number:  42,
            ..
        };
        orig_hdr.dcid.append([1, 2, 3, 4, 5, 6, 7, 8]);
        orig_hdr.scid.append([9, 10, 11, 12]);

        var wire: u8[..128] = [];
        let ok_enc = quic::encode_header(orig_hdr, 2, wire);
        sub.assert_true(ok_enc, "encode Initial header ok");

        let parsed, ok_dec = quic::parse_header(wire[..], 0);
        sub.assert_true(ok_dec, "parse Initial header ok");
        sub.assert_eq(parsed.header_type, quic::QuicHeaderType.Initial, "header type Initial");
        sub.assert_eq(parsed.version, rfc::QUIC_VERSION_1, "version QUIC v1");
        sub.assert_eq(parsed.dcid[..], orig_hdr.dcid[..], "dcid matches");
        sub.assert_eq(parsed.scid[..], orig_hdr.scid[..], "scid matches");
        sub.assert_eq(parsed.payload_length, 1200, "payload length matches");
    };

    t.run("STREAM-01: Stream Identifier Classification (RFC 9000 Section 2.1)") { sub =>
        // Client Bidirectional: 0, 4, 8
        sub.assert_true(quic::is_client_stream(0), "stream 0 is client");
        sub.assert_true(quic::is_bidi_stream(0), "stream 0 is bidi");

        // Server Bidirectional: 1, 5, 9
        sub.assert_true(quic::is_server_stream(1), "stream 1 is server");
        sub.assert_true(quic::is_bidi_stream(1), "stream 1 is bidi");

        // Client Unidirectional: 2, 6, 10
        sub.assert_true(quic::is_client_stream(2), "stream 2 is client");
        sub.assert_true(quic::is_uni_stream(2), "stream 2 is uni");

        // Server Unidirectional: 3, 7, 11
        sub.assert_true(quic::is_server_stream(3), "stream 3 is server");
        sub.assert_true(quic::is_uni_stream(3), "stream 3 is uni");
    };

    t.run("DATAGRAM-01: RFC 9221 Unreliable Datagram Framing") { sub =>
        var buf1: u8[..64] = [];
        sub.assert_true(quic::encode_datagram_frame("telemetry-payload", buf1, true), "encode datagram with length");
        let d1, next1, ok1 = quic::decode_datagram_frame(buf1[..], 0);
        sub.assert_true(ok1, "decode datagram with length");
        sub.assert_eq(d1, "telemetry-payload", "payload matches with length");
        sub.assert_eq(next1, buf1.len as u64, "consumed all bytes");

        var buf2: u8[..64] = [];
        sub.assert_true(quic::encode_datagram_frame("raw-stream-end", buf2, false), "encode datagram without length");
        let d2, next2, ok2 = quic::decode_datagram_frame(buf2[..], 0, buf2.len as u64);
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
        let mask = quic_internal::aes128_header_protect_mask(hp_key, sample);
        let expected_mask: u8[5] = [0x43, 0x7b, 0x9a, 0xec, 0x36];
        sub.assert_eq(mask[..], expected_mask[..], "AES-128 HP mask matches RFC 9001 Appendix A.2");
    };

    t.run("HP-02: Header Protection Mask Application & In-Place Removal") { sub =>
        // Simulated 1-RTT short header with 2-byte packet number (PN = 0x1234)
        var pkt: u8[8] = [0x41, 0x12, 0x34, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
        let mask: u8[5] = [0x1A, 0x55, 0xAA, 0x00, 0x00];

        quic::apply_header_protection(pkt[..], 1, 2, mask);
        // Header first byte and PN fields are now masked
        sub.assert_true(pkt[0] != 0x41, "header first byte is masked");
        sub.assert_true(pkt[1] != 0x12, "PN byte 0 is masked");

        // Remove protection in-place
        let pn_len, trunc_pn = quic::remove_header_protection(pkt[..], 1, mask);
        sub.assert_eq(pn_len, 2, "recovered PN length is 2");
        sub.assert_eq(trunc_pn, 0x1234, "recovered truncated PN is 0x1234");
        sub.assert_eq(pkt[0], 0x41, "first byte unmasked to 0x41");
    };

    t.run("PN-01: RFC 9000 Appendix A.3 Packet Number Reconstruction") { sub =>
        // Normal sequential packet numbers
        let pn1 = quic::decode_packet_number(0, 1, 1);
        sub.assert_eq(pn1, 1, "pn 1 decoded from largest_acked 0");

        let pn64 = quic::decode_packet_number(63, 64, 1);
        sub.assert_eq(pn64, 64, "pn 64 decoded from largest_acked 63");

        // Window wrap across 1-byte truncated boundary (255 -> 256)
        let pn256 = quic::decode_packet_number(255, 0, 1);
        sub.assert_eq(pn256, 256, "pn 256 decoded from wrap 0 with largest_acked 255");

        // Out-of-order packet in the past (e.g. pn 254 arriving when largest acked is 256)
        let pn_past = quic::decode_packet_number(256, 254, 1);
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
        let chacha_mask = quic_internal::chacha20_header_protect_mask(hp_key, sample);
        sub.assert_true(chacha_mask.len == 5, "chacha20 mask is 5 bytes");

        let aes256_mask = quic_internal::aes256_header_protect_mask(hp_key, sample);
        sub.assert_true(aes256_mask.len == 5, "aes256 mask is 5 bytes");

        // Protect & unprotect with ChaCha20 mask on long header
        var pkt: u8[16] = [
            0xC3, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x05, 0x12, 0x34, 0x56, 0x78, 0xAA, 0xBB, 0xCC,
        ];
        let orig_b0 = pkt[0];
        quic::apply_header_protection(pkt[..], 9, 4, chacha_mask);
        sub.assert_true(pkt[0] != orig_b0, "first byte masked");

        let pn_len, trunc_pn = quic::remove_header_protection(pkt[..], 9, chacha_mask);
        sub.assert_eq(pn_len, 4, "recovered 4-byte PN");
        sub.assert_eq(trunc_pn, 0x12345678, "recovered truncated PN matches");
        sub.assert_eq(pkt[0], orig_b0, "first byte restored");
    };

    t.run("HDR-02: QUIC Header Parsing Across All Packet Types") { sub =>
        // 1. Handshake Packet Header
        var h_hdr = quic::QuicHeader {
            header_type:    quic::QuicHeaderType.Handshake,
            version:        rfc::QUIC_VERSION_1,
            payload_length: 120,
            packet_number:  42,
            ..
        };
        h_hdr.dcid.append("dcid1234");
        h_hdr.scid.append("scid5678");

        var h_buf: u8[..128] = [];
        sub.assert_true(quic::encode_header(h_hdr, 2, h_buf), "encode Handshake header");
        let parsed_h, ok_h = quic::parse_header(h_buf[..], 0);
        sub.assert_true(ok_h, "parse Handshake header");
        sub.assert_eq(parsed_h.header_type, quic::QuicHeaderType.Handshake, "type is Handshake");
        sub.assert_eq(parsed_h.dcid[..], "dcid1234", "dcid matches");
        sub.assert_eq(parsed_h.scid[..], "scid5678", "scid matches");
        sub.assert_eq(parsed_h.payload_length, 120, "payload length matches");

        // 2. 0-RTT Packet Header
        var z_hdr = quic::QuicHeader {
            header_type:    quic::QuicHeaderType.ZeroRtt,
            version:        rfc::QUIC_VERSION_1,
            payload_length: 50,
            packet_number:  1,
            ..
        };
        z_hdr.dcid.append("zero-dcid");
        var z_buf: u8[..128] = [];
        sub.assert_true(quic::encode_header(z_hdr, 1, z_buf), "encode 0-RTT header");
        let parsed_z, ok_z = quic::parse_header(z_buf[..], 0);
        sub.assert_true(ok_z, "parse 0-RTT header");
        sub.assert_eq(parsed_z.header_type, quic::QuicHeaderType.ZeroRtt, "type is ZeroRtt");

        // 3. Retry Packet Header
        var r_hdr = quic::QuicHeader {
            header_type: quic::QuicHeaderType.Retry,
            version:     rfc::QUIC_VERSION_1,
            ..
        };
        r_hdr.dcid.append("retry-dcid");
        r_hdr.scid.append("retry-scid");
        var r_buf: u8[..128] = [];
        sub.assert_true(quic::encode_header(r_hdr, 1, r_buf), "encode Retry header");
        r_buf.append("retry-token-data-16bytes");
        let parsed_r, ok_r = quic::parse_header(r_buf[..], 0);
        sub.assert_true(ok_r, "parse Retry header");
        sub.assert_eq(parsed_r.header_type, quic::QuicHeaderType.Retry, "type is Retry");

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

        let parsed_vn, ok_vn = quic::parse_header(vn_buf[..], 0);
        sub.assert_true(ok_vn, "parse Version Negotiation header");
        sub.assert_eq(parsed_vn.header_type, quic::QuicHeaderType.VersionNegotiation, "type is VersionNegotiation");
        sub.assert_eq(parsed_vn.dcid[..], "dcid", "VN dcid matches");
        sub.assert_eq(parsed_vn.scid[..], "scid", "VN scid matches");
    };
}

// 5. Anti-Amplification 3x Limit & Zero-Heap Reassembly (RFC 9000)
fn test_anti_amplification_and_reassembly(t: lit::T&) {
    t.run("PATH-01: Server Anti-Amplification 3x Credit Tracking") { sub =>
        let ip: u8[16] = [0; 16];
        var path = quic::new_path_state(ip, 443, false); // unvalidated client path

        // Client sends 1200 bytes Initial packet
        quic::on_bytes_received(path, 1200);
        // Total credit = 3 * 1200 = 3600 bytes

        sub.assert_true(quic::can_send(path, 1200), "can send 1st 1200B packet");
        quic::on_bytes_sent(path, 1200);

        sub.assert_true(quic::can_send(path, 1200), "can send 2nd 1200B packet");
        quic::on_bytes_sent(path, 1200);

        sub.assert_true(quic::can_send(path, 1200), "can send 3rd 1200B packet");
        quic::on_bytes_sent(path, 1200);
        // Total sent = 3600 = 3 * 1200. Further packets must be blocked!

        sub.assert_false(quic::can_send(path, 1), "4th packet blocked by 3x limit");

        // Validate path -> credit limit lifted
        quic::validate(path);
        sub.assert_true(quic::can_send(path, 1200), "sending allowed on validated path");
    };

    t.run("REASSEMBLY-01: Out-of-Order & Overlapping Stream Fragments") { sub =>
        var rbuf = quic::new_reassembly_buffer(65536);

        // Fragment 2 arrives first: offset 5..10 ("WORLD")
        let ok2 = quic::insert_fragment(rbuf, 5, "WORLD", false);
        sub.assert_true(ok2, "insert fragment 2 ok");
        sub.assert_eq(rbuf.consumed_offset, 0, "consumed remains 0 while waiting for head");

        // Fragment 1 arrives: offset 0..5 ("HELLO")
        let ok1 = quic::insert_fragment(rbuf, 0, "HELLO", false);
        sub.assert_true(ok1, "insert fragment 1 ok");

        // Contiguous read
        var out: u8[..64] = [];
        let n = quic::read_contiguous(rbuf, out);
        sub.assert_eq(n, 10, "read 10 contiguous bytes");
        sub.assert_eq(out[..], "HELLOWORLD", "assembled payload is HELLOWORLD");
        sub.assert_eq(rbuf.consumed_offset, 10, "consumed offset advanced to 10");
    };

    t.run("REASSEMBLY-02: Flow Control & Final Size Guard") { sub =>
        var rbuf = quic::new_reassembly_buffer(100); // 100 bytes max limit

        // Fragment exceeding flow control limit
        let ok_overflow = quic::insert_fragment(rbuf, 90, "0123456789ABCDEF", false); // end 106 > 100
        sub.assert_false(ok_overflow, "flow control overflow rejected");

        // Consistent FIN
        let ok_fin1 = quic::insert_fragment(rbuf, 0, "DATA", true);
        sub.assert_true(ok_fin1, "FIN set at offset 4");
        sub.assert_eq(rbuf.final_size, 4, "final size is 4");

        // Conflicting FIN -> QUIC_ERR_FINAL_SIZE
        let ok_fin2 = quic::insert_fragment(rbuf, 0, "DATA123", true);
        sub.assert_false(ok_fin2, "mismatched final size rejected");
    };
}

// 6. ACK Framing, OACK Defense & 5-Priority PTO (RFC 9000, RFC 9002, ANRW 2025)
fn test_ack_and_pto_engine(t: lit::T&) {
    t.run("ACK-01: ACK & ACK_ECN Encode / Decode Roundtrip") { sub =>
        var orig_ack = quic::AckFrame {
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
        orig_ack.ranges.push(quic::AckRange { gap: 2, ack_range: 5 });

        var wire: u8[..64] = [];
        sub.assert_true(quic::encode_ack_frame(orig_ack, wire), "encode ACK_ECN");

        let dec_ack, consumed, ok_dec = quic::decode_ack_frame(wire[..], 0);
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
        var space = quic::PnSpaceState { space_id: quic::PnSpaceId.Handshake, .. };
        var hp:   u8[16] = [1; 16];
        var aead: u8[32] = [2; 32];
        var iv:   u8[12] = [3; 12];
        let ok = quic::install_keys(space, hp[..], aead[..], iv[..], 0x1301);
        sub.assert_true(ok, "keys installed");
        sub.assert_true(space.keys_installed, "keys_installed flag set");
        sub.assert_eq(space.hp_key.len, 16, "hp_key len 16");
    };

    t.run("ACK-02: Optimistic ACK (OACK) Forward-Dated Attack Rejection") { sub =>
        var space = quic::PnSpaceState {
            space_id:         quic::PnSpaceId.ApplicationData,
            largest_sent_pn:  50, // Sender only sent up to PN 50!
            has_sent_packets: true,
            ..
        };

        // Malicious peer sends ACK for PN 60 > largest_sent_pn
        let malicious_ack = quic::AckFrame {
            largest_acked:   60,
            ack_delay:       0,
            first_ack_range: 0,
            ..
        };

        var intervals: quic::AckInterval[..64] = [];
        let ok_valid = quic::parse_and_validate_ack(space, malicious_ack, intervals);
        sub.assert_false(ok_valid, "OACK attack claiming unsent PN 60 rejected");
    };

    t.run("RTT-01: RTT Estimators & Max ACK Delay Clamping (RFC 9002 Sec 5.3)") { sub =>
        var rtt = quic::RttState {};
        sub.assert_eq(rtt.smoothed_rtt_us, 333000, "initial smoothed_rtt is 333 ms");

        // First sample: 40 ms
        quic::update_rtt(rtt, 40000, 2000, true, 1000000);
        sub.assert_eq(rtt.min_rtt_us, 40000, "min_rtt updated to 40 ms");
        sub.assert_eq(rtt.smoothed_rtt_us, 40000, "smoothed_rtt initialized to 40 ms");
        sub.assert_eq(rtt.rttvar_us, 20000, "rttvar initialized to 20 ms");

        // Second sample: 48 ms with 5 ms delay -> adjusted 43 ms
        quic::update_rtt(rtt, 48000, 5000, true, 2000000);
        sub.assert_eq(rtt.min_rtt_us, 40000, "min_rtt remains 40 ms");
        // smoothed_rtt = (7 * 40000 + 43000) / 8 = 40375 us
        sub.assert_eq(rtt.smoothed_rtt_us, 40375, "smoothed_rtt weighted average updated");
    };

    t.run("PTO-01: 5-Priority PTO State Machine Decisions") { sub =>
        var spaces: quic::PnSpaceState[3] = [
            quic::PnSpaceState { space_id: quic::PnSpaceId.Initial, .. },
            quic::PnSpaceState { space_id: quic::PnSpaceId.Handshake, .. },
            quic::PnSpaceState { space_id: quic::PnSpaceId.ApplicationData, .. },
        ];
        var rtt = quic::RttState { smoothed_rtt_us: 50000, rttvar_us: 10000, .. };

        // Priority 2: Server at anti-amplification limit
        let dec_amp = quic::evaluate_pto_timer(
            spaces, rtt, 0, 1000000, quic::PtoContext {
                is_server:                true,
                is_amplification_limited: true,
            },
        );
        sub.assert_eq(dec_amp.mode, quic::PtoTimerMode.AntiAmplification, "server at amp limit returns AntiAmplification");

        // Priority 3: Client Anti-deadlock PTO when no packets in flight
        let dec_deadlock = quic::evaluate_pto_timer(
            spaces, rtt, 0, 1000000, quic::PtoContext {
                is_server:                      false,
                is_amplification_limited:       false,
                peer_completed_addr_validation: false,
                handshake_confirmed:            false,
            },
        );
        sub.assert_eq(dec_deadlock.mode, quic::PtoTimerMode.AntiDeadlock, "client anti-deadlock armed");

        // Priority 5: Standard PTO when packets in flight
        spaces[0].sent_packets.push(quic::SentPacketMeta {
            pn: 1, time_sent_us: 1000000, ack_eliciting: true, in_flight: true,
        });
        spaces[0].time_of_last_ack_eliciting_us = 1000000;
        let dec_std = quic::evaluate_pto_timer(
            spaces, rtt, 0, 1000000, quic::PtoContext {
                is_server:                      true,
                peer_completed_addr_validation: true,
            },
        );
        sub.assert_eq(dec_std.mode, quic::PtoTimerMode.StandardPto, "standard PTO scheduled");

        // Priority 1: Time threshold loss detection takes precedence over PTO
        spaces[0].loss_time_us = 1010000;
        let dec_loss = quic::evaluate_pto_timer(
            spaces, rtt, 0, 1000000, quic::PtoContext {
                is_server:                      true,
                peer_completed_addr_validation: true,
            },
        );
        sub.assert_eq(dec_loss.mode, quic::PtoTimerMode.LossTime, "loss time timer takes Priority 1");
    };

    t.run("ACK-03: Descending Interval Tracking & Frame Construction") { sub =>
        var ranges: quic::AckInterval[..64] = [];

        // Record PN 10
        quic::record_received_pn(ranges, 10);
        sub.assert_eq(ranges.len, 1, "1 range recorded");
        sub.assert_eq(ranges[0].smallest, 10, "smallest is 10");
        sub.assert_eq(ranges[0].largest, 10, "largest is 10");

        // Record PN 11 -> merges into [10..11]
        quic::record_received_pn(ranges, 11);
        sub.assert_eq(ranges.len, 1, "still 1 range after contiguous PN 11");
        sub.assert_eq(ranges[0].smallest, 10, "smallest is 10");
        sub.assert_eq(ranges[0].largest, 11, "largest is 11");

        // Record PN 13 -> creates new range: [13..13], [10..11]
        quic::record_received_pn(ranges, 13);
        sub.assert_eq(ranges.len, 2, "2 ranges after gap");
        sub.assert_eq(ranges[0].largest, 13, "range 0 largest is 13");
        sub.assert_eq(ranges[1].largest, 11, "range 1 largest is 11");

        // Record duplicate PN 10 -> ignored
        quic::record_received_pn(ranges, 10);
        sub.assert_eq(ranges.len, 2, "duplicate PN 10 ignored");

        // Record PN 12 -> bridges the gap, merging into [10..13]
        quic::record_received_pn(ranges, 12);
        sub.assert_eq(ranges.len, 1, "gap bridged into 1 range [10..13]");
        sub.assert_eq(ranges[0].smallest, 10, "smallest is 10");
        sub.assert_eq(ranges[0].largest, 13, "largest is 13");

        // Build ACK frame from interval set
        let ack, ok_ack = quic::build_ack_frame(ranges, 150, false);
        sub.assert_true(ok_ack, "build_ack_frame succeeds");
        sub.assert_eq(ack.largest_acked, 13, "largest acked is 13");
        sub.assert_eq(ack.first_ack_range, 3, "first ack range is 13 - 10 = 3");
        sub.assert_eq(ack.ranges.len, 0, "no extra ranges");
        sub.assert_eq(ack.ack_delay, 150, "ack delay is 150");
    };

    t.run("LOSS-01: Packet and Time Threshold Loss Detection (RFC 9002)") { sub =>
        var space = quic::PnSpaceState {
            space_id:          quic::PnSpaceId.ApplicationData,
            has_acked_packets: true,
            largest_acked_pn:  10,
            ..
        };
        // Sent packets: PN 5 (t=1000), PN 6 (t=1000), PN 8 (t=1000)
        space.sent_packets.push(quic::SentPacketMeta {
            pn: 5, time_sent_us: 1000, ack_eliciting: true, in_flight: true,
        });
        space.sent_packets.push(quic::SentPacketMeta {
            pn: 6, time_sent_us: 1000, ack_eliciting: true, in_flight: true,
        });
        space.sent_packets.push(quic::SentPacketMeta {
            pn: 8, time_sent_us: 1000, ack_eliciting: true, in_flight: true,
        });

        var rtt = quic::RttState {
            smoothed_rtt_us: 40000,
            latest_rtt_us:   40000,
            ..
        };

        var lost: quic::SentPacketMeta[..64] = [];
        quic::detect_lost_packets(space, rtt, 100000, lost);

        // Packets 5 and 6 meet packet threshold (10 >= 5 + 3 and 10 >= 6 + 3)
        sub.assert_true(lost.len >= 2, "at least 2 lost packets detected");
        sub.assert_eq(lost[0].pn, 5, "packet 5 detected as lost");
        sub.assert_eq(lost[1].pn, 6, "packet 6 detected as lost");
    };
}

// 7. BBRv2/v3, CUBIC & Pacing Engine (draft-ietf-ccwg-bbr-06, RFC 9438)
fn test_bbr_cubic_and_pacing(t: lit::T&) {
    t.run("PACER-01: User-Space Leaky Bucket Token Tracking") { sub =>
        var pacer = quic::new_pacer(8000000); // 8 Mbps -> 1 byte per microsecond

        // Transmit 1000 bytes at t = 1000000 us -> takes 1000 us
        let _, ok1 = quic::can_send(pacer, 1000000, 1000);
        sub.assert_true(ok1, "first packet sent immediately");

        // Next packet at t = 1000100 us (only 100 us later) -> bucket in deficit (-900 us)
        let delay, ok2 = quic::can_send(pacer, 1000100, 1000);
        sub.assert_false(ok2, "second packet paced / held in bucket");
        sub.assert_true(delay > 0, "pacer returns non-zero pacing delay");

        // At t = 1002000 us (1900 us later) -> deficit repaid
        let _, ok3 = quic::can_send(pacer, 1002000, 1000);
        sub.assert_true(ok3, "packet permitted after pacing interval elapsed");
    };

    t.run("BBR-01: 7-State Phase Transitions & Dual-Envelope Congestion") { sub =>
        var bbr = quic::BbrState { .. };
        bbr.bw_hi_bps = 100000000; // 100 Mbps
        bbr.min_rtt_us = 40000;    // 40 ms -> BDP = 500 KB

        sub.assert_eq(bbr.mode, quic::BbrMode.Startup, "initial mode is Startup");

        // Cycle through phases: Startup -> Drain -> Cruise -> Refill -> Up -> Down
        quic::advance_cycle(bbr, true);
        sub.assert_eq(bbr.mode, quic::BbrMode.Drain, "advanced to Drain");

        quic::advance_cycle(bbr, true);
        sub.assert_eq(bbr.mode, quic::BbrMode.ProbeBwCruise, "advanced to ProbeBwCruise");

        // Congestion signal: loss rate 5% (> 2%)
        quic::on_congestion_signal(bbr, 500000, 5000, 100000, 0, 100);
        sub.assert_eq(bbr.mode, quic::BbrMode.ProbeBwDown, "dropped to ProbeBwDown on >2% loss");
        // inflight_hi reduced to 70% of 500,000 = 350,000 bytes
        sub.assert_eq(bbr.inflight_hi_bytes, 350000, "inflight_hi reduced by 70% beta");
    };

    t.run("BBR-02: 5-Second ProbeRTT Trigger & 0.5 BDP Floor") { sub =>
        var bbr = quic::BbrState { .. };
        bbr.bw_hi_bps = 80000000; // 80 Mbps
        bbr.min_rtt_us = 50000;   // 50 ms -> BDP = 500,000 bytes
        bbr.min_rtt_stamp_us = 1000000;
        bbr.mode = quic::BbrMode.ProbeBwCruise;

        // Check at t = 2s (within 5s window) -> remains in Cruise
        quic::check_probe_rtt(bbr, 2000000, 52000);
        sub.assert_eq(bbr.mode, quic::BbrMode.ProbeBwCruise, "remains in Cruise before 5s expiration");

        // Check at t = 6.1s (> 5s window) -> triggers ProbeRtt!
        quic::check_probe_rtt(bbr, 6100000, 51000);
        sub.assert_eq(bbr.mode, quic::BbrMode.ProbeRtt, "switched to ProbeRtt after 5s");
        // cwnd in ProbeRtt = max(0.5 * BDP, 4800) = 250,000 bytes
        sub.assert_eq(bbr.cwnd_bytes, 250000, "ProbeRtt cwnd set to 0.5 BDP floor");
    };

    t.run("CUBIC-01: Integer Cube Root & Application-Limited Freeze") { sub =>
        // Test int_cbrt exact values
        sub.assert_eq(quic_internal::int_cbrt(0), 0, "cbrt(0) = 0");
        sub.assert_eq(quic_internal::int_cbrt(1), 1, "cbrt(1) = 1");
        sub.assert_eq(quic_internal::int_cbrt(8), 2, "cbrt(8) = 2");
        sub.assert_eq(quic_internal::int_cbrt(27), 3, "cbrt(27) = 3");
        sub.assert_eq(quic_internal::int_cbrt(1000), 10, "cbrt(1000) = 10");
        sub.assert_eq(quic_internal::int_cbrt(1000000), 100, "cbrt(1000000) = 100");

        var cubic = quic::CubicState { .. };
        cubic.cwnd_segments = 20; // 20 * 1200 = 24000 bytes
        cubic.epoch_start_us = 1000000;
        cubic.last_update_us = 1000000;

        // Inflight = 10000 bytes (< 75% of 24000 = 18000) -> Application Limited!
        let cwnd1 = quic::on_ack(cubic, 2000000, 40000, 10000, 1200);
        sub.assert_true(cubic.app_limited, "sender detected as application-limited");
        sub.assert_eq(cwnd1, 24000, "cwnd frozen during application-limited period");
        // Epoch start advanced by 1s idle time (from 1000000 to 2000000)
        sub.assert_eq(cubic.epoch_start_us, 2000000, "epoch start frozen/advanced by elapsed idle time");
    };

    t.run("CUBIC-02: Loss Multiplicative Window Reduction (RFC 9438)") { sub =>
        var cubic = quic::CubicState { .. };
        cubic.cwnd_segments = 100;
        quic::on_loss(cubic, 5000000);
        sub.assert_eq(cubic.w_max_segments, 100, "w_max saved as 100");
        sub.assert_eq(cubic.cwnd_segments, 70, "cwnd reduced to 70 (beta 0.7)");
        sub.assert_eq(cubic.epoch_start_us, 5000000, "epoch start reset to now");
    };
}

// Main Conformance Runner

// --- Component: quic_frames ---
// Test suite for QUIC Transport RFC 9000 Section 19 Frame Codecs,
// Demuxer, and Section 3 Stream State Machine Invariants.

// ----------------------------------------------------------------------------
// 8. RFC 9000 §19.8 STREAM Frame Codec
// ----------------------------------------------------------------------------
fn test_quic_stream_frame_codec(t: lit::T&) {
    // 1. STREAM frame: Base (stream_id=4, offset=0, no FIN, with length)
    var wire1: u8[..128] = [];
    let flags1 = quic::QuicStreamFlags { fin: false, with_len: true };
    let ok_enc1 = quic::encode_stream_frame(4, 0, "hello quic", wire1, flags1);
    t.assert_true(ok_enc1, "encode basic stream frame");

    var cur1: i64 = 0;
    let frame1, ok_dec1 = quic::decode_frame_cursor(wire1[..], cur1);
    t.assert_true(ok_dec1, "decode basic stream frame");
    t.assert_eq(frame1.stream_id, 4, "stream id matches");
    t.assert_eq(frame1.offset, 0, "offset is 0");
    t.assert_false(frame1.fin, "fin flag is false");
    t.assert_eq(frame1.payload, "hello quic", "payload matches");

    // 2. STREAM frame with Offset and FIN
    var wire2: u8[..128] = [];
    let flags2 = quic::QuicStreamFlags { fin: true, with_len: true };
    let ok_enc2 = quic::encode_stream_frame(8, 1024, "world", wire2, flags2);
    t.assert_true(ok_enc2, "encode stream frame with off and fin");

    var cur2: i64 = 0;
    let frame2, ok_dec2 = quic::decode_frame_cursor(wire2[..], cur2);
    t.assert_true(ok_dec2, "decode stream frame with off and fin");
    t.assert_eq(frame2.stream_id, 8, "stream id matches");
    t.assert_eq(frame2.offset, 1024, "offset matches");
    t.assert_true(frame2.fin, "fin flag is true");
    t.assert_eq(frame2.payload, "world", "payload matches");

    // 3. STREAM frame without length (consumes remainder of buffer)
    var wire3: u8[..128] = [];
    let flags3 = quic::QuicStreamFlags { fin: false, with_len: false };
    let ok_enc3 = quic::encode_stream_frame(12, 2048, "rest-of-packet", wire3, flags3);
    t.assert_true(ok_enc3, "encode stream frame without length");

    var cur3: i64 = 0;
    let frame3, ok_dec3 = quic::decode_frame_cursor(wire3[..], cur3);
    t.assert_true(ok_dec3, "decode stream frame without length");
    t.assert_eq(frame3.stream_id, 12, "stream id matches");
    t.assert_eq(frame3.offset, 2048, "offset matches");
    t.assert_eq(frame3.payload, "rest-of-packet", "payload matches");

    // 4. Zero-length payload STREAM with FIN
    var wire4: u8[..64] = [];
    let flags4 = quic::QuicStreamFlags { fin: true, with_len: true };
    let ok_enc4 = quic::encode_stream_frame(16, 5000, "", wire4, flags4);
    t.assert_true(ok_enc4, "encode empty fin stream frame");

    var cur4: i64 = 0;
    let frame4, ok_dec4 = quic::decode_frame_cursor(wire4[..], cur4);
    t.assert_true(ok_dec4, "decode empty fin stream frame");
    t.assert_eq(frame4.stream_id, 16, "stream id matches");
    t.assert_eq(frame4.offset, 5000, "offset matches");
    t.assert_true(frame4.fin, "fin is true");
    t.assert_eq(frame4.length, 0, "length is 0");

    // 5. RFC 9000 §19.8 bounds check: offset + length > 2^62 - 1 rejected
    var wire_bad: u8[..64] = [];
    let flags_bad = quic::QuicStreamFlags { fin: false, with_len: true };
    let ok_bad_enc = quic::encode_stream_frame(4, 0x3FFFFFFFFFFFFFFF, "overflow", wire_bad, flags_bad);
    t.assert_false(ok_bad_enc, "offset + len exceeding 2^62-1 rejected during encoding");
}

// ----------------------------------------------------------------------------
// 9. RFC 9000 §19.6 CRYPTO Frame Codec
// ----------------------------------------------------------------------------
fn test_quic_crypto_frame_codec(t: lit::T&) {
    var wire: u8[..256] = [];
    let tls_data: const u8[6] = [0x01, 0x00, 0x00, 0x02, 0x03, 0x03];
    let ok_enc = quic::encode_crypto_frame(500, tls_data[..], wire);
    t.assert_true(ok_enc, "encode crypto frame");

    var cur: i64 = 0;
    let frame, ok_dec = quic::decode_frame_cursor(wire[..], cur);
    t.assert_true(ok_dec, "decode crypto frame");
    t.assert_eq(frame.raw_type, rfc::QUIC_FRAME_CRYPTO, "frame type is crypto");
    t.assert_eq(frame.offset, 500, "crypto offset matches");
    t.assert_eq(frame.length, 6, "crypto length matches");
    t.assert_eq(frame.payload.len, 6, "crypto payload slice matches");
    t.assert_eq(frame.payload[0], 0x01, "first payload byte matches");

    // RFC 9000 §19.6 bounds: offset + len > 2^62 - 1
    var wire_bad: u8[..64] = [];
    let ok_bad = quic::encode_crypto_frame(0x3FFFFFFFFFFFFFFF, tls_data[..], wire_bad);
    t.assert_false(ok_bad, "crypto offset overflow rejected");
}

// ----------------------------------------------------------------------------
// 10. RFC 9000 §19 Control Frames Codec
// ----------------------------------------------------------------------------
fn test_quic_control_frames_codec(t: lit::T&) {
    // 1. RESET_STREAM
    var wire_rst: u8[..64] = [];
    let ok_rst_enc = quic::encode_reset_stream_frame(4, 0x101, 4096, wire_rst);
    t.assert_true(ok_rst_enc, "encode reset stream frame");

    var cur_rst: i64 = 0;
    let f_rst, ok_rst_dec = quic::decode_frame_cursor(wire_rst[..], cur_rst);
    t.assert_true(ok_rst_dec, "decode reset stream frame");
    t.assert_eq(f_rst.stream_id, 4, "reset stream id matches");
    t.assert_eq(f_rst.error_code, 0x101, "reset error code matches");
    t.assert_eq(f_rst.final_size, 4096, "reset final size matches");

    // 2. STOP_SENDING
    var wire_ss: u8[..64] = [];
    let ok_ss_enc = quic::encode_stop_sending_frame(8, 0x102, wire_ss);
    t.assert_true(ok_ss_enc, "encode stop sending frame");

    var cur_ss: i64 = 0;
    let f_ss, ok_ss_dec = quic::decode_frame_cursor(wire_ss[..], cur_ss);
    t.assert_true(ok_ss_dec, "decode stop sending frame");
    t.assert_eq(f_ss.stream_id, 8, "stop sending stream id matches");
    t.assert_eq(f_ss.error_code, 0x102, "stop sending error code matches");

    // 3. MAX_DATA
    var wire_md: u8[..64] = [];
    let ok_md_enc = quic::encode_max_data_frame(1048576, wire_md);
    t.assert_true(ok_md_enc, "encode max data frame");

    var cur_md: i64 = 0;
    let f_md, ok_md_dec = quic::decode_frame_cursor(wire_md[..], cur_md);
    t.assert_true(ok_md_dec, "decode max data frame");
    t.assert_eq(f_md.max_data, 1048576, "max data limit matches");

    // 4. MAX_STREAM_DATA
    var wire_msd: u8[..64] = [];
    let ok_msd_enc = quic::encode_max_stream_data_frame(12, 262144, wire_msd);
    t.assert_true(ok_msd_enc, "encode max stream data frame");

    var cur_msd: i64 = 0;
    let f_msd, ok_msd_dec = quic::decode_frame_cursor(wire_msd[..], cur_msd);
    t.assert_true(ok_msd_dec, "decode max stream data frame");
    t.assert_eq(f_msd.stream_id, 12, "max stream data stream id matches");
    t.assert_eq(f_msd.max_data, 262144, "max stream data limit matches");

    // 5. PING and PADDING
    var wire_ping: u8[..16] = [];
    t.assert_true(quic::encode_ping_frame(wire_ping), "encode ping");
    t.assert_eq(wire_ping.len, 1, "ping length 1");
    t.assert_eq(wire_ping[0], 0x01, "ping byte 0x01");

    var wire_pad: u8[..16] = [];
    t.assert_true(quic::encode_padding_frame(wire_pad, 5), "encode padding x5");
    t.assert_eq(wire_pad.len, 5, "padding length 5");
    for i in 5 {
        t.assert_eq(wire_pad[i], 0x00, "padding byte 0x00");
    }
}

// ----------------------------------------------------------------------------
// 11. RFC 9000 Zero-Alloc Frame Demuxer
// ----------------------------------------------------------------------------
fn test_quic_frame_demuxer(t: lit::T&) {
    // Pack multiple distinct frames into a single datagram payload buffer
    var packet_wire: u8[..512] = [];

    // Frame 1: PADDING
    quic::encode_padding_frame(packet_wire, 1);
    // Frame 2: PING
    quic::encode_ping_frame(packet_wire);
    // Frame 3: MAX_DATA
    quic::encode_max_data_frame(2000000, packet_wire);
    // Frame 4: STREAM (id=0, offset=0, fin=false)
    quic::encode_stream_frame(0, 0, "demux-part-1", packet_wire, quic::QuicStreamFlags { fin: false, with_len: true });
    // Frame 5: STOP_SENDING (id=4, err=0x99)
    quic::encode_stop_sending_frame(4, 0x99, packet_wire);
    // Frame 6: STREAM (id=0, offset=12, fin=true)
    quic::encode_stream_frame(0, 12, "-part-2", packet_wire, quic::QuicStreamFlags { fin: true, with_len: true });

    // Iteratively demux packet frames using zero-alloc slice cursor
    var p_cur: i64 = 0;

    // 1. PADDING
    let f1, ok1 = quic::decode_frame_cursor(packet_wire[..], p_cur);
    t.assert_true(ok1, "demux f1 padding ok");
    t.assert_eq(f1.raw_type, rfc::QUIC_FRAME_PADDING, "f1 is padding");

    // 2. PING
    let f2, ok2 = quic::decode_frame_cursor(packet_wire[..], p_cur);
    t.assert_true(ok2, "demux f2 ping ok");
    t.assert_eq(f2.raw_type, rfc::QUIC_FRAME_PING, "f2 is ping");

    // 3. MAX_DATA
    let f3, ok3 = quic::decode_frame_cursor(packet_wire[..], p_cur);
    t.assert_true(ok3, "demux f3 max_data ok");
    t.assert_eq(f3.raw_type, rfc::QUIC_FRAME_MAX_DATA, "f3 is max_data");
    t.assert_eq(f3.max_data, 2000000, "f3 limit matches");

    // 4. STREAM part 1
    let f4, ok4 = quic::decode_frame_cursor(packet_wire[..], p_cur);
    t.assert_true(ok4, "demux f4 stream ok");
    t.assert_eq(f4.stream_id, 0, "f4 stream_id is 0");
    t.assert_eq(f4.payload, "demux-part-1", "f4 payload matches");
    t.assert_false(f4.fin, "f4 fin is false");

    // 5. STOP_SENDING
    let f5, ok5 = quic::decode_frame_cursor(packet_wire[..], p_cur);
    t.assert_true(ok5, "demux f5 stop_sending ok");
    t.assert_eq(f5.stream_id, 4, "f5 stream_id is 4");
    t.assert_eq(f5.error_code, 0x99, "f5 err code matches");

    // 6. STREAM part 2 with FIN
    let f6, ok6 = quic::decode_frame_cursor(packet_wire[..], p_cur);
    t.assert_true(ok6, "demux f6 stream fin ok");
    t.assert_eq(f6.stream_id, 0, "f6 stream_id is 0");
    t.assert_eq(f6.offset, 12, "f6 offset is 12");
    t.assert_eq(f6.payload, "-part-2", "f6 payload matches");
    t.assert_true(f6.fin, "f6 fin is true");

    // Reached end of datagram
    t.assert_eq(p_cur, packet_wire.len, "slice cursor reached end of packet");

    // Test offset-based decode_quic_frame API
    var off: u64 = 0;
    let frame_from_off, next_off, ok_off = quic::decode_frame(packet_wire[..], off);
    t.assert_true(ok_off, "decode from offset 0 ok");
    t.assert_eq(frame_from_off.raw_type, rfc::QUIC_FRAME_PADDING, "offset 0 is padding");
    t.assert_eq(next_off, 1, "next offset is 1");
}

// ----------------------------------------------------------------------------
// 12. RFC 9000 §3.1 Sending Stream State Machine
// ----------------------------------------------------------------------------
fn test_quic_stream_state_machine_send(t: lit::T&) {
    var s = quic::new_stream(0, 10000); // Bidi client stream, max recv 10000
    s.send_max_data = 5000;

    t.assert_eq(s.send_state, quic::QuicSendState.Ready, "initial state is ready");

    // 1. Ready -> Send: send first data fragment
    let err1, ok1 = quic::on_send_data(s, 0, 1000, false);
    t.assert_true(ok1, "send 1000 bytes ok");
    t.assert_eq(err1, rfc::QUIC_ERR_NO_ERROR, "no error");
    t.assert_eq(s.send_state, quic::QuicSendState.Send, "state is Send");
    t.assert_eq(s.bytes_sent, 1000, "bytes sent is 1000");

    // 2. Flow control violation: send beyond send_max_data (5000)
    let err_fc, ok_fc = quic::on_send_data(s, 4500, 1000, false); // 5500 > 5000
    t.assert_false(ok_fc, "sending beyond max_stream_data fails");
    t.assert_eq(err_fc, rfc::QUIC_ERR_FLOW_CONTROL, "error is flow control");

    // 3. Send -> DataSent: send FIN
    let err2, ok2 = quic::on_send_data(s, 1000, 500, true);
    t.assert_true(ok2, "send fin fragment ok");
    t.assert_eq(s.send_state, quic::QuicSendState.DataSent, "state is DataSent");
    t.assert_true(s.has_send_final_size, "has final size");
    t.assert_eq(s.send_final_size, 1500, "final size is 1500");

    // 4. DataSent -> DataRecvd (peer acknowledged all data)
    let ack_ok = quic::on_send_ack(s, true);
    t.assert_true(ack_ok, "ack all data accepted");
    t.assert_eq(s.send_state, quic::QuicSendState.DataRecvd, "state is DataRecvd (terminal)");
    t.assert_true(quic::is_send_closed(s), "sender is closed");

    // 5. Reset sending path
    var s2 = quic::new_stream(4, 10000);
    let _, ok_rst = quic::on_send_reset(s2, 0x404, 300);
    t.assert_true(ok_rst, "send reset ok");
    t.assert_eq(s2.send_state, quic::QuicSendState.ResetSent, "state is ResetSent");
    t.assert_eq(s2.send_error_code, 0x404, "error code is 0x404");

    let ok_rst_ack = quic::on_send_ack(s2, false);
    t.assert_true(ok_rst_ack, "ack reset accepted");
    t.assert_eq(s2.send_state, quic::QuicSendState.ResetRecvd, "state is ResetRecvd (terminal)");
    t.assert_true(quic::is_send_closed(s2), "sender is closed");
}

// ----------------------------------------------------------------------------
// 13. RFC 9000 §3.2 & §4.5 Receiving Stream State Machine
// ----------------------------------------------------------------------------
fn test_quic_stream_state_machine_recv(t: lit::T&) {
    var s = quic::new_stream(0, 10000); // Recv limit = 10000
    t.assert_eq(s.recv_state, quic::QuicRecvState.Receive, "initial state is Receive");

    // 1. Receive data fragment [0, 500)
    let err1, ok1 = quic::on_recv_stream_frame(s, 0, 500, false);
    t.assert_true(ok1, "recv 500 bytes ok");
    t.assert_eq(err1, rfc::QUIC_ERR_NO_ERROR, "no error");
    t.assert_eq(s.bytes_recv, 500, "bytes_recv is 500");

    // 2. Receive FIN fragment [500, 1000)
    let err2, ok2 = quic::on_recv_stream_frame(s, 500, 500, true);
    t.assert_true(ok2, "recv fin fragment ok");
    t.assert_true(s.has_recv_final_size, "final size known");
    t.assert_eq(s.recv_final_size, 1000, "final size is 1000");
    t.assert_eq(s.recv_state, quic::QuicRecvState.DataRecvd, "state is DataRecvd");

    // 3. Final size violation (RFC 9000 §4.5): frame exceeding declared final size
    let err_bad_fs, ok_bad_fs = quic::on_recv_stream_frame(s, 1000, 10, false);
    t.assert_false(ok_bad_fs, "data exceeding final size rejected");
    t.assert_eq(err_bad_fs, rfc::QUIC_ERR_FINAL_SIZE, "error is FINAL_SIZE_ERROR");

    // 4. Application reads all data -> transitions to DataRead
    quic::on_app_read(s, 1000);
    t.assert_eq(s.recv_state, quic::QuicRecvState.DataRead, "state is DataRead (terminal)");
    t.assert_true(quic::is_recv_closed(s), "recv is closed");

    // 5. RFC 9000 §3.2: RESET_STREAM arriving after DataRecvd / DataRead is ignored
    let err_rst_ign, ok_rst_ign = quic::on_recv_reset(s, 0x123, 1000);
    t.assert_true(ok_rst_ign, "reset on DataRead ignored");
    t.assert_eq(err_rst_ign, rfc::QUIC_ERR_NO_ERROR, "no error");
    t.assert_eq(s.recv_state, quic::QuicRecvState.DataRead, "state remains DataRead");

    // 5b. RFC 9000 §3.2: Duplicate RESET_STREAM arriving on ResetRead state MUST NOT reopen stream
    var s_rst = quic::new_stream(0, 10000);
    let _, ok_r1 = quic::on_recv_reset(s_rst, 0x123, 500);
    t.assert_true(ok_r1, "first reset stream accepted");
    t.assert_eq(s_rst.recv_state, quic::QuicRecvState.ResetRecvd, "state is ResetRecvd");
    quic::on_app_read_reset(s_rst);
    t.assert_eq(s_rst.recv_state, quic::QuicRecvState.ResetRead, "state is ResetRead (terminal)");
    t.assert_true(quic::is_recv_closed(s_rst), "recv is closed");
    let err_r2, ok_r2 = quic::on_recv_reset(s_rst, 0x123, 500);
    t.assert_true(ok_r2, "duplicate reset stream accepted without error");
    t.assert_eq(err_r2, rfc::QUIC_ERR_NO_ERROR, "no error on duplicate reset");
    t.assert_eq(s_rst.recv_state, quic::QuicRecvState.ResetRead, "stream remains ResetRead, does NOT reopen");
    t.assert_true(quic::is_recv_closed(s_rst), "stream remains closed");

    // 6. Receiving STOP_SENDING on send-capable stream
    var s_bidi = quic::new_stream(0, 10000);
    let _, ok_ss = quic::on_recv_stop_sending(s_bidi, 0x55, quic::QuicRole.Server);
    t.assert_true(ok_ss, "stop sending accepted on bidi stream");
    t.assert_eq(s_bidi.send_state, quic::QuicSendState.ResetSent, "sender transitioned to ResetSent");

    // 7. RFC 9000 §19.5: Receiving STOP_SENDING on receive-only stream -> STREAM_STATE_ERROR
    // Stream ID 2 is ClientUni: Server can ONLY receive on stream 2, cannot send!
    var s_uni = quic::new_stream(2, 10000);
    let err_ss_bad, ok_ss_bad = quic::on_recv_stop_sending(s_uni, 0x55, quic::QuicRole.Server);
    t.assert_false(ok_ss_bad, "stop sending on receive-only stream rejected");
    t.assert_eq(err_ss_bad, rfc::QUIC_ERR_STREAM_STATE, "error is STREAM_STATE_ERROR");
}

// ----------------------------------------------------------------------------
// 14. RFC 9000 Zero-Alloc Stream Table
// ----------------------------------------------------------------------------
fn test_quic_stream_table(t: lit::T&) {
    var tbl = quic::new_stream_table(quic::QuicRole.Client);

    // Open first local client bidi stream (ID 0)
    let id0, idx0, ok0 = quic::open_local_stream(tbl, true);
    t.assert_true(ok0, "open client bidi stream 0 ok");
    t.assert_eq(id0, 0, "first client bidi stream id is 0");
    t.assert_eq(idx0, 0, "index is 0");

    // Open second local client bidi stream (ID 4)
    let id4, idx4, ok4 = quic::open_local_stream(tbl, true);
    t.assert_true(ok4, "open client bidi stream 4 ok");
    t.assert_eq(id4, 4, "second client bidi stream id is 4");
    t.assert_eq(idx4, 1, "index is 1");

    // Open client unidirectional stream (ID 2)
    let id2, idx2, ok2 = quic::open_local_stream(tbl, false);
    t.assert_true(ok2, "open client uni stream 2 ok");
    t.assert_eq(id2, 2, "first client uni stream id is 2");
    t.assert_eq(idx2, 2, "index is 2");

    // Lookup existing stream
    let _fs_found0_idx, _fs_found0_ok = quic::find_stream(tbl, 0);
    let found0 = if _fs_found0_ok { _fs_found0_idx } else { -1 };
    t.assert_eq(found0, 0, "found stream 0 at index 0");
    let _fs_found4_idx, _fs_found4_ok = quic::find_stream(tbl, 4);
    let found4 = if _fs_found4_ok { _fs_found4_idx } else { -1 };
    t.assert_eq(found4, 1, "found stream 4 at index 1");

    // Peer stream opening (Server bidi stream ID 1)
    let idx_peer, ok_peer = quic::get_or_open_stream(tbl, 1);
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

// ----------------------------------------------------------------------------
// 15. Connection Flow Control Budget (RFC 9000 §4.1)
// ----------------------------------------------------------------------------
fn test_connection_flow_control_budget(t: lit::T&) {
    var fc = quic::new_flow_control(1000, 65536); // Remote limit 1000
    var s0 = quic::new_stream(0, 65536);
    s0.send_max_data = 10000; // Unlimited stream credit

    t.assert_eq(quic::remaining_conn_credit(fc), 1000, "initial conn credit 1000");

    // Send 600 bytes on stream 0
    let _fc_can_send1 = quic::can_send(fc, s0, 0, 600);
    let can_send1 = _fc_can_send1.allowed;
    let blk_s1 = _fc_can_send1.blocked_stream;
    let blk_c1 = _fc_can_send1.blocked_conn;
    t.assert_true(can_send1, "can send 600 bytes");
    t.assert_false(blk_s1, "not blocked on stream");
    t.assert_false(blk_c1, "not blocked on conn");

    let ok_send1 = quic::record_send(fc, s0, 0, 600);
    t.assert_true(ok_send1, "record send 600 ok");
    t.assert_eq(fc.bytes_sent_total, 600, "bytes_sent_total 600");
    t.assert_eq(quic::remaining_conn_credit(fc), 400, "conn credit remaining 400");
    t.assert_false(fc.is_data_blocked, "not blocked yet");

    // Send remaining 400 bytes on stream 4
    var s4 = quic::new_stream(4, 65536);
    s4.send_max_data = 10000;

    let ok_send2 = quic::record_send(fc, s4, 0, 400);
    t.assert_true(ok_send2, "record send 400 on s4 ok");
    t.assert_eq(fc.bytes_sent_total, 1000, "bytes_sent_total 1000");
    t.assert_eq(quic::remaining_conn_credit(fc), 0, "conn credit exhausted");
    t.assert_true(fc.is_data_blocked, "marked data blocked");

    // Attempt to send 1 additional byte on stream 0
    let _fc_can_send3 = quic::can_send(fc, s0, 600, 1);
    let can_send3 = _fc_can_send3.allowed;
    let blk_s3 = _fc_can_send3.blocked_stream;
    let blk_c3 = _fc_can_send3.blocked_conn;
    t.assert_false(can_send3, "cannot send when conn credit is 0");
    t.assert_false(blk_s3, "stream has credit");
    t.assert_true(blk_c3, "blocked on conn credit");

    let ok_send3 = quic::record_send(fc, s0, 600, 1);
    t.assert_false(ok_send3, "record send fails when conn budget exceeded");
}

// ----------------------------------------------------------------------------
// 16. Monotonic MAX_DATA Limit Updates
// ----------------------------------------------------------------------------
fn test_monotonic_remote_max_data(t: lit::T&) {
    var fc = quic::new_flow_control(500, 65536);
    var s = quic::new_stream(0, 65536);
    s.send_max_data = 5000;

    let _ = quic::record_send(fc, s, 0, 500);
    t.assert_true(fc.is_data_blocked, "connection is blocked at 500");

    // Non-monotonic / decreasing update MUST be rejected
    let rej_down = quic::update_remote_max_data(fc, 400);
    t.assert_false(rej_down, "reject lower MAX_DATA 400");
    t.assert_eq(fc.max_data_remote, 500, "limit remains 500");
    t.assert_true(fc.is_data_blocked, "remains blocked");

    // Stale identical update MUST be rejected
    let rej_same = quic::update_remote_max_data(fc, 500);
    t.assert_false(rej_same, "reject identical MAX_DATA 500");

    // Monotonic increase unblocks connection
    let ok_up = quic::update_remote_max_data(fc, 1200);
    t.assert_true(ok_up, "accept higher MAX_DATA 1200");
    t.assert_eq(fc.max_data_remote, 1200, "limit updated to 1200");
    t.assert_false(fc.is_data_blocked, "connection unblocked");
    t.assert_eq(quic::remaining_conn_credit(fc), 700, "remaining credit 700");

    // Sending now succeeds
    let _fc_can_send = quic::can_send(fc, s, 500, 200);
    let can_send = _fc_can_send.allowed;
    t.assert_true(can_send, "send 200 succeeds after unblocking");
}

// ----------------------------------------------------------------------------
// 17. Stream Flow Control Budget (RFC 9000 §4.1)
// ----------------------------------------------------------------------------
fn test_stream_flow_control_budget(t: lit::T&) {
    var fc = quic::new_flow_control(100000, 65536); // Unlimited conn credit
    var s = quic::new_stream(0, 65536);
    s.send_max_data = 300; // 300 bytes stream budget

    t.assert_eq(quic::remaining_stream_credit(s), 300, "stream credit 300");

    // Send 200 bytes
    let ok1 = quic::record_send(fc, s, 0, 200);
    t.assert_true(ok1, "send 200 bytes ok");
    t.assert_eq(s.bytes_sent, 200, "stream bytes sent 200");
    t.assert_eq(quic::remaining_stream_credit(s), 100, "stream remaining credit 100");

    // Attempting to send 150 bytes exceeds stream budget (200 + 150 = 350 > 300)
    let _fc_can_send_excess = quic::can_send(fc, s, 200, 150);
    let can_send_excess = _fc_can_send_excess.allowed;
    let blk_s = _fc_can_send_excess.blocked_stream;
    let blk_c = _fc_can_send_excess.blocked_conn;
    t.assert_false(can_send_excess, "cannot exceed stream limit");
    t.assert_true(blk_s, "blocked on stream limit");
    t.assert_false(blk_c, "connection not blocked");

    let ok_excess = quic::record_send(fc, s, 200, 150);
    t.assert_false(ok_excess, "record send exceeds stream budget fails");

    // Receive MAX_STREAM_DATA increasing limit to 800
    let ok_update = quic::update_send_max_data(s, 800);
    t.assert_true(ok_update, "stream limit updated to 800");
    t.assert_eq(s.send_max_data, 800, "s.send_max_data is 800");
    t.assert_eq(quic::remaining_stream_credit(s), 600, "stream credit now 600");

    // Now sending 150 bytes succeeds
    let ok2 = quic::record_send(fc, s, 200, 150);
    t.assert_true(ok2, "send 150 succeeds after MAX_STREAM_DATA");
    t.assert_eq(s.bytes_sent, 350, "stream bytes sent 350");
}

// ----------------------------------------------------------------------------
// 18. Ingress Flow Control & FLOW_CONTROL_ERROR
// ----------------------------------------------------------------------------
fn test_ingress_flow_control_and_errors(t: lit::T&) {
    var fc = quic::new_flow_control(10000, 1000); // Local conn limit 1000
    var s = quic::new_stream(0, 500); // Local stream limit 500

    // Ingress 400 bytes at offset 0
    let err1, ok1 = quic::record_recv_stream(fc, s, 0, 400);
    t.assert_true(ok1, "recv 400 bytes ok");
    t.assert_eq(err1, rfc::QUIC_ERR_NO_ERROR, "no error");
    t.assert_eq(s.bytes_recv, 400, "stream bytes_recv 400");
    t.assert_eq(fc.bytes_recv_total, 400, "conn bytes_recv_total 400");

    // Re-transmission / duplicate interval (offset 100, len 100) MUST NOT inflate conn total
    let _, ok_dup = quic::record_recv_stream(fc, s, 100, 100);
    t.assert_true(ok_dup, "duplicate interval accepted");
    t.assert_eq(s.bytes_recv, 400, "bytes_recv still 400");
    t.assert_eq(fc.bytes_recv_total, 400, "conn total not inflated by retransmission");

    // Ingress exceeding stream limit (offset 400, len 150 -> end 550 > 500)
    let err_stream_violation, ok_stream_violation = quic::record_recv_stream(fc, s, 400, 150);
    t.assert_false(ok_stream_violation, "stream flow control violation rejected");
    t.assert_eq(err_stream_violation, rfc::QUIC_ERR_FLOW_CONTROL, "returns FLOW_CONTROL_ERROR (0x03)");

    // Now test connection-level ingress violation with another stream
    var s4 = quic::new_stream(4, 2000); // Large stream limit
    // Current conn total is 400. Conn limit is 1000.
    // Ingress 500 bytes on s4 -> conn total = 900 <= 1000 (ok)
    let _, ok2 = quic::record_recv_stream(fc, s4, 0, 500);
    t.assert_true(ok2, "recv 500 bytes on s4 ok");
    t.assert_eq(fc.bytes_recv_total, 900, "conn total 900");

    // Ingress 200 bytes on s4 -> 900 + 200 = 1100 > 1000 -> Connection FLOW_CONTROL_ERROR
    let err_conn_violation, ok_conn_violation = quic::record_recv_stream(fc, s4, 500, 200);
    t.assert_false(ok_conn_violation, "connection flow control violation rejected");
    t.assert_eq(err_conn_violation, rfc::QUIC_ERR_FLOW_CONTROL, "returns FLOW_CONTROL_ERROR (0x03)");
}

// ----------------------------------------------------------------------------
// 19. RESET_STREAM Final Size Accounting (RFC 9000 §4.5)
// ----------------------------------------------------------------------------
fn test_reset_stream_flow_control_accounting(t: lit::T&) {
    var fc = quic::new_flow_control(10000, 1000);
    var s = quic::new_stream(0, 800);

    // Stream had received 200 bytes
    let _ = quic::record_recv_stream(fc, s, 0, 200);
    t.assert_eq(fc.bytes_recv_total, 200, "conn total 200");

    // RESET_STREAM arrives with final_size = 500.
    // Additional 300 bytes committed to connection total.
    let err_rst, ok_rst = quic::record_recv_reset(fc, s, 500);
    t.assert_true(ok_rst, "reset final size 500 accepted");
    t.assert_eq(err_rst, rfc::QUIC_ERR_NO_ERROR, "no error");
    t.assert_eq(s.bytes_recv, 500, "stream bytes_recv set to final size 500");
    t.assert_eq(fc.bytes_recv_total, 500, "conn total advanced to 500");

    // RESET_STREAM with final size exceeding connection limit (e.g. 1200 > 1000)
    var s4 = quic::new_stream(4, 2000);
    let err_rst_exceed, ok_rst_exceed = quic::record_recv_reset(fc, s4, 1200);
    t.assert_false(ok_rst_exceed, "reset exceeding conn limit rejected");
    t.assert_eq(err_rst_exceed, rfc::QUIC_ERR_FLOW_CONTROL, "returns FLOW_CONTROL_ERROR");
}

// ----------------------------------------------------------------------------
// 20. Window Update Auto-Generation (RFC 9000 §4.2)
// ----------------------------------------------------------------------------
fn test_window_update_thresholds(t: lit::T&) {
    // Configure local window of 64KB (65536)
    var fc = quic::new_flow_control(65536, 65536);
    var s = quic::new_stream(0, 65536);

    // App reads 20000 bytes. Available credit: 65536 - 20000 = 45536 > 32768 (half window)
    quic::on_app_read(fc, s, 20000);
    let _, need_update1 = quic::check_conn_window_update(fc);
    t.assert_false(need_update1, "no MAX_DATA update before threshold (credit > half)");

    // App reads another 15000 bytes. Total read = 35000.
    // Available credit: 65536 - 35000 = 30536 < 32768 (credit < half window)
    quic::on_app_read(fc, s, 15000);
    let new_max_data, need_update2 = quic::check_conn_window_update(fc);
    t.assert_true(need_update2, "MAX_DATA update triggered when available < half window");
    t.assert_eq(new_max_data, 100536, "new MAX_DATA is consumed (35000) + window (65536) = 100536");
    t.assert_eq(fc.max_data_local, 100536, "local max data updated");

    // Immediately checking again returns false (already advertised)
    let _, need_update3 = quic::check_conn_window_update(fc);
    t.assert_false(need_update3, "subsequent check does not re-trigger without more reads");

    // RFC 9000 §4.1: Received bytes trigger MAX_DATA update preventing deadlock without app reads
    var fc_rx = quic::new_flow_control(65536, 65536);
    var s_rx = quic::new_stream(0, 65536);
    let _, ok_rx = quic::record_recv_stream(fc_rx, s_rx, 0, 35000);
    t.assert_true(ok_rx, "record receive 35000 bytes ok");
    let new_max_rx, need_update_rx = quic::check_conn_window_update(fc_rx);
    t.assert_true(need_update_rx, "MAX_DATA update triggered by received bytes preventing deadlock");
    t.assert_eq(new_max_rx, 100536, "new MAX_DATA calculated from received bytes (35000 + 65536)");

    // Stream window update threshold test
    var s_up = quic::new_stream(0, 1000);
    s_up.recv_consumed = 600; // Read 600 bytes out of 1000. Available = 400 < 500 (half)
    let s_new_limit, s_need = quic::check_stream_window_update(s_up, 1000);
    t.assert_true(s_need, "MAX_STREAM_DATA triggered");
    t.assert_eq(s_new_limit, 1600, "new stream limit is 600 + 1000 = 1600");
}

// ----------------------------------------------------------------------------
// 21. RFC 9000 Appendix A Packet Number Decoding
// ----------------------------------------------------------------------------
fn test_rfc9000_packet_number_decoding(t: lit::T&) {
    // Vector 1 from RFC 9000 Appendix A:
    // largest_pn = 0xABE8B, truncated_pn = 0xACEB, pn_nbits = 16 (2 bytes)
    // expected reconstructed PN = 0x0AACEB (699627)
    let pn1 = quic::decode_packet_number(0xABE8B, 0xACEB, 2);
    t.assert_eq(pn1, 0x0AACEB, "RFC 9000 Appendix A Vector 1 decoded correctly");

    let pn1_chk, ok1 = quic::decode_packet_number_checked(0xABE8B, 0xACEB, 2);
    t.assert_true(ok1, "checked decode vector 1 ok");
    t.assert_eq(pn1_chk, 0x0AACEB, "checked decode vector 1 matches");

    // 1-byte packet number (8 bits, window 256):
    // largest_pn = 100, truncated = 105 -> 105
    let pn_1b = quic::decode_packet_number(100, 105, 1);
    t.assert_eq(pn_1b, 105, "1-byte PN near largest");

    // 1-byte wrapping around window:
    // largest_pn = 250, truncated = 5 -> candidate = 250 - 250 + 5 = 5.
    // candidate + 256 = 261. Diff |261 - 250| = 11 < |5 - 250| = 245.
    // Decoded PN = 261!
    let pn_wrap = quic::decode_packet_number(250, 5, 1);
    t.assert_eq(pn_wrap, 261, "1-byte PN wrapping around 256");

    // 3-byte packet number (24 bits, window 0x1000000):
    let pn_3b = quic::decode_packet_number(0x1000000, 0x000010, 3);
    t.assert_eq(pn_3b, 0x1000010, "3-byte PN window reconstruction");

    // 4-byte packet number (32 bits, window 0x100000000):
    let pn_4b = quic::decode_packet_number(0x200000000, 0x00000005, 4);
    t.assert_eq(pn_4b, 0x200000005, "4-byte PN window reconstruction");

    // Invalid length (0 or > 4) MUST fail in checked version
    let _, ok_inv0 = quic::decode_packet_number_checked(100, 10, 0);
    t.assert_false(ok_inv0, "0-byte length rejected");

    let _, ok_inv5 = quic::decode_packet_number_checked(100, 10, 5);
    t.assert_false(ok_inv5, "5-byte length rejected");
}

// ----------------------------------------------------------------------------
// 22. QuicConnection Inbound Frame Demuxing
// ----------------------------------------------------------------------------
fn test_connection_datagram_demuxing(t: lit::T&) {
    let scid: u8[4] = [0x01, 0x02, 0x03, 0x04];
    var conn = quic::new_server_connection(scid[..]);

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
    let ok_enc = quic::encode_stream_frame(0, 0, "WING", dgram, quic::QuicStreamFlags { fin: true, with_len: false });
    t.assert_true(ok_enc, "stream frame encoded into datagram");

    var out_ack = quic::AckFrame { .. };
    let _pr_handled = quic_internal::process_unencrypted_test_datagram(conn, dgram[..], 1000, out_ack);
    let handled = _pr_handled.handled;
    let needs_ack = _pr_handled.needs_ack;
    t.assert_true(handled, "datagram handled successfully");
    t.assert_true(needs_ack, "STREAM frame is ack-eliciting, needs_ack is true");

    // Verify stream state in connection
    t.assert_eq(conn.stream_table.streams.len, 1, "stream table has 1 stream");
    t.assert_eq(conn.stream_table.streams[0].stream_id, 0, "stream 0 registered");
    t.assert_eq(conn.stream_table.streams[0].bytes_recv, 4, "stream 0 received 4 bytes");
    t.assert_eq(conn.flow_ctrl.bytes_recv_total, 4, "flow control recorded 4 bytes received");

    // Now test connection-level ingress violation with exceeding payload
    let scid2: u8[4] = [0x05, 0x06, 0x07, 0x08];
    var conn2 = quic::new_server_connection(scid2[..]);
    conn2.flow_ctrl.max_data_local = 10; // Low limit

    var dgram2: u8[..128] = [];
    dgram2.push(0x40);
    dgram2.append(scid2[..]);
    dgram2.push(0x02);

    let _ = quic::encode_stream_frame(0, 0, "0123456789ABCDEFGHIJ", dgram2, quic::QuicStreamFlags { fin: true, with_len: false }); // 20 bytes > 10

    var out_ack2 = quic::AckFrame { .. };
    let _pr_handled2 = quic_internal::process_unencrypted_test_datagram(conn2, dgram2[..], 2000, out_ack2);
    let handled2 = _pr_handled2.handled;
    t.assert_false(handled2, "violating datagram returns handled=false");
    t.assert_eq(conn2.state, quic::QuicConnState.Closing, "connection transitioned to Closing");
    t.assert_eq(conn2.close_code, rfc::QUIC_ERR_FLOW_CONTROL, "closed with FLOW_CONTROL_ERROR (0x03)");
}

// --- Component: quic_ack_invariants ---
// Security invariant tests for QUIC Transport (RFC 9000, RFC 9002):
// 1. ACK Frame encoding, decoding, and RFC 9000 §19.3.1 underflow defense.
// 2. Optimistic ACK (OACK) attack prevention.
// 3. QUIC packet header fixed and reserved bits validation.

// ----------------------------------------------------------------------------
// 23. QUIC ACK Frame Decoding Invariants
// ----------------------------------------------------------------------------
fn test_quic_ack_frame_decoding_invariants(t: lit::T&) {
    // 1. Valid ACK Frame
    var ack = quic::AckFrame {
        is_ecn:          false,
        largest_acked:   100,
        ack_delay:       25,
        first_ack_range: 10,
        ..
    };
    var wire: u8[..64] = [];
    t.assert_true(quic::encode_ack_frame(ack, wire), "encode ack frame");

    let dec_ack, read_len, ok = quic::decode_ack_frame(wire[..], 0);
    t.assert_true(ok, "decode valid ack frame");
    t.assert_eq(dec_ack.largest_acked, 100, "largest acked matches");
    t.assert_eq(dec_ack.first_ack_range, 10, "first range matches");
    t.assert_eq(dec_ack.ack_delay, 25, "delay matches");

    // 2. RFC 9000 §19.3.1: Largest Acknowledged < First ACK Range must be rejected
    // Type 0x02, Largest Acked = 5, Delay = 0, Range Count = 0, First Range = 10
    let bad_wire: const u8[5] = [0x02, 0x05, 0x00, 0x00, 0x0A];
    let _, _, bad_ok = quic::decode_ack_frame(bad_wire[..], 0);
    t.assert_false(bad_ok, "largest_acked < first_ack_range must be rejected");

    // 3. Range gap underflow: subsequent range underflows packet number space
    // Type 0x02, Largest = 10, Delay = 0, Range Count = 1, First Range = 5 (smallest = 5),
    // Gap = 10 (needs 5 - 10 - 2, underflow!)
    let bad_gap_wire: const u8[7] = [0x02, 0x0A, 0x00, 0x01, 0x05, 0x0A, 0x01];
    let _, _, bad_gap_ok = quic::decode_ack_frame(bad_gap_wire[..], 0);
    t.assert_false(bad_gap_ok, "range gap underflowing PN space must be rejected");
}

// ----------------------------------------------------------------------------
// 24. QUIC OACK Attack Prevention
// ----------------------------------------------------------------------------
fn test_quic_oack_defense(t: lit::T&) {
    var space = quic::PnSpaceState {
        has_sent_packets: true,
        largest_sent_pn:  50,
        ..
    };

    // Forward-dated ACK (largest_acked = 60 > largest_sent_pn = 50)
    var fwd_ack = quic::AckFrame {
        largest_acked:   60,
        first_ack_range: 0,
        ..
    };
    var intervals: quic::AckInterval[..64] = [];
    let ok_fwd = quic::parse_and_validate_ack(space, fwd_ack, intervals);
    t.assert_false(ok_fwd, "OACK forward-dated packet number must be rejected");

    // Valid ACK within sent range
    var valid_ack = quic::AckFrame {
        largest_acked:   50,
        first_ack_range: 5,
        ..
    };
    let ok_valid = quic::parse_and_validate_ack(space, valid_ack, intervals);
    t.assert_true(ok_valid, "valid ack within sent range passes");
    t.assert_eq(intervals.len, 1, "1 interval extracted");
    t.assert_eq(intervals[0].smallest, 45, "smallest is 45");
    t.assert_eq(intervals[0].largest, 50, "largest is 50");
}

// ----------------------------------------------------------------------------
// 25. QUIC Header Security Bits
// ----------------------------------------------------------------------------
fn test_quic_header_security_bits(t: lit::T&) {
    // 1. Long Header Fixed Bit (0x40) check: byte 0 = 0x80 (Long=1, Fixed=0)
    let bad_fixed_long: const u8[12] = [0x80, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let _, ok_fixed = quic::parse_header(bad_fixed_long[..]);
    t.assert_false(ok_fixed, "long header with fixed bit cleared must be rejected");

    // 2. Long Header Initial Reserved Bits (0x0C) check: byte 0 = 0xC4 (Reserved bit set)
    let bad_res_long: const u8[12] = [0xC4, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let _, ok_res = quic::parse_header(bad_res_long[..]);
    t.assert_false(ok_res, "long header with reserved bits set must be rejected");

    // 3. Short Header Fixed Bit (0x40) check: byte 0 = 0x00 (Fixed=0)
    let bad_fixed_short: const u8[8] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    let _, ok_short_fix = quic::parse_header(bad_fixed_short[..], 4);
    t.assert_false(ok_short_fix, "short header with fixed bit cleared must be rejected");

    // 4. Short Header Reserved Bits (0x18) check: byte 0 = 0x58 (Fixed=1, Reserved bit 4 set)
    let bad_res_short: const u8[8] = [0x58, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    let _, ok_short_res = quic::parse_header(bad_res_short[..], 4);
    t.assert_false(ok_short_res, "short header with reserved bits set must be rejected");
}

// RFC 9000 Section 19.17: PATH_CHALLENGE Frames - 8-byte payload test
// RFC 9000 Section 19.18: PATH_RESPONSE Frames - 8-byte payload test
// ----------------------------------------------------------------------------
// 26. QUIC PATH_CHALLENGE & PATH_RESPONSE Codecs (RFC 9000)
// ----------------------------------------------------------------------------
fn test_quic_path_frames(t: lit::T&) {
    t.run("PATH-01: PATH_CHALLENGE frame serialization and parsing") { sub =>
        let challenge_token: u8[8] = [1, 2, 3, 4, 5, 6, 7, 8];
        var out_wire: u8[..32] = [];
        let enc_ok = quic::encode_path_challenge_frame(challenge_token, out_wire);
        sub.assert_true(enc_ok, "encode_path_challenge_frame succeeded");
        sub.assert_eq(out_wire.len, 9, "wire buffer has 9 bytes (1 type + 8 payload)");
        sub.assert_eq(out_wire[0], 0x1A as u8, "frame type byte is 0x1A");

        var idx: i64 = 1;
        let decoded, dec_ok = quic_internal::decode_path_challenge_frame(out_wire[..], idx);
        sub.assert_true(dec_ok, "decode_path_challenge_frame succeeded");
        sub.assert_eq(idx, 9, "cursor advanced to end of frame (9)");
        for i in 8 {
            sub.assert_eq(decoded.data[i], challenge_token[i], "challenge data byte matched");
        }
    };

    t.run("PATH-02: PATH_RESPONSE frame serialization and parsing") { sub =>
        let response_token: u8[8] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22];
        var out_wire: u8[..32] = [];
        let enc_ok = quic::encode_path_response_frame(response_token, out_wire);
        sub.assert_true(enc_ok, "encode_path_response_frame succeeded");
        sub.assert_eq(out_wire.len, 9, "wire buffer has 9 bytes (1 type + 8 payload)");
        sub.assert_eq(out_wire[0], 0x1B as u8, "frame type byte is 0x1B");

        var idx: i64 = 1;
        let decoded, dec_ok = quic_internal::decode_path_response_frame(out_wire[..], idx);
        sub.assert_true(dec_ok, "decode_path_response_frame succeeded");
        sub.assert_eq(idx, 9, "cursor advanced to end of frame (9)");
        for i in 8 {
            sub.assert_eq(decoded.data[i], response_token[i], "response data byte matched");
        }
    };

    t.run("PATH-03: Unified QUIC frame demuxer dispatches PATH frames") { sub =>
        let token: u8[8] = [10, 20, 30, 40, 50, 60, 70, 80];
        var wire: u8[..32] = [];
        quic::encode_path_challenge_frame(token, wire);
        quic::encode_path_response_frame(token, wire);

        let f1, next_off1, ok1 = quic::decode_frame(wire[..], 0);
        sub.assert_true(ok1, "demuxed PATH_CHALLENGE frame");
        sub.assert_true(f1.frame_type == quic::QuicFrameType.PathChallenge, "type is PathChallenge");
        sub.assert_eq(f1.length, 8, "length is 8");
        sub.assert_eq(next_off1, 9, "next offset is 9");

        let f2, next_off2, ok2 = quic::decode_frame(wire[..], next_off1);
        sub.assert_true(ok2, "demuxed PATH_RESPONSE frame");
        sub.assert_true(f2.frame_type == quic::QuicFrameType.PathResponse, "type is PathResponse");
        sub.assert_eq(f2.length, 8, "length is 8");
        sub.assert_eq(next_off2, 18, "next offset is 18");
    };

    t.run("PATH-04: Truncated PATH payload rejection") { sub =>
        let truncated: u8[5] = [0x1A, 1, 2, 3, 4];
        var idx: i64 = 1;
        let _, ok = quic_internal::decode_path_challenge_frame(truncated[..], idx);
        sub.assert_false(ok, "truncated PATH_CHALLENGE payload rejected");
    };
}

// RFC 9000 Section 9: Connection Migration - State machine test
// RFC 9000 Section 8.2: Path Validation - Token verification and anti-amplification
// ----------------------------------------------------------------------------
// 27. Connection Migration FSM & Anti-Amplification (RFC 9000)
// ----------------------------------------------------------------------------
fn test_connection_migration(t: lit::T&) {
    t.run("MIG-01: Path validation lifecycle (Initiated -> Validating -> Validated)") { sub =>
        let initial_addr = quic::new_endpoint_addr("198.51.100.1", 4433);
        var mgr = quic::new_migration_manager(initial_addr);

        let active_addr = mgr.active_path.remote_addr;
        sub.assert_eq(active_addr.port, 4433, "initial port is 4433");
        sub.assert_true(quic::addr_eq(active_addr, initial_addr), "initial addr matched");

        let token, ok_tok = quic::generate_path_challenge_token();
        sub.assert_true(ok_tok, "CSPRNG path challenge token generated");

        let new_addr = quic::new_endpoint_addr("203.0.113.50", 9000);
        quic::start_probing(mgr, new_addr, token);
        sub.assert_true(mgr.has_probing_path, "probing path active");
        sub.assert_true(mgr.probing_path.state == quic::PathValidationState.Validating, "state is Validating");

        // Response mismatch: must reject and stay Validating
        let wrong_token: u8[8] = [0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8];
        let rej_ok = quic::on_path_response(mgr, wrong_token[..]);
        sub.assert_false(rej_ok, "mismatched response token rejected");
        sub.assert_true(mgr.probing_path.state == quic::PathValidationState.Validating, "still Validating");

        // Response match: succeeds and transitions to Validated
        let match_ok = quic::on_path_response(mgr, token[..]);
        sub.assert_true(match_ok, "matching response token accepted");
        sub.assert_true(mgr.probing_path.state == quic::PathValidationState.Validated, "state is Validated");

        // Migration completion: moves active path to new address
        let mig_ok = quic::complete(mgr);
        sub.assert_true(mig_ok, "migration completed successfully");
        sub.assert_false(mgr.has_probing_path, "probing path cleared");

        let current_addr = mgr.active_path.remote_addr;
        sub.assert_true(quic::addr_eq(current_addr, new_addr), "active address updated to new endpoint");
    };

    t.run("MIG-02: Anti-amplification 3x limit on unvalidated paths") { sub =>
        let addr = quic::new_endpoint_addr("192.0.2.1", 443);
        var mgr = quic::new_migration_manager(addr);

        let token: u8[8] = [1, 2, 3, 4, 5, 6, 7, 8];
        let candidate_addr = quic::new_endpoint_addr("192.0.2.200", 5000);
        quic::start_probing(mgr, candidate_addr, token);

        // Before receiving any bytes on candidate path: limit = 0
        sub.assert_false(quic::can_send(mgr.probing_path, 1), "cannot send before receiving bytes");

        // Receive 1200 bytes -> limit is 3600 bytes (3x)
        mgr.probing_path.bytes_received += 1200;
        sub.assert_true(quic::can_send(mgr.probing_path, 3600), "can send up to 3600 bytes");
        sub.assert_false(quic::can_send(mgr.probing_path, 3601), "cannot exceed 3x budget");

        // Send 2000 bytes
        mgr.probing_path.bytes_sent += 2000;
        sub.assert_true(quic::can_send(mgr.probing_path, 1600), "can send remaining 1600 bytes");
        sub.assert_false(quic::can_send(mgr.probing_path, 1601), "budget exceeded after partial send");

        // Validate path: limit is lifted completely
        let ok = quic::on_path_response(mgr, token[..]);
        sub.assert_true(ok, "path validated");
        sub.assert_true(quic::can_send(mgr.probing_path, 100000), "unlimited sending once path validated");
    };

    t.run("MIG-03: Probe retry counter exhaustion transitions to Failed") { sub =>
        let addr = quic::new_endpoint_addr("192.0.2.1", 443);
        var mgr = quic::new_migration_manager(addr);

        let token: u8[8] = [9, 8, 7, 6, 5, 4, 3, 2];
        let candidate = quic::new_endpoint_addr("192.0.2.99", 6000);
        quic::start_probing(mgr, candidate, token);

        sub.assert_true(quic::retry_probe(mgr), "retry 1 succeeded");
        sub.assert_true(quic::retry_probe(mgr), "retry 2 succeeded");
        sub.assert_false(quic::retry_probe(mgr), "retry 3 exhausted (max 3)");
        sub.assert_false(mgr.has_probing_path, "probing path removed after failure");
    };

    t.run("MIG-04: Constant-time token verification") { sub =>
        let tok_a: u8[8] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let tok_b: u8[8] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let tok_c: u8[8] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x89];

        sub.assert_true(quic::verify_path_response_token(tok_a, tok_b[..]), "identical tokens match");
        sub.assert_false(quic::verify_path_response_token(tok_a, tok_c[..]), "1-bit differing tokens mismatch");
        sub.assert_false(quic::verify_path_response_token(tok_a, tok_a[..7]), "truncated token rejected");
    };

    t.run("MIG-05: QuicConnection integrated migration and DPLPMTUD") { sub =>
        let scid: u8[4] = [0x01, 0x02, 0x03, 0x04];
        var conn = quic::new_server_connection(scid[..]);
        let cand_addr = quic::new_endpoint_addr("198.51.100.99", 8443);
        let token: u8[8] = [1, 2, 3, 4, 5, 6, 7, 8];

        quic::migrate(conn, cand_addr, token);
        sub.assert_true(conn.migration.has_probing_path, "conn migration probing path initiated");

        // Simulate incoming PathResponse frame dispatch
        let resp_frame = quic::QuicFrame {
            frame_type: quic::QuicFrameType.PathResponse,
            length:     8,
            payload:    token[..],
            ..
        };
        let _pr_ok_disp = quic_internal::dispatch_inbound_frame(conn, resp_frame);
        let ok_disp = _pr_ok_disp.handled;
        sub.assert_true(ok_disp, "PathResponse dispatched to connection migration");
        sub.assert_true(conn.validated_address, "connection address marked validated after migration");

        // DPLPMTUD integration on connection
        sub.assert_eq(conn.dplpmtud.current_pmtu, 1200, "initial connection PMTU is 1200");
        sub.assert_true(quic::on_probe_acked(conn, 1200), "conn probe 1200 acked");
        sub.assert_eq(conn.dplpmtud.current_pmtu, 1200, "PMTU verified after ack");
        sub.assert_eq(conn.dplpmtud.probed_size, 1280, "target probe size progressed to 1280");
    };
}

// RFC 8899 Section 3: Probe Packets - Padded probe generation
// RFC 8899 Section 5.1: State Machine - DPLPMTUD state transitions
// ----------------------------------------------------------------------------
// 28. DPLPMTUD Probe Generator & State Machine (RFC 8899)
// ----------------------------------------------------------------------------
fn test_dplpmtud(t: lit::T&) {
    t.run("DPL-01: Padded PING probe generation across target sizes") { sub =>
        let sizes: u32[4] = [1200, 1280, 1420, 1500];
        var buf: u8[..1600] = [];
        for sz in sizes {
            buf.clear();
            let ok = quic::generate_ping_probe(sz, buf);
            sub.assert_true(ok, "generate_ping_probe succeeded");
            sub.assert_eq(buf.len as u32, sz, "probe buffer length matches target size exactly");
            sub.assert_eq(buf[0], 0x01 as u8, "first byte is PING frame (0x01)");
            sub.assert_eq(buf[buf.len - 1], 0x00 as u8, "trailing byte is PADDING frame (0x00)");
        }
    };

    t.run("DPL-02: Padded PATH_CHALLENGE probe generation across target sizes") { sub =>
        let challenge: u8[8]  = [0xCA, 0xFE, 0xBA, 0xBE, 0x01, 0x02, 0x03, 0x04];
        let sizes:     u32[4] = [1200, 1280, 1420, 1500];
        var buf: u8[..1600] = [];
        for sz in sizes {
            buf.clear();
            let ok = quic::generate_path_challenge_probe(challenge, sz, buf);
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
        var d = quic::Dplpmtud { .. };
        sub.assert_true(d.state == quic::DplpmtudState.Base, "initial state is Base");
        sub.assert_eq(d.current_pmtu, 1200, "initial confirmed PMTU is 1200");
        sub.assert_eq(d.probed_size, 1200, "initial target probe size is 1200");

        // Base probe 1200 acknowledged -> Transitions to Search, probes 1280
        sub.assert_true(quic::on_probe_acked(d, 1200), "ack 1200 ok");
        sub.assert_true(d.state == quic::DplpmtudState.Search, "state is Search");
        sub.assert_eq(d.probed_size, 1280, "probing 1280");

        // Probe 1280 acknowledged -> probes 1420
        sub.assert_true(quic::on_probe_acked(d, 1280), "ack 1280 ok");
        sub.assert_eq(d.current_pmtu, 1280, "confirmed PMTU is 1280");
        sub.assert_eq(d.probed_size, 1420, "probing 1420");

        // Probe 1420 acknowledged -> probes 1500
        sub.assert_true(quic::on_probe_acked(d, 1420), "ack 1420 ok");
        sub.assert_eq(d.current_pmtu, 1420, "confirmed PMTU is 1420");
        sub.assert_eq(d.probed_size, 1500, "probing 1500");

        // Probe 1500 acknowledged -> SearchComplete (ceiling reached)
        sub.assert_true(quic::on_probe_acked(d, 1500), "ack 1500 ok");
        sub.assert_true(d.state == quic::DplpmtudState.SearchComplete, "state is SearchComplete");
        sub.assert_eq(d.current_pmtu, 1500, "final confirmed PMTU is 1500");
    };

    t.run("DPL-04: Probe loss and search ceiling discovery") { sub =>
        var d = quic::Dplpmtud { .. };
        quic::on_probe_acked(d, 1200); // Now in Search, probing 1280
        quic::on_probe_acked(d, 1280); // Now probing 1420

        // Lose 1420 probe 3 times -> stops search, remains SearchComplete with 1280 PMTU
        sub.assert_true(quic::on_probe_lost(d, 1420), "loss 1 recorded");
        sub.assert_true(quic::on_probe_lost(d, 1420), "loss 2 recorded");
        sub.assert_false(quic::on_probe_lost(d, 1420), "loss 3 reaches max probes");

        sub.assert_true(d.state == quic::DplpmtudState.SearchComplete, "search completed on loss");
        sub.assert_eq(d.current_pmtu, 1280, "PMTU established at last confirmed size (1280)");
    };

    t.run("DPL-05: Base probe failure leads to Error state") { sub =>
        var d = quic::Dplpmtud { .. };
        quic::on_probe_lost(d, 1200);
        quic::on_probe_lost(d, 1200);
        quic::on_probe_lost(d, 1200);
        sub.assert_true(d.state == quic::DplpmtudState.Error, "state transitioned to Error");
    };
}

// ----------------------------------------------------------------------------
// 29. Cross-Module QUIC Integration & RFC Conformance Fixes
// ----------------------------------------------------------------------------
fn test_quic_cross_module_bug_fixes(t: lit::T&) {
    t.run("FIX-01: Flow Control & ResetStream field mapping (RFC 9000)") { sub =>
        let scid: u8[4] = [0x11, 0x22, 0x33, 0x44];
        var conn = quic::new_server_connection(scid[..]);

        // 1. MAX_DATA datagram updates conn.flow_ctrl.max_data_remote
        var dgram_md: u8[..64] = [];
        dgram_md.push(0x40);
        dgram_md.append(scid[..]);
        dgram_md.push(0x01);
        quic::encode_max_data_frame(750000, dgram_md);

        var ack_out = quic::AckFrame { .. };
        let _pr_handled_md = quic_internal::process_unencrypted_test_datagram(conn, dgram_md[..], 1000, ack_out);
        let handled_md = _pr_handled_md.handled;
        sub.assert_true(handled_md, "max_data datagram handled");
        sub.assert_eq(conn.flow_ctrl.max_data_remote, 750000, "remote max_data updated to 750000");

        // 2. Open stream 0 first
        var dgram_st: u8[..64] = [];
        dgram_st.push(0x40);
        dgram_st.append(scid[..]);
        dgram_st.push(0x02);
        quic::encode_stream_frame(0, 0, "ping", dgram_st, quic::QuicStreamFlags { fin: false, with_len: true });
        let _pr_handled_st = quic_internal::process_unencrypted_test_datagram(conn, dgram_st[..], 1001, ack_out);
        let handled_st = _pr_handled_st.handled;
        sub.assert_true(handled_st, "stream 0 created");

        // 3. MAX_STREAM_DATA datagram updates stream.flow_ctrl.max_data_remote
        var dgram_msd: u8[..64] = [];
        dgram_msd.push(0x40);
        dgram_msd.append(scid[..]);
        dgram_msd.push(0x03);
        quic::encode_max_stream_data_frame(0, 350000, dgram_msd);
        let _pr_handled_msd = quic_internal::process_unencrypted_test_datagram(conn, dgram_msd[..], 1002, ack_out);
        let handled_msd = _pr_handled_msd.handled;
        sub.assert_true(handled_msd, "max_stream_data datagram handled");
        let _fs_st_idx_idx, _fs_st_idx_ok = quic::find_stream(conn.stream_table, 0);
        let st_idx = if _fs_st_idx_ok { _fs_st_idx_idx } else { -1 };
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
        quic::encode_reset_stream_frame(0, 0x99, 1200, dgram_rst);
        let _pr_handled_rst = quic_internal::process_unencrypted_test_datagram(conn, dgram_rst[..], 1003, ack_out);
        let handled_rst = _pr_handled_rst.handled;
        sub.assert_true(handled_rst, "reset_stream datagram handled");
        sub.assert_eq(conn.stream_table.streams[st_idx as i64].recv_final_size, 1200, "stream recv_final_size set to 1200");
        sub.assert_eq(conn.flow_ctrl.bytes_recv_total, 1200, "flow control bytes_recv_total reflects final_size");
    };

    t.run("FIX-02: Multiplexed ACK and STREAM payload processing & Frame Error") { sub =>
        let scid: u8[4] = [0x21, 0x22, 0x23, 0x24];
        var conn = quic::new_server_connection(scid[..]);
        quic::record_sent(conn, quic::PnSpaceId.ApplicationData, 0, 1200, true, 1000);

        // Synthesize datagram containing ACK frame followed by STREAM frame
        var dgram: u8[..128] = [];
        dgram.push(0x40);
        dgram.append(scid[..]);
        dgram.push(0x01); // PN = 1

        let ack = quic::AckFrame {
            is_ecn:          false,
            largest_acked:   0,
            ack_delay:       5,
            first_ack_range: 0,
            ..
        };
        quic::encode_ack_frame(ack, dgram);
        quic::encode_stream_frame(0, 0, "ACK+STREAM", dgram, quic::QuicStreamFlags { fin: true, with_len: true });

        var ack_out = quic::AckFrame { .. };
        let _pr_handled = quic_internal::process_unencrypted_test_datagram(conn, dgram[..], 2000, ack_out);
        let handled = _pr_handled.handled;
        let needs_ack = _pr_handled.needs_ack;
        sub.assert_true(handled, "multiplexed ACK+STREAM datagram handled successfully");
        sub.assert_true(needs_ack, "trailing STREAM frame elicited ACK requirement");
        let _fs_idx_idx, _fs_idx_ok = quic::find_stream(conn.stream_table, 0);
        let idx = if _fs_idx_ok { _fs_idx_idx } else { -1 };
        sub.assert_true(idx >= 0, "stream 0 found and populated from trailing frame");
        sub.assert_eq(conn.stream_table.streams[idx as i64].bytes_recv, 10, "stream 0 received payload after ACK");

        // Corrupt frame: truncated varint inside payload
        var bad_dgram: u8[..32] = [];
        bad_dgram.push(0x40);
        bad_dgram.append(scid[..]);
        bad_dgram.push(0x02);
        // Varint with 2-bit prefix 11 (requires 8 bytes) but only 1 byte present
        bad_dgram.push(0xC0);

        let _pr_bad_handled = quic_internal::process_unencrypted_test_datagram(conn, bad_dgram[..], 2001, ack_out);
        let bad_handled = _pr_bad_handled.handled;
        sub.assert_false(bad_handled, "corrupt frame payload rejected");
        sub.assert_true(conn.state == quic::QuicConnState.Closing, "connection moved to Closing on corrupt frame");
        sub.assert_eq(conn.close_code, rfc::QUIC_ERR_FRAME_ENCODING, "closed with FRAME_ENCODING_ERROR (0x07)");
    };

    t.run("FIX-03: Peer Stream Limit Enforcement (RFC 9000 §4.6)") { sub =>
        let scid: u8[4] = [0x31, 0x32, 0x33, 0x34];
        var conn = quic::new_server_connection(scid[..]);
        conn.stream_table.max_streams_bidi = 5; // Allow streams 0, 4, 8, 12, 16 (stream_idx 0..4)

        // Stream ID 20 corresponds to stream_idx 5 -> exceeds limit 5!
        var dgram: u8[..64] = [];
        dgram.push(0x40);
        dgram.append(scid[..]);
        dgram.push(0x01);
        quic::encode_stream_frame(20, 0, "limit-exceeded", dgram, quic::QuicStreamFlags { fin: false, with_len: true });

        var ack_out = quic::AckFrame { .. };
        let _pr_handled = quic_internal::process_unencrypted_test_datagram(conn, dgram[..], 3000, ack_out);
        let handled = _pr_handled.handled;
        sub.assert_false(handled, "stream ID exceeding max_streams_bidi rejected");
        sub.assert_true(conn.state == quic::QuicConnState.Closing, "connection in Closing state");
        sub.assert_eq(conn.close_code, rfc::QUIC_ERR_STREAM_LIMIT, "closed with STREAM_LIMIT_ERROR (0x04)");
    };

    t.run("FIX-04: HANDSHAKE_DONE server rejection and PATH_CHALLENGE accounting") { sub =>
        let scid: u8[4] = [0x41, 0x42, 0x43, 0x44];
        var conn = quic::new_server_connection(scid[..]);

        // Server receives HANDSHAKE_DONE frame (0x1E)
        var dgram_hd: u8[..32] = [];
        dgram_hd.push(0x40);
        dgram_hd.append(scid[..]);
        dgram_hd.push(0x01);
        quic::encode_handshake_done_frame(dgram_hd);

        var ack_out = quic::AckFrame { .. };
        let _pr_handled_hd = quic_internal::process_unencrypted_test_datagram(conn, dgram_hd[..], 4000, ack_out);
        let handled_hd = _pr_handled_hd.handled;
        sub.assert_false(handled_hd, "server rejects HANDSHAKE_DONE");
        sub.assert_true(conn.state == quic::QuicConnState.Closing, "connection Closing");
        sub.assert_eq(conn.close_code, rfc::QUIC_ERR_PROTOCOL_VIOLATION, "closed with PROTOCOL_VIOLATION (0x0A)");

        // Fresh connection: PATH_CHALLENGE byte accounting
        var conn2 = quic::new_server_connection(scid[..]);
        var dgram_pc: u8[..32] = [];
        dgram_pc.push(0x40);
        dgram_pc.append(scid[..]);
        dgram_pc.push(0x02);
        let challenge_data: const u8[8] = [1, 2, 3, 4, 5, 6, 7, 8];
        quic::encode_path_challenge_frame(challenge_data, dgram_pc);

        let initial_bytes = conn2.bytes_received;
        let _pr_handled_pc = quic_internal::process_unencrypted_test_datagram(conn2, dgram_pc[..], 4001, ack_out);
        let handled_pc = _pr_handled_pc.handled;
        sub.assert_true(handled_pc, "path challenge processed");
        sub.assert_eq(
            conn2.bytes_received - initial_bytes,
            dgram_pc.len as u64,
            "bytes_received incremented exactly once by datagram len",
        );
    };

    t.run("FIX-05: BBR inflight_hi clamp & CUBIC millisecond scaling") { sub =>
        var bbr = quic::BbrState { .. };
        bbr.bw_hi_bps = 800000000; // 800 Mbps -> high BDP
        bbr.min_rtt_us = 100000;    // 100 ms
        bbr.mode = quic::BbrMode.ProbeBwCruise;
        bbr.inflight_hi_bytes = 15000; // low cap
        quic::update_pacing_and_cwnd(bbr);
        sub.assert_eq(bbr.cwnd_bytes, 15000, "cwnd clamped to inflight_hi_bytes");

        // CUBIC millisecond scaling:
        // 1. Verify K precision: for w_max = 100, K = cbrt(75) s = 4217 ms (old code truncated to 4s)
        let k_ms = quic_internal::cubic_compute_k(100);
        sub.assert_eq(k_ms, 4217, "cubic_compute_k achieves millisecond precision (exactly 4217ms)");

        // 2. Verify sub-second growth: at t = 1400ms (1.4s), delta = 1 segment
        // Old integer-seconds code stayed flat at delta = 0 until t = 2s
        var cubic = quic::CubicState { .. };
        cubic.cwnd_segments = 50;
        cubic.w_max_segments = 50;
        cubic.epoch_start_us = 1000000;
        cubic.last_update_us = 1000000;

        let cwnd_1400ms = quic::on_ack(cubic, 2400000, 50000, 60000, 1200);
        sub.assert_eq(cubic.cwnd_segments, 51, "cubic cwnd incremented by 1 segment at 1.4s");
        sub.assert_eq(cwnd_1400ms, 51 * 1200, "cubic window grew at 1.4s without waiting for 2s integer floor");
    };

    t.run("FIX-06: DPLPMTUD IP overheads and payload size calculation") { sub =>
        let p_v4 = quic::calc_dplpmtud_probe_payload_size(1500, quic::DPLPMTUD_OVERHEAD_IPV4);
        sub.assert_eq(p_v4, 1500 - quic::DPLPMTUD_OVERHEAD_IPV4, "IPv4 payload equals 1500 - 49 = 1451");

        let p_v6 = quic::calc_dplpmtud_probe_payload_size(1500, quic::DPLPMTUD_OVERHEAD_IPV6);
        sub.assert_eq(p_v6, 1500 - quic::DPLPMTUD_OVERHEAD_IPV6, "IPv6 payload equals 1500 - 69 = 1431");
    };
}

// 30. RFC 9369 QUIC Version 2
fn test_quic_version2(t: lit::T&) {
    t.run("V2-01: Version constant and initial salt (RFC 9369 §3.1, §3.3.1)") { sub =>
        sub.assert_eq(rfc::QUIC_VERSION_2, 0x6b3343cf, "QUIC_VERSION_2 is 0x6b3343cf");

        let salt_v2 = rfc::quic_initial_salt(rfc::QUIC_VERSION_2);
        let salt_v1 = rfc::quic_initial_salt(rfc::QUIC_VERSION_1);
        let exp_v2: u8[20] = [
            0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
            0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
        ];
        sub.assert_eq(salt_v2.len, 20, "v2 salt is 20 bytes");
        sub.assert_eq(salt_v2[..], exp_v2[..], "v2 salt matches RFC 9369 §3.3.1 bytes");
        sub.assert_eq(salt_v1.len, 20, "v1 salt is 20 bytes");
        sub.assert_false(salt_v1[..] == salt_v2[..], "v1 and v2 initial salts differ");

        let salt_bad = rfc::quic_initial_salt(0x0A0A0A0A);
        sub.assert_eq(salt_bad.len, 0, "unknown version yields empty salt");
    };

    t.run("V2-02: HKDF label prefixes and HP key divergence (RFC 9369 §3.3.2)") { sub =>
        sub.assert_eq(rfc::quic_hkdf_label_prefix(rfc::QUIC_VERSION_1), "quic ", "v1 prefix is 'quic '");
        sub.assert_eq(
            rfc::quic_hkdf_label_prefix(rfc::QUIC_VERSION_2),
            "quicv2 ",
            "v2 prefix is 'quicv2 '",
        );
        sub.assert_eq(rfc::quic_hkdf_label_prefix(0x0A0A0A0A), "", "unknown version yields empty prefix");

        // Same secret must derive different HP keys under v1 vs v2 labels.
        let secret: u8[32] = [0x42; 32];
        var hp1: u8[16] = [0; 16];
        var hp2: u8[16] = [0; 16];
        let ok1 = tls_internal::ks_derive_quic_hp_key(
            tls_internal::HASH_SHA256,
            secret[..],
            16,
            hp1[..],
            rfc::QUIC_VERSION_1,
        );
        let ok2 = tls_internal::ks_derive_quic_hp_key(
            tls_internal::HASH_SHA256,
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
        let t1, ok1 = quic_internal::quic_long_header_type(rfc::QUIC_VERSION_1, 0);
        sub.assert_true(ok1, "v1 type bits known");
        sub.assert_eq(t1, quic::QuicHeaderType.Initial, "v1 0b00 = Initial");

        let t2, ok2 = quic_internal::quic_long_header_type(rfc::QUIC_VERSION_2, 1);
        sub.assert_true(ok2, "v2 type bits known");
        sub.assert_eq(t2, quic::QuicHeaderType.Initial, "v2 0b01 = Initial");

        let t3, ok3 = quic_internal::quic_long_header_type(rfc::QUIC_VERSION_2, 0);
        sub.assert_true(ok3, "v2 type bits known (Retry)");
        sub.assert_eq(t3, quic::QuicHeaderType.Retry, "v2 0b00 = Retry");

        let t4, _ = quic_internal::quic_long_header_type(rfc::QUIC_VERSION_2, 2);
        sub.assert_eq(t4, quic::QuicHeaderType.ZeroRtt, "v2 0b10 = 0-RTT");
        let t5, _ = quic_internal::quic_long_header_type(rfc::QUIC_VERSION_2, 3);
        sub.assert_eq(t5, quic::QuicHeaderType.Handshake, "v2 0b11 = Handshake");

        let _, ok_unk = quic_internal::quic_long_header_type(0x0A0A0A0A, 0);
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

        let hdr, ok = quic::parse_header(vn_buf[..], 0);
        sub.assert_true(ok, "VN packet with v2 entry parses");
        sub.assert_eq(hdr.header_type, quic::QuicHeaderType.VersionNegotiation, "type is VersionNegotiation");
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

        let hdr, ok = quic::parse_header(v2_init[..], 0);
        sub.assert_true(ok, "v2 Initial long header parses");
        sub.assert_eq(hdr.header_type, quic::QuicHeaderType.Initial, "v2 Type 0b01 decodes as Initial");
        sub.assert_eq(hdr.version, rfc::QUIC_VERSION_2, "version field is 0x6b3343cf");
    };

    t.run("V2-06: RFC 9001 Encrypted Packet Seal/Open & CRYPTO Frame Ingestion") { sub =>
        let scid:   u8[8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        let c_scid: u8[4] = [0xAA, 0xBB, 0xCC, 0xDD];
        var client_conn = quic::new_client_connection(scid[..], c_scid[..]);
        var server_conn = quic::new_server_connection(scid[..]);

        sub.assert_true(quic::install_initial_keys(client_conn, scid[..]), "client initial keys derived");
        sub.assert_true(quic::install_initial_keys(server_conn, scid[..]), "server initial keys derived");

        // Construct plaintext payload with CRYPTO frame + PADDING to 1200+ bytes
        var plain: u8[..1300] = [];
        let ch_msg = "ClientHelloHandshakeFlight";
        sub.assert_true(quic::encode_crypto_frame(0, ch_msg, plain), "encode crypto frame");
        sub.assert_true(quic::encode_padding_frame(plain, 1180), "pad initial payload");

        var hdr = quic::QuicHeader {
            header_type:   quic::QuicHeaderType.Initial,
            version:       rfc::QUIC_VERSION_1,
            packet_number: 1,
            ..
        };
        hdr.dcid.append(scid[..]);
        hdr.scid.append(c_scid[..]);

        var sealed_pkt: u8[..1400] = [];
        let ok_seal = quic::seal_packet(client_conn.tx_initial_space, hdr, 2, plain[..], sealed_pkt);
        sub.assert_true(ok_seal, "quic_seal_packet succeeded");
        sub.assert_true(sealed_pkt.len >= 1200, "Initial datagram >= 1200 bytes");

        var out_ack = quic::AckFrame { .. };
        let _pr_handled = quic::process_datagram(server_conn, sealed_pkt[..], 5000, out_ack);
        let handled = _pr_handled.handled;
        let needs_ack = _pr_handled.needs_ack;
        sub.assert_true(handled, "server decrypted and processed Initial datagram");
        sub.assert_true(needs_ack, "CRYPTO frame is ack-eliciting");
        sub.assert_eq(server_conn.initial_crypto.consumed_offset, ch_msg.len as u64, "CRYPTO stream ingested ClientHello");
        sub.assert_eq(server_conn.initial_crypto.buf[..], ch_msg, "CRYPTO stream buffer matches ClientHello");
    };
}

// --- Component: ngtcp2_and_quinn_vendor_conformance ---
// Ported test vectors from vendor/ngtcp2 (tests/ngtcp2_conv_test.c,
// tests/ngtcp2_pkt_test.c, tests/ngtcp2_acktr_test.c) and vendor/quinn:
// - Exact varint boundary roundtrips (0, 63, 64, 16383, 16384, 1073741823, 1073741824, 4611686018427387903)
//   and truncation rejection at every byte prefix 1..len-1
// - Long/Short header encoding/decoding with max CID length (20B) and oversized CID (21B) rejection
// - Exhaustive frame prefix truncation loops (ngtcp2_pkt_test.c) for ACK, RESET_STREAM, STOP_SENDING,
//   CONNECTION_CLOSE (transport & app), MAX_DATA, MAX_STREAM_DATA, MAX_STREAMS, DATA_BLOCKED,
//   STREAM_DATA_BLOCKED, STREAMS_BLOCKED, NEW_CONNECTION_ID, RETIRE_CONNECTION_ID, NEW_TOKEN
// ----------------------------------------------------------------------------
// 31. ngtcp2 & quinn Vendor Conformance Vectors
// ----------------------------------------------------------------------------
fn test_ngtcp2_and_quinn_vendor_conformance(t: lit::T&) {
    t.run("NGTCP2-CONV-01: Exhaustive VarInt Boundary Roundtrip & Prefix Truncation (test_ngtcp2_put_uvarint)") { sub =>
        let vals: u64[8] = [
            0,
            63,
            64,
            16383,
            16384,
            1073741823,
            1073741824,
            4611686018427387903,
        ];
        let exp_lens: i64[8] = [1, 1, 2, 2, 4, 4, 8, 8];

        for i in 8 {
            var buf: u8[..16] = [];
            let ok_enc = quic::encode_varint(vals[i], buf);
            sub.assert_true(ok_enc, "varint boundary encodes cleanly");
            sub.assert_eq(buf.len, exp_lens[i], "encoded wire length matches RFC 9000 Table 4");

            // Every truncated prefix 0..buf.len-1 MUST fail decoding
            var trunc_len: i64 = 0;
            while trunc_len < buf.len {
                var cur_t: i64 = 0;
                let _, ok_t = quic::decode_varint_cursor(buf[..trunc_len], cur_t);
                sub.assert_false(ok_t, "truncated varint prefix must be rejected");
                sub.assert_eq(cur_t, 0, "cursor unchanged on truncated varint");
                trunc_len += 1;
            }

            // Full slice decodes to exact value
            var cur: i64 = 0;
            let dec_val, ok_dec = quic::decode_varint_cursor(buf[..], cur);
            sub.assert_true(ok_dec, "full varint decodes cleanly");
            sub.assert_eq(dec_val, vals[i], "decoded varint value matches input");
            sub.assert_eq(cur, buf.len, "cursor advanced by exact varint length");
        }
    };

    t.run("NGTCP2-PKT-01: Max CID (20B) Long/Short Header Roundtrip & Oversized CID (21B) Rejection") { sub =>
        let max_dcid: u8[20] = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
            11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        ];
        let max_scid: u8[20] = [
            21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
            31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        ];

        var hs_hdr = quic::QuicHeader {
            header_type:    quic::QuicHeaderType.Handshake,
            version:        0xECEEEFF0,
            payload_length: 16383,
            packet_number:  0xE1E2E301,
            ..
        };
        hs_hdr.dcid.append(max_dcid[..]);
        hs_hdr.scid.append(max_scid[..]);

        var wire_hs: u8[..128] = [];
        sub.assert_false(quic::encode_header(hs_hdr, 4, wire_hs), "reject Handshake header encode with unknown version 0xECEEEFF0");

        // Unknown version 0xECEEEFF0 in raw wire must also be rejected by strict v1/v2 parser
        var raw_unk_ver: u8[..64] = [];
        raw_unk_ver.push(0xE0); // Handshake
        core::append_u32_be(raw_unk_ver, 0xECEEEFF0);
        raw_unk_ver.push(8); // DCID len
        for _ in 30 { raw_unk_ver.push(0xAA); }
        let _, ok_unk_ver = quic::parse_header(raw_unk_ver[..], 0);
        sub.assert_false(ok_unk_ver, "unknown QUIC version rejected by long header parser");

        // Now test with QUIC_VERSION_1 and 20B CIDs
        hs_hdr.version = rfc::QUIC_VERSION_1;
        hs_hdr.payload_length = 8;
        wire_hs.clear();
        sub.assert_true(quic::encode_header(hs_hdr, 4, wire_hs), "encode v1 Handshake with 20B CIDs");
        let hdr_end = wire_hs.len;
        for _ in 4 { wire_hs.push(0xBB); } // 4B PN + 4B payload = 8B payload_length

        let parsed_hs, ok_hs = quic::parse_header(wire_hs[..], 0);
        sub.assert_true(ok_hs, "parse v1 Handshake with 20B CIDs");
        sub.assert_eq(parsed_hs.dcid[..], max_dcid[..], "20B DCID preserved");
        sub.assert_eq(parsed_hs.scid[..], max_scid[..], "20B SCID preserved");
        sub.assert_eq(parsed_hs.packet_number, 0xE1E2E301, "4-byte PN preserved");
        sub.assert_eq(parsed_hs.header_len as i64, hdr_end, "header_len matches encoded header");

        // Oversized DCID (21 bytes > QUIC_MAX_CID_LEN) in raw wire must fail
        var bad_cid_wire: u8[..64] = [];
        bad_cid_wire.push(0xE0); // Handshake
        core::append_u32_be(bad_cid_wire, rfc::QUIC_VERSION_1);
        bad_cid_wire.push(21); // DCID len = 21 (illegal!)
        for _ in 30 { bad_cid_wire.push(0x01); }
        let _, ok_bad_cid = quic::parse_header(bad_cid_wire[..], 0);
        sub.assert_false(ok_bad_cid, "Long header with DCID len 21 (> 20) rejected");
    };

    t.run("NGTCP2-PKT-02: Exhaustive Control & Flow Frame Truncation Loops (ngtcp2_pkt_test.c)") { sub =>
        // 1. RESET_STREAM: stream_id=1000000007, app_error_code=0xE1E2 (57826 -> 4B varint), final_size=0x31F2F3F4F5F6F7F8
        var rst_wire: u8[..64] = [];
        sub.assert_true(
            quic::encode_reset_stream_frame(1000000007, 0xE1E2, 0x31F2F3F4F5F6F7F8, rst_wire),
            "encode ngtcp2 RESET_STREAM vector",
        );
        sub.assert_eq(rst_wire.len, 1 + 4 + 4 + 8, "RESET_STREAM wire length is 17 bytes");
        var i: i64 = 1;
        while i < rst_wire.len {
            var cur_t: i64 = 0;
            let _, ok_t = quic::decode_frame_cursor(rst_wire[..i], cur_t);
            sub.assert_false(ok_t, "truncated RESET_STREAM frame rejected");
            i += 1;
        }
        var cur_rst: i64 = 0;
        let dec_rst, ok_rst = quic::decode_frame_cursor(rst_wire[..], cur_rst);
        sub.assert_true(ok_rst, "full RESET_STREAM decoded");
        sub.assert_eq(dec_rst.stream_id, 1000000007, "stream_id matches");
        sub.assert_eq(dec_rst.error_code, 0xE1E2, "error_code matches");
        sub.assert_eq(dec_rst.final_size, 0x31F2F3F4F5F6F7F8, "final_size matches");

        // 2. STOP_SENDING: stream_id=0xF1F2F3F4, app_error_code=0xE1E2
        var ss_wire: u8[..64] = [];
        sub.assert_true(quic::encode_stop_sending_frame(0xF1F2F3F4, 0xE1E2, ss_wire), "encode ngtcp2 STOP_SENDING vector");
        i = 1;
        while i < ss_wire.len {
            var cur_t: i64 = 0;
            let _, ok_t = quic::decode_frame_cursor(ss_wire[..i], cur_t);
            sub.assert_false(ok_t, "truncated STOP_SENDING frame rejected");
            i += 1;
        }
        var cur_ss: i64 = 0;
        let dec_ss, ok_ss = quic::decode_frame_cursor(ss_wire[..], cur_ss);
        sub.assert_true(ok_ss, "full STOP_SENDING decoded");
        sub.assert_eq(dec_ss.stream_id, 0xF1F2F3F4, "stream_id matches");
        sub.assert_eq(dec_ss.error_code, 0xE1E2, "error_code matches");

        // 3. CONNECTION_CLOSE (Transport 0x1C & Application 0x1D)
        var cc_wire: u8[..64] = [];
        sub.assert_true(
            quic::encode_connection_close_frame(0xF1F2, 0x06, "tls handshake failure", cc_wire, false),
            "encode transport CONNECTION_CLOSE",
        );
        i = 1;
        while i < cc_wire.len {
            var cur_t: i64 = 0;
            let _, ok_t = quic::decode_frame_cursor(cc_wire[..i], cur_t);
            sub.assert_false(ok_t, "truncated transport CONNECTION_CLOSE rejected");
            i += 1;
        }
        var cur_cc: i64 = 0;
        let dec_cc, ok_cc = quic::decode_frame_cursor(cc_wire[..], cur_cc);
        sub.assert_true(ok_cc, "full transport CONNECTION_CLOSE decoded");
        sub.assert_eq(dec_cc.error_code, 0xF1F2, "close error_code matches");
        sub.assert_eq(dec_cc.payload, "tls handshake failure", "close reason matches");

        // 4. NEW_CONNECTION_ID: seq=1000000009, retire_prior_to=1000000007, 16B CID, 16B reset token
        var ncid_wire: u8[..64] = [];
        let cid16: u8[16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let srt16: u8[16] = [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF];
        sub.assert_true(
            quic::encode_new_conn_id_frame(1000000009, 1000000007, cid16[..], srt16, ncid_wire),
            "encode NEW_CONNECTION_ID",
        );
        i = 1;
        while i < ncid_wire.len {
            var cur_t: i64 = 0;
            let _, ok_t = quic::decode_frame_cursor(ncid_wire[..i], cur_t);
            sub.assert_false(ok_t, "truncated NEW_CONNECTION_ID rejected");
            i += 1;
        }
        var cur_ncid: i64 = 0;
        let dec_ncid, ok_ncid = quic::decode_frame_cursor(ncid_wire[..], cur_ncid);
        sub.assert_true(ok_ncid, "full NEW_CONNECTION_ID decoded");
        sub.assert_eq(dec_ncid.frame_type, quic::QuicFrameType.NewConnectionId, "frame_type is NewConnectionId");

        // Illegal NEW_CONNECTION_ID where retire_prior_to > seq MUST fail encoding and decoding
        var bad_ncid: u8[..64] = [];
        sub.assert_false(
            quic::encode_new_conn_id_frame(5, 10, cid16[..], srt16, bad_ncid),
            "NEW_CONNECTION_ID with retire_prior_to > seq rejected",
        );

        // 5. NEW_TOKEN empty token rejection & truncation loop
        var empty_nt: u8[..16] = [];
        sub.assert_false(quic::encode_new_token_frame("", empty_nt), "empty NEW_TOKEN rejected on encode");
        let raw_empty_nt: u8[2] = [0x07, 0x00]; // type 0x07, len 0
        var cur_ent: i64 = 0;
        let _, ok_ent = quic::decode_frame_cursor(raw_empty_nt[..], cur_ent);
        sub.assert_false(ok_ent, "0-length NEW_TOKEN rejected on decode per RFC 9000 §19.7");
    };

    t.run("NGTCP2-ACK-01: Multi-Range ACK Frame Codec & Truncation Loop (test_ngtcp2_pkt_encode_ack_frame)") { sub =>
        // Largest Acked = 0xF1F2F3F4, Ack Delay = 0xE1E2, First Range = 0xD1D2,
        // Range 1: Gap = 11, Len = 0xC1C2
        var ack = quic::AckFrame {
            is_ecn:          false,
            largest_acked:   0xF1F2F3F4,
            ack_delay:       0xE1E2,
            first_ack_range: 0xD1D2,
            ..
        };
        ack.ranges.push(quic::AckRange { gap: 11, ack_range: 0xC1C2 });

        var wire: u8[..64] = [];
        sub.assert_true(quic::encode_ack_frame(ack, wire), "encode multi-range ACK frame");

        var i: i64 = 1;
        while i < wire.len {
            let _, _, ok_t = quic::decode_ack_frame(wire[..i], 0);
            sub.assert_false(ok_t, "truncated multi-range ACK frame rejected");
            i += 1;
        }

        let dec, read_len, ok_dec = quic::decode_ack_frame(wire[..], 0);
        sub.assert_true(ok_dec, "full multi-range ACK frame decoded");
        sub.assert_eq(read_len as i64, wire.len, "consumed exact wire length");
        sub.assert_eq(dec.largest_acked, 0xF1F2F3F4, "largest_acked matches");
        sub.assert_eq(dec.ack_delay, 0xE1E2, "ack_delay matches");
        sub.assert_eq(dec.first_ack_range, 0xD1D2, "first_ack_range matches");
        sub.assert_eq(dec.ranges.len, 1, "1 additional ACK range decoded");
        sub.assert_eq(dec.ranges[0].gap, 11, "range 0 gap is 11");
        sub.assert_eq(dec.ranges[0].ack_range, 0xC1C2, "range 0 len is 0xC1C2");
    };
}

// 32. Ported Reassembly, ACK Interval Merging & Loss Recovery Vectors (vendor/ngtcp2/tests/ngtcp2_rob_test.c, ngtcp2_acktr_test.c, ngtcp2_rtb_test.c)
fn test_ngtcp2_conn_and_recovery_semantics(t: lit::T&) {
    t.run("NGTCP2-ROB-01: Reverse-Order & Overlapping Fragment Reassembly (ngtcp2_rob_test.c)") { sub =>
        var rbuf = quic::new_reassembly_buffer(65536);

        // Push 8 4-byte fragments in strictly reverse order: offsets 28, 24, 20, 16, 12, 8, 4
        let chunks: const u8[:][8] = ["0000", "1111", "2222", "3333", "4444", "5555", "6666", "7777"];
        var idx: i64 = 7;
        while idx >= 1 {
            let off = (idx * 4) as u64;
            let is_fin = idx == 7;
            sub.assert_true(quic::insert_fragment(rbuf, off, chunks[idx], is_fin), "insert reverse-order fragment");
            sub.assert_eq(rbuf.consumed_offset, 0, "cannot consume before offset 0 arrives");
            idx -= 1;
        }
        sub.assert_eq(rbuf.final_size, 32, "FIN recorded from last fragment at offset 28..32 (final_size is 32)");

        // Now deliver missing head fragment at offset 0 ("0000")
        sub.assert_true(quic::insert_fragment(rbuf, 0, chunks[0], false), "insert head fragment at offset 0");

        var assembled: u8[..64] = [];
        let n_read = quic::read_contiguous(rbuf, assembled);
        sub.assert_eq(n_read, 32, "all 32 bytes become contiguous once offset 0 arrives");
        sub.assert_eq(assembled[..], "00001111222233334444555566667777", "reassembled payload matches exact sequence");
        sub.assert_eq(rbuf.consumed_offset, 32, "consumed_offset advanced to 32");

        // Retransmitted / duplicate fragment below consumed_offset (offset 4, len 4) is accepted idempotently
        sub.assert_true(quic::insert_fragment(rbuf, 4, "1111", false), "duplicate old fragment below consumed_offset accepted");
        sub.assert_eq(rbuf.consumed_offset, 32, "consumed_offset unchanged at 32");

        // Conflicting FIN at offset 16 (final_size 20 != 32) must be rejected
        sub.assert_false(quic::insert_fragment(rbuf, 16, "4444", true), "conflicting FIN at offset 20 != 32 rejected");
    };

    t.run("NGTCP2-ACKTR-01: Comb-Pattern Gap Bridging & ACK Range Compaction (ngtcp2_acktr_test.c)") { sub =>
        var ranges: quic::AckInterval[..64] = [];

        // 1. Receive 10 even packet numbers: 0, 2, 4, 6, 8, 10, 12, 14, 16, 18 -> 10 separate 1-packet intervals
        var i: u64 = 0;
        while i < 10 {
            quic::record_received_pn(ranges, i * 2);
            i += 1;
        }
        sub.assert_eq(ranges.len, 10, "10 disjoint even packet intervals recorded");
        sub.assert_eq(ranges[0].largest, 18, "highest interval is [18..18]");
        sub.assert_eq(ranges[9].smallest, 0, "lowest interval is [0..0]");

        // 2. Fill all odd gaps: 1, 3, 5, 7, 9, 11, 13, 15, 17 -> must coalesce into a single interval [0..18]
        var j: u64 = 0;
        while j < 9 {
            quic::record_received_pn(ranges, j * 2 + 1);
            j += 1;
        }
        sub.assert_eq(ranges.len, 1, "all 10 intervals coalesced into 1 contiguous range");
        sub.assert_eq(ranges[0].smallest, 0, "coalesced range smallest is 0");
        sub.assert_eq(ranges[0].largest, 18, "coalesced range largest is 18");

        let ack_frame, ok_build = quic::build_ack_frame(ranges, 80, true);
        sub.assert_true(ok_build, "build_ack_frame from coalesced interval");
        sub.assert_eq(ack_frame.largest_acked, 18, "largest_acked is 18");
        sub.assert_eq(ack_frame.first_ack_range, 18, "first_ack_range covers [0..18]");
        sub.assert_eq(ack_frame.ranges.len, 0, "0 gap ranges after full coalescing");
    };

    t.run("NGTCP2-RTB-01: Packet Threshold & Time Threshold Loss Detection (ngtcp2_rtb_test.c & quinn)") { sub =>
        var space = quic::PnSpaceState {
            space_id:          quic::PnSpaceId.ApplicationData,
            has_acked_packets: true,
            largest_acked_pn:  20,
            ..
        };
        // Send packets PN 15..19 at t = 10_000 us
        var pn: u64 = 15;
        while pn < 20 {
            space.sent_packets.push(quic::SentPacketMeta {
                pn:            pn,
                time_sent_us:  10000,
                ack_eliciting: true,
                in_flight:     true,
            });
            pn += 1;
        }
        var rtt = quic::RttState {
            smoothed_rtt_us: 40000,
            latest_rtt_us:   40000,
            rttvar_us:       10000,
            ..
        };

        // At t = 20_000 us (elapsed 10ms < time_threshold 45ms):
        // Only packets with largest_acked (20) >= pn + 3 (i.e. PN 15, 16, 17) are lost by packet threshold!
        // PN 18 and 19 remain in flight and arm loss_time_us.
        var lost1: quic::SentPacketMeta[..64] = [];
        quic::detect_lost_packets(space, rtt, 20000, lost1);
        sub.assert_eq(lost1.len, 3, "PN 15, 16, 17 declared lost by kPacketThreshold=3");
        sub.assert_eq(lost1[0].pn, 15, "lost[0] is PN 15");
        sub.assert_eq(lost1[1].pn, 16, "lost[1] is PN 16");
        sub.assert_eq(lost1[2].pn, 17, "lost[2] is PN 17");
        sub.assert_true(space.loss_time_us > 0, "loss_time_us armed for remaining unacked PN 18, 19");

        // At t = 60_000 us (elapsed 50ms >= 9/8 * 40ms = 45ms):
        // Remaining PN 18 and 19 are declared lost by time threshold!
        var lost2: quic::SentPacketMeta[..64] = [];
        quic::detect_lost_packets(space, rtt, 60000, lost2);
        sub.assert_eq(lost2.len, 2, "PN 18 and 19 declared lost by kTimeThreshold (9/8 RTT)");
        sub.assert_eq(lost2[0].pn, 18, "lost2[0] is PN 18");
        sub.assert_eq(lost2[1].pn, 19, "lost2[1] is PN 19");
    };

    t.run("NGTCP2-PKT-02: Packet Number Reconstruction Wrap-Around & RFC 9000 Table 3 Frame Matrix (ngtcp2_pkt_test.c)") { sub =>
        // 1. test_ngtcp2_pkt_adjust_pkt_num (ngtcp2_pkt_test.c & RFC 9000 Appendix A.3):
        // RFC 9000 A.3 vector: largest_acked = 0xa82f30ea, truncated = 0x9b32 (16-bit) -> 0xa82f9b32
        let pn_a3, ok_a3 = quic::decode_packet_number_checked(0xa82f30ea, 0x9b32, 2);
        sub.assert_true(ok_a3, "RFC 9000 A.3 PN reconstruction ok");
        sub.assert_eq(pn_a3, 0xa82f9b32, "reconstructed 0xa82f9b32");

        // Window wrap-around upward: largest_acked = 0x00ff, truncated = 0x01 (8-bit) -> 0x0101
        let pn_up, ok_up = quic::decode_packet_number_checked(0x00ff, 0x01, 1);
        sub.assert_true(ok_up, "8-bit upward wrap-around ok");
        sub.assert_eq(pn_up, 0x0101, "0x00ff + 0x01 (8-bit) -> 0x0101");

        // Window wrap-around downward: largest_acked = 0x0100, truncated = 0xff (8-bit) -> 0x00ff
        let pn_dn, ok_dn = quic::decode_packet_number_checked(0x0100, 0xff, 1);
        sub.assert_true(ok_dn, "8-bit downward wrap-around ok");
        sub.assert_eq(pn_dn, 0x00ff, "0x0100 + 0xff (8-bit) -> 0x00ff");

        // Boundary at QUIC_MAX_PN (2^62 - 1 = 0x3fffffffffffffff)
        let pn_max, ok_max = quic::decode_packet_number_checked(0x3ffffffffffffff0, 0xff, 1);
        sub.assert_true(ok_max, "PN at QUIC_MAX_PN (2^62 - 1) valid");
        sub.assert_eq(pn_max, 0x3fffffffffffffff, "reconstructed 2^62 - 1");

        // Boundary clamp at (1 << 62) - pn_win (RFC 9000 Appendix A.3 & test_ngtcp2_pkt_adjust_pkt_num):
        // largest_acked = 0x3ffffffffffffff0, truncated = 0x00 (8-bit) does NOT wrap to 2^62; stays at 0x3fffffffffffff00
        let pn_clamp, ok_clamp = quic::decode_packet_number_checked(0x3ffffffffffffff0, 0x00, 1);
        sub.assert_true(ok_clamp, "PN near 2^62 clamps below 2^62 per RFC 9000 A.3");
        sub.assert_eq(pn_clamp, 0x3fffffffffffff00, "clamped to 0x3fffffffffffff00 instead of 2^62");

        // Overflow past QUIC_MAX_PN when largest_acked == QUIC_MAX_PN (2^62 - 1) and truncated = 0x80 -> rejected
        let _, ok_ovf = quic::decode_packet_number_checked(0x3fffffffffffffff, 0x80, 1);
        sub.assert_false(ok_ovf, "PN exceeding QUIC_MAX_PN (2^62 - 1) rejected");

        // 2. RFC 9000 §12.5 Table 3 frame-in-packet matrix
        sub.assert_true(
            quic::is_frame_allowed_in_packet(quic::QuicFrameType.Crypto, quic::QuicHeaderType.Initial),
            "CRYPTO allowed in Initial",
        );
        sub.assert_false(
            quic::is_frame_allowed_in_packet(quic::QuicFrameType.Stream, quic::QuicHeaderType.Initial),
            "STREAM forbidden in Initial",
        );
        sub.assert_false(
            quic::is_frame_allowed_in_packet(quic::QuicFrameType.ConnectionCloseApp, quic::QuicHeaderType.Handshake),
            "APPLICATION_CLOSE (0x1D) forbidden in Handshake",
        );
        sub.assert_true(
            quic::is_frame_allowed_in_packet(quic::QuicFrameType.Stream, quic::QuicHeaderType.ZeroRtt),
            "STREAM allowed in 0-RTT",
        );
        sub.assert_false(
            quic::is_frame_allowed_in_packet(quic::QuicFrameType.Ack, quic::QuicHeaderType.ZeroRtt),
            "ACK forbidden in 0-RTT",
        );
        sub.assert_false(
            quic::is_frame_allowed_in_packet(quic::QuicFrameType.Crypto, quic::QuicHeaderType.ZeroRtt),
            "CRYPTO forbidden in 0-RTT",
        );
        sub.assert_false(
            quic::is_frame_allowed_in_packet(quic::QuicFrameType.HandshakeDone, quic::QuicHeaderType.ZeroRtt),
            "HANDSHAKE_DONE forbidden in 0-RTT",
        );
        sub.assert_false(
            quic::is_frame_allowed_in_packet(quic::QuicFrameType.Ping, quic::QuicHeaderType.Retry),
            "all frames forbidden in Retry packet",
        );
    };
}

// --- Component: ngtcp2_and_quinn_connection_dynamics ---
// Ported end-to-end connection lifecycle, multi-space recovery, stream directionality,
// coalesced encryption, and PTO/BBRv3 test vectors from vendor/ngtcp2/tests/ngtcp2_conn_test.c,
// ngtcp2_rtb_test.c, ngtcp2_acktr_test.c, and vendor/quinn/quinn-proto/src/connection/:
// ----------------------------------------------------------------------------
// 33. ngtcp2 & quinn Connection Lifecycle, Stream Polarity & BBRv3/PTO
// ----------------------------------------------------------------------------
fn test_ngtcp2_and_quinn_connection_dynamics(t: lit::T&) {
    t.run("QUINN-CONN-01: Coalesced Encrypted Datagrams (Initial + Handshake + 1-RTT) & Cipher Matrix") { sub =>
        let orig_dcid: u8[8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        let cli_scid:  u8[4] = [0xC1, 0xC2, 0xC3, 0xC4];
        var cli = quic::new_client_connection(orig_dcid[..], cli_scid[..]);
        var srv = quic::new_server_connection(orig_dcid[..]);

        // Install Initial keys (AES-128-GCM) + Handshake keys (ChaCha20-Poly1305) + 1-RTT keys (AES-256-GCM)
        sub.assert_true(quic::install_initial_keys(cli, orig_dcid[..]), "cli initial keys");
        sub.assert_true(quic::install_initial_keys(srv, orig_dcid[..]), "srv initial keys");

        let hs_hp:   u8[32] = [0x21; 32];
        let hs_key:  u8[32] = [0x22; 32];
        let hs_iv:   u8[12] = [0x23; 12];
        let app_hp:  u8[32] = [0x31; 32];
        let app_key: u8[32] = [0x32; 32];
        let app_iv:  u8[12] = [0x33; 12];

        sub.assert_true(
            quic::install_keys(cli.tx_handshake_space, hs_hp[..], hs_key[..], hs_iv[..], rfc::TLS_CIPHER_CHACHA20_POLY1305_SHA256),
            "cli tx handshake keys (ChaCha20-Poly1305)",
        );
        sub.assert_true(
            quic::install_keys(srv.handshake_space, hs_hp[..], hs_key[..], hs_iv[..], rfc::TLS_CIPHER_CHACHA20_POLY1305_SHA256),
            "srv rx handshake keys (ChaCha20-Poly1305)",
        );
        sub.assert_true(
            quic::install_keys(cli.tx_app_space, app_hp[..], app_key[..], app_iv[..], rfc::TLS_CIPHER_AES_256_GCM_SHA384),
            "cli tx 1-RTT keys (AES-256-GCM)",
        );
        sub.assert_true(
            quic::install_keys(srv.app_space, app_hp[..], app_key[..], app_iv[..], rfc::TLS_CIPHER_AES_256_GCM_SHA384),
            "srv rx 1-RTT keys (AES-256-GCM)",
        );

        // Build a single coalesced UDP datagram containing:
        //   [Packet 1: Encrypted Initial (CRYPTO "CH")] +
        //   [Packet 2: Encrypted Handshake (CRYPTO "FIN")] +
        //   [Packet 3: Encrypted 1-RTT Short Header (STREAM 0 "GET /") padded to >=1200 total]
        var coalesced: u8[..1500] = [];

        // 1. Seal Initial packet
        var plain_init: u8[..64] = [];
        sub.assert_true(quic::encode_crypto_frame(0, "CH-Flight", plain_init), "encode Initial CRYPTO");
        var hdr_init = quic::QuicHeader {
            header_type:   quic::QuicHeaderType.Initial,
            version:       rfc::QUIC_VERSION_1,
            packet_number: 0,
            ..
        };
        hdr_init.dcid.append(orig_dcid[..]);
        hdr_init.scid.append(cli_scid[..]);
        var pkt_init: u8[..256] = [];
        sub.assert_true(quic::seal_packet(cli.tx_initial_space, hdr_init, 2, plain_init[..], pkt_init), "seal Initial");
        coalesced.append(pkt_init[..]);

        // 2. Seal Handshake packet (ChaCha20-Poly1305)
        var plain_hs: u8[..64] = [];
        sub.assert_true(quic::encode_crypto_frame(0, "ClientFinished", plain_hs), "encode Handshake CRYPTO");
        var hdr_hs = quic::QuicHeader {
            header_type:   quic::QuicHeaderType.Handshake,
            version:       rfc::QUIC_VERSION_1,
            packet_number: 0,
            ..
        };
        hdr_hs.dcid.append(orig_dcid[..]);
        hdr_hs.scid.append(cli_scid[..]);
        var pkt_hs: u8[..256] = [];
        sub.assert_true(quic::seal_packet(cli.tx_handshake_space, hdr_hs, 2, plain_hs[..], pkt_hs), "seal Handshake");
        coalesced.append(pkt_hs[..]);

        // 3. Seal 1-RTT Short Header packet (AES-256-GCM), padded so total coalesced datagram >= 1200 bytes
        var plain_app: u8[..1200] = [];
        sub.assert_true(
            quic::encode_stream_frame(0, 0, "GET /index.html", plain_app, quic::QuicStreamFlags { fin: true, with_len: true }),
            "encode 1-RTT STREAM 0",
        );
        sub.assert_true(quic::encode_padding_frame(plain_app, 1100), "pad 1-RTT payload");
        var hdr_app = quic::QuicHeader {
            header_type:   quic::QuicHeaderType.OneRtt,
            packet_number: 0,
            ..
        };
        hdr_app.dcid.append(orig_dcid[..]);
        var pkt_app: u8[..1300] = [];
        sub.assert_true(quic::seal_packet(cli.tx_app_space, hdr_app, 2, plain_app[..], pkt_app), "seal 1-RTT Short");
        coalesced.append(pkt_app[..]);
        sub.assert_true(coalesced.len >= 1200, "coalesced UDP datagram >= 1200 bytes");

        var ack_out = quic::AckFrame { .. };
        let _pr_ok_coal = quic::process_datagram(srv, coalesced[..], 10000, ack_out);
        let ok_coal = _pr_ok_coal.handled;
        let needs_ack = _pr_ok_coal.needs_ack;
        sub.assert_true(ok_coal, "server processed 3-packet coalesced encrypted datagram");
        sub.assert_true(needs_ack, "coalesced datagram is ACK-eliciting");
        sub.assert_true(srv.validated_address, "peer address implicitly validated by Handshake/1-RTT packet");
        sub.assert_true(srv.state == quic::QuicConnState.Established, "connection transitioned Initial -> Handshake -> Established");
        sub.assert_eq(srv.dcid[..], cli_scid[..], "server learned peer SCID as its outbound DCID");
        sub.assert_eq(srv.initial_crypto.buf[..], "CH-Flight", "Initial CRYPTO stream reassembled");
        sub.assert_eq(srv.handshake_crypto.buf[..], "ClientFinished", "Handshake CRYPTO stream reassembled");

        let _fs_st0_idx_idx, _fs_st0_idx_ok = quic::find_stream(srv.stream_table, 0);
        let st0_idx = if _fs_st0_idx_ok { _fs_st0_idx_idx } else { -1 };
        sub.assert_true(st0_idx >= 0, "stream 0 opened from 1-RTT packet");
        sub.assert_eq(srv.stream_table.streams[st0_idx as i64].bytes_recv, 15, "stream 0 received 15 bytes");
        sub.assert_true(
            srv.stream_table.streams[st0_idx as i64].recv_state == quic::QuicRecvState.DataRecvd,
            "stream 0 transitioned to DataRecvd on FIN",
        );

        // Wrong DCID on Server Short header must be rejected (payload >= 4 bytes for 16B HP sample)
        var wrong_hdr = quic::QuicHeader {
            header_type:   quic::QuicHeaderType.OneRtt,
            packet_number: 1,
            ..
        };
        let bad_dcid: u8[8] = [0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99];
        wrong_hdr.dcid.append(bad_dcid[..]);
        var wrong_pkt: u8[..128] = [];
        sub.assert_true(quic::seal_packet(cli.tx_app_space, wrong_hdr, 2, "0123", wrong_pkt), "seal wrong DCID pkt");
        let _pr_ok_wrong = quic::process_datagram(srv, wrong_pkt[..], 11000, ack_out);
        let ok_wrong = _pr_ok_wrong.handled;
        sub.assert_false(ok_wrong, "Short header with mismatched DCID rejected by server");
    };

    t.run("QUINN-CONN-02: Out-of-Order STREAM + Early FIN + Conflicting RESET_STREAM Final-Size Guard (RFC 9000 §4.5)") { sub =>
        let scid: u8[4] = [0x10, 0x20, 0x30, 0x40];
        var srv = quic::new_server_connection(scid[..]);
        var ack_out = quic::AckFrame { .. };

        // 1. Arrive out-of-order tail fragment [offset=10, len=5, fin=true] -> establishes final_size = 15 (SizeKnown)
        var dgram1: u8[..64] = [];
        dgram1.push(0x40);
        dgram1.append(scid[..]);
        dgram1.push(0x01);
        sub.assert_true(
            quic::encode_stream_frame(0, 10, "KLMNO", dgram1, quic::QuicStreamFlags { fin: true, with_len: true }),
            "encode tail FIN fragment at offset 10..15",
        );
        let _pr_ok1 = quic_internal::process_unencrypted_test_datagram(srv, dgram1[..], 1000, ack_out);
        let ok1 = _pr_ok1.handled;
        sub.assert_true(ok1, "tail FIN fragment accepted");
        let _fs_idx_idx, _fs_idx_ok = quic::find_stream(srv.stream_table, 0);
        let idx = if _fs_idx_ok { _fs_idx_idx } else { -1 };
        sub.assert_true(idx >= 0, "stream 0 created");
        sub.assert_true(
            srv.stream_table.streams[idx as i64].recv_state == quic::QuicRecvState.SizeKnown,
            "stream 0 in SizeKnown (missing 0..10)",
        );
        sub.assert_eq(srv.stream_table.streams[idx as i64].recv_final_size, 15, "recv_final_size locked at 15");
        sub.assert_eq(srv.flow_ctrl.bytes_recv_total, 15, "flow control committed 15 bytes");

        // 2. Arrive middle fragment [offset=5, len=5, fin=false] -> still SizeKnown (missing 0..5)
        var dgram2: u8[..64] = [];
        dgram2.push(0x40);
        dgram2.append(scid[..]);
        dgram2.push(0x02);
        sub.assert_true(
            quic::encode_stream_frame(0, 5, "FGHIJ", dgram2, quic::QuicStreamFlags { fin: false, with_len: true }),
            "encode middle fragment 5..10",
        );
        let _pr_ok2 = quic_internal::process_unencrypted_test_datagram(srv, dgram2[..], 1010, ack_out);
        let ok2 = _pr_ok2.handled;
        sub.assert_true(ok2, "middle fragment accepted");
        sub.assert_true(
            srv.stream_table.streams[idx as i64].recv_state == quic::QuicRecvState.SizeKnown,
            "still SizeKnown until head arrives",
        );

        // 3. Conflicting RESET_STREAM with final_size = 25 (!= 15) when max_data_local = 20:
        //    Must fail with QUIC_ERR_FINAL_SIZE (0x06), NOT QUIC_ERR_FLOW_CONTROL (0x03),
        //    and MUST NOT corrupt srv.flow_ctrl.bytes_recv_total!
        var srv_conflict = srv;
        srv_conflict.flow_ctrl.max_data_local = 20;
        var dgram_bad_rst: u8[..64] = [];
        dgram_bad_rst.push(0x40);
        dgram_bad_rst.append(scid[..]);
        dgram_bad_rst.push(0x03);
        sub.assert_true(
            quic::encode_reset_stream_frame(0, 0x42, 25, dgram_bad_rst),
            "encode conflicting RESET_STREAM final_size=25",
        );
        let _pr_ok_bad_rst = quic_internal::process_unencrypted_test_datagram(srv_conflict, dgram_bad_rst[..], 1020, ack_out);
        let ok_bad_rst = _pr_ok_bad_rst.handled;
        sub.assert_false(ok_bad_rst, "conflicting RESET_STREAM final_size=25 (!= 15) rejected");
        sub.assert_eq(
            srv_conflict.close_code,
            rfc::QUIC_ERR_FINAL_SIZE,
            "closed with FINAL_SIZE_ERROR (0x06), not FLOW_CONTROL_ERROR",
        );
        sub.assert_eq(srv_conflict.flow_ctrl.bytes_recv_total, 15, "bytes_recv_total uncorrupted on rejected RESET_STREAM");

        // 4. Conflicting STREAM frame exceeding established FIN [offset=12, len=5 -> end=17 > 15] -> FINAL_SIZE_ERROR
        var srv_past_fin = srv;
        var dgram_past: u8[..64] = [];
        dgram_past.push(0x40);
        dgram_past.append(scid[..]);
        dgram_past.push(0x03);
        sub.assert_true(
            quic::encode_stream_frame(0, 12, "PQRST", dgram_past, quic::QuicStreamFlags { fin: false, with_len: true }),
            "encode STREAM past established FIN",
        );
        let _pr_ok_past = quic_internal::process_unencrypted_test_datagram(srv_past_fin, dgram_past[..], 1020, ack_out);
        let ok_past = _pr_ok_past.handled;
        sub.assert_false(ok_past, "STREAM past established final_size rejected");
        sub.assert_eq(srv_past_fin.close_code, rfc::QUIC_ERR_FINAL_SIZE, "closed with FINAL_SIZE_ERROR (0x06)");

        // 5. Deliver missing head fragment [offset=0, len=5, fin=false] on valid connection -> transitions SizeKnown -> DataRecvd!
        var dgram3: u8[..64] = [];
        dgram3.push(0x40);
        dgram3.append(scid[..]);
        dgram3.push(0x03);
        sub.assert_true(
            quic::encode_stream_frame(0, 0, "ABCDE", dgram3, quic::QuicStreamFlags { fin: false, with_len: true }),
            "encode head fragment 0..5",
        );
        let _pr_ok3 = quic_internal::process_unencrypted_test_datagram(srv, dgram3[..], 1030, ack_out);
        let ok3 = _pr_ok3.handled;
        sub.assert_true(ok3, "head fragment 0..5 accepted");
        sub.assert_true(
            srv.stream_table.streams[idx as i64].recv_state == quic::QuicRecvState.DataRecvd,
            "stream 0 transitioned SizeKnown -> DataRecvd once all 15 bytes arrived",
        );

        sub.assert_eq(
            srv.stream_table.streams[idx as i64].contiguous_recv_bytes,
            15,
            "all 15 bytes contiguous in stream recv_ranges",
        );
        sub.assert_eq(srv.stream_table.streams[idx as i64].recv_ranges.len, 1, "recv_ranges coalesced into 1 interval [0..15]");
        sub.assert_true(
            quic::on_app_read(srv.stream_table.streams[idx as i64], 15),
            "app read transitions DataRecvd -> DataRead",
        );
        sub.assert_true(
            srv.stream_table.streams[idx as i64].recv_state == quic::QuicRecvState.DataRead,
            "terminal state is DataRead",
        );
    };

    t.run("NGTCP2-CONN-03: Stream Directionality & Role Polarity Matrix (RFC 9000 §19.4, §19.5, §19.8, §19.10, §19.13)") { sub =>
        let scid: u8[4] = [0xAA, 0xBB, 0xCC, 0xDD];
        var ack_out = quic::AckFrame { .. };

        // Case A: Server receives STREAM on Server-Initiated Uni stream (ID 3) -> STREAM_STATE_ERROR (cannot receive on send-only stream)
        var srv_a = quic::new_server_connection(scid[..]);
        let sid_a, _, ok_open_s3 = quic::open_local_stream(srv_a.stream_table, false);
        sub.assert_true(ok_open_s3, "server opens its own Uni stream 3");
        sub.assert_eq(sid_a, 3, "server local Uni stream ID is 3");
        var d_s3: u8[..64] = [];
        d_s3.push(0x40);
        d_s3.append(scid[..]);
        d_s3.push(0x01);
        quic::encode_stream_frame(3, 0, "illegal", d_s3, quic::QuicStreamFlags { fin: false, with_len: true });
        let _pr_ok_a = quic_internal::process_unencrypted_test_datagram(srv_a, d_s3[..], 1000, ack_out);
        let ok_a = _pr_ok_a.handled;
        sub.assert_false(ok_a, "Server rejects inbound STREAM on Server-Uni stream 3");
        sub.assert_eq(srv_a.close_code, rfc::QUIC_ERR_STREAM_STATE, "STREAM_STATE_ERROR (0x05)");

        // Case B: Server receives STREAM on unopened Server-Initiated Bidi stream (ID 1) -> STREAM_STATE_ERROR
        var srv_b = quic::new_server_connection(scid[..]);
        var d_s1: u8[..64] = [];
        d_s1.push(0x40);
        d_s1.append(scid[..]);
        d_s1.push(0x01);
        quic::encode_stream_frame(1, 0, "unopened-local", d_s1, quic::QuicStreamFlags { fin: false, with_len: true });
        let _pr_ok_b = quic_internal::process_unencrypted_test_datagram(srv_b, d_s1[..], 1000, ack_out);
        let ok_b = _pr_ok_b.handled;
        sub.assert_false(ok_b, "Server rejects inbound STREAM on unopened local Bidi stream 1");
        sub.assert_eq(srv_b.close_code, rfc::QUIC_ERR_STREAM_STATE, "STREAM_STATE_ERROR (0x05)");

        // Case C: Server receives STOP_SENDING on Client-Initiated Uni stream (ID 2, recv-only for server) -> STREAM_STATE_ERROR
        var srv_c = quic::new_server_connection(scid[..]);
        var d_ss2: u8[..64] = [];
        d_ss2.push(0x40);
        d_ss2.append(scid[..]);
        d_ss2.push(0x01);
        quic::encode_stop_sending_frame(2, 0x01, d_ss2);
        let _pr_ok_c = quic_internal::process_unencrypted_test_datagram(srv_c, d_ss2[..], 1000, ack_out);
        let ok_c = _pr_ok_c.handled;
        sub.assert_false(ok_c, "Server rejects STOP_SENDING on Client-Uni stream 2 (server has no send side)");
        sub.assert_eq(srv_c.close_code, rfc::QUIC_ERR_STREAM_STATE, "STREAM_STATE_ERROR (0x05)");

        // Case D: Server receives MAX_STREAM_DATA on Client-Initiated Uni stream (ID 2) -> STREAM_STATE_ERROR
        var srv_d = quic::new_server_connection(scid[..]);
        var d_msd2: u8[..64] = [];
        d_msd2.push(0x40);
        d_msd2.append(scid[..]);
        d_msd2.push(0x01);
        quic::encode_max_stream_data_frame(2, 65536, d_msd2);
        let _pr_ok_d = quic_internal::process_unencrypted_test_datagram(srv_d, d_msd2[..], 1000, ack_out);
        let ok_d = _pr_ok_d.handled;
        sub.assert_false(ok_d, "Server rejects MAX_STREAM_DATA on recv-only Client-Uni stream 2");
        sub.assert_eq(srv_d.close_code, rfc::QUIC_ERR_STREAM_STATE, "STREAM_STATE_ERROR (0x05)");

        // Case E: Server receives STREAM_DATA_BLOCKED on Server-Initiated Uni stream (ID 3) -> STREAM_STATE_ERROR
        var srv_e = quic::new_server_connection(scid[..]);
        let _, _, _ = quic::open_local_stream(srv_e.stream_table, false);
        var d_sdb3: u8[..64] = [];
        d_sdb3.push(0x40);
        d_sdb3.append(scid[..]);
        d_sdb3.push(0x01);
        quic::encode_stream_data_blocked_frame(3, 1024, d_sdb3);
        let _pr_ok_e = quic_internal::process_unencrypted_test_datagram(srv_e, d_sdb3[..], 1000, ack_out);
        let ok_e = _pr_ok_e.handled;
        sub.assert_false(ok_e, "Server rejects STREAM_DATA_BLOCKED on send-only Server-Uni stream 3");
        sub.assert_eq(srv_e.close_code, rfc::QUIC_ERR_STREAM_STATE, "STREAM_STATE_ERROR (0x05)");

        // Case F: Client connection receives STREAM on Server-Initiated Uni stream (ID 3) -> VALID!
        var cli_f = quic::new_client_connection(scid[..], scid[..]);
        var d_cli3: u8[..64] = [];
        d_cli3.push(0x40);
        d_cli3.append(scid[..]);
        d_cli3.push(0x01);
        quic::encode_stream_frame(3, 0, "server-push-uni", d_cli3, quic::QuicStreamFlags { fin: true, with_len: true });
        let _pr_ok_f = quic_internal::process_unencrypted_test_datagram(cli_f, d_cli3[..], 1000, ack_out);
        let ok_f = _pr_ok_f.handled;
        sub.assert_true(ok_f, "Client accepts inbound STREAM on Server-Uni stream 3");

        // Case G: Client connection receives RESET_STREAM on Client-Initiated Uni stream (ID 2) -> STREAM_STATE_ERROR
        var cli_g = quic::new_client_connection(scid[..], scid[..]);
        let _, _, _ = quic::open_local_stream(cli_g.stream_table, false);
        var d_rst2: u8[..64] = [];
        d_rst2.push(0x40);
        d_rst2.append(scid[..]);
        d_rst2.push(0x02);
        quic::encode_reset_stream_frame(2, 0x01, 0, d_rst2);
        let _pr_ok_g = quic_internal::process_unencrypted_test_datagram(cli_g, d_rst2[..], 1010, ack_out);
        let ok_g = _pr_ok_g.handled;
        sub.assert_false(ok_g, "Client rejects inbound RESET_STREAM on its own send-only Uni stream 2");
        sub.assert_eq(cli_g.close_code, rfc::QUIC_ERR_STREAM_STATE, "STREAM_STATE_ERROR (0x05)");
    };

    t.run("NGTCP2-CONN-04: Multi-Space Loss Recovery, RTT Clamping & BBRv3 Round-Trip Gating (ngtcp2_rtb_test.c)") { sub =>
        let scid: u8[4] = [0x51, 0x52, 0x53, 0x54];
        var conn = quic::new_server_connection(scid[..]);
        conn.state = quic::QuicConnState.Established;

        // Force BBR out of Startup into Drain so we can verify round_done gating on cycle transitions
        conn.bbr.mode = quic::BbrMode.Drain;
        conn.bbr.bw_hi_bps = 100000000; // 100 Mbps
        conn.bbr.min_rtt_us = 20000;    // 20 ms

        // Send 3 packets in ApplicationData space: PN 0, PN 1, PN 2 at t = 10_000 us
        quic::record_sent(conn, quic::PnSpaceId.ApplicationData, 0, 1200, true, 10000);
        quic::record_sent(conn, quic::PnSpaceId.ApplicationData, 1, 1200, true, 10000);
        quic::record_sent(conn, quic::PnSpaceId.ApplicationData, 2, 1200, true, 10000);
        sub.assert_eq(conn.app_space.largest_sent_pn, 2, "largest_sent_pn is 2");

        // 1. Partial ACK for PN 0 only (largest_acked_pn = 0 < largest_sent_pn = 2 -> round_done == false):
        //    BBR must stay in Drain because the round trip has not completed!
        let ack_partial = quic::AckFrame {
            is_ecn:          false,
            largest_acked:   0,
            ack_delay:       100, // 800 us
            first_ack_range: 0,
            ..
        };
        sub.assert_true(
            quic::on_ack(conn, ack_partial, 30000, quic::PnSpaceId.ApplicationData),
            "process partial ACK for PN 0",
        );
        sub.assert_eq(conn.rtt.latest_rtt_us, 20000, "latest_rtt_us is 20ms");
        sub.assert_eq(conn.rtt.min_rtt_us, 20000, "min_rtt_us initialized to 20ms");
        sub.assert_true(
            conn.bbr.mode == quic::BbrMode.Drain,
            "BBR remains in Drain on partial ACK (round_done == false)",
        );

        // 2. Full ACK covering PN 2 (largest_acked_pn = 2 >= largest_sent_pn = 2 -> round_done == true):
        //    BBR advances Drain -> ProbeBwCruise!
        let ack_full = quic::AckFrame {
            is_ecn:          false,
            largest_acked:   2,
            ack_delay:       100,
            first_ack_range: 2,
            ..
        };
        sub.assert_true(
            quic::on_ack(conn, ack_full, 35000, quic::PnSpaceId.ApplicationData),
            "process full ACK up to PN 2",
        );
        sub.assert_true(
            conn.bbr.mode == quic::BbrMode.ProbeBwCruise,
            "BBR advanced Drain -> ProbeBwCruise once round_done == true",
        );

        // 3. ECN-CE congestion signal on PN 3 updates ecn_alpha_scaled and reduces cwnd without being overwritten
        let cwnd_before_ecn = conn.bbr.cwnd_bytes;
        quic::record_sent(conn, quic::PnSpaceId.ApplicationData, 3, 12000, true, 40000);
        let ack_ecn = quic::AckFrame {
            is_ecn:          true,
            largest_acked:   3,
            ack_delay:       0,
            first_ack_range: 0,
            ecn_ce_count:    2,
            ..
        };
        sub.assert_true(
            quic::on_ack(conn, ack_ecn, 60000, quic::PnSpaceId.ApplicationData),
            "process ECN-CE ACK for PN 3",
        );
        sub.assert_true(conn.bbr.ecn_alpha_scaled > 0, "ECN-CE updated ecn_alpha_scaled");
        sub.assert_true(
            conn.bbr.cwnd_bytes < cwnd_before_ecn,
            "ECN-CE reduced cwnd_bytes (preserved after update_bbr_on_ack)",
        );

        // 4. Packet-threshold loss (>2% loss rate: PN 4 lost when PN 7 acked) transitions ProbeBwCruise -> ProbeBwDown
        quic::record_sent(conn, quic::PnSpaceId.ApplicationData, 4, 12000, true, 65000);
        quic::record_sent(conn, quic::PnSpaceId.ApplicationData, 5, 1200, true, 65000);
        quic::record_sent(conn, quic::PnSpaceId.ApplicationData, 6, 1200, true, 65000);
        quic::record_sent(conn, quic::PnSpaceId.ApplicationData, 7, 1200, true, 65000);
        let ack_loss = quic::AckFrame {
            is_ecn:          false,
            largest_acked:   7,
            ack_delay:       0,
            first_ack_range: 2, // ACKs PN 5, 6, 7 -> PN 4 is lost by kPacketThreshold=3!
            ..
        };
        sub.assert_true(
            quic::on_ack(conn, ack_loss, 85000, quic::PnSpaceId.ApplicationData),
            "process ACK for PN 5..7 triggering loss of PN 4",
        );
        sub.assert_true(
            conn.bbr.mode == quic::BbrMode.ProbeBwDown,
            ">2% packet loss signal transitioned BBR from ProbeBwCruise to ProbeBwDown",
        );
    };

    t.run("NGTCP2-CONN-05: 5-Priority PTO & Loss Timer Matrix Across Spaces (RFC 9002 §6.2)") { sub =>
        let scid: u8[4] = [0x61, 0x62, 0x63, 0x64];
        var srv = quic::new_server_connection(scid[..]);

        // 1. Client with 0 in-flight before address validation -> AntiDeadlock armed
        var spaces_cli: quic::PnSpaceState[3] = [
            srv.initial_space,
            srv.handshake_space,
            srv.app_space,
        ];
        let t_deadlock = quic::evaluate_pto_timer(
            spaces_cli,
            srv.rtt,
            0,
            50000,
            quic::PtoContext {
                is_server:                      false,
                is_amplification_limited:       false,
                peer_completed_addr_validation: false,
                handshake_confirmed:            false,
            },
        );
        sub.assert_true(
            t_deadlock.mode == quic::PtoTimerMode.AntiDeadlock,
            "Client with 0 in-flight before address validation arms AntiDeadlock timer",
        );
        sub.assert_true(t_deadlock.target_time_us > 50000, "AntiDeadlock deadline in the future");

        // 2. Server at 3x anti-amplification limit before address validation -> AntiAmplification
        let t_amp = quic::evaluate_pto_timer(
            spaces_cli,
            srv.rtt,
            0,
            10000,
            quic::PtoContext {
                is_server:                true,
                is_amplification_limited: true,
            },
        );
        sub.assert_true(
            t_amp.mode == quic::PtoTimerMode.AntiAmplification,
            "Server at 3x limit before address validation returns AntiAmplification",
        );

        // 3. Explicit loss_time_us in Handshake space preempts PTO -> Priority 1 LossTime
        quic::record_sent(srv, quic::PnSpaceId.Handshake, 0, 1200, true, 12000);
        srv.handshake_space.loss_time_us = 18000;
        var spaces_srv: quic::PnSpaceState[3] = [
            srv.initial_space,
            srv.handshake_space,
            srv.app_space,
        ];
        let t_loss = quic::evaluate_pto_timer(
            spaces_srv,
            srv.rtt,
            0,
            15000,
            quic::PtoContext {
                is_server:                      true,
                peer_completed_addr_validation: true,
            },
        );
        sub.assert_true(
            t_loss.mode == quic::PtoTimerMode.LossTime,
            "Armed loss_time_us takes Priority 1 (LossTime) over PTO",
        );
        sub.assert_eq(t_loss.target_time_us, 18000, "LossTime deadline matches earliest loss_time_us (18000)");
        sub.assert_true(t_loss.space_id == quic::PnSpaceId.Handshake, "LossTime space is Handshake");

        // 4. ClearInitial & Handshake in-flight; ApplicationData in-flight is ignored BEFORE handshake_confirmed
        srv.handshake_space.loss_time_us = 0;
        srv.handshake_space.sent_packets.clear();
        quic::record_sent(srv, quic::PnSpaceId.ApplicationData, 0, 1200, true, 11000);
        var spaces_unconf: quic::PnSpaceState[3] = [
            srv.initial_space,
            srv.handshake_space,
            srv.app_space,
        ];
        let t_unconf = quic::evaluate_pto_timer(
            spaces_unconf,
            srv.rtt,
            0,
            15000,
            quic::PtoContext {
                is_server:                      true,
                peer_completed_addr_validation: true,
                handshake_confirmed:            false,
            },
        );
        sub.assert_true(
            t_unconf.mode == quic::PtoTimerMode.None,
            "ApplicationData PTO ignored before handshake_confirmed (RFC 9002 §6.2.1)",
        );

        // 5. Once handshake_confirmed = true, ApplicationData arms StandardPto with 2^pto_count backoff
        let t_std0 = quic::evaluate_pto_timer(
            spaces_unconf,
            srv.rtt,
            0,
            15000,
            quic::PtoContext {
                is_server:                      true,
                peer_completed_addr_validation: true,
                handshake_confirmed:            true,
            },
        );
        sub.assert_true(
            t_std0.mode == quic::PtoTimerMode.StandardPto,
            "ApplicationData arms StandardPto after handshake_confirmed",
        );
        let t_std1 = quic::evaluate_pto_timer(
            spaces_unconf,
            srv.rtt,
            1,
            15000,
            quic::PtoContext {
                is_server:                      true,
                peer_completed_addr_validation: true,
                handshake_confirmed:            true,
            },
        );
        sub.assert_true(
            t_std1.target_time_us > t_std0.target_time_us,
            "PTO deadline doubles on pto_count backoff",
        );
    };

    t.run("QUINN-CONN-06: NEW_CONNECTION_ID, RETIRE_CONNECTION_ID, NEW_TOKEN & Role Violations (ngtcp2_conn_test.c)") { sub =>
        let scid: u8[8] = [1, 2, 3, 4, 5, 6, 7, 8];
        var ack_out = quic::AckFrame { .. };

        // 1. Valid NEW_CONNECTION_ID (seq=2, retire_prior_to=1 <= seq) on connection with non-empty peer DCID
        var srv1 = quic::new_client_connection(scid[..], scid[..]);
        var d_ncid_ok: u8[..64] = [];
        d_ncid_ok.push(0x40);
        d_ncid_ok.append(scid[..]);
        d_ncid_ok.push(0x01);
        let new_cid:   u8[8]  = [0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8];
        let reset_tok: u8[16] = [0xEE; 16];
        sub.assert_true(
            quic::encode_new_conn_id_frame(2, 1, new_cid[..], reset_tok, d_ncid_ok),
            "encode valid NEW_CONNECTION_ID",
        );
        let _pr_ok_ncid = quic_internal::process_unencrypted_test_datagram(srv1, d_ncid_ok[..], 1000, ack_out);
        let ok_ncid = _pr_ok_ncid.handled;
        sub.assert_true(ok_ncid, "valid NEW_CONNECTION_ID accepted");

        // 1b. NEW_CONNECTION_ID on endpoint with 0-length peer DCID -> PROTOCOL_VIOLATION (RFC 9000 §19.15)
        var srv1_zero_dcid = quic::new_server_connection(scid[..]); // dcid is initially empty
        let _pr_ok_ncid_zero = quic_internal::process_unencrypted_test_datagram(srv1_zero_dcid, d_ncid_ok[..], 1000, ack_out);
        let ok_ncid_zero = _pr_ok_ncid_zero.handled;
        sub.assert_false(ok_ncid_zero, "NEW_CONNECTION_ID rejected when peer DCID is 0-length (RFC 9000 §19.15)");
        sub.assert_eq(srv1_zero_dcid.close_code, rfc::QUIC_ERR_PROTOCOL_VIOLATION, "PROTOCOL_VIOLATION (0x0A)");

        // 2. Invalid NEW_CONNECTION_ID with retire_prior_to (5) > seq_num (3) -> rejected at frame decode as FRAME_ENCODING_ERROR
        var srv2 = quic::new_server_connection(scid[..]);
        var d_ncid_bad: u8[..64] = [];
        d_ncid_bad.push(0x40);
        d_ncid_bad.append(scid[..]);
        d_ncid_bad.push(0x01);
        d_ncid_bad.push(0x18); // NEW_CONNECTION_ID
        d_ncid_bad.push(0x03); // seq_num = 3
        d_ncid_bad.push(0x05); // retire_prior_to = 5 (> 3, illegal per RFC 9000 §19.15)
        d_ncid_bad.push(0x04); // cid len = 4
        d_ncid_bad.append("1234");
        d_ncid_bad.append(reset_tok[..]);
        let _pr_ok_ncid_bad = quic_internal::process_unencrypted_test_datagram(srv2, d_ncid_bad[..], 1000, ack_out);
        let ok_ncid_bad = _pr_ok_ncid_bad.handled;
        sub.assert_false(ok_ncid_bad, "NEW_CONNECTION_ID with retire_prior_to > seq_num rejected");
        sub.assert_eq(srv2.close_code, rfc::QUIC_ERR_FRAME_ENCODING, "FRAME_ENCODING_ERROR (0x07)");

        // 3. Server receiving NEW_TOKEN (0x07) -> PROTOCOL_VIOLATION (RFC 9000 §19.7: only client may receive NEW_TOKEN)
        var srv3 = quic::new_server_connection(scid[..]);
        var d_nt_srv: u8[..64] = [];
        d_nt_srv.push(0x40);
        d_nt_srv.append(scid[..]);
        d_nt_srv.push(0x01);
        quic::encode_new_token_frame("address-validation-token", d_nt_srv);
        let _pr_ok_nt_srv = quic_internal::process_unencrypted_test_datagram(srv3, d_nt_srv[..], 1000, ack_out);
        let ok_nt_srv = _pr_ok_nt_srv.handled;
        sub.assert_false(ok_nt_srv, "Server rejects inbound NEW_TOKEN frame");
        sub.assert_eq(srv3.close_code, rfc::QUIC_ERR_PROTOCOL_VIOLATION, "PROTOCOL_VIOLATION (0x0A)");

        // 4. Client receiving NEW_TOKEN + HANDSHAKE_DONE -> accepted and sets handshake_confirmed = true
        var cli4 = quic::new_client_connection(scid[..], scid[..]);
        var d_cli_ok: u8[..64] = [];
        d_cli_ok.push(0x40);
        d_cli_ok.append(scid[..]);
        d_cli_ok.push(0x01);
        quic::encode_new_token_frame("address-validation-token", d_cli_ok);
        quic::encode_handshake_done_frame(d_cli_ok);
        let _pr_ok_cli = quic_internal::process_unencrypted_test_datagram(cli4, d_cli_ok[..], 1000, ack_out);
        let ok_cli = _pr_ok_cli.handled;
        let needs_ack_cli = _pr_ok_cli.needs_ack;
        sub.assert_true(ok_cli, "Client accepts NEW_TOKEN + HANDSHAKE_DONE");
        sub.assert_true(needs_ack_cli, "HANDSHAKE_DONE is ACK-eliciting");
        sub.assert_true(cli4.state == quic::QuicConnState.Established, "Client state is Established");

        // 5. RETIRE_CONNECTION_ID on connection with 0-length local SCID -> PROTOCOL_VIOLATION (RFC 9000 §19.16)
        let empty_cid: u8[0] = [];
        var srv5 = quic::new_server_connection(empty_cid[..]);
        var d_ret: u8[..32] = [];
        d_ret.push(0x40);
        d_ret.push(0x01);
        d_ret.push(0x19); // RETIRE_CONNECTION_ID (0x19)
        d_ret.push(0x00); // sequence_number = 0
        let _pr_ok_ret_empty = quic_internal::process_unencrypted_test_datagram(srv5, d_ret[..], 1000, ack_out);
        let ok_ret_empty = _pr_ok_ret_empty.handled;
        sub.assert_false(ok_ret_empty, "RETIRE_CONNECTION_ID on 0-len SCID connection rejected");
        sub.assert_eq(srv5.close_code, rfc::QUIC_ERR_PROTOCOL_VIOLATION, "PROTOCOL_VIOLATION (0x0A)");
    };
}

// --- Component: regress_issues_batch15 ---
// Phase 15 RED test suite: HTTP/3 & QUIC Transport Engine RFC Invariants,
// QPACK Dynamic Table Ring Decoders, Header Protection & Stream Multiplexer Defenses.
//
// 1. QUIC Packet Headers, Header Protection & Interval Reassembly (quic/packet.goose)
// 2. QPACK Modular RIC, Post-Base Bounds & Bare-Colon Token Sanitization (http3/qpack.goose)
// 3. HTTP/3 Framing, Reserved 0x00 Setting & Malformed Payloads (http3/framing.goose)
// 4. HTTP/3 Multiplexer, Unidirectional Encoder/Decoder Dispatch & Trailer Defenses (http3/connection.goose)

// ----------------------------------------------------------------------------
// 34. QUIC Packet Headers, Header Protection & Interval Reassembly
// ----------------------------------------------------------------------------
fn test_quic_packet_and_reassembly(t: lit::T&) {
    t.run("parse_quic_header enforces fixed bit, CID lengths, and plen >= pn_len") { sub =>
        // 1. Short header with fixed bit cleared (bit 6 = 0) MUST fail per RFC 9000 §17.3
        let bad_short: u8[16] = [
            0x00, // Fixed bit (0x40) is not set!
            0x01, 0x02, 0x03, 0x04,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let _, ok_s = quic::parse_header(bad_short[..], 4);
        sub.assert_false(ok_s, "Short header with fixed bit 0 rejected");

        // 2. Short header with dcid_len_short > 20 MUST fail
        let valid_short: u8[16] = [
            0x40, // Short header, fixed bit 1, pn_len 1
            0x01, 0x02, 0x03, 0x04,
            0x2A, // packet number
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let _, ok_dcid_lg = quic::parse_header(valid_short[..], 21);
        sub.assert_false(ok_dcid_lg, "Short header with dcid > 20 rejected");

        let hdr_s, ok_s_valid = quic::parse_header(valid_short[..], 4);
        sub.assert_true(ok_s_valid, "Valid short header accepted");
        sub.assert_eq(hdr_s.header_type, quic::QuicHeaderType.OneRtt, "Header type is OneRtt");
        sub.assert_eq(hdr_s.pn_length, 1, "PN length is 1");

        // 3. Long header with fixed bit cleared MUST fail per RFC 9000 §17.2
        var bad_long: u8[..64] = [];
        bad_long.push(0x80); // Long header, but fixed bit 0x40 NOT set!
        core::append_u32_be(bad_long, rfc::QUIC_VERSION_1);
        bad_long.push(4); // DCID len
        bad_long.append([1, 2, 3, 4]);
        bad_long.push(4); // SCID len
        bad_long.append([5, 6, 7, 8]);
        quic::encode_varint(10, bad_long); // plen
        bad_long.push(1); // pn
        let _, ok_l_fix = quic::parse_header(bad_long[..], 0);
        sub.assert_false(ok_l_fix, "Long header with fixed bit 0 rejected");

        // 4. Long header with plen < pn_len MUST fail per RFC 9000 §17.2
        var bad_plen: u8[..64] = [];
        bad_plen.push(0xC1); // Long header, Initial, pn_len = 2 (bits 0..1 = 1)
        core::append_u32_be(bad_plen, rfc::QUIC_VERSION_1);
        bad_plen.push(0); // DCID len 0
        bad_plen.push(0); // SCID len 0
        quic::encode_varint(0, bad_plen); // token len 0
        quic::encode_varint(1, bad_plen); // plen = 1, but pn_len = 2!
        bad_plen.append([0x00, 0x2A]); // 2 bytes PN
        let _, ok_plen = quic::parse_header(bad_plen[..], 0);
        sub.assert_false(ok_plen, "Long header with plen < pn_len rejected");
    };

    t.run("encode_quic_header enforces pn_len bounds and 20-byte CID") { sub =>
        var hdr = quic::QuicHeader {
            header_type:    quic::QuicHeaderType.Initial,
            version:        rfc::QUIC_VERSION_1,
            payload_length: 64,
            packet_number:  1,
            ..
        };
        // Valid 20-byte DCID (matches QUIC_MAX_CID_LEN = 20)
        for i in 20 { hdr.dcid.push(i as u8); }

        var out: u8[..128] = [];
        let ok_valid = quic::encode_header(hdr, 1, out);
        sub.assert_true(ok_valid, "encode with DCID == 20 accepted");

        // Invalid pn_len 0 or 5
        out.clear();
        sub.assert_false(quic::encode_header(hdr, 0, out), "pn_len 0 rejected");
        sub.assert_false(quic::encode_header(hdr, 5, out), "pn_len 5 rejected");
    };

    t.run("apply and remove header protection with truncated buffers") { sub =>
        let hp_mask: u8[5] = [0x5A, 0x11, 0x22, 0x33, 0x44];

        // Empty buffer
        var empty_buf: u8[..4] = [];
        quic::apply_header_protection(empty_buf[..], 0, 1, hp_mask);
        let pn_len_e, pn_e = quic::remove_header_protection(empty_buf[..], 0, hp_mask);
        sub.assert_eq(pn_len_e, 0, "remove on empty returns 0");
        sub.assert_eq(pn_e, 0, "pn on empty returns 0");

        // Truncated buffer where pn_offset + pn_len > pkt.len
        var trunc_buf: u8[4] = [0xC0, 0x00, 0x00, 0x00];
        quic::apply_header_protection(trunc_buf[..], 10, 2, hp_mask); // offset 10 > len 4: safe no-op
        sub.assert_eq(trunc_buf[0], 0xC0, "first byte untouched when out of bounds");

        let pn_len_tr, _ = quic::remove_header_protection(trunc_buf[..], 10, hp_mask);
        sub.assert_eq(pn_len_tr, 0, "remove out of bounds returns 0");
        sub.assert_eq(trunc_buf[0], 0xC0, "first byte restored on out-of-bounds");

        // Valid round-trip
        var valid_pkt: u8[8] = [0xC0, 0x01, 0x02, 0x03, 0x12, 0x34, 0xAA, 0xBB];
        let orig_first = valid_pkt[0];
        let orig_pn0 = valid_pkt[4];
        let orig_pn1 = valid_pkt[5];

        quic::apply_header_protection(valid_pkt[..], 4, 2, hp_mask);
        sub.assert_ne(valid_pkt[0], orig_first, "first byte masked");

        let dec_pn_len, dec_pn = quic::remove_header_protection(valid_pkt[..], 4, hp_mask);
        sub.assert_eq(dec_pn_len, 1, "pn_len unmasked is (first & 3) + 1");
        sub.assert_eq(valid_pkt[0], orig_first, "first byte restored");
    };

    t.run("decode_packet_number bounds checking and epoch shifts") { sub =>
        // Out of bounds pn_len
        let pn_raw = quic::decode_packet_number(100, 42, 0);
        sub.assert_eq(pn_raw, 42, "pn_len 0 returns truncated");
        let pn_lg = quic::decode_packet_number(100, 42, 5);
        sub.assert_eq(pn_lg, 42, "pn_len 5 returns truncated");

        // 1-byte PN decoding near wrap-around
        let pn1 = quic::decode_packet_number(0xA8252, 0x9B, 1);
        sub.assert_eq(pn1, 0xA829B, "RFC 9000 Appendix A.3 1-byte decode vector");

        // 2-byte PN decoding
        let pn2 = quic::decode_packet_number(0xA8252, 0x9B3F, 2);
        sub.assert_eq(pn2, 0xA9B3F, "RFC 9000 Appendix A.3 2-byte decode vector");
    };

    t.run("can_send_on_path anti-amplification overflow protection") { sub =>
        let ip: u8[16] = [0; 16];
        var path = quic::new_path_state(ip, 443, false);

        // Path received 1000 bytes -> can send up to 3000 bytes
        quic::on_bytes_received(path, 1000);
        sub.assert_true(quic::can_send(path, 3000), "3000 <= 3 * 1000 allowed");
        sub.assert_false(quic::can_send(path, 3001), "3001 > 3 * 1000 blocked");

        // Test with massive numbers that would overflow 3 * received or sent + packet
        var path_huge = quic::new_path_state(ip, 443, false);
        path_huge.bytes_received = 0x7FFFFFFFFFFFFFFF; // 3 * bytes_received overflows u64
        path_huge.bytes_sent = 0xFFFFFFFFFFFFFFF0;
        sub.assert_false(quic::can_send(path_huge, 32), "sent + packet overflow safely blocked");

        // Validated path ignores limit
        quic::validate(path);
        sub.assert_true(quic::can_send(path, 1000000), "validated path allows send");
    };

    t.run("decode_quic_datagram_frame respects packet_end boundary") { sub =>
        var wire: u8[..32] = [];
        // DATAGRAM with Length (0x31)
        sub.assert_true(quic::encode_datagram_frame("hello", wire, true), "encode datagram len");

        // Normal decode without packet_end
        let payload1, end1, ok1 = quic::decode_datagram_frame(wire[..], 0, 0);
        sub.assert_true(ok1, "decode ok without packet_end");
        sub.assert_bytes_eq(payload1, "hello", "payload matches");

        // Decode with packet_end cutting into datagram length
        let _, _, ok_trunc = quic::decode_datagram_frame(wire[..], 0, end1 - 1);
        sub.assert_false(ok_trunc, "datagram exceeding packet_end rejected");
    };

    t.run("merge_reassembly_interval enforces 64 intervals capacity") { sub =>
        var r_buf = quic::new_reassembly_buffer(65536);

        // Insert 64 disjunct intervals [0, 1), [2, 3), [4, 5), ...
        for i in 64 {
            let s = (i as u64) * 2;
            let ok = quic::insert_fragment(r_buf, s, "X", false);
            sub.assert_true(ok, "insert interval");
        }
        sub.assert_eq(r_buf.intervals.len, 64, "intervals array full at cap 64");

        // 65th disjunct interval cannot be added
        let ok_65 = quic::insert_fragment(r_buf, 200, "Y", false);
        sub.assert_false(ok_65, "65th disjunct interval safely rejected on capacity exhaustion");
    };
}

// ----------------------------------------------------------------------------
// 35. QUIC ACK Frame Gap Addition Overflow Defense
// ----------------------------------------------------------------------------
fn test_quic_ack_underflow(t: lit::T&) {
    var ack = quic::AckFrame {};
    ack.largest_acked = 10;
    ack.first_ack_range = 10;
    // Malicious huge gap that would wrap around in gap + 2
    ack.ranges.push(quic::AckRange { gap: 0xFFFFFFFFFFFFFFFF, ack_range: 0 });

    var space = quic::PnSpaceState {};
    space.has_sent_packets = true;
    space.largest_sent_pn = 100;
    var out_intervals: quic::AckInterval[..64] = [];

    let ok = quic::parse_and_validate_ack(space, ack, out_intervals);
    t.assert_false(ok, "Huge gap wrapping in gap + 2 must be safely rejected");
}

// ----------------------------------------------------------------------------
// 36. Wave 4 Crypto Audit Hardening: Retry Tag, 0-RTT, KeyUpdate, AEAD Limits
// ----------------------------------------------------------------------------
fn test_quic_wave4_crypto_audit_hardening(t: lit::T&) {
    t.run("TLS-08: RFC 9369 Appendix A.4 Retry Integrity Tag & Client State Binding") { sub =>
        // RFC 9369 Appendix A.4 exact QUIC v2 Retry packet vector
        let odcid_v2: u8[8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        let retry_v2: u8[36] = [
            0xcf, 0x6b, 0x33, 0x43, 0xcf, 0x00, 0x08, 0xf0,
            0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5, 0x74,
            0x6f, 0x6b, 0x65, 0x6e, 0xc8, 0x64, 0x6c, 0xe8,
            0xbf, 0xe3, 0x39, 0x52, 0xd9, 0x55, 0x54, 0x36,
            0x65, 0xdc, 0xc7, 0xb6,
        ];
        sub.assert_true(
            quic::verify_retry_integrity_tag(odcid_v2[..], retry_v2[..], rfc::QUIC_VERSION_2),
            "RFC 9369 Appendix A.4 v2 Retry tag verifies",
        );

        var tampered_v2 = retry_v2;
        tampered_v2[35] ^= 0x01;
        sub.assert_false(
            quic::verify_retry_integrity_tag(odcid_v2[..], tampered_v2[..], rfc::QUIC_VERSION_2),
            "tampered v2 Retry tag rejected",
        );

        // Client in Initial accepts valid Retry once, updates DCID & token, rejects duplicate Retry
        let empty_scid: u8[0] = [];
        var cli = quic::new_client_connection(odcid_v2[..], empty_scid[..]);
        sub.assert_true(quic::install_initial_keys(cli, odcid_v2[..], rfc::QUIC_VERSION_2), "install initial v2 keys");
        var out_ack = quic::AckFrame { .. };
        let res_bad = quic::process_datagram(cli, tampered_v2[..], 1000, out_ack);
        sub.assert_false(res_bad.handled, "client rejects tampered Retry");
        sub.assert_false(cli.retry_received, "retry_received stays false after bad Retry");

        let res_ok = quic::process_datagram(cli, retry_v2[..], 1001, out_ack);
        sub.assert_true(res_ok.handled, "client accepts valid v2 Retry");
        sub.assert_true(cli.retry_received, "retry_received set to true");
        sub.assert_eq(cli.retry_token[..], "token", "Retry token stored");
        let new_scid: u8[8] = [0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5];
        sub.assert_eq(cli.dcid[..], new_scid[..], "client DCID switched to Retry SCID");

        let res_dup = quic::process_datagram(cli, retry_v2[..], 1002, out_ack);
        sub.assert_false(res_dup.handled, "second Retry rejected");

        // Server MUST reject Retry packets
        var srv = quic::new_server_connection(empty_scid[..]);
        let res_srv = quic::process_datagram(srv, retry_v2[..], 1003, out_ack);
        sub.assert_false(res_srv.handled, "server discards Retry packet");
    };

    t.run("TLS-09: 0-RTT Key Separation, Client Rejection & Replay Protection") { sub =>
        let srv_cid = "srv0rtt1";
        let cli_cid = "cli0rtt1";
        let hp0: u8[16] = [0x11; 16];
        let k0:  u8[16] = [0x22; 16];
        let iv0: u8[12] = [0x33; 12];
        let hp1: u8[16] = [0x44; 16];
        let k1:  u8[16] = [0x55; 16];
        let iv1: u8[12] = [0x66; 12];

        var tx0 = quic::PnSpaceState { space_id: quic::PnSpaceId.ApplicationData, .. };
        sub.assert_true(quic::install_keys(tx0, hp0[..], k0[..], iv0[..], 0x1301), "install tx 0-RTT keys");

        var hdr0 = quic::QuicHeader {
            header_type:   quic::QuicHeaderType.ZeroRtt,
            version:       rfc::QUIC_VERSION_1,
            packet_number: 7,
            ..
        };
        hdr0.dcid.append(srv_cid);
        hdr0.scid.append(cli_cid);
        var ping_pl: u8[2]     = [0x01, 0x00]; // PING + PADDING (>= 2B so pn_len=2 + ct + 16B tag >= 20B HP sample)
        var pkt0:    u8[..256] = [];
        sub.assert_true(quic::seal_packet(tx0, hdr0, 2, ping_pl[..], pkt0), "seal 0-RTT packet");

        // Client MUST reject 0-RTT packets with PROTOCOL_VIOLATION
        var cli = quic::new_client_connection(srv_cid, cli_cid);
        var ack_out = quic::AckFrame { .. };
        let res_cli = quic::process_datagram(cli, pkt0[..], 1000, ack_out);
        sub.assert_false(res_cli.handled, "client rejects 0-RTT packet");
        sub.assert_eq(cli.close_code, rfc::QUIC_ERR_PROTOCOL_VIOLATION, "client closes with PROTOCOL_VIOLATION");

        // Server with ONLY 1-RTT app_space keys (even matching values) MUST NOT decrypt 0-RTT
        var srv_only_1rtt = quic::new_server_connection(srv_cid);
        sub.assert_true(quic::install_keys(srv_only_1rtt.app_space, hp0[..], k0[..], iv0[..], 0x1301), "install 1-RTT only");
        let res_no0 = quic::process_datagram(srv_only_1rtt, pkt0[..], 1000, ack_out);
        sub.assert_false(res_no0.handled, "server without zero_rtt_keys does not use 1-RTT keys for 0-RTT");

        // Server with separate zero_rtt_keys accepts first 0-RTT packet and suppresses replay
        var srv = quic::new_server_connection(srv_cid);
        sub.assert_true(quic::install_keys(srv.app_space, hp1[..], k1[..], iv1[..], 0x1301), "install separate 1-RTT keys");
        sub.assert_true(quic::install_zero_rtt_keys(srv, hp0[..], k0[..], iv0[..], 0x1301), "install separate 0-RTT keys");
        let res_first = quic::process_datagram(srv, pkt0[..], 1000, ack_out);
        sub.assert_true(res_first.handled, "server accepts valid 0-RTT packet");
        sub.assert_true(srv.state == quic::QuicConnState.Initial, "0-RTT does not prematurely promote state to Established");
        let res_replay = quic::process_datagram(srv, pkt0[..], 1001, ack_out);
        sub.assert_false(res_replay.handled, "replayed 0-RTT PN rejected");
    };

    t.run("TLS-10, TLS-12, TLS-13, EDGE-16: CSPRNG Path Token, KeyUpdate, AEAD Limits & Fail-Closed") { sub =>
        // TLS-10: OS CSPRNG path challenge tokens
        let tok1, ok_t1 = quic::generate_path_challenge_token();
        let tok2, ok_t2 = quic::generate_path_challenge_token();
        sub.assert_true(ok_t1 && ok_t2, "CSPRNG path challenge tokens generated");
        sub.assert_false(tok1[..] == tok2[..], "consecutive CSPRNG path tokens differ");

        // TLS-12: RFC 9369 Appendix A.5 ChaCha20-Poly1305 QUIC v2 "quicv2 ku" vector
        let sec_a5: u8[32] = [
            0x9a, 0xc3, 0x12, 0xa7, 0xf8, 0x77, 0x46, 0x8e, 0xbe, 0x69, 0x42, 0x27, 0x48, 0xad, 0x00, 0xa1,
            0x54, 0x43, 0xf1, 0x82, 0x03, 0xa0, 0x7d, 0x60, 0x60, 0xf6, 0x88, 0xf3, 0x0f, 0x21, 0x63, 0x2b,
        ];
        let exp_ku_a5: u8[32] = [
            0xc6, 0x93, 0x74, 0xc4, 0x9e, 0x3d, 0x2a, 0x94, 0x66, 0xfa, 0x68, 0x9e, 0x49, 0xd4, 0x76, 0xdb,
            0x5d, 0x0d, 0xfb, 0xc8, 0x7d, 0x32, 0xce, 0xea, 0xa6, 0x34, 0x3f, 0xd0, 0xae, 0x4c, 0x7d, 0x88,
        ];
        let hp_a5: u8[32] = [
            0xd6, 0x59, 0x76, 0x0d, 0x2b, 0xa4, 0x34, 0xa2, 0x26, 0xfd, 0x37, 0xb3, 0x5c, 0x69, 0xe2, 0xda,
            0x82, 0x11, 0xd1, 0x0c, 0x4f, 0x12, 0x53, 0x87, 0x87, 0xd6, 0x56, 0x45, 0xd5, 0xd1, 0xb8, 0xe2,
        ];
        let k_a5: u8[32] = [
            0x3b, 0xfc, 0xdd, 0xd7, 0x2b, 0xcf, 0x02, 0x54, 0x1d, 0x7f, 0xa0, 0xdd, 0x1f, 0x5f, 0x9e, 0xee,
            0xa8, 0x17, 0xe0, 0x9a, 0x69, 0x63, 0xa0, 0xe6, 0xc7, 0xdf, 0x0f, 0x9a, 0x1b, 0xab, 0x90, 0xf2,
        ];
        let iv_a5: u8[12] = [0xa6, 0xb5, 0xbc, 0x6a, 0xb7, 0xda, 0xfc, 0xe3, 0x0f, 0xff, 0xf5, 0xdd];

        var cli_ku = quic::new_client_connection("ku_srv", "ku_cli");
        cli_ku.version = rfc::QUIC_VERSION_2;
        var srv_ku = quic::new_server_connection("ku_srv");
        srv_ku.version = rfc::QUIC_VERSION_2;
        sub.assert_true(
            quic::install_keys_with_secret(
                cli_ku.tx_app_space, hp_a5[..], k_a5[..], iv_a5[..], sec_a5[..], rfc::TLS_CIPHER_CHACHA20_POLY1305_SHA256,
            ),
            "install client 1-RTT secret",
        );
        sub.assert_true(
            quic::install_keys_with_secret(
                srv_ku.app_space, hp_a5[..], k_a5[..], iv_a5[..], sec_a5[..], rfc::TLS_CIPHER_CHACHA20_POLY1305_SHA256,
            ),
            "install server 1-RTT secret",
        );

        // Forged key_phase=1 sealed under phase-0 keys MUST be rejected
        var forged_tx = cli_ku.tx_app_space;
        forged_tx.key_phase = true;
        var h_bad_kp = quic::QuicHeader { header_type: quic::QuicHeaderType.OneRtt, packet_number: 1, .. };
        h_bad_kp.dcid.append("ku_srv");
        var ping:       u8[2]     = [0x01, 0x00];
        var pkt_bad_kp: u8[..128] = [];
        sub.assert_true(quic::seal_packet(forged_tx, h_bad_kp, 2, ping[..], pkt_bad_kp), "seal forged key_phase pkt");
        var ack_out = quic::AckFrame { .. };
        sub.assert_false(
            quic::process_datagram(srv_ku, pkt_bad_kp[..], 1000, ack_out).handled,
            "mismatched key_phase rejected without ratcheting keys",
        );
        sub.assert_false(srv_ku.app_space.key_phase, "server stays on key_phase 0 after forged packet");
        sub.assert_eq(srv_ku.aead_failed_decrypts, 1, "failed decrypt counter incremented");

        // Send phase-0 packet PN=5, then initiate legitimate Key Update (phase 1) PN=10, then delayed phase-0 PN=3
        var h_p0_5 = quic::QuicHeader { header_type: quic::QuicHeaderType.OneRtt, packet_number: 5, .. };
        h_p0_5.dcid.append("ku_srv");
        var pkt_p0_5: u8[..128] = [];
        sub.assert_true(quic::seal_packet_tracked(cli_ku.tx_app_space, h_p0_5, 2, ping[..], pkt_p0_5), "seal p0 PN=5");
        var h_p0_3 = quic::QuicHeader { header_type: quic::QuicHeaderType.OneRtt, packet_number: 3, .. };
        h_p0_3.dcid.append("ku_srv");
        var pkt_p0_3: u8[..128] = [];
        sub.assert_true(quic::seal_packet_tracked(cli_ku.tx_app_space, h_p0_3, 2, ping[..], pkt_p0_3), "seal delayed p0 PN=3");

        sub.assert_true(quic::initiate_key_update(cli_ku.tx_app_space, rfc::QUIC_VERSION_2), "client key update");
        sub.assert_eq(cli_ku.tx_app_space.traffic_secret[..], exp_ku_a5[..], "RFC 9369 A.5 quicv2 ku matches verbatim");
        sub.assert_true(cli_ku.tx_app_space.key_phase, "client key_phase flipped to 1");

        var h_p1_10 = quic::QuicHeader { header_type: quic::QuicHeaderType.OneRtt, packet_number: 10, .. };
        h_p1_10.dcid.append("ku_srv");
        var pkt_p1_10: u8[..128] = [];
        sub.assert_true(quic::seal_packet_tracked(cli_ku.tx_app_space, h_p1_10, 2, ping[..], pkt_p1_10), "seal p1 PN=10");

        sub.assert_true(quic::process_datagram(srv_ku, pkt_p0_5[..], 1010, ack_out).handled, "server accepts p0 PN=5");
        sub.assert_true(quic::process_datagram(srv_ku, pkt_p1_10[..], 1020, ack_out).handled, "server ratchets on p1 PN=10");
        sub.assert_true(srv_ku.app_space.key_phase, "server key_phase flipped to 1");
        sub.assert_eq(srv_ku.app_space.traffic_secret[..], exp_ku_a5[..], "server ratcheted secret matches RFC 9369 A.5");
        sub.assert_true(quic::process_datagram(srv_ku, pkt_p0_3[..], 1030, ack_out).handled, "delayed p0 PN=3 opened via prev keys");
        sub.assert_true(srv_ku.app_space.key_phase, "delayed p0 packet keeps server on key_phase 1");

        // TLS-13: PN ceiling (> 2^62 - 1), AES-GCM confidentiality limit (2^23), and integrity limit (AEAD_LIMIT_REACHED)
        var h_over_pn = quic::QuicHeader {
            header_type:   quic::QuicHeaderType.OneRtt,
            packet_number: rfc::QUIC_PN_LIMIT,
            ..
        };
        h_over_pn.dcid.append("ku_srv");
        var pkt_over: u8[..128] = [];
        sub.assert_false(quic::seal_packet(cli_ku.tx_app_space, h_over_pn, 4, ping[..], pkt_over), "PN >= 2^62 rejected");

        var gcm_tx = quic::PnSpaceState { space_id: quic::PnSpaceId.ApplicationData, .. };
        let g16: u8[16] = [0x77; 16];
        let giv: u8[12] = [0x88; 12];
        sub.assert_true(quic::install_keys(gcm_tx, g16[..], g16[..], giv[..], 0x1301), "install AES-128-GCM tx");
        gcm_tx.aead_encrypted_packets = rfc::QUIC_AES_GCM_CONFIDENTIALITY_LIMIT;
        sub.assert_false(quic::seal_packet(gcm_tx, h_p0_5, 2, ping[..], pkt_over), "AES-GCM confidentiality limit enforced");

        srv_ku.aead_failed_decrypts = rfc::QUIC_CHACHA20_INTEGRITY_LIMIT - 1;
        sub.assert_false(quic::process_datagram(srv_ku, pkt_bad_kp[..], 1040, ack_out).handled, "final bad decrypt rejected");
        sub.assert_eq(srv_ku.close_code, rfc::QUIC_ERR_AEAD_LIMIT_REACHED, "connection closed with AEAD_LIMIT_REACHED");

        // EDGE-16: production process_datagram fails closed when keys are not installed
        var unkeyed = quic::new_server_connection("nk01");
        var raw_pkt: u8[..32] = [0x40, 'n', 'k', '0', '1', 0x01, 0x01];
        sub.assert_false(quic::process_datagram(unkeyed, raw_pkt[..], 1000, ack_out).handled, "unkeyed process_datagram fails closed");
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
    lit::run_case(runner, "31. ngtcp2 & quinn Vendor Conformance Vectors", test_ngtcp2_and_quinn_vendor_conformance);
    lit::run_case(runner, "32. ngtcp2 & quinn Reassembly, ACK Compaction & Loss Recovery", test_ngtcp2_conn_and_recovery_semantics);
    lit::run_case(runner, "33. ngtcp2 & quinn Connection Lifecycle, Stream Polarity & BBRv3/PTO", test_ngtcp2_and_quinn_connection_dynamics);
    lit::run_case(runner, "34. QUIC Packet Headers, Header Protection & Interval Reassembly", test_quic_packet_and_reassembly);
    lit::run_case(runner, "35. QUIC ACK Frame Gap Addition Overflow Defense", test_quic_ack_underflow);
    lit::run_case(runner, "36. Wave 4 Crypto Audit Hardening: Retry, 0-RTT, KeyUpdate, AEAD Limits", test_quic_wave4_crypto_audit_hardening);

    let ok = lit::finish(runner);
    assert(ok);
}
