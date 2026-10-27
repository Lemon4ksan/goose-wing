// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// QUIC Transport & HTTP/3 Echelon 7 Conformance Suite (RFC 9000, RFC 9001, RFC 9002, RFC 9114, RFC 9204).
// Tests QPACK Static/Dynamic tables, Header Accordion DoS Defenses, VarInt codec,
// AES/ChaCha Header Protection, Packet Number Reconstruction, Anti-Amplification 3x,
// ReassemblyBuffer, ACK Framing, OACK Defense, 5-Priority PTO, BBRv2/v3, CUBIC & Pacer.
import std;
import core from "..";
import wing from "..";

// ============================================================================
// 1. QPACK Static Table, Dynamic Table & Codecs (RFC 9204)
// ============================================================================
fn test_qpack_table_and_codecs(t: core::T&) {
    t.run("QPACK-01: RFC 9204 Appendix A Static Table Lookups") { sub =>
        // Index 0: :authority
        let ent0, ok0 = wing::get_qpack_static_field(0);
        sub.assert_true(ok0, "static lookup index 0 ok");
        sub.assert_eq(ent0.name, ":authority", "index 0 name is :authority");
        sub.assert_eq(ent0.val, "", "index 0 value is empty");

        // Index 1: :path /
        let ent1, ok1 = wing::get_qpack_static_field(1);
        sub.assert_true(ok1, "static lookup index 1 ok");
        sub.assert_eq(ent1.name, ":path", "index 1 name is :path");
        sub.assert_eq(ent1.val, "/", "index 1 value is /");

        // Index 17: :method GET
        let ent17, ok17 = wing::get_qpack_static_field(17);
        sub.assert_true(ok17, "static lookup index 17 ok");
        sub.assert_eq(ent17.name, ":method", "index 17 name is :method");
        sub.assert_eq(ent17.val, "GET", "index 17 value is GET");

        // Index 25: :status 200
        let ent25, ok25 = wing::get_qpack_static_field(25);
        sub.assert_true(ok25, "static lookup index 25 ok");
        sub.assert_eq(ent25.name, ":status", "index 25 name is :status");
        sub.assert_eq(ent25.val, "200", "index 25 value is 200");

        // Out of bounds: index 99
        let _, ok99 = wing::get_qpack_static_field(99);
        sub.assert_false(ok99, "index 99 is out of bounds for 99-entry static table");
    };

    t.run("QPACK-02: Zero-Allocation Dynamic Table Ring Buffer & Eviction") { sub =>
        var tbl = wing::new_qpack_table(128, 16); // 128 bytes max capacity
        // Each entry size = name.len + value.len + 32
        // Entry 1: custom-header (13) + value1 (6) + 32 = 51 bytes
        let ok1 = wing::qpack_insert_literal(tbl, "custom-header", "value1");
        sub.assert_true(ok1, "insert entry 1 ok");
        sub.assert_eq(tbl.insert_count, 1, "inserted count is 1");
        sub.assert_eq(tbl.used_bytes, 51, "used 51 bytes");

        // Entry 2: custom-header (13) + value2 (6) + 32 = 51 bytes. Total = 102 <= 128
        let ok2 = wing::qpack_insert_literal(tbl, "custom-header", "value2");
        sub.assert_true(ok2, "insert entry 2 ok");
        sub.assert_eq(tbl.insert_count, 2, "inserted count is 2");
        sub.assert_eq(tbl.used_bytes, 102, "used 102 bytes");

        // Entry 3: custom-header (13) + value3 (6) + 32 = 51 bytes.
        // 102 + 51 = 153 > 128 -> Must evict entry 1 (oldest)!
        let ok3 = wing::qpack_insert_literal(tbl, "custom-header", "value3");
        sub.assert_true(ok3, "insert entry 3 ok with eviction");
        sub.assert_eq(tbl.insert_count, 3, "total inserted count is 3");
        sub.assert_eq(tbl.used_bytes, 102, "used bytes remains 102 after eviction");

        // Absolute index 0 was evicted
        var n0: u8[..256] = [];
        var v0: u8[..4096] = [];
        let ok_evicted = wing::qpack_lookup_absolute(tbl, 0, n0, v0);
        sub.assert_false(ok_evicted, "evicted entry 0 cannot be looked up");

        // Absolute index 2 (latest) is active
        var n2: u8[..256] = [];
        var v2: u8[..4096] = [];
        let ok_act = wing::qpack_lookup_absolute(tbl, 2, n2, v2);
        sub.assert_true(ok_act, "active entry 2 looked up");
        sub.assert_eq(v2[..], "value3", "entry 2 value is value3");
    };

    t.run("QPACK-03: RIC and Delta Base Prefix Codecs") { sub =>
        // Test RIC encode/decode
        let enc_ric = wing::encode_ric(15, 128);
        let ric, err_ric = wing::decode_ric(enc_ric, 15, 128);
        sub.assert_eq(err_ric, wing::QpackError.None, "decode RIC no error");
        sub.assert_eq(ric, 15, "decoded RIC matches original");

        // Test Delta Base encode/decode
        let sign_bit, delta_base = wing::encode_base(20, 25); // base < ric -> sign = 1, delta = 4
        let base, err_base = wing::decode_base(sign_bit, delta_base, 25);
        sub.assert_eq(err_base, wing::QpackError.None, "decode base no error");
        sub.assert_eq(base, 20, "decoded base matches original");
    };
}

// ============================================================================
// 2. QPACK Header Accordion DoS Defense & Post-Decode RIC Validation
// ============================================================================
fn test_qpack_security_defenses(t: core::T&) {
    t.run("QPACK-DOS-01: Header Accordion 32-Byte Overhead Enforcement") { sub =>
        var fields: wing::HeaderField[>..] = [];
        var budget_left: u64 = 100; // 100 bytes budget

        // Entry: "a": "b" -> length 2. Plus 32 overhead = 34 bytes!
        let err1 = wing::emit_field_checked(fields, budget_left, "a", "b", false);
        sub.assert_eq(err1, wing::QpackError.None, "first field accepted");
        sub.assert_eq(budget_left, 66, "budget left is 66 (100 - 34)");

        // Second entry: "c": "d" -> 34 bytes. Budget left = 32 <= 100
        let err2 = wing::emit_field_checked(fields, budget_left, "c", "d", false);
        sub.assert_eq(err2, wing::QpackError.None, "second field accepted");
        sub.assert_eq(budget_left, 32, "budget left is 32");

        // Third entry: "e": "f" -> 34 bytes. 32 < 34 -> Must reject with HeaderListTooLarge!
        let err3 = wing::emit_field_checked(fields, budget_left, "e", "f", false);
        sub.assert_eq(err3, wing::QpackError.HeaderListTooLarge, "third field rejected to prevent 33x memory amplification DoS");
    };

    t.run("QPACK-DOS-02: Post-Decode RIC Validation (RFC 9204 Section 4.5.1)") { sub =>
        var tbl = wing::new_qpack_table(4096, 16);
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

        var out_fields: wing::HeaderField[>..] = [];
        let err = wing::decode_qpack_section(tbl, malicious_block[..], out_fields, 16384);
        sub.assert_eq(err, wing::QpackError.DecompressionFailed, "malicious non-zero RIC on static-only block rejected");
    };
}

// ============================================================================
// 3. QUIC VarInt Codec & Packet Framing (RFC 9000, RFC 9001)
// ============================================================================
fn test_quic_varint_and_framing(t: core::T&) {
    t.run("VARINT-01: 1, 2, 4, 8-Byte Boundary Roundtrips") { sub =>
        // 1-byte boundary: 0, 63
        var buf1: u8[..16] = [];
        sub.assert_true(wing::quic_encode_varint(buf1, 63), "encode 63");
        sub.assert_eq(buf1.len, 1, "63 encoded in 1 byte");
        let v1, _, ok1 = wing::quic_decode_varint(buf1[..], 0);
        sub.assert_true(ok1, "decode 63");
        sub.assert_eq(v1, 63, "value 63 matches");

        // 2-byte boundary: 64, 16383
        var buf2: u8[..16] = [];
        sub.assert_true(wing::quic_encode_varint(buf2, 16383), "encode 16383");
        sub.assert_eq(buf2.len, 2, "16383 encoded in 2 bytes");
        let v2, _, ok2 = wing::quic_decode_varint(buf2[..], 0);
        sub.assert_true(ok2, "decode 16383");
        sub.assert_eq(v2, 16383, "value 16383 matches");

        // 4-byte boundary: 1073741823
        var buf4: u8[..16] = [];
        sub.assert_true(wing::quic_encode_varint(buf4, 1073741823), "encode 1073741823");
        sub.assert_eq(buf4.len, 4, "1073741823 encoded in 4 bytes");
        let v4, _, ok4 = wing::quic_decode_varint(buf4[..], 0);
        sub.assert_true(ok4, "decode 1073741823");
        sub.assert_eq(v4, 1073741823, "value 1073741823 matches");

        // 8-byte boundary: 0x3FFFFFFFFFFFFFFF
        var buf8: u8[..16] = [];
        sub.assert_true(wing::quic_encode_varint(buf8, 0x3FFFFFFFFFFFFFFF), "encode max varint");
        sub.assert_eq(buf8.len, 8, "max varint encoded in 8 bytes");
        let v8, _, ok8 = wing::quic_decode_varint(buf8[..], 0);
        sub.assert_true(ok8, "decode max varint");
        sub.assert_eq(v8, 0x3FFFFFFFFFFFFFFF, "value max varint matches");
    };

    t.run("FRAMING-01: Long & Short Header Encode / Decode Roundtrip") { sub =>
        // Initial Header
        var orig_hdr = wing::QuicHeader {
            header_type: wing::QuicHeaderType.Initial,
            version: wing::QUIC_VERSION_1,
            payload_length: 1200,
            packet_number: 42,
            ..
        };
        orig_hdr.dcid.append([1, 2, 3, 4, 5, 6, 7, 8]);
        orig_hdr.scid.append([9, 10, 11, 12]);

        var wire: u8[..128] = [];
        let ok_enc = wing::encode_quic_header(wire, orig_hdr, 2);
        sub.assert_true(ok_enc, "encode Initial header ok");

        let parsed, ok_dec = wing::parse_quic_header(wire[..], 0);
        sub.assert_true(ok_dec, "parse Initial header ok");
        sub.assert_eq(parsed.header_type, wing::QuicHeaderType.Initial, "header type Initial");
        sub.assert_eq(parsed.version, wing::QUIC_VERSION_1, "version QUIC v1");
        sub.assert_eq(parsed.dcid[..], orig_hdr.dcid[..], "dcid matches");
        sub.assert_eq(parsed.scid[..], orig_hdr.scid[..], "scid matches");
        sub.assert_eq(parsed.payload_length, 1200, "payload length matches");
    };

    t.run("STREAM-01: Stream Identifier Classification (RFC 9000 Section 2.1)") { sub =>
        // Client Bidirectional: 0, 4, 8
        sub.assert_true(wing::quic_is_client_stream(0), "stream 0 is client");
        sub.assert_true(wing::quic_is_bidi_stream(0), "stream 0 is bidi");

        // Server Bidirectional: 1, 5, 9
        sub.assert_true(wing::quic_is_server_stream(1), "stream 1 is server");
        sub.assert_true(wing::quic_is_bidi_stream(1), "stream 1 is bidi");

        // Client Unidirectional: 2, 6, 10
        sub.assert_true(wing::quic_is_client_stream(2), "stream 2 is client");
        sub.assert_true(wing::quic_is_uni_stream(2), "stream 2 is uni");

        // Server Unidirectional: 3, 7, 11
        sub.assert_true(wing::quic_is_server_stream(3), "stream 3 is server");
        sub.assert_true(wing::quic_is_uni_stream(3), "stream 3 is uni");
    };

    t.run("DATAGRAM-01: RFC 9221 Unreliable Datagram Framing") { sub =>
        var buf1: u8[..64] = [];
        sub.assert_true(wing::encode_quic_datagram_frame(buf1, "telemetry-payload", true), "encode datagram with length");
        let d1, next1, ok1 = wing::decode_quic_datagram_frame(buf1[..], 0);
        sub.assert_true(ok1, "decode datagram with length");
        sub.assert_eq(d1, "telemetry-payload", "payload matches with length");
        sub.assert_eq(next1, buf1.len as u64, "consumed all bytes");

        var buf2: u8[..64] = [];
        sub.assert_true(wing::encode_quic_datagram_frame(buf2, "raw-stream-end", false), "encode datagram without length");
        let d2, next2, ok2 = wing::decode_quic_datagram_frame(buf2[..], 0, buf2.len as u64);
        sub.assert_true(ok2, "decode datagram without length");
        sub.assert_eq(d2, "raw-stream-end", "payload matches without length");
        sub.assert_eq(next2, buf2.len as u64, "consumed all bytes");
    };
}

// ============================================================================
// 4. Header Protection & Packet Number Reconstruction (RFC 9001, RFC 9000)
// ============================================================================
fn test_header_protection_and_pn(t: core::T&) {
    t.run("HP-01: RFC 9001 Appendix A.2 Header Protection Vector") { sub =>
        let hp_key: u8[16] = [
            0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10,
            0x28, 0x3a, 0x1e, 0x99, 0x33, 0xad, 0xed, 0xd2,
        ];
        let sample: u8[16] = [
            0xd1, 0xb1, 0xc9, 0x8d, 0xd7, 0x68, 0x9f, 0xb8,
            0xec, 0x11, 0xd2, 0x42, 0xb1, 0x23, 0xdc, 0x9b,
        ];
        let mask = wing::aes128_header_protect_mask(hp_key, sample);
        let expected_mask: u8[5] = [0x43, 0x7b, 0x9a, 0xec, 0x36];
        sub.assert_eq(mask[..], expected_mask[..], "AES-128 HP mask matches RFC 9001 Appendix A.2");
    };

    t.run("HP-02: Header Protection Mask Application & In-Place Removal") { sub =>
        // Simulated 1-RTT short header with 2-byte packet number (PN = 0x1234)
        var pkt: u8[8] = [0x41, 0x12, 0x34, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
        let mask: u8[5] = [0x1A, 0x55, 0xAA, 0x00, 0x00];

        wing::apply_header_protection(pkt[..], 1, 2, mask);
        // Header first byte and PN fields are now masked
        sub.assert_true(pkt[0] != 0x41, "header first byte is masked");
        sub.assert_true(pkt[1] != 0x12, "PN byte 0 is masked");

        // Remove protection in-place
        let pn_len, trunc_pn = wing::remove_header_protection(pkt[..], 1, mask);
        sub.assert_eq(pn_len, 2, "recovered PN length is 2");
        sub.assert_eq(trunc_pn, 0x1234, "recovered truncated PN is 0x1234");
        sub.assert_eq(pkt[0], 0x41, "first byte unmasked to 0x41");
    };

    t.run("PN-01: RFC 9000 Appendix A.3 Packet Number Reconstruction") { sub =>
        // Normal sequential packet numbers
        let pn1 = wing::decode_packet_number(0, 1, 1);
        sub.assert_eq(pn1, 1, "pn 1 decoded from largest_acked 0");

        let pn64 = wing::decode_packet_number(63, 64, 1);
        sub.assert_eq(pn64, 64, "pn 64 decoded from largest_acked 63");

        // Window wrap across 1-byte truncated boundary (255 -> 256)
        let pn256 = wing::decode_packet_number(255, 0, 1);
        sub.assert_eq(pn256, 256, "pn 256 decoded from wrap 0 with largest_acked 255");

        // Out-of-order packet in the past (e.g. pn 254 arriving when largest acked is 256)
        let pn_past = wing::decode_packet_number(256, 254, 1);
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
        let chacha_mask = wing::chacha20_header_protect_mask(hp_key, sample);
        sub.assert_true(chacha_mask.len == 5, "chacha20 mask is 5 bytes");

        let aes256_mask = wing::aes256_header_protect_mask(hp_key, sample);
        sub.assert_true(aes256_mask.len == 5, "aes256 mask is 5 bytes");

        // Protect & unprotect with ChaCha20 mask on long header
        var pkt: u8[16] = [
            0xC3, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x05, 0x12, 0x34, 0x56, 0x78, 0xAA, 0xBB, 0xCC,
        ];
        let orig_b0 = pkt[0];
        wing::apply_header_protection(pkt[..], 9, 4, chacha_mask);
        sub.assert_true(pkt[0] != orig_b0, "first byte masked");

        let pn_len, trunc_pn = wing::remove_header_protection(pkt[..], 9, chacha_mask);
        sub.assert_eq(pn_len, 4, "recovered 4-byte PN");
        sub.assert_eq(trunc_pn, 0x12345678, "recovered truncated PN matches");
        sub.assert_eq(pkt[0], orig_b0, "first byte restored");
    };

    t.run("HDR-02: QUIC Header Parsing Across All Packet Types") { sub =>
        // 1. Handshake Packet Header
        var h_hdr = wing::QuicHeader {
            header_type: wing::QuicHeaderType.Handshake,
            version: wing::QUIC_VERSION_1,
            payload_length: 120,
            packet_number: 42,
            ..
        };
        h_hdr.dcid.append("dcid1234");
        h_hdr.scid.append("scid5678");

        var h_buf: u8[..128] = [];
        sub.assert_true(wing::encode_quic_header(h_buf, h_hdr, 2), "encode Handshake header");
        let parsed_h, ok_h = wing::parse_quic_header(h_buf[..], 0);
        sub.assert_true(ok_h, "parse Handshake header");
        sub.assert_eq(parsed_h.header_type, wing::QuicHeaderType.Handshake, "type is Handshake");
        sub.assert_eq(parsed_h.dcid[..], "dcid1234", "dcid matches");
        sub.assert_eq(parsed_h.scid[..], "scid5678", "scid matches");
        sub.assert_eq(parsed_h.payload_length, 120, "payload length matches");

        // 2. 0-RTT Packet Header
        var z_hdr = wing::QuicHeader {
            header_type: wing::QuicHeaderType.ZeroRtt,
            version: wing::QUIC_VERSION_1,
            payload_length: 50,
            packet_number: 1,
            ..
        };
        z_hdr.dcid.append("zero-dcid");
        var z_buf: u8[..128] = [];
        sub.assert_true(wing::encode_quic_header(z_buf, z_hdr, 1), "encode 0-RTT header");
        let parsed_z, ok_z = wing::parse_quic_header(z_buf[..], 0);
        sub.assert_true(ok_z, "parse 0-RTT header");
        sub.assert_eq(parsed_z.header_type, wing::QuicHeaderType.ZeroRtt, "type is ZeroRtt");

        // 3. Retry Packet Header
        var r_hdr = wing::QuicHeader {
            header_type: wing::QuicHeaderType.Retry,
            version: wing::QUIC_VERSION_1,
            ..
        };
        r_hdr.dcid.append("retry-dcid");
        r_hdr.scid.append("retry-scid");
        var r_buf: u8[..128] = [];
        sub.assert_true(wing::encode_quic_header(r_buf, r_hdr, 1), "encode Retry header");
        r_buf.append("retry-token-data-16bytes");
        let parsed_r, ok_r = wing::parse_quic_header(r_buf[..], 0);
        sub.assert_true(ok_r, "parse Retry header");
        sub.assert_eq(parsed_r.header_type, wing::QuicHeaderType.Retry, "type is Retry");

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

        let parsed_vn, ok_vn = wing::parse_quic_header(vn_buf[..], 0);
        sub.assert_true(ok_vn, "parse Version Negotiation header");
        sub.assert_eq(parsed_vn.header_type, wing::QuicHeaderType.VersionNegotiation, "type is VersionNegotiation");
        sub.assert_eq(parsed_vn.dcid[..], "dcid", "VN dcid matches");
        sub.assert_eq(parsed_vn.scid[..], "scid", "VN scid matches");
    };
}

// ============================================================================
// 5. Anti-Amplification 3x Limit & Zero-Heap Reassembly (RFC 9000)
// ============================================================================
fn test_anti_amplification_and_reassembly(t: core::T&) {
    t.run("PATH-01: Server Anti-Amplification 3x Credit Tracking") { sub =>
        let ip: u8[16] = [0; 16];
        var path = wing::new_path_state(ip, 443, false); // unvalidated client path

        // Client sends 1200 bytes Initial packet
        wing::on_path_bytes_received(path, 1200);
        // Total credit = 3 * 1200 = 3600 bytes

        sub.assert_true(wing::can_send_on_path(path, 1200), "can send 1st 1200B packet");
        wing::on_path_bytes_sent(path, 1200);

        sub.assert_true(wing::can_send_on_path(path, 1200), "can send 2nd 1200B packet");
        wing::on_path_bytes_sent(path, 1200);

        sub.assert_true(wing::can_send_on_path(path, 1200), "can send 3rd 1200B packet");
        wing::on_path_bytes_sent(path, 1200);
        // Total sent = 3600 = 3 * 1200. Further packets must be blocked!

        sub.assert_false(wing::can_send_on_path(path, 1), "4th packet blocked by 3x limit");

        // Validate path -> credit limit lifted
        wing::validate_path(path);
        sub.assert_true(wing::can_send_on_path(path, 1200), "sending allowed on validated path");
    };

    t.run("REASSEMBLY-01: Out-of-Order & Overlapping Stream Fragments") { sub =>
        var rbuf = wing::new_reassembly_buffer(65536);

        // Fragment 2 arrives first: offset 5..10 ("WORLD")
        let ok2 = wing::insert_fragment(rbuf, 5, "WORLD", false);
        sub.assert_true(ok2, "insert fragment 2 ok");
        sub.assert_eq(rbuf.consumed_offset, 0, "consumed remains 0 while waiting for head");

        // Fragment 1 arrives: offset 0..5 ("HELLO")
        let ok1 = wing::insert_fragment(rbuf, 0, "HELLO", false);
        sub.assert_true(ok1, "insert fragment 1 ok");

        // Contiguous read
        var out: u8[..64] = [];
        let n = wing::read_contiguous(rbuf, out);
        sub.assert_eq(n, 10, "read 10 contiguous bytes");
        sub.assert_eq(out[..], "HELLOWORLD", "assembled payload is HELLOWORLD");
        sub.assert_eq(rbuf.consumed_offset, 10, "consumed offset advanced to 10");
    };

    t.run("REASSEMBLY-02: Flow Control & Final Size Guard") { sub =>
        var rbuf = wing::new_reassembly_buffer(100); // 100 bytes max limit

        // Fragment exceeding flow control limit
        let ok_overflow = wing::insert_fragment(rbuf, 90, "0123456789ABCDEF", false); // end 106 > 100
        sub.assert_false(ok_overflow, "flow control overflow rejected");

        // Consistent FIN
        let ok_fin1 = wing::insert_fragment(rbuf, 0, "DATA", true);
        sub.assert_true(ok_fin1, "FIN set at offset 4");
        sub.assert_eq(rbuf.final_size, 4, "final size is 4");

        // Conflicting FIN -> QUIC_ERR_FINAL_SIZE
        let ok_fin2 = wing::insert_fragment(rbuf, 0, "DATA123", true);
        sub.assert_false(ok_fin2, "mismatched final size rejected");
    };
}

// ============================================================================
// 6. ACK Framing, OACK Defense & 5-Priority PTO (RFC 9000, RFC 9002, ANRW 2025)
// ============================================================================
fn test_ack_and_pto_engine(t: core::T&) {
    t.run("ACK-01: ACK & ACK_ECN Encode / Decode Roundtrip") { sub =>
        var orig_ack = wing::AckFrame {
            is_ecn: true,
            largest_acked: 100,
            ack_delay: 250,
            first_ack_range: 10, // packets 90..100
            ect0_count: 5,
            ect1_count: 0,
            ecn_ce_count: 2,
            ..
        };
        // Gap 2 (packets 87..89 unacked), ACK range 5 (packets 81..86 acked)
        orig_ack.ranges.push(wing::AckRange { gap: 2, ack_range: 5 });

        var wire: u8[..64] = [];
        sub.assert_true(wing::encode_ack_frame(wire, orig_ack), "encode ACK_ECN");

        let dec_ack, consumed, ok_dec = wing::decode_ack_frame(wire[..], 0);
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

    t.run("ACK-02: Optimistic ACK (OACK) Forward-Dated Attack Rejection") { sub =>
        var space = wing::PnSpaceState {
            space_id: wing::PnSpaceId.ApplicationData,
            largest_sent_pn: 50, // Sender only sent up to PN 50!
            has_sent_packets: true,
            ..
        };

        // Malicious peer sends ACK for PN 60 > largest_sent_pn
        let malicious_ack = wing::AckFrame {
            largest_acked: 60,
            ack_delay: 0,
            first_ack_range: 0,
            ..
        };

        var intervals: wing::AckInterval[..64] = [];
        let ok_valid = wing::parse_and_validate_ack(space, malicious_ack, intervals);
        sub.assert_false(ok_valid, "OACK attack claiming unsent PN 60 rejected");
    };

    t.run("RTT-01: RTT Estimators & Max ACK Delay Clamping (RFC 9002 Sec 5.3)") { sub =>
        var rtt = wing::RttState {};
        sub.assert_eq(rtt.smoothed_rtt_us, 333000, "initial smoothed_rtt is 333 ms");

        // First sample: 40 ms
        wing::update_rtt(rtt, 40000, 2000, true, 1000000);
        sub.assert_eq(rtt.min_rtt_us, 40000, "min_rtt updated to 40 ms");
        sub.assert_eq(rtt.smoothed_rtt_us, 40000, "smoothed_rtt initialized to 40 ms");
        sub.assert_eq(rtt.rttvar_us, 20000, "rttvar initialized to 20 ms");

        // Second sample: 48 ms with 5 ms delay -> adjusted 43 ms
        wing::update_rtt(rtt, 48000, 5000, true, 2000000);
        sub.assert_eq(rtt.min_rtt_us, 40000, "min_rtt remains 40 ms");
        // smoothed_rtt = (7 * 40000 + 43000) / 8 = 40375 us
        sub.assert_eq(rtt.smoothed_rtt_us, 40375, "smoothed_rtt weighted average updated");
    };

    t.run("PTO-01: 5-Priority PTO State Machine Decisions") { sub =>
        var spaces: wing::PnSpaceState[3] = [
            wing::PnSpaceState { space_id: wing::PnSpaceId.Initial, .. },
            wing::PnSpaceState { space_id: wing::PnSpaceId.Handshake, .. },
            wing::PnSpaceState { space_id: wing::PnSpaceId.ApplicationData, .. },
        ];
        var rtt = wing::RttState { smoothed_rtt_us: 50000, rttvar_us: 10000, .. };

        // Priority 2: Server at anti-amplification limit
        let dec_amp = wing::evaluate_pto_timer(
            spaces, rtt, 0, 1000000, true, true, false, false,
        );
        sub.assert_eq(dec_amp.mode, wing::PtoTimerMode.AntiAmplification, "server at amp limit returns AntiAmplification");

        // Priority 3: Client Anti-deadlock PTO when no packets in flight
        let dec_deadlock = wing::evaluate_pto_timer(
            spaces, rtt, 0, 1000000, false, false, false, false,
        );
        sub.assert_eq(dec_deadlock.mode, wing::PtoTimerMode.AntiDeadlock, "client anti-deadlock armed");

        // Priority 5: Standard PTO when packets in flight
        spaces[0].sent_packets.push(wing::SentPacketMeta {
            pn: 1, time_sent_us: 1000000, ack_eliciting: true, in_flight: true,
        });
        spaces[0].time_of_last_ack_eliciting_us = 1000000;
        let dec_std = wing::evaluate_pto_timer(
            spaces, rtt, 0, 1000000, true, false, true, false,
        );
        sub.assert_eq(dec_std.mode, wing::PtoTimerMode.StandardPto, "standard PTO scheduled");

        // Priority 1: Time threshold loss detection takes precedence over PTO
        spaces[0].loss_time_us = 1010000;
        let dec_loss = wing::evaluate_pto_timer(
            spaces, rtt, 0, 1000000, true, false, true, false,
        );
        sub.assert_eq(dec_loss.mode, wing::PtoTimerMode.LossTime, "loss time timer takes Priority 1");
    };

    t.run("ACK-03: Descending Interval Tracking & Frame Construction") { sub =>
        var ranges: wing::AckInterval[..64] = [];

        // Record PN 10
        wing::record_received_pn(ranges, 10);
        sub.assert_eq(ranges.len, 1, "1 range recorded");
        sub.assert_eq(ranges[0].smallest, 10, "smallest is 10");
        sub.assert_eq(ranges[0].largest, 10, "largest is 10");

        // Record PN 11 -> merges into [10..11]
        wing::record_received_pn(ranges, 11);
        sub.assert_eq(ranges.len, 1, "still 1 range after contiguous PN 11");
        sub.assert_eq(ranges[0].smallest, 10, "smallest is 10");
        sub.assert_eq(ranges[0].largest, 11, "largest is 11");

        // Record PN 13 -> creates new range: [13..13], [10..11]
        wing::record_received_pn(ranges, 13);
        sub.assert_eq(ranges.len, 2, "2 ranges after gap");
        sub.assert_eq(ranges[0].largest, 13, "range 0 largest is 13");
        sub.assert_eq(ranges[1].largest, 11, "range 1 largest is 11");

        // Record duplicate PN 10 -> ignored
        wing::record_received_pn(ranges, 10);
        sub.assert_eq(ranges.len, 2, "duplicate PN 10 ignored");

        // Record PN 12 -> bridges the gap, merging into [10..13]
        wing::record_received_pn(ranges, 12);
        sub.assert_eq(ranges.len, 1, "gap bridged into 1 range [10..13]");
        sub.assert_eq(ranges[0].smallest, 10, "smallest is 10");
        sub.assert_eq(ranges[0].largest, 13, "largest is 13");

        // Build ACK frame from interval set
        let ack, ok_ack = wing::build_ack_frame(ranges, 150, false);
        sub.assert_true(ok_ack, "build_ack_frame succeeds");
        sub.assert_eq(ack.largest_acked, 13, "largest acked is 13");
        sub.assert_eq(ack.first_ack_range, 3, "first ack range is 13 - 10 = 3");
        sub.assert_eq(ack.ranges.len, 0, "no extra ranges");
        sub.assert_eq(ack.ack_delay, 150, "ack delay is 150");
    };

    t.run("LOSS-01: Packet and Time Threshold Loss Detection (RFC 9002)") { sub =>
        var space = wing::PnSpaceState {
            space_id: wing::PnSpaceId.ApplicationData,
            has_acked_packets: true,
            largest_acked_pn: 10,
            ..
        };
        // Sent packets: PN 5 (t=1000), PN 6 (t=1000), PN 8 (t=1000)
        space.sent_packets.push(wing::SentPacketMeta {
            pn: 5, time_sent_us: 1000, ack_eliciting: true, in_flight: true,
        });
        space.sent_packets.push(wing::SentPacketMeta {
            pn: 6, time_sent_us: 1000, ack_eliciting: true, in_flight: true,
        });
        space.sent_packets.push(wing::SentPacketMeta {
            pn: 8, time_sent_us: 1000, ack_eliciting: true, in_flight: true,
        });

        var rtt = wing::RttState {
            smoothed_rtt_us: 40000,
            latest_rtt_us: 40000,
            ..
        };

        var lost: wing::SentPacketMeta[..64] = [];
        wing::detect_lost_packets(space, rtt, 100000, lost);

        // Packets 5 and 6 meet packet threshold (10 >= 5 + 3 and 10 >= 6 + 3)
        sub.assert_true(lost.len >= 2, "at least 2 lost packets detected");
        sub.assert_eq(lost[0].pn, 5, "packet 5 detected as lost");
        sub.assert_eq(lost[1].pn, 6, "packet 6 detected as lost");
    };
}

// ============================================================================
// 7. BBRv2/v3, CUBIC & Pacing Engine (draft-ietf-ccwg-bbr-06, RFC 9438)
// ============================================================================
fn test_bbr_cubic_and_pacing(t: core::T&) {
    t.run("PACER-01: User-Space Leaky Bucket Token Tracking") { sub =>
        var pacer = wing::new_pacer(8000000); // 8 Mbps -> 1 byte per microsecond

        // Transmit 1000 bytes at t = 1000000 us -> takes 1000 us
        let ok1, _ = wing::pacer_can_send(pacer, 1000000, 1000);
        sub.assert_true(ok1, "first packet sent immediately");

        // Next packet at t = 1000100 us (only 100 us later) -> bucket in deficit (-900 us)
        let ok2, delay = wing::pacer_can_send(pacer, 1000100, 1000);
        sub.assert_false(ok2, "second packet paced / held in bucket");
        sub.assert_true(delay > 0, "pacer returns non-zero pacing delay");

        // At t = 1002000 us (1900 us later) -> deficit repaid
        let ok3, _ = wing::pacer_can_send(pacer, 1002000, 1000);
        sub.assert_true(ok3, "packet permitted after pacing interval elapsed");
    };

    t.run("BBR-01: 7-State Phase Transitions & Dual-Envelope Congestion") { sub =>
        var bbr = wing::new_bbr_state();
        bbr.bw_hi_bps = 100000000; // 100 Mbps
        bbr.min_rtt_us = 40000;    // 40 ms -> BDP = 500 KB

        sub.assert_eq(bbr.mode, wing::BbrMode.Startup, "initial mode is Startup");

        // Cycle through phases: Startup -> Drain -> Cruise -> Refill -> Up -> Down
        wing::bbr_advance_cycle(bbr, true);
        sub.assert_eq(bbr.mode, wing::BbrMode.Drain, "advanced to Drain");

        wing::bbr_advance_cycle(bbr, true);
        sub.assert_eq(bbr.mode, wing::BbrMode.ProbeBwCruise, "advanced to ProbeBwCruise");

        // Congestion signal: loss rate 5% (> 2%)
        wing::bbr_on_congestion_signal(bbr, 500000, 5000, 100000, 0, 100);
        sub.assert_eq(bbr.mode, wing::BbrMode.ProbeBwDown, "dropped to ProbeBwDown on >2% loss");
        // inflight_hi reduced to 70% of 500,000 = 350,000 bytes
        sub.assert_eq(bbr.inflight_hi_bytes, 350000, "inflight_hi reduced by 70% beta");
    };

    t.run("BBR-02: 5-Second ProbeRTT Trigger & 0.5 BDP Floor") { sub =>
        var bbr = wing::new_bbr_state();
        bbr.bw_hi_bps = 80000000; // 80 Mbps
        bbr.min_rtt_us = 50000;   // 50 ms -> BDP = 500,000 bytes
        bbr.min_rtt_stamp_us = 1000000;
        bbr.mode = wing::BbrMode.ProbeBwCruise;

        // Check at t = 2s (within 5s window) -> remains in Cruise
        wing::bbr_check_probe_rtt(bbr, 2000000, 52000);
        sub.assert_eq(bbr.mode, wing::BbrMode.ProbeBwCruise, "remains in Cruise before 5s expiration");

        // Check at t = 6.1s (> 5s window) -> triggers ProbeRtt!
        wing::bbr_check_probe_rtt(bbr, 6100000, 51000);
        sub.assert_eq(bbr.mode, wing::BbrMode.ProbeRtt, "switched to ProbeRtt after 5s");
        // cwnd in ProbeRtt = max(0.5 * BDP, 4800) = 250,000 bytes
        sub.assert_eq(bbr.cwnd_bytes, 250000, "ProbeRtt cwnd set to 0.5 BDP floor");
    };

    t.run("CUBIC-01: Integer Cube Root & Application-Limited Freeze") { sub =>
        // Test int_cbrt exact values
        sub.assert_eq(wing::int_cbrt(0), 0, "cbrt(0) = 0");
        sub.assert_eq(wing::int_cbrt(1), 1, "cbrt(1) = 1");
        sub.assert_eq(wing::int_cbrt(8), 2, "cbrt(8) = 2");
        sub.assert_eq(wing::int_cbrt(27), 3, "cbrt(27) = 3");
        sub.assert_eq(wing::int_cbrt(1000), 10, "cbrt(1000) = 10");
        sub.assert_eq(wing::int_cbrt(1000000), 100, "cbrt(1000000) = 100");

        var cubic = wing::new_cubic_state();
        cubic.cwnd_segments = 20; // 20 * 1200 = 24000 bytes
        cubic.epoch_start_us = 1000000;
        cubic.last_update_us = 1000000;

        // Inflight = 10000 bytes (< 75% of 24000 = 18000) -> Application Limited!
        let cwnd1 = wing::cubic_on_ack(cubic, 2000000, 40000, 10000, 1200);
        sub.assert_true(cubic.app_limited, "sender detected as application-limited");
        sub.assert_eq(cwnd1, 24000, "cwnd frozen during application-limited period");
        // Epoch start advanced by 1s idle time (from 1000000 to 2000000)
        sub.assert_eq(cubic.epoch_start_us, 2000000, "epoch start frozen/advanced by elapsed idle time");
    };

    t.run("CUBIC-02: Loss Multiplicative Window Reduction (RFC 9438)") { sub =>
        var cubic = wing::new_cubic_state();
        cubic.cwnd_segments = 100;
        wing::cubic_on_loss(cubic, 5000000);
        sub.assert_eq(cubic.w_max_segments, 100, "w_max saved as 100");
        sub.assert_eq(cubic.cwnd_segments, 70, "cwnd reduced to 70 (beta 0.7)");
        sub.assert_eq(cubic.epoch_start_us, 5000000, "epoch start reset to now");
    };
}

// ============================================================================
// Main Conformance Runner
// ============================================================================
fn main() {
    var runner = core::new_runner("QUIC & HTTP/3 Echelon 7 Conformance Suite", core::Verbosity.Verbose);

    core::run_case(runner, "1. QPACK Static Table, Dynamic Table & Codecs (RFC 9204)", test_qpack_table_and_codecs);
    core::run_case(runner, "2. QPACK Header Accordion DoS Defenses & Post-Decode RIC", test_qpack_security_defenses);
    core::run_case(runner, "3. QUIC VarInt Codec & Packet Framing (RFC 9000)", test_quic_varint_and_framing);
    core::run_case(runner, "4. Header Protection & Packet Number Reconstruction (RFC 9001)", test_header_protection_and_pn);
    core::run_case(runner, "5. Anti-Amplification 3x & Zero-Heap Reassembly (RFC 9000)", test_anti_amplification_and_reassembly);
    core::run_case(runner, "6. ACK Framing, OACK Defense & 5-Priority PTO (RFC 9002)", test_ack_and_pto_engine);
    core::run_case(runner, "7. BBRv2/v3, CUBIC & Pacing Engine (RFC 9438)", test_bbr_cubic_and_pacing);

    let ok = core::finish(runner);
    assert(ok);
}
