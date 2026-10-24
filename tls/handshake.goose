// tls/handshake.goose
// Deterministic zero-allocation TLS 1.3 Handshake State Machine and Extensions.
// Conforms to RFC 8446 Sections 4 and 4.4, RFC 9001 (QUIC), RFC 6066 (SNI), and RFC 7301 (ALPN).
namespace wing;

import std;
import core from "..";
import tls.record;
import tls.key_schedule;

// ---- 1. Handshake Message Types (RFC 8446 Section 4) ------------------------

const HS_MSG_CLIENT_HELLO: u8 = 1;
const HS_MSG_SERVER_HELLO: u8 = 2;
const HS_MSG_NEW_SESSION_TICKET: u8 = 4;
const HS_MSG_END_OF_EARLY_DATA: u8 = 5;
const HS_MSG_ENCRYPTED_EXTENSIONS: u8 = 8;
const HS_MSG_CERTIFICATE: u8 = 11;
const HS_MSG_CERTIFICATE_REQUEST: u8 = 13;
const HS_MSG_CERTIFICATE_VERIFY: u8 = 15;
const HS_MSG_FINISHED: u8 = 20;
const HS_MSG_KEY_UPDATE: u8 = 24;
const HS_MSG_COMPRESSED_CERTIFICATE: u8 = 25; // RFC 8879 Section 4
const HS_MSG_MESSAGE_HASH: u8 = 254; // 0xFE synthetic HRR message

// ---- 2. Extension Type Identifiers ------------------------------------------

const EXT_SERVER_NAME: u16 = 0;              // RFC 6066
const EXT_STATUS_REQUEST: u16 = 5;           // OCSP stapling
const EXT_SUPPORTED_GROUPS: u16 = 10;
const EXT_SIGNATURE_ALGORITHMS: u16 = 13;
const EXT_ALPN: u16 = 16;                     // RFC 7301
const EXT_COMPRESS_CERTIFICATE: u16 = 27;     // RFC 8879 Section 3
const EXT_PRE_SHARED_KEY: u16 = 41;
const EXT_EARLY_DATA: u16 = 42;
const EXT_SUPPORTED_VERSIONS: u16 = 43;
const EXT_COOKIE: u16 = 44;
const EXT_PSK_KEY_EXCHANGE_MODES: u16 = 45;
const EXT_KEY_SHARE: u16 = 51;
const EXT_QUIC_TRANSPORT_PARAMETERS: u16 = 0x39; // RFC 9001 Section 8.2

// ---- 3. Handshake State ADT and Transitions ---------------------------------

enum HsState {
    ClientStart,
    ClientWaitSH,
    ClientWaitEE,
    ClientWaitCertCr,
    ClientWaitCert,
    ClientWaitCV,
    ClientWaitFinished,
    ServerWaitCH,
    ServerWaitEOED,
    ServerWaitCert,
    ServerWaitCV,
    ServerWaitFinished,
    Connected,
    Closed,
}

// Case functions for state transition validation.
fn can_client_transition(current: HsState, incoming_msg_type: u8) -> HsState, bool {
    if current == HsState.ClientWaitSH {
        if incoming_msg_type == HS_MSG_SERVER_HELLO {
            return HsState.ClientWaitEE, true;
        }
    } else if current == HsState.ClientWaitEE {
        if incoming_msg_type == HS_MSG_ENCRYPTED_EXTENSIONS {
            return HsState.ClientWaitCertCr, true;
        }
    } else if current == HsState.ClientWaitCertCr {
        if incoming_msg_type == HS_MSG_CERTIFICATE_REQUEST {
            return HsState.ClientWaitCert, true;
        }
        if incoming_msg_type == HS_MSG_CERTIFICATE {
            return HsState.ClientWaitCV, true;
        }
        if incoming_msg_type == HS_MSG_FINISHED {
            return HsState.ClientWaitFinished, true;
        }
    } else if current == HsState.ClientWaitCert {
        if incoming_msg_type == HS_MSG_CERTIFICATE {
            return HsState.ClientWaitCV, true;
        }
    } else if current == HsState.ClientWaitCV {
        if incoming_msg_type == HS_MSG_CERTIFICATE_VERIFY {
            return HsState.ClientWaitFinished, true;
        }
    } else if current == HsState.ClientWaitFinished {
        if incoming_msg_type == HS_MSG_FINISHED {
            return HsState.Connected, true;
        }
    } else if current == HsState.Connected {
        if incoming_msg_type == HS_MSG_NEW_SESSION_TICKET || incoming_msg_type == HS_MSG_KEY_UPDATE {
            return HsState.Connected, true;
        }
    }
    return HsState.Closed, false;
}

fn can_server_transition(current: HsState, incoming_msg_type: u8) -> HsState, bool {
    if current == HsState.ServerWaitCH {
        if incoming_msg_type == HS_MSG_CLIENT_HELLO {
            return HsState.ServerWaitFinished, true;
        }
    } else if current == HsState.ServerWaitEOED {
        if incoming_msg_type == HS_MSG_END_OF_EARLY_DATA {
            return HsState.ServerWaitFinished, true;
        }
    } else if current == HsState.ServerWaitCert {
        if incoming_msg_type == HS_MSG_CERTIFICATE {
            return HsState.ServerWaitCV, true;
        }
    } else if current == HsState.ServerWaitCV {
        if incoming_msg_type == HS_MSG_CERTIFICATE_VERIFY {
            return HsState.ServerWaitFinished, true;
        }
    } else if current == HsState.ServerWaitFinished {
        if incoming_msg_type == HS_MSG_FINISHED {
            return HsState.Connected, true;
        }
    } else if current == HsState.Connected {
        if incoming_msg_type == HS_MSG_KEY_UPDATE {
            return HsState.Connected, true;
        }
    }
    return HsState.Closed, false;
}

// ---- 4. Framing: Handshake Message Header -----------------------------------

// Handshake message header is 4 bytes: [msg_type: 1 byte] || [msg_len: 3 bytes (u24)].
fn parse_handshake_header(data: const u8[:]) -> u8, u32, bool {
    guard data.len >= 4 else { return 0, 0, false; }
    let msg_type = data[0];
    let msg_len = ((data[1] as u32) << 16) | ((data[2] as u32) << 8) | data[3];
    return msg_type, msg_len, true;
}

fn encode_handshake_header(msg_type: u8, msg_len: u32, out: u8[4]&) {
    out[0] = msg_type;
    out[1] = ((msg_len >> 16) & 0xFF) as u8;
    out[2] = ((msg_len >> 8) & 0xFF) as u8;
    out[3] = (msg_len & 0xFF) as u8;
}

// ---- 5. HelloRetryRequest & Synthetic message_hash Compression --------------

// RFC 8446 Section 4.1.3 HelloRetryRequest special random value:
// CF 21 AD 74 7E 00 7E 27 9F 7F 07 E0 EB 10 DC 03 BE 3D 68 A8 63 FE 95 D6 53 0E 32 30 79 28 8A 2D
const HRR_RANDOM: u8[32] = [
    0xCF, 0x21, 0xAD, 0x74, 0x7E, 0x00, 0x7E, 0x27,
    0x9F, 0x7F, 0x07, 0xE0, 0xEB, 0x10, 0xDC, 0x03,
    0xBE, 0x3D, 0x68, 0xA8, 0x63, 0xFE, 0x95, 0xD6,
    0x53, 0x0E, 0x32, 0x30, 0x79, 0x28, 0x8A, 0x2D,
];

fn is_hello_retry_request(server_random: const u8[32]&) -> bool {
    return core::ct_eq_tag32(server_random, HRR_RANDOM);
}

// Generates synthetic message_hash handshake message (RFC 8446 Section 4.4.1):
// struct {
//     HandshakeType msg_type = message_hash (254);
//     uint24 length = Hash.length;
//     opaque hash[Hash.length];
// }
// Output buffer must have capacity >= 4 + hash_len (36 for SHA-256, 52 for SHA-384).
fn compress_hrr_transcript(
    hash_len: u8,
    ch1_hash: const u8[:],
    out: u8[:]
) -> i64, bool {
    guard ch1_hash.len == hash_len else { return 0, false; }
    let total_len = 4 + (hash_len as i64);
    guard out.len >= total_len else { return 0, false; }

    out[0] = HS_MSG_MESSAGE_HASH;
    out[1] = 0x00;
    out[2] = 0x00;
    out[3] = hash_len;

    for i in hash_len {
        out[4 + i] = ch1_hash[i];
    }
    return total_len, true;
}

// ---- 6. SNI Extension Parser (RFC 6066 Section 3) ---------------------------

// Parses server_name extension:
// struct {
//     ServerName server_name_list<1..2^16-1>;
// } ServerNameList;
// struct {
//     NameType name_type; // 0 = host_name
//     opaque host_name<1..2^16-1>;
// } ServerName;
//
// Validation rules:
// - name_type must be 0 (host_name)
// - host_name length must be 1..255
// - no NUL bytes permitted
// - IPv4 and IPv6 address literals strictly forbidden in host_name (RFC 6066 Section 3)
// - Normalized to ASCII lowercase
fn parse_sni_extension(ext_bytes: const u8[:], out_sni: u8[..255]&) -> bool {
    out_sni.clear();
    var cursor = cursor_from(ext_bytes);

    var list_cursor = cursor_from(ext_bytes[..0]);
    if !get_u16_length_prefixed(cursor, list_cursor) {
        return false;
    }

    while cursor_len(list_cursor) > 0 {
        var name_type: u8 = 0;
        if !get_u8(list_cursor, name_type) { return false; }

        var name_bytes = cursor_from(ext_bytes[..0]);
        if !get_u16_length_prefixed(list_cursor, name_bytes) { return false; }

        if name_type == 0 { // host_name
            let raw = name_bytes.buf;
            guard raw.len >= 1 && raw.len <= 255 else { return false; }

            // Reject NUL bytes and check for IP address format
            var has_colon = false;
            var is_all_digits_and_dots = true;

            for b in raw {
                if b == 0 { return false; }
                if b == ':' { has_colon = true; }
                if !(b >= '0' && b <= '9') && b != '.' {
                    is_all_digits_and_dots = false;
                }
            }

            // Reject literal IPv6 (has colon) or IPv4 (only digits and dots)
            if has_colon || (is_all_digits_and_dots && raw.len > 0) {
                return false;
            }

            // Copy and normalize to lowercase
            for b in raw {
                var ch = b;
                if ch >= 'A' && ch <= 'Z' {
                    ch += 32;
                }
                out_sni.push(ch);
            }
            return true;
        }
    }
    return false;
}

// ---- 7. ALPN Negotiation (RFC 7301) -----------------------------------------

enum NegotiatedAlpn {
    None,
    H3,
    H2,
    Http11,
    Other,
}

// Parses ALPN ProtocolNameList and negotiates best matching protocol.
// For QUIC (is_quic == true): strictly requires "h3" (RFC 9001 Section 8.1).
// For TCP (is_quic == false): prefers "h2", then "http/1.1".
fn negotiate_alpn(alpn_ext_bytes: const u8[:], is_quic: bool) -> NegotiatedAlpn {
    var cursor = cursor_from(alpn_ext_bytes);
    var list_cursor = cursor_from(alpn_ext_bytes[..0]);
    if !get_u16_length_prefixed(cursor, list_cursor) {
        return NegotiatedAlpn.None;
    }

    var has_h3 = false;
    var has_h2 = false;
    var has_http11 = false;
    var has_any = false;

    while cursor_len(list_cursor) > 0 {
        var proto_cursor = cursor_from(alpn_ext_bytes[..0]);
        if !get_u8_length_prefixed(list_cursor, proto_cursor) {
            return NegotiatedAlpn.None;
        }
        let proto = proto_cursor.buf;
        if proto.len == 0 { return NegotiatedAlpn.None; }

        // RFC 7301 Section 3.1 & Go #40928: Protocol names MUST NOT contain NUL bytes
        for b in proto {
            if b == 0 {
                return NegotiatedAlpn.None;
            }
        }

        has_any = true;
        if proto.len == 2 && proto[0] == 'h' && proto[1] == '3' {
            has_h3 = true;
        } else if proto.len == 2 && proto[0] == 'h' && proto[1] == '2' {
            has_h2 = true;
        } else if proto.len == 8 &&
                  proto[0] == 'h' && proto[1] == 't' && proto[2] == 't' && proto[3] == 'p' &&
                  proto[4] == '/' && proto[5] == '1' && proto[6] == '.' && proto[7] == '1' {
            has_http11 = true;
        }
    }

    if is_quic {
        if has_h3 {
            return NegotiatedAlpn.H3;
        }
        return NegotiatedAlpn.None;
    } else {
        if has_h2 {
            return NegotiatedAlpn.H2;
        }
        if has_http11 {
            return NegotiatedAlpn.Http11;
        }
        if has_any {
            return NegotiatedAlpn.Other;
        }
    }
    return NegotiatedAlpn.None;
}

// ---- 8. Extensions Parser Combinator ----------------------------------------

struct TlsExtensionEntry {
    ext_type: u16 = 0,
    data: const u8[:] = [],
}

// Parses extension block into static array of entries without heap allocation.
fn parse_extensions_block(
    ext_block_bytes: const u8[:],
    entries: TlsExtensionEntry[..32]&
) -> bool {
    entries.clear();
    var cursor = cursor_from(ext_block_bytes);
    var extensions_cursor = cursor_from(ext_block_bytes[..0]);

    if !get_u16_length_prefixed(cursor, extensions_cursor) {
        return false;
    }

    while cursor_len(extensions_cursor) > 0 {
        var ext_type: u16 = 0;
        if !get_u16(extensions_cursor, ext_type) { return false; }

        var ext_data = cursor_from(ext_block_bytes[..0]);
        if !get_u16_length_prefixed(extensions_cursor, ext_data) { return false; }

        if entries.len < entries.cap {
            entries.push(TlsExtensionEntry {
                ext_type: ext_type,
                data: ext_data.buf,
            });
        }
    }
    return true;
}

// Finds an extension by type in the parsed entries array.
fn find_extension(entries: const TlsExtensionEntry[..32]&, ext_type: u16, out_data: const u8[:]&) -> bool {
    for i in entries.len {
        if entries[i].ext_type == ext_type {
            out_data = entries[i].data;
            return true;
        }
    }
    return false;
}

// ---- 9. RFC 8879 Certificate Compression & ClientHello Fragmentation --------

const CERT_COMPRESS_ZLIB: u16   = 1;
const CERT_COMPRESS_BROTLI: u16 = 2;
const CERT_COMPRESS_ZSTD: u16   = 3; // RFC 8879 Section 3 (Zstandard)

struct CompressedCertMsg {
    algorithm: u16 = CERT_COMPRESS_ZSTD,
    uncompressed_len: u32 = 0,
    compressed_data: const u8[:],
}

// Encodes the client's `compress_certificate` extension (RFC 8879 Section 3)
fn encode_compress_certificate_extension<B>(out: B&, algorithms: const u16[:]) {
    out.push(((EXT_COMPRESS_CERTIFICATE >> 8) & 0xFF) as u8);
    out.push((EXT_COMPRESS_CERTIFICATE & 0xFF) as u8);

    let ext_len = 1 + algorithms.len * 2;
    out.push(((ext_len >> 8) & 0xFF) as u8);
    out.push((ext_len & 0xFF) as u8);

    let list_len = (algorithms.len * 2) as u8;
    out.push(list_len);
    for algo in algorithms {
        out.push(((algo >> 8) & 0xFF) as u8);
        out.push((algo & 0xFF) as u8);
    }
}

// Parses a CompressedCertificate handshake message payload (RFC 8879 Section 4)
fn parse_compressed_certificate(payload: const u8[:]) -> CompressedCertMsg, bool {
    var msg = CompressedCertMsg { compressed_data: payload[..0], .. };
    guard payload.len >= 5 else { return msg, false; }

    let algo = ((payload[0] as u16) << 8) | payload[1];
    let ulen = ((payload[2] as u32) << 16) | ((payload[3] as u32) << 8) | payload[4];
    guard ulen > 0 && ulen <= 16777215 else { return msg, false; }

    msg.algorithm = algo;
    msg.uncompressed_len = ulen;
    msg.compressed_data = payload[5..];
    return msg, true;
}

// Encodes a CompressedCertificate handshake message payload (RFC 8879 Section 4)
fn encode_compressed_certificate_payload<B>(
    out: B&,
    algorithm: u16,
    uncompressed_len: u32,
    compressed_data: const u8[:]
) {
    out.push(((algorithm >> 8) & 0xFF) as u8);
    out.push((algorithm & 0xFF) as u8);
    out.push(((uncompressed_len >> 16) & 0xFF) as u8);
    out.push(((uncompressed_len >> 8) & 0xFF) as u8);
    out.push((uncompressed_len & 0xFF) as u8);
    out.append(compressed_data);
}

// Decompresses a CompressedCertificate using Wing's pure RFC 8878 Zstandard engine
fn decompress_certificate_zstd<B>(compressed_data: const u8[:], uncompressed_len: u32, out_cert: B&) -> bool {
    let ok, _ = core::decompress_zstd(compressed_data, out_cert);
    guard ok else { return false; }
    guard (out_cert.len as u32) == uncompressed_len else { return false; }
    return true;
}

// Splits a TLS ClientHello into multiple TLS records (RFC 8446 Section 5.1).
// This evades naive Middlebox / DPI SNI filtering by splitting the ClientHello record
// across two or more records without altering cryptographic validity.
fn fragment_client_hello<B>(
    raw_ch: const u8[:],
    first_record_len: i64,
    out_records: B&
) -> bool {
    guard first_record_len > 0 && first_record_len < raw_ch.len else { return false; }

    // Record 1: type 22 (handshake), legacy version 0x0301 (TLS 1.0)
    out_records.push(22);
    out_records.push(0x03); out_records.push(0x01);
    out_records.push(((first_record_len >> 8) & 0xFF) as u8);
    out_records.push((first_record_len & 0xFF) as u8);
    out_records.append(raw_ch[..first_record_len]);

    // Record 2: type 22 (handshake), legacy version 0x0301 (TLS 1.0)
    let rem_len = raw_ch.len - first_record_len;
    out_records.push(22);
    out_records.push(0x03); out_records.push(0x01);
    out_records.push(((rem_len >> 8) & 0xFF) as u8);
    out_records.push((rem_len & 0xFF) as u8);
    out_records.append(raw_ch[first_record_len..]);

    return true;
}
