// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// HTTP/3, QPACK, and QUIC transport wire constants.
// Conforms to RFC 9114, RFC 9204, RFC 9000, RFC 9001, RFC 9221, and RFC 9369.
namespace rfc;

import std;

// ---- QUIC Protocol Versions & Wire Limits (RFC 9000, RFC 9369) -----------

const QUIC_VERSION_1:                u32 = 0x00000001;         // RFC 9000 Section 15
const QUIC_VERSION_2:                u32 = 0x6b3343cf;         // RFC 9369 Section 3.1
const QUIC_VERSION_NEGOTIATION:      u32 = 0x00000000;         // RFC 9000 Section 15
const QUIC_MIN_INITIAL_DATAGRAM_LEN: u64 = 1200;               // RFC 9000 Section 8.1
const QUIC_MAX_CID_LEN:              u8  = 20;                 // RFC 9000 Section 17.2
const QUIC_VARINT_MAX:               u64 = 0x3FFFFFFFFFFFFFFF; // RFC 9000 Section 16 (2^62 - 1)
const QUIC_MAX_STREAMS_LIMIT:        u64 = 0x1000000000000000; // RFC 9000 Section 19.11 (2^60)

// ---- QUIC Transport Error Codes (RFC 9000 Section 20.1) ------------------

const QUIC_ERR_NO_ERROR:               u64 = 0x00;
const QUIC_ERR_INTERNAL:               u64 = 0x01;
const QUIC_ERR_CONNECTION_REFUSED:     u64 = 0x02;
const QUIC_ERR_FLOW_CONTROL:           u64 = 0x03;
const QUIC_ERR_STREAM_LIMIT:           u64 = 0x04;
const QUIC_ERR_STREAM_STATE:           u64 = 0x05;
const QUIC_ERR_FINAL_SIZE:             u64 = 0x06;
const QUIC_ERR_FRAME_ENCODING:         u64 = 0x07;
const QUIC_ERR_TRANSPORT_PARAMETER:    u64 = 0x08;
const QUIC_ERR_CONNECTION_ID_LIMIT:    u64 = 0x09;
const QUIC_ERR_PROTOCOL_VIOLATION:     u64 = 0x0A;
const QUIC_ERR_INVALID_TOKEN:          u64 = 0x0B;
const QUIC_ERR_APPLICATION_ERROR:      u64 = 0x0C;
const QUIC_ERR_CRYPTO_BUFFER_EXCEEDED: u64 = 0x0D;
const QUIC_ERR_KEY_UPDATE_ERROR:       u64 = 0x0E;
const QUIC_ERR_AEAD_LIMIT_REACHED:     u64 = 0x0F;
const QUIC_ERR_NO_VIABLE_PATH:         u64 = 0x10;

// ---- QUIC Frame Types (RFC 9000 Section 19 & RFC 9221 Section 3) ---------

const QUIC_FRAME_PADDING:              u64 = 0x00;
const QUIC_FRAME_PING:                 u64 = 0x01;
const QUIC_FRAME_ACK:                  u64 = 0x02;
const QUIC_FRAME_ACK_ECN:              u64 = 0x03;
const QUIC_FRAME_RESET_STREAM:         u64 = 0x04;
const QUIC_FRAME_STOP_SENDING:         u64 = 0x05;
const QUIC_FRAME_CRYPTO:               u64 = 0x06;
const QUIC_FRAME_NEW_TOKEN:            u64 = 0x07;
const QUIC_FRAME_STREAM_BASE:          u64 = 0x08;
const QUIC_FRAME_MAX_DATA:             u64 = 0x10;
const QUIC_FRAME_MAX_STREAM_DATA:      u64 = 0x11;
const QUIC_FRAME_MAX_STREAMS_BIDI:     u64 = 0x12;
const QUIC_FRAME_MAX_STREAMS_UNI:      u64 = 0x13;
const QUIC_FRAME_DATA_BLOCKED:         u64 = 0x14;
const QUIC_FRAME_STREAM_DATA_BLOCKED:  u64 = 0x15;
const QUIC_FRAME_STREAMS_BLOCKED_BIDI: u64 = 0x16;
const QUIC_FRAME_STREAMS_BLOCKED_UNI:  u64 = 0x17;
const QUIC_FRAME_NEW_CONNECTION_ID:    u64 = 0x18;
const QUIC_FRAME_RETIRE_CONNECTION_ID: u64 = 0x19;
const QUIC_FRAME_PATH_CHALLENGE:       u64 = 0x1A;
const QUIC_FRAME_PATH_RESPONSE:        u64 = 0x1B;
const QUIC_FRAME_CONNECTION_CLOSE:     u64 = 0x1C;
const QUIC_FRAME_CONNECTION_CLOSE_APP: u64 = 0x1D;
const QUIC_FRAME_HANDSHAKE_DONE:       u64 = 0x1E;
const QUIC_FRAME_IMMEDIATE_ACK:        u64 = 0x1F; // draft-ietf-quic-ack-frequency Section 4.2
const QUIC_FRAME_DATAGRAM:             u64 = 0x30; // RFC 9221 Section 3
const QUIC_FRAME_DATAGRAM_LEN:         u64 = 0x31; // RFC 9221 Section 3
const QUIC_FRAME_ACK_FREQUENCY:        u64 = 0xAF; // draft-ietf-quic-ack-frequency Section 4.1

// ---- QUIC Transport Parameters (RFC 9000 Section 18, RFC 9221, RFC 9287, RFC 9368) -

const QUIC_TP_ORIGINAL_DESTINATION_CONNECTION_ID:  u64 = 0x00;   // RFC 9000 Section 18.2
const QUIC_TP_MAX_IDLE_TIMEOUT:                    u64 = 0x01;   // RFC 9000 Section 18.2
const QUIC_TP_STATELESS_RESET_TOKEN:               u64 = 0x02;   // RFC 9000 Section 18.2
const QUIC_TP_MAX_UDP_PAYLOAD_SIZE:                u64 = 0x03;   // RFC 9000 Section 18.2
const QUIC_TP_INITIAL_MAX_DATA:                    u64 = 0x04;   // RFC 9000 Section 18.2
const QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL:  u64 = 0x05;   // RFC 9000 Section 18.2
const QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: u64 = 0x06;   // RFC 9000 Section 18.2
const QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI:         u64 = 0x07;   // RFC 9000 Section 18.2
const QUIC_TP_INITIAL_MAX_STREAMS_BIDI:            u64 = 0x08;   // RFC 9000 Section 18.2
const QUIC_TP_INITIAL_MAX_STREAMS_UNI:             u64 = 0x09;   // RFC 9000 Section 18.2
const QUIC_TP_ACK_DELAY_EXPONENT:                  u64 = 0x0A;   // RFC 9000 Section 18.2
const QUIC_TP_MAX_ACK_DELAY:                       u64 = 0x0B;   // RFC 9000 Section 18.2
const QUIC_TP_DISABLE_ACTIVE_MIGRATION:            u64 = 0x0C;   // RFC 9000 Section 18.2
const QUIC_TP_PREFERRED_ADDRESS:                   u64 = 0x0D;   // RFC 9000 Section 18.2
const QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT:          u64 = 0x0E;   // RFC 9000 Section 18.2
const QUIC_TP_INITIAL_SOURCE_CONNECTION_ID:        u64 = 0x0F;   // RFC 9000 Section 18.2
const QUIC_TP_RETRY_SOURCE_CONNECTION_ID:          u64 = 0x10;   // RFC 9000 Section 18.2
const QUIC_TP_VERSION_INFORMATION:                 u64 = 0x11;   // RFC 9368 Section 3
const QUIC_TP_MAX_DATAGRAM_FRAME_SIZE:             u64 = 0x20;   // RFC 9221 Section 3
const QUIC_TP_GREASE_QUIC_BIT:                     u64 = 0x2AB2; // RFC 9287 Section 3
const QUIC_TP_MIN_ACK_DELAY:                       u64 = 0xDE1A; // draft-ietf-quic-ack-frequency Section 3

// ---- HTTP/3 & QPACK Constants (RFC 9114 & RFC 9204) ----------------------

const QPACK_STATIC_TABLE_SIZE: u64 = 99; // RFC 9204 Appendix A
const QPACK_ENTRY_OVERHEAD:    u64 = 32; // RFC 9204 Section 3.2.1

// HTTP/3 Error Codes (RFC 9114 Section 8.1 & RFC 9204 Section 2.2.3)
const H3_ERR_NO_ERROR:                   u64 = 0x0100;
const H3_ERR_GENERAL_PROTOCOL:           u64 = 0x0101;
const H3_ERR_INTERNAL:                   u64 = 0x0102;
const H3_ERR_STREAM_CREATION:            u64 = 0x0103;
const H3_ERR_CLOSED_CRITICAL_STREAM:     u64 = 0x0104;
const H3_ERR_FRAME_UNEXPECTED:           u64 = 0x0105;
const H3_ERR_FRAME_ERROR:                u64 = 0x0106;
const H3_ERR_EXCESSIVE_LOAD:             u64 = 0x0107;
const H3_ERR_ID_ERROR:                   u64 = 0x0108;
const H3_ERR_SETTINGS_ERROR:             u64 = 0x0109;
const H3_ERR_MISSING_SETTINGS:           u64 = 0x010A;
const H3_ERR_REQUEST_REJECTED:           u64 = 0x010B;
const H3_ERR_REQUEST_CANCELLED:          u64 = 0x010C;
const H3_ERR_REQUEST_INCOMPLETE:         u64 = 0x010D;
const H3_ERR_MESSAGE_ERROR:              u64 = 0x010E;
const H3_ERR_CONNECT_ERROR:              u64 = 0x010F;
const H3_ERR_VERSION_FALLBACK:           u64 = 0x0110;
const H3_ERR_QPACK_DECOMPRESSION_FAILED: u64 = 0x0200;
const H3_ERR_QPACK_ENCODER_STREAM_ERROR: u64 = 0x0201;
const H3_ERR_QPACK_DECODER_STREAM_ERROR: u64 = 0x0202;

// HTTP/3 Frame Types (RFC 9114 Section 7.2 & RFC 9218 Section 7.2)
const H3_FRAME_DATA:                    u64 = 0x00;
const H3_FRAME_HEADERS:                 u64 = 0x01;
const H3_FRAME_CANCEL_PUSH:             u64 = 0x03;
const H3_FRAME_SETTINGS:                u64 = 0x04;
const H3_FRAME_PUSH_PROMISE:            u64 = 0x05;
const H3_FRAME_GOAWAY:                  u64 = 0x07;
const H3_FRAME_ORIGIN:                  u64 = 0x0C;
const H3_FRAME_MAX_PUSH_ID:             u64 = 0x0D;
const H3_FRAME_PRIORITY_UPDATE_REQUEST: u64 = 0xF0700; // RFC 9218 Section 7.2
const H3_FRAME_PRIORITY_UPDATE_PUSH:    u64 = 0xF0701; // RFC 9218 Section 7.2

// HTTP/3 Unidirectional Stream Types (RFC 9114 Section 6.2 & RFC 9204 Section 4.2)
const H3_STREAM_CONTROL:       u64 = 0x00;
const H3_STREAM_PUSH:          u64 = 0x01;
const H3_STREAM_QPACK_ENCODER: u64 = 0x02;
const H3_STREAM_QPACK_DECODER: u64 = 0x03;

// HTTP/3 Settings Identifiers (RFC 9114 Section 7.2.4.1 & RFC 9204 Section 5)
const H3_SETTING_QPACK_MAX_TABLE_CAPACITY: u64 = 0x01;
const H3_SETTING_MAX_FIELD_SECTION_SIZE:   u64 = 0x06;
const H3_SETTING_QPACK_BLOCKED_STREAMS:    u64 = 0x07;
const H3_SETTING_ENABLE_CONNECT_PROTOCOL:  u64 = 0x08; // RFC 9220 Section 3
const H3_SETTING_H3_DATAGRAM:              u64 = 0x33; // RFC 9297 Section 2.1.1

// RFC 9114 Section 7.2.8: Reserved Frame Types - Frame types 0x1f * N + 0x21 within 62-bit varint bounds.
inline fn is_h3_grease_frame(frame_type: u64) -> bool {
    guard frame_type >= 0x21 && frame_type <= QUIC_VARINT_MAX else { return false; }
    return ((frame_type - 0x21) % 0x1F) == 0;
}

// RFC 9114 Section 7.2.8: Reserved Frame Types - Checks if a frame type is reserved from HTTP/2 (0x02, 0x06, 0x08, 0x09).
inline fn is_h2_reserved_frame_in_h3(frame_type: u64) -> bool {
    return frame_type == 0x02 || frame_type == 0x06 || frame_type == 0x08 || frame_type == 0x09;
}

// RFC 9114 Section 7.2: Frame Definitions - Checks if a frame is permitted on the HTTP/3 Control Stream.
inline fn is_allowed_on_control_stream(frame_type: u64) -> bool {
    guard frame_type <= QUIC_VARINT_MAX && !is_h2_reserved_frame_in_h3(frame_type) else { return false; }
    return frame_type != H3_FRAME_DATA &&
           frame_type != H3_FRAME_HEADERS &&
           frame_type != H3_FRAME_PUSH_PROMISE;
}

// RFC 9114 Section 7.2: Frame Definitions - Checks if a frame is permitted on an HTTP/3 Request Stream (RFC 9218 Section 7.2).
inline fn is_allowed_on_request_stream(frame_type: u64) -> bool {
    guard frame_type <= QUIC_VARINT_MAX && !is_h2_reserved_frame_in_h3(frame_type) else { return false; }
    if frame_type == H3_FRAME_SETTINGS || frame_type == H3_FRAME_GOAWAY ||
       frame_type == H3_FRAME_CANCEL_PUSH || frame_type == H3_FRAME_MAX_PUSH_ID ||
       frame_type == H3_FRAME_ORIGIN ||
       frame_type == H3_FRAME_PRIORITY_UPDATE_REQUEST || frame_type == H3_FRAME_PRIORITY_UPDATE_PUSH {
        return false;
    }
    return true;
}

// RFC 9114 Section 7.2.4.1: Defined SETTINGS Parameters - Checks if a setting identifier is reserved from HTTP/2 (0x00, 0x02..0x05).
inline fn is_h2_reserved_setting_in_h3(id: u64) -> bool {
    return id == 0x00 || id == 0x02 || id == 0x03 || id == 0x04 || id == 0x05;
}

// ---- QUIC Stream Flags, Initial Salts & Loss Recovery (RFC 9000, 9001, 9002)

const QUIC_STREAM_FLAG_FIN: u64 = 0x01; // RFC 9000 Section 19.8
const QUIC_STREAM_FLAG_LEN: u64 = 0x02; // RFC 9000 Section 19.8
const QUIC_STREAM_FLAG_OFF: u64 = 0x04; // RFC 9000 Section 19.8
const QUIC_STREAM_MAX_TYPE: u64 = 0x0F; // RFC 9000 Section 19.8

const QUIC_MAX_PN:   u64 = 0x3FFFFFFFFFFFFFFF; // RFC 9000 Section 17.1 (2^62 - 1)
const QUIC_PN_LIMIT: u64 = (1 as u64) << 62;   // RFC 9000 Section 17.1 (2^62)

const QUIC_V1_INITIAL_SALT: const u8[..20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
    0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
]; // RFC 9001 Section 5.2

const QUIC_V2_INITIAL_SALT: const u8[..20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
    0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
]; // RFC 9369 Section 3.3.1

const QUIC_V1_RETRY_KEY: const u8[..16] = [
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a,
    0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
]; // RFC 9001 Section 5.8

const QUIC_V1_RETRY_NONCE: const u8[..12] = [
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
]; // RFC 9001 Section 5.8

const QUIC_V2_RETRY_KEY: const u8[..16] = [
    0x8f, 0xb4, 0xb0, 0x1b, 0x56, 0xac, 0x48, 0xe2,
    0x60, 0xfb, 0xcb, 0xce, 0xad, 0x7c, 0xcc, 0x92,
]; // RFC 9369 Section 3.3.3

const QUIC_V2_RETRY_NONCE: const u8[..12] = [
    0xd8, 0x69, 0x69, 0xbc, 0x2d, 0x7c, 0x6d, 0x99, 0x90, 0xef, 0xb0, 0x4a,
]; // RFC 9369 Section 3.3.3

const QUIC_AES_GCM_CONFIDENTIALITY_LIMIT: u64 = (1 as u64) << 23; // RFC 9001 Section 6.6
const QUIC_AES_GCM_INTEGRITY_LIMIT:       u64 = (1 as u64) << 52; // RFC 9001 Section 6.6
const QUIC_CHACHA20_INTEGRITY_LIMIT:      u64 = (1 as u64) << 36; // RFC 9001 Section 6.6

const QUIC_LOSS_PACKET_THRESHOLD: u64 = 3;    // RFC 9002 Section 6.1.1 (kPacketThreshold)
const QUIC_LOSS_TIME_NUMERATOR:   u64 = 9;    // RFC 9002 Section 6.1.2 (9/8 kTimeThreshold)
const QUIC_LOSS_TIME_DENOMINATOR: u64 = 8;    // RFC 9002 Section 6.1.2
const QUIC_TIMER_GRANULARITY_US:  u64 = 1000; // RFC 9002 Section 6.1.2 (1 ms kGranularity)

const PMTU_BASE:         u32 = 1200; // RFC 9000 Section 14.1
const PMTU_IPV6_MIN:     u32 = 1280; // RFC 8899 Section 5.1.2
const PMTU_INTERMEDIATE: u32 = 1420; // RFC 8899 Section 5.1.2
const PMTU_ETHERNET:     u32 = 1500; // RFC 8899 Section 5.1.2

// ---- HTTP Datagrams, MASQUE & WebTransport (RFC 9297, RFC 9298, RFC 9484) --

const CAPSULE_DATAGRAM:                  u64 = 0x00;       // RFC 9297 Section 3.5
const CAPSULE_ADDRESS_ASSIGN:            u64 = 0x01;       // RFC 9484 Section 4.7.1
const CAPSULE_ADDRESS_REQUEST:           u64 = 0x02;       // RFC 9484 Section 4.7.2
const CAPSULE_ROUTE_ADVERTISEMENT:       u64 = 0x03;       // RFC 9484 Section 4.7.3
const CAPSULE_WT_RESET_STREAM:           u64 = 0x190B4D39;
const CAPSULE_WT_STOP_SENDING:           u64 = 0x190B4D3A;
const CAPSULE_CLOSE_WEBTRANSPORT:        u64 = 0x2843;
const CAPSULE_DRAIN_WEBTRANSPORT:        u64 = 0x78AE;
const CAPSULE_DRAFT_ADDRESS_ASSIGN:      u64 = 0x3861;
const CAPSULE_DRAFT_ADDRESS_REQUEST:     u64 = 0x3862;
const CAPSULE_DRAFT_ROUTE_ADVERTISEMENT: u64 = 0x3863;

const MASQUE_PROTOCOL_CONNECT_UDP: const u8[:] = "connect-udp";      // RFC 9298 Section 3
const MASQUE_PROTOCOL_CONNECT_IP:  const u8[:] = "connect-ip";       // RFC 9484 Section 3
const MASQUE_CAPSULE_HEADER:       const u8[:] = "capsule-protocol"; // RFC 9297 Section 3.4
const MASQUE_CAPSULE_VALUE:        const u8[:] = "?1";               // RFC 9297 Section 3.4

const WEBTRANSPORT_PROTOCOL:              const u8[:] = "webtransport";
const SETTINGS_WEBTRANSPORT_MAX_SESSIONS: u64         = 0x2b603742;
const STREAM_TYPE_WEBTRANSPORT:           u64         = 0x54;
const WEBTRANSPORT_BIDI_SIGNAL:           u64         = 0x41;
const WEBTRANSPORT_ERROR_FIRST:           u64         = 0x52e4a40fa8db;
const WEBTRANSPORT_ERROR_LAST:            u64         = 0x52e5ac983162;

// ---- DNS, HTTPS/SVCB RR, Happy Eyeballs & IP ECN (RFC 1035, 9460, 8305, 3168)

const DNS_QTYPE_A:     u16 = 1;  // RFC 1035 Section 3.2.2
const DNS_QTYPE_AAAA:  u16 = 28; // RFC 8484 Section 4.1
const DNS_QTYPE_SVCB:  u16 = 64; // RFC 9460 Section 14.1
const DNS_QTYPE_HTTPS: u16 = 65; // RFC 9460 Section 14.2
const DNS_QCLASS_IN:   u16 = 1;  // RFC 1035 Section 3.2.4

const DNS_RCODE_NOERROR:  u8 = 0; // RFC 1035 Section 4.1.1
const DNS_RCODE_FORMERR:  u8 = 1; // RFC 1035 Section 4.1.1
const DNS_RCODE_SERVFAIL: u8 = 2; // RFC 1035 Section 4.1.1
const DNS_RCODE_NXDOMAIN: u8 = 3; // RFC 1035 Section 4.1.1

const SVC_PARAM_MANDATORY:       u16 = 0; // RFC 9460 Section 14.3.2
const SVC_PARAM_ALPN:            u16 = 1; // RFC 9460 Section 14.3.2
const SVC_PARAM_NO_DEFAULT_ALPN: u16 = 2; // RFC 9460 Section 14.3.2
const SVC_PARAM_PORT:            u16 = 3; // RFC 9460 Section 14.3.2
const SVC_PARAM_IPV4HINT:        u16 = 4; // RFC 9460 Section 14.3.2
const SVC_PARAM_ECH:             u16 = 5; // RFC 9460 Section 14.3.2
const SVC_PARAM_IPV6HINT:        u16 = 6; // RFC 9460 Section 14.3.2

const HE_RESOLUTION_DELAY_MS:            i64 = 50;   // RFC 8305 Section 8
const HE_FIRST_ADDRESS_FAMILY_COUNT:     i32 = 1;    // RFC 8305 Section 8
const HE_DEFAULT_CAD_MS:                 i64 = 250;  // RFC 8305 Section 8
const HE_MIN_CAD_MS:                     i64 = 100;  // RFC 8305 Section 8
const HE_ABSOLUTE_FLOOR_CAD_MS:          i64 = 10;   // RFC 8305 Section 8
const HE_MAX_CAD_MS:                     i64 = 2000; // RFC 8305 Section 8
const HE_LAST_RESORT_SYNTHESIS_DELAY_MS: i64 = 2000; // RFC 8305 Section 8
const HE_ADDRESS_FAMILY_CACHE_TTL_SEC:   i64 = 600;  // RFC 8305 Section 8

const ECN_NOT_ECT: u8 = 0x00; // RFC 3168 Section 5
const ECN_ECT_1:   u8 = 0x01; // RFC 3168 Section 5
const ECN_ECT_0:   u8 = 0x02; // RFC 3168 Section 5
const ECN_CE:      u8 = 0x03; // RFC 3168 Section 5
const ECN_MASK:    u8 = 0x03; // RFC 3168 Section 5

// ---- SOCKS5 Protocol Wire Constants (RFC 1928 & RFC 1929) ----------------

const SOCKS5_VER:         u8 = 0x05; // RFC 1928 Section 3
const SOCKS5_RFC1929_VER: u8 = 0x01; // RFC 1929 Section 2

const SOCKS5_AUTH_NONE:          u8 = 0x00; // RFC 1928 Section 3
const SOCKS5_AUTH_GSSAPI:        u8 = 0x01; // RFC 1928 Section 3
const SOCKS5_AUTH_USERPASS:      u8 = 0x02; // RFC 1928 Section 3
const SOCKS5_AUTH_NO_ACCEPTABLE: u8 = 0xFF; // RFC 1928 Section 3

const SOCKS5_CMD_CONNECT:       u8 = 0x01; // RFC 1928 Section 4
const SOCKS5_CMD_BIND:          u8 = 0x02; // RFC 1928 Section 4
const SOCKS5_CMD_UDP_ASSOCIATE: u8 = 0x03; // RFC 1928 Section 4

const SOCKS5_ATYP_IPV4:   u8 = 0x01; // RFC 1928 Section 5
const SOCKS5_ATYP_DOMAIN: u8 = 0x03; // RFC 1928 Section 5
const SOCKS5_ATYP_IPV6:   u8 = 0x04; // RFC 1928 Section 5

const SOCKS5_REP_SUCCEEDED:          u8 = 0x00; // RFC 1928 Section 6
const SOCKS5_REP_GENERAL_FAILURE:    u8 = 0x01; // RFC 1928 Section 6
const SOCKS5_REP_NOT_ALLOWED:        u8 = 0x02; // RFC 1928 Section 6
const SOCKS5_REP_NET_UNREACHABLE:    u8 = 0x03; // RFC 1928 Section 6
const SOCKS5_REP_HOST_UNREACHABLE:   u8 = 0x04; // RFC 1928 Section 6
const SOCKS5_REP_CONN_REFUSED:       u8 = 0x05; // RFC 1928 Section 6
const SOCKS5_REP_TTL_EXPIRED:        u8 = 0x06; // RFC 1928 Section 6
const SOCKS5_REP_CMD_NOT_SUPPORTED:  u8 = 0x07; // RFC 1928 Section 6
const SOCKS5_REP_ATYP_NOT_SUPPORTED: u8 = 0x08; // RFC 1928 Section 6

// ---- QUIC Initial Salts & HKDF Label Prefixes (RFC 9001 §5.2, RFC 9369 §3.3) ----

// Selects the Initial salt for a QUIC version; empty for unknown versions.
//
// Example:
//   version = 0x6b3343cf -> 20-byte v2 salt, ok via non-empty slice
//   version = 0x0a0a0a0a -> empty slice
fn quic_initial_salt(version: u32) -> const u8[:] {
    if version == QUIC_VERSION_1 { return QUIC_V1_INITIAL_SALT[..]; }
    if version == QUIC_VERSION_2 { return QUIC_V2_INITIAL_SALT[..]; }
    return "";
}

// Returns the HKDF label prefix for a QUIC version: "quic " (v1) or
// "quicv2 " (v2, RFC 9369 §3.3.2); empty for unknown versions.
fn quic_hkdf_label_prefix(version: u32) -> const u8[:] {
    if version == QUIC_VERSION_1 { return "quic "; }
    if version == QUIC_VERSION_2 { return "quicv2 "; }
    return "";
}

// Returns the 16-byte Retry Integrity Tag AES-128-GCM key (RFC 9001 §5.8, RFC 9369 §3.3.3).
fn quic_retry_key(version: u32) -> const u8[:] {
    if version == QUIC_VERSION_1 { return QUIC_V1_RETRY_KEY[..]; }
    if version == QUIC_VERSION_2 { return QUIC_V2_RETRY_KEY[..]; }
    return "";
}

// Returns the 12-byte Retry Integrity Tag AES-128-GCM nonce (RFC 9001 §5.8, RFC 9369 §3.3.3).
fn quic_retry_nonce(version: u32) -> const u8[:] {
    if version == QUIC_VERSION_1 { return QUIC_V1_RETRY_NONCE[..]; }
    if version == QUIC_VERSION_2 { return QUIC_V2_RETRY_NONCE[..]; }
    return "";
}
