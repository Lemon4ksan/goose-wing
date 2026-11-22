// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// TLS 1.3 record layer, handshake message types, extensions, and alert constants.
// Conforms to RFC 8446, RFC 6066, RFC 7301, RFC 8879, and RFC 9001.
namespace rfc;

import std;

// ---- TLS Record Content Types & Versions (RFC 8446 Section 5) ------------

const TLS_CONTENT_INVALID:            u8 = 0;
const TLS_CONTENT_CHANGE_CIPHER_SPEC: u8 = 0x14; // 20
const TLS_CONTENT_ALERT:              u8 = 0x15; // 21
const TLS_CONTENT_HANDSHAKE:          u8 = 0x16; // 22
const TLS_CONTENT_APPLICATION_DATA:   u8 = 0x17; // 23

const TLS_LEGACY_VERSION_1_0: u16 = 0x0301; // RFC 8446 Section 5.1
const TLS_LEGACY_VERSION_1_2: u16 = 0x0303; // RFC 8446 Section 5.1
const TLS_VERSION_1_3:        u16 = 0x0304; // RFC 8446 Section 4.2.1

// ---- TLS 1.3 Record Layer Wire Limits (RFC 8446 Section 5.1 & 5.2) -------

const TLS_RECORD_HEADER_LEN:         i64 = 5;     // RFC 8446 Section 5.1
const TLS_AEAD_TAG_LEN:              i64 = 16;    // RFC 8446 Section 5.2
const TLS_MAX_RECORD_PLAINTEXT_LEN:  i64 = 16384; // RFC 8446 Section 5.1 (2^14)
const TLS_MAX_INNER_PLAINTEXT_LEN:   i64 = 16385; // RFC 8446 Section 5.4 (2^14 + 1)
const TLS_MAX_RECORD_CIPHERTEXT_LEN: i64 = 16640; // RFC 8446 Section 5.2 (2^14 + 256)

// RFC 8446 Appendix D.4: At most one dummy ChangeCipherSpec record is permitted.
const MAX_CCS_RECORDS:            i32 = 1;
const TLS_CCS_DUMMY_PAYLOAD_BYTE: u8  = 0x01;

// RFC 8446 Appendix D.4: Validates whether payload matches dummy ChangeCipherSpec (single byte 0x01).
inline fn is_valid_ccs_payload(payload: const u8[:]) -> bool {
    return payload.len == 1 && payload[0] == rfc::TLS_CCS_DUMMY_PAYLOAD_BYTE;
}

// ---- TLS 1.3 Handshake Message Types (RFC 8446 Section 4) ----------------

const TLS_HS_CLIENT_HELLO:           u8 = 1;
const TLS_HS_SERVER_HELLO:           u8 = 2;
const TLS_HS_NEW_SESSION_TICKET:     u8 = 4;
const TLS_HS_END_OF_EARLY_DATA:      u8 = 5;
const TLS_HS_ENCRYPTED_EXTENSIONS:   u8 = 8;
const TLS_HS_CERTIFICATE:            u8 = 11;
const TLS_HS_CERTIFICATE_REQUEST:    u8 = 13;
const TLS_HS_CERTIFICATE_VERIFY:     u8 = 15;
const TLS_HS_FINISHED:               u8 = 20;
const TLS_HS_KEY_UPDATE:             u8 = 24;
const TLS_HS_COMPRESSED_CERTIFICATE: u8 = 25;  // RFC 8879 Section 4
const TLS_HS_MESSAGE_HASH:           u8 = 254; // RFC 8446 Section 4.4.1

// ---- TLS Extension Identifiers (RFC 8446 Section 4.2) --------------------

const TLS_EXT_SERVER_NAME:                  u16 = 0;    // RFC 6066 Section 3
const TLS_EXT_MAX_FRAGMENT_LENGTH:          u16 = 1;    // RFC 6066 Section 4
const TLS_EXT_STATUS_REQUEST:               u16 = 5;    // RFC 6066 Section 8
const TLS_EXT_SUPPORTED_GROUPS:             u16 = 10;     // RFC 8446 Section 4.2.7
const TLS_EXT_EC_POINT_FORMATS:             u16 = 11;     // RFC 8446 Section 4.2
const TLS_EXT_SIGNATURE_ALGORITHMS:         u16 = 13;     // RFC 8446 Section 4.2.3
const TLS_EXT_USE_SRTP:                     u16 = 14;     // RFC 8446 Section 4.2
const TLS_EXT_HEARTBEAT:                    u16 = 15;     // RFC 8446 Section 4.2
const TLS_EXT_ALPN:                         u16 = 16;     // RFC 7301 Section 3.1
const TLS_EXT_SIGNED_CERTIFICATE_TIMESTAMP: u16 = 18;     // RFC 8446 Section 4.2
const TLS_EXT_CLIENT_CERTIFICATE_TYPE:      u16 = 19;     // RFC 8446 Section 4.2
const TLS_EXT_SERVER_CERTIFICATE_TYPE:      u16 = 20;     // RFC 8446 Section 4.2
const TLS_EXT_PADDING:                      u16 = 21;     // RFC 8446 Section 4.2
const TLS_EXT_EXTENDED_MASTER_SECRET:       u16 = 23;     // RFC 8446 Section 4.2
const TLS_EXT_COMPRESS_CERTIFICATE:         u16 = 27;     // RFC 8879 Section 3
const TLS_EXT_SESSION_TICKET:               u16 = 35;     // RFC 8446 Section 4.2
const TLS_EXT_PRE_SHARED_KEY:               u16 = 41;     // RFC 8446 Section 4.2.11
const TLS_EXT_EARLY_DATA:                   u16 = 42;     // RFC 8446 Section 4.2.10
const TLS_EXT_SUPPORTED_VERSIONS:           u16 = 43;     // RFC 8446 Section 4.2.1
const TLS_EXT_COOKIE:                       u16 = 44;     // RFC 8446 Section 4.2.2
const TLS_EXT_PSK_KEY_EXCHANGE_MODES:       u16 = 45;     // RFC 8446 Section 4.2.9
const TLS_EXT_CERTIFICATE_AUTHORITIES:      u16 = 47;     // RFC 8446 Section 4.2.4
const TLS_EXT_OID_FILTERS:                  u16 = 48;     // RFC 8446 Section 4.2.5
const TLS_EXT_POST_HANDSHAKE_AUTH:          u16 = 49;     // RFC 8446 Section 4.2.6
const TLS_EXT_SIGNATURE_ALGORITHMS_CERT:    u16 = 50;     // RFC 8446 Section 4.2.3
const TLS_EXT_KEY_SHARE:                    u16 = 51;     // RFC 8446 Section 4.2.8
const TLS_EXT_QUIC_TRANSPORT_PARAMETERS:    u16 = 0x39;   // RFC 9001 Section 8.2
const TLS_EXT_RENEGOTIATION_INFO:           u16 = 0xFF01; // RFC 8446 Section 4.1.3

// RFC 8446 Section 4.2: Extensions - Table 2 indicates recognized TLS extensions.
fn is_known_tls_extension(ext_type: u16) -> bool {
    return match ext_type {
        rfc::TLS_EXT_SERVER_NAME => true,
        rfc::TLS_EXT_MAX_FRAGMENT_LENGTH => true,
        rfc::TLS_EXT_STATUS_REQUEST => true,
        rfc::TLS_EXT_SUPPORTED_GROUPS => true,
        rfc::TLS_EXT_EC_POINT_FORMATS => true,
        rfc::TLS_EXT_SIGNATURE_ALGORITHMS => true,
        rfc::TLS_EXT_USE_SRTP => true,
        rfc::TLS_EXT_HEARTBEAT => true,
        rfc::TLS_EXT_ALPN => true,
        rfc::TLS_EXT_SIGNED_CERTIFICATE_TIMESTAMP => true,
        rfc::TLS_EXT_CLIENT_CERTIFICATE_TYPE => true,
        rfc::TLS_EXT_SERVER_CERTIFICATE_TYPE => true,
        rfc::TLS_EXT_PADDING => true,
        rfc::TLS_EXT_EXTENDED_MASTER_SECRET => true,
        rfc::TLS_EXT_COMPRESS_CERTIFICATE => true,
        rfc::TLS_EXT_SESSION_TICKET => true,
        rfc::TLS_EXT_PRE_SHARED_KEY => true,
        rfc::TLS_EXT_EARLY_DATA => true,
        rfc::TLS_EXT_SUPPORTED_VERSIONS => true,
        rfc::TLS_EXT_COOKIE => true,
        rfc::TLS_EXT_PSK_KEY_EXCHANGE_MODES => true,
        rfc::TLS_EXT_CERTIFICATE_AUTHORITIES => true,
        rfc::TLS_EXT_OID_FILTERS => true,
        rfc::TLS_EXT_POST_HANDSHAKE_AUTH => true,
        rfc::TLS_EXT_SIGNATURE_ALGORITHMS_CERT => true,
        rfc::TLS_EXT_KEY_SHARE => true,
        rfc::TLS_EXT_QUIC_TRANSPORT_PARAMETERS => true,
        rfc::TLS_EXT_ECH_OUTER_EXTENSIONS => true,
        rfc::EXT_ENCRYPTED_CLIENT_HELLO => true,
        rfc::TLS_EXT_RENEGOTIATION_INFO => true,
        _ => false,
    };
}

// RFC 8446 Section 4.2: Extensions - Extensions permitted in CertificateRequest (RFC 8879 Section 7.1).
inline fn is_permitted_cert_req_extension(ext_type: u16) -> bool {
    return match ext_type {
        rfc::TLS_EXT_STATUS_REQUEST => true,
        rfc::TLS_EXT_SIGNATURE_ALGORITHMS => true,
        rfc::TLS_EXT_SIGNED_CERTIFICATE_TIMESTAMP => true,
        rfc::TLS_EXT_COMPRESS_CERTIFICATE => true,
        rfc::TLS_EXT_CERTIFICATE_AUTHORITIES => true,
        rfc::TLS_EXT_OID_FILTERS => true,
        rfc::TLS_EXT_SIGNATURE_ALGORITHMS_CERT => true,
        _ => false,
    };
}

// RFC 8446 Section 4.2: Extensions - Forbidden extension in CertificateRequest
inline fn is_forbidden_cert_req_extension(ext_type: u16) -> bool {
    if rfc::is_permitted_cert_req_extension(ext_type) {
        return false;
    }
    return rfc::is_known_tls_extension(ext_type);
}

// RFC 8446 Section 4.2: Extensions - Forbidden extension in NewSessionTicket
inline fn is_forbidden_nst_extension(ext_type: u16) -> bool {
    if ext_type == rfc::TLS_EXT_EARLY_DATA {
        return false;
    }
    return rfc::is_known_tls_extension(ext_type);
}

// RFC 8446 Section 4.2: Extensions - Rejects oid_filters and uncompressed ech_outer_extensions (RFC 9849 Section 5.1).
inline fn is_forbidden_ch_extension(ext_type: u16) -> bool {
    return ext_type == rfc::TLS_EXT_OID_FILTERS || ext_type == rfc::TLS_EXT_ECH_OUTER_EXTENSIONS;
}

// RFC 8446 Section 4.2: Extensions - Table 2 indicates extensions permitted in ServerHello.
inline fn is_permitted_sh_extension(ext_type: u16) -> bool {
    return match ext_type {
        rfc::TLS_EXT_KEY_SHARE => true,
        rfc::TLS_EXT_PRE_SHARED_KEY => true,
        rfc::TLS_EXT_SUPPORTED_VERSIONS => true,
        _ => false,
    };
}

// RFC 8446 Section 4.2: Extensions - Forbidden extension in ServerHello.
inline fn is_forbidden_sh_extension(ext_type: u16) -> bool {
    if rfc::is_permitted_sh_extension(ext_type) {
        return false;
    }
    return rfc::is_known_tls_extension(ext_type);
}

// RFC 8446 Section 4.2: Extensions - Table 2 indicates extensions permitted in HelloRetryRequest.
inline fn is_permitted_hrr_extension(ext_type: u16) -> bool {
    return match ext_type {
        rfc::TLS_EXT_KEY_SHARE => true,
        rfc::TLS_EXT_COOKIE => true,
        rfc::TLS_EXT_SUPPORTED_VERSIONS => true,
        rfc::EXT_ENCRYPTED_CLIENT_HELLO => true,
        _ => false,
    };
}

// RFC 8446 Section 4.2: Extensions - Forbidden extension in HelloRetryRequest.
inline fn is_forbidden_hrr_extension(ext_type: u16) -> bool {
    if rfc::is_permitted_hrr_extension(ext_type) {
        return false;
    }
    return rfc::is_known_tls_extension(ext_type);
}

// RFC 8446 Section 4.2: Extensions - Table 2 indicates extensions permitted in EncryptedExtensions.
inline fn is_permitted_ee_extension(ext_type: u16) -> bool {
    return match ext_type {
        rfc::TLS_EXT_SERVER_NAME => true,
        rfc::TLS_EXT_MAX_FRAGMENT_LENGTH => true,
        rfc::TLS_EXT_SUPPORTED_GROUPS => true,
        rfc::TLS_EXT_USE_SRTP => true,
        rfc::TLS_EXT_HEARTBEAT => true,
        rfc::TLS_EXT_ALPN => true,
        rfc::TLS_EXT_CLIENT_CERTIFICATE_TYPE => true,
        rfc::TLS_EXT_SERVER_CERTIFICATE_TYPE => true,
        rfc::TLS_EXT_EARLY_DATA => true,
        rfc::TLS_EXT_QUIC_TRANSPORT_PARAMETERS => true,
        rfc::EXT_ENCRYPTED_CLIENT_HELLO => true,
        _ => false,
    };
}

// RFC 8446 Section 4.2: Extensions - Forbidden extension in EncryptedExtensions.
inline fn is_forbidden_ee_extension(ext_type: u16) -> bool {
    if rfc::is_permitted_ee_extension(ext_type) {
        return false;
    }
    return rfc::is_known_tls_extension(ext_type);
}

// ---- TLS Alert Description Codes (RFC 8446 Section 6.2) ------------------

const TLS_ALERT_CLOSE_NOTIFY:                    u8 = 0;
const TLS_ALERT_UNEXPECTED_MESSAGE:              u8 = 10;
const TLS_ALERT_BAD_RECORD_MAC:                  u8 = 20;
const TLS_ALERT_RECORD_OVERFLOW:                 u8 = 22;
const TLS_ALERT_HANDSHAKE_FAILURE:               u8 = 40;
const TLS_ALERT_BAD_CERTIFICATE:                 u8 = 42;
const TLS_ALERT_UNSUPPORTED_CERTIFICATE:         u8 = 43;
const TLS_ALERT_CERTIFICATE_REVOKED:             u8 = 44;
const TLS_ALERT_CERTIFICATE_EXPIRED:             u8 = 45;
const TLS_ALERT_CERTIFICATE_UNKNOWN:             u8 = 46;
const TLS_ALERT_ILLEGAL_PARAMETER:               u8 = 47;
const TLS_ALERT_UNKNOWN_CA:                      u8 = 48;
const TLS_ALERT_ACCESS_DENIED:                   u8 = 49;
const TLS_ALERT_DECODE_ERROR:                    u8 = 50;
const TLS_ALERT_DECRYPT_ERROR:                   u8 = 51;
const TLS_ALERT_PROTOCOL_VERSION:                u8 = 70;
const TLS_ALERT_INSUFFICIENT_SECURITY:           u8 = 71;
const TLS_ALERT_INTERNAL_ERROR:                  u8 = 80;
const TLS_ALERT_INAPPROPRIATE_FALLBACK:          u8 = 86;
const TLS_ALERT_USER_CANCELED:                   u8 = 90;
const TLS_ALERT_MISSING_EXTENSION:               u8 = 109;
const TLS_ALERT_UNSUPPORTED_EXTENSION:           u8 = 110;
const TLS_ALERT_UNRECOGNIZED_NAME:               u8 = 112;
const TLS_ALERT_BAD_CERTIFICATE_STATUS_RESPONSE: u8 = 113;
const TLS_ALERT_UNKNOWN_PSK_IDENTITY:            u8 = 115;
const TLS_ALERT_CERTIFICATE_REQUIRED:            u8 = 116;
const TLS_ALERT_NO_APPLICATION_PROTOCOL:         u8 = 120;

// ---- TLS 1.3 Cipher Suites, HRR, Downgrade Sentinels & Ticket Limits ------

const TLS_CIPHER_AES_128_GCM_SHA256:       u16 = 0x1301; // RFC 8446 Appendix B.4
const TLS_CIPHER_AES_256_GCM_SHA384:       u16 = 0x1302; // RFC 8446 Appendix B.4
const TLS_CIPHER_CHACHA20_POLY1305_SHA256: u16 = 0x1303; // RFC 8446 Appendix B.4
const TLS_CIPHER_AES_128_CCM_SHA256:       u16 = 0x1304; // RFC 8446 Appendix B.4
const TLS_CIPHER_AES_128_CCM_8_SHA256:     u16 = 0x1305; // RFC 8446 Appendix B.4

// RFC 8446 Appendix B.4: Cipher Suites - Validates whether `cs` is a supported TLS 1.3 AEAD cipher suite.
inline fn is_supported_tls13_cipher_suite(cs: u16) -> bool {
    return cs >= rfc::TLS_CIPHER_AES_128_GCM_SHA256 && cs <= rfc::TLS_CIPHER_CHACHA20_POLY1305_SHA256;
}

// RFC 8446 Appendix B.4: Cipher Suites - Returns AEAD key length in bytes, or 0 if unsupported.
inline fn tls13_cipher_suite_key_len(cs: u16) -> u16 {
    return match cs {
        rfc::TLS_CIPHER_AES_128_GCM_SHA256 => 16,
        rfc::TLS_CIPHER_AES_256_GCM_SHA384 => 32,
        rfc::TLS_CIPHER_CHACHA20_POLY1305_SHA256 => 32,
        _ => 0,
    };
}

// RFC 8446 Appendix B.4: Cipher Suites - Returns HKDF hash output length in bytes, or 0 if unsupported.
inline fn tls13_cipher_suite_hash_len(cs: u16) -> u8 {
    return match cs {
        rfc::TLS_CIPHER_AES_128_GCM_SHA256 => 32,
        rfc::TLS_CIPHER_CHACHA20_POLY1305_SHA256 => 32,
        rfc::TLS_CIPHER_AES_256_GCM_SHA384 => 48,
        _ => 0,
    };
}

const MAX_HANDSHAKE_MSG_LEN:    u32 = 16777215;  // RFC 8446 Section 5.1 (2^24 - 1)
const MAX_TICKET_LIFETIME_SECS: u32 = 604800;    // RFC 8446 Section 4.6.1 (7 days)
const MAX_TICKET_LIFETIME_MS:   i64 = 604800000; // RFC 8446 Section 4.6.1 (7 days in ms)

const KEY_UPDATE_NOT_REQUESTED: u8 = 0; // RFC 8446 Section 4.6.3
const KEY_UPDATE_REQUESTED:     u8 = 1; // RFC 8446 Section 4.6.3

const HRR_RANDOM: const u8[32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
    0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
    0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
]; // RFC 8446 Section 4.1.3

// RFC 8446 Section 4.1.3: Server Hello - Downgrade protection sentinels
const DOWNGRADE_SENTINEL_TLS12: const u8[8] = [0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01];
const DOWNGRADE_SENTINEL_TLS11: const u8[8] = [0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x00];

// ---- Certificate Compression, ECH, HPKE & Post-Quantum (RFC 8879, 9849, 9180, 10024)

const CERT_COMPRESSION_ZLIB:   u16 = 1; // RFC 8879 Section 3
const CERT_COMPRESSION_BROTLI: u16 = 2; // RFC 8879 Section 3
const CERT_COMPRESSION_ZSTD:   u16 = 3; // RFC 8879 Section 3

// RFC 8879 Section 4: Compressed Certificate Message - Decompression ceiling
const MAX_UNCOMPRESSED_CERT_SIZE: u32 = 65536; // 64 KB decompression ceiling (bomb defense)
const MAX_CERT_EXPANSION_RATIO:   u32 = 1024;  // RFC 8879 Section 4: 1024x compression ratio ceiling

// Returns true if algorithm is recognized by RFC 8879
inline fn is_valid_compression_algorithm(algo: u16) -> bool {
    return algo == rfc::CERT_COMPRESSION_BROTLI
        || algo == rfc::CERT_COMPRESSION_ZSTD
        || algo == rfc::CERT_COMPRESSION_ZLIB;
}

// RFC 8879 Section 4: Compressed Certificate Message - Validates 1024x expansion ratio and 64 KB ceiling.
inline fn is_within_decompression_ratio(uncompressed_len: u32, compressed_len: u32) -> bool {
    guard compressed_len > 0 && uncompressed_len > 0 && uncompressed_len <= rfc::MAX_UNCOMPRESSED_CERT_SIZE else {
        return false;
    }
    let blocks = uncompressed_len >> 10;
    if blocks < compressed_len {
        return true;
    }
    return blocks == compressed_len && (uncompressed_len & 0x3FF) == 0;
}

const EXT_ENCRYPTED_CLIENT_HELLO:   u16 = 0xFE0D; // RFC 9849 Section 5
const TLS_EXT_ECH_OUTER_EXTENSIONS: u16 = 0xFD00; // RFC 9849 Section 5.1
const ECH_VERSION_RFC9849:          u16 = 0xFE0D; // RFC 9849 Section 4
const ECH_CLIENT_OUTER:             u8  = 0;      // RFC 9849 Section 5
const ECH_CLIENT_INNER:             u8  = 1;      // RFC 9849 Section 5
const ECH_ACCEPT_CONFIRM_LEN:       u16 = 8;      // RFC 9849 Section 7.2
const ECH_SH_CONFIRM_START:         i64 = 30;     // RFC 9849 Section 7.2: 4B hs hdr + 2B version + 24B random prefix
const ECH_SH_MIN_HEADER_LEN:        i64 = 38;     // RFC 9849 Section 7.2: 4B hs hdr + 2B version + 32B random

const HPKE_MODE_BASE:                    u8  = 0;       // RFC 9180 Section 5
const HPKE_KEM_DHKEM_X25519_HKDF_SHA256: u16 = 0x0020;  // RFC 9180 Section 7.1
const HPKE_KDF_HKDF_SHA256:              u16 = 0x0001;  // RFC 9180 Section 7.2
const HPKE_AEAD_AES_128_GCM:             u16 = 0x0001;  // RFC 9180 Section 7.3
const HPKE_AEAD_AES_256_GCM:             u16 = 0x0002;  // RFC 9180 Section 7.3
const HPKE_AEAD_CHACHA20_POLY1305:       u16 = 0x0003;  // RFC 9180 Section 7.3

const GROUP_SECP256R1:               u16 = 0x0017; // RFC 8446 Section 4.2.7
const GROUP_SECP384R1:               u16 = 0x0018; // RFC 8446 Section 4.2.7
const GROUP_X25519:                  u16 = 0x001D; // RFC 8446 Section 4.2.7
const GROUP_SECP256R1_MLKEM768:      u16 = 0x11EB; // RFC 10024 Section 7.2
const GROUP_X25519_MLKEM768:         u16 = 0x11EC; // RFC 10024 Section 7.1
const GROUP_SECP384R1_MLKEM1024:     u16 = 0x11ED; // RFC 10024 Section 7.3
const GROUP_X25519_KYBER768_DRAFT00: u16 = 0x6399;

// Returns true if the group identifier is an X25519 hybrid post-quantum group (0x11EC or 0x6399).
inline fn is_x25519_pq_group(group: u16) -> bool {
    return group == rfc::GROUP_X25519_MLKEM768 || group == rfc::GROUP_X25519_KYBER768_DRAFT00;
}

// Checks whether a TLS supported group is a Post-Quantum Hybrid group (RFC 10024 / draft-ietf-tls-hybrid-design)
inline fn is_post_quantum_group(group: u16) -> bool {
    return group == rfc::GROUP_SECP256R1_MLKEM768
        || group == rfc::GROUP_X25519_MLKEM768
        || group == rfc::GROUP_SECP384R1_MLKEM1024
        || group == rfc::GROUP_X25519_KYBER768_DRAFT00;
}

const X25519_KEY_LEN:             i64 = 32;   // RFC 7748 Section 5
const SECP256R1_POINT_LEN:        i64 = 65;   // RFC 8446 Section 4.2.8.2
const SECP384R1_POINT_LEN:        i64 = 97;   // RFC 8446 Section 4.2.8.2
const MLKEM768_PUBLIC_LEN:        i64 = 1184; // FIPS 203 / RFC 10024 Section 3
const MLKEM768_CIPHERTEXT_LEN:    i64 = 1088; // FIPS 203 / RFC 10024 Section 3
const MLKEM768_SECRET_KEY_LEN:    i64 = 2400; // FIPS 203
const MLKEM768_SHARED_SECRET_LEN: i64 = 32;   // FIPS 203
const MLKEM1024_PUBLIC_LEN:       i64 = 1568; // FIPS 203 / RFC 10024 Section 3
const MLKEM1024_CIPHERTEXT_LEN:   i64 = 1568; // FIPS 203 / RFC 10024 Section 3

const HYBRID_CLIENT_SHARE_LEN:              i64 = 1216; // 32 + 1184 (RFC 10024 Section 7.1)
const HYBRID_SERVER_SHARE_LEN:              i64 = 1120; // 32 + 1088 (RFC 10024 Section 7.1)
const SECP256R1_MLKEM768_CLIENT_SHARE_LEN:  i64 = 1249; // 65 + 1184 (RFC 10024 Section 7.2)
const SECP256R1_MLKEM768_SERVER_SHARE_LEN:  i64 = 1153; // 65 + 1088 (RFC 10024 Section 7.2)
const SECP384R1_MLKEM1024_CLIENT_SHARE_LEN: i64 = 1665; // 97 + 1568 (RFC 10024 Section 7.3)
const SECP384R1_MLKEM1024_SERVER_SHARE_LEN: i64 = 1665; // 97 + 1568 (RFC 10024 Section 7.3)

// ---- ASN.1 DER Tags, X.509 OIDs & TLS Signature Schemes (RFC 5280, RFC 8446)

const ASN1_TAG_BOOLEAN:          u8 = 0x01;
const ASN1_TAG_INTEGER:          u8 = 0x02;
const ASN1_TAG_BIT_STRING:       u8 = 0x03;
const ASN1_TAG_OCTET_STRING:     u8 = 0x04;
const ASN1_TAG_NULL:             u8 = 0x05;
const ASN1_TAG_OID:              u8 = 0x06;
const ASN1_TAG_ENUMERATED:       u8 = 0x0A;
const ASN1_TAG_UTF8_STRING:      u8 = 0x0C;
const ASN1_TAG_PRINTABLE_STRING: u8 = 0x13;
const ASN1_TAG_IA5_STRING:       u8 = 0x16;
const ASN1_TAG_UTC_TIME:         u8 = 0x17;
const ASN1_TAG_GENERALIZED_TIME: u8 = 0x18;
const ASN1_TAG_SEQUENCE:         u8 = 0x30;
const ASN1_TAG_SET:              u8 = 0x31;

const OID_COMMON_NAME:            const u8[3]  = [0x55, 0x04, 0x03];
const OID_BASIC_CONSTRAINTS:      const u8[3]  = [0x55, 0x1D, 0x13];
const OID_KEY_USAGE:              const u8[3]  = [0x55, 0x1D, 0x0F];
const OID_SUBJECT_ALT_NAME:       const u8[3]  = [0x55, 0x1D, 0x11];
const OID_EC_PUBLIC_KEY:          const u8[7]  = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
const OID_SECP256R1:              const u8[8]  = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
const OID_SECP384R1:              const u8[5]  = [0x2B, 0x81, 0x04, 0x00, 0x22];
const OID_RSA_ENCRYPTION:         const u8[9]  = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];
const OID_ED25519:                const u8[3]  = [0x2B, 0x65, 0x70];
const OID_SUBJECT_KEY_IDENTIFIER: const u8[3]  = [0x55, 0x1D, 0x0E];
const OID_NAME_CONSTRAINTS:       const u8[3]  = [0x55, 0x1D, 0x1E];
const OID_AUTH_KEY_IDENTIFIER:    const u8[3]  = [0x55, 0x1D, 0x23];
const OID_POLICY_CONSTRAINTS:     const u8[3]  = [0x55, 0x1D, 0x24];
const OID_EXT_KEY_USAGE:          const u8[3]  = [0x55, 0x1D, 0x25]; // RFC 5280 Section 4.2.1.12
const OID_INHIBIT_ANY_POLICY:     const u8[3]  = [0x55, 0x1D, 0x36];
const OID_TLS_FEATURE:            const u8[8]  = [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x18];
const OID_CT_PRECERT_SCTS:        const u8[10] = [0x2B, 0x06, 0x01, 0x04, 0x01, 0xD6, 0x79, 0x02, 0x04, 0x02];
const OID_OCSP_BASIC:             const u8[9]  = [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01];

const OID_EKU_SERVER_AUTH:  const u8[8] = [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01]; // RFC 5280 Section 4.2.1.12
const OID_EKU_CLIENT_AUTH:  const u8[8] = [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02]; // RFC 5280 Section 4.2.1.12
const OID_EKU_OCSP_SIGNING: const u8[8] = [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09]; // RFC 5280 Section 4.2.1.12
const OID_EKU_ANY:          const u8[4] = [0x55, 0x1D, 0x25, 0x00];                         // RFC 5280 Section 4.2.1.12

const EKU_SERVER_AUTH:  u8 = 1; // RFC 5280 Section 4.2.1.12
const EKU_CLIENT_AUTH:  u8 = 2; // RFC 5280 Section 4.2.1.12
const EKU_OCSP_SIGNING: u8 = 4; // RFC 5280 Section 4.2.1.12
const EKU_ANY:          u8 = 8; // RFC 5280 Section 4.2.1.12

const OID_SIG_MD2_RSA:      const u8[9] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x02];
const OID_SIG_MD4_RSA:      const u8[9] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x03];
const OID_SIG_MD5_RSA:      const u8[9] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x04];
const OID_SIG_MD5_RSA_OIW:  const u8[5] = [0x2B, 0x0E, 0x03, 0x02, 0x03];
const OID_SIG_SHA1_RSA:     const u8[9] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05];
const OID_SIG_RSASSA_PSS:   const u8[9] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A]; // RFC 4055 §3.1
const OID_SIG_SHA256_RSA:   const u8[9] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B]; // RFC 4055 §5
const OID_SIG_SHA384_RSA:   const u8[9] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C]; // RFC 4055 §5
const OID_SIG_SHA1_ECDSA:   const u8[7] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x01];
const OID_SIG_ECDSA_SHA256: const u8[8] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];       // RFC 5758 §3.2
const OID_SIG_ECDSA_SHA384: const u8[8] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03];       // RFC 5758 §3.2
const OID_SIG_SHA1_DSA:     const u8[7] = [0x2A, 0x86, 0x48, 0xCE, 0x38, 0x04, 0x03];

const KEY_USAGE_DIGITAL_SIGNATURE: u16 = 0x8000; // RFC 5280 Section 4.2.1.3
const KEY_USAGE_KEY_ENCIPHERMENT:  u16 = 0x2000; // RFC 5280 Section 4.2.1.3
const KEY_USAGE_KEY_CERT_SIGN:     u16 = 0x0400; // RFC 5280 Section 4.2.1.3
const KEY_USAGE_CRL_SIGN:          u16 = 0x0200; // RFC 5280 Section 4.2.1.3

const SIG_SCHEME_RSA_PKCS1_SHA256:       u16 = 0x0401; // RFC 8446 Section 4.2.3
const SIG_SCHEME_ECDSA_SECP256R1_SHA256: u16 = 0x0403; // RFC 8446 Section 4.2.3
const SIG_SCHEME_RSA_PKCS1_SHA384:       u16 = 0x0501; // RFC 8446 Section 4.2.3
const SIG_SCHEME_ECDSA_SECP384R1_SHA384: u16 = 0x0503; // RFC 8446 Section 4.2.3
const SIG_SCHEME_RSA_PKCS1_SHA512:       u16 = 0x0601; // RFC 8446 Section 4.2.3
const SIG_SCHEME_RSA_PKCS1_SHA1:         u16 = 0x0201; // RFC 8446 Section 4.2.3
const SIG_SCHEME_ECDSA_SHA1:             u16 = 0x0203; // RFC 8446 Section 4.2.3
const SIG_SCHEME_RSA_PKCS1_MD5:          u16 = 0x0101;
const SIG_SCHEME_RSA_PSS_RSAE_SHA256:    u16 = 0x0804; // RFC 8446 Section 4.2.3
const SIG_SCHEME_RSA_PSS_RSAE_SHA384:    u16 = 0x0805; // RFC 8446 Section 4.2.3
const SIG_SCHEME_ED25519:                u16 = 0x0807; // RFC 8446 Section 4.2.3

// RFC 8446 Section 4.4.3: Certificate Verify - Rejects PKCS#1 v1.5, SHA-1/SHA-224/MD5, DSA, and anonymous schemes.
inline fn is_forbidden_tls13_sig_scheme(sig_scheme: u16) -> bool {
    let hi = (sig_scheme >> 8) as u8;
    let lo = (sig_scheme & 0xFF) as u8;
    if hi <= 0x03 { return true; }
    if hi < 0x08 && (lo == 0x00 || lo == 0x01 || lo == 0x02) { return true; }
    return false;
}

// RFC 8446 Section 4.4.2.4: Receiving a Certificate Message - Prohibited MD2/MD4/MD5 and SHA-1 certificate signature OIDs.
inline fn is_forbidden_cert_signature_algorithm(sig_alg_oid: const u8[:]) -> bool {
    return sig_alg_oid == rfc::OID_SIG_MD5_RSA[..]
        || sig_alg_oid == rfc::OID_SIG_MD5_RSA_OIW[..]
        || sig_alg_oid == rfc::OID_SIG_MD2_RSA[..]
        || sig_alg_oid == rfc::OID_SIG_MD4_RSA[..]
        || sig_alg_oid == rfc::OID_SIG_SHA1_RSA[..]
        || sig_alg_oid == rfc::OID_SIG_SHA1_ECDSA[..]
        || sig_alg_oid == rfc::OID_SIG_SHA1_DSA[..];
}

// ---- OCSP Response Status & Certificate Transparency (RFC 6960, RFC 6962)

const OCSP_STATUS_SUCCESSFUL:     u8 = 0;
const OCSP_STATUS_MALFORMED_REQ:  u8 = 1;
const OCSP_STATUS_INTERNAL_ERROR: u8 = 2;
const OCSP_STATUS_TRY_LATER:      u8 = 3;
const OCSP_STATUS_SIG_REQUIRED:   u8 = 5;
const OCSP_STATUS_UNAUTHORIZED:   u8 = 6;

const SCT_VERSION_V1:        u8  = 0;  // RFC 6962 Section 3.2
const SCT_V1_HEADER_MIN_LEN: i64 = 43; // RFC 6962 Section 3.2
const SCT_LOG_ID_LEN:        i64 = 32; // RFC 6962 Section 3.2
const SCT_HASH_ALG_SHA256:   u8  = 4;  // RFC 6962 Section 3.2
const SCT_SIG_ALG_RSA:       u8  = 1;  // RFC 6962 Section 3.2
const SCT_SIG_ALG_ECDSA:     u8  = 3;  // RFC 6962 Section 3.2

// ---- TLS GREASE (RFC 8701 Section 2) -------------------------------------

// RFC 8701 Section 2: GREASE Values for TLS - Checks whether a 16-bit code point is a reserved GREASE value (0x?a?a).
inline fn is_grease_u16(val: u16) -> bool {
    return (val & 0x0F0F) == 0x0A0A && ((val >> 8) == (val & 0x00FF));
}
