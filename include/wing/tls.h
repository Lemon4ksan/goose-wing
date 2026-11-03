// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

#ifndef WING_TLS_H
#define WING_TLS_H

#include <wing/types.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// TLS Record Layer Content Types (RFC 8446 §5.1)
// ============================================================================

typedef enum wing_tls_content_type {
    WING_TLS_CONTENT_INVALID            = 0,
    WING_TLS_CONTENT_CHANGE_CIPHER_SPEC = 20,
    WING_TLS_CONTENT_ALERT              = 21,
    WING_TLS_CONTENT_HANDSHAKE          = 22,
    WING_TLS_CONTENT_APPLICATION_DATA   = 23,
} wing_tls_content_type_t;

// ============================================================================
// TLS Alert Levels & Descriptions (RFC 8446 §B.2)
// ============================================================================

typedef enum wing_tls_alert_level {
    WING_TLS_ALERT_LEVEL_WARNING = 1,
    WING_TLS_ALERT_LEVEL_FATAL   = 2,
} wing_tls_alert_level_t;

typedef enum wing_tls_alert_desc {
    WING_TLS_ALERT_CLOSE_NOTIFY            = 0,
    WING_TLS_ALERT_UNEXPECTED_MESSAGE      = 10,
    WING_TLS_ALERT_BAD_RECORD_MAC          = 20,
    WING_TLS_ALERT_RECORD_OVERFLOW         = 22,
    WING_TLS_ALERT_HANDSHAKE_FAILURE       = 40,
    WING_TLS_ALERT_BAD_CERTIFICATE         = 42,
    WING_TLS_ALERT_UNSUPPORTED_CERTIFICATE = 43,
    WING_TLS_ALERT_CERTIFICATE_REVOKED     = 44,
    WING_TLS_ALERT_CERTIFICATE_EXPIRED     = 45,
    WING_TLS_ALERT_CERTIFICATE_UNKNOWN     = 46,
    WING_TLS_ALERT_ILLEGAL_PARAMETER       = 47,
    WING_TLS_ALERT_UNKNOWN_CA              = 48,
    WING_TLS_ALERT_ACCESS_DENIED           = 49,
    WING_TLS_ALERT_DECODE_ERROR            = 50,
    WING_TLS_ALERT_DECRYPT_ERROR           = 51,
    WING_TLS_ALERT_PROTOCOL_VERSION        = 70,
    WING_TLS_ALERT_INSUFFICIENT_SECURITY   = 71,
    WING_TLS_ALERT_INTERNAL_ERROR          = 80,
    WING_TLS_ALERT_INAPPROPRIATE_FALLBACK  = 86,
    WING_TLS_ALERT_USER_CANCELED           = 90,
    WING_TLS_ALERT_NO_RENEGOTIATION        = 100,
    WING_TLS_ALERT_MISSING_EXTENSION       = 109,
    WING_TLS_ALERT_UNSUPPORTED_EXTENSION   = 110,
    WING_TLS_ALERT_UNRECOGNIZED_NAME       = 112,
    WING_TLS_ALERT_BAD_CERTIFICATE_STATUS_RESPONSE = 113,
    WING_TLS_ALERT_UNKNOWN_PSK_IDENTITY    = 115,
    WING_TLS_ALERT_CERTIFICATE_REQUIRED    = 116,
    WING_TLS_ALERT_NO_APPLICATION_PROTOCOL = 120,
} wing_tls_alert_desc_t;

// ============================================================================
// TLS 1.3 Cipher Suites (RFC 8446 §B.4)
// ============================================================================

typedef enum wing_tls_cipher_suite {
    WING_TLS_AES_128_GCM_SHA256       = 0x1301,
    WING_TLS_AES_256_GCM_SHA384       = 0x1302,
    WING_TLS_CHACHA20_POLY1305_SHA256 = 0x1303,
    WING_TLS_AES_128_CCM_SHA256       = 0x1304,
    WING_TLS_AES_128_CCM_8_SHA256     = 0x1305,
} wing_tls_cipher_suite_t;

// ============================================================================
// TLS Record Framing (RFC 8446 §5.1)
// ============================================================================

typedef struct wing_tls_record {
    uint8_t      content_type;
    uint16_t     legacy_version;
    wing_slice_t payload;
} wing_tls_record_t;

WING_API bool wing_parse_tls_record(wing_slice_t raw, wing_tls_record_t *out, int64_t *consumed);

// ============================================================================
// Encrypted Client Hello (ECH RFC 9460 / draft-ietf-tls-esni)
// ============================================================================

typedef struct wing_ech_config {
    uint16_t     version;
    uint16_t     kem_id;
    wing_slice_t public_name;
    wing_slice_t public_key;
    uint16_t     cipher_suite;
    uint8_t      max_name_len;
} wing_ech_config_t;

WING_API bool wing_parse_ech_config(wing_slice_t raw, wing_ech_config_t *out, int64_t *consumed);

#ifdef __cplusplus
}
#endif

#endif // WING_TLS_H
