// Internal PROXY protocol wire constants, nibbles, magic preambles, and TLV subtypes.
namespace internal;

import std;

// PROXY protocol version 1 prefix: "PROXY "
const PROXY_V1_PREFIX: const u8[6] = ['P', 'R', 'O', 'X', 'Y', ' '];
const PROXY_V1_MAX_LEN: i64 = 107; // RFC / HAProxy specification maximum v1 line length

// PROXY protocol version 2 12-byte constant preamble:
// \x0D \x0A \x0D \x0A \x00 \x0D \x0A \x51 \x55 \x49 \x54 \x0A ("\r\n\r\n\0\r\nQUIT\n")
const PROXY_V2_PREAMBLE: const u8[12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A
];

// Protocol Commands (v2 nibble 0..3)
const PP2_CMD_LOCAL: u8 = 0x00; // Connection initiated by proxy (health check / discard address)
const PP2_CMD_PROXY: u8 = 0x01; // Forwarded connection (contains original address)

// Address Families (v2 upper nibble)
const PP2_FAM_UNSPEC: u8 = 0x00;
const PP2_FAM_INET4:  u8 = 0x01; // IPv4 (12 bytes: 4B src + 4B dst + 2B sport + 2B dport)
const PP2_FAM_INET6:  u8 = 0x02; // IPv6 (36 bytes: 16B src + 16B dst + 2B sport + 2B dport)
const PP2_FAM_UNIX:   u8 = 0x03; // Unix (216 bytes: 108B src + 108B dst)

// Transport Protocols (v2 lower nibble)
const PP2_TRANS_UNSPEC: u8 = 0x00;
const PP2_TRANS_STREAM: u8 = 0x01; // TCP
const PP2_TRANS_DGRAM:  u8 = 0x02; // UDP

// Type-Length-Value (TLV) Types
const PP2_TYPE_ALPN:      u8 = 0x01; // Application-Layer Protocol Negotiation (e.g. "h2")
const PP2_TYPE_AUTHORITY: u8 = 0x02; // Host name passed by the client (SNI / Host)
const PP2_TYPE_CRC32C:    u8 = 0x03; // CRC32c checksum
const PP2_TYPE_NOOP:      u8 = 0x04; // Ignored padding
const PP2_TYPE_UNIQUE_ID: u8 = 0x05; // Unique connection ID for tracing
const PP2_TYPE_SSL:       u8 = 0x20; // SSL/TLS client information
const PP2_TYPE_NETNS:     u8 = 0x30; // Network namespace name

// SSL Sub-TLV Types
const PP2_SUBTYPE_SSL_VERSION: u8 = 0x21; // TLS version string (e.g. "TLSv1.3")
const PP2_SUBTYPE_SSL_CN:      u8 = 0x22; // Client Common Name
const PP2_SUBTYPE_SSL_CIPHER:  u8 = 0x23; // Cipher name (e.g. "ECDHE-RSA-AES128-GCM-SHA256")
const PP2_SUBTYPE_SSL_SIG_ALG: u8 = 0x24; // Signature algorithm
const PP2_SUBTYPE_SSL_KEY_ALG: u8 = 0x25; // Key exchange algorithm

// SSL Client Bitmask Flags
const PP2_CLIENT_SSL:       u8 = 0x01; // Connection was over TLS
const PP2_CLIENT_CERT_CONN: u8 = 0x02; // Client provided a certificate in this connection
const PP2_CLIENT_CERT_SESS: u8 = 0x04; // Client provided a certificate in this session
