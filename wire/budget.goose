// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Compile-time per-connection and per-request RAM ceilings for untrusted wire ingress
// across HTTP/1.1, HTTP/2 (HPACK), QUIC/HTTP/3 (QPACK), TLS 1.3 (ASN.1), and DNS.
namespace wire;

import std;
import rfc.h2;
import rfc.tls;
import http.headers;
import http.headers.chunked;
import http2.hpack;

// ---- HTTP/1.1 Ingress RAM Ceilings (RFC 9110, RFC 9112) --------------------

const H1_INLINE_HEADER_MAP_BYTES:    u64 = 10496; // HeaderMap: 8192 raw + 128*16 entries + slots/flags
const H1_OVERFLOW_ARENA_MAX_BYTES:   u64 = 139262; // OverflowArena: 65535 raw + 512*16 entries + 65535 URL
const H1_MAX_WIRE_HEADER_BYTES:      u64 = 8192; // Strict RFC 9112 Section 2.1 inline header block ceiling
const H1_MAX_OVERFLOW_HEADER_BYTES:  u64 = 65535; // Hard OverflowArena spill ceiling
const H1_MAX_BODY_PAYLOAD_BYTES:     u64 = 10485760; // 10 MiB hard decoded chunked / Content-Length body cap
const H1_PER_REQUEST_METADATA_BYTES: u64 = 23040; // Request + trailer HeaderMaps + ChunkFsmDecoder metadata
const H1_WIRE_READ_BUFFER_BYTES:     u64 = 16384; // Per-connection ingress read staging buffer
const H1_PER_CONNECTION_MAX_BYTES:   u64 = 178686; // Request metadata + OverflowArena cap + read buffer

// ---- HTTP/2 & HPACK Ingress RAM Ceilings (RFC 9113, RFC 7541) --------------

const H2_DYNAMIC_TABLE_BYTES:       u64 = 9088; // DynamicTable: 4096 arena + 128*32 entries + 768 hash + meta
const H2_PSEUDO_HEADERS_BYTES:      u64 = 2432; // PseudoHeaders: method + scheme + authority + path + protocol
const H2_MAX_FRAME_SIZE_BYTES:      u64 = 16384; // RFC 9113 Section 4.2 default SETTINGS_MAX_FRAME_SIZE
const H2_MAX_HUFF_DECODE_BYTES:     u64 = 65536; // HPACK_MAX_HUFF_OUT_BYTES cumulative Huffman sink cap
const H2_MAX_CONCURRENT_STREAMS:    u32 = 100; // RFC 9113 Section 6.5.2 concurrent stream ceiling
const H2_DEFAULT_CONN_WINDOW_BYTES: u64 = 1048576; // 1 MiB connection flow-control window cap
const H2_PER_STREAM_METADATA_BYTES: u64 = 12928; // HeaderMap (10496) + PseudoHeaders (2432)
const H2_PER_CONNECTION_MAX_BYTES:  u64 = 1383808; // DynamicTable + Huff cap + frame buf + 100 streams

// ---- QUIC & HTTP/3 & QPACK Ingress RAM Ceilings (RFC 9000, 9114, 9204) -----

const QUIC_MAX_DATAGRAM_BYTES:      u64 = 1472; // Standard path MTU UDP datagram payload
const QUIC_REASSEMBLY_ARENA_BYTES:  u64 = 17472; // SegmentedArena (16384) + Interval[..64] (1024) + meta
const QUIC_DEFAULT_MAX_DATA_BYTES:  u64 = 1048576; // ReassemblyBuffer default 1 MiB flow-control limit
const H3_QPACK_TABLE_BYTES:         u64 = 22144; // QpackTable: 16384 arena + entries + blocked + unacked
const H3_MAX_HEADER_FIELD_COUNT:    u64 = 128; // Hard cap enforced by http3::try_push_header_field
const H3_HEADER_FIELD_BYTES:        u64 = 4368; // HeaderField: 256 name + 4096 value + flags
const H3_MAX_HEADER_BLOCK_BYTES:    u64 = 559104; // 128 * 4368 worst-case decoded QPACK header list
const H3_PSEUDO_HEADERS_BYTES:      u64 = 1408; // http3::PseudoHeaders fixed inline buffers
const H3_MAX_CONCURRENT_STREAMS:    u32 = 100; // Concurrent bidirectional HTTP/3 request streams
const H3_PER_STREAM_METADATA_BYTES: u64 = 29376; // HeaderMap + PseudoHeaders + QUIC reassembly arena
const H3_PER_CONNECTION_MAX_BYTES:  u64 = 3535232; // QpackTable + QPACK list cap + CRYPTO buf + 100 streams

// ---- TLS 1.3 & ASN.1 Ingress RAM Ceilings (RFC 8446, RFC 9001) -------------

const TLS_MAX_RECORD_CIPHERTEXT_BYTES: u64 = 16640; // RFC 8446 Section 5.2 (2^14 + 256)
const TLS_MAX_RECORD_PLAINTEXT_BYTES:  u64 = 16384; // RFC 8446 Section 5.1 (2^14)
const TLS_QUIC_CRYPTO_STREAM_BYTES:    u64 = 16384; // QuicCryptoStream.buf inline capacity
const TLS_HANDSHAKE_SCRATCH_BYTES:     u64 = 16384; // DER certificate / handshake message parse scratch
const TLS_PER_RECORD_WORKING_BYTES:    u64 = 33024; // Ciphertext record + decrypted inner plaintext
const TLS_PER_CONNECTION_MAX_BYTES:    u64 = 65792; // Record working set + QUIC CRYPTO buf + handshake scratch

// ---- DNS & HTTPS/SVCB Ingress RAM Ceilings (RFC 1035, RFC 9460) ------------

const DNS_MAX_WIRE_PACKET_BYTES:     u64 = 4096; // EDNS0 / DoH wire message ceiling
const DNS_RESPONSE_STRUCT_BYTES:     u64 = 4704; // dns::Response (8 A + 8 AAAA + 4 HttpsRecord inline)
const DNS_NAME_DECODE_SCRATCH_BYTES: u64 = 256; // RFC 1035 Section 2.3.4 max domain name (255 + NUL)
const DNS_PER_PACKET_MAX_BYTES:      u64 = 9056; // Wire packet + decoded Response + name scratch

// ---- Global DoS Upper Envelopes --------------------------------------------

const MAX_H1_CONN_CONTROL_CEILING:  u64 = 262144; // 256 KiB
const MAX_H2_CONN_CONTROL_CEILING:  u64 = 2097152; // 2 MiB
const MAX_H3_CONN_CONTROL_CEILING:  u64 = 4194304; // 4 MiB
const MAX_TLS_CONN_CONTROL_CEILING: u64 = 131072; // 128 KiB
const MAX_DNS_PACKET_CEILING:       u64 = 16384; // 16 KiB

enum IngressProtocol {
    Http1,
    Http2,
    Http3Quic,
    Tls13,
    Dns,
}

struct IngressRamBudget {
    protocol:                IngressProtocol = IngressProtocol.Http1,
    per_connection_bytes:    u64             = 0,
    per_request_bytes:       u64             = 0,
    max_frame_or_record_len: u64             = 0,
    max_header_block_bytes:  u64             = 0,
    max_payload_bytes:       u64             = 0,
    max_concurrent_streams:  u32             = 1,
}

checkfree fn h1_connection_ram_budget() -> IngressRamBudget {
    return IngressRamBudget {
        protocol:                IngressProtocol.Http1,
        per_connection_bytes:    H1_PER_CONNECTION_MAX_BYTES,
        per_request_bytes:       H1_PER_REQUEST_METADATA_BYTES,
        max_frame_or_record_len: H1_MAX_WIRE_HEADER_BYTES,
        max_header_block_bytes:  H1_MAX_OVERFLOW_HEADER_BYTES,
        max_payload_bytes:       H1_MAX_BODY_PAYLOAD_BYTES,
        max_concurrent_streams:  1,
    };
}

checkfree fn h2_connection_ram_budget() -> IngressRamBudget {
    return IngressRamBudget {
        protocol:                IngressProtocol.Http2,
        per_connection_bytes:    H2_PER_CONNECTION_MAX_BYTES,
        per_request_bytes:       H2_PER_STREAM_METADATA_BYTES,
        max_frame_or_record_len: H2_MAX_FRAME_SIZE_BYTES,
        max_header_block_bytes:  H2_MAX_HUFF_DECODE_BYTES,
        max_payload_bytes:       H2_DEFAULT_CONN_WINDOW_BYTES,
        max_concurrent_streams:  H2_MAX_CONCURRENT_STREAMS,
    };
}

checkfree fn h3_connection_ram_budget() -> IngressRamBudget {
    return IngressRamBudget {
        protocol:                IngressProtocol.Http3Quic,
        per_connection_bytes:    H3_PER_CONNECTION_MAX_BYTES,
        per_request_bytes:       H3_PER_STREAM_METADATA_BYTES,
        max_frame_or_record_len: QUIC_MAX_DATAGRAM_BYTES,
        max_header_block_bytes:  H3_MAX_HEADER_BLOCK_BYTES,
        max_payload_bytes:       QUIC_DEFAULT_MAX_DATA_BYTES,
        max_concurrent_streams:  H3_MAX_CONCURRENT_STREAMS,
    };
}

checkfree fn tls_connection_ram_budget() -> IngressRamBudget {
    return IngressRamBudget {
        protocol:                IngressProtocol.Tls13,
        per_connection_bytes:    TLS_PER_CONNECTION_MAX_BYTES,
        per_request_bytes:       TLS_PER_RECORD_WORKING_BYTES,
        max_frame_or_record_len: TLS_MAX_RECORD_CIPHERTEXT_BYTES,
        max_header_block_bytes:  TLS_HANDSHAKE_SCRATCH_BYTES,
        max_payload_bytes:       TLS_MAX_RECORD_PLAINTEXT_BYTES,
        max_concurrent_streams:  1,
    };
}

checkfree fn dns_packet_ram_budget() -> IngressRamBudget {
    return IngressRamBudget {
        protocol:                IngressProtocol.Dns,
        per_connection_bytes:    DNS_PER_PACKET_MAX_BYTES,
        per_request_bytes:       DNS_RESPONSE_STRUCT_BYTES,
        max_frame_or_record_len: DNS_MAX_WIRE_PACKET_BYTES,
        max_header_block_bytes:  DNS_NAME_DECODE_SCRATCH_BYTES,
        max_payload_bytes:       DNS_MAX_WIRE_PACKET_BYTES,
        max_concurrent_streams:  1,
    };
}

checkfree inline fn is_budget_within_envelope(b: const IngressRamBudget&, max_conn_cap: u64) -> bool {
    guard b.per_request_bytes > 0 && b.per_connection_bytes >= b.per_request_bytes else { return false; }
    guard b.per_connection_bytes <= max_conn_cap else { return false; }
    return b.max_frame_or_record_len > 0 && b.max_payload_bytes > 0 && b.max_concurrent_streams >= 1;
}

// Verifies that all 5 ingress protocol RAM budgets stay within compile-time envelopes
// and remain synchronized with the live parser capacity constants across protocol modules.
checkfree fn verify_ingress_budget_bounds() -> bool {
    let h1 = h1_connection_ram_budget();
    let h2 = h2_connection_ram_budget();
    let h3 = h3_connection_ram_budget();
    let tls = tls_connection_ram_budget();
    let dns = dns_packet_ram_budget();

    guard is_budget_within_envelope(h1, MAX_H1_CONN_CONTROL_CEILING) else { return false; }
    guard is_budget_within_envelope(h2, MAX_H2_CONN_CONTROL_CEILING) else { return false; }
    guard is_budget_within_envelope(h3, MAX_H3_CONN_CONTROL_CEILING) else { return false; }
    guard is_budget_within_envelope(tls, MAX_TLS_CONN_CONTROL_CEILING) else { return false; }
    guard is_budget_within_envelope(dns, MAX_DNS_PACKET_CEILING) else { return false; }

    let h1_sync = (http::MAX_OVERFLOW_RAW_BYTES as u64) == H1_MAX_OVERFLOW_HEADER_BYTES &&
        (http::MAX_OVERFLOW_URL_BYTES as u64) == H1_MAX_OVERFLOW_HEADER_BYTES &&
        http::MAX_OVERFLOW_SPILL_ENTRIES == 512 &&
        (http::MAX_CHUNKED_BODY_BYTES as u64) == H1_MAX_BODY_PAYLOAD_BYTES;
    let h2_tls_sync = (http2::HPACK_MAX_HUFF_OUT_BYTES as u64) == H2_MAX_HUFF_DECODE_BYTES &&
        rfc::H2_DEFAULT_MAX_FRAME_SIZE == H2_MAX_FRAME_SIZE_BYTES &&
        (rfc::TLS_MAX_RECORD_CIPHERTEXT_LEN as u64) == TLS_MAX_RECORD_CIPHERTEXT_BYTES &&
        (rfc::TLS_MAX_RECORD_PLAINTEXT_LEN as u64) == TLS_MAX_RECORD_PLAINTEXT_BYTES;
    return h1_sync && h2_tls_sync;
}
