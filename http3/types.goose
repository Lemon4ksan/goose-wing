// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Public HTTP/3 framing, QPACK, and connection types and enums (RFC 9114, RFC 9204).
namespace http3;

import std;
import core from "..";
import rfc.h3_quic;
import http.headers;
import http.priority;
import fingerprint.profile;
import .internal;

// ---- Framing Types ---------------------------------------------------------

struct FrameHeader {
    frame_type:  u64 = 0,
    payload_len: u64 = 0,
    header_len:  u64 = 0,
}

// ---- QPACK Types -----------------------------------------------------------

struct QpackStaticEntry {
    name: const u8[:] = "",
    val:  const u8[:] = "",
}

enum QpackError {
    None,
    StreamBlocked,           // Stream is blocked waiting for encoder stream
    DecompressionFailed,     // H3_ERR_QPACK_DECOMPRESSION_FAILED (0x0200)
    EncoderStreamError,      // H3_ERR_QPACK_ENCODER_STREAM_ERROR (0x0201)
    DecoderStreamError,      // H3_ERR_QPACK_DECODER_STREAM_ERROR (0x0202)
    HeaderListTooLarge,      // Exceeded SETTINGS_MAX_FIELD_SECTION_SIZE
    BlockedStreamsExhausted, // Exceeded SETTINGS_QPACK_BLOCKED_STREAMS
    ClosedCriticalStream,    // H3_ERR_CLOSED_CRITICAL_STREAM (0x0104)
    StreamCreationError,     // H3_ERR_STREAM_CREATION (0x0103)
    FrameEncodingError,      // H3_ERR_FRAME_ERROR
    MessageError,            // H3_ERR_GENERAL_PROTOCOL (0x0101) / H3_ERR_MESSAGE_ERROR (0x010E)
}

// Decoded HTTP/3 pseudo-header fields and message validation metadata (RFC 9114 §4.3).
struct PseudoHeaders {
    method:             u8[..16]   = [],
    scheme:             u8[..16]   = [],
    authority:          u8[..256]  = [],
    path:               u8[..1024] = [],
    protocol:           u8[..64]   = [],
    status:             i32        = 0,
    has_method:         bool       = false,
    has_scheme:         bool       = false,
    has_authority:      bool       = false,
    has_path:           bool       = false,
    has_protocol:       bool       = false,
    has_status:         bool       = false,
    has_regular_header: bool       = false,
    content_length:     i64        = -1,
    is_trailer:         bool       = false,
}

struct HeaderField {
    name:        u8[..256]  = [],
    value:       u8[..4096] = [],
    never_index: bool       = false,
}

struct QpackTable {
    capacity_bytes:     u64                                    = 0,
    max_capacity_bytes: u64                                    = 0,
    used_bytes:         u64                                    = 0,
    insert_count:       u64                                    = 0, // TotalNumberOfInserts
    known_rcvd_count:   u64                                    = 0, // Known Received Count
    draining_index:     u64                                    = 0, // Active indexing lower bound
    max_blocked:        u32                                    = 16,
    blocked_streams:    h3_internal::BlockedStreamEntry[..128] = [],
    unacked_sections:   h3_internal::UnackedSection[..32]      = [],
    arena:              u8[16384]                              = [0; 16384],
    arena_write_pos:    u32                                    = 0,
    entries:            h3_internal::DynamicEntryDesc[..128]   = [],
}

// ---- Connection Types ------------------------------------------------------

enum StreamKind {
    Request,
    Control,
    QpackEncoder,
    QpackDecoder,
    Push,
    UnknownUni,
}

enum StreamState {
    Idle,
    Open,
    HalfClosedLocal,
    HalfClosedRemote,
    Closed,
}

struct StreamEntry {
    stream_id:            u64                 = 0,
    kind:                 StreamKind          = StreamKind.Request,
    state:                StreamState         = StreamState.Idle,
    headers_sent:         bool                = false,
    headers_received:     bool                = false,
    trailers_received:    bool                = false,
    fin_sent:             bool                = false,
    fin_received:         bool                = false,
    status_code:          i32                 = 0,
    body_received_len:    u64                 = 0,
    content_length:       i64                 = -1,
    priority:             http::PriorityParam = http::PriorityParam { urgency: 3, incremental: false },
    priority_updated:     bool                = false,
    tx_pending_bytes:     u64                 = 0,
    last_scheduled_cycle: u64                 = 0,
    req_method:           u8[..16]            = [],
    req_path:             u8[..1024]          = [],
    req_authority:        u8[..256]           = [],
    headers:              http::HeaderMap     = http::HeaderMap { .. },
    trailers:             http::HeaderMap     = http::HeaderMap { .. },
    received_body:        u8[..4096]          = [],
    blocked_wire:         u8[..4096]          = [],
    rx_partial_buf:       u8[..4096]          = [],
}

enum ConnRole {
    Client,
    Server,
}

enum ConnState {
    Connecting,
    Active,
    Draining,
    Closed,
}

// Fixed-capacity HTTP/3 connection state machine without heap allocations.
struct Connection {
    role:                      ConnRole                              = ConnRole.Client,
    state:                     ConnState                             = ConnState.Connecting,
    next_bidi_stream_id:       u64                                   = 0,
    local_settings_sent:       bool                                  = false,
    peer_control_stream_id:    u64                                   = 0xFFFFFFFFFFFFFFFF,
    peer_control_opened:       bool                                  = false,
    peer_settings_received:    bool                                  = false,
    peer_qpack_enc_stream_id:  u64                                   = 0xFFFFFFFFFFFFFFFF,
    peer_qpack_enc_opened:     bool                                  = false,
    peer_qpack_dec_stream_id:  u64                                   = 0xFFFFFFFFFFFFFFFF,
    peer_qpack_dec_opened:     bool                                  = false,
    ignored_uni_streams:       u64[..64]                             = [],
    opened_push_ids:           u64[..64]                             = [],
    push_uni_streams:          u64[..16]                             = [],
    promised_pushes:           h3_internal::PromisedPushRecord[..64] = [],
    goaway_received:           bool                                  = false,
    goaway_max_stream_id:      u64                                   = 0xFFFFFFFFFFFFFFFF,
    max_push_id_sent:          bool                                  = false,
    max_push_id_advertised:    u64                                   = 0,
    has_received_max_push_id:  bool                                  = false,
    max_push_id_received:      u64                                   = 0,
    has_promised_push_id:      bool                                  = false,
    max_promised_push_id:      u64                                   = 0,
    empty_frame_streak:        u32                                   = 0,
    control_glitch_count:      u32                                   = 0,
    max_control_glitches:      u32                                   = 256,
    sched_cycle:               u64                                   = 0,
    peer_origins:              u8[..128][..16]                       = [],
    error_code:                u64                                   = rfc::H3_ERR_NO_ERROR,
    local_settings:            fingerprint::H3Settings               = fingerprint::H3Settings { .. },
    peer_settings:             fingerprint::H3Settings               = fingerprint::H3Settings { .. },
    encoder_stream_buf:        u8[..4096]                            = [],
    ctrl_partial_buf:          u8[..1024]                            = [],
    qpack_enc_partial_buf:     u8[..4224]                            = [],
    qpack_dec_partial_buf:     u8[..64]                              = [],
    local_qpack_enc_activated: bool                                  = false,
    streams:                   StreamEntry[..32]                     = [],
    qpack_static_only_tbl:     QpackTable                            = QpackTable { .. },
    qpack_dec_table:           QpackTable                            = QpackTable { .. },
    qpack_table:               QpackTable                            = QpackTable { .. },
}
