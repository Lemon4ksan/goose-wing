// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// gRPC wire framing constants, canonical status codes, and HTTP/2 / HTTP/3 content types.
// Conforms to gRPC Over HTTP/2 Specification and gRPC-Web Specification.
namespace grpc;

import std;
import core;
import rfc.http;
import rfc.h2;
import rfc.grpc;
import .internal;

// ---- Canonical gRPC Status Codes (RFC / gRPC Core) ----------------------

enum StatusCode {
    Ok,
    Cancelled,
    Unknown,
    InvalidArgument,
    DeadlineExceeded,
    NotFound,
    AlreadyExists,
    PermissionDenied,
    ResourceExhausted,
    FailedPrecondition,
    Aborted,
    OutOfRange,
    Unimplemented,
    Internal,
    Unavailable,
    DataLoss,
    Unauthenticated,
}

const GRPC_STATUS_NAMES: const u8[:][17] = [
    "OK", "CANCELLED", "UNKNOWN", "INVALID_ARGUMENT", "DEADLINE_EXCEEDED",
    "NOT_FOUND", "ALREADY_EXISTS", "PERMISSION_DENIED", "RESOURCE_EXHAUSTED",
    "FAILED_PRECONDITION", "ABORTED", "OUT_OF_RANGE", "UNIMPLEMENTED",
    "INTERNAL", "UNAVAILABLE", "DATA_LOSS", "UNAUTHENTICATED",
];

// Converts a StatusCode enum value to its integer code (0..16).
checkfree fn status_to_code(code: StatusCode) -> u32 {
    var idx: u32 = 0;
    const for <N, V> in variants<StatusCode> {
        let v: StatusCode = default<V>();
        if code == v { return idx; }
        idx += 1;
    }
    return 2;
}

// Converts a StatusCode to its standard string representation.
checkfree fn status_name(code: StatusCode) -> const u8[:] {
    let idx = status_to_code(code) as i64;
    return if idx < 17 { GRPC_STATUS_NAMES[idx] } else { "UNKNOWN" };
}

// Converts an integer code to its StatusCode enum value.
checkfree fn status_from_code(code: u32) -> StatusCode {
    var idx: u32 = 0;
    const for <N, V> in variants<StatusCode> {
        if code == idx { return default<V>(); }
        idx += 1;
    }
    return StatusCode.Unknown;
}

// Maps standard HTTP status codes to canonical gRPC status codes when grpc-status is missing.
// Follows gRPC HTTP/2 transport mapping specifications:
// HTTP 200 without grpc-status maps to Unknown (success requires explicit grpc-status: 0).
fn status_from_http(http_status: i32) -> StatusCode {
    return match http_status {
        rfc::STATUS_OK => StatusCode.Unknown,
        rfc::STATUS_BAD_REQUEST => StatusCode.Internal,
        rfc::STATUS_UNAUTHORIZED => StatusCode.Unauthenticated,
        rfc::STATUS_FORBIDDEN => StatusCode.PermissionDenied,
        rfc::STATUS_NOT_FOUND => StatusCode.Unimplemented,
        rfc::STATUS_TOO_MANY_REQUESTS => StatusCode.ResourceExhausted,
        rfc::STATUS_BAD_GATEWAY => StatusCode.Unavailable,
        rfc::STATUS_SERVICE_UNAVAILABLE => StatusCode.Unavailable,
        rfc::STATUS_GATEWAY_TIMEOUT => StatusCode.DeadlineExceeded,
        _ => StatusCode.Unknown,
    };
}

// Returns true if Content-Type matches standard gRPC, gRPC-Web, or gRPC-Web-Text.
fn is_content_type(ct: const u8[:]) -> bool {
    let trimmed = ct.trim_lws();
    return grpc_internal::matches_media_type(trimmed, rfc::GRPC_CONTENT_TYPE)
        || grpc_internal::matches_media_type(trimmed, rfc::GRPC_WEB_CONTENT_TYPE)
        || grpc_internal::matches_media_type(trimmed, rfc::GRPC_WEB_TEXT_CONTENT_TYPE);
}

// Maps HTTP/2 RST_STREAM error codes (RFC 9113 §7) to canonical gRPC status codes.
fn h2_error_to_status(h2_err: u32) -> StatusCode {
    if h2_err == rfc::H2_ERR_REFUSED_STREAM { return StatusCode.Unavailable; }
    if h2_err == rfc::H2_ERR_CANCEL { return StatusCode.Cancelled; }
    if h2_err == rfc::H2_ERR_ENHANCE_YOUR_CALM { return StatusCode.ResourceExhausted; }
    if h2_err == rfc::H2_ERR_INADEQUATE_SECURITY { return StatusCode.PermissionDenied; }
    if h2_err <= rfc::H2_ERR_SETTINGS_TIMEOUT
        || h2_err == rfc::H2_ERR_FRAME_SIZE_ERROR
        || h2_err == rfc::H2_ERR_COMPRESSION_ERROR
        || h2_err == rfc::H2_ERR_CONNECT_ERROR {
        return StatusCode.Internal;
    }
    return StatusCode.Unknown;
}

struct Metadata {
    key:   u8[..64]  = [],
    value: u8[..256] = [],
}

// Structured error detail extracted from `google.rpc.Status.details` (`google.protobuf.Any`).
struct ErrorDetail {
    type_url: u8[..128] = [],
    value:    u8[..256] = [],
}

// Value-returned gRPC status outcome for unary and streaming RPC handlers.
struct Status {
    code:    StatusCode       = StatusCode.Ok,
    message: u8[..256]        = [],
    details: ErrorDetail[..4] = [],
}
