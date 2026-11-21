// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// gRPC wire framing constants, canonical status codes, and HTTP/2 / HTTP/3 content types.
// Conforms to gRPC Over HTTP/2 Specification and gRPC-Web Specification.
namespace grpc;

import std;
import core from "..";
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

// Converts a StatusCode to its standard string representation.
fn status_name(code: StatusCode) -> const u8[:] {
    return match code {
        Ok => "OK",
        Cancelled => "CANCELLED",
        Unknown => "UNKNOWN",
        InvalidArgument => "INVALID_ARGUMENT",
        DeadlineExceeded => "DEADLINE_EXCEEDED",
        NotFound => "NOT_FOUND",
        AlreadyExists => "ALREADY_EXISTS",
        PermissionDenied => "PERMISSION_DENIED",
        ResourceExhausted => "RESOURCE_EXHAUSTED",
        FailedPrecondition => "FAILED_PRECONDITION",
        Aborted => "ABORTED",
        OutOfRange => "OUT_OF_RANGE",
        Unimplemented => "UNIMPLEMENTED",
        Internal => "INTERNAL",
        Unavailable => "UNAVAILABLE",
        DataLoss => "DATA_LOSS",
        Unauthenticated => "UNAUTHENTICATED",
        _ => "UNKNOWN",
    };
}

// Converts a StatusCode enum value to its integer code (0..16).
fn status_to_code(code: StatusCode) -> u32 {
    return match code {
        Ok => 0,
        Cancelled => 1,
        Unknown => 2,
        InvalidArgument => 3,
        DeadlineExceeded => 4,
        NotFound => 5,
        AlreadyExists => 6,
        PermissionDenied => 7,
        ResourceExhausted => 8,
        FailedPrecondition => 9,
        Aborted => 10,
        OutOfRange => 11,
        Unimplemented => 12,
        Internal => 13,
        Unavailable => 14,
        DataLoss => 15,
        Unauthenticated => 16,
        _ => 2,
    };
}

// Converts an integer code to its StatusCode enum value.
fn status_from_code(code: u32) -> StatusCode {
    return match code {
        0 => StatusCode.Ok,
        1 => StatusCode.Cancelled,
        2 => StatusCode.Unknown,
        3 => StatusCode.InvalidArgument,
        4 => StatusCode.DeadlineExceeded,
        5 => StatusCode.NotFound,
        6 => StatusCode.AlreadyExists,
        7 => StatusCode.PermissionDenied,
        8 => StatusCode.ResourceExhausted,
        9 => StatusCode.FailedPrecondition,
        10 => StatusCode.Aborted,
        11 => StatusCode.OutOfRange,
        12 => StatusCode.Unimplemented,
        13 => StatusCode.Internal,
        14 => StatusCode.Unavailable,
        15 => StatusCode.DataLoss,
        16 => StatusCode.Unauthenticated,
        _ => StatusCode.Unknown,
    };
}

// Maps standard HTTP status codes to canonical gRPC status codes when grpc-status is missing.
// Follows gRPC HTTP/2 transport mapping specifications:
// HTTP 200 without grpc-status maps to Unknown (success requires explicit grpc-status: 0).
fn status_from_http(http_status: i32) -> StatusCode {
    return match http_status {
        200 => StatusCode.Unknown,
        400 => StatusCode.Internal,
        401 => StatusCode.Unauthenticated,
        403 => StatusCode.PermissionDenied,
        404 => StatusCode.Unimplemented,
        429 => StatusCode.ResourceExhausted,
        502 => StatusCode.Unavailable,
        503 => StatusCode.Unavailable,
        504 => StatusCode.DeadlineExceeded,
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
