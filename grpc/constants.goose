// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// gRPC wire framing constants, canonical status codes, and HTTP/2 / HTTP/3 content types.
// Conforms to gRPC Over HTTP/2 Specification and gRPC-Web Specification.
namespace wing;

import std;
import rfc.h2;
import rfc.grpc;

// ---- Canonical gRPC Status Codes (RFC / gRPC Core) ----------------------

enum GrpcStatusCode {
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

// Converts a GrpcStatusCode to its standard string representation.
fn grpc_status_name(code: GrpcStatusCode) -> const u8[:] {
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

// Converts a GrpcStatusCode enum value to its integer code (0..16).
fn grpc_status_to_code(code: GrpcStatusCode) -> u32 {
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

// Converts an integer code to its GrpcStatusCode enum value.
fn grpc_status_from_code(code: u32) -> GrpcStatusCode {
    return match code {
        0 => GrpcStatusCode.Ok,
        1 => GrpcStatusCode.Cancelled,
        2 => GrpcStatusCode.Unknown,
        3 => GrpcStatusCode.InvalidArgument,
        4 => GrpcStatusCode.DeadlineExceeded,
        5 => GrpcStatusCode.NotFound,
        6 => GrpcStatusCode.AlreadyExists,
        7 => GrpcStatusCode.PermissionDenied,
        8 => GrpcStatusCode.ResourceExhausted,
        9 => GrpcStatusCode.FailedPrecondition,
        10 => GrpcStatusCode.Aborted,
        11 => GrpcStatusCode.OutOfRange,
        12 => GrpcStatusCode.Unimplemented,
        13 => GrpcStatusCode.Internal,
        14 => GrpcStatusCode.Unavailable,
        15 => GrpcStatusCode.DataLoss,
        16 => GrpcStatusCode.Unauthenticated,
        _ => GrpcStatusCode.Unknown,
    };
}

// Maps standard HTTP status codes to canonical gRPC status codes when grpc-status is missing.
// Follows gRPC HTTP/2 transport mapping specifications:
// HTTP 200 without grpc-status maps to Unknown (success requires explicit grpc-status: 0).
fn grpc_status_from_http(http_status: i32) -> GrpcStatusCode {
    return match http_status {
        200 => GrpcStatusCode.Unknown,
        400 => GrpcStatusCode.Internal,
        401 => GrpcStatusCode.Unauthenticated,
        403 => GrpcStatusCode.PermissionDenied,
        404 => GrpcStatusCode.Unimplemented,
        409 => GrpcStatusCode.Aborted,
        429 => GrpcStatusCode.ResourceExhausted,
        499 => GrpcStatusCode.Cancelled,
        500 => GrpcStatusCode.Internal,
        501 => GrpcStatusCode.Unimplemented,
        502 => GrpcStatusCode.Unavailable,
        503 => GrpcStatusCode.Unavailable,
        504 => GrpcStatusCode.DeadlineExceeded,
        _ => GrpcStatusCode.Unknown,
    };
}

// Maps HTTP/2 RST_STREAM error codes (RFC 9113 §7) to canonical gRPC status codes.
fn h2_error_to_grpc_status(h2_err: u32) -> GrpcStatusCode {
    if h2_err == rfc::H2_ERR_REFUSED_STREAM { return GrpcStatusCode.Unavailable; }
    if h2_err == rfc::H2_ERR_CANCEL { return GrpcStatusCode.Cancelled; }
    if h2_err == rfc::H2_ERR_ENHANCE_YOUR_CALM { return GrpcStatusCode.ResourceExhausted; }
    if h2_err == rfc::H2_ERR_INADEQUATE_SECURITY { return GrpcStatusCode.PermissionDenied; }
    if h2_err <= rfc::H2_ERR_SETTINGS_TIMEOUT ||
       h2_err == rfc::H2_ERR_FRAME_SIZE_ERROR ||
       h2_err == rfc::H2_ERR_COMPRESSION_ERROR ||
       h2_err == rfc::H2_ERR_CONNECT_ERROR {
        return GrpcStatusCode.Internal;
    }
    return GrpcStatusCode.Unknown;
}

struct GrpcMetadata {
    key:   u8[..64]  = [],
    value: u8[..256] = [],
}

// Structured error detail extracted from `google.rpc.Status.details` (`google.protobuf.Any`).
struct GrpcErrorDetail {
    type_url: u8[..128] = [],
    value:    u8[..256] = [],
}

// Value-returned gRPC status outcome for unary and streaming RPC handlers.
struct GrpcStatus {
    code:    GrpcStatusCode       = GrpcStatusCode.Ok,
    message: u8[..256]            = [],
    details: GrpcErrorDetail[..4] = [],
}
