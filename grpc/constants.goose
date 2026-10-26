// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// gRPC wire framing constants, canonical status codes, and HTTP/2 / HTTP/3 content types.
// Conforms to gRPC Over HTTP/2 Specification and gRPC-Web Specification.
namespace wing;

import std;

// ---- 1. Framing Constants (LPM: Length-Prefixed Message) -------------------

// 5-byte LPM Header: 1-byte compression flag + 4-byte big-endian uint32 payload length.
const GRPC_LPM_HEADER_LEN: u32 = 5;

// gRPC-Web wire flags (stored in the 1st byte of the LPM header):
// Bit 0: Compressed flag (RFC gRPC)
const GRPC_FLAG_COMPRESSED: u8 = 0x01;

// Bit 7: Trailers-in-body flag (RFC gRPC-Web Section 2.1)
const GRPC_WEB_FLAG_TRAILERS: u8 = 0x80;

// Maximum allowed single gRPC message payload size (default 4MB, bounded for zero-heap stack)
const GRPC_DEFAULT_MAX_MESSAGE_SIZE: u32 = 4194304;

// ---- 2. Canonical gRPC Status Codes (RFC / gRPC Core) ----------------------

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
// Follows gRPC HTTP/2 transport mapping specifications.
fn grpc_status_from_http(http_status: i32) -> GrpcStatusCode {
    return match http_status {
        200 => GrpcStatusCode.Ok,
        400 => GrpcStatusCode.InvalidArgument,
        401 => GrpcStatusCode.Unauthenticated,
        403 => GrpcStatusCode.PermissionDenied,
        404 => GrpcStatusCode.NotFound,
        409 => GrpcStatusCode.Aborted,
        429 => GrpcStatusCode.ResourceExhausted,
        499 => GrpcStatusCode.Cancelled,
        500 => GrpcStatusCode.Internal,
        501 => GrpcStatusCode.Unimplemented,
        502 => GrpcStatusCode.Unavailable,
        503 => GrpcStatusCode.Unavailable,
        504 => GrpcStatusCode.DeadlineExceeded,
        _ => if http_status >= 200 && http_status < 300 { GrpcStatusCode.Ok } else { GrpcStatusCode.Unknown },
    };
}

// ---- 3. Well-Known gRPC Headers and Content Types --------------------------

let GRPC_CONTENT_TYPE: const u8[:] = "application/grpc";
let GRPC_CONTENT_TYPE_PROTO: const u8[:] = "application/grpc+proto";
let GRPC_CONTENT_TYPE_JSON: const u8[:] = "application/grpc+json";

let GRPC_WEB_CONTENT_TYPE: const u8[:] = "application/grpc-web";
let GRPC_WEB_CONTENT_TYPE_PROTO: const u8[:] = "application/grpc-web+proto";
let GRPC_WEB_CONTENT_TYPE_JSON: const u8[:] = "application/grpc-web+json";
let GRPC_WEB_TEXT_CONTENT_TYPE: const u8[:] = "application/grpc-web-text";
let GRPC_WEB_TEXT_PROTO: const u8[:] = "application/grpc-web-text+proto";

let HEADER_GRPC_STATUS: const u8[:] = "grpc-status";
let HEADER_GRPC_MESSAGE: const u8[:] = "grpc-message";
let HEADER_GRPC_TIMEOUT: const u8[:] = "grpc-timeout";
let HEADER_GRPC_ENCODING: const u8[:] = "grpc-encoding";
let HEADER_GRPC_ACCEPT_ENCODING: const u8[:] = "grpc-accept-encoding";
let HEADER_GRPC_STATUS_DETAILS_BIN: const u8[:] = "grpc-status-details-bin";
