// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// gRPC over HTTP/2, HTTP/3, and gRPC-Web wire framing constants and headers.
namespace rfc;

import std;

// ---- gRPC Wire Framing Constants (Length-Prefixed Message) ---------------

// Default 4 MiB gRPC inbound message size ceiling.
const GRPC_DEFAULT_MAX_MESSAGE_SIZE: u32 = 4194304;
// 1-byte compression flag + 4-byte big-endian message length prefix.
const GRPC_LPM_HEADER_LEN:    u32 = 5;
const GRPC_FLAG_UNCOMPRESSED: u8  = 0x00;
const GRPC_FLAG_COMPRESSED:   u8  = 0x01;
// gRPC-Web trailer frame flag bit (RFC / gRPC-Web spec: MSB set).
const GRPC_WEB_FLAG_TRAILERS: u8          = 0x80;
const MIME_GRPC:              const u8[:] = "application/grpc";
const MIME_GRPC_PROTO:        const u8[:] = "application/grpc+proto";
// Protobuf field 1 varint wire tag for `google.rpc.Status.code`.
const PROTO_TAG_STATUS_CODE: u8 = 0x08;
// Protobuf field 2 length-delimited wire tag for `google.rpc.Status.message`.
const PROTO_TAG_STATUS_MESSAGE: u8 = 0x12;

const GRPC_CONTENT_TYPE:       const u8[:] = "application/grpc";
const GRPC_CONTENT_TYPE_PROTO: const u8[:] = "application/grpc+proto";
const GRPC_CONTENT_TYPE_JSON:  const u8[:] = "application/grpc+json";

const GRPC_WEB_CONTENT_TYPE:       const u8[:] = "application/grpc-web";
const GRPC_WEB_CONTENT_TYPE_PROTO: const u8[:] = "application/grpc-web+proto";
const GRPC_WEB_CONTENT_TYPE_JSON:  const u8[:] = "application/grpc-web+json";
const GRPC_WEB_TEXT_CONTENT_TYPE:  const u8[:] = "application/grpc-web-text";
const GRPC_WEB_TEXT_PROTO:         const u8[:] = "application/grpc-web-text+proto";

const HEADER_GRPC_STATUS:             const u8[:] = "grpc-status";
const HEADER_GRPC_MESSAGE:            const u8[:] = "grpc-message";
const HEADER_GRPC_TIMEOUT:            const u8[:] = "grpc-timeout";
const HEADER_GRPC_ENCODING:           const u8[:] = "grpc-encoding";
const HEADER_GRPC_ACCEPT_ENCODING:    const u8[:] = "grpc-accept-encoding";
const HEADER_GRPC_STATUS_DETAILS_BIN: const u8[:] = "grpc-status-details-bin";

// ---- Connect-RPC Wire Framing & Content-Types ----------------------------

// Connect Protocol streaming EndStream envelope flag.
const CONNECT_FLAG_END_STREAM: u8 = 0x02;
// Connect Protocol streaming content-type prefix.
const CONNECT_CONTENT_PREFIX: const u8[:] = "application/connect+";
// Connect Protocol unary protobuf media type.
const CONNECT_MIME_PROTO: const u8[:] = "application/proto";
// Connect Protocol unary JSON media type.
const CONNECT_MIME_JSON: const u8[:] = "application/json";
