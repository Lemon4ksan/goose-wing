// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// gRPC over HTTP/2, HTTP/3, and gRPC-Web wire framing constants and headers.
namespace rfc;

import std;

// ---- gRPC Wire Framing Constants (Length-Prefixed Message) ---------------

const GRPC_DEFAULT_MAX_MESSAGE_SIZE: u32         = 4194304;
const GRPC_LPM_HEADER_LEN:           u32         = 5;
const GRPC_FLAG_UNCOMPRESSED:        u8          = 0x00;
const GRPC_FLAG_COMPRESSED:          u8          = 0x01;
const GRPC_WEB_FLAG_TRAILERS:        u8          = 0x80;
const MIME_GRPC:                     const u8[:] = "application/grpc";
const MIME_GRPC_PROTO:               const u8[:] = "application/grpc+proto";
const PROTO_TAG_STATUS_CODE:         u8          = 0x08;
const PROTO_TAG_STATUS_MESSAGE:      u8          = 0x12;

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
