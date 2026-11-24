// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Standardized IETF RFC wire protocol constants and zero-allocation status helpers.
// Exposes a flat `rfc` namespace covering HTTP/1.1, HTTP/2, HTTP/3, QUIC, DNS, TLS 1.3, WebSocket, and gRPC.
namespace rfc;

import std;
import core;

import rfc.http;
import rfc.dns;
import rfc.h2;
import rfc.h3_quic;
import rfc.tls;
import rfc.ws;
import rfc.grpc;
