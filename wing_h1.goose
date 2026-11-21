// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Minimal "Vulkan Pipeline" HTTP/1.1 package entrypoint for goose-wing.
// Wires only TCP/Memory transport, RingBuffer, zero-copy HTTP/1.1 codec, compact Router,
// compile-time StageChain pipeline, optional H1 client, and core::csprng_fill.
// Excludes tls, http2, http3, quic, grpc, realtime, auth, cookie, dns, security, and compress.
namespace h1;

import std;

import core.bytes.case;
import core.bytes.trim;
import core.bytes.search;
import core.bytes.split;
import core.bytes.parse;
import core.bytes.format;
import core.bytes.utf8;
import core.math.arithmetic;
import core.math.bits;
import core.math.ct;
import core.io.types;
import core.io.ring;
import core.io.reactor;
import core.crypto.ct;
import core.crypto.csprng;

import h1.transport;
import h1.wire;
import h1.router;
import h1.pipeline;
import h1.client;
