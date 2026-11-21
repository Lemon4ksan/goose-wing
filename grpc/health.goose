// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Built-in gRPC Health Checking Protocol (`grpc.health.v1.Health/Check`, gRFC A66).
namespace grpc;

import std;

enum ServingStatus {
    Unknown,
    Serving,
    NotServing,
    ServiceUnknown,
}

struct HealthServiceEntry {
    service: u8[..128]     = [],
    status:  ServingStatus = ServingStatus.Serving,
}
