// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Built-in gRPC Health Checking Protocol (`grpc.health.v1.Health/Check`, gRFC A66).
namespace wing;

import std;
import core from "..";
import grpc.constants;
import grpc.framing;

enum GrpcServingStatus {
    Unknown,
    Serving,
    NotServing,
    ServiceUnknown,
}

struct GrpcHealthServiceEntry {
    service: u8[..64]          = [],
    status:  GrpcServingStatus = GrpcServingStatus.Serving,
}

// Extracts the target `service` string (field 1) from a protobuf `HealthCheckRequest` payload.
//
// Example:
//   req_payload = "\x0A\x0Amy.Service"
//   returns: "my.Service"
fn decode_grpc_health_check_service(req_payload: const u8[:]) -> const u8[:] {
    let svc_slice, ok_svc = pb_read_bytes_field(req_payload, 1);
    return if ok_svc { svc_slice } else { "" };
}

// Encodes a protobuf `HealthCheckResponse` message (field 1 = `ServingStatus` varint) wrapped
// in an uncompressed gRPC Length-Prefixed-Message (LPM) frame.
fn encode_grpc_health_check_lpm(serving_st: GrpcServingStatus, out_lpm: u8[>..]&) {
    var res_payload: u8[..16] = [];
    if serving_st != GrpcServingStatus.Unknown {
        let code_u64: u64 = match serving_st {
            Unknown => 0,
            Serving => 1,
            NotServing => 2,
            ServiceUnknown => 3,
        };
        let _ = pb_write_varint_field(1, code_u64, res_payload);
    }
    encode_grpc_lpm(res_payload[..], out_lpm, false);
}
