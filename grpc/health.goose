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
    service: u8[..128]         = [],
    status:  GrpcServingStatus = GrpcServingStatus.Serving,
}

// Decodes and validates a protobuf `HealthCheckRequest` payload (field 1 = `service` UTF-8 string).
// Rejects truncated varints, invalid wire types, or invalid UTF-8 in `service`.
//
// Example:
//   req_payload = "\x0A\x0Amy.Service"
//   returns: "my.Service", true
fn try_decode_grpc_health_check_request(req_payload: const u8[:]) -> const u8[:], bool {
    var pos:       i64 = 0;
    var svc_start: i64 = 0;
    var svc_end:   i64 = 0;
    while pos < req_payload.len {
        let tag, ok_tag = pb_read_varint(req_payload, pos);
        let raw_fnum = tag >> 3;
        guard ok_tag && raw_fnum >= 1 && raw_fnum <= PB_MAX_FIELD_NUM else { return "", false; }
        let fnum = raw_fnum as u32;
        let wtype = (tag & 0x07) as u32;
        if fnum == 1 {
            guard wtype == PB_WIRE_LEN else { return "", false; }
            let len_u64, ok_len = pb_read_varint(req_payload, pos);
            let rem = core::sub_sat_i64(req_payload.len, pos);
            guard ok_len && len_u64 <= (rem as u64) else { return "", false; }
            let end_pos = core::add_sat_i64(pos, len_u64 as i64);
            guard req_payload[pos..end_pos].validate_utf8() else { return "", false; }
            svc_start = pos;
            svc_end = end_pos;
            pos = end_pos;
        } else {
            guard pb_skip_field(req_payload, pos, wtype) else { return "", false; }
        }
    }
    return req_payload[svc_start..svc_end], true;
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
