// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Demonstration of goose-wing gRPC Microservices Engine:
// High-performance, zero-allocation gRPC Unary RPC dispatching,
// Length-Prefixed Message (LPM) framing, metadata propagation, and trailers.
import std;
import core from "..";
import wing from "..";

fn service_unary_handler(
    handler_id:  u16,
    ctx:         wing::GrpcServerContext&,
    req_payload: const u8[:],
    res_payload: u8[>..]&,
) -> wing::GrpcStatus {
    if handler_id == 1 {
        // Greeter.SayHello
        let auth = wing::get_metadata(ctx, "authorization");
        if auth.len == 0 {
            return wing::grpc_error(wing::GrpcStatusCode.Unauthenticated, "Missing required Bearer token");
        }

        wing::add_response_metadata(ctx, "x-server-version", "goose-wing-grpc/2.0");

        res_payload.append("Hello, ");
        res_payload.append(req_payload);
        res_payload.append("! Welcome to goose-wing gRPC engine.");
        return wing::grpc_ok();
    }
    if handler_id == 2 {
        // PaymentService.ProcessPayment
        wing::add_response_metadata(ctx, "x-payment-gw", "eu-central-wing");
        res_payload.append("{\"transaction_id\":\"tx_grpc_778899\",\"status\":\"SETTLED\"}");
        return wing::grpc_ok();
    }
    return wing::grpc_error(wing::GrpcStatusCode.Unimplemented, "RPC method not implemented");
}

fn main() {
    print("goose-wing High-Performance gRPC Microservices Demo\n");

    // 1. Initialize gRPC Server Dispatcher
    var dispatcher = wing::new_grpc_server_dispatcher();

    // 2. Register Unary RPC Service Endpoints
    wing::register_unary(dispatcher, "helloworld.Greeter", "SayHello", 1);
    wing::register_unary(dispatcher, "payment.PaymentService", "ProcessPayment", 2);

    print("[1] gRPC Service Endpoints Registered:");
    print("    -> helloworld.Greeter/SayHello (ID: 1)");
    print("    -> payment.PaymentService/ProcessPayment (ID: 2)");

    // 3. Simulate Inbound HTTP/2 gRPC Unary Request for Greeter
    var req1 = wing::new_request("POST", "/helloworld.Greeter/SayHello") { r =>
        r.set_header("content-type", rfc::GRPC_CONTENT_TYPE_PROTO);
        r.set_header("authorization", "Bearer secret-cluster-token-xyz");
    };

    // Encode payload "Citadel-Worker-42" into 5-byte Length-Prefixed Message (LPM)
    wing::encode_grpc_lpm("Citadel-Worker-42", req1.body, false);

    print("\n[2] Inbound Greeter Call Received:");
    print("    Target: ", req1.url);
    print("    Content-Type: ", wing::header(req1, "content-type"));
    print("    LPM Wire Size: ", req1.body.len, " bytes");

    // 4. Dispatch through zero-allocation gRPC dispatcher
    var res1 = wing::Response { .. };
    let now_mono_ns: u64 = 1000000000;
    let handled1 = wing::dispatch_grpc_unary(dispatcher, req1, now_mono_ns, res1, service_unary_handler);

    print("\n[3] Dispatch Execution Result:");
    print("    Handled: ", handled1);
    print("    HTTP Status: ", res1.status_code);
    print("    Metadata x-server-version: ", wing::header(res1, "x-server-version"));
    print("    Trailer grpc-status: ", wing::trailer(res1, rfc::HEADER_GRPC_STATUS));

    // Decode response LPM payload
    var decoded_msg: u8[>..] = [];
    var is_comp = false;
    let ok_lpm, _ = wing::decode_grpc_lpm(res1.body[..], 0, decoded_msg, is_comp);
    print("    Decoded Response Payload: ", decoded_msg[..]);

    // 5. Simulate Inbound Call Without Credentials (Unauthenticated error test)
    var req2 = wing::new_request("POST", "/helloworld.Greeter/SayHello") { r =>
        r.set_header("content-type", rfc::GRPC_CONTENT_TYPE_PROTO);
    };
    wing::encode_grpc_lpm("Intruder", req2.body, false);

    var res2 = wing::Response { .. };
    let handled2 = wing::dispatch_grpc_unary(dispatcher, req2, now_mono_ns, res2, service_unary_handler);

    // In RFC gRPC over HTTP/2, pure errors are returned as 'Trailers-Only'
    // in the initial response HEADERS block to avoid allocating stream data frames.
    let err_status = wing::header(res2, rfc::HEADER_GRPC_STATUS);
    let err_msg = wing::header(res2, rfc::HEADER_GRPC_MESSAGE);

    print("\n[4] Unauthenticated Call Handling (RFC Trailers-Only):");
    print("    Handled: ", handled2);
    print("    HTTP Status: ", res2.status_code);
    print("    Header grpc-status: ", err_status, " (Code 16: Unauthenticated)");
    print("    Header grpc-message: ", err_msg);
}
