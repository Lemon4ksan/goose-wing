// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Demonstration of goose-wing gRPC Microservices Engine:
// High-performance, zero-allocation gRPC Unary RPC dispatching,
// Length-Prefixed Message (LPM) framing, metadata propagation, and trailers.
import std;
import wing from "..";

fn service_unary_handler(
    handler_id:  u16,
    ctx:         grpc::ServerContext&,
    req_payload: const u8[:],
    res_payload: u8[>..]&,
) -> grpc::Status {
    if handler_id == 1 {
        // Greeter.SayHello
        let auth = grpc::get_metadata(ctx, "authorization");
        if auth.len == 0 {
            return grpc::error(grpc::StatusCode.Unauthenticated, "Missing required Bearer token");
        }

        grpc::add_response_metadata(ctx, "x-server-version", "goose-wing-grpc/2.0");

        res_payload.append("Hello, ");
        res_payload.append(req_payload);
        res_payload.append("! Welcome to goose-wing gRPC engine.");
        return grpc::ok();
    }
    if handler_id == 2 {
        // PaymentService.ProcessPayment
        grpc::add_response_metadata(ctx, "x-payment-gw", "eu-central-wing");
        res_payload.append("{\"transaction_id\":\"tx_grpc_778899\",\"status\":\"SETTLED\"}");
        return grpc::ok();
    }
    return grpc::error(grpc::StatusCode.Unimplemented, "RPC method not implemented");
}

fn main() {
    print("goose-wing High-Performance gRPC Microservices Demo\n");

    // 1. Initialize gRPC Server Dispatcher
    var dispatcher = grpc::new_server_dispatcher();

    // 2. Register Unary RPC Service Endpoints
    grpc::register_unary(dispatcher, "helloworld.Greeter", "SayHello", 1);
    grpc::register_unary(dispatcher, "payment.PaymentService", "ProcessPayment", 2);

    print("[1] gRPC Service Endpoints Registered:");
    print("    -> helloworld.Greeter/SayHello (ID: 1)");
    print("    -> payment.PaymentService/ProcessPayment (ID: 2)");

    // 3. Simulate Inbound HTTP/2 gRPC Unary Request for Greeter
    var req1 = http::new_request("POST", "/helloworld.Greeter/SayHello") { r =>
        r.set_header("content-type", rfc::GRPC_CONTENT_TYPE_PROTO);
        r.set_header("authorization", "Bearer secret-cluster-token-xyz");
    };

    // Encode payload "Citadel-Worker-42" into 5-byte Length-Prefixed Message (LPM)
    grpc::encode_lpm("Citadel-Worker-42", req1.body, false);

    print("\n[2] Inbound Greeter Call Received:");
    print("    Target: ", req1.url);
    print("    Content-Type: ", http::header(req1, "content-type"));
    print("    LPM Wire Size: ", req1.body.len, " bytes");

    // 4. Dispatch through zero-allocation gRPC dispatcher
    var res1 = http::Response { .. };
    let now_mono_ns: u64 = 1000000000;
    let handled1 = grpc::dispatch_unary(dispatcher, req1, now_mono_ns, res1, service_unary_handler);

    print("\n[3] Dispatch Execution Result:");
    print("    Handled: ", handled1);
    print("    HTTP Status: ", res1.status_code);
    print("    Metadata x-server-version: ", http::header(res1, "x-server-version"));
    print("    Trailer grpc-status: ", http::trailer(res1, rfc::HEADER_GRPC_STATUS));

    // Decode response LPM payload
    var decoded_msg: u8[>..] = [];
    var is_comp = false;
    let _, ok_lpm = grpc::decode_lpm(res1.body[..], 0, decoded_msg, is_comp);
    print("    Decoded Response Payload: ", decoded_msg[..]);

    // 5. Simulate Inbound Call Without Credentials (Unauthenticated error test)
    var req2 = http::new_request("POST", "/helloworld.Greeter/SayHello") { r =>
        r.set_header("content-type", rfc::GRPC_CONTENT_TYPE_PROTO);
    };
    grpc::encode_lpm("Intruder", req2.body, false);

    var res2 = http::Response { .. };
    let handled2 = grpc::dispatch_unary(dispatcher, req2, now_mono_ns, res2, service_unary_handler);

    // In RFC gRPC over HTTP/2, pure errors are returned as 'Trailers-Only'
    // in the initial response HEADERS block to avoid allocating stream data frames.
    let err_status = http::header(res2, rfc::HEADER_GRPC_STATUS);
    let err_msg = http::header(res2, rfc::HEADER_GRPC_MESSAGE);

    print("\n[4] Unauthenticated Call Handling (RFC Trailers-Only):");
    print("    Handled: ", handled2);
    print("    HTTP Status: ", res2.status_code);
    print("    Header grpc-status: ", err_status, " (Code 16: Unauthenticated)");
    print("    Header grpc-message: ", err_msg);
}
