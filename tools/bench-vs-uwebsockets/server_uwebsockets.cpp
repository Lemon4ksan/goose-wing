// uWebSockets Official C++ Benchmark Server
// Provides identical HTTP/1.1 and WebSocket endpoints for head-to-head comparison with goose-wing.
#include "App.h"
#include <iostream>
#include <cstdlib>
#include <string>

struct PerSocketData {
    /* Per-socket state */
};

int main(int argc, char **argv) {
    int port = 3002;
    if (const char *env_p = std::getenv("UWS_PORT")) {
        port = std::atoi(env_p);
    }
    if (argc > 1) {
        port = std::atoi(argv[1]);
    }

    uWS::App()
        .get("/plaintext", [](auto *res, auto *req) {
            res->cork([res]() {
                res->writeHeader("Server", "uWebSockets")
                   ->writeHeader("Content-Type", "text/plain")
                   ->end("Hello, World!");
            });
        })
        .get("/json", [](auto *res, auto *req) {
            res->cork([res]() {
                res->writeHeader("Server", "uWebSockets")
                   ->writeHeader("Content-Type", "application/json")
                   ->end("{\"message\":\"Hello, World!\"}");
            });
        })
        .get("/metrics", [](auto *res, auto *req) {
            res->cork([res]() {
                res->writeHeader("Server", "uWebSockets")
                   ->writeHeader("Content-Type", "application/json")
                   ->end("{\"engine\":\"uWebSockets\",\"allocator\":\"glibc malloc/new\",\"model\":\"heap_dynamic\"}");
            });
        })
        .ws<PerSocketData>("/ws", {
            /* Settings */
            .compression = uWS::DISABLED,
            .maxPayloadLength = 64 * 1024,
            .idleTimeout = 120,
            .maxBackpressure = 16 * 1024 * 1024,
            .closeOnBackpressureLimit = false,
            .resetIdleTimeoutOnSend = false,
            .sendPingsAutomatically = true,
            /* Handlers */
            .upgrade = nullptr,
            .open = [](auto *ws) {
                /* Connection opened */
            },
            .message = [](auto *ws, std::string_view message, uWS::OpCode opCode) {
                // Echo payload back with explicit corking
                ws->cork([ws, message, opCode]() {
                    ws->send(message, opCode);
                });
            },
            .drain = [](auto *ws) {
                /* Backpressure drained */
            },
            .ping = [](auto *ws, std::string_view) {},
            .pong = [](auto *ws, std::string_view) {},
            .close = [](auto *ws, int code, std::string_view message) {}
        })
        .listen("0.0.0.0", port, [port](auto *listen_socket) {
            if (listen_socket) {
                std::cout << "uWebSockets server listening on 0.0.0.0:" << port << " [Heap / uSockets EventLoop]" << std::endl;
            } else {
                std::cerr << "FATAL: uWebSockets failed to bind on 0.0.0.0:" << port << std::endl;
            }
        })
        .run();

    return 0;
}
