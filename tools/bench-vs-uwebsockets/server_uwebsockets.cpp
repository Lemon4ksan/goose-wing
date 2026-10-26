// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// uWebSockets Official C++ Benchmark Server
// Provides identical HTTP/1.1 and WebSocket endpoints for head-to-head comparison with goose-wing.
#include "App.h"
#include <iostream>
#include <cstdlib>
#include <string>
#include <vector>
#include <thread>

#if defined(__linux__)
#include <pthread.h>
#include <sched.h>
#include <unistd.h>
static void set_cpu_affinity(int cpu_id) {
    if (cpu_id < 0) return;
    long total_cpus = sysconf(_SC_NPROCESSORS_ONLN);
    int target_cpu = cpu_id;
    if (total_cpus > 1) {
        int phys = (int)(total_cpus / 2);
        target_cpu = (cpu_id < phys) ? (cpu_id * 2) : ((cpu_id - phys) * 2 + 1);
    }
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(target_cpu % (int)total_cpus, &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
}
#elif defined(_WIN32)
#include <windows.h>
static void set_cpu_affinity(int cpu_id) {
    if (cpu_id < 0 || cpu_id >= 64) return;
    DWORD_PTR mask = ((DWORD_PTR)1) << cpu_id;
    SetThreadAffinityMask(GetCurrentThread(), mask);
}
#else
static void set_cpu_affinity(int) {}
#endif

struct PerSocketData {
    /* Per-socket state */
};

void run_uws_worker(int port, int cpu_id = 0) {
    set_cpu_affinity(cpu_id);
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
            .open = [](auto *ws) {},
            .message = [](auto *ws, std::string_view message, uWS::OpCode opCode) {
                // Echo payload back with explicit corking
                ws->cork([ws, message, opCode]() {
                    ws->send(message, opCode);
                });
            },
            .drain = [](auto *ws) {},
            .ping = [](auto *ws, std::string_view) {},
            .pong = [](auto *ws, std::string_view) {},
            .close = [](auto *ws, int code, std::string_view message) {}
        })
        .listen("0.0.0.0", port, [port](auto *listen_socket) {
            if (!listen_socket) {
                std::cerr << "FATAL: uWebSockets worker failed to bind on 0.0.0.0:" << port << std::endl;
            }
        })
        .run();
}

int main(int argc, char **argv) {
    int port = 3002;
    if (const char *env_p = std::getenv("UWS_PORT")) {
        port = std::atoi(env_p);
    }
    if (argc > 1) {
        port = std::atoi(argv[1]);
    }

    int workers = 1;
    if (const char *env_w = std::getenv("UWS_WORKERS")) {
        workers = std::atoi(env_w);
    } else if (const char *env_w2 = std::getenv("WING_WORKERS")) {
        workers = std::atoi(env_w2);
    }
    if (workers < 1) workers = 1;

    if (workers <= 1) {
        std::cout << "uWebSockets server listening on 0.0.0.0:" << port << " [Heap / Single-Threaded uSockets EventLoop]" << std::endl;
        run_uws_worker(port, 0);
    } else {
        std::cout << "uWebSockets server listening on 0.0.0.0:" << port << " [Share-Nothing SO_REUSEPORT Workers: " << workers << "]" << std::endl;
        std::vector<std::thread> threads;
        for (int i = 0; i < workers; i++) {
            threads.emplace_back(run_uws_worker, port, i);
        }
        for (auto &t : threads) {
            t.join();
        }
    }

    return 0;
}
