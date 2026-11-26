// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// uWebSockets Official C++ Benchmark Server
// Provides identical HTTP/1.1, dynamic API routing, WebSocket, and optional TLS 1.3 endpoints for comparison.
#include "App.h"
#include <iostream>
#include <cstdlib>
#include <string>
#include <string_view>
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

static std::string build_user_json_body(std::string_view uid) {
    static const std::string kPrefix =
        "{\"id\":\"";
    static const std::string kSuffix =
        "\",\"username\":\"edge_user\",\"tier\":\"enterprise\",\"region\":\"eu-central-1\","
        "\"waf_policy\":{\"mode\":\"enforce\",\"sqli_guard\":true,\"xss_guard\":true,\"rate_limit\":10000,"
        "\"geo_allow\":[\"DE\",\"FR\",\"NL\",\"US\",\"GB\",\"JP\",\"SG\",\"CA\"],\"bot_score_min\":30},"
        "\"permissions\":[\"edge:read\",\"edge:write\",\"routes:manage\",\"tls:terminate\","
        "\"waf:inspect\",\"metrics:read\",\"audit:stream\",\"cache:purge\",\"origins:balance\"],"
        "\"limits\":{\"max_rps\":250000,\"max_conns\":100000,\"max_body_kb\":10240,\"burst_window_ms\":1000},"
        "\"origins\":[{\"host\":\"10.0.1.10\",\"port\":8443,\"weight\":100,\"healthy\":true,\"rtt_us\":142},"
        "{\"host\":\"10.0.1.11\",\"port\":8443,\"weight\":100,\"healthy\":true,\"rtt_us\":158},"
        "{\"host\":\"10.0.2.10\",\"port\":8443,\"weight\":80,\"healthy\":true,\"rtt_us\":194},"
        "{\"host\":\"10.0.2.11\",\"port\":8443,\"weight\":80,\"healthy\":true,\"rtt_us\":201}],"
        "\"feature_flags\":{\"http2\":true,\"http3\":true,\"ktls\":true,\"io_uring\":true,"
        "\"early_data\":false,\"strict_host_validation\":true,\"zero_copy_static\":true,"
        "\"packed_radix_router\":true,\"swar_header_scanner\":true,\"soa_timer_wheel\":true},"
        "\"tags\":[\"edge\",\"waf\",\"api-gateway\",\"zero-alloc\",\"tls13\",\"h2\",\"keepalive\","
        "\"low-latency\",\"multi-worker\",\"reuseport\",\"production\",\"v2\",\"canary\",\"verified\"],"
        "\"audit_trail\":["
        "{\"seq\":1,\"action\":\"session.verified\",\"actor\":\"gateway-01\",\"status\":\"ok\",\"cost_us\":4},"
        "{\"seq\":2,\"action\":\"waf.prefilter\",\"actor\":\"ruleset-2026\",\"status\":\"pass\",\"cost_us\":2},"
        "{\"seq\":3,\"action\":\"route.resolved\",\"actor\":\"radix-tree\",\"status\":\"hit\",\"cost_us\":1},"
        "{\"seq\":4,\"action\":\"origin.selected\",\"actor\":\"maglev-ring\",\"status\":\"ready\",\"cost_us\":1},"
        "{\"seq\":5,\"action\":\"cache.checked\",\"actor\":\"l1-slab\",\"status\":\"bypass\",\"cost_us\":1},"
        "{\"seq\":6,\"action\":\"response.sealed\",\"actor\":\"worker-loop\",\"status\":\"sent\",\"cost_us\":2}"
        "],\"telemetry\":{\"node\":\"eu-edge-04\",\"build\":\"2026.11\",\"padding\":"
        "\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"}}";
    std::string out;
    out.reserve(kPrefix.size() + uid.size() + kSuffix.size());
    out.append(kPrefix);
    out.append(uid);
    out.append(kSuffix);
    return out;
}

template <typename AppT>
static void register_routes(AppT &app) {
    app.get("/plaintext", [](auto *res, auto *req) {
        (void)req;
        res->cork([res]() {
            res->writeHeader("Server", "uWebSockets")
               ->writeHeader("Content-Type", "text/plain")
               ->end("Hello, World!");
        });
    })
    .get("/json", [](auto *res, auto *req) {
        (void)req;
        res->cork([res]() {
            res->writeHeader("Server", "uWebSockets")
               ->writeHeader("Content-Type", "application/json")
               ->end("{\"message\":\"Hello, World!\"}");
        });
    })
    .get("/metrics", [](auto *res, auto *req) {
        (void)req;
        res->cork([res]() {
            res->writeHeader("Server", "uWebSockets")
               ->writeHeader("Content-Type", "application/json")
               ->end("{\"engine\":\"uWebSockets\",\"allocator\":\"glibc malloc/new\",\"model\":\"heap_dynamic\"}");
        });
    })
    .get("/health", [](auto *res, auto *req) {
        (void)req;
        res->cork([res]() {
            res->writeHeader("Server", "uWebSockets")
               ->writeHeader("Content-Type", "application/json")
               ->end("{\"status\":\"ok\"}");
        });
    })
    .get("/v1/status", [](auto *res, auto *req) {
        (void)req;
        res->cork([res]() {
            res->writeHeader("Server", "uWebSockets")
               ->writeHeader("Content-Type", "application/json")
               ->end("{\"version\":\"1.0\",\"healthy\":true}");
        });
    })
    .get("/api/v1/auth/session", [](auto *res, auto *req) {
        (void)req;
        res->cork([res]() {
            res->writeHeader("Server", "uWebSockets")
               ->writeHeader("Content-Type", "application/json")
               ->end("{\"authenticated\":false}");
        });
    })
    .get("/api/v1/audit/events", [](auto *res, auto *req) {
        (void)req;
        res->cork([res]() {
            res->writeHeader("Server", "uWebSockets")
               ->writeHeader("Content-Type", "application/json")
               ->end("{\"events\":[]}");
        });
    })
    .get("/api/v1/orgs/:org", [](auto *res, auto *req) {
        std::string org(req->getParameter("org"));
        res->cork([res, org]() {
            res->writeHeader("Server", "uWebSockets")
               ->writeHeader("Content-Type", "application/json")
               ->end("{\"org\":\"" + org + "\"}");
        });
    })
    .get("/api/v1/orders/:id", [](auto *res, auto *req) {
        std::string oid(req->getParameter("id"));
        res->cork([res, oid]() {
            res->writeHeader("Server", "uWebSockets")
               ->writeHeader("Content-Type", "application/json")
               ->end("{\"order\":\"" + oid + "\"}");
        });
    })
    .get("/api/v1/products/:cat/:id", [](auto *res, auto *req) {
        std::string pid(req->getParameter("id"));
        res->cork([res, pid]() {
            res->writeHeader("Server", "uWebSockets")
               ->writeHeader("Content-Type", "application/json")
               ->end("{\"product\":\"" + pid + "\"}");
        });
    })
    .get("/api/v1/users/:id", [](auto *res, auto *req) {
        std::string_view uid = req->getParameter("id");
        std::string body = build_user_json_body(uid);
        res->cork([res, body = std::move(body)]() {
            res->writeHeader("Server", "uWebSockets")
               ->writeHeader("Content-Type", "application/json")
               ->writeHeader("Cache-Control", "no-store")
               ->writeHeader("X-Route-Match", "users-by-id")
               ->end(body);
        });
    })
    .template ws<PerSocketData>("/ws", {
        .compression = uWS::DISABLED,
        .maxPayloadLength = 64 * 1024,
        .idleTimeout = 120,
        .maxBackpressure = 16 * 1024 * 1024,
        .closeOnBackpressureLimit = false,
        .resetIdleTimeoutOnSend = false,
        .sendPingsAutomatically = true,
        .upgrade = nullptr,
        .open = [](auto *ws) { (void)ws; },
        .message = [](auto *ws, std::string_view message, uWS::OpCode opCode) {
            ws->cork([ws, message, opCode]() {
                ws->send(message, opCode);
            });
        },
        .drain = [](auto *ws) { (void)ws; },
        .ping = [](auto *ws, std::string_view) { (void)ws; },
        .pong = [](auto *ws, std::string_view) { (void)ws; },
        .close = [](auto *ws, int, std::string_view) { (void)ws; }
    });
}

void run_uws_worker(int port, int cpu_id = 0, bool use_tls = false) {
    set_cpu_affinity(cpu_id);
#ifdef WITH_OPENSSL
    if (use_tls) {
        uWS::SSLApp app({
            .key_file_name = "/app/bench_key.pem",
            .cert_file_name = "/app/bench_cert.pem",
        });
        register_routes(app);
        app.listen("0.0.0.0", port, [port](auto *listen_socket) {
            if (!listen_socket) {
                std::cerr << "FATAL: uWebSockets SSL worker failed to bind on 0.0.0.0:" << port << std::endl;
            }
        }).run();
        return;
    }
#else
    (void)use_tls;
#endif
    uWS::App app;
    register_routes(app);
    app.listen("0.0.0.0", port, [port](auto *listen_socket) {
        if (!listen_socket) {
            std::cerr << "FATAL: uWebSockets worker failed to bind on 0.0.0.0:" << port << std::endl;
        }
    }).run();
}

int main(int argc, char **argv) {
    int port = 3002;
    if (const char *env_p = std::getenv("UWS_PORT")) {
        port = std::atoi(env_p);
    }
    if (argc > 1) {
        port = std::atoi(argv[1]);
    }

    bool use_tls = (port == 3444);
    if (const char *env_tls = std::getenv("UWS_TLS")) {
        if (std::atoi(env_tls) != 0) use_tls = true;
    }

    int workers = 1;
    if (const char *env_w = std::getenv("UWS_WORKERS")) {
        workers = std::atoi(env_w);
    } else if (const char *env_w2 = std::getenv("WING_WORKERS")) {
        workers = std::atoi(env_w2);
    }
    if (workers < 1) workers = 1;

    if (workers <= 1) {
        std::cout << "uWebSockets server listening on 0.0.0.0:" << port
                  << (use_tls ? " [TLS 1.3 / uSockets EventLoop]" : " [Heap / Single-Threaded uSockets EventLoop]")
                  << std::endl;
        run_uws_worker(port, 0, use_tls);
    } else {
        std::cout << "uWebSockets server listening on 0.0.0.0:" << port
                  << " [Share-Nothing SO_REUSEPORT Workers: " << workers
                  << (use_tls ? ", TLS 1.3" : "") << "]" << std::endl;
        std::vector<std::thread> threads;
        for (int i = 0; i < workers; i++) {
            threads.emplace_back(run_uws_worker, port, i, use_tls);
        }
        for (auto &t : threads) {
            t.join();
        }
    }

    return 0;
}
