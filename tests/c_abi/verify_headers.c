// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

/**
 * @file verify_headers.c
 * @brief C99/C++11 ABI verification test for Goose-Wing headers.
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <wing/wing.h>

static void dummy_handler(
    const wing_server_request_t *req,
    wing_server_response_t      *res,
    void                        *user_data
) {
    (void)req;
    (void)res;
    (void)user_data;
}

int main(void) {
    printf("[c-abi] checking wing/types.h macros and memory layout...\n");

    // 1. Slice macros and string literals
    wing_slice_t s = WING_STR("HTTP/2");
    assert(s.len == 6);
    assert(s.ptr[0] == 'H' && s.ptr[5] == '2');
    assert(memcmp(s.ptr, "HTTP/2", 6) == 0);

    uint8_t raw[8] = { 0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44 };
    wing_slice_t slice_view = WING_SLICE(raw, 8);
    assert(slice_view.ptr == raw);
    assert(slice_view.len == 8);

    wing_mut_slice_t mut_view = WING_MUT_SLICE(raw, 8);
    assert(mut_view.ptr == raw);
    assert(mut_view.len == 8);

    // 2. Fundamental type sizes on 64-bit platform
    assert(sizeof(wing_slice_t) == 16);
    assert(sizeof(wing_mut_slice_t) == 16);
    assert(sizeof(wing_instant_t) == 8);

    printf("[c-abi] checking HTTP constants and structures...\n");

    // 3. HTTP method enum
    assert(WING_HTTP_METHOD_GET == 1);
    assert(WING_HTTP_METHOD_POST == 3);
    assert(WING_HTTP_METHOD_PATCH == 9);

    // 4. HTTP status codes
    assert(WING_HTTP_STATUS_OK == 200);
    assert(WING_HTTP_STATUS_CREATED == 201);
    assert(WING_HTTP_STATUS_NOT_FOUND == 404);
    assert(WING_HTTP_STATUS_INTERNAL_SERVER_ERROR == 500);

    // 5. Header map struct initialization
    wing_header_entry_t storage[8];
    wing_header_map_t map;
    wing_header_map_init(&map, storage, 8);
    assert(map.capacity == 8);
    assert(map.count == 0);
    assert(map.entries == storage);

    // 5b. Zero-copy cookie span (exact 8 bytes)
    assert(sizeof(wing_cookie_span_t) == 8);
    wing_cookie_span_t span = { 0, 4, 5, 10 };
    assert(span.name_pos == 0 && span.name_len == 4);
    assert(span.val_pos == 5 && span.val_len == 10);

    printf("[c-abi] checking TLS record and alert constants...\n");

    // 6. TLS definitions
    assert(WING_TLS_CONTENT_APPLICATION_DATA == 23);
    assert(WING_TLS_ALERT_LEVEL_FATAL == 2);
    assert(WING_TLS_ALERT_HANDSHAKE_FAILURE == 40);
    assert(WING_TLS_AES_128_GCM_SHA256 == 0x1301);
    assert(WING_TLS_CHACHA20_POLY1305_SHA256 == 0x1303);

    // 6b. X.509 certificate summary layout
    wing_x509_cert_summary_t cert_summary;
    memset(&cert_summary, 0, sizeof(cert_summary));
    cert_summary.not_before_unix = 1700000000;
    cert_summary.is_ca = true;
    assert(cert_summary.not_before_unix == 1700000000);
    assert(cert_summary.is_ca == true);

    printf("[c-abi] checking Net and Server interfaces...\n");

    // 7. Net definitions
    assert(WING_IP_V4 == 4 && WING_IP_V6 == 6);
    assert(WING_PROXY_VERSION_1 == 1);
    assert(WING_PROXY_VERSION_2 == 2);
    assert((WING_POLL_READ | WING_POLL_WRITE) == 0x03);

    // 8. Server structures and route handler function pointer
    wing_route_handler_fn fn = dummy_handler;
    assert(fn != NULL);

    wing_server_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host = "127.0.0.1";
    cfg.port = 8080;
    cfg.backlog = 128;
    cfg.num_workers = 4;
    assert(cfg.port == 8080);

    wing_problem_details_t prob;
    memset(&prob, 0, sizeof(prob));
    prob.status = 404;
    prob.title = WING_STR("Not Found");
    assert(prob.status == 404);
    assert(prob.title.len == 9);

    printf("[c-abi] header definitions and ABI constraints verified.\n");
    return 0;
}
