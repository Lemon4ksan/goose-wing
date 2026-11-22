// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Dynamically-loaded sans-IO TLS backend C shim for goose-wing.
// Loads OpenSSL/BoringSSL (cross-platform) and Windows Schannel (secur32.dll)
// at runtime with zero link-time OpenSSL or Secur32 library dependencies.
// Optional overrides:
//   - Runtime path: WING_OPENSSL_LIB / WING_CRYPTO_LIB environment variables.
//   - Direct link:  compile with -DWING_TLS_LINK_OPENSSL and link -lssl -lcrypto.

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef WING_TLS_LINK_OPENSSL
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#endif

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef SECURITY_WIN32
#define SECURITY_WIN32
#endif
#include <windows.h>
#include <security.h>
#include <schannel.h>
#include <wincrypt.h>
#elif !defined(__wasm__)
#include <dlfcn.h>
#include <pthread.h>
#endif

#define WING_TLS_KIND_PURE 0
#define WING_TLS_KIND_OPENSSL 1
#define WING_TLS_KIND_SCHANNEL 2
#define WING_TLS_KIND_SECURE_TRANSPORT 3
#define WING_TLS_KIND_AUTO 4

#define WING_TLS_MIN_TLS13 0
#define WING_TLS_MIN_TLS12 1

#define WING_TLS_FLAG_INSECURE_SKIP_VERIFY 1
#define WING_TLS_FLAG_NO_SYSTEM_ROOTS 2
#define WING_TLS_FLAG_NO_SESSION_TICKETS 4

#define WING_TLS_ST_OK 0
#define WING_TLS_ST_WANT_READ 1
#define WING_TLS_ST_WANT_WRITE 2
#define WING_TLS_ST_CLOSED 3
#define WING_TLS_ST_UNAVAILABLE 4
#define WING_TLS_ST_HS_ERR 5
#define WING_TLS_ST_VERIFY_ERR 6
#define WING_TLS_ST_ERR 7

#define WING_TLS_MAX_HANDLES 4096
#define WING_TLS_MAX_BUF_CAP (4 * 1024 * 1024)

#pragma pack(push, 1)
typedef struct {
    const uint8_t *data;
    int64_t len;
} wing_tls_ro;

typedef struct {
    uint8_t *data;
    int64_t len;
} wing_tls_rw;
#pragma pack(pop)

static void wing_tls_zeroize(volatile void *ptr, size_t len) {
    if (ptr == NULL || len == 0) return;
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    for (size_t i = 0; i < len; i++)
        p[i] = 0;
}

static int clamp_i32(int64_t n) {
    if (n <= 0) return 0;
    return n > 0x7FFFFFFF ? 0x7FFFFFFF : (int)n;
}

static int load_fn_sym(void *dst, const void *src) {
    if (src == NULL) return 0;
    memcpy(dst, &src, sizeof(void *));
    return 1;
}

#if defined(_WIN32) || defined(__APPLE__)
typedef struct {
    uint8_t *data;
    size_t len;
    size_t cap;
} tls_buf_t;

static int tls_buf_append(tls_buf_t *b, const uint8_t *src, size_t n) {
    if (n == 0) return 1;
    if (src == NULL || n > WING_TLS_MAX_BUF_CAP || b->len > WING_TLS_MAX_BUF_CAP - n) return 0;
    size_t need = b->len + n;
    if (need > b->cap) {
        size_t ncap = b->cap ? b->cap : 4096;
        while (ncap < need)
            ncap *= 2;
        if (ncap > WING_TLS_MAX_BUF_CAP) ncap = need;
        uint8_t *nb = (uint8_t *)realloc(b->data, ncap);
        if (nb == NULL) return 0;
        b->data = nb;
        b->cap = ncap;
    }
    memcpy(b->data + b->len, src, n);
    b->len += n;
    return 1;
}

static void tls_buf_consume(tls_buf_t *b, size_t n) {
    if (n == 0 || b->len == 0) return;
    if (n >= b->len) {
        wing_tls_zeroize(b->data, b->len);
        b->len = 0;
        return;
    }
    size_t rem = b->len - n;
    memmove(b->data, b->data + n, rem);
    wing_tls_zeroize(b->data + rem, n);
    b->len = rem;
}

static void tls_buf_free(tls_buf_t *b) {
    if (b->data != NULL) {
        wing_tls_zeroize(b->data, b->cap);
        free(b->data);
    }
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
}
#endif

/* ---- OpenSSL / BoringSSL Driver (Dynamic or Direct-Link) --------------- */

#define OSSL_SSL_ERROR_NONE 0
#define OSSL_SSL_ERROR_WANT_READ 2
#define OSSL_SSL_ERROR_WANT_WRITE 3
#define OSSL_SSL_ERROR_ZERO_RETURN 6
#define OSSL_SSL_VERIFY_NONE 0
#define OSSL_SSL_VERIFY_PEER 1
#define OSSL_SSL_VERIFY_FAIL_IF_NO_PEER_CERT 2
#define OSSL_CTRL_SET_SNI 55
#define OSSL_CTRL_SET_MIN_PROTO_VERSION 123
#define OSSL_TLS1_2_VERSION 0x0303
#define OSSL_TLS1_3_VERSION 0x0304
#define OSSL_FILETYPE_PEM 1
#define OSSL_BIO_CTRL_PENDING 10
#define OSSL_TLSEXT_ERR_OK 0
#define OSSL_TLSEXT_ERR_NOACK 3
#define OSSL_SSL_OP_NO_TICKET 0x00004000ULL

typedef int (*ossl_alpn_cb_t)(void *ssl, const unsigned char **out, unsigned char *outlen, const unsigned char *in,
                              unsigned int inlen, void *arg);
typedef void (*ossl_keylog_cb_t)(const void *ssl, const char *line);

typedef struct {
    int probed;
    int available;
    const void *(*TLS_client_method)(void);
    const void *(*TLS_server_method)(void);
    void *(*SSL_CTX_new)(const void *);
    void (*SSL_CTX_free)(void *);
    long (*SSL_CTX_ctrl)(void *, int, long, void *);
    uint64_t (*SSL_CTX_set_options)(void *, uint64_t);
    int (*SSL_CTX_set_num_tickets)(void *, size_t);
    void (*SSL_CTX_set_keylog_callback)(void *, ossl_keylog_cb_t);
    void *(*SSL_CTX_get_cert_store)(const void *);
    int (*SSL_CTX_set_default_verify_paths)(void *);
    int (*SSL_CTX_load_verify_locations)(void *, const char *, const char *);
    void (*SSL_CTX_set_verify)(void *, int, void *);
    int (*SSL_CTX_use_certificate_chain_file)(void *, const char *);
    int (*SSL_CTX_use_PrivateKey_file)(void *, const char *, int);
    int (*SSL_CTX_check_private_key)(const void *);
    void (*SSL_CTX_set_alpn_select_cb)(void *, ossl_alpn_cb_t, void *);
    void *(*SSL_new)(void *);
    void (*SSL_free)(void *);
    int (*SSL_set_ex_data)(void *, int, void *);
    void *(*SSL_get_ex_data)(const void *, int);
    void (*SSL_set_connect_state)(void *);
    void (*SSL_set_accept_state)(void *);
    void (*SSL_set_bio)(void *, void *, void *);
    int (*SSL_do_handshake)(void *);
    int (*SSL_read)(void *, void *, int);
    int (*SSL_write)(void *, const void *, int);
    int (*SSL_shutdown)(void *);
    int (*SSL_get_error)(const void *, int);
    long (*SSL_ctrl)(void *, int, long, void *);
    int (*SSL_set1_host)(void *, const char *);
    void *(*SSL_get0_param)(void *);
    int (*X509_VERIFY_PARAM_set1_ip_asc)(void *, const char *);
    void *(*d2i_X509)(void **, const unsigned char **, long);
    int (*X509_STORE_add_cert)(void *, void *);
    void (*X509_free)(void *);
    void (*ERR_clear_error)(void);
    int (*SSL_set_alpn_protos)(void *, const unsigned char *, unsigned int);
    void (*SSL_get0_alpn_selected)(const void *, const unsigned char **, unsigned int *);
    long (*SSL_get_verify_result)(const void *);
    const void *(*BIO_s_mem)(void);
    void *(*BIO_new)(const void *);
    int (*BIO_free)(void *);
    int (*BIO_write)(void *, const void *, int);
    int (*BIO_read)(void *, void *, int);
    long (*BIO_ctrl)(void *, int, long, void *);
} ossl_api_t;

static ossl_api_t g_ossl;

#if !defined(__wasm__)
static void *dyn_open_one(const char *name) {
    if (name == NULL || name[0] == '\0') return NULL;
#ifdef _WIN32
    return (void *)LoadLibraryA(name);
#else
    return dlopen(name, RTLD_NOW | RTLD_LOCAL);
#endif
}

static void *dyn_open_any(const char *const *names) {
    for (size_t i = 0; names[i] != NULL; i++) {
        void *h = dyn_open_one(names[i]);
        if (h != NULL) return h;
    }
    return NULL;
}

static void *dyn_sym(void *lib, const char *name) {
    if (lib == NULL) return NULL;
#ifdef _WIN32
    FARPROC p = GetProcAddress((HMODULE)lib, name);
    return (void *)(uintptr_t)p;
#else
    return dlsym(lib, name);
#endif
}

#ifdef WING_TLS_LINK_OPENSSL
static const void *lk_TLS_client_method(void) { return (const void *)TLS_client_method(); }
static const void *lk_TLS_server_method(void) { return (const void *)TLS_server_method(); }
static void *lk_SSL_CTX_new(const void *m) { return (void *)SSL_CTX_new((const SSL_METHOD *)m); }
static void lk_SSL_CTX_free(void *c) { SSL_CTX_free((SSL_CTX *)c); }
static long lk_SSL_CTX_ctrl(void *c, int cmd, long larg, void *parg) {
    return SSL_CTX_ctrl((SSL_CTX *)c, cmd, larg, parg);
}
static uint64_t lk_SSL_CTX_set_options(void *c, uint64_t op) { return (uint64_t)SSL_CTX_set_options((SSL_CTX *)c, op); }
static int lk_SSL_CTX_set_num_tickets(void *c, size_t n) {
#if defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x10101000L && !defined(OPENSSL_IS_BORINGSSL)
    return SSL_CTX_set_num_tickets((SSL_CTX *)c, n);
#else
    (void)c;
    (void)n;
    return 1;
#endif
}
static void ossl_keylog_cb(const void *ssl, const char *line);
static void lk_keylog_cb_adapter(const SSL *s, const char *line) { ossl_keylog_cb((const void *)s, line); }
static void lk_SSL_CTX_set_keylog_callback(void *c, ossl_keylog_cb_t cb) {
    SSL_CTX_set_keylog_callback((SSL_CTX *)c, cb != NULL ? lk_keylog_cb_adapter : NULL);
}
static void *lk_SSL_CTX_get_cert_store(const void *c) { return (void *)SSL_CTX_get_cert_store((const SSL_CTX *)c); }
static int lk_SSL_CTX_set_default_verify_paths(void *c) { return SSL_CTX_set_default_verify_paths((SSL_CTX *)c); }
static int lk_SSL_CTX_load_verify_locations(void *c, const char *f, const char *p) {
    return SSL_CTX_load_verify_locations((SSL_CTX *)c, f, p);
}
static void lk_SSL_CTX_set_verify(void *c, int mode, void *cb) {
    (void)cb;
    SSL_CTX_set_verify((SSL_CTX *)c, mode, NULL);
}
static int lk_SSL_CTX_use_cert_chain(void *c, const char *f) {
    return SSL_CTX_use_certificate_chain_file((SSL_CTX *)c, f);
}
static int lk_SSL_CTX_use_privkey(void *c, const char *f, int t) {
    return SSL_CTX_use_PrivateKey_file((SSL_CTX *)c, f, t);
}
static int lk_SSL_CTX_check_privkey(const void *c) { return SSL_CTX_check_private_key((const SSL_CTX *)c); }
static int ossl_alpn_select_cb(void *ssl, const unsigned char **out, unsigned char *outlen, const unsigned char *in,
                               unsigned int inlen, void *arg);

static int lk_alpn_cb_adapter(SSL *s, const unsigned char **out, unsigned char *outlen, const unsigned char *in,
                              unsigned int inlen, void *arg) {
    return ossl_alpn_select_cb((void *)s, out, outlen, in, inlen, arg);
}
static void lk_SSL_CTX_set_alpn_select_cb(void *c, ossl_alpn_cb_t cb, void *arg) {
    (void)cb;
    SSL_CTX_set_alpn_select_cb((SSL_CTX *)c, lk_alpn_cb_adapter, arg);
}
static void *lk_SSL_new(void *c) { return (void *)SSL_new((SSL_CTX *)c); }
static void lk_SSL_free(void *s) { SSL_free((SSL *)s); }
static int lk_SSL_set_ex_data(void *s, int idx, void *arg) { return SSL_set_ex_data((SSL *)s, idx, arg); }
static void *lk_SSL_get_ex_data(const void *s, int idx) { return SSL_get_ex_data((const SSL *)s, idx); }
static void lk_SSL_set_connect_state(void *s) { SSL_set_connect_state((SSL *)s); }
static void lk_SSL_set_accept_state(void *s) { SSL_set_accept_state((SSL *)s); }
static void lk_SSL_set_bio(void *s, void *r, void *w) { SSL_set_bio((SSL *)s, (BIO *)r, (BIO *)w); }
static int lk_SSL_do_handshake(void *s) { return SSL_do_handshake((SSL *)s); }
static int lk_SSL_read(void *s, void *b, int n) { return SSL_read((SSL *)s, b, n); }
static int lk_SSL_write(void *s, const void *b, int n) { return SSL_write((SSL *)s, b, n); }
static int lk_SSL_shutdown(void *s) { return SSL_shutdown((SSL *)s); }
static int lk_SSL_get_error(const void *s, int r) { return SSL_get_error((const SSL *)s, r); }
static long lk_SSL_ctrl(void *s, int cmd, long larg, void *parg) { return SSL_ctrl((SSL *)s, cmd, larg, parg); }
static int lk_SSL_set1_host(void *s, const char *h) { return SSL_set1_host((SSL *)s, h); }
static void *lk_SSL_get0_param(void *s) { return (void *)SSL_get0_param((SSL *)s); }
static int lk_X509_VERIFY_PARAM_set1_ip_asc(void *p, const char *ip) {
    return X509_VERIFY_PARAM_set1_ip_asc((X509_VERIFY_PARAM *)p, ip);
}
static void *lk_d2i_X509(void **px, const unsigned char **in, long len) {
    (void)px;
    return (void *)d2i_X509(NULL, in, len);
}
static int lk_X509_STORE_add_cert(void *s, void *x) { return X509_STORE_add_cert((X509_STORE *)s, (X509 *)x); }
static void lk_X509_free(void *x) { X509_free((X509 *)x); }
static void lk_ERR_clear_error(void) { ERR_clear_error(); }
static int lk_SSL_set_alpn_protos(void *s, const unsigned char *p, unsigned int n) {
    return SSL_set_alpn_protos((SSL *)s, p, n);
}
static void lk_SSL_get0_alpn_selected(const void *s, const unsigned char **p, unsigned int *n) {
    SSL_get0_alpn_selected((const SSL *)s, p, n);
}
static long lk_SSL_get_verify_result(const void *s) { return SSL_get_verify_result((const SSL *)s); }
static const void *lk_BIO_s_mem(void) { return (const void *)BIO_s_mem(); }
static void *lk_BIO_new(const void *m) { return (void *)BIO_new((const BIO_METHOD *)m); }
static int lk_BIO_free(void *b) { return BIO_free((BIO *)b); }
static int lk_BIO_write(void *b, const void *d, int n) { return BIO_write((BIO *)b, d, n); }
static int lk_BIO_read(void *b, void *d, int n) { return BIO_read((BIO *)b, d, n); }
static long lk_BIO_ctrl(void *b, int cmd, long larg, void *parg) { return BIO_ctrl((BIO *)b, cmd, larg, parg); }

static void ossl_probe_impl(void) {
    g_ossl.probed = 1;
    g_ossl.TLS_client_method = lk_TLS_client_method;
    g_ossl.TLS_server_method = lk_TLS_server_method;
    g_ossl.SSL_CTX_new = lk_SSL_CTX_new;
    g_ossl.SSL_CTX_free = lk_SSL_CTX_free;
    g_ossl.SSL_CTX_ctrl = lk_SSL_CTX_ctrl;
    g_ossl.SSL_CTX_set_options = lk_SSL_CTX_set_options;
    g_ossl.SSL_CTX_set_num_tickets = lk_SSL_CTX_set_num_tickets;
    g_ossl.SSL_CTX_set_keylog_callback = lk_SSL_CTX_set_keylog_callback;
    g_ossl.SSL_CTX_get_cert_store = lk_SSL_CTX_get_cert_store;
    g_ossl.SSL_CTX_set_default_verify_paths = lk_SSL_CTX_set_default_verify_paths;
    g_ossl.SSL_CTX_load_verify_locations = lk_SSL_CTX_load_verify_locations;
    g_ossl.SSL_CTX_set_verify = lk_SSL_CTX_set_verify;
    g_ossl.SSL_CTX_use_certificate_chain_file = lk_SSL_CTX_use_cert_chain;
    g_ossl.SSL_CTX_use_PrivateKey_file = lk_SSL_CTX_use_privkey;
    g_ossl.SSL_CTX_check_private_key = lk_SSL_CTX_check_privkey;
    g_ossl.SSL_CTX_set_alpn_select_cb = lk_SSL_CTX_set_alpn_select_cb;
    g_ossl.SSL_new = lk_SSL_new;
    g_ossl.SSL_free = lk_SSL_free;
    g_ossl.SSL_set_ex_data = lk_SSL_set_ex_data;
    g_ossl.SSL_get_ex_data = lk_SSL_get_ex_data;
    g_ossl.SSL_set_connect_state = lk_SSL_set_connect_state;
    g_ossl.SSL_set_accept_state = lk_SSL_set_accept_state;
    g_ossl.SSL_set_bio = lk_SSL_set_bio;
    g_ossl.SSL_do_handshake = lk_SSL_do_handshake;
    g_ossl.SSL_read = lk_SSL_read;
    g_ossl.SSL_write = lk_SSL_write;
    g_ossl.SSL_shutdown = lk_SSL_shutdown;
    g_ossl.SSL_get_error = lk_SSL_get_error;
    g_ossl.SSL_ctrl = lk_SSL_ctrl;
    g_ossl.SSL_set1_host = lk_SSL_set1_host;
    g_ossl.SSL_get0_param = lk_SSL_get0_param;
    g_ossl.X509_VERIFY_PARAM_set1_ip_asc = lk_X509_VERIFY_PARAM_set1_ip_asc;
    g_ossl.d2i_X509 = lk_d2i_X509;
    g_ossl.X509_STORE_add_cert = lk_X509_STORE_add_cert;
    g_ossl.X509_free = lk_X509_free;
    g_ossl.ERR_clear_error = lk_ERR_clear_error;
    g_ossl.SSL_set_alpn_protos = lk_SSL_set_alpn_protos;
    g_ossl.SSL_get0_alpn_selected = lk_SSL_get0_alpn_selected;
    g_ossl.SSL_get_verify_result = lk_SSL_get_verify_result;
    g_ossl.BIO_s_mem = lk_BIO_s_mem;
    g_ossl.BIO_new = lk_BIO_new;
    g_ossl.BIO_free = lk_BIO_free;
    g_ossl.BIO_write = lk_BIO_write;
    g_ossl.BIO_read = lk_BIO_read;
    g_ossl.BIO_ctrl = lk_BIO_ctrl;
    g_ossl.available = 1;
}
#else
static void ossl_probe_impl(void) {
    g_ossl.probed = 1;
#ifdef _WIN32
    static const char *const ssl_names[] = {"libssl-3-x64.dll", "libssl-3.dll", "libssl-1_1-x64.dll", "libssl.dll",
                                            NULL};
    static const char *const cry_names[] = {"libcrypto-3-x64.dll", "libcrypto-3.dll", "libcrypto-1_1-x64.dll",
                                            "libcrypto.dll", NULL};
#elif defined(__APPLE__)
    static const char *const ssl_names[] = {"libssl.3.dylib",
                                            "libssl.dylib",
                                            "/opt/homebrew/opt/openssl@3/lib/libssl.3.dylib",
                                            "/opt/homebrew/lib/libssl.3.dylib",
                                            "/usr/local/opt/openssl@3/lib/libssl.3.dylib",
                                            "/usr/local/lib/libssl.3.dylib",
                                            "/opt/local/lib/libssl.3.dylib",
                                            NULL};
    static const char *const cry_names[] = {"libcrypto.3.dylib",
                                            "libcrypto.dylib",
                                            "/opt/homebrew/opt/openssl@3/lib/libcrypto.3.dylib",
                                            "/opt/homebrew/lib/libcrypto.3.dylib",
                                            "/usr/local/opt/openssl@3/lib/libcrypto.3.dylib",
                                            "/usr/local/lib/libcrypto.3.dylib",
                                            "/opt/local/lib/libcrypto.3.dylib",
                                            NULL};
#else
    static const char *const ssl_names[] = {"libssl.so.3", "libssl.so.1.1", "libssl.so", NULL};
    static const char *const cry_names[] = {"libcrypto.so.3", "libcrypto.so.1.1", "libcrypto.so", NULL};
#endif
    void *clib = dyn_open_one(getenv("WING_CRYPTO_LIB"));
    void *slib = dyn_open_one(getenv("WING_OPENSSL_LIB"));
    if (clib == NULL) clib = dyn_open_any(cry_names);
    if (slib == NULL) slib = dyn_open_any(ssl_names);
    if (slib == NULL) return;
    if (clib == NULL) clib = slib;

    int ok = 1;
    ok &= load_fn_sym(&g_ossl.TLS_client_method, dyn_sym(slib, "TLS_client_method"));
    ok &= load_fn_sym(&g_ossl.TLS_server_method, dyn_sym(slib, "TLS_server_method"));
    ok &= load_fn_sym(&g_ossl.SSL_CTX_new, dyn_sym(slib, "SSL_CTX_new"));
    ok &= load_fn_sym(&g_ossl.SSL_CTX_free, dyn_sym(slib, "SSL_CTX_free"));
    ok &= load_fn_sym(&g_ossl.SSL_CTX_ctrl, dyn_sym(slib, "SSL_CTX_ctrl"));
    (void)load_fn_sym(&g_ossl.SSL_CTX_set_options, dyn_sym(slib, "SSL_CTX_set_options"));
    (void)load_fn_sym(&g_ossl.SSL_CTX_set_num_tickets, dyn_sym(slib, "SSL_CTX_set_num_tickets"));
    (void)load_fn_sym(&g_ossl.SSL_CTX_set_keylog_callback, dyn_sym(slib, "SSL_CTX_set_keylog_callback"));
    (void)load_fn_sym(&g_ossl.SSL_CTX_get_cert_store, dyn_sym(slib, "SSL_CTX_get_cert_store"));
    ok &= load_fn_sym(&g_ossl.SSL_CTX_set_default_verify_paths, dyn_sym(slib, "SSL_CTX_set_default_verify_paths"));
    ok &= load_fn_sym(&g_ossl.SSL_CTX_load_verify_locations, dyn_sym(slib, "SSL_CTX_load_verify_locations"));
    ok &= load_fn_sym(&g_ossl.SSL_CTX_set_verify, dyn_sym(slib, "SSL_CTX_set_verify"));
    ok &= load_fn_sym(&g_ossl.SSL_CTX_use_certificate_chain_file, dyn_sym(slib, "SSL_CTX_use_certificate_chain_file"));
    ok &= load_fn_sym(&g_ossl.SSL_CTX_use_PrivateKey_file, dyn_sym(slib, "SSL_CTX_use_PrivateKey_file"));
    ok &= load_fn_sym(&g_ossl.SSL_CTX_check_private_key, dyn_sym(slib, "SSL_CTX_check_private_key"));
    (void)load_fn_sym(&g_ossl.SSL_CTX_set_alpn_select_cb, dyn_sym(slib, "SSL_CTX_set_alpn_select_cb"));
    ok &= load_fn_sym(&g_ossl.SSL_new, dyn_sym(slib, "SSL_new"));
    ok &= load_fn_sym(&g_ossl.SSL_free, dyn_sym(slib, "SSL_free"));
    (void)load_fn_sym(&g_ossl.SSL_set_ex_data, dyn_sym(slib, "SSL_set_ex_data"));
    (void)load_fn_sym(&g_ossl.SSL_get_ex_data, dyn_sym(slib, "SSL_get_ex_data"));
    ok &= load_fn_sym(&g_ossl.SSL_set_connect_state, dyn_sym(slib, "SSL_set_connect_state"));
    ok &= load_fn_sym(&g_ossl.SSL_set_accept_state, dyn_sym(slib, "SSL_set_accept_state"));
    ok &= load_fn_sym(&g_ossl.SSL_set_bio, dyn_sym(slib, "SSL_set_bio"));
    ok &= load_fn_sym(&g_ossl.SSL_do_handshake, dyn_sym(slib, "SSL_do_handshake"));
    ok &= load_fn_sym(&g_ossl.SSL_read, dyn_sym(slib, "SSL_read"));
    ok &= load_fn_sym(&g_ossl.SSL_write, dyn_sym(slib, "SSL_write"));
    (void)load_fn_sym(&g_ossl.SSL_shutdown, dyn_sym(slib, "SSL_shutdown"));
    ok &= load_fn_sym(&g_ossl.SSL_get_error, dyn_sym(slib, "SSL_get_error"));
    ok &= load_fn_sym(&g_ossl.SSL_ctrl, dyn_sym(slib, "SSL_ctrl"));
    ok &= load_fn_sym(&g_ossl.SSL_set1_host, dyn_sym(slib, "SSL_set1_host"));
    (void)load_fn_sym(&g_ossl.SSL_get0_param, dyn_sym(slib, "SSL_get0_param"));
    (void)load_fn_sym(&g_ossl.X509_VERIFY_PARAM_set1_ip_asc, dyn_sym(clib, "X509_VERIFY_PARAM_set1_ip_asc"));
    (void)load_fn_sym(&g_ossl.d2i_X509, dyn_sym(clib, "d2i_X509"));
    (void)load_fn_sym(&g_ossl.X509_STORE_add_cert, dyn_sym(clib, "X509_STORE_add_cert"));
    (void)load_fn_sym(&g_ossl.X509_free, dyn_sym(clib, "X509_free"));
    (void)load_fn_sym(&g_ossl.ERR_clear_error, dyn_sym(clib, "ERR_clear_error"));
    ok &= load_fn_sym(&g_ossl.SSL_set_alpn_protos, dyn_sym(slib, "SSL_set_alpn_protos"));
    ok &= load_fn_sym(&g_ossl.SSL_get0_alpn_selected, dyn_sym(slib, "SSL_get0_alpn_selected"));
    (void)load_fn_sym(&g_ossl.SSL_get_verify_result, dyn_sym(slib, "SSL_get_verify_result"));
    ok &= load_fn_sym(&g_ossl.BIO_s_mem, dyn_sym(clib, "BIO_s_mem"));
    ok &= load_fn_sym(&g_ossl.BIO_new, dyn_sym(clib, "BIO_new"));
    (void)load_fn_sym(&g_ossl.BIO_free, dyn_sym(clib, "BIO_free"));
    ok &= load_fn_sym(&g_ossl.BIO_write, dyn_sym(clib, "BIO_write"));
    ok &= load_fn_sym(&g_ossl.BIO_read, dyn_sym(clib, "BIO_read"));
    ok &= load_fn_sym(&g_ossl.BIO_ctrl, dyn_sym(clib, "BIO_ctrl"));

    g_ossl.available = ok;
}
#endif

#ifdef _WIN32
static INIT_ONCE g_ossl_once = INIT_ONCE_STATIC_INIT;

static BOOL CALLBACK ossl_probe_once_cb(PINIT_ONCE once, PVOID param, PVOID *ctx) {
    (void)once;
    (void)param;
    (void)ctx;
    ossl_probe_impl();
    return TRUE;
}

static int ossl_probe(void) {
    InitOnceExecuteOnce(&g_ossl_once, ossl_probe_once_cb, NULL, NULL);
    return g_ossl.available;
}
#else
static pthread_once_t g_ossl_once = PTHREAD_ONCE_INIT;

static int ossl_probe(void) {
    pthread_once(&g_ossl_once, ossl_probe_impl);
    return g_ossl.available;
}
#endif
#else
static int ossl_probe(void) { return 0; }
#endif

/* ---- Windows Schannel Dynamic Driver (secur32.dll) --------------------- */

#ifdef _WIN32
#ifndef SECBUFFER_APPLICATION_PROTOCOLS
#define SECBUFFER_APPLICATION_PROTOCOLS 18
#endif
#ifndef SECPKG_ATTR_APPLICATION_PROTOCOL
#define SECPKG_ATTR_APPLICATION_PROTOCOL 35
#endif
#ifndef SCH_USE_STRONG_CRYPTO
#define SCH_USE_STRONG_CRYPTO 0x00400000
#endif
#ifndef SP_PROT_TLS1_2_CLIENT
#define SP_PROT_TLS1_2_CLIENT 0x00000800
#endif
#ifndef SP_PROT_TLS1_3_CLIENT
#define SP_PROT_TLS1_3_CLIENT 0x00002000
#endif

typedef struct {
    DWORD cAlpnIds;
    void *rgstrAlpnIds;
    DWORD grbitDisabledProtocols;
    DWORD cDisabledCrypto;
    void *pDisabledCrypto;
    DWORD dwFlags;
} wing_sch_tls_params_t;

typedef struct {
    DWORD dwVersion;
    DWORD dwCredFormat;
    DWORD cCreds;
    PCCERT_CONTEXT *paCred;
    HCERTSTORE hRootStore;
    DWORD cMappers;
    void **aphMappers;
    DWORD dwSessionLifespan;
    DWORD dwFlags;
    DWORD cTlsParameters;
    wing_sch_tls_params_t *pTlsParameters;
} wing_sch_cred_v5_t;

typedef struct {
    int probed;
    int available;
    ACQUIRE_CREDENTIALS_HANDLE_FN_A AcquireCredentialsHandleA;
    FREE_CREDENTIALS_HANDLE_FN FreeCredentialsHandle;
    INITIALIZE_SECURITY_CONTEXT_FN_A InitializeSecurityContextA;
    ACCEPT_SECURITY_CONTEXT_FN AcceptSecurityContext;
    DELETE_SECURITY_CONTEXT_FN DeleteSecurityContext;
    FREE_CONTEXT_BUFFER_FN FreeContextBuffer;
    QUERY_CONTEXT_ATTRIBUTES_FN_A QueryContextAttributesA;
    ENCRYPT_MESSAGE_FN EncryptMessage;
    DECRYPT_MESSAGE_FN DecryptMessage;
} schannel_api_t;

static schannel_api_t g_sch;
static INIT_ONCE g_sch_once = INIT_ONCE_STATIC_INIT;

static BOOL CALLBACK schannel_probe_once_cb(PINIT_ONCE once, PVOID param, PVOID *ctx) {
    (void)once;
    (void)param;
    (void)ctx;
    g_sch.probed = 1;
    static const char *const names[] = {"secur32.dll", "security.dll", NULL};
    void *lib = dyn_open_any(names);
    if (lib == NULL) return TRUE;
    int ok = 1;
    ok &= load_fn_sym(&g_sch.AcquireCredentialsHandleA, dyn_sym(lib, "AcquireCredentialsHandleA"));
    ok &= load_fn_sym(&g_sch.FreeCredentialsHandle, dyn_sym(lib, "FreeCredentialsHandle"));
    ok &= load_fn_sym(&g_sch.InitializeSecurityContextA, dyn_sym(lib, "InitializeSecurityContextA"));
    ok &= load_fn_sym(&g_sch.AcceptSecurityContext, dyn_sym(lib, "AcceptSecurityContext"));
    ok &= load_fn_sym(&g_sch.DeleteSecurityContext, dyn_sym(lib, "DeleteSecurityContext"));
    ok &= load_fn_sym(&g_sch.FreeContextBuffer, dyn_sym(lib, "FreeContextBuffer"));
    ok &= load_fn_sym(&g_sch.QueryContextAttributesA, dyn_sym(lib, "QueryContextAttributesA"));
    ok &= load_fn_sym(&g_sch.EncryptMessage, dyn_sym(lib, "EncryptMessage"));
    ok &= load_fn_sym(&g_sch.DecryptMessage, dyn_sym(lib, "DecryptMessage"));
    g_sch.available = ok;
    return TRUE;
}

static int schannel_probe(void) {
    InitOnceExecuteOnce(&g_sch_once, schannel_probe_once_cb, NULL, NULL);
    return g_sch.available;
}
#else
static int schannel_probe(void) { return 0; }
#endif

/* ---- macOS SecureTransport Dynamic Driver (TLS 1.2 opt-in fallback) ---- */

#ifdef __APPLE__
#define ST_SSL_CLIENT_SIDE 1
#define ST_SSL_STREAM_TYPE 0
#define ST_TLS_PROTOCOL_12 8
#define ST_OPT_BREAK_ON_SERVER_AUTH 0
#define ST_ERR_SUCCESS 0
#define ST_ERR_WOULD_BLOCK (-9803)
#define ST_ERR_CLOSED_GRACEFUL (-9805)
#define ST_ERR_XCERT_CHAIN_INVALID (-9807)
#define ST_ERR_UNKNOWN_ROOT_CERT (-9812)
#define ST_ERR_NO_ROOT_CERT (-9813)
#define ST_ERR_CERT_EXPIRED (-9814)
#define ST_ERR_CERT_NOT_YET_VALID (-9815)
#define ST_ERR_CLOSED_NO_NOTIFY (-9816)
#define ST_ERR_PEER_AUTH_COMPLETED (-9841)
#define ST_ERR_HOSTNAME_MISMATCH (-9843)

typedef int32_t st_osstatus_t;
typedef st_osstatus_t (*st_read_fn_t)(const void *conn, void *data, size_t *data_len);
typedef st_osstatus_t (*st_write_fn_t)(const void *conn, const void *data, size_t *data_len);

typedef struct {
    int probed;
    int available;
    void *(*SSLCreateContext)(void *, int, int);
    st_osstatus_t (*SSLSetIOFuncs)(void *, st_read_fn_t, st_write_fn_t);
    st_osstatus_t (*SSLSetConnection)(void *, const void *);
    st_osstatus_t (*SSLSetPeerDomainName)(void *, const char *, size_t);
    st_osstatus_t (*SSLSetProtocolVersionMin)(void *, int);
    st_osstatus_t (*SSLSetSessionOption)(void *, int, uint8_t);
    st_osstatus_t (*SSLHandshake)(void *);
    st_osstatus_t (*SSLRead)(void *, void *, size_t, size_t *);
    st_osstatus_t (*SSLWrite)(void *, const void *, size_t, size_t *);
    st_osstatus_t (*SSLClose)(void *);
    void (*CFRelease)(const void *);
} secure_transport_api_t;

static secure_transport_api_t g_st;
static pthread_once_t g_st_once = PTHREAD_ONCE_INIT;

static void secure_transport_probe_impl(void) {
    g_st.probed = 1;
    static const char *const sec_names[] = {"/System/Library/Frameworks/Security.framework/Security",
                                            "/System/Library/Frameworks/Security.framework/Versions/A/Security", NULL};
    static const char *const cf_names[] = {"/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", NULL};
    void *slib = dyn_open_any(sec_names);
    if (slib == NULL) return;
    void *cflib = dyn_open_any(cf_names);
    if (cflib == NULL) cflib = slib;

    int ok = 1;
    ok &= load_fn_sym(&g_st.SSLCreateContext, dyn_sym(slib, "SSLCreateContext"));
    ok &= load_fn_sym(&g_st.SSLSetIOFuncs, dyn_sym(slib, "SSLSetIOFuncs"));
    ok &= load_fn_sym(&g_st.SSLSetConnection, dyn_sym(slib, "SSLSetConnection"));
    ok &= load_fn_sym(&g_st.SSLSetPeerDomainName, dyn_sym(slib, "SSLSetPeerDomainName"));
    ok &= load_fn_sym(&g_st.SSLSetProtocolVersionMin, dyn_sym(slib, "SSLSetProtocolVersionMin"));
    ok &= load_fn_sym(&g_st.SSLSetSessionOption, dyn_sym(slib, "SSLSetSessionOption"));
    ok &= load_fn_sym(&g_st.SSLHandshake, dyn_sym(slib, "SSLHandshake"));
    ok &= load_fn_sym(&g_st.SSLRead, dyn_sym(slib, "SSLRead"));
    ok &= load_fn_sym(&g_st.SSLWrite, dyn_sym(slib, "SSLWrite"));
    ok &= load_fn_sym(&g_st.SSLClose, dyn_sym(slib, "SSLClose"));
    ok &= load_fn_sym(&g_st.CFRelease, dyn_sym(cflib, "CFRelease"));
    g_st.available = ok;
}

static int secure_transport_probe(void) {
    pthread_once(&g_st_once, secure_transport_probe_impl);
    return g_st.available;
}
#else
static int secure_transport_probe(void) { return 0; }
#endif

/* ---- Unified Endpoint Handle Table ------------------------------------- */

typedef struct {
    int in_use;
    int closing;
    uint32_t refcount;
    uint32_t generation;
#ifdef _WIN32
    SRWLOCK io_lock;
#elif !defined(__wasm__)
    pthread_mutex_t io_lock;
    int io_lock_init;
#endif
    int kind;
    int is_server;
    int insecure_skip_verify;
    int use_system_roots;
    int no_session_tickets;
    int min_version;
    int established;
    int closed;
    char sni[257];
    char ca_file[257];
    char cert_pem_file[257];
    char key_pem_file[257];
    char keylog_file[257];
    uint8_t alpn_wire[64];
    size_t alpn_wire_len;
    uint8_t selected_alpn[64];
    size_t selected_alpn_len;
    /* OpenSSL state */
    void *ossl_ctx;
    void *ossl_ssl;
    void *ossl_rbio;
    void *ossl_wbio;
#ifdef _WIN32
    /* Schannel state */
    CredHandle cred;
    CtxtHandle ctxt;
    int has_cred;
    int has_ctxt;
    SecPkgContext_StreamSizes stream_sizes;
    tls_buf_t sch_in;
    tls_buf_t sch_out;
    tls_buf_t sch_app;
#endif
#ifdef __APPLE__
    /* SecureTransport state */
    void *st_ctx;
    tls_buf_t st_in;
    tls_buf_t st_out;
#endif
} wing_tls_ep_t;

static wing_tls_ep_t *g_eps[WING_TLS_MAX_HANDLES];
static int g_eps_cursor = 0;
static uint32_t g_next_gen = 0;

static void wing_tls_ep_destroy(wing_tls_ep_t *ep);

#ifdef _WIN32
static SRWLOCK g_eps_lock = SRWLOCK_INIT;
static SRWLOCK g_keylog_lock = SRWLOCK_INIT;
static void eps_lock(void) { AcquireSRWLockExclusive(&g_eps_lock); }
static void eps_unlock(void) { ReleaseSRWLockExclusive(&g_eps_lock); }
static void keylog_lock(void) { AcquireSRWLockExclusive(&g_keylog_lock); }
static void keylog_unlock(void) { ReleaseSRWLockExclusive(&g_keylog_lock); }
static void ep_io_lock(wing_tls_ep_t *ep) { AcquireSRWLockExclusive(&ep->io_lock); }
static void ep_io_unlock(wing_tls_ep_t *ep) { ReleaseSRWLockExclusive(&ep->io_lock); }
#elif !defined(__wasm__)
static pthread_mutex_t g_eps_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_keylog_lock = PTHREAD_MUTEX_INITIALIZER;
static void eps_lock(void) { pthread_mutex_lock(&g_eps_lock); }
static void eps_unlock(void) { pthread_mutex_unlock(&g_eps_lock); }
static void keylog_lock(void) { pthread_mutex_lock(&g_keylog_lock); }
static void keylog_unlock(void) { pthread_mutex_unlock(&g_keylog_lock); }
static void ep_io_lock(wing_tls_ep_t *ep) { pthread_mutex_lock(&ep->io_lock); }
static void ep_io_unlock(wing_tls_ep_t *ep) { pthread_mutex_unlock(&ep->io_lock); }
#else
static void eps_lock(void) {}
static void eps_unlock(void) {}
static void keylog_lock(void) {}
static void keylog_unlock(void) {}
static void ep_io_lock(wing_tls_ep_t *ep) { (void)ep; }
static void ep_io_unlock(wing_tls_ep_t *ep) { (void)ep; }
#endif

static int decode_ep_handle(int64_t handle, size_t *out_slot, uint32_t *out_gen) {
    if (handle <= 0) return 0;
    uint64_t h = (uint64_t)handle;
    uint64_t idx1 = h & 0xFFFFU;
    uint32_t gen = (uint32_t)(h >> 16);
    if (idx1 < 1 || idx1 > WING_TLS_MAX_HANDLES || gen == 0) return 0;
    *out_slot = (size_t)(idx1 - 1);
    *out_gen = gen;
    return 1;
}

static wing_tls_ep_t *acquire_ep(int64_t handle) {
    size_t slot = 0;
    uint32_t gen = 0;
    if (!decode_ep_handle(handle, &slot, &gen)) return NULL;
    eps_lock();
    wing_tls_ep_t *ep = g_eps[slot];
    if (ep != NULL && ep->in_use && !ep->closing && ep->generation == gen && ep->refcount < UINT32_MAX) {
        ep->refcount++;
    } else {
        ep = NULL;
    }
    eps_unlock();
    return ep;
}

static void release_ep(wing_tls_ep_t *ep) {
    if (ep == NULL) return;
    int should_destroy = 0;
    eps_lock();
    if (ep->refcount > 0) ep->refcount--;
    if (ep->refcount == 0 && ep->closing) should_destroy = 1;
    eps_unlock();
    if (should_destroy) wing_tls_ep_destroy(ep);
}

static void copy_cstr_ro(char *dst, size_t cap, wing_tls_ro src) {
    if (dst == NULL || cap == 0) return;
    dst[0] = '\0';
    if (src.data == NULL || src.len <= 0) return;
    size_t max_n = cap - 1;
    size_t n = (size_t)src.len < max_n ? (size_t)src.len : max_n;
    memcpy(dst, src.data, n);
    dst[n] = '\0';
}

static int ossl_alpn_select_cb(void *ssl, const unsigned char **out, unsigned char *outlen, const unsigned char *in,
                               unsigned int inlen, void *arg) {
    (void)ssl;
    const wing_tls_ep_t *ep = (const wing_tls_ep_t *)arg;
    if (ep == NULL || ep->alpn_wire_len == 0 || in == NULL || inlen == 0) return OSSL_TLSEXT_ERR_NOACK;
    size_t si = 0;
    while (si < ep->alpn_wire_len) {
        unsigned int slen = ep->alpn_wire[si++];
        if (slen == 0 || slen > ep->alpn_wire_len - si) break;
        const unsigned char *sproto = ep->alpn_wire + si;
        size_t ci = 0;
        while (ci < inlen) {
            unsigned int clen = in[ci++];
            if (clen == 0 || clen > inlen - ci) break;
            if (clen == slen && memcmp(in + ci, sproto, slen) == 0) {
                *out = in + ci;
                *outlen = (unsigned char)clen;
                return OSSL_TLSEXT_ERR_OK;
            }
            ci += clen;
        }
        si += slen;
    }
    return OSSL_TLSEXT_ERR_NOACK;
}

static void ossl_keylog_cb(const void *ssl, const char *line) {
    if (ssl == NULL || line == NULL || line[0] == '\0' || g_ossl.SSL_get_ex_data == NULL) return;
    const wing_tls_ep_t *ep = (const wing_tls_ep_t *)g_ossl.SSL_get_ex_data(ssl, 0);
    if (ep == NULL || ep->keylog_file[0] == '\0') return;
    size_t n = strlen(line);
    keylog_lock();
    FILE *fp = fopen(ep->keylog_file, "ab");
    if (fp != NULL) {
        (void)fwrite(line, 1, n, fp);
        if (line[n - 1] != '\n') (void)fputc('\n', fp);
        (void)fflush(fp);
        (void)fclose(fp);
    }
    keylog_unlock();
}

static int32_t ossl_map_err(wing_tls_ep_t *ep, int ret, int is_hs) {
    int err = g_ossl.SSL_get_error(ep->ossl_ssl, ret);
    if (err == OSSL_SSL_ERROR_WANT_READ) return WING_TLS_ST_WANT_READ;
    if (err == OSSL_SSL_ERROR_WANT_WRITE) return WING_TLS_ST_WANT_WRITE;
    if (err == OSSL_SSL_ERROR_ZERO_RETURN) return WING_TLS_ST_CLOSED;
    if (is_hs && g_ossl.SSL_get_verify_result != NULL && g_ossl.SSL_get_verify_result(ep->ossl_ssl) != 0) {
        return WING_TLS_ST_VERIFY_ERR;
    }
    return is_hs ? WING_TLS_ST_HS_ERR : WING_TLS_ST_ERR;
}

static void ossl_cleanup_ep(wing_tls_ep_t *ep) {
    wing_tls_zeroize(ep->keylog_file, sizeof(ep->keylog_file));
    if (ep->ossl_ctx != NULL && g_ossl.SSL_CTX_set_keylog_callback != NULL) {
        g_ossl.SSL_CTX_set_keylog_callback(ep->ossl_ctx, NULL);
    }
    if (ep->ossl_ssl != NULL) {
        g_ossl.SSL_free(ep->ossl_ssl);
        ep->ossl_ssl = NULL;
        ep->ossl_rbio = NULL;
        ep->ossl_wbio = NULL;
    } else {
        if (ep->ossl_rbio != NULL && g_ossl.BIO_free != NULL) g_ossl.BIO_free(ep->ossl_rbio);
        if (ep->ossl_wbio != NULL && g_ossl.BIO_free != NULL) g_ossl.BIO_free(ep->ossl_wbio);
        ep->ossl_rbio = NULL;
        ep->ossl_wbio = NULL;
    }
    if (ep->ossl_ctx != NULL) {
        g_ossl.SSL_CTX_free(ep->ossl_ctx);
        ep->ossl_ctx = NULL;
    }
    if (g_ossl.ERR_clear_error != NULL) {
        g_ossl.ERR_clear_error();
    }
}

static int is_ipv4_literal_n(const char *s, size_t len) {
    if (s == NULL || len == 0) return 0;
    int parts = 0;
    size_t i = 0;
    while (i < len) {
        if (parts >= 4 || s[i] < '0' || s[i] > '9') return 0;
        int val = 0;
        int digits = 0;
        while (i < len && s[i] >= '0' && s[i] <= '9') {
            val = val * 10 + (s[i] - '0');
            if (val > 255) return 0;
            digits++;
            i++;
        }
        if (digits == 0) return 0;
        parts++;
        if (i < len) {
            if (s[i] != '.') return 0;
            i++;
            if (i == len) return 0;
        }
    }
    return parts == 4;
}

static int strip_ip_brackets(const char *host, char *out_ip, size_t out_cap) {
    if (host == NULL || host[0] == '\0' || out_cap < 2) return 0;
    size_t len = strlen(host);
    const char *start = host;
    if (len >= 2 && host[0] == '[' && host[len - 1] == ']') {
        start = host + 1;
        len -= 2;
    }
    if (len == 0 || len >= out_cap) return 0;
    memcpy(out_ip, start, len);
    out_ip[len] = '\0';
    return 1;
}

static int is_ip_literal(const char *host) {
    if (host == NULL || host[0] == '\0') return 0;
    size_t len = strlen(host);
    const char *start = host;
    if (len >= 2 && host[0] == '[' && host[len - 1] == ']') {
        start = host + 1;
        len -= 2;
    }
    if (len == 0) return 0;
    if (is_ipv4_literal_n(start, len)) return 1;
    return memchr(start, ':', len) != NULL;
}

static int ossl_configure_client_host(wing_tls_ep_t *ep) {
    if (ep->sni[0] == '\0') return WING_TLS_ST_OK;
    if (is_ip_literal(ep->sni)) {
        /* RFC 6066 Section 3: literal IPv4 and IPv6 addresses are not permitted in TLS SNI. */
        if (ep->insecure_skip_verify) return WING_TLS_ST_OK;
        if (g_ossl.SSL_get0_param == NULL || g_ossl.X509_VERIFY_PARAM_set1_ip_asc == NULL) {
            return WING_TLS_ST_VERIFY_ERR;
        }
        char clean_ip[sizeof(ep->sni)];
        if (!strip_ip_brackets(ep->sni, clean_ip, sizeof(clean_ip))) {
            return WING_TLS_ST_VERIFY_ERR;
        }
        void *param = g_ossl.SSL_get0_param(ep->ossl_ssl);
        if (param == NULL || g_ossl.X509_VERIFY_PARAM_set1_ip_asc(param, clean_ip) != 1) {
            return WING_TLS_ST_VERIFY_ERR;
        }
        return WING_TLS_ST_OK;
    }
    (void)g_ossl.SSL_ctrl(ep->ossl_ssl, OSSL_CTRL_SET_SNI, 0, ep->sni);
    if (!ep->insecure_skip_verify && g_ossl.SSL_set1_host(ep->ossl_ssl, ep->sni) != 1) {
        return WING_TLS_ST_VERIFY_ERR;
    }
    return WING_TLS_ST_OK;
}

#ifdef _WIN32
static int ossl_load_win_root_store(void *ssl_ctx);
#endif

static int ossl_open_ep(wing_tls_ep_t *ep) {
    if (!ossl_probe()) return WING_TLS_ST_UNAVAILABLE;
    const void *meth = ep->is_server ? g_ossl.TLS_server_method() : g_ossl.TLS_client_method();
    if (meth == NULL) return WING_TLS_ST_ERR;
    ep->ossl_ctx = g_ossl.SSL_CTX_new(meth);
    if (ep->ossl_ctx == NULL) return WING_TLS_ST_ERR;

    /* Enforce configured minimum protocol floor (default TLS 1.3; opt-in TLS 1.2 fallback). */
    long min_proto = (ep->min_version == WING_TLS_MIN_TLS12) ? OSSL_TLS1_2_VERSION : OSSL_TLS1_3_VERSION;
    if (g_ossl.SSL_CTX_ctrl != NULL &&
        g_ossl.SSL_CTX_ctrl(ep->ossl_ctx, OSSL_CTRL_SET_MIN_PROTO_VERSION, min_proto, NULL) != 1) {
        ossl_cleanup_ep(ep);
        return WING_TLS_ST_ERR;
    }

    if (ep->no_session_tickets) {
        if (g_ossl.SSL_CTX_set_options != NULL) {
            (void)g_ossl.SSL_CTX_set_options(ep->ossl_ctx, OSSL_SSL_OP_NO_TICKET);
        }
        if (g_ossl.SSL_CTX_set_num_tickets != NULL) {
            (void)g_ossl.SSL_CTX_set_num_tickets(ep->ossl_ctx, 0);
        }
    }

    /* Load PEM certificate chain + private key for both server endpoints and mTLS clients. */
    int has_cert = ep->cert_pem_file[0] != '\0';
    int has_key = ep->key_pem_file[0] != '\0';
    if (has_cert != has_key) {
        ossl_cleanup_ep(ep);
        return WING_TLS_ST_HS_ERR;
    }
    if (has_cert && has_key) {
        if (g_ossl.SSL_CTX_use_certificate_chain_file(ep->ossl_ctx, ep->cert_pem_file) != 1 ||
            g_ossl.SSL_CTX_use_PrivateKey_file(ep->ossl_ctx, ep->key_pem_file, OSSL_FILETYPE_PEM) != 1 ||
            g_ossl.SSL_CTX_check_private_key(ep->ossl_ctx) != 1) {
            ossl_cleanup_ep(ep);
            return WING_TLS_ST_HS_ERR;
        }
    }

    if (ep->is_server) {
        if (!ep->insecure_skip_verify && ep->ca_file[0] != '\0') {
            if (g_ossl.SSL_CTX_load_verify_locations(ep->ossl_ctx, ep->ca_file, NULL) != 1) {
                ossl_cleanup_ep(ep);
                return WING_TLS_ST_VERIFY_ERR;
            }
            g_ossl.SSL_CTX_set_verify(ep->ossl_ctx, OSSL_SSL_VERIFY_PEER | OSSL_SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
        }
        if (ep->alpn_wire_len > 0 && g_ossl.SSL_CTX_set_alpn_select_cb != NULL) {
            g_ossl.SSL_CTX_set_alpn_select_cb(ep->ossl_ctx, ossl_alpn_select_cb, ep);
        }
    } else if (ep->insecure_skip_verify) {
        g_ossl.SSL_CTX_set_verify(ep->ossl_ctx, OSSL_SSL_VERIFY_NONE, NULL);
    } else {
        if (ep->ca_file[0] != '\0') {
            if (g_ossl.SSL_CTX_load_verify_locations(ep->ossl_ctx, ep->ca_file, NULL) != 1) {
                ossl_cleanup_ep(ep);
                return WING_TLS_ST_VERIFY_ERR;
            }
        } else if (ep->use_system_roots) {
            (void)g_ossl.SSL_CTX_set_default_verify_paths(ep->ossl_ctx);
#ifdef _WIN32
            (void)ossl_load_win_root_store(ep->ossl_ctx);
#endif
        }
        g_ossl.SSL_CTX_set_verify(ep->ossl_ctx, OSSL_SSL_VERIFY_PEER, NULL);
    }

    void *ssl = g_ossl.SSL_new(ep->ossl_ctx);
    void *rbio = g_ossl.BIO_new(g_ossl.BIO_s_mem());
    void *wbio = g_ossl.BIO_new(g_ossl.BIO_s_mem());
    if (ssl == NULL || rbio == NULL || wbio == NULL) {
        if (ssl != NULL) g_ossl.SSL_free(ssl);
        if (rbio != NULL && g_ossl.BIO_free != NULL) g_ossl.BIO_free(rbio);
        if (wbio != NULL && g_ossl.BIO_free != NULL) g_ossl.BIO_free(wbio);
        ossl_cleanup_ep(ep);
        return WING_TLS_ST_ERR;
    }
    ep->ossl_ssl = ssl;
    ep->ossl_rbio = rbio;
    ep->ossl_wbio = wbio;
    g_ossl.SSL_set_bio(ep->ossl_ssl, ep->ossl_rbio, ep->ossl_wbio);
    if (g_ossl.SSL_set_ex_data != NULL) {
        (void)g_ossl.SSL_set_ex_data(ep->ossl_ssl, 0, ep);
    }

    if (ep->is_server) {
        g_ossl.SSL_set_accept_state(ep->ossl_ssl);
    } else {
        g_ossl.SSL_set_connect_state(ep->ossl_ssl);
        int host_st = ossl_configure_client_host(ep);
        if (host_st != WING_TLS_ST_OK) {
            ossl_cleanup_ep(ep);
            return host_st;
        }
        if (ep->alpn_wire_len > 0) {
            (void)g_ossl.SSL_set_alpn_protos(ep->ossl_ssl, ep->alpn_wire, (unsigned int)ep->alpn_wire_len);
        }
    }
    return WING_TLS_ST_OK;
}

#ifdef _WIN32
static int schannel_open_ep(wing_tls_ep_t *ep) {
    if (!schannel_probe()) return WING_TLS_ST_UNAVAILABLE;
    if (ep->is_server) return WING_TLS_ST_UNAVAILABLE;
    if (!ep->insecure_skip_verify && !ep->use_system_roots) return WING_TLS_ST_VERIFY_ERR;
    DWORD flags = SCH_CRED_NO_DEFAULT_CREDS | SCH_USE_STRONG_CRYPTO;
    flags |= ep->insecure_skip_verify ? (SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_IGNORE_NO_REVOCATION_CHECK |
                                         SCH_CRED_IGNORE_REVOCATION_OFFLINE)
                                      : SCH_CRED_AUTO_CRED_VALIDATION;

    wing_sch_tls_params_t tp;
    memset(&tp, 0, sizeof(tp));
    tp.grbitDisabledProtocols = (ep->min_version == WING_TLS_MIN_TLS12)
                                    ? ~(DWORD)(SP_PROT_TLS1_2_CLIENT | SP_PROT_TLS1_3_CLIENT)
                                    : ~(DWORD)SP_PROT_TLS1_3_CLIENT;
    wing_sch_cred_v5_t cred5;
    memset(&cred5, 0, sizeof(cred5));
    cred5.dwVersion = 5;
    cred5.dwFlags = flags;
    cred5.cTlsParameters = 1;
    cred5.pTlsParameters = &tp;

    TimeStamp ts;
    SECURITY_STATUS ss = g_sch.AcquireCredentialsHandleA(NULL, (SEC_CHAR *)UNISP_NAME_A, SECPKG_CRED_OUTBOUND, NULL,
                                                         &cred5, NULL, NULL, &ep->cred, &ts);
    if (ss != SEC_E_OK && ep->min_version == WING_TLS_MIN_TLS12) {
        /* Fallback to SCHANNEL_CRED v4 on Windows 10 builds without SCH_CREDENTIALS v5. */
        SCHANNEL_CRED cred4;
        memset(&cred4, 0, sizeof(cred4));
        cred4.dwVersion = SCHANNEL_CRED_VERSION;
        cred4.dwFlags = flags;
        cred4.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT | SP_PROT_TLS1_3_CLIENT;
        ss = g_sch.AcquireCredentialsHandleA(NULL, (SEC_CHAR *)UNISP_NAME_A, SECPKG_CRED_OUTBOUND, NULL, &cred4, NULL,
                                             NULL, &ep->cred, &ts);
        if (ss != SEC_E_OK) {
            cred4.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT;
            ss = g_sch.AcquireCredentialsHandleA(NULL, (SEC_CHAR *)UNISP_NAME_A, SECPKG_CRED_OUTBOUND, NULL, &cred4,
                                                 NULL, NULL, &ep->cred, &ts);
        }
    }
    if (ss != SEC_E_OK) {
        return (ep->min_version == WING_TLS_MIN_TLS13) ? WING_TLS_ST_UNAVAILABLE : WING_TLS_ST_HS_ERR;
    }
    ep->has_cred = 1;
    return WING_TLS_ST_OK;
}

static int32_t schannel_step_hs(wing_tls_ep_t *ep) {
    if (ep->established) return WING_TLS_ST_OK;
    SecBuffer in_bufs[2];
    SecBufferDesc in_desc;
    SecBufferDesc *in_ptr = NULL;
    uint8_t alpn_ext[80];

    if (!ep->has_ctxt) {
        if (ep->alpn_wire_len > 0 && ep->alpn_wire_len <= 64) {
            uint32_t list_sz = (uint32_t)ep->alpn_wire_len;
            uint32_t total_sz = 4 + 2 + list_sz;
            uint32_t ext_id = 2; /* SecApplicationProtocolNegotiationExt_ALPN */
            uint16_t list_u16 = (uint16_t)list_sz;
            memcpy(alpn_ext + 0, &total_sz, 4);
            memcpy(alpn_ext + 4, &ext_id, 4);
            memcpy(alpn_ext + 8, &list_u16, 2);
            memcpy(alpn_ext + 10, ep->alpn_wire, list_sz);
            in_bufs[0].BufferType = SECBUFFER_APPLICATION_PROTOCOLS;
            in_bufs[0].cbBuffer = 4 + total_sz;
            in_bufs[0].pvBuffer = alpn_ext;
            in_desc.ulVersion = SECBUFFER_VERSION;
            in_desc.cBuffers = 1;
            in_desc.pBuffers = in_bufs;
            in_ptr = &in_desc;
        }
    } else {
        if (ep->sch_in.len == 0) return WING_TLS_ST_WANT_READ;
        in_bufs[0].BufferType = SECBUFFER_TOKEN;
        in_bufs[0].cbBuffer = (unsigned long)ep->sch_in.len;
        in_bufs[0].pvBuffer = ep->sch_in.data;
        in_bufs[1].BufferType = SECBUFFER_EMPTY;
        in_bufs[1].cbBuffer = 0;
        in_bufs[1].pvBuffer = NULL;
        in_desc.ulVersion = SECBUFFER_VERSION;
        in_desc.cBuffers = 2;
        in_desc.pBuffers = in_bufs;
        in_ptr = &in_desc;
    }

    SecBuffer out_buf;
    out_buf.BufferType = SECBUFFER_TOKEN;
    out_buf.cbBuffer = 0;
    out_buf.pvBuffer = NULL;
    SecBufferDesc out_desc;
    out_desc.ulVersion = SECBUFFER_VERSION;
    out_desc.cBuffers = 1;
    out_desc.pBuffers = &out_buf;

    ULONG flags = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY | ISC_REQ_EXTENDED_ERROR |
                  ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM;
    if (ep->insecure_skip_verify) flags |= ISC_REQ_MANUAL_CRED_VALIDATION;
    ULONG out_flags = 0;
    TimeStamp ts;
    SEC_CHAR *target = ep->sni[0] != '\0' ? (SEC_CHAR *)ep->sni : NULL;

    SECURITY_STATUS ss = g_sch.InitializeSecurityContextA(&ep->cred, ep->has_ctxt ? &ep->ctxt : NULL, target, flags, 0,
                                                          0, in_ptr, 0, &ep->ctxt, &out_desc, &out_flags, &ts);
    if (!ep->has_ctxt && (ss == SEC_E_OK || ss == SEC_I_CONTINUE_NEEDED)) ep->has_ctxt = 1;
    if (out_buf.pvBuffer != NULL && out_buf.cbBuffer > 0) {
        (void)tls_buf_append(&ep->sch_out, (const uint8_t *)out_buf.pvBuffer, out_buf.cbBuffer);
        g_sch.FreeContextBuffer(out_buf.pvBuffer);
    }
    if (in_ptr != NULL && ep->has_ctxt && in_desc.cBuffers == 2 && ss != SEC_E_INCOMPLETE_MESSAGE) {
        size_t extra = (in_bufs[1].BufferType == SECBUFFER_EXTRA) ? (size_t)in_bufs[1].cbBuffer : 0;
        if (extra <= ep->sch_in.len) tls_buf_consume(&ep->sch_in, ep->sch_in.len - extra);
    }
    if (ss == SEC_E_OK) {
        ep->established = 1;
        (void)g_sch.QueryContextAttributesA(&ep->ctxt, SECPKG_ATTR_STREAM_SIZES, &ep->stream_sizes);
        uint8_t proto_info[272];
        memset(proto_info, 0, sizeof(proto_info));
        if (g_sch.QueryContextAttributesA(&ep->ctxt, SECPKG_ATTR_APPLICATION_PROTOCOL, proto_info) == SEC_E_OK) {
            uint32_t nego_status = 0;
            memcpy(&nego_status, proto_info, 4);
            uint8_t plen = proto_info[8];
            if (nego_status == 1 && plen > 0 && plen <= 64) {
                memcpy(ep->selected_alpn, proto_info + 9, plen);
                ep->selected_alpn_len = plen;
            }
        }
        return WING_TLS_ST_OK;
    }
    if (ss == SEC_I_CONTINUE_NEEDED || ss == SEC_E_INCOMPLETE_MESSAGE) return WING_TLS_ST_WANT_READ;
    if (ss == SEC_E_UNTRUSTED_ROOT || ss == SEC_E_CERT_EXPIRED || ss == SEC_E_WRONG_PRINCIPAL) {
        return WING_TLS_ST_VERIFY_ERR;
    }
    return WING_TLS_ST_HS_ERR;
}

static int64_t schannel_write_app(wing_tls_ep_t *ep, wing_tls_ro plain, int32_t *out_st) {
    if (!ep->established || ep->stream_sizes.cbMaximumMessage == 0) {
        *out_st = WING_TLS_ST_ERR;
        return 0;
    }
    size_t chunk = (size_t)plain.len;
    if (chunk > ep->stream_sizes.cbMaximumMessage) chunk = ep->stream_sizes.cbMaximumMessage;
    size_t total = ep->stream_sizes.cbHeader + chunk + ep->stream_sizes.cbTrailer;
    uint8_t *msg = (uint8_t *)malloc(total);
    if (msg == NULL) {
        *out_st = WING_TLS_ST_ERR;
        return 0;
    }
    memcpy(msg + ep->stream_sizes.cbHeader, plain.data, chunk);

    SecBuffer bufs[4];
    bufs[0].BufferType = SECBUFFER_STREAM_HEADER;
    bufs[0].cbBuffer = ep->stream_sizes.cbHeader;
    bufs[0].pvBuffer = msg;
    bufs[1].BufferType = SECBUFFER_DATA;
    bufs[1].cbBuffer = (unsigned long)chunk;
    bufs[1].pvBuffer = msg + ep->stream_sizes.cbHeader;
    bufs[2].BufferType = SECBUFFER_STREAM_TRAILER;
    bufs[2].cbBuffer = ep->stream_sizes.cbTrailer;
    bufs[2].pvBuffer = msg + ep->stream_sizes.cbHeader + chunk;
    bufs[3].BufferType = SECBUFFER_EMPTY;
    bufs[3].cbBuffer = 0;
    bufs[3].pvBuffer = NULL;
    SecBufferDesc desc = {SECBUFFER_VERSION, 4, bufs};

    SECURITY_STATUS ss = g_sch.EncryptMessage(&ep->ctxt, 0, &desc, 0);
    int ok = (ss == SEC_E_OK) &&
             tls_buf_append(&ep->sch_out, msg, (size_t)bufs[0].cbBuffer + bufs[1].cbBuffer + bufs[2].cbBuffer);
    wing_tls_zeroize(msg, total);
    free(msg);
    if (!ok) {
        *out_st = WING_TLS_ST_ERR;
        return 0;
    }
    *out_st = WING_TLS_ST_OK;
    return (int64_t)chunk;
}

static int64_t schannel_read_app(wing_tls_ep_t *ep, wing_tls_rw dst, int32_t *out_st) {
    if (ep->sch_app.len > 0) {
        size_t take = ep->sch_app.len < (size_t)dst.len ? ep->sch_app.len : (size_t)dst.len;
        memcpy(dst.data, ep->sch_app.data, take);
        tls_buf_consume(&ep->sch_app, take);
        *out_st = WING_TLS_ST_OK;
        return (int64_t)take;
    }
    if (ep->sch_in.len == 0) {
        *out_st = WING_TLS_ST_WANT_READ;
        return 0;
    }
    SecBuffer bufs[4];
    memset(bufs, 0, sizeof(bufs));
    bufs[0].BufferType = SECBUFFER_DATA;
    bufs[0].cbBuffer = (unsigned long)ep->sch_in.len;
    bufs[0].pvBuffer = ep->sch_in.data;
    bufs[1].BufferType = SECBUFFER_EMPTY;
    bufs[2].BufferType = SECBUFFER_EMPTY;
    bufs[3].BufferType = SECBUFFER_EMPTY;
    SecBufferDesc desc = {SECBUFFER_VERSION, 4, bufs};

    SECURITY_STATUS ss = g_sch.DecryptMessage(&ep->ctxt, &desc, 0, NULL);
    if (ss == SEC_E_INCOMPLETE_MESSAGE) {
        *out_st = WING_TLS_ST_WANT_READ;
        return 0;
    }
    if (ss == SEC_I_CONTEXT_EXPIRED) {
        ep->closed = 1;
        *out_st = WING_TLS_ST_CLOSED;
        return 0;
    }
    if (ss != SEC_E_OK) {
        *out_st = WING_TLS_ST_ERR;
        return 0;
    }

    size_t extra_len = 0;
    for (int i = 0; i < 4; i++) {
        if (bufs[i].BufferType == SECBUFFER_DATA && bufs[i].cbBuffer > 0) {
            (void)tls_buf_append(&ep->sch_app, (const uint8_t *)bufs[i].pvBuffer, bufs[i].cbBuffer);
        } else if (bufs[i].BufferType == SECBUFFER_EXTRA) {
            extra_len = bufs[i].cbBuffer;
        }
    }
    if (extra_len <= ep->sch_in.len) tls_buf_consume(&ep->sch_in, ep->sch_in.len - extra_len);
    if (ep->sch_app.len == 0) {
        *out_st = WING_TLS_ST_WANT_READ;
        return 0;
    }
    size_t take = ep->sch_app.len < (size_t)dst.len ? ep->sch_app.len : (size_t)dst.len;
    memcpy(dst.data, ep->sch_app.data, take);
    tls_buf_consume(&ep->sch_app, take);
    *out_st = WING_TLS_ST_OK;
    return (int64_t)take;
}
#endif

#ifdef __APPLE__
static st_osstatus_t st_io_read(const void *conn, void *data, size_t *data_len) {
    wing_tls_ep_t *ep = (wing_tls_ep_t *)(uintptr_t)conn;
    size_t want = *data_len;
    if (want == 0) return ST_ERR_SUCCESS;
    if (ep == NULL || ep->st_in.len == 0) {
        *data_len = 0;
        return ST_ERR_WOULD_BLOCK;
    }
    size_t take = ep->st_in.len < want ? ep->st_in.len : want;
    memcpy(data, ep->st_in.data, take);
    tls_buf_consume(&ep->st_in, take);
    *data_len = take;
    return take < want ? ST_ERR_WOULD_BLOCK : ST_ERR_SUCCESS;
}

static st_osstatus_t st_io_write(const void *conn, const void *data, size_t *data_len) {
    wing_tls_ep_t *ep = (wing_tls_ep_t *)(uintptr_t)conn;
    size_t n = *data_len;
    if (n == 0) return ST_ERR_SUCCESS;
    if (ep == NULL || !tls_buf_append(&ep->st_out, (const uint8_t *)data, n)) {
        *data_len = 0;
        return ST_ERR_WOULD_BLOCK;
    }
    return ST_ERR_SUCCESS;
}

static int32_t st_map_err(st_osstatus_t st, int is_hs) {
    if (st == ST_ERR_SUCCESS) return WING_TLS_ST_OK;
    if (st == ST_ERR_WOULD_BLOCK) return WING_TLS_ST_WANT_READ;
    if (st == ST_ERR_CLOSED_GRACEFUL || st == ST_ERR_CLOSED_NO_NOTIFY) return WING_TLS_ST_CLOSED;
    if (st == ST_ERR_XCERT_CHAIN_INVALID || st == ST_ERR_UNKNOWN_ROOT_CERT || st == ST_ERR_NO_ROOT_CERT ||
        st == ST_ERR_CERT_EXPIRED || st == ST_ERR_CERT_NOT_YET_VALID || st == ST_ERR_HOSTNAME_MISMATCH) {
        return WING_TLS_ST_VERIFY_ERR;
    }
    return is_hs ? WING_TLS_ST_HS_ERR : WING_TLS_ST_ERR;
}

static void st_cleanup_ep(wing_tls_ep_t *ep) {
    if (ep->st_ctx != NULL) {
        (void)g_st.SSLClose(ep->st_ctx);
        g_st.CFRelease(ep->st_ctx);
        ep->st_ctx = NULL;
    }
    tls_buf_free(&ep->st_in);
    tls_buf_free(&ep->st_out);
}

static int st_open_ep(wing_tls_ep_t *ep) {
    if (!secure_transport_probe()) return WING_TLS_ST_UNAVAILABLE;
    /* SecureTransport supports up to TLS 1.2 only: require explicit TlsMinVersion.Tls12 opt-in. */
    if (ep->is_server || ep->min_version != WING_TLS_MIN_TLS12) return WING_TLS_ST_UNAVAILABLE;
    if (!ep->insecure_skip_verify && !ep->use_system_roots) return WING_TLS_ST_VERIFY_ERR;
    ep->st_ctx = g_st.SSLCreateContext(NULL, ST_SSL_CLIENT_SIDE, ST_SSL_STREAM_TYPE);
    if (ep->st_ctx == NULL) return WING_TLS_ST_ERR;
    if (g_st.SSLSetIOFuncs(ep->st_ctx, st_io_read, st_io_write) != ST_ERR_SUCCESS ||
        g_st.SSLSetConnection(ep->st_ctx, (const void *)ep) != ST_ERR_SUCCESS ||
        g_st.SSLSetProtocolVersionMin(ep->st_ctx, ST_TLS_PROTOCOL_12) != ST_ERR_SUCCESS) {
        st_cleanup_ep(ep);
        return WING_TLS_ST_ERR;
    }
    if (ep->sni[0] != '\0') {
        if (g_st.SSLSetPeerDomainName(ep->st_ctx, ep->sni, strlen(ep->sni)) != ST_ERR_SUCCESS) {
            st_cleanup_ep(ep);
            return WING_TLS_ST_ERR;
        }
    }
    if (ep->insecure_skip_verify) {
        (void)g_st.SSLSetSessionOption(ep->st_ctx, ST_OPT_BREAK_ON_SERVER_AUTH, 1);
    }
    return WING_TLS_ST_OK;
}

static int32_t st_step_hs(wing_tls_ep_t *ep) {
    if (ep->established) return WING_TLS_ST_OK;
    for (int i = 0; i < 4; i++) {
        st_osstatus_t st = g_st.SSLHandshake(ep->st_ctx);
        if (st == ST_ERR_PEER_AUTH_COMPLETED && ep->insecure_skip_verify) continue;
        if (st == ST_ERR_SUCCESS) {
            ep->established = 1;
            return WING_TLS_ST_OK;
        }
        return st_map_err(st, 1);
    }
    return WING_TLS_ST_WANT_READ;
}

static int64_t st_write_app(wing_tls_ep_t *ep, wing_tls_ro plain, int32_t *out_st) {
    size_t processed = 0;
    st_osstatus_t st = g_st.SSLWrite(ep->st_ctx, plain.data, (size_t)plain.len, &processed);
    if (processed > 0) {
        *out_st = WING_TLS_ST_OK;
        return (int64_t)processed;
    }
    *out_st = st_map_err(st, 0);
    return 0;
}

static int64_t st_read_app(wing_tls_ep_t *ep, wing_tls_rw dst, int32_t *out_st) {
    size_t processed = 0;
    st_osstatus_t st = g_st.SSLRead(ep->st_ctx, dst.data, (size_t)dst.len, &processed);
    if (processed > 0) {
        *out_st = WING_TLS_ST_OK;
        return (int64_t)processed;
    }
    if (st == ST_ERR_CLOSED_GRACEFUL || st == ST_ERR_CLOSED_NO_NOTIFY) ep->closed = 1;
    *out_st = st_map_err(st, 0);
    return 0;
}
#endif

/* ---- Public Exported C ABI for tls/backend.goose ----------------------- */

int32_t wing_tls_backend_available(int32_t kind) {
    if (kind == WING_TLS_KIND_PURE || kind == WING_TLS_KIND_AUTO) return 1;
    if (kind == WING_TLS_KIND_OPENSSL) return ossl_probe();
    if (kind == WING_TLS_KIND_SCHANNEL) return schannel_probe();
    if (kind == WING_TLS_KIND_SECURE_TRANSPORT) return secure_transport_probe();
    return 0;
}

static void wing_tls_ep_destroy(wing_tls_ep_t *ep) {
    if (ep == NULL) return;
    if (ep->kind == WING_TLS_KIND_OPENSSL) {
        ossl_cleanup_ep(ep);
    }
#ifdef _WIN32
    else if (ep->kind == WING_TLS_KIND_SCHANNEL) {
        if (ep->has_ctxt) g_sch.DeleteSecurityContext(&ep->ctxt);
        if (ep->has_cred) g_sch.FreeCredentialsHandle(&ep->cred);
        tls_buf_free(&ep->sch_in);
        tls_buf_free(&ep->sch_out);
        tls_buf_free(&ep->sch_app);
    }
#endif
#ifdef __APPLE__
    else if (ep->kind == WING_TLS_KIND_SECURE_TRANSPORT) {
        st_cleanup_ep(ep);
    }
#endif
#if !defined(_WIN32) && !defined(__wasm__)
    if (ep->io_lock_init) {
        pthread_mutex_destroy(&ep->io_lock);
        ep->io_lock_init = 0;
    }
#endif
    wing_tls_zeroize(ep, sizeof(*ep));
    free(ep);
}

int64_t wing_tls_backend_open(int32_t kind, int32_t is_server, int32_t insecure_skip_verify, int32_t min_version,
                              wing_tls_ro server_name, wing_tls_ro alpn_wire, wing_tls_ro ca_file,
                              wing_tls_ro cert_pem_file, wing_tls_ro key_pem_file, int32_t *out_status,
                              int32_t *out_active_kind) {
    int resolved = kind;
    int has_pem_files = (ca_file.len > 0) || (cert_pem_file.len > 0) || (key_pem_file.len > 0);
    if (kind == WING_TLS_KIND_AUTO) {
        if (ossl_probe())
            resolved = WING_TLS_KIND_OPENSSL;
        else if (!is_server && !has_pem_files && schannel_probe())
            resolved = WING_TLS_KIND_SCHANNEL;
        else if (!is_server && !has_pem_files && min_version == WING_TLS_MIN_TLS12 && secure_transport_probe()) {
            resolved = WING_TLS_KIND_SECURE_TRANSPORT;
        } else {
            *out_status = WING_TLS_ST_UNAVAILABLE;
            *out_active_kind = WING_TLS_KIND_PURE;
            return -1;
        }
    }

    wing_tls_ep_t *ep = (wing_tls_ep_t *)calloc(1, sizeof(wing_tls_ep_t));
    if (ep == NULL) {
        *out_status = WING_TLS_ST_ERR;
        return -1;
    }
#ifdef _WIN32
    InitializeSRWLock(&ep->io_lock);
#elif !defined(__wasm__)
    if (pthread_mutex_init(&ep->io_lock, NULL) != 0) {
        free(ep);
        *out_status = WING_TLS_ST_ERR;
        return -1;
    }
    ep->io_lock_init = 1;
#endif
    ep->in_use = 1;
    ep->closing = 0;
    ep->refcount = 0;
    ep->kind = resolved;
    ep->is_server = is_server ? 1 : 0;
    ep->insecure_skip_verify = (insecure_skip_verify & WING_TLS_FLAG_INSECURE_SKIP_VERIFY) != 0 ? 1 : 0;
    ep->use_system_roots = (insecure_skip_verify & WING_TLS_FLAG_NO_SYSTEM_ROOTS) == 0 ? 1 : 0;
    ep->no_session_tickets = (insecure_skip_verify & WING_TLS_FLAG_NO_SESSION_TICKETS) != 0 ? 1 : 0;
    ep->min_version = (min_version == WING_TLS_MIN_TLS12) ? WING_TLS_MIN_TLS12 : WING_TLS_MIN_TLS13;
    copy_cstr_ro(ep->sni, sizeof(ep->sni), server_name);
    copy_cstr_ro(ep->ca_file, sizeof(ep->ca_file), ca_file);
    copy_cstr_ro(ep->cert_pem_file, sizeof(ep->cert_pem_file), cert_pem_file);
    copy_cstr_ro(ep->key_pem_file, sizeof(ep->key_pem_file), key_pem_file);
    if (alpn_wire.data != NULL && alpn_wire.len > 0) {
        size_t n = (size_t)alpn_wire.len < 64 ? (size_t)alpn_wire.len : 64;
        memcpy(ep->alpn_wire, alpn_wire.data, n);
        ep->alpn_wire_len = n;
    }

    int st = WING_TLS_ST_UNAVAILABLE;
    if (resolved == WING_TLS_KIND_OPENSSL) st = ossl_open_ep(ep);
#ifdef _WIN32
    else if (resolved == WING_TLS_KIND_SCHANNEL)
        st = schannel_open_ep(ep);
#endif
#ifdef __APPLE__
    else if (resolved == WING_TLS_KIND_SECURE_TRANSPORT)
        st = st_open_ep(ep);
#endif
    if (st != WING_TLS_ST_OK) {
        wing_tls_ep_destroy(ep);
        *out_status = st;
        return -1;
    }

    int slot = -1;
    uint32_t gen = 0;
    eps_lock();
    for (int step = 0; step < WING_TLS_MAX_HANDLES; step++) {
        int i = (g_eps_cursor + step) % WING_TLS_MAX_HANDLES;
        if (g_eps[i] == NULL) {
            g_next_gen = (g_next_gen + 1U) & 0x7FFFFFFFU;
            if (g_next_gen == 0U) g_next_gen = 1U;
            gen = g_next_gen;
            ep->generation = gen;
            g_eps[i] = ep;
            g_eps_cursor = (i + 1) % WING_TLS_MAX_HANDLES;
            slot = i;
            break;
        }
    }
    eps_unlock();
    if (slot < 0) {
        wing_tls_ep_destroy(ep);
        *out_status = WING_TLS_ST_ERR;
        return -1;
    }
    *out_status = WING_TLS_ST_OK;
    *out_active_kind = resolved;
    return (int64_t)(((uint64_t)gen << 16) | (uint64_t)(slot + 1));
}

void wing_tls_backend_close(int64_t handle) {
    size_t slot = 0;
    uint32_t gen = 0;
    if (!decode_ep_handle(handle, &slot, &gen)) return;
    wing_tls_ep_t *ep = NULL;
    int should_destroy = 0;
    eps_lock();
    wing_tls_ep_t *cand = g_eps[slot];
    if (cand != NULL && cand->generation == gen) {
        g_eps[slot] = NULL;
        cand->closing = 1;
        ep = cand;
        if (ep->refcount == 0) should_destroy = 1;
    }
    eps_unlock();
    if (should_destroy) wing_tls_ep_destroy(ep);
}

int64_t wing_tls_backend_feed_wire(int64_t handle, wing_tls_ro ct, int32_t *out_status) {
    wing_tls_ep_t *ep = acquire_ep(handle);
    if (ep == NULL) {
        *out_status = WING_TLS_ST_CLOSED;
        return 0;
    }
    int64_t res = 0;
    int32_t st = WING_TLS_ST_UNAVAILABLE;
    ep_io_lock(ep);
    if (ep->closed) {
        st = WING_TLS_ST_CLOSED;
    } else if (ct.data == NULL || ct.len <= 0) {
        st = WING_TLS_ST_OK;
    } else if (ep->kind == WING_TLS_KIND_OPENSSL) {
        int n = g_ossl.BIO_write(ep->ossl_rbio, ct.data, clamp_i32(ct.len));
        st = (n >= 0) ? WING_TLS_ST_OK : WING_TLS_ST_ERR;
        res = n > 0 ? (int64_t)n : 0;
    }
#ifdef _WIN32
    else if (ep->kind == WING_TLS_KIND_SCHANNEL) {
        if (!tls_buf_append(&ep->sch_in, ct.data, (size_t)ct.len)) {
            st = WING_TLS_ST_ERR;
        } else {
            st = WING_TLS_ST_OK;
            res = ct.len;
        }
    }
#endif
#ifdef __APPLE__
    else if (ep->kind == WING_TLS_KIND_SECURE_TRANSPORT) {
        if (!tls_buf_append(&ep->st_in, ct.data, (size_t)ct.len)) {
            st = WING_TLS_ST_ERR;
        } else {
            st = WING_TLS_ST_OK;
            res = ct.len;
        }
    }
#endif
    ep_io_unlock(ep);
    release_ep(ep);
    *out_status = st;
    return res;
}

int64_t wing_tls_backend_drain_wire(int64_t handle, wing_tls_rw dst, int32_t *out_status) {
    wing_tls_ep_t *ep = acquire_ep(handle);
    if (ep == NULL) {
        *out_status = WING_TLS_ST_CLOSED;
        return 0;
    }
    int64_t res = 0;
    int32_t st = WING_TLS_ST_UNAVAILABLE;
    ep_io_lock(ep);
    if (dst.data == NULL || dst.len <= 0) {
        st = WING_TLS_ST_OK;
    } else if (ep->kind == WING_TLS_KIND_OPENSSL) {
        long pend = g_ossl.BIO_ctrl(ep->ossl_wbio, OSSL_BIO_CTRL_PENDING, 0, NULL);
        st = WING_TLS_ST_OK;
        if (pend > 0) {
            int n = g_ossl.BIO_read(ep->ossl_wbio, dst.data, clamp_i32(dst.len));
            res = n > 0 ? (int64_t)n : 0;
        }
    }
#ifdef _WIN32
    else if (ep->kind == WING_TLS_KIND_SCHANNEL) {
        st = WING_TLS_ST_OK;
        if (ep->sch_out.len > 0) {
            size_t take = ep->sch_out.len < (size_t)dst.len ? ep->sch_out.len : (size_t)dst.len;
            memcpy(dst.data, ep->sch_out.data, take);
            tls_buf_consume(&ep->sch_out, take);
            res = (int64_t)take;
        }
    }
#endif
#ifdef __APPLE__
    else if (ep->kind == WING_TLS_KIND_SECURE_TRANSPORT) {
        st = WING_TLS_ST_OK;
        if (ep->st_out.len > 0) {
            size_t take = ep->st_out.len < (size_t)dst.len ? ep->st_out.len : (size_t)dst.len;
            memcpy(dst.data, ep->st_out.data, take);
            tls_buf_consume(&ep->st_out, take);
            res = (int64_t)take;
        }
    }
#endif
    ep_io_unlock(ep);
    release_ep(ep);
    *out_status = st;
    return res;
}

int32_t wing_tls_backend_step_handshake(int64_t handle) {
    wing_tls_ep_t *ep = acquire_ep(handle);
    if (ep == NULL) return WING_TLS_ST_CLOSED;
    int32_t st = WING_TLS_ST_UNAVAILABLE;
    ep_io_lock(ep);
    if (ep->closed) {
        st = WING_TLS_ST_CLOSED;
    } else if (ep->established) {
        st = WING_TLS_ST_OK;
    } else if (ep->kind == WING_TLS_KIND_OPENSSL) {
        int r = g_ossl.SSL_do_handshake(ep->ossl_ssl);
        if (r == 1) {
            ep->established = 1;
            const unsigned char *alpn = NULL;
            unsigned int alen = 0;
            g_ossl.SSL_get0_alpn_selected(ep->ossl_ssl, &alpn, &alen);
            if (alpn != NULL && alen > 0) {
                size_t n = alen < 64 ? (size_t)alen : 64;
                memcpy(ep->selected_alpn, alpn, n);
                ep->selected_alpn_len = n;
            }
            st = WING_TLS_ST_OK;
        } else {
            st = ossl_map_err(ep, r, 1);
        }
    }
#ifdef _WIN32
    else if (ep->kind == WING_TLS_KIND_SCHANNEL) {
        st = schannel_step_hs(ep);
    }
#endif
#ifdef __APPLE__
    else if (ep->kind == WING_TLS_KIND_SECURE_TRANSPORT) {
        st = st_step_hs(ep);
    }
#endif
    ep_io_unlock(ep);
    release_ep(ep);
    return st;
}

int64_t wing_tls_backend_write_app(int64_t handle, wing_tls_ro plain, int32_t *out_status) {
    wing_tls_ep_t *ep = acquire_ep(handle);
    if (ep == NULL) {
        *out_status = WING_TLS_ST_CLOSED;
        return 0;
    }
    int64_t res = 0;
    int32_t st = WING_TLS_ST_UNAVAILABLE;
    ep_io_lock(ep);
    if (ep->closed) {
        st = WING_TLS_ST_CLOSED;
    } else if (!ep->established) {
        st = WING_TLS_ST_HS_ERR;
    } else if (plain.data == NULL || plain.len <= 0) {
        st = WING_TLS_ST_OK;
    } else if (ep->kind == WING_TLS_KIND_OPENSSL) {
        int n = g_ossl.SSL_write(ep->ossl_ssl, plain.data, clamp_i32(plain.len));
        if (n > 0) {
            st = WING_TLS_ST_OK;
            res = (int64_t)n;
        } else {
            st = ossl_map_err(ep, n, 0);
        }
    }
#ifdef _WIN32
    else if (ep->kind == WING_TLS_KIND_SCHANNEL) {
        res = schannel_write_app(ep, plain, &st);
    }
#endif
#ifdef __APPLE__
    else if (ep->kind == WING_TLS_KIND_SECURE_TRANSPORT) {
        res = st_write_app(ep, plain, &st);
    }
#endif
    ep_io_unlock(ep);
    release_ep(ep);
    *out_status = st;
    return res;
}

int64_t wing_tls_backend_read_app(int64_t handle, wing_tls_rw dst, int32_t *out_status) {
    wing_tls_ep_t *ep = acquire_ep(handle);
    if (ep == NULL) {
        *out_status = WING_TLS_ST_CLOSED;
        return 0;
    }
    int64_t res = 0;
    int32_t st = WING_TLS_ST_UNAVAILABLE;
    ep_io_lock(ep);
    if (ep->closed) {
        st = WING_TLS_ST_CLOSED;
    } else if (!ep->established) {
        st = WING_TLS_ST_HS_ERR;
    } else if (dst.data == NULL || dst.len <= 0) {
        st = WING_TLS_ST_OK;
    } else if (ep->kind == WING_TLS_KIND_OPENSSL) {
        int n = g_ossl.SSL_read(ep->ossl_ssl, dst.data, clamp_i32(dst.len));
        if (n > 0) {
            st = WING_TLS_ST_OK;
            res = (int64_t)n;
        } else {
            st = ossl_map_err(ep, n, 0);
        }
    }
#ifdef _WIN32
    else if (ep->kind == WING_TLS_KIND_SCHANNEL) {
        res = schannel_read_app(ep, dst, &st);
    }
#endif
#ifdef __APPLE__
    else if (ep->kind == WING_TLS_KIND_SECURE_TRANSPORT) {
        res = st_read_app(ep, dst, &st);
    }
#endif
    ep_io_unlock(ep);
    release_ep(ep);
    *out_status = st;
    return res;
}

int64_t wing_tls_backend_selected_alpn(int64_t handle, wing_tls_rw dst) {
    wing_tls_ep_t *ep = acquire_ep(handle);
    if (ep == NULL) return 0;
    int64_t res = 0;
    ep_io_lock(ep);
    if (dst.data != NULL && dst.len > 0 && ep->selected_alpn_len > 0) {
        size_t n = ep->selected_alpn_len < (size_t)dst.len ? ep->selected_alpn_len : (size_t)dst.len;
        memcpy(dst.data, ep->selected_alpn, n);
        res = (int64_t)n;
    }
    ep_io_unlock(ep);
    release_ep(ep);
    return res;
}

int32_t wing_tls_backend_is_established(int64_t handle) {
    wing_tls_ep_t *ep = acquire_ep(handle);
    if (ep == NULL) return 0;
    ep_io_lock(ep);
    int32_t res = (!ep->closed && ep->established) ? 1 : 0;
    ep_io_unlock(ep);
    release_ep(ep);
    return res;
}

int64_t wing_tls_backend_pending_wire(int64_t handle) {
    wing_tls_ep_t *ep = acquire_ep(handle);
    if (ep == NULL) return 0;
    int64_t res = 0;
    ep_io_lock(ep);
    if (!ep->closed) {
        if (ep->kind == WING_TLS_KIND_OPENSSL) {
            long pend = g_ossl.BIO_ctrl(ep->ossl_wbio, OSSL_BIO_CTRL_PENDING, 0, NULL);
            res = pend > 0 ? (int64_t)pend : 0;
        }
#ifdef _WIN32
        else if (ep->kind == WING_TLS_KIND_SCHANNEL) {
            res = (int64_t)ep->sch_out.len;
        }
#endif
#ifdef __APPLE__
        else if (ep->kind == WING_TLS_KIND_SECURE_TRANSPORT) {
            res = (int64_t)ep->st_out.len;
        }
#endif
    }
    ep_io_unlock(ep);
    release_ep(ep);
    return res;
}

int32_t wing_tls_backend_shutdown(int64_t handle) {
    wing_tls_ep_t *ep = acquire_ep(handle);
    if (ep == NULL) return WING_TLS_ST_CLOSED;
    int32_t st = WING_TLS_ST_OK;
    ep_io_lock(ep);
    if (ep->closed) {
        st = WING_TLS_ST_CLOSED;
    } else if (ep->established && ep->kind == WING_TLS_KIND_OPENSSL && g_ossl.SSL_shutdown != NULL) {
        int r = g_ossl.SSL_shutdown(ep->ossl_ssl);
        if (r < 0) st = ossl_map_err(ep, r, 0);
    }
    ep_io_unlock(ep);
    release_ep(ep);
    return st;
}

int32_t wing_tls_backend_set_keylog(int64_t handle, wing_tls_ro path) {
    wing_tls_ep_t *ep = acquire_ep(handle);
    if (ep == NULL) return WING_TLS_ST_CLOSED;
    int32_t st = WING_TLS_ST_OK;
    ep_io_lock(ep);
    if (ep->closed) {
        st = WING_TLS_ST_CLOSED;
    } else if (path.data == NULL || path.len <= 0) {
        wing_tls_zeroize(ep->keylog_file, sizeof(ep->keylog_file));
        if (ep->kind == WING_TLS_KIND_OPENSSL && ep->ossl_ctx != NULL && g_ossl.SSL_CTX_set_keylog_callback != NULL) {
            g_ossl.SSL_CTX_set_keylog_callback(ep->ossl_ctx, NULL);
        }
        st = WING_TLS_ST_OK;
    } else if (ep->kind == WING_TLS_KIND_OPENSSL) {
        if (ep->ossl_ctx == NULL || ep->ossl_ssl == NULL || g_ossl.SSL_CTX_set_keylog_callback == NULL ||
            g_ossl.SSL_set_ex_data == NULL || g_ossl.SSL_get_ex_data == NULL) {
            st = WING_TLS_ST_UNAVAILABLE;
        } else {
            copy_cstr_ro(ep->keylog_file, sizeof(ep->keylog_file), path);
            (void)g_ossl.SSL_set_ex_data(ep->ossl_ssl, 0, ep);
            g_ossl.SSL_CTX_set_keylog_callback(ep->ossl_ctx, ossl_keylog_cb);
            st = WING_TLS_ST_OK;
        }
    } else {
        st = WING_TLS_ST_UNAVAILABLE;
    }
    ep_io_unlock(ep);
    release_ep(ep);
    return st;
}

/* ---- OS System Root CA Lookup (Windows Crypt32 dynamic loader) --------- */

#ifdef _WIN32
typedef HCERTSTORE(WINAPI *pfn_CertOpenSystemStoreA)(HCRYPTPROV_LEGACY, LPCSTR);
typedef PCCERT_CONTEXT(WINAPI *pfn_CertEnumCertificatesInStore)(HCERTSTORE, PCCERT_CONTEXT);
typedef BOOL(WINAPI *pfn_CertCloseStore)(HCERTSTORE, DWORD);
typedef PCCERT_CONTEXT(WINAPI *pfn_CertFindCertificateInStore)(HCERTSTORE, DWORD, DWORD, DWORD, const void *,
                                                               PCCERT_CONTEXT);
typedef BOOL(WINAPI *pfn_CertFreeCertificateContext)(PCCERT_CONTEXT);
typedef BOOL(WINAPI *pfn_CertGetEnhancedKeyUsage)(PCCERT_CONTEXT, DWORD, PCERT_ENHKEY_USAGE, DWORD *);

typedef struct {
    int available;
    pfn_CertOpenSystemStoreA CertOpenSystemStoreA;
    pfn_CertEnumCertificatesInStore CertEnumCertificatesInStore;
    pfn_CertCloseStore CertCloseStore;
    pfn_CertFindCertificateInStore CertFindCertificateInStore;
    pfn_CertFreeCertificateContext CertFreeCertificateContext;
    pfn_CertGetEnhancedKeyUsage CertGetEnhancedKeyUsage;
} wing_crypt32_t;

static INIT_ONCE g_crypt32_once = INIT_ONCE_STATIC_INIT;
static wing_crypt32_t g_crypt32 = {0};

static BOOL CALLBACK crypt32_init_once_cb(PINIT_ONCE once, PVOID param, PVOID *ctx) {
    (void)once;
    (void)param;
    (void)ctx;
    HMODULE h = LoadLibraryA("crypt32.dll");
    if (h == NULL) return TRUE;
    if (!load_fn_sym(&g_crypt32.CertOpenSystemStoreA, GetProcAddress(h, "CertOpenSystemStoreA")) ||
        !load_fn_sym(&g_crypt32.CertEnumCertificatesInStore, GetProcAddress(h, "CertEnumCertificatesInStore")) ||
        !load_fn_sym(&g_crypt32.CertCloseStore, GetProcAddress(h, "CertCloseStore")) ||
        !load_fn_sym(&g_crypt32.CertFindCertificateInStore, GetProcAddress(h, "CertFindCertificateInStore")) ||
        !load_fn_sym(&g_crypt32.CertFreeCertificateContext, GetProcAddress(h, "CertFreeCertificateContext")) ||
        !load_fn_sym(&g_crypt32.CertGetEnhancedKeyUsage, GetProcAddress(h, "CertGetEnhancedKeyUsage"))) {
        FreeLibrary(h);
        return TRUE;
    }
    g_crypt32.available = 1;
    return TRUE;
}

static int crypt32_ensure_loaded(void) {
    InitOnceExecuteOnce(&g_crypt32_once, crypt32_init_once_cb, NULL, NULL);
    return g_crypt32.available;
}

static int crypt32_allows_server_auth(PCCERT_CONTEXT ctx) {
    DWORD cb = 0;
    if (!g_crypt32.CertGetEnhancedKeyUsage(ctx, 0, NULL, &cb)) {
        return GetLastError() == (DWORD)CRYPT_E_NOT_FOUND ? 1 : 0;
    }
    if (cb == 0) {
        return GetLastError() == (DWORD)CRYPT_E_NOT_FOUND ? 1 : 0;
    }
    uint8_t stack_buf[1024];
    uint8_t *buf = stack_buf;
    if (cb > sizeof(stack_buf)) {
        if (cb > 65536) return 0;
        buf = (uint8_t *)malloc(cb);
        if (buf == NULL) return 0;
    }
    int allowed = 0;
    if (g_crypt32.CertGetEnhancedKeyUsage(ctx, 0, (PCERT_ENHKEY_USAGE)buf, &cb)) {
        PCERT_ENHKEY_USAGE usage = (PCERT_ENHKEY_USAGE)buf;
        if (usage->cUsageIdentifier == 0) {
            allowed = (GetLastError() == (DWORD)CRYPT_E_NOT_FOUND) ? 1 : 0;
        } else {
            for (DWORD i = 0; i < usage->cUsageIdentifier; i++) {
                const char *oid = usage->rgpszUsageIdentifier[i];
                if (oid != NULL && (strcmp(oid, "1.3.6.1.5.5.7.3.1") == 0 || strcmp(oid, "2.5.29.37.0") == 0)) {
                    allowed = 1;
                    break;
                }
            }
        }
    }
    if (buf != stack_buf) free(buf);
    return allowed;
}

static int ossl_load_win_root_store(void *ssl_ctx) {
    if (ssl_ctx == NULL || g_ossl.SSL_CTX_get_cert_store == NULL || g_ossl.d2i_X509 == NULL ||
        g_ossl.X509_STORE_add_cert == NULL || g_ossl.X509_free == NULL || g_ossl.ERR_clear_error == NULL) {
        return 0;
    }
    if (!crypt32_ensure_loaded()) return 0;
    void *store = g_ossl.SSL_CTX_get_cert_store(ssl_ctx);
    if (store == NULL) return 0;
    HCERTSTORE hStore = g_crypt32.CertOpenSystemStoreA(0, "ROOT");
    if (hStore == NULL) return 0;
    HCERTSTORE hDisallowed = g_crypt32.CertOpenSystemStoreA(0, "Disallowed");

    int loaded = 0;
    PCCERT_CONTEXT ctx = NULL;
    while ((ctx = g_crypt32.CertEnumCertificatesInStore(hStore, ctx)) != NULL) {
        if ((ctx->dwCertEncodingType & X509_ASN_ENCODING) == 0) continue;
        if (ctx->pbCertEncoded == NULL || ctx->cbCertEncoded == 0) continue;
        if (hDisallowed != NULL) {
            PCCERT_CONTEXT hit =
                g_crypt32.CertFindCertificateInStore(hDisallowed, X509_ASN_ENCODING, 0, CERT_FIND_EXISTING, ctx, NULL);
            if (hit != NULL) {
                g_crypt32.CertFreeCertificateContext(hit);
                continue;
            }
        }
        if (!crypt32_allows_server_auth(ctx)) continue;
        const unsigned char *der = (const unsigned char *)ctx->pbCertEncoded;
        void *x509 = g_ossl.d2i_X509(NULL, &der, (long)ctx->cbCertEncoded);
        if (x509 != NULL) {
            if (g_ossl.X509_STORE_add_cert(store, x509) == 1) {
                loaded++;
            } else {
                g_ossl.ERR_clear_error();
            }
            g_ossl.X509_free(x509);
        } else {
            g_ossl.ERR_clear_error();
        }
    }
    if (hDisallowed != NULL) g_crypt32.CertCloseStore(hDisallowed, 0);
    g_crypt32.CertCloseStore(hStore, 0);
    return loaded;
}
#endif

/* Looks up trusted root CA certificates in the OS root store whose DER Subject
 * Name TLV equals `subject_der_tlv`, excluding certificates in Windows
 * `"Disallowed"` or restricted away from TLS ServerAuth EKU. Packs matches as
 * `[u32_be len][der]` into `out_buf` and stores bytes written in `*out_written`.
 * Returns matched count (>= 0) on native OS stores, or -1 on Unix/macOS where
 * Goose scans standard system PEM bundle paths instead. */
int32_t wing_tls_system_roots_by_subject(wing_tls_ro subject_der_tlv, wing_tls_rw out_buf, int32_t *out_written) {
    if (out_written != NULL) *out_written = 0;
    if (subject_der_tlv.data == NULL || subject_der_tlv.len <= 0 || out_buf.data == NULL || out_buf.len < 8) {
        return 0;
    }
#ifdef _WIN32
    if (!crypt32_ensure_loaded()) return -1;
    HCERTSTORE hStore = g_crypt32.CertOpenSystemStoreA(0, "ROOT");
    if (hStore == NULL) return -1;
    HCERTSTORE hDisallowed = g_crypt32.CertOpenSystemStoreA(0, "Disallowed");

    int32_t count = 0;
    size_t pos = 0;
    size_t cap = (size_t)out_buf.len;
    size_t target_len = (size_t)subject_der_tlv.len;
    PCCERT_CONTEXT ctx = NULL;
    while ((ctx = g_crypt32.CertEnumCertificatesInStore(hStore, ctx)) != NULL) {
        if (count >= 8) continue;
        if ((ctx->dwCertEncodingType & X509_ASN_ENCODING) == 0 || ctx->pCertInfo == NULL) continue;
        if (ctx->pCertInfo->Subject.pbData == NULL || ctx->pbCertEncoded == NULL) continue;
        if ((size_t)ctx->pCertInfo->Subject.cbData != target_len) continue;
        if (memcmp(ctx->pCertInfo->Subject.pbData, subject_der_tlv.data, target_len) != 0) continue;
        if (hDisallowed != NULL) {
            PCCERT_CONTEXT hit =
                g_crypt32.CertFindCertificateInStore(hDisallowed, X509_ASN_ENCODING, 0, CERT_FIND_EXISTING, ctx, NULL);
            if (hit != NULL) {
                g_crypt32.CertFreeCertificateContext(hit);
                continue;
            }
        }
        if (!crypt32_allows_server_auth(ctx)) continue;
        size_t der_len = (size_t)ctx->cbCertEncoded;
        if (der_len == 0 || der_len > 4096 || pos + 4 + der_len > cap) continue;
        out_buf.data[pos + 0] = (uint8_t)((der_len >> 24) & 0xFF);
        out_buf.data[pos + 1] = (uint8_t)((der_len >> 16) & 0xFF);
        out_buf.data[pos + 2] = (uint8_t)((der_len >> 8) & 0xFF);
        out_buf.data[pos + 3] = (uint8_t)(der_len & 0xFF);
        memcpy(out_buf.data + pos + 4, ctx->pbCertEncoded, der_len);
        pos += 4 + der_len;
        count++;
    }
    if (hDisallowed != NULL) g_crypt32.CertCloseStore(hDisallowed, 0);
    g_crypt32.CertCloseStore(hStore, 0);
    if (out_written != NULL) *out_written = (int32_t)pos;
    return count;
#else
    (void)subject_der_tlv;
    (void)out_buf;
    return -1;
#endif
}
