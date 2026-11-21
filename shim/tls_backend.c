// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Dynamically-loaded sans-IO TLS backend C shim for goose-wing.
// Loads OpenSSL/BoringSSL (cross-platform) and Windows Schannel (secur32.dll)
// at runtime with zero link-time OpenSSL or Secur32 library dependencies.

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

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
#elif !defined(__wasm__)
#include <dlfcn.h>
#endif

#define WING_TLS_KIND_PURE      0
#define WING_TLS_KIND_OPENSSL   1
#define WING_TLS_KIND_SCHANNEL  2
#define WING_TLS_KIND_AUTO      3

#define WING_TLS_ST_OK          0
#define WING_TLS_ST_WANT_READ   1
#define WING_TLS_ST_WANT_WRITE  2
#define WING_TLS_ST_CLOSED      3
#define WING_TLS_ST_UNAVAILABLE 4
#define WING_TLS_ST_HS_ERR      5
#define WING_TLS_ST_VERIFY_ERR  6
#define WING_TLS_ST_ERR         7

#define WING_TLS_MAX_HANDLES    64
#define WING_TLS_MAX_BUF_CAP    (4 * 1024 * 1024)

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
    for (size_t i = 0; i < len; i++) p[i] = 0;
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
        while (ncap < need) ncap *= 2;
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

/* ---- OpenSSL / BoringSSL Dynamic Driver -------------------------------- */

#define OSSL_SSL_ERROR_NONE        0
#define OSSL_SSL_ERROR_WANT_READ   2
#define OSSL_SSL_ERROR_WANT_WRITE  3
#define OSSL_SSL_ERROR_ZERO_RETURN 6
#define OSSL_SSL_VERIFY_NONE       0
#define OSSL_SSL_VERIFY_PEER       1
#define OSSL_CTRL_SET_SNI          55
#define OSSL_BIO_CTRL_PENDING      10

typedef struct {
    int probed;
    int available;
    const void *(*TLS_client_method)(void);
    const void *(*TLS_server_method)(void);
    void *(*SSL_CTX_new)(const void *);
    void (*SSL_CTX_free)(void *);
    int (*SSL_CTX_set_default_verify_paths)(void *);
    void (*SSL_CTX_set_verify)(void *, int, void *);
    void *(*SSL_new)(void *);
    void (*SSL_free)(void *);
    void (*SSL_set_connect_state)(void *);
    void (*SSL_set_accept_state)(void *);
    void (*SSL_set_bio)(void *, void *, void *);
    int (*SSL_do_handshake)(void *);
    int (*SSL_read)(void *, void *, int);
    int (*SSL_write)(void *, const void *, int);
    int (*SSL_get_error)(const void *, int);
    long (*SSL_ctrl)(void *, int, long, void *);
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
static void *dyn_open_any(const char *const *names) {
    for (size_t i = 0; names[i] != NULL; i++) {
#ifdef _WIN32
        HMODULE h = LoadLibraryA(names[i]);
        if (h != NULL) return (void *)h;
#else
        void *h = dlopen(names[i], RTLD_NOW | RTLD_LOCAL);
        if (h != NULL) return h;
#endif
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

static int ossl_probe(void) {
    if (g_ossl.probed) return g_ossl.available;
    g_ossl.probed = 1;
#ifdef _WIN32
    static const char *const ssl_names[] = {
        "libssl-3-x64.dll", "libssl-3.dll", "libssl-1_1-x64.dll", "libssl.dll", NULL
    };
    static const char *const cry_names[] = {
        "libcrypto-3-x64.dll", "libcrypto-3.dll", "libcrypto-1_1-x64.dll", "libcrypto.dll", NULL
    };
#elif defined(__APPLE__)
    static const char *const ssl_names[] = {
        "libssl.3.dylib", "libssl.dylib",
        "/opt/homebrew/opt/openssl@3/lib/libssl.3.dylib",
        "/usr/local/opt/openssl@3/lib/libssl.3.dylib", NULL
    };
    static const char *const cry_names[] = {
        "libcrypto.3.dylib", "libcrypto.dylib",
        "/opt/homebrew/opt/openssl@3/lib/libcrypto.3.dylib",
        "/usr/local/opt/openssl@3/lib/libcrypto.3.dylib", NULL
    };
#else
    static const char *const ssl_names[] = { "libssl.so.3", "libssl.so.1.1", "libssl.so", NULL };
    static const char *const cry_names[] = { "libcrypto.so.3", "libcrypto.so.1.1", "libcrypto.so", NULL };
#endif
    void *slib = dyn_open_any(ssl_names);
    if (slib == NULL) return 0;
    void *clib = dyn_open_any(cry_names);
    if (clib == NULL) clib = slib;

    int ok = 1;
    ok &= load_fn_sym(&g_ossl.TLS_client_method, dyn_sym(slib, "TLS_client_method"));
    ok &= load_fn_sym(&g_ossl.TLS_server_method, dyn_sym(slib, "TLS_server_method"));
    ok &= load_fn_sym(&g_ossl.SSL_CTX_new, dyn_sym(slib, "SSL_CTX_new"));
    ok &= load_fn_sym(&g_ossl.SSL_CTX_free, dyn_sym(slib, "SSL_CTX_free"));
    ok &= load_fn_sym(&g_ossl.SSL_CTX_set_default_verify_paths, dyn_sym(slib, "SSL_CTX_set_default_verify_paths"));
    ok &= load_fn_sym(&g_ossl.SSL_CTX_set_verify, dyn_sym(slib, "SSL_CTX_set_verify"));
    ok &= load_fn_sym(&g_ossl.SSL_new, dyn_sym(slib, "SSL_new"));
    ok &= load_fn_sym(&g_ossl.SSL_free, dyn_sym(slib, "SSL_free"));
    ok &= load_fn_sym(&g_ossl.SSL_set_connect_state, dyn_sym(slib, "SSL_set_connect_state"));
    ok &= load_fn_sym(&g_ossl.SSL_set_accept_state, dyn_sym(slib, "SSL_set_accept_state"));
    ok &= load_fn_sym(&g_ossl.SSL_set_bio, dyn_sym(slib, "SSL_set_bio"));
    ok &= load_fn_sym(&g_ossl.SSL_do_handshake, dyn_sym(slib, "SSL_do_handshake"));
    ok &= load_fn_sym(&g_ossl.SSL_read, dyn_sym(slib, "SSL_read"));
    ok &= load_fn_sym(&g_ossl.SSL_write, dyn_sym(slib, "SSL_write"));
    ok &= load_fn_sym(&g_ossl.SSL_get_error, dyn_sym(slib, "SSL_get_error"));
    ok &= load_fn_sym(&g_ossl.SSL_ctrl, dyn_sym(slib, "SSL_ctrl"));
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
    return g_ossl.available;
}
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

static int schannel_probe(void) {
    if (g_sch.probed) return g_sch.available;
    g_sch.probed = 1;
    static const char *const names[] = { "secur32.dll", "security.dll", NULL };
    void *lib = dyn_open_any(names);
    if (lib == NULL) return 0;
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
    return g_sch.available;
}
#else
static int schannel_probe(void) { return 0; }
#endif

/* ---- Unified Endpoint Handle Table ------------------------------------- */

typedef struct {
    int in_use;
    int kind;
    int is_server;
    int insecure_skip_verify;
    int established;
    int closed;
    char sni[257];
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
} wing_tls_ep_t;

static wing_tls_ep_t *g_eps[WING_TLS_MAX_HANDLES];

static wing_tls_ep_t *get_ep(int64_t handle) {
    if (handle < 1 || handle > WING_TLS_MAX_HANDLES) return NULL;
    wing_tls_ep_t *ep = g_eps[handle - 1];
    return (ep != NULL && ep->in_use) ? ep : NULL;
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

static int ossl_open_ep(wing_tls_ep_t *ep) {
    if (!ossl_probe()) return WING_TLS_ST_UNAVAILABLE;
    const void *meth = ep->is_server ? g_ossl.TLS_server_method() : g_ossl.TLS_client_method();
    if (meth == NULL) return WING_TLS_ST_ERR;
    ep->ossl_ctx = g_ossl.SSL_CTX_new(meth);
    if (ep->ossl_ctx == NULL) return WING_TLS_ST_ERR;
    if (ep->insecure_skip_verify) {
        g_ossl.SSL_CTX_set_verify(ep->ossl_ctx, OSSL_SSL_VERIFY_NONE, NULL);
    } else {
        (void)g_ossl.SSL_CTX_set_default_verify_paths(ep->ossl_ctx);
        g_ossl.SSL_CTX_set_verify(ep->ossl_ctx, OSSL_SSL_VERIFY_PEER, NULL);
    }
    ep->ossl_ssl = g_ossl.SSL_new(ep->ossl_ctx);
    ep->ossl_rbio = g_ossl.BIO_new(g_ossl.BIO_s_mem());
    ep->ossl_wbio = g_ossl.BIO_new(g_ossl.BIO_s_mem());
    if (ep->ossl_ssl == NULL || ep->ossl_rbio == NULL || ep->ossl_wbio == NULL) {
        if (ep->ossl_rbio != NULL && g_ossl.BIO_free != NULL) g_ossl.BIO_free(ep->ossl_rbio);
        if (ep->ossl_wbio != NULL && g_ossl.BIO_free != NULL) g_ossl.BIO_free(ep->ossl_wbio);
        if (ep->ossl_ssl != NULL) g_ossl.SSL_free(ep->ossl_ssl);
        g_ossl.SSL_CTX_free(ep->ossl_ctx);
        return WING_TLS_ST_ERR;
    }
    g_ossl.SSL_set_bio(ep->ossl_ssl, ep->ossl_rbio, ep->ossl_wbio);
    if (ep->is_server) {
        g_ossl.SSL_set_accept_state(ep->ossl_ssl);
    } else {
        g_ossl.SSL_set_connect_state(ep->ossl_ssl);
        if (ep->sni[0] != '\0') (void)g_ossl.SSL_ctrl(ep->ossl_ssl, OSSL_CTRL_SET_SNI, 0, ep->sni);
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
    SCHANNEL_CRED cred;
    memset(&cred, 0, sizeof(cred));
    cred.dwVersion = SCHANNEL_CRED_VERSION;
    cred.dwFlags = SCH_CRED_NO_DEFAULT_CREDS | SCH_USE_STRONG_CRYPTO;
    cred.dwFlags |= ep->insecure_skip_verify
        ? (SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_IGNORE_NO_REVOCATION_CHECK | SCH_CRED_IGNORE_REVOCATION_OFFLINE)
        : SCH_CRED_AUTO_CRED_VALIDATION;
    TimeStamp ts;
    SECURITY_STATUS ss = g_sch.AcquireCredentialsHandleA(
        NULL, (SEC_CHAR *)UNISP_NAME_A, SECPKG_CRED_OUTBOUND, NULL, &cred, NULL, NULL, &ep->cred, &ts);
    if (ss != SEC_E_OK) return WING_TLS_ST_HS_ERR;
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

    ULONG flags = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY |
                  ISC_REQ_EXTENDED_ERROR | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM;
    if (ep->insecure_skip_verify) flags |= ISC_REQ_MANUAL_CRED_VALIDATION;
    ULONG out_flags = 0;
    TimeStamp ts;
    SEC_CHAR *target = ep->sni[0] != '\0' ? (SEC_CHAR *)ep->sni : NULL;

    SECURITY_STATUS ss = g_sch.InitializeSecurityContextA(
        &ep->cred, ep->has_ctxt ? &ep->ctxt : NULL, target, flags, 0, 0,
        in_ptr, 0, &ep->ctxt, &out_desc, &out_flags, &ts);
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
    if (!ep->established || ep->stream_sizes.cbMaximumMessage == 0) { *out_st = WING_TLS_ST_ERR; return 0; }
    size_t chunk = (size_t)plain.len;
    if (chunk > ep->stream_sizes.cbMaximumMessage) chunk = ep->stream_sizes.cbMaximumMessage;
    size_t total = ep->stream_sizes.cbHeader + chunk + ep->stream_sizes.cbTrailer;
    uint8_t *msg = (uint8_t *)malloc(total);
    if (msg == NULL) { *out_st = WING_TLS_ST_ERR; return 0; }
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
    SecBufferDesc desc = { SECBUFFER_VERSION, 4, bufs };

    SECURITY_STATUS ss = g_sch.EncryptMessage(&ep->ctxt, 0, &desc, 0);
    int ok = (ss == SEC_E_OK) && tls_buf_append(
        &ep->sch_out, msg, (size_t)bufs[0].cbBuffer + bufs[1].cbBuffer + bufs[2].cbBuffer);
    wing_tls_zeroize(msg, total);
    free(msg);
    if (!ok) { *out_st = WING_TLS_ST_ERR; return 0; }
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
    if (ep->sch_in.len == 0) { *out_st = WING_TLS_ST_WANT_READ; return 0; }
    SecBuffer bufs[4];
    memset(bufs, 0, sizeof(bufs));
    bufs[0].BufferType = SECBUFFER_DATA;
    bufs[0].cbBuffer = (unsigned long)ep->sch_in.len;
    bufs[0].pvBuffer = ep->sch_in.data;
    bufs[1].BufferType = SECBUFFER_EMPTY;
    bufs[2].BufferType = SECBUFFER_EMPTY;
    bufs[3].BufferType = SECBUFFER_EMPTY;
    SecBufferDesc desc = { SECBUFFER_VERSION, 4, bufs };

    SECURITY_STATUS ss = g_sch.DecryptMessage(&ep->ctxt, &desc, 0, NULL);
    if (ss == SEC_E_INCOMPLETE_MESSAGE) { *out_st = WING_TLS_ST_WANT_READ; return 0; }
    if (ss == SEC_I_CONTEXT_EXPIRED) { ep->closed = 1; *out_st = WING_TLS_ST_CLOSED; return 0; }
    if (ss != SEC_E_OK) { *out_st = WING_TLS_ST_ERR; return 0; }

    size_t extra_len = 0;
    for (int i = 0; i < 4; i++) {
        if (bufs[i].BufferType == SECBUFFER_DATA && bufs[i].cbBuffer > 0) {
            (void)tls_buf_append(&ep->sch_app, (const uint8_t *)bufs[i].pvBuffer, bufs[i].cbBuffer);
        } else if (bufs[i].BufferType == SECBUFFER_EXTRA) {
            extra_len = bufs[i].cbBuffer;
        }
    }
    if (extra_len <= ep->sch_in.len) tls_buf_consume(&ep->sch_in, ep->sch_in.len - extra_len);
    if (ep->sch_app.len == 0) { *out_st = WING_TLS_ST_WANT_READ; return 0; }
    size_t take = ep->sch_app.len < (size_t)dst.len ? ep->sch_app.len : (size_t)dst.len;
    memcpy(dst.data, ep->sch_app.data, take);
    tls_buf_consume(&ep->sch_app, take);
    *out_st = WING_TLS_ST_OK;
    return (int64_t)take;
}
#endif

/* ---- Public Exported C ABI for tls/backend.goose ----------------------- */

int32_t wing_tls_backend_available(int32_t kind) {
    if (kind == WING_TLS_KIND_PURE || kind == WING_TLS_KIND_AUTO) return 1;
    if (kind == WING_TLS_KIND_OPENSSL) return ossl_probe();
    if (kind == WING_TLS_KIND_SCHANNEL) return schannel_probe();
    return 0;
}

int64_t wing_tls_backend_open(
    int32_t kind,
    int32_t is_server,
    int32_t insecure_skip_verify,
    wing_tls_ro server_name,
    wing_tls_ro alpn_wire,
    int32_t *out_status,
    int32_t *out_active_kind
) {
    int resolved = kind;
    if (kind == WING_TLS_KIND_AUTO) {
        if (ossl_probe()) resolved = WING_TLS_KIND_OPENSSL;
        else if (!is_server && schannel_probe()) resolved = WING_TLS_KIND_SCHANNEL;
        else { *out_status = WING_TLS_ST_UNAVAILABLE; *out_active_kind = WING_TLS_KIND_PURE; return -1; }
    }
    int slot = -1;
    for (int i = 0; i < WING_TLS_MAX_HANDLES; i++) {
        if (g_eps[i] == NULL) { slot = i; break; }
    }
    if (slot < 0) { *out_status = WING_TLS_ST_ERR; return -1; }

    wing_tls_ep_t *ep = (wing_tls_ep_t *)calloc(1, sizeof(wing_tls_ep_t));
    if (ep == NULL) { *out_status = WING_TLS_ST_ERR; return -1; }
    ep->in_use = 1;
    ep->kind = resolved;
    ep->is_server = is_server ? 1 : 0;
    ep->insecure_skip_verify = insecure_skip_verify ? 1 : 0;
    if (server_name.data != NULL && server_name.len > 0) {
        size_t n = (size_t)server_name.len < 256 ? (size_t)server_name.len : 256;
        memcpy(ep->sni, server_name.data, n);
        ep->sni[n] = '\0';
    }
    if (alpn_wire.data != NULL && alpn_wire.len > 0) {
        size_t n = (size_t)alpn_wire.len < 64 ? (size_t)alpn_wire.len : 64;
        memcpy(ep->alpn_wire, alpn_wire.data, n);
        ep->alpn_wire_len = n;
    }

    int st = WING_TLS_ST_UNAVAILABLE;
    if (resolved == WING_TLS_KIND_OPENSSL) st = ossl_open_ep(ep);
#ifdef _WIN32
    else if (resolved == WING_TLS_KIND_SCHANNEL) st = schannel_open_ep(ep);
#endif
    if (st != WING_TLS_ST_OK) {
        wing_tls_zeroize(ep, sizeof(*ep));
        free(ep);
        *out_status = st;
        return -1;
    }
    g_eps[slot] = ep;
    *out_status = WING_TLS_ST_OK;
    *out_active_kind = resolved;
    return (int64_t)(slot + 1);
}

void wing_tls_backend_close(int64_t handle) {
    wing_tls_ep_t *ep = get_ep(handle);
    if (ep == NULL) return;
    if (ep->kind == WING_TLS_KIND_OPENSSL) {
        if (ep->ossl_ssl != NULL) g_ossl.SSL_free(ep->ossl_ssl);
        if (ep->ossl_ctx != NULL) g_ossl.SSL_CTX_free(ep->ossl_ctx);
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
    g_eps[handle - 1] = NULL;
    wing_tls_zeroize(ep, sizeof(*ep));
    free(ep);
}

int64_t wing_tls_backend_feed_wire(int64_t handle, wing_tls_ro ct, int32_t *out_status) {
    wing_tls_ep_t *ep = get_ep(handle);
    if (ep == NULL || ep->closed) { *out_status = WING_TLS_ST_CLOSED; return 0; }
    if (ct.data == NULL || ct.len <= 0) { *out_status = WING_TLS_ST_OK; return 0; }
    if (ep->kind == WING_TLS_KIND_OPENSSL) {
        int n = g_ossl.BIO_write(ep->ossl_rbio, ct.data, clamp_i32(ct.len));
        *out_status = (n >= 0) ? WING_TLS_ST_OK : WING_TLS_ST_ERR;
        return n > 0 ? (int64_t)n : 0;
    }
#ifdef _WIN32
    if (ep->kind == WING_TLS_KIND_SCHANNEL) {
        if (!tls_buf_append(&ep->sch_in, ct.data, (size_t)ct.len)) { *out_status = WING_TLS_ST_ERR; return 0; }
        *out_status = WING_TLS_ST_OK;
        return ct.len;
    }
#endif
    *out_status = WING_TLS_ST_UNAVAILABLE;
    return 0;
}

int64_t wing_tls_backend_drain_wire(int64_t handle, wing_tls_rw dst, int32_t *out_status) {
    wing_tls_ep_t *ep = get_ep(handle);
    if (ep == NULL) { *out_status = WING_TLS_ST_CLOSED; return 0; }
    if (dst.data == NULL || dst.len <= 0) { *out_status = WING_TLS_ST_OK; return 0; }
    if (ep->kind == WING_TLS_KIND_OPENSSL) {
        long pend = g_ossl.BIO_ctrl(ep->ossl_wbio, OSSL_BIO_CTRL_PENDING, 0, NULL);
        if (pend <= 0) { *out_status = WING_TLS_ST_OK; return 0; }
        int n = g_ossl.BIO_read(ep->ossl_wbio, dst.data, clamp_i32(dst.len));
        *out_status = WING_TLS_ST_OK;
        return n > 0 ? (int64_t)n : 0;
    }
#ifdef _WIN32
    if (ep->kind == WING_TLS_KIND_SCHANNEL) {
        if (ep->sch_out.len == 0) { *out_status = WING_TLS_ST_OK; return 0; }
        size_t take = ep->sch_out.len < (size_t)dst.len ? ep->sch_out.len : (size_t)dst.len;
        memcpy(dst.data, ep->sch_out.data, take);
        tls_buf_consume(&ep->sch_out, take);
        *out_status = WING_TLS_ST_OK;
        return (int64_t)take;
    }
#endif
    *out_status = WING_TLS_ST_UNAVAILABLE;
    return 0;
}

int32_t wing_tls_backend_step_handshake(int64_t handle) {
    wing_tls_ep_t *ep = get_ep(handle);
    if (ep == NULL || ep->closed) return WING_TLS_ST_CLOSED;
    if (ep->established) return WING_TLS_ST_OK;
    if (ep->kind == WING_TLS_KIND_OPENSSL) {
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
            return WING_TLS_ST_OK;
        }
        return ossl_map_err(ep, r, 1);
    }
#ifdef _WIN32
    if (ep->kind == WING_TLS_KIND_SCHANNEL) return schannel_step_hs(ep);
#endif
    return WING_TLS_ST_UNAVAILABLE;
}

int64_t wing_tls_backend_write_app(int64_t handle, wing_tls_ro plain, int32_t *out_status) {
    wing_tls_ep_t *ep = get_ep(handle);
    if (ep == NULL || ep->closed) { *out_status = WING_TLS_ST_CLOSED; return 0; }
    if (!ep->established) { *out_status = WING_TLS_ST_HS_ERR; return 0; }
    if (plain.data == NULL || plain.len <= 0) { *out_status = WING_TLS_ST_OK; return 0; }
    if (ep->kind == WING_TLS_KIND_OPENSSL) {
        int n = g_ossl.SSL_write(ep->ossl_ssl, plain.data, clamp_i32(plain.len));
        if (n > 0) { *out_status = WING_TLS_ST_OK; return (int64_t)n; }
        *out_status = ossl_map_err(ep, n, 0);
        return 0;
    }
#ifdef _WIN32
    if (ep->kind == WING_TLS_KIND_SCHANNEL) return schannel_write_app(ep, plain, out_status);
#endif
    *out_status = WING_TLS_ST_UNAVAILABLE;
    return 0;
}

int64_t wing_tls_backend_read_app(int64_t handle, wing_tls_rw dst, int32_t *out_status) {
    wing_tls_ep_t *ep = get_ep(handle);
    if (ep == NULL || ep->closed) { *out_status = WING_TLS_ST_CLOSED; return 0; }
    if (!ep->established) { *out_status = WING_TLS_ST_HS_ERR; return 0; }
    if (dst.data == NULL || dst.len <= 0) { *out_status = WING_TLS_ST_OK; return 0; }
    if (ep->kind == WING_TLS_KIND_OPENSSL) {
        int n = g_ossl.SSL_read(ep->ossl_ssl, dst.data, clamp_i32(dst.len));
        if (n > 0) { *out_status = WING_TLS_ST_OK; return (int64_t)n; }
        *out_status = ossl_map_err(ep, n, 0);
        return 0;
    }
#ifdef _WIN32
    if (ep->kind == WING_TLS_KIND_SCHANNEL) return schannel_read_app(ep, dst, out_status);
#endif
    *out_status = WING_TLS_ST_UNAVAILABLE;
    return 0;
}

int64_t wing_tls_backend_selected_alpn(int64_t handle, wing_tls_rw dst) {
    wing_tls_ep_t *ep = get_ep(handle);
    if (ep == NULL || dst.data == NULL || dst.len <= 0 || ep->selected_alpn_len == 0) return 0;
    size_t n = ep->selected_alpn_len < (size_t)dst.len ? ep->selected_alpn_len : (size_t)dst.len;
    memcpy(dst.data, ep->selected_alpn, n);
    return (int64_t)n;
}

int32_t wing_tls_backend_is_established(int64_t handle) {
    wing_tls_ep_t *ep = get_ep(handle);
    return (ep != NULL && !ep->closed && ep->established) ? 1 : 0;
}
