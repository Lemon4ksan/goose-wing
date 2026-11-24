// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Statistical constant-time timing verifier (dudect,
// Reparaz/Balasch/Verbauwhede 2017) linked natively against goose-wing
// cryptographic primitives and shim/crypto_fusion.c.

#if defined(__linux__) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <time.h>
#endif

#include "../../shim/crypto_fusion.c"

#pragma pack(push, 1)
typedef struct {
  uint8_t *data;
  int64_t len;
} sl_u8;
#pragma pack(pop)

#ifdef __cplusplus
extern "C" {
#endif
void goose_init(int argc, char **argv);
uint8_t wing_dudect_ct_eq_bytes(sl_u8 a, sl_u8 b);
uint8_t wing_dudect_aes128_block(sl_u8 key, sl_u8 pt, sl_u8 out);
uint8_t wing_dudect_aes256_block(sl_u8 key, sl_u8 pt, sl_u8 out);
uint8_t wing_dudect_chacha20_poly1305(sl_u8 key, sl_u8 iv, sl_u8 pt, sl_u8 out);
uint8_t wing_dudect_x25519_scalarmult(sl_u8 scalar, sl_u8 point, sl_u8 out);
uint8_t wing_dudect_ecdsa_p256_sign(sl_u8 priv, sl_u8 msg, sl_u8 out);
uint8_t wing_dudect_ed25519_sign(sl_u8 seed, sl_u8 msg, sl_u8 out);
uint8_t wing_dudect_rsa_mod_exp(sl_u8 base, sl_u8 exp, sl_u8 mod_be, sl_u8 out);
uint8_t wing_dudect_p256_public_key(sl_u8 priv, sl_u8 out);
uint8_t wing_dudect_p256_ecdh(sl_u8 priv, sl_u8 peer_pub, sl_u8 out);
uint8_t wing_dudect_rsa_pss_sign_blinded(sl_u8 n_be, sl_u8 d_be, sl_u8 e_be,
                                         sl_u8 salt, sl_u8 msg, sl_u8 out);
uint8_t wing_dudect_mlkem768_keygen(sl_u8 d_seed, sl_u8 z_seed, sl_u8 ek_out,
                                    sl_u8 dk_out);
uint8_t wing_dudect_mlkem768_encaps(sl_u8 ek_in, sl_u8 m_seed, sl_u8 ct_out,
                                    sl_u8 ss_out);
uint8_t wing_dudect_mlkem768_decapsulate(sl_u8 ct, sl_u8 dk, sl_u8 ss_out);
#ifdef __cplusplus
}
#endif

static volatile uint8_t g_sink = 0;

static inline sl_u8 make_slice(uint8_t *ptr, int64_t len) {
  sl_u8 s;
  s.data = ptr;
  s.len = len;
  return s;
}

static uint64_t xorshift64(uint64_t *state) {
  uint64_t x = *state;
  x ^= x << 13;
  x ^= x >> 7;
  x ^= x << 17;
  *state = x;
  return x;
}

static void fill_random(uint64_t *rng, uint8_t *buf, size_t len) {
  for (size_t i = 0; i < len; i++) {
    buf[i] = (uint8_t)(xorshift64(rng) & 0xFFu);
  }
}

static inline uint64_t read_ticks_start(void) {
#if defined(__x86_64__) || defined(_M_X64)
  uint32_t lo = 0, hi = 0;
  __asm__ __volatile__("lfence\n\trdtsc" : "=a"(lo), "=d"(hi) : : "memory");
  return ((uint64_t)hi << 32) | (uint64_t)lo;
#elif defined(_WIN32)
  LARGE_INTEGER li;
  QueryPerformanceCounter(&li);
  return (uint64_t)li.QuadPart;
#else
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
#endif
}

static inline uint64_t read_ticks_end(void) {
#if defined(__x86_64__) || defined(_M_X64)
  uint32_t lo = 0, hi = 0, aux = 0;
  __asm__ __volatile__("rdtscp\n\tlfence"
                       : "=a"(lo), "=d"(hi), "=c"(aux)
                       :
                       : "memory");
  return ((uint64_t)hi << 32) | (uint64_t)lo;
#else
  return read_ticks_start();
#endif
}

typedef struct {
  double n[2];
  double mean[2];
  double m2[2];
} WelfordCtx;

static void welford_push(WelfordCtx *ctx, int cls, double x) {
  ctx->n[cls] += 1.0;
  double delta = x - ctx->mean[cls];
  ctx->mean[cls] += delta / ctx->n[cls];
  double delta2 = x - ctx->mean[cls];
  ctx->m2[cls] += delta * delta2;
}

static double welford_abs_t(const WelfordCtx *ctx) {
  if (ctx->n[0] < 10.0 || ctx->n[1] < 10.0) {
    return 0.0;
  }
  double diff = fabs(ctx->mean[0] - ctx->mean[1]);
  if (diff <= 1e-12) {
    return 0.0;
  }
  double var0 = ctx->m2[0] / (ctx->n[0] - 1.0);
  double var1 = ctx->m2[1] / (ctx->n[1] - 1.0);
  double denom = sqrt((var0 / ctx->n[0]) + (var1 / ctx->n[1]));
  if (denom <= 1e-12) {
    return 0.0;
  }
  return diff / denom;
}

static int cmp_u64(const void *a, const void *b) {
  uint64_t va = *(const uint64_t *)a;
  uint64_t vb = *(const uint64_t *)b;
  return (va > vb) - (va < vb);
}

typedef struct {
  double abs_t;
  double mean0;
  double mean1;
  size_t n0;
  size_t n1;
} DudectResult;

static DudectResult compute_cropped_welch(const uint8_t *classes,
                                          const uint64_t *ticks, size_t n) {
  DudectResult out;
  memset(&out, 0, sizeof(out));
  uint64_t *sorted = (uint64_t *)malloc(n * sizeof(uint64_t));
  if (!sorted) {
    return out;
  }
  memcpy(sorted, ticks, n * sizeof(uint64_t));
  qsort(sorted, n, sizeof(uint64_t), cmp_u64);
  uint64_t lo = sorted[n / 100];
  uint64_t hi = sorted[(n * 85) / 100];
  free(sorted);

  WelfordCtx ctx;
  memset(&ctx, 0, sizeof(ctx));
  for (size_t i = 0; i < n; i++) {
    if (ticks[i] >= lo && ticks[i] <= hi) {
      welford_push(&ctx, classes[i] & 1u, (double)ticks[i]);
    }
  }
  out.abs_t = welford_abs_t(&ctx);
  out.mean0 = ctx.mean[0];
  out.mean1 = ctx.mean[1];
  out.n0 = (size_t)ctx.n[0];
  out.n1 = (size_t)ctx.n[1];
  return out;
}

#define POOL_SLOTS 32

typedef struct {
  uint8_t eq_a[64];
  uint8_t eq_b[64];
  uint8_t aes128_k[16];
  uint8_t aes256_k[32];
  uint8_t aes_pt[16];
  uint8_t gcm_iv[12];
  uint8_t gcm_aad[16];
  uint8_t gcm_pt[64];
  uint8_t x25519_s[32];
  uint8_t x25519_p[32];
  uint8_t ecdsa_priv[32];
  uint8_t ed_seed[32];
  uint8_t msg[32];
  uint8_t rsa_base[64];
  uint8_t rsa_exp[64];
  uint8_t rsa_d2048[256];
  uint8_t rsa_salt32[32];
  uint8_t mlkem_ct[1088];
} ClassSlot;

typedef struct {
  ClassSlot c0[POOL_SLOTS];
  ClassSlot c1[POOL_SLOTS];
  uint8_t rsa_mod[64];
  uint8_t rsa_n2048[256];
  uint8_t rsa_e3[1];
  uint8_t p256_peer_pub[65];
  uint8_t mlkem_ek[1184];
  uint8_t mlkem_dk[2400];
  uint8_t out[512];
} DudectFixtures;

static int init_fixtures(DudectFixtures *f, uint64_t *rng) {
  memset(f, 0, sizeof(*f));
  memset(f->rsa_mod, 0xFF, sizeof(f->rsa_mod));
  f->rsa_mod[63] = 0xEF;
  memset(f->rsa_n2048, 0xFF, sizeof(f->rsa_n2048));
  f->rsa_n2048[253] = 0xE2;
  f->rsa_n2048[254] = 0x5C;
  f->rsa_n2048[255] = 0xEF;
  f->rsa_e3[0] = 0x03;

  uint8_t peer_priv[32];
  for (int i = 0; i < 32; i++) {
    peer_priv[i] = (uint8_t)(0x41 + i);
  }
  if (!wing_dudect_p256_public_key(make_slice(peer_priv, 32),
                                   make_slice(f->p256_peer_pub, 65))) {
    return 0;
  }

  uint8_t d_seed[32], z_seed[32], m_seed[32], ct_valid[1088], ss_tmp[32];
  memset(d_seed, 0x11, sizeof(d_seed));
  memset(z_seed, 0x22, sizeof(z_seed));
  memset(m_seed, 0x33, sizeof(m_seed));
  if (!wing_dudect_mlkem768_keygen(
          make_slice(d_seed, 32), make_slice(z_seed, 32),
          make_slice(f->mlkem_ek, 1184), make_slice(f->mlkem_dk, 2400))) {
    return 0;
  }
  if (!wing_dudect_mlkem768_encaps(
          make_slice(f->mlkem_ek, 1184), make_slice(m_seed, 32),
          make_slice(ct_valid, 1088), make_slice(ss_tmp, 32))) {
    return 0;
  }

  for (int i = 0; i < POOL_SLOTS; i++) {
    ClassSlot *a = &f->c0[i];
    ClassSlot *b = &f->c1[i];
    memset(a->eq_a, 0x5A, 64);
    memset(a->eq_b, 0x5A, 64);
    memset(b->eq_a, 0x5A, 64);
    memset(b->eq_b, 0x5A, 64);
    b->eq_b[0] ^= 0x01;

    a->x25519_p[0] = 9;
    b->x25519_p[0] = 9;
    a->ecdsa_priv[31] = 1;
    a->rsa_base[0] = 0x12;
    a->rsa_base[63] = 0x34;
    a->rsa_exp[0] = 0x80;
    a->rsa_exp[63] = 0x01;
    memset(a->rsa_d2048, 0xAA, 256);
    a->rsa_d2048[253] = 0x96;
    a->rsa_d2048[254] = 0xE8;
    a->rsa_d2048[255] = 0x9F;
    memset(a->rsa_salt32, 0x42, 32);
    memcpy(a->mlkem_ct, ct_valid, 1088);

    fill_random(rng, b->aes128_k, 16);
    fill_random(rng, b->aes256_k, 32);
    fill_random(rng, b->aes_pt, 16);
    fill_random(rng, b->gcm_iv, 12);
    fill_random(rng, b->gcm_aad, 16);
    fill_random(rng, b->gcm_pt, 64);
    fill_random(rng, b->x25519_s, 32);
    fill_random(rng, b->ecdsa_priv, 32);
    b->ecdsa_priv[0] &= 0x7Fu;
    b->ecdsa_priv[31] |= 0x01u;
    fill_random(rng, b->ed_seed, 32);
    fill_random(rng, b->msg, 32);
    fill_random(rng, b->rsa_base, 64);
    b->rsa_base[0] &= 0x7Fu;
    fill_random(rng, b->rsa_exp, 64);
    b->rsa_exp[0] |= 0x80u;
    b->rsa_exp[63] |= 0x01u;
    fill_random(rng, b->rsa_d2048, 256);
    b->rsa_d2048[0] |= 0x80u;
    b->rsa_d2048[255] |= 0x01u;
    fill_random(rng, b->rsa_salt32, 32);
    memcpy(b->mlkem_ct, ct_valid, 1088);
    b->mlkem_ct[(size_t)(i * 31) % 1088] ^= 0x80u;
  }
  return 1;
}

typedef uint8_t (*TargetFn)(DudectFixtures *f, ClassSlot *slot);

static uint8_t run_ct_eq_bytes(DudectFixtures *f, ClassSlot *s) {
  (void)f;
  uint8_t acc = 0;
  for (int i = 0; i < 32; i++) {
    acc ^= wing_dudect_ct_eq_bytes(make_slice(s->eq_a, 64),
                                   make_slice(s->eq_b, 64));
  }
  return acc;
}

static uint8_t run_aes128_block(DudectFixtures *f, ClassSlot *s) {
  uint8_t acc = 0;
  for (int i = 0; i < 8; i++) {
    acc ^= wing_dudect_aes128_block(make_slice(s->aes128_k, 16),
                                    make_slice(s->aes_pt, 16),
                                    make_slice(f->out, 16));
  }
  return acc;
}

static uint8_t run_aes256_block(DudectFixtures *f, ClassSlot *s) {
  uint8_t acc = 0;
  for (int i = 0; i < 8; i++) {
    acc ^= wing_dudect_aes256_block(make_slice(s->aes256_k, 32),
                                    make_slice(s->aes_pt, 16),
                                    make_slice(f->out, 16));
  }
  return acc;
}

static uint8_t run_aes_gcm_seal_scalar(DudectFixtures *f, ClassSlot *s) {
  uint8_t tag[16];
  int64_t n = wing_aes_gcm_seal_scalar(s->aes128_k, 16, s->gcm_iv, s->gcm_pt,
                                       64, s->gcm_aad, 16, f->out, tag);
  return (uint8_t)(tag[0] ^ (uint8_t)n);
}

static uint8_t run_chacha20_poly1305(DudectFixtures *f, ClassSlot *s) {
  uint8_t acc = 0;
  for (int i = 0; i < 4; i++) {
    acc ^= wing_dudect_chacha20_poly1305(
        make_slice(s->aes256_k, 32), make_slice(s->gcm_iv, 12),
        make_slice(s->gcm_pt, 64), make_slice(f->out, 80));
  }
  return acc;
}

static uint8_t run_x25519_scalarmult(DudectFixtures *f, ClassSlot *s) {
  return wing_dudect_x25519_scalarmult(make_slice(s->x25519_s, 32),
                                       make_slice(s->x25519_p, 32),
                                       make_slice(f->out, 32));
}

static uint8_t run_ecdsa_p256_sign(DudectFixtures *f, ClassSlot *s) {
  return wing_dudect_ecdsa_p256_sign(make_slice(s->ecdsa_priv, 32),
                                     make_slice(s->msg, 32),
                                     make_slice(f->out, 64));
}

static uint8_t run_ed25519_sign(DudectFixtures *f, ClassSlot *s) {
  return wing_dudect_ed25519_sign(make_slice(s->ed_seed, 32),
                                  make_slice(s->msg, 32),
                                  make_slice(f->out, 64));
}

static uint8_t run_rsa_mod_exp(DudectFixtures *f, ClassSlot *s) {
  return wing_dudect_rsa_mod_exp(
      make_slice(s->rsa_base, 64), make_slice(s->rsa_exp, 64),
      make_slice(f->rsa_mod, 64), make_slice(f->out, 64));
}

static uint8_t run_p256_ecdh(DudectFixtures *f, ClassSlot *s) {
  return wing_dudect_p256_ecdh(make_slice(s->ecdsa_priv, 32),
                               make_slice(f->p256_peer_pub, 65),
                               make_slice(f->out, 32));
}

static uint8_t run_rsa_pss_sign_blinded(DudectFixtures *f, ClassSlot *s) {
  return wing_dudect_rsa_pss_sign_blinded(
      make_slice(f->rsa_n2048, 256), make_slice(s->rsa_d2048, 256),
      make_slice(f->rsa_e3, 1), make_slice(s->rsa_salt32, 32),
      make_slice(s->msg, 32), make_slice(f->out, 256));
}

static uint8_t run_mlkem768_decapsulate(DudectFixtures *f, ClassSlot *s) {
  return wing_dudect_mlkem768_decapsulate(make_slice(s->mlkem_ct, 1088),
                                          make_slice(f->mlkem_dk, 2400),
                                          make_slice(f->out, 32));
}

typedef struct {
  const char *name;
  TargetFn fn;
  size_t sample_cap;
} TargetSpec;

static const TargetSpec g_targets[] = {
    {"ct_eq_bytes", run_ct_eq_bytes, 0},
    {"aes128_encrypt_block", run_aes128_block, 0},
    {"aes_encrypt_block", run_aes256_block, 0},
    {"wing_aes_gcm_seal_scalar", run_aes_gcm_seal_scalar, 0},
    {"chacha20_poly1305", run_chacha20_poly1305, 0},
    {"x25519_scalarmult", run_x25519_scalarmult, 0},
    {"ecdsa_p256_sign", run_ecdsa_p256_sign, 0},
    {"p256_ecdh_shared_secret", run_p256_ecdh, 0},
    {"ed25519_sign", run_ed25519_sign, 0},
    {"rsa_mod_exp", run_rsa_mod_exp, 0},
    {"rsa_pss_sha256_sign_blinded", run_rsa_pss_sign_blinded, 2000},
    {"mlkem768_decapsulate", run_mlkem768_decapsulate, 0},
};

static int measure_target(const TargetSpec *spec, DudectFixtures *f,
                          size_t req_samples, double threshold, int max_retries,
                          uint64_t *rng) {
  size_t samples = (spec->sample_cap > 0 && req_samples > spec->sample_cap)
                       ? spec->sample_cap
                       : req_samples;
  uint8_t *classes = (uint8_t *)malloc(samples);
  uint64_t *ticks = (uint64_t *)malloc(samples * sizeof(uint64_t));
  if (!classes || !ticks) {
    free(classes);
    free(ticks);
    fprintf(stderr, "ERROR: allocation failed for %s\n", spec->name);
    return 0;
  }

  size_t warmup = samples / 10;
  if (warmup < 32) {
    warmup = 32;
  }
  if (warmup > 500) {
    warmup = 500;
  }

  DudectResult res;
  memset(&res, 0, sizeof(res));
  int passed = 0;
  int attempt = 0;

  for (attempt = 1; attempt <= max_retries; attempt++) {
    for (size_t i = 0; i < warmup; i++) {
      ClassSlot *s = (i & 1u) ? &f->c1[i & (POOL_SLOTS - 1)]
                              : &f->c0[i & (POOL_SLOTS - 1)];
      g_sink ^= spec->fn(f, s);
    }
    for (size_t i = 0; i < samples; i++) {
      uint8_t cls = (uint8_t)(xorshift64(rng) & 1u);
      classes[i] = cls;
      ClassSlot *s =
          cls ? &f->c1[i & (POOL_SLOTS - 1)] : &f->c0[i & (POOL_SLOTS - 1)];
      uint64_t t0 = read_ticks_start();
      uint8_t v = spec->fn(f, s);
      uint64_t t1 = read_ticks_end();
      g_sink ^= v;
      ticks[i] = (t1 >= t0) ? (t1 - t0) : 0u;
    }
    res = compute_cropped_welch(classes, ticks, samples);
    if (res.abs_t < threshold) {
      passed = 1;
      break;
    }
  }

  printf("DUDECT\t%s\t%s\t%.4f\t%.2f\t%.2f\t%zu\t%zu\t%d\n", spec->name,
         passed ? "PASS" : "FAIL", res.abs_t, res.mean0, res.mean1, res.n0,
         res.n1, attempt);
  fflush(stdout);
  free(classes);
  free(ticks);
  return passed;
}

int main(int argc, char **argv) {
  size_t samples = 6000;
  double threshold = 4.5;
  int max_retries = 1;
  uint64_t seed = 0x5EED1234CAFEBEEFULL;
  const char *only = NULL;

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--samples") == 0 && i + 1 < argc) {
      long long v = strtoll(argv[++i], NULL, 10);
      if (v >= 100 && v <= 1000000) {
        samples = (size_t)v;
      }
    } else if (strcmp(argv[i], "--threshold") == 0 && i + 1 < argc) {
      threshold = strtod(argv[++i], NULL);
    } else if (strcmp(argv[i], "--retries") == 0 && i + 1 < argc) {
      int r = (int)strtol(argv[++i], NULL, 10);
      if (r >= 1 && r <= 10) {
        max_retries = r;
      }
    } else if (strcmp(argv[i], "--seed") == 0 && i + 1 < argc) {
      seed = strtoull(argv[++i], NULL, 10);
    } else if (strcmp(argv[i], "--only") == 0 && i + 1 < argc) {
      only = argv[++i];
    }
  }

  goose_init(argc, argv);
  DudectFixtures *fixtures = (DudectFixtures *)malloc(sizeof(DudectFixtures));
  if (!fixtures || !init_fixtures(fixtures, &seed)) {
    fprintf(stderr, "ERROR: failed to initialize dudect crypto fixtures\n");
    free(fixtures);
    return 2;
  }

  int all_ok = 1;
  size_t count = sizeof(g_targets) / sizeof(g_targets[0]);
  for (size_t i = 0; i < count; i++) {
    if (only && strcmp(only, g_targets[i].name) != 0) {
      continue;
    }
    if (!measure_target(&g_targets[i], fixtures, samples, threshold,
                        max_retries, &seed)) {
      all_ok = 0;
    }
  }
  free(fixtures);
  return all_ok ? 0 : 1;
}
