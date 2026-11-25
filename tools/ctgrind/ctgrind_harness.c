// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// ctgrind / TIMECOP Valgrind taint harness for goose-wing cryptographic
// primitives. Marks secret keys, scalars, nonces, and plaintexts as
// Valgrind-UNDEFINED prior to executing each primitive so Valgrind memcheck
// flags any secret-dependent branch or secret-indexed memory access with exit
// code 42.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__has_include)
#if __has_include(<valgrind/memcheck.h>)
#include <valgrind/memcheck.h>
#define WING_HAS_VALGRIND 1
#endif
#elif defined(USE_VALGRIND)
#include <valgrind/memcheck.h>
#define WING_HAS_VALGRIND 1
#endif

#if defined(WING_HAS_VALGRIND)
#define CT_POISON(ptr, len) ((void)VALGRIND_MAKE_MEM_UNDEFINED((ptr), (len)))
#define CT_UNPOISON(ptr, len) ((void)VALGRIND_MAKE_MEM_DEFINED((ptr), (len)))
#else
#define CT_POISON(ptr, len)                                                    \
  do {                                                                         \
    (void)(ptr);                                                               \
    (void)(len);                                                               \
  } while (0)
#define CT_UNPOISON(ptr, len)                                                  \
  do {                                                                         \
    (void)(ptr);                                                               \
    (void)(len);                                                               \
  } while (0)
#endif

#include "../../shim/crypto_fusion.c"

#if defined(WING_CTGRIND_VALGRIND)
void wing_ct_declassify(wing_slice s) {
  if (s.ptr && s.len > 0) {
    CT_UNPOISON(s.ptr, (size_t)s.len);
  }
}

uint8_t wing_ct_declassify_u8(uint8_t v) {
  volatile uint8_t tmp = v;
  CT_UNPOISON(&tmp, sizeof(tmp));
  return tmp;
}
#endif

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
uint8_t wing_ctgrind_ct_eq_bytes(sl_u8 a, sl_u8 b);
uint8_t wing_ctgrind_aes128_block(sl_u8 key, sl_u8 pt, sl_u8 out);
uint8_t wing_ctgrind_aes256_block(sl_u8 key, sl_u8 pt, sl_u8 out);
uint8_t wing_ctgrind_chacha20_poly1305(sl_u8 key, sl_u8 iv, sl_u8 pt,
                                       sl_u8 out);
uint8_t wing_ctgrind_x25519_scalarmult(sl_u8 scalar, sl_u8 point, sl_u8 out);
uint8_t wing_ctgrind_ecdsa_p256_sign(sl_u8 priv, sl_u8 msg, sl_u8 out);
uint8_t wing_ctgrind_ed25519_sign(sl_u8 seed, sl_u8 msg, sl_u8 out);
uint8_t wing_ctgrind_rsa_mod_exp(sl_u8 base, sl_u8 exp, sl_u8 mod_be,
                                 sl_u8 out);
uint8_t wing_ctgrind_p256_public_key(sl_u8 priv, sl_u8 out);
uint8_t wing_ctgrind_p256_ecdh(sl_u8 priv, sl_u8 peer_pub, sl_u8 out);
uint8_t wing_ctgrind_rsa_pss_sign_blinded(sl_u8 n_be, sl_u8 d_be, sl_u8 e_be,
                                          sl_u8 salt, sl_u8 msg, sl_u8 out);
uint8_t wing_ctgrind_rsa_pss_verify(sl_u8 n_be, sl_u8 e_be, sl_u8 msg,
                                    sl_u8 sig);
uint8_t wing_ctgrind_mlkem768_keygen(sl_u8 d_seed, sl_u8 z_seed, sl_u8 ek_out,
                                     sl_u8 dk_out);
uint8_t wing_ctgrind_mlkem768_encaps(sl_u8 ek_in, sl_u8 m_seed, sl_u8 ct_out,
                                     sl_u8 ss_out);
uint8_t wing_ctgrind_mlkem768_decapsulate(sl_u8 ct, sl_u8 dk, sl_u8 ss_out);
uint8_t wing_ctgrind_ecdsa_p384_sign(sl_u8 priv, sl_u8 msg, sl_u8 out);
uint8_t wing_ctgrind_p384_public_key(sl_u8 priv, sl_u8 out);
uint8_t wing_ctgrind_p384_ecdh(sl_u8 priv, sl_u8 peer_pub, sl_u8 out);
uint8_t wing_ctgrind_rsa_pkcs1_sha256_sign(sl_u8 n_be, sl_u8 d_be, sl_u8 msg,
                                           sl_u8 out);
uint8_t wing_ctgrind_rsa_pss_sha256_sign(sl_u8 n_be, sl_u8 d_be, sl_u8 salt,
                                         sl_u8 msg, sl_u8 out);
uint8_t wing_ctgrind_rsa_pss_sha512_sign(sl_u8 n_be, sl_u8 d_be, sl_u8 salt,
                                         sl_u8 msg, sl_u8 out);
uint8_t wing_ctgrind_xchacha20_poly1305(sl_u8 key, sl_u8 iv, sl_u8 pt,
                                        sl_u8 out);
uint8_t wing_ctgrind_hmac_hkdf_sha256(sl_u8 key, sl_u8 salt, sl_u8 info,
                                      sl_u8 out);
#ifdef __cplusplus
}
#endif

static inline sl_u8 make_slice(uint8_t *ptr, int64_t len) {
  sl_u8 s;
  s.data = ptr;
  s.len = len;
  return s;
}

static int test_aes_gcm_scalar(void) {
  uint8_t key[16] = {0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
                     0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08};
  uint8_t iv[12] = {0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce,
                    0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88};
  uint8_t aad[20] = {0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe,
                     0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad,
                     0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2};
  uint8_t pt[16] = {0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5,
                    0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a};
  uint8_t ct[16] = {0};
  uint8_t tag[16] = {0};
  const uint8_t exp_ct[16] = {0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24,
                              0x4b, 0x72, 0x21, 0xb7, 0x84, 0xd0, 0xd4, 0x9c};

  CT_POISON(key, sizeof(key));
  CT_POISON(iv, sizeof(iv));
  CT_POISON(pt, sizeof(pt));
  int64_t n = wing_aes_gcm_seal_scalar(key, 16, iv, pt, 16, aad, 20, ct, tag);
  CT_UNPOISON(ct, sizeof(ct));
  CT_UNPOISON(tag, sizeof(tag));
  CT_UNPOISON(key, sizeof(key));
  CT_UNPOISON(iv, sizeof(iv));
  CT_UNPOISON(pt, sizeof(pt));
  return (n == 16 && memcmp(ct, exp_ct, 16) == 0);
}

static int test_ct_eq_bytes(void) {
  uint8_t a[32];
  uint8_t b[32];
  uint8_t c[32];
  memset(a, 0x5A, sizeof(a));
  memset(b, 0x5A, sizeof(b));
  memset(c, 0x5A, sizeof(c));
  c[17] ^= 0x80u;

  CT_POISON(a, sizeof(a));
  CT_POISON(b, sizeof(b));
  CT_POISON(c, sizeof(c));
  uint8_t eq_same =
      wing_ctgrind_ct_eq_bytes(make_slice(a, 32), make_slice(b, 32));
  uint8_t eq_diff =
      wing_ctgrind_ct_eq_bytes(make_slice(a, 32), make_slice(c, 32));
  CT_UNPOISON(&eq_same, sizeof(eq_same));
  CT_UNPOISON(&eq_diff, sizeof(eq_diff));
  CT_UNPOISON(a, sizeof(a));
  CT_UNPOISON(b, sizeof(b));
  CT_UNPOISON(c, sizeof(c));
  return (eq_same == 1u && eq_diff == 0u);
}

static int test_aes_blocks(void) {
  uint8_t k128[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                      0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
  uint8_t k256[32];
  for (int i = 0; i < 32; i++) {
    k256[i] = (uint8_t)i;
  }
  uint8_t pt[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
  const uint8_t exp128[16] = {0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
                              0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a};
  const uint8_t exp256[16] = {0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf,
                              0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89};
  uint8_t out128[16] = {0};
  uint8_t out256[16] = {0};

  CT_POISON(k128, sizeof(k128));
  CT_POISON(pt, sizeof(pt));
  uint8_t ok1 = wing_ctgrind_aes128_block(
      make_slice(k128, 16), make_slice(pt, 16), make_slice(out128, 16));
  CT_POISON(k256, sizeof(k256));
  uint8_t ok2 = wing_ctgrind_aes256_block(
      make_slice(k256, 32), make_slice(pt, 16), make_slice(out256, 16));
  CT_UNPOISON(out128, sizeof(out128));
  CT_UNPOISON(out256, sizeof(out256));
  CT_UNPOISON(k128, sizeof(k128));
  CT_UNPOISON(k256, sizeof(k256));
  CT_UNPOISON(pt, sizeof(pt));
  return (ok1 == 1u && ok2 == 1u && memcmp(out128, exp128, 16) == 0 &&
          memcmp(out256, exp256, 16) == 0);
}

static int test_chacha20_poly1305(void) {
  uint8_t key[32];
  uint8_t iv[12] = {0x07, 0,    0,    0,    0x40, 0x41,
                    0x42, 0x43, 0x44, 0x45, 0x46, 0x47};
  uint8_t pt[64];
  uint8_t out[80] = {0};
  for (int i = 0; i < 32; i++) {
    key[i] = (uint8_t)(0x80 + i);
  }
  for (int i = 0; i < 64; i++) {
    pt[i] = (uint8_t)(0x20 + i);
  }

  CT_POISON(key, sizeof(key));
  CT_POISON(iv, sizeof(iv));
  CT_POISON(pt, sizeof(pt));
  uint8_t ok =
      wing_ctgrind_chacha20_poly1305(make_slice(key, 32), make_slice(iv, 12),
                                     make_slice(pt, 64), make_slice(out, 80));
  CT_UNPOISON(out, sizeof(out));
  CT_UNPOISON(key, sizeof(key));
  CT_UNPOISON(iv, sizeof(iv));
  CT_UNPOISON(pt, sizeof(pt));
  return ok == 1u;
}

static int test_x25519(void) {
  uint8_t scalar[32] = {0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
                        0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
                        0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
                        0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a};
  uint8_t base[32] = {9};
  uint8_t out[32] = {0};
  const uint8_t exp[4] = {0x85, 0x20, 0xf0, 0x09};

  CT_POISON(scalar, sizeof(scalar));
  uint8_t ok = wing_ctgrind_x25519_scalarmult(
      make_slice(scalar, 32), make_slice(base, 32), make_slice(out, 32));
  CT_UNPOISON(out, sizeof(out));
  CT_UNPOISON(scalar, sizeof(scalar));
  return (ok == 1u && memcmp(out, exp, 4) == 0);
}

static int test_ecdsa_p256_sign(void) {
  uint8_t priv[32];
  uint8_t msg[32];
  uint8_t sig[64] = {0};
  for (int i = 0; i < 32; i++) {
    priv[i] = (uint8_t)(0x31 + i);
    msg[i] = (uint8_t)(0xA0 + i);
  }

  CT_POISON(priv, sizeof(priv));
  CT_POISON(msg, sizeof(msg));
  uint8_t ok = wing_ctgrind_ecdsa_p256_sign(
      make_slice(priv, 32), make_slice(msg, 32), make_slice(sig, 64));
  CT_UNPOISON(sig, sizeof(sig));
  CT_UNPOISON(priv, sizeof(priv));
  CT_UNPOISON(msg, sizeof(msg));
  uint8_t acc = 0;
  for (int i = 0; i < 64; i++) {
    acc |= sig[i];
  }
  return (ok == 1u && acc != 0u);
}

static int test_ed25519_sign(void) {
  uint8_t seed[32] = {0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
                      0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
                      0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
                      0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60};
  uint8_t msg[1] = {0};
  uint8_t sig[64] = {0};
  const uint8_t exp_prefix[4] = {0xe5, 0x56, 0x43, 0x00};

  CT_POISON(seed, sizeof(seed));
  uint8_t ok = wing_ctgrind_ed25519_sign(
      make_slice(seed, 32), make_slice(msg, 0), make_slice(sig, 64));
  CT_UNPOISON(sig, sizeof(sig));
  CT_UNPOISON(seed, sizeof(seed));
  return (ok == 1u && memcmp(sig, exp_prefix, 4) == 0);
}

static int test_rsa_mod_exp(void) {
  uint8_t mod_be[64];
  uint8_t base[64];
  uint8_t exp[64];
  uint8_t out[64] = {0};
  memset(mod_be, 0xA5, sizeof(mod_be));
  mod_be[0] = 0x80;
  mod_be[1] = 0x40;
  mod_be[63] = 0xEF;
  memset(base, 0x22, sizeof(base));
  base[0] = 0x12;
  memset(exp, 0x55, sizeof(exp));
  exp[63] = 0x01;

  CT_POISON(base, sizeof(base));
  CT_POISON(exp, sizeof(exp));
  uint8_t ok =
      wing_ctgrind_rsa_mod_exp(make_slice(base, 64), make_slice(exp, 64),
                               make_slice(mod_be, 64), make_slice(out, 64));
  CT_UNPOISON(out, sizeof(out));
  CT_UNPOISON(base, sizeof(base));
  CT_UNPOISON(exp, sizeof(exp));
  return ok == 1u;
}

static int test_p256_ecdh(void) {
  uint8_t priv[32];
  uint8_t peer_priv[32];
  uint8_t peer_pub[65] = {0};
  uint8_t ss[32] = {0};
  for (int i = 0; i < 32; i++) {
    priv[i] = (uint8_t)(0x21 + i);
    peer_priv[i] = (uint8_t)(0x51 + i);
  }
  if (!wing_ctgrind_p256_public_key(make_slice(peer_priv, 32),
                                    make_slice(peer_pub, 65))) {
    return 0;
  }

  CT_POISON(priv, sizeof(priv));
  uint8_t ok = wing_ctgrind_p256_ecdh(
      make_slice(priv, 32), make_slice(peer_pub, 65), make_slice(ss, 32));
  CT_UNPOISON(ss, sizeof(ss));
  CT_UNPOISON(priv, sizeof(priv));
  uint8_t acc = 0;
  for (int i = 0; i < 32; i++) {
    acc |= ss[i];
  }
  return (ok == 1u && acc != 0u);
}

static int test_rsa_pss_sign_blinded(void) {
  uint8_t n2048[256];
  uint8_t d2048[256];
  uint8_t e3[1] = {0x03};
  uint8_t salt[32];
  uint8_t msg[32];
  uint8_t sig[256] = {0};
  memset(n2048, 0xFF, sizeof(n2048));
  n2048[253] = 0xE2;
  n2048[254] = 0x5C;
  n2048[255] = 0xEF;
  memset(d2048, 0xAA, sizeof(d2048));
  d2048[253] = 0x96;
  d2048[254] = 0xE8;
  d2048[255] = 0x9F;
  memset(salt, 0x42, sizeof(salt));
  memset(msg, 0x5A, sizeof(msg));

  CT_POISON(d2048, sizeof(d2048));
  CT_POISON(salt, sizeof(salt));
  CT_POISON(msg, sizeof(msg));
  uint8_t ok = wing_ctgrind_rsa_pss_sign_blinded(
      make_slice(n2048, 256), make_slice(d2048, 256), make_slice(e3, 1),
      make_slice(salt, 32), make_slice(msg, 32), make_slice(sig, 256));
  CT_UNPOISON(sig, sizeof(sig));
  CT_UNPOISON(d2048, sizeof(d2048));
  CT_UNPOISON(salt, sizeof(salt));
  CT_UNPOISON(msg, sizeof(msg));
  uint8_t verified = wing_ctgrind_rsa_pss_verify(
      make_slice(n2048, 256), make_slice(e3, 1), make_slice(msg, 32),
      make_slice(sig, 256));
  msg[0] ^= 0x01u;
  uint8_t tampered_ok = wing_ctgrind_rsa_pss_verify(
      make_slice(n2048, 256), make_slice(e3, 1), make_slice(msg, 32),
      make_slice(sig, 256));
  return (ok == 1u && verified == 1u && tampered_ok == 0u);
}

static int test_mlkem768_decapsulate(void) {
  uint8_t d_seed[32];
  uint8_t z_seed[32];
  uint8_t m_seed[32];
  uint8_t ek[1184];
  uint8_t dk[2400];
  uint8_t ct[1088];
  uint8_t ct_bad[1088];
  uint8_t ss_enc[32];
  uint8_t ss_valid[32] = {0};
  uint8_t ss_rej[32] = {0};
  memset(d_seed, 0x11, sizeof(d_seed));
  memset(z_seed, 0x22, sizeof(z_seed));
  memset(m_seed, 0x33, sizeof(m_seed));

  CT_POISON(d_seed, sizeof(d_seed));
  CT_POISON(z_seed, sizeof(z_seed));
  uint8_t ok_kg = wing_ctgrind_mlkem768_keygen(
      make_slice(d_seed, 32), make_slice(z_seed, 32), make_slice(ek, 1184),
      make_slice(dk, 2400));
  CT_UNPOISON(d_seed, sizeof(d_seed));
  CT_UNPOISON(z_seed, sizeof(z_seed));
  CT_UNPOISON(ek, sizeof(ek));
  CT_UNPOISON(dk, sizeof(dk));
  if (!ok_kg) {
    return 0;
  }
  CT_POISON(m_seed, sizeof(m_seed));
  uint8_t ok_enc = wing_ctgrind_mlkem768_encaps(
      make_slice(ek, 1184), make_slice(m_seed, 32), make_slice(ct, 1088),
      make_slice(ss_enc, 32));
  CT_UNPOISON(m_seed, sizeof(m_seed));
  CT_UNPOISON(ct, sizeof(ct));
  CT_UNPOISON(ss_enc, sizeof(ss_enc));
  if (!ok_enc) {
    return 0;
  }
  memcpy(ct_bad, ct, sizeof(ct));
  ct_bad[42] ^= 0x80u;

  CT_POISON(dk, 1152);
  CT_POISON(dk + 2368, 32);
  uint8_t ok1 = wing_ctgrind_mlkem768_decapsulate(
      make_slice(ct, 1088), make_slice(dk, 2400), make_slice(ss_valid, 32));
  uint8_t ok2 = wing_ctgrind_mlkem768_decapsulate(
      make_slice(ct_bad, 1088), make_slice(dk, 2400), make_slice(ss_rej, 32));
  CT_UNPOISON(ss_valid, sizeof(ss_valid));
  CT_UNPOISON(ss_rej, sizeof(ss_rej));
  CT_UNPOISON(dk, sizeof(dk));
  return (ok1 == 1u && ok2 == 1u && memcmp(ss_valid, ss_enc, 32) == 0 &&
          memcmp(ss_rej, ss_enc, 32) != 0);
}

static int test_ecdsa_p384_sign(void) {
  uint8_t priv[48];
  uint8_t msg[32];
  uint8_t sig[96] = {0};
  for (int i = 0; i < 48; i++) {
    priv[i] = (uint8_t)(0x31 + i);
  }
  for (int i = 0; i < 32; i++) {
    msg[i] = (uint8_t)(0xA0 + i);
  }

  CT_POISON(priv, sizeof(priv));
  CT_POISON(msg, sizeof(msg));
  uint8_t ok = wing_ctgrind_ecdsa_p384_sign(
      make_slice(priv, 48), make_slice(msg, 32), make_slice(sig, 96));
  CT_UNPOISON(sig, sizeof(sig));
  CT_UNPOISON(priv, sizeof(priv));
  CT_UNPOISON(msg, sizeof(msg));
  uint8_t acc = 0;
  for (int i = 0; i < 96; i++) {
    acc |= sig[i];
  }
  return (ok == 1u && acc != 0u);
}

static int test_p384_ecdh(void) {
  uint8_t priv[48];
  uint8_t peer_priv[48];
  uint8_t peer_pub[97] = {0};
  uint8_t ss[48] = {0};
  for (int i = 0; i < 48; i++) {
    priv[i] = (uint8_t)(0x21 + i);
    peer_priv[i] = (uint8_t)(0x51 + i);
  }
  if (!wing_ctgrind_p384_public_key(make_slice(peer_priv, 48),
                                    make_slice(peer_pub, 97))) {
    return 0;
  }

  CT_POISON(priv, sizeof(priv));
  uint8_t ok = wing_ctgrind_p384_ecdh(
      make_slice(priv, 48), make_slice(peer_pub, 97), make_slice(ss, 48));
  CT_UNPOISON(ss, sizeof(ss));
  CT_UNPOISON(priv, sizeof(priv));
  uint8_t acc = 0;
  for (int i = 0; i < 48; i++) {
    acc |= ss[i];
  }
  return (ok == 1u && acc != 0u);
}

static int test_rsa_exp_blinded_signs(void) {
  uint8_t n2048[256];
  uint8_t d2048[256];
  uint8_t d_padded[258];
  uint8_t e3[1] = {0x03};
  uint8_t salt32[32];
  uint8_t salt64[64];
  uint8_t msg[32];
  uint8_t sig1[256] = {0};
  uint8_t sig2[256] = {0};
  uint8_t sig_pss256[256] = {0};
  uint8_t sig_pss512[256] = {0};
  memset(n2048, 0xFF, sizeof(n2048));
  n2048[253] = 0xE2;
  n2048[254] = 0x5C;
  n2048[255] = 0xEF;
  memset(d2048, 0xAA, sizeof(d2048));
  d2048[253] = 0x96;
  d2048[254] = 0xE8;
  d2048[255] = 0x9F;
  d_padded[0] = 0x00;
  d_padded[1] = 0x00;
  memcpy(d_padded + 2, d2048, 256);
  memset(salt32, 0x42, sizeof(salt32));
  memset(salt64, 0x67, sizeof(salt64));
  memset(msg, 0x5A, sizeof(msg));

  CT_POISON(d2048, sizeof(d2048));
  CT_POISON(d_padded, sizeof(d_padded));
  CT_POISON(salt32, sizeof(salt32));
  CT_POISON(salt64, sizeof(salt64));
  CT_POISON(msg, sizeof(msg));

  uint8_t ok1 = wing_ctgrind_rsa_pkcs1_sha256_sign(
      make_slice(n2048, 256), make_slice(d2048, 256), make_slice(msg, 32),
      make_slice(sig1, 256));
  uint8_t ok2 = wing_ctgrind_rsa_pkcs1_sha256_sign(
      make_slice(n2048, 256), make_slice(d_padded, 258), make_slice(msg, 32),
      make_slice(sig2, 256));
  uint8_t ok3 = wing_ctgrind_rsa_pss_sha256_sign(
      make_slice(n2048, 256), make_slice(d2048, 256), make_slice(salt32, 32),
      make_slice(msg, 32), make_slice(sig_pss256, 256));
  uint8_t ok4 = wing_ctgrind_rsa_pss_sha512_sign(
      make_slice(n2048, 256), make_slice(d2048, 256), make_slice(salt64, 64),
      make_slice(msg, 32), make_slice(sig_pss512, 256));

  CT_UNPOISON(sig1, sizeof(sig1));
  CT_UNPOISON(sig2, sizeof(sig2));
  CT_UNPOISON(sig_pss256, sizeof(sig_pss256));
  CT_UNPOISON(sig_pss512, sizeof(sig_pss512));
  CT_UNPOISON(d2048, sizeof(d2048));
  CT_UNPOISON(d_padded, sizeof(d_padded));
  CT_UNPOISON(salt32, sizeof(salt32));
  CT_UNPOISON(salt64, sizeof(salt64));
  CT_UNPOISON(msg, sizeof(msg));

  uint8_t pss_ok = wing_ctgrind_rsa_pss_verify(
      make_slice(n2048, 256), make_slice(e3, 1), make_slice(msg, 32),
      make_slice(sig_pss256, 256));
  return (ok1 == 1u && ok2 == 1u && ok3 == 1u && ok4 == 1u &&
          pss_ok == 1u && memcmp(sig1, sig2, 256) == 0);
}

static int test_xchacha20_poly1305(void) {
  uint8_t key[32];
  uint8_t iv[24];
  uint8_t pt[64];
  uint8_t out[80] = {0};
  for (int i = 0; i < 32; i++) {
    key[i] = (uint8_t)(0x80 + i);
  }
  for (int i = 0; i < 24; i++) {
    iv[i] = (uint8_t)(0x40 + i);
  }
  for (int i = 0; i < 64; i++) {
    pt[i] = (uint8_t)(0x20 + i);
  }

  CT_POISON(key, sizeof(key));
  CT_POISON(iv, sizeof(iv));
  CT_POISON(pt, sizeof(pt));
  uint8_t ok =
      wing_ctgrind_xchacha20_poly1305(make_slice(key, 32), make_slice(iv, 24),
                                      make_slice(pt, 64), make_slice(out, 80));
  CT_UNPOISON(out, sizeof(out));
  CT_UNPOISON(key, sizeof(key));
  CT_UNPOISON(iv, sizeof(iv));
  CT_UNPOISON(pt, sizeof(pt));
  return ok == 1u;
}

static int test_hmac_hkdf_sha256(void) {
  uint8_t key[32];
  uint8_t salt[16];
  uint8_t info[16];
  uint8_t out[64] = {0};
  for (int i = 0; i < 32; i++) {
    key[i] = (uint8_t)(0x10 + i);
  }
  for (int i = 0; i < 16; i++) {
    salt[i] = (uint8_t)(0x60 + i);
    info[i] = (uint8_t)(0x90 + i);
  }

  CT_POISON(key, sizeof(key));
  CT_POISON(salt, sizeof(salt));
  uint8_t ok =
      wing_ctgrind_hmac_hkdf_sha256(make_slice(key, 32), make_slice(salt, 16),
                                    make_slice(info, 16), make_slice(out, 64));
  CT_UNPOISON(out, sizeof(out));
  CT_UNPOISON(key, sizeof(key));
  CT_UNPOISON(salt, sizeof(salt));
  uint8_t acc = 0;
  for (int i = 0; i < 64; i++) {
    acc |= out[i];
  }
  return (ok == 1u && acc != 0u);
}

typedef struct {
  const char *name;
  int (*fn)(void);
} CtCheck;

int main(int argc, char **argv) {
  goose_init(argc, argv);
  const CtCheck checks[] = {
      {"wing_aes_gcm_seal_scalar", test_aes_gcm_scalar},
      {"ct_eq_bytes", test_ct_eq_bytes},
      {"aes128_and_aes256_encrypt_block", test_aes_blocks},
      {"chacha20_poly1305", test_chacha20_poly1305},
      {"xchacha20_poly1305", test_xchacha20_poly1305},
      {"hmac_and_hkdf_sha256", test_hmac_hkdf_sha256},
      {"x25519_scalarmult", test_x25519},
      {"ecdsa_p256_sign", test_ecdsa_p256_sign},
      {"p256_ecdh_shared_secret", test_p256_ecdh},
      {"ecdsa_p384_sign", test_ecdsa_p384_sign},
      {"p384_ecdh_shared_secret", test_p384_ecdh},
      {"ed25519_sign", test_ed25519_sign},
      {"rsa_mod_exp", test_rsa_mod_exp},
      {"rsa_exp_blinded_signs", test_rsa_exp_blinded_signs},
      {"rsa_pss_sha256_sign_blinded", test_rsa_pss_sign_blinded},
      {"mlkem768_decapsulate", test_mlkem768_decapsulate},
  };
  int all_ok = 1;
  size_t count = sizeof(checks) / sizeof(checks[0]);
  for (size_t i = 0; i < count; i++) {
    int ok = checks[i].fn();
    printf("CTGRIND\t%s\t%s\n", checks[i].name, ok ? "PASS" : "FAIL");
    if (!ok) {
      all_ok = 0;
    }
  }
  return all_ok ? 0 : 1;
}
