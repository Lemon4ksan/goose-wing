# goose-wing ctgrind / TIMECOP taint harness

Valgrind TIMECOP taint harness and static/disassembly constant-time auditor for
`goose-wing` cryptographic primitives across `core/crypto/*.goose`,
`tls/post_quantum.goose`, and `shim/crypto_fusion.c`.

## Quick start

### Local native run, static audit, and objdump check

```bash
python tools/ctgrind.py --local
```

### Docker Valgrind TIMECOP mode

```bash
python tools/ctgrind.py --docker
```

## Audit checks

- Native execution of `ctgrind_harness` covering `wing_aes_gcm_seal_scalar`,
  `ct_eq_bytes`, `aes128_encrypt_block`, `aes_encrypt_block`,
  `chacha20_poly1305`, `x25519_scalarmult`, `ecdsa_p256_sign`, `ed25519_sign`,
  `rsa_mod_exp`, and `mlkem768_decapsulate`.
- Valgrind `<valgrind/memcheck.h>` taint tracking (`VALGRIND_MAKE_MEM_UNDEFINED`
  and `VALGRIND_MAKE_MEM_DEFINED`) under
  `valgrind --error-exitcode=42 --track-origins=yes` in Docker.
- Static source audit checking zero AES SBOX or 256-entry lookup tables, zero
  division or modulo operators in `tls/post_quantum.goose`, and constant-time
  tag comparisons.
- `objdump` symbol and disassembly check confirming zero `SBOX` data symbols and
  zero `idiv`/`div` instructions in compiled ML-KEM-768 functions.
