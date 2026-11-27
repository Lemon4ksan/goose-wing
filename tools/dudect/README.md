# goose-wing dudect statistical constant-time timing harness

Native Welch's t-test statistical timing harness (Reparaz, Balasch, and
Verbauwhede 2017) that links `tools/dudect/dudect_target.goose`,
`tools/dudect/dudect_harness.c`, and `shim/crypto_fusion.c` to verify
`|t| < 4.5` across 10 cryptographic primitives.

## Quick start

### Local native measurement

```bash
python tools/dudect.py --local
python tools/dudect.py --local --samples 10000
```

### Docker mode

```bash
python tools/dudect.py --docker --samples 5000
```

## Method

- Serialized x86_64 cycle counter (`lfence; rdtsc` to `rdtscp; lfence`) with
  monotonic clock fallback on non-x86 hosts.
- Interleaved random class assignment (`Class 0` fixed inputs vs `Class 1`
  random inputs across identically strided 32-slot pools).
- Percentile cropping (`p1..p85`) followed by two-class online Welford mean and
  variance accumulation to compute Welch's `|t|`.
- Pass ceiling is `|t| < 4.5` per primitive.

## Verified primitives

| Primitive | Class 0 (fixed) | Class 1 (random / adversarial) |
| :--- | :--- | :--- |
| `ct_eq_bytes` | Identical 64-byte buffers | First-byte mismatch (`eq_b[0] ^= 1`) |
| `aes128_encrypt_block` | All-zero 128-bit key and block | Random 128-bit keys and blocks |
| `aes_encrypt_block` | All-zero 256-bit key and block | Random 256-bit keys and blocks |
| `aes_gcm_seal_pure` | Fixed key, IV, AAD, 64B plaintext | Random key, IV, AAD, 64B plaintext |
| `chacha20_poly1305` | Fixed key, IV, 64B plaintext | Random key, IV, 64B plaintext |
| `x25519_scalarmult` | Fixed all-zero clamped scalar | Random 32-byte scalars |
| `ecdsa_p256_sign` | Fixed private key (`d = 1`) | Random 256-bit private keys |
| `ed25519_sign` | Fixed all-zero 32-byte seed | Random 32-byte seeds |
| `rsa_mod_exp` | Low-Hamming 512-bit exponent | Random 512-bit exponents |
| `mlkem768_decapsulate` | Valid FIPS 203 ciphertext (`K`) | Tampered ciphertexts (`K_bar` rejection) |
