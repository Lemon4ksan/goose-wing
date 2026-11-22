# goose-wing cryptographic test vector suite

Offline and upstream conformance testbed that runs `goose-wing` cryptographic
primitives in `tools/crypto_vectors/harness.goose` against C2SP Wycheproof, C2SP
CCTV, and NIST ACVP test vectors over stdin/stdout TSV.

## Quick start

### Local offline adversarial suite

```bash
python tools/crypto_vectors.py --local --suite all
python tools/crypto_vectors.py --local --suite wycheproof
python tools/crypto_vectors.py --local --suite cctv
python tools/crypto_vectors.py --local --suite acvp
```

### Fetch and run full upstream corpora

```bash
python tools/crypto_vectors.py --fetch --dir .lit/cache/crypto_vectors/upstream --suite all
python tools/crypto_vectors.py --dir .lit/cache/crypto_vectors/upstream --suite all
```

### Docker mode

```bash
python tools/crypto_vectors.py --docker --suite all
```

## Covered primitives and schemas

| Suite | Schema | Primitives and edge cases |
| :--- | :--- | :--- |
| Wycheproof | `aead_test_schema.json`, `xdh_comp_schema.json`, `ecdsa_verify_schema.json`, `eddsa_verify_schema.json`, `rsassa_pkcs1_verify_schema.json`, `rsassa_pss_verify_schema.json`, `hkdf_test_schema.json`, `mac_test_schema.json` | AES-128/256-GCM IV/tag/AAD edge cases, ChaCha20-Poly1305, X25519 low-order and non-canonical points, ECDSA P-256/P-384 DER malleability (`r=0`, `s=0`, `r=n`, `s=n`), Ed25519 small-order and `s >= L`, RSA-2048 PKCS#1 v1.5 and PSS, HKDF-SHA256/384, HMAC-SHA256/384. |
| C2SP CCTV | `C2SP/CCTV` JSON and `ML-KEM-768.txt` | ML-KEM-768 encapsulation key modulus checks (`>= 3329`), Fujisaki-Okamoto implicit rejection `J(z |
| NIST ACVP | `ACVP-Server` `internalProjection.json` | FIPS 203 ML-KEM-768 `keyGen`, `encapsulation`, `decapsulation`, and `encapsulationKeyCheck`; SHA-256/384/512; HMAC-SHA256/384; AES-128/256-GCM. |
