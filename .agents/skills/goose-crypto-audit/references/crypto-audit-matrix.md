# Four-pillar cryptographic and protocol audit matrix

Use this matrix for both Track 1 (black-box conformance testing on `127.0.0.1`)
and Track 2 (white-box source inspection).

## Pillar 1: Asymmetric cryptography (X25519, ECDSA, Ed25519, RSA, ML-KEM)

| Primitive | Required security checks |
| :--- | :--- |
| X25519 (RFC 7748) | Reject all-zero shared secret resulting from all 7 low-order points (`0x00*32`, `0x01||0x00*31`, order-8 points); verify non-canonical $u \ge 2^{255}-19$ masking of MSB; verify constant-time Montgomery ladder (no secret-bit branches, no variable shifts/divisions); zeroize scalar copies. |
| ECDSA (P-256 / P-384) | Reject off-curve public keys (invalid-curve attack), point at infinity, $x \ge p$ or $y \ge p$, wrong point encoding prefix; reject $r = 0$, $s = 0$, $r \ge n$, $s \ge n$; check strict DER vs BER `(r, s)` parsing (no overlong length, no negative integers, no unneeded leading `0x00`, no trailing bytes); check malleability (high-$s$ handling where protocol requires low-$s$); check RFC 6979 / CSPRNG nonce bias and zeroization during signing. |
| Ed25519 (RFC 8032 / ZIP-215) | Reject $S \ge L$ (signature malleability); reject non-canonical point encodings ($y \ge p$ or non-zero sign bit when $x = 0$); check small-order $A$ and $R$ handling (torsion component / cofactorless vs cofactored verification consistency); check private seed expansion and zeroization. |
| RSA (PKCS#1 v1.5 / PSS) | Reject Bleichenbacher-style PKCS#1 v1.5 forgery: strict ASN.1 DER DigestInfo match, zero trailing garbage after hash, exact `0x00 0x01 0xFF... 0x00` padding with $\ge 8$ `0xFF` bytes (no `e=3` cube-root forgery); reject $s \ge n$, short modulus ($< 2048$ bits), even modulus, `e < 3` or even `e`; for RSA-PSS verify exact MGF1 hash, salt length, trailer byte `0xBC`, top zero bits, and constant-time padding check. |
| ML-KEM-768 (FIPS 203) | Reject encapsulation keys whose 12-bit coefficients are $\ge 3329$ (`encapsulationKeyCheck`); verify Fujisaki-Okamoto implicit rejection `J(z \|\| c)` uses constant-time selection without branching on ciphertext re-encryption mismatch; zeroize decapsulation key and intermediate polynomials. |

## Pillar 2: Symmetric ciphers and AEAD (AES-GCM, ChaCha20-Poly1305)

| Property | Required security checks |
| :--- | :--- |
| Nonce / IV discipline | Reject IV length $\neq 12$ bytes for 96-bit TLS/QUIC/JWE/HPKE AEAD; verify counter wraparound protection (TLS 1.3 sequence number limit $2^{64}-1$, QUIC AEAD confidentiality/integrity limits, AES-GCM $2^{32}-2$ block counter limit); ensure no static or repeated nonces across key reuse, tickets, or `crypto_jar`. |
| Tag verification | Reject truncated or oversized tags (`tag.len != 16`); verify full 16-byte constant-time comparison (`ct_eq_tag16` / `ct_eq_bytes`); test single-bit tag flips and all-zero tags. |
| AAD integrity | Verify any bit flip, insertion, truncation, or empty-vs-nonempty change in AAD fails decryption; verify AAD bit-length encoding does not overflow. |
| Doom Principle (no unverified plaintext) | Decryption must not leave unauthenticated plaintext visible in the caller's output buffer on tag mismatch: either verify tag before writing output or zeroize (`secure_zeroize_slice`) and roll back `.len` before returning `false`. |
| Constant-time implementation | No secret-indexed S-box table lookups in pure-Goose AES (verify bitsliced AES or AES-NI); no secret branches in GHASH or Poly1305 final reduction; zeroize round keys, GHASH subkey `H`, and Poly1305 one-time key `(r, s)` on every exit. |

## Pillar 3: TLS 1.3, QUIC, and X.509/ASN.1 DER

| Surface | Required security checks |
| :--- | :--- |
| Downgrade defenses | Reject SSL 3.0 / TLS 1.0 / 1.1 / 1.2 in PureGoose; verify client checks RFC 8446 Section 4.1.3 downgrade sentinels (`DOWNGRD\x01`, `DOWNGRD\x00`) in `ServerHello.random`; reject weak cipher suites, non-null compression, and legacy signature schemes (`rsa_pkcs1_sha1`, `ecdsa_sha1`). |
| State machine ordering | Reject out-of-order flights (ApplicationData before Finished, plaintext Finished, duplicate ClientHello/ServerHello/EncryptedExtensions/Finished, unsolicited Certificate/NewSessionTicket/KeyUpdate, second HelloRetryRequest, HRR changing cipher suite, EndOfEarlyData without 0-RTT, CCS floods or malformed CCS != `0x01`, renegotiation ClientHello post-handshake). |
| Record framing & fragmentation | Handle 1-byte TCP splits and multi-record handshake fragmentation; reject zero-length handshake/encrypted records, all-zero inner plaintext (missing inner content type), plaintext records $> 16384$ bytes, ciphertext records $> 16384 + 256$ bytes, handshake messages crossing encryption key-change boundaries (RFC 8446 Section 5.1). |
| 0-RTT & QUIC replay | Verify 0-RTT early data replay protection (single-use ticket / anti-replay filter, ticket age window, `max_early_data_size`, ALPN/cipher match); verify QUIC packet number protection, anti-replay, retry token authentication, address validation amplification limit (3x), and AEAD key-phase update limits. |
| Oracle behavior | Verify invalid AEAD tags, invalid Finished MACs, invalid padding, and invalid records do not leak internal state via distinct plaintext error text, non-fatal alerts, or continuing the session after fatal error. |
| X.509 / ASN.1 DER | Reject indefinite length (`0x80`), non-minimal length (`0x81 0x05`), non-minimal INTEGER (`0x00 0x01`, `0xFF 0x80`), negative serial numbers where forbidden, non-zero BIT STRING padding bits or unused bits $> 7$, trailing bytes inside SEQUENCE/SET/extensions, duplicate extensions, TBSCertificate vs outer `signatureAlgorithm` mismatch, NUL bytes in CN/SAN, invalid `BasicConstraints`/`pathLenConstraint`/`KeyUsage`/`EKU`/`NameConstraints`, expired or not-yet-valid certs. |

## Pillar 4: Authentication (JWT, JWE, DPoP, JWKS, Digest, PKCE)

| Surface | Required security checks |
| :--- | :--- |
| Algorithm confusion | Reject `alg: "none"` (any case); reject symmetric `HS256`/`HS384`/`HS512` when verifying with an asymmetric RSA/EC/OKP public key; require caller-specified algorithm allowlist instead of trusting untrusted header `alg`; reject untrusted embedded `jwk`/`jku`/`x5u` or path-traversal `kid`. |
| Signature bypass & framing | Reject empty signature, missing or extra `.` segments, non-canonical Base64URL padding/characters, trailing bytes; verify signature BEFORE parsing or trusting payload claims or recording `jti` in replay caches. |
| Claims validation | Enforce strict `exp` (`now >= exp` MUST reject per RFC 7519 Section 4.1.4), `nbf` (`now < nbf` MUST reject), `iat` sanity, exact `aud` match (handle both JSON string and JSON array without substring match), exact `iss`, and `crit` header rejection for unknown critical extensions. |
| JWE & DPoP | For JWE: verify `alg`/`enc` pairing, IV/tag lengths, AAD = ASCII protected header, constant-time tag check, no plaintext leak on failure, compression bomb limit (`zip: "DEF"`). For DPoP (RFC 9449): enforce `typ: "dpop+jwt"`, disallow symmetric `alg`, reject private key fields (`d`) in header `jwk`, validate `htm` exact method match, canonicalize `htu` (strip query/fragment, normalize scheme/host), validate `ath` SHA-256 hash of access token in constant time, enforce `jti` replay window and `iat` freshness. |
