# goose-wing TLS audit suite (tlsfuzzer, TLS-Anvil, TLS-Attacker, testssl.sh)

Live wire conformance and negative state-machine audit harness targeting
`tools/tls/server.goose` for `tlsfuzzer`, `TLS-Anvil`, `TLS-Attacker`, and
`drwetter/testssl.sh` in local host (`--local`) and Docker (`--docker`) modes.

## Quick start

### Local live wire audit (all four suites)

```bash
python tools/tls_audit.py --local --suite all
```

### Run an individual suite locally

```bash
python tools/tls_audit.py --local --suite tlsfuzzer
python tools/tls_audit.py --local --suite tls-anvil
python tools/tls_audit.py --local --suite tls-attacker
python tools/tls_audit.py --local --suite testssl
```

### Docker upstream suite execution

```bash
python tools/tls_audit.py --docker --suite all
python tools/tls_audit.py --docker --suite testssl
```

## Audited suites and coverage

| Suite | Live wire checks against `tools/tls/server.goose` |
| :--- | :--- |
| `tlsfuzzer` | 1-byte TCP fragmented TLS 1.3 + HTTP/1.1 exchange, corrupted handshake AEAD MAC, short AEAD ciphertext padding (< 17 bytes), oversized record length (> 16640 bytes), clean `CloseNotify` alert recovery, duplicate SNI and `supported_versions` extensions, and invalid record content type (`0xFF`). |
| `tls-anvil` | Combinatorial `ClientHello` matrix: `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`, non-null compression rejection, empty compression list rejection, legacy version mismatch (`0x0301`), missing `signature_algorithms`, forbidden legacy `rsa_pkcs1_sha1` (`0x0201`), and unmatched ALPN rejection. |
| `tls-attacker` | XML validation of [attacker_workflows.xml](attacker_workflows.xml) plus live out-of-order probes: pre-handshake CCS, pre-handshake `ApplicationData`, `ServerHello` as first client message, `Finished` as first client message, unencrypted `Finished` after `ServerHello`, multi-CCS flood after `ServerHello`, malformed CCS byte (`0x02`), low-order all-zero X25519 `key_share`, and truncated X25519 `key_share`. |
| `testssl` | Strict protocol version rejection (SSL 3.0, TLS 1.0, TLS 1.1, TLS 1.2), weak cipher suite rejection (NULL, RC4, 3DES, AES-CBC, TLS 1.2 ECDHE), live OpenSSL TLS 1.3 handshake + HTTP verification, and OpenSSL TLS 1.2-only rejection check. |
