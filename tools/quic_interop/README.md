# goose-wing quic-interop-runner endpoint

Official
[`marten-seemann/quic-interop-runner`](https://github.com/marten-seemann/quic-interop-runner)
Docker endpoint contract and local loopback QUIC/HTTP/3 self-interop suite for
`goose-wing`.

## Quick start

### Local loopback self-interop

```bash
python tools/quic_interop.py --local
python tools/quic_interop.py --local --testcase keyupdate
```

### Docker Compose self-interop and cross-stack matrix

```bash
python tools/quic_interop.py --docker
docker compose -f tools/quic_interop/docker-compose.yml --profile ngtcp2 up
docker compose -f tools/quic_interop/docker-compose.yml --profile quiche up
docker compose -f tools/quic_interop/docker-compose.yml --profile quic-go up
```

### Official QNS image build

```bash
docker build \
    --build-arg BASE_IMAGE=martenseemann/quic-network-simulator-endpoint:latest \
    -f tools/quic_interop/Dockerfile -t goose-wing-quic-interop .
```

## Endpoint contract (`run_endpoint.sh`)

- Honors `ROLE=client|server`, `TESTCASE`, `SSLKEYLOGFILE`, `REQUESTS`, `/www`,
  and `/downloads`.
- Supported testcases: `handshake`, `transfer`, `retry`, `resumption`,
  `keyupdate`, `chacha20`, `multiconnect`, `zerortt`, and `http3`.
- Exits with code `127` on unsupported `TESTCASE` values per the
  `quic-interop-runner` specification.

## Local self-interop scenarios

| Scenario | Verified protocol path |
| :--- | :--- |
| `handshake` | RFC 9000/9001 padded 1200-byte QUIC v1 Initial AEAD + Header Protection handshake and `SSLKEYLOGFILE` output. |
| `transfer` | 32 KiB 1-RTT AES-128-GCM `STREAM` file transfer over loopback UDP with SHA-256 verification. |
| `retry` | RFC 9000 Section 17.2.5 Retry packet with RFC 9001 Section 5.8 AES-128-GCM Retry Integrity Tag, token echo, and 16 KiB transfer. |
| `keyupdate` | 24 KiB transfer with mid-stream RFC 9001 Section 6.1 `"quic ku"` Key Phase 0 to Phase 1 rotation and SHA-256 verification. |
| `chacha20` | 20 KiB 1-RTT `TLS_CHACHA20_POLY1305_SHA256` (`0x1303`) AEAD and ChaCha20 Header Protection transfer with SHA-256 verification. |
| `http3` | 16 KiB RFC 9114 HTTP/3 QPACK `HEADERS` and `DATA` transfer over encrypted 1-RTT QUIC with SHA-256 verification. |
