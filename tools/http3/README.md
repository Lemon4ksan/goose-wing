# goose-wing HTTP/3 and QUIC interop verification suite

End-to-end verification suite testing `goose-wing`'s RFC 9000 QUIC transport,
RFC 9114 HTTP/3 framing, RFC 9204 QPACK compression, UDP fault resilience
(packet loss, duplication, reordering), 2 MiB flow-controlled streaming with
`MAX_DATA` and `MAX_STREAM_DATA` backpressure, and RFC 9000 Section 9 connection
migration over live UDP datagrams.

## Quick start

### Host mode (local compiler)

```bash
python tools/http3.py
```

### Docker mode (containerized suite)

```bash
docker compose -f tools/http3/docker-compose.yml up --build --abort-on-container-exit
```

## Verified capabilities

| Capability | Verification details |
| :--- | :--- |
| RFC 9000 Version Negotiation and Initial | Unknown QUIC versions return Version Negotiation (`QUIC_VERSION_1`); Initial datagrams enforce the 1200-byte minimum bound. |
| RFC 9114 Control Stream, SETTINGS, GREASE | Validates Control Stream (`0x00`), QPACK/section-size `SETTINGS`, GREASE (`0x21`) tolerance, and `H3_ERR_SETTINGS_ERROR` (`0x0109`) on forbidden HTTP/2 settings. |
| RFC 9114 and RFC 9204 roundtrips | Validates HEADERS + DATA request/response exchanges, static index 25 (`:status 200` = `0xD9`), and native Goose Alt-Svc `h3` client promotion. |
| UDP fault resilience (`quic-interop-runner`) | Deterministic local UDP fault proxy injects packet loss (retransmission recovery), 2x packet duplication, and out-of-order datagram reordering. |
| 2 MiB streaming and backpressure | Streams 2,097,152 bytes over live UDP using `server::ResponseStream` with `MAX_DATA` (`0x10`) and `MAX_STREAM_DATA` (`0x11`) replenishment and SHA-256 verification. |
| RFC 9000 Section 9 connection migration | Simulates NAT port rebinding across two UDP sockets, verifies `PATH_CHALLENGE` (`0x1A`) / `PATH_RESPONSE` (`0x1B`), rejects tampered tokens, and serves HTTP/3 on the migrated port. |
