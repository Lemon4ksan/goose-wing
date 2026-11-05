# goose-wing HTTP/3 & QUIC Interop Verification Suite

End-to-end verification suite testing `goose-wing`'s native RFC 9000 QUIC transport, RFC 9114 HTTP/3 framing, and RFC 9204 QPACK static/dynamic compression over live UDP datagrams.

## Quick Start

### Host Mode (Local Compiler)

```bash
python tools/http3.py
```

### Docker Mode (Hermetic Container)

```bash
docker compose -f tools/http3/docker-compose.yml up --build --abort-on-container-exit
```

## Verified Capabilities

1. **RFC 9000 Section 17.2.1 Version Negotiation**: Server handles unknown QUIC versions and returns valid Version Negotiation packet with supported version list (`QUIC_VERSION_1`).
2. **RFC 9000 Section 17.2.2 QUIC v1 Initial Datagram Ingestion**: Parses Long Header Initial packets and validates 1200-byte datagram minimum anti-amplification bound.
3. **RFC 9114 Section 6.2.1 HTTP/3 Control Stream Preamble**: Validates Unidirectional Control Stream (`0x00`) initialization with `SETTINGS` frame.
4. **RFC 9114 Section 7.2.4 SETTINGS Parameters Validation**: Validates `QPACK_MAX_TABLE_CAPACITY`, `MAX_FIELD_SECTION_SIZE`, `QPACK_BLOCKED_STREAMS`, and `ENABLE_CONNECT_PROTOCOL`.
5. **RFC 9114 Section 7.2.8 GREASE Frame Conformance**: Validates frame type tolerance for GREASE (`0x1F * N + 0x21`).
6. **Rejection of Forbidden HTTP/2 Settings**: Enforces strict protocol boundary defense by rejecting forbidden HTTP/2 settings with `H3_ERR_SETTINGS_ERROR` (`0x0109`).
7. **RFC 9114 HEADERS & DATA Request/Response Roundtrip**: Validates full bidirectional stream exchange with payload delivery over UDP.
8. **RFC 9204 QPACK Static Table Indexing**: Validates static index 25 (`:status 200` = `0xD9`).
