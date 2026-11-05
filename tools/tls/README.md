# goose-wing TLS 1.3 Interop Verification Suite

End-to-end verification suite testing `goose-wing`'s native RFC 8446 TLS 1.3 implementation, RFC 6066 SNI normalization, RFC 7301 ALPN protocol selection, Middlebox Compatibility ChangeCipherSpec injection, and Alert CloseNotify clean session teardown.

## Quick Start

### Host Mode (Local Compiler)

```bash
python tools/tls.py
```

### Docker Mode (Hermetic Container)

```bash
docker compose -f tools/tls/docker-compose.yml up --build --abort-on-container-exit
```

## Verified Capabilities

1. **RFC 8446 TLS 1.3 ClientHello / ServerHello Negotiation**: Full handshake negotiation with `TLS_AES_128_GCM_SHA256` (0x1301) and `supported_versions` (0x0304).
2. **RFC 8446 Appendix D.4 Middlebox Compatibility**: Validates synthetic ChangeCipherSpec record generation (`0x14 0x03 0x03 0x00 0x01 0x01`).
3. **RFC 6066 Server Name Indication (SNI)**: Server parses SNI extension with uppercase-to-lowercase normalization and IP literal rejection.
4. **RFC 7301 Application Layer Protocol Negotiation (ALPN)**: Validates negotiation preferring HTTP/2 (`h2`) over HTTP/1.1 (`http/1.1`).
5. **Clean Alert CloseNotify**: Validates clean socket teardown on warning / error alert frames.
