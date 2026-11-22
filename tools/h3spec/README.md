# goose-wing h3spec HTTP/3 conformance suite

HTTP/3 (RFC 9114) and QUIC (RFC 9000) conformance suite combining
[`kazu-yamamoto/h3spec`](https://github.com/kazu-yamamoto/h3spec) in Docker with
local UDP and native `http3::Connection` error-handling probes against
`tools/http3/server.goose`.

## Quick start

### Local UDP and native conformance probes

```bash
python tools/h3spec.py --local
```

### Docker mode (`kazu-yamamoto/h3spec` + `http3-server`)

```bash
python tools/h3spec.py --docker
```

## Verified RFC 9114 and RFC 9000 error classes

| Probe category | RFC requirement | Expected behavior |
| :--- | :--- | :--- |
| Invalid QUIC version | RFC 9000 Section 17.2.1 | Emits Version Negotiation (`0x00000000`) echoing SCID. |
| Undersized Initial (`< 1200B`) | RFC 9000 Section 14.1 | Silently discards 512B and 1199B Initial datagrams. |
| Duplicate H3 Control / QPACK Encoder stream | RFC 9114 Section 6.2.1 | Closes with `H3_STREAM_CREATION_ERROR` (`0x0103`). |
| Closed critical Control stream | RFC 9114 Section 6.2.1 | Closes with `H3_CLOSED_CRITICAL_STREAM` (`0x0104`). |
| Non-SETTINGS first Control frame | RFC 9114 Section 6.2.1 | Closes with `H3_MISSING_SETTINGS` (`0x010A`). |
| Forbidden HTTP/2 SETTINGS and duplicate ID | RFC 9114 Section 7.2.4.1 | Closes with `H3_SETTINGS_ERROR` (`0x0109`). |
| `DATA` before `HEADERS` and duplicate `SETTINGS` | RFC 9114 Section 4.1 / 7.2.4 | Closes with `H3_FRAME_UNEXPECTED` (`0x0105`). |
| Malformed varint and truncated frame length | RFC 9114 Section 7.1 | Rejects or drops safely (`H3_FRAME_ERROR` `0x0106`) without crashing. |
| Unknown GREASE streams and frames (`0x21`, `0x40`) | RFC 9114 Section 7.2.8 | Tolerates unknown GREASE IDs and serves HTTP/3 `200 OK`. |
