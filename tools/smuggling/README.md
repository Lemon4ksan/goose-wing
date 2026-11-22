# goose-wing HTTP/1.1 smuggling differential wall

Differential HTTP/1.1 request smuggling and desync testbed (`http-garden` style)
comparing full `wing`, modular `wing_h1`, a Python RFC 9112 parser, and Docker
`nginx` + `haproxy` frontends across 34 wire payloads (5 baselines and 29
adversarial desync vectors).

## Quick start

### Local offline mode

```bash
python tools/smuggling.py --local
```

### Docker differential mode (nginx + haproxy)

```bash
python tools/smuggling.py --docker
```

## Verified smuggling categories

| Category | Vectors | Assertion |
| :--- | :--- | :--- |
| CL.TE and TE.CL | 2 | Rejected by both `wing` and `wing_h1` with HTTP 400 on `HttpServer`. |
| TE.TE obfuscations | 8 | Rejects `xchunked`, space before colon, leading tab/space header names, dual TE headers, non-final `chunked`, and HTTP/1.0 TE. |
| Content-Length anomalies | 6 | Rejects differing duplicate CL, comma-list differing CL, negative, `+` prefix, hex CL, and space before colon. |
| Line endings and obs-fold | 4 | Rejects bare LF, bare CR, and obsolete folded continuation lines. |
| Version, Host, and CTL injection | 6 | Rejects HTTP/0.9, HTTP/1.2, missing or duplicate `Host`, and NUL bytes in targets or header values. |
| Chunked and pipeline desync | 3 | Rejects chunk-size overflow with oversized extension, trailing non-CRLF garbage after `0\r\n`, and pipelined split-frame smuggling. |
| RFC 9112 baselines | 5 | Strict parity on consumed byte count, method, target, and decoded body between `wing`, `wing_h1`, and the Python reference parser. |

## HTTP Garden origin-echo adapter

`http_garden_adapter.py` and `Dockerfile.garden` expose `wing_harness` (`wing`)
and `wing_h1_harness` (`wing_h1`) in the JSON origin-echo format expected by
[`narfindustries/http-garden`](https://github.com/narfindustries/http-garden).

### Local self-test

```bash
python tools/smuggling/http_garden_adapter.py --self-test
```

### Differential JSON evaluation (`--mode eval`)

```bash
python tools/smuggling/http_garden_adapter.py --mode eval --engine wing \
    --raw-b64 R0VUIC8gSFRUUC8xLjENCkhvc3Q6IGV4YW1wbGUuY29tDQoNCg==
```

Accepted requests return base64-encoded `method`, `uri`, `version`, `headers`,
and `body` fields. Rejected smuggling payloads return HTTP 400 with a JSON
`error` payload in `--mode serve` and `"accepted": false` in `--mode eval`.

### Docker HTTP Garden origin image

```bash
docker build -f tools/smuggling/Dockerfile.garden -t http-garden-goose-wing .
docker run --rm -p 8080:80 -e GARDEN_ENGINE=wing http-garden-goose-wing
```
