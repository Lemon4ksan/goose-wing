# gRPC & gRPC-Web End-to-End Verification Test Suite

Live end-to-end conformance and verification harness for `goose-wing`'s
zero-allocation gRPC and gRPC-Web dispatcher engine.

## Verification Scope

| Feature | Verification Details |
| :--- | :--- |
| Unary RPC over HTTP/2 & HTTP/1.1 | Length-prefixed message (LPM) framing (5-byte header: flag + length), Protobuf payload transmission, and parsing. |
| Metadata Propagation | Request metadata extraction and response metadata header injection (`x-server-version`, `x-grpc-engine`). |
| Error Handling | Non-zero `grpc-status` codes (`Unauthenticated = 16`, `PermissionDenied = 7`) and `grpc-message` encoding in trailers. |
| gRPC-Web Binary Protocol | `application/grpc-web+proto` payload and body-framed trailing status (flag `0x80`). |
| gRPC-Web Text Protocol | `application/grpc-web-text` Base64 stream decoding and encoding. |
| Large Message Payloads | Multi-kilobyte (32 KB+) LPM framing and TCP stream assembly. |

## Quick Start

### 1. Run Locally

```powershell
python tools/grpc.py
```

### 2. Run in Docker (Docker Compose)

```powershell
docker compose -f tools/grpc/docker-compose.yml up --build --abort-on-container-exit
```

Or via the Python runner:

```powershell
python tools/grpc.py --compose
```
