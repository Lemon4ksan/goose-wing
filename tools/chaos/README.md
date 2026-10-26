# goose-wing Network Chaos & TCP Micro-Slicing E2E Suite

End-to-end verification suite testing the `serve_reactor` event loop against real-world packet fragmentation, 1-byte TCP micro-slicing, slowloris progressive header drips, MTU boundary splits, and HTTP/1.1 pipelining across arbitrary frame boundaries.

## Architecture & Verification Targets

1. **1-Byte TCP Micro-Slicing**:
   Transmits requests 1 byte per TCP packet with inter-byte delays to verify the reactor accurately reconstructs fragmented request frames without premature `400 Bad Request` or dropped connections.

2. **CRLF & Header Boundary Fragmentation**:
   Splits frames across HTTP methods, path strings, header colons, and `\r\n\r\n` boundaries.

3. **Pipelining Split Across MTU Boundaries**:
   Sends batches of 3 pipelined HTTP requests sliced into uneven chunk sizes across MTU limits, verifying that all responses arrive in strict FIFO sequence.

4. **POST Body Chunking**:
   Transmits request headers in one packet and the Content-Length payload across multiple downstream fragments with inter-packet delays.

5. **Poisoning & Trailing Bytes Defense (RFC 9112 §9.3 / uWS #1898)**:
   Asserts that unparseable junk following a completed request is immediately rejected with `400 Bad Request` to prevent request smuggling.

6. **Slowloris Progressive Header Drip**:
   Verifies that slow, progressive header transmissions within timeout allowances complete successfully without breaking.

7. **Header Overflow (> 8KB) Defense**:
   Asserts that oversized header blocks exceeding the 8192-byte limit are rejected.

8. **Concurrent Chaos Blast**:
   Fires 10 concurrent threads running micro-sliced streams simultaneously to ensure lock-free reactor stability and zero connection slot leakage.

## Running Locally

```bash
python tools/chaos.py
```

Or target a specific running server:

```bash
python tools/chaos/runner.py --host 127.0.0.1 --port 8088
```

## Running via Docker Compose

```bash
docker compose -f tools/chaos/docker-compose.yml up --build --abort-on-container-exit
```
