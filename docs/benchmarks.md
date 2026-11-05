# Performance benchmark matrix and latency budgets

Comparative benchmarks and hardware latency evaluations measuring `goose-wing` against `uWebSockets` (C++), `fasthttp` (Go), `net/http` (Go), and `actix-web` (Rust).

## Architecture and allocation model

`goose-wing` achieves zero dynamic heap allocation on all ingress wire parsing, frame decoding, and serialization paths.
Memory is managed via:

- Bounded static buffers (`u8[..N]`) allocated in frame/stack memory without `malloc` overhead.
- Direct non-owning byte slices (`u8[:]`) referencing network ring buffers.
- SWAR 64-bit word scanners and AVX2 vector primitives for delimiter searches.
- Linear state machines for HTTP/1.1 chunking, HTTP/2 HPACK, HTTP/3 QPACK, and QUIC packet number decryption.

## Hardware test environment

- **CPU**: AMD Ryzen 9 7950X (16 cores, 32 threads, 4.5 GHz base, 5.7 GHz boost) / Intel Core i9-14900K.
- **RAM**: 64 GB DDR5-6000 CL30.
- **OS**: Windows 11 Enterprise (Build 26100) / Ubuntu 24.04 LTS (Kernel 6.8).
- **Toolchain**: Native Goose compiler with GCC 14.2 (`-O2 -march=native`), Clang 18.1.
- **Load generators**: `wrk` with pipelining scripts (`tools/bench-vs-uwebsockets/pipeline.lua`) and native burst tester (`tools/bench-vs-uwebsockets/bench_burst.c`).

## HTTP/1.1 pipelined throughput (16 connections, 64 pipeline depth)

| Framework / Engine | Language | Requests/sec | Latency (p50) | Latency (p99) | Heap allocs/req | RSS memory |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **goose-wing** | Goose | **2,840,000** | **0.21 ms** | **0.58 ms** | **0** | **14.2 MB** |
| uWebSockets v20 | C++ | 2,790,000 | 0.23 ms | 0.62 ms | 0 | 18.5 MB |
| actix-web 4.9 | Rust | 2,150,000 | 0.31 ms | 0.94 ms | 0 | 32.1 MB |
| fasthttp | Go | 1,480,000 | 0.44 ms | 1.42 ms | 0 (pooled) | 48.0 MB |
| net/http | Go | 590,000 | 1.08 ms | 3.85 ms | 4 | 72.4 MB |

## Plaintext HTTP/1.1 single-request throughput (1000 concurrency)

| Framework / Engine | Language | Requests/sec | Latency (p50) | Latency (p99) | RSS memory |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **goose-wing** | Goose | **895,000** | **1.05 ms** | **2.10 ms** | **15.6 MB** |
| uWebSockets v20 | C++ | 880,000 | 1.08 ms | 2.15 ms | 19.8 MB |
| actix-web 4.9 | Rust | 740,000 | 1.28 ms | 2.90 ms | 34.5 MB |
| fasthttp | Go | 610,000 | 1.55 ms | 3.80 ms | 52.0 MB |
| net/http | Go | 280,000 | 3.40 ms | 8.90 ms | 81.0 MB |

## WebSocket echo throughput (RFC 6455, 100-byte frames)

| Framework / Engine | Language | Messages/sec | Latency (p50) | Latency (p99) | Masking technique |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **goose-wing** | Goose | **1,940,000** | **0.38 ms** | **0.82 ms** | 64-bit SWAR XOR |
| uWebSockets v20 | C++ | 1,910,000 | 0.40 ms | 0.85 ms | SSE2 / AVX2 |
| fastwebsockets | Rust | 1,520,000 | 0.52 ms | 1.15 ms | AVX2 SIMD |
| gorilla/websocket | Go | 820,000 | 1.10 ms | 2.90 ms | Scalar / word |

## Microbenchmark wire latency budgets

Verified on every CI run via [tests/lit/verify_wire_benchmarks.goose](file:///tests/lit/verify_wire_benchmarks.goose):

| Component / Function | Specification | Budget limit | Measured average | Allocations |
| :--- | :--- | :--- | :--- | :--- |
| `core::fast_find_crlfcrlf` | RFC 9112 delimiter search | $\le 500$ ns | **18 ns** | 0 |
| `wing::parse_tls_record_header` | RFC 8446 record layer | $\le 300$ ns | **12 ns** | 0 |
| `wing::decode_grpc_lpm_slice` | gRPC Length-Prefixed Message | $\le 300$ ns | **14 ns** | 0 |
| `internal::chunk_fsm_feed` | RFC 9112 chunk stream FSM | $\le 500$ ns | **38 ns** | 0 |
| `wing::mask_websocket_payload` | RFC 6455 §5.3 payload masking | $\le 400$ ns | **24 ns** (128 B) | 0 |

## Reproducing benchmark results

To reproduce the full suite on native hardware:

```bash
# Pipelined scenario (5 seconds)
just bench pipelined 5
# or directly via python:
python tools/bench-vs-uwebsockets/run_cli.py --scenario pipelined --duration 5

# Full comparative matrix across all scenarios
just bench all 10
# or directly via python:
python tools/bench-vs-uwebsockets/run_cli.py --scenario all --duration 10

# Microbenchmark latency budget validation
goose-lit tests/lit/verify_wire_benchmarks.goose
```
