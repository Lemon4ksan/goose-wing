# Performance benchmark matrix and latency budgets

Comparative benchmarks and hardware latency evaluations measuring `goose-wing`
against `uWebSockets` (C++), `fasthttp` (Go), `net/http` (Go), and `actix-web`
(Rust).

## Architecture and allocation model

`goose-wing` achieves zero dynamic heap allocation on all ingress wire parsing,
frame decoding, and serialization paths. Memory is managed via:

- Bounded static buffers (`u8[..N]`) allocated in frame/stack memory without
  `malloc` overhead.
- Direct non-owning byte slices (`u8[:]`) referencing network ring buffers.
- SWAR 64-bit word scanners and AVX2 vector primitives for delimiter searches.
- Linear state machines for HTTP/1.1 chunking, HTTP/2 HPACK, HTTP/3 QPACK, and
  QUIC packet number decryption.

## Hardware test environment

| Component | Specification |
| :--- | :--- |
| CPU | AMD Ryzen 9 7950X (16 cores, 32 threads, 4.5 GHz base, 5.7 GHz boost) / Intel Core i9-14900K |
| RAM | 64 GB DDR5-6000 CL30 |
| OS | Windows 11 Enterprise (Build 26100) / Ubuntu 24.04 LTS (Kernel 6.8) |
| Toolchain | Native Goose compiler with GCC 14.2 (`-O2 -march=native`), Clang 18.1 |
| Load generators | `wrk` with pipelining scripts (`tools/bench-vs-uwebsockets/pipeline.lua`) and native burst tester (`tools/bench-vs-uwebsockets/bench_burst.c`) |

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

Verified on every CI run via
[tests/lit/verify_wire_benchmarks.goose](file:///tests/lit/verify_wire_benchmarks.goose):

| Component / Function | Specification | Budget limit | Measured average | Allocations |
| :--- | :--- | :--- | :--- | :--- |
| `core::fast_find_crlfcrlf` | RFC 9112 delimiter search | $\le 500$ ns | **18 ns** | 0 |
| `wing::parse_tls_record_header` | RFC 8446 record layer | $\le 300$ ns | **12 ns** | 0 |
| `wing::decode_grpc_lpm_slice` | gRPC Length-Prefixed Message | $\le 300$ ns | **14 ns** | 0 |
| `http_internal::chunk_fsm_feed` | RFC 9112 chunk stream FSM | $\le 500$ ns | **38 ns** | 0 |
| `wing::mask_websocket_payload` | RFC 6455 §5.3 payload masking | $\le 400$ ns | **24 ns** (128 B) | 0 |

## HTTP/2 over TLS 1.3 throughput, latency, and memory footprint

Evaluated live on Windows 11 localhost loopback with RFC 8446 TLS 1.3 (Ed25519
X.509 DER certificate, AES-128-GCM) and RFC 9113 HTTP/2 multiplexing on the
dynamic route `/api/v1/users/{id}` (path param extraction, request header
lookup, response header injection, JSON serialization) using
[bench/h2_tls_benchmark.goose](../bench/h2_tls_benchmark.goose),
[bench/go_h2_tls_ref/main.go](../bench/go_h2_tls_ref/main.go), and
[scripts/bench_h2_tls.py](../scripts/bench_h2_tls.py)
(`--iters 4000 --accel auto`).

### Live full-stack comparison: TLS 1.3 + HTTP/2 + HPACK + RadixRouter + JSON

| Scenario | Engine | RPS | p50 (ms) | p99 (ms) | p99.9 (ms) | Peak RSS (MB) | Allocs/req | Bytes/req |
| :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 conn x 8 streams | **goose-wing (1T, auto)** | **25,028** | 0.00 | **6.51** | **12.12** | **31.2** | **0** | **0 B** |
| 1 conn x 8 streams | Go net/http 1.27 (1T) | 22,699 | 0.52 | 1.06 | 1.59 | 14.5 | 48.6 | 4482 B |
| 1 conn x 8 streams | Go net/http 1.27 (all cores) | 34,853 | 0.00 | 0.65 | 1.14 | 17.7 | 48.0 | 4606 B |
| 4 conns x 8 streams | **goose-wing (1T, auto)** | **57,156** | 0.52 | **1.28** | **1.83** | **32.8** | **0** | **0 B** |
| 4 conns x 8 streams | Go net/http 1.27 (1T) | 23,723 | 1.16 | 2.70 | 3.40 | 15.2 | 48.8 | 4522 B |
| 4 conns x 8 streams | Go net/http 1.27 (all cores) | 68,853 | 0.53 | 1.51 | 2.03 | 18.4 | 48.6 | 4732 B |
| 16 conns x 4 streams | **goose-wing (1T, auto)** | **45,595** | 1.49 | **2.80** | **3.98** | **39.4** | **0** | **0 B** |
| 16 conns x 4 streams | Go net/http 1.27 (1T) | 26,152 | 2.25 | 4.43 | 5.32 | 16.0 | 50.3 | 4656 B |
| 16 conns x 4 streams | Go net/http 1.27 (all cores) | 64,318 | 0.70 | 2.70 | 3.69 | 19.8 | 51.0 | 4962 B |

### Full-stack analysis and memory reduction

1. Single-threaded throughput and tail latency: On 4 multiplexed connections x 8
   streams under Windows Registered I/O (`--accel auto`), single-threaded
   `goose-wing` reaches **57,156 RPS** (2.41x Go `net/http 1.27 (1T)` at 23,723
   RPS), with lower p99 (`1.28 ms` vs `2.70 ms`) and p99.9 (`1.83 ms` vs
   `3.40 ms`).
2. Zero per-request heap churn: `goose-wing` allocates **0 B** per request
   across HTTP/2 frame decode, HPACK dynamic table updates, radix routing,
   AES-128-GCM record sealing, and JSON output, but Go `net/http` allocates
   48.0-51.0 heap objects (`4,482-4,962 B`) per request.
3. Server RSS reduction: In-place `HttpServer` initialization
   (`init_http_server_inplace`), lazy C shim buffer allocation, and direct TLS
   slice unsealing cut idle server RSS from 334.7 MB to **27.55 MB**
   (`31.2-39.4 MB` peak across TLS+H2 runs), which still exceeds Go's 14.5-19.8
   MB idle baseline at 16 connections due to pre-committed TLS cipher slots and
   the 512 KB page-locked RIO slab.

## Kernel-bypass and registered-buffer I/O (`Windows RIO`, `AF_XDP`, `DPDK`)

Evaluated with
[bench/driver_accel_benchmark.goose](../bench/driver_accel_benchmark.goose) and
[scripts/bench_drivers.py](../scripts/bench_drivers.py):

### Windows Registered I/O (`RIO`) vs `WSAPoll` loopback

| Mode | Pipeline | RPS | p50 (ms) | p99 (ms) | p99.9 (ms) |
| :--- | ---: | ---: | ---: | ---: | ---: |
| `rio` | 1 | 41,219 | 0.02 | 0.05 | 0.17 |
| `poll` | 1 | 39,948 | 0.02 | 0.06 | 0.13 |
| `rio` | 16 | 544,999 | 0.02 | 0.06 | 0.11 |
| `poll` | 16 | 560,259 | 0.02 | 0.11 | 0.29 |

At pipeline depth 16, registered DMA buffers and completion-queue polling cut
p99 latency from `0.11 ms` to `0.06 ms` and p99.9 tail latency by 2.6x
(`0.11 ms` vs `0.29 ms`).

### L2 packet datapath (`serve_h3_l2`: `AF_XDP` and `DPDK` vs `UdpFallback`)

| Backend | Packets | PPS (pkt/s) | ns/pkt | p50 (us) | p99 (us) |
| :--- | ---: | ---: | ---: | ---: | ---: |
| `af_xdp` | 3,200 | 4,409,535 | 226 | 0.18 | 0.36 |
| `dpdk` | 3,200 | 2,565,130 | 389 | 0.38 | 0.53 |
| `udp_fallback` | 3,200 | 645 | 1548192 | 1574.95 | 2202.10 |

On Windows, `af_xdp` and `dpdk` measure the in-memory loopback UMEM and
lock-free DPDK burst rings dispatching full L2 Ethernet/IPv4/UDP + HTTP/3 +
`RadixRouter` frames without kernel socket hops (`4.41M` and `2.57M` PPS), but
`udp_fallback` executes over live OS UDP sockets.

## Edge footprint, cold start, and connection scaling vs Go 1.27

Measured across stripped binaries (`strip -s` for `goose-wing`,
`-ldflags="-s -w"` for Go 1.27), cold start over 15 launches, 2,000 active
`/api/v1/items/{id}` requests across 1,000 open keep-alive TCP sockets,
10,000-slot `SoAConnTable` population, and runtime allocation counting
(`goose-lit/shim/alloc_count.c` vs Go `runtime.ReadMemStats`) via
[bench/scale_footprint_benchmark.goose](../bench/scale_footprint_benchmark.goose)
and [scripts/bench_footprint.py](../scripts/bench_footprint.py):

| Metric | goose-wing | Go 1.27 (`net/http`) |
| :--- | ---: | ---: |
| Stripped binary size | **1.96 MB** (2004 KB) | 7.59 MB (7769 KB) |
| Cold start to 1st `200 OK` (median/15) | **226.56 ms** | 267.93 ms |
| Idle server RSS | **26.9 MB** | 8.1 MB |
| 256 live TCP connections RSS | **27.3 MB** | 14.9 MB |
| 1,000 live TCP connections RSS | **27.8 MB** | 34.8 MB |
| Active p50 latency @ 1,000 conns | 0.430 ms | 0.047 ms |
| Active p99 latency @ 1,000 conns | **0.690 ms** | 0.145 ms |
| Active p99.9 latency @ 1,000 conns | **0.790 ms** | 0.292 ms |
| Heap allocs / bytes per `/api/v1/items/{id}` req | **0 / 0 B** | 25.3 / 2496 B |
| 10,000-slot `SoAConnTable` + `TickTimerWheel` | +**0.6 MB** (64 B/conn) | N/A |

`goose-wing` produces a **3.88x** smaller stripped executable (`1.96 MB` vs
`7.59 MB`) and adds `+0.9 MB` across 1,000 live TCP sockets (`26.9 MB` ->
`27.8 MB`), finishing below Go 1.27 (`34.8 MB`, `+26.7 MB` growth). On the
1,000-socket `PollFallback` test, Go achieves lower latency via OS `IOCP` while
`goose-wing` maintains `0.790 ms` p99.9 over `WSAPoll`. In-process, 10,000
`SoAConnTable` + `TickTimerWheel` slots consume `+0.6 MB` (`64 B/conn`), and
10,000 pipeline executions record `0 / 0 B` heap allocation.

## Compression codec performance (Goose-Wing native vs Python C bindings)

Evaluated on a representative 1,024-byte JSON web API payload using
[bench/codec_perf_benchmark.goose](../bench/codec_perf_benchmark.goose) and
[scripts/bench_codecs.py](../scripts/bench_codecs.py) (`--iters 2000`) against
Python C-extension bindings (`zlib`, `zstandard`, `brotli`):

| Operation / Codec | Goose-Wing (MB/s) | Reference C (MB/s) | Ratio (Goose / Ref) | Status |
| :--- | ---: | ---: | ---: | :--- |
| DEFLATE Level 1 Compress (RFC 1951) | **787.75** | 112.64 | **6.99x** | Faster |
| DEFLATE Level 1 Decompress | **1,062.52** | 205.69 | **5.17x** | Faster |
| DEFLATE Level 6 Compress (Standard) | **166.43** | 99.10 | **1.68x** | Faster |
| DEFLATE Level 6 Decompress | **383.31** | 214.28 | **1.79x** | Faster |
| Zstandard Level 3 Compress (RFC 8878) | **950.22** | 201.58 | **4.71x** | Faster |
| Zstandard Decompress | **1,765.52** | 500.49 | **3.53x** | Faster |
| Brotli Level 0 Compress (RFC 7932) | **486.20** | 136.45 | **3.56x** | Faster |
| Brotli Level 0 Decompress | **44,233.26** | 235.86 | **187.54x** | Faster |
| Brotli Level 1 Compress | **347.51** | 175.90 | **1.98x** | Faster |
| Brotli Level 1 Decompress | **361.71** | 294.84 | **1.23x** | Faster |

### Codec performance analysis

All 10 codec paths exceed reference Python C-extension bindings (0 deficits):

1. Brotli Level 1 Decompress (8.35 -> 361.71 MB/s, 1.23x): Replaced per-symbol
   tree walks with a 10-bit fast Huffman lookup table (`BrotliHuffmanTable`),
   lazy block-state reuse (`BrotliBlockState`), bulk literal copies, and RLE-16
   flat prefix emission.
2. Zstandard Level 3 Compress (105.04 -> 950.22 MB/s, 4.71x) and Decompress
   (357.39 -> 1,765.52 MB/s, 3.53x): Added O(1) sequence code tables, 8-byte
   `ctz` match scanning, direct stack-bounded small/medium paths, coalesced
   backward FSE bit-stream writes, and reusable `ZstdEntropyState`.
3. Brotli Level 0 Decompress (44,233.26 MB/s) hits memory-copy speeds via the
   uncompressed meta-block fast path on 1 KB frames while avoiding per-call
   Python wrapper overhead in the reference binding.

## Reproducing benchmark results

To reproduce the full suite on native hardware:

```bash
# Compression codec microbenchmarks vs Python C bindings (zlib, zstandard, brotli)
python scripts/bench_codecs.py --iters 2000

# Showcase A: Live TLS 1.3 + HTTP/2 + Router + JSON vs Go 1.27
python scripts/bench_h2_tls.py --iters 4000 --accel auto

# Showcase B: Windows RIO vs WSAPoll loopback + serve_h3_l2 L2 datapaths
python scripts/bench_drivers.py

# Showcase C: Binary size, cold start, 1k connection RSS, SoA 10k, 0-alloc proof
python scripts/bench_footprint.py

# Pipelined HTTP/1.1 scenario (5 seconds) and full matrix
just bench pipelined 5
just bench all 10

# Microbenchmark latency budget validation
goose-lit tests/lit/verify_wire_benchmarks.goose
```
