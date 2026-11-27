# goose-wing vs uWebSockets Benchmark Harness

Reproducible Docker benchmark environment comparing **`goose-wing`** (written in
pure Goose) and **`uWebSockets`** (written in C++ by uNetworking) under
identical network, hardware, and kernel conditions.

## 1. Quick Start

### Web Benchmark Dashboard

```bash
cd tools/bench-vs-uwebsockets
docker compose up --build
```

Once started, open **`http://localhost:8080`** in your browser.

| Port | Service |
| :--- | :--- |
| 8080 | Interactive Web Benchmark Console & Orchestrator |
| 3001 | `goose-wing` Zero-Allocation HTTP/1.1 & WebSocket Server |
| 3002 | `uWebSockets` C++ Server (`uWS::App`) |

### Automated Headless CLI Benchmark

To run the automated test suite directly in terminal without a browser (ideal
for CI/CD):

```bash
docker compose run --rm benchmark --cli
```

## 2. Four Core Benchmark Disciplines

To prevent synthetic benchmark conflation, the harness and
`bench/server_profiling_benchmark.goose` separate server workloads into four
explicit disciplines, with Keep-Alive header memoization
(`enable_header_memoization`) **disabled by default (`false`)** so every single
request executes full 64-bit SWAR header parsing:

| Discipline | Focus Area | Workload & Configuration |
| :--- | :--- | :--- |
| **1. HTTP/1.1 Pipelined (depth 16 / 32)** | Wire throughput, Corking & Memoization comparison | Measured in two explicit modes: **(a) Without Memoization (`enable_header_memoization = false`, default)**: full SWAR parsing of every pipelined request; and **(b) With Keep-Alive Memoization (`set_header_memoization(server, true)`)**: opt-in Keep-Alive header block memoization (`g_h1_parse_cache` and pipelined batch draining). |
| **2. HTTP/1.1 Non-Pipelined (depth 1)** | Roundtrip latency & SWAR | 1 request per socket read/write turn (`L0_Plaintext_GET`, `Live_TCP_Roundtrip`, `wrk` depth 1). Measures per-turn syscall, framing, and 64-bit SWAR header scanner overhead without pipelined cork batching. |
| **3. Dynamic Route (`/users/:id`) + JSON Serialization** | Radix trie parameter extraction & `const for` JSON | Parameterized route matching (`/api/v1/users/{id}` via `RadixRouter` + `ZeroAllocParams`) and compile-time `const for` struct-to-JSON serialization into stack buffers (`Dynamic_Route_JSON_Serialize`). |
| **4. HTTP/2 (`h2load`)** | Multiplexed streams & HPACK | Concurrent stream multiplexing (`H2ServerSession`, 128-slot reactor pool `REACTOR_MAX_H2_SESSIONS = 128` across 4096-slot `SoAConnTable`), HPACK decoding, and flow-control window management. |
| **WebSocket Echo** | RFC 6455 64-bit Masking | In-place XOR payload unmasking via unrolled 64-bit SIMD/SWAR loop vs scalar C++ loop. |
| **High Concurrency (1,000+ conns)** | Scale & 4096-slot `SoAConnTable` | 1,000+ persistent keep-alive connections across the 4096-slot `SoAConnTable` (`SOA_TABLE_CAP = 4096`) and 1-second tick timer wheel. |

## 3. Empirical Reference Benchmarks

Conducted on an **Intel Core i5-12400F (6 P-Cores / 12 Threads)** on Linux
x86_64 (Ubuntu 24.04 container, `io_uring`/`epoll`, GCC `-O3 -flto`):

### Table 2. Benchmarks vs. uWebSockets

| Workload / Benchmark Suite | goose-wing (Goose) | uWebSockets (C++) | Delta |
| :--- | :---: | :---: | :---: |
| 1 Worker: Ping-Pong (`wrk`, 4 threads, 64 conns) | 178,859 req/s | 134,802 req/s | +32.7% |
| - Median / tail latency (p50 / p99.9) | 334.0 / 862.0 µs | 445.0 / 1,374.0 µs | -24.9% / -37.3% |
| - Transfer rate | 27.12 MB/s | 19.67 MB/s | +37.9% |
| 1 Worker: 32x Pipelined (`wrk`, 4 threads, 64 conns) | 176,433 req/s | 125,263 req/s | +40.8% |
| - Median / tail latency (p50 / p99) | 333.0 / 723.0 µs | 486.0 / 1,100.0 µs | -31.5% / -34.3% |
| - Transfer rate | 26.75 MB/s | 18.28 MB/s | +46.3% |
| 3 Workers: Ping-Pong (`wrk`, 3 threads, 96 conns) | 515,458 req/s | 494,432 req/s | +4.3% |
| - Median latency (p50) | 102.0 µs | 115.0 µs | -11.3% |
| 3 Workers: 32x Pipelined (`wrk`, 3 threads, 96 conns) | 535,148 req/s | 508,459 req/s | +5.2% |
| - Median / tail latency (p50 / p99.9) | 100.0 / 385.0 µs | 112.0 / 466.0 µs | -10.7% / -17.4% |
| 4 Workers: Ping-Pong (`wrk`, 4 threads, 128 conns) | 679,778 req/s | 659,075 req/s | +3.1% |
| - Median / tail latency (p50 / p99.9) | 103.0 / 680.0 µs | 117.0 / 853.0 µs | -12.0% / -20.3% |
| 4 Workers: 32x Pipelined (`wrk`, 4 threads, 128 conns) | 625,234 req/s | 584,258 req/s | +7.0% |
| - Median latency (p50) | 109.0 µs | 127.0 µs | -14.2% |
| 4 Workers: Keep-Alive 10k conns (`wrk`, 4 threads) | 385,007 req/s | 376,188 req/s | +2.3% |
| - Tail latency (p99.9) | 21,498 µs | 25,784 µs | -16.6% |
| 4 Workers: Dynamic Route + 2KB JSON (`wrk`, 128 conns) | 460,460 req/s | 301,484 req/s | +52.7% |
| - Tail latency (p95 / p99) | 1,342.0 / 10,915 µs | 6,041.0 / 14,753 µs | -77.8% / -26.0% |
| - Transfer rate | 972.80 MB/s | 635.42 MB/s | +53.1% |
| 4 Workers: HTTP/2 h2c (`h2load`, 64c x 16) | 161,184 req/s | N/A | Native RFC 9113 |
| 4 Workers: TLS 1.3 HTTP/2 (`h2load`, 64c x 16) | 183,978 req/s | N/A | Native TLS 1.3 + H2 |
| 6 Workers: 128x Pipelined (`wrk`, 512 conns) | 830,063 req/s | 763,720 req/s | +8.7% |
| - Median / tail latency (p50 / p99.9) | 334.0 / 13,524 µs | 376.0 / 15,377 µs | -11.2% / -12.1% |
| - Transfer rate | 125.87 MB/s | 111.44 MB/s | +12.9% |
| 6 Workers: C Burst (`bench_burst`, 512 conns, 64x) | 9,766,267 req/s | 7,944,337 req/s | +22.9% |
| - Transfer rate | 1,480.90 MB/s | 1,159.18 MB/s | +27.8% |
| Heap allocations per request | 0 B (0 allocs) | 0 B (0 allocs) | Parity |

```text
====================================================================================
 SUITE: Physical-Core-Isolated & Shared-SMT Comparison (GCC -O3 -flto, 0 Err, 0 T/O)
====================================================================================
| Scenario                     |       goose-wing |      uWebSockets |          Delta |
|------------------------------|------------------|------------------|----------------|
| 1W Ping-Pong (64c)           |     178,859 req/s|     134,802 req/s|         +32.7% |
| 1W 32x Pipelined (64c)       |     176,433 req/s|     125,263 req/s|         +40.8% |
| 3W Ping-Pong (96c)           |     515,458 req/s|     494,432 req/s|          +4.3% |
| 3W 32x Pipelined (96c)       |     535,148 req/s|     508,459 req/s|          +5.2% |
| 4W Ping-Pong (128c)          |     679,778 req/s|     659,075 req/s|          +3.1% |
| 4W 32x Pipelined (128c)      |     625,234 req/s|     584,258 req/s|          +7.0% |
| 4W Keep-Alive 10k conns      |     385,007 req/s|     376,188 req/s|          +2.3% |
| 4W Dynamic Route + 2KB JSON  |     460,460 req/s|     301,484 req/s|         +52.7% |
| 4W HTTP/2 h2c (64c x 16)     |     161,184 req/s|              N/A |  Native H2     |
| 4W TLS 1.3 HTTP/2 (64c x 16) |     183,978 req/s|              N/A |  Native TLS+H2 |
| 6W 128x Pipelined (512c)     |     830,063 req/s|     763,720 req/s|          +8.7% |
| 6W C Burst (512c, 64x)       |   9,766,267 req/s|   7,944,337 req/s|         +22.9% |
| Heap Allocations per request |       0 B / 0 al |       0 B / 0 al |         Parity |
====================================================================================
```

## 4. Key Architectural Advantages

### 1. Zero-Heap Allocation Invariant (0 B malloc)

- **`uWebSockets`**: Uses standard C++ dynamic memory (`std::string`,
  `uWS::HttpResponseData`, per-connection socket buffers). Under high
  concurrency (1k-10k connections), glibc's `ptmalloc` experiences thread arena
  lock contention, page fragmentation, and unbounded RSS growth.
- **`goose-wing`**: Allocates **0 bytes from the dynamic heap** during request
  handling. State machines, URL parameter maps (`ZeroAllocParams`), and header
  tokenizers execute on statically bounded compiler-managed data stacks.

### 2. Tail Latency Predictability (p99 / p99.9)

- By eliminating runtime memory allocator locks, cache churn from dynamic
  pointers, and garbage collection pauses, `goose-wing` maintains predictable
  low tail latency (e.g. **385 µs** p99.9 on `3W 32x Pipelined` and **680 µs**
  p99.9 on `4W Ping-Pong`) without `wrk` timeouts.

### 3. 64-bit SWAR Lexical Tokenizer

- Instead of scanning HTTP request streams byte-by-byte with a traditional state
  machine, `goose-wing` checks 8 bytes per CPU instruction cycle via 64-bit SWAR
  (SIMD Within A Register) operations to scan CRLF boundaries, methods, and
  header colons.

### 4. Vectorized WebSocket Masking

- RFC 6455 requires all client-to-server WebSocket frames to be masked with a
  4-byte key. `goose-wing` implements an unrolled 64-bit SIMD/SWAR XOR loop that
  processes 64 bytes per iteration directly in-place on data stacks, avoiding
  intermediate buffer copies.

### 5. Built-in Defense-in-Depth

- `goose-wing` enforces wire-level defenses against:
  - CVE-2023-44487 (HTTP/2 Rapid Reset)
  - CONTINUATION Flood attacks
  - RFC 9112 Section 6.1 Request Smuggling (TE.CL / CL.TE conflict detection)
  - Slowloris socket tarpits via bounded nanosecond timer wheels.

## 5. Local Reproduction Without Docker

If you have a local C compiler (`gcc`) and Python 3 installed:

```powershell
# 1. Compile goose-wing server on Windows / POSIX
gcc -O2 -I. .\tools\bench-vs-uwebsockets\server_goose_wing.c .\shim\tcp.c .\shim\simd.c -lws2_32 -lmswsock -o .\tools\bench-vs-uwebsockets\server_goose_wing.exe

# 2. Run the orchestrator
python .\tools\bench-vs-uwebsockets\orchestrator.py
```
