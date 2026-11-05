# `net`

Package `net` delivers the low-level, zero-allocation networking foundations of `goose-wing`. It provides high-performance TCP socket operations, an event loop reactor, connection pooling, Happy Eyeballs v3 (RFC 8305 / RFC 9460), DNS-over-HTTPS (RFC 8484), MASQUE HTTP datagram tunneling (RFC 9297, RFC 9298, RFC 9484), HAProxy PROXY protocol v1/v2, SOCKS5 proxying, and adaptive retry/circuit breaking.

All parsers and serializers operate with zero dynamic heap allocations on the hot path, using stack-bounded buffers (`u8[..N]`) and zero-copy byte slices (`const u8[:]`).

## Public API Reference

### 1. TCP Sockets and I/O (`net/tcp.goose`)

Low-level POSIX and Windows socket operations with corking, vectored writes, keepalive tuning, and RFC 1122 abortive teardowns.

- **`fn tcp_init() -> bool`**: Initializes socket subsystem.
- **`fn tcp_cleanup()`**: Cleans up socket subsystem.
- **`fn tcp_listen(host: const u8[:], port: u16 = 0, backlog: i32 = 128) -> i64`**: Binds and listens on TCP port.
- **`fn tcp_listen_unix(path: const u8[:], backlog: i32 = 128) -> i64`**: Binds and listens on UNIX domain socket.
- **`fn tcp_connect(host: const u8[:], port: u16, timeout_ms: u32 = 5000) -> i64`**: Connects to remote TCP endpoint.
- **`fn tcp_connect_unix(path: const u8[:]) -> i64`**: Connects to UNIX domain socket.
- **`fn tcp_close(fd: i64)`**: Gracefully closes socket file descriptor.
- **`fn tcp_abort(fd: i64)`**: RFC 1122 §4.2.2.13 immediate abortive RST teardown.
- **`fn tcp_send(fd: i64, data: const u8[:]) -> i64`**: Sends byte buffer over socket.
- **`fn tcp_send2(fd: i64, h: const u8[:], b: const u8[:]) -> i64`**: Vectored send combining header and body buffers.
- **`fn tcp_recv(fd: i64, buf: u8[:]) -> i64`**: Receives bytes into buffer.
- **`fn tcp_set_nodelay(fd: i64, enable: bool) -> bool`**: Toggles TCP_NODELAY (Nagle algorithm disable).
- **`fn tcp_set_cork(fd: i64, enable: bool) -> bool`**: Toggles TCP_CORK packet coalescing.
- **`fn tcp_set_quickack(fd: i64, enable: bool) -> bool`**: Toggles TCP_QUICKACK.
- **`fn tcp_set_keepalive(fd: i64, enable: bool, idle_sec: i32 = 60, interval_sec: i32 = 10, count: i32 = 3) -> bool`**: Configures keepalive probes.
- **`fn tcp_set_fastopen(fd: i64, enable: bool) -> bool`**: Toggles TCP Fast Open.

### 2. Poller & Event Reactor (`net/poller.goose`)

Cross-platform I/O multiplexer dispatching across kernel-bypass and OS backends (io_uring, kqueue, Windows RIO, or standard poll).

- **`enum PollInterest`**: Socket event interest (`None`, `Read`, `Write`, `ReadWrite`).
- **`struct PollReadyEvent`**: Readiness event holding socket fd, user tag, readable/writable flags, and error status.
- **`struct Poller`**: Cross-platform I/O multiplexer.
- **`fn new_poller(driver_cfg: const internal::TransportDriverConfig&) -> Poller`**: Constructs event poller.
- **`fn close_poller(p: Poller&)`**: Closes poller and frees underlying OS resources.
- **`fn register_socket(p: Poller&, fd: i32, interest: PollInterest, tag: u64 = 0) -> bool`**: Registers socket interest.
- **`fn modify_socket(p: Poller&, fd: i32, interest: PollInterest) -> bool`**: Modifies registered socket interest.
- **`fn deregister_socket(p: Poller&, fd: i32) -> bool`**: Deregisters socket from poller.
- **`fn poll_events(p: Poller&, timeout_ms: i32, out_events: PollReadyEvent[..64]&) -> i32`**: Polls ready I/O events.

### 3. DNS & DoH Resolution (`net/dns.goose`)

RFC 1035 wire decoding, RFC 8484 DNS-over-HTTPS (DoH), RFC 9460 HTTPS/SVCB service binding parameters, and stale-while-revalidate caching (RFC 5861).

- **`enum DnsCacheStatus`**: Cache freshness status (`Fresh`, `Stale`, `Expired`).
- **`struct HttpsRecord`**: RFC 9460 HTTPS/SVCB service binding parameters.
- **`struct DnsResponse`**: Parsed DNS wire response holding IP addresses and HTTPS records.
- **`struct DohResolver`**: DNS-over-HTTPS resolver client.
- **`fn parse_dns_response(raw: const u8[:]) -> DnsResponse, bool`**: Zero-copy parser for RFC 1035 DNS wire responses.
- **`fn serialize_doh_query<B>(domain: const u8[:], qtype: u16, out: B&) -> bool`**: Serializes RFC 8484 DoH query.

### 4. Happy Eyeballs v3 (`net/happy_eyeballs.goose`)

RFC 8305 dual-stack IPv4/IPv6 candidate racing augmented with RFC 9460 HTTPS/SVCB protocol interleaving (HEv3) for QUIC/HTTP/3 vs TCP/HTTP/2 promotion.

- **`enum AddressFamily`**: Network address family (`IPv4`, `IPv6`).
- **`enum L4Protocol`**: Transport layer protocol (`Tcp`, `Quic`).
- **`struct DnsCandidate`**: Resolved network endpoint candidate.
- **`fn interleave_candidates_he(ipv6: const DnsCandidate[:], ipv4: const DnsCandidate[:], out: DnsCandidate[..32]&)`**: RFC 8305 IPv4/IPv6 address interleaving.
- **`fn interleave_protocols_hev3(candidates: const DnsCandidate[:], out: DnsCandidate[..32]&)`**: RFC 9460 protocol interleaving.

### 5. Connection Pooling & HTTP/2 Coalescing (`net/pool.goose`)

L4/L7 connection multiplexing, IP coalescing for HTTP/2 SAN matching, and cross-site partition keying.

- **`enum PoolScheme`**: Connection protocol scheme (`Http`, `Https`, `Ws`, `Wss`).
- **`struct OriginEndpoint`**: Target endpoint identifier.
- **`struct StreamPool`**: Multiplexed connection pool.
- **`fn new_origin_endpoint(host_str: const u8[:], port_num: u16) -> OriginEndpoint`**: Constructs origin endpoint.
- **`fn new_stream_pool(max_idle_per_host: i64 = 6, idle_timeout_sec: u64 = 90) -> StreamPool`**: Constructs connection pool.
- **`fn acquire_pooled_connection(pool: StreamPool&, key: const PoolKey&) -> i64, bool`**: Acquires pooled connection matching key.
- **`fn release_connection(pool: StreamPool&, conn_id: i64, reusable: bool)`**: Releases connection back to pool.

### 6. MASQUE HTTP Datagram Tunneling (`net/masque.goose`)

RFC 9297 Capsule Protocol, RFC 9298 CONNECT-UDP, and RFC 9484 CONNECT-IP tunneling primitives over HTTP/2 and HTTP/3.

- **`struct HttpCapsule`**: Parsed RFC 9297 Capsule Protocol frame.
- **`struct MasqueTunnelConfig`**: MASQUE proxy tunnel configuration.
- **`fn parse_http_capsule(src: const u8[:]) -> HttpCapsule, bool`**: Parses capsule frame.
- **`fn encode_http_capsule<B>(out: B&, capsule_type: u64, payload: const u8[:]) -> bool`**: Serializes capsule frame.
- **`fn parse_connect_udp_path(path: const u8[:]) -> const u8[:], u16, bool`**: Parses RFC 9298 CONNECT-UDP request URI.

### 7. PROXY Protocol v1 & v2 (`net/proxy_protocol.goose`)

Zero-copy HAProxy PROXY Protocol v1 (text) and v2 (binary with TLV extensions) framer and parser.

- **`enum ProxyProtocolVersion`**: Wire version (`V1_Text`, `V2_Binary`).
- **`enum ProxyCommand`**: Command mode (`Local`, `Proxy`).
- **`enum ProxyTransportProtocol`**: Transport protocol (`Unspec`, `Stream`, `Dgram`).
- **`struct ProxyHeader`**: Parsed PROXY protocol header with source and destination addresses.
- **`fn parse_proxy_header(raw: const u8[:]) -> ProxyHeader, i64, bool`**: Zero-copy parser for PROXY v1/v2 headers.
- **`fn serialize_proxy_v1_header<B>(header: const ProxyHeader&, out: B&) -> bool`**: Serializes PROXY v1 text header.
- **`fn serialize_proxy_v2_header<B>(header: const ProxyHeader&, out: B&) -> bool`**: Serializes PROXY v2 binary header.

### 8. Retry, Backoff, and Circuit Breakers (`net/retry.goose`)

RFC 9110 Retry-After parser, decorrelated jitter backoff, token-bucket retry budget limits, and host-level circuit breakers.

- **`enum JitterStrategy`**: Jitter algorithm (`Full`, `Equal`, `Decorrelated`).
- **`struct BackoffConfig`**: Exponential backoff and jitter configuration.
- **`struct HostCircuitBreaker`**: Host-level circuit breaker state machine.
- **`fn compute_backoff_jitter_ms(cfg: const BackoffConfig&, attempt: u32, rng_state: u64&) -> u64`**: Calculates decorrelated jitter delay.
- **`fn try_parse_retry_after_http(header_val: const u8[:], now_epoch_sec: u64) -> u64, bool`**: Parses RFC 9110 Retry-After header.
- **`fn evaluate_tier1_retry<Req>(req: const Req&, err_code: i32, bytes_sent: i64) -> bool`**: Evaluates request idempotency for retry safety.

### 9. Network Isolation Keys (`net/isolation.goose`)

Cross-site tracking defense via partitioned cache keys according to modern browser privacy partitioning standards.

- **`struct NetworkIsolationKey`**: Partitioned isolation key holding top-level origin and frame origin.
- **`fn new_network_isolation_key(top_level: const u8[:], frame: const u8[:]) -> NetworkIsolationKey`**: Constructs isolation key.
- **`fn empty_network_isolation_key() -> NetworkIsolationKey`**: Returns empty isolation key.
- **`fn format_partitioned_key<B>(base_key: const u8[:], nik: const NetworkIsolationKey&, out: B&)`**: Serializes partitioned cache key.
