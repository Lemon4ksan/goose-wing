# `net`

Package `net` delivers the low-level, zero-allocation networking foundations of `goose-wing`. It provides high-performance TCP socket operations, an event loop reactor, connection pooling, Happy Eyeballs v3 (RFC 8305 / RFC 9460), DNS-over-HTTPS (RFC 8484), MASQUE HTTP datagram tunneling (RFC 9297, RFC 9298, RFC 9484), HAProxy PROXY protocol v1/v2, SOCKS5 proxying, and adaptive retry/circuit breaking.

All parsers and serializers operate with zero dynamic heap allocations on the hot path, leveraging stack-bounded buffers (`u8[..N]`) and zero-copy byte slices (`const u8[:]`).

## Public API Reference

### 1. TCP Sockets and I/O (`net/tcp.goose`)

Low-level POSIX and Windows socket operations with corking, vectored writes, keepalive tuning, and RFC 1122 abortive teardowns.

```goose
// Lifecycle
fn tcp_init() -> bool;
fn tcp_cleanup();

// Connection management
fn tcp_listen(host: const u8[:], port: u16 = 0, backlog: i32 = 128) -> i64;
fn tcp_listen_unix(path: const u8[:], backlog: i32 = 128) -> i64;
fn tcp_connect(host: const u8[:], port: u16, timeout_ms: u32 = 5000) -> i64;
fn tcp_connect_unix(path: const u8[:]) -> i64;
fn tcp_close(fd: i64);

// RFC 1122 §4.2.2.13 immediate abortive RST teardown
fn tcp_abort(fd: i64);

// Data transfer
fn tcp_send(fd: i64, data: const u8[:]) -> i64;
fn tcp_send2(fd: i64, h: const u8[:], b: const u8[:]) -> i64;
fn tcp_recv(fd: i64, buf: u8[:]) -> i64;

// Socket options and flow control
fn tcp_set_nodelay(fd: i64, enable: bool) -> bool;
fn tcp_set_cork(fd: i64, enable: bool) -> bool;
fn tcp_set_quickack(fd: i64, enable: bool) -> bool;
fn tcp_set_keepalive(fd: i64, enable: bool, idle_sec: i32 = 60, interval_sec: i32 = 10, count: i32 = 3) -> bool;
fn tcp_set_fastopen(fd: i64, enable: bool) -> bool;
```

### 2. Poller & Event Reactor (`net/poller.goose`)

Cross-platform I/O multiplexer dispatching across kernel-bypass and OS backends (io_uring, kqueue, Windows RIO, or standard poll).

```goose
enum PollInterest {
    None,
    Read,
    Write,
    ReadWrite,
}

struct PollReadyEvent {
    fd:       i32  = -1,
    tag:      u64  = 0,
    readable: bool = false,
    writable: bool = false,
    error:    bool = false,
}

struct Poller { .. }

fn new_poller(driver_cfg: const internal::TransportDriverConfig&) -> Poller;
fn close_poller(p: Poller&);
fn register_socket(p: Poller&, fd: i32, interest: PollInterest, tag: u64 = 0) -> bool;
fn modify_socket(p: Poller&, fd: i32, interest: PollInterest) -> bool;
fn deregister_socket(p: Poller&, fd: i32) -> bool;
fn poll_events(p: Poller&, timeout_ms: i32, out_events: PollReadyEvent[..64]&) -> i32;
```

### 3. DNS & DoH Resolution (`net/dns.goose`)

RFC 1035 wire decoding, RFC 8484 DNS-over-HTTPS (DoH), RFC 9460 HTTPS/SVCB service binding parameters, and stale-while-revalidate caching (RFC 5861).

```goose
enum DnsCacheStatus {
    Fresh,
    Stale,
    Expired,
}

struct HttpsRecord {
    priority: u16        = 0,
    target:   u8[..256]  = [],
    alpn:     u8[..64]   = [],
    port:     u16        = 0,
    ipv4hint: u8[..64]   = [],
    ipv6hint: u8[..128]  = [],
    ech:      u8[..512]  = [],
}

struct DnsResponse {
    id:        u16               = 0,
    rcode:     u8                = 0,
    a_ips:     u8[4][..8]        = [],
    a_ttls:    u32[..8]          = [],
    aaaa_ips:  u8[16][..8]       = [],
    aaaa_ttls: u32[..8]          = [],
    https_rec: HttpsRecord[..4]  = [],
}

struct DohResolver {
    endpoint: u8[..256] = "https://cloudflare-dns.com/dns-query",
    use_post: bool      = true,
}

fn parse_dns_response(raw: const u8[:]) -> DnsResponse, bool;
fn serialize_doh_query<B>(domain: const u8[:], qtype: u16, out: B&) -> bool;
```

### 4. Happy Eyeballs v3 (`net/happy_eyeballs.goose`)

RFC 8305 dual-stack IPv4/IPv6 candidate racing augmented with RFC 9460 HTTPS/SVCB protocol interleaving (HEv3) for QUIC/HTTP/3 vs TCP/HTTP/2 promotion.

```goose
enum AddressFamily {
    IPv4,
    IPv6,
}

enum L4Protocol {
    Tcp,
    Quic,
}

struct DnsCandidate {
    family:   AddressFamily = AddressFamily.IPv4,
    protocol: L4Protocol    = L4Protocol.Tcp,
    port:     u16           = 0,
    ip_len:   u8            = 4,
    ip:       u8[16]        = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    priority: u16           = 0,
}

fn interleave_candidates_he(
    ipv6: const DnsCandidate[:],
    ipv4: const DnsCandidate[:],
    out: DnsCandidate[..32]&,
);

fn interleave_protocols_hev3(
    candidates: const DnsCandidate[:],
    out: DnsCandidate[..32]&,
);
```

### 5. Connection Pooling & HTTP/2 Coalescing (`net/pool.goose`)

L4/L7 connection multiplexing, IP coalescing for HTTP/2 SAN matching, and cross-site partition keying.

```goose
enum PoolScheme {
    Http,
    Https,
    Ws,
    Wss,
}

struct OriginEndpoint {
    host: u8[..256] = [],
    port: u16       = 80,
}

struct StreamPool { .. }

fn new_origin_endpoint(host_str: const u8[:], port_num: u16) -> OriginEndpoint;
fn new_stream_pool(max_idle_per_host: i64 = 6, idle_timeout_sec: u64 = 90) -> StreamPool;
fn acquire_pooled_connection(pool: StreamPool&, key: const PoolKey&) -> i64, bool;
fn release_connection(pool: StreamPool&, conn_id: i64, reusable: bool);
```

### 6. MASQUE HTTP Datagram Tunneling (`net/masque.goose`)

RFC 9297 Capsule Protocol, RFC 9298 CONNECT-UDP, and RFC 9484 CONNECT-IP tunneling primitives over HTTP/2 and HTTP/3.

```goose
struct HttpCapsule {
    capsule_type: u64       = 0,
    payload:      const u8[:] = "",
}

struct MasqueTunnelConfig {
    proxy_uri: u8[..256] = [],
    use_h3:    bool      = true,
}

fn parse_http_capsule(src: const u8[:]) -> HttpCapsule, bool;
fn encode_http_capsule<B>(out: B&, capsule_type: u64, payload: const u8[:]) -> bool;
fn parse_connect_udp_path(path: const u8[:]) -> const u8[:], u16, bool;
```

### 7. PROXY Protocol v1 & v2 (`net/proxy_protocol.goose`)

Zero-copy HAProxy PROXY Protocol v1 (text) and v2 (binary with TLV extensions) framer and parser.

```goose
enum ProxyProtocolVersion {
    V1_Text,
    V2_Binary,
}

enum ProxyCommand {
    Local,
    Proxy,
}

enum ProxyTransportProtocol {
    Unspec,
    Stream,
    Dgram,
}

struct ProxyHeader {
    version:   ProxyProtocolVersion   = ProxyProtocolVersion.V2_Binary,
    command:   ProxyCommand           = ProxyCommand.Proxy,
    transport: ProxyTransportProtocol = ProxyTransportProtocol.Stream,
    src_port:  u16                    = 0,
    dst_port:  u16                    = 0,
    src_ip:    u8[16]                 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    dst_ip:    u8[16]                 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    ip_len:    u8                     = 4,
}

fn parse_proxy_header(raw: const u8[:]) -> ProxyHeader, i64, bool;
fn serialize_proxy_v1_header<B>(header: const ProxyHeader&, out: B&) -> bool;
fn serialize_proxy_v2_header<B>(header: const ProxyHeader&, out: B&) -> bool;
```

### 8. Retry, Backoff, and Circuit Breakers (`net/retry.goose`)

RFC 9110 Retry-After parser, decorrelated jitter backoff, token-bucket retry budget limits, and host-level circuit breakers.

```goose
enum JitterStrategy {
    Full,
    Equal,
    Decorrelated,
}

struct BackoffConfig {
    initial_delay_ms: u64            = 100,
    max_delay_ms:     u64            = 10000,
    multiplier:       u64            = 2,
    jitter:           JitterStrategy = JitterStrategy.Full,
}

struct HostCircuitBreaker { .. }

fn compute_backoff_jitter_ms(cfg: const BackoffConfig&, attempt: u32, rng_state: u64&) -> u64;
fn try_parse_retry_after_http(header_val: const u8[:], now_epoch_sec: u64) -> u64, bool;
fn evaluate_tier1_retry<Req>(req: const Req&, err_code: i32, bytes_sent: i64) -> bool;
```

### 9. Network Isolation Keys (`net/isolation.goose`)

Cross-site tracking defense via partitioned cache keys according to modern browser privacy partitioning standards.

```goose
struct NetworkIsolationKey {
    top_level_origin: u8[..256] = [],
    frame_origin:     u8[..256] = [],
}

fn new_network_isolation_key(top_level: const u8[:], frame: const u8[:]) -> NetworkIsolationKey;
fn empty_network_isolation_key() -> NetworkIsolationKey;
fn format_partitioned_key<B>(base_key: const u8[:], nik: const NetworkIsolationKey&, out: B&);
```
