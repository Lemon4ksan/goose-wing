# `net`

Package `net` provides zero-allocation TCP and UDP socket primitives, I/O event
multiplexing, Happy Eyeballs v3 racing, MASQUE tunneling, PROXY protocol
framing, connection pooling, and single-seed Deterministic Simulation Testing
(DST) for `goose-wing`.

All parsers and serializers operate without dynamic heap allocations on the hot
path, using stack-bounded buffers (`u8[..N]`) and zero-copy byte slices
(`const u8[:]`).

```goose
var poller = net::new_poller(net_internal::auto_transport_driver_config());
let fd = net::tcp_connect("93.184.216.34", 80, 5000);
poller.register_socket(fd as i32, 1, core::PollInterest.ReadWrite);
net::tcp_close(fd);
poller.close_poller();
```

## Public API Reference

### 1. TCP Sockets and Async Corking (`net/tcp.goose`)

```goose
struct BackPressure { pending: u8[>..], high_water_mark: i64, corked: bool }
fn async_socket_write(fd: i64, bp: BackPressure&, data: const u8[:]) -> i64
fn async_socket_uncork(fd: i64, bp: BackPressure&) -> i64
fn async_socket_drain(fd: i64, bp: BackPressure&) -> i64
fn tcp_init() -> bool
fn tcp_cleanup()
fn tcp_listen(host: const u8[:], port: u16 = 0, backlog: i32 = 128) -> i64
fn tcp_listen_unix(path: const u8[:], backlog: i32 = 128) -> i64
enum IpFamily { Auto, Ipv4Only, Ipv6Only }
fn tcp_connect(host: const u8[:], port: u16, timeout_ms: u32 = 5000) -> i64
fn tcp_connect_ex(host: const u8[:], port: u16, timeout_ms: u32 = 5000, ip_family: IpFamily = IpFamily.Auto, local_bind_addr: const u8[:] = "") -> i64
fn tcp_connect_unix(path: const u8[:]) -> i64
fn tcp_close(fd: i64)
fn tcp_abort(fd: i64)
fn tcp_send(fd: i64, data: const u8[:]) -> i64
fn tcp_send2(fd: i64, h: const u8[:], b: const u8[:]) -> i64
fn tcp_sendv(fd: i64, chunks: const u8[:][..16], count: i32) -> i64
fn tcp_recv(fd: i64, buf: u8[:]) -> i64
fn tcp_set_nodelay(fd: i64, enable: bool) -> bool
fn tcp_set_cork(fd: i64, enable: bool) -> bool
fn tcp_set_quickack(fd: i64, enable: bool) -> bool
fn tcp_set_keepalive(fd: i64, enable: bool, idle_sec: i32 = 60, interval_sec: i32 = 10, count: i32 = 3) -> bool
fn tcp_set_fastopen(fd: i64, enable: bool) -> bool
fn tcp_send_fastopen(fd: i64, host: const u8[:], port: u16, syn_payload: const u8[:]) -> i64
fn tcp_set_tos(fd: i64, dscp: u8, ecn: u8 = 0) -> bool
fn tcp_set_ecn(fd: i64, ecn_bits: u8) -> bool
struct TcpConnectOptions {
    src_ip: const u8[:], local_bind_addr: u8[..64], dst_ip: const u8[:],
    dst_port: u16, ip_family: IpFamily, so_mark: u32,
    ttl: i32, mss: i32, rcvbuf: i32, tcp_nodelay: bool,
    keepalive_idle_sec: i32, keepalive_intvl_sec: i32, keepalive_cnt: i32,
    user_timeout_ms: u32
}
fn tcp_connect_with_options(opts: const TcpConnectOptions&, out_state: i32&, out_err: i32&) -> i64
fn tcp_set_ttl(sock_fd: i64, ttl: i32, is_ipv6: bool = false) -> bool
fn tcp_set_mss(sock_fd: i64, mss: i32) -> bool
fn tcp_set_rcvbuf(sock_fd: i64, bytes: i32) -> bool
```

`BackPressure` coalesces user-space writes until `pending.len` reaches
`high_water_mark` or the caller invokes `async_socket_uncork`. `tcp_sendv` packs
up to 16 slices (`const u8[:][..16]`) into a single scatter-gather vectored
write, while `tcp_abort` forces an immediate RFC 1122 §4.2.2.13 RST teardown
(`SO_LINGER` with timeout 0) without waiting for `TIME_WAIT`. TCP Fast Open
(RFC 7413) attaches initial application bytes to the SYN packet via
`tcp_send_fastopen`, and `tcp_set_ecn` updates IPv4/IPv6 ECN bits while
preserving the active DSCP traffic class. `tcp_connect_ex` and
`tcp_connect_with_options` enforce `IpFamily` (`Auto`, `Ipv4Only`, `Ipv6Only`)
and bind an optional `local_bind_addr` before `connect()`;
`tcp_connect_with_options` also applies `SO_MARK`, `IP_TTL` /
`IPV6_UNICAST_HOPS`, `TCP_MAXSEG`, `SO_RCVBUF`, and `TCP_NODELAY` so the initial
SYN carries the configured OS profile. Blocking socket timeout waits use
`poll(2)` on POSIX to avoid `FD_SETSIZE` (`1024`) descriptor limits.

### 2. Unified Transport Handle (`net/transport.goose`)

```goose
enum Transport {
    Disconnected,
    Tcp { fd: i64 },
    Unix { fd: i64 },
    Tls { fd: i64, record_seq_rx: u64, record_seq_tx: u64, cipher_slot: u16 },
    TlsBackend { fd: i64, endpoint_slot: i64 },
    Udp { fd: i64, peer_ip4: u32, peer_port: u16 },
    Mock { route_idx: u16, cursor: u32 },
    Virtual { pipe_slot: u16, is_b_end: bool },
}
fn udp_bind(host: const u8[:], port: u16 = 0) -> i64
fn udp_recvfrom(sock_fd: i64, buf: u8[:], timeout_ms: u32, peer_ip4: u32&, peer_port: u16&) -> i32
fn is_connected(t: Transport) -> bool
fn send(t: Transport, data: const u8[:]) -> i32
fn recv_slice(t: Transport, dst: u8[:], timeout_ms: u32 = 5000) -> i32
fn close(t: Transport&)
fn virtual_pipe_inject_rst(pipe_slot: u16, is_b_end: bool) -> bool
```

`Transport` is a closed-polymorphism enum dispatching TCP, Unix domain, pure TLS
1.3 (`Tls`), pluggable TLS backend (`TlsBackend`, backed by
`tls::endpoint_transport_*`), UDP, mock, and in-memory virtual pipe I/O without
vtable indirection. `close` is idempotent: it tears down the active descriptor
or endpoint slot and resets `t` to `Transport.Disconnected`. `udp_recvfrom`
writes the peer IPv4 address and port into `peer_ip4` and `peer_port`, returning
the received payload length or `-1` on error.

### 3. Batch UDP Datagrams (`net/udp.goose`)

```goose
struct UdpDatagram { payload: u8[..1472], peer_ip4: u32, peer_port: u16, gso_size: u16 }
struct UdpBatchQueue { msgs: UdpDatagram[..32], count: i32, flushed_batches: u64, total_sent: u64, total_recvd: u64 }
fn build_udp_datagram(data: const u8[:], peer_ip4: u32, peer_port: u16, gso_size: u16 = 0) -> UdpDatagram, bool
fn enqueue_udp_datagram(queue: UdpBatchQueue&, fd: i32, dgram: const UdpDatagram&) -> i32, bool
fn batch_send_messages(queue: UdpBatchQueue&, fd: i32) -> i32, bool
fn batch_recv_messages(queue: UdpBatchQueue&, fd: i32) -> i32, bool
```

`UdpBatchQueue` batches `sendmmsg` and `recvmmsg` transitions over a bounded
32-packet queue (`UdpDatagram[..32]`) where each datagram holds a QUIC-safe
1472-byte UDP payload (`u8[..1472]`) and Generic Segmentation Offload segment
size (`gso_size`). When `enqueue_udp_datagram` reaches 32 buffered datagrams, it
flushes the full batch via `batch_send_messages` before appending packet 33 so
zero datagrams are silently dropped.

### 4. Poller, Event Reactor, Push Host & Driver Facade (`net/poller.goose`, `net/event_loop.goose`, `net/io_host.goose`, `net/driver.goose`)

```goose
struct Poller { ... }
struct EventLoop { ... }
struct Host { ... }
struct TcpDialer { default_timeout_ms: u32 = 5000 }
fn new_poller(driver_cfg: const net_internal::TransportDriverConfig&) -> Poller
fn enable_os_multiplexing(p: Poller&) -> bool
fn close_poller(p: Poller&)
fn enable_os_multiplexing(ev_loop: EventLoop&) -> bool
fn register_socket(p: Poller&, fd: i32, tag: u64, interest: core::PollInterest, trigger: core::PollTrigger = core::PollTrigger.Level) -> bool
fn modify_socket(p: Poller&, fd: i32, tag: u64, interest: core::PollInterest, trigger: core::PollTrigger = core::PollTrigger.Level) -> bool
fn deregister_socket(p: Poller&, fd: i32) -> bool
fn wake_tag(p: Poller&, tag: u64) -> bool
fn poll_events(p: Poller&, timeout_ms: i64, now_ns: u64, out_events: core::PollReadyEvent[..64]&) -> i32
fn dial_endpoint(d: const TcpDialer&, target: core::DialTarget) -> i64
fn new_host(driver_cfg: const net_internal::TransportDriverConfig&) -> Host
fn close_host(host: Host&)
fn link_listen(host: Host&, addr: core::ConnectAddr, owner: u16, tag: u64, backlog: i32) -> core::IoLink, core::IoError
fn link_local_port(host: const Host&, link: core::IoLink) -> u16
fn link_connect(host: Host&, addr: core::ConnectAddr, owner: u16, tag: u64) -> core::IoLink, core::ConnectStatus
fn open_virtual_pair(host: Host&, owner_a: u16, owner_b: u16, tag_a: u64 = 0, tag_b: u64 = 0) -> core::IoLink, core::IoLink, bool
fn link_send(host: Host&, link: core::IoLink, data: const u8[:]) -> i32, core::IoError
fn link_set_rx_paused(host: Host&, link: core::IoLink, paused: bool) -> bool
fn link_shutdown_write(host: Host&, link: core::IoLink) -> bool
fn link_close(host: Host&, link: core::IoLink) -> bool
fn link_abort(host: Host&, link: core::IoLink) -> bool
fn link_add_timer(host: Host&, timer_id: u64, delay_ms: u64, owner: u16, tag: u64, periodic: bool, now_ns: u64) -> bool
fn link_cancel_timer(host: Host&, timer_id: u64) -> bool
fn link_wake(host: Host&, token: core::WakeToken) -> bool
fn link_poll_dispatch<D>(host: Host&, driver: D&, timeout_ms: i64, now_ns: u64) -> i32
fn host_next_timer_ns(host: const Host&) -> u64, bool
```

`Host` implements the `core::host_*` push/completion contract across Linux
`epoll` & `io_uring` (`pbuf_ring`), Windows `WSAPoll` & `RIO`, macOS `kqueue`,
and in-memory virtual pairs, delivering generation-checked `IoLink` and
`WakeToken` events to passive protocol drivers (`core::on_link_event`). Both
`Poller` and `EventLoop` implement the shared `core::Poll*` and
`core::reactor_*` UFCS contract (`register_socket`, `modify_socket`,
`deregister_socket`, `add_timer`, `cancel_timer`, `wake_tag`, and
`poll_events`). Call `enable_os_multiplexing` to attach Linux `io_uring`
(`IORING_OP_POLL_ADD`) or `epoll`, macOS/BSD `kqueue`, or Windows `WSAPoll`
before calling `core::reactor_poll` on live sockets. `poll_events` harvests up
to 64 ready events per call into `out_events`, preserving the caller's 64-bit
`tag` for constant-time connection table lookup.

### 5. Socket Options & TCP/IP Stack Fingerprinting (`net/sockopt.goose`)

```goose
enum SocketP0fProfile { OSDefault, LinuxModern, Windows11, MacOS14, iOS17, Android14 }
struct SocketOptions {
    recv_buf_size: i32, send_buf_size: i32, ip_ttl: u8, tcp_mss: u16,
    tcp_window_clamp: i32, tcp_wscale: u8, ip_dont_fragment: bool,
    tcp_timestamps: bool, tcp_sack: bool, tcp_nodelay: bool, tcp_fastopen: bool
}
fn p0f_socket_config(profile: SocketP0fProfile) -> SocketOptions
fn validate_p0f_socket_invariants(opts: const SocketOptions&) -> bool
fn format_socket_p0f_summary<B>(opts: const SocketOptions&, out: B&)
fn apply_socket_options(fd: i64, opts: const SocketOptions&) -> bool
```

`p0f_socket_config` returns preset TCP/IP stack parameters (TTL, MSS, window
clamp, window scaling shift `0..14`, and `IP_DONTFRAG`) matching passive OS
fingerprinting profiles. `validate_p0f_socket_invariants` rejects out-of-range
TTL (`0`), invalid MSS (`< 536` or `> 9000`), or RFC 7323 window scale shifts
exceeding `14` before `apply_socket_options` configures the live socket.

### 6. Happy Eyeballs v3 (`net/happy_eyeballs.goose`)

```goose
enum AddressFamily { IPv6, IPv4 }
enum L4Protocol { Tcp, QuicUdp }
struct DnsCandidate {
    family: AddressFamily, l4_proto: L4Protocol, ip: u8[..64],
    port: u16, scope_id: u32, precedence: i32
}
struct DnsRaceTask { ... }
struct AttemptManager { ... }
fn new_dns_race_task(now_ms: i64, resolution_delay_ms: i64 = rfc::HE_RESOLUTION_DELAY_MS) -> DnsRaceTask
fn on_dns_aaaa_response(task: DnsRaceTask&, count: i32, now_ms: i64)
fn on_dns_a_response(task: DnsRaceTask&, count: i32, now_ms: i64)
fn check_dns_resolution_delay_tick(task: DnsRaceTask&, now_ms: i64) -> bool
fn new_attempt_manager(cad_ms: i64 = rfc::HE_DEFAULT_CAD_MS) -> AttemptManager
fn start_attempt_race(mgr: AttemptManager&, candidates: const DnsCandidate[:], now_ms: i64)
fn tick_attempt_manager(mgr: AttemptManager&, now_ms: i64) -> i32
fn bind_winner_attempt(mgr: AttemptManager&, idx: i32, now_ms: i64) -> bool
fn compute_effective_cad_ms(observed_rtt_ms: i64, rtt_known: bool, min_cad_ms: i64 = rfc::HE_MIN_CAD_MS, max_cad_ms: i64 = rfc::HE_MAX_CAD_MS) -> i64
fn interleave_candidates_he(ipv6_list: const DnsCandidate[:], ipv4_list: const DnsCandidate[:], out: DnsCandidate[..32]&, first_family_count: i32 = rfc::HE_FIRST_ADDRESS_FAMILY_COUNT)
fn interleave_protocols_hev3(candidates: const DnsCandidate[:], out: DnsCandidate[..32]&)
```

Happy Eyeballs v3 combines RFC 8305 dual-stack address interleaving with RFC
9460 `HTTPS` service binding prioritization. `DnsRaceTask` enforces the 50 ms
Resolution Delay (`rfc::HE_RESOLUTION_DELAY_MS`) when `A` records arrive before
`AAAA`. `interleave_candidates_he` and `interleave_protocols_hev3` order up to
32 candidates (`DnsCandidate[..32]`) so QUIC (`L4Protocol.QuicUdp`) and IPv6
candidates lead TCP and IPv4 fallbacks, while `AttemptManager` spaces parallel
connection attempts by the Connection Attempt Delay (`10 ms..2000 ms`, default
`250 ms`) and cancels in-flight losers when `bind_winner_attempt` succeeds.

### 7. Connection Pooling & HTTP/2 Coalescing (`net/pool.goose`)

```goose
enum PoolScheme { Http, Https, Socks5, Masque }
struct NetworkAnonymizationKey {
    top_frame_site: u8[..128], frame_site: u8[..128], is_cross_site: bool, nonce: u64
}
struct PoolKey {
    scheme: PoolScheme, host: u8[..256], port: u16, alpn: u8[..16],
    proxy_url: u8[..256], nak: NetworkAnonymizationKey
}
struct OriginEndpoint { host: u8[..256], port: u16, is_tls: bool, resolved_ip: u8[..64] }
struct StreamPool { ... }
struct UpstreamPool { entries: UpstreamKeepAliveEntry[..128] }
fn new_origin_endpoint(host_str: const u8[:], port_num: u16) -> OriginEndpoint
fn new_stream_pool(max_idle_per_host: i64 = 6, idle_timeout_sec: u64 = 90) -> StreamPool
fn configure_stream_pool(pool: StreamPool&, max_conns_per_host: i32, disable_keepalive: bool, idle_timeout_ns: i64 = -1)
fn acquire_pooled_connection(pool: StreamPool&, key: const PoolKey&, resolved_ip: const u8[:], now_ms: u64) -> i64, bool
fn release_connection(pool: StreamPool&, idx: i64, now_ms: u64)
fn acquire_upstream_conn(pool: UpstreamPool&, host: const u8[:], port: u16, is_tls: bool, now_ms: u64) -> i64
fn release_upstream_conn(pool: UpstreamPool&, fd: i64, host: const u8[:], port: u16, is_tls: bool, now_ms: u64) -> bool
```

`StreamPool` partitions client connections by `PoolKey` (including
`NetworkAnonymizationKey` to prevent cross-site timing leaks) and supports RFC
9113 §9.1.1 HTTP/2 connection coalescing when two origins share a resolved IP
and SAN certificate coverage. `configure_stream_pool` caps sockets per host
(`max_conns_per_host`), disables idle keep-alive reuse (`disable_keepalive`),
and updates `idle_timeout_ns`. `UpstreamPool` maintains up to 128 idle backend
keep-alive sockets (`UpstreamKeepAliveEntry[..128]`) for reverse proxy reuse;
`acquire_upstream_conn` returns `-1` on a cache miss.

### 8. MASQUE HTTP Datagram & IP Tunneling (`net/masque.goose`)

```goose
struct HttpCapsule { capsule_type: u64, payload: u8[..1500] }
struct IpAddressRequest { request_id: u64, ip_version: u8, address: u8[16], prefix_len: u8 }
struct IpAddressAssign { request_id: u64, ip_version: u8, address: u8[16], prefix_len: u8 }
struct RouteAdvertisement { ip_version: u8, start_address: u8[16], end_address: u8[16], ip_protocol: u8 }
struct MasqueTunnelSession { ... }
fn encode_http_capsule<B>(out: B&, capsule_type: u64, payload: const u8[:]) -> bool
fn parse_http_capsule(src: const u8[:]) -> HttpCapsule, bool
fn encode_http_datagram<B>(out: B&, quarter_stream_id: u64, context_id: u64, payload: const u8[:]) -> bool
fn decode_http_datagram(wire: const u8[:]) -> u64, u64, const u8[:], bool
fn format_connect_udp_path<B>(out: B&, target_host: const u8[:], target_port: u16)
fn new_connect_udp_tunnel(stream_id: u64, host: const u8[:], port: u16) -> MasqueTunnelSession
fn new_connect_ip_tunnel(stream_id: u64, target: const u8[:] = "*") -> MasqueTunnelSession
fn build_masque_connect_request(sess: const MasqueTunnelSession&, authority: const u8[:], out_req: Request&)
fn send_packet<B>(sess: MasqueTunnelSession&, packet: const u8[:], use_h3_dgram: bool, out_wire: B&) -> bool
fn receive_capsule(sess: MasqueTunnelSession&, wire: const u8[:], idx: i64&, out_packet: u8[..1500]&) -> bool, bool
fn receive_quic_datagram(sess: MasqueTunnelSession&, wire: const u8[:], out_packet: u8[..1500]&) -> bool
```

Implements RFC 9297 HTTP Datagrams and the Capsule Protocol alongside RFC 9298
(`connect-udp`) and RFC 9484 (`connect-ip`). `receive_capsule` advances `idx`
past a complete RFC 9297 variable-length integer capsule frame, updating `sess`
on `ADDRESS_ASSIGN`, `ADDRESS_REQUEST`, or `ROUTE_ADVERTISEMENT` capsules and
copying forwarded packets into `out_packet` (`u8[..1500]`); if `wire` is
truncated or malformed, `idx` is left at the failing offset and the trailing
`bool` is `false`.

### 9. PROXY Protocol v1 & v2 (`net/proxy_protocol.goose`, `net/proxy_protocol_internal.goose`)

```goose
enum ProxyProtocolVersion { None, V1, V2 }
enum ProxyCommand { Local, Proxy }
enum ProxyTransportProtocol { Unspec, Stream, Datagram }
struct ProxyHeader {
    version: ProxyProtocolVersion, command: ProxyCommand,
    transport: ProxyTransportProtocol, src_ip: u8[..64], dst_ip: u8[..64],
    src_port: u16, dst_port: u16, alpn: u8[..32], sni_authority: u8[..256],
    tls_cipher: u8[..64], crc32c: u32, has_crc32c: bool,
    unique_id: u8[..128], netns: u8[..128]
}
fn parse_proxy_header(wire: const u8[:]) -> ProxyHeader, i64, bool
fn parse_proxy_v1(wire: const u8[:]) -> ProxyHeader, i64, bool
fn parse_proxy_v2(wire: const u8[:]) -> ProxyHeader, i64, bool
fn format_proxy_v1<B>(hdr: const ProxyHeader&, out: B&) -> bool
fn format_proxy_v2<B>(hdr: const ProxyHeader&, out: B&) -> bool
fn append_proxy_v2_crc32c<B>(out: B&) -> bool
fn compute_proxy_v2_crc32c(wire_hdr: const u8[:]) -> u32
fn detect_and_strip_proxy_header(wire: const u8[:], out_hdr: ProxyHeader&) -> const u8[:], bool
```

`parse_proxy_header`, `parse_proxy_v1`, and `parse_proxy_v2` inspect leading
ingress bytes (`net/proxy_protocol.goose`, `net/proxy_protocol_internal.goose`)
and return `(hdr, consumed_bytes, ok)`, returning `consumed_bytes = 0` and
`ok = false` on malformed headers or failed RFC 3720 Castagnoli CRC32c
(`PP2_TYPE_CRC32C`) verification. `detect_and_strip_proxy_header` populates
`out_hdr` and returns the remaining zero-copy payload slice following the PROXY
header.

### 10. Forward Proxies & Slowloris Defense (`net/proxy.goose`)

```goose
enum ProxyScheme { Direct, Http, Https, Socks4, Socks4a, Socks5, Socks5h }
enum Socks5Error {
    None, InvalidVersion, NoAcceptableAuth, AuthFailed, InvalidAuthResponse,
    InvalidReplyHeader, ServerFailure, ConnectionNotAllowed, NetworkUnreachable,
    HostUnreachable, ConnectionRefused, TtlExpired, CommandNotSupported,
    AddressTypeNotSupported, BufferTruncated
}
enum ConnectTunnelError {
    None, InvalidStatusLine, ProxyAuthRequired, ConnectFailed,
    TunnelBufferedTooManyBytes, MalformedHeaders
}
enum SlowlorisViolation {
    None, HeaderTimeoutExpired, ExpectContinueTimeoutExpired,
    MaxHeaderBytesExceeded, MinIngressRateViolated, MaxHeaderCountExceeded
}
struct SlowlorisDefenseConfig { ... }
struct HeaderReader { ... }
fn socks5_client_handshake(sock_fd: i64, scheme: ProxyScheme, target_host: const u8[:], target_port: u16, username: const u8[:], password: const u8[:], timeout_ms: u32 = 5000) -> Socks5Error
fn http_connect_client_handshake(sock_fd: i64, target_host: const u8[:], target_port: u16, proxy_auth: const u8[:], user_agent: const u8[:], timeout_ms: u32 = 5000) -> ConnectTunnelError
fn sanitize_tunnel_headers_for_origin(headers: HeaderMap&)
fn new_header_reader(cfg: SlowlorisDefenseConfig, start_mono_ns: i64) -> HeaderReader
fn feed_header_bytes(reader: HeaderReader&, chunk: const u8[:], now_mono_ns: i64) -> SlowlorisViolation
```

`socks5_client_handshake` runs RFC 1928 negotiation and optional RFC 1929
username/password authentication, while `http_connect_client_handshake`
establishes an RFC 9110 §9.3.6 `CONNECT` tunnel and
`sanitize_tunnel_headers_for_origin` strips `Proxy-Authorization` and
`Proxy-Connection` before origin forwarding. `HeaderReader` accumulates ingress
header bytes up to `\r\n\r\n` and returns a `SlowlorisViolation` if the header
deadline, minimum byte rate, total header byte ceiling, or field count limit is
breached.

### 11. Retry, Backoff, and Circuit Breakers (`net/retry.goose`)

```goose
enum JitterStrategy { None, FullJitter, EqualJitter, DecorrelatedJitter }
struct BackoffConfig { base_ms: i64, cap_ms: i64, strategy: JitterStrategy }
struct AdaptiveRetryBudget { ... }
struct HostCircuitBreaker { ... }
struct Tier1Decision { retry_immediately: bool, disable_alternative_services: bool }
fn new_backoff_config(base: i64 = 100, cap: i64 = 10000, strat: JitterStrategy = JitterStrategy.FullJitter) -> BackoffConfig
fn compute_backoff_jitter_ms(cfg: const BackoffConfig&, attempt: i64, prev_sleep_ms: i64&, rng_seed: u64&) -> i64
fn new_adaptive_retry_budget(max_retry_ratio: f64 = 0.2, min_retries_per_sec: i32 = 10) -> AdaptiveRetryBudget
fn record_primary_request(budget: AdaptiveRetryBudget&, now_ms: i64)
fn allow_retry_budget(budget: AdaptiveRetryBudget&, now_ms: i64) -> bool
fn new_host_circuit_breaker(failure_threshold: i32 = 5, open_duration_ms: i64 = 30000) -> HostCircuitBreaker
fn trip_circuit_breaker_if_exceeded(cb: HostCircuitBreaker&, consecutive_failures: i32, now_ms: i64) -> bool
fn is_host_circuit_broken(cb: HostCircuitBreaker&, now_ms: i64) -> bool
fn should_retry_tier1_stale_socket<Req>(reused_connection: bool, req: const Req&, headers_received: bool = false) -> bool
fn evaluate_tier1_retry<Req>(err_code: i32, reused_connection: bool, req: const Req&, headers_received: bool = false) -> Tier1Decision
fn parse_retry_after_ms(header_raw: const u8[:], now_unix_ms: i64) -> i64, bool
```

`compute_backoff_jitter_ms` updates `prev_sleep_ms` and `rng_seed` in place to
compute exponential or decorrelated-jitter delays bounded by `cfg.cap_ms`.
`evaluate_tier1_retry` permits zero-delay replay on a fresh socket when a pooled
connection fails before response headers arrive, and disables broken QUIC
alternative services on `ERR_QUIC_PROTOCOL_ERROR`. `parse_retry_after_ms` parses
RFC 9110 §10.2.3 `Retry-After` headers in either delta-seconds or IMF-fixdate
format into non-negative milliseconds.

### 12. Reactor I/O Accelerators (`net/accel.goose`)

```goose
enum ReactorAccelMode { Auto, IoUring, Rio, Kqueue, PollFallback }
struct ReactorAccelRuntime { ... }
fn listen_accelerated_tcp(host: const u8[:], port: u16, accel_mode: ReactorAccelMode, backlog: i32 = 128) -> i64
fn reactor_init_accel(accel: ReactorAccelRuntime&, requested: ReactorAccelMode, listener_fd: i64) -> bool
fn reactor_close_accel(accel: ReactorAccelRuntime&)
fn reactor_reset_accel_slot(accel: ReactorAccelRuntime&, slot: i64)
```

`ReactorAccelRuntime` encapsulates Linux `io_uring`, Windows `RIO`, BSD/macOS
`kqueue`, and Linux `epoll` completion/readiness runtimes behind a uniform state
machine with automatic `poll`/`WSAPoll` fallback.

### 13. Network Isolation Keys (`net/isolation.goose`)

```goose
struct NetworkIsolationKey {
    top_level_site: u8[..128], frame_site: u8[..128], is_cross_site: bool, is_opaque: bool
}
fn new_network_isolation_key(top_level_url: const u8[:], frame_url: const u8[:]) -> NetworkIsolationKey
fn empty_network_isolation_key() -> NetworkIsolationKey
fn format_partitioned_key<B>(nik: const NetworkIsolationKey&, target_url: const u8[:], out: B&)
```

`NetworkIsolationKey` extracts registrable eTLD+1 sites from `top_level_url` and
`frame_url` into 128-byte buffers (`u8[..128]`) and formats partitioned
`nik=<top>|<frame>|<cs>|url=<target>` cache lookup keys via
`format_partitioned_key`.

### 14. Deterministic simulation testing (`net/dst.goose`)

```goose
enum DstDir { AToB, BToA }
enum DstFaultProfile { Clean, FragmentedTcp, MidStreamRst, LossyQuic, Chaos }
enum DstEventKind { None, TcpData, TcpFin, TcpRst, UdpDatagram, Timer }
struct DstFaultConfig { ... }
struct DstEndpoint { ip4: u32, port: u16, clock_skew_ns: i64, in_use: bool }
struct DstTcpLink { ... }
struct DstUdpLink { ep_a: u16, ep_b: u16, faults: DstFaultConfig, in_use: bool }
struct DstStats { ... }
struct DstStepResult { ... }
root struct DstWorld { ... }
fn dst_fault_profile(profile: DstFaultProfile) -> DstFaultConfig
fn dst_init(world: DstWorld&, seed: u64, start_ns: u64 = 1000000000)
fn dst_shutdown(world: DstWorld&)
fn dst_add_endpoint(world: DstWorld&, ip4: u32, port: u16, clock_skew_ns: i64 = 0) -> u16, bool
fn dst_set_endpoint_skew(world: DstWorld&, ep_id: u16, skew_ns: i64) -> bool
fn dst_endpoint_now_ns(world: const DstWorld&, ep_id: u16) -> u64
fn dst_endpoint_now_sec(world: const DstWorld&, ep_id: u16) -> i64
fn dst_jump_clock(world: DstWorld&, delta_ns: u64)
fn dst_open_tcp_link(world: DstWorld&, ep_a: u16, ep_b: u16, faults: const DstFaultConfig&) -> u16, bool
fn dst_attach_host_pair(world: DstWorld&, host: Host&, link_id: u16, owner_a: u16, owner_b: u16) -> core::IoLink, core::IoLink, bool
fn dst_set_tcp_faults(world: DstWorld&, link_id: u16, faults: const DstFaultConfig&) -> bool
fn dst_tcp_set_rx_window(world: DstWorld&, link_id: u16, dir: DstDir, window_bytes: i64) -> bool
fn dst_tcp_set_rx_paused(world: DstWorld&, link_id: u16, dir: DstDir, paused: bool) -> bool
fn dst_tcp_send(world: DstWorld&, link_id: u16, dir: DstDir, data: const u8[:]) -> i64, core::IoError
fn dst_tcp_recv(world: DstWorld&, link_id: u16, dir: DstDir, dst: u8[:]) -> i32, core::IoError
fn dst_tcp_shutdown_write(world: DstWorld&, link_id: u16, dir: DstDir) -> bool
fn dst_tcp_inject_rst(world: DstWorld&, link_id: u16, dir: DstDir, delay_ns: u64 = 0) -> bool
fn dst_open_udp_link(world: DstWorld&, ep_a: u16, ep_b: u16, faults: const DstFaultConfig&) -> u16, bool
fn dst_udp_rebind_endpoint_port(world: DstWorld&, ep_id: u16, new_port: u16) -> bool
fn dst_udp_send(world: DstWorld&, link_id: u16, dir: DstDir, data: const u8[:]) -> bool
fn dst_udp_recv(world: DstWorld&, link_id: u16, dir: DstDir, dst: u8[:]) -> i32, u32, u16, bool
fn dst_schedule_timer(world: DstWorld&, timer_id: u64, delay_ns: u64, owner: u16, tag: u64) -> bool
fn dst_cancel_timer(world: DstWorld&, timer_id: u64) -> bool
fn dst_next_event_ns(world: const DstWorld&) -> u64, bool
fn dst_step(world: DstWorld&) -> DstStepResult
fn dst_run_until(world: DstWorld&, max_ns: u64, max_steps: i64 = 100000) -> i64
fn dst_step_host<D>(world: DstWorld&, host: Host&, driver: D&) -> i32
```

`DstWorld` drives single-seed deterministic simulation across virtual TCP
streams, virtual UDP channels, timers, and `net::Host` virtual link pairs.
`dst_init` activates the deterministic virtual clock and `WyRand` entropy
override in `core/time/sim.goose`, and `dst_shutdown` restores live OS clock and
CSPRNG behavior. `dst_step` and `dst_run_until` jump virtual time directly to
the next scheduled event without wall-clock sleeps, maintaining a 64-bit running
trace digest (`world.stats.trace_digest`) over all delivered, dropped,
corrupted, and reset events for exact seed reproduction.

TCP fault injection covers latency and jitter, byte-level fragmentation
(`tcp_frag_min_bytes`..`tcp_frag_max_bytes`), receive-window backpressure,
half-close FIN, and scheduled or probabilistic mid-stream RST. UDP fault
injection adds packet drops, reordering spread, duplication, single-bit payload
corruption, and NAT source-port rebinding for QUIC and HTTP/3 testing.
Per-endpoint clock skew (`dst_set_endpoint_skew`) and instant clock jumps
(`dst_jump_clock`) validate JWT, DPoP, rate-limiter, and cache TTL expiration.

```goose
var world = net::DstWorld { .. };
net::dst_init(world, 0xC0FFEE_2026, 1700000000000000000);
defer net::dst_shutdown(world);

let cli, _ = net::dst_add_endpoint(world, 0x0A000001, 41000);
let srv, _ = net::dst_add_endpoint(world, 0x0A000002, 443);
let cfg = net::dst_fault_profile(net::DstFaultProfile.FragmentedTcp);
let link, _ = net::dst_open_tcp_link(world, cli, srv, cfg);

let _, _ = net::dst_tcp_send(world, link, net::DstDir.AToB, "GET / HTTP/1.1\r\n\r\n");
let _ = net::dst_run_until(world, world.now_ns + 500000000);
```
