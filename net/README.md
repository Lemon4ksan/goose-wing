# `net`

Package `net` (`namespace net;`) provides TCP and UDP sockets, event
multiplexers (`Poller`, `EventLoop`, `Host`), unified `Transport` handles,
connection pooling, Happy Eyeballs v3 racing, forward proxy handshakes (HTTP
CONNECT, SOCKS4/5, MASQUE), HAProxy PROXY protocol framing, retry and
circuit-breaker controls, and single-seed Deterministic Simulation Testing
(DST).

Hot-path parsers and wire encoders avoid heap allocation by operating on
stack-bounded buffers (`u8[..N]`) and byte slices (`const u8[:]`). Native C
shims and internal wire/loop mechanics live in `namespace net_internal;` across
`net/internal.goose`, `net/tunnel_internal.goose`, `net/pool_internal.goose`,
`net/poller_internal.goose`, `net/io_host_internal.goose`,
`net/io_host_loop_internal.goose`, `net/proxy_protocol_internal.goose`,
`net/wasm_loopback_internal.goose`, `net/dst_internal.goose`, and `net/driver/`.
WASM loopback rings and non-Linux UDP batch fallbacks execute in pure Goose.

## Quick start

```goose
import wing;

let fd = net::tcp_connect("93.184.216.34", 80, 5000);
guard fd > 0 else { return; }
defer net::tcp_close(fd);

let req = "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
let _ = net::tcp_send(fd, req);

var buf: u8[..4096] = [];
let n = net::tcp_recv(fd, buf, 4096, 5000);
print("read bytes: ", n, "\n");
```

## Task recipes

### DNS-rebinding-safe resolve-then-connect

Standard `tcp_connect(host, port)` resolves DNS inside the connect call, which
leaves a TOCTOU window if an attacker rebinds DNS between SSRF validation and
`connect(2)`. Use `tcp_connect_resolved` to resolve once, validate every
returned IP fail-closed inside the trailing block, and dial strictly by numeric
IP literal (`tcp_connect_ip`). Pass the original hostname explicitly as TLS SNI.

```goose
var connected_ip: u8[..64] = [];
let fd = net::tcp_connect_resolved(
    "api.example.com", 443, connected_ip, 5000, net::IpFamily.Auto,
) { ip, allowed =>
    allowed = !security::is_private_or_reserved_ip(ip);
};
guard fd > 0 else { return; }
defer net::tcp_close(fd);
```

When you manage IP selection manually (for example with Happy Eyeballs or custom
pinning), call `resolve_host_ips` followed by `tcp_connect_ip`:

```goose
var ips: u8[..64][..16] = [];
guard net::resolve_host_ips("api.example.com", ips, net::IpFamily.Ipv4Only) else {
    return;
}
let fd = net::tcp_connect_ip(ips[0][..], 443, 5000, net::IpFamily.Ipv4Only);
```

### TCP/UDP sockets and options

Listen on a local TCP port, tune socket latency flags, or batch up to 32 UDP
datagrams through `sendmmsg`/`recvmmsg` via `UdpBatchQueue`:

```goose
let lst = net::tcp_listen("127.0.0.1", 0, 128);
guard lst > 0 else { return; }
defer net::tcp_close(lst);

let port = net::tcp_getsockname_port(lst);
let _ = net::tcp_set_nodelay(lst, true);
let _ = net::tcp_set_keepalive(lst, 30, 10, 3);
```

For non-blocking outbound sockets with corking and FIFO backpressure draining,
pair `core::CorkBuffer` with `net::BackPressure` and call `async_socket_write`,
`async_socket_uncork`, and `async_socket_drain`. For batched UDP:

```goose
var q = net::UdpBatchQueue { .. };
let dgram, ok = net::build_udp_datagram("ping", 0x7F000001, 9000);
if ok {
    let _, _ = net::enqueue_udp_datagram(q, udp_fd as i32, dgram);
    let _, _ = net::batch_send_messages(q, udp_fd as i32);
}
```

### Unified `Transport`, `Poller`, and `Host`

Wrap TCP, Unix domain, TLS, UDP, or in-memory virtual pipe descriptors behind
`Transport` for closed-polymorphism `send`, `recv_slice`, and idempotent
`close`:

```goose
var a, b, ok = net::open_virtual_pipe_pair();
guard ok else { return; }
defer a.close();
defer b.close();

let _ = a.send("hello");
var rx: u8[64] = [0; 64];
let n = b.recv_slice(rx[..], 1000);
```

Multiplex live sockets and coarse timers with `Poller` (Linux `io_uring` or
`epoll`, macOS/BSD `kqueue`, Windows `WSAPoll`/`RIO`):

```goose
var poller = net::new_poller(net_internal::auto_transport_driver_config());
defer poller.close_poller();
let _ = poller.enable_os_multiplexing();
let _ = poller.register_socket(fd as i32, 1, core::PollInterest.ReadWrite);

var events: core::PollReadyEvent[..64] = [];
let ready = poller.poll_events(100, now_ns, events);
```

For push-completion drivers implementing `core::on_link_event`, use `Host`
(`new_host`, `link_listen`, `link_connect`, `link_send`, `link_poll_dispatch`).

### Connection pool and Happy Eyeballs

Partition client connections across a 5-dimensional `PoolKey` (scheme, origin,
proxy chain, `NetworkAnonymizationKey`, and `TlsAndDnsPolicy`) and reuse idle or
HTTP/2-coalesced sockets in `StreamPool`:

```goose
var pool = net::new_stream_pool();
net::configure_stream_pool(pool, 6, false, 90000000000);

let key = net::new_pool_key(
    net::PoolScheme.Https,
    "api.example.com",
    443,
    net::new_direct_proxy_chain(),
    net::new_network_anonymization_key("https://example.com"),
    net::TlsAndDnsPolicy { .. },
);
let conn_id, hit = net::acquire_pooled_connection(pool, key, "93.184.216.34", now_ns);
```

For dual-stack and HTTP/3 racing (RFC 8305 + RFC 9460), feed AAAA/A responses
into `DnsRaceTask`, order candidates with `interleave_candidates_he` and
`interleave_protocols_hev3`, and pace attempts with `AttemptManager`.

### HTTP CONNECT, SOCKS5, PROXY protocol, and MASQUE

Upgrade a connected proxy socket through HTTP CONNECT (RFC 9110) or SOCKS5 (RFC
1928/1929):

```goose
let err_hc = net::http_connect_client_handshake(
    proxy_fd, "api.example.com", 443, "", "goose-wing/1.0", 5000,
);
let err_s5 = net::socks5_client_handshake(
    socks_fd, net::ProxyScheme.Socks5h, "api.example.com", 443, "", "", 5000,
);
```

Strip leading HAProxy PROXY v1 or v2 headers on server ingress with zero-copy
payload slicing:

```goose
var hdr = net::ProxyHeader { .. };
let payload, has_proxy = net::detect_and_strip_proxy_header(wire, hdr);
```

Open a MASQUE `connect-udp` (RFC 9298) or `connect-ip` (RFC 9484) tunnel session
and exchange capsules or QUIC datagrams:

```goose
var tun = net::new_connect_udp_tunnel("https://proxy.example.com:443", "1.1.1.1", 53, 4);
var headers = http::HeaderMap { .. };
var path: u8[..256] = [];
net::build_masque_connect_request(tun, headers, path);
```

### Deterministic simulation testing (DST)

Run reproducible, wall-clock-free TCP, UDP, and timer fault injection under a
single PRNG seed with `DstWorld`:

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

## Public API reference

### TCP sockets, DNS-pinning, and async corking (`net/tcp.goose`)

Blocking and non-blocking TCP/Unix sockets, resolve-then-connect IP pinning,
socket tuning options, kernel splice, and FIFO backpressure corking.

```goose
enum IpFamily { Auto, Ipv4Only, Ipv6Only }
struct TcpConnectOptions { .. }
struct BackPressure { .. }
struct FreeSlotStack { .. }
struct BackpressureSlot { .. }

fn tcp_init() -> bool
fn tcp_cleanup()
fn tcp_listen(host: const u8[:], port: u16 = 0, backlog: i32 = 128) -> i64
fn tcp_listen_unix(path: const u8[:], backlog: i32 = 128) -> i64
fn tcp_listen_dual(host: const u8[:], port: u16, backlog: i32 = 512, flags: i32 = 0) -> i64
fn tcp_accept(listener_fd: i64, timeout_ms: u32 = 0) -> i64
fn tcp_accept_nonblocking(listener_fd: i64) -> i64
fn tcp_getsockname_port(fd: i64) -> u16
fn tcp_get_peer_ip(fd: i64, out_ip: u8[..64]&)
fn tcp_connect(host: const u8[:], port: u16, timeout_ms: u32 = 5000) -> i64
fn tcp_connect_ex(host: const u8[:], port: u16, timeout_ms: u32 = 5000, ip_family: IpFamily = IpFamily.Auto, local_bind_addr: const u8[:] = "") -> i64
fn resolve_host_ips(host: const u8[:], out_ips: u8[..64][..16]&, ip_family: IpFamily = IpFamily.Auto) -> bool
fn tcp_connect_ip(ip: const u8[:], port: u16, timeout_ms: u32 = 5000, ip_family: IpFamily = IpFamily.Auto, local_bind_addr: const u8[:] = "") -> i64
fn tcp_connect_resolved<F: fn(const u8[:], bool&)>(host: const u8[:], port: u16, out_connected_ip: u8[..64]&, timeout_ms: u32 = 5000, ip_family: IpFamily = IpFamily.Auto, local_bind_addr: const u8[:] = "") -> i64
fn tcp_connect_with_options(opts: const TcpConnectOptions&, out_state: i32&, out_err: i32&) -> i64
fn tcp_connect_unix(path: const u8[:]) -> i64
fn tcp_connect_begin(host: const u8[:], port: u16, out_state: i32&) -> i64
fn tcp_connect_poll(fd: i64) -> i32
fn tcp_send(fd: i64, data: const u8[:]) -> i32
fn tcp_send2(fd: i64, hdr: const u8[:], payload: const u8[:]) -> i32
fn tcp_sendv(fd: i64, arr: core::IoVecArray&) -> i32
fn tcp_recv<B>(fd: i64, out: B&, max_len: i32 = 4096, timeout_ms: u32 = 5000) -> i32
fn tcp_recv_slice(fd: i64, dst: u8[:], timeout_ms: u32 = 5000) -> i32
fn tcp_recv_pipe(fd: i64, pipe: core::PipeBuffer&, min_span: i64 = 4096, timeout_ms: u32 = 5000) -> i32
fn tcp_close(fd: i64)
fn tcp_abort(fd: i64) -> bool
fn tcp_shutdown(fd: i64, how: i32 = SHUT_WR) -> bool
fn tcp_set_nodelay(fd: i64, enable: bool = true) -> bool
fn tcp_set_cork(fd: i64, enable: bool = true) -> bool
fn tcp_set_quickack(fd: i64, enable: bool = true) -> bool
fn tcp_set_keepalive(fd: i64, idle_sec: i32 = 1, intvl_sec: i32 = 11, cnt: i32 = 3) -> bool
fn tcp_set_fastopen(fd: i64, qlen: i32 = TCP_FASTOPEN_DEFAULT_QLEN) -> bool
fn tcp_send_fastopen(fd: i64, data: const u8[:]) -> i32
fn tcp_set_tos(fd: i64, tos: u8) -> bool
fn tcp_set_ecn(fd: i64, codepoint: u8) -> bool
fn tcp_set_ttl(sock_fd: i64, ttl: i32, is_ipv6: bool = false) -> bool
fn tcp_set_mss(sock_fd: i64, mss: i32) -> bool
fn tcp_set_rcvbuf(sock_fd: i64, bytes: i32) -> bool
fn async_socket_write(fd: i64, cork: core::CorkBuffer&, bp: BackPressure&, data: const u8[:], optionally: bool = false) -> i32, bool
fn async_socket_uncork(fd: i64, cork: core::CorkBuffer&, bp: BackPressure&) -> i32, bool
fn async_socket_drain(fd: i64, bp: BackPressure&) -> i32, bool
fn async_socket_shutdown(fd: i64, bp: BackPressure&, cork: core::CorkBuffer&) -> bool, bool
```

### Unified `Transport` and batched UDP (`net/transport.goose`, `net/udp.goose`)

Closed-polymorphism I/O across TCP, Unix, TLS, UDP, mock, virtual pipe, and
layered tunnel descriptors, plus 32-packet `sendmmsg`/`recvmmsg` batching.

```goose
enum Transport { Disconnected, Tcp, Unix, Tls, TlsBackend, Udp, Mock, Virtual }
struct TcpDialer { default_timeout_ms: u32 = 5000 }
struct UdpDatagram { .. }
struct UdpBatchQueue { .. }

fn is_connected(t: Transport) -> bool
fn send(t: Transport, data: const u8[:]) -> i32
fn recv_slice(t: Transport, dst: u8[:], timeout_ms: u32 = 5000) -> i32
fn close(t: Transport&)
fn dial_endpoint(d: const TcpDialer&, target: core::DialTarget) -> i64
fn open_virtual_pipe_pair() -> Transport, Transport, bool
fn alloc_tunnel_fd(outer: Transport) -> i64, bool
fn http_connect_transport_handshake(t: Transport, target_host: const u8[:], target_port: u16, proxy_auth: const u8[:], user_agent: const u8[:], timeout_ms: u32 = 5000) -> ConnectTunnelError
fn udp_bind(host: const u8[:], port: u16 = 0) -> i64
fn udp_recvfrom(sock_fd: i64, buf: u8[:], timeout_ms: u32, peer_ip4: u32&, peer_port: u16&) -> i32
fn build_udp_datagram(data: const u8[:], peer_ip4: u32, peer_port: u16, gso_size: u16 = 0) -> UdpDatagram, bool
fn enqueue_udp_datagram(queue: UdpBatchQueue&, fd: i32, dgram: const UdpDatagram&) -> i32, bool
fn batch_send_messages(queue: UdpBatchQueue&, fd: i32) -> i32, bool
fn batch_recv_messages(queue: UdpBatchQueue&, fd: i32) -> i32, bool
```

### Multiplexers, event loop, push host, and accelerators (`net/poller.goose`, `net/event_loop.goose`, `net/io_host.goose`, `net/accel.goose`)

Readiness polling (`Poller`, `UringPoller`, `EventLoop`), completion-based
`Host` link dispatch, and kernel I/O accelerator setup (`io_uring`, RIO,
`kqueue`, `epoll`).

```goose
struct Poller { .. }
struct UringPoller { .. }
struct EventLoop { .. }
struct Host { .. }
enum ReactorAccelMode { Auto, IoUring, Rio, Kqueue, PollFallback }
struct ReactorAccelRuntime { .. }

fn new_poller(driver_cfg: const net_internal::TransportDriverConfig&) -> Poller
fn enable_os_multiplexing(p: Poller&) -> bool
fn close_poller(p: Poller&)
fn register_socket(p: Poller&, fd: i32, tag: u64, interest: core::PollInterest, trigger: core::PollTrigger = core::PollTrigger.Level) -> bool
fn modify_socket(p: Poller&, fd: i32, tag: u64, interest: core::PollInterest, trigger: core::PollTrigger = core::PollTrigger.Level) -> bool
fn deregister_socket(p: Poller&, fd: i32) -> bool
fn add_timer(p: Poller&, timer_id: u64, delay_ms: u64, tag: u64, periodic: bool = false, now_ns: u64 = 0) -> bool
fn cancel_timer(p: Poller&, timer_id: u64) -> bool
fn wake_tag(p: Poller&, tag: u64) -> bool
fn poll_events(p: Poller&, timeout_ms: i64, now_ns: u64, out_events: core::PollReadyEvent[..64]&) -> i32
fn new_event_loop(driver_cfg: const net_internal::TransportDriverConfig&) -> EventLoop
fn close_event_loop(ev_loop: EventLoop&)
fn new_host(driver_cfg: const net_internal::TransportDriverConfig&) -> Host
fn close_host(host: Host&)
fn link_listen(host: Host&, addr: core::ConnectAddr, owner: u16, tag: u64, backlog: i32) -> core::IoLink, core::IoError
fn link_connect(host: Host&, addr: core::ConnectAddr, owner: u16, tag: u64) -> core::IoLink, core::ConnectStatus
fn open_virtual_pair(host: Host&, owner_a: u16, owner_b: u16, tag_a: u64 = 0, tag_b: u64 = 0) -> core::IoLink, core::IoLink, bool
fn link_send(host: Host&, link: core::IoLink, data: const u8[:]) -> i32, core::IoError
fn link_close(host: Host&, link: core::IoLink) -> bool
fn link_poll_dispatch<D>(host: Host&, driver: D&, timeout_ms: i64, now_ns: u64) -> i32
fn listen_accelerated_tcp(host: const u8[:], port: u16, accel_mode: ReactorAccelMode, backlog: i32 = 128) -> i64
fn reactor_init_accel(accel: ReactorAccelRuntime&, requested: ReactorAccelMode, listener_fd: i64) -> bool
fn reactor_close_accel(accel: ReactorAccelRuntime&)
```

### Connection pools, isolation keys, Happy Eyeballs, and retry (`net/pool.goose`, `net/upstream_pool.goose`, `net/isolation.goose`, `net/happy_eyeballs.goose`, `net/retry.goose`)

Partitioned client and reverse-proxy keep-alive pools with HTTP/2 IP coalescing,
RFC 8305/9460 endpoint racing, jittered backoff, retry budgets, and per-host
circuit breakers.

```goose
enum PoolScheme { Http, Https, Ws, Wss, H2c }
struct OriginEndpoint { .. }
struct PoolKey { .. }
struct StreamPool { .. }
struct UpstreamPool { .. }
struct NetworkIsolationKey { .. }
struct NetworkAnonymizationKey { .. }
struct DnsCandidate { .. }
struct DnsRaceTask { .. }
struct AttemptManager { .. }
struct BackoffConfig { .. }
struct AdaptiveRetryBudget { .. }
struct HostCircuitBreaker { .. }

fn new_origin_endpoint(host_str: const u8[:], port_num: u16) -> OriginEndpoint
fn new_pool_key(scheme_val: PoolScheme, host_str: const u8[:], port_num: u16, proxy_val: ProxyChain, partition_val: NetworkAnonymizationKey, policy_val: TlsAndDnsPolicy) -> PoolKey
fn new_stream_pool(max_per_group: i32 = DEFAULT_MAX_SOCKETS_PER_GROUP, max_per_proxy: i32 = DEFAULT_MAX_SOCKETS_PER_PROXY_CHAIN, soft_cap: i32 = DEFAULT_SOCKET_SOFT_CAP_PER_POOL) -> StreamPool
fn configure_stream_pool(pool: StreamPool&, max_conns_per_host: i32, disable_keepalive: bool, idle_timeout_ns: i64 = -1)
fn acquire_pooled_connection(pool: StreamPool&, key: const PoolKey&, target_resolved_ip: const u8[:], now_ns: i64, do_extensive_checks: bool = false) -> i32, bool
fn register_connection(pool: StreamPool&, key: const PoolKey&, proto: NegotiatedProtocol, t: Transport, resolved_ip: const u8[:], max_streams: i32, now_ns: i64, respect_limits: RespectLimits = RespectLimits.Enabled) -> i32
fn release_connection(pool: StreamPool&, conn_id: i32, now_ns: i64) -> bool
fn acquire_upstream_conn(pool: UpstreamPool&, endpoint: const OriginEndpoint&, tls_fingerprint: u64, nik: u64) -> i32, bool
fn release_upstream_conn(pool: UpstreamPool&, fd: i32, events: u32 = 0) -> bool
fn new_network_isolation_key(top_level: const u8[:], frame: const u8[:]) -> NetworkIsolationKey
fn new_network_anonymization_key(top_site: const u8[:], cross_site: bool = false, nonce_val: u64 = 0, partition_id: u32 = 0, worker_id: u32 = 0) -> NetworkAnonymizationKey
fn new_dns_race_task(target_port: u16 = 443) -> DnsRaceTask
fn interleave_candidates_he(ipv6_list: const DnsCandidate[:], ipv4_list: const DnsCandidate[:], out: DnsCandidate[..32]&, first_family_count: i32 = rfc::HE_FIRST_ADDRESS_FAMILY_COUNT)
fn interleave_protocols_hev3(candidates: const DnsCandidate[:], out: DnsCandidate[..32]&)
fn new_attempt_manager(cad_ms: i64 = rfc::HE_DEFAULT_CAD_MS) -> AttemptManager
fn start_attempt_race(manager: AttemptManager&, candidates: const DnsCandidate[:], now_ms: i64)
fn bind_winner_attempt(manager: AttemptManager&, winner_id: i32, is_alternative_h3: bool = false) -> bool
fn new_backoff_config(base: i64 = 100, cap: i64 = 10000, strat: JitterStrategy = JitterStrategy.FullJitter) -> BackoffConfig
fn compute_backoff_jitter_ms(cfg: const BackoffConfig&, attempt: i64, prev_sleep_ms: i64&, rng_seed: u64&) -> i64
fn new_host_circuit_breaker(max_wait_ms: i64 = 60000) -> HostCircuitBreaker
fn trip_circuit_breaker_if_exceeded(breaker: HostCircuitBreaker&, host_str: const u8[:], retry_after_ms: i64, now_mono_ns: i64) -> bool
fn is_host_circuit_broken(breaker: HostCircuitBreaker&, host_str: const u8[:], now_mono_ns: i64) -> bool
fn new_adaptive_retry_budget(ratio_pct: i64 = 20, min_per_sec: i64 = 2, window_dur_sec: i64 = 10) -> AdaptiveRetryBudget
fn parse_retry_after_ms(header_raw: const u8[:], now_unix_ms: i64) -> i64, bool
```

### Forward proxies, PROXY protocol, MASQUE, and Slowloris (`net/proxy.goose`, `net/http_connect.goose`, `net/socks5.goose`, `net/proxy_protocol.goose`, `net/masque.goose`, `net/slowloris.goose`)

Client and server codecs for HTTP CONNECT, SOCKS4/5, HAProxy PROXY v1/v2 with
CRC32c, RFC 9297/9298/9484 MASQUE tunnels, and ingress header-rate guards.

```goose
enum ProxyScheme { Direct, Http, Https, Socks4, Socks4a, Socks5, Socks5h }
struct ProxyServer { .. }
struct ProxyChain { .. }
struct ProxyHeader { .. }
struct MasqueTunnelSession { .. }
struct HeaderReader { .. }

fn new_direct_proxy_chain() -> ProxyChain
fn new_single_proxy_chain(ps: ProxyServer) -> ProxyChain
fn http_connect_client_handshake(sock_fd: i64, target_host: const u8[:], target_port: u16, proxy_auth: const u8[:], user_agent: const u8[:], timeout_ms: u32 = 5000) -> ConnectTunnelError
fn sanitize_tunnel_headers_for_origin(headers: http::HeaderMap&)
fn parse_authority_host_port(raw: const u8[:], default_port: u16, port_rule: PortRequirement) -> u8[..256], u16, bool
fn decode_basic_proxy_auth(header_val: const u8[:], out_login: u8[..128]&, out_pwd: u8[..256]&) -> bool
fn socks5_client_handshake(sock_fd: i64, scheme: ProxyScheme, target_host: const u8[:], target_port: u16, username: const u8[:], password: const u8[:], timeout_ms: u32 = 5000) -> Socks5Error
fn parse_socks5_client_greeting(buf: const u8[:]) -> Socks5ClientGreeting, SocksParseStatus
fn parse_socks5_client_request(buf: const u8[:]) -> SocksTarget, SocksParseStatus
fn encode_socks5_server_reply(rep_code: u8, bind_ip: const core::IpAddr&, bind_port: u16, out: u8[..32]&) -> bool
fn parse_socks4_client_request(buf: const u8[:]) -> SocksTarget, bool, SocksParseStatus
fn parse_proxy_header(wire: const u8[:]) -> ProxyHeader, i64, bool
fn parse_proxy_v1(wire: const u8[:]) -> ProxyHeader, i64, bool
fn parse_proxy_v2(wire: const u8[:]) -> ProxyHeader, i64, bool
fn format_proxy_v1<B>(hdr: const ProxyHeader&, out: B&) -> bool
fn format_proxy_v2<B>(hdr: const ProxyHeader&, out: B&) -> bool
fn append_proxy_v2_crc32c<B>(out: B&) -> bool
fn detect_and_strip_proxy_header(wire: const u8[:], out_hdr: ProxyHeader&) -> const u8[:], bool
fn encode_http_capsule<B>(out: B&, capsule_type: u64, payload: const u8[:]) -> bool
fn parse_http_capsule(src: const u8[:]) -> HttpCapsule, bool
fn encode_http_datagram<B>(out: B&, quarter_stream_id: u64, context_id: u64, payload: const u8[:]) -> bool
fn decode_http_datagram(wire: const u8[:]) -> u64, u64, const u8[:], bool
fn new_connect_udp_tunnel(proxy_url: const u8[:], target_host: const u8[:], target_port: u16, stream_id: u64 = 0, use_datagrams: bool = true) -> MasqueTunnelSession
fn new_connect_ip_tunnel(proxy_url: const u8[:], stream_id: u64 = 0, use_datagrams: bool = true) -> MasqueTunnelSession
fn build_masque_connect_request(tunnel: const MasqueTunnelSession&, out_headers: http::HeaderMap&, out_path: u8[..256]&)
fn send_packet<B>(tunnel: MasqueTunnelSession&, packet: const u8[:], out_wire: B&) -> bool
fn receive_capsule<B>(tunnel: MasqueTunnelSession&, capsule_wire: const u8[:], out_packet: B&) -> bool
fn receive_quic_datagram<B>(tunnel: MasqueTunnelSession&, datagram_frame_payload: const u8[:], out_packet: B&) -> bool
fn new_header_reader(cfg: SlowlorisDefenseConfig, start_mono_ns: i64) -> HeaderReader
fn feed_header_bytes(reader: HeaderReader&, chunk: const u8[:], now_mono_ns: i64) -> SlowlorisViolation
```

### Deterministic simulation testing (`net/dst.goose`)

Single-seed virtual clock, PRNG, TCP/UDP fault injection (fragmentation, RST,
drops, reordering, corruption, NAT rebinding), and trace digesting.

```goose
enum DstDir { AToB, BToA }
enum DstFaultProfile { Clean, FragmentedTcp, MidStreamRst, LossyQuic, Chaos }
root struct DstWorld { .. }

fn dst_fault_profile(profile: DstFaultProfile) -> DstFaultConfig
fn dst_init(world: DstWorld&, seed: u64, start_ns: u64 = 1000000000)
fn dst_shutdown(world: DstWorld&)
fn dst_add_endpoint(world: DstWorld&, ip4: u32, port: u16, clock_skew_ns: i64 = 0) -> u16, bool
fn dst_jump_clock(world: DstWorld&, delta_ns: u64)
fn dst_open_tcp_link(world: DstWorld&, ep_a: u16, ep_b: u16, faults: const DstFaultConfig&) -> u16, bool
fn dst_attach_host_pair(world: DstWorld&, host: Host&, link_id: u16, owner_a: u16, owner_b: u16) -> core::IoLink, core::IoLink, bool
fn dst_tcp_send(world: DstWorld&, link_id: u16, dir: DstDir, data: const u8[:]) -> i64, core::IoError
fn dst_tcp_recv(world: DstWorld&, link_id: u16, dir: DstDir, dst: u8[:]) -> i32, core::IoError
fn dst_tcp_inject_rst(world: DstWorld&, link_id: u16, dir: DstDir, delay_ns: u64 = 0) -> bool
fn dst_open_udp_link(world: DstWorld&, ep_a: u16, ep_b: u16, faults: const DstFaultConfig&) -> u16, bool
fn dst_udp_send(world: DstWorld&, link_id: u16, dir: DstDir, data: const u8[:]) -> bool
fn dst_udp_recv(world: DstWorld&, link_id: u16, dir: DstDir, dst: u8[:]) -> i32, u32, u16, bool
fn dst_schedule_timer(world: DstWorld&, timer_id: u64, delay_ns: u64, owner: u16, tag: u64) -> bool
fn dst_step(world: DstWorld&) -> DstStepResult
fn dst_run_until(world: DstWorld&, max_ns: u64, max_steps: i64 = 100000) -> i64
fn dst_step_host<D>(world: DstWorld&, host: Host&, driver: D&) -> i32
```
