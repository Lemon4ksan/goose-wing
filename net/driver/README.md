# `net/driver`

Package `net/driver` implements the hardware-accelerated and kernel-bypass
network I/O backends that power the `net/poller.goose` event multiplexer in
`goose-wing`.

```goose
var cfg = internal::auto_transport_driver_config();
let ok = internal::init_transport_driver(cfg);
```

## Supported Drivers

| Driver | Submodule | Target Platform | Architecture |
| :--- | :--- | :--- | :--- |
| **`Standard`** | `net/driver/manager.goose` | Cross-platform | POSIX `poll()` / Windows `WSAPoll()` multiplexing |
| **`IoUring`** | `net/driver/uring.goose` | Linux >= 5.1 | Kernel SQ/CQ submission and completion rings with provided buffer rings |
| **`WindowsRIO`** | `net/driver/rio.goose` | Windows 8+ / Server 2012+ | Winsock Registered I/O (RIO) pre-pinned buffer and address slices |
| **`Kqueue`** | `net/driver/kqueue.goose` | macOS / FreeBSD | BSD `kevent` readiness and timer filters |
| **`AfXdp`** | `net/driver/af_xdp.goose` | Linux >= 4.18 | `AF_XDP` zero-copy UMEM Fill/Completion/RX/TX descriptor rings |
| **`Dpdk`** | `net/driver/dpdk.goose` | Linux user-space | Poll-Mode Driver (PMD) burst RX/TX queues and mbuf mempools |
| **`SmartNicOffload`** | `net/driver/smartnic.goose` | Linux / Windows | ConnectX / BlueField hardware kTLS, QUIC AEAD, and TSO offload |

## Driver API Reference (`namespace internal;`)

### 1. Core Driver Types & Probing (`net/driver/types.goose`, `net/driver/manager.goose`)

```goose
enum TransportDriverKind { Auto, Standard, IoUring, WindowsRIO, Kqueue, AfXdp, Dpdk, SmartNicOffload }
enum TargetPlatform { Windows, Linux, Darwin, Unknown }
struct DriverProbeResult {
    kind: TransportDriverKind, available: bool, capabilities: u32,
    error_code: i32, reason: u8[..128]
}
struct TransportDriverConfig {
    preferred_kind: TransportDriverKind, active_kind: TransportDriverKind,
    capabilities: u32, ring_size: u32, enable_kernel_bypass: bool,
    registered_buffer_size: u32, status_message: u8[..128], is_probed: bool
}
fn detect_target_platform() -> TargetPlatform
fn probe_transport_driver(kind: TransportDriverKind) -> DriverProbeResult
fn probe_transport_driver_for_platform(kind: TransportDriverKind, plat: TargetPlatform) -> DriverProbeResult
fn init_transport_driver(cfg: TransportDriverConfig&) -> bool
fn init_transport_driver_with_platform(cfg: TransportDriverConfig&, plat: TargetPlatform) -> bool
fn auto_transport_driver_config(ring_size: u32 = DEFAULT_RING_SIZE, reg_buf_size: u32 = DEFAULT_REGISTERED_BUFFER_SIZE) -> TransportDriverConfig
fn format_driver_summary<B>(cfg: const TransportDriverConfig&, out: B&)
fn driver_kind_name(kind: TransportDriverKind) -> const u8[:]
```

`probe_transport_driver` and `init_transport_driver` inspect the host OS via
`detect_target_platform` and resolve `TransportDriverKind.Auto` to the
highest-capability backend available (`IoUring` on Linux, `WindowsRIO` on
Windows, `Kqueue` on Darwin/BSD), falling back to `Standard` if kernel rings or
pinned memory limits are unavailable.

### 2. Linux `io_uring` Backend (`net/driver/uring.goose`)

```goose
struct UringSqe {
    opcode: u8, flags: u8, ioprio: u16, fd: i32, off: u64,
    addr: u64, len: u32, op_flags: u32, user_data: u64, buf_index: u16, ...
}
struct UringCqe { user_data: u64, res: i32, flags: u32 }
struct UringBufRing { bgid: u16, mask: u16, tail: u16, entries: UringBufEntry[..64] }
struct RingQueueState { ... }
fn uring_create(entries: u32 = 256, flags: u32 = 0) -> i32
fn uring_close(ring_fd: i32)
fn uring_submit_sqes(ring_fd: i32, sqes: const UringSqe[:]) -> i32
fn uring_wait_cqes(ring_fd: i32, out_cqes: UringCqe[..64]&, min_complete: u32 = 0, timeout_ms: i32 = 0) -> i32
fn uring_alloc_pbuf_ring(ring_fd: i32, bgid: u16, count: u16 = 64, buf_size: u32 = 8192) -> bool
fn uring_read_pbuf_slice(ring_fd: i32, bgid: u16, bid: u16, byte_len: u32, out_buf: u8[..8192]&) -> bool
fn uring_recycle_pbuf(ring_fd: i32, bgid: u16, bid: u16) -> bool
fn uring_prep_poll_add(sqe: UringSqe&, fd: i32, poll_mask: u32, user_data: u64)
fn uring_prep_poll_remove(sqe: UringSqe&, target_user_data: u64, user_data: u64)
fn uring_prep_send_slice(sqe: UringSqe&, fd: i32, buf: const u8[:], user_data: u64)
fn uring_register_buf_ring(ring: UringBufRing&, bgid: u16, base_addr: u64, buf_size: u32, count: u16) -> bool
fn uring_buf_ring_recycle(ring: UringBufRing&, bid: u16, addr: u64, len: u32)
fn uring_prep_recv_multishot(sqe: UringSqe&, fd: i32, buf_group: u16, user_data: u64)
fn uring_submit_batch(q: RingQueueState&, sqes: const UringSqe[:]) -> i32
```

Models 64-byte `UringSqe` submission entries, 16-byte `UringCqe` completion
entries, and kernel-provided buffer rings (`uring_alloc_pbuf_ring` and
`UringBufRing`) up to 64 entries. `uring_submit_sqes` and `uring_wait_cqes`
exchange slice-safe SQE/CQE batches with the Linux kernel ring, while
`uring_prep_recv_multishot` and `uring_prep_send_slice` drive zero-syscall-copy
completion reactor I/O.

### 3. Windows Registered I/O Backend (`net/driver/rio.goose`)

```goose
struct RioBufferDescriptor {
    buffer_id: u64, offset: u64, length: u32,
    is_registered: bool, page_locked: bool
}
struct RIO_BUF { buffer_id: u64, offset: u32, length: u32, next_free: i32, in_use: bool }
struct RioAddressPool { descriptors: RIO_BUF[..128], free_head: i32, active_count: i32, ... }
struct RioResult { status: i32, bytes_transferred: u32, socket_context: u64, request_context: u64 }
fn rio_create_socket() -> i64
fn rio_listen(host: const u8[:], port: u16 = 0, backlog: i32 = 128) -> i64
fn rio_is_listener(listen_fd: i64) -> bool
fn rio_poll_accept(listen_fd: i64) -> i64
fn rio_cancel_accept(listen_fd: i64)
fn rio_register_buffer_slice(slab: u8[:]) -> RioBufferDescriptor
fn rio_create_cq(queue_size: u32 = 256) -> u64, i64
fn rio_close_cq(cq_id: u64, event_handle: i64)
fn rio_notify_cq(cq_id: u64) -> i32
fn rio_wait_cq(event_handle: i64, timeout_ms: u32) -> i32
fn rio_create_rq(sock_fd: i64, cq_id: u64, max_recv: u32, max_send: u32, sock_ctx: u64) -> u64
fn new_rio_buffer(id: u64, len: u32) -> RioBufferDescriptor
fn rio_sub_buffer(parent: const RioBufferDescriptor&, off: u64, len: u32) -> RioBufferDescriptor
fn rio_deregister_buffer(desc: RioBufferDescriptor&)
fn rio_can_zero_copy(desc: const RioBufferDescriptor&, req_len: u32) -> bool
fn rio_init_address_pool(pool: RioAddressPool&, slab_buf_id: u64) -> bool
fn rio_acquire_address_buf(pool: RioAddressPool&) -> i32, RIO_BUF, bool
fn rio_release_address_buf(pool: RioAddressPool&, slot_idx: i32) -> bool
fn rio_submit_send(rq_id: u64, desc: const RioBufferDescriptor&, req_context: u64 = 0) -> i32
fn rio_submit_recv(rq_id: u64, desc: const RioBufferDescriptor&, req_context: u64 = 0) -> i32
fn rio_drain_completions(cq_id: u64, out_results: RioResult[..64]&) -> u32
```

Manages pre-pinned virtual memory slabs (`rio_register_buffer_slice`),
persistent overlapped `AcceptEx` listeners (`rio_listen`, `rio_poll_accept`),
and `RIO_BUF` slices so Winsock skips per-call page locking on `RIOSend` and
`RIOReceive`. `rio_drain_completions` dequeues up to 64 `RioResult` completion
records per sweep.

### 4. BSD / macOS `kqueue` Backend (`net/driver/kqueue.goose`)

```goose
struct Kevent { ident: u64, filter: i16, flags: u16, fflags: u32, data: i64, udata: u64 }
fn kqueue_create() -> i32
fn kqueue_close(kq_fd: i32)
fn kqueue_poll_slice(kq_fd: i32, changes: const Kevent[:], out_events: Kevent[..64]&, timeout_ms: i32) -> i32
fn kevent_prep_read(fd: i32, udata: u64, clear_edge: bool = true) -> Kevent
fn kevent_prep_write(fd: i32, udata: u64, clear_edge: bool = true) -> Kevent
fn kevent_prep_timer(ident: u64, timeout_ms: i64, one_shot: bool = true) -> Kevent
fn kevent_bytes_available(ev: const Kevent&) -> i64
fn kevent_is_eof(ev: const Kevent&) -> bool
```

Encodes BSD `kevent` change records for `EVFILT_READ`, `EVFILT_WRITE`, and
`EVFILT_TIMER` filters with optional `EV_CLEAR` edge-triggered semantics, and
submits/harvests up to 64 events in one syscall via `kqueue_poll_slice`.

### 5. Linux `AF_XDP` Kernel-Bypass Backend (`net/driver/af_xdp.goose`)

```goose
struct XdpDesc { addr: u64, len: u32, options: u32 }
struct AfXdpUmem { addr: u64, len: u64, chunk_size: u32, headroom: u32, is_registered: bool }
struct XskRingState { ... }
struct AfXdpSocket { fd: i64, ifindex: u32, queue_id: u32, umem: AfXdpUmem, ... }
fn af_xdp_open_socket(ifindex: u32, queue_id: u32, umem_addr: u64, umem_len: u64, chunk_size: u32 = 2048, zero_copy: bool = true) -> AfXdpSocket, i32
fn af_xdp_open_loopback(num_frames: u32 = 64, frame_size: u32 = 2048) -> AfXdpSocket, bool
fn af_xdp_umem_write(sock: const AfXdpSocket&, addr: u64, data: const u8[:]) -> bool
fn af_xdp_umem_read(sock: const AfXdpSocket&, addr: u64, frame_len: u32, out_frame: u8[..2048]&) -> bool
fn af_xdp_inject_loopback_rx(sock: AfXdpSocket&, addr: u64, frame_len: u32) -> bool
fn af_xdp_fill_push(sock: const AfXdpSocket&, umem_offset: u64) -> bool
fn af_xdp_tx_submit(sock: const AfXdpSocket&, desc: const XdpDesc&) -> bool
fn af_xdp_rx_poll(sock: const AfXdpSocket&) -> XdpDesc, bool
fn af_xdp_complete_pop(sock: const AfXdpSocket&) -> u64, bool
fn af_xdp_close(sock: AfXdpSocket&)
fn xsk_fill_ring_enqueue_burst(ring: XskRingState&, addrs: const u64[:]) -> u32
```

Manages the four `AF_XDP` producer/consumer rings (`fill`, `comp`, `rx`, `tx`)
over a bounds-checked `AfXdpUmem` arena (`af_xdp_umem_write` and
`af_xdp_umem_read` validate `[0..umem.len)` and `<= 2048` byte chunks), plus an
unprivileged cross-platform UMEM loopback ring (`af_xdp_open_loopback`).

### 6. DPDK Poll-Mode Driver Backend (`net/driver/dpdk.goose`)

```goose
struct DpdkPortConfig {
    port_id: u16, rx_queues: u16, tx_queues: u16,
    rx_ring_size: u16, tx_ring_size: u16, promiscuous: bool
}
struct DpdkMempool { pool_handle: u64, n_elements: u32, element_size: u32, socket_id: i32, is_created: bool }
struct DpdkDevice { port_id: u16, is_initialized: bool, is_started: bool, rx_burst_size: u32, tx_burst_size: u32 }
struct DpdkContext { port_id: u16, queue_id: u16, rx_count: u32, rx_burst: u64[64], tx_count: u32, tx_burst: u64[64], ... }
fn new_dpdk_device(port_id: u16 = 0) -> DpdkDevice
fn dpdk_create_mempool(n_elements: u32 = 8192, element_size: u32 = 2048) -> DpdkMempool
fn dpdk_init_port(dev: DpdkDevice&, cfg: const DpdkPortConfig&) -> i32
fn dpdk_start_port(dev: DpdkDevice&) -> i32
fn dpdk_stop_port(dev: DpdkDevice&)
fn dpdk_tx_burst(dev: const DpdkDevice&, queue_id: u16, mbufs: const u64[:]) -> u16
fn dpdk_rx_burst(dev: const DpdkDevice&, queue_id: u16, out_mbufs: u64[..32]&, max_pkts: u16 = 32) -> u16
fn dpdk_tx_packet_push(port_id: u16, queue_id: u16, frame: const u8[:]) -> bool
fn dpdk_rx_burst_read(port_id: u16, queue_id: u16, out_frames: u8[..2048][..32]&) -> u32
fn dpdk_stage_tx_burst(ctx: DpdkContext&, mbufs: const u64[:]) -> u32
```

Provides a user-space Poll-Mode Driver (PMD) abstraction over fixed-size
2048-byte mbuf packet pools (`DpdkMempool`), supporting both `libdpdk` queues
and a lock-free userspace packet ring (`dpdk_tx_packet_push`,
`dpdk_rx_burst_read`).

### 7. SmartNIC & Linux kTLS Offload (`net/driver/smartnic.goose`)

```goose
enum SmartNicModel {
    Generic, MellanoxConnectX6Dx, MellanoxConnectX7Dx,
    NvidiaBlueField2, NvidiaBlueField3, IntelMountEvans
}
enum SmartNicCipherSuite { AesGcm128, AesGcm256 }
struct SmartNicConfig {
    model: SmartNicModel, enable_hardware_tls: bool,
    enable_tcp_chimney: bool, rx_coalesce_usecs: u32, tx_coalesce_usecs: u32
}
struct SmartNicSession {
    fd: i64, ktls_active: bool, tx_offloaded: bool,
    rx_offloaded: bool, cipher: SmartNicCipherSuite
}
fn smartnic_model_name(m: SmartNicModel) -> const u8[:]
fn new_smartnic_session(fd: i64 = -1) -> SmartNicSession
fn smartnic_probe_ktls() -> bool
fn smartnic_attach_hardware_tls(fd: i64, cipher: SmartNicCipherSuite, tx_key: const u8[:], tx_iv: const u8[:], tx_salt: const u8[:], tx_seq: const u8[:], rx_key: const u8[:] = "", rx_iv: const u8[:] = "", rx_salt: const u8[:] = "", rx_seq: const u8[:] = "") -> SmartNicSession, i32
fn smartnic_ktls_send_record(fd: i64, record_type: u8, payload: const u8[:]) -> i64
fn smartnic_ktls_recv_record(fd: i64, buf: u8[:]) -> i64, u8
```

`smartnic_attach_hardware_tls` installs directional TLS 1.3 AES-GCM keys, IVs,
salts, and sequence numbers via Linux `SOL_TLS`, while
`smartnic_ktls_send_record` and `smartnic_ktls_recv_record` exchange TLS record
content types through `TLS_SET_RECORD_TYPE` / `TLS_GET_RECORD_TYPE` control
messages.

### 8. L2/L3/L4 Ethernet/IP/UDP Packet Codec (`net/driver/l2_frame.goose`)

```goose
struct L2UdpEndpoint { mac: u8[6], ip: u8[16], is_ipv6: bool, port: u16 }
struct L2ParsedUdpFrame { src: L2UdpEndpoint, dst: L2UdpEndpoint, payload_offset: i64, payload_len: i64 }
fn decode_l2_udp_frame(frame: const u8[:]) -> L2ParsedUdpFrame, bool
fn encode_l2_udp_frame(src: const L2UdpEndpoint&, dst: const L2UdpEndpoint&, payload: const u8[:], ip_id: u16, out_frame: u8[..2048]&) -> bool
```

Zero-allocation Ethernet II + IPv4/IPv6 + UDP frame encoder/decoder for `AF_XDP`
and `DPDK` datapaths, validating IPv4 header and UDP pseudo-header
ones'-complement checksums and rejecting IPv4 fragments.
