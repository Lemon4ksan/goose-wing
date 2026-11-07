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
    addr: u64, len: u32, op_flags: u32, user_data: u64, buf_index: u16
}
struct UringCqe { user_data: u64, res: i32, flags: u32 }
struct UringBufRing { bgid: u16, mask: u16, tail: u16, entries: UringBufEntry[..64] }
struct RingQueueState { ... }
fn uring_register_buf_ring(ring: UringBufRing&, bgid: u16, base_addr: u64, buf_size: u32, count: u16) -> bool
fn uring_buf_ring_recycle(ring: UringBufRing&, bid: u16, addr: u64, len: u32)
fn uring_prep_recv_multishot(sqe: UringSqe&, fd: i32, buf_group: u16, user_data: u64)
fn uring_submit_batch(q: RingQueueState&, sqes: const UringSqe[:]) -> i32
```

Models 64-byte `UringSqe` submission entries, 16-byte `UringCqe` completion
entries, and kernel-provided buffer rings (`UringBufRing`) up to 64 entries.
`uring_prep_recv_multishot` configures `IORING_OP_RECV` with
`IOSQE_BUFFER_SELECT` so a single SQE yields multiple completions until the
buffer group (`bgid`) is exhausted, after which `uring_buf_ring_recycle` returns
consumed buffers to the ring tail.

### 3. Windows Registered I/O Backend (`net/driver/rio.goose`)

```goose
struct RioBufferDescriptor {
    buffer_id: u64, offset: u64, length: u32,
    is_registered: bool, page_locked: bool
}
struct RIO_BUF { buffer_id: u64, offset: u32, length: u32, next_free: i32, in_use: bool }
struct RioAddressPool { descriptors: RIO_BUF[..128], free_head: i32, active_count: i32, ... }
struct RioResult { status: i32, bytes_transferred: u32, socket_context: u64, request_context: u64 }
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

Manages pre-pinned virtual memory slabs (`RioBufferDescriptor`) and `RIO_BUF`
slices so Winsock skips per-call page locking on `RIOSend` and `RIOReceive`.
`RioAddressPool` partitions a registered `SOCKADDR_INET` slab into 128 reusable
address slots (`RIO_BUF[..128]`), and `rio_drain_completions` dequeues up to 64
`RioResult` records per sweep.

### 4. BSD / macOS `kqueue` Backend (`net/driver/kqueue.goose`)

```goose
struct Kevent { ident: u64, filter: i16, flags: u16, fflags: u32, data: i64, udata: u64 }
fn kevent_prep_read(fd: i32, udata: u64, clear_edge: bool = true) -> Kevent
fn kevent_prep_write(fd: i32, udata: u64, clear_edge: bool = true) -> Kevent
fn kevent_prep_timer(ident: u64, timeout_ms: i64, one_shot: bool = true) -> Kevent
fn kevent_bytes_available(ev: const Kevent&) -> i64
fn kevent_is_eof(ev: const Kevent&) -> bool
```

Encodes BSD `kevent` change records for `EVFILT_READ`, `EVFILT_WRITE`, and
`EVFILT_TIMER` filters with optional `EV_CLEAR` edge-triggered semantics.
`kevent_bytes_available` returns the readable byte count stored in `ev.data`,
and `kevent_is_eof` checks the `EV_EOF` bit in `ev.flags`.

### 5. Linux `AF_XDP` Kernel-Bypass Backend (`net/driver/af_xdp.goose`)

```goose
struct XdpDesc { addr: u64, len: u32, options: u32 }
struct AfXdpUmem { ... }
struct XskRingState { ... }
struct AfXdpSocket { fill_ring: XskRingState, comp_ring: XskRingState, rx_ring: XskRingState, tx_ring: XskRingState, ... }
fn af_xdp_open_socket(ifname: const u8[:], queue_id: u32, frame_size: u32 = 4096, num_frames: u32 = 64) -> AfXdpSocket, bool
fn af_xdp_fill_push(sock: AfXdpSocket&, count: u32) -> u32
fn af_xdp_tx_submit(sock: AfXdpSocket&, payloads: const u8[:][..64], count: i32) -> u32
fn af_xdp_rx_poll(sock: AfXdpSocket&, out_descs: XdpDesc[..64]&) -> u32
fn af_xdp_complete_pop(sock: AfXdpSocket&) -> u32
fn af_xdp_close(sock: AfXdpSocket&)
fn xsk_fill_ring_enqueue_burst(fill: XskRingState&, umem: AfXdpUmem&, max_frames: u32) -> u32
```

Manages the four `AF_XDP` producer/consumer rings (`fill_ring`, `comp_ring`,
`rx_ring`, `tx_ring`) over a fixed-chunk `AfXdpUmem` arena (default 64 frames of
4096 bytes). `af_xdp_tx_submit` and `af_xdp_rx_poll` transfer bursts of up to 64
frames (`XdpDesc[..64]`), while `af_xdp_complete_pop` reclaims transmitted UMEM
frame addresses back to the free list.

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
fn dpdk_stage_tx_burst(ctx: DpdkContext&, mbufs: const u64[:]) -> u32
```

Provides a user-space Poll-Mode Driver (PMD) abstraction over fixed-size
2048-byte mbuf packet pools (`DpdkMempool`). `dpdk_tx_burst` and `dpdk_rx_burst`
process batches of up to 32 mbuf handles (`u64[..32]`) per queue poll without
kernel context switches.

### 7. SmartNIC Hardware Offload (`net/driver/smartnic.goose`)

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
fn smartnic_attach_hardware_tls(fd: i64, cipher: SmartNicCipherSuite, tx_key: const u8[:], tx_iv: const u8[:], tx_salt: const u8[:], tx_seq: const u8[:], rx_key: const u8[:] = "", rx_iv: const u8[:] = "", rx_salt: const u8[:] = "", rx_seq: const u8[:] = "") -> SmartNicSession, i32
```

`smartnic_attach_hardware_tls` installs directional TLS 1.3 AES-GCM key
material, IVs, salts, and sequence numbers into the NIC flow table, returning
`(sess, err)` and failing closed if TX offload setup fails.
