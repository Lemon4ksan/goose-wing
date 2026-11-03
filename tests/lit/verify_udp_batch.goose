// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s
// RUN: goose check %s

// Native LIT verification suite for Ring-Zero L4 & Wire Engine:
// - Task #1: Batched UDP & GSO Engine (`UdpBatchQueue`, `batch_send_messages`, `batch_recv_messages`, auto-flush on 33rd packet)
// - Task #2: Linux `io_uring` Provided Buffer Ring (`uring_register_buf_ring` power-of-2 & bounds validation)
// - Task #3: Windows RIO `RioAddressPool` O(1) free-list acquire/release and fail-closed exhaustion at 129th acquire
// - Task #4: Upstream Pool (`UpstreamPool`) NIK partition isolation and `EPOLLRDHUP` (`0x2000`) idle closure eviction
// - Task #5: Canonical HTTP/2 frame reader (`read_wire_h2_frame` over `const u8[:]` + `cursor: i64&`) with transactional cursor
// - Task #6: `WireCommandPool` 64 KB arena zero-copy slice allocation and fail-closed capacity enforcement
import std;
import core from "../..";
import wing from "../..";

inline fn advance_test_loop_idx(idx: i32) -> i32 {
    return idx + 1;
}

fn verify_udp_batch_engine() {
    var queue = wing::UdpBatchQueue { .. };
    print("WING_UDP_BATCH_INITIALIZED: capacity=", wing::UDP_BATCH_CAPACITY, "\n");

    let payload = "QUIC-SHORT-HEADER-FRAME-PAYLOAD-1200";
    let dgram, build_ok = wing::build_udp_datagram(payload, 0x0100007F, 4433, 1200);
    assert(build_ok);
    assert(dgram.gso_size == 1200);

    // Negative test: oversize UDP datagram (> 1472 bytes) must be rejected (Invariant 13)
    var oversize_buf: u8[1500] = [0x41; 1500];
    let _, ovf_ok = wing::build_udp_datagram(oversize_buf[..], 0x0100007F, 4433, 0);
    if ovf_ok {
        print("WING_BUFFER_OVERFLOW_SILENT_DROP\n");
    }
    assert(!ovf_ok);

    // Enqueue 32 datagrams without triggering an intermediate flush
    var i: i32 = 0;
    while i < 32 {
        let flushed, enq_ok = wing::enqueue_udp_datagram(0, queue, dgram);
        assert(enq_ok);
        assert(flushed == 0);
        i = advance_test_loop_idx(i);
    }
    assert(queue.count == 32);
    assert(queue.flushed_batches == 0);

    // Enqueue 33rd datagram: must automatically flush the 32 queued datagrams before buffering packet 33
    let flushed_on_33, ok_33 = wing::enqueue_udp_datagram(0, queue, dgram);
    if !ok_33 || flushed_on_33 != 32 || queue.count != 1 {
        print("WING_BUFFER_OVERFLOW_SILENT_DROP\n");
    }
    assert(ok_33);
    assert(flushed_on_33 == 32);
    assert(queue.count == 1);
    assert(queue.flushed_batches == 1);
    assert(queue.total_sent == 32);
    print("UDP_BATCH_AUTO_FLUSH_33RD: flushed=", flushed_on_33, " remaining=", queue.count, "\n");

    // Flush the remaining 1 datagram explicitly
    let final_sent, final_ok = wing::batch_send_messages(0, queue);
    assert(final_ok && final_sent == 1 && queue.count == 0);

    // Verify batch_recv_messages on virtual descriptor 0 and negative fd rejection
    let recvd, recv_ok = wing::batch_recv_messages(0, queue);
    assert(recv_ok && recvd == 0);
    let _, bad_recv_ok = wing::batch_recv_messages(-1, queue);
    assert(!bad_recv_ok);
    let _, bad_send_ok = wing::batch_send_messages(-1, queue);
    assert(!bad_send_ok);
    print("UDP_BATCH_RECV_AND_BOUNDS: OK\n");
}

fn verify_uring_pbuf_ring() {
    // Negative tests: non-power-of-2 entries (0, 3, 100), negative ring_fd
    assert(!internal::uring_register_buf_ring(1, 0, 1));
    assert(!internal::uring_register_buf_ring(1, 3, 1));
    assert(!internal::uring_register_buf_ring(1, 100, 1));
    assert(!internal::uring_register_buf_ring(1, 40000, 1));
    assert(!internal::uring_register_buf_ring(-1, 128, 1));

    // Positive power-of-2 validator check
    assert(internal::is_valid_pbuf_ring_entries(1));
    assert(internal::is_valid_pbuf_ring_entries(64));
    assert(internal::is_valid_pbuf_ring_entries(1024));
    assert(internal::is_valid_pbuf_ring_entries(32768));
    assert(!internal::is_valid_pbuf_ring_entries(32769));
    print("URING_PBUF_RING_VALIDATION: OK\n");
}

fn verify_rio_address_pool() {
    var pool = internal::RioAddressPool { .. };
    assert(internal::rio_init_address_pool(pool, 0xCAFE0001));
    assert(pool.initialized && pool.active_count == 0);

    // Acquire all 128 pre-registered address descriptors in O(1)
    var k: i32 = 0;
    while k < 128 {
        let slot_idx, buf_desc, ok = internal::rio_acquire_address_buf(pool);
        assert(ok);
        assert(slot_idx == k);
        assert(buf_desc.length == 28);
        k = advance_test_loop_idx(k);
    }
    assert(pool.active_count == 128);

    // 129th acquire MUST fail closed (Invariant 13)
    let _, _, ok_129 = internal::rio_acquire_address_buf(pool);
    if ok_129 {
        print("WING_BUFFER_OVERFLOW_SILENT_DROP\n");
    }
    assert(!ok_129);
    print("RIO_ADDRESS_POOL_EXHAUSTION_129: REJECTED_OK\n");

    // Release descriptor 42 and re-acquire in O(1)
    assert(internal::rio_release_address_buf(pool, 42));
    assert(!internal::rio_release_address_buf(pool, 42)); // Double-release rejected
    assert(!internal::rio_release_address_buf(pool, -1));
    assert(!internal::rio_release_address_buf(pool, 128));

    let re_idx, _, re_ok = internal::rio_acquire_address_buf(pool);
    assert(re_ok && re_idx == 42);
    print("RIO_ADDRESS_POOL_RECYCLE: slot=", re_idx, "\n");
}

fn verify_upstream_pool_nik_and_rdhup() {
    var upool = wing::UpstreamPool { .. };
    let origin = wing::new_origin_endpoint("api.internal.example.com", 443);
    let tls_fp:       u64 = 0xAABBCCDDEEFF0011;
    let nik_tenant_a: u64 = 1001;
    let nik_tenant_b: u64 = 2002;

    assert(wing::register_upstream_conn(upool, 55, origin, tls_fp, nik_tenant_a));

    // Tenant B (different NIK) MUST NOT acquire Tenant A's warm socket
    let _, cross_nik_ok = wing::acquire_upstream_conn(upool, origin, tls_fp, nik_tenant_b);
    assert(!cross_nik_ok);
    print("UPSTREAM_POOL_NIK_ISOLATION: OK\n");

    // Tenant A acquires and releases its socket cleanly
    let fd_a, ok_a = wing::acquire_upstream_conn(upool, origin, tls_fp, nik_tenant_a);
    assert(ok_a && fd_a == 55);
    assert(wing::release_upstream_conn(upool, 55, 0));

    // Simulate kernel signaling EPOLLRDHUP (0x2000) while idle
    assert(wing::notify_upstream_epoll_events(upool, 55, wing::EPOLLRDHUP));
    assert(upool.evicted_rdhup == 1);

    // Subsequent acquire for Tenant A MUST NOT return the half-closed socket
    let _, stale_ok = wing::acquire_upstream_conn(upool, origin, tls_fp, nik_tenant_a);
    assert(!stale_ok);
    print("UPSTREAM_POOL_EPOLLRDHUP_EVICTION: evicted=", upool.evicted_rdhup, "\n");
}

fn verify_wire_h2_frame_slice_cursor() {
    var buf: u8[..64] = [];
    assert(wire::encode_window_update_frame(0, 2048, buf));
    let ping_payload: u8[8] = [1, 2, 3, 4, 5, 6, 7, 8];
    assert(wire::encode_ping_frame(ping_payload, true, buf));

    var cursor: i64 = 0;
    let hdr1, pay1, ok1 = wire::read_wire_h2_frame(buf[..], cursor);
    assert(ok1 && hdr1.frame_type == wire::H2_FRAME_WINDOW_UPDATE && pay1.len == 4 && cursor == 13);

    // Truncated frame test: slice off the last 2 bytes of the PING frame and verify cursor rollback
    let truncated_view = buf[..28];
    let saved_cursor = cursor;
    let _, _, trunc_ok = wire::read_wire_h2_frame(truncated_view, cursor);
    assert(!trunc_ok);
    assert(cursor == saved_cursor);

    // Full second frame read succeeds
    let hdr2, pay2, ok2 = wire::read_wire_h2_frame(buf[..], cursor);
    assert(ok2 && hdr2.frame_type == wire::H2_FRAME_PING && pay2.len == 8 && cursor == 30);
    print("WIRE_H2_SLICE_CURSOR: cursor=", cursor, "\n");
}

fn verify_wire_command_pool_arena() {
    let inst = wire::WireInstance { .. };
    var phys_devs: wire::WirePhysicalDevice[..4] = [];
    assert(wire::is_success(wire::enumerate_physical_devices(inst, phys_devs)));
    let dev_info = wire::WireDeviceCreateInfo {
        config:           wire::WireDeviceConfig { .. },
        enabled_features: wire::WirePhysicalDeviceFeatures { .. },
    };
    var dev, dev_res = wire::create_wire_device(phys_devs[0], dev_info);
    assert(wire::is_success(dev_res));

    let pool_info = wire::WireCommandPoolCreateInfo {
        flags:              wire::WIRE_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT,
        queue_family_index: 0,
    };
    var pool, pool_res = wire::create_command_pool(dev, pool_info);
    assert(wire::is_success(pool_res));

    // Allocate 4 command buffers (4 x 16384 = 65536 bytes of pool.arena)
    var cmd1, r1 = wire::allocate_command_buffer(pool);
    var cmd2, r2 = wire::allocate_command_buffer(pool);
    var cmd3, r3 = wire::allocate_command_buffer(pool);
    var cmd4, r4 = wire::allocate_command_buffer(pool);
    assert(wire::is_success(r1) && wire::is_success(r2) && wire::is_success(r3) && wire::is_success(r4));
    assert(pool.arena.len == 65536);

    // 5th allocation must fail closed with ErrorOutOfDeviceMemory (Invariant 13)
    var _, r5 = wire::allocate_command_buffer(pool);
    if wire::is_success(r5) {
        print("WING_BUFFER_OVERFLOW_SILENT_DROP\n");
    }
    assert(r5 == wire::WireResult.ErrorOutOfDeviceMemory);

    // Record into cmd1 and commit directly into its carved pool.arena slice
    let begin_info = wire::WireCommandBufferBeginInfo {
        flags: wire::WIRE_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT,
    };
    assert(wire::is_success(wire::begin_command_buffer(cmd1, begin_info)));
    assert(wire::write_h2_preface(cmd1));
    assert(wire::is_success(wire::end_command_buffer(cmd1)));
    let arena_slice, commit_ok = wire::commit_command_buffer_to_arena(pool, cmd1);
    assert(commit_ok && arena_slice.len == 24);
    print("WIRE_COMMAND_POOL_ARENA_SLICED: bytes=", arena_slice.len, " total_arena=", pool.arena.len, "\n");

    wire::free_command_buffer(pool, cmd4);
    wire::free_command_buffer(pool, cmd3);
    wire::free_command_buffer(pool, cmd2);
    wire::free_command_buffer(pool, cmd1);
    wire::destroy_command_pool(pool);
    wire::destroy_wire_device(dev);
}

fn main() {
    // CHECK: WING_UDP_BATCH_INITIALIZED: capacity=32
    // CHECK-NOT: WING_BUFFER_OVERFLOW_SILENT_DROP
    // CHECK: UDP_BATCH_AUTO_FLUSH_33RD: flushed=32 remaining=1
    // CHECK: UDP_BATCH_RECV_AND_BOUNDS: OK
    // CHECK: URING_PBUF_RING_VALIDATION: OK
    // CHECK: RIO_ADDRESS_POOL_EXHAUSTION_129: REJECTED_OK
    // CHECK: RIO_ADDRESS_POOL_RECYCLE: slot=42
    // CHECK: UPSTREAM_POOL_NIK_ISOLATION: OK
    // CHECK: UPSTREAM_POOL_EPOLLRDHUP_EVICTION: evicted=1
    // CHECK: WIRE_H2_SLICE_CURSOR: cursor=30
    // CHECK: WIRE_COMMAND_POOL_ARENA_SLICED: bytes=24 total_arena=65536
    verify_udp_batch_engine();
    verify_uring_pbuf_ring();
    verify_rio_address_pool();
    verify_upstream_pool_nik_and_rdhup();
    verify_wire_h2_frame_slice_cursor();
    verify_wire_command_pool_arena();
}
