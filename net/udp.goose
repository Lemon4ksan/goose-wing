// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Layer 4 Batched UDP Datagram & GSO Engine (RFC 9000 Section 14, sendmmsg / recvmmsg).
// Zero-allocation batching up to 32 packets per syscall transition.
namespace wing;

import std;
import core from "..";

// Maximum IPv4/IPv6 UDP payload size for QUIC Ethernet frames without IP fragmentation (RFC 9000 Section 14).
const UDP_MAX_PAYLOAD_LEN: i64 = 1472;

// Maximum number of UDP datagrams batched in a single sendmmsg / recvmmsg transition.
const UDP_BATCH_CAPACITY: i32 = 32;

// Flat contiguous arena size for 32 x 1472-byte UDP payloads (47,104 bytes).
const UDP_BATCH_ARENA_BYTES: i64 = 47104;

// Native C shims for batched UDP datagram transmission and reception.
extern fn native_udp_sendmmsg(
    sock_fd:  i64,
    payloads: const u8[:],
    lengths:  const i32[:],
    ips:      const u32[:],
    ports:    const u16[:],
    count:    i32,
) -> i32 = "wing_udp_sendmmsg";

extern fn native_udp_recvmmsg(
    sock_fd:    i64,
    payloads:   u8[:],
    lengths:    i32[:],
    ips:        u32[:],
    ports:      u16[:],
    max_count:  i32,
    timeout_ms: u32,
) -> i32 = "wing_udp_recvmmsg";

// Single bounded UDP datagram descriptor with Generic Segmentation Offload (UDP_SEGMENT / GSO) metadata.
struct UdpDatagram {
    payload:   u8[..1472] = [],
    peer_ip4:  u32        = 0,
    peer_port: u16        = 0,
    gso_size:  u16        = 0,
}

// Builds a bounded UDP datagram descriptor, rejecting oversize payloads (Invariant 13).
fn build_udp_datagram(
    data:      const u8[:],
    peer_ip4:  u32,
    peer_port: u16,
    gso_size:  u16 = 0,
) -> UdpDatagram, bool {
    guard data.len <= UDP_MAX_PAYLOAD_LEN else {
        return UdpDatagram { .. }, false;
    }
    var dgram = UdpDatagram {
        peer_ip4:  peer_ip4,
        peer_port: peer_port,
        gso_size:  gso_size,
        ..
    };
    guard dgram.payload.try_append(data) else {
        return UdpDatagram { .. }, false;
    }
    return dgram, true;
}

// Stack-allocated UDP batch queue holding up to 32 datagrams for a single syscall transition.
struct UdpBatchQueue {
    msgs:            UdpDatagram[..32] = [],
    count:           i32               = 0,
    flushed_batches: u64               = 0,
    total_sent:      u64               = 0,
    total_recvd:     u64               = 0,
}

inline fn record_batch_sent_stats(queue: UdpBatchQueue&, sent_count: i32) {
    queue.flushed_batches += 1;
    queue.total_sent += (sent_count as u64);
    queue.msgs.clear();
    queue.count = 0;
}

inline fn record_batch_recv_stats(queue: UdpBatchQueue&, recv_count: i32) {
    queue.total_recvd += (recv_count as u64);
    queue.count = recv_count;
}

inline fn copy_datagram_to_arena(
    dgram:   const UdpDatagram&,
    slot:    i64,
    arena:   u8[47104]&,
    lengths: i32[32]&,
    ips:     u32[32]&,
    ports:   u16[32]&,
) {
    let base_off = slot * UDP_MAX_PAYLOAD_LEN;
    let plen = dgram.payload.len;
    lengths[slot] = plen as i32;
    ips[slot] = dgram.peer_ip4;
    ports[slot] = dgram.peer_port;
    for b_idx in plen {
        arena[base_off + b_idx] = dgram.payload[b_idx];
    }
}

inline fn unpack_arena_to_datagram(
    slot:    i64,
    arena:   const u8[:],
    pkt_len: i32,
    ip4:     u32,
    port:    u16,
) -> UdpDatagram, bool {
    let base_off = slot * UDP_MAX_PAYLOAD_LEN;
    let safe_len = core::ct_min_i64(UDP_MAX_PAYLOAD_LEN, core::ct_max_i64(0, pkt_len));
    let end_off = base_off + safe_len;
    guard end_off <= arena.len else {
        return UdpDatagram { .. }, false;
    }
    var dgram = UdpDatagram {
        peer_ip4:  ip4,
        peer_port: port,
        gso_size:  0,
        ..
    };
    let slice = arena[base_off..end_off];
    guard dgram.payload.try_append(slice) else {
        return UdpDatagram { .. }, false;
    }
    return dgram, true;
}

// Flushes all queued datagrams in `queue` via a single batched sendmmsg syscall transition.
// Resets queue count to 0 on successful flush.
fn batch_send_messages(fd: i32, queue: UdpBatchQueue&) -> i32, bool {
    let actual_count = queue.msgs.len as i32;
    guard fd >= 0 && actual_count >= 0 && actual_count <= UDP_BATCH_CAPACITY else {
        return 0, false;
    }
    if actual_count == 0 {
        queue.count = 0;
        return 0, true;
    }

    var arena:   u8[47104] = [0; 47104];
    var lengths: i32[32]   = [0; 32];
    var ips:     u32[32]   = [0; 32];
    var ports:   u16[32]   = [0; 32];

    for i in queue.msgs.len {
        copy_datagram_to_arena(queue.msgs[i], i, arena, lengths, ips, ports);
    }

    let sent = native_udp_sendmmsg(
        fd,
        arena[..],
        lengths[..],
        ips[..],
        ports[..],
        actual_count,
    );
    guard sent >= 0 else {
        return 0, false;
    }
    record_batch_sent_stats(queue, sent);
    return sent, true;
}

// Receives up to 32 datagrams in a single batched recvmmsg transition into `queue`.
fn batch_recv_messages(fd: i32, queue: UdpBatchQueue&) -> i32, bool {
    guard fd >= 0 else {
        return 0, false;
    }
    queue.msgs.clear();
    queue.count = 0;

    var arena:   u8[47104] = [0; 47104];
    var lengths: i32[32]   = [0; 32];
    var ips:     u32[32]   = [0; 32];
    var ports:   u16[32]   = [0; 32];

    let recvd = native_udp_recvmmsg(
        fd,
        arena[..],
        lengths[..],
        ips[..],
        ports[..],
        UDP_BATCH_CAPACITY,
        10,
    );
    guard recvd >= 0 && recvd <= UDP_BATCH_CAPACITY else {
        return 0, false;
    }

    let count_i64: i64 = recvd;
    for i in count_i64 {
        let dgram, ok = unpack_arena_to_datagram(i, arena[..], lengths[i], ips[i], ports[i]);
        guard ok && queue.msgs.try_push(dgram) else {
            return 0, false;
        }
    }
    record_batch_recv_stats(queue, recvd);
    return recvd, true;
}

// Enqueues a datagram into `queue`, automatically flushing when capacity (32) is reached
// before buffering packet 33 (enforcing Invariant 13: zero silent buffer drops).
fn enqueue_udp_datagram(fd: i32, queue: UdpBatchQueue&, dgram: const UdpDatagram&) -> i32, bool {
    guard fd >= 0 && dgram.payload.len <= UDP_MAX_PAYLOAD_LEN else {
        return 0, false;
    }
    var flushed: i32 = 0;
    if queue.msgs.len >= 32 {
        let sent, ok = batch_send_messages(fd, queue);
        guard ok else {
            return 0, false;
        }
        flushed = sent;
    }
    guard queue.msgs.try_push(copy(dgram)) else {
        return flushed, false;
    }
    queue.count = queue.msgs.len as i32;
    return flushed, true;
}
