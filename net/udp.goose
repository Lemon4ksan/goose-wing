// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Layer 4 Batched UDP Datagram & GSO Engine (RFC 9000 Section 14, sendmmsg / recvmmsg).
// Zero-allocation batching up to 32 packets per syscall transition.
namespace net;

import std;
import core;
import .internal;
import .driver.types;

// Maximum IPv4/IPv6 UDP payload size for QUIC Ethernet frames without IP fragmentation (RFC 9000 Section 14).
const UDP_MAX_PAYLOAD_LEN: i64 = 1472;

// Maximum number of UDP datagrams batched in a single sendmmsg / recvmmsg transition.
const UDP_BATCH_CAPACITY: i32 = 32;

// Flat contiguous arena size for 32 x 1472-byte UDP payloads (47,104 bytes).
const UDP_BATCH_ARENA_BYTES: i64 = 47104;

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

inline fn udp_fallback_send_batch(queue: const UdpBatchQueue&, fd: i32) -> i32 {
    guard fd != 0 else { return queue.msgs.len as i32; }
    var sent: i32 = 0;
    for i in queue.msgs.len {
        let r = net_internal::native_udp_sendto_ip4(
            fd, queue.msgs[i].payload[..], queue.msgs[i].peer_ip4, queue.msgs[i].peer_port,
        );
        if r < 0 {
            return if sent == 0 { -1 } else { sent };
        }
        sent += 1;
    }
    return sent;
}

inline fn udp_fallback_recv_batch(queue: UdpBatchQueue&, fd: i32) -> i32, bool {
    guard fd != 0 else { return 0, true; }
    var recvd:   i32      = 0;
    var scratch: u8[1472] = [0; 1472];
    for i in UDP_BATCH_CAPACITY {
        let tmo: u32 = if i == 0 { 10 } else { 1 };
        var ip4:  u32 = 0;
        var port: u16 = 0;
        let r = net_internal::native_udp_recvfrom(fd, scratch[..], tmo, ip4, port);
        if r == -2 { break; }
        if r < 0 {
            return if recvd == 0 { -1 } else { recvd }, recvd > 0;
        }
        let dgram, ok_d = build_udp_datagram(scratch[..r], ip4, port);
        guard ok_d && queue.msgs.try_push(dgram) else {
            queue.msgs.clear();
            return 0, false;
        }
        recvd += 1;
    }
    return recvd, true;
}

// Flushes all queued datagrams in `queue` via a single batched sendmmsg syscall transition.
// Resets queue count to 0 on successful flush.
fn batch_send_messages(queue: UdpBatchQueue&, fd: i32) -> i32, bool {
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
        net_internal::copy_datagram_to_arena(queue.msgs[i], i, arena, lengths, ips, ports);
    }

    var sent = net_internal::native_udp_sendmmsg(
        fd,
        arena[..],
        lengths[..],
        ips[..],
        ports[..],
        actual_count,
    );
    if sent == net_internal::ERR_ENOSYS {
        sent = udp_fallback_send_batch(queue, fd);
    }
    guard sent >= 0 else {
        return 0, false;
    }
    net_internal::record_batch_sent_stats(queue, sent);
    return sent, true;
}

// Receives up to 32 datagrams in a single batched recvmmsg transition into `queue`.
fn batch_recv_messages(queue: UdpBatchQueue&, fd: i32) -> i32, bool {
    guard fd >= 0 else {
        return 0, false;
    }
    queue.msgs.clear();
    queue.count = 0;

    var arena:   u8[47104] = [0; 47104];
    var lengths: i32[32]   = [0; 32];
    var ips:     u32[32]   = [0; 32];
    var ports:   u16[32]   = [0; 32];

    let recvd = net_internal::native_udp_recvmmsg(
        fd,
        arena[..],
        lengths[..],
        ips[..],
        ports[..],
        UDP_BATCH_CAPACITY,
        10,
    );
    if recvd == net_internal::ERR_ENOSYS {
        let fb_recvd, fb_ok = udp_fallback_recv_batch(queue, fd);
        guard fb_ok else { return 0, false; }
        net_internal::record_batch_recv_stats(queue, fb_recvd);
        return fb_recvd, true;
    }
    guard recvd >= 0 && recvd <= UDP_BATCH_CAPACITY else {
        return 0, false;
    }

    var staged: UdpDatagram[..32] = [];
    let count_i64: i64 = recvd;
    for i in count_i64 {
        let dgram, ok = net_internal::unpack_arena_to_datagram(i, arena[..], lengths[i], ips[i], ports[i]);
        guard ok && staged.try_push(dgram) else {
            return 0, false;
        }
    }
    for i in staged.len {
        guard queue.msgs.try_push(copy(staged[i])) else {
            queue.msgs.clear();
            return 0, false;
        }
    }
    net_internal::record_batch_recv_stats(queue, recvd);
    return recvd, true;
}

// Enqueues a datagram into `queue`, automatically flushing when capacity (32) is reached
// before buffering packet 33 (enforcing Invariant 13: zero silent buffer drops).
fn enqueue_udp_datagram(queue: UdpBatchQueue&, fd: i32, dgram: const UdpDatagram&) -> i32, bool {
    guard fd >= 0 && dgram.payload.len <= UDP_MAX_PAYLOAD_LEN else {
        return 0, false;
    }
    var flushed: i32 = 0;
    if queue.msgs.len >= 32 {
        let sent, ok = queue.batch_send_messages(fd);
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
