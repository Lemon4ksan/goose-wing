// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// I/O types, error models, and stream status codes.
// Conforms to Goose Core zero-heap systems semantics.
namespace core;

import std;
import core.math.arithmetic;

enum IoError {
    None,
    WouldBlock,       // Non-blocking operation cannot make immediate progress (EAGAIN / EWOULDBLOCK)
    Eof,              // Natural end of stream reached
    UnexpectedEof,    // Stream truncated unexpectedly during fixed-width or exact read
    BufferFull,       // Destination buffer exhausted, cannot accommodate write
    LimitExceeded,    // Bounded stream limiter threshold reached (DoS protection)
    ShortWrite,       // Incomplete write: fewer bytes accepted than provided
    Closed,           // Channel, descriptor, or stream has been closed
    InvalidArgument,  // Parameter out of range (e.g. negative length, null slice)
}

// Readiness bitmask flags shared across cross-framework async I/O reactors.
const POLL_NONE:   u32 = 0;
const POLL_READ:   u32 = 1 << 0;
const POLL_WRITE:  u32 = 1 << 1;
const POLL_ERROR:  u32 = 1 << 2;
const POLL_HANGUP: u32 = 1 << 3;
const POLL_TIMER:  u32 = 1 << 4;
const POLL_WAKE:   u32 = 1 << 5;

enum PollInterest {
    None,
    Read,
    Write,
    ReadWrite,
}

fn interest_to_poll_flags(_: PollInterest.None) -> u32 { return POLL_NONE; }
fn interest_to_poll_flags(_: PollInterest.Read) -> u32 { return POLL_READ; }
fn interest_to_poll_flags(_: PollInterest.Write) -> u32 { return POLL_WRITE; }
fn interest_to_poll_flags(_: PollInterest.ReadWrite) -> u32 { return POLL_READ | POLL_WRITE; }

enum PollTrigger {
    Level,
    Edge,
}

struct PollReadyEvent {
    tag:             u64  = 0,
    fd:              i32  = -1,
    events:          u32  = POLL_NONE,
    bytes_available: i64  = 0,
    is_eof:          bool = false,
    is_timer:        bool = false,
}

struct DialTarget {
    host:         const u8[:] = "",
    port:         u16         = 0,
    timeout_ms:   u32         = 5000,
    non_blocking: bool        = true,
    unix_path:    const u8[:] = "",
}

const IO_OWNER_HTTP_SERVER: u16 = 1;
const IO_OWNER_USER_START:  u16 = 16;

// Transport-independent endpoint address supporting TCP and Unix domain sockets.
enum ConnectAddr {
    Tcp { host: const u8[:], port: u16 },
    Unix { path: const u8[:] },
}

inline fn is_valid_connect_addr(addr: ConnectAddr) -> bool {
    return match addr {
        Tcp t => t.host.len > 0 && t.port != 0,
        Unix u => u.path.len > 0 && u.path.len < 108,
    };
}

inline fn is_valid_listen_addr(addr: ConnectAddr) -> bool {
    return match addr {
        Tcp t => t.host.len > 0,
        Unix u => u.path.len > 0 && u.path.len < 108,
    };
}

enum ConnectStatus {
    Connected,
    InProgress,
    InvalidArgument,
    Failed,
}

// Opaque generation-checked connection handle shared across readiness,
// completion (io_uring/RIO), and virtual pipe hosts.
// Bit layout in `raw`: bits 0..31 = slot, bits 32..47 = gen (non-zero), bits 48..63 = owner.
struct IoLink {
    raw: u64 = 0,
}

inline fn make_io_link(owner: u16, gen: u16, slot: u32) -> IoLink {
    let packed = shl_sat_u64(owner, 48) | shl_sat_u64(gen, 32) | slot;
    return IoLink { raw: packed };
}

inline fn io_link_is_valid(link: IoLink) -> bool {
    return link.raw != 0 && ((link.raw >> 32) & 0xFFFF) != 0;
}

inline fn io_link_slot(link: IoLink) -> i64 {
    return (link.raw & 0xFFFFFFFF) as i64;
}

inline fn io_link_gen(link: IoLink) -> u16 {
    return ((link.raw >> 32) & 0xFFFF) as u16;
}

inline fn io_link_owner(link: IoLink) -> u16 {
    return ((link.raw >> 48) & 0xFFFF) as u16;
}

// Opaque generation-checked wakeup token handed to external async drivers (e.g. DB pools)
// to resume a parked HTTP request or stream task on the host event loop.
struct WakeToken {
    owner:     u16 = 0,
    gen:       u16 = 0,
    slot:      u32 = 0,
    stream_id: u32 = 0,
    req_seq:   u32 = 0,
}

inline fn wake_token_is_valid(tok: WakeToken) -> bool {
    return tok.owner != 0 && tok.gen != 0;
}

enum LinkEventKind {
    Accepted,
    Connected,
    Data,
    Writable,
    Eof,
    Closed,
    Timer,
    Wake,
    Pump,
}

// Zero-copy push event delivered from an event-loop host into a protocol driver.
struct LinkEvent {
    kind:     LinkEventKind = LinkEventKind.Data,
    link:     IoLink        = IoLink { .. },
    listener: IoLink        = IoLink { .. },
    tag:      u64           = 0,
    data:     const u8[:]   = "",
    err:      IoError       = IoError.None,
    timer_id: u64           = 0,
    token:    WakeToken     = WakeToken { .. },
}
