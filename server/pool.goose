// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Server state, connection timers, and pooled buffers for request processing.
namespace internal;

import std;
import .router;

// ---- extractor bitmasks ----------------------------------------------------

let ENTRY_NONE:     u32 = 0;
let ENTRY_CONN:     u32 = 1 << 0;
let ENTRY_PARAMS:   u32 = 1 << 1;
let ENTRY_COOKIES:  u32 = 1 << 2;
let ENTRY_SECURITY: u32 = 1 << 3;
let ENTRY_ALL:      u32 = 0x0F;

// ---- header map pool -------------------------------------------------------

struct PooledHeaderMap {
    headers: wing::HeaderMap = wing::HeaderMap { .. },
    in_use:  bool            = false,
}

struct HeaderMapPool {
    pool: PooledHeaderMap[..16] = [PooledHeaderMap { .. }; 16],
}

fn acquire_header_map(pool: HeaderMapPool&) -> i32 {
    for idx in pool.pool.len {
        if !pool.pool[idx].in_use {
            pool.pool[idx].in_use = true;
            pool.pool[idx].headers.clear();
            return idx as i32;
        }
    }
    return -1;
}

fn release_header_map(pool: HeaderMapPool&, idx: i32) {
    guard idx >= 0 && idx < pool.pool.len else { return; }
    pool.pool[idx].headers.clear();
    pool.pool[idx].in_use = false;
}

// ---- extensions pool -------------------------------------------------------

struct RequestExtensions {
    peer_ip:           u8[..48]              = [],
    matched_route:     u8[..64]              = [],
    conn_id:           u64                   = 0,
    request_seq:       u64                   = 0,
    params:            wing::ZeroAllocParams = wing::ZeroAllocParams { .. },
    session_data:      u8[..512]             = [],
    canon_url:         u8[..2048]            = [],
    cors_origin:       u8[..128]             = [],
    auth_subject:      u8[..64]              = [],
    auth_scopes:       u64                   = 0,
    jwt_claims:        wing::JwtClaims       = wing::JwtClaims { .. },
    start_time_ns:     u64                   = 0,
    effective_pso:     u64                   = 0,
    populated_entries: u32                   = 0,
    in_use:            bool                  = false,
}

struct ExtensionsPool {
    slots: RequestExtensions[..16] = [RequestExtensions { .. }; 16],
}

fn reset_slot_jwt_claims(claims: wing::JwtClaims&) {
    claims.iss.clear();
    claims.sub.clear();
    claims.aud.clear();
    claims.audiences.clear();
    claims.jti.clear();
    claims.exp = -1;
    claims.nbf = -1;
    claims.iat = -1;
    claims.custom_claims.clear();
    claims.raw_payload.clear();
}

inline fn is_jwt_claims_dirty(slot: const RequestExtensions&) -> bool {
    return (slot.populated_entries & ENTRY_SECURITY) != 0
        || slot.jwt_claims.raw_payload.len > 0
        || slot.jwt_claims.sub.len > 0
        || slot.jwt_claims.iss.len > 0
        || slot.jwt_claims.exp != -1
        || slot.jwt_claims.custom_claims.len > 0;
}

fn clear_extension_slot_fields(slot: RequestExtensions&) {
    slot.peer_ip.clear();
    slot.matched_route.clear();
    slot.conn_id = 0;
    slot.request_seq = 0;
    slot.params.clear();
    if (slot.populated_entries & ENTRY_COOKIES) != 0 || slot.session_data.len > 0 {
        core::secure_zeroize_slice(slot.session_data[..]);
        slot.session_data.clear();
    }
    slot.canon_url.clear();
    slot.cors_origin.clear();
    slot.auth_subject.clear();
    slot.auth_scopes = 0;
    if is_jwt_claims_dirty(slot) {
        reset_slot_jwt_claims(slot.jwt_claims);
    }
    slot.start_time_ns = 0;
    slot.effective_pso = 0;
    slot.populated_entries = 0;
}

fn acquire_extensions(pool: ExtensionsPool&) -> i32 {
    for idx in pool.slots.len {
        if !pool.slots[idx].in_use {
            pool.slots[idx].in_use = true;
            clear_extension_slot_fields(pool.slots[idx]);
            return idx as i32;
        }
    }
    return -1;
}

// Sanitizes and returns extension slot to pool, preventing state leak across requests
fn release_extensions(pool: ExtensionsPool&, idx: i32) {
    guard idx >= 0 && idx < pool.slots.len else { return; }
    clear_extension_slot_fields(pool.slots[idx]);
    pool.slots[idx].in_use = false;
}

// ---- spill slab pool -------------------------------------------------------

const SPILL_SLAB_SIZE: u64 = 65536;
const MAX_SPILL_SLABS: u64 = 16;

struct SpillSlab {
    data:   u8[..65536] = [],
    in_use: bool        = false,
}

struct SpillSlabPool {
    in_use_mask: u16             = 0,
    slabs:       SpillSlab[..16] = [SpillSlab { .. }; 16],
}

// Leases an available 64 KiB slab from the worker pool.
// Returns non-negative slab index on success, or -1 if the pool is saturated.
fn acquire_spill_slab(pool: SpillSlabPool&) -> i32 {
    for idx in pool.slabs.len {
        if !pool.slabs[idx].in_use {
            pool.slabs[idx].in_use = true;
            pool.slabs[idx].data.clear();
            return idx as i32;
        }
    }
    return -1;
}

// Releases a leased slab back to the pool and resets its in_use status.
fn release_spill_slab(pool: SpillSlabPool&, idx: i32) {
    guard idx >= 0 && idx < pool.slabs.len else { return; }
    pool.slabs[idx].data.clear();
    pool.slabs[idx].in_use = false;
}

// ---- head buffer release ---------------------------------------------------

struct SyncHeadRelease {
    head_buffer_released: bool = false,
    bytes_consumed:       i64  = 0,
}

fn new_sync_head_release() -> SyncHeadRelease {
    return SyncHeadRelease { head_buffer_released: false, bytes_consumed: 0 };
}

fn mark_head_released(shr: SyncHeadRelease&, consumed: i64) {
    shr.head_buffer_released = true;
    shr.bytes_consumed = consumed;
}

// ---- inline handler future -------------------------------------------------

struct InlineHandlerFuture {
    vtable_tag:   u16    = 0,
    state_len:    u8     = 0,
    completed:    bool   = false,
    inline_state: u8[48] = [0; 48],
}

fn new_inline_handler_future(tag: u16 = 1) -> InlineHandlerFuture {
    return InlineHandlerFuture { vtable_tag: tag, state_len: 0, completed: false, inline_state: [0; 48] };
}

fn poll_future(fut: InlineHandlerFuture&) -> bool {
    fut.completed = true;
    return true;
}

// ---- connection timer ------------------------------------------------------

struct ConnectionTimer {
    active_req_seq:    u64  = 0,
    last_observed_seq: u64  = 0,
    in_flight_handler: bool = false,
    half_deadline_ns:  u64  = 15000000000, // 15 seconds (for 30s deadline)
    last_tick_mono_ns: u64  = 0,
    missed_ticks:      u8   = 0,
}

fn new_connection_timer(deadline_ns: u64, now_ns: u64) -> ConnectionTimer {
    let half_ns = if deadline_ns == 0 { 15000000000 } else { deadline_ns >> 1 };
    return ConnectionTimer {
        active_req_seq:    0,
        last_observed_seq: 0,
        in_flight_handler: false,
        half_deadline_ns:  half_ns,
        last_tick_mono_ns: now_ns,
        missed_ticks:      0,
    };
}

fn notify_request_start(timer: ConnectionTimer&) {
    timer.active_req_seq += 1;
    timer.in_flight_handler = true;
    timer.missed_ticks = 0;
}

fn notify_request_end(timer: ConnectionTimer&) {
    timer.in_flight_handler = false;
}

inline fn is_connection_tick_due(timer: const ConnectionTimer&, now_ns: u64) -> bool {
    return (max(now_ns, timer.last_tick_mono_ns) - timer.last_tick_mono_ns) >= timer.half_deadline_ns;
}

inline fn advance_connection_tick(timer: ConnectionTimer&) -> bool {
    if timer.active_req_seq != timer.last_observed_seq {
        timer.last_observed_seq = timer.active_req_seq;
        timer.missed_ticks = 0;
        return true;
    }
    timer.missed_ticks += 1;
    return timer.missed_ticks < 2;
}

// Checks connection liveliness every half-deadline.
// Returns false if connection should be closed as Slowloris/timed out.
fn check_connection_tick(timer: ConnectionTimer&, now_ns: u64) -> bool {
    guard is_connection_tick_due(timer, now_ns) else {
        return true;
    }
    timer.last_tick_mono_ns = now_ns;
    guard !timer.in_flight_handler else {
        return true;
    }
    return advance_connection_tick(timer);
}
