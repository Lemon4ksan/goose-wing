// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// CSP channels, synchronous rendezvous, and in-order stream reassembler.
namespace core;

import std;

// Static typed channel envelope. Generates an isolated physical queue per (Tag, T).
struct Envelope<Tag, T> {
    payload: T,
}

fn chan_send<Tag, T>(msg: T) -> bool {
    return qput(Envelope<Tag, T> { payload: msg });
}

fn chan_recv<Tag, T>() -> T {
    let env = qget<Envelope<Tag, T>>();
    return env.payload;
}

fn chan_try_recv<Tag, T>() -> T, bool {
    let env, ok = qpoll<Envelope<Tag, T>>();
    if ok {
        return env.payload, true;
    }
    return default<T>(), false;
}

fn chan_recv_timeout<Tag, T>(timeout_ms: i64) -> T, bool {
    if timeout_ms < 0 {
        return default<T>(), false;
    }
    let env, ok = qget<Envelope<Tag, T>>(timeout_ms);
    if ok {
        return env.payload, true;
    }
    return default<T>(), false;
}

// Bidirectional synchronous rendezvous acknowledgment token.
struct Ack<Tag> {
    status_ok: bool = true,
}

fn chan_rendezvous<Tag, Req>(req: Req) -> bool {
    qput(Envelope<Tag, Req> { payload: req });
    let ack = qget<Ack<Tag>>();
    return ack.status_ok;
}

fn chan_rendezvous_reply<Tag>(ok: bool = true) -> bool {
    return qput(Ack<Tag> { status_ok: ok });
}

// Variable-mode ADT multiplexing event enum.
enum MuxEvent {
    DataPacket { stream_id: u16, bytes: u8[..256] },
    ControlCmd { code: u8 },
    TimerTick { timestamp_ns: u64 },
    Shutdown,
}

// Generic in-order reassembler item.
struct ReassemblerItem {
    seq_id: i64 = 0,
    data: u8[..256] = [],
}

// In-Order stream reassembly buffer for Fan-Out parallel worker pipelines.
struct Reassembler {
    next_expected_seq: i64 = 0,
    stash: ReassemblerItem[>..<] = [],
}

fn new_reassembler(initial_seq: i64 = 0) -> Reassembler {
    return Reassembler { next_expected_seq: initial_seq, .. };
}

fn push_unordered(r: Reassembler&, item: ReassemblerItem) {
    r.stash.push(item);
}

fn pop_next_in_order(r: Reassembler&) -> ReassemblerItem, bool {
    for idx in r.stash.len {
        if r.stash[idx].seq_id == r.next_expected_seq {
            let found = r.stash[idx];
            r.stash[idx] = r.stash[r.stash.len - 1];
            r.stash.pop();
            r.next_expected_seq++;
            return found, true;
        }
    }
    return ReassemblerItem { .. }, false;
}

fn pending_count(r: const Reassembler&) -> i64 {
    return r.stash.len;
}
