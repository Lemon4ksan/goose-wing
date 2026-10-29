// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Position-independent actor addressing, stash buffer, and zero-allocation priority mailboxes.
namespace core;

import std;

// 16-byte flat position-independent actor handle without heap references or pointers.
struct ActorRef {
    actor_id: u32 = 0,
    generation: u32 = 0,
    node_id: u32 = 0,
    mailbox_tag: u32 = 0,
}

fn new_actor_ref(actor_id: u32, generation: u32 = 1, node_id: u32 = 0, mailbox_tag: u32 = 0) -> ActorRef {
    return ActorRef {
        actor_id: actor_id,
        generation: generation,
        node_id: node_id,
        mailbox_tag: mailbox_tag,
    };
}

fn eq_actor_ref(a: const ActorRef&, b: const ActorRef&) -> bool {
    return a.actor_id == b.actor_id &&
           a.generation == b.generation &&
           a.node_id == b.node_id &&
           a.mailbox_tag == b.mailbox_tag;
}

// Deferred envelope stored on bump-pointer data stacks during state transitions.
struct StashedEnvelope {
    priority: u32 = 0,
    seq: u32 = 0,
    payload_type: u16 = 0,
    data: u8[..256] = [],
}

struct StashBuffer {
    messages: StashedEnvelope[>..] = [],
}

fn stash(sb: StashBuffer&, env: StashedEnvelope) {
    sb.messages.push(env);
}

fn unstash_all(sb: StashBuffer&, out_pending: StashedEnvelope[>..]&) -> i64 {
    let count = sb.messages.len;
    for msg in sb.messages {
        out_pending.push(msg);
    }
    sb.messages.clear();
    return count;
}

fn stash_count(sb: const StashBuffer&) -> i64 {
    return sb.messages.len;
}

fn is_empty(sb: const StashBuffer&) -> bool {
    return sb.messages.len == 0;
}

// Stable priority queue item for binary heap mailboxes.
struct PriorityItem {
    sort_key: u64 = 0, // (priority_u32 << 32) | (seq_counter_u32 & 0xFFFFFFFF)
    payload_type: u16 = 0,
    payload_val: i64 = 0,
}

// Zero-allocation binary min-heap priority mailbox on grow-shrink data stacks.
struct PriorityMailbox {
    seq_counter: u32 = 0,
    heap: PriorityItem[>..<] = [],
}

fn push(mb: PriorityMailbox&, priority: u32, payload_type: u16, val: i64) {
    let key = ((priority as u64) << 32) | ((mb.seq_counter as u64) & 0xFFFFFFFF);
    mb.seq_counter++;
    mb.heap.heap_push(PriorityItem {
        sort_key: key,
        payload_type: payload_type,
        payload_val: val,
    }) { a, b => a.sort_key < b.sort_key };
}

fn pop(mb: PriorityMailbox&) -> PriorityItem, bool {
    if mb.heap.len == 0 {
        return PriorityItem { .. }, false;
    }
    let item = mb.heap.heap_pop() { a, b => a.sort_key < b.sort_key };
    return item, true;
}

fn count(mb: const PriorityMailbox&) -> i64 {
    return mb.heap.len;
}
