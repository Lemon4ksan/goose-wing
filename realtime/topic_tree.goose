// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Pub/sub topic tree engine for goose-wing based on the uWebSockets TopicTree design.
// Conforms to RFC 6455 and MQTT Topic Specification (OASIS MQTT v5.0 §4.7):
// - Multi-level wildcard '#' matches arbitrary trailing topic hierarchy
// - Single-level wildcard '+' matches any individual topic segment
// - Zero-Heap Subscription Pool (4096 subscriptions, 256 buckets)
// - Single-Pass Server Frame Encoding: serializes RFC 6455 frame once for all subscribers
namespace realtime;

import std;
import core;
import rfc.ws;
import net.tcp;
import .internal;
import .websocket;
import .ws_deflate;

// Matches an MQTT topic pattern (with optional '+' and '#' wildcards) against a concrete topic name.
fn match_topic(pattern: const u8[:], topic: const u8[:]) -> bool {
    guard is_valid_topic_filter(pattern) && is_valid_publish_topic(topic) else { return false; }

    // OASIS MQTT v5.0 §4.7.2: Topics starting with '$' MUST NOT match filters starting with '+' or '#'
    if topic[0] == '$' && (pattern[0] == '+' || pattern[0] == '#') {
        return false;
    }

    if pattern == topic || pattern == "#" { return true; }

    var p_cur: i64 = 0;
    var t_cur: i64 = 0;

    loop {
        let p_next = realtime_internal::scan_topic_segment_end(pattern, p_cur);
        let p_seg = pattern[p_cur..p_next];
        if p_seg == "#" { return true; }

        let t_next = realtime_internal::scan_topic_segment_end(topic, t_cur);
        let t_seg = topic[t_cur..t_next];
        guard p_seg == "+" || p_seg == t_seg else { return false; }

        let p_has_more = p_next < pattern.len;
        let t_has_more = t_next < topic.len;

        if !p_has_more && !t_has_more { return true; }
        if !t_has_more {
            // MQTT §4.7.1.2: 'sport/#' matches parent level 'sport'
            return pattern[p_next..] == "/#";
        }
        guard p_has_more else { return false; }
        p_cur = core::add_sat_i64(p_next, 1);
        t_cur = core::add_sat_i64(t_next, 1);
    }
    return false;
}

struct TopicBucket {
    topic_pattern:    u8[..64] = [],
    pattern_hash:     u32      = 0,
    first_seg_hash:   u32      = 0,
    head_sub:         i32      = -1,
    subscriber_count: i32      = 0,
    has_wildcard:     bool     = false,
    in_use:           bool     = false,
}

enum PubSubError {
    None,
    InvalidTopic,
    MessageTooLarge,
    CapacityExceeded,
}

struct RetainedEntry {
    active:    bool       = false,
    is_binary: bool       = false,
    topic:     u8[..128]  = [],
    payload:   u8[..1024] = [],
}

// Fixed-capacity palette message for single-serialization broadcast (uWebSockets TopicTree pattern)
struct TopicPaletteMessage {
    wire:   u8[..4096] = [],
    in_use: bool       = false,
}

// Pre-formatted RFC 6455 WebSocket frame buffer for zero-copy multi-subscriber broadcast
// (uWebSockets PreparedMessage pattern). Pre-encodes raw and optionally compressed wire frames
// once, avoiding per-subscriber serialization passes.
struct PreparedMessage {
    wire:            u8[..16384] = [],
    compressed_wire: u8[..16384] = [],
    has_compressed:  bool        = false,
    opcode:          u8          = rfc::WS_OPCODE_TEXT,
}

struct SubscriptionNode {
    sock_fd:  i64  = -1,
    next_sub: i32  = -1,
    in_use:   bool = false,
    // uWebSockets batch drainage & message palette
    message_indices:     u16[32] = [0; 32],
    num_message_indices: u8      = 0,
    prev_drainable:      i32     = -1,
    next_drainable:      i32     = -1,
}

struct TopicTree {
    buckets:                  TopicBucket[..256]        = [TopicBucket { .. }; 256],
    nodes:                    SubscriptionNode[..4096]  = [SubscriptionNode { .. }; 4096],
    palette:                  TopicPaletteMessage[..64] = [TopicPaletteMessage { .. }; 64],
    retained:                 RetainedEntry[..64]       = [RetainedEntry { .. }; 64],
    palette_len:              i32                       = 0,
    drainable_head:           i32                       = -1,
    active_buckets:           i32                       = 0,
    active_subscriptions:     i32                       = 0,
    total_publishes:          u64                       = 0,
    total_messages_delivered: u64                       = 0,
}

// Validates an MQTT topic filter per OASIS MQTT v5.0 §4.7.1.2:
// - Multi-level wildcard '#' must be the last character and either standalone ("#") or preceded by '/' ("sport/#").
// - Single-level wildcard '+' must occupy an entire level (must be preceded by '/' or start-of-filter,
//   and followed by '/' or end-of-filter).
// - Topic filter must not be empty, exceed 64 bytes, or contain null characters.
fn is_valid_topic_filter(pattern: const u8[:]) -> bool {
    guard pattern.len > 0 && pattern.len <= 64 else { return false; }

    for i in pattern.len {
        guard realtime_internal::is_valid_wildcard_char(pattern, i, pattern[i]) else { return false; }
    }

    return true;
}

// Subscribes a socket descriptor to a topic pattern, returning `(old_count, new_count, ok)`.
fn subscribe_ex(
    tree:    TopicTree&,
    sock_fd: i64,
    pattern: const u8[:],
) -> i32, i32, bool {
    guard sock_fd > 0 && is_valid_topic_filter(pattern) else { return 0, 0, false; }

    let b_idx, ok_b = realtime_internal::get_or_create_topic_bucket(tree, pattern);
    guard ok_b else { return 0, 0, false; }
    let b = b_idx as i64;
    var committed = false;
    defer if !committed { realtime_internal::reclaim_empty_bucket(tree, b); };

    if realtime_internal::is_subscribed_in_bucket(tree, b, sock_fd) {
        let cnt = tree.buckets[b].subscriber_count;
        committed = true;
        return cnt, cnt, true;
    }

    // Enforce bounded 512-subscriber limit per topic bucket (Invariant 13 fail-closed rejection)
    let cur_cnt = tree.buckets[b].subscriber_count;
    guard cur_cnt < realtime_internal::TOPIC_MAX_SUBSCRIBERS_PER_BUCKET else {
        return cur_cnt, cur_cnt, false;
    }

    // Allocate subscription node from bounded pool
    for &node, i in tree.nodes {
        if !node.in_use {
            node.sock_fd = sock_fd;
            node.next_sub = tree.buckets[b].head_sub;
            node.in_use = true;
            node.num_message_indices = 0;
            node.prev_drainable = -1;
            node.next_drainable = -1;

            let old_cnt = tree.buckets[b].subscriber_count;
            let new_cnt = old_cnt + 1;
            tree.buckets[b].head_sub = i as i32;
            tree.buckets[b].subscriber_count = new_cnt;
            tree.active_subscriptions += 1;

            committed = true;
            return old_cnt, new_cnt, true;
        }
    }

    return 0, 0, false;
}

// Subscribes a socket descriptor to a topic pattern.
// Returns true on success, false if capacity is exceeded, invalid pattern, or already subscribed.
fn subscribe(tree: TopicTree&, sock_fd: i64, pattern: const u8[:]) -> bool {
    let _, _, ok = subscribe_ex(tree, sock_fd, pattern);
    return ok;
}

// Subscribes a socket descriptor with subscription lifecycle callback notification (uWebSockets subscription hook).
fn subscribe_with_hook<HookFn: fn(const u8[:], i32, i32, i64)>(
    tree:    TopicTree&,
    sock_fd: i64,
    pattern: const u8[:],
) -> bool {
    let old_cnt, new_cnt, ok = subscribe_ex(tree, sock_fd, pattern);
    if ok && old_cnt != new_cnt {
        HookFn(pattern, old_cnt, new_cnt, sock_fd);
    }
    return ok;
}

// Unsubscribes a socket descriptor from a topic pattern, returning `(old_count, new_count, ok)`.
fn unsubscribe_ex(
    tree:    TopicTree&,
    sock_fd: i64,
    pattern: const u8[:],
) -> i32, i32, bool {
    guard sock_fd > 0 && pattern.len > 0 else { return 0, 0, false; }

    let b_idx, ok_b = realtime_internal::find_topic_bucket(tree, pattern);
    guard ok_b else { return 0, 0, false; }
    let b = b_idx as i64;

    var prev: i32 = -1;
    var cur = tree.buckets[b].head_sub;

    while cur >= 0 {
        let cur_i64 = cur as i64;
        if tree.nodes[cur_i64].in_use && tree.nodes[cur_i64].sock_fd == sock_fd {
            let _, old_cnt = realtime_internal::release_subscription_node(tree, b, prev, cur);
            realtime_internal::reclaim_empty_bucket(tree, b);
            return old_cnt, old_cnt - 1, true;
        }
        prev = cur;
        cur = tree.nodes[cur_i64].next_sub;
    }

    return 0, 0, false;
}

// Unsubscribes a socket descriptor from a topic pattern.
// Returns true if unsubscription succeeded, false if not subscribed.
fn unsubscribe(tree: TopicTree&, sock_fd: i64, pattern: const u8[:]) -> bool {
    let _, _, ok = unsubscribe_ex(tree, sock_fd, pattern);
    return ok;
}

// Unsubscribes a socket descriptor with subscription lifecycle callback notification (uWebSockets subscription hook).
fn unsubscribe_with_hook<HookFn: fn(const u8[:], i32, i32, i64)>(
    tree:    TopicTree&,
    sock_fd: i64,
    pattern: const u8[:],
) -> bool {
    let old_cnt, new_cnt, ok = unsubscribe_ex(tree, sock_fd, pattern);
    if ok {
        HookFn(pattern, old_cnt, new_cnt, sock_fd);
    }
    return ok;
}

// Unsubscribes a socket descriptor from all subscribed topics.
// Invoked automatically when a connection terminates to reclaim pool slots.
// Returns total number of unsubscriptions performed.
fn unsubscribe_all(tree: TopicTree&, sock_fd: i64) -> i32 {
    guard sock_fd > 0 else { return 0; }
    var unsubs: i32 = 0;

    for b in tree.buckets.len {
        guard tree.buckets[b].in_use else { continue; }

        var prev: i32 = -1;
        var cur = tree.buckets[b].head_sub;

        while cur >= 0 {
            let cur_i64 = cur as i64;
            if tree.nodes[cur_i64].in_use && tree.nodes[cur_i64].sock_fd == sock_fd {
                let next, _ = realtime_internal::release_subscription_node(tree, b, prev, cur);
                unsubs += 1;
                cur = next;
            } else {
                prev = cur;
                cur = tree.nodes[cur_i64].next_sub;
            }
        }

        realtime_internal::reclaim_empty_bucket(tree, b);
    }

    return unsubs;
}

// Unsubscribes a socket descriptor from all subscribed topics with callback notification per topic.
fn unsubscribe_all_with_hook<HookFn: fn(const u8[:], i32, i32, i64)>(
    tree:    TopicTree&,
    sock_fd: i64,
) -> i32 {
    guard sock_fd > 0 else { return 0; }
    var unsubs: i32 = 0;

    for b in tree.buckets.len {
        guard tree.buckets[b].in_use else { continue; }

        var prev: i32 = -1;
        var cur = tree.buckets[b].head_sub;

        while cur >= 0 {
            let cur_i64 = cur as i64;
            if tree.nodes[cur_i64].in_use && tree.nodes[cur_i64].sock_fd == sock_fd {
                let next, old_cnt = realtime_internal::release_subscription_node(tree, b, prev, cur);
                unsubs += 1;
                let new_cnt = old_cnt - 1;
                HookFn(tree.buckets[b].topic_pattern[..], old_cnt, new_cnt, sock_fd);
                cur = next;
            } else {
                prev = cur;
                cur = tree.nodes[cur_i64].next_sub;
            }
        }

        realtime_internal::reclaim_empty_bucket(tree, b);
    }

    return unsubs;
}

// Checks if a socket is subscribed to a topic pattern.
fn is_subscribed(tree: const TopicTree&, sock_fd: i64, pattern: const u8[:]) -> bool {
    let b_idx, ok_b = realtime_internal::find_topic_bucket(tree, pattern);
    guard ok_b else { return false; }
    return realtime_internal::is_subscribed_in_bucket(tree, b_idx, sock_fd);
}

// Returns the total number of subscribers for a given topic pattern.
fn subscriber_count(tree: const TopicTree&, pattern: const u8[:]) -> i32 {
    let b_idx, ok_b = realtime_internal::find_topic_bucket(tree, pattern);
    guard ok_b else { return 0; }
    return tree.buckets[b_idx as i64].subscriber_count;
}

// Returns the number of distinct topic patterns a socket is currently subscribed to.
fn socket_subscription_count(tree: const TopicTree&, sock_fd: i64) -> i32 {
    guard sock_fd > 0 else { return 0; }
    var count: i32 = 0;
    for b in tree.buckets.len {
        if tree.buckets[b].in_use && realtime_internal::is_subscribed_in_bucket(tree, b, sock_fd) {
            count += 1;
        }
    }
    return count;
}

// Retrieves all topic patterns a socket is subscribed to (uWebSockets ws->iterateTopics pattern).
fn get_socket_topics(
    tree:       const TopicTree&,
    sock_fd:    i64,
    out_topics: u8[..64][..32]&,
) -> i32 {
    guard sock_fd > 0 else {
        out_topics.clear();
        return 0;
    }
    out_topics.clear();
    for &b_entry, b in tree.buckets {
        if b_entry.in_use && realtime_internal::is_subscribed_in_bucket(tree, b, sock_fd) {
            var pat: u8[..64] = [];
            pat.append(b_entry.topic_pattern[..]);
            guard out_topics.try_push(pat) else { break; }
        }
    }
    return out_topics.len as i32;
}

// Iterates through all topic patterns a socket is subscribed to via callback (uWebSockets ws->iterateTopics pattern).
fn iterate_socket_topics<IterFn: fn(const u8[:])>(
    tree:    const TopicTree&,
    sock_fd: i64,
) -> i32 {
    guard sock_fd > 0 else { return 0; }
    var count: i32 = 0;
    for &b_entry, b in tree.buckets {
        if b_entry.in_use && realtime_internal::is_subscribed_in_bucket(tree, b, sock_fd) {
            IterFn(b_entry.topic_pattern[..]);
            count += 1;
        }
    }
    return count;
}

// Validates a publish topic name per OASIS MQTT v5.0 §3.3.2.1 and uWS #1090:
// Topic Name in PUBLISH packet MUST NOT contain wildcards ('+' or '#') or null bytes.
fn is_valid_publish_topic(topic: const u8[:]) -> bool {
    guard topic.len > 0 && topic.len <= 64 else { return false; }
    for b in topic {
        guard b != '+' && b != '#' && b != 0 else { return false; }
    }
    return true;
}

// Adds a distinct subscriber `sub_id` to `topic` in `tree`, enforcing the 512-subscriber limit.
// Returns `(subscriber_count: i32, ok: bool)` with `ok = false` when the 512-subscriber limit is exceeded.
fn add_distinct_subscriber(tree: TopicTree&, topic: const u8[:], sub_id: u32) -> i32, bool {
    guard sub_id > 0 else { return 0, false; }
    let _, new_cnt, ok = subscribe_ex(tree, sub_id, topic);
    return new_cnt, ok;
}

// Appends a socket descriptor to `out_fds` if not previously recorded in bitmask or array.
// Returns `(count: i32, ok: bool)` with `ok = false` when `out_fds` reaches its 512-subscriber capacity.
fn add_distinct_subscriber(out_fds: i64[..512]&, seen_mask: u64[4]&, fd: i64) -> i32, bool {
    guard fd > 0 else { return out_fds.len as i32, false; }
    let h = realtime_internal::hash_fd_bucket(fd);
    let word_idx = (h >> 6) as i64;
    let bit = (1 as u64) << (h & 63);

    if (seen_mask[word_idx] & bit) == 0 {
        guard out_fds.try_push(fd) else { return out_fds.len as i32, false; }
        seen_mask[word_idx] |= bit;
        return out_fds.len as i32, true;
    }

    for d_fd in out_fds {
        if d_fd == fd { return out_fds.len as i32, true; }
    }
    guard out_fds.try_push(fd) else { return out_fds.len as i32, false; }
    return out_fds.len as i32, true;
}

// Finds all distinct sockets subscribed to patterns matching the target topic,
// returning `(count: i64, ok: bool)` where `ok == false` if the 512-subscriber buffer overflows.
fn find_subscribers_checked(tree: const TopicTree&, topic: const u8[:], out_fds: i64[..512]&) -> i64, bool {
    guard is_valid_publish_topic(topic) else { return 0, false; }
    out_fds.clear();
    var seen_mask: u64[4] = [0, 0, 0, 0];
    let t_hash = core::fnv1a_32(topic);
    let t_seg_hash = realtime_internal::compute_topic_first_seg_hash(topic);

    for &b_entry in tree.buckets {
        guard b_entry.in_use && b_entry.subscriber_count > 0 else { continue; }
        guard realtime_internal::does_bucket_match_topic(b_entry, topic, t_hash, t_seg_hash) else { continue; }

        var cur = b_entry.head_sub;
        while cur >= 0 {
            let cur_i64 = cur as i64;
            let n_entry .= tree.nodes[cur_i64];
            if n_entry.in_use {
                let _, add_ok = add_distinct_subscriber(out_fds, seen_mask, n_entry.sock_fd);
                guard add_ok else { return out_fds.len, false; }
            }
            cur = n_entry.next_sub;
        }
    }
    return out_fds.len, true;
}

// Finds all distinct sockets subscribed to patterns matching the target topic.
// Returns the number of distinct sockets stored into out_fds.
fn find_subscribers(tree: const TopicTree&, topic: const u8[:], out_fds: i64[..512]&) -> i64 {
    let count, _ = find_subscribers_checked(tree, topic, out_fds);
    return count;
}

// Publishes a pre-encoded raw WebSocket frame to all subscribers matching the target topic.
// Avoids duplicate delivery if a socket matches multiple wildcard patterns.
// Returns the number of distinct sockets the message was dispatched to.
fn publish_frame(tree: TopicTree&, topic: const u8[:], frame_wire: const u8[:]) -> i64 {
    guard is_valid_publish_topic(topic) && frame_wire.len > 0 else { return 0; }

    var matched_fds: i64[..512] = [];
    find_subscribers(tree, topic, matched_fds);

    var delivered: i64 = 0;
    for fd in matched_fds {
        let sent = net::tcp_send(fd, frame_wire);
        if sent > 0 {
            delivered += 1;
        }
    }

    realtime_internal::record_publish_stats(tree, delivered);
    return delivered;
}

// Encodes the message once into a server frame (unmasked per RFC 6455) and broadcasts to all topic subscribers.
fn publish(
    tree:    TopicTree&,
    topic:   const u8[:],
    message: const u8[:],
    opcode:  u8 = rfc::WS_OPCODE_TEXT,
) -> i64 {
    guard message.len + 14 <= 65536 else { return 0; }
    var frame: u8[..65536] = [];
    let no_mask: u8[4] = [0, 0, 0, 0];
    encode_ws_frame(frame, opcode, message, false, no_mask, true);
    return publish_frame(tree, topic, frame[..]);
}

// Convenience helper to publish UTF-8 text message to a topic.
fn publish_text(tree: TopicTree&, topic: const u8[:], text: const u8[:]) -> i64 {
    return publish(tree, topic, text, rfc::WS_OPCODE_TEXT);
}

// Convenience helper to publish binary message to a topic.
fn publish_binary(tree: TopicTree&, topic: const u8[:], data: const u8[:]) -> i64 {
    return publish(tree, topic, data, rfc::WS_OPCODE_BINARY);
}

// Encodes an unmasked RFC 6455 server frame once for PreparedMessage broadcast
// (uWebSockets Loop::prepareMessage pattern).
//
// Example:
//   payload = "{\"ticker\":\"AAPL\",\"price\":182.50}", opcode = WS_OPCODE_TEXT
//   returns: true, out_msg.wire populated with [0x81, 0x22, ...], out_msg.has_compressed = false
fn prepare_message(
    out_msg: PreparedMessage&,
    payload: const u8[:],
    opcode:  u8 = rfc::WS_OPCODE_TEXT,
) -> bool {
    guard payload.len + 14 <= out_msg.wire.cap else { return false; }
    out_msg.wire.clear();
    out_msg.compressed_wire.clear();
    out_msg.has_compressed = false;
    out_msg.opcode = opcode;

    let no_mask: u8[4] = [0, 0, 0, 0];
    encode_ws_frame(out_msg.wire, opcode, payload, false, no_mask, true);
    return true;
}

// Pre-encodes both uncompressed and RFC 7692 compressed frames into a PreparedMessage
// (uWebSockets Loop::prepareMessage pattern). If compression yields a smaller wire frame,
// sets `has_compressed = true`.
//
// Example:
//   payload = "long repetitive json text ...", opcode = WS_OPCODE_TEXT
//   returns: true, out_msg.has_compressed = true, out_msg.compressed_wire.len < out_msg.wire.len
fn prepare_message_compressed(
    out_msg:     PreparedMessage&,
    payload:     const u8[:],
    shared_comp: SharedWsCompressor&,
    opcode:      u8 = rfc::WS_OPCODE_TEXT,
) -> bool {
    guard prepare_message(out_msg, payload, opcode) else { return false; }

    if payload.len > 0 {
        let comp_slice, ok_c = ws_deflate_message_slice(shared_comp, payload, true);
        guard ok_c && comp_slice.len > 0 && comp_slice.len + 14 <= out_msg.compressed_wire.cap else {
            return true;
        }
        let no_mask: u8[4] = [0, 0, 0, 0];
        encode_ws_frame_compressed(out_msg.compressed_wire, opcode, comp_slice, false, no_mask, true);
        if out_msg.compressed_wire.len < out_msg.wire.len {
            out_msg.has_compressed = true;
        }
    }
    return true;
}

// Publishes a pre-framed PreparedMessage to all subscribers of a topic (uWebSockets publishPrepared pattern).
// Returns the number of distinct sockets the message was dispatched to.
fn publish_prepared(
    tree:  TopicTree&,
    topic: const u8[:],
    msg:   const PreparedMessage&,
) -> i64 {
    guard is_valid_publish_topic(topic) && msg.wire.len > 0 else { return 0; }

    var matched_fds: i64[..512] = [];
    find_subscribers(tree, topic, matched_fds);

    var delivered: i64 = 0;
    for fd in matched_fds {
        let sent = net::tcp_send(fd, msg.wire[..]);
        if sent > 0 {
            delivered += 1;
        }
    }

    realtime_internal::record_publish_stats(tree, delivered);
    return delivered;
}

// ---- uWebSockets TopicTree Batch Drainage & Message Palette Engine ---------

// Drains all batched messages for a specific subscriber node.
// Unlinks from drainable list and sends wire frames directly to the socket descriptor.
fn drain_subscriber(tree: TopicTree&, node_idx: i32) -> i64 {
    guard node_idx >= 0 && node_idx < tree.nodes.len as i32 else { return 0; }
    let n_i64 = node_idx as i64;
    guard tree.nodes[n_i64].in_use && tree.nodes[n_i64].num_message_indices > 0 else { return 0; }

    realtime_internal::unlink_drainable_node(tree, node_idx);
    let count = tree.nodes[n_i64].num_message_indices as i64;
    let fd = tree.nodes[n_i64].sock_fd;
    tree.nodes[n_i64].num_message_indices = 0;

    let sent = realtime_internal::flush_node_palette_messages(tree, n_i64, fd, count);
    tree.total_messages_delivered += (sent as u64);
    return sent;
}

// Drains all drainable subscribers in batch.
// Iterates through the drainable linked list once, eliminating redundant topic tree traversal.
// Resets the outgoing message palette to 0 allocations.
fn drain(tree: TopicTree&) -> i64 {
    var cur = tree.drainable_head;
    if cur < 0 {
        tree.palette_len = 0;
        return 0;
    }

    var total_delivered: i64 = 0;
    while cur >= 0 {
        let c_i64 = cur as i64;
        let next = tree.nodes[c_i64].next_drainable;
        let fd = tree.nodes[c_i64].sock_fd;
        let count = tree.nodes[c_i64].num_message_indices as i64;

        tree.nodes[c_i64].num_message_indices = 0;
        tree.nodes[c_i64].prev_drainable = -1;
        tree.nodes[c_i64].next_drainable = -1;

        let batch_sent = realtime_internal::flush_node_palette_messages(tree, c_i64, fd, count);
        total_delivered += batch_sent;
        cur = next;
    }

    tree.drainable_head = -1;
    tree.palette_len = 0;
    tree.total_messages_delivered += (total_delivered as u64);
    return total_delivered;
}

// Publishes a message into the outgoing message palette and batches delivery to all subscribers
// without re-serializing the frame per subscriber. Any subscriber reaching 32 queued messages
// is drained immediately. Returns the number of distinct sockets queued to.
fn publish_batch(
    tree:      TopicTree&,
    topic:     const u8[:],
    payload:   const u8[:],
    opcode:    u8  = rfc::WS_OPCODE_TEXT,
    sender_fd: i64 = -1,
) -> i64 {
    guard is_valid_publish_topic(topic) && payload.len + 14 <= 4096 else { return 0; }

    // If palette reached capacity (64 messages), drain all pending subscribers first
    if tree.palette_len >= (tree.palette.cap as i32) {
        drain(tree);
    }

    let msg_idx = tree.palette_len as i64;
    tree.palette[msg_idx].wire.clear();
    let no_mask: u8[4] = [0, 0, 0, 0];
    encode_ws_frame(tree.palette[msg_idx].wire, opcode, payload, false, no_mask, true);
    tree.palette_len += 1;

    var seen_fds:  i64[..512] = [];
    var seen_mask: u64[4]     = [0, 0, 0, 0];
    var queued:    i64        = 0;
    let t_hash = core::fnv1a_32(topic);
    let t_seg_hash = realtime_internal::compute_topic_first_seg_hash(topic);
    for &b_entry in tree.buckets {
        guard b_entry.in_use && b_entry.subscriber_count > 0 else { continue; }
        guard realtime_internal::does_bucket_match_topic(b_entry, topic, t_hash, t_seg_hash) else { continue; }

        var cur = b_entry.head_sub;
        while cur >= 0 {
            if realtime_internal::queue_subscriber_batch(tree, cur, msg_idx, sender_fd, seen_fds, seen_mask) {
                queued += 1;
            }
            cur = tree.nodes[cur as i64].next_sub;
        }
    }

    if queued == 0 && tree.palette_len == ((msg_idx + 1) as i32) {
        tree.palette_len = msg_idx as i32;
    }

    tree.total_publishes += 1;
    return queued;
}

// Returns the number of subscribers currently queued for batch drainage.
fn drainable_count(tree: const TopicTree&) -> i32 {
    var count: i32 = 0;
    var cur = tree.drainable_head;
    while cur >= 0 {
        count += 1;
        cur = tree.nodes[cur as i64].next_drainable;
    }
    return count;
}

// Checks if a socket descriptor has queued messages awaiting drainage.
fn subscriber_needs_drain(tree: const TopicTree&, sock_fd: i64) -> bool {
    guard sock_fd > 0 else { return false; }
    for &node in tree.nodes {
        if node.in_use && node.sock_fd == sock_fd && node.num_message_indices > 0 {
            return true;
        }
    }
    return false;
}

// Returns the number of messages queued for a given socket descriptor.
fn subscriber_queued_messages(tree: const TopicTree&, sock_fd: i64) -> i32 {
    guard sock_fd > 0 else { return 0; }
    var total: i32 = 0;
    for &node in tree.nodes {
        if node.in_use && node.sock_fd == sock_fd {
            total += node.num_message_indices;
        }
    }
    return total;
}

// Publishes a retained message on `topic` (OASIS MQTT v5.0 §3.3.1.3 & mosquitto retain__store pattern).
// - When `payload.len == 0`, deletes any existing retained message on `topic` and returns `(0, PubSubError.None)`.
// - When `payload.len > 0`, stores or overwrites the retained message and fans out to current subscribers.
fn publish_retained(
    tree:      TopicTree&,
    topic:     const u8[:],
    payload:   const u8[:],
    is_binary: bool,
) -> u32, PubSubError {
    guard is_valid_publish_topic(topic) else { return 0, PubSubError.InvalidTopic; }

    if payload.len == 0 {
        for &entry in tree.retained {
            if entry.active && entry.topic[..] == topic {
                entry.active = false;
                entry.is_binary = false;
                entry.topic.clear();
                entry.payload.clear();
            }
        }
        return 0, PubSubError.None;
    }

    guard payload.len <= 1024 else { return 0, PubSubError.MessageTooLarge; }

    let slot = realtime_internal::find_retained_slot_for_topic(tree, topic);
    guard slot >= 0 else { return 0, PubSubError.CapacityExceeded; }

    guard tree.retained[slot].topic.try_set(topic) && tree.retained[slot].payload.try_set(payload) else {
        return 0, PubSubError.MessageTooLarge;
    }
    tree.retained[slot].is_binary = is_binary;
    tree.retained[slot].active = true;

    let opcode = if is_binary { rfc::WS_OPCODE_BINARY } else { rfc::WS_OPCODE_TEXT };
    let queued = publish_batch(tree, topic, payload, opcode, -1);
    return max(0, queued) as u32, PubSubError.None;
}

// Subscribes `sub_id` to `pattern` and immediately replays all matching retained messages
// into `sub_id`'s outgoing 32-slot message palette (OASIS MQTT v5.0 §3.3.1.3).
fn subscribe_with_retained(tree: TopicTree&, sub_id: u64, pattern: const u8[:]) -> PubSubError {
    guard sub_id > 0 && is_valid_topic_filter(pattern) else { return PubSubError.InvalidTopic; }
    let sub_fd = sub_id as i64;
    guard subscribe(tree, sub_fd, pattern) else { return PubSubError.CapacityExceeded; }

    for &entry in tree.retained {
        if entry.active && match_topic(pattern, entry.topic[..]) {
            realtime_internal::enqueue_retained_to_subscriber(tree, sub_fd, entry.payload[..], entry.is_binary);
        }
    }
    return PubSubError.None;
}
