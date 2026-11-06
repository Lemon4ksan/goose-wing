// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Pub/sub topic tree engine for goose-wing based on the uWebSockets TopicTree design.
// Conforms to RFC 6455 and MQTT Topic Specification (OASIS MQTT v5.0 §4.7):
// - Multi-level wildcard '#' matches arbitrary trailing topic hierarchy
// - Single-level wildcard '+' matches any individual topic segment
// - Zero-Heap Subscription Pool (4096 subscriptions, 256 buckets)
// - Single-Pass Server Frame Encoding: serializes RFC 6455 frame once for all subscribers
namespace wing;

import std;
import core from "..";
import .websocket;

const TOPIC_TREE_MAX_BUCKETS:       i64 = 256;
const TOPIC_TREE_MAX_SUBSCRIPTIONS: i64 = 4096;

// Scans forward from `start` until '/' or end of slice (OASIS MQTT v5.0 §4.7).
//
// Example:
//   raw = "sensors/temp", start = 0
//   returns: 7
fn scan_topic_segment_end(raw: const u8[:], start: i64) -> i64 {
    var next = start;
    while next < raw.len && raw[next] != '/' {
        next += 1;
    }
    return next;
}

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
        let p_next = scan_topic_segment_end(pattern, p_cur);
        let p_seg = pattern[p_cur..p_next];
        if p_seg == "#" { return true; }

        let t_next = scan_topic_segment_end(topic, t_cur);
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
        p_cur = p_next + 1;
        t_cur = t_next + 1;
    }
    return false;
}

struct TopicBucket {
    topic_pattern:    u8[..64] = [],
    head_sub:         i32      = -1,
    subscriber_count: i32      = 0,
    has_wildcard:     bool     = false,
    in_use:           bool     = false,
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

const TOPIC_PALETTE_CAP: i64 = 64;

struct TopicTree {
    buckets:                  TopicBucket[..256]        = [TopicBucket { .. }; 256],
    nodes:                    SubscriptionNode[..4096]  = [SubscriptionNode { .. }; 4096],
    palette:                  TopicPaletteMessage[..64] = [TopicPaletteMessage { .. }; 64],
    palette_len:              i32                       = 0,
    drainable_head:           i32                       = -1,
    active_buckets:           i32                       = 0,
    active_subscriptions:     i32                       = 0,
    total_publishes:          u64                       = 0,
    total_messages_delivered: u64                       = 0,
}

inline fn is_valid_wildcard_char(pattern: const u8[:], i: i64, b: u8) -> bool {
    guard b != 0 else { return false; }
    if b == '#' {
        guard i == pattern.len - 1 else { return false; }
        if i > 0 {
            guard pattern[i - 1] == '/' else { return false; }
        }
        return true;
    }
    if b == '+' {
        if i > 0 {
            guard pattern[i - 1] == '/' else { return false; }
        }
        if i + 1 < pattern.len {
            guard pattern[i + 1] == '/' else { return false; }
        }
    }
    return true;
}

// Validates an MQTT topic filter per OASIS MQTT v5.0 §4.7.1.2:
// - Multi-level wildcard '#' must be the last character and either standalone ("#") or preceded by '/' ("sport/#").
// - Single-level wildcard '+' must occupy an entire level (must be preceded by '/' or start-of-filter,
//   and followed by '/' or end-of-filter).
// - Topic filter must not be empty, exceed 64 bytes, or contain null characters.
fn is_valid_topic_filter(pattern: const u8[:]) -> bool {
    guard pattern.len > 0 && pattern.len <= 64 else { return false; }

    for i in pattern.len {
        guard is_valid_wildcard_char(pattern, i, pattern[i]) else { return false; }
    }

    return true;
}

// Finds the index of a bucket matching the given topic pattern, or -1 if not found.
fn find_topic_bucket(tree: const TopicTree&, pattern: const u8[:]) -> i32 {
    for i in tree.buckets.len {
        if tree.buckets[i].in_use && tree.buckets[i].topic_pattern[..] == pattern {
            return i as i32;
        }
    }
    return -1;
}

// Allocates or retrieves a topic bucket for the given pattern.
fn get_or_create_topic_bucket(tree: TopicTree&, pattern: const u8[:]) -> i32 {
    guard is_valid_topic_filter(pattern) else { return -1; }

    let existing = find_topic_bucket(tree, pattern);
    if existing >= 0 {
        return existing;
    }

    for i in tree.buckets.len {
        if !tree.buckets[i].in_use {
            tree.buckets[i].topic_pattern.clear();
            tree.buckets[i].topic_pattern.append(pattern);
            tree.buckets[i].head_sub = -1;
            tree.buckets[i].subscriber_count = 0;
            let has_plus = core::index_of_byte(pattern, '+') >= 0;
            let has_hash = core::index_of_byte(pattern, '#') >= 0;
            tree.buckets[i].has_wildcard = has_plus || has_hash;
            tree.buckets[i].in_use = true;
            tree.active_buckets += 1;
            return i as i32;
        }
    }

    return -1; // Topic buckets full
}

// Subscription lifecycle event descriptor (uWebSockets subscription hook pattern)
struct TopicSubscriptionEvent {
    topic:           u8[..64] = [],
    sock_fd:         i64      = -1,
    old_subscribers: i32      = 0,
    new_subscribers: i32      = 0,
    is_joined:       bool     = false,
}

const TOPIC_MAX_SUBSCRIBERS_PER_BUCKET: i32 = 512;

// Subscribes a socket descriptor to a topic pattern with old and new subscriber count feedback.
// Returns true on success, false if capacity is exceeded, invalid pattern, or already subscribed.
fn subscribe_ex(
    tree:    TopicTree&,
    sock_fd: i64,
    pattern: const u8[:],
    out_old: i32&,
    out_new: i32&,
) -> bool {
    out_old = 0;
    out_new = 0;
    guard sock_fd > 0 && is_valid_topic_filter(pattern) else { return false; }

    let b_idx = get_or_create_topic_bucket(tree, pattern);
    guard b_idx >= 0 else { return false; }

    // Check if already subscribed to this bucket
    if is_subscribed_in_bucket(tree, b_idx, sock_fd) {
        out_old = tree.buckets[b_idx as i64].subscriber_count;
        out_new = tree.buckets[b_idx as i64].subscriber_count;
        return true;
    }

    // Enforce bounded 512-subscriber limit per topic bucket (Invariant 13 fail-closed rejection)
    guard tree.buckets[b_idx as i64].subscriber_count < TOPIC_MAX_SUBSCRIBERS_PER_BUCKET else {
        out_old = tree.buckets[b_idx as i64].subscriber_count;
        out_new = tree.buckets[b_idx as i64].subscriber_count;
        return false;
    }

    // Allocate subscription node from bounded pool
    for i in tree.nodes.len {
        if !tree.nodes[i].in_use {
            tree.nodes[i].sock_fd = sock_fd;
            tree.nodes[i].next_sub = tree.buckets[b_idx as i64].head_sub;
            tree.nodes[i].in_use = true;

            let old_cnt = tree.buckets[b_idx as i64].subscriber_count;
            let new_cnt = old_cnt + 1;
            tree.buckets[b_idx as i64].head_sub = i as i32;
            tree.buckets[b_idx as i64].subscriber_count = new_cnt;
            tree.active_subscriptions += 1;

            out_old = old_cnt;
            out_new = new_cnt;
            return true;
        }
    }

    reclaim_empty_bucket(tree, b_idx);
    return false; // Subscription pool full
}

fn is_subscribed_in_bucket(tree: const TopicTree&, b: i64, sock_fd: i64) -> bool {
    var cur = tree.buckets[b].head_sub;
    while cur >= 0 {
        let cur_i64 = cur as i64;
        if tree.nodes[cur_i64].in_use && tree.nodes[cur_i64].sock_fd == sock_fd {
            return true;
        }
        cur = tree.nodes[cur_i64].next_sub;
    }
    return false;
}

// Subscribes a socket descriptor to a topic pattern.
// Returns true on success, false if capacity is exceeded, invalid pattern, or already subscribed.
fn subscribe(tree: TopicTree&, sock_fd: i64, pattern: const u8[:]) -> bool {
    var old_cnt: i32 = 0;
    var new_cnt: i32 = 0;
    return subscribe_ex(tree, sock_fd, pattern, old_cnt, new_cnt);
}

// Subscribes a socket descriptor with subscription lifecycle callback notification (uWebSockets subscription hook)
fn subscribe_with_hook<HookFn: fn(const u8[:], i32, i32, i64)>(
    tree:    TopicTree&,
    sock_fd: i64,
    pattern: const u8[:],
) -> bool {
    var old_cnt: i32 = 0;
    var new_cnt: i32 = 0;
    let ok = subscribe_ex(tree, sock_fd, pattern, old_cnt, new_cnt);
    if ok && old_cnt != new_cnt {
        HookFn(pattern, old_cnt, new_cnt, sock_fd);
    }
    return ok;
}

// Unlinks a subscriber node from the double-linked list of drainable subscribers
fn unlink_drainable_node(tree: TopicTree&, node_idx: i32) {
    guard node_idx >= 0 && node_idx < tree.nodes.len as i32 else { return; }
    let n_i64 = node_idx as i64;
    let prev = tree.nodes[n_i64].prev_drainable;
    let next = tree.nodes[n_i64].next_drainable;

    if prev >= 0 {
        tree.nodes[prev as i64].next_drainable = next;
    }
    if next >= 0 {
        tree.nodes[next as i64].prev_drainable = prev;
    }
    if tree.drainable_head == node_idx {
        tree.drainable_head = next;
    }
    tree.nodes[n_i64].prev_drainable = -1;
    tree.nodes[n_i64].next_drainable = -1;
}

fn release_subscription_node(tree: TopicTree&, b: i64, prev: i32, cur: i32) -> i32, i32 {
    let cur_i64 = cur as i64;
    let next = tree.nodes[cur_i64].next_sub;
    if prev < 0 {
        tree.buckets[b].head_sub = next;
    } else {
        tree.nodes[prev as i64].next_sub = next;
    }

    if tree.nodes[cur_i64].num_message_indices > 0 {
        unlink_drainable_node(tree, cur);
        tree.nodes[cur_i64].num_message_indices = 0;
    }

    tree.nodes[cur_i64].in_use = false;
    tree.nodes[cur_i64].sock_fd = -1;
    tree.nodes[cur_i64].next_sub = -1;

    let old_cnt = tree.buckets[b].subscriber_count;
    tree.buckets[b].subscriber_count = old_cnt - 1;
    tree.active_subscriptions -= 1;
    return next, old_cnt;
}

fn reclaim_empty_bucket(tree: TopicTree&, b: i64) {
    if tree.buckets[b].subscriber_count <= 0 {
        tree.buckets[b].in_use = false;
        tree.buckets[b].head_sub = -1;
        tree.active_buckets -= 1;
    }
}

// Unsubscribes a socket descriptor from a topic pattern with old and new subscriber count feedback.
// Returns true if unsubscription succeeded, false if not subscribed.
fn unsubscribe_ex(
    tree:    TopicTree&,
    sock_fd: i64,
    pattern: const u8[:],
    out_old: i32&,
    out_new: i32&,
) -> bool {
    out_old = 0;
    out_new = 0;
    guard sock_fd > 0 && pattern.len > 0 else { return false; }

    let b_idx = find_topic_bucket(tree, pattern);
    guard b_idx >= 0 else { return false; }
    let b = b_idx as i64;

    var prev: i32 = -1;
    var cur = tree.buckets[b].head_sub;

    while cur >= 0 {
        let cur_i64 = cur as i64;
        if tree.nodes[cur_i64].in_use && tree.nodes[cur_i64].sock_fd == sock_fd {
            let _, old_cnt = release_subscription_node(tree, b, prev, cur);
            out_old = old_cnt;
            out_new = old_cnt - 1;
            reclaim_empty_bucket(tree, b);
            return true;
        }
        prev = cur;
        cur = tree.nodes[cur_i64].next_sub;
    }

    return false;
}

// Unsubscribes a socket descriptor from a topic pattern.
// Returns true if unsubscription succeeded, false if not subscribed.
fn unsubscribe(tree: TopicTree&, sock_fd: i64, pattern: const u8[:]) -> bool {
    var old_cnt: i32 = 0;
    var new_cnt: i32 = 0;
    return unsubscribe_ex(tree, sock_fd, pattern, old_cnt, new_cnt);
}

// Unsubscribes a socket descriptor with subscription lifecycle callback notification (uWebSockets subscription hook)
fn unsubscribe_with_hook<HookFn: fn(const u8[:], i32, i32, i64)>(
    tree:    TopicTree&,
    sock_fd: i64,
    pattern: const u8[:],
) -> bool {
    var old_cnt: i32 = 0;
    var new_cnt: i32 = 0;
    let ok = unsubscribe_ex(tree, sock_fd, pattern, old_cnt, new_cnt);
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
                let next, _ = release_subscription_node(tree, b, prev, cur);
                unsubs += 1;
                cur = next;
            } else {
                prev = cur;
                cur = tree.nodes[cur_i64].next_sub;
            }
        }

        reclaim_empty_bucket(tree, b);
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
                let next, old_cnt = release_subscription_node(tree, b, prev, cur);
                unsubs += 1;
                let new_cnt = old_cnt - 1;
                HookFn(tree.buckets[b].topic_pattern[..], old_cnt, new_cnt, sock_fd);
                cur = next;
            } else {
                prev = cur;
                cur = tree.nodes[cur_i64].next_sub;
            }
        }

        reclaim_empty_bucket(tree, b);
    }

    return unsubs;
}

// Checks if a socket is subscribed to a topic pattern.
fn is_subscribed(tree: const TopicTree&, sock_fd: i64, pattern: const u8[:]) -> bool {
    let b_idx = find_topic_bucket(tree, pattern);
    guard b_idx >= 0 else { return false; }
    return is_subscribed_in_bucket(tree, b_idx, sock_fd);
}

// Returns the total number of subscribers for a given topic pattern.
fn subscriber_count(tree: const TopicTree&, pattern: const u8[:]) -> i32 {
    let b_idx = find_topic_bucket(tree, pattern);
    guard b_idx >= 0 else { return 0; }
    return tree.buckets[b_idx as i64].subscriber_count;
}

// Returns the number of distinct topic patterns a socket is currently subscribed to
fn socket_subscription_count(tree: const TopicTree&, sock_fd: i64) -> i32 {
    guard sock_fd > 0 else { return 0; }
    var count: i32 = 0;
    for b in tree.buckets.len {
        if tree.buckets[b].in_use && is_subscribed_in_bucket(tree, b, sock_fd) {
            count += 1;
        }
    }
    return count;
}

// Retrieves all topic patterns a socket is subscribed to (uWebSockets ws->iterateTopics pattern)
fn get_socket_topics(
    tree:       const TopicTree&,
    sock_fd:    i64,
    out_topics: u8[..64][..32]&,
) -> i32 {
    out_topics.clear();
    guard sock_fd > 0 else { return 0; }
    for b in tree.buckets.len {
        if tree.buckets[b].in_use && is_subscribed_in_bucket(tree, b, sock_fd) {
            guard out_topics.len < out_topics.cap else { break; }
            var pat: u8[..64] = [];
            pat.append(tree.buckets[b].topic_pattern[..]);
            out_topics.push(pat);
        }
    }
    return out_topics.len as i32;
}

// Iterates through all topic patterns a socket is subscribed to via callback (uWebSockets ws->iterateTopics pattern)
fn iterate_socket_topics<IterFn: fn(const u8[:])>(
    tree:    const TopicTree&,
    sock_fd: i64,
) -> i32 {
    guard sock_fd > 0 else { return 0; }
    var count: i32 = 0;
    for b in tree.buckets.len {
        if tree.buckets[b].in_use && is_subscribed_in_bucket(tree, b, sock_fd) {
            IterFn(tree.buckets[b].topic_pattern[..]);
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
    var old_cnt: i32 = 0;
    var new_cnt: i32 = 0;
    let ok = subscribe_ex(tree, sub_id, topic, old_cnt, new_cnt);
    return new_cnt, ok;
}

inline fn hash_fd_bucket(fd: i64) -> u64 {
    let u = fd as u64;
    return (u ^ (u >> 8)) & 255;
}

// Appends a socket descriptor to `out_fds` if not previously recorded in bitmask or array.
// Returns `(count: i32, ok: bool)` with `ok = false` when `out_fds` reaches its 512-subscriber capacity.
fn add_distinct_subscriber(out_fds: i64[..512]&, seen_mask: u64[4]&, fd: i64) -> i32, bool {
    let h = hash_fd_bucket(fd);
    let word_idx = (h >> 6) as i64;
    let bit = (1 as u64) << (h & 63);

    if (seen_mask[word_idx] & bit) == 0 {
        guard out_fds.len < out_fds.cap else { return out_fds.len as i32, false; }
        seen_mask[word_idx] |= bit;
        out_fds.push(fd);
        return out_fds.len as i32, true;
    }

    for d_fd in out_fds {
        if d_fd == fd { return out_fds.len as i32, true; }
    }
    guard out_fds.len < out_fds.cap else { return out_fds.len as i32, false; }
    out_fds.push(fd);
    return out_fds.len as i32, true;
}

// Finds all distinct sockets subscribed to patterns matching the target topic,
// returning `(count: i64, ok: bool)` where `ok == false` if the 512-subscriber buffer overflows.
fn find_subscribers_checked(tree: const TopicTree&, topic: const u8[:], out_fds: i64[..512]&) -> i64, bool {
    guard is_valid_publish_topic(topic) else { return 0, false; }
    out_fds.clear();
    var seen_mask: u64[4] = [0, 0, 0, 0];

    for b in tree.buckets.len {
        guard tree.buckets[b].in_use && tree.buckets[b].subscriber_count > 0 else { continue; }
        guard match_topic(tree.buckets[b].topic_pattern[..], topic) else { continue; }

        var cur = tree.buckets[b].head_sub;
        while cur >= 0 {
            let cur_i64 = cur as i64;
            if tree.nodes[cur_i64].in_use {
                let _, add_ok = add_distinct_subscriber(out_fds, seen_mask, tree.nodes[cur_i64].sock_fd);
                guard add_ok else { return out_fds.len, false; }
            }
            cur = tree.nodes[cur_i64].next_sub;
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

inline fn record_publish_stats(tree: TopicTree&, delivered: i64) {
    tree.total_publishes += 1;
    tree.total_messages_delivered += (delivered as u64);
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
        let sent = tcp_send(fd, frame_wire);
        if sent > 0 {
            delivered += 1;
        }
    }

    record_publish_stats(tree, delivered);
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
        let sent = tcp_send(fd, msg.wire[..]);
        if sent > 0 {
            delivered += 1;
        }
    }

    record_publish_stats(tree, delivered);
    return delivered;
}

// Publishes a PreparedMessage with selective compression support (uWebSockets sendPrepared pattern).
// Dispatches `msg.compressed_wire` if `msg.has_compressed` is true and `supports_compression(fd)` returns true;
// otherwise dispatches `msg.wire`.
fn publish_prepared_selective<LookupFn: fn(i64) -> bool>(
    tree:                 TopicTree&,
    topic:                const u8[:],
    msg:                  const PreparedMessage&,
    supports_compression: LookupFn,
) -> i64 {
    guard is_valid_publish_topic(topic) && msg.wire.len > 0 else { return 0; }

    var matched_fds: i64[..512] = [];
    find_subscribers(tree, topic, matched_fds);

    var delivered: i64 = 0;
    for fd in matched_fds {
        let wire_to_send = if msg.has_compressed && supports_compression(fd) {
            msg.compressed_wire[..]
        } else {
            msg.wire[..]
        };

        let sent = tcp_send(fd, wire_to_send);
        if sent > 0 {
            delivered += 1;
        }
    }

    record_publish_stats(tree, delivered);
    return delivered;
}

// ---- uWebSockets TopicTree Batch Drainage & Message Palette Engine ---------

fn flush_node_palette_messages(tree: const TopicTree&, n_i64: i64, fd: i64, count: i64) -> i64 {
    var sent_total: i64 = 0;
    for i in count {
        let msg_idx = tree.nodes[n_i64].message_indices[i] as i64;
        if msg_idx >= 0 && msg_idx < tree.palette_len {
            let sent = tcp_send(fd, tree.palette[msg_idx].wire[..]);
            if sent > 0 {
                sent_total += 1;
            }
        }
    }
    return sent_total;
}

// Drains all batched messages for a specific subscriber node.
// Unlinks from drainable list and sends wire frames directly to the socket descriptor.
fn drain_subscriber(tree: TopicTree&, node_idx: i32) -> i64 {
    guard node_idx >= 0 && node_idx < tree.nodes.len as i32 else { return 0; }
    let n_i64 = node_idx as i64;
    guard tree.nodes[n_i64].in_use && tree.nodes[n_i64].num_message_indices > 0 else { return 0; }

    unlink_drainable_node(tree, node_idx);
    let count = tree.nodes[n_i64].num_message_indices as i64;
    let fd = tree.nodes[n_i64].sock_fd;
    tree.nodes[n_i64].num_message_indices = 0;

    let sent = flush_node_palette_messages(tree, n_i64, fd, count);
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

        let batch_sent = flush_node_palette_messages(tree, c_i64, fd, count);
        total_delivered += batch_sent;
        cur = next;
    }

    tree.drainable_head = -1;
    tree.palette_len = 0;
    tree.total_messages_delivered += (total_delivered as u64);
    return total_delivered;
}

fn check_and_mark_batch_seen(
    fd:        i64,
    seen_fds:  i64[..512]&,
    seen_mask: u64[4]&,
) -> bool, bool {
    let h = hash_fd_bucket(fd);
    let word_idx = (h >> 6) as i64;
    let bit = (1 as u64) << (h & 63);

    if (seen_mask[word_idx] & bit) == 0 {
        guard seen_fds.len < seen_fds.cap else { return false, false; }
        seen_mask[word_idx] |= bit;
        seen_fds.push(fd);
        return false, true;
    }

    for s_fd in seen_fds {
        if s_fd == fd {
            return true, true;
        }
    }
    guard seen_fds.len < seen_fds.cap else { return false, false; }
    seen_fds.push(fd);
    return false, true;
}

fn link_drainable_head(tree: TopicTree&, cur: i32, c_i64: i64) {
    tree.nodes[c_i64].next_drainable = tree.drainable_head;
    tree.nodes[c_i64].prev_drainable = -1;
    if tree.drainable_head >= 0 {
        tree.nodes[tree.drainable_head as i64].prev_drainable = cur;
    }
    tree.drainable_head = cur;
}

// Enqueues a message index to a single subscriber node if matching and not already queued in this batch.
fn queue_subscriber_batch(
    tree:      TopicTree&,
    cur:       i32,
    msg_idx:   i64,
    sender_fd: i64,
    seen_fds:  i64[..512]&,
    seen_mask: u64[4]&,
) -> bool {
    let c_i64 = cur as i64;
    guard tree.nodes[c_i64].in_use && tree.nodes[c_i64].sock_fd != sender_fd else { return false; }
    let fd = tree.nodes[c_i64].sock_fd;

    var already_queued, ok_seen = check_and_mark_batch_seen(fd, seen_fds, seen_mask);
    guard ok_seen else { return false; }

    let num = tree.nodes[c_i64].num_message_indices as i64;
    if num > 0 {
        if tree.nodes[c_i64].message_indices[num - 1] == (msg_idx as u16) {
            already_queued = true;
        }
    }

    guard !already_queued else { return false; }

    if tree.nodes[c_i64].num_message_indices >= 32 {
        drain_subscriber(tree, cur);
    }

    let cur_num = tree.nodes[c_i64].num_message_indices as i64;
    tree.nodes[c_i64].message_indices[cur_num] = msg_idx as u16;
    tree.nodes[c_i64].num_message_indices += 1;

    if tree.nodes[c_i64].num_message_indices == 1 {
        link_drainable_head(tree, cur, c_i64);
    }
    return true;
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
    for b in tree.buckets.len {
        guard tree.buckets[b].in_use && tree.buckets[b].subscriber_count > 0 else { continue; }
        guard match_topic(tree.buckets[b].topic_pattern[..], topic) else { continue; }

        var cur = tree.buckets[b].head_sub;
        while cur >= 0 {
            if queue_subscriber_batch(tree, cur, msg_idx, sender_fd, seen_fds, seen_mask) {
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
    for i in tree.nodes.len {
        if tree.nodes[i].in_use && tree.nodes[i].sock_fd == sock_fd && tree.nodes[i].num_message_indices > 0 {
            return true;
        }
    }
    return false;
}

// Returns the number of messages queued for a given socket descriptor.
fn subscriber_queued_messages(tree: const TopicTree&, sock_fd: i64) -> i32 {
    guard sock_fd > 0 else { return 0; }
    var total: i32 = 0;
    for i in tree.nodes.len {
        if tree.nodes[i].in_use && tree.nodes[i].sock_fd == sock_fd {
            total += tree.nodes[i].num_message_indices;
        }
    }
    return total;
}
