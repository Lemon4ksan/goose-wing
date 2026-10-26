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

const TOPIC_TREE_MAX_BUCKETS: i64 = 256;
const TOPIC_TREE_MAX_SUBSCRIPTIONS: i64 = 4096;

// Matches an MQTT topic pattern (with optional '+' and '#' wildcards) against a concrete topic name.
fn match_topic(pattern: const u8[:], topic: const u8[:]) -> bool {
    if pattern == topic { return true; }
    if pattern == "#" { return true; }

    var p_cur: i64 = 0;
    var t_cur: i64 = 0;

    while p_cur < pattern.len && t_cur < topic.len {
        var p_next = p_cur;
        while p_next < pattern.len && pattern[p_next] != '/' {
            p_next++;
        }
        let p_seg = pattern[p_cur..p_next];

        if p_seg == "#" {
            return true;
        }

        var t_next = t_cur;
        while t_next < topic.len && topic[t_next] != '/' {
            t_next++;
        }
        let t_seg = topic[t_cur..t_next];

        if p_seg != "+" && p_seg != t_seg {
            return false;
        }

        p_cur = if p_next < pattern.len { p_next + 1 } else { p_next };
        t_cur = if t_next < topic.len { t_next + 1 } else { t_next };
    }

    if p_cur < pattern.len && pattern[p_cur..] == "#" {
        return true;
    }

    // MQTT §4.7.1.3 & uWS #1933: A trailing '+' wildcard matches the empty level after a trailing slash (e.g. 'sport/+' matches 'sport/')
    if p_cur < pattern.len && pattern[p_cur..] == "+" && t_cur == topic.len && topic.len > 0 && topic[topic.len - 1] == '/' {
        return true;
    }

    return p_cur == pattern.len && t_cur == topic.len;
}

struct TopicBucket {
    topic_pattern: u8[..64] = [],
    head_sub: i32 = -1,
    subscriber_count: i32 = 0,
    has_wildcard: bool = false,
    in_use: bool = false,
}

// Fixed-capacity palette message for single-serialization broadcast (uWebSockets TopicTree pattern)
struct TopicPaletteMessage {
    wire: u8[..4096] = [],
    in_use: bool = false,
}

struct SubscriptionNode {
    sock_fd: i64 = -1,
    next_sub: i32 = -1,
    in_use: bool = false,
    // uWebSockets batch drainage & message palette
    message_indices: u16[32] = [0; 32],
    num_message_indices: u8 = 0,
    prev_drainable: i32 = -1,
    next_drainable: i32 = -1,
}

const TOPIC_PALETTE_CAP: i64 = 64;

struct TopicTree {
    buckets: TopicBucket[..256] = [TopicBucket { .. }; 256],
    nodes: SubscriptionNode[..4096] = [SubscriptionNode { .. }; 4096],
    palette: TopicPaletteMessage[..64] = [TopicPaletteMessage { .. }; 64],
    palette_len: i32 = 0,
    drainable_head: i32 = -1,
    active_buckets: i32 = 0,
    active_subscriptions: i32 = 0,
    total_publishes: u64 = 0,
    total_messages_delivered: u64 = 0,
}

fn new_topic_tree() -> TopicTree {
    return TopicTree { .. };
}

// Validates an MQTT topic filter per OASIS MQTT v5.0 §4.7.1.2:
// - Multi-level wildcard '#' must be the last character and either standalone ("#") or preceded by '/' ("sport/#").
// - Single-level wildcard '+' must occupy an entire level (must be preceded by '/' or start-of-filter, and followed by '/' or end-of-filter).
// - Topic filter must not be empty, exceed 64 bytes, or contain null characters.
fn is_valid_topic_filter(pattern: const u8[:]) -> bool {
    guard pattern.len > 0 && pattern.len <= 64 else { return false; }

    for i in pattern.len {
        let b = pattern[i];
        guard b != 0 else { return false; }

        if b == '#' {
            // Must be the last character
            guard i == pattern.len - 1 else { return false; }
            // If preceded by anything, previous byte must be '/'
            if i > 0 {
                guard pattern[i - 1] == '/' else { return false; }
            }
        } else if b == '+' {
            // If preceded by anything, previous byte must be '/'
            if i > 0 {
                guard pattern[i - 1] == '/' else { return false; }
            }
            // If followed by anything, next byte must be '/'
            if i + 1 < pattern.len {
                guard pattern[i + 1] == '/' else { return false; }
            }
        }
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
            tree.buckets[i].has_wildcard = core::index_of_byte(pattern, '+') >= 0 || core::index_of_byte(pattern, '#') >= 0;
            tree.buckets[i].in_use = true;
            tree.active_buckets += 1;
            return i as i32;
        }
    }

    return -1; // Topic buckets full
}

// Subscription lifecycle event descriptor (uWebSockets subscription hook pattern)
struct TopicSubscriptionEvent {
    topic: u8[..64] = [],
    sock_fd: i64 = -1,
    old_subscribers: i32 = 0,
    new_subscribers: i32 = 0,
    is_joined: bool = false,
}

// Subscribes a socket descriptor to a topic pattern with old and new subscriber count feedback.
// Returns true on success, false if capacity is exceeded, invalid pattern, or already subscribed.
fn subscribe_ex(
    tree: TopicTree&,
    sock_fd: i64,
    pattern: const u8[:],
    out_old: i32&,
    out_new: i32&
) -> bool {
    guard sock_fd > 0 && is_valid_topic_filter(pattern) else { return false; }

    let b_idx = get_or_create_topic_bucket(tree, pattern);
    guard b_idx >= 0 else { return false; }

    // Check if already subscribed to this bucket
    var cur = tree.buckets[b_idx as i64].head_sub;
    while cur >= 0 {
        let cur_i64 = cur as i64;
        if tree.nodes[cur_i64].in_use && tree.nodes[cur_i64].sock_fd == sock_fd {
            out_old = tree.buckets[b_idx as i64].subscriber_count;
            out_new = tree.buckets[b_idx as i64].subscriber_count;
            return true; // Already subscribed
        }
        cur = tree.nodes[cur_i64].next_sub;
    }

    // Allocate subscription node from bounded pool
    for i in tree.nodes.len {
        if !tree.nodes[i].in_use {
            tree.nodes[i].sock_fd = sock_fd;
            tree.nodes[i].next_sub = tree.buckets[b_idx as i64].head_sub;
            tree.nodes[i].in_use = true;

            let old_cnt = tree.buckets[b_idx as i64].subscriber_count;
            tree.buckets[b_idx as i64].head_sub = i as i32;
            tree.buckets[b_idx as i64].subscriber_count += 1;
            tree.active_subscriptions += 1;

            out_old = old_cnt;
            out_new = old_cnt + 1;
            return true;
        }
    }

    return false; // Subscription pool full
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
    tree: TopicTree&,
    sock_fd: i64,
    pattern: const u8[:]
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

// Unsubscribes a socket descriptor from a topic pattern with old and new subscriber count feedback.
// Returns true if unsubscription succeeded, false if not subscribed.
fn unsubscribe_ex(
    tree: TopicTree&,
    sock_fd: i64,
    pattern: const u8[:],
    out_old: i32&,
    out_new: i32&
) -> bool {
    guard sock_fd > 0 && pattern.len > 0 else { return false; }

    let b_idx = find_topic_bucket(tree, pattern);
    guard b_idx >= 0 else { return false; }

    var prev: i32 = -1;
    var cur = tree.buckets[b_idx as i64].head_sub;

    while cur >= 0 {
        let cur_i64 = cur as i64;
        if tree.nodes[cur_i64].in_use && tree.nodes[cur_i64].sock_fd == sock_fd {
            if prev < 0 {
                tree.buckets[b_idx as i64].head_sub = tree.nodes[cur_i64].next_sub;
            } else {
                tree.nodes[prev as i64].next_sub = tree.nodes[cur_i64].next_sub;
            }

            if tree.nodes[cur_i64].num_message_indices > 0 {
                unlink_drainable_node(tree, cur);
                tree.nodes[cur_i64].num_message_indices = 0;
            }

            tree.nodes[cur_i64].in_use = false;
            tree.nodes[cur_i64].sock_fd = -1;
            tree.nodes[cur_i64].next_sub = -1;

            let old_cnt = tree.buckets[b_idx as i64].subscriber_count;
            tree.buckets[b_idx as i64].subscriber_count -= 1;
            tree.active_subscriptions -= 1;

            out_old = old_cnt;
            out_new = old_cnt - 1;

            if tree.buckets[b_idx as i64].subscriber_count <= 0 {
                tree.buckets[b_idx as i64].in_use = false;
                tree.buckets[b_idx as i64].head_sub = -1;
                tree.active_buckets -= 1;
            }
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
    tree: TopicTree&,
    sock_fd: i64,
    pattern: const u8[:]
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
                tree.buckets[b].subscriber_count -= 1;
                tree.active_subscriptions -= 1;
                unsubs += 1;

                cur = next;
            } else {
                prev = cur;
                cur = tree.nodes[cur_i64].next_sub;
            }
        }

        if tree.buckets[b].subscriber_count <= 0 {
            tree.buckets[b].in_use = false;
            tree.buckets[b].head_sub = -1;
            tree.active_buckets -= 1;
        }
    }

    return unsubs;
}

// Unsubscribes a socket descriptor from all subscribed topics with callback notification per topic.
fn unsubscribe_all_with_hook<HookFn: fn(const u8[:], i32, i32, i64)>(
    tree: TopicTree&,
    sock_fd: i64
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
                tree.buckets[b].subscriber_count -= 1;
                tree.active_subscriptions -= 1;
                unsubs += 1;

                HookFn(tree.buckets[b].topic_pattern[..], old_cnt, old_cnt - 1, sock_fd);

                cur = next;
            } else {
                prev = cur;
                cur = tree.nodes[cur_i64].next_sub;
            }
        }

        if tree.buckets[b].subscriber_count <= 0 {
            tree.buckets[b].in_use = false;
            tree.buckets[b].head_sub = -1;
            tree.active_buckets -= 1;
        }
    }

    return unsubs;
}

// Checks if a socket is subscribed to a topic pattern.
fn is_subscribed(tree: const TopicTree&, sock_fd: i64, pattern: const u8[:]) -> bool {
    let b_idx = find_topic_bucket(tree, pattern);
    guard b_idx >= 0 else { return false; }

    var cur = tree.buckets[b_idx as i64].head_sub;
    while cur >= 0 {
        let cur_i64 = cur as i64;
        if tree.nodes[cur_i64].in_use && tree.nodes[cur_i64].sock_fd == sock_fd {
            return true;
        }
        cur = tree.nodes[cur_i64].next_sub;
    }
    return false;
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
        guard tree.buckets[b].in_use else { continue; }
        var cur = tree.buckets[b].head_sub;
        while cur >= 0 {
            let cur_i64 = cur as i64;
            if tree.nodes[cur_i64].in_use && tree.nodes[cur_i64].sock_fd == sock_fd {
                count += 1;
                break;
            }
            cur = tree.nodes[cur_i64].next_sub;
        }
    }
    return count;
}

// Retrieves all topic patterns a socket is subscribed to (uWebSockets ws->iterateTopics pattern)
fn get_socket_topics(
    tree: const TopicTree&,
    sock_fd: i64,
    out_topics: u8[..64][..32]&
) -> i32 {
    guard sock_fd > 0 else { return 0; }
    out_topics.clear();
    for b in tree.buckets.len {
        guard tree.buckets[b].in_use else { continue; }
        var cur = tree.buckets[b].head_sub;
        while cur >= 0 {
            let cur_i64 = cur as i64;
            if tree.nodes[cur_i64].in_use && tree.nodes[cur_i64].sock_fd == sock_fd {
                if out_topics.len < out_topics.cap {
                    var pat: u8[..64] = [];
                    pat.append(tree.buckets[b].topic_pattern[..]);
                    out_topics.push(pat);
                }
                break;
            }
            cur = tree.nodes[cur_i64].next_sub;
        }
    }
    return out_topics.len as i32;
}

// Iterates through all topic patterns a socket is subscribed to via callback (uWebSockets ws->iterateTopics pattern)
fn iterate_socket_topics<IterFn: fn(const u8[:])>(
    tree: const TopicTree&,
    sock_fd: i64
) -> i32 {
    guard sock_fd > 0 else { return 0; }
    var count: i32 = 0;
    for b in tree.buckets.len {
        guard tree.buckets[b].in_use else { continue; }
        var cur = tree.buckets[b].head_sub;
        while cur >= 0 {
            let cur_i64 = cur as i64;
            if tree.nodes[cur_i64].in_use && tree.nodes[cur_i64].sock_fd == sock_fd {
                IterFn(tree.buckets[b].topic_pattern[..]);
                count += 1;
                break;
            }
            cur = tree.nodes[cur_i64].next_sub;
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

// Finds all distinct sockets subscribed to patterns matching the target topic.
// Returns the number of distinct sockets stored into out_fds.
fn find_subscribers(tree: const TopicTree&, topic: const u8[:], out_fds: i64[..512]&) -> i64 {
    guard is_valid_publish_topic(topic) else { return 0; }
    out_fds.clear();
    var seen_mask: u64[4] = [0, 0, 0, 0];

    for b in tree.buckets.len {
        guard tree.buckets[b].in_use && tree.buckets[b].subscriber_count > 0 else { continue; }

        if match_topic(tree.buckets[b].topic_pattern[..], topic) {
            var cur = tree.buckets[b].head_sub;
            while cur >= 0 {
                let cur_i64 = cur as i64;
                if tree.nodes[cur_i64].in_use {
                    let fd = tree.nodes[cur_i64].sock_fd;

                    let h = ((fd as u64) ^ ((fd as u64) >> 8)) & 255;
                    let word_idx = (h >> 6) as i64;
                    let bit = (1 as u64) << (h & 63);

                    if (seen_mask[word_idx] & bit) == 0 {
                        seen_mask[word_idx] = seen_mask[word_idx] | bit;
                        if out_fds.len < out_fds.cap {
                            out_fds.push(fd);
                        }
                    } else {
                        var already_added = false;
                        for d_fd in out_fds {
                            if d_fd == fd {
                                already_added = true;
                                break;
                            }
                        }
                        if !already_added && out_fds.len < out_fds.cap {
                            out_fds.push(fd);
                        }
                    }
                }
                cur = tree.nodes[cur_i64].next_sub;
            }
        }
    }
    return out_fds.len;
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

    tree.total_publishes += 1;
    tree.total_messages_delivered += delivered as u64;
    return delivered;
}

// Encodes the message once into a server frame (unmasked per RFC 6455) and broadcasts to all topic subscribers.
fn publish(
    tree: TopicTree&,
    topic: const u8[:],
    message: const u8[:],
    opcode: u8 = WS_OPCODE_TEXT
) -> i64 {
    var frame: u8[..65536] = [];
    let no_mask: u8[4] = [0, 0, 0, 0];
    encode_ws_frame(frame, opcode, message, false, no_mask, true);
    return publish_frame(tree, topic, frame[..]);
}

// Convenience helper to publish UTF-8 text message to a topic.
fn publish_text(tree: TopicTree&, topic: const u8[:], text: const u8[:]) -> i64 {
    return publish(tree, topic, text, WS_OPCODE_TEXT);
}

// Convenience helper to publish binary message to a topic.
fn publish_binary(tree: TopicTree&, topic: const u8[:], data: const u8[:]) -> i64 {
    return publish(tree, topic, data, WS_OPCODE_BINARY);
}

// ---- uWebSockets TopicTree Batch Drainage & Message Palette Engine ---------

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

    var sent_total: i64 = 0;
    for i in count {
        let msg_idx = tree.nodes[n_i64].message_indices[i] as i64;
        if msg_idx >= 0 && msg_idx < tree.palette.len {
            let sent = tcp_send(fd, tree.palette[msg_idx].wire[..]);
            if sent > 0 {
                sent_total += 1;
            }
        }
    }

    if tree.drainable_head < 0 {
        tree.palette_len = 0;
    }
    return sent_total;
}

// Drains all drainable subscribers in batch.
// Iterates through the drainable linked list once, eliminating redundant topic tree traversal.
// Resets the outgoing message palette to 0 allocations.
fn drain(tree: TopicTree&) -> i64 {
    var cur = tree.drainable_head;
    guard cur >= 0 else { return 0; }

    var total_delivered: i64 = 0;
    while cur >= 0 {
        let c_i64 = cur as i64;
        let next = tree.nodes[c_i64].next_drainable;
        let fd = tree.nodes[c_i64].sock_fd;
        let count = tree.nodes[c_i64].num_message_indices as i64;

        tree.nodes[c_i64].num_message_indices = 0;
        tree.nodes[c_i64].prev_drainable = -1;
        tree.nodes[c_i64].next_drainable = -1;

        for i in count {
            let msg_idx = tree.nodes[c_i64].message_indices[i] as i64;
            if msg_idx >= 0 && msg_idx < tree.palette.len {
                let sent = tcp_send(fd, tree.palette[msg_idx].wire[..]);
                if sent > 0 {
                    total_delivered += 1;
                }
            }
        }
        cur = next;
    }

    tree.drainable_head = -1;
    tree.palette_len = 0;
    tree.total_messages_delivered += total_delivered as u64;
    return total_delivered;
}

// Publishes a message into the outgoing message palette and batches delivery to all subscribers
// without re-serializing the frame per subscriber. Any subscriber reaching 32 queued messages
// is drained immediately. Returns the number of distinct sockets queued to.
fn publish_batch(
    tree: TopicTree&,
    topic: const u8[:],
    payload: const u8[:],
    opcode: u8 = WS_OPCODE_TEXT,
    sender_fd: i64 = -1
) -> i64 {
    guard is_valid_publish_topic(topic) else { return 0; }

    // If palette reached capacity (64 messages), drain all pending subscribers first
    if tree.palette_len >= tree.palette.cap as i32 {
        drain(tree);
    }

    let msg_idx = tree.palette_len as i64;
    tree.palette[msg_idx].wire.clear();
    let no_mask: u8[4] = [0, 0, 0, 0];
    encode_ws_frame(tree.palette[msg_idx].wire, opcode, payload, false, no_mask, true);
    tree.palette_len += 1;

    var queued: i64 = 0;
    for b in tree.buckets.len {
        guard tree.buckets[b].in_use && tree.buckets[b].subscriber_count > 0 else { continue; }
        if match_topic(tree.buckets[b].topic_pattern[..], topic) {
            var cur = tree.buckets[b].head_sub;
            while cur >= 0 {
                let c_i64 = cur as i64;
                if tree.nodes[c_i64].in_use && tree.nodes[c_i64].sock_fd != sender_fd {
                    var already_queued = false;
                    let num = tree.nodes[c_i64].num_message_indices as i64;
                    if num > 0 && tree.nodes[c_i64].message_indices[num - 1] == (msg_idx as u16) {
                        already_queued = true;
                    }

                    if !already_queued {
                        if tree.nodes[c_i64].num_message_indices >= 32 {
                            drain_subscriber(tree, cur);
                        }

                        let cur_num = tree.nodes[c_i64].num_message_indices as i64;
                        tree.nodes[c_i64].message_indices[cur_num] = msg_idx as u16;
                        tree.nodes[c_i64].num_message_indices += 1;

                        if tree.nodes[c_i64].num_message_indices == 1 {
                            tree.nodes[c_i64].next_drainable = tree.drainable_head;
                            tree.nodes[c_i64].prev_drainable = -1;
                            if tree.drainable_head >= 0 {
                                tree.nodes[tree.drainable_head as i64].prev_drainable = cur;
                            }
                            tree.drainable_head = cur;
                        }
                        queued += 1;
                    }
                }
                cur = tree.nodes[c_i64].next_sub;
            }
        }
    }

    tree.total_publishes += 1;
    return queued;
}

// Returns the number of currently active messages in the outgoing palette.
fn palette_size(tree: const TopicTree&) -> i32 {
    return tree.palette_len;
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
        if tree.nodes[i].in_use && tree.nodes[i].sock_fd == sock_fd {
            return tree.nodes[i].num_message_indices > 0;
        }
    }
    return false;
}

// Returns the number of messages queued for a given socket descriptor.
fn subscriber_queued_messages(tree: const TopicTree&, sock_fd: i64) -> i32 {
    guard sock_fd > 0 else { return 0; }
    for i in tree.nodes.len {
        if tree.nodes[i].in_use && tree.nodes[i].sock_fd == sock_fd {
            return tree.nodes[i].num_message_indices;
        }
    }
    return 0;
}
