// High-Performance Native Pub/Sub TopicTree Engine for goose-wing (uWebSockets TopicTree pattern).
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

    return p_cur == pattern.len && t_cur == topic.len;
}

struct TopicBucket {
    topic_pattern: u8[..64] = [],
    head_sub: i32 = -1,
    subscriber_count: i32 = 0,
    has_wildcard: bool = false,
    in_use: bool = false,
}

struct SubscriptionNode {
    sock_fd: i64 = -1,
    next_sub: i32 = -1,
    in_use: bool = false,
}

struct TopicTree {
    buckets: TopicBucket[..256] = [TopicBucket { .. }; 256],
    nodes: SubscriptionNode[..4096] = [SubscriptionNode { .. }; 4096],
    active_buckets: i32 = 0,
    active_subscriptions: i32 = 0,
    total_publishes: u64 = 0,
    total_messages_delivered: u64 = 0,
}

fn new_topic_tree() -> TopicTree {
    return TopicTree { .. };
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
    let existing = find_topic_bucket(tree, pattern);
    if existing >= 0 {
        return existing;
    }

    guard pattern.len > 0 && pattern.len <= 64 else { return -1; }

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

// Subscribes a socket descriptor to a topic pattern.
// Returns true on success, false if capacity is exceeded or already subscribed.
fn topic_subscribe(tree: TopicTree&, sock_fd: i64, pattern: const u8[:]) -> bool {
    guard sock_fd > 0 && pattern.len > 0 else { return false; }

    let b_idx = get_or_create_topic_bucket(tree, pattern);
    guard b_idx >= 0 else { return false; }

    // Check if already subscribed to this bucket
    var cur = tree.buckets[b_idx as i64].head_sub;
    while cur >= 0 {
        let cur_i64 = cur as i64;
        if tree.nodes[cur_i64].in_use && tree.nodes[cur_i64].sock_fd == sock_fd {
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

            tree.buckets[b_idx as i64].head_sub = i as i32;
            tree.buckets[b_idx as i64].subscriber_count += 1;
            tree.active_subscriptions += 1;
            return true;
        }
    }

    return false; // Subscription pool full
}

// Unsubscribes a socket descriptor from a topic pattern.
// Returns true if unsubscription succeeded, false if not subscribed.
fn topic_unsubscribe(tree: TopicTree&, sock_fd: i64, pattern: const u8[:]) -> bool {
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

            tree.nodes[cur_i64].in_use = false;
            tree.nodes[cur_i64].sock_fd = -1;
            tree.nodes[cur_i64].next_sub = -1;
            tree.buckets[b_idx as i64].subscriber_count -= 1;
            tree.active_subscriptions -= 1;

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

// Unsubscribes a socket descriptor from all subscribed topics.
// Invoked automatically when a connection terminates to reclaim pool slots.
// Returns total number of unsubscriptions performed.
fn topic_unsubscribe_all(tree: TopicTree&, sock_fd: i64) -> i32 {
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

// Checks if a socket is subscribed to a topic pattern.
fn is_topic_subscribed(tree: const TopicTree&, sock_fd: i64, pattern: const u8[:]) -> bool {
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
fn topic_subscriber_count(tree: const TopicTree&, pattern: const u8[:]) -> i32 {
    let b_idx = find_topic_bucket(tree, pattern);
    guard b_idx >= 0 else { return 0; }
    return tree.buckets[b_idx as i64].subscriber_count;
}

// Finds all distinct sockets subscribed to patterns matching the target topic.
// Returns the number of distinct sockets stored into out_fds.
fn topic_find_subscribers(tree: const TopicTree&, topic: const u8[:], out_fds: i64[..512]&) -> i64 {
    guard topic.len > 0 else { return 0; }
    out_fds.clear();

    for b in tree.buckets.len {
        guard tree.buckets[b].in_use && tree.buckets[b].subscriber_count > 0 else { continue; }

        if match_topic(tree.buckets[b].topic_pattern[..], topic) {
            var cur = tree.buckets[b].head_sub;
            while cur >= 0 {
                let cur_i64 = cur as i64;
                if tree.nodes[cur_i64].in_use {
                    let fd = tree.nodes[cur_i64].sock_fd;

                    var already_added = false;
                    for d_fd in out_fds {
                        if d_fd == fd {
                            already_added = true;
                            break;
                        }
                    }

                    if !already_added {
                        if out_fds.len < out_fds.cap {
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
fn topic_publish_frame(tree: TopicTree&, topic: const u8[:], frame_wire: const u8[:]) -> i64 {
    guard topic.len > 0 && frame_wire.len > 0 else { return 0; }

    var matched_fds: i64[..512] = [];
    topic_find_subscribers(tree, topic, matched_fds);

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
fn topic_publish(
    tree: TopicTree&,
    topic: const u8[:],
    message: const u8[:],
    opcode: u8 = WS_OPCODE_TEXT
) -> i64 {
    var frame: u8[..65536] = [];
    let no_mask: u8[4] = [0, 0, 0, 0];
    encode_ws_frame(frame, opcode, message, false, no_mask, true);
    return topic_publish_frame(tree, topic, frame[..]);
}

// Convenience helper to publish UTF-8 text message to a topic.
fn topic_publish_text(tree: TopicTree&, topic: const u8[:], text: const u8[:]) -> i64 {
    return topic_publish(tree, topic, text, WS_OPCODE_TEXT);
}

// Convenience helper to publish binary message to a topic.
fn topic_publish_binary(tree: TopicTree&, topic: const u8[:], data: const u8[:]) -> i64 {
    return topic_publish(tree, topic, data, WS_OPCODE_BINARY);
}
