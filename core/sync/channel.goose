// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Runtime primitives, bounded message channels, and hardware execution parallelism.
namespace core;

import std;
import os;

// Returns the number of physical hardware execution threads available.
fn available_parallelism() -> i64 {
    return max(1, hardware_threads());
}

// Sets queue capacity backpressure limit for type T. Past this limit, send_msg returns false.
// Returns false if limit <= 0 without invoking qlimit, preventing unrecoverable runtime aborts.
fn set_channel_limit<T>(limit: i64) -> bool {
    if limit <= 0 {
        return false;
    }
    qlimit<T>(limit);
    return true;
}

// Sends a flat message to the queue for type T. Returns false if bounded queue is full.
fn send_msg<T>(msg: T) -> bool {
    return qput(msg);
}

// Sends a flat message to the queue for type T, waiting at most timeout_ms if bounded queue is full.
fn send_msg_timeout<T>(msg: T, timeout_ms: i64) -> bool {
    if qput(msg) { return true; }
    if timeout_ms <= 0 { return false; }
    let start_ns = clock_ns();
    let timeout_ns = timeout_ms * 1000000;
    while clock_ns() - start_ns < timeout_ns {
        sleep_ms(1);
        if qput(msg) { return true; }
    }
    return false;
}

// Receives a message from the queue for type T, blocking indefinitely until available.
fn recv_msg<T>() -> T {
    return qget<T>();
}

// Receives a message from the queue for type T, waiting at most timeout_ms milliseconds.
// Negative timeout_ms represents an expired deadline and returns zero value + false immediately.
fn recv_msg_timeout<T>(timeout_ms: i64) -> T, bool {
    if timeout_ms < 0 {
        return default<T>(), false;
    }
    return qget<T>(timeout_ms);
}

// Non-blocking poll for a message of type T. Returns zero value and false if empty.
fn try_recv_msg<T>() -> T, bool {
    return qpoll<T>();
}

// Drains up to max_items available messages from queue T into a buffer.
// Returns the number of messages successfully drained.
fn drain_channel<T, B>(max_items: i64, out: B&) -> i64 {
    if max_items <= 0 { return 0; }
    var count = 0;
    while count < max_items {
        let item, ok = qpoll<T>();
        if !ok { break; }
        out.push(item);
        count++;
    }
    return count;
}
