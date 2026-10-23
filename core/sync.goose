// The Goose concurrency and actor synchronization primitives: candidate for `core::sync`.
//
// Concurrency Model:
//   Goose adheres to the Share-Nothing / Actor / Communicating Sequential Processes (CSP) model.
//   There is no shared mutable memory, no data races, no memory barriers, and no mutex locks.
//   Threads communicate exclusively via typed message queues (qput, qget, qpoll, qlimit).
//
// Provided Primitives:
//   WaitGroup      - Synchronizes completion of multiple background worker threads.
//   Channel / Queue- Ergonomic typed message passing with capacity limits, timeouts, and polling.
//   Supervisor     - Fault-tolerant crash containment and worker status monitoring.
//   Parallelism    - Hardware thread detection and workload distribution.
namespace wing;

import std;

// ---- wait group primitive --------------------------------------------------

// WaitGroup coordinates and waits for a collection of worker threads to finish.
struct WaitGroup {
    worker_ids: i64[..64] = [],
}

fn new_wait_group() -> WaitGroup {
    return WaitGroup { .. };
}

fn add_worker(wg: WaitGroup&, worker_id: i64) {
    if wg.worker_ids.len < 64 {
        wg.worker_ids.push(worker_id);
    }
}

// Blocks until all registered workers terminate. Returns true if all finished without aborting.
fn wait_all(wg: WaitGroup&) -> bool {
    var all_ok = true;
    for id in wg.worker_ids {
        let ok = thread_wait(id);
        if !ok { all_ok = false; }
    }
    wg.worker_ids.clear();
    return all_ok;
}

// ---- typed channel / queue operations --------------------------------------

// Sets queue capacity backpressure limit for type T. Past this limit, send_msg returns false.
fn set_channel_limit<T>(limit: i64) {
    qlimit<T>(limit);
}

// Sends a flat message to the queue for type T. Returns false if bounded queue is full.
fn send_msg<T>(msg: T) -> bool {
    return qput(msg);
}

// Receives a message from the queue for type T, blocking indefinitely until available.
fn recv_msg<T>() -> T {
    return qget<T>();
}

// Receives a message from the queue for type T, waiting at most timeout_ms milliseconds.
fn recv_msg_timeout<T>(timeout_ms: i64) -> T, bool {
    return qget<T>(timeout_ms);
}

// Non-blocking poll for a message of type T. Returns zero value and false if empty.
fn try_recv_msg<T>() -> T, bool {
    return qpoll<T>();
}

// Drains up to max_items available messages from queue T into a buffer.
fn drain_channel<T, B>(max_items: i64, out: B&) {
    var count = 0;
    while count < max_items {
        let item, ok = qpoll<T>();
        if !ok { break; }
        out.push(item);
        count++;
    }
}

// ---- hardware thread inspector ---------------------------------------------

fn available_parallelism() -> i64 {
    return max(1, hardware_threads());
}
