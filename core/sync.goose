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
    failed_count_val: i64 = 0,
    worker_ids: i64[>..] = [],
}

fn new_wait_group() -> WaitGroup {
    return WaitGroup { .. };
}

fn add_worker(wg: WaitGroup&, worker_id: i64) -> bool {
    wg.worker_ids.push(worker_id);
    return true;
}

// Returns the number of workers registered in the wait group.
fn worker_count(wg: const WaitGroup&) -> i64 {
    return wg.worker_ids.len;
}

// Returns the count of failed/aborted workers from the last wait_all.
fn failed_count(wg: const WaitGroup&) -> i64 {
    return wg.failed_count_val;
}

// Blocks until all registered workers terminate, capturing failure diagnostics.
// Returns true if all finished without aborting, false otherwise.
fn wait_all(wg: WaitGroup&, out_diagnostics: u8[>..]&) -> bool {
    var all_ok = true;
    wg.failed_count_val = 0;
    for id in wg.worker_ids {
        var err: u8[>..] = [];
        let ok = thread_wait(id, err);
        if !ok {
            all_ok = false;
            wg.failed_count_val++;
            if err.len > 0 {
                out_diagnostics.append(err);
                out_diagnostics.push('\n');
            }
        }
    }
    wg.worker_ids.clear();
    return all_ok;
}

// Blocks until all registered workers terminate. Returns true if all finished without aborting.
fn wait_all(wg: WaitGroup&) -> bool {
    var dummy: u8[>..] = [];
    return wait_all(wg, dummy);
}

// ---- typed channel / queue operations --------------------------------------

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

// ---- hardware thread inspector ---------------------------------------------

fn available_parallelism() -> i64 {
    return max(1, hardware_threads());
}

// ---- supervisor fault-recovery primitive ------------------------------------

// Represents the terminal execution status of a supervised worker.
struct WorkerStatus {
    worker_id: i64 = 0,
    ok: bool = false,
}

// Supervisor monitors background workers, containing crashes and tracking status.
struct Supervisor {
    failed_count_val: i64 = 0,
    success_count_val: i64 = 0,
    statuses: WorkerStatus[>..] = [],
}

fn new_supervisor() -> Supervisor {
    return Supervisor { .. };
}

fn add_worker(sup: Supervisor&, worker_id: i64) -> bool {
    sup.statuses.push(WorkerStatus { worker_id: worker_id, ok: false });
    return true;
}

// Blocks until all supervised workers terminate, capturing execution status and crash diagnostics.
// Returns true if all workers succeeded, false if any worker aborted.
fn wait_all(sup: Supervisor&, out_diagnostics: u8[>..]&) -> bool {
    var all_ok = true;
    sup.failed_count_val = 0;
    sup.success_count_val = 0;
    for i in sup.statuses.len {
        var err: u8[>..] = [];
        let ok = thread_wait(sup.statuses[i].worker_id, err);
        sup.statuses[i].ok = ok;
        if ok {
            sup.success_count_val++;
        } else {
            all_ok = false;
            sup.failed_count_val++;
            if err.len > 0 {
                out_diagnostics.append(err);
                out_diagnostics.push('\n');
            }
        }
    }
    return all_ok;
}

// Blocks until all supervised workers terminate. Returns true if all finished without aborting.
fn wait_all(sup: Supervisor&) -> bool {
    var dummy: u8[>..] = [];
    return wait_all(sup, dummy);
}

fn failed_count(sup: const Supervisor&) -> i64 {
    return sup.failed_count_val;
}

fn success_count(sup: const Supervisor&) -> i64 {
    return sup.success_count_val;
}
