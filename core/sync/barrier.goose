// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// WaitGroup, CountDownLatch, and two-phase turnstile CyclicBarrier synchronization primitives.
namespace core;

import std;
import os;

// WaitGroup coordinates and waits for a collection of worker threads to finish.
struct WaitGroup {
    failed_count_val: i64 = 0,
    worker_ids: i64[>..] = [],
}

// Creates an empty WaitGroup.
// Registers a worker thread ID with the WaitGroup.
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

// One-shot synchronization latch for K ticking workers and M awaiting threads.
struct LatchTick {
    step: i32 = 1,
}

struct LatchOpen {
    marker: u8 = 1,
}

struct CountDownLatch {
    expected: i64 = 0,
}

// Creates a new CountDownLatch expecting expected tickets.
fn new_count_down_latch(expected: i64) -> CountDownLatch {
    return CountDownLatch { expected: expected };
}

// Emits a tick to decrement the latch.
fn count_down(latch: CountDownLatch&) -> bool {
    return qput(LatchTick { step: 1 });
}

// Sends a tick signal to the latch queue.
fn latch_tick() -> bool {
    return qput(LatchTick { step: 1 });
}

// Opens the latch by placing marker tokens for waiter_count threads.
fn latch_open(waiter_count: i64) {
    for i in waiter_count {
        qput(LatchOpen { marker: 1 });
    }
}

// Blocks until the latch is opened.
fn latch_wait(latch: CountDownLatch&) {
    let open = qget<LatchOpen>();
}

// Blocks until a latch open marker is received.
fn latch_wait() {
    let open = qget<LatchOpen>();
}

// Two-phase turnstile cyclic barrier message types
struct BarrierArrive {
    worker_id: i32 = 0,
    epoch: u64 = 0,
}

struct BarrierRelease {
    epoch: u64 = 0,
}

struct BarrierDepart {
    worker_id: i32 = 0,
    epoch: u64 = 0,
}

struct BarrierDepartAck {
    epoch: u64 = 0,
}

// Coordinator process implementing a mathematically safe two-phase turnstile cyclic barrier.
thread_fn barrier_coordinator(n_participants: i32) {
    var current_epoch: u64 = 0;

    loop {
        // Phase 1: Wait for all N participants to arrive at current_epoch
        var arrived_count: i32 = 0;
        while arrived_count < n_participants {
            let msg = qget<BarrierArrive>();
            if msg.epoch == 0xFFFFFFFFFFFFFFFF {
                return; // Shutdown signal
            }
            if msg.epoch == current_epoch {
                arrived_count++;
            }
        }

        // Release Turnstile 1
        for i in n_participants {
            qput(BarrierRelease { epoch: current_epoch });
        }

        // Phase 2: Wait for all N participants to depart Turnstile 1
        var departed_count: i32 = 0;
        while departed_count < n_participants {
            let dep = qget<BarrierDepart>();
            if dep.epoch == current_epoch {
                departed_count++;
            }
        }

        // Release Turnstile 2: All participants can now safely advance
        for i in n_participants {
            qput(BarrierDepartAck { epoch: current_epoch });
        }

        current_epoch++;
    }
}

// Spawns a background barrier coordinator for N participants.
fn barrier_start(n_participants: i32) -> i64 {
    return thread_spawn(barrier_coordinator, n_participants);
}

// Synchronizes participant on the cyclic barrier. Returns the incremented local epoch.
fn barrier_sync(worker_id: i32, local_epoch: u64) -> u64 {
    qput(BarrierArrive { worker_id: worker_id, epoch: local_epoch });
    let rel = qget<BarrierRelease>();
    qput(BarrierDepart { worker_id: worker_id, epoch: local_epoch });
    let ack = qget<BarrierDepartAck>();
    return local_epoch + 1;
}

// Signals the barrier coordinator to terminate cleanly.
fn barrier_stop() {
    qput(BarrierArrive { worker_id: -1, epoch: 0xFFFFFFFFFFFFFFFF });
}
