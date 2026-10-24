// Tests for concurrency primitives, channel limits, and worker supervisors.
import std;
import core from "..";
import wing from "..";

// ----------------------------------------------------------------------------
// Round 1: WaitGroup Capacity Limit
// ----------------------------------------------------------------------------
struct WorkerCompletion {
    worker_id: i64 = 0,
}

thread_fn test_worker(id: i64) {
    if id == 70 {
        // Slow worker: sleeps 50ms so we can detect if wait_all returned prematurely
        sleep_ms(50);
    }
    core::send_msg(WorkerCompletion { worker_id: id });
}

fn test_wait_group_capacity_and_completion(t: core::T&) {
    t.run("ASYNC-01: WaitGroup must track and wait for >64 workers") { sub =>
        let total_workers: i64 = 72;
        var wg = core::new_wait_group();

        for i in total_workers {
            let tid = thread_spawn(test_worker, i);
            wg.add_worker(tid);
        }

        // On unpatched code, worker_ids is capped at 64 elements, silently dropping workers 64..71.
        sub.assert_eq(wg.worker_ids.len, total_workers, "WaitGroup must track all 72 registered workers");

        // Wait for all workers to finish
        let ok = wg.wait_all();
        sub.assert_true(ok, "wait_all returned true");

        // Drain completions: all 72 workers must have completed by the time wait_all finishes.
        var completed_count = 0;
        var worker_70_completed = false;

        for _ in total_workers {
            let comp, found = core::try_recv_msg<WorkerCompletion>();
            if found {
                completed_count++;
                if comp.worker_id == 70 {
                    worker_70_completed = true;
                }
            }
        }

        sub.assert_eq(completed_count, total_workers, "All 72 workers completed before wait_all returned");
        sub.assert_true(worker_70_completed, "Slow worker #70 completed before wait_all returned");
    };
}

// ----------------------------------------------------------------------------
// Round 2: Queue Bounds & Timeout Handling
// ----------------------------------------------------------------------------
struct QueueTestItem {
    val: i64 = 0,
}

thread_fn zero_limit_worker() {
    core::set_channel_limit<QueueTestItem>(0);
}

thread_fn negative_limit_worker() {
    core::set_channel_limit<QueueTestItem>(-5);
}

fn test_queue_bounds_and_timeout(t: core::T&) {
    t.run("ASYNC-02: Non-positive queue limits must not abort process") { sub =>
        // Test limit = 0
        let tid0 = thread_spawn_contained(zero_limit_worker);
        var err0: u8[>..] = [];
        let ok0 = thread_wait(tid0, err0);
        sub.assert_true(ok0, "set_channel_limit(0) must not abort the process");

        // Test limit = -5
        let tid_neg = thread_spawn_contained(negative_limit_worker);
        var err_neg: u8[>..] = [];
        let ok_neg = thread_wait(tid_neg, err_neg);
        sub.assert_true(ok_neg, "set_channel_limit(-5) must not abort the process");
    };

    t.run("ASYNC-02: Negative timeout must not consume messages from queue") { sub =>
        // Send a test message
        core::send_msg(QueueTestItem { val: 42 });

        // Attempt receive with negative timeout (expired / invalid)
        let item, received = core::recv_msg_timeout<QueueTestItem>(-1);
        sub.assert_false(received, "recv_msg_timeout(-1) must return false on expired timeout");

        // The message should still be available in the queue for a valid receive
        let valid_item, valid_received = core::try_recv_msg<QueueTestItem>();
        sub.assert_true(valid_received, "Message must remain in queue after negative timeout call");
        sub.assert_eq(valid_item.val, 42, "Message value preserved in queue");
    };
}

// ----------------------------------------------------------------------------
// Round 3: Crash Diagnostics & Supervisor Pattern
// ----------------------------------------------------------------------------
thread_fn crashing_contained_worker() {
    abort("intentional worker abort: worker_failed_for_test");
}

thread_fn normal_contained_worker() {
    // Normal worker: terminates successfully without aborting
}

fn test_crash_diagnostics_and_supervision(t: core::T&) {
    t.run("ASYNC-03 Case 1: WaitGroup must preserve crash diagnostics and track failed workers") { sub =>
        var wg = core::new_wait_group();

        let tid1 = thread_spawn_contained(crashing_contained_worker);
        let tid2 = thread_spawn_contained(normal_contained_worker);
        wg.add_worker(tid1);
        wg.add_worker(tid2);

        var diagnostics: u8[>..] = [];
        let all_ok = wg.wait_all(diagnostics);

        sub.assert_false(all_ok, "wait_all reports failure when a contained worker aborts");
        sub.assert_true(diagnostics.len > 0, "Crash diagnostics must be captured by wait_all");
        sub.assert_eq(wg.failed_count(), 1, "Exactly one worker marked as failed");
    };

    t.run("ASYNC-03 Case 2: Supervisor fault-tolerant containment & worker status monitoring") { sub =>
        var sup = core::new_supervisor();

        let tid1 = thread_spawn_contained(crashing_contained_worker);
        let tid2 = thread_spawn_contained(normal_contained_worker);
        sup.add_worker(tid1);
        sup.add_worker(tid2);

        var sup_diag: u8[>..] = [];
        let all_ok = sup.wait_all(sup_diag);
        sub.assert_false(all_ok, "Supervisor wait_all reports false on worker abort");
        sub.assert_eq(sup.failed_count(), 1, "Supervisor recorded 1 failed worker");
        sub.assert_eq(sup.success_count(), 1, "Supervisor recorded 1 successful worker");

        sub.assert_false(sup.statuses[0].ok, "First worker marked as failed");
        sub.assert_true(sup_diag.len > 0, "Supervisor captured abort diagnostic");
        sub.assert_true(sup.statuses[1].ok, "Second worker marked as successful");
    };
}

// ----------------------------------------------------------------------------
// Consolidated Suite Entry Point
// ----------------------------------------------------------------------------
fn main() {
    var runner = core::new_runner("Concurrency & Supervision Suite", core::Verbosity.Verbose);

    core::run_case(runner, "1. WaitGroup Capacity Limit", test_wait_group_capacity_and_completion);
    core::run_case(runner, "2. Queue Bounds & Timeout Handling", test_queue_bounds_and_timeout);
    core::run_case(runner, "3. Crash Diagnostics & Supervisor Pattern", test_crash_diagnostics_and_supervision);

    let ok = core::finish(runner);
    assert(ok);
}
