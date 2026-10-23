// Concurrency & Actor Verification Suite for wing (core::sync).
// Verifies WaitGroup, typed message passing, Actor state management, and crash containment.
import std;
import wing from "..";

struct ComputeTask {
    task_id: i64 = 0,
    operand: i64 = 0,
    is_terminal: bool = false,
}

struct ComputeResult {
    task_id: i64 = 0,
    computed_val: i64 = 0,
}

thread_fn compute_worker() {
    loop {
        let task = wing::recv_msg<ComputeTask>();
        guard !task.is_terminal else { break; }
        wing::send_msg(ComputeResult {
            task_id: task.task_id,
            computed_val: task.operand * task.operand,
        });
    }
}

// Actor pattern: State manager thread that owns mutable counter without mutexes
struct CounterCommand {
    delta: i64 = 0,
    query: bool = false,
    quit: bool = false,
}

struct CounterResponse {
    current_value: i64 = 0,
}

thread_fn counter_actor() {
    var state: i64 = 0;
    loop {
        let cmd = wing::recv_msg<CounterCommand>();
        if cmd.quit { break; }
        if cmd.query {
            wing::send_msg(CounterResponse { current_value: state });
        } else {
            state += cmd.delta;
        }
    }
}

thread_fn contained_crashing_worker() {
    let task = wing::recv_msg<ComputeTask>();
    if task.operand == 999 {
        abort("intentional contained worker failure for test");
    }
}

fn test_multithreading_and_actors(t: wing::T&) {
    t.run("Case 1: WaitGroup & Parallel Worker Pool Dispatch") { sub =>
        let num_tasks: i64 = 8;
        let num_workers: i64 = 2;

        var wg = wing::new_wait_group();
        for worker_idx in num_workers {
            let tid = thread_spawn(compute_worker);
            wg.add_worker(tid);
        }

        // Send compute tasks
        for task_idx in num_tasks {
            wing::send_msg(ComputeTask {
                task_id: task_idx,
                operand: task_idx + 1,
                is_terminal: false,
            });
        }

        // Send quit tasks to each worker
        for worker_idx in num_workers {
            wing::send_msg(ComputeTask { is_terminal: true, .. });
        }

        // Collect results
        var total_sum: i64 = 0;
        for task_idx in num_tasks {
            let res = wing::recv_msg<ComputeResult>();
            total_sum += res.computed_val;
        }

        let wg_ok = wg.wait_all();
        sub.assert_true(wg_ok, "All workers finished successfully");

        // Sum of (1^2 + 2^2 + ... + 8^2) = 204
        sub.assert_eq(total_sum, 204, "Parallel computation matched 1^2 + ... + 8^2");
    };

    t.run("Case 2: Actor-Based State Management (Zero Mutexes)") { sub =>
        let actor_tid = thread_spawn(counter_actor);

        // Send state mutation commands
        wing::send_msg(CounterCommand { delta: 10, .. });
        wing::send_msg(CounterCommand { delta: 25, .. });
        wing::send_msg(CounterCommand { delta: -5, .. });

        // Query current state
        wing::send_msg(CounterCommand { query: true, .. });
        let resp = wing::recv_msg<CounterResponse>();
        sub.assert_eq(resp.current_value, 30, "Actor returned accurate state (10 + 25 - 5 = 30)");

        // Terminate actor cleanly
        wing::send_msg(CounterCommand { quit: true, .. });
        let actor_ok = thread_wait(actor_tid);
        sub.assert_true(actor_ok, "Actor terminated cleanly");
    };

    t.run("Case 3: Crash Containment via thread_spawn_contained") { sub =>
        let crash_tid = thread_spawn_contained(contained_crashing_worker);

        // Send triggering task that aborts the worker
        wing::send_msg(ComputeTask { operand: 999, .. });

        var abort_msg: u8[>..] = [];
        let ok = thread_wait(crash_tid, abort_msg);
        sub.assert_false(ok, "Contained thread reported abort status");
        sub.assert_true(abort_msg.len > 0, "Contained thread captured abort diagnostic message");
    };
}

fn main() {
    var runner = wing::new_runner("Concurrency & Actor Verification Suite", wing::Verbosity.Verbose);
    wing::run_case(runner, "1. Multithreading, Actors & Crash Containment", test_multithreading_and_actors);
    let ok = wing::finish(runner);
    assert(ok);
}
