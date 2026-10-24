// Tests for concurrency primitives, actors, channels, and singleflight.
import std;
import os;
import wing from "..";

// ---- suite 1: multithreading, actors & crash containment ------------------

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

        for task_idx in num_tasks {
            wing::send_msg(ComputeTask {
                task_id: task_idx,
                operand: task_idx + 1,
                is_terminal: false,
            });
        }

        for worker_idx in num_workers {
            wing::send_msg(ComputeTask { is_terminal: true, .. });
        }

        var total_sum: i64 = 0;
        for task_idx in num_tasks {
            let res = wing::recv_msg<ComputeResult>();
            total_sum += res.computed_val;
        }

        let wg_ok = wg.wait_all();
        sub.assert_true(wg_ok, "All workers finished successfully");
        sub.assert_eq(total_sum, 204, "Parallel computation matched 1^2 + ... + 8^2");
    };

    t.run("Case 2: Actor-Based State Management (Zero Mutexes)") { sub =>
        let actor_tid = thread_spawn(counter_actor);

        wing::send_msg(CounterCommand { delta: 10, .. });
        wing::send_msg(CounterCommand { delta: 25, .. });
        wing::send_msg(CounterCommand { delta: -5, .. });

        wing::send_msg(CounterCommand { query: true, .. });
        let resp = wing::recv_msg<CounterResponse>();
        sub.assert_eq(resp.current_value, 30, "Actor returned accurate state (10 + 25 - 5 = 30)");

        wing::send_msg(CounterCommand { quit: true, .. });
        let actor_ok = thread_wait(actor_tid);
        sub.assert_true(actor_ok, "Actor terminated cleanly");
    };

    t.run("Case 3: Crash Containment via thread_spawn_contained") { sub =>
        let crash_tid = thread_spawn_contained(contained_crashing_worker);
        wing::send_msg(ComputeTask { operand: 999, .. });

        var abort_msg: u8[>..] = [];
        let ok = thread_wait(crash_tid, abort_msg);
        sub.assert_false(ok, "Contained thread reported abort status");
        sub.assert_true(abort_msg.len > 0, "Contained thread captured abort diagnostic message");
    };
}

// ---- suite 2: classical concurrency (baton mutex, semaphore, latch) -------

thread_fn baton_worker() {
    for i in 10 {
        var count = wing::baton_lock<i64>();
        count++;
        wing::baton_unlock(count);
    }
}

fn test_classical_primitives(t: wing::T&) {
    t.run("Case 1: BatonMutex Share-Nothing Mutual Exclusion") { sub =>
        wing::new_baton_mutex(0 as i64);

        let w1 = thread_spawn(baton_worker);
        let w2 = thread_spawn(baton_worker);
        let w3 = thread_spawn(baton_worker);

        let ok1 = thread_wait(w1);
        let ok2 = thread_wait(w2);
        let ok3 = thread_wait(w3);
        sub.assert_true(ok1, "Worker 1 terminated cleanly");
        sub.assert_true(ok2, "Worker 2 terminated cleanly");
        sub.assert_true(ok3, "Worker 3 terminated cleanly");

        let final_count = wing::baton_lock<i64>();
        sub.assert_eq(final_count, 30, "Atomic baton increments summed correctly (3 * 10 = 30)");
    };

    t.run("Case 2: Counting Semaphore & Bulkhead Capacity Limiting") { sub =>
        var sem = wing::new_semaphore(2);

        let p1 = sem.acquire();
        let p2 = sem.acquire();
        sub.assert_eq(p1.epoch, 1, "First permit has epoch 1");
        sub.assert_eq(p2.epoch, 1, "Second permit has epoch 1");

        // Quota saturated: try_acquire must return false
        let p3, ok3 = sem.try_acquire();
        sub.assert_false(ok3, "try_acquire fails when bulkhead quota is exhausted");

        // Release one permit
        sem.release(p1);

        // Slot freed: try_acquire must now succeed
        let p4, ok4 = sem.try_acquire();
        sub.assert_true(ok4, "try_acquire succeeds after permit return");

        // Clean up
        sem.release(p2);
        sem.release(p4);
    };

    t.run("Case 3: CountDownLatch One-Shot Coordination") { sub =>
        var latch = wing::new_count_down_latch(3);

        latch.count_down();
        latch.count_down();
        latch.count_down();

        // Drain the 3 ticks
        var ticks_collected: i64 = 0;
        for i in 3 {
            let item, ok = wing::try_recv_msg<wing::LatchTick>();
            if ok { ticks_collected++; }
        }
        sub.assert_eq(ticks_collected, 3, "All 3 countdown ticks were captured");
    };
}

// ---- suite 3: cyclic barrier two-phase turnstile synchronization ----------

thread_fn barrier_test_worker(worker_id: i32) {
    var epoch: u64 = 0;
    for step in 5 {
        epoch = wing::barrier_sync(worker_id, epoch);
    }
}

fn test_cyclic_barrier(t: wing::T&) {
    t.run("Case 1: Two-Phase Turnstile Multi-Worker Synchronization") { sub =>
        let barrier_tid = wing::barrier_start(3);
        let w1 = thread_spawn(barrier_test_worker, 1 as i32);
        let w2 = thread_spawn(barrier_test_worker, 2 as i32);
        let w3 = thread_spawn(barrier_test_worker, 3 as i32);

        let ok1 = thread_wait(w1);
        let ok2 = thread_wait(w2);
        let ok3 = thread_wait(w3);
        sub.assert_true(ok1, "Barrier participant 1 succeeded");
        sub.assert_true(ok2, "Barrier participant 2 succeeded");
        sub.assert_true(ok3, "Barrier participant 3 succeeded");

        wing::barrier_stop();
        let coord_ok = thread_wait(barrier_tid);
        sub.assert_true(coord_ok, "Barrier coordinator shutdown cleanly");
    };
}

// ---- suite 4: csp patterns & in-order stream reassembly -------------------

struct ChannelTagA {}
struct ChannelTagB {}

struct RendezvousReq {
    command_id: i32 = 0,
}

thread_fn rendezvous_server() {
    let req = wing::chan_recv<ChannelTagA, RendezvousReq>();
    wing::chan_rendezvous_reply<ChannelTagA>(req.command_id == 100);
}

fn test_csp_patterns(t: wing::T&) {
    t.run("Case 1: Reassembler In-Order Stream Reconstruction") { sub =>
        var r = wing::new_reassembler(0);

        // Push packets in out-of-order sequence: 3, 0, 2, 1
        var item3 = wing::ReassemblerItem { seq_id: 3, .. }; item3.data.append("three");
        var item0 = wing::ReassemblerItem { seq_id: 0, .. }; item0.data.append("zero");
        var item2 = wing::ReassemblerItem { seq_id: 2, .. }; item2.data.append("two");
        var item1 = wing::ReassemblerItem { seq_id: 1, .. }; item1.data.append("one");

        r.push_unordered(item3);
        r.push_unordered(item0);
        r.push_unordered(item2);
        r.push_unordered(item1);

        sub.assert_eq(r.pending_count(), 4, "Reassembler holds 4 unordered items");

        let p0, ok0 = r.pop_next_in_order();
        sub.assert_true(ok0, "Pop item 0 ok");
        sub.assert_eq(p0.seq_id, 0, "Item 0 sequence verified");

        let p1, ok1 = r.pop_next_in_order();
        sub.assert_true(ok1, "Pop item 1 ok");
        sub.assert_eq(p1.seq_id, 1, "Item 1 sequence verified");

        let p2, ok2 = r.pop_next_in_order();
        sub.assert_true(ok2, "Pop item 2 ok");
        sub.assert_eq(p2.seq_id, 2, "Item 2 sequence verified");

        let p3, ok3 = r.pop_next_in_order();
        sub.assert_true(ok3, "Pop item 3 ok");
        sub.assert_eq(p3.seq_id, 3, "Item 3 sequence verified");

        let p4, ok4 = r.pop_next_in_order();
        sub.assert_false(ok4, "Pop item 4 returns false (empty)");
        sub.assert_eq(r.pending_count(), 0, "All items drained");
    };

    t.run("Case 2: StaticChan Envelope Tagging & Rendezvous") { sub =>
        let srv = thread_spawn(rendezvous_server);
        let ok = wing::chan_rendezvous<ChannelTagA, RendezvousReq>(RendezvousReq { command_id: 100 });
        sub.assert_true(ok, "Rendezvous server confirmed command 100 with Ack");
        thread_wait(srv);
    };
}

// ---- suite 5: actor mailbox, stash buffer & 16-byte actor ref -------------

fn test_actor_subsystem(t: wing::T&) {
    t.run("Case 1: PriorityMailbox Stable Binary Min-Heap Ordering") { sub =>
        var mb = wing::new_priority_mailbox();

        // Push entries with different priorities:
        // Priority 10 (Low), Priority 1 (High), Priority 5 (Medium), Priority 1 (High FIFO second)
        mb.push(10, 1, 1000);
        mb.push(1, 2, 2001);
        mb.push(5, 3, 5000);
        mb.push(1, 4, 2002);

        sub.assert_eq(mb.count(), 4, "Mailbox has 4 pending messages");

        let e1, ok1 = mb.pop();
        sub.assert_true(ok1, "Pop 1 ok");
        sub.assert_eq(e1.payload_val, 2001, "First high-priority message popped first");

        let e2, ok2 = mb.pop();
        sub.assert_true(ok2, "Pop 2 ok");
        sub.assert_eq(e2.payload_val, 2002, "Second high-priority message preserved FIFO order");

        let e3, ok3 = mb.pop();
        sub.assert_true(ok3, "Pop 3 ok");
        sub.assert_eq(e3.payload_val, 5000, "Medium priority message popped next");

        let e4, ok4 = mb.pop();
        sub.assert_true(ok4, "Pop 4 ok");
        sub.assert_eq(e4.payload_val, 1000, "Low priority message popped last");

        let e5, ok5 = mb.pop();
        sub.assert_false(ok5, "Mailbox empty");
    };

    t.run("Case 2: StashBuffer Message Deferral and Replay") { sub =>
        var stash = wing::new_stash_buffer();
        sub.assert_true(stash.is_empty(), "StashBuffer starts empty");

        stash.stash(wing::StashedEnvelope { priority: 1, seq: 1, payload_type: 10, .. });
        stash.stash(wing::StashedEnvelope { priority: 1, seq: 2, payload_type: 20, .. });
        stash.stash(wing::StashedEnvelope { priority: 1, seq: 3, payload_type: 30, .. });

        sub.assert_eq(stash.stash_count(), 3, "Stashed 3 messages");
        sub.assert_false(stash.is_empty(), "StashBuffer not empty");

        var pending: wing::StashedEnvelope[>..] = [];
        let unstashed = stash.unstash_all(pending);
        sub.assert_eq(unstashed, 3, "Unstashed exactly 3 messages");
        sub.assert_eq(pending.len, 3, "Pending array received all 3 messages");
        sub.assert_true(stash.is_empty(), "StashBuffer cleared after unstash_all");
    };

    t.run("Case 3: ActorRef 16-Byte Flat Handle Value Semantics") { sub =>
        let ref_a = wing::new_actor_ref(101, 1, 0, 42);
        let ref_b = wing::new_actor_ref(101, 1, 0, 42);
        let ref_c = wing::new_actor_ref(102, 1, 0, 42);

        sub.assert_true(wing::eq_actor_ref(ref_a, ref_b), "ref_a and ref_b are equal");
        sub.assert_false(wing::eq_actor_ref(ref_a, ref_c), "ref_a and ref_c differ in actor_id");
    };
}

// ---- suite 6: otp supervision trees & fault tolerance ---------------------

fn test_supervision_trees(t: wing::T&) {
    t.run("Case 1: RestartType Specification & Restart Evaluation") { sub =>
        var sup = wing::new_supervisor();

        let ok_perm = sup.add_child(wing::ChildSpec { id: 1, restart_type: core::RestartType.Permanent, .. }, 101);
        let ok_trans = sup.add_child(wing::ChildSpec { id: 2, restart_type: core::RestartType.Transient, .. }, 102);
        let ok_temp = sup.add_child(wing::ChildSpec { id: 3, restart_type: core::RestartType.Temporary, .. }, 103);
        sub.assert_true(ok_perm, "Permanent child added");
        sub.assert_true(ok_trans, "Transient child added");
        sub.assert_true(ok_temp, "Temporary child added");
        sub.assert_eq(sup.child_count(), 3, "Supervisor has 3 children");

        var normal_reason: wing::ExitReason = core::ExitReason.Normal;
        var abnormal_reason: wing::ExitReason = core::ExitReason.Abnormal { error_code: 1, details: [] };

        // Permanent: always restarts
        sub.assert_true(sup.should_restart_child(0, normal_reason), "Permanent child restarts on Normal");
        sub.assert_true(sup.should_restart_child(0, abnormal_reason), "Permanent child restarts on Abnormal");

        // Transient: restarts ONLY on Abnormal
        sub.assert_false(sup.should_restart_child(1, normal_reason), "Transient child does NOT restart on Normal");
        sub.assert_true(sup.should_restart_child(1, abnormal_reason), "Transient child restarts on Abnormal");

        // Temporary: never restarts
        sub.assert_false(sup.should_restart_child(2, normal_reason), "Temporary child never restarts (Normal)");
        sub.assert_false(sup.should_restart_child(2, abnormal_reason), "Temporary child never restarts (Abnormal)");
    };

    t.run("Case 2: Restart Intensity Throttling (max_restarts / max_seconds)") { sub =>
        var spec = wing::SupervisorSpec {
            strategy: core::Strategy.OneForOne,
            max_restarts: 3,
            max_seconds: 5,
            auto_shutdown: core::AutoShutdown.Never,
        };
        var sup = wing::new_supervisor(spec);
        sup.add_child(wing::ChildSpec { id: 1, .. }, 201);

        // Record 3 failures within 5-second window
        let r1 = sup.record_failure(0, 1000);
        let r2 = sup.record_failure(0, 1001);
        let r3 = sup.record_failure(0, 1002);
        sub.assert_true(r1, "Failure 1 accepted");
        sub.assert_true(r2, "Failure 2 accepted");
        sub.assert_true(r3, "Failure 3 accepted");

        // 4th failure within window must be rejected (intensity limit exceeded!)
        let r4 = sup.record_failure(0, 1003);
        sub.assert_false(r4, "Failure 4 rejected: intensity limit exceeded");

        // Failure after window has rolled forward past 5 seconds must succeed
        let r5 = sup.record_failure(0, 1010);
        sub.assert_true(r5, "Failure after window expiry accepted");
    };

    t.run("Case 3: AutoShutdown & Specification Validation") { sub =>
        // Invalid config: significant child when auto_shutdown is Never must be rejected
        var sup_never = wing::new_supervisor(wing::SupervisorSpec { auto_shutdown: core::AutoShutdown.Never, .. });
        let rejected_sig = sup_never.add_child(wing::ChildSpec {
            id: 1,
            restart_type: core::RestartType.Transient,
            significant: true,
            ..
        }, 301);
        sub.assert_false(rejected_sig, "Child with significant=true rejected when auto_shutdown is Never");

        // Invalid config: permanent child marked significant must be rejected
        var sup_auto = wing::new_supervisor(wing::SupervisorSpec { auto_shutdown: core::AutoShutdown.AnySignificant, .. });
        let rejected_perm_sig = sup_auto.add_child(wing::ChildSpec {
            id: 2,
            restart_type: core::RestartType.Permanent,
            significant: true,
            ..
        }, 302);
        sub.assert_false(rejected_perm_sig, "Permanent child cannot be marked significant");

        // Valid config: transient child marked significant
        let accepted = sup_auto.add_child(wing::ChildSpec {
            id: 3,
            restart_type: core::RestartType.Transient,
            significant: true,
            ..
        }, 303);
        sub.assert_true(accepted, "Transient significant child accepted");
        sub.assert_false(sup_auto.is_auto_shutdown(), "AutoShutdown initially false");
    };
}

// ---- consolidated suite entry point ---------------------------------------

fn main() {
    var runner = wing::new_runner("Comprehensive core::sync Verification Suite", wing::Verbosity.Verbose);

    wing::run_case(runner, "1. Multithreading, Actors & Crash Containment", test_multithreading_and_actors);
    wing::run_case(runner, "2. Classical Concurrency Primitives", test_classical_primitives);
    wing::run_case(runner, "3. Two-Phase CyclicBarrier Synchronization", test_cyclic_barrier);
    wing::run_case(runner, "4. CSP Patterns & In-Order Reassembly", test_csp_patterns);
    wing::run_case(runner, "5. Actor Subsystem & Priority Mailboxes", test_actor_subsystem);
    wing::run_case(runner, "6. OTP Supervision Trees & Fault Tolerance", test_supervision_trees);

    let ok = wing::finish(runner);
    assert(ok);
}
