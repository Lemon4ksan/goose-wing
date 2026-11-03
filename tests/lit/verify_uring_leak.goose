// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

// Verification of io_uring completion balance under saturated CQE batch (BUG-06).
import std;
import core from "../..";
import wing from "../..";

fn main() {
    print("=== VERIFY_URING_LEAK ===\n");

    var state = internal::RingQueueState {
        ring_size:         32,
        active_pending:    0,
        submissions_total: 0,
        completions_total: 0,
    };

    var sqes: internal::UringSqe[33] = [internal::UringSqe { .. }; 33];
    for i in 33 {
        sqes[i].opcode = internal::URING_OP_SEND;
        sqes[i].fd = 10;
        sqes[i].len = 64;
        sqes[i].user_data = (i + 1) as u64;
    }

    var cqes: internal::UringCqe[..32] = [];

    // Batch 1: Submit 33 SQEs with 32 CQE slots available
    let submitted = internal::uring_submit_batch(state, sqes[..], cqes);
    assert(submitted == 32);
    assert(cqes.len == 32);
    // After reaping 32 completions, active_pending MUST be 0, not 1!
    assert(state.active_pending == 0);
    print("BATCH_1_SUBMITTED: ", submitted, " PENDING: ", state.active_pending, "\n");
    // CHECK: BATCH_1_SUBMITTED: 32 PENDING: 0

    // Batch 2: Submit another batch - must NOT be rejected due to leaked active_pending!
    cqes.clear();
    let submitted2 = internal::uring_submit_batch(state, sqes[..], cqes);
    assert(submitted2 == 32);
    assert(state.active_pending == 0);
    print("BATCH_2_NO_DEADLOCK: OK\n");
    // CHECK: BATCH_2_NO_DEADLOCK: OK

    print("ALL_URING_INVARIANTS_VERIFIED: OK\n");
    // CHECK: ALL_URING_INVARIANTS_VERIFIED: OK
}
