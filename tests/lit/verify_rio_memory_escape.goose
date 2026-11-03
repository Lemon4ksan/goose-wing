// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

// Verification of RIO memory partition bounds enforcement (BUG-05).
import std;
import core from "../..";
import wing from "../..";

fn main() {
    print("=== VERIFY_RIO_MEMORY_ESCAPE ===\n");

    // Create a parent RIO buffer descriptor representing an offset partition (4096..5120)
    let parent = internal::RioBufferDescriptor {
        buffer_id:     101,
        offset:        4096,
        length:        1024,
        is_registered: true,
        page_locked:   true,
    };

    // Case 1: Valid sub-slice within the partition
    let valid_sub = internal::rio_sub_buffer(parent, 4096, 512);
    assert(valid_sub.is_registered);
    assert(valid_sub.offset == 4096);
    assert(valid_sub.length == 512);
    print("CASE_1_VALID_SUB: OK\n");
    // CHECK: CASE_1_VALID_SUB: OK

    // Case 2: Attempt memory escape: off = 0 (before parent.offset = 4096)
    // Previously, off + len = 1024 <= 5120 was true, erroneously permitting access to bytes 0..1024!
    let escape_sub = internal::rio_sub_buffer(parent, 0, 1024);
    assert(!escape_sub.is_registered);
    assert(escape_sub.length == 0);
    print("CASE_2_ESCAPE_BEFORE_OFFSET_REJECTED: OK\n");
    // CHECK: CASE_2_ESCAPE_BEFORE_OFFSET_REJECTED: OK

    // Case 3: Attempt memory escape: off = 5000, len = 200 (past parent.offset + length = 5120)
    let escape_past = internal::rio_sub_buffer(parent, 5000, 200);
    assert(!escape_past.is_registered);
    assert(escape_past.length == 0);
    print("CASE_3_ESCAPE_PAST_END_REJECTED: OK\n");
    // CHECK: CASE_3_ESCAPE_PAST_END_REJECTED: OK

    print("ALL_RIO_BOUNDS_VERIFIED: OK\n");
    // CHECK: ALL_RIO_BOUNDS_VERIFIED: OK
}
