# Goose LIT: LLVM-grade wire & protocol verification

This directory houses native LLVM-style LIT (`goose-lit`) verification suites for `goose-wing`. Tests here verify wire framing, RFC conformance, protocol state machines (FSM), partial reads, and edge cases under zero-allocation memory constraints.

## Table of contents

- [Design principles](#design-principles)
- [Directive reference](#directive-reference)
- [The six-pillar testing methodology](#the-six-pillar-testing-methodology)
- [Canonical test template](#canonical-test-template)
- [Running LIT tests](#running-lit-tests)
- [Hardware complexity gate](#hardware-complexity-gate)

---

## Design principles

Standard unit tests rely on private helper assertions (`assert(x == y)`). This leaves hidden bugs in streaming parsers:
1. **Partial reads**: Real sockets deliver frames split across arbitrary 1-byte chunks.
2. **Silent state corruption**: Internal FSMs may enter unhandled states without failing immediate return values.
3. **Off-by-one pointer errors**: Buffers with trailing bytes or missing delimiters can trigger silent out-of-bounds access.
4. **Vector vs. scalar divergence**: AVX2/NEON scanners can disagree with scalar fallbacks on unaligned boundaries.

Goose LIT adopts the LLVM testing paradigm:
- Compile tests directly to native machine code without Wasm virtualization.
- Pipe stdout streams through `FileCheck` pattern matchers.
- Trace every FSM state transition and cursor movement explicitly.
- Exercise all prefix slices `1..N-1` through `wire_kit::verify_split_stream`.
- Mutate wire streams via in-process deterministic fuzzing (`wire_kit::fuzz_payload`).

---

## Directive reference

Directives are parsed directly from comments at the top of each `.goose` test file.

### Runner directives

| Directive | Expansion / Semantics | Purpose |
| :--- | :--- | :--- |
| `// RUN: <cmd>` | Executes command line. `%s` = source file, `%S` = directory, `%t` = temp scratch. | Primary compilation and execution rule. |
| `%FileCheck %s` | Expands to `goose-lit filecheck <file>`. | Pipes stdout to the FileCheck matcher. |
| `not <cmd>` | Executes command and inverts exit status (`0 -> 1`, `!= 0 -> 0`). | Negative testing (compiler rejection, aborts). |
| `// XFAIL: <target>` | Marks test as expected failure (`*`, `windows`, `gcc`, etc.). | Tracks known upstream bugs or WIP features. |
| `// REQUIRES: <feat>` | Requires host feature (`windows`, `x86_64`, `gcc`). | Skips test on unsupported platforms. |
| `// UNSUPPORTED: <feat>` | Disables test when host feature is present. | Excludes platform-incompatible suites. |

### FileCheck match directives

| Directive | Semantics |
| :--- | :--- |
| `// CHECK: <pattern>` | Searches downstream from current match position for `<pattern>`. |
| `// CHECK-NEXT: <pattern>` | Requires `<pattern>` to match on the immediate next output line. |
| `// CHECK-NOT: <pattern>` | Asserts that `<pattern>` does not appear before the next match. |
| `// CHECK-LABEL: <tag>` | Divides file into independent verification blocks (prevents cross-block matching). |
| `// CHECK-SAME: <pattern>` | Matches `<pattern>` on the same line as the previous match. |

---

## The six-pillar testing methodology

### 1. Deterministic FSM state tracing
Instead of checking a single boolean outcome, emit state machine transitions and frame decodes to stdout:
```goose
// CHECK-LABEL: === H2_FSM_TRANSITION ===
// CHECK-NEXT: STATE: Idle -> Active
// CHECK-NEXT: FRAME[0]: type=SETTINGS stream=0 len=18
// CHECK-NEXT: FRAME[1]: type=HEADERS stream=1 flags=0x05 len=42
// CHECK-NOT: ALERT
// CHECK-NEXT: STATE: HalfClosedRemote
```

### 2. Prefix fragmentation verification
Every wire parser must be validated against incremental packet arrivals. Using `wire_kit`:
```goose
fn parse_step(buf: const u8[:]) -> i64 {
    let _, ok = wing::parse_frame(buf);
    if !ok { return -1; }
    return 0;
}

// Tests buf[..1], buf[..2], ..., buf[..N-1] return -1, buf[..N] returns 0
assert(wire_kit::verify_split_stream<parse_step>(valid_wire[..], -1, 0));
print("SPLIT_STREAM: OK");
// CHECK: SPLIT_STREAM: OK
```

### 3. In-process deterministic chaos fuzzing
Exercise thousands of bit-flips, swaps, and boundary bytes (`0x00`, `0xFF`, `0x7F`, `0x80`) without external fuzzing daemons:
```goose
// Runs 10,000 deterministic mutations using xorshift64
assert(wire_kit::fuzz_payload<parse_step>(valid_wire[..], 10000));
print("CHAOS_FUZZ: OK");
// CHECK: CHAOS_FUZZ: OK
```

### 4. Dual-engine verification (AVX2 vs. scalar)
Validate that optimized SIMD routines match scalar fallbacks on all boundary conditions:
```goose
// RUN: goose build --cc gcc -O2 -o %t.opt.exe %s
// RUN: %t.opt.exe | %FileCheck %s --prefix=CHECK
// RUN: goose build --cc tools/gcc_noavx.cmd -O0 -o %t.scalar.exe %s
// RUN: %t.scalar.exe | %FileCheck %s --prefix=CHECK
```

### 5. Static complexity and bounds gating
Enforce function flatness and proven index bounds before compilation:
```powershell
..\goose-lit\bin\goose-lit.exe gate auth/pkce.goose 25 --cov 0.85
```

### 6. Bug regression reproducers
Every fixed bug receives a dedicated reproducer block with a unique `HIST_` or `BUG_` label:
```goose
// CVE or bug fix regression
let malicious_input = "...";
assert(wing::safe_decoder(malicious_input) == -1);
print("HIST_BUG_123: DEFENDED");
// CHECK: HIST_BUG_123: DEFENDED
```

---

## Canonical test template

```goose
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_example_protocol.goose
// Verification of Example Protocol wire parsing and streaming FSM.
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";
import wire_kit from ".";

fn parse_packet(buf: const u8[:]) -> i64 {
    let pkt, ok = wing::parse_my_packet(buf);
    guard ok else { return -1; }
    return pkt.payload_len as! i64;
}

fn main() {
    print("=== EXAMPLE_PROTOCOL_VERIFICATION ===");

    var valid_packet: u8[>..] = [];
    assert(wire_kit::parse_hex("0100000568656C6C6F", valid_packet));

    // Pillar 1: Valid frame decode & FSM trace
    let len = parse_packet(valid_packet[..]);
    assert(len == 5);
    print("FRAME_PAYLOAD_LEN: ", len);

    // Pillar 2: Incremental prefix streaming
    assert(wire_kit::verify_split_stream<parse_packet>(valid_packet[..], -1, 5));
    print("STREAM_SLICING: PASS");

    // Pillar 3: Mutation fuzzing
    assert(wire_kit::fuzz_payload<parse_packet>(valid_packet[..], 5000));
    print("MUTATION_FUZZ: PASS");
}

// CHECK-LABEL: === EXAMPLE_PROTOCOL_VERIFICATION ===
// CHECK-NEXT: FRAME_PAYLOAD_LEN: 5
// CHECK-NEXT: STREAM_SLICING: PASS
// CHECK-NEXT: MUTATION_FUZZ: PASS
```

---

## Running LIT tests

### Run all suites in parallel
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\test_lit.ps1 -Jobs 8
```

### Run a specific pattern
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\test_lit.ps1 -Pattern "*h2*"
```

### Verbose tracing
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\test_lit.ps1 -Pattern "verify_wire_framing" -Verbose
```

### Integrated with full test runner
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\test_all.ps1 -Lit -Jobs 8
```
