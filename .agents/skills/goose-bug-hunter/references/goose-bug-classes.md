# The 8 Universal Goose Bug Classes (`GOOSE-BUG-1` .. `GOOSE-BUG-8`)

This reference defines the 8 canonical bug classes for the Goose programming language (`.goose`). Every class is grounded in Goose's actual compilation, memory, arithmetic, and concurrency semantics.

---

## `GOOSE-BUG-1`: Validation/Crypto/FFI Stubs & Fail-Open Returns

### Goose Language & Systems Mechanism
Functions named `verify_*`, `validate_*`, `authenticate_*`, `decrypt_*`, `open_*`, or `check_*` that return a success constant (`true`, `0`, `Ok`, `CloseNotify`, `ERR_NO_ERROR`) on an unhandled enum branch, empty input (`len == 0`), simulated flag, or stubbed C FFI wrapper instead of rejecting untrusted input.

### Vulnerable `.goose` Pattern
```goose
pub fn verify_cert_signature(cert_der: const u8[:], sig: const u8[:], alg: SigAlg) -> bool {
    guard cert_der.len > 0 && sig.len > 0 else { return false; }
    match alg {
        SigAlg.Ed25519 => {
            return verify_ed25519(cert_der, sig);
        }
        _ => {
            // BUG: Fail-open return on unhandled or stubbed algorithm branch
            return true;
        }
    }
}
```

### Safe Zero-Allocation `.goose` Fix
```goose
pub fn verify_cert_signature(cert_der: const u8[:], sig: const u8[:], alg: SigAlg) -> bool {
    guard cert_der.len > 0 && sig.len > 0 else { return false; }
    match alg {
        SigAlg.Ed25519 => return verify_ed25519(cert_der, sig),
        _ => return false,
    }
}
```

### Variant Hunting Queries (`rg`)
```bash
rg -n "fn\s+(?:verify|validate|authenticate|check|decrypt|open)_" -A 25
rg -n "CloseNotify|return\s+true\s*;"
```

---

## `GOOSE-BUG-2`: Silent Bounded-Array (`T[..N]`) Truncation & Cap Mismatch

### Goose Language & Systems Mechanism
In Goose, `T[..N]` is a fixed-capacity, inline stack/struct array tracked by `.len` and `.cap` (`i64`). Calling `.append(slice)` or `.push(elem)` on a `T[..N]` when `dst.len + src.len > dst.cap` does not grow the buffer onto a heap; without an explicit capacity `guard`, trailing bytes are either silently dropped or cause a capacity violation, or a caller passes a `const u8[:]` slice larger than a callee's internal `u8[..N]` scratch buffer.

### Vulnerable `.goose` Pattern
```goose
pub fn format_bearer_header(token: const u8[:], out: u8[..512]&) -> bool {
    out.clear();
    out.append("Authorization: Bearer ");
    // BUG: Enterprise JWT/OAuth tokens can be up to 4096 bytes; no capacity guard!
    out.append(token);
    out.append("\r\n");
    return true;
}
```

### Safe Zero-Allocation `.goose` Fix
```goose
pub fn format_bearer_header(token: const u8[:], out: u8[..8192]&) -> bool {
    let prefix = "Authorization: Bearer ";
    let suffix = "\r\n";
    guard prefix.len + token.len + suffix.len <= out.cap else {
        return false;
    }
    out.clear();
    out.append(prefix);
    out.append(token);
    out.append(suffix);
    return true;
}
```

### Variant Hunting Queries (`rg`)
```bash
rg -n "\.(?:append|push)\s*\("
rg -n "u8\[\.\.(?:64|128|256|384|512)\]"
```

---

## `GOOSE-BUG-3`: Ring-Buffer/Arena Wrap, Narrow `as!` Casts, Signed Overflow Differential, & SWAR Carry

### Goose Language & Systems Mechanism
1. **Ring-Buffer / Arena Wrap-Around**: Resetting `write_pos = 0` on wrap-around while eviction only inspects `entries[head]` and `break`s when `entries[head].offset >= write_pos`, leaving stale entries overlapping new bytes.
2. **Narrowing Casts (`as` / `as!`)**: Slice `.len` in Goose is strictly `i64`. Casting a length or offset via `as u16`, `as u8`, `as i32`, or force-casting `as!` truncates values exceeding the target width or converts negative `i64` values into huge `u64` numbers.
3. **Signed Overflow Debug/Release Differential & Euclidean `%`**: In Goose, **signed integer overflow aborts in debug builds and wraps in release builds** (`i64`, `i32`), creating a severe differential hazard between test runs and production binaries. Furthermore, `%` in Goose is **Euclidean** (`-7 % 3 == 2`), whereas `rem` is truncating (`-7 rem 3 == -1`).
4. **Saturating Arithmetic in PRNGs / Offsets**: Using `mul_sat_u64` or `add_sat_u64` inside LCG/Xorshift PRNG state transitions or ring offsets clamps the state permanently to `0xFFFFFFFFFFFFFFFF`.
5. **SWAR Byte-Lane Carry**: Performing 64-bit word addition/subtraction (`word + 0x0101...` or `word - 0x0101...`) without masking high bits causes carries to corrupt adjacent byte lanes.

### Vulnerable `.goose` Pattern
```goose
pub fn next_prng(state: u64&) -> u64 {
    // BUG: mul_sat_u64 saturates to u64::MAX on the first large state, locking PRNG output!
    let prod = core::mul_sat_u64(state, 6364136223846793005);
    state = core::add_sat_u64(prod, 1442695040888963407);
    return state;
}
```

### Safe Zero-Allocation `.goose` Fix
```goose
pub fn next_prng(state: u64&) -> u64 {
    // Wrapping unsigned 64-bit arithmetic (`*` and `+` on u64) preserves full LCG period
    state = state * 6364136223846793005 + 1442695040888963407;
    return state;
}
```

### Variant Hunting Queries (`rg`)
```bash
rg -n "\bas!\s*[A-Za-z0-9_]+|\bas\s+(?:u8|u16|u32|i8|i16|i32)\b"
rg -n "\b(?:mul_sat_|add_sat_|sub_sat_)"
rg -n "0x0*101010101010101|0x8080808080808080"
```

---

## `GOOSE-BUG-4`: Non-Transactional Mutation, Pre-Verification Parsing, & `T[>..]` Reference Aliasing

### Goose Language & Systems Mechanism
1. **Non-Transactional Mutation**: Advancing an in-out cursor (`idx: i64&`), incrementing sequence numbers (`seq += 1`), inserting into a replay cache, or deleting an existing table entry *before* verifying that the frame/signature is valid or that the replacement entry fits in capacity.
2. **Accidental Reference Aliasing on `T[>..]` (`let b = a`)**: In Goose, assigning a growable array `let b = a` (where `a: T[>..]`) **binds `b` by reference to `a`** rather than copying its elements (copying requires `copy(a)`). Mutating `b` silently mutates `a`. Conversely, `for x in xs` on fixed-size elements binds a read-only value copy unless written `for &x in xs`.

### Vulnerable `.goose` Pattern
```goose
pub fn consume_prefixed_token(raw: const u8[:], idx: i64&) -> const u8[:], bool {
    guard idx < raw.len && raw[idx] == ('"' as u8) else { return "", false; }
    idx += 1; // BUG: Mutates caller's idx before verifying closing quote exists!
    let start = idx;
    while idx < raw.len && raw[idx] != ('"' as u8) {
        idx += 1;
    }
    guard idx < raw.len else { return "", false; } // idx left at raw.len on error!
    idx += 1;
    return raw[start..idx - 1], true;
}
```

### Safe Zero-Allocation `.goose` Fix
```goose
pub fn consume_prefixed_token(raw: const u8[:], idx: i64&) -> const u8[:], bool {
    guard idx >= 0 && idx < raw.len && raw[idx] == ('"' as u8) else { return "", false; }
    var scan = idx + 1;
    let start = scan;
    while scan < raw.len && raw[scan] != ('"' as u8) {
        scan += 1;
    }
    guard scan < raw.len else { return "", false; } // idx remains unchanged on failure
    idx = scan + 1;
    return raw[start..scan], true;
}
```

### Variant Hunting Queries (`rg`)
```bash
rg -n "\b(?:idx|pos|cursor|offset)\s*:\s*(?:i64|u64)&"
rg -n "\b(?:let|var)\s+[A-Za-z0-9_]+\s*=\s*[A-Za-z0-9_]+\s*;"
```

---

## `GOOSE-BUG-5`: Discarded Error Tuples & Fallback-to-Valid Enum Variants

### Goose Language & Systems Mechanism
1. **Discarded Multi-Return Error Flag**: Goose functions commonly return `(value, ok)` or `(consumed_len, err)`. Destructuring with `let val, _ = parse_foo(...)` discards the failure flag and operates on uninitialized or zero-defaulted values.
2. **Fallback-to-Valid Enum in Parsers**: Mapping unrecognized wire strings or integer codes in a parser's `else` or wildcard `_` branch to an active operational enum variant (e.g., returning `KeyType.OKP` for `"RSA"` or `HashAlg.Sha256` for `"none"`) instead of returning `(Enum.Unknown, false)`.

### Vulnerable `.goose` Pattern
```goose
pub fn parse_key_type(s: const u8[:]) -> KeyType {
    if core::eq_bytes(s, "oct") { return KeyType.Oct; }
    // BUG: Unknown key types like "RSA" silently become Ed25519 OKP keys!
    return KeyType.OKP;
}
```

### Safe Zero-Allocation `.goose` Fix
```goose
pub fn parse_key_type(s: const u8[:]) -> KeyType, bool {
    if core::eq_bytes(s, "oct") { return KeyType.Oct, true; }
    if core::eq_bytes(s, "OKP") { return KeyType.OKP, true; }
    return KeyType.Oct, false;
}
```

### Variant Hunting Queries (`rg`)
```bash
rg -n "\b(?:let|var)\s+(?:[A-Za-z0-9_]+\s*,\s*_|_{1}\s*,\s*[A-Za-z0-9_]+)\s*="
rg -n "fn\s+(?:parse|str_to|decode)_[A-Za-z0-9_]+" -A 20
```

---

## `GOOSE-BUG-6`: Order-Dependent State/Grammar Validation & Normalization Bypasses

### Goose Language & Systems Mechanism
1. **Order-Dependent Loop Validation**: Checking cross-field dependencies inside a loop as fields are encountered (for example, rejecting parameter `B` if parameter `A` has not yet been parsed in a JSON object or header list where field order is unspecified).
2. **Pre-Normalization Security Checks**: Checking hostnames, URLs, paths, or headers against allowlists/blocklists *before* normalizing case (`LOCALHOST`), trailing dots (`metadata.google.internal.`), percent-encoding (`%2e%2e`), or IPv4-mapped IPv6 addresses (`::ffff:127.0.0.1`).

### Vulnerable `.goose` Pattern
```goose
pub fn is_blocked_metadata_host(host: const u8[:]) -> bool {
    // BUG: Bypassed by "169.254.169.254." (trailing dot) or "METADATA.GOOGLE.INTERNAL"
    return core::eq_bytes(host, "169.254.169.254")
        || core::eq_bytes(host, "metadata.google.internal");
}
```

### Safe Zero-Allocation `.goose` Fix
```goose
pub fn is_blocked_metadata_host(raw_host: const u8[:]) -> bool {
    let host = trim_trailing_ascii_dots(raw_host);
    return core::eq_ignore_ascii_case(host, "169.254.169.254")
        || core::eq_ignore_ascii_case(host, "metadata.google.internal");
}
```

### Variant Hunting Queries (`rg`)
```bash
rg -n "eq_bytes\s*\([^,]+,\s*\"(?:http|localhost|127\.|169\.254)"
```

---

## `GOOSE-BUG-7`: `reusable` Pool Stale-Slot / `realloc_slice` Invalidation, Early-Return Leaks, & Global State Hazards

### Goose Language & Systems Mechanism
1. **`reusable var` Pool Stale Indices & `realloc_slice` Offset Moves**:
   - In Goose, `reusable var pool: T[>..] = []` supports `alloc_index(pool)` and `free(pool, idx)`. Calling `free(pool, idx)` puts slot `idx` on a freelist while keeping the underlying array live; holding an old `idx` without a generation counter reads or overwrites a *newly reallocated* item (`use-after-reallocate`).
   - In `reusable[]` slice pools (`alloc_slice`, `realloc_slice`, `free_slice`), `realloc_slice` may relocate the byte run in the backing arena, invalidating any previously saved sub-slice views or offsets.
2. **Early-Return Resource Leaks (No RAII / No `defer`)**:
   - Goose has **no destructors (RAII) and no `defer` statement**. Any function that acquires a pool slot, file descriptor, socket, or native handle and then exits early via `guard ... else { return ...; }` or `return E from f` without explicitly releasing the resource leaks the slot permanently.
3. **Module-Level `var` Globals (Single-Thread Re-Entrancy & `thread_fn` Copy Isolation)**:
   - Goose has **no shared mutable memory between threads**: every `thread_fn` is compiled with its own separate data stack and **its own thread-local copy of every global it uses**.
   - Therefore, mutating a global inside a `thread_fn` expecting `main` to see the change is a logic bug (the mutation affects only the worker's copy). Conversely, on a single thread, sharing a module-level `var g_scratch` buffer across re-entrant callbacks or interleaved state machines corrupts state across calls.

### Vulnerable `.goose` Pattern
```goose
reusable var g_sessions: Session[>..] = [];

pub fn open_authenticated_session(pkt: const u8[:]) -> i64, bool {
    let slot_idx = g_sessions.alloc_index();
    g_sessions[slot_idx].active = true;
    // BUG: Early guard return leaks `slot_idx` in `g_sessions` because Goose has no RAII/defer!
    guard verify_packet_mac(pkt) else {
        return -1, false;
    }
    return slot_idx, true;
}
```

### Safe Zero-Allocation `.goose` Fix
```goose
reusable var g_sessions: Session[>..] = [];

pub fn open_authenticated_session(pkt: const u8[:]) -> i64, bool {
    // Validate untrusted input BEFORE allocating from the reusable pool
    guard verify_packet_mac(pkt) else {
        return -1, false;
    }
    let slot_idx = g_sessions.alloc_index();
    g_sessions[slot_idx].generation += 1;
    g_sessions[slot_idx].active = true;
    return slot_idx, true;
}
```

### Variant Hunting Queries (`rg`)
```bash
rg -n "\b(?:alloc_index|alloc_slice|realloc_slice|free_slice)\b|\breusable\s+var\b"
rg -n "^\s*(?:pub\s+)?var\s+[A-Za-z0-9_]+"
```

---

## `GOOSE-BUG-8`: Unbounded Loop Data-Stack Growth (`T[>..]`), `checkfree` / BCE Preconditions, & $O(N)$ Hot-Path Loops

### Goose Language & Systems Mechanism
1. **Unbounded Loop Data-Stack Growth (`var buf: T[>..]` Outside Loops)**:
   - In Goose, `T[>..]` lives on a compiler-sized data stack (not a heap), and freeing a local `T[>..]` at scope exit is a single stack-pointer store. While a fresh local inside a loop body resets each iteration in standard Goose, declaring `var buf: T[>..]` **outside** a loop and calling `buf.push(...)` or `buf.append(...)` on every iteration without `.clear()` / `.truncate()` grows the data stack without bound until stack overflow.
   - *(Note: In strict zero-allocation networking profiles such as `--profile wing`, declaring `var buf: T[>..]` inside hot loops is also prohibited by project convention.)*
2. **`checkfree fn` & Bounds Check Elimination (BCE) Precondition Faults**:
   - In Goose, `checkfree fn` does **not** disable bounds checks at runtime; instead, it makes any surviving bounds check that the compiler cannot statically eliminate via BCE a **compile error**.
   - Bugs in `checkfree` or BCE-sensitive code arise when a developer forces BCE satisfaction using an unchecked narrowing cast (`idx as! u64`), a bitwise mask that exceeds the actual runtime `.len` of a smaller slice, or a faulty `assert` precondition.
3. **$O(N)$ Rebuilds in Per-Frame Hot Paths**:
   - Rebuilding lookup tables, re-scanning entire buffers from index `0` on incremental stream reads, or performing $O(N^2)$ duplicate-key scans on untrusted wire arrays.

### Vulnerable `.goose` Pattern
```goose
checkfree pub fn read_masked_word(buf: const u8[:], raw_idx: i64) -> u8 {
    // Compiler sees 0..255 due to `& 0xFF`, satisfying BCE if buf is assumed >= 256,
    // or developer used `as!` / bad precondition when caller passes a 16-byte slice!
    let idx = raw_idx & 0xFF;
    assert idx < buf.len; // Aborts at runtime if buf.len <= 255!
    return buf[idx];
}
```

### Safe Zero-Allocation `.goose` Fix
```goose
checkfree pub fn read_masked_word(buf: const u8[:], raw_idx: i64) -> u8, bool {
    let idx = raw_idx & 0xFF;
    guard idx >= 0 && idx < buf.len else {
        return 0, false;
    }
    return buf[idx], true;
}
```

### Variant Hunting Queries (`rg`)
```bash
rg -n "\bcheckfree\b" -A 15
rg -n "var\s+[A-Za-z0-9_]+\s*:\s*[A-Za-z0-9_:]+\[>\.\.\]"
```
