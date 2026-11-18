# Refactoring Catalog: API, Readability, Dead Code, & Trivial Optimizations

Every change in `<pkg>/` must belong to one of these four workstreams and obey all 19 invariants in [`.agents/AGENTS.md`](../../../.agents/AGENTS.md). Keep behavior, RFC protocol semantics, and security checks intact.

---

## 1. API & Namespace (`API-1` .. `API-7`)

### `API-1`: Split monolithic `namespace wing;` into `<pkg>` + `<pkg>_internal`
- Move public structs, enums, constants, and public functions from `namespace wing;` into `namespace <pkg>;`.
- Move internal-only helpers (`bucket == "INTERNAL_CANDIDATE"`, zero external references verified via `rg`) into `namespace <pkg>_internal;` (or a dedicated `<pkg>_internal` block/file inside `<pkg>/`) and remove them from `<pkg>/README.md`.
- If a sub-package already uses `<pkg>_internal` for everything (e.g. `http2/`, `http3/`, `quic/`), keep low-level tables/plumbing in `*_internal` and move the clean public API types/functions into `namespace http2;` / `namespace http3;` / `namespace quic;`.
- **Anti-bloat rule**: Never create per-file namespaces (`dns_wire`, `auth_acme`). Use at most `<pkg>` and `<pkg>_internal`.

### `API-2`: Strip redundant package-name prefixes on public symbols
Once symbols live in `<pkg>::`, remove stuttering folder prefixes:
- `wing::DnsCache` -> `dns::Cache`, `wing::DnsResponse` -> `dns::Response`, `wing::build_dns_query` -> `dns::build_query`.
- `wing::CookieSameSite` -> `cookie::SameSite`, `wing::CookiePriority` -> `cookie::Priority`.
- `wing::GrpcStatus` -> `grpc::Status`, `wing::GrpcServingStatus` -> `grpc::ServingStatus`.
- Keep sub-protocol qualifiers inside multi-protocol packages (`auth::validate_acme_token`, `auth::verify_jwt`, `auth::verify_dpop_header`).

### `API-3`: UFCS receiver-first parameter ordering
Place the primary domain struct first (`self`-style parameter: `T&` for mutators, `const T&` for readers) so callers use dot-syntax `obj.method(...)` without typing `<pkg>::`:
```goose
// Before
fn generate_sqlite_insert_sql<B>(out: B&, cookie_val: const CanonicalCookie&) { ... }
fn dns_cache_lookup(cache: const DnsCache&, domain: const u8[:], ...) -> ...

// After (in namespace cookie; / namespace dns;)
fn format_sqlite_insert<B>(c: const CanonicalCookie&, out: B&) { ... }
fn lookup(cache: DnsCache&, domain: const u8[:], qtype: u16, now_sec: i64) -> const Entry?, Status { ... }
```
Streaming sink `out: B&` goes **last** (matching `core::` and `http/` conventions).

### `API-4`: Return values (`-> T, bool` / `-> T?`) over C-style out-params & `-1` sentinels
Replace C-style fixed-cap out buffers (`out: u8[..256]&`), dual out-params (`out_body: u8[..256]&, out_len: i32&`), and `-> i32` returning `-1`:
```goose
// Before (auth/acme.goose)
fn acme_http01_path(token: const u8[:], out: u8[..128]&) -> i32 {
    out.clear();
    ...
    guard token_valid && total <= out.cap else { return -1; }
    out.append(rfc::ACME_HTTP01_PREFIX[..]);
    out.append(token);
    return total as i32;
}

// After: generic sink <B>, transactional rollback, canonical bool return
fn build_acme_http01_path<B>(token: const u8[:], out: B&) -> bool {
    let saved_len = out.len;
    var committed = false;
    defer if !committed { out.resize(saved_len); };

    guard acme_validate_token(token) else { return false; }
    guard out.try_append(rfc::ACME_HTTP01_PREFIX[..]) else { return false; }
    guard out.try_append(token) else { return false; }
    committed = true;
    return true;
}
```
- Single fixed/small result: return directly via RVO (`-> u8[..64], bool` or `-> ParsedThing, bool`).
- Tuple order is **always** `(Value, bool)`, never `(bool, Value)`.
- Functions returning `Enum` from string parsing must return `(Enum, bool)` or `Enum.Unknown`/`Enum.Invalid`, never an operational variant fallback.

### `API-5`: Transactional error hygiene (`guard` before `out.clear()`)
Never clear or append to `out: B&` or advance `idx: i64&` before validating preconditions; otherwise guard failures with `defer if !committed { idx = saved_idx; out.resize(saved_len); };`.

### `API-6`: Eliminate boolean traps
Replace consecutive `bool` parameters (`fn foo(a: bool, b: bool)`) with a domain `enum` or options struct (`struct ...Options`).

### `API-7`: Consolidate overlapping modules or duplicate APIs inside `<pkg>`
If two files or structs inside `<pkg>` implement the same capability (e.g. `security/gcra.goose` vs `security/rate_limiter.goose`), check cross-repo callers via `rg`; merge or delete the superseded duplicate instead of keeping two competing APIs.

---

## 2. Readability & Code Geometry (`READ-1` .. `READ-5`)

### `READ-1`: Flatten deep nesting with `guard`
Keep control-flow nesting inside functions `<= 3` levels (`<= 16` spaces indentation; `>= 20` spaces fails `lint_invariants.py`). Invert preconditions into early `guard cond else { return ...; }`.

### `READ-2`: Enforce loop-function size (`<= 65` lines) without micro-fragmenting flat tables
- Extract cohesive inner loop steps into domain-named `inline fn` helpers when a loop function exceeds 65 lines.
- **Never** split flat `match` tables (`<= 100` lines, depth `<= 2`, no loops) into `*_part1` / `*_part2`.
- **Never** add 1-line getters, setters, 0-arg `new_*()` constructors, or pass-through aliases (`lint_invariants.py` Rule 1).

### `READ-3`: Decouple hidden mutable globals (`var g_*`) where local to `<pkg>`
- Check every `var g_*` in `<pkg>` (from `globals` in `refactor-ledger.json`).
- If a mutable global holds request/cache/session state (not process-wide entropy or immutable lookup tables) and only serves callers that already pass a context struct (`Server`, `Session`, `Reactor`), fold it into the owning struct so data flow is explicit.
- Keep thread-local/process-wide entropy pools (`g_tls_entropy_pool`) or hardware slot tables intact unless refactoring the session model explicitly.

### `READ-4`: Separate cohesive sub-configs in god-structs
When a struct mixes unrelated fields across 30+ members, group cohesive subsets into nested sub-structs with defaults (`cache: CacheConfig = CacheConfig { .. }`) instead of adding more flat boolean flags. Check all struct-literal callers before modifying field paths.

### `READ-5`: Hygiene, imports, and `// Example:` contracts
- Remove duplicate `import` lines, unused imports, redundant local re-aliasing (`let a = x; let b = a;`), and obvious comments (`// Parses header`).
- Ensure every wire parser, cursor mutator (`idx: i64&`), and transformer has an accurate `// Example:` block matching `scripts/lint_invariants.py --strict-examples`.
- Sync `<pkg>/README.md` with exact updated namespaces, structs, and signatures (`scripts/verify_readme_signatures.py`).

---

## 3. Dead Code Elimination (`DEAD-1` .. `DEAD-5`)

Always confirm zero callers across the **entire repository** (`.`, including `tests/`, `examples/`, `bench/`, `tools/`, `cli/`, `shim/`) with `rg -n "\b<name>\b"` before deleting:

### `DEAD-1`: Dead single functions & dead call islands
- Delete functions with 0 references (`DEAD_CANDIDATE`) and mutually calling unused islands (`DEAD_ISLAND_OR_UNREACHABLE`) not exposed as public API or tested.
- If a helper is only called by a dead function, delete both together.

### `DEAD-2`: Dead structs, enums, constants, and `type` aliases
- Remove unreferenced `struct`, `enum`, `const`, and `type` declarations (`type Foo = Bar;` outside `wing.goose` facade re-exports).

### `DEAD-3`: Unused or redundant struct fields
- Remove fields marked `UNUSED_FIELD` after verifying with `rg -n "\.<field>\b"` that they are never read.
- Remove `REDUNDANT_LEN_FIELD` shadows (e.g. `key_auth_len: i32` beside `key_auth: u8[..256]`) and use `key_auth.len` directly.

### `DEAD-4`: Dead local variables, dead branches, and dead imports
- Remove unused imports, unreachable `else` branches after unconditional `return`, and variables assigned but never read.

### `DEAD-5`: Stale documentation and phantom signatures
- Delete references in `<pkg>/README.md` to removed or internal-only helpers so `scripts/verify_readme_signatures.py` reports 0 mismatches for `<pkg>`.

---

## 4. Trivial & Safe Optimizations (`OPT-1` .. `OPT-6`)

Only apply optimizations that are locally provable, preserve exact semantics, and keep/improve `checkfree` and G-CRAP:

### `OPT-1`: Replace hand-rolled byte loops with `core::*` / UFCS primitives
- `(b >= 'A' && b <= 'Z') || ...` -> `core::is_ascii_alpha(b)` / `core::is_ascii_alnum(b)` / `core::is_ascii_digit(b)` / `core::is_tchar(b)`.
- Byte-by-byte prefix/suffix/case-fold loops -> `s.starts_with(...)`, `s.ends_with(...)`, `s.eq_ascii_fold(...)`, `s.starts_with_fold(...)`, `s.trim_lws()`, `s.strip_prefix(...)`.
- Manual decimal/hex parsing loops -> `s.parse_u64_dec()`, `s.parse_u32_hex()`, `val.format_u64_dec(out)`.
- Manual big-endian byte shifts -> `core::read_be_u16/u32/u64`, `out.append_u16_be/u32_be`, `core::ByteCursor`, `core::ByteBuilder` (in binary protocols).

### `OPT-2`: Eliminate unnecessary large struct copies (`T&` / `const T&` / `.=` / `for &x in xs`)
In Goose, `=` and `for x in xs` copy fixed-size structs implicitly (and `DnsCacheEntry`, `ClientProfile`, `Request`, `HeaderMap` are multi-KB):
```goose
// Before: copies entire entry struct on every iteration and index
for e in cache.entries { ... }
var cur = cache.entries[i];

// After: 8-byte reference, zero copy
for &e in cache.entries { ... }
let cur .= cache.entries[i];
```
Pass read-only structs (`> 16` bytes) by `const T&` instead of by value.

### `OPT-3`: Cheap preconditions first (early exit before heavy work)
- Check `.len` bounds, empty slices, and prefix equality **before** calling SHA/HMAC/base64 decoding or scanning loops.
- Example: in constant-time prefix+suffix checks, validate `path.len == expected_len` and cheap format bounds before computing hashes or running `core::ct_eq_bytes` (note: never replace secret comparison itself with an early-exit loop!).

### `OPT-4`: Bitwise masking for power-of-2 modulo & `min`/`max` clamping
- On unsigned integers or proven non-negative indices, replace `x % 2`, `x % 64`, `x % 256` with `x & 1`, `x & 63`, `x & 255` (also removes Euclidean `%` branch/div overhead in G-CRAP).
- Replace ternary clamp `if x > N { N } else { x }` with `min(x, N)` and `max(a, b)`.

### `OPT-5`: Avoid repeated scans and redundant buffer clears
- Replace `out.clear()` + unconditional `out.append(...)` failure checks with `out.try_set(src)` (`core/ufcs.goose`) when overwriting a bounded buffer `T[..N]`.
- Replace repeated `find` / `split` scans of the same slice with `s.split_once_byte(...)` or `core::make_byte_tokenizer`.

### `OPT-6`: Preserve `checkfree` / BCE and zero hot-loop growth
- Never move a `T[>..]` allocation inside a loop; hoist and `.clear()` or use bounded `u8[..N]`.
- Keep `guard idx + n <= buf.len` immediately before `buf[idx..idx + n]` so Goose's BCE eliminates bounds checks cleanly.
