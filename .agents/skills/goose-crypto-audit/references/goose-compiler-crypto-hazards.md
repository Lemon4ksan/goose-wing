# Goose compiler cryptographic and security hazards (`../goose/src/`)

Verified directly against the local Goose compiler sources in `../goose/src/`.
Cite these exact codegen rules during white-box auditing and `fp-check`
refutation.

## 1. Release `as` casts silently truncate like `as!`

- **Compiler source**: `../goose/src/codegen_nodes.h:345-390`,
  `../goose/src/runtime/runtime.h:107-108`.
- **Behavior**: `GS_RANGE` and `GS_RANGE_U` perform runtime range checks only
  when `-DGS_DEBUG=1` (`goose build --debug`). In default release builds
  (`GS_DEBUG=0`, `-O2`), `as` compiles to an unchecked C cast, identical to
  `as!`.
- **Audit check**: Every cast from `i64` (such as `.len` or parsed varints) to
  `u8`, `u16`, `u32`, or `i32` in TLS/QUIC/ASN.1/JWT length fields must have an
  explicit `guard val >= 0 && val <= MAX` before the cast.

## 2. Debug vs release signed arithmetic differential

- **Compiler source**: `../goose/src/runtime/runtime.h:591-721`,
  `../goose/src/codegen_values.h:598-601`.
- **Behavior**: Signed `+`, `-`, `*`, and unary `-` abort on overflow in
  `--debug` (`GS_DEBUG=1`), but wrap in two's complement in release builds
  (`GS_DEBUG=0`). Unsigned arithmetic wraps modulo $2^w$ in all builds.
- **Audit check**: Look for signed timestamp math (`exp`, `nbf`, `not_after`),
  ASN.1 length additions, and flow-control window math using `i64` without
  `core::add_sat_i64` / `core::sub_sat_i64` or explicit range guards.

## 3. Shift-count masking (`n & (BITS - 1)`)

- **Compiler source**: `../goose/src/runtime/runtime.h:612-626, 673-719`.
- **Behavior**: `gs_shl_*` and `gs_shr_*` mask the shift amount to the operand
  bit width (`n & 63` for `u64`, `n & 31` for `u32`, `n & 7` for `u8`). Thus
  `x << 64` evaluates to `x` (not `0`), and `1 << 32` on `u32` evaluates to
  `1`.
- **Audit check**: Audit bignum/limb arithmetic (`rsa.goose`, `ecdsa.goose`,
  `ed25519.goose`, `x25519.goose`), bit readers, and anti-replay bitmask shifts
  (`1 << delta`) for shift amounts equal to or exceeding operand bit width.

## 4. Short-circuit `&&` and `||` emit secret-dependent branches

- **Compiler source**: `../goose/src/codegen_nodes.h:146-175`,
  `../goose/src/codegen_stmts.h:112-120`.
- **Behavior**: Outside straight-line loops (`StraightCode` without calls or
  control jumps), `a && b` and `a || b` emit C `if (t) { ... }`.
- **Audit check**: Constant-time code must combine secret booleans or masks
  with bitwise `&`, `|`, `^`, and `core::ct_barrier_u8` (`wing_ct_barrier_u8`),
  never `&&`, `||`, or `if` on secret-derived values.

## 5. Variable-time division, modulo, and loop-hoisted `gs_divu_gen`

- **Compiler source**: `../goose/src/runtime/runtime.h:539-573, 765-802`,
  `../goose/src/codegen_values.h:602-605`.
- **Behavior**: `/` and `%` emit hardware division (`divq` or C `/` and `%`),
  and loop-invariant divisors call `gs_divu_gen`, which loops over leading
  zero bits (`while (!(d >> k)) k--;`).
- **Audit check**: Flag any `/` or `%` operating on secret scalars, nonces,
  private exponents, field elements, or secret padding lengths. Note: `%` in
  Goose is Euclidean (always non-negative when divisor > 0); do not confuse
  with C signed `%`.

## 6. Dead-store elimination on secret zeroization

- **Compiler source**: `../goose/src/runtime/runtime.h:428` (`GS_MEMZERO` is
  plain `memset`).
- **Behavior**: Plain Goose loops (`for i in 32 { key[i] = 0; }`) or
  re-assigning `key = [0; 32]` compile to non-volatile stores that GCC/Clang
  `-O2` eliminates before return.
- **Audit check**: Verify all secret buffers (keys, seeds, shared secrets,
  expanded round keys, PRKs, private scalars, decrypted plaintexts on AEAD
  failure) are wiped via `core::secure_zeroize_*` (`wing_secure_zeroize*` in
  `shim/simd.c:991-1014`, volatile writes plus memory barrier) on every return
  path, including early `guard` exits.

## 7. Data-stack residue, implicit value copies, and `defer` limits

- **Compiler source**: `../goose/src/docs/implementation.md`,
  `../goose/src/codegen_stmts.h:40-50`.
- **Behavior**:
  - `T[>..]` data-stack cleanup only rewinds a stack pointer without zeroing
    memory. Secrets placed in `u8[>..]` persist on the data stack unless wiped
    before `.clear()` or scope exit.
  - Passing fixed arrays (`u8[32]`) or fixed structs (`KeySlot`, cipher state)
    by value or iterating `for x in arr` copies secret bytes onto the stack.
    Prefer `const T&` / `T&` and `for &x in arr`.
  - `defer` runs on `return`, `break`, `continue`, and `return E from f`, but
    does not run on `abort`, `assert`, bounds failure, or `exit`.

## 8. Stdlib `os::random_u64` fallback vs fail-closed CSPRNG

- **Compiler source**: `../goose/src/runtime/runtime_os.h:839-868`.
- **Behavior**: `gs_os_random_u64()` silently falls back to non-cryptographic
  `splitmix64(time, clock, pid, stack_addr, counter)` if OS entropy fails.
- **Audit check**: Cryptographic callers (keys, nonces, IVs, TLS random,
  tickets, JTI, OAuth state, ECDSA nonces, ML-KEM coins) must use
  `core::csprng_fill` / `core::csprng_u64` (backed by fail-closed
  `wing_crypto_random_bytes` in `shim/tcp.c:1886`), never `os::random_u64`,
  `WyRand`, or clock/counter seeds. Verify that `sim_rng_is_active()` cannot
  be enabled by untrusted input.

## 9. C-shim FFI boundary (`shim/*.c`)

- **Audit check**: `wing_slice` carries a signed `int64_t len`. Check every
  `extern fn` in `shim/crypto_fusion.c`, `shim/tls_backend.c`, `shim/simd.c`,
  and `shim/tcp.c` for:
  - Negative or zero `len` handling before casting to `size_t`.
  - Integer overflow in bit-length (`len * 8`) or buffer-size arithmetic.
  - Partial overlap between `src` and `dst` slices.
  - Writing decrypted plaintext into `dst` before AEAD tag verification without
    volatile zeroization on tag mismatch.
  - Secret register spills (`WING_ZERO_REGS`, `wing_scrub_stack_1024`).
