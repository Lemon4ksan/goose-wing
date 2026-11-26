---
name: goose-crypto-audit
description: "Use when auditing custom cryptography, TLS 1.3, QUIC, X.509/ASN.1 DER, authentication protocols (JWT/JWE/DPoP), or network state machines implemented in Goose (.goose) and C shims, or when running black-box conformance testing and white-box source verification."
license: Apache-2.0
---

# Goose cryptographic and protocol security audit (`goose-crypto-audit`)

Adapts `trailofbits/skills` (`audit-context-building`, `constant-time`,
`fp-check`, `variant-analysis`, `differential-review`),
`cloudflare/security-audit-skill` (six-phase externalized-state pipeline with
separated hunters and independent verifiers), and
`performing-cryptographic-audit-of-application` (cryptographic primitive,
protocol, and Wycheproof/NIST/RFC conformance audit) to the Goose compiler and
runtime (`../goose`).

## 1. Companion references (load on demand)

- [`references/goose-compiler-crypto-hazards.md`](references/goose-compiler-crypto-hazards.md):
  Compiler-verified codegen hazards from `../goose/src/` (release `as` vs `as!`,
  signed overflow debug/release divergence, shift-count masking, short-circuit
  `&&`/`||` branching, variable-time division, dead-store elimination on
  zeroization, data-stack residue, `defer` skips on abort, `os::random_u64`
  weak fallback, and C-shim ABI edges).
- [`references/crypto-audit-matrix.md`](references/crypto-audit-matrix.md):
  Four-pillar audit checklist covering asymmetric crypto (X25519, ECDSA,
  Ed25519, RSA, ML-KEM), symmetric/AEAD (AES-GCM, ChaCha20-Poly1305), TLS 1.3
  and QUIC + X.509/ASN.1 DER, and auth (JWT, JWE, DPoP, JWKS), plus black-box
  wire test cases.
- [`../goose-bug-hunter/SKILL.md`](../goose-bug-hunter/SKILL.md) and
  [`../goose-bug-hunter/references/fp-gate-checklist.md`](../goose-bug-hunter/references/fp-gate-checklist.md):
  `goose_audit_scanner.py`, the 8 Goose bug classes, the 6 verification gates,
  and the 8 Goose false-positive traps.

## 2. Dual-track architecture

Run two independent tracks in parallel before synthesizing verdicts:

1. **Track 1: Black-box conformance and negative wire testing.**
   Do not read `.goose` implementation sources during this track. Start the
   target binary locally on `127.0.0.1` and drive an independent client (and
   fault-injecting server for client targets) using standard libraries and RFC,
   NIST ACVP, C2SP CCTV, and Wycheproof vectors. Record exact wire inputs,
   observed alerts or exit codes, oracle timing or error differences, and
   crashes or hangs.
2. **Track 2: White-box six-phase source audit.**
   Follow the Cloudflare six-phase workflow with Trail of Bits context building,
   Goose constant-time codegen checks, and adversarial refutation.

## 3. Six-phase white-box workflow

### Phase 1: Context building and deterministic reconnaissance

Follow Trail of Bits `audit-context-building`: map trust boundaries, entry
points, secret lifetimes, and invariants before reporting any bugs.

1. Run `goose_audit_scanner.py` to produce externalized ledgers outside the git
   working tree:

```bash
python ./.agents/skills/goose-bug-hunter/scripts/goose_audit_scanner.py \
    scan <target_dir> --out-dir <scratch_dir> --profile wing
```

2. Read `references/goose-compiler-crypto-hazards.md` and
   `references/crypto-audit-matrix.md`.
3. Map every boundary where untrusted wire bytes cross into parsers,
   cryptographic primitives, state machines, or C FFI shims (`extern fn`).

### Phase 2: Coverage-led sliced hunting

Partition functions from `coverage-ledger.json` into isolated subagent slices
by security domain (asymmetric/AEAD primitives, TLS/PKI/DER, auth/JWT/JWE/DPoP,
QUIC/framing). Each hunter subagent:

- Inspects full function bodies (`start_line..end_line`) and C shim callees;
  never infers behavior from function names.
- Checks both Goose-specific compiler hazards (`as` silent narrowing in release,
  shift-width masking, `&&`/`||` branch emission, unzeroized early returns,
  data-stack copies, `defer` skipped on abort) and cryptographic invariants
  (Doom Principle, nonce uniqueness, small-order/invalid-curve points,
  signature malleability, canonical DER, constant-time comparisons, algorithm
  confusion).
- Returns structured JSON candidates only; never mutates the ledger on disk
  (Single-Writer Rule).

### Phase 3: Independent candidate validation (`fp-check`)

Every candidate from Track 1 and Track 2 must be verified by an independent
verifier agent that did not author the candidate. Apply all 6 gates from
`goose-bug-hunter/references/fp-gate-checklist.md` plus Goose compiler checks:

1. **Gate 1 (Source trace)**: Exact `file:line` chain from untrusted ingress to
   sink, including C shims if crossed.
2. **Gate 2 (Caller reachability)**: Verify callers across the whole repo via
   `rg`; downgrade to `partial` or `rejected` if every caller enforces the
   precondition.
3. **Gate 3 (Bounds, cast, and release math)**: Prove an input satisfies prior
   guards yet fails under release semantics (`GS_DEBUG=0`, where `as` truncates
   and signed math wraps).
4. **Gate 4 (Goose FP traps)**: Reject claims based on wrong language rules
   (`checkfree` compile-time BCE, Euclidean `%`, thread-local `thread_fn`
   globals, non-secret `==` comparisons).
5. **Gate 5 (Concrete security impact)**: Classify as `confirmed`, `partial`,
   or `rejected` with explicit security impact class (authentication bypass,
   malleability, plaintext oracle, side-channel, state desync, DoS/abort).
6. **Gate 6 (Minimal deterministic reproducer)**: Exact wire vector, Wycheproof
   case, or runnable Goose / `goose-lit` test.

### Phase 4: Variant analysis and differential check

For each confirmed defect, apply Trail of Bits `variant-analysis` (extract root
cause, write exact `rg` query, generalize across sibling modules, triage hits)
and check debug (`--debug` / `-DGS_DEBUG=1`) vs release (`-O2`) behavior.

### Phase 5: Deterministic regression tests

Do not modify production source files during a read-only audit pass. Encode
every confirmed edge case and conformance requirement as deterministic
regression tests in `tests/` and `tests/lit/` (and verify with `goose check`
and `goose run` / `goose-lit`).

### Phase 6: Target-neutral verified report

Emit a structured report separating Track 1 (black-box) and Track 2 (white-box)
results, cross-linking verified `confirmed`, `partial`, and `rejected` records
with exact `file:line` citations, reproduction commands, and recommended fixes.

## 4. Rationalizations to reject

| Rationalization | Counter |
| :--- | :--- |
| "`as u16` checks range at runtime." | False in release builds (`GS_DEBUG=0`). `GS_RANGE` compiles to a bare C cast (`../goose/src/codegen_nodes.h:345`). Require an explicit `guard`. |
| "Zeroing a secret array in a `for` loop clears stack memory." | GCC/Clang `-O2` deletes dead non-volatile stores. Require `core::secure_zeroize_*` (`wing_secure_zeroize` volatile loop + memory barrier). |
| "A `defer` guarantees zeroization on every exit." | `defer` does not execute on `abort`, `assert`, bounds failure, or `exit`. Check for panic paths before secret wipe. |
| "`ok && secret_eq` is constant time because both inputs are `bool`." | Outside `StraightCode` loops, `&&` emits a C `if` branch (`../goose/src/codegen_nodes.h:166`). Use bitwise `&` with `ct_barrier_u8`. |
| "Wycheproof already passes in `tools/crypto_vectors`, so no bugs exist." | Harness vectors test only wired entry points; check TLS/QUIC/JWT/DPoP call sites, unauthenticated buffer writes, and C-shim overlap or truncation edges. |
