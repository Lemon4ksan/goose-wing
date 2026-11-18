---
name: goose-package-refactor
description: "Use when refactoring goose-wing packages in parallel isolated worktrees to split monolithic wing namespaces into ergonomic sub-namespaces, fix API signatures, improve readability, delete dead code, and apply trivial optimizations before merging."
license: Apache-2.0
---

# Goose Package Refactor (`goose-package-refactor`)

A structured, verification-gated refactoring workflow for **`goose-wing`** modeled on [`goose-bug-hunter`](../goose-bug-hunter/SKILL.md). Designed for launching **one worker subagent per package directory in its own isolated git worktree**, followed by a conflict-free Coordinator merge and repo-wide verification pass.

> **Cross-Platform Invocation Note**: Run bundled scripts through the Python interpreter (`python3` on Linux/macOS, `python` or `py -3` on Windows). Never execute `.py` files by bare path in case executable bits are absent. Commands below use POSIX forward slashes (`/`), which work across Linux, macOS, and Windows Git Bash / PowerShell.

---

## 1. Progressive Context Loading & Directory Layout

Load companion references relative to this skill directory (`<SKILL_DIR>`, by default `.agents/skills/goose-package-refactor/`):

- [`references/refactor-catalog.md`](references/refactor-catalog.md) - **Read before editing**: Exact patterns and `.goose` before/after examples for API fixes (`API-1`..`7`), Readability (`READ-1`..`5`), Dead Code (`DEAD-1`..`5`), and Trivial Optimizations (`OPT-1`..`6`).
- [`references/verification-gates.md`](references/verification-gates.md) - **Read before committing**: The 6 Verification Gates, 8 Goose Refactor Traps, and JSON schemas (`refactor-ledger.json`, `api-migration-map.json`).
- [`references/subagent-prompts.md`](references/subagent-prompts.md) - **Read when dispatching subagents**: Copy-paste prompt contracts for Package Worker subagents (isolated worktree) and the Coordinator merge pass.
- [`../goose/references/language.md`](../goose/references/language.md) and [`../../AGENTS.md`](../../AGENTS.md) - Canonical Goose syntax and the 19 static invariants enforced by [`scripts/lint_invariants.py`](../../../scripts/lint_invariants.py).

---

## 2. Ergonomic Namespace Split Standard (`wing` -> `<pkg>` + `<pkg>_internal`)

Goose has **no `pub` visibility keyword** and **no nested namespaces** (`namespace wing::dns;` and `namespace wing.dns;` are compile errors). Namespaces are flat single identifiers, imports in `wing.goose` are transitive, and **UFCS resolves dot-calls in the receiver type's namespace** (so `cache.lookup(...)` works anywhere without typing `dns::`).

Follow these 4 ergonomic rules so splitting `wing` makes call sites shorter rather than noisy:

1. **One public namespace per package folder (never per file) + optional `<pkg>_internal`:**
   - Every public type, constant, and function in `<pkg>/` uses `namespace <pkg>;`.
   - Internal-only helpers (`IN_PKG` only, never part of the package's public contract) move to `namespace <pkg>_internal;` and are excluded from `<pkg>/README.md`.
2. **Keep `wing` as a single-import facade without pass-through wrappers:**
   - `wing.goose` still imports all subsystems so callers write only `import wing;`.
   - Top-level app entrypoints (`wing::Client`, `wing::HttpServer`, `wing::Request`, `wing::Response`, `wing::HeaderMap`) can be re-exported in `wing.goose` as struct/enum `type` aliases (`type Request = http::Request;`) - verified to preserve UFCS and allowed by `lint_invariants.py` Rule 2 (which bans only primitive/slice `type` aliases). Never add pass-through wrapper functions (`lint_invariants.py` Rule 1a).
3. **UFCS-first signatures + drop redundant prefixes:**
   - Put the primary domain struct first (`req: Request&`, `cache: Cache&`, `jar: CookieJar&`) so callers use `obj.method(...)` with zero namespace qualifier.
   - Strip package-word stuttering when moving from `wing::` into `<pkg>::`: e.g. `wing::DnsCache` -> `dns::Cache`, `wing::build_dns_query` -> `dns::build_query`, `wing::CookieSameSite` -> `cookie::SameSite`, `wing::GrpcStatus` -> `grpc::Status`. Keep sub-protocol nouns inside multi-RFC folders (`auth::validate_acme_token`, `auth::verify_jwt`).
4. **Canonical Package Namespace Map:**

| Folder | Public Namespace | Internal Namespace | Notes |
| :--- | :--- | :--- | :--- |
| `core/`, `rfc/`, `wire/` | `core`, `rfc`, `wire` | - | Already split; move `wire/h1_exchange.goose` from `wing` to `wire`. |
| `dns/`, `security/`, `auth/`, `cookie/` | `dns`, `security`, `auth`, `cookie` | `<pkg>_internal` | `cookie_internal` already exists in `cookie/limits.goose`. |
| `http/`, `http2/`, `http3/`, `quic/` | `http`, `http2`, `http3`, `quic` | `http_internal`, `h2_internal`, `h3_internal`, `quic_internal` | Move public frame/conn APIs from `*_internal` into `http2`/`http3`/`quic`; keep low-level tables in `*_internal`. |
| `fingerprint/`, `net/`, `tls/` | `fingerprint`, `net`, `tls` | `<pkg>_internal` | Keep `net_internal`, `tls_internal`; keep `goose_io` if isolated contract. |
| `realtime/`, `client/`, `server/`, `grpc/`, `proxy/` | `realtime`, `client`, `server`, `grpc`, `proxy` | `<pkg>_internal` | Keep `server_internal`; re-export core app structs in `wing.goose`. |

---

## 3. Worktree Isolation & Merge Ownership Rules

To run parallel worktree subagents without 15-way merge conflicts on `client/`, `server/`, `wing.goose`, `tests/`, and `.lit/baseline`:

### Strict Dual-Commit Worktree Pattern
1. **Commit 1 (Mergeable Package Patch - strict write boundary):**
   - Worker edits **ONLY**:
     - `<pkg>/**/*.goose`
     - `<pkg>/README.md` (updated to match new namespace and public signatures)
     - `<pkg>/api-migration-map.json` (temporary handoff map; deleted by Coordinator after merge)
     - **Optional**: dedicated single-package test file `tests/<pkg>_test.goose` if and only if no other package owns it.
   - Worker **MUST NOT** include in Commit 1: edits to other production packages (`wing.goose`, `client/`, `server/`, `proxy/`, `core/`), multi-package integration tests (`tests/fuzz/*`, `tests/lit/*`, `tests/compat_*`), `examples/`, `bench/`, or `.lit/baseline`.
2. **Commit 2 (Temporary Local Proof - never merged directly):**
   - Because `goose check` resolves imports from `wing.goose`, the worker temporarily updates cross-package callers and shared tests in Commit 2 inside its own worktree, runs `goose check` + `goose-lit` + `verify_wing_gate.py`, and proves the refactored `<pkg>` compiles and passes all tests.
   - The worker reports **both** Commit 1 SHA (clean package patch) and Commit 2 SHA (caller reference diff) + `api-migration-map.json`.

---

## 4. The 4-Phase Package Refactor Workflow

### Phase 1: Deterministic Recon (Worker in isolated worktree)
Run the package scanner first (writes temporary ledger/template to the OS temp directory by default so the git tree stays clean):
```bash
python3 <SKILL_DIR>/scripts/goose_refactor_scanner.py scan <pkg>
```
Inspect the generated `refactor-ledger.json` and `api-migration-map.json`:
- Classify every symbol (`PUBLIC_API`, `INTERNAL_CANDIDATE`, `DEAD_CANDIDATE`, `DEAD_ISLAND_OR_UNREACHABLE`, `UNUSED_FIELD`, `REDUNDANT_LEN_FIELD`).
- Note all static signals (`MONOLITHIC_WING_NS`, `C_OUT_PARAM`, `SENTINEL_MINUS_ONE`, `TUPLE_BOOL_FIRST`, `BOOL_TRAP`, `OUT_MUTATION_BEFORE_GUARD`, `MANUAL_ASCII_LOOP`, `MANUAL_PREFIX_LOOP`, `MODULO_POW2`, `VALUE_COPY_LOOP_CANDIDATE`, `MUTABLE_GLOBAL`, `HIGH_GCRAP`).

### Phase 2: Execute the 4 Refactoring Workstreams (Worker in isolated worktree)
Read [`references/refactor-catalog.md`](references/refactor-catalog.md) and apply minimal, semantics-preserving improvements in `<pkg>/`:
1. **API & Namespace (`API-1`..`7`)**: Split `namespace <pkg>;` vs `<pkg>_internal;`, strip stuttering prefixes, make methods UFCS-friendly, convert `-1` sentinels and C-style `out_*` to `(T, bool)` / RVO / `<B>(..., out: B&) -> bool`, fix `out` mutation before `guard`, resolve bool traps, merge duplicate modules/structs.
2. **Readability (`READ-1`..`5`)**: Enforce all 19 invariants in `scripts/lint_invariants.py`, flatten nesting (`<= 3` levels via `guard`), trim loop functions (`<= 65` lines), decouple mixed mutable globals (`g_*`) into explicit context structs where external contracts allow, add `// Example:` on wire parsers, sync `<pkg>/README.md`.
3. **Dead Code (`DEAD-1`..`5`)**: Verify with `rg` across the entire repo (`.`) before deleting dead functions, dead call islands, dead structs/enums/consts, unused struct fields, redundant `*_len` fields next to `T[..N]`, duplicate imports, and stale README entries.
4. **Trivial Optimizations (`OPT-1`..`6`)**: Replace manual byte/ASCII loops with `core::*` & UFCS (`starts_with`, `eq_ascii_fold`, `trim_lws`, `parse_*`, `try_set`), eliminate large struct copies (`let x .= arr[i];`, `for &x in xs`), hoist cheap length/bound guards before expensive loops/hashes, use `& (pow2 - 1)` instead of `% pow2` on unsigned/non-negative values, preserve `checkfree` / BCE.

### Phase 3: Gate Verification & Dual-Commit Packaging (Worker in isolated worktree)
1. Pass all 6 gates in [`references/verification-gates.md`](references/verification-gates.md) (`goose format --check`, `lint_invariants.py --check-dead-code`, `verify_readme_signatures.py`, `api-migration-map.json` completeness, `goose_refactor_scanner.py validate`).
2. Copy the finalized `api-migration-map.json` to `<pkg>/api-migration-map.json`, commit **Commit 1** (strictly `<pkg>/` + `<pkg>/README.md` + `<pkg>/api-migration-map.json`), then create **Commit 2** (temporary cross-package caller fixups) and run `goose check` + `goose-lit` tests covering `<pkg>`, plus `scripts/verify_wing_gate.py`. Return the structured JSON handoff to the Coordinator.

### Phase 4: Coordinator Wave Merge & Repo-Wide Verification (Coordinator)
1. Check `git status` before merging (stash or branch any pre-existing uncommitted work first).
2. Cherry-pick / merge **Commit 1** from each worker worktree in dependency layer order (Layers 0-12 from `wing.goose`).
3. Apply all `api-migration-map.json` entries across `wing.goose` (including struct `type` facade aliases), cross-package callers (`client/`, `server/`, `proxy/`, `cli/`), `tests/`, `examples/`, and `bench/` (referencing workers' Commit 2 diffs where non-trivial).
4. Delete temporary `api-migration-map.json` files, then run full repo gates once:
   - `python3 tools/test_runner.py --check-only`
   - `goose format --check .`
   - `python3 scripts/lint_invariants.py --check-dead-code`
   - `python3 scripts/verify_readme_signatures.py`
   - `python3 scripts/test_lit.py` (and `goose-lit tests`)
   - Update `.lit/baseline` once via `python3 scripts/ratchet.py` / `goose-lit crap` if legitimate complexity shifts occurred.

---

## 5. Quick Reference: The 4 Refactoring Workstreams

| Stream | Focus | High-Yield Targets in `goose-wing` |
| :--- | :--- | :--- |
| **API** | Ergonomic namespace & signatures | `namespace wing;` -> `<pkg>` + `<pkg>_internal`, UFCS first-arg receiver, `-> T, bool` over `-1` / C `out_*`, `<B>(..., out: B&) -> bool`, `guard` before mutating `out`, drop stuttering prefixes, merge duplicate implementations (`gcra` vs `rate_limiter`). |
| **Readability** | Clarity & invariants | Nesting `<= 3` via `guard`, loop functions `<= 65` lines, decouple `var g_*` globals, split god-structs into cohesive sub-structs, `// Example:` contracts, remove stale comments and duplicate imports. |
| **Dead Code** | Zero dead symbols | 0-caller functions, dead call islands, dead structs/enums/consts, write-only or unused struct fields, redundant `*_len` fields next to `T[..N]`, stale `README.md` signatures. |
| **Optimization** | Obvious zero-cost wins | Replace hand-rolled loops with `core::*` / `.starts_with` / `.eq_ascii_fold`, `let x .= arr[i];` & `for &x in xs` instead of copying structs, cheap guards before heavy loops/crypto, `& (pow2 - 1)` instead of `% pow2`, zero inner-loop re-scans. |

---

## 6. Rationalizations to Reject

| Rationalization | Why You Must Reject It |
| :--- | :--- |
| *"Changing `namespace wing;` to `namespace dns;` will force users to write `dns::` everywhere."* | False in Goose. `wing.goose` keeps `import wing;` transitive, UFCS resolves methods like `cache.lookup(...)` without any namespace prefix, and `wing.goose` struct `type` aliases preserve UFCS cleanly. |
| *"I'll add pass-through `fn wing::foo(...) { return dns::foo(...); }` for backwards compatibility."* | Violates `lint_invariants.py` Rule 1a (meaningless pass-through wrapper). Migrate callers cleanly via `api-migration-map.json` and use struct `type` aliases in `wing.goose` only where helpful. |
| *"I'll edit `client/client.goose` and `.lit/baseline` directly in my worktree commit so everything builds."* | Causes 15-way merge conflicts across parallel worktrees. Put cross-package caller edits ONLY in Commit 2 for local testing; Commit 1 touches strictly `<pkg>/` + `<pkg>/README.md`. |
| *"`goose_refactor_scanner.py` marked `parse_foo` as `DEAD_ISLAND`, so I can delete it without `rg`."* | Static token scan is a hint, not proof. Always run `rg -n "\b<symbol>\b"` across the entire repo (and check `tools/`, `tests/`, `examples/`, `shim/`) before deleting. |
| *"I'll split this flat 70-line `match` table into `part1`/`part2` to make it shorter."* | Explicitly forbidden by `.agents/AGENTS.md`: flat dispatch tables up to 100 lines stay whole; never split flat `match` tables artificially. |
| *"I didn't touch behavior, so I don't need to run `goose check` or `goose-lit`."* | Namespace moves, prefix stripping, and dead-code removals silently break callers, UFCS resolution, or BCE. Every worktree must prove compilation and tests via Commit 2 before handoff. |
