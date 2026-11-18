# Subagent Prompt Contracts (`goose-package-refactor`)

Use these templates when launching **one worker subagent per package folder** in isolated worktrees (via `git worktree` or your agent harness's shared worktree mode, e.g. `workspace: "share"`), followed by the Coordinator merge pass.

---

## 1. Package Refactor Worker Subagent (Isolated Worktree)

Launch one worker per package (`dns`, `security`, `auth`, `cookie`, `http`, `http2`, `http3`, `quic`, `fingerprint`, `net`, `tls`, `wire`, `realtime`, `grpc`, `proxy`, `client`, `server`).

```markdown
You are a **Goose Package Refactor Worker** assigned strictly to package `<PKG>` in your isolated git worktree.

Note: Run Python commands via `python3` (Linux/macOS) or `python` / `py -3` (Windows), and resolve `<SKILL_DIR>` to `.agents/skills/goose-package-refactor` (or the installed global skill path).

### 1. Required References (Read First)
1. Read `<SKILL_DIR>/SKILL.md`.
2. Read `<SKILL_DIR>/references/refactor-catalog.md`.
3. Read `<SKILL_DIR>/references/verification-gates.md`.
4. Read `.agents/AGENTS.md` (19 invariants, formatting, G-CRAP limits).

### 2. Phase 1: Deterministic Recon
Run the scanner in your worktree before touching any file (writes to OS temp dir by default so your git tree stays clean):
```bash
python3 <SKILL_DIR>/scripts/goose_refactor_scanner.py scan <PKG>
```
Inspect the reported `ledger` (`refactor-ledger.json`) and `migration_template` (`api-migration-map.json`) paths.

### 3. Strict Worktree Dual-Commit Rules
You MUST create **two clean commits** in your worktree so the Coordinator can merge all packages without conflicts:

1. **Commit 1 (Package-Only Mergeable Patch)**:
   - Allowed files ONLY:
     - `<PKG>/**/*.goose`
     - `<PKG>/README.md`
     - `<PKG>/api-migration-map.json` (copy and complete from `migration_template`)
     - Optionally `tests/<PKG>_test.goose` ONLY if it is dedicated 1:1 to `<PKG>`.
   - FORBIDDEN in Commit 1:
     - Do NOT touch `wing.goose`, other production packages (`client/`, `server/`, `proxy/`, `core/`), multi-package tests (`tests/fuzz/*`, `tests/lit/*`, `tests/compat_*`), `examples/`, `bench/`, or `.lit/baseline`.

2. **Commit 2 (Temporary Compilation & Test Proof - NOT merged directly)**:
   - On top of Commit 1, temporarily update affected callers in `wing.goose`, downstream packages, and `tests/` so your refactored `<PKG>` builds and passes tests.
   - Run `goose check wing.goose` and `goose-lit` on all tests referencing `<PKG>`.
   - Commit those caller fixups as Commit 2 so the Coordinator can inspect the exact caller diff if needed.

### 4. Refactoring Scope inside `<PKG>`
Execute all 4 workstreams from `refactor-catalog.md`:
1. **Namespace & API (`API-1`..`7`)**:
   - Split `namespace wing;` into `namespace <PKG>;` (public API) and `namespace <PKG>_internal;` (internal-only helpers). Never use nested namespaces (`wing::foo` is invalid in Goose) and never create per-file namespaces.
   - Strip redundant `<PKG>_` stuttering prefixes on public symbols, make primary-struct operations UFCS-friendly (receiver first, `out: B&` last), convert `-1` sentinels and C-style fixed `out_*` params to `(T, bool)` / `T?` / `<B>(..., out: B&) -> bool` with transactional `defer if !committed` rollback, fix boolean traps, and merge internal duplicate implementations.
2. **Readability (`READ-1`..`5`)**:
   - Obey all 19 invariants in `scripts/lint_invariants.py`, flatten nesting (`<= 3` levels via `guard`), keep loop functions `<= 65` lines (never split flat `<= 100`-line `match` tables), fold package-local mutable `var g_*` into explicit structs where safe, add missing `// Example:` blocks, and sync `<PKG>/README.md`.
3. **Dead Code (`DEAD-1`..`5`)**:
   - Confirm zero repo-wide callers (`rg -n "\b<sym>\b" .`) before deleting dead functions, dead call islands, dead structs/enums/consts, unused struct fields, redundant `*_len` shadows next to `T[..N]`, and duplicate imports.
4. **Trivial Optimizations (`OPT-1`..`6`)**:
   - Replace manual ASCII/prefix loops with `core::*` & UFCS (`starts_with`, `eq_ascii_fold`, `trim_lws`, `parse_*`, `try_set`), eliminate large struct copies (`let x .= arr[i];`, `for &x in xs`, `const T&`), hoist cheap length guards before heavy loops/crypto, replace unsigned/non-negative `% pow2` with `& (pow2 - 1)`, preserve `checkfree`/BCE.

### 5. Mandatory Verification Before Returning
Before creating Commit 1:
- `goose format --check <PKG>`
- `python3 scripts/lint_invariants.py --target-file <file> --check-dead-code --strict-examples` (on every `.goose` file in `<PKG>`)
- `python3 <SKILL_DIR>/scripts/goose_refactor_scanner.py validate <PKG> --ledger <ledger-path> --migration <PKG>/api-migration-map.json`
- `python3 scripts/verify_readme_signatures.py` (0 errors for `<PKG>`)
- `goose-lit crap <PKG> --threshold 25.0` (no unapproved `uncovered_bce_keep` or G-CRAP regressions)

Before returning (after Commit 2):
- `goose check wing.goose` passes (exit code 0).
- All relevant `goose-lit` tests for `<PKG>` pass (exit code 0).

### 6. Required Handoff Format (Return to Coordinator)
Return a single fenced `json` block matching the Worker Handoff schema in `references/verification-gates.md` with exact `commit_1_pkg_sha`, `commit_2_proof_sha`, `migration_map_path`, summary counts, and observed command results.
```

---

## 2. Coordinator Wave Merge & Cross-Caller Pass

Executed by the Coordinator after all package worktrees return Commit 1 + `api-migration-map.json` + Commit 2:

```markdown
1. Verify clean integration base branch (`git status`). Stash or branch any pre-existing uncommitted work first.
2. Merge or cherry-pick `commit_1_pkg_sha` from each package worktree in dependency layer order:
   - Wave 1 (Layers 0-2): `core`, `rfc`, `dns`, `security`
   - Wave 2 (Layers 3-4): `http`, `cookie`, `http2`, `auth`
   - Wave 3 (Layers 5-8): `fingerprint`, `net`, `tls`, `quic`, `http3`
   - Wave 4 (Layers 9-12): `wire`, `realtime`, `client`, `server`, `grpc`, `proxy`
3. Read all `<PKG>/api-migration-map.json` files (plus workers' `commit_2_proof_sha` diffs as reference):
   - Update `wing.goose` (add struct/enum `type` facade aliases like `type Request = http::Request;` where ergonomic; never add pass-through wrapper functions).
   - Update cross-package call sites (`client/`, `server/`, `proxy/`, `cli/`), shared integration tests (`tests/*`), `examples/`, `bench/`, and `docs/`.
   - Remove temporary `<PKG>/api-migration-map.json` files.
4. Run full repo verification once:
   - `goose format --check .`
   - `python3 tools/test_runner.py --check-only`
   - `python3 scripts/lint_invariants.py --check-dead-code`
   - `python3 scripts/verify_readme_signatures.py`
   - `python3 scripts/test_lit.py`
   - `python3 scripts/ratchet.py` (update `.lit/baseline` once if needed after verifying zero `uncovered_bce_keep` regressions).
```
