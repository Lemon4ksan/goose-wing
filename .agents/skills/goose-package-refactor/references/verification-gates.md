# Refactor Verification Gates, Goose Traps, & Schemas

Every refactored package worktree must satisfy all 6 verification gates before producing Commit 1 and Commit 2 for Coordinator merge.

> **Python binary**: Use `python3` on Linux/macOS, or `python` / `py -3` on Windows.

---

## 1. The 6 Verification Gates (`GATE-1` .. `GATE-6`)

### `GATE-1` - Whole-Repo Caller & Test Proof Before Deletion or Rename
- Before deleting any `DEAD_CANDIDATE` or `DEAD_ISLAND_OR_UNREACHABLE`, run `rg -n "\b<symbol>\b" .` across the entire repository (`tests/`, `examples/`, `bench/`, `tools/`, `cli/`, `shim/`, `wing.goose`).
- Before deleting an `UNUSED_FIELD`, check `rg -n "\.<field>\b" .` and struct-literal initialization sites.
- Never delete an entrypoint referenced by `tools/`, `tests/fuzz/`, or `shim/` C wrappers.

### `GATE-2` - Ergonomic Namespace & Facade Compliance
- Every `.goose` file in `<pkg>/` declares `namespace <pkg>;` (public API) or `namespace <pkg>_internal;` (internal helpers). Zero production files inside `<pkg>/` remain in `namespace wing;`.
- Public types and functions drop redundant `<pkg>_` stuttering prefixes where unambiguous, and receiver-first signatures enable UFCS dot-calls without `ns::`.
- Every renamed, moved-to-internal, signature-changed, or deleted `PUBLIC_API` symbol has a complete entry in `api-migration-map.json`.

### `GATE-3` - Strict Dual-Commit Worktree Isolation
- Verify `git diff --name-only <base>..COMMIT_1` touches **ONLY**:
  - `<pkg>/**`
  - `<pkg>/README.md`
  - `<pkg>/api-migration-map.json`
  - Optional dedicated single-package test `tests/<pkg>_test.goose` (only if dedicated 1:1 to `<pkg>`).
- Zero edits in Commit 1 to `wing.goose`, other production packages, shared tests, `examples/`, or `.lit/baseline`.

### `GATE-4` - Goose Invariants, Formatting, & Complexity Gate
Run inside the worktree on `<pkg>/`:
1. `goose format --check <pkg>`
2. `python3 scripts/lint_invariants.py --target-file <file> --check-dead-code --strict-examples` for every `.goose` file in `<pkg>/`
3. `python3 <SKILL_DIR>/scripts/goose_refactor_scanner.py validate <pkg> --ledger <ledger> --migration <pkg>/api-migration-map.json`
4. `goose-lit crap <pkg> --threshold 25.0` (verify no regressions in `uncovered_bce_keep` or unnecessary G-CRAP spikes).

### `GATE-5` - Local Compilation & Test Proof (Commit 2)
- In Commit 2 (temporary verification commit on top of Commit 1 in the worktree), update impacted callers in `wing.goose`, downstream packages, and package tests using `api-migration-map.json`.
- Run `goose check wing.goose`, `python3 tools/test_runner.py --check-only` (or targeted `goose check` on affected tests), and run `goose-lit` on every test file listed in `external_files_impacted` that exercises `<pkg>`.
- Never hand off a Commit 1 that failed compilation or tests in Commit 2.

### `GATE-6` - README Signature Sync
- Update `<pkg>/README.md` examples and API blocks to use the new `<pkg>::` / UFCS APIs and drop internal helpers moved to `<pkg>_internal`.
- Run `python3 scripts/verify_readme_signatures.py` and verify zero mismatches for `<pkg>`.

---

## 2. The 8 Goose Refactor Traps

| Trap # | Common Mistake | Actual Goose Rule / Repo Reality |
| :--- | :--- | :--- |
| **Trap 1** | Writing `namespace wing::dns;` or `namespace wing.dns;`. | Goose rejects nested namespaces with a syntax error. Namespaces are single flat identifiers (`namespace dns;`, `namespace dns_internal;`). |
| **Trap 2** | Trying to hide helpers using `pub fn` vs `fn`. | `pub` does not exist in Goose (`error: top-level declaration expected, found 'pub'`). Use `namespace <pkg>_internal;` to isolate internal helpers. |
| **Trap 3** | Adding pass-through functions in `wing.goose` (`fn wing::foo(a) { return dns::foo(a); }`). | Rejected by `scripts/lint_invariants.py` Rule 1a. Use direct `<pkg>::` calls, UFCS dot-calls, or struct `type` aliases (`type Cache = dns::Cache;`) in `wing.goose`. |
| **Trap 4** | Adding `import <pkg>.*` to every caller file after splitting namespaces. | `import wing;` is transitive in Goose. Callers importing `wing` automatically see `dns::`, `auth::`, `http::`, etc., and UFCS resolves methods on receiver types without qualifiers. |
| **Trap 5** | Trusting generic token counts for common names (`clear`, `reset`, `init`, `verify`, `lookup`). | `goose_refactor_scanner.py` counts plain token matches. Always verify receiver type and namespace with `rg` before treating a generic name as `PUBLIC_API` or `DEAD`. |
| **Trap 6** | Deleting functions called only via UFCS (`obj.method()`) or generic trailing blocks (`F(...)`). | `rg -n "method\("` finds both `method(obj)` and `obj.method()`. Search by bare function name, not just `<ns>::<name>`. |
| **Trap 7** | Replacing `for x in xs` with `for &x in xs` without checking mutability/slice lifetimes. | Fixed-size elements copy in `for x in xs`. `for &x in xs` takes a reference (valid to read or mutate if container is mutable `T&`); check `const` qualifiers so `for &x in const_slice` compiles cleanly. |
| **Trap 8** | Splitting flat `match` tables or adding 1-line helpers to shrink functions. | `lint_invariants.py` forbids 1-line field getters and mechanical helpers, and `.agents/AGENTS.md` forbids splitting flat `match` dispatch tables (`<= 100` lines). |

---

## 3. Canonical JSON Schemas

### 3.1 `api-migration-map.json`
Written by the worker in `<pkg>/api-migration-map.json` and included in Commit 1:
```json
{
  "package": "dns",
  "target_public_namespace": "dns",
  "target_internal_namespace": "dns_internal",
  "symbol_renames": [
    {
      "kind": "struct",
      "old": "wing::DnsCache",
      "new": "dns::Cache"
    },
    {
      "kind": "fn",
      "old": "wing::build_dns_query",
      "new": "dns::build_query",
      "ufcs_receiver": false
    }
  ],
  "signature_changes": [
    {
      "symbol": "dns::lookup",
      "old_sig": "fn dns_cache_lookup(cache: const DnsCache&, domain: const u8[:], qtype: u16, now_sec: i64, out_entry: DnsCacheEntry&) -> DnsCacheStatus",
      "new_sig": "fn lookup(cache: const Cache&, domain: const u8[:], qtype: u16, now_sec: i64) -> const Entry?, Status",
      "caller_rewrite_hint": "Replace out_entry param with tuple destructuring `let entry, st = cache.lookup(domain, qtype, now_sec);`"
    }
  ],
  "removed_public_symbols": [
    {
      "old": "wing::detach_dns_lru",
      "reason": "Moved to dns_internal::detach_lru; only used inside dns/cache.goose"
    }
  ],
  "external_files_impacted": [
    "client/client.goose",
    "tests/lit/lit_dns_and_sockets.goose"
  ]
}
```

### 3.2 Worker Handoff Message (returned to Coordinator)
```json
{
  "package": "dns",
  "worktree_path": "<worktree-root>",
  "branch": "refactor/dns",
  "commit_1_pkg_sha": "abc1234",
  "commit_2_proof_sha": "def5678",
  "migration_map_path": "dns/api-migration-map.json",
  "summary": {
    "files_modified": ["dns/cache.goose", "dns/wire.goose", "dns/README.md"],
    "dead_symbols_deleted": 3,
    "internal_symbols_isolated": 23,
    "api_signatures_fixed": 4,
    "optimizations_applied": 6
  },
  "verification": {
    "goose_format_check": "passed",
    "lint_invariants": "passed",
    "verify_readme_signatures": "passed",
    "commit_2_goose_check": "passed",
    "commit_2_tests": ["tests/lit/lit_dns_and_sockets.goose: passed"]
  }
}
```
