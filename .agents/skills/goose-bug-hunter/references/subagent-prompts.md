# Subagent Prompt Contracts (`Full Pipeline Mode`)

Use these prompt templates when dispatching **Hunter** and **Refuter** subagents via `invoke_subagent` (with `TypeName: "research"` or `"self"` in read-only audit mode).

> **Single-Writer Ledger Invariant**:
> Hunter and Refuter subagents **never modify** `coverage-ledger.json` or `findings.json` on disk. They treat all files as read-only and return structured JSON results to the Coordinator via `send_message`. Only the Coordinator updates `coverage-ledger.json` and `findings.json`.

---

## 1. Sliced Hunter Subagent Prompt Template

Assign each Hunter subagent **1 slice** (or up to 2 small adjacent slices totaling $\le 15$ functions) from `coverage-ledger.json`.

```markdown
You are a **Goose Bug Hunter Subagent** auditing slice `<SLICE_ID>` in repository `<REPO_ROOT>`.

### 1. Required References (Read First)
1. Read `file:///.agents/skills/goose-bug-hunter/references/goose-bug-classes.md`.
2. If your assigned functions involve cryptography, authentication, wire protocols, or RFC citations, also read `file:///.agents/skills/goose-bug-hunter/references/crypto-and-protocols.md`.

### 2. Scope & Boundaries
- **Finding Scope (`finding_scope_root`)**: File new candidate bugs ONLY for functions listed in your assigned slice `<SLICE_ID>` inside `<LEDGER_PATH>`.
- **Context Scope (`context_roots`)**: You have read-only access to the entire repository (`<REPO_ROOT>`) to trace callers, callees, struct definitions (`T[..N]`, `T[>..]`, `reusable var`), and upstream guards.
- **Read-Only Rule**: Do NOT edit any repository files or ledger files.

### 3. Assigned Function Units (`<SLICE_ID>`)
<PASTE_SLICE_UNITS_JSON_HERE>

### 4. Mandatory Audit Procedure for Every Unit
For each assigned `unit_id`:
1. Read the complete function body (`start_line..end_line`) and its surrounding struct/constant definitions. Never infer behavior from a function's name.
2. Inspect every attached `static_signal` (`BOUNDED_APPEND_NO_GUARD`, `NARROW_OR_FORCE_CAST`, `BCE_OR_CHECKFREE_RISK`, `UNBOUNDED_LOOP_GROWTH_OR_ALIAS`, `IGNORED_RETURN_TUPLE`, `SATURATING_OR_SIGNED_OVERFLOW`, `REUSABLE_POOL_OR_GLOBAL_STATE`, `EARLY_RETURN_RESOURCE_LEAK`, `SWAR_ARITHMETIC`, `EARLY_EXIT_SECRET_CMP`, `SECRET_NO_ZEROIZE`, `EXTERN_FFI_OR_STUB_RETURN`).
3. Check all 8 Universal Goose Bug Classes (`GOOSE-BUG-1`..`8`), paying special attention to:
   - `.append()` / `.push()` on `T[..N]` without a preceding `guard` on `.len` and `.cap`.
   - Narrowing casts (`as u8`, `as u16`, `as u32`, `as i32`, `as!`), signed overflow (debug abort vs. release wrap), or `mul_sat_u64` / `add_sat_u64` in state/PRNG math.
   - Non-transactional mutations (`idx: i64&`, sequence numbers, table deletes) before validation succeeds, or unintended reference aliasing (`let b = a` on `T[>..]`).
   - Discarded error tuples (`let x, _ =`) or fallback-to-valid enum variants in parsers.
   - `reusable` pool stale-slot access without generation checks, `realloc_slice` offset invalidation, or early `guard` returns leaking acquired slots/resources (Goose has no RAII/`defer`).

### 5. Required Return Format (Send via `send_message`)
Return a single fenced `json` block with this exact structure:
```json
{
  "slice_id": "<SLICE_ID>",
  "unit_results": [
    {
      "unit_id": "U0001",
      "status": "covered",
      "skip_reason": ""
    }
  ],
  "candidates": [
    {
      "candidate_id": "<SLICE_ID>_C01",
      "unit_id": "U0004",
      "file": "path/to/file.goose",
      "lines": "83-98",
      "bug_class": "GOOSE-BUG-2",
      "severity": "P1",
      "title": "Short factual title",
      "entrypoint_to_sink_trace": "Exact file:line call chain from caller to sink",
      "bounds_or_state_math": "Algebraic proof or state transition showing how preceding guards are bypassed",
      "trigger_input": "Concrete input length/bytes that trigger the bug"
    }
  ]
}
```
```

---

## 2. Module-Batched Adversarial Refuter Subagent Prompt Template

Group deduplicated Hunter candidates by file/module into bounded batches of **up to 3–5 candidates per Refuter subagent**.

```markdown
You are an **Adversarial Refuter Subagent** (`fp-check`). You did NOT author these bug candidates. Your job is to rigorously verify or disprove each candidate in your batch using the 6-Gate Refutation Protocol.

### 1. Required Reference (Read First)
Read `file:///.agents/skills/goose-bug-hunter/references/fp-gate-checklist.md` in full (all 6 Gates and all 8 Goose False-Positive Traps).

### 2. Candidate Batch to Verify (3–5 Candidates)
<PASTE_CANDIDATE_BATCH_JSON_HERE>

### 3. Verification Procedure for Each Candidate
For each candidate:
1. **Gate 1 (Source Trace)**: Read the exact `.goose` lines cited and every helper called along the path.
2. **Gate 2 (Upstream Caller Reachability)**: Run `rg -n "<fn_name>\s*\("` across `<REPO_ROOT>` to find all callers. Check whether an upstream parser, framer, or caller guard already prevents the offending input from reaching this function.
3. **Gate 3 (Goose Bounds & Cast Math)**: Write out the exact capacity (`.cap`), length (`.len: i64`), and type width inequalities.
4. **Gate 4 (8 Goose FP Traps)**: Verify the candidate is NOT a false positive caused by misunderstanding Goose semantics:
   - `checkfree fn` is a compile-time BCE guarantee (not a runtime bounds bypass).
   - `T[>..]` lives on a data stack and frees on scope exit (only a universal bug if grown in an outer loop without reset, or if `--profile wing` applies).
   - `thread_fn` gets its own thread-local copy of globals (no shared-memory thread races in Goose).
   - `%` in Goose is Euclidean (`-7 % 3 == 2`).
5. **Gate 5 & 6 (Concrete Impact & Minimal Trigger)**: Assign `confirmed`, `partial`, or `rejected`.

### 4. Required Return Format (Send via `send_message`)
Return a single fenced `json` block with this exact structure:
```json
{
  "verdicts": [
    {
      "candidate_id": "S001_C01",
      "unit_id": "U0004",
      "file": "path/to/file.goose",
      "lines": "83-98",
      "bug_class": "GOOSE-BUG-2",
      "severity": "P1",
      "confidence": "HIGH",
      "verdict": "confirmed",
      "gates_passed": [1, 2, 3, 4, 5, 6],
      "trigger_trace": "Complete file:line trace and algebraic inequality",
      "refutation_notes": "Why upstream callers in context_roots do NOT prevent this input, or why the candidate was downgraded/rejected",
      "proposed_fix": "Minimal zero-allocation .goose guard or state fix",
      "variant_regex": "Optional rg regex to find sibling bugs across the repo (if confirmed)"
    }
  ]
}
```
```
