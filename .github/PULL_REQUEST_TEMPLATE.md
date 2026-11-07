<!--
If you are using AI to make this PR, fill in the below fields.
If purely human authored, use model-id `human`, no effort/prompt needed.

NOTE: please use "frontier" LLMs at high effort only. If you don't you cause the
maintainers more work having to review/redo. Report an issue instead if you
don't have access to these.
-->

model-id: unspecified
effort: low
prompt: find a bug in this repo to fix

## Description

Provide a concise summary of the change and its architectural rationale. Link any related issues or RFC sections below.

Fixes # (issue)

## Type of change

<!-- Remove unchecked -->

- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that breaks backwards compatibility)
- [ ] Performance improvement
- [ ] Refactoring (no functional changes)
- [ ] Documentation update

## Checklist

- [ ] Typecheck and unit suites pass (`just check` / `python tools/test_runner.py --check-only`)
- [ ] Native LIT wire suites and G-CRAP complexity gate (`<= 25.0`) pass (`just lit` and `just gate "<file.goose>" 25`)
- [ ] Code invariants pass with `--strict-examples` (`python scripts/lint_invariants.py --staged --strict-examples`): no pass-through wrappers, trivial getters/setters, or missing parser `// Example:` blocks
- [ ] Modified `.goose` files are formatted (`goose format --check .` reports 0 unformatted files)
- [ ] Modified `.md` files pass prose, 80-column wrap, and format checks (`./tools/bin/goosemarklint check .` and `./tools/bin/goosemarklint fmt --check .`)
- [ ] Zero dynamic memory allocation invariant is maintained on wire parsing and serialization hot paths
- [ ] Commits follow Conventional Commits (`feat:`, `fix:`, `refactor:`, `perf:`, `chore:`) with a linear Git history (no merge commits)
- [ ] Breaking changes include `!` in the commit prefix (`feat!:`) or a `BREAKING CHANGE:` footer for `release-please`
- [ ] SPDX Apache-2.0 and Copyright headers are present in any new files (`python tools/licensing.py --check`)

## How has this been tested?

List the verification commands executed and their results:

```bash
just check
just lit
python scripts/verify_wing_gate.py "<path/to/file.goose>" --max-gcrap 25
```
