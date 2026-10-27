## Description

Provide a concise summary of the change. Link any related issues below.

Fixes # (issue)

## Type of change

- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that breaks backwards compatibility)
- [ ] Performance improvement
- [ ] Refactoring (no functional changes)
- [ ] Documentation update

## Checklist

- [ ] I have run `python tools/test_runner.py --check-only` (or `powershell -ExecutionPolicy Bypass -File .\scripts\test_all.ps1 -CheckOnly`) - all 81 test suites pass cleanly
- [ ] I have formatted modified files with `goose format` (`goose format --check .` reports 0 unformatted files)
- [ ] Any extern declarations follow Goose §7.10 (`extern fn name(...) -> ret = "symbol";`)
- [ ] Zero dynamic memory allocation invariant is maintained on wire parsing and serialization hot paths
- [ ] Commits follow Conventional Commits formatting (`feat:`, `fix:`, `refactor:`, `perf:`, `chore:`)
- [ ] Breaking changes include `!` in the commit prefix (`feat!:`) or a `BREAKING CHANGE:` footer for `release-please`
- [ ] SPDX Apache-2.0 and Copyright headers are present in any new files (`python tools/licensing.py --check`)

## How has this been tested?

Describe how you verified the changes work:

```bash
python tools/test_runner.py --check-only
```
