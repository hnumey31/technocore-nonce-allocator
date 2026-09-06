# Eval Criteria: reject replay-audit state symlinks
**Domain:** security hardening
**Date:** 2026-09-06

## Pass criteria (ALL must be true)

1. **Reproducibility**
   - [ ] `python3 -m unittest -v` passes from a clean checkout.
   - [ ] The focused symlink regression test returns the same result on two runs.

2. **Demonstrability**
   - [ ] A CLI invocation with `--state` pointing to a symlink exits 2.
   - [ ] The symlink and its target's content and mode remain unchanged.

3. **Negative test**
   - [ ] Before the fix, `ReplayAuditTests.test_cli_rejects_state_symlink_without_reading_or_replacing_target` fails because the CLI accepts/follows the symlink.
   - [ ] With the fix restored, the focused test passes.

4. **User-spec match**
   - [ ] The change is substantive Technocore replay-safety/security hardening.
   - [ ] Work is committed and pushed only to the standalone, non-fork repository `hnumey31/technocore-nonce-allocator`.
   - [ ] The pushed commit and changed files are verified through the GitHub API.

## Fail criteria (ANY = no-go)

- State symlinks are followed, read, or replaced.
- A malformed-state error can mask symlink acceptance in the regression test.
- Existing tests regress.
- Test output contains errors or warnings.
- Contribution is pushed anywhere other than `hnumey31/technocore-nonce-allocator`.

## Output location

- `eval-results/reject-replay-state-symlinks/run-N.json`
- Each run records command, exit code, output tail, criteria result, duration, and artifacts.
