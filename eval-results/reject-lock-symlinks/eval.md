# Eval Criteria: reject nonce lock-file symlinks
**Domain:** security hardening
**Date:** 2026-09-03

## Pass criteria (ALL must be true)

1. **Reproducibility**
   - [x] `python3 -m unittest -v` passes from a clean checkout of this branch.
   - [x] Two consecutive full-suite runs have the same pass count and exit code 0.

2. **Demonstrability**
   - [x] A regression test creates `state.json.lock` as a symlink to a sentinel.
   - [x] Reservation rejects the symlink and leaves sentinel content and mode unchanged.

3. **Negative test**
   - [x] With only the production hardening reverted to baseline, the regression test fails because the operation does not reject the symlink.
   - [x] Reapplying the production hardening makes the regression test and full suite pass.

4. **User-spec match**
   - [x] Change is substantive nonce-safety/security hardening in the standalone `hnumey31/technocore-nonce-allocator` repository.
   - [ ] Commit is pushed and its file/commit artifact is verified via the GitHub API as `hnumey31`.

## Fail criteria (ANY = no-go)

- Test only mocks filesystem behavior.
- Existing nonce allocation behavior regresses.
- Symlink rejection modifies the symlink target.
- Work is pushed anywhere except `hnumey31/technocore-nonce-allocator`.
- Remote commit cannot be verified through GitHub.

## Output location

- `eval-results/reject-lock-symlinks/run-N.json`
- Each run records command, exit code, stdout/stderr tail, result, duration, and artifact paths.
