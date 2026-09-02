# Eval Criteria: secure nonce-state atomic write
**Domain:** security hardening
**Date:** 2026-09-02

## Pass criteria (ALL must be true)

1. **Reproducibility**
   - [x] `python3 -m unittest -v` passes from a clean checkout.
   - [x] The targeted symlink test gives the same result on two unchanged runs.

2. **Demonstrability**
   - [x] A real filesystem test creates `<state>.tmp` as a symlink to a sentinel file, reserves a nonce, and asserts the sentinel remains unchanged.
   - [x] The resulting nonce state is valid JSON, mode `0600`, and no allocator temporary file remains.

3. **Negative test**
   - [x] With the secure temporary-file implementation reverted, the targeted test fails because the sentinel is overwritten.
   - [x] With the implementation restored, the targeted test passes.

4. **User-spec match**
   - [x] Exactly one substantive contribution is committed and pushed to the standalone, non-fork `hnumey31/technocore-nonce-allocator` repository.
   - [x] Active GitHub identity is verified as `hnumey31` before push, and the remote commit is verified through GitHub.

## Fail criteria (ANY = no-go)

- Critical filesystem behavior is mocked rather than exercised.
- Existing test suite regresses.
- The sentinel target is modified.
- A predictable allocator temporary file remains after a successful write.
- Work is pushed anywhere except `hnumey31/technocore-nonce-allocator`.

## Output location

- `eval-results/secure-atomic-state-write/run-1.json` — RED baseline.
- `eval-results/secure-atomic-state-write/run-2.json` — GREEN implementation.
- `eval-results/secure-atomic-state-write/run-3.json` — negative-test revert.
- `eval-results/secure-atomic-state-write/run-4.json` — restored final verification.
