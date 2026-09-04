# Eval Criteria: Reject nonce state-file symlinks
**Domain:** security hardening
**Date:** 2026-09-04

## Pass criteria (ALL must be true)

1. **Reproducibility**
   - [ ] `python3 -m unittest discover -v` passes from a clean checkout.
   - [ ] The focused state-symlink test produces the same result on two fixed-input runs.

2. **Demonstrability**
   - [ ] A test creates `state.json` as a symlink to valid attacker-controlled JSON.
   - [ ] Allocation rejects the symlink, leaves its target content and mode unchanged, and does not replace the symlink.

3. **Negative test**
   - [ ] On baseline code, the focused test fails because allocation accepts and replaces the state symlink.
   - [ ] With the hardening restored, the focused test passes.

4. **User-spec match**
   - [ ] The change is substantive Technocore nonce/replay-safety hardening.
   - [ ] Existing regular state-file allocation and all prior tests remain green.

## Fail criteria (ANY = no-go)

- The allocator follows the state symlink even if it later replaces the link.
- The symlink target is modified or has its permissions changed.
- The implementation relies only on a check-then-read `Path.is_symlink()` sequence.
- Any existing test regresses.
- The contribution is not pushed and verified from GitHub.

## Output location

- `eval-results/reject-state-symlinks/run-N.json`
- Each run records command, exit code, stdout/stderr tail, criterion result, duration, and artifact paths.
