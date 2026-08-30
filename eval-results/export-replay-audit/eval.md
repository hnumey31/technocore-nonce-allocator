# Eval Criteria: audit Technocore exports for replay gaps
**Domain:** build
**Date:** 2026-08-30

## Pass criteria (ALL must be true)

1. **Reproducibility**
   - [x] `python3 -m unittest -v` passes from a clean checkout with no third-party dependencies.
   - [x] The same JSONL input produces byte-identical CLI output and exit code on repeated runs.

2. **Demonstrability**
   - [x] A fixture mirroring Technocore's exported signed-record schema identifies the exact later `seq`, DID, previous nonce, and regressed/replayed nonce.
   - [x] A strictly increasing per-DID export prints a clean summary and exits 0.

3. **Negative test**
   - [x] Removing `replay_audit.py` makes the focused audit tests fail.
   - [x] Restoring it makes the full suite pass.

4. **User-spec match**
   - [x] The implementation is substantive nonce/replay functionality in `hnumey31/technocore-nonce-allocator`, not cosmetic documentation.
   - [x] README explains the problem → command → verified result and links immutable upstream commits that retain signatures and add byte-exact export.
   - [x] A malformed JSONL line or malformed signed record fails closed with a nonzero exit and a line-numbered error.

## Fail criteria (ANY = no-go)

- Critical export parsing or replay detection is mocked/stubbed.
- The audit treats different DIDs as sharing one nonce sequence.
- A malformed signed record is silently skipped.
- Test passes with `replay_audit.py` removed.
- CLI result varies for the same input.

## Output location

- `eval-results/export-replay-audit/run-N.json`
- Include command, stdout/stderr tail, exit code, pass/fail per criterion, duration, and artifact paths.
