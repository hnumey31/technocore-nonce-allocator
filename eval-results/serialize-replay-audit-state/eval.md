# Eval Criteria: serialize persisted replay-audit state
**Domain:** security hardening
**Date:** 2026-09-05

## Pass criteria (ALL must be true)

1. **Reproducibility**
   - [ ] `python3 -m unittest -v` passes from a clean checkout.
   - [ ] The focused concurrency test is deterministic across two consecutive runs.

2. **Demonstrability**
   - [ ] A real replay-audit CLI process blocks while another process owns the state lock.
   - [ ] After the lock owner advances the high-water mark, the waiting CLI reloads it, reports the candidate nonce as a replay, and exits 1.

3. **Negative test**
   - [ ] Before implementation, the focused test fails because the CLI does not wait for the state lock.
   - [ ] Removing the critical lock scope after implementation makes the focused test fail; restoring it makes the test pass.

4. **User-spec match**
   - [ ] Change is nonce/replay-safety security hardening in the standalone `hnumey31/technocore-nonce-allocator` repository.
   - [ ] Tests and concise technical documentation explain that stateful load/audit/save is serialized.
   - [ ] One substantive commit is pushed and its remote GitHub artifact is verified.

## Fail criteria (ANY = no-go)

- Locking only the save operation, allowing two processes to audit stale state.
- Mocked lock or mocked CLI process.
- Existing state can be overwritten before a waiting auditor reloads it.
- Any regression in the full dependency-free test suite.
- Commit targets a fork or repository not owned by `hnumey31`.

## Output location

- `eval-results/serialize-replay-audit-state/run-N.json`
- Each run records command, exit code, stdout/stderr tail, criterion result, duration, and artifact paths.
