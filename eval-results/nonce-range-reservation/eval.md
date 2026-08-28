# Eval Criteria: atomic nonce range reservation
**Domain:** build
**Date:** 2026-08-28 (WIB)

## Pass criteria (ALL must be true)

1. **Reproducibility**
   - [ ] `python3 -m unittest -v` passes from a fresh checkout with one command.
   - [ ] Two unchanged full-suite runs produce the same pass count.

2. **Demonstrability**
   - [ ] A real test reserves a contiguous range and proves the next allocation starts after it.
   - [ ] The persisted nonce remains scoped independently by DID and room.

3. **Negative test**
   - [ ] On baseline/reverted production code, the focused range-reservation test fails because the API is absent.
   - [ ] Restoring the implementation makes the focused test and full suite pass.

4. **User-spec match**
   - [ ] Repository is owned by `hnumey31`, is standalone, and is not a fork.
   - [ ] Change materially improves Technocore nonce/replay safety with code, tests, and documentation.
   - [ ] Commit is pushed, visible on GitHub, and its GitHub Actions run succeeds.

## Fail criteria (ANY = no-go)

- Critical nonce behavior is mocked or stubbed.
- Test relies on an external service.
- Range count accepts booleans, zero, negatives, or non-integers.
- State can be partially advanced when validation fails.
- Baseline passes the new focused test.
- GitHub owner/author differs from `hnumey31`, repository is a fork, or CI is not successful.

## Output location

- `eval-results/nonce-range-reservation/run-N.json`
- Include exact command, exit code, stdout/stderr tail, criterion verdicts, elapsed time, and proof paths/URLs.
