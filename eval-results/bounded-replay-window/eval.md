# Eval Criteria: explain Technocore's bounded replay window
**Domain:** build
**Date:** 2026-09-01

## Pass criteria (ALL must be true)

1. **Reproducibility**
   - [x] `python3 -m unittest -v` passes from a clean checkout.
   - [x] Running the checked-in bounded-window example twice produces byte-identical JSON and exit codes.

2. **Demonstrability**
   - [x] A synthetic replay whose prior signed record is inside the configured guard byte window is reported with `service_outcome: refused` and the exact guarding nonce.
   - [x] The same replay, after filler moves that record outside the configured guard byte window, is reported with `service_outcome: accepted` while remaining an offline historical-reuse finding.
   - [x] CLI `--explain-window --guard-bytes N` emits the distinction as machine-readable JSON without changing the default CLI schema.

3. **Negative test**
   - [x] Reverting the implementation while keeping tests makes the focused bounded-window tests fail for the expected missing behavior.
   - [x] Restoring the implementation returns the focused tests and full suite to green.

4. **User-spec match**
   - [x] Contribution is on the standalone, non-fork `hnumey31/technocore-nonce-allocator` repository.
   - [x] It addresses the fresh official bounded replay-window trust boundary documented by `f03af147ae5bdee3e14f2c220a50341836393f41`.
   - [ ] Live commit and GitHub Actions CI are verified before state is recorded.

## Fail criteria (ANY = no-go)

- Generic promotion, README padding, cosmetic-only edits, or dependency churn.
- Claims that every historical nonce reuse is rejected by the live service.
- Mocked critical replay-window classification.
- Tests pass without the implementation.
- X and GitHub are both used on the same WIB day.

## Output location

- `eval-results/bounded-replay-window/run-N.json`
- Include command, stdout tail, exit code, criterion result, duration, and artifact paths.
