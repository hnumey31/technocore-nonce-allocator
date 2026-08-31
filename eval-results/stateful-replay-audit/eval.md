# Eval Criteria: stateful Technocore replay audit
**Domain:** build
**Date:** 2026-08-31

## Pass criteria (ALL must be true)

1. **Reproducibility**
   - [ ] `python3 -m unittest -v` passes from a clean checkout.
   - [ ] Running the two-export example twice from fresh temporary state produces byte-identical JSON output.

2. **Demonstrability**
   - [ ] First clean export (nonce 100) exits 0 and durably records DID high-water 100.
   - [ ] A second export whose first signed record reuses nonce 100 exits 1 and reports line 1, previous_nonce 100, nonce 100.
   - [ ] The state file is dependency-free JSON, atomically replaced, and mode 0600 on Unix.

3. **Negative test**
   - [ ] Removing the stateful audit implementation makes the focused cross-export test fail for the expected missing behavior.
   - [ ] Restoring it makes the focused test and full suite pass.

4. **User-spec match**
   - [ ] Contribution is tied to a concrete replay boundary rather than campaign paraphrase or cosmetic documentation.
   - [ ] Malformed state fails closed without overwriting the prior file.
   - [ ] Existing stateless CLI/API behavior remains compatible.

## Fail criteria (ANY = no-go)

- Mocked/stubbed replay detection.
- State lowers its high-water mark after a replay.
- Malformed state is silently reset.
- Test passes on baseline.
- Output differs across identical clean runs.

## Output location

- `eval-results/stateful-replay-audit/run-N.json`
- Include command, stdout tail, exit code, criterion verdicts, elapsed time, and artifact paths.
