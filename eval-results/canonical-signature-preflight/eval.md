# Eval Criteria: canonical Technocore signature preflight
**Domain:** build
**Date:** 2026-08-29

## Grounding

Fresh upstream change: `flop-labs/technocore-chat@b7ad42ed8f7759d29d7fc32d7aa6317e2ff707f8` tightened the signed-write contract so an 86-character unpadded base64url Ed25519 signature has exactly one canonical spelling. For a 64-byte signature, the final character must be one of `A`, `Q`, `g`, or `w`; fifteen non-canonical aliases can decode to the same bytes.

## Pass criteria (ALL must be true)

1. **Reproducibility**
   - [ ] `python3 -m unittest -v` passes from a clean checkout with no third-party dependencies.
   - [ ] Repeating the full suite produces the same test count and verdict.

2. **Demonstrability**
   - [ ] A real 64-byte fixture encodes canonically and is accepted.
   - [ ] All 15 alternate final-character spellings that decode to those same bytes are rejected.
   - [ ] The CLI exits 0 for the canonical spelling and nonzero for a same-bytes alias.

3. **Negative test**
   - [ ] Removing the production implementation makes the focused eval fail for the expected missing-feature reason.
   - [ ] Restoring the implementation makes the focused and full evals pass.

4. **User-spec match**
   - [ ] Contribution is in the standalone, owned, non-fork repo `hnumey31/technocore-nonce-allocator`.
   - [ ] README explains problem → preflight mechanism → verified result and links the immutable upstream commit.
   - [ ] Live commit author is `hnumey31` and GitHub Actions succeeds for its exact SHA.

## Fail criteria (ANY = no-go)

- Formatting, badge, dependency, or README-only change
- Validator accepts any same-bytes non-canonical alias
- Critical behavior is mocked
- Test passes with the production module removed
- GitHub proof is not live or CI does not match the pushed SHA

## Output location

- `eval-results/canonical-signature-preflight/run-N.json`
- Each run records exact command, exit code, stdout/stderr tail, criterion verdict, duration, and artifact paths.
