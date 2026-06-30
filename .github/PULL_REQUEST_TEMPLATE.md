## What & why

<!-- What does this change and what forensic/quality problem does it solve? -->

## Type
- [ ] Collector module
- [ ] Raw parser
- [ ] Detection / MRI rule
- [ ] Analyzer / report / export
- [ ] Docs / CI / build

## Checklist
- [ ] `.\test\Run-AllTests.ps1` is green locally (all 5 gates)
- [ ] Collector changes collect **raw observations only** (no verdicts/scores)
- [ ] Timestamps are UTC; binary references hashed; read-only; no network calls
- [ ] Updated `README.md` (module count / coverage) if applicable
- [ ] No real/sensitive evidence committed (synthetic samples only)
