# Whitelist Engine

Two layers, both consulted at import time (step 1–2 of the trust ladder):

## 1. NSRL RDS (National Software Reference Library)

- Download: https://www.nist.gov/itl/ssd/software-quality-group/national-software-reference-library-nsrl/nsrl-download
  → "RDS Modern (minimal)" set (SQLite distribution since 2022, ~few GB).
- Public domain, same data source Mandiant used for Redline's DefaultWhitelist.
- Build step (`hawk whitelist build`):
  1. Extract MD5 column from the RDS minimal set
  2. Build a Bloom filter (~1.4 bytes/hash @ 0.1% FP rate → ~60 MB for 40M hashes)
  3. Output `nsrl.bloom` + `nsrl.meta.json` (version, count, fp-rate)
- Lookup: O(1) per hash at import. Bloom false-positive rate of 0.1% is
  acceptable because a whitelist FP only *suppresses* a finding for a file
  that is also signed/normal-looking; confirmed-bad IOC hashes are checked
  against an exact-match set BEFORE the whitelist (known-bad always wins).

## 2. Org Baseline

- `hawk baseline create <session.hawk>` run against a KNOWN-CLEAN gold image
  produces `org-baseline.json`: exact SHA256 set + paths + service names +
  scheduled tasks + run keys observed on the clean system.
- Subsequent imports diff against it; baseline matches → TRUSTED.
- This is Hawk's improvement over Redline (Redline had no org-level baseline).

## Order of evaluation (must never change)

```
known-bad IOC hash (exact)   → MALICIOUS  (wins over everything)
NSRL bloom match             → TRUSTED
org baseline exact match     → TRUSTED
→ continue to signer / rules
```
