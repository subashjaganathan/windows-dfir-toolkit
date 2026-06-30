# Contributing to HawkSuite

Thanks for your interest in improving HawkSuite. It's an offline, explainable
Windows DFIR triage tool: a PowerShell collector → `.hawk` evidence package →
.NET analyzer with MRI trust-ladder scoring. Contributions of collector
modules, analyzer parsers, detections, and docs are all welcome.

## Ground rules

- **Collector modules collect raw observations only.** No verdicts, severities,
  or risk scores in collected output — scoring is the analyzer's job. See
  [`Collector/Modules/CONTRACT.md`](Collector/Modules/CONTRACT.md).
- **The collector targets Windows PowerShell 5.1** (no PS 7-only syntax). It
  must be read-only against the target and make no network calls.
- **Forensic soundness first.** Timestamps are UTC; unknown timestamps stay
  null (never substituted). Every binary reference is hashed. Evidence is
  hash-sealed.
- **Parsers must be tolerant:** a missing/corrupt input is a logged no-op, never
  a crash that aborts the rest of the import.

## Before you open a PR

Run the full test suite (no admin required):

```powershell
.\test\Run-AllTests.ps1
```

All five gates must be green: parse-lint, analyzer build, collector modules,
raw parsers, and the end-to-end self-test. CI runs the same script on
`windows-latest` for every push and PR.

## Adding a collector module

1. Create `Collector/Modules/<Category>/<name>.ps1` following the contract
   (`param([Parameter(Mandatory)][string]$SessionRoot, $Config)` first;
   `Export-HawkArtifact ... -Records $records` last; try/catch everywhere;
   graceful-empty; `Get-HawkFileIdentity` / `ConvertTo-HawkUtc`).
2. `Test-Modules.ps1` auto-discovers it — confirm it passes.
3. Update the module count + coverage list in `README.md`.

## Adding an analyzer parser

1. Implement `IRawArtifactParser` in `Analyzer/src/Hawk.Parsers`, register it in
   `RawParsers.cs`, and add its table to `Db.cs`.
2. Add synthetic coverage so it's exercised by `Test-RawParsers.ps1` + CI.

## Commit style

Clear, present-tense messages describing the change and the why. Keep evidence
formats and schema changes backward-compatible where possible.
