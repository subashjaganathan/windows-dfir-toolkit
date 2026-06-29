# HawkSuite

An open-source, Redline-class Windows DFIR triage platform: a dependency-free
PowerShell **collector** that produces a sealed `.hawk` evidence session, and a
.NET 8 **analyzer** (`hawk.exe`) that imports it, scores artifacts with a
false-positive-resistant Malware Risk Index (MRI), parses raw forensic
artifacts, matches IOCs, and produces an interactive UI and a self-contained
HTML report.

Built as a modern replacement for Mandiant Redline (discontinued, no Win11
support). Clean-room implementation — no Redline code or data; the known-good
whitelist is built from NIST NSRL. HawkSuite runs on
**Windows 7 SP1 → Windows 11 / Server 2025**.

---

## Why it exists

The predecessor (`windows-dfir-toolkit`) collected well but its analysis was
noisy: single-signal rules (any `certutil`, any HKCU CLSID, any unsigned binary)
produced wall-to-wall false positives, and its HTML output was inaccurate.

HawkSuite fixes that at the architecture level by separating **collection** from
**analysis** (like Redline):

- **Collector** emits *raw observations only* — no verdicts, no severity.
- **Analyzer** applies a **trust ladder** (known-good hash → org baseline →
  trusted signer → expected-process conformance) and only *scores what
  survives*. Findings require **converging signals**, not one rule.

On a clean reference workstation the analyzer reports mostly **trusted** with a
handful of low/medium items — not a screen of red.

---

## Architecture

```
 TARGET HOST                          ANALYST WORKSTATION
 ┌─────────────────────┐             ┌──────────────────────────────────┐
 │ Hawk Collector      │   .hawk     │ hawk.exe (analyzer)              │
 │ (PowerShell 5.1)    │  ────────►  │  • import → SQLite session db    │
 │  • 22 modules       │  (ZIP +     │  • MRI trust-ladder scoring      │
 │  • raw EVTX/hives/  │   SHA256)   │  • raw parsers (EVTX/prefetch/   │
 │    prefetch via VSS │             │    shimcache/amcache)            │
 │  • no analysis      │             │  • event rules + IOC matching    │
 └─────────────────────┘             │  • WebView2 UI + HTML report     │
                                      └──────────────────────────────────┘
```

**Session format** (`.hawk`): a ZIP containing `manifest.json`,
`artifacts/*.json` (typed raw observations), `raw/` (acquired EVTX, hives,
prefetch), and `hashes.json` (per-file SHA256). The container has its own
`.sha256` sidecar. This is the authoritative evidence; everything else is a
derived view.

---

## Quick start

### 1. Build a collector package (on the analyst box)
```powershell
.\Collector\Builder\New-HawkCollector.ps1 -Preset comprehensive `
    -CaseNumber CASE-2026-001 -Investigator "you" -OutputPath E:\HawkCollector
```
Presets: `standard` (~10-15 min triage), `comprehensive` (full, incl. raw
hives/MFT/SRUM via VSS), `ioc-search`.

### 2. Collect (on the target host, elevated)
Copy the package to the target, then run, as Administrator:
```
RunCollector.bat
```
Produces `CASE-…_HOST_….hawk` next to the package.

### 3. Analyze (on the analyst box)
GUI: double-click `dist\hawk.exe`, **Import Session Data**, pick the `.hawk`,
then click **Generate Report**.

CLI:
```
hawk import   <session.hawk>            import, parse, score → hawk.db
hawk worklist <hawk.db>                 MRI-ranked process worklist
hawk persistence <hawk.db>              MRI-ranked persistence
hawk findings <hawk.db>                 event-rule + IOC findings
hawk events   <hawk.db> [channel] [eid] parsed event-log rows
hawk evidence <hawk.db>                 prefetch / shimcache / amcache
hawk timeline <hawk.db> [from] [to]     timeline (ISO-8601 UTC bounds)
hawk report   <hawk.db|session> [-o f]  self-contained HTML report
```

---

## What the analyzer does

| Stage | Detail |
|-------|--------|
| **Import** | Typed tables for processes/services/tasks/run-keys/startup/WMI/network; generic table for everything else. Unknown timestamps stay `[UNKNOWN]` — never substituted. |
| **Raw parsers** | EVTX (11 channels, curated IDs), Prefetch (MAM + SCCA v17-31), Registry hive reader (regf), Shimcache, Amcache. |
| **MRI scoring** | Trust ladder first; identity rules skipped for trusted binaries, behavioral rules always run. Per-item graduated score + band (trusted/low/medium/high/critical). Host-role aware. |
| **Event rules** | Log cleared, Defender detections/RTP-off, suspicious service install, encoded-PS task, script-block convergence, brute-force/password-spray. |
| **IOC matching** | IP/domain/hash indicators from `Configuration/IOC` → critical findings. |
| **Output** | WebView2 UI (worklist, findings, persistence, network, timeline w/ pivot, event logs, execution evidence) + portable HTML report. |

### Trust data (optional, recommended)
- `hawk whitelist build <NSRL RDS>` → `Configuration/Whitelist/nsrl.bloom`
  (known-good suppression; accepts RDSv3 SQLite, legacy NSRLFile.txt, or
  MD5-per-line).
- `hawk baseline create <gold-image.hawk>` → org baseline (exact-match trust).
- `Configuration/Whitelist/known-bad-md5.txt` → forces MALICIOUS verdict.
- `Configuration/IOC/*.csv|json|txt` → IOC indicators (see `IOC/README.md`).

---

## Tests
```powershell
.\test\Test-Modules.ps1        # parse + execute all collector modules (no admin)
.\test\Test-HawkSelfTest.ps1   # end-to-end: import → score → IOC → report (17 asserts)
.\test\Test-RawParsers.ps1     # EVTX/prefetch/shimcache/amcache parsers
```

## Build
```powershell
$dotnet = "C:\Program Files\dotnet\dotnet.exe"
& $dotnet publish Analyzer\src\Hawk.Analyzer\Hawk.Analyzer.csproj `
    -c Release -r win-x64 --self-contained true `
    -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o dist
```

## Not yet implemented (roadmap)
SRUM (ESE) parsing, YARA/Sigma scanning, memory-image post-processing
(Volatility hand-off). The collector already acquires SRUDB.dat and memory
when configured; analyzer-side parsing of those is future work.

## License
See `LICENSE`.
