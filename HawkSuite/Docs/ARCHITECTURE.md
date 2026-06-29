# Hawk Suite — Architecture

A modern, open-source replacement for Mandiant Redline (EOL). Same workflow, clean-room implementation.

```
┌─────────────────────────────────────────────────────────────────────┐
│ ANALYST MACHINE                                                     │
│                                                                     │
│  Hawk Analyzer (hawk.exe — .NET 8, single file)                     │
│  ├── Collector Builder UI  → generates portable collector package   │
│  ├── Session Importer      → .hawk → SQLite (hawk.db)               │
│  ├── Parser Engine         → EVTX / Prefetch / Shimcache / Amcache  │
│  │                           / SRUM / MFT parsed at IMPORT time     │
│  ├── Whitelist Engine      → NSRL bloom filter + org baseline       │
│  ├── MRI Scoring Engine    → per-process risk 0–100                 │
│  ├── IOC Matcher           → Sigma / YARA / OpenIOC                 │
│  └── UI (WebView2 window)  → MRI worklist, timeline, pivoting,      │
│                              tagging, HTML report export            │
└─────────────────────────────────────────────────────────────────────┘
                              ▲
                              │  SessionName.hawk  (ZIP container)
                              │
┌─────────────────────────────────────────────────────────────────────┐
│ TARGET HOST (victim machine — USB / network share, no install)      │
│                                                                     │
│  Hawk Collector (pure PowerShell 5.1 — Win7 → Server 2025)          │
│  ├── RunCollector.bat      → elevation + execution policy bypass    │
│  ├── Collector.ps1         → orchestrator (from Run_IR_Collection)  │
│  ├── Modules\*.ps1         → collection-only modules (existing 60+) │
│  └── config.json           → which modules + parameters (preset)    │
└─────────────────────────────────────────────────────────────────────┘
```

## Design rules (learned from Redline teardown)

1. **Collector collects. Analyzer analyzes.** No scoring, no detection logic,
   no HTML on the target host. This is what kills false positives: detection
   runs where the whitelist lives.
2. **Trust ladder before suspicion.** Order of evaluation per artifact:
   NSRL hash match → trusted Authenticode signer → org baseline match →
   expected path/args/user rules → THEN scoring of what remains.
3. **Raw acquisition, deferred parsing.** Collector grabs locked files raw
   (VSS): $MFT, registry hives, EVTX, Amcache.hve, SRUM. Parsing happens at
   import on the analyst machine.
4. **One session = one SQLite DB.** All analysis state (scores, tags, notes,
   IOC hits) lives in hawk.db next to the session. Reports are generated
   from the DB *after* triage, not before.
5. **Schema versioning everywhere.** Every JSON artifact carries
   schemaVersion; the importer refuses unknown majors.

## Redline feature → Hawk equivalent

| Redline                          | Hawk                                   |
|----------------------------------|----------------------------------------|
| Collector Builder (3 types)      | Builder presets: Standard / Comprehensive / IOC-Search |
| .mans session file               | .hawk (ZIP: manifest + JSON + raw artifacts) |
| MRI score + worklist             | MRI engine (Configuration/MRI/*.json)  |
| DefaultWhitelist (676k MD5)      | NSRL RDS bloom filter + org baseline   |
| Whitelist bloom filter           | Same technique, built from NSRL        |
| TimeWrinkle / TimeCrunch         | Timeline pivot windows + field filters |
| IOC Finder (OpenIOC)             | Sigma + YARA + OpenIOC import          |
| XulRunner desktop UI             | WebView2 desktop window (same idea, modern engine) |
| Memoryze integration             | WinPmem acquisition + Volatility3 hand-off (later phase) |

## Legal

No Redline binaries, whitelist data, or configuration content is included.
All rule content is sourced from public documentation (Microsoft docs, NSRL,
SANS posters, MITRE ATT&CK) and original work.
