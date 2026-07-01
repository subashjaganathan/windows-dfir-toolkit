# HawkSuite

[![CI](https://github.com/subashjaganathan/windows-dfir-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/subashjaganathan/windows-dfir-toolkit/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11%2FServer-0078D6)](#)

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
 │  • 53 modules       │  (ZIP +     │  • MRI trust-ladder scoring      │
 │  • raw EVTX/hives/  │   SHA256)   │  • raw parsers (EVTX/prefetch/   │
 │    prefetch/$MFT/   │             │    shimcache/amcache/MFT/USN)    │
 │    $UsnJrnl via VSS │             │  • event rules + IOC matching    │
 │  • no analysis      │             │  • WebView2 UI + HTML report     │
 └─────────────────────┘             └──────────────────────────────────┘
```

**Session format** (`.hawk`): a ZIP containing `manifest.json`,
`artifacts/*.json` (typed raw observations), `raw/` (acquired EVTX, registry
hives, prefetch, `$MFT`, `$UsnJrnl:$J`, SRUM), and `hashes.json` (per-file
SHA256). The container has its own `.sha256` sidecar. This is the authoritative
evidence; everything else is a derived view.

---

## Quick start

### 1. Build a collector package (on the analyst box)
```powershell
.\Collector\Builder\New-HawkCollector.ps1 -Preset comprehensive `
    -CaseNumber CASE-2026-001 -Investigator "you" -OutputPath E:\HawkCollector
```
Presets: `standard` (~10-15 min triage), `comprehensive` (full, incl. raw
hives/MFT/SRUM via VSS), `ioc-search`.

**Single-file build (for isolated / quarantined hosts):** wrap a built package
into one self-extracting, self-elevating `.exe` (no internet, no dependencies -
uses the in-box .NET compiler; bundles any staged `Tools\` memory tool):
```powershell
.\Collector\Builder\New-HawkCollectorExe.ps1 -PackageRoot E:\HawkCollector `
    -OutputExe E:\HawkCollector.exe
```
Copy the one `.exe` to the target and double-click (it prompts for Admin). The
`.hawk` lands beside the `.exe`, falling back to `%SystemDrive%\HawkOutput`.

### 2. Collect (on the target host, elevated)
Copy the package (or the single `.exe`) to the target, then run as
Administrator:
```
RunCollector.bat      (folder package)   -or-   HawkCollector.exe (single file)
```
Produces `CASE-…_HOST_….hawk` next to the package. The collector makes **no
network calls**; on an isolated host it auto-detects the lack of internet,
records it in the manifest (`host.isolated`), and skips online-dependent OS
behavior (certificate revocation lookups) so it never stalls.

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
hawk mft      <hawk.db> [filter] [--deleted]   $MFT file inventory / deleted files
hawk usn      <hawk.db> [filter]        $UsnJrnl change journal (create/delete/rename)
hawk timeline <hawk.db> [from] [to]     timeline (ISO-8601 UTC bounds)
hawk report   <hawk.db|session> [-o f]  self-contained HTML report
```

---

## What the analyzer does

| Stage | Detail |
|-------|--------|
| **Import** | Typed tables for processes/services/tasks/run-keys/startup/WMI/network; generic table for everything else. Unknown timestamps stay `[UNKNOWN]` — never substituted. |
| **Raw parsers** | EVTX (11 curated channels + any other channel kept for Warning+), Prefetch (MAM + SCCA v17-31), Registry hive reader (regf), Shimcache, Amcache, **`$MFT`** (file inventory, resolved paths, `$SI`/`$FN` timestamps, deleted-file recovery), **`$UsnJrnl:$J`** (create/delete/rename change history). |
| **MRI scoring** | Trust ladder first; identity rules skipped for trusted binaries, behavioral rules always run. Per-item graduated score + band (trusted/low/medium/high/critical). Host-role aware. |
| **Event/artifact rules** | Log cleared, Defender detections/RTP-off, suspicious service install, encoded-PS task, script-block convergence, brute-force/password-spray, **lateral movement** (remote/external logons), **injected memory** (private RWX in unsigned procs), **recycle-bin executable deletion**, **API-hidden scheduled tasks** (raw XML), **deleted executables** (`$MFT`). All false-positive-resistant (convergence + trust gating). |
| **IOC matching** | IP/domain/hash indicators from `Configuration/IOC` → critical findings. |
| **Output** | WebView2 UI (worklist, findings, persistence, network, timeline w/ pivot, event logs, execution evidence) + portable HTML report. Timeline includes process/network/persistence/logon/EVTX, plus BAM execution, recent-file access, recycle-bin deletions, and USN file-system changes. |

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

## Collector coverage (53 modules)
Processes, loaded DLLs, **injected memory** (private RWX regions), **loaded
kernel drivers + signatures** (BYOVD surface); services,
scheduled tasks (+ raw XML), run keys, deep-registry persistence, startup,
**GPO startup/logon scripts**, WMI subscriptions; network
connections/listeners/routes/ARP/DNS, named pipes, **WLAN profiles + hosts**,
**outbound RDP history (mstsc)**, **SMB shares / sessions / open files /
mappings**, **remote-access / RMM tools (AnyDesk/TeamViewer/ScreenConnect/
NinjaRMM/Splashtop/… + connection logs)**; local users/groups, logon sessions, **Windows Hello / NGC
enrollment + PassportForWork policy**; Defender/AV status, firewall rules;
certificates, patches, USB history, AppX, BitLocker/TPM, **VSS shadow copies +
restore points**; **BAM/DAM execution**, UserAssist/MRU, **recent files
(LNK/Jump Lists/Recycle Bin)**, PowerShell history; browser/Office/**Outlook +
O365 identity**/cloud artifacts, **WER crash reports**; **SQL Server instances /
ERRORLOG / service accounts**; AD/Kerberoast/LAPS + **NTDS.dit location**
(domain); IIS/firewall logs; WSL/Hyper-V.
Raw acquisition (via VSS): all EVTX channels, registry hives (incl.
**`UsrClass.dat`** for shellbags), Amcache, SRUM, prefetch, **`$MFT`**,
**`$UsnJrnl:$J`**.

**Full physical RAM capture** (volatile-first): the comprehensive preset runs
memory acquisition *before* any disk/VSS activity if an acquisition tool is
staged in the package's `Tools\` folder (`winpmem_mini_x64.exe`, `DumpIt.exe`,
or `MagnetRAMCapture.exe`). With no tool present it skips gracefully. The image
lands in `raw/memory/` (multi-GB; the session grows accordingly).

**Live packet capture** (volatile): the comprehensive preset captures network
traffic passively via the **built-in** `netsh trace` (kernel NDIS capture →
`.etl`, converted to `.pcapng` with `pktmon` when available) — no third-party
tool required. Fixed-duration (`packetCaptureSeconds`, default 120s),
size-capped circular buffer (`packetCaptureMaxMB`, default 500). Output lands in
`raw/network/` for analysis in Wireshark/Zeek. Same approach as the v1 toolkit.

## Not yet implemented (roadmap)
- **YARA / Sigma scanning**; memory-image post-processing (Volatility hand-off).
- **NSRL whitelist data** — `hawk whitelist build` + `Scripts\Get-NsrlWhitelist.ps1`
  are ready; load a NIST NSRL RDS set to cut residual false positives.

> Note: the `$MFT`/`$UsnJrnl`/**SRUM (ESE)** parsers are implemented
> (SRUM via ManagedEsent) and unit/synthetic-validated; full validation on real
> elevated-collection data is recommended before production use.

## License
See `LICENSE`.
