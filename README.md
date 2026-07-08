# Windows DFIR Toolkit v1.0

[![CI](https://github.com/subashjaganathan/windows-dfir-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/subashjaganathan/windows-dfir-toolkit/actions/workflows/ci.yml)

**Professional Windows Incident Response Evidence Collection Platform**

A comprehensive, forensically sound PowerShell toolkit for collecting digital evidence from Windows endpoints during incident response investigations. One command collects all forensic evidence and produces a professional HTML report with chain of custody documentation.

Lightweight, dependency-free, and built for the field: drop it on a target, run one command, walk away with a hashed evidence package. That is all this repository does and it does it well.

> ### Building something bigger? Meet DFIR Hawk
> This toolkit grew up. If you need an enterprise-grade platform (a sealed-evidence
> collector paired with a .NET 8 analyzer that *scores* what it finds), check out the
> successor, **DFIR Hawk**:
>
> - Explainable, false-positive-resistant **MRI** risk scoring
> - Raw artifact parsers: EVTX, Prefetch, Shimcache, Amcache, `$MFT`, `$UsnJrnl`, SRUM
> - **Volatility3 memory analysis** (injected code, hidden processes, hooks)
> - **MITRE ATT&CK**-tagged findings, IOC matching, and a self-contained HTML report
>
> **[github.com/subashjaganathan/dfir-hawk](https://github.com/subashjaganathan/dfir-hawk)**
>
> *This repo remains the original, standalone v1 collection scripts, still fully usable on its own.*

---

## Table of Contents

- [Overview](#overview)
- [What It Does in Plain English](#what-it-does-in-plain-english)
- [Why This Tool](#why-this-tool)
- [Technical Architecture](#technical-architecture)
- [Requirements](#requirements)
- [Installation](#installation)
- [Download Integrity & Code Signing](#download-integrity--code-signing)
- [Quick Start](#quick-start)
- [Run Commands](#run-commands)
- [Complete Script Reference](#complete-script-reference)
- [Volatile Data Coverage](#volatile-data-coverage)
- [Non-Volatile Data Coverage](#non-volatile-data-coverage)
- [Order of Volatility](#order-of-volatility)
- [Standards Coverage](#standards-coverage)
- [AI Attack Detection](#ai-attack-detection)
- [MITRE ATT&CK Coverage](#mitre-attck-coverage)
- [Output Structure](#output-structure)
- [Evidence Integrity](#evidence-integrity)
- [Platform Compatibility](#platform-compatibility)
- [Post-Collection Analysis](#post-collection-analysis)
- [Enterprise Deployment](#enterprise-deployment)
- [Troubleshooting](#troubleshooting)
- [Changelog](#changelog)
- [Known Issues and Workarounds](#known-issues-and-workarounds)
- [License](#license)
- [Credits](#credits)
- [Testing](#testing)
- [Contributing](#contributing)
- [Acknowledgements](#acknowledgements)

---

## Overview

The Windows DFIR Toolkit is a PowerShell-based forensic evidence collection suite designed for incident response investigations on Windows endpoints. It collects volatile and non-volatile digital evidence in a single execution, following RFC 3227 order of volatility, and produces forensically sound output with SHA256 integrity verification and chain-of-custody supporting metadata.

> **On admissibility:** admissibility is decided by a court, not by a tool. This toolkit is
> *designed to support* a forensically sound process — per-file hashing, an independently
> verifiable manifest, and provenance metadata — but the actual chain of custody is a human
> and organizational process (documented handoffs, storage, and access control) that the tool
> cannot replace. Treat the embedded metadata as *supporting* chain of custody, not as a
> substitute for it.

```
One command. 63 scripts. Complete forensic evidence collection including AI attack detection.
```

**What it produces:**

- Structured JSON evidence files with embedded chain of custody
- SHA256 integrity hash per evidence file
- Evidence manifest covering all collected artifacts
- Professional HTML incident response report with 15 sections and risk scoring
- Unified forensic timeline across all artifact types with severity levels
- IOC extraction file with VirusTotal enrichment and priority submission
- SIEM-ready CSV export for Splunk, Sentinel, and Elastic
- Live network packet capture with automatic PCAP conversion
- AI attack detection report with context-aware malicious vs legitimate classification

---

## What It Does in Plain English

When a company gets hacked, an incident responder must answer six questions:

```
1. Who got in?
2. How did they get in?
3. What did they do inside?
4. What did they steal or break?
5. When did all of this happen?
6. Are they still inside?
```

To answer these questions, the investigator needs evidence from the compromised machine. This toolkit collects all of that evidence in one command in about 18 minutes.

Without this toolkit an experienced investigator manually running commands would take **2 to 3 days** to collect the same evidence. With this toolkit a junior analyst can collect complete forensic evidence on their first day.

### The Real-World Use Case

```
Monday 9:00 AM   Company calls. Ransomware found on server.
Monday 9:18 AM   Analyst runs toolkit. 881 MB of evidence collected.
Monday 9:19 AM   Analyst opens HTML report. Risk score: CRITICAL 65/100.
Monday 9:20 AM   Timeline shows first suspicious PowerShell at 2 AM Friday.
Monday 9:21 AM   IOC report flags 3 malicious hashes on VirusTotal.
Monday 9:22 AM   Investigation begins. Attacker identified.

Without toolkit: Still collecting evidence manually through Wednesday.
```

---

## Why This Tool

### Comparison With Existing Tools

| Tool | Problem | This Toolkit |
|------|---------|-------------|
| **CrowdStrike Falcon** | $150/endpoint/year, vendor lock-in | Free, MIT license, no vendor |
| **Microsoft Sentinel** | $2.46/GB/day, requires Azure | Free, runs on the machine itself |
| **Magnet AXIOM** | $3,500/seat, forensic workstation needed | No extra hardware required |
| **EnCase** | $3,500/seat, training required | Zero training, one command |
| **Velociraptor** | Requires server, agent deployment, training | Single PowerShell file, nothing to install |
| **KAPE** | Separate download, GUI, steep learning curve | Built on PowerShell already on every Windows machine |
| **Manual investigation** | 2-3 days, expert knowledge required | 18 minutes, junior analyst can run it |
| **Scattered open source scripts** | No chain of custody, no reporting, no IOC enrichment | 63 scripts + report + timeline + IOC in one command |

### The Three Things No Other Free Tool Does Together

**1. Zero Dependency**
```
Every other tool requires:
  - Separate agent or binary download
  - Network connectivity to a collection server
  - Installation or configuration
  - Training

This toolkit requires:
  - Nothing. PowerShell 5.1 is already on every Windows machine since 2016.
  - Extract zip. Run one command. Done.
```

**2. Integrity + Provenance Metadata Out of the Box**
```
Every JSON output file contains:
  - SHA256 hash of the evidence file
  - NTP-verified timestamp
  - Investigator name
  - Case number
  - Tool version
  - Hostname

This is the metadata that SUPPORTS chain of custody and lets a recipient prove
integrity (re-verify with Verify-Evidence.ps1). Chain of custody itself is the
documented human handling of the evidence - this metadata strengthens it, it
does not replace it. Commercial tools charge thousands for equivalent tooling.
```

**3. End to End in One Command**
```
Collection   63 scripts in RFC 3227 order of volatility
Analysis     IOC extraction and VirusTotal enrichment
Reporting    Professional HTML report with risk score and MITRE mapping
Timeline     Unified MACB forensic timeline across all artifact types
Integrity    SHA256 manifest of all evidence files

No other free tool does all five in one command.
```

### Who Uses This Type of Tool

```
Blue Team / SOC Analysts     Responding to security alerts
Incident Responders          Investigating confirmed breaches
Digital Forensics Examiners  Building legal cases
Penetration Testers          Post-exploitation evidence
IT Security Teams            Proactive threat hunting
Law Enforcement              Digital crime investigation
MSSP / Managed Security      Client incident response
```

### Market Context

```
Enterprise IR Tools (annual cost):
  CrowdStrike Falcon       $150/endpoint/year
  Microsoft Sentinel       $2.46/GB/day
  Axonius                  $50,000+/year
  Magnet AXIOM             $3,500/seat
  EnCase                   $3,500/seat

Free Alternatives (limitations):
  KAPE                     Complex, no chain of custody, no reporting
  Velociraptor             Needs server, training required, complex setup
  Eric Zimmerman tools     Individual tools only, no integrated workflow
  Various PS scripts       Scattered, no reporting, no IOC enrichment

Windows DFIR Toolkit:
  Free. MIT License.
  Zero dependencies.
  Court-ready evidence.
  Professional HTML report.
  End to end in one command.
```

**Core advantages:**

- Zero external dependencies - pure PowerShell 5.1 built into every Windows machine
- No installation required - extract and run
- Read-only by default - disk, registry and event artifacts are never modified. The only
  state-changing actions are explicit live-response operations: memory acquisition loads a
  signed WinPmem driver, packet capture starts an ETW/netsh trace, and an optional Windows
  Defender exclusion (opt-in via DFIR_ADD_AV_EXCLUSION=1). All are clearly delineated.
- Verifiable evidence integrity - SHA256 on every evidence file (raw and structured) in a
  master manifest, NTP-verified timestamps, investigator binding, and an independent
  re-verification tool (Verify-Evidence.ps1)
- OS-aware - auto-adapts collection for Workstation vs Server
- Runs on air-gapped networks - no internet required for core collection
- RFC 3227 order of volatility - RAM captured first, then volatile state, then disk/registry

---

## Technical Architecture

### Design Principles

```
Native API first        : CIM/WMI, .NET framework, COM objects, registry
Zero dependencies       : No external modules, no third-party libraries
Atomic writes           : No partial evidence files ever written
Parallel-safe           : Each script is fully independent
Fail-safe execution     : One script failure never stops the rest
Read-only by default    : Disk/registry/event artifacts never modified; live-response
                          actions (memory driver, packet-capture trace, opt-in AV exclusion)
                          are the only state changes and are explicit
```

### Performance Engineering

- Pre-built hashtables for O(1) process lookups instead of O(n) loops
- Single WMI call for process table shared across scripts
- SHA256 hash cache to avoid recomputing the same binary
- Generic List over array concatenation for large datasets
- Event log FilterHashtable queries instead of post-filter Where-Object
- Depth-limited, files-only scans scoped to staging/document folders (ADS, Mark-of-the-Web,
  macro documents, AI model files) instead of unbounded full-profile recursion

### Evidence Integrity Pipeline

```
Collection -> SHA256 hash -> .hash.json file -> Evidence manifest -> Manifest hash
```

Every artifact file receives an individual SHA256 hash stored in a companion `.hash.json` file. A master evidence manifest aggregates all file hashes and is itself SHA256 hashed, creating a tamper-evident chain.

### OS-Aware Collection

The toolkit auto-detects the operating system at runtime and adapts:

| Feature | Workstation Mode | Server Mode |
|---------|-----------------|-------------|
| Prefetch | Collected | Fallback to RecentFileCache |
| Browser history | Chrome, Edge, Firefox | IIS access logs |
| SRUM database | Full collection | Full collection |
| File share events | Not applicable | Events 4663, 5140, 5145 |
| DFS replication | Not applicable | Collected |

---

## Requirements

### Minimum Requirements

| Requirement | Detail |
|-------------|--------|
| Operating System | Windows 10 1607+, Windows 11, Server 2016/2019/2022 |
| PowerShell | 5.1 (built-in on all supported OS versions) |
| Privileges | Local Administrator |
| Disk Space | 2 GB minimum, 10+ GB recommended for full collection with RAM dump |
| RAM | No additional requirement |

### Recommended

- Run as Domain Administrator for full Active Directory artifact collection
- Exclude toolkit folder from Windows Defender before running
- Internet access for WinPmem auto-download (RAM dump only)
- VirusTotal API key for IOC enrichment (free tier available)

### Optional Tools

Place in the `Tools\` folder before running:

| Tool | Purpose | Source |
|------|---------|--------|
| winpmem_mini_x64.exe | Live RAM capture | github.com/Velocidex/WinPmem/releases |
| etl2pcapng.exe | ETL to PCAP conversion | github.com/microsoft/etl2pcapng/releases |

Both tools are auto-downloaded from GitHub if not present and internet is available.

---

## Installation

**Step 1  -  Download**

Download `windows-dfir-toolkit-v1.0.zip` from the releases page.

**Step 2  -  Extract**

Extract to a local folder. Avoid network drives for performance.

```
Recommended locations:
  C:\DFIR\
  C:\Users\[investigator]\Desktop\dfir-toolkit\
```

**Step 3  -  Add AV Exclusion (Recommended)**

```powershell
Add-MpPreference -ExclusionPath "C:\path\to\dfir-toolkit"
```

Remove after collection:

```powershell
Remove-MpPreference -ExclusionPath "C:\path\to\dfir-toolkit"
```

**Step 4  -  Set Execution Policy**

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
```

---

## Download Integrity & Code Signing

**Verify what you downloaded before you run it on a target.** Every release ships a
`.sha256` file next to each artifact. Confirm the hash matches before use:

```powershell
# Compare the printed hash to the value in HawkWindowsCollector.exe.sha256 from the release
Get-FileHash .\HawkWindowsCollector.exe -Algorithm SHA256

# Or verify the source zip
Get-FileHash .\windows-dfir-toolkit-v1.0.zip -Algorithm SHA256
```

The authoritative SHA256 for each artifact is published in the **release notes** and in the
`.sha256` sidecar file on the [Releases page](https://github.com/subashjaganathan/windows-dfir-toolkit/releases).
If the hash does not match, do not run it.

### About the signature (self-signed)

The `HawkWindowsCollector.exe` is **Authenticode-signed with a self-signed certificate**
(`CN=DFIR-Hawk`), which proves file integrity but is **not** chain-trusted by a public CA. This is
a deliberate, honest choice for a free open-source tool. Consequences:

- **Windows SmartScreen may warn** ("Windows protected your PC") the first time it runs. This is
  expected for any unsigned/self-signed binary, not a sign of tampering. To proceed on a host you
  trust: **More info -> Run anyway** (after you have verified the SHA256).
- The PowerShell scripts themselves are plain text — you can (and should) read them before running.
  Nothing is obfuscated.

**For an exe without SmartScreen warnings**, rebuild and sign it with a CA-issued code-signing
certificate on your own machine (the source is identical — you are just signing it yourself):

```powershell
.\Build\Build-Exe.ps1 -SignThumbprint <your-code-signing-cert-thumbprint>
```

Options for a trusted certificate: **Microsoft Azure Trusted Signing** (low-cost, CA-backed),
or an **OV/EV code-signing certificate** from a CA such as Sectigo, DigiCert, or SSL.com (EV
certificates earn SmartScreen trust immediately). Prefer running the plain PowerShell scripts
directly if you would rather not deal with signing at all.

---

## Quick Start

```powershell
# Step 1 - Open PowerShell as Administrator

# Step 2 - Navigate to toolkit
cd "C:\path\to\dfir-toolkit"

# Step 3 - Add AV exclusion
Add-MpPreference -ExclusionPath (Get-Location).Path

# Step 4 - Set case metadata
$env:DFIR_CASE = "IR-2026-001"
$env:DFIR_INV  = "InvestigatorName"
$env:DFIR_DAYS = "30"

# Step 5 - Allow execution
Set-ExecutionPolicy Bypass -Scope Process -Force

# Step 6 - Run full collection
.\Run_IR_Collection.ps1

# Step 7 - View results
explorer C:\IR_Collection
```

Expected runtime: 15 to 30 minutes depending on system size and data volume.

---

## Run Commands

### Full Collection

```powershell
.\Run_IR_Collection.ps1
```

### Save to External Drive (USB / Hard Disk)

```powershell
# Save directly to USB drive
.\Run_IR_Collection.ps1 -OutputPath "E:\IR_Collection"

# Save to external hard disk
.\Run_IR_Collection.ps1 -OutputPath "D:\Cases\IR-2026-001"

# Save to network share
.\Run_IR_Collection.ps1 -OutputPath "\\FileServer\IR\Cases\IR-2026-001"
```

### With Case Metadata

```powershell
$env:DFIR_CASE = "IR-2026-001"
$env:DFIR_INV  = "InvestigatorName"
$env:DFIR_DAYS = "30"
.\Run_IR_Collection.ps1
```

### Single Phase

```powershell
.\Run_IR_Collection.ps1 -Phase System
.\Run_IR_Collection.ps1 -Phase Network
.\Run_IR_Collection.ps1 -Phase EventLogs
.\Run_IR_Collection.ps1 -Phase Persistence
.\Run_IR_Collection.ps1 -Phase Memory
.\Run_IR_Collection.ps1 -Phase Execution
.\Run_IR_Collection.ps1 -Phase FileSystem
.\Run_IR_Collection.ps1 -Phase Credentials
.\Run_IR_Collection.ps1 -Phase ActiveDirectory
.\Run_IR_Collection.ps1 -Phase ThreatHunting
.\Run_IR_Collection.ps1 -Phase Reporting
.\Run_IR_Collection.ps1 -Phase NetCapture
```

### Skip Specific Modules

```powershell
# Skip heavy modules for quick triage
.\Run_IR_Collection.ps1 -Skip Loaded_DLLs,RAM_Dump,Browser

# Skip browser and WSL
.\Run_IR_Collection.ps1 -Skip Browser,WSL_HyperV
```

### Single Script Directly

```powershell
# Run any individual script standalone
.\Scripts\Network\Network_Connections.ps1
.\Scripts\Memory\RAM_Dump.ps1
.\Scripts\EventLogs\Security_EventLog.ps1
.\Scripts\Reporting\Generate_IR_Report.ps1
```

### IOC Enrichment with VirusTotal

```powershell
$env:VT_API_KEY = "your-virustotal-api-key"
.\Scripts\Reporting\IOC_ThreatIntel.ps1
```

### Network Packet Capture

```powershell
# Default 5 minute capture
.\Scripts\Network\Network_Packet_Capture.ps1

# Custom duration
.\Scripts\Network\Network_Packet_Capture.ps1 -Duration 600 -MaxSizeMB 1000
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| DFIR_OUTPUT | Output directory path | C:\IR_Collection |
| DFIR_CASE | Case number for chain of custody | CASE-YYYYMMDD-HHMMSS |
| DFIR_INV | Investigator name | Current Windows username |
| DFIR_DAYS | Event log lookback days | 30 |
| VT_API_KEY | VirusTotal API key | None (prompts if missing) |
| DFIR_WINPMEM_SHA256 | Known-good WinPmem hash to pin/verify before RAM capture | None (unverified, warns) |
| DFIR_COPY_PAGEFILE | Set to `1` to raw-capture pagefile/hiberfil/swapfile via VSS (large) | 0 (metadata only) |
| DFIR_ADD_AV_EXCLUSION | Set to `1` to auto-add a Defender exclusion (modifies state) | 0 (guidance only) |
| DFIR_PACKAGE | Set to `0` to skip sealing the evidence ZIP | 1 (package) |
| DFIR_PACKAGE_MAXMB | Per-file size ceiling for ZIP embedding | 1024 |

---

## Complete Script Reference

### System (2 scripts)

| Script | Data Collected | Investigation Use | Attacks Detected |
|--------|---------------|-------------------|-----------------|
| System_Info | OS version, hardware, uptime, NTP sync, network adapters, domain role | Establish case baseline, verify clock accuracy | Unauthorized system changes, VM detection |
| Patch_Level | Installed hotfixes, update history, pending critical patches | Identify unpatched vulnerabilities, determine exploit entry point | CVE exploitation, EternalBlue, PrintNightmare, ZeroLogon |

### Network (5 scripts)

| Script | Data Collected | Investigation Use | Attacks Detected |
|--------|---------------|-------------------|-----------------|
| ARP_Entries | ARP cache, IP to MAC mappings | Identify rogue devices, detect network impersonation | ARP spoofing, MITM, rogue gateway |
| DNS_Cache | Recently resolved domains, record types, TTL | Identify C2 domains, DGA patterns | C2 beaconing, DNS tunneling, DGA malware |
| Network_Connections | All TCP/UDP connections with owning process and path | Identify active C2 channels, unauthorized listeners | Reverse shells, C2 beacons, backdoors, exfiltration |
| Network_Advanced | WiFi profiles, RDP history, proxy config, clipboard history | Physical location history, credential exposure | WiFi theft, RDP brute force, proxy-based C2 |
| Network_Packet_Capture | Live kernel-level network capture via netsh, auto-converted to PCAP | Capture active C2 traffic, exfiltration in progress | All network-based attacks, live C2 communication |

**Packet Capture Method:**
Uses `netsh trace start capture=yes` with no explicit ETW providers. Specifying providers switches netsh into event-logging mode and suppresses actual packet capture, so the toolkit deliberately omits them to capture real packets. The trace status is verified as Running before the capture window begins, and if netsh cannot start a packet capture on the host, the script skips the wait and records metadata instead of hanging.

**PCAP Conversion Methods (in priority order):**
1. pktmon etl2pcap (built-in Windows 10 2004+)
2. etl2pcapng auto-downloaded from Microsoft GitHub (handles all traffic types)
3. ETL file retained for manual conversion if both methods fail

### Event Logs (4 scripts)

| Script | Data Collected | Investigation Use | Attacks Detected |
|--------|---------------|-------------------|-----------------|
| Security_EventLog | 39 event types including logon, account management, process creation, Kerberos | Reconstruct attacker timeline, identify compromised accounts | Pass-the-hash, credential stuffing, lateral movement |
| System_EventLog | Service installs, driver loads, crashes, Defender, RDP, BITS, AppLocker | Detect malicious service installation, defender tampering | Service persistence, driver rootkits, ransomware |
| PowerShell_EventLog | Script block logs, module logs, obfuscated commands, PS history | Reconstruct attacker PowerShell commands, fileless malware | PowerShell Empire, Cobalt Strike, AMSI bypass |
| EventLogs_Raw_Export | 29 raw EVTX files for offline analysis | Independent verification, SIEM import, Hayabusa analysis | All event-based attacks |

### Persistence (6 scripts)

| Script | Data Collected | Investigation Use | Attacks Detected |
|--------|---------------|-------------------|-----------------|
| Registry_RunKeys | 11 registry auto-start locations | Identify malware auto-start mechanisms | Malware persistence, RAT installation |
| Scheduled_Tasks | All tasks with command, trigger, privilege, last run | Identify attacker-created tasks | Task-based persistence, SYSTEM privilege abuse |
| Windows_Services | All services with binary path, hash, signature | Detect malicious services | Service persistence, PSExec artifacts |
| Startup_Folder | User and system startup folder items | Identify startup malware | Malware persistence, RAT startup |
| WMI_Persistence | WMI event filters, CommandLine and ActiveScript consumers | Detect fileless WMI persistence | WMI backdoors, APT persistence, Cobalt Strike |
| Scheduled_Task_XML | Raw XML of every scheduled task | Find obfuscated commands invisible in parsed output | Encoded task payloads, hidden persistence |

### Registry (4 scripts)

| Script | Data Collected | Investigation Use | Attacks Detected |
|--------|---------------|-------------------|-----------------|
| Registry_Execution_Artifacts | BAM, UserAssist, ShimCache, MRU lists | Prove execution of deleted files | Anti-forensics, deleted tool execution |
| Registry_Deep_Persistence | IFEO, SSP, AppCert DLLs, Port Monitors, Time Providers, Shellbags | Find advanced persistence missed by standard tools | Accessibility backdoors, DLL hijacking, credential capture |
| GPO_Cache_Scripts | Applied GPO logon scripts from SYSVOL cache | Detect attacker-modified group policy scripts | GPO abuse, domain-wide persistence |
| Registry_Hive_Export | Raw SYSTEM, SOFTWARE, SAM, SECURITY, Amcache, and per-user NTUSER/UsrClass hives | Enable offline parsing with RegRipper/Registry Explorer; offline password-hash analysis | Registry-based persistence, credential theft, anti-forensics |

### Defense Evasion (4 scripts)

| Script | Data Collected | Investigation Use | Attacks Detected |
|--------|---------------|-------------------|-----------------|
| Firewall_Rules | All firewall rules, per-profile state | Identify rules added to allow C2 traffic | Firewall bypass, C2 allowlisting |
| AV_EDR_Status | All registered AV products, Defender status, quarantine, 14 EDR agents | Determine if protection was disabled before attack | AV tampering, EDR bypass, pre-ransomware disabling |
| Defender_Scan_History | Full detection timeline, quarantine items, disabled events | Reconstruct what Defender saw and when | AV evasion, partial detection, missed threats |
| Anti_Forensics | Event-log clearing (1102/104), disabled log channels, PowerShell-logging/Defender/AMSI tampering, USN journal deletion, prefetch disablement, audit-policy changes | Detect attempts to destroy evidence and blind detection | Log clearing, logging tamper, anti-forensics (T1070, T1562) |

### Privilege (2 scripts)

| Script | Data Collected | Investigation Use | Attacks Detected |
|--------|---------------|-------------------|-----------------|
| Local_Users_Groups | All accounts, group memberships, last logon, SID | Identify backdoor accounts, unauthorized admin additions | Account creation persistence, privilege escalation |
| Logon_Sessions_Deep | All logon sessions with source IP, auth type, duration, brute force detection | Map who logged in from where and when | Unauthorized access, credential reuse, pass-the-hash |

### Credentials (2 scripts)

| Script | Data Collected | Investigation Use | Attacks Detected |
|--------|---------------|-------------------|-----------------|
| Credential_Artifacts | CredMgr, Kerberos tickets, LSASS PPL state, WDigest, DPAPI keys | Assess credential exposure risk | Credential dumping, pass-the-hash, Mimikatz |
| LSA_Secrets_Metadata | Service account credential metadata, cached domain credential count | Identify stored credentials attackers can extract offline | LSA secrets dumping, offline registry attacks |

### Certificates (1 script)

| Script | Data Collected | Investigation Use | Attacks Detected |
|--------|---------------|-------------------|-----------------|
| Certificate_Store | All certificate stores, rogue root detection, expired certs with private keys | Detect rogue CAs installed for MITM | SSL interception, malicious code signing, trust poisoning |

### Memory (4 scripts)

| Script | Data Collected | Investigation Use | Attacks Detected |
|--------|---------------|-------------------|-----------------|
| Named_Pipes | All named pipes with C2 framework pattern matching | Detect active C2 frameworks communicating via pipes | Cobalt Strike, Metasploit, Sliver, PSExec |
| Loaded_DLLs | All DLLs per process with hash, signature, load path | Detect injected or hijacked DLLs | DLL injection, DLL hijacking, process hollowing |
| RAM_Dump | Full physical memory capture via WinPmem (optional hash-pin via DFIR_WINPMEM_SHA256) | Extract decrypted malware, credentials, encryption keys | Fileless malware, injected shellcode, ransomware keys |
| Pagefile_Hiberfil | pagefile/hiberfil/swapfile config + metadata; optional VSS raw capture (DFIR_COPY_PAGEFILE=1) | RAM-capture fallback; recover paged-out secrets and a full hibernation memory image | Fileless malware, credentials paged to disk, anti-memory-forensics |

### Execution (4 scripts)

| Script | Data Collected | Investigation Use | Attacks Detected |
|--------|---------------|-------------------|-----------------|
| Running_Processes | All processes with parent PID, command line, hash, signature | Identify malicious processes, masquerading | Process injection, hollow processes, C2 agents |
| Collect_Prefetch | All prefetch files with timestamps and hash | Prove execution of deleted files | Anti-forensics, deleted tool execution |
| SRUM_PowerShell_History | SRUM database, PS command history, Windows Timeline | Long-term execution and network activity reconstruction | Slow and low attacks, historical C2 activity |
| PS_Transcript_Collection | Full PowerShell session transcripts if transcription enabled | Complete record of every PS command during attack | All PS-based attacks with full output |

### File System (4 scripts)

| Script | Data Collected | Investigation Use | Attacks Detected |
|--------|---------------|-------------------|-----------------|
| FileSystem_Artifacts | LNK files, malware drops, ADS, Zone.Identifier | Reconstruct user activity, detect hidden payloads | Phishing file execution, hidden payload delivery |
| MFT_USN_Collection | MFT, USN Journal, LogFile from all NTFS volumes | Prove file existence after deletion | Anti-forensics, file deletion cover-up, ransomware |

**MFT Collection Methods (in priority order):**
1. VSS shadow copy path (if VSS exists)
2. robocopy /B backup mode (no VSS needed - works on live systems)
3. esentutl /vss (fallback)
4. Metadata only with offline extraction note
| Backup_VSS_Deep | Shadow copy inventory, VSS deletion events, backup history | Detect ransomware preparation, backup deletion evidence | Ransomware, vssadmin delete shadows, data destruction |
| AppX_UWP_Apps | Windows Store apps, sideloaded packages, developer mode state | Detect malicious store apps, unauthorized packages | Malicious UWP apps, sideloaded malware |

### USB and Devices (1 script)

| Script | Data Collected | Investigation Use | Attacks Detected |
|--------|---------------|-------------------|-----------------|
| USB_Device_History | Every USB ever connected, serial numbers, kernel drivers, WER crash dumps | Detect unauthorized data exfiltration via physical media | USB exfiltration, BadUSB, malicious device insertion |

### Lateral Movement (1 script)

| Script | Data Collected | Investigation Use | Attacks Detected |
|--------|---------------|-------------------|-----------------|
| Lateral_Movement | SMB sessions, shares, RDP config, WinRM, PSExec traces, hosts file | Reconstruct attacker movement between systems | SMB lateral movement, RDP hijacking, PsExec, Impacket |

### Threat Hunting (3 scripts)

| Script | Data Collected | Investigation Use | Attacks Detected |
|--------|---------------|-------------------|-----------------|
| ThreatHunting | COM hijacks, LOLBAS hits, Defender exclusions, UAC, PATH hijacking | Proactive hunting across multiple attack surfaces | Living-off-the-land, COM hijacking, UAC bypass |
| IIS_WebShell_Detection | Recently modified web files in IIS wwwroot with signature matching | Identify web shells for persistent server access | Web shell installation, ProxyShell, ProxyLogon |
| AI_Attack_Detection | Local LLM tools, AI model files, high-entropy PS scripts, prompt injection, AI-assisted credential attacks, AI API DNS entries | Detect AI-assisted attacks and unauthorized AI tool usage | AI-generated malware, LLM-assisted attacks, prompt injection, AI credential stuffing |

### Browser (1 script)

| Script | Data Collected | Investigation Use | Attacks Detected |
|--------|---------------|-------------------|-----------------|
| Browser_Artifacts | Chrome/Edge/Firefox history DBs, extensions with permissions | Reconstruct web activity, identify malicious extensions | Phishing, credential harvesting, malicious downloads |

### Email and Office (2 scripts)

| Script | Data Collected | Investigation Use | Attacks Detected |
|--------|---------------|-------------------|-----------------|
| Email_Office_Artifacts | Outlook PST/OST, macro settings, trusted locations, Jump Lists | Identify phishing delivery, malicious macro execution | Spear phishing, macro malware, VBA exploitation |
| Office365_Exchange | Inbox rules, auto-forward config, Outlook accounts, BEC risk indicators | Detect Business Email Compromise, unauthorized forwarding | BEC, inbox rule persistence, mail exfiltration |

### Cloud (1 script)

| Script | Data Collected | Investigation Use | Attacks Detected |
|--------|---------------|-------------------|-----------------|
| Cloud_Artifacts | OneDrive, Teams, Azure/AWS/GCP credential artifacts | Detect cloud-based exfiltration, exposed credentials | Data exfiltration via cloud, credential theft, token abuse |

### Virtualization (1 script)

| Script | Data Collected | Investigation Use | Attacks Detected |
|--------|---------------|-------------------|-----------------|
| WSL_HyperV_Artifacts | WSL distros, bash history, Hyper-V VMs, Docker containers | Detect attackers hiding activity inside VMs or WSL | VM-based AV evasion, WSL malware hiding, container escape |

### Platform Security (2 scripts)

| Script | Data Collected | Investigation Use | Attacks Detected |
|--------|---------------|-------------------|-----------------|
| TPM_SecureBoot_BitLocker | TPM, Secure Boot, BitLocker, Device Guard, VBS, HVCI | Assess platform integrity, detect firmware tampering | Bootkit, firmware implants, BitLocker ransomware |
| WindowsHello_ModernAuth | Azure AD join, Hello PIN/biometric, NGC keys, MSA accounts | Detect unauthorized authentication mechanism changes | Credential provider backdoor, AAD account takeover |

### Active Directory (4 scripts)

| Script | Data Collected | Investigation Use | Attacks Detected |
|--------|---------------|-------------------|-----------------|
| ActiveDirectory_Artifacts | Domain controllers, GPOs, Kerberos config, domain sessions | Assess domain security posture, detect policy abuse | GPO abuse, Kerberos attacks, domain enumeration |
| LAPS_Status | LAPS deployment, password rotation policy, local admin password age | Identify machines sharing same local admin password | Lateral movement via shared credentials, pass-the-hash at scale |
| Kerberoasting_Evidence | Event 4769 RC4 TGS requests, burst analysis, AS-REP roasting, AD SPNs | Identify accounts vulnerable to offline password cracking | Kerberoasting, service account credential theft |
| DCSync_Detection | Event 4662 replication GUIDs, DCSync candidates, PS tool signatures, AD ACLs | Detect accounts performing unauthorized domain replication | DCSync, Golden Ticket creation, Mimikatz dcsync |

### Application (1 script)

| Script | Data Collected | Investigation Use | Attacks Detected |
|--------|---------------|-------------------|-----------------|
| SQL_Server_Artifacts | SQL instances, error logs, xp_cmdshell events, firewall exposure, service accounts | Detect SQL injection exploitation, command execution via SQL | SQL injection, xp_cmdshell abuse, SQL lateral movement |

### Reporting (4 scripts)

| Script | Data Collected | Investigation Use | Attacks Detected |
|--------|---------------|-------------------|-----------------|
| Generate_IR_Report | Reads all evidence JSONs, produces risk-scored HTML report | Deliver professional findings to management, legal, or client | Summary across all detected attack techniques |
| Timeline_Builder | Merges all artifact timestamps into unified MACB timeline | Answer what happened and when across all evidence | Attack chain reconstruction, dwell time analysis |
| Verify-Evidence | Re-hashes every file in the manifest and checks the manifest's own hash | Prove an evidence set is unchanged since collection (integrity at handoff / in court) | Evidence tampering, corruption, incomplete transfer |

**Timeline Features:**
- Severity levels: CRITICAL, HIGH, MEDIUM, INFO
- Search and filter by severity and category
- All artifact types mapped with verified field names
- First and last event timestamps shown
- Top categories summary panel
- Handles both string and DateTime objects from JSON
| IOC_ThreatIntel | Submits hashes, IPs, domains to VirusTotal API | Instantly flag known malware without manual lookup | Known malware identification, threat actor attribution |

**IOC Collection - Scans ALL 60 evidence files for:**
- External IPs from network connections, logon events, brute force
- Domains from DNS cache, PS scripts, RDP history
- SHA256 hashes from processes, services, DLLs, web shells
- Suspicious items from Defender, DCSync, Kerberoasting, web shells

**VT Submission - Priority order:**
1. Suspicious process and DLL hashes first
2. Brute force and C2 IPs next
3. Remaining hashes and domains last

### Infrastructure (1 script)

| Script | Data Collected | Investigation Use | Attacks Detected |
|--------|---------------|-------------------|-----------------|
| Autoruns_Master_Summary | Aggregates all persistence artifacts into one unified view | Single-pane view of everything that auto-executes | All persistence mechanisms in one place for rapid triage |

---

## Volatile Data Coverage

Volatile data exists only in live system memory and is lost on reboot. The toolkit collects all volatile artifacts first, following RFC 3227 order of volatility.

| # | Volatile Artifact | Script | Coverage |
|---|------------------|--------|---------|
| 1 | Running processes with command lines | Running_Processes | Full |
| 2 | Active network connections | Network_Connections | Full |
| 3 | ARP cache | ARP_Entries | Full |
| 4 | DNS resolver cache | DNS_Cache | Full |
| 5 | Logged on users | System_Info | Full |
| 6 | Open SMB files and sessions | Lateral_Movement | Full |
| 7 | Named pipes | Named_Pipes | Full |
| 8 | Loaded DLLs per process | Loaded_DLLs | Full |
| 9 | Kerberos ticket cache | Credential_Artifacts | Full |
| 10 | Live RAM contents | RAM_Dump | Full |
| 11 | Live network traffic | Network_Packet_Capture | Full |
| 12 | Clipboard history files | Network_Advanced | Full |
| 13 | Active logon sessions | Logon_Sessions_Deep | Full |
| 14 | Live scheduled task states | Scheduled_Tasks | Full |
| 15 | Active service states | Windows_Services | Full |

**Volatile coverage: 100%**

---

## Non-Volatile Data Coverage

Non-volatile data persists across reboots and is stored on disk or in the registry.

### Registry Artifacts

| # | Artifact | Script |
|---|----------|--------|
| 1 | Run / RunOnce keys (11 paths) | Registry_RunKeys |
| 2 | Scheduled task definitions | Scheduled_Tasks |
| 3 | Service configurations | Windows_Services |
| 4 | WMI event subscriptions | WMI_Persistence |
| 5 | IFEO / AppCert / SSP / AppInit DLLs | Registry_Deep_Persistence |
| 6 | BAM / UserAssist / ShimCache | Registry_Execution_Artifacts |
| 7 | GPO cache scripts | GPO_Cache_Scripts |
| 8 | LSA secrets metadata | LSA_Secrets_Metadata |
| 9 | Shellbags | Registry_Deep_Persistence |
| 10 | MRU lists | Registry_Execution_Artifacts |
| 11 | Netsh helpers / KnownDLLs / Port Monitors | Registry_Deep_Persistence |

### File System Artifacts

| # | Artifact | Script |
|---|----------|--------|
| 12 | MFT (Master File Table) | MFT_USN_Collection |
| 13 | USN Change Journal | MFT_USN_Collection |
| 14 | Prefetch files | Collect_Prefetch |
| 15 | LNK recently opened files | FileSystem_Artifacts |
| 16 | Alternate Data Streams | FileSystem_Artifacts |
| 17 | Zone.Identifier (Mark of the Web) | FileSystem_Artifacts |
| 18 | Recycle Bin metadata | Registry_Deep_Persistence |
| 19 | Volume Shadow Copies | Backup_VSS_Deep |
| 20 | NTDS.dit location | NTDS_Location |
| 21 | Web shell files | IIS_WebShell_Detection |
| 22 | PowerShell transcript files | PS_Transcript_Collection |
| 23 | AppX / UWP packages | AppX_UWP_Apps |

### Event Log Artifacts

| # | Artifact | Script |
|---|----------|--------|
| 24 | Security event log | Security_EventLog |
| 25 | System event log | System_EventLog |
| 26 | PowerShell event log | PowerShell_EventLog |
| 27 | Raw EVTX files (29 channels) | EventLogs_Raw_Export |
| 28 | Defender detection history | Defender_Scan_History |

### User Activity Artifacts

| # | Artifact | Script |
|---|----------|--------|
| 29 | Browser history databases | Browser_Artifacts |
| 30 | SRUM database (60 days) | SRUM_PowerShell_History |
| 31 | Windows Timeline | SRUM_PowerShell_History |
| 32 | Jump Lists | Email_Office_Artifacts |
| 33 | PowerShell command history | SRUM_PowerShell_History |
| 34 | Outlook PST / OST files | Email_Office_Artifacts |
| 35 | Office macro-enabled files | Email_Office_Artifacts |

### Hardware and Device Artifacts

| # | Artifact | Script |
|---|----------|--------|
| 36 | USB device history | USB_Device_History |
| 37 | Kernel drivers | USB_Device_History |
| 38 | WER crash dumps | USB_Device_History |
| 39 | TPM and Secure Boot state | TPM_SecureBoot_BitLocker |
| 40 | BitLocker status | TPM_SecureBoot_BitLocker |

### Network Artifacts

| # | Artifact | Script |
|---|----------|--------|
| 41 | WiFi profiles | Network_Advanced |
| 42 | RDP saved connections and bitmap cache | Network_Advanced |
| 43 | Firewall rules | Firewall_Rules |
| 44 | Hosts file | Lateral_Movement |
| 45 | Proxy settings | Network_Advanced |

### Credential and Certificate Artifacts

| # | Artifact | Script |
|---|----------|--------|
| 46 | Certificate stores | Certificate_Store |
| 47 | Windows Credential Manager | Credential_Artifacts |
| 48 | DPAPI key file locations | Credential_Artifacts |
| 49 | WDigest plaintext flag | Credential_Artifacts |
| 50 | Autologon registry settings | Credential_Artifacts |

### Cloud and Modern Artifacts

| # | Artifact | Script |
|---|----------|--------|
| 51 | OneDrive and Teams files | Cloud_Artifacts |
| 52 | Azure / AWS / GCP token caches | Cloud_Artifacts |
| 53 | WSL bash history | WSL_HyperV_Artifacts |
| 54 | Hyper-V VM inventory | WSL_HyperV_Artifacts |
| 55 | Windows Hello and AAD join | WindowsHello_ModernAuth |

**Non-volatile coverage: 100%**

---

## Order of Volatility

The master runner follows RFC 3227 order of volatility in execution sequence:

```
1.  System state and baseline      (System_Info)
2.  Network connections            (Network_Connections, ARP, DNS)
3.  Live network traffic           (Network_Packet_Capture)
4.  Running processes              (Running_Processes)
5.  Memory                         (Named_Pipes, Loaded_DLLs, RAM_Dump)
6.  Event logs                     (Security, System, PowerShell, Raw EVTX)
7.  Persistence mechanisms         (Run Keys, Tasks, Services, WMI)
8.  Registry artifacts             (Execution history, deep persistence)
9.  File system                    (Prefetch, LNK, MFT, USN)
10. User activity                  (Browser, SRUM, Timeline)
11. Hardware and credentials       (USB, Certs, Credential store)
12. Cloud and modern artifacts     (OneDrive, Teams, AAD)
13. Active Directory               (GPO, Kerberos, DCSync, LAPS)
14. Report generation              (HTML report, Timeline, IOC enrichment)
```

---

## Standards Coverage

> **These percentages are the author's own self-assessment, not a certified or audited
> conformance rating.** They indicate which areas of each standard the toolkit's collection
> methodology aligns with — they are not a claim of formal compliance or accreditation. Only
> RFC 3227 (a concrete ordering rule) can be stated objectively. Treat the rest as a rough
> self-evaluation of alignment.

| Standard | Alignment (self-assessed) | Key Areas |
|----------|---------|-----------|
| NIST SP 800-86 (Forensics) | 90% | Evidence preservation, chain of custody, SHA256 integrity, order of volatility |
| ISO/IEC 27037 (Digital Evidence) | 95% | Collection, preservation, documentation, NTP verification, investigator identity |
| MITRE ATT&CK v15 | 78% | 12 tactics, 40+ techniques with script-level mapping |
| ISO/IEC 27035 (Incident Management) | 65% | Evidence preservation, incident logging, forensic readiness |
| NIST SP 800-61 Rev 2 (IR) | 60% | Detection, analysis, and documentation phases |
| CIS Controls v8 | 60% | Asset inventory, log management, account control, network monitoring |
| RFC 3227 | 100% | Order of volatility followed exactly in execution sequence |
| ISO/IEC 27042 (Analysis) | 60% | Evidence interpretation and analysis documentation |
| ISO/IEC 27043 (Investigation) | 65% | Incident investigation principles and processes |
| SWGDE Guidelines | 70% | Scientific working group on digital evidence standards |
| ACPO Guidelines | 75% | Association of Chief Police Officers digital evidence principles |

---

## AI Attack Detection

The toolkit includes a dedicated AI attack detection module (AI_Attack_Detection.ps1) that identifies both AI-assisted malicious activity and unauthorized AI tool usage on Windows endpoints.

### What It Detects

| Detection Module | What It Finds | Severity |
|-----------------|---------------|---------|
| Local LLM Runtime | Ollama, LM Studio, GPT4All, LlamaCPP running as live processes | Context-dependent |
| LLM Installation | Tool installation folders, config files, registry keys | Context-dependent |
| AI Model Files | .gguf .ggml .safetensors model files on disk | Context-dependent |
| High-Entropy Scripts | AI-generated or obfuscated PowerShell with anomalous entropy | HIGH |
| GPT Comment Patterns | LLM-style comments such as step-by-step or explanatory patterns | HIGH |
| Python AI Packages | transformers, langchain, openai, torch installed | Context-dependent |
| Prompt Injection | Injection patterns in recent files | HIGH |
| AI Credential Attacks | High-velocity brute force, password spray with AI-generated lists | CRITICAL |
| AI API DNS Entries | openai.com, anthropic.com, huggingface.co in DNS cache | Context-dependent |
| DGA Domain Patterns | AI-generated domain names with high consonant ratio | MEDIUM |

### Context-Aware Classification

The script does not blindly flag all AI activity as malicious. It uses machine context to separate legitimate from suspicious:

```
Developer Workstation + Ollama installed   = INFO  (likely legitimate)
Production Server     + Ollama installed   = HIGH  (investigate)
Domain Controller     + AI model files     = HIGH  (investigate)
Any machine           + High entropy PS    = HIGH  (always suspicious)
Any machine           + Prompt injection   = HIGH  (always suspicious)
Any machine           + 500 failed logons  = CRITICAL (always malicious)
```

### Output Classification

Every finding is sorted into one of three buckets:

```
Definitely Malicious  AI-generated PS scripts, prompt injection, brute force
Needs Human Review    LLM tools, model files, AI API access
Informational         Developer tools on known developer machines
```

### Why AI Attacks Are Different

Traditional malware uses static signatures. AI-generated attacks change the payload on every generation, which makes signatures useless. They produce polymorphic PowerShell that varies per execution, generate convincing phishing that bypasses human detection, and automate credential attacks with AI-generated username lists. This toolkit detects the effects and artifacts of these attacks at the endpoint level regardless of how the payload was generated.

### MITRE ATT&CK Mapping for AI Attacks

| Technique | ID | Detection |
|-----------|-----|-----------|
| PowerShell obfuscation | T1059.001 | High entropy script block analysis |
| Credential stuffing | T1110.003 | Velocity analysis of failed logons |
| DGA C2 domains | T1568.002 | Consonant ratio analysis of DNS cache |
| Software supply chain | T1588 | AI package and model file inventory |
| Prompt injection | T1566 | Pattern matching in recent files |
| Impair defenses | T1562.001 | AMSI-related PowerShell pattern detection |

---

## MITRE ATT&CK Coverage

| Tactic | Techniques Covered | Scripts |
|--------|-------------------|---------|
| Initial Access | T1566 Phishing artifacts | Browser_Artifacts, Email_Office_Artifacts |
| Execution | T1059.001 PowerShell, T1059.003 CMD, T1204 User Execution | PS_EventLog, Running_Processes, Prefetch |
| Persistence | T1547.001 Run Keys, T1053.005 Tasks, T1543.003 Services, T1546.003 WMI | Registry_RunKeys, Scheduled_Tasks, Windows_Services, WMI_Persistence |
| Privilege Escalation | T1078 Valid Accounts, T1548 UAC Bypass, T1134 Token Manipulation | Local_Users_Groups, ThreatHunting, Credential_Artifacts |
| Defense Evasion | T1562 Impair Defenses, T1027 Obfuscation, T1574 DLL Hijack, T1036 Masquerade | Firewall_Rules, AV_EDR_Status, Loaded_DLLs, ThreatHunting |
| Credential Access | T1003 LSASS, T1555 Credential Store, T1558 Kerberos, T1552 Unsecured Creds | RAM_Dump, Credential_Artifacts, Kerberoasting_Evidence |
| Discovery | T1082 System Info, T1049 Connections, T1057 Processes, T1083 Files | System_Info, Network_Connections, Running_Processes |
| Lateral Movement | T1021.001 RDP, T1021.002 SMB, T1021.006 WinRM, T1570 Tool Transfer | Lateral_Movement, Network_Advanced |
| Collection | T1074 Staged Data, T1113 Screenshot, T1217 Browser History | FileSystem_Artifacts, Browser_Artifacts, USB_Device_History |
| Command and Control | T1071 App Layer, T1571 Non-Standard Port, T1572 Protocol Tunneling | Network_Connections, Named_Pipes, DNS_Cache |
| Exfiltration | T1052.001 USB, T1567.002 Cloud Storage, T1041 C2 Channel | USB_Device_History, Cloud_Artifacts, Network_Connections |
| Impact | T1486 Ransomware, T1490 Inhibit Recovery | TPM_SecureBoot_BitLocker, Backup_VSS_Deep |

---

## Output Structure

All output is saved to `C:\IR_Collection\`

```
C:\IR_Collection\
    System_Info_HOSTNAME_TIMESTAMP.json
    System_Info_HOSTNAME_TIMESTAMP.json.hash.json
    Network_Connections_HOSTNAME_TIMESTAMP.json
    Network_Connections_HOSTNAME_TIMESTAMP.json.hash.json
    ... (one .json + one .hash.json per script)

    Prefetch_HOSTNAME_TIMESTAMP\          (prefetch .pf files)
    EventLogs_Raw_HOSTNAME_TIMESTAMP\     (raw .evtx files)
    ScheduledTask_XML_HOSTNAME_TIMESTAMP\ (raw task XML files)
    WebShell_Suspects_HOSTNAME_TIMESTAMP\ (copied suspect files)
    PS_Transcripts_HOSTNAME_TIMESTAMP\    (copied transcript files)
    NetCapture_HOSTNAME_TIMESTAMP\        (ETL and PCAP files)
    RAM_HOSTNAME_TIMESTAMP\               (memory dump .raw file)

    Report_TIMESTAMP\
        IR_Report_HOSTNAME_TIMESTAMP.html    (main HTML report)
        IR_Summary_HOSTNAME_TIMESTAMP.txt    (text summary)
        IOC_HOSTNAME_TIMESTAMP.json          (IOC export)
        IOC_HOSTNAME_TIMESTAMP.csv           (SIEM-ready CSV)

    Timeline_TIMESTAMP\
        Timeline_HOSTNAME_TIMESTAMP.html     (searchable timeline)
        Timeline_HOSTNAME_TIMESTAMP.csv      (timeline CSV)

    IOC_ThreatIntel_HOSTNAME_TIMESTAMP.html  (VirusTotal results)
    Evidence_Manifest_TIMESTAMP.json         (master file index)
    Evidence_Manifest_TIMESTAMP.json.hash.json
    MasterRun_TIMESTAMP.log                  (full execution log)
```

### File Types

| Extension | Description |
|-----------|-------------|
| .json | Structured evidence with embedded chain of custody |
| .hash.json | SHA256 integrity proof for each evidence file |
| Evidence_Manifest | Master index of all files with hashes and timestamps |
| MasterRun.log | Complete execution log with timings and errors |
| IR_Report.html | Professional HTML incident response report |
| Timeline.html | Interactive searchable forensic event timeline |
| IOC*.csv | SIEM-ready IOC file for Splunk, Sentinel, and Elastic import |

---

## Evidence Integrity

Every artifact produced by this toolkit includes the following integrity measures:

```
SHA256 hash per artifact file
SHA256 of the evidence manifest
Independent re-verification tool (Verify-Evidence.ps1) that re-hashes the whole set vs the manifest
NTP stratum-level clock verification
ISO 8601 timestamps (newer artifacts are UTC; some legacy scripts still emit local time + offset)
Investigator identity bound to every record
Case number embedded in chain-of-custody metadata
Tool version recorded per artifact
Read-only by default (live-response actions are explicit and opt-in where they change state)
Collector footprint artifact (the tool's own PID/process/files) so tool noise can be excluded
```

### Re-verifying an Evidence Set

Prove that a collected evidence package is byte-for-byte unchanged since collection (run this on
the analyst workstation, not the target):

```powershell
.\Scripts\Reporting\Verify-Evidence.ps1                      # newest manifest under C:\IR_Collection
.\Scripts\Reporting\Verify-Evidence.ps1 -ManifestPath D:\Case\Evidence_Manifest_20260708_101500.json
```

It re-hashes every file the manifest lists, checks the manifest's own hash against its
`.hash.json` sidecar, and writes `Evidence_Verification_<time>.json` with a per-file MATCH /
MISMATCH / MISSING verdict. Exit code is non-zero if verification fails.

### Forensic Limitations (read before relying on this in a case)

Honesty about what a live PowerShell collector can and cannot guarantee:

- **Live collection perturbs the target.** Running the toolkit spawns processes, writes files,
  and generates event-log/registry entries. This is inherent to live response. The
  `Collector_Footprint_*.json` artifact records the tool's own PID, process, and output paths so
  an analyst can separate tool noise from attacker activity.
- **Output is written to disk.** By default output goes to `C:\IR_Collection` on the system
  volume, which consumes free space and can overwrite unallocated space. **Prefer an external or
  network path** (`-OutputPath E:\...`) to minimize impact on the evidence volume.
- **RAM-dump hashes prove post-acquisition integrity, not reproducibility.** Memory changes
  constantly; a RAM image can never be re-acquired to the same hash. The hash proves the dump
  has not changed *since* capture.
- **EVTX hashes are of the `wevtutil` export, not the byte-image of the live log file.**
  `wevtutil epl` re-serializes the log into a logically equivalent copy; the SHA256 covers that
  copy.
- **MACB timestamps from live enumeration are `$STANDARD_INFORMATION`-based** and are trivially
  forgeable (timestomping). For tamper-resistant `$FILE_NAME` timestamps, parse the collected
  `$MFT` offline.
- **The acquisition tool (WinPmem) is only *verified* if you pin it.** Set
  `DFIR_WINPMEM_SHA256` to a known-good hash to refuse a tampered/MITM'd binary; otherwise the
  recorded hash proves only *what ran*, not that it is trusted. Pre-stage WinPmem in `Tools\`
  for air-gapped/verified acquisition instead of auto-downloading at IR time.
- **Collect on the target, analyze offline.** VirusTotal enrichment and tool auto-download
  generate outbound traffic from the endpoint. On a live intrusion, prefer running the reporting
  / enrichment phase (`-Phase Reporting`) on a clean analyst workstation against the evidence
  package, not on the target.

### Chain of Custody Format

Every JSON evidence file contains:

```json
{
  "ChainOfCustody": {
    "CaseNumber"    : "IR-2026-001",
    "Investigator"  : "InvestigatorName",
    "Hostname"      : "HOSTNAME",
    "CollectedAt"   : "2026-05-28T10:30:00.000Z",
    "NTPSource"     : "time.windows.com",
    "NTPOffset"     : "0.002s",
    "ToolVersion"   : "1.0"
  }
}
```

---

## Platform Compatibility

| Category | Win10 | Win11 | Server 2016 | Server 2019 | Server 2022 |
|----------|-------|-------|-------------|-------------|-------------|
| System | Full | Full | Full | Full | Full |
| Network | Full | Full | Full | Full | Full |
| Event Logs | Full | Full | Full | Full | Full |
| Persistence | Full | Full | Full | Full | Full |
| Registry | Full | Full | Full | Full | Full |
| Memory / RAM | Full | Full | Full | Full | Full |
| Execution | Full | Full | Partial | Full | Full |
| File System | Full | Full | Full | Full | Full |
| Browser | Full | Full | IIS Logs | IIS Logs | IIS Logs |
| Active Directory | Full | Full | Full | Full | Full |
| Cloud | Full | Full | Partial | Partial | Partial |
| Reporting | Full | Full | Full | Full | Full |

Note: Prefetch is disabled by default on Server OS. The script auto-detects and falls back to RecentFileCache.

---

## Post-Collection Analysis

### Recommended Tools

| Artifact | Tool | Source |
|----------|------|--------|
| MFT / UsnJrnl | MFTECmd.exe | EricZimmerman.github.io |
| Prefetch | PECmd.exe | EricZimmerman.github.io |
| Jump Lists | JLECmd.exe | EricZimmerman.github.io |
| Shellbags | ShellBagsExplorer | EricZimmerman.github.io |
| EVTX files | EvtxECmd.exe | EricZimmerman.github.io |
| EVTX hunting | Hayabusa | github.com/Yamato-Security |
| AmCache | AmcacheParser.exe | EricZimmerman.github.io |
| ShimCache | AppCompatCacheParser | EricZimmerman.github.io |
| SRUM Database | srum-dump | github.com/MarkBaggett |
| RAM Dump | Volatility 3 | github.com/volatilityfoundation |
| Registry Hives | Registry Explorer | EricZimmerman.github.io |
| SQLite DBs | DB Browser for SQLite | sqlitebrowser.org |
| Recycle Bin | RBCmd.exe | EricZimmerman.github.io |

### Volatility 3 Quick Commands

```bash
vol.py -f RAM.raw windows.pslist        # Running processes
vol.py -f RAM.raw windows.netscan       # Network connections
vol.py -f RAM.raw windows.malfind       # Injected code regions
vol.py -f RAM.raw windows.cmdline       # Process command lines
vol.py -f RAM.raw windows.dlllist       # Loaded DLLs per process
vol.py -f RAM.raw windows.hashdump      # Password hashes
```

### PCAP Analysis in Wireshark

```
Open file: C:\IR_Collection\NetCapture_*\capture_*.pcap

Useful filters:
  !(ip.dst == 10.0.0.0/8)              External traffic only
  dns                                   DNS queries
  tcp.flags.syn == 1 && tcp.flags.ack == 0  New connections
  tcp.port == 4444 or tcp.port == 8080  Common C2 ports
  http.request.method == "POST"         Data exfiltration
```

---

## Enterprise Deployment

### Group Policy Deployment

```powershell
# Create GPO startup script pointing to:
\\fileserver\DFIR\Run_IR_Collection.ps1
```

### SCCM / Intune

Package the toolkit as a Win32 app with the following install command:

```powershell
powershell.exe -ExecutionPolicy Bypass -File Run_IR_Collection.ps1
```

### Offline / Air-Gapped Networks

All scripts operate fully offline. The only features requiring internet are:

- WinPmem auto-download (place manually in Tools\ folder)
- etl2pcapng auto-download (place manually in Tools\ folder)
- VirusTotal IOC enrichment (skipped automatically if no API key)

### Signed Script Deployment

For environments requiring signed scripts:

```powershell
# Sign all scripts with your code signing certificate
Get-ChildItem -Recurse -Filter "*.ps1" | ForEach-Object {
    Set-AuthenticodeSignature $_.FullName -Certificate $cert
}
```

---

## Troubleshooting

### Script blocked by Antivirus

```powershell
Add-MpPreference -ExclusionPath "C:\path\to\dfir-toolkit"
# Remove after collection:
Remove-MpPreference -ExclusionPath "C:\path\to\dfir-toolkit"
```

### Execution Policy Error

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
```

### Access Denied Errors

Run PowerShell as Administrator. Right-click PowerShell and select Run as Administrator.

### PSScriptRoot Empty

Run as a file, not by pasting into the console:

```powershell
# Correct
cd "C:\path\to\dfir-toolkit"
.\Run_IR_Collection.ps1

# Incorrect - do not paste script content into console
```

### WinPmem Not Found

Option A  -  Auto-download (requires internet):
Run `.\Scripts\Memory\RAM_Dump.ps1` and it downloads automatically.

Option B  -  Manual:
Download `winpmem_mini_x64.exe` from github.com/Velocidex/WinPmem/releases and place in `Tools\` folder.

### Loaded_DLLs Takes Too Long

```powershell
.\Run_IR_Collection.ps1 -Skip Loaded_DLLs
```

### VirusTotal Rate Limit

Free tier is limited to 4 requests per minute and 500 per day. The script auto-throttles. Wait and retry if the limit is hit. Upgrade at virustotal.com for higher limits.

### SRUM_PowerShell_History Blocked by Antivirus

Run this once before executing the toolkit:

```powershell
Add-MpPreference -ExclusionPath "C:\path\to\dfir-toolkit"
Add-MpPreference -ExclusionProcess "powershell.exe"
```

### Insufficient Disk Space for RAM Dump

Disk space required equals RAM size multiplied by 1.1. Free space on the target drive or redirect output path before running.

---

## Changelog

### Forensic hardening (v1.0 maintenance)

Reliability, soundness, and data-handling fixes:

- **Fixed a run-aborting bug:** several sub-scripts (RAM_Dump, Network_Packet_Capture, the shared
  `Assert-AdminPrivilege`) called `exit` on a failure path. Because the orchestrator invokes
  scripts in-process, `exit` terminated the *entire* collection session — a failed RAM capture
  (the first phase) could abort everything else. Replaced with `return`/`throw` so the run
  continues, as intended.
- **New: `Verify-Evidence.ps1`** — an independent, offline re-verification tool that re-hashes
  every file in a manifest, checks the manifest's own hash sidecar, and emits a MATCH/MISMATCH/
  MISSING verdict. Closes the other half of the integrity loop (proving integrity at handoff).
- **New: `Memory\Pagefile_Hiberfil.ps1`** — documents pagefile/hiberfil/swapfile configuration and
  metadata, with opt-in VSS raw capture (`DFIR_COPY_PAGEFILE=1`). Provides a memory-forensics
  fallback when live RAM acquisition fails, and access to a full hibernation memory image.
- **New: collector footprint artifact** — the orchestrator now writes `Collector_Footprint_*.json`
  (its own PID, parent, command line, user, output paths) so an analyst can subtract tool noise
  from attacker activity.
- **WinPmem hash pinning** — set `DFIR_WINPMEM_SHA256` to a known-good value and RAM_Dump refuses
  to run on mismatch. Without a pin it now clearly logs that the acquisition tool is *unverified*
  (records what ran; does not claim it is trusted).
- **Data-handling / OPSEC:** IOC_ThreatIntel no longer submits internal or non-public names
  (`.local/.internal/.corp/.lan/.home/.arpa`, single-label hostnames) to VirusTotal, preventing
  leakage of internal AD/host naming to a third party. Added HTTP 429 exponential backoff so a
  rate-limited IOC is retried rather than silently dropped.
- **Documentation honesty:** corrected "court-admissible" / "chain of custody" / compliance-
  percentage / "UTC-normalized" claims to what the tool actually provides, and added a
  **Forensic Limitations** section (collector footprint, on-disk output, RAM-hash reproducibility,
  EVTX export vs byte-image, timestomping, collect-vs-analyze separation).
- **Internal refactor:** all collection scripts now import the shared `DFIR_Common.psm1` module
  and take the toolkit version from its single `$Global:DFIR_ToolVersion` constant (was a
  hardcoded string in each script). Evidence timestamps normalized to UTC. The shared module now
  honors `DFIR_OUTPUT` so shared paths match per-script output paths.

### New: Hawk Windows Collector single-file executable (current)

The toolkit can now be packaged into one self-extracting, signed `.exe` - **Hawk Windows
Collector** - for drop-and-run field use, via `Build\Build-Exe.ps1` (compiles with the built-in
.NET Framework `csc.exe`; no external toolchain). The exe self-elevates (UAC), extracts the full
toolkit to a temp working folder preserving the `Scripts\` structure, then runs the orchestrator
with `-ExecutionPolicy Bypass` so collection never fails on machine execution policy. It only
unpacks and invokes, so collection stays deterministic and forensically sound. The build
self-signs by default (use `-SignThumbprint` for a CA-issued cert). The compiled binary is a
build artifact published on the **Releases** page, not committed to the tree. See
`Build\README.md`.

### Sealed evidence package + user-supplied IOC matching

- **Sealed evidence package** - the orchestrator now bundles the whole collection into a single
  hashed `Evidence_Package_<host>_<time>.zip` for clean chain-of-custody handoff (SHA256 sidecar).
  Very large raw captures (RAM images, big pcaps) are referenced but not embedded - they are
  already hashed individually in the manifest. Opt out with `DFIR_PACKAGE=0`; tune the per-file
  size ceiling with `DFIR_PACKAGE_MAXMB`.
- **User-supplied IOC matching** (`Scripts/Reporting/IOC_Match.ps1`) - drop your own hash / IP /
  domain / filename indicators (via `DFIR_IOC_FILE`, the `IOCs\` folder, or `<output>\IOCs\`) and
  the toolkit sweeps every collected artifact for them, surfacing hits as a CRITICAL "Indicator
  Match" finding and a summary stat in the HTML report. Boundary-aware matching keeps false
  positives low. See `IOCs\README.md` for the file format.

### Prefetch parsing into the execution timeline

Collect_Prefetch now decompresses (XPRESS-Huffman) and parses `.pf` files into executable name,
run count and last-run timestamps, which flow onto the forensic timeline as execution events
(the raw `.pf` is still copied for offline verification).

### New: Anti-Forensics / tamper-detection module

Added `DefenseEvasion\Anti_Forensics.ps1`, integrated into the orchestrator, HTML report
(risk findings + summary stat) and forensic timeline. It consolidates the indicators an
attacker leaves when destroying evidence and blinding defenders:
- Event-log clearing (Security 1102, System 104) with who/when
- Log channels disabled that are enabled by default (Security, System, PowerShell, Defender, Sysmon)
- PowerShell ScriptBlock/Module/Transcription logging explicitly disabled by policy
- Defender / AMSI tampering (real-time / tamper-protection off, disabled scan toggles, missing AMSI provider)
- USN change-journal deletion, prefetch disablement, audit-policy changes (4719)

Tuned for low false positives: does not flag Defender real-time-off when a third-party AV is
registered, does not treat default-off PowerShell logging or default-off Operational log
channels as tampering, and only flags prefetch-disabled on client SKUs.

### Detection accuracy, false-positive resistance, and performance

Detection tuning (verified on a clean host: overall risk dropped from CRITICAL to MEDIUM
with only accurate, true-positive findings remaining):
- Certificate_Store: "rogue root" now checks membership in the Microsoft AuthRoot CTL and
  enterprise/GPO trusted-root sets that Windows records, instead of a small hardcoded name
  allowlist. Legitimate public CAs (SSL.com, Starfield, Go Daddy, emSign, ...) are no longer
  flagged; results are de-duplicated across the LocalMachine and CurrentUser stores.
- Registry_Deep_Persistence: signed-System32 DLL trust filter added to the time-provider,
  netsh, KnownDLLs and port-monitor checks; SSP/notification baselines expanded and the
  notification-package comparison wired up; x86-on-ARM64 emulation KnownDLLs (xtajit*,
  wowarmhw) added to the baseline; RecycleBin metadata filter fixed.
- ThreatHunting: COM-hijack detection requires an HKLM override outside system paths (was
  flagging all per-user COM); LOLBAS detection parses the real process path and command line
  from 4688/Sysmon and requires an abuse-argument pattern (was matching the bare binary name).
- AI_Attack_Detection: PowerShell and prompt-injection heuristics split into strong-malice vs
  weak-context; CRITICAL requires an actual obfuscated (high-entropy) payload; the scanner no
  longer self-detects security/detection tooling or log-hunting scripts; AI API endpoints in
  DNS are informational context, not an attack.
- IIS_WebShell_Detection: signatures split into strong/weak so legitimate framework code no
  longer flags; IIS logs parsed via the #Fields header instead of fixed column indices.
- Scheduled_Task_XML: requires a strong indicator (encoded/download/IEX or interpreter from
  temp/public); built-in Windows tasks are not flagged on bare LOLBAS names or AppData paths.
- Lateral_Movement: hidden shares and custom hosts entries no longer flagged as suspicious;
  the SMB client field is labelled correctly (user, not IP).
- Generate_IR_Report: unsigned-process count excludes unreadable protected-process paths;
  timestamps labelled UTC are UTC; collection-start is the earliest artifact, not last boot;
  attacker-controlled values are HTML-encoded.
- Timeline_Builder: handler field names aligned to producer schemas (deep-persistence, WMI,
  lateral-movement and threat-hunting events were being dropped); times normalised to UTC.

Reliability and performance:
- Email_Office_Artifacts: full-profile macro scan replaced with a depth-limited pass over
  document folders (~1038s to ~5s).
- FileSystem_Artifacts: unbounded ADS/Mark-of-the-Web recursion bounded and scoped (~1229s to ~12s).
- AI_Attack_Detection: model-file, prompt-injection and site-packages scans depth-limited (no
  longer times out); multi-part PowerShell 4104 script blocks are reassembled and the raw
  ScriptBlockText is analysed.
- WSL_HyperV_Artifacts: Windows Sandbox/Docker queries wrapped so the module degrades
  gracefully instead of aborting on non-admin hosts.
- IOC_ThreatIntel: VirusTotal key prompt is skipped when run non-interactively (was hanging
  the orchestrator); priority hashing and truncation reporting corrected.

### v1.0

Initial public release.

**Core Features**
- 63 scripts across 24 categories (60 collection scripts plus AI attack detection and anti-forensics; 3 reporting)
- Full volatile and non-volatile artifact coverage in RFC 3227 order of volatility
- Live RAM capture via WinPmem (auto-download) with SHA256 verification
- Live network packet capture via netsh with automatic ETL-to-PCAP conversion
- Professional HTML incident response report: 15 sections, risk scoring, MITRE ATT&CK mapping
- Unified MACB forensic timeline with severity levels and search/filter
- VirusTotal IOC enrichment scanning all evidence files with priority submission
- AI attack detection with context-aware malicious/benign classification
- SHA256 integrity per artifact and a master evidence manifest
- Chain of custody embedded in every JSON output
- OS-aware collection (Workstation vs Server) and air-gapped support
- Auto Defender exclusion at startup

**Reliability Fixes**
- System_Info: full-path query.exe with CIM fallback for all Windows editions
- Registry_Deep_Persistence: StartsWith replaces fragile regex for Recycle Bin parsing
- AppX_UWP_Apps and Backup_VSS_Deep: Environment.NewLine handling replaces broken patterns
- SQL_Server_Artifacts: string .Replace() replaces invalid -replace regex
- Patch_Level: locale-safe DateTime sorting
- MFT_USN_Collection: robocopy /B backup mode as primary no-VSS method
- RAM_Dump: corrected WinPmem positional argument
- Network_Packet_Capture: corrected to netsh capture=yes without ETW providers (the cause of empty captures), with trace-status verification and graceful skip when unsupported
- PowerShell_EventLog: streamed event reading to prevent OutOfMemory on heavily-logged hosts
- Timeline_Builder: resolved reserved-variable collision and added timezone-aware parsing; produces full timeline
- IOC_ThreatIntel: scans all evidence files directly with priority VirusTotal submission
- Report risk score capped at 100

---

## Known Issues and Workarounds

| Issue | Cause | Workaround |
|-------|-------|-----------|
| SRUM_PowerShell_History AV blocked | Defender heuristic on SRUM code | Run `Add-MpPreference -ExclusionProcess "powershell.exe"` before toolkit |
| MFT 0/N collected | No VSS on machine, Group Policy blocks backup privilege | robocopy /B attempted automatically, metadata always collected |
| PCAP 0 MB | netsh NDIS packet capture disabled at OS level on some builds/VMs | Capture method fixed to use capture=yes without providers; if still empty, host's netsh capture is OS-disabled - use Wireshark/tshark instead |
| PowerShell_EventLog OutOfMemory | High JSON serialization depth on large event sets, plus loading all events at once | Resolved - events streamed with a hard cap and JSON serialized at reduced depth with a suspicious-only fallback; full text preserved in raw EVTX export |
| Timeline 0 events | $Host reserved-variable collision in event builder | Resolved - parameter renamed and timezone-aware parsing added; produces full timeline |

---

## License

MIT License

Copyright (c) 2026 Subash J

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

---

## Credits

**Tool Created by Subash J**

LinkedIn: https://www.linkedin.com/in/subash-j/

---

## Testing

Every push and pull request runs a continuous-integration safety net
(GitHub Actions, `windows-latest`, Windows PowerShell 5.1) so a broken script
never reaches a target host. Run the same checks locally before contributing:

```powershell
.\test\Run-AllTests.ps1
```

Three gates, no admin, no network, no evidence collected:

1. **Parse-lint** - every `.ps1` (all collection scripts + the orchestrator)
   tokenizes with zero parse errors.
2. **Orchestrator integrity** - every script the runner's execution plan
   references exists on disk (a dangling reference would surface as a
   `NOT FOUND` phase in the field), and any script present but not wired into
   the runner is reported.
3. **PSScriptAnalyzer** - Error-severity static analysis across the repo.

Exit code equals the number of failed gates (`0` = all green).

---

## Contributing

Contributions are welcome. Please open an issue or submit a pull request.

For major changes please open an issue first to discuss what you would like to change.

New collection scripts must parse cleanly and, if they run as part of a
collection phase, be wired into `Run_IR_Collection.ps1` so the orchestrator
integrity gate stays green. Run `.\test\Run-AllTests.ps1` before opening a PR.

---

## Acknowledgements

- Eric Zimmerman for his suite of forensic tools referenced in post-collection analysis
- Velocidex for WinPmem used in live RAM capture
- Microsoft for etl2pcapng used in network capture conversion
- The DFIR and blue team community for continuous research and knowledge sharing

---

*Windows DFIR Toolkit v1.0  -  Professional incident response evidence collection for Windows endpoints.*
*Free. Open Source. No dependencies. Forensically sound, independently verifiable output.*
