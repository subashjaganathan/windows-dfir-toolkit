# Windows DFIR Toolkit v1.0

**Professional Windows Incident Response Evidence Collection Platform**

A comprehensive, forensically sound PowerShell toolkit for collecting digital evidence from Windows endpoints during incident response investigations. One command collects all forensic evidence and produces a professional HTML report with chain of custody documentation.

---

## Table of Contents

- [Overview](#overview)
- [Why This Tool](#why-this-tool)
- [Technical Architecture](#technical-architecture)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Run Commands](#run-commands)
- [Complete Script Reference](#complete-script-reference)
- [Volatile Data Coverage](#volatile-data-coverage)
- [Non-Volatile Data Coverage](#non-volatile-data-coverage)
- [Order of Volatility](#order-of-volatility)
- [Standards Coverage](#standards-coverage)
- [MITRE ATT&CK Coverage](#mitre-attck-coverage)
- [Output Structure](#output-structure)
- [Evidence Integrity](#evidence-integrity)
- [Platform Compatibility](#platform-compatibility)
- [Post-Collection Analysis](#post-collection-analysis)
- [Enterprise Deployment](#enterprise-deployment)
- [Troubleshooting](#troubleshooting)
- [Changelog](#changelog)
- [License](#license)

---

## Overview

The Windows DFIR Toolkit is a PowerShell-based forensic evidence collection suite designed for incident response investigations on Windows endpoints. It collects volatile and non-volatile digital evidence in a single execution, following RFC 3227 order of volatility, and produces court-admissible output with SHA256 integrity verification and full chain of custody documentation.

```
One command. 60 scripts. Complete forensic evidence collection.
```

**What it produces:**

- Structured JSON evidence files with embedded chain of custody
- SHA256 integrity hash per evidence file
- Evidence manifest covering all collected artifacts
- Professional HTML incident response report with risk scoring
- Unified forensic timeline across all artifact types
- IOC extraction file with VirusTotal enrichment
- SIEM-ready CSV export for Splunk, Sentinel, and Elastic
- Live network packet capture with automatic PCAP conversion

---

## Why This Tool

| Compared To | Advantage |
|-------------|-----------|
| Commercial tools (CrowdStrike, Axiom) | Free, no license, no vendor dependency |
| Manual investigation | 30 minutes vs 2 days |
| Other open source scripts | 60 scripts vs handful, court-ready output |
| Velociraptor / KAPE | No training required, single PowerShell file |

**Core advantages:**

- Zero external dependencies  -  pure PowerShell 5.1 built into every Windows machine
- No installation required  -  extract and run
- Read-only forensically sound collection  -  never modifies the system
- Court-admissible evidence integrity  -  SHA256, NTP-verified timestamps, investigator binding
- OS-aware  -  auto-adapts collection for Workstation vs Server
- Runs on air-gapped networks  -  no internet required for core collection
- RFC 3227 order of volatility followed in execution sequence

---

## Technical Architecture

### Design Principles

```
Native API first        : CIM/WMI, .NET framework, COM objects, registry
Zero dependencies       : No external modules, no third-party libraries
Atomic writes           : No partial evidence files ever written
Parallel-safe           : Each script is fully independent
Fail-safe execution     : One script failure never stops the rest
Read-only               : No system state modification under any condition
```

### Performance Engineering

- Pre-built hashtables for O(1) process lookups instead of O(n) loops
- Single WMI call for process table shared across scripts
- SHA256 hash cache to avoid recomputing the same binary
- Generic List over array concatenation for large datasets
- Event log FilterHashtable queries instead of post-filter Where-Object
- Top-level ADS scan only to prevent false positive explosion

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

### Registry (3 scripts)

| Script | Data Collected | Investigation Use | Attacks Detected |
|--------|---------------|-------------------|-----------------|
| Registry_Execution_Artifacts | BAM, UserAssist, ShimCache, MRU lists | Prove execution of deleted files | Anti-forensics, deleted tool execution |
| Registry_Deep_Persistence | IFEO, SSP, AppCert DLLs, Port Monitors, Time Providers, Shellbags | Find advanced persistence missed by standard tools | Accessibility backdoors, DLL hijacking, credential capture |
| GPO_Cache_Scripts | Applied GPO logon scripts from SYSVOL cache | Detect attacker-modified group policy scripts | GPO abuse, domain-wide persistence |

### Defense Evasion (3 scripts)

| Script | Data Collected | Investigation Use | Attacks Detected |
|--------|---------------|-------------------|-----------------|
| Firewall_Rules | All firewall rules, per-profile state | Identify rules added to allow C2 traffic | Firewall bypass, C2 allowlisting |
| AV_EDR_Status | All registered AV products, Defender status, quarantine, 14 EDR agents | Determine if protection was disabled before attack | AV tampering, EDR bypass, pre-ransomware disabling |
| Defender_Scan_History | Full detection timeline, quarantine items, disabled events | Reconstruct what Defender saw and when | AV evasion, partial detection, missed threats |

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

### Memory (3 scripts)

| Script | Data Collected | Investigation Use | Attacks Detected |
|--------|---------------|-------------------|-----------------|
| Named_Pipes | All named pipes with C2 framework pattern matching | Detect active C2 frameworks communicating via pipes | Cobalt Strike, Metasploit, Sliver, PSExec |
| Loaded_DLLs | All DLLs per process with hash, signature, load path | Detect injected or hijacked DLLs | DLL injection, DLL hijacking, process hollowing |
| RAM_Dump | Full physical memory capture via WinPmem (auto-downloaded) | Extract decrypted malware, credentials, encryption keys | Fileless malware, injected shellcode, ransomware keys |

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

### Threat Hunting (2 scripts)

| Script | Data Collected | Investigation Use | Attacks Detected |
|--------|---------------|-------------------|-----------------|
| ThreatHunting | COM hijacks, LOLBAS hits, Defender exclusions, UAC, PATH hijacking | Proactive hunting across multiple attack surfaces | Living-off-the-land, COM hijacking, UAC bypass |
| IIS_WebShell_Detection | Recently modified web files in IIS wwwroot with signature matching | Identify web shells for persistent server access | Web shell installation, ProxyShell, ProxyLogon |

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

### Reporting (3 scripts)

| Script | Data Collected | Investigation Use | Attacks Detected |
|--------|---------------|-------------------|-----------------|
| Generate_IR_Report | Reads all evidence JSONs, produces risk-scored HTML report | Deliver professional findings to management, legal, or client | Summary across all detected attack techniques |
| Timeline_Builder | Merges all artifact timestamps into unified MACB timeline | Answer what happened and when across all evidence | Attack chain reconstruction, dwell time analysis |
| IOC_ThreatIntel | Submits hashes, IPs, domains to VirusTotal API | Instantly flag known malware without manual lookup | Known malware identification, threat actor attribution |

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

| Standard | Coverage | Key Areas |
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
NTP stratum-level clock verification
UTC-normalized ISO 8601 timestamps throughout
Investigator identity bound to every record
Case number embedded in chain of custody
Tool version recorded per artifact
Read-only collection verified by design
```

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

### Insufficient Disk Space for RAM Dump

Disk space required equals RAM size multiplied by 1.1. Free space on the target drive or redirect output path before running.

---

## Changelog

### v1.0 (Current Release)

Initial public release.

- 60 collection scripts across 25 categories
- Full volatile and non-volatile artifact coverage
- RFC 3227 order of volatility in execution sequence
- Live RAM capture via WinPmem with auto-download
- Live network capture via netsh with automatic ETL to PCAP conversion
- Professional HTML incident response report with risk scoring
- Unified MACB forensic timeline across all artifact types
- VirusTotal IOC enrichment for hashes, IPs, and domains
- SHA256 integrity per artifact file with evidence manifest
- Chain of custody embedded in every JSON output
- OS-aware collection for Workstation and Server
- Full Active Directory coverage including DCSync and Kerberoasting detection
- Web shell detection across IIS web roots
- USB device history and kernel driver inventory
- Cloud artifact collection for Azure, AWS, and GCP
- WSL and Hyper-V virtualization artifacts
- Full enterprise deployment support

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

## Contributing

Contributions are welcome. Please open an issue or submit a pull request.

For major changes please open an issue first to discuss what you would like to change.

---

## Acknowledgements

- Eric Zimmerman for his suite of forensic tools referenced in post-collection analysis
- Velocidex for WinPmem used in live RAM capture
- Microsoft for etl2pcapng used in network capture conversion
- The DFIR and blue team community for continuous research and knowledge sharing

---

*Windows DFIR Toolkit v1.0  -  Professional incident response evidence collection for Windows endpoints.*
*Free. Open Source. No dependencies. Court ready.*
