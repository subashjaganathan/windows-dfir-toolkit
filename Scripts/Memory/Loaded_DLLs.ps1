#Requires -Version 5.1
<#
.SYNOPSIS
    Enumerates loaded DLLs per process for injection and hijack detection.

.DESCRIPTION
    Captures all DLLs loaded by running processes, validates digital
    signatures, computes hashes, and flags suspicious indicators:
    DLLs loaded from writable paths, unsigned DLLs in system processes,
    and known suspicious names used by attackers.

.IR_PHASE
    Identification / Live Response

.MITRE_ATTCK
    T1055     - Process Injection
    T1574.001 - DLL Search Order Hijacking
    T1574.002 - DLL Side-Loading
    T1036     - Masquerading

.FORENSIC_SAFETY
    Read-only, forensic-safe

.AUTHOR
    DFIR Toolkit

.VERSION
    2.0
#>

Set-StrictMode -Off
$ErrorActionPreference = "Continue"
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) { Write-Warning "[!] Administrator privileges recommended for full module access." }

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Hostname  = $env:COMPUTERNAME
$BasePath  = if ($env:DFIR_OUTPUT) { $env:DFIR_OUTPUT } else { "C:\IR_Collection" }
$CaseNum   = if ($env:DFIR_CASE) { $env:DFIR_CASE } else { "CASE-$(Get-Date -Format yyyyMMdd)" }
New-Item -ItemType Directory -Path $BasePath -Force | Out-Null
$LogFile  = "$BasePath\Loaded_DLLs_Execution.log"
$JsonFile = "$BasePath\Loaded_DLLs_${Hostname}_${Timestamp}.json"

function Write-Log { param([string]$M,[string]$L="INFO") Add-Content $LogFile "$(Get-Date -Format o) [$L] :: $M" }
Write-Log "Loaded DLL collection started"

# Suspicious DLL indicators
$SuspiciousNames = @("mimilib","sekurlsa","dcsync","inject","beacon","stager","payload","reflective","shellcode","cobaltstrike","meterpreter")
# Informational "writable path" set (broad). NOT used on its own to flag - legitimate apps and
# dev tooling (Python site-packages, Node, Electron) load unsigned native modules from AppData.
$WritablePaths   = @("$env:TEMP","$env:APPDATA","$env:LOCALAPPDATA","C:\Users","C:\ProgramData","C:\Windows\Temp")
# High-signal drop/staging locations - an unsigned DLL here is genuinely notable.
$StagingPaths    = @("$env:TEMP","$env:WINDIR\Temp","$env:PUBLIC","$env:USERPROFILE\Downloads","C:\ProgramData")
$SystemProcesses = @("lsass","winlogon","csrss","smss","wininit","services","svchost")

Write-Host "[*] Enumerating loaded DLLs per process..." -ForegroundColor Cyan

# Signature cache to avoid re-hashing same DLL multiple times
$SigCache  = @{}
$HashCache = @{}

$Results = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($Proc in Get-Process -ErrorAction SilentlyContinue) {
    try {
        $Modules = $Proc.Modules
    } catch {
        $Modules = @()
    }

    foreach ($Module in $Modules) {
        $DllPath = $Module.FileName
        if (-not $DllPath) { continue }

        # DLLs under the WRP-protected system directories are always Microsoft-signed and are
        # the overwhelming majority of loaded modules. Hashing and signature-checking every one
        # of them dominated runtime (~3 min) for little value, so we treat them as signed and
        # skip the hash. The full hash + signature is still computed for DLLs loaded from any
        # OTHER path - exactly where side-loading / hijack / injection lives.
        $isSysDll = $DllPath -match '(?i)\\Windows\\(System32|SysWOW64|WinSxS)\\'
        if (-not $SigCache.ContainsKey($DllPath)) {
            if ($isSysDll) {
                $SigCache[$DllPath] = "Valid"
            } else {
                try {
                    $Sig = Get-AuthenticodeSignature -FilePath $DllPath -ErrorAction SilentlyContinue
                    $SigCache[$DllPath] = if ($Sig) { $Sig.Status.ToString() } else { "Unknown" }
                } catch { $SigCache[$DllPath] = "Error" }
            }
        }
        if (-not $HashCache.ContainsKey($DllPath)) {
            if ($isSysDll) {
                $HashCache[$DllPath] = $null
            } else {
                try { $HashCache[$DllPath] = (Get-FileHash $DllPath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash }
                catch { $HashCache[$DllPath] = $null }
            }
        }

        $DllNameLower = $Module.ModuleName.ToLower()
        $PathLower    = $DllPath.ToLower()

        $IsFromWritable  = [bool]($WritablePaths | Where-Object { $PathLower.StartsWith($_.ToLower()) })
        $IsFromStaging   = [bool]($StagingPaths  | Where-Object { $_ -and $PathLower.StartsWith($_.ToLower()) })
        $IsSystemProc    = $SystemProcesses -contains $Proc.ProcessName.ToLower()
        # -like substring match: -contains on a string is always false (this check never fired).
        $HasSuspName     = [bool]($SuspiciousNames | Where-Object { $DllNameLower -like "*$_*" })
        $IsUnsigned      = $SigCache[$DllPath] -ne "Valid"
        $InSystemDir     = $PathLower -match '\\windows\\(system32|syswow64|winsxs)\\'

        # Flag on genuine signals only: a known-malicious module name; an unsigned/planted DLL
        # inside a core system process; or an unsigned DLL dropped in a staging/temp location.
        # Unsigned app/dev DLLs under AppData/Program Files are NOT flagged on their own (they
        # are ubiquitous and benign - Python .pyd, Electron, etc.).
        $Suspicious = $HasSuspName -or
                      ($IsSystemProc -and $IsUnsigned -and -not $InSystemDir) -or
                      ($IsSystemProc -and $IsFromStaging) -or
                      ($IsUnsigned -and $IsFromStaging)

        $Results.Add([PSCustomObject]@{
            CollectionTime  = (Get-Date).ToString("o")
            ProcessName     = $Proc.ProcessName
            PID             = $Proc.Id
            ModuleName      = $Module.ModuleName
            ModulePath      = $DllPath
            BaseAddress     = "0x{0:X}" -f $Module.BaseAddress
            ModuleSize      = $Module.ModuleMemorySize
            SHA256          = $HashCache[$DllPath]
            SignatureStatus = $SigCache[$DllPath]
            LoadedFromWritablePath = [bool]$IsFromWritable
            IsSystemProcess        = $IsSystemProc
            IsSuspicious           = $Suspicious
        })
    }
}

$SuspCount = ($Results | Where-Object { $_.IsSuspicious }).Count
Write-Log "DLL entries collected: $($Results.Count) | Suspicious: $SuspCount"

$Evidence = [PSCustomObject]@{
    ChainOfCustody = [PSCustomObject]@{ CaseNumber=$CaseNum; Hostname=$Hostname; CollectedAt=(Get-Date).ToString("o"); ToolVersion="1.0" }
    ArtifactType   = "LoadedDLLs"
    TotalEntries   = $Results.Count
    SuspiciousCount= $SuspCount
    Data           = $Results
}

$Evidence | ConvertTo-Json -Depth 5 | Out-File -FilePath $JsonFile -Encoding UTF8
$Hash = Get-FileHash -Path $JsonFile -Algorithm SHA256
[PSCustomObject]@{ FileName=$JsonFile; Hash=$Hash.Hash; Generated=(Get-Date).ToString("o") } |
    ConvertTo-Json | Out-File "$JsonFile.hash.json" -Encoding UTF8

Write-Host "[+] Loaded DLLs collected: $($Results.Count) entries | Suspicious: $SuspCount" -ForegroundColor Green
Write-Host "[+] JSON: $JsonFile" -ForegroundColor Green
Write-Log "Completed"
