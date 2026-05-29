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
$SuspiciousNames = @("mimilib","sekurlsa","kerberos","wdigest","dcsync","inject","hook","bypass","loader","beacon","stager","payload","reflective","shellcode")
$WritablePaths   = @("$env:TEMP","$env:APPDATA","$env:LOCALAPPDATA","C:\Users","C:\ProgramData","C:\Windows\Temp")
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

        # Get or compute signature
        if (-not $SigCache.ContainsKey($DllPath)) {
            try {
                $Sig = Get-AuthenticodeSignature -FilePath $DllPath -ErrorAction SilentlyContinue
                $SigCache[$DllPath] = if ($Sig) { $Sig.Status.ToString() } else { "Unknown" }
            } catch { $SigCache[$DllPath] = "Error" }
        }
        if (-not $HashCache.ContainsKey($DllPath)) {
            try { $HashCache[$DllPath] = (Get-FileHash $DllPath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash }
            catch { $HashCache[$DllPath] = $null }
        }

        $DllNameLower = $Module.ModuleName.ToLower()
        $PathLower    = $DllPath.ToLower()

        $IsFromWritable  = $WritablePaths | Where-Object { $PathLower.StartsWith($_.ToLower()) }
        $IsSystemProc    = $SystemProcesses -contains $Proc.ProcessName.ToLower()
        $HasSuspName     = $SuspiciousNames | Where-Object { $DllNameLower -contains $_ }
        $IsUnsigned      = $SigCache[$DllPath] -ne "Valid"

        $Suspicious = ($IsFromWritable -and $IsSystemProc) -or $HasSuspName -or
                      ($IsFromWritable -and $IsUnsigned) -or
                      ($IsSystemProc -and $IsUnsigned -and -not ($PathLower -like "*windows\system32*"))

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
