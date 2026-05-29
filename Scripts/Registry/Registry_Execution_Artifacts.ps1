#Requires -Version 5.1
<#
.SYNOPSIS
    Collects AmCache, ShimCache (AppCompatCache), BAM/DAM, and UserAssist
    registry artifacts for execution history reconstruction.

.DESCRIPTION
    These registry artifacts survive process termination and file deletion,
    providing evidence of what executed on the system and when:
    - AmCache.hve    : File metadata + SHA1 hash of executed files
    - ShimCache      : Application execution history (no timestamp on Win10+)
    - BAM/DAM        : Background Activity Monitor - per-user execution with timestamps
    - UserAssist     : GUI program execution counts + timestamps (ROT13 encoded)
    - MRU Lists      : Most Recently Used file/command lists

.IR_PHASE
    Execution Evidence / Investigation

.MITRE_ATTCK
    T1059  - Command and Scripting Interpreter
    T1204  - User Execution
    T1036  - Masquerading

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
if (-not $IsAdmin) { Write-Warning "[!] Administrator privileges required for some registry hives." }

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Hostname  = $env:COMPUTERNAME
$BasePath  = if ($env:DFIR_OUTPUT) { $env:DFIR_OUTPUT } else { "C:\IR_Collection" }
$CaseNum   = if ($env:DFIR_CASE) { $env:DFIR_CASE } else { "CASE-$(Get-Date -Format yyyyMMdd)" }
New-Item -ItemType Directory -Path $BasePath -Force | Out-Null
$LogFile  = "$BasePath\Registry_Execution_Artifacts_log.log"
$JsonFile = "$BasePath\Registry_Execution_Artifacts_${Hostname}_${Timestamp}.json"

function Write-Log { param([string]$M,[string]$L="INFO") Add-Content $LogFile "$(Get-Date -Format o) [$L] :: $M" }
Write-Log "Registry execution artifact collection started"

# -- ROT13 decoder for UserAssist -----------------------------------------------
function ConvertFrom-ROT13 {
    param([string]$Text)
    -join ($Text.ToCharArray() | ForEach-Object {
        if ($_ -match '[a-zA-Z]') {
            $Base = if ($_ -cmatch '[A-Z]') { [int][char]'A' } else { [int][char]'a' }
            [char](($([int][char]$_) - $Base + 13) % 26 + $Base)
        } else { $_ }
    })
}

# -- ShimCache (AppCompatCache) -------------------------------------------------
Write-Host "[*] Collecting ShimCache entries..." -ForegroundColor Cyan
$ShimData = [System.Collections.Generic.List[PSCustomObject]]::new()
try {
    $ShimKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache"
    $ShimRaw = (Get-ItemProperty -Path $ShimKey -ErrorAction Stop).AppCompatCache
    # Raw binary - we record the presence and size; full parsing requires external tool (AppCompatCacheParser)
    $ShimData.Add([PSCustomObject]@{
        Note       = "Raw binary cached - use AppCompatCacheParser.exe for full timeline"
        SizeBytes  = $ShimRaw.Length
        RegistryKey= $ShimKey
        Collected  = $true
    })
    Write-Log "ShimCache: raw binary collected ($($ShimRaw.Length) bytes)"
} catch { Write-Log "ShimCache collection error: $_" "WARN" }

# -- BAM / DAM (Background Activity Monitor) -----------------------------------
Write-Host "[*] Collecting BAM/DAM entries..." -ForegroundColor Cyan
$BAMData = [System.Collections.Generic.List[PSCustomObject]]::new()
try {
    $BAMBasePath = "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"
    if (Test-Path $BAMBasePath) {
        Get-ChildItem $BAMBasePath -ErrorAction SilentlyContinue | ForEach-Object {
            $UserSID = $_.PSChildName
            $Values  = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
            foreach ($Prop in $Values.PSObject.Properties) {
                if ($Prop.Name -match "^PS" -or $Prop.Name -in @("SequenceNumber","Version")) { continue }
                # BAM timestamps are stored as 8-byte FILETIME in the value data
                $LastExec = $null
                try {
                    if ($Prop.Value -is [byte[]] -and $Prop.Value.Length -ge 8) {
                        $FT = [System.BitConverter]::ToInt64($Prop.Value, 0)
                        if ($FT -gt 0) { $LastExec = [DateTime]::FromFileTimeUtc($FT).ToString("o") }
                    }
                } catch {}
                $BAMData.Add([PSCustomObject]@{
                    UserSID       = $UserSID
                    ExecutablePath= $Prop.Name
                    LastExecution = $LastExec
                    Source        = "BAM"
                })
            }
        }
    }
    Write-Log "BAM entries: $($BAMData.Count)"
} catch { Write-Log "BAM collection error: $_" "WARN" }

# -- UserAssist -----------------------------------------------------------------
Write-Host "[*] Collecting UserAssist entries..." -ForegroundColor Cyan
$UAData = [System.Collections.Generic.List[PSCustomObject]]::new()
try {
    $UserHives = Get-ChildItem "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist" -ErrorAction SilentlyContinue
    foreach ($GUID in $UserHives) {
        $CountKey = "$($GUID.PSPath)\Count"
        if (Test-Path $CountKey) {
            $Values = Get-ItemProperty $CountKey -ErrorAction SilentlyContinue
            foreach ($Prop in $Values.PSObject.Properties) {
                if ($Prop.Name -match "^PS") { continue }
                $Decoded = ConvertFrom-ROT13 $Prop.Name
                $RunCount = $null; $LastRun = $null
                try {
                    if ($Prop.Value -is [byte[]] -and $Prop.Value.Length -ge 16) {
                        $RunCount = [System.BitConverter]::ToInt32($Prop.Value, 4)
                        $FT = [System.BitConverter]::ToInt64($Prop.Value, 8)
                        if ($FT -gt 0) { $LastRun = [DateTime]::FromFileTimeUtc($FT).ToString("o") }
                    }
                } catch {}
                $UAData.Add([PSCustomObject]@{
                    EncodedName = $Prop.Name
                    DecodedName = $Decoded
                    RunCount    = $RunCount
                    LastRun     = $LastRun
                    GUID        = $GUID.PSChildName
                })
            }
        }
    }
    Write-Log "UserAssist entries: $($UAData.Count)"
} catch { Write-Log "UserAssist error: $_" "WARN" }

# -- MRU Lists -----------------------------------------------------------------
Write-Host "[*] Collecting MRU lists..." -ForegroundColor Cyan
$MRUData = [System.Collections.Generic.List[PSCustomObject]]::new()
$MRUPaths = @(
    @{ Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU";       Type="RunDialog" }
    @{ Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs";   Type="RecentDocs" }
    @{ Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU"; Type="OpenSave" }
    @{ Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths";   Type="TypedPaths" }
)
foreach ($MRU in $MRUPaths) {
    if (Test-Path $MRU.Path) {
        $Vals = Get-ItemProperty $MRU.Path -ErrorAction SilentlyContinue
        foreach ($P in $Vals.PSObject.Properties) {
            if ($P.Name -match "^PS|^MRUList") { continue }
            $MRUData.Add([PSCustomObject]@{
                Type    = $MRU.Type
                Key     = $P.Name
                Value   = if ($P.Value -is [string]) { $P.Value } else { "[Binary]" }
            })
        }
    }
}
Write-Log "MRU entries: $($MRUData.Count)"

# -- AmCache note ---------------------------------------------------------------
$AmCacheNote = [PSCustomObject]@{
    Note    = "AmCache.hve is a locked registry hive. Use AmcacheParser.exe (Eric Zimmerman) on a copy of C:\Windows\AppCompat\Programs\Amcache.hve for full parsing."
    HivePath= "C:\Windows\AppCompat\Programs\Amcache.hve"
    Exists  = (Test-Path "C:\Windows\AppCompat\Programs\Amcache.hve")
}

$Evidence = [PSCustomObject]@{
    ChainOfCustody = [PSCustomObject]@{ CaseNumber=$CaseNum; Hostname=$Hostname; CollectedAt=(Get-Date).ToString("o"); ToolVersion="1.0" }
    ArtifactType   = "RegistryExecutionArtifacts"
    AmCacheNote    = $AmCacheNote
    ShimCache      = $ShimData
    BAM            = $BAMData
    UserAssist     = $UAData
    MRU            = $MRUData
}

$Evidence | ConvertTo-Json -Depth 5 -Compress | Out-File -FilePath $JsonFile -Encoding UTF8
$Hash = Get-FileHash -Path $JsonFile -Algorithm SHA256
[PSCustomObject]@{ FileName=$JsonFile; Hash=$Hash.Hash; Generated=(Get-Date).ToString("o") } |
    ConvertTo-Json | Out-File "$JsonFile.hash.json" -Encoding UTF8

Write-Host "[+] Registry execution artifacts collected | BAM: $($BAMData.Count) | UserAssist: $($UAData.Count) | MRU: $($MRUData.Count)" -ForegroundColor Green
Write-Host "[+] JSON: $JsonFile" -ForegroundColor Green
Write-Log "Completed"
