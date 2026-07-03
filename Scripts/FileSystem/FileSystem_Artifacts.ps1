#Requires -Version 5.1
<#
.SYNOPSIS
    Collects filesystem artifacts: recent files, temp dirs, ADS, suspicious drops.

.DESCRIPTION
    Enumerates LNK files (recently accessed), JumpLists, files in common
    malware drop locations, Alternate Data Streams, downloads folders,
    and recently modified executables.

.IR_PHASE
    Execution Evidence / Investigation

.MITRE_ATTCK
    T1036  - Masquerading
    T1027  - Obfuscated Files
    T1564  - Hide Artifacts
    T1074  - Data Staged

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

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Hostname  = $env:COMPUTERNAME
$BasePath  = if ($env:DFIR_OUTPUT) { $env:DFIR_OUTPUT } else { "C:\IR_Collection" }
$CaseNum   = if ($env:DFIR_CASE) { $env:DFIR_CASE } else { "CASE-$(Get-Date -Format yyyyMMdd)" }
New-Item -ItemType Directory -Path $BasePath -Force | Out-Null
$LogFile  = "$BasePath\FileSystem_Artifacts_Execution.log"
$JsonFile = "$BasePath\FileSystem_Artifacts_${Hostname}_${Timestamp}.json"

function Write-Log { param([string]$M,[string]$L="INFO") Add-Content $LogFile "$(Get-Date -Format o) [$L] :: $M" }
Write-Log "FileSystem artifact collection started"

$DaysBack  = if ($env:DFIR_DAYS) { [int]$env:DFIR_DAYS } else { 30 }
$SinceDate = (Get-Date).AddDays(-$DaysBack)

# -- Recent LNK Files (shell:recent) -------------------------------------------
Write-Host "[*] Collecting recent LNK files..." -ForegroundColor Cyan
$LNKData = [System.Collections.Generic.List[PSCustomObject]]::new()
$WshShell = New-Object -ComObject WScript.Shell
Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    $RecentPath = "$($_.FullName)\AppData\Roaming\Microsoft\Windows\Recent"
    if (Test-Path $RecentPath) {
        Get-ChildItem $RecentPath -Filter "*.lnk" -ErrorAction SilentlyContinue | ForEach-Object {
            $Target = $null
            try { $Target = $WshShell.CreateShortcut($_.FullName).TargetPath } catch {}
            $LNKData.Add([PSCustomObject]@{
                User           = (Split-Path (Split-Path (Split-Path (Split-Path $_.FullName)))) | Split-Path -Leaf
                LNKFile        = $_.Name
                LNKPath        = $_.FullName
                TargetPath     = $Target
                LastWriteTime  = $_.LastWriteTimeUtc.ToString("o")
                CreationTime   = $_.CreationTimeUtc.ToString("o")
            })
        }
    }
}
Write-Log "LNK files: $($LNKData.Count)"

# -- Common Malware Drop Locations ---------------------------------------------
Write-Host "[*] Scanning malware drop locations..." -ForegroundColor Cyan
$SuspiciousDrops = [System.Collections.Generic.List[PSCustomObject]]::new()
$DropPaths = @(
    $env:TEMP, "$env:WINDIR\Temp", "$env:APPDATA",
    "$env:LOCALAPPDATA\Temp", "$env:LOCALAPPDATA",
    "C:\ProgramData", "$env:PUBLIC", "C:\Windows\System32\Tasks",
    "$env:LOCALAPPDATA\Microsoft\Windows\INetCache"
)
$ExeExtensions = @(".exe",".dll",".bat",".cmd",".vbs",".js",".ps1",".hta",".scr",".pif",".com")

foreach ($DropPath in $DropPaths) {
    if (-not (Test-Path $DropPath)) { continue }
    Get-ChildItem $DropPath -Force -ErrorAction SilentlyContinue |
        Where-Object { $ExeExtensions -contains $_.Extension.ToLower() -and $_.LastWriteTimeUtc -gt $SinceDate } |
        ForEach-Object {
            $Hash = $null
            try { $Hash = (Get-FileHash $_.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash } catch {}
            $Sig = $null
            try { $Sig = (Get-AuthenticodeSignature $_.FullName -ErrorAction SilentlyContinue).Status.ToString() } catch {}
            $SuspiciousDrops.Add([PSCustomObject]@{
                Path          = $_.FullName
                FileName      = $_.Name
                Extension     = $_.Extension
                SizeBytes     = $_.Length
                CreationTime  = $_.CreationTimeUtc.ToString("o")
                LastWriteTime = $_.LastWriteTimeUtc.ToString("o")
                SHA256        = $Hash
                Signature     = $Sig
                DropLocation  = $DropPath
            })
        }
}
Write-Log "Suspicious drop files: $($SuspiciousDrops.Count)"

# -- Alternate Data Streams -----------------------------------------------------
Write-Host "[*] Scanning for Alternate Data Streams (ADS)..." -ForegroundColor Cyan
$ADSData = [System.Collections.Generic.List[PSCustomObject]]::new()
$ADSScanPaths = @($env:TEMP, "$env:WINDIR\Temp", $env:APPDATA, "C:\ProgramData")
foreach ($APath in $ADSScanPaths) {
    if (-not (Test-Path $APath)) { continue }
    # Depth-limit and files-only: an unbounded recursive stream-enumeration over AppData /
    # ProgramData took many minutes. Depth 3 covers the realistic staging locations.
    Get-ChildItem $APath -Force -Recurse -Depth 3 -File -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            $Streams = Get-Item $_.FullName -Stream * -ErrorAction SilentlyContinue |
                       Where-Object { $_.Stream -ne ":$DATA" -and $_.Stream -ne "Zone.Identifier" }
            foreach ($Stream in $Streams) {
                $ADSData.Add([PSCustomObject]@{
                    FilePath    = $_.FullName
                    StreamName  = $Stream.Stream
                    StreamSize  = $Stream.Length
                    LastWrite   = $_.LastWriteTimeUtc.ToString("o")
                    Note        = "Non-standard ADS detected"
                })
            }
        } catch {}
    }
}
Write-Log "ADS entries found: $($ADSData.Count)"

# -- Zone Identifier / Mark of the Web -----------------------------------------
Write-Host "[*] Collecting Zone Identifier (Mark of the Web) on recent executables..." -ForegroundColor Cyan
# Scope Mark-of-the-Web scanning to the folders downloaded files land in, per user, rather
# than recursing all of C:\Users (which pulls in every AppData tree).
$ZoneData = [System.Collections.Generic.List[PSCustomObject]]::new()
$ZoneScanPaths = [System.Collections.Generic.List[string]]::new()
$ZoneScanPaths.Add($env:TEMP); $ZoneScanPaths.Add($env:APPDATA)
foreach ($u in (Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue)) {
    foreach ($s in @("Downloads","Desktop","Documents")) { $ZoneScanPaths.Add((Join-Path $u.FullName $s)) }
}
foreach ($DropPath in $ZoneScanPaths) {
    if (-not (Test-Path $DropPath)) { continue }
    Get-ChildItem $DropPath -Force -Recurse -ErrorAction SilentlyContinue -Depth 3 -File |
        Where-Object { $ExeExtensions -contains $_.Extension.ToLower() } |
        ForEach-Object {
            try {
                $Zone = Get-Content "$($_.FullName):Zone.Identifier" -ErrorAction SilentlyContinue
                if ($Zone) {
                    $ZoneID  = if ($Zone -match "ZoneId=(\d)") { $Matches[1] } else { $null }
                    $RefURL  = if ($Zone -match "ReferrerUrl=(.+)") { $Matches[1] } else { $null }
                    $HostURL = if ($Zone -match "HostUrl=(.+)") { $Matches[1] } else { $null }
                    $ZoneLabel = switch ($ZoneID) { "0"{"Local"} "1"{"Intranet"} "2"{"Trusted"} "3"{"Internet"} "4"{"Untrusted"} default {"Unknown"} }
                    $ZoneData.Add([PSCustomObject]@{
                        FilePath    = $_.FullName
                        ZoneID      = $ZoneID
                        ZoneLabel   = $ZoneLabel
                        ReferrerUrl = $RefURL
                        HostUrl     = $HostURL
                        LastWrite   = $_.LastWriteTimeUtc.ToString("o")
                    })
                }
            } catch {}
        }
}
Write-Log "Zone identifier entries: $($ZoneData.Count)"

# -- Recently Modified System Files --------------------------------------------
Write-Host "[*] Scanning recently modified executables in System32..." -ForegroundColor Cyan
$RecentSysFiles = @(
    Get-ChildItem "C:\Windows\System32" -Filter "*.exe" -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTimeUtc -gt $SinceDate } |
        ForEach-Object { [PSCustomObject]@{
            Path         = $_.FullName
            LastModified = $_.LastWriteTimeUtc.ToString("o")
            SizeBytes    = $_.Length
            SHA256       = (Get-FileHash $_.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
        }}
)
Write-Log "Recently modified system files: $($RecentSysFiles.Count)"

# -- Shadow Copies -------------------------------------------------------------
Write-Host "[*] Enumerating shadow copies (VSS)..." -ForegroundColor Cyan
$ShadowCopies = @(Get-CimInstance Win32_ShadowCopy -ErrorAction SilentlyContinue | ForEach-Object {
    [PSCustomObject]@{
        ID           = $_.ID
        VolumeName   = $_.VolumeName
        DeviceName   = $_.DeviceObject
        CreationDate = $null
        ClientAccessible = $_.ClientAccessible
    }
})
Write-Log "Shadow copies: $($ShadowCopies.Count)"

$Evidence = [PSCustomObject]@{
    ChainOfCustody    = [PSCustomObject]@{ CaseNumber=$CaseNum; Hostname=$Hostname; CollectedAt=(Get-Date).ToString("o"); ToolVersion="1.0"; DaysBack=$DaysBack }
    ArtifactType      = "FileSystemArtifacts"
    RecentLNKFiles    = $LNKData
    SuspiciousDrops   = $SuspiciousDrops
    AlternateDataStreams = $ADSData
    ZoneIdentifiers   = $ZoneData
    RecentSystemFiles = $RecentSysFiles
    ShadowCopies      = $ShadowCopies
}

$Evidence | ConvertTo-Json -Depth 7 | Out-File -FilePath $JsonFile -Encoding UTF8
$Hash = Get-FileHash -Path $JsonFile -Algorithm SHA256
[PSCustomObject]@{ FileName=$JsonFile; Hash=$Hash.Hash; Generated=(Get-Date).ToString("o") } |
    ConvertTo-Json | Out-File "$JsonFile.hash.json" -Encoding UTF8

Write-Host "[+] FileSystem artifacts collected" -ForegroundColor Green
Write-Host "    LNK: $($LNKData.Count) | Drops: $($SuspiciousDrops.Count) | ADS: $($ADSData.Count) | ZoneID: $($ZoneData.Count)" -ForegroundColor Cyan
Write-Host "[+] JSON: $JsonFile" -ForegroundColor Green
Write-Log "Completed"
