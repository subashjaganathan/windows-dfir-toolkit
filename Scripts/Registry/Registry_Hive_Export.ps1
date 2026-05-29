#Requires -Version 5.1
<#
.SYNOPSIS
    Exports raw registry hive files (SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER,
    UsrClass, Amcache) for offline forensic analysis.

.DESCRIPTION
    Copies the raw registry hive files from a live Windows system so they can be
    parsed offline with RegRipper, Registry Explorer, or AmcacheParser. The
    primary registry hives are locked while Windows is running, so this script
    uses "reg save" (which leverages the backup API) as the main method, with a
    VSS shadow-copy fallback for hives that reg save cannot capture. Per-user
    NTUSER.DAT and UsrClass.dat hives are collected for every loaded profile.
    Amcache.hve is also copied as it is a primary execution-evidence artifact.

    All output hive files are SHA256-hashed and recorded in a chain-of-custody
    JSON manifest. This is a read-only collection: no hive is modified.

.COMPATIBILITY
    Windows 10/11 / Server 2016+ : Full

.IR_PHASE
    Registry Forensics / Offline Analysis

.MITRE_ATTCK
    T1112 - Modify Registry
    T1552.002 - Credentials in Registry
    T1547.001 - Registry Run Keys / Startup Folder
    T1003.002 - OS Credential Dumping: Security Account Manager

.FORENSIC_SAFETY
    Read-only. Uses reg save (backup API) and VSS copy; never writes to a hive.

.AUTHOR
    Subash J

.VERSION
    1.0
#>

Set-StrictMode -Off
$ErrorActionPreference = "Continue"
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) { Write-Error "[!] Must run as Administrator."; exit 1 }

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Hostname  = $env:COMPUTERNAME
$BasePath  = if ($env:DFIR_OUTPUT) { $env:DFIR_OUTPUT } else { "C:\IR_Collection" }
$CaseNum   = if ($env:DFIR_CASE) { $env:DFIR_CASE } else { "CASE-$(Get-Date -Format yyyyMMdd)" }
$OutDir    = "$BasePath\RegistryHives_${Hostname}_${Timestamp}"
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$LogFile  = "$BasePath\Registry_Hive_Export_Execution.log"
$JsonFile = "$BasePath\Registry_Hive_Export_${Hostname}_${Timestamp}.json"

function Write-Log { param([string]$M,[string]$L="INFO") Add-Content $LogFile "$(Get-Date -Format o) [$L] :: $M" }
Write-Log "Registry hive export started | Case: $CaseNum"

Write-Host "[*] Exporting raw registry hives for offline analysis..." -ForegroundColor Cyan

$Results = [System.Collections.Generic.List[PSCustomObject]]::new()

function Add-HiveResult {
    param([string]$Name,[string]$Source,[string]$Dest,[bool]$Copied,[string]$Method,[string]$Note="")
    $Size = if ($Copied -and (Test-Path $Dest)) { (Get-Item $Dest -ErrorAction SilentlyContinue).Length } else { 0 }
    $Hash = ""
    if ($Copied -and $Size -gt 0) {
        try { $Hash = (Get-FileHash -Path $Dest -Algorithm SHA256 -ErrorAction Stop).Hash } catch { $Hash = "" }
    }
    $script:Results.Add([PSCustomObject]@{
        HiveName   = $Name
        Source     = $Source
        Exported   = $Copied
        OutputFile = if ($Copied) { $Dest } else { $null }
        SizeBytes  = $Size
        SHA256     = $Hash
        Method     = $Method
        Note       = $Note
    })
}

# -- System hives via reg save (backup API handles the lock) --------------------
$SystemHives = @{
    "SYSTEM"   = "HKLM\SYSTEM"
    "SOFTWARE" = "HKLM\SOFTWARE"
    "SAM"      = "HKLM\SAM"
    "SECURITY" = "HKLM\SECURITY"
}

foreach ($HiveName in $SystemHives.Keys) {
    $RegPath = $SystemHives[$HiveName]
    $Dest    = "$OutDir\$HiveName"
    Write-Host "  [*] Exporting $HiveName hive..." -ForegroundColor Cyan
    $Copied = $false

    # Method 1: reg save (uses SeBackupPrivilege, works on locked hives)
    try {
        $RegResult = reg save "$RegPath" "$Dest" /y 2>&1
        if ((Test-Path $Dest) -and (Get-Item $Dest).Length -gt 0) {
            $Copied = $true
            Add-HiveResult $HiveName $RegPath $Dest $true "reg save (backup API)"
            Write-Log "Exported $HiveName via reg save ($((Get-Item $Dest).Length) bytes)"
        } else {
            Write-Log "reg save produced no output for ${HiveName}: $RegResult" "WARN"
        }
    } catch {
        Write-Log "reg save failed for ${HiveName}: $_" "WARN"
    }

    # Method 2: VSS shadow copy fallback
    if (-not $Copied) {
        try {
            $VSSResult = (vssadmin list shadows /for=C: 2>&1) -join " "
            if ($VSSResult -match "Shadow Copy Volume Name:\s*(\S+)") {
                $ShadowPath = $Matches[1].TrimEnd("\")
                $HiveSource = "${ShadowPath}\Windows\System32\config\$HiveName"
                Copy-Item $HiveSource $Dest -Force -ErrorAction Stop
                if ((Test-Path $Dest) -and (Get-Item $Dest).Length -gt 0) {
                    $Copied = $true
                    Add-HiveResult $HiveName $HiveSource $Dest $true "VSS shadow copy"
                    Write-Log "Exported $HiveName via VSS shadow copy"
                }
            }
        } catch {
            Write-Log "VSS copy failed for ${HiveName}: $_" "WARN"
        }
    }

    if (-not $Copied) {
        Add-HiveResult $HiveName $RegPath "" $false "none" "Locked and no VSS available - image disk offline to recover this hive"
        Write-Host "    [!] Could not export $HiveName (locked, no VSS)" -ForegroundColor Yellow
        Write-Log "Could not export $HiveName - no method succeeded" "WARN"
    }
}

# -- Amcache.hve (execution evidence) -------------------------------------------
Write-Host "  [*] Exporting Amcache.hve..." -ForegroundColor Cyan
$AmcacheSrc  = "C:\Windows\AppCompat\Programs\Amcache.hve"
$AmcacheDest = "$OutDir\Amcache.hve"
$AmcacheCopied = $false
if (Test-Path $AmcacheSrc) {
    # Method 1: reg save against the live, auto-loaded Amcache key (backup API handles lock)
    try {
        $AmKey = "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Amcache"
        # The Amcache.hve is mounted at this key on most systems; if not, fall back below
        reg query "$AmKey" 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            reg save "$AmKey" "$AmcacheDest" /y 2>&1 | Out-Null
        }
        if ((Test-Path $AmcacheDest) -and (Get-Item $AmcacheDest).Length -gt 0) {
            $AmcacheCopied = $true
            Add-HiveResult "Amcache.hve" $AmcacheSrc $AmcacheDest $true "reg save (backup API)"
            Write-Log "Exported Amcache via reg save"
        }
    } catch { Write-Log "Amcache reg save failed: $_" "WARN" }

    # Method 1b: direct copy (works if not currently locked)
    if (-not $AmcacheCopied) {
        try {
            Copy-Item $AmcacheSrc $AmcacheDest -Force -ErrorAction Stop
            if ((Test-Path $AmcacheDest) -and (Get-Item $AmcacheDest).Length -gt 0) {
                $AmcacheCopied = $true
                Add-HiveResult "Amcache.hve" $AmcacheSrc $AmcacheDest $true "direct copy"
                Write-Log "Exported Amcache.hve via direct copy"
            }
        } catch {
            Write-Log "Amcache direct copy failed: $_" "WARN"
        }
    }
    if (-not $AmcacheCopied) {
        try {
            $VSSResult = (vssadmin list shadows /for=C: 2>&1) -join " "
            if ($VSSResult -match "Shadow Copy Volume Name:\s*(\S+)") {
                $ShadowPath = $Matches[1].TrimEnd("\")
                $AmSrc = "${ShadowPath}\Windows\AppCompat\Programs\Amcache.hve"
                Copy-Item $AmSrc $AmcacheDest -Force -ErrorAction Stop
                if ((Test-Path $AmcacheDest) -and (Get-Item $AmcacheDest).Length -gt 0) {
                    $AmcacheCopied = $true
                    Add-HiveResult "Amcache.hve" $AmSrc $AmcacheDest $true "VSS shadow copy"
                    Write-Log "Exported Amcache.hve via VSS"
                }
            }
        } catch { Write-Log "Amcache VSS copy failed: $_" "WARN" }
    }
    if (-not $AmcacheCopied) {
        Add-HiveResult "Amcache.hve" $AmcacheSrc "" $false "none" "Locked - parse offline with AmcacheParser.exe (Eric Zimmerman)"
        Write-Host "    [!] Amcache.hve locked - offline extraction required" -ForegroundColor Yellow
    }
} else {
    Add-HiveResult "Amcache.hve" $AmcacheSrc "" $false "none" "Amcache.hve not present on this system"
    Write-Log "Amcache.hve not present"
}

# -- Per-user NTUSER.DAT and UsrClass.dat ---------------------------------------
Write-Host "  [*] Exporting per-user NTUSER.DAT and UsrClass.dat hives..." -ForegroundColor Cyan
$UserCount = 0
$ProfileList = @(Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -notin @("Public","Default","Default User","All Users") })

# Build a map of loaded user hives: SID -> profile path (from HKEY_USERS)
$LoadedSids = @{}
try {
    $ProfKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
    Get-ChildItem $ProfKey -ErrorAction SilentlyContinue | ForEach-Object {
        $sid  = Split-Path $_.Name -Leaf
        $path = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).ProfileImagePath
        if ($path) { $LoadedSids[$path.ToLower()] = $sid }
    }
} catch { Write-Log "Could not enumerate ProfileList: $_" "WARN" }

foreach ($Profile in $ProfileList) {
    $UserName = $Profile.Name
    $ProfPath = $Profile.FullName.ToLower()
    $Sid = $LoadedSids[$ProfPath]

    # NTUSER.DAT
    $NtuserSrc  = "$($Profile.FullName)\NTUSER.DAT"
    $NtuserDest = "$OutDir\NTUSER_${UserName}.DAT"
    if (Test-Path $NtuserSrc) {
        $Done = $false
        # Method 1: direct copy (works if profile not loaded)
        try {
            Copy-Item $NtuserSrc $NtuserDest -Force -ErrorAction Stop
            if ((Test-Path $NtuserDest) -and (Get-Item $NtuserDest).Length -gt 0) {
                $Done = $true; $UserCount++
                Add-HiveResult "NTUSER.DAT ($UserName)" $NtuserSrc $NtuserDest $true "direct copy"
                Write-Log "Exported NTUSER.DAT for $UserName via copy"
            }
        } catch { Write-Log "NTUSER.DAT copy locked for $UserName, trying reg save" "WARN" }

        # Method 2: reg save against loaded HKEY_USERS\<SID> (backup API handles the lock)
        if (-not $Done -and $Sid -and (Test-Path "Registry::HKEY_USERS\$Sid")) {
            try {
                reg save "HKU\$Sid" "$NtuserDest" /y 2>&1 | Out-Null
                if ((Test-Path $NtuserDest) -and (Get-Item $NtuserDest).Length -gt 0) {
                    $Done = $true; $UserCount++
                    Add-HiveResult "NTUSER.DAT ($UserName)" "HKU\$Sid" $NtuserDest $true "reg save (backup API)"
                    Write-Log "Exported NTUSER.DAT for $UserName via reg save"
                }
            } catch { Write-Log "NTUSER.DAT reg save failed for ${UserName}: $_" "WARN" }
        }

        if (-not $Done) {
            Add-HiveResult "NTUSER.DAT ($UserName)" $NtuserSrc "" $false "none" "Loaded/locked and not in HKEY_USERS - recover from disk image or VSS offline"
        }
    }

    # UsrClass.dat
    $UsrClassSrc  = "$($Profile.FullName)\AppData\Local\Microsoft\Windows\UsrClass.dat"
    $UsrClassDest = "$OutDir\UsrClass_${UserName}.dat"
    if (Test-Path $UsrClassSrc) {
        $UDone = $false
        try {
            Copy-Item $UsrClassSrc $UsrClassDest -Force -ErrorAction Stop
            if ((Test-Path $UsrClassDest) -and (Get-Item $UsrClassDest).Length -gt 0) {
                $UDone = $true
                Add-HiveResult "UsrClass.dat ($UserName)" $UsrClassSrc $UsrClassDest $true "direct copy"
                Write-Log "Exported UsrClass.dat for $UserName via copy"
            }
        } catch { Write-Log "UsrClass.dat copy locked for $UserName, trying reg save" "WARN" }

        # UsrClass loads under HKU\<SID>_Classes
        if (-not $UDone -and $Sid -and (Test-Path "Registry::HKEY_USERS\${Sid}_Classes")) {
            try {
                reg save "HKU\${Sid}_Classes" "$UsrClassDest" /y 2>&1 | Out-Null
                if ((Test-Path $UsrClassDest) -and (Get-Item $UsrClassDest).Length -gt 0) {
                    $UDone = $true
                    Add-HiveResult "UsrClass.dat ($UserName)" "HKU\${Sid}_Classes" $UsrClassDest $true "reg save (backup API)"
                    Write-Log "Exported UsrClass.dat for $UserName via reg save"
                }
            } catch { Write-Log "UsrClass.dat reg save failed for ${UserName}: $_" "WARN" }
        }

        if (-not $UDone) {
            Add-HiveResult "UsrClass.dat ($UserName)" $UsrClassSrc "" $false "none" "Loaded/locked - recover offline"
        }
    }
}

# -- Evidence manifest ----------------------------------------------------------
$Exported = @($Results | Where-Object { $_.Exported })
$Failed   = @($Results | Where-Object { -not $_.Exported })

$Evidence = [PSCustomObject]@{
    ChainOfCustody = [PSCustomObject]@{
        CaseNumber  = $CaseNum
        Hostname    = $Hostname
        CollectedAt = (Get-Date).ToString("o")
        ToolVersion = "1.0"
    }
    ArtifactType    = "RegistryHiveExport"
    OutputDirectory = $OutDir
    HivesExported   = $Exported.Count
    HivesFailed     = $Failed.Count
    PerUserProfiles = $UserCount
    Results         = $Results
    ParseNote       = "Parse with RegRipper (rip.exe), Registry Explorer (Eric Zimmerman), or AmcacheParser.exe for Amcache.hve. SAM + SYSTEM together enable offline local password-hash analysis."
}

try {
    $Evidence | ConvertTo-Json -Depth 5 -Compress | Out-File -FilePath $JsonFile -Encoding UTF8
} catch {
    Write-Log "JSON serialization failed: $_" "WARN"
    $Evidence | ConvertTo-Json -Depth 3 -Compress | Out-File -FilePath $JsonFile -Encoding UTF8
}
$Hash = Get-FileHash -Path $JsonFile -Algorithm SHA256
[PSCustomObject]@{ FileName=$JsonFile; Hash=$Hash.Hash; Generated=(Get-Date).ToString("o") } |
    ConvertTo-Json | Out-File "$JsonFile.hash.json" -Encoding UTF8

Write-Host "[+] Registry hive export complete | Exported: $($Exported.Count) | Failed: $($Failed.Count) | User profiles: $UserCount" -ForegroundColor Green
Write-Host "[+] Output: $OutDir" -ForegroundColor Green
Write-Host "[+] JSON  : $JsonFile" -ForegroundColor Green
Write-Log "Completed | Exported: $($Exported.Count) | Failed: $($Failed.Count)"
