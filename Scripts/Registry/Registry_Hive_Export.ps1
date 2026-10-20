#Requires -Version 5.1
<#
.SYNOPSIS
    Exports raw registry hive files (SYSTEM, SOFTWARE, SAM, SECURITY, DEFAULT,
    NTUSER, UsrClass, Amcache) WITH their transaction logs for offline analysis.

.DESCRIPTION
    Primary method: a FRESH Volume Shadow Copy of the system volume (one per
    collection run, shared with MFT_USN_Collection and removed at the end), from
    which each hive file is copied byte-for-byte together with its .LOG1/.LOG2
    transaction logs. A raw copy keeps what forensic tools need: deleted keys and
    values in free cells, slack, and the logs to replay a dirty hive (Registry
    Explorer / RECmd / RegRipper).

    Fallback (only when no shadow can be created): "reg save" via the backup API.
    That writes a NEW, re-serialized hive - deleted keys, slack and transaction
    logs are lost - so every such file is labelled "reg save (re-serialized)".

    Previously reg save was the primary method, the VSS fallback read the OLDEST
    existing shadow from `vssadmin list shadows` (a stale hive labelled as
    current), Amcache was "saved" from a registry key it is not mounted at, and
    user profiles were found only under C:\Users.

    Per-user hives are found through the ProfileList (any profile path, local /
    domain / Entra ID). All output files are SHA256-hashed in the JSON manifest.

.COMPATIBILITY
    Windows 10/11 / Server 2016+ : Full (Win32_ShadowCopy.Create works on client SKUs)

.IR_PHASE
    Registry Forensics / Offline Analysis

.MITRE_ATTCK
    T1112 - Modify Registry
    T1552.002 - Credentials in Registry
    T1547.001 - Registry Run Keys / Startup Folder
    T1003.002 - OS Credential Dumping: Security Account Manager

.FORENSIC_SAFETY
    Read-only for the hives. Creating a shadow copy writes copy-on-write data to the
    system volume; the shadow ID is recorded and the shadow is removed afterwards.

.AUTHOR
    Subash J

.VERSION
    2.0
#>

Set-StrictMode -Off
$ErrorActionPreference = "Continue"

# --- Shared toolkit modules ---------------------------------------------------
$__DFIRMod = Join-Path $PSScriptRoot '..\Infrastructure\DFIR_Common.psm1'
if (Test-Path $__DFIRMod) { Import-Module $__DFIRMod -Force -ErrorAction SilentlyContinue }
if (-not $Global:DFIR_ToolVersion) { $Global:DFIR_ToolVersion = '1.1' }
Import-Module (Join-Path $PSScriptRoot '..\Infrastructure\DFIR_RawAcquisition.psm1') -Force -ErrorAction Stop

$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
# throw (not exit): the orchestrator records a throw as Failed; an exit was recorded as "Success".
if (-not $IsAdmin) { throw "Registry_Hive_Export requires Administrator (locked hives, shadow copies)." }

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
Write-Host "[*] Exporting raw registry hives (+ transaction logs) for offline analysis..." -ForegroundColor Cyan

$Results = [System.Collections.Generic.List[PSCustomObject]]::new()

function Add-HiveResult {
    param([string]$Name, [string]$Source, [string[]]$Files, [string]$Method, [string]$Note = "")
    $Files = @($Files | Where-Object { $_ -and (Test-Path -LiteralPath $_) })
    $main = if ($Files.Count) { $Files[0] } else { $null }
    $script:Results.Add([PSCustomObject]@{
        HiveName        = $Name
        Source          = $Source
        Exported        = [bool]$main
        OutputFile      = $main
        SizeBytes       = if ($main) { (Get-Item -LiteralPath $main).Length } else { 0 }
        SHA256          = if ($main) { (Get-FileHash -LiteralPath $main -Algorithm SHA256).Hash } else { "" }
        TransactionLogs = @($Files | Select-Object -Skip 1 | ForEach-Object {
                              [PSCustomObject]@{ File = $_; SHA256 = (Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash } })
        Method          = $Method
        Note            = $Note
    })
}

$SysRoot = $env:SystemDrive.TrimEnd('\') + '\'
$WinRel  = $env:SystemRoot.Substring($SysRoot.Length)
$Shadow  = Get-DfirShadow -Volume $env:SystemDrive -LogFile $LogFile
if ($Shadow) {
    Write-Host "  [*] Reading hives from shadow copy $($Shadow.Id)" -ForegroundColor DarkGray
} else {
    Write-Host "  [!] No shadow copy could be created - falling back to reg save (re-serialized hives, no deleted keys / transaction logs)" -ForegroundColor Yellow
    Write-Log "No shadow copy - reg save fallback only" "WARN"
}

function Export-Hive {
    param([string]$Name, [string]$RelPath, [string]$Dest, [string]$RegKey)
    if ($Shadow) {
        try {
            $files = Copy-DfirFromShadow -Shadow $Shadow -RelPath $RelPath -Destination $Dest -WithTransactionLogs
            if (@($files).Count) {
                Add-HiveResult $Name "$SysRoot$RelPath" $files "VSS raw copy (+transaction logs)" "shadow $($Shadow.Id)"
                Write-Log "Exported $Name from shadow ($(@($files).Count) file(s))"
                return
            }
        } catch { Write-Log "Shadow copy of $Name failed: $_" "WARN" }
    }
    if ($RegKey) {
        try {
            reg save "$RegKey" "$Dest" /y 2>&1 | Out-Null
            if ((Test-Path -LiteralPath $Dest) -and (Get-Item -LiteralPath $Dest).Length -gt 0) {
                Add-HiveResult $Name $RegKey @($Dest) "reg save (re-serialized)" "NOT a raw copy: deleted keys, slack and transaction logs are absent"
                Write-Log "Exported $Name via reg save (re-serialized)" "WARN"
                return
            }
        } catch { Write-Log "reg save of $Name failed: $_" "WARN" }
    }
    Add-HiveResult $Name "$SysRoot$RelPath" @() "none" "Not exported (no shadow copy, and not saveable) - acquire from a disk image"
    Write-Host "    [!] Could not export $Name" -ForegroundColor Yellow
}

# -- System hives ---------------------------------------------------------------
foreach ($h in @(
    @{ N = "SYSTEM";   K = "HKLM\SYSTEM" }, @{ N = "SOFTWARE"; K = "HKLM\SOFTWARE" },
    @{ N = "SAM";      K = "HKLM\SAM" },    @{ N = "SECURITY"; K = "HKLM\SECURITY" },
    @{ N = "DEFAULT";  K = "HKU\.DEFAULT" })) {
    Write-Host "  [*] $($h.N)" -ForegroundColor Cyan
    Export-Hive -Name $h.N -RelPath "$WinRel\System32\config\$($h.N)" -Dest "$OutDir\$($h.N)" -RegKey $h.K
}

# -- Amcache.hve (execution evidence; not a mounted key - shadow or nothing) --------
Write-Host "  [*] Amcache.hve" -ForegroundColor Cyan
if (Test-Path -LiteralPath "$env:SystemRoot\AppCompat\Programs\Amcache.hve") {
    Export-Hive -Name "Amcache.hve" -RelPath "$WinRel\AppCompat\Programs\Amcache.hve" -Dest "$OutDir\Amcache.hve" -RegKey $null
} else {
    Add-HiveResult "Amcache.hve" "$env:SystemRoot\AppCompat\Programs\Amcache.hve" @() "none" "Amcache.hve not present on this system"
}

# -- Per-user NTUSER.DAT and UsrClass.dat ---------------------------------------------
Write-Host "  [*] Per-user NTUSER.DAT / UsrClass.dat (ProfileList)" -ForegroundColor Cyan
$UserCount = 0
foreach ($P in (Get-DfirUserProfiles)) {
    $Tag = $P.Name -replace '[^\w.-]', '_'
    if (-not $P.Path.StartsWith($SysRoot, [StringComparison]::OrdinalIgnoreCase)) {
        Add-HiveResult "NTUSER.DAT ($($P.Name))" $P.Path @() "none" "Profile is not on the system volume - not in this shadow copy"
        continue
    }
    $Rel = $P.Path.Substring($SysRoot.Length)
    $NtKey = if ($P.Sid -and (Test-Path "Registry::HKEY_USERS\$($P.Sid)")) { "HKU\$($P.Sid)" } else { $null }
    $UcKey = if ($P.Sid -and (Test-Path "Registry::HKEY_USERS\$($P.Sid)_Classes")) { "HKU\$($P.Sid)_Classes" } else { $null }
    if (Test-Path -LiteralPath "$($P.Path)\NTUSER.DAT") {
        Export-Hive -Name "NTUSER.DAT ($($P.Name))" -RelPath "$Rel\NTUSER.DAT" -Dest "$OutDir\NTUSER_$Tag.DAT" -RegKey $NtKey
        $UserCount++
    }
    if (Test-Path -LiteralPath "$($P.Path)\AppData\Local\Microsoft\Windows\UsrClass.dat") {
        Export-Hive -Name "UsrClass.dat ($($P.Name))" -RelPath "$Rel\AppData\Local\Microsoft\Windows\UsrClass.dat" -Dest "$OutDir\UsrClass_$Tag.dat" -RegKey $UcKey
    }
}

# Standalone run: remove the shadow we created. Under the orchestrator it is shared
# with later scripts and removed once at the end of the run.
if ($Shadow -and $Shadow.Created -and -not $env:DFIR_ORCHESTRATED) { Remove-DfirShadows -LogFile $LogFile }

# -- Evidence manifest ----------------------------------------------------------
$Exported = @($Results | Where-Object { $_.Exported })
$Failed   = @($Results | Where-Object { -not $_.Exported })
$Evidence = [PSCustomObject]@{
    ChainOfCustody = [PSCustomObject]@{
        CaseNumber  = $CaseNum
        Hostname    = $Hostname
        CollectedAt = ([DateTime]::UtcNow).ToString("o")
        ToolVersion = $Global:DFIR_ToolVersion
    }
    ArtifactType     = "RegistryHiveExport"
    OutputDirectory  = $OutDir
    ShadowCopy       = if ($Shadow) { [PSCustomObject]@{ Id = $Shadow.Id; Device = $Shadow.Device; CreatedByToolkit = $true } } else { $null }
    HivesExported    = $Exported.Count
    HivesRawCopy     = @($Exported | Where-Object { $_.Method -like 'VSS*' }).Count
    HivesReSerialized = @($Exported | Where-Object { $_.Method -like 'reg save*' }).Count
    HivesFailed      = $Failed.Count
    PerUserProfiles  = $UserCount
    Results          = $Results
    ParseNote        = "Parse with Registry Explorer / RECmd (replays .LOG1/.LOG2 automatically), RegRipper, or AmcacheParser for Amcache.hve. SAM + SYSTEM together enable offline local password-hash analysis."
}
$Evidence | ConvertTo-Json -Depth 6 | Out-File -FilePath $JsonFile -Encoding UTF8
$Hash = Get-FileHash -Path $JsonFile -Algorithm SHA256
[PSCustomObject]@{ FileName=$JsonFile; Hash=$Hash.Hash; Generated=([DateTime]::UtcNow).ToString("o") } |
    ConvertTo-Json | Out-File "$JsonFile.hash.json" -Encoding UTF8

Write-Host "[+] Registry hive export complete | Raw (VSS): $($Evidence.HivesRawCopy) | Re-serialized: $($Evidence.HivesReSerialized) | Failed: $($Failed.Count) | Profiles: $UserCount" -ForegroundColor Green
Write-Host "[+] Output: $OutDir" -ForegroundColor Green
Write-Log "Completed | raw $($Evidence.HivesRawCopy) | re-serialized $($Evidence.HivesReSerialized) | failed $($Failed.Count)"
