#Requires -Version 5.1
Set-StrictMode -Off
$ErrorActionPreference = "Continue"
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Hostname  = $env:COMPUTERNAME
$BasePath  = if ($env:DFIR_OUTPUT) { $env:DFIR_OUTPUT } else { "C:\IR_Collection" }
$CaseNum   = if ($env:DFIR_CASE) { $env:DFIR_CASE } else { "CASE-$(Get-Date -Format yyyyMMdd)" }
New-Item -ItemType Directory -Path $BasePath -Force | Out-Null
$LogFile  = "$BasePath\Patch_Level_Execution.log"
$JsonFile = "$BasePath\Patch_Level_${Hostname}_${Timestamp}.json"

function Write-Log { param([string]$M,[string]$L="INFO") Add-Content $LogFile "$(Get-Date -Format o) [$L] :: $M" }
Write-Log "Patch level collection started | Case: $CaseNum"

# Installed hotfixes
Write-Host "[*] Collecting installed hotfixes..." -ForegroundColor Cyan
# Collect hotfixes with locale-safe date handling
$RawHotfixes = @(Get-HotFix -ErrorAction SilentlyContinue)
$HotfixList  = [System.Collections.Generic.List[PSCustomObject]]::new()
foreach ($HF in $RawHotfixes) {
    $SortDate = [datetime]::MinValue
    try { if ($HF.InstalledOn) { $SortDate = [datetime]$HF.InstalledOn } } catch {}
    $HotfixList.Add([PSCustomObject]@{
        HotFixID    = $HF.HotFixID
        Description = $HF.Description
        InstalledOn = if ($HF.InstalledOn) { try { ([datetime]$HF.InstalledOn).ToString("o") } catch { $HF.InstalledOn.ToString() } } else { $null }
        InstalledBy = $HF.InstalledBy
        SortDate    = $SortDate
    })
}
$Hotfixes = @($HotfixList | Sort-Object SortDate -Descending)
Write-Log "Hotfixes installed: $($Hotfixes.Count)"

# Windows Update history via COM
Write-Host "[*] Collecting Windows Update history..." -ForegroundColor Cyan
$UpdateHistory = [System.Collections.Generic.List[PSCustomObject]]::new()
try {
    $Session   = New-Object -ComObject Microsoft.Update.Session
    $Searcher  = $Session.CreateUpdateSearcher()
    $HistCount = $Searcher.GetTotalHistoryCount()
    $History   = $Searcher.QueryHistory(0, [Math]::Min($HistCount, 200))
    foreach ($Update in $History) {
        $UpdateHistory.Add([PSCustomObject]@{
            Title       = $Update.Title
            Date        = $Update.Date.ToString("o")
            Operation   = switch ($Update.Operation) { 1{"Install"} 2{"Uninstall"} 3{"Other"} default{"Unknown"} }
            ResultCode  = switch ($Update.ResultCode) { 1{"InProgress"} 2{"Succeeded"} 3{"SucceededWithErrors"} 4{"Failed"} 5{"Aborted"} default{"Unknown"} }
            HResult     = "0x{0:X8}" -f $Update.HResult
            UpdateID    = $Update.UpdateIdentity.UpdateID
        })
    }
    Write-Log "Update history entries: $($UpdateHistory.Count)"
} catch { Write-Log "Update history COM failed: $_" "WARN" }

# Last update check and install times
Write-Host "[*] Checking Windows Update configuration..." -ForegroundColor Cyan
$WUConfig = [PSCustomObject]@{}
try {
    $AutoUpdate = New-Object -ComObject Microsoft.Update.AutoUpdate
    $WUConfig = [PSCustomObject]@{
        LastSearchSuccess  = if ($AutoUpdate.Results.LastSearchSuccessDate) { $AutoUpdate.Results.LastSearchSuccessDate.ToString("o") } else { $null }
        LastInstallSuccess = if ($AutoUpdate.Results.LastInstallationSuccessDate) { $AutoUpdate.Results.LastInstallationSuccessDate.ToString("o") } else { $null }
        NotificationLevel  = $AutoUpdate.Settings.NotificationLevel
        AutoUpdateEnabled  = ($AutoUpdate.Settings.NotificationLevel -gt 1)
    }
} catch { Write-Log "WU config COM failed: $_" "WARN" }

# OS version and build (for CVE mapping)
$OSInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
$OSBuild = [PSCustomObject]@{
    Caption          = $OSInfo.Caption
    Version          = $OSInfo.Version
    BuildNumber      = $OSInfo.BuildNumber
    ServicePackMajor = $OSInfo.ServicePackMajorVersion
    OSArchitecture   = $OSInfo.OSArchitecture
    LastBootTime     = $OSInfo.LastBootUpTime.ToString("o")
    InstallDate      = $OSInfo.InstallDate.ToString("o")
}

# Pending updates check
Write-Host "[*] Checking for pending updates..." -ForegroundColor Cyan
$PendingUpdates = [System.Collections.Generic.List[PSCustomObject]]::new()
try {
    $Searcher2    = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()
    $SearchResult = $Searcher2.Search("IsInstalled=0 and IsHidden=0")
    foreach ($Update in $SearchResult.Updates) {
        $PendingUpdates.Add([PSCustomObject]@{
            Title       = $Update.Title
            Severity    = $Update.MsrcSeverity
            IsMandatory = $Update.IsMandatory
            Size        = [math]::Round($Update.MaxDownloadSize / 1MB, 1)
        })
    }
    Write-Log "Pending updates: $($PendingUpdates.Count)"
} catch { Write-Log "Pending update check failed: $_" "WARN" }

$CriticalPending = @($PendingUpdates | Where-Object { $_.Severity -eq "Critical" }).Count
Write-Log "Critical pending: $CriticalPending"

$Evidence = [PSCustomObject]@{
    ChainOfCustody  = [PSCustomObject]@{ CaseNumber=$CaseNum; Hostname=$Hostname; CollectedAt=(Get-Date).ToString("o"); ToolVersion="1.0" }
    ArtifactType    = "PatchLevel"
    OSBuild         = $OSBuild
    WUConfig        = $WUConfig
    HotfixCount     = $Hotfixes.Count
    PendingCount    = $PendingUpdates.Count
    CriticalPending = $CriticalPending
    Hotfixes        = $Hotfixes
    UpdateHistory   = $UpdateHistory
    PendingUpdates  = $PendingUpdates
}

$Evidence | ConvertTo-Json -Depth 6 | Out-File $JsonFile -Encoding UTF8
$Hash = Get-FileHash $JsonFile -Algorithm SHA256
[PSCustomObject]@{ FileName=$JsonFile; Hash=$Hash.Hash; Generated=(Get-Date).ToString("o") } |
    ConvertTo-Json | Out-File "$JsonFile.hash.json" -Encoding UTF8

Write-Host "[+] Patch level collected | Hotfixes: $($Hotfixes.Count) | Pending: $($PendingUpdates.Count) | Critical Pending: $CriticalPending" -ForegroundColor Green
Write-Host "[+] JSON: $JsonFile" -ForegroundColor Green
Write-Log "Completed"
