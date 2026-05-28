#Requires -Version 5.1
Set-StrictMode -Off
$ErrorActionPreference = "Continue"

$Timestamp    = Get-Date -Format "yyyyMMdd_HHmmss"
$Hostname     = $env:COMPUTERNAME
$BasePath     = if ($env:DFIR_OUTPUT) { $env:DFIR_OUTPUT } else { "C:\IR_Collection" }
$CaseNum      = if ($env:DFIR_CASE) { $env:DFIR_CASE } else { "CASE-$(Get-Date -Format yyyyMMdd)" }
$Investigator = if ($env:DFIR_INV)  { $env:DFIR_INV  } else { $env:USERNAME }
$ReportDir    = "$BasePath\Timeline_${Timestamp}"
New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null
$LogFile      = "$BasePath\Timeline_Execution.log"
$JsonFile     = "$BasePath\Timeline_${Hostname}_${Timestamp}.json"
$CSVFile      = "$ReportDir\Timeline_${Hostname}_${Timestamp}.csv"
$HTMLFile     = "$ReportDir\Timeline_${Hostname}_${Timestamp}.html"

function Write-Log { param([string]$M,[string]$L="INFO") Add-Content $LogFile "$(Get-Date -Format o) [$L] :: $M" }
Write-Log "Timeline builder started | Case: $CaseNum"

Write-Host "[*] Loading all evidence artifacts..." -ForegroundColor Cyan

$EvidenceFiles = @(Get-ChildItem $BasePath -Filter "*.json" -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -notmatch "\.hash\.json$|Manifest|Timeline|Report|IOC" })

$Timeline = [System.Collections.Generic.List[PSCustomObject]]::new()

function Add-Event {
    param([string]$Time, [string]$Source, [string]$Category, [string]$Description, [string]$User="", [string]$Host="", [string]$Detail="")
    if (-not $Time -or $Time -eq "" -or $Time -eq "null") { return }
    try {
        $DT = [datetime]::Parse($Time)
        $script:Timeline.Add([PSCustomObject]@{
            DateTime    = $DT.ToString("o")
            DateTimeUTC = $DT.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
            Source      = $Source
            Category    = $Category
            Description = $Description
            User        = $User
            Hostname    = if ($Host) { $Host } else { $Hostname }
            Detail      = ($Detail -replace '\r?\n',' ').Substring(0,[Math]::Min(200,$Detail.Length))
        })
    } catch {}
}

foreach ($F in $EvidenceFiles) {
    try {
        $Data = Get-Content $F.FullName -Raw | ConvertFrom-Json
        if (-not $Data -or -not $Data.ArtifactType) { continue }

        Write-Host "  [*] Processing $($Data.ArtifactType)..." -ForegroundColor Cyan

        switch ($Data.ArtifactType) {

            "SecurityEventLog" {
                foreach ($E in $Data.Data) {
                    Add-Event $E.TimeCreated "SecurityLog" "EventLog" "EventID $($E.EventID): $($E.EventType)" "" $E.Computer ($E.Message -replace '\r?\n',' ')
                }
            }

            "SystemApplicationEventLog" {
                foreach ($Group in $Data.EventGroups.PSObject.Properties) {
                    foreach ($E in $Group.Value) {
                        Add-Event $E.TimeCreated "SystemLog_$($Group.Name)" "EventLog" "EventID $($E.EventID): $($E.Message.Substring(0,[Math]::Min(100,$E.Message.Length)))" "" $E.Computer ""
                    }
                }
            }

            "RunningProcesses" {
                foreach ($P in $Data.Data) {
                    if ($P.StartTime) { Add-Event $P.StartTime "RunningProcesses" "ProcessExecution" "Process started: $($P.ProcessName) (PID:$($P.PID))" "" "" $P.ExecutablePath }
                }
            }

            "ScheduledTasks" {
                foreach ($T in $Data.Data) {
                    if ($T.LastRunTime) { Add-Event $T.LastRunTime "ScheduledTasks" "Execution" "Task executed: $($T.TaskName)" $T.RunAsUser "" "$($T.Command) $($T.Arguments)" }
                }
            }

            "WindowsServices" {
                foreach ($S in $Data.Data) {
                    if ($S.State -eq "Running") { Add-Event (Get-Date).ToString("o") "WindowsServices" "Persistence" "Service running: $($S.ServiceName)" $S.RunAsAccount "" $S.BinaryPath }
                }
            }

            "FileSystemArtifacts" {
                foreach ($F2 in $Data.RecentLNKFiles) {
                    Add-Event $F2.LastWriteTime "LNKFiles" "UserActivity" "File accessed: $($F2.TargetPath)" $F2.User "" $F2.LNKPath
                }
                foreach ($F2 in $Data.SuspiciousDrops) {
                    Add-Event $F2.CreationTime "SuspiciousDrops" "FileSystem" "Suspicious file created: $($F2.FileName)" "" "" $F2.Path
                }
            }

            "USB_Device_Driver_WER" {
                foreach ($W in $Data.WERCrashReports) {
                    Add-Event $W.CreationTime "WERCrash" "ApplicationCrash" "Application crash: $($W.AppName)" "" "" $W.ReportPath
                }
            }

            "BrowserArtifacts" {
                # Browser history timestamps extracted from DB - note for analyst
                Add-Event (Get-Date).ToString("o") "BrowserArtifacts" "UserActivity" "Browser DB files collected - use DB Browser for full history timeline" "" "" ""
            }

            "PowerShellEventLog" {
                foreach ($S in $Data.ScriptBlockEvents) {
                    if ($S.IsSuspicious) { Add-Event $S.TimeCreated "PowerShellLog" "SuspiciousExecution" "Suspicious PS script block detected" $S.UserSID "" ($S.ScriptText.Substring(0,[Math]::Min(200,$S.ScriptText.Length))) }
                }
            }

            "RAMDump" {
                if ($Data.PreDumpState.CaptureStartTime) { Add-Event $Data.PreDumpState.CaptureStartTime "RAMDump" "ForensicCollection" "Live RAM capture performed" "" "" "Dump: $($Data.DumpResult.DumpFile)" }
            }

            "PatchLevel" {
                foreach ($H in $Data.Hotfixes | Select-Object -First 20) {
                    if ($H.InstalledOn) { Add-Event $H.InstalledOn "WindowsUpdate" "SystemChange" "Hotfix installed: $($H.HotFixID) - $($H.Description)" $H.InstalledBy "" "" }
                }
            }
        }
    } catch { Write-Log "Error processing $($F.Name): $_" "WARN" }
}

# Sort timeline by datetime
$Sorted = @($Timeline | Sort-Object DateTime)
Write-Log "Timeline entries: $($Sorted.Count)"

# Export CSV
$Sorted | Export-Csv $CSVFile -NoTypeInformation -Encoding UTF8
Write-Log "Timeline CSV exported: $CSVFile"

# Export HTML Timeline
Write-Host "[*] Generating HTML timeline..." -ForegroundColor Cyan

$CategoryColors = @{
    "EventLog"            = "#1e3a5f"
    "ProcessExecution"    = "#065f46"
    "Execution"           = "#064e3b"
    "SuspiciousExecution" = "#7f1d1d"
    "Persistence"         = "#7c2d12"
    "UserActivity"        = "#1e40af"
    "FileSystem"          = "#4c1d95"
    "SystemChange"        = "#374151"
    "ApplicationCrash"    = "#92400e"
    "ForensicCollection"  = "#134e4a"
}

$TimelineRows = ($Sorted | Select-Object -Last 500 | ForEach-Object {
    $Color = if ($CategoryColors[$_.Category]) { $CategoryColors[$_.Category] } else { "#374151" }
    $IsSusp = $_.Category -match "Suspicious|Persistence" -or $_.Source -match "Suspicious"
    $RowBG  = if ($IsSusp) { "#fef2f2" } else { "white" }
    "<tr style='background:$RowBG'>
        <td style='padding:7px 10px;font-size:12px;white-space:nowrap;color:#6b7280'>$($_.DateTimeUTC)</td>
        <td style='padding:7px 10px'><span style='background:$Color;color:white;padding:2px 7px;border-radius:3px;font-size:11px'>$($_.Category)</span></td>
        <td style='padding:7px 10px;font-size:12px'>$($_.Source)</td>
        <td style='padding:7px 10px;font-size:12px'>$($_.Description)</td>
        <td style='padding:7px 10px;font-size:11px;color:#6b7280'>$($_.User)</td>
        <td style='padding:7px 10px;font-size:11px;color:#6b7280;max-width:200px;overflow:hidden'>$($_.Detail)</td>
    </tr>"
}) -join "`n"

$HTMLContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Forensic Timeline - $CaseNum</title>
<style>
  body { font-family: 'Segoe UI', Arial, sans-serif; background:#f1f5f9; margin:0; }
  .header { background:#1e3a5f; color:white; padding:20px 32px; }
  .header h1 { font-size:22px; margin:0; }
  .header p  { font-size:13px; opacity:0.75; margin:4px 0 0; }
  .container { padding:24px 32px; }
  .card { background:white; border-radius:8px; box-shadow:0 1px 3px rgba(0,0,0,0.08); overflow:hidden; }
  .card-header { background:#f8fafc; border-bottom:1px solid #e2e8f0; padding:12px 16px; }
  .card-header h2 { font-size:15px; font-weight:600; color:#1e3a5f; margin:0; }
  table { width:100%; border-collapse:collapse; }
  th { background:#1e3a5f; color:white; padding:10px; text-align:left; font-size:11px; text-transform:uppercase; letter-spacing:0.5px; }
  td { border-bottom:1px solid #f1f5f9; vertical-align:top; }
  tr:hover td { background:#f8fafc!important; }
  .search-bar { padding:12px 16px; background:#f8fafc; border-bottom:1px solid #e2e8f0; }
  .search-bar input { width:100%; padding:8px 12px; border:1px solid #d1d5db; border-radius:6px; font-size:13px; }
  .stats { display:flex; gap:16px; padding:16px; flex-wrap:wrap; }
  .stat { background:#f8fafc; border:1px solid #e2e8f0; border-radius:6px; padding:12px 16px; text-align:center; }
  .stat-num { font-size:24px; font-weight:bold; color:#1e3a5f; }
  .stat-lbl { font-size:11px; color:#6b7280; text-transform:uppercase; }
  .footer { text-align:center; padding:16px; font-size:12px; color:#94a3b8; }
</style>
</head>
<body>
<div class="header">
  <h1>Forensic Event Timeline</h1>
  <p>Case: $CaseNum | Investigator: $Investigator | Host: $Hostname | Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | Showing last 500 of $($Sorted.Count) events</p>
</div>
<div class="container">
  <div class="card">
    <div class="stats">
      <div class="stat"><div class="stat-num">$($Sorted.Count)</div><div class="stat-lbl">Total Events</div></div>
      <div class="stat"><div class="stat-num">$(@($Sorted | Where-Object {$_.Category -match 'Suspicious'}).Count)</div><div class="stat-lbl">Suspicious</div></div>
      <div class="stat"><div class="stat-num">$(@($Sorted | Where-Object {$_.Category -eq 'Persistence'}).Count)</div><div class="stat-lbl">Persistence</div></div>
      <div class="stat"><div class="stat-num">$(@($Sorted | Where-Object {$_.Category -eq 'ProcessExecution'}).Count)</div><div class="stat-lbl">Process Events</div></div>
      <div class="stat"><div class="stat-num">$(@($Sorted | Select-Object -ExpandProperty Source -Unique).Count)</div><div class="stat-lbl">Data Sources</div></div>
    </div>
    <div class="search-bar">
      <input type="text" id="searchBox" placeholder="Search timeline..." onkeyup="filterTable()">
    </div>
    <div style="overflow-x:auto;max-height:75vh;overflow-y:auto">
      <table id="timelineTable">
        <tr><th>Date/Time (UTC)</th><th>Category</th><th>Source</th><th>Description</th><th>User</th><th>Detail</th></tr>
        $TimelineRows
      </table>
    </div>
  </div>
</div>
<div class="footer">Windows DFIR Toolkit v1.0 | Timeline Builder | Case: $CaseNum | CSV export: $CSVFile</div>
<script>
function filterTable() {
  var input = document.getElementById('searchBox').value.toLowerCase();
  var rows = document.getElementById('timelineTable').getElementsByTagName('tr');
  for (var i = 1; i < rows.length; i++) {
    var text = rows[i].textContent.toLowerCase();
    rows[i].style.display = text.includes(input) ? '' : 'none';
  }
}
</script>
</body>
</html>
"@

$HTMLContent | Out-File $HTMLFile -Encoding UTF8
Write-Log "Timeline HTML exported: $HTMLFile"

$Evidence = [PSCustomObject]@{
    ChainOfCustody = [PSCustomObject]@{ CaseNumber=$CaseNum; Hostname=$Hostname; CollectedAt=(Get-Date).ToString("o"); ToolVersion="1.0" }
    ArtifactType   = "ForensicTimeline"
    TotalEvents    = $Sorted.Count
    OutputDirectory= $ReportDir
    CSVFile        = $CSVFile
    HTMLFile       = $HTMLFile
    CategorySummary= @($Sorted | Group-Object Category | Sort-Object Count -Descending | ForEach-Object { [PSCustomObject]@{ Category=$_.Name; Count=$_.Count } })
    SourceSummary  = @($Sorted | Group-Object Source | Sort-Object Count -Descending | ForEach-Object { [PSCustomObject]@{ Source=$_.Name; Count=$_.Count } })
    Data           = $Sorted | Select-Object -First 1000
}

$Evidence | ConvertTo-Json -Depth 6 | Out-File $JsonFile -Encoding UTF8
$Hash = Get-FileHash $JsonFile -Algorithm SHA256
[PSCustomObject]@{ FileName=$JsonFile; Hash=$Hash.Hash; Generated=(Get-Date).ToString("o") } |
    ConvertTo-Json | Out-File "$JsonFile.hash.json" -Encoding UTF8

Write-Host "[+] Timeline built | Total Events: $($Sorted.Count)" -ForegroundColor Green
Write-Host "[+] HTML Timeline : $HTMLFile" -ForegroundColor Green
Write-Host "[+] CSV Export    : $CSVFile" -ForegroundColor Green
Write-Host "[+] JSON          : $JsonFile" -ForegroundColor Green
Write-Log "Completed"
