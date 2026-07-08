#Requires -Version 5.1
Set-StrictMode -Off
$ErrorActionPreference = "Continue"


# --- Shared toolkit module: single source of truth for version + base paths ---
$__DFIRMod = Join-Path $PSScriptRoot '..\Infrastructure\DFIR_Common.psm1'
if (Test-Path $__DFIRMod) { Import-Module $__DFIRMod -Force -ErrorAction SilentlyContinue }
if (-not $Global:DFIR_ToolVersion) { $Global:DFIR_ToolVersion = '1.0' }
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Hostname  = $env:COMPUTERNAME
$BasePath  = if ($env:DFIR_OUTPUT) { $env:DFIR_OUTPUT } else { "C:\IR_Collection" }
$CaseNum   = if ($env:DFIR_CASE) { $env:DFIR_CASE } else { "CASE-$(Get-Date -Format yyyyMMdd)" }
New-Item -ItemType Directory -Path $BasePath -Force | Out-Null
$LogFile  = "$BasePath\Scheduled_Task_XML_Execution.log"
$JsonFile = "$BasePath\Scheduled_Task_XML_${Hostname}_${Timestamp}.json"
$XMLDir   = "$BasePath\ScheduledTask_XML_${Hostname}_${Timestamp}"
New-Item -ItemType Directory -Path $XMLDir -Force | Out-Null

function Write-Log { param([string]$M,[string]$L="INFO") Add-Content $LogFile "$(Get-Date -Format o) [$L] :: $M" }
Write-Log "Scheduled Task XML collection started | Case: $CaseNum"

Write-Host "[*] Exporting all scheduled tasks as raw XML..." -ForegroundColor Cyan

$TaskResults  = [System.Collections.Generic.List[PSCustomObject]]::new()
$SuspiciousTasks = [System.Collections.Generic.List[PSCustomObject]]::new()

# Get all tasks including subfolders
$AllTasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue)
Write-Host "[*] Found $($AllTasks.Count) scheduled tasks" -ForegroundColor Cyan
Write-Log "Total tasks found: $($AllTasks.Count)"

foreach ($Task in $AllTasks) {
    try {
        # Export raw XML
        $RawXML   = Export-ScheduledTask -TaskName $Task.TaskName -TaskPath $Task.TaskPath -ErrorAction SilentlyContinue
        $SafeName = ($Task.TaskPath + $Task.TaskName) -replace "[/\\:<>|?*]","-" -replace "\s+","_"
        $SafeName = $SafeName.TrimStart("-") -replace "-+","-"
        $XMLFile  = "$XMLDir\${SafeName}.xml"

        if ($RawXML) {
            $RawXML | Out-File $XMLFile -Encoding UTF8 -ErrorAction SilentlyContinue
        }

        # Parse for suspicious indicators. STRONG indicators (encoded/download/IEX, or an
        # interpreter launching from temp/public) mark a task suspicious. A bare LOLBAS binary
        # name or an AppData path is NOT suspicious by itself - built-in Windows tasks legitimately
        # invoke rundll32 etc., and many legitimate per-user apps run from AppData - so those are
        # recorded only as context. Microsoft built-in tasks (\Microsoft\...) are never flagged on
        # context alone. This eliminated a flood of false positives on clean systems.
        $IsSuspicious = $false
        $SuspiciousReason = @()
        $ContextNotes     = @()
        $IsMSBuiltin = ($Task.TaskPath -like '\Microsoft\*')

        if ($RawXML) {
            if ($RawXML -match "(?i)-enc(odedcommand)?\s+[A-Za-z0-9+/]{40,}")                       { $SuspiciousReason += "Encoded PowerShell command" }
            if ($RawXML -match "(?i)frombase64string")                                              { $SuspiciousReason += "Base64 decode" }
            if ($RawXML -match "(?i)(downloadstring|downloadfile|invoke-webrequest|\bcurl\b|\bwget\b)[^<]{0,120}https?://") { $SuspiciousReason += "Download activity" }
            if ($RawXML -match "(?i)\b(iex|invoke-expression)\b")                                    { $SuspiciousReason += "Invoke-Expression" }
            if ($RawXML -match "(?i)(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32)[^<]{0,120}(\\temp\\|\\appdata\\local\\temp\\|\\public\\|%temp%|\\programdata\\)") { $SuspiciousReason += "Interpreter executing from temp/public" }

            if ($RawXML -match "(?i)\b(wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin)\b") { $ContextNotes += "LOLBAS binary referenced" }
            if ($RawXML -match "(?i)\\appdata\\")                                                    { $ContextNotes += "Runs from AppData" }

            if ($SuspiciousReason.Count -ge 1) { $IsSuspicious = $true }
        }

        # Get task info
        $TaskInfo = $null
        try { $TaskInfo = Get-ScheduledTaskInfo -TaskName $Task.TaskName -TaskPath $Task.TaskPath -ErrorAction SilentlyContinue } catch {}

        $TaskObj = [PSCustomObject]@{
            TaskName      = $Task.TaskName
            TaskPath      = $Task.TaskPath
            State         = $Task.State.ToString()
            Author        = $Task.Author
            Description   = $Task.Description
            RunAs         = if ($Task.Principal) { $Task.Principal.UserId } else { $null }
            RunLevel      = if ($Task.Principal) { $Task.Principal.RunLevel.ToString() } else { $null }
            LastRunTime   = if ($TaskInfo -and $TaskInfo.LastRunTime -and $TaskInfo.LastRunTime -ne [datetime]::MinValue) { $TaskInfo.LastRunTime.ToString("o") } else { $null }
            LastResult    = if ($TaskInfo) { "0x{0:X8}" -f $TaskInfo.LastTaskResult } else { $null }
            NextRunTime   = if ($TaskInfo -and $TaskInfo.NextRunTime -and $TaskInfo.NextRunTime -ne [datetime]::MinValue) { $TaskInfo.NextRunTime.ToString("o") } else { $null }
            XMLFile       = $XMLFile
            IsSuspicious  = $IsSuspicious
            SuspiciousReasons = ($SuspiciousReason -join "; ")
            ContextNotes  = ($ContextNotes -join "; ")
            RawXML        = $RawXML
        }

        $TaskResults.Add($TaskObj)

        if ($IsSuspicious) {
            $SuspiciousTasks.Add($TaskObj)
            Write-Host "  [!] SUSPICIOUS: $($Task.TaskPath)$($Task.TaskName) -- $($SuspiciousReason -join ', ')" -ForegroundColor Red
        }

    } catch {
        Write-Log "Task export failed: $($Task.TaskName) -- $_" "WARN"
    }
}

$SuspCount = $SuspiciousTasks.Count
Write-Log "Tasks exported: $($TaskResults.Count) | Suspicious: $SuspCount"

$Evidence = [PSCustomObject]@{
    ChainOfCustody   = [PSCustomObject]@{ CaseNumber=$CaseNum; Hostname=$Hostname; CollectedAt=([DateTime]::UtcNow).ToString("o"); ToolVersion=$Global:DFIR_ToolVersion }
    ArtifactType     = "ScheduledTaskXML"
    TotalTasks       = $TaskResults.Count
    SuspiciousCount  = $SuspCount
    XMLDirectory     = $XMLDir
    SuspiciousTasks  = $SuspiciousTasks
    AllTasks         = $TaskResults
}

$Evidence | ConvertTo-Json -Depth 8 | Out-File $JsonFile -Encoding UTF8
$Hash = Get-FileHash $JsonFile -Algorithm SHA256
[PSCustomObject]@{ FileName=$JsonFile; Hash=$Hash.Hash; Generated=([DateTime]::UtcNow).ToString("o") } |
    ConvertTo-Json | Out-File "$JsonFile.hash.json" -Encoding UTF8

Write-Host "[+] Scheduled Task XML export complete | Total: $($TaskResults.Count) | Suspicious: $SuspCount" -ForegroundColor Green
Write-Host "[+] XML Files : $XMLDir" -ForegroundColor Green
Write-Host "[+] JSON      : $JsonFile" -ForegroundColor Green
Write-Log "Completed"
