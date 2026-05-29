#Requires -Version 5.1
Set-StrictMode -Off
$ErrorActionPreference = "Continue"
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Hostname  = $env:COMPUTERNAME
$BasePath  = if ($env:DFIR_OUTPUT) { $env:DFIR_OUTPUT } else { "C:\IR_Collection" }
$CaseNum   = if ($env:DFIR_CASE) { $env:DFIR_CASE } else { "CASE-$(Get-Date -Format yyyyMMdd)" }
New-Item -ItemType Directory -Path $BasePath -Force | Out-Null
$LogFile  = "$BasePath\GPO_Cache_Execution.log"
$JsonFile = "$BasePath\GPO_Cache_${Hostname}_${Timestamp}.json"
$OutDir   = "$BasePath\GPO_Scripts_${Hostname}_${Timestamp}"
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

function Write-Log { param([string]$M,[string]$L="INFO") Add-Content $LogFile "$(Get-Date -Format o) [$L] :: $M" }
Write-Log "GPO Cache collection started | Case: $CaseNum"

# GPO script cache locations
$GPOScriptPaths = @(
    "$env:SystemRoot\System32\GroupPolicy\User\Scripts",
    "$env:SystemRoot\System32\GroupPolicy\Machine\Scripts",
    "$env:SystemRoot\SysWOW64\GroupPolicy\User\Scripts",
    "$env:SystemRoot\SysWOW64\GroupPolicy\Machine\Scripts",
    "$env:SystemRoot\System32\GroupPolicyUsers"
)

Write-Host "[*] Collecting GPO cached scripts..." -ForegroundColor Cyan
$GPOScripts     = [System.Collections.Generic.List[PSCustomObject]]::new()
$SuspiciousScripts = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($GPOPath in $GPOScriptPaths) {
    if (-not (Test-Path $GPOPath)) { continue }
    $ScriptFiles = @(Get-ChildItem $GPOPath -Recurse -Include "*.bat","*.cmd","*.ps1","*.vbs","*.wsf","*.js","*.exe","*.dll" -ErrorAction SilentlyContinue)
    foreach ($SF in $ScriptFiles) {
        $Content     = $null
        $IsSuspicious= $false
        $SuspReasons = @()
        try { $Content = Get-Content $SF.FullName -ErrorAction SilentlyContinue } catch {}

        if ($Content) {
            $FullText = $Content -join " "
            if ($FullText -match "-EncodedCommand|-enc\s+[A-Za-z0-9+/]{20}") { $IsSuspicious=$true; $SuspReasons+="Encoded command" }
            if ($FullText -match "DownloadString|DownloadFile|WebClient|curl|wget") { $IsSuspicious=$true; $SuspReasons+="Download activity" }
            if ($FullText -match "net user|net localgroup|New-LocalUser|Add-LocalGroupMember") { $IsSuspicious=$true; $SuspReasons+="Account manipulation" }
            if ($FullText -match "Invoke-Expression|IEX\s*\(") { $IsSuspicious=$true; $SuspReasons+="Dynamic execution" }
            if ($FullText -match "reg add|regsvr32|rundll32|mshta|wscript") { $IsSuspicious=$true; $SuspReasons+="LOLBAS usage" }
        }

        $SHA256 = $null
        try { $SHA256 = (Get-FileHash $SF.FullName -Algorithm SHA256).Hash } catch {}

        $ScriptCopy = $null
        if ($IsSuspicious) {
            $ScriptCopy = "$OutDir\SUSPICIOUS_$($SF.Name)"
            Copy-Item $SF.FullName $ScriptCopy -Force -ErrorAction SilentlyContinue
        }

        $SObj = [PSCustomObject]@{
            ScriptName       = $SF.Name
            FullPath         = $SF.FullName
            Extension        = $SF.Extension
            SizeBytes        = $SF.Length
            CreationTime     = $SF.CreationTimeUtc.ToString("o")
            LastModified     = $SF.LastWriteTimeUtc.ToString("o")
            SHA256           = $SHA256
            IsSuspicious     = $IsSuspicious
            SuspiciousReasons= ($SuspReasons -join "; ")
            CopiedTo         = $ScriptCopy
            ContentPreview   = if ($Content) { ($Content | Select-Object -First 10) -join "`n" } else { $null }
        }
        $GPOScripts.Add($SObj)
        if ($IsSuspicious) { $SuspiciousScripts.Add($SObj) }
    }
}

# GPO registry-based script configuration
Write-Host "[*] Collecting GPO script registry configuration..." -ForegroundColor Cyan
$GPOScriptConfig = [System.Collections.Generic.List[PSCustomObject]]::new()
$GPORegPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logon",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logoff",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Shutdown",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logon",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logoff"
)

foreach ($GRPath in $GPORegPaths) {
    if (-not (Test-Path $GRPath)) { continue }
    Get-ChildItem $GRPath -ErrorAction SilentlyContinue | ForEach-Object {
        Get-ChildItem $_.PSPath -ErrorAction SilentlyContinue | ForEach-Object {
            $Props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
            if ($Props.Script) {
                $GPOScriptConfig.Add([PSCustomObject]@{
                    Type         = Split-Path $GRPath -Leaf
                    ScriptPath   = $Props.Script
                    Parameters   = $Props.Parameters
                    RegistryKey  = $_.PSPath
                    ExecutionTime= $Props.ExecTime
                })
            }
        }
    }
}

# Applied GPO summary
Write-Host "[*] Collecting applied GPO information..." -ForegroundColor Cyan
$GPOInfo = [PSCustomObject]@{ Applied = @() }
try {
    $GPResult = (gpresult /r /scope:computer 2>&1) -join "`n"
    $GPOInfo  = [PSCustomObject]@{
        Applied      = @($GPResult -split "`n" | Where-Object { $_ -match "^\s{4}\S" -and $_ -notmatch "Computer|User|Group Policy" } | ForEach-Object { $_.Trim() })
        LastRefresh  = if ($GPResult -match "Last time Group Policy was applied:\s*(.+)") { $Matches[1].Trim() } else { $null }
        AppliedFrom  = if ($GPResult -match "Group Policy was applied from:\s*(.+)") { $Matches[1].Trim() } else { $null }
    }
} catch { Write-Log "gpresult failed: $_" "WARN" }

Write-Log "GPO scripts: $($GPOScripts.Count) | Suspicious: $($SuspiciousScripts.Count) | Config entries: $($GPOScriptConfig.Count)"

$Evidence = [PSCustomObject]@{
    ChainOfCustody   = [PSCustomObject]@{ CaseNumber=$CaseNum; Hostname=$Hostname; CollectedAt=(Get-Date).ToString("o"); ToolVersion="1.0" }
    ArtifactType     = "GPO_Cache_Scripts"
    TotalScripts     = $GPOScripts.Count
    SuspiciousCount  = $SuspiciousScripts.Count
    OutputDirectory  = $OutDir
    GPOInfo          = $GPOInfo
    ScriptConfig     = $GPOScriptConfig
    SuspiciousScripts= $SuspiciousScripts
    AllGPOScripts    = $GPOScripts
}

$Evidence | ConvertTo-Json -Depth 7 | Out-File $JsonFile -Encoding UTF8
$Hash = Get-FileHash $JsonFile -Algorithm SHA256
[PSCustomObject]@{ FileName=$JsonFile; Hash=$Hash.Hash; Generated=(Get-Date).ToString("o") } |
    ConvertTo-Json | Out-File "$JsonFile.hash.json" -Encoding UTF8

Write-Host "[+] GPO Cache collection complete | Scripts: $($GPOScripts.Count) | Suspicious: $($SuspiciousScripts.Count) | Config: $($GPOScriptConfig.Count)" -ForegroundColor Green
Write-Host "[+] Output: $OutDir" -ForegroundColor Green
Write-Host "[+] JSON  : $JsonFile" -ForegroundColor Green
Write-Log "Completed"
