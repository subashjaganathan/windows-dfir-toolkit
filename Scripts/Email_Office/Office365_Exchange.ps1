#Requires -Version 5.1
Set-StrictMode -Off
$ErrorActionPreference = "Continue"


# --- Shared toolkit module: single source of truth for version + base paths ---
$__DFIRMod = Join-Path $PSScriptRoot '..\Infrastructure\DFIR_Common.psm1'
if (Test-Path $__DFIRMod) { Import-Module $__DFIRMod -Force -ErrorAction SilentlyContinue }
if (-not $Global:DFIR_ToolVersion) { $Global:DFIR_ToolVersion = '1.0' }

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Hostname  = $env:COMPUTERNAME
$BasePath  = if ($env:DFIR_OUTPUT) { $env:DFIR_OUTPUT } else { "C:\IR_Collection" }
$CaseNum   = if ($env:DFIR_CASE) { $env:DFIR_CASE } else { "CASE-$(Get-Date -Format yyyyMMdd)" }
New-Item -ItemType Directory -Path $BasePath -Force | Out-Null
$LogFile  = "$BasePath\Office365_Execution.log"
$JsonFile = "$BasePath\Office365_Exchange_${Hostname}_${Timestamp}.json"

function Write-Log { param([string]$M,[string]$L="INFO") Add-Content $LogFile "$(Get-Date -Format o) [$L] :: $M" }
Write-Log "Office 365 / Exchange artifact collection started | Case: $CaseNum"

$AllUsers = @(Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue)

# Outlook inbox rules from registry
Write-Host "[*] Collecting Outlook inbox rule metadata..." -ForegroundColor Cyan
$InboxRules = [System.Collections.Generic.List[PSCustomObject]]::new()
foreach ($User in $AllUsers) {
    $OutlookKey = "HKCU:\SOFTWARE\Microsoft\Office"
    $ProfilePaths = @(
        "HKCU:\SOFTWARE\Microsoft\Office\16.0\Outlook\Profiles",
        "HKCU:\SOFTWARE\Microsoft\Office\15.0\Outlook\Profiles",
        "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles"
    )
    foreach ($PP in $ProfilePaths) {
        if (-not (Test-Path $PP)) { continue }
        Get-ChildItem $PP -ErrorAction SilentlyContinue | ForEach-Object {
            $ProfileName = $_.PSChildName
            Get-ChildItem $_.PSPath -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                $Props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
                if ($Props -and ($Props."Rule Name" -or $Props.RuleName)) {
                    $InboxRules.Add([PSCustomObject]@{
                        User        = $User.Name
                        Profile     = $ProfileName
                        RuleName    = if ($Props."Rule Name") { $Props."Rule Name" } else { $Props.RuleName }
                        RegistryKey = $_.PSPath
                    })
                }
            }
        }
    }
}
Write-Log "Inbox rules from registry: $($InboxRules.Count)"

# Outlook auto-forward settings
Write-Host "[*] Checking Outlook auto-forward configuration..." -ForegroundColor Cyan
$AutoForwardSettings = [System.Collections.Generic.List[PSCustomObject]]::new()
$AutoForwardKeys = @(
    "HKCU:\SOFTWARE\Microsoft\Office\16.0\Outlook\Options\Mail",
    "HKCU:\SOFTWARE\Microsoft\Office\15.0\Outlook\Options\Mail"
)
foreach ($AFK in $AutoForwardKeys) {
    if (-not (Test-Path $AFK)) { continue }
    $Props = Get-ItemProperty $AFK -ErrorAction SilentlyContinue
    if ($Props) {
        $AutoForwardSettings.Add([PSCustomObject]@{
            RegistryKey     = $AFK
            AutoForward     = $Props.AutoForward
            OOFForwardState = $Props.OOFForwardState
        })
    }
}

# Outlook profile accounts - detect unexpected email accounts
Write-Host "[*] Collecting Outlook account configuration..." -ForegroundColor Cyan
$OutlookAccounts = [System.Collections.Generic.List[PSCustomObject]]::new()
$OLVersions = @("16.0","15.0","14.0")
foreach ($Ver in $OLVersions) {
    $ProfKey = "HKCU:\SOFTWARE\Microsoft\Office\$Ver\Outlook\Profiles"
    if (-not (Test-Path $ProfKey)) { continue }
    Get-ChildItem $ProfKey -ErrorAction SilentlyContinue | ForEach-Object {
        $ProfileName = $_.PSChildName
        Get-ChildItem $_.PSPath -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
            $Props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
            $Email = $Props."Account Name"
            $Server= $Props."POP3 Server"
            if (-not $Server) { $Server = $Props."IMAP Server" }
            if (-not $Server) { $Server = $Props."EAS Server Name" }
            if ($Email -or $Server) {
                $OutlookAccounts.Add([PSCustomObject]@{
                    Version     = $Ver
                    Profile     = $ProfileName
                    AccountName = $Email
                    Server      = $Server
                    SMTPAddress = $Props."SMTP Email Address"
                })
            }
        }
    }
}
Write-Log "Outlook accounts: $($OutlookAccounts.Count)"

# OST/PST files - detect unexpected data files
Write-Host "[*] Locating Outlook data files (OST/PST)..." -ForegroundColor Cyan
$OutlookDataFiles = [System.Collections.Generic.List[PSCustomObject]]::new()
foreach ($User in $AllUsers) {
    $SearchPaths = @(
        "$($User.FullName)\Documents\Outlook Files",
        "$($User.FullName)\AppData\Local\Microsoft\Outlook",
        "$($User.FullName)\AppData\Roaming\Microsoft\Outlook"
    )
    foreach ($SP in $SearchPaths) {
        if (-not (Test-Path $SP)) { continue }
        Get-ChildItem $SP -Recurse -Include "*.pst","*.ost" -ErrorAction SilentlyContinue | ForEach-Object {
            $OutlookDataFiles.Add([PSCustomObject]@{
                User         = $User.Name
                FileName     = $_.Name
                FullPath     = $_.FullName
                Type         = $_.Extension.TrimStart(".").ToUpper()
                SizeGB       = [math]::Round($_.Length/1GB,3)
                CreationTime = $_.CreationTimeUtc.ToString("o")
                LastModified = $_.LastWriteTimeUtc.ToString("o")
                SHA256       = (Get-FileHash $_.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
            })
        }
    }
}
Write-Log "Outlook data files: $($OutlookDataFiles.Count)"

# Exchange/O365 connection history from event logs
Write-Host "[*] Checking Exchange/O365 connection events..." -ForegroundColor Cyan
$O365Events = [System.Collections.Generic.List[PSCustomObject]]::new()
$DaysBack   = if ($env:DFIR_DAYS) { [int]$env:DFIR_DAYS } else { 30 }
$SinceDate  = (Get-Date).AddDays(-$DaysBack)
try {
    $Filter = @{ LogName="Application"; ProviderName="MSExchangeIS*","Outlook","Microsoft Office*"; StartTime=$SinceDate }
    $Events = @(Get-WinEvent -FilterHashtable $Filter -ErrorAction SilentlyContinue | Select-Object -First 100)
    foreach ($E in $Events) {
        $O365Events.Add([PSCustomObject]@{
            TimeCreated  = $E.TimeCreated.ToString("o")
            Provider     = $E.ProviderName
            EventID      = $E.Id
            Level        = $E.LevelDisplayName
            Message      = ($E.Message -split "`r?`n" -join " ").Substring(0,[Math]::Min(200,$E.Message.Length))
        })
    }
    Write-Log "Office/Exchange events: $($O365Events.Count)"
} catch { Write-Log "O365 event query failed: $_" "WARN" }

# Teams auth tokens and config
Write-Host "[*] Checking Microsoft Teams artifacts..." -ForegroundColor Cyan
$TeamsArtifacts = [System.Collections.Generic.List[PSCustomObject]]::new()
foreach ($User in $AllUsers) {
    $TeamsPaths = @(
        "$($User.FullName)\AppData\Roaming\Microsoft\Teams",
        "$($User.FullName)\AppData\Local\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams"
    )
    foreach ($TP in $TeamsPaths) {
        if (-not (Test-Path $TP)) { continue }
        # Collect metadata only - no token values
        $TeamsFiles = @(Get-ChildItem $TP -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match "token|auth|account|profile|setting" })
        foreach ($TF in $TeamsFiles) {
            $TeamsArtifacts.Add([PSCustomObject]@{
                User         = $User.Name
                FileName     = $TF.Name
                FullPath     = $TF.FullName
                SizeBytes    = $TF.Length
                LastModified = $TF.LastWriteTimeUtc.ToString("o")
            })
        }
    }
}

# BEC risk indicators
$BECRisk = @()
$SuspiciousAccounts = @($OutlookAccounts | Where-Object {
    $_.Server -and $_.Server -notmatch "outlook\.com|office365|exchange|microsoft|hotmail|live|o365"
})
if ($SuspiciousAccounts.Count -gt 0) { $BECRisk += "Non-standard mail server configured in Outlook" }
if ($AutoForwardSettings | Where-Object { $_.AutoForward -eq 1 }) { $BECRisk += "Auto-forward enabled in Outlook settings" }

Write-Log "Inbox rules: $($InboxRules.Count) | Accounts: $($OutlookAccounts.Count) | DataFiles: $($OutlookDataFiles.Count) | BEC risks: $($BECRisk.Count)"

$Evidence = [PSCustomObject]@{
    ChainOfCustody      = [PSCustomObject]@{ CaseNumber=$CaseNum; Hostname=$Hostname; CollectedAt=([DateTime]::UtcNow).ToString("o"); ToolVersion=$Global:DFIR_ToolVersion }
    ArtifactType        = "Office365_Exchange"
    BECRiskIndicators   = $BECRisk
    BECRiskCount        = $BECRisk.Count
    InboxRulesCount     = $InboxRules.Count
    OutlookAccountCount = $OutlookAccounts.Count
    DataFileCount       = $OutlookDataFiles.Count
    InboxRules          = $InboxRules
    AutoForwardSettings = $AutoForwardSettings
    OutlookAccounts     = $OutlookAccounts
    OutlookDataFiles    = $OutlookDataFiles
    TeamsArtifacts      = $TeamsArtifacts
    O365Events          = $O365Events
    Note                = "For full mailbox rule analysis use: Get-InboxRule (requires Exchange Online PowerShell module with admin credentials)"
}

$Evidence | ConvertTo-Json -Depth 6 | Out-File $JsonFile -Encoding UTF8
$Hash = Get-FileHash $JsonFile -Algorithm SHA256
[PSCustomObject]@{ FileName=$JsonFile; Hash=$Hash.Hash; Generated=([DateTime]::UtcNow).ToString("o") } |
    ConvertTo-Json | Out-File "$JsonFile.hash.json" -Encoding UTF8

Write-Host "[+] Office365/Exchange collected | Inbox Rules: $($InboxRules.Count) | Accounts: $($OutlookAccounts.Count) | Data Files: $($OutlookDataFiles.Count) | BEC Risk: $($BECRisk.Count)" -ForegroundColor Green
Write-Host "[+] JSON: $JsonFile" -ForegroundColor Green
Write-Log "Completed"
