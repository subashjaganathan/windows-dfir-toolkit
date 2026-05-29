#Requires -Version 5.1
<#
.SYNOPSIS
    Collects cloud service artifacts from OneDrive, Teams, and Azure.

.DESCRIPTION
    Enumerates OneDrive sync status and file activity, Microsoft
    Teams chat database metadata, Azure CLI/PowerShell credential
    artifacts, cloud storage sync folders, and Microsoft 365
    application artifacts. Critical for data exfiltration
    and insider threat investigations.

.COMPATIBILITY
    Windows 10 1607+  : Full
    Windows 11        : Full
    Server 2016+      : Partial (no OneDrive/Teams typically)

.IR_PHASE
    Exfiltration / User Activity / Investigation

.MITRE_ATTCK
    T1567.002 - Exfiltration to Cloud Storage
    T1213.002 - SharePoint
    T1530     - Data from Cloud Storage

.FORENSIC_SAFETY
    Read-only - DB files copied before access

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
$OutDir    = "$BasePath\Cloud_Artifacts_${Hostname}_${Timestamp}"
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$LogFile  = "$BasePath\Cloud_Artifacts_Execution.log"
$JsonFile = "$BasePath\Cloud_Artifacts_${Hostname}_${Timestamp}.json"

function Write-Log { param([string]$M,[string]$L="INFO") Add-Content $LogFile "$(Get-Date -Format o) [$L] :: $M" }
Write-Log "Cloud artifact collection started | Case: $CaseNum"

# -- OS Detection --------------------------------------------------------------
$OSInfo    = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
$OSCaption = $OSInfo.Caption
$IsServer  = $OSCaption -match "Server"
Write-Log ("OS: " + $OSCaption + " | IsServer: " + $IsServer)

$AllUsers = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue

# -- OneDrive Artifacts --------------------------------------------------------
Write-Host "[*] Collecting OneDrive artifacts..." -ForegroundColor Cyan
$OneDriveData = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($User in $AllUsers) {
    # OneDrive sync folders
    $ODPaths = @(
        "$($User.FullName)\OneDrive",
        "$($User.FullName)\OneDrive - *"
    )
    foreach ($ODPattern in $ODPaths) {
        $ODFolders = @(Get-Item $ODPattern -ErrorAction SilentlyContinue)
        foreach ($ODFolder in $ODFolders) {
            if (-not (Test-Path $ODFolder.FullName)) { continue }

            # OneDrive settings registry
            $ODRegPath = "HKCU:\SOFTWARE\Microsoft\OneDrive\Accounts"
            $Accounts  = @()
            if (Test-Path $ODRegPath) {
                $Accounts = @(Get-ChildItem $ODRegPath -ErrorAction SilentlyContinue | ForEach-Object {
                    $Props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
                    [PSCustomObject]@{
                        AccountType   = $_.PSChildName
                        UserEmail     = $Props.UserEmail
                        UserName      = $Props.DisplayName
                        TenantID      = $Props.Tenantid
                        ServiceEndpt  = $Props.ServiceEndpointUri
                        SPOEnabled    = $Props.SPOEnabled
                        LastSync      = $Props.LastFolderListSyncTime
                    }
                })
            }

            # Recently modified files in OneDrive
            $RecentFiles = @(Get-ChildItem $ODFolder.FullName -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTimeUtc -gt (Get-Date).AddDays(-7) } |
                Sort-Object LastWriteTimeUtc -Descending |
                Select-Object -First 50 |
                ForEach-Object {
                    [PSCustomObject]@{
                        FileName      = $_.Name
                        Path          = $_.FullName
                        SizeBytes     = $_.Length
                        LastModified  = $_.LastWriteTimeUtc.ToString("o")
                        Extension     = $_.Extension
                    }
                })

            $OneDriveData.Add([PSCustomObject]@{
                UserProfile      = $User.Name
                SyncFolder       = $ODFolder.FullName
                FolderName       = $ODFolder.Name
                Accounts         = $Accounts
                RecentFilesCount = $RecentFiles.Count
                RecentFiles      = $RecentFiles
                TotalSizeGB      = [math]::Round((Get-ChildItem $ODFolder.FullName -Recurse -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum / 1GB, 3)
            })
        }
    }

    # OneDrive sync log
    $ODLog = "$($User.FullName)\AppData\Local\Microsoft\OneDrive\logs\Common"
    if (Test-Path $ODLog) {
        $LogFiles = @(Get-ChildItem $ODLog -Filter "*.log" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 3)
        foreach ($LF in $LogFiles) {
            $Dest = "$OutDir\OneDrive_$($User.Name)_$($LF.Name)"
            Copy-Item $LF.FullName $Dest -Force -ErrorAction SilentlyContinue
        }
    }
}
Write-Log "OneDrive profiles found: $($OneDriveData.Count)"

# -- Microsoft Teams Artifacts -------------------------------------------------
Write-Host "[*] Collecting Microsoft Teams artifacts..." -ForegroundColor Cyan
$TeamsData = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($User in $AllUsers) {
    # Teams classic
    $TeamsClassic = "$($User.FullName)\AppData\Roaming\Microsoft\Teams"
    # Teams new (Windows 11 / Teams 2.0)
    $TeamsNew = "$($User.FullName)\AppData\Local\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams"

    foreach ($TeamsPath in @($TeamsClassic, $TeamsNew)) {
        if (-not (Test-Path $TeamsPath)) { continue }

        $UserDir = New-Item -ItemType Directory -Path "$OutDir\Teams_$($User.Name)_$(Split-Path $TeamsPath -Leaf)" -Force

        # Copy key DBs
        $DBFiles = @("IndexedDB", "databases", "Cache")
        foreach ($DB in $DBFiles) {
            $DBPath = Join-Path $TeamsPath $DB
            if (Test-Path $DBPath) {
                Copy-Item $DBPath "$UserDir\" -Recurse -Force -ErrorAction SilentlyContinue
            }
        }

        # Teams settings/accounts
        $SettingsFile = Join-Path $TeamsPath "settings.json"
        $Settings = $null
        if (Test-Path $SettingsFile) {
            try { $Settings = Get-Content $SettingsFile -Raw | ConvertFrom-Json } catch {}
        }

        # Downloaded files
        $Downloads = @(Get-ChildItem "$($User.FullName)\Downloads" -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTimeUtc -gt (Get-Date).AddDays(-30) } |
            Select-Object Name, LastWriteTimeUtc, Length)

        $TeamsData.Add([PSCustomObject]@{
            UserProfile    = $User.Name
            TeamsPath      = $TeamsPath
            TeamsVersion   = if ($TeamsPath -match "MSTeams") { "Teams 2.0 (New)" } else { "Teams Classic" }
            SettingsFound  = ($null -ne $Settings)
            CopiedTo       = $UserDir.FullName
            Note           = "Use DB Browser for SQLite on copied IndexedDB files for message history"
        })
    }
}
Write-Log "Teams profiles found: $($TeamsData.Count)"

# -- Azure CLI / PowerShell Credential Artifacts --------------------------------
Write-Host "[*] Checking Azure CLI and PowerShell credential artifacts..." -ForegroundColor Cyan
$AzureCredData = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($User in $AllUsers) {
    # Azure CLI
    $AzCLIPath = "$($User.FullName)\.azure"
    if (Test-Path $AzCLIPath) {
        $ProfileFile = Join-Path $AzCLIPath "azureProfile.json"
        $TokensFile  = Join-Path $AzCLIPath "msal_token_cache.json"
        $Profile     = $null
        if (Test-Path $ProfileFile) {
            try { $Profile = Get-Content $ProfileFile -Raw | ConvertFrom-Json } catch {}
        }
        $AzureCredData.Add([PSCustomObject]@{
            UserProfile       = $User.Name
            Tool              = "Azure CLI"
            ProfilePath       = $AzCLIPath
            TokenCacheExists  = (Test-Path $TokensFile)
            Subscriptions     = if ($Profile) { @($Profile.subscriptions | Select-Object name, id, state, isDefault) } else { @() }
            Note              = if (Test-Path $TokensFile) { "CRITICAL: Token cache found - may contain valid auth tokens" } else { "No token cache" }
        })
    }

    # Azure PowerShell
    $AzPSPath = "$($User.FullName)\.Azure"
    $AzPSTokenPath = "$($User.FullName)\AppData\Local\Microsoft\TokenBroker"
    if (Test-Path $AzPSTokenPath) {
        $TokenFiles = @(Get-ChildItem $AzPSTokenPath -Recurse -ErrorAction SilentlyContinue)
        if ($TokenFiles.Count -gt 0) {
            $AzureCredData.Add([PSCustomObject]@{
                UserProfile      = $User.Name
                Tool             = "Azure PowerShell / Token Broker"
                TokenBrokerPath  = $AzPSTokenPath
                TokenFileCount   = $TokenFiles.Count
                Note             = "Token Broker files may contain cached OAuth tokens"
            })
        }
    }

    # AWS CLI credentials
    $AWSPath = "$($User.FullName)\.aws\credentials"
    if (Test-Path $AWSPath) {
        $AzureCredData.Add([PSCustomObject]@{
            UserProfile  = $User.Name
            Tool         = "AWS CLI"
            CredPath     = $AWSPath
            FileExists   = $true
            Note         = "CRITICAL: AWS credentials file found - review for access keys"
        })
    }

    # GCP credentials
    $GCPPath = "$($User.FullName)\AppData\Roaming\gcloud\credentials.db"
    if (Test-Path $GCPPath) {
        $AzureCredData.Add([PSCustomObject]@{
            UserProfile  = $User.Name
            Tool         = "Google Cloud CLI"
            CredPath     = $GCPPath
            FileExists   = $true
            Note         = "GCP credentials database found"
        })
    }
}
Write-Log "Cloud credential artifacts: $($AzureCredData.Count)"

# -- Installed Cloud Apps ------------------------------------------------------
Write-Host "[*] Checking installed cloud sync applications..." -ForegroundColor Cyan
$CloudApps = @(
    "OneDrive", "Dropbox", "Google Drive", "Box", "SharePoint",
    "Teams", "Slack", "Zoom", "WebEx", "GoogleBackupAndSync",
    "iCloud", "MEGA", "pCloud", "Tresorit"
)

$AllInstalled = @()
$AllInstalled += @(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue)
$AllInstalled += @(Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue)
$InstalledCloudApps = @($AllInstalled | Where-Object {
    $App = $_
    $CloudApps | Where-Object { $App.DisplayName -and $App.DisplayName -match $_ }
} | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate)
Write-Log "Cloud apps installed: $($InstalledCloudApps.Count)"

# -- Server File Share Auditing Logs (Server OS) --------------------------------
$FileServerAudit = [PSCustomObject]@{ Collected = $false }
if ($IsServer) {
    Write-Host "[*] Server OS - collecting file server and share audit artifacts..." -ForegroundColor Cyan

    $DaysBack   = if ($env:DFIR_DAYS) { [int]$env:DFIR_DAYS } else { 30 }
    $StartTime  = (Get-Date).AddDays(-$DaysBack)

    # Object Access audit events (file/share access)
    $FileAccessEvents = [System.Collections.Generic.List[PSCustomObject]]::new()
    try {
        $FAEvents = Get-WinEvent -FilterHashtable @{
            LogName   = "Security"
            Id        = @(4663, 4656, 5140, 5145)
            StartTime = $StartTime
        } -ErrorAction SilentlyContinue | Select-Object -First 500

        foreach ($E in $FAEvents) {
            $Msg = $E.Message
            $FileAccessEvents.Add([PSCustomObject]@{
                TimeCreated = $E.TimeCreated.ToString("o")
                EventID     = $E.Id
                EventType   = switch ($E.Id) {
                    4663 {"Object Access Attempt"}
                    4656 {"Object Handle Requested"}
                    5140 {"Network Share Accessed"}
                    5145 {"Network Share Object Checked"}
                }
                ShareName   = if ($Msg -match "Share Name:\s*(.+)") { $Matches[1].Trim() } else { $null }
                ObjectName  = if ($Msg -match "Object Name:\s*(.+)") { $Matches[1].Trim() } else { $null }
                AccountName = if ($Msg -match "Account Name:\s*(\S+)") { $Matches[1].Trim() } else { $null }
            })
        }
        Write-Log ("File/share access events: " + $FileAccessEvents.Count)
    } catch { Write-Log "File access events failed: $_" "WARN" }

    # DFS Replication events (data movement)
    $DFSEvents = [System.Collections.Generic.List[PSCustomObject]]::new()
    try {
        $DFSEvts = Get-WinEvent -FilterHashtable @{
            LogName   = "DFS Replication"
            StartTime = $StartTime
        } -ErrorAction SilentlyContinue | Select-Object -First 200

        foreach ($E in $DFSEvts) {
            $DFSEvents.Add([PSCustomObject]@{
                TimeCreated = $E.TimeCreated.ToString("o")
                EventID     = $E.Id
                Level       = $E.LevelDisplayName
                Message     = ($E.Message -replace "
?
"," ").Substring(0,[Math]::Min(200,$E.Message.Length))
            })
        }
        Write-Log ("DFS replication events: " + $DFSEvents.Count)
    } catch { Write-Log "DFS events not available: $_" "WARN" }

    # Mapped drives and share connections from this server
    $ServerShares = @(Get-SmbShare -ErrorAction SilentlyContinue | Select-Object Name, Path, Description, ShareType, CurrentUsers)
    $ServerSessions = @(Get-SmbSession -ErrorAction SilentlyContinue | Select-Object SessionId, ClientComputerName, ClientUserName, NumOpens, SecondsIdle)

    $FileServerAudit = [PSCustomObject]@{
        Collected         = $true
        FileAccessEvents  = $FileAccessEvents
        DFSEvents         = $DFSEvents
        ActiveShares      = $ServerShares
        ActiveSessions    = $ServerSessions
        DaysBack          = $DaysBack
    }
    Write-Log ("Server file audit: Access=" + $FileAccessEvents.Count + " DFS=" + $DFSEvents.Count + " Shares=" + $ServerShares.Count)
}

$Evidence = [PSCustomObject]@{
    ChainOfCustody     = [PSCustomObject]@{ CaseNumber=$CaseNum; Hostname=$Hostname; CollectedAt=(Get-Date).ToString("o"); ToolVersion="1.0"; IsAdmin=$IsAdmin }
    ArtifactType       = "CloudServiceArtifacts"
    Compatibility      = "Windows 10/11 (OneDrive/Teams); Server partial"
    OutputDirectory    = $OutDir
    OneDrive           = $OneDriveData
    MicrosoftTeams     = $TeamsData
    CloudCredentials   = $AzureCredData
    InstalledCloudApps = $InstalledCloudApps
    FileServerAudit    = $FileServerAudit
    OSMode             = if ($IsServer) { "Server OS - file share audit + cloud CLI artifacts" } else { "Workstation OS - OneDrive/Teams/browser cloud artifacts" }
    Note               = "DB files copied to OutputDirectory for offline analysis"
}

$Evidence | ConvertTo-Json -Depth 7 | Out-File -FilePath $JsonFile -Encoding UTF8
$Hash = Get-FileHash -Path $JsonFile -Algorithm SHA256
[PSCustomObject]@{ FileName=$JsonFile; Hash=$Hash.Hash; Generated=(Get-Date).ToString("o") } |
    ConvertTo-Json | Out-File "$JsonFile.hash.json" -Encoding UTF8

Write-Host "[+] Cloud artifacts collected" -ForegroundColor Green
Write-Host "    OneDrive: $($OneDriveData.Count) | Teams: $($TeamsData.Count) | Cloud Creds: $($AzureCredData.Count)" -ForegroundColor Cyan
Write-Host "[+] JSON: $JsonFile" -ForegroundColor Green
Write-Log "Completed"
