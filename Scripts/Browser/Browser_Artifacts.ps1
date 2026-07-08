#Requires -Version 5.1
<#
.SYNOPSIS
    Collects browser artifacts (Win10/11) or IIS/web server logs (Server OS).

.DESCRIPTION
    On Workstation OS (Win10/11):
      Extracts browser artifacts from Chrome, Edge, and Firefox across
      all user profiles - history DBs, downloads, and extensions.
    On Server OS:
      No browsers typically installed - instead collects IIS access
      logs, IIS error logs, HTTP.sys logs, FTP logs, and web app
      event logs for incident investigation.

.COMPATIBILITY
    Windows 10/11   : Full browser artifact collection
    Server 2016+    : Full IIS/web server log collection

.IR_PHASE
    User Activity / Web Investigation

.MITRE_ATTCK
    T1217 - Browser Bookmark Discovery
    T1539 - Steal Web Session Cookie
    T1190 - Exploit Public-Facing Application (IIS logs)

.FORENSIC_SAFETY
    Read-only - browser DBs copied before reading

.AUTHOR
    DFIR Toolkit

.VERSION
    2.1
#>

Set-StrictMode -Off
$ErrorActionPreference = "Continue"


# --- Shared toolkit module: single source of truth for version + base paths ---
$__DFIRMod = Join-Path $PSScriptRoot '..\Infrastructure\DFIR_Common.psm1'
if (Test-Path $__DFIRMod) { Import-Module $__DFIRMod -Force -ErrorAction SilentlyContinue }
if (-not $Global:DFIR_ToolVersion) { $Global:DFIR_ToolVersion = '1.0' }
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

$Timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
$Hostname   = $env:COMPUTERNAME
$BasePath = if ($env:DFIR_OUTPUT) { $env:DFIR_OUTPUT } else { "C:\IR_Collection" }
$CaseNum    = if ($env:DFIR_CASE) { $env:DFIR_CASE } else { "CASE-$(Get-Date -Format yyyyMMdd)" }
$BrowserDir = "$BasePath\Browser_Artifacts_${Hostname}_${Timestamp}"
New-Item -ItemType Directory -Path $BrowserDir -Force | Out-Null
$LogFile    = "$BasePath\Browser_Artifacts_Execution.log"
$JsonFile   = "$BasePath\Browser_Artifacts_${Hostname}_${Timestamp}.json"

function Write-Log { param([string]$M,[string]$L="INFO") Add-Content $LogFile "$(Get-Date -Format o) [$L] :: $M" }
Write-Log "Browser/Web artifact collection started | Case: $CaseNum"

# -- OS Detection --------------------------------------------------------------
$OSInfo    = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
$OSCaption = $OSInfo.Caption
$IsServer  = $OSCaption -match "Server"
$OSBuild   = [int]$OSInfo.BuildNumber
Write-Log "OS: $OSCaption | IsServer: $IsServer"

function Copy-SafeDB {
    param([string]$Source, [string]$DestDir, [string]$Label)
    if (-not (Test-Path $Source)) { return $null }
    $Dest = Join-Path $DestDir "$Label.db"
    try { Copy-Item $Source $Dest -Force -ErrorAction Stop; return $Dest }
    catch { Write-Log "Could not copy DB $Source : $_" "WARN"; return $null }
}

# ==============================================================================
# WORKSTATION PATH - Chrome, Edge, Firefox
# ==============================================================================
$ChromeProfiles  = [System.Collections.Generic.List[PSCustomObject]]::new()
$EdgeProfiles    = [System.Collections.Generic.List[PSCustomObject]]::new()
$FirefoxProfiles = [System.Collections.Generic.List[PSCustomObject]]::new()
$IISData         = [PSCustomObject]@{ Collected = $false }

if (-not $IsServer) {
    Write-Host "[*] Workstation OS - collecting browser artifacts..." -ForegroundColor Cyan
    $AllUsers = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue

    # -- Chrome ----------------------------------------------------------------
    Write-Host "[*] Collecting Chrome artifacts..." -ForegroundColor Cyan
    foreach ($User in $AllUsers) {
        $ChromeBase = "$($User.FullName)\AppData\Local\Google\Chrome\User Data"
        if (-not (Test-Path $ChromeBase)) { continue }
        Get-ChildItem $ChromeBase -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match "^(Default|Profile)" } | ForEach-Object {
                $ProfileDir  = $_.FullName
                $ProfileName = $_.Name
                $UserDir     = New-Item -ItemType Directory -Path "$BrowserDir\Chrome_$($User.Name)_$ProfileName" -Force
                $HistoryDB   = Copy-SafeDB "$ProfileDir\History" $UserDir "History"
                $Extensions  = @()
                if (Test-Path "$ProfileDir\Extensions") {
                    $Extensions = @(Get-ChildItem "$ProfileDir\Extensions" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                        $MPath = Get-ChildItem $_.FullName -Recurse -Filter "manifest.json" -ErrorAction SilentlyContinue | Select-Object -First 1
                        $M = $null; if ($MPath) { try { $M = Get-Content $MPath.FullName -Raw | ConvertFrom-Json } catch {} }
                        [PSCustomObject]@{ ExtensionID=$_.Name; Name=$M.name; Version=$M.version; Permissions=$M.permissions }
                    })
                }
                $ChromeProfiles.Add([PSCustomObject]@{
                    User=$User.Name; Profile=$ProfileName
                    HistoryDBCopied=[bool]$HistoryDB; HistoryDBPath=$HistoryDB
                    ExtensionCount=$Extensions.Count; Extensions=$Extensions
                    Note="Run: SELECT url,title,last_visit_time FROM urls ORDER BY last_visit_time DESC on History.db"
                })
                Write-Log ("Chrome " + $User.Name + " " + $ProfileName + ": " + $Extensions.Count + " extensions")
            }
    }

    # -- Edge ------------------------------------------------------------------
    Write-Host "[*] Collecting Edge artifacts..." -ForegroundColor Cyan
    foreach ($User in $AllUsers) {
        $EdgeBase = "$($User.FullName)\AppData\Local\Microsoft\Edge\User Data"
        if (-not (Test-Path $EdgeBase)) { continue }
        Get-ChildItem $EdgeBase -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match "^(Default|Profile)" } | ForEach-Object {
                $UserDir   = New-Item -ItemType Directory -Path "$BrowserDir\Edge_$($User.Name)_$($_.Name)" -Force
                $HistoryDB = Copy-SafeDB "$($_.FullName)\History" $UserDir "History"
                $Extensions = @()
                if (Test-Path "$($_.FullName)\Extensions") {
                    $Extensions = @(Get-ChildItem "$($_.FullName)\Extensions" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                        $MPath = Get-ChildItem $_.FullName -Recurse -Filter "manifest.json" -ErrorAction SilentlyContinue | Select-Object -First 1
                        $M = $null; if ($MPath) { try { $M = Get-Content $MPath.FullName -Raw | ConvertFrom-Json } catch {} }
                        [PSCustomObject]@{ ExtensionID=$_.Name; Name=$M.name; Version=$M.version; Permissions=$M.permissions }
                    })
                }
                $EdgeProfiles.Add([PSCustomObject]@{
                    User=$User.Name; Profile=$_.Name
                    HistoryDBCopied=[bool]$HistoryDB; HistoryDBPath=$HistoryDB
                    ExtensionCount=$Extensions.Count; Extensions=$Extensions
                })
            }
    }

    # -- Firefox ---------------------------------------------------------------
    Write-Host "[*] Collecting Firefox artifacts..." -ForegroundColor Cyan
    foreach ($User in $AllUsers) {
        $FFBase = "$($User.FullName)\AppData\Roaming\Mozilla\Firefox\Profiles"
        if (-not (Test-Path $FFBase)) { continue }
        Get-ChildItem $FFBase -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $UserDir  = New-Item -ItemType Directory -Path "$BrowserDir\Firefox_$($User.Name)_$($_.Name)" -Force
            $PlacesDB = Copy-SafeDB "$($_.FullName)\places.sqlite" $UserDir "Places"
            $ExtData  = @()
            $ExtJson  = "$($_.FullName)\extensions.json"
            if (Test-Path $ExtJson) {
                try {
                    $ExtObj  = Get-Content $ExtJson -Raw | ConvertFrom-Json
                    $ExtData = @($ExtObj.addons | ForEach-Object {
                        [PSCustomObject]@{ ID=$_.id; Name=$_.defaultLocale.name; Version=$_.version; Active=$_.active }
                    })
                } catch {}
            }
            $FirefoxProfiles.Add([PSCustomObject]@{
                User=$User.Name; Profile=$_.Name
                PlacesDBCopied=[bool]$PlacesDB; PlacesDBPath=$PlacesDB
                ExtensionCount=$ExtData.Count; Extensions=$ExtData
                Note="Run: SELECT url,title,last_visit_date FROM moz_places on Places.db"
            })
            Write-Log ("Firefox " + $User.Name + ": " + $ExtData.Count + " extensions")
        }
    }
}

# ==============================================================================
# SERVER PATH - IIS Logs, HTTP.sys, Web Application Logs
# ==============================================================================
if ($IsServer) {
    Write-Host "[*] Server OS - collecting IIS and web server artifacts..." -ForegroundColor Cyan
    Write-Log "Server OS detected - collecting IIS/web artifacts instead of browser"

    $IISLogData  = [System.Collections.Generic.List[PSCustomObject]]::new()
    $IISConfig   = [PSCustomObject]@{}
    $IISLogDir   = New-Item -ItemType Directory -Path "$BrowserDir\IIS_Logs" -Force

    # IIS Service Status
    $IISService = Get-Service W3SVC -ErrorAction SilentlyContinue
    $IISInstalled = $null -ne $IISService

    if ($IISInstalled) {
        Write-Host "[*] IIS detected - collecting log files..." -ForegroundColor Cyan

        # IIS config via appcmd
        $AppCmdPath = "C:\Windows\System32\inetsrv\appcmd.exe"
        $Sites = @()
        if (Test-Path $AppCmdPath) {
            try {
                $SiteList = (& $AppCmdPath list site 2>&1)
                $Sites = @($SiteList | ForEach-Object {
                    if ($_ -match 'SITE "(.+?)" \(id:(\d+),bindings:(.+?),state:(.+?)\)') {
                        [PSCustomObject]@{ Name=$Matches[1]; ID=$Matches[2]; Bindings=$Matches[3]; State=$Matches[4] }
                    }
                })
            } catch {}
        }

        # Default IIS log paths
        $IISLogPaths = @(
            "C:\inetpub\logs\LogFiles",
            "C:\Windows\System32\LogFiles\W3SVC*",
            "C:\Windows\System32\LogFiles\HTTPERR"
        )

        $DaysBack = if ($env:DFIR_DAYS) { [int]$env:DFIR_DAYS } else { 30 }
        $SinceDate = (Get-Date).AddDays(-$DaysBack)

        foreach ($LogPattern in $IISLogPaths) {
            $LogDirs = @(Get-Item $LogPattern -ErrorAction SilentlyContinue)
            foreach ($LogDir in $LogDirs) {
                if (-not (Test-Path $LogDir)) { continue }
                $LogFiles = @(Get-ChildItem $LogDir -Recurse -Filter "*.log" -ErrorAction SilentlyContinue |
                    Where-Object { $_.LastWriteTimeUtc -gt $SinceDate } |
                    Sort-Object LastWriteTimeUtc -Descending)

                foreach ($LogFile in $LogFiles) {
                    $DestFile = "$IISLogDir\$($LogFile.Directory.Name)_$($LogFile.Name)"
                    try {
                        Copy-Item $LogFile.FullName $DestFile -Force -ErrorAction Stop
                        $IISLogData.Add([PSCustomObject]@{
                            SourcePath    = $LogFile.FullName
                            CopiedTo      = $DestFile
                            SizeBytes     = $LogFile.Length
                            LastModified  = $LogFile.LastWriteTimeUtc.ToString("o")
                            LogType       = if ($LogFile.FullName -match "HTTPERR") { "HTTP Error" } else { "IIS Access" }
                            CopyStatus    = "Success"
                        })
                    } catch {
                        $IISLogData.Add([PSCustomObject]@{ SourcePath=$LogFile.FullName; CopyStatus="Failed: $_" })
                    }
                }
            }
        }

        # HTTP.sys error log
        $HTTPSysLog = "C:\Windows\System32\LogFiles\HTTPERR"
        if (Test-Path $HTTPSysLog) {
            Get-ChildItem $HTTPSysLog -Filter "*.log" -ErrorAction SilentlyContinue | ForEach-Object {
                Copy-Item $_.FullName "$IISLogDir\HTTPErr_$($_.Name)" -Force -ErrorAction SilentlyContinue
            }
        }

        $IISConfig = [PSCustomObject]@{
            IISInstalled      = $true
            ServiceStatus     = $IISService.Status.ToString()
            ServiceStartType  = $IISService.StartType.ToString()
            Sites             = $Sites
            LogFilesCollected = $IISLogData.Count
            OutputDirectory   = $IISLogDir.FullName
            DaysBack          = $DaysBack
        }
        Write-Log ("IIS log files collected: " + $IISLogData.Count)
    } else {
        Write-Host "[*] IIS not installed - checking other web services..." -ForegroundColor Cyan
        $IISConfig = [PSCustomObject]@{
            IISInstalled = $false
            Note         = "IIS (W3SVC) not found on this server"
        }
        Write-Log "IIS not installed on this server"
    }

    # Apache/Nginx log paths (if installed)
    $ThirdPartyWebLogs = [System.Collections.Generic.List[PSCustomObject]]::new()
    $WebLogPaths = @(
        @{ App="Apache";  Path="C:\Apache*\logs" }
        @{ App="Apache";  Path="C:\xampp\apache\logs" }
        @{ App="Nginx";   Path="C:\nginx\logs" }
        @{ App="Tomcat";  Path="C:\Tomcat*\logs" }
    )
    foreach ($WLP in $WebLogPaths) {
        $LogItems = @(Get-Item $WLP.Path -ErrorAction SilentlyContinue)
        foreach ($LI in $LogItems) {
            if (Test-Path $LI) {
                $ThirdPartyWebLogs.Add([PSCustomObject]@{
                    Application = $WLP.App
                    LogPath     = $LI.FullName
                    Files       = @(Get-ChildItem $LI -Filter "*.log" -ErrorAction SilentlyContinue | Select-Object Name, LastWriteTime, Length)
                })
                Write-Log ("Third-party web logs found: " + $WLP.App + " at " + $LI.FullName)
            }
        }
    }

    $IISData = [PSCustomObject]@{
        Collected          = $true
        IISConfig          = $IISConfig
        IISLogFiles        = $IISLogData
        ThirdPartyWebLogs  = $ThirdPartyWebLogs
        OutputDirectory    = $IISLogDir.FullName
    }
}

$Evidence = [PSCustomObject]@{
    ChainOfCustody  = [PSCustomObject]@{ CaseNumber=$CaseNum; Hostname=$Hostname; CollectedAt=([DateTime]::UtcNow).ToString("o"); ToolVersion=$Global:DFIR_ToolVersion; IsServer=$IsServer }
    ArtifactType    = if ($IsServer) { "WebServerLogs" } else { "BrowserArtifacts" }
    OSMode          = if ($IsServer) { "Server - IIS/Web logs collected" } else { "Workstation - Browser artifacts collected" }
    OutputDirectory = $BrowserDir
    Chrome          = $ChromeProfiles
    Edge            = $EdgeProfiles
    Firefox         = $FirefoxProfiles
    IISWebServer    = $IISData
}

$Evidence | ConvertTo-Json -Depth 8 | Out-File -FilePath $JsonFile -Encoding UTF8
$Hash = Get-FileHash -Path $JsonFile -Algorithm SHA256
[PSCustomObject]@{ FileName=$JsonFile; Hash=$Hash.Hash; Generated=([DateTime]::UtcNow).ToString("o") } |
    ConvertTo-Json | Out-File "$JsonFile.hash.json" -Encoding UTF8

if ($IsServer) {
    Write-Host "[+] Server web artifacts collected | IIS Logs: $($IISData.IISLogFiles.Count)" -ForegroundColor Green
} else {
    Write-Host "[+] Browser artifacts collected | Chrome: $($ChromeProfiles.Count) | Edge: $($EdgeProfiles.Count) | Firefox: $($FirefoxProfiles.Count)" -ForegroundColor Green
}
Write-Host "[+] JSON: $JsonFile" -ForegroundColor Green
Write-Log "Completed"
