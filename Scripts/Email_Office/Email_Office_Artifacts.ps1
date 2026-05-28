#Requires -Version 5.1
Set-StrictMode -Off
$ErrorActionPreference = "Continue"
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Hostname  = $env:COMPUTERNAME
$BasePath  = if ($env:DFIR_OUTPUT) { $env:DFIR_OUTPUT } else { "C:\IR_Collection" }
$CaseNum   = if ($env:DFIR_CASE) { $env:DFIR_CASE } else { "CASE-$(Get-Date -Format yyyyMMdd)" }
New-Item -ItemType Directory -Path $BasePath -Force | Out-Null
$LogFile  = "$BasePath\Email_Office_Execution.log"
$JsonFile = "$BasePath\Email_Office_${Hostname}_${Timestamp}.json"

function Write-Log { param([string]$M,[string]$L="INFO") Add-Content $LogFile "$(Get-Date -Format o) [$L] :: $M" }
Write-Log "Email/Office artifact collection started | Case: $CaseNum"

$AllUsers = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue

# Outlook PST/OST files
Write-Host "[*] Locating Outlook PST/OST files..." -ForegroundColor Cyan
$OutlookFiles = [System.Collections.Generic.List[PSCustomObject]]::new()
foreach ($User in $AllUsers) {
    $OLPaths = @(
        "$($User.FullName)\Documents\Outlook Files",
        "$($User.FullName)\AppData\Local\Microsoft\Outlook",
        "$($User.FullName)\AppData\Roaming\Microsoft\Outlook"
    )
    foreach ($OLPath in $OLPaths) {
        if (-not (Test-Path $OLPath)) { continue }
        Get-ChildItem $OLPath -Recurse -Include "*.pst","*.ost" -ErrorAction SilentlyContinue | ForEach-Object {
            $OutlookFiles.Add([PSCustomObject]@{
                User         = $User.Name
                FileName     = $_.Name
                FullPath     = $_.FullName
                Type         = $_.Extension.TrimStart(".").ToUpper()
                SizeGB       = [math]::Round($_.Length/1GB,3)
                LastModified = $_.LastWriteTimeUtc.ToString("o")
                CreationTime = $_.CreationTimeUtc.ToString("o")
            })
        }
    }
}

# Outlook profiles and account config
Write-Host "[*] Collecting Outlook profile configuration..." -ForegroundColor Cyan
$OutlookProfiles = [System.Collections.Generic.List[PSCustomObject]]::new()
$OLProfileKey = "HKCU:\SOFTWARE\Microsoft\Office\*\Outlook\Profiles"
Get-ChildItem $OLProfileKey -ErrorAction SilentlyContinue | ForEach-Object {
    $ProfileName = $_.PSChildName
    Get-ChildItem $_.PSPath -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        $Props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
        if ($Props."Account Name") {
            $OutlookProfiles.Add([PSCustomObject]@{
                Profile      = $ProfileName
                AccountName  = $Props."Account Name"
                EmailAddress = $Props."Email"
                ServerName   = $Props."POP3 Server"
            })
        }
    }
}

# Office Recent files and macro settings
Write-Host "[*] Collecting Office recent files and macro settings..." -ForegroundColor Cyan
$OfficeApps = @("Word","Excel","PowerPoint","Access","OneNote")
$OfficeData = [System.Collections.Generic.List[PSCustomObject]]::new()
foreach ($App in $OfficeApps) {
    $RecentKey = "HKCU:\SOFTWARE\Microsoft\Office\*\$App\File MRU"
    $MacroKey  = "HKCU:\SOFTWARE\Microsoft\Office\*\$App\Security"
    Get-ChildItem $RecentKey -ErrorAction SilentlyContinue | ForEach-Object {
        $Props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
        $Files = @($Props.PSObject.Properties | Where-Object { $_.Name -match "^Item" } | ForEach-Object { $_.Value -replace "^\[.+\]\*","" })
        if ($Files.Count -gt 0) {
            $MacroProps  = $null
            $MacroSetting= $null
            try {
                $MacroParent = $_.PSPath -replace "File MRU","Security"
                $MacroProps  = Get-ItemProperty $MacroParent -ErrorAction SilentlyContinue
                $MacroSetting= $MacroProps.VBAWarnings
            } catch {}
            $OfficeData.Add([PSCustomObject]@{
                Application   = $App
                RecentFiles   = $Files
                RecentCount   = $Files.Count
                VBAWarnings   = $MacroSetting
                MacroRisk     = switch ($MacroSetting) { 1{"All enabled - HIGH RISK"} 2{"Signed only"} 3{"Disabled with notification"} 4{"Disabled - most secure"} default{"Unknown"} }
            })
        }
    }
}

# Office trusted locations
Write-Host "[*] Checking Office Trusted Locations..." -ForegroundColor Cyan
$TrustedLocations = [System.Collections.Generic.List[PSCustomObject]]::new()
foreach ($App in $OfficeApps) {
    Get-ChildItem "HKCU:\SOFTWARE\Microsoft\Office\*\$App\Security\Trusted Locations" -ErrorAction SilentlyContinue | ForEach-Object {
        Get-ChildItem $_.PSPath -ErrorAction SilentlyContinue | ForEach-Object {
            $Props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
            if ($Props.Path) {
                $TrustedLocations.Add([PSCustomObject]@{
                    Application    = $App
                    Path           = $Props.Path
                    AllowSubFolders= $Props.AllowSubFolders
                    Description    = $Props.Description
                    IsSuspicious   = ($Props.Path -match "%TEMP%|%APPDATA%|Downloads|Desktop" )
                })
            }
        }
    }
}

# Recently opened Office files with macro indicators
Write-Host "[*] Scanning recent Office files for macro-enabled formats..." -ForegroundColor Cyan
$MacroFiles = [System.Collections.Generic.List[PSCustomObject]]::new()
$DaysBack   = if ($env:DFIR_DAYS) { [int]$env:DFIR_DAYS } else { 30 }
$SinceDate  = (Get-Date).AddDays(-$DaysBack)
$MacroExtensions = @("*.xlsm","*.xlsb","*.docm","*.dotm","*.pptm","*.potm","*.xltm","*.xlam","*.docb")

foreach ($User in $AllUsers) {
    foreach ($Ext in $MacroExtensions) {
        Get-ChildItem "$($User.FullName)" -Recurse -Filter $Ext -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTimeUtc -gt $SinceDate } | ForEach-Object {
                $MacroFiles.Add([PSCustomObject]@{
                    User         = $User.Name
                    FileName     = $_.Name
                    FullPath     = $_.FullName
                    Extension    = $_.Extension
                    SizeBytes    = $_.Length
                    LastModified = $_.LastWriteTimeUtc.ToString("o")
                    Note         = "Macro-enabled file found - review for malicious macros"
                })
            }
    }
}

# Jump Lists
Write-Host "[*] Collecting Jump List metadata..." -ForegroundColor Cyan
$JumpLists = [System.Collections.Generic.List[PSCustomObject]]::new()
foreach ($User in $AllUsers) {
    $JLPaths = @(
        "$($User.FullName)\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations",
        "$($User.FullName)\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations"
    )
    foreach ($JLPath in $JLPaths) {
        if (-not (Test-Path $JLPath)) { continue }
        $JLType = Split-Path $JLPath -Leaf
        Get-ChildItem $JLPath -ErrorAction SilentlyContinue | ForEach-Object {
            $JumpLists.Add([PSCustomObject]@{
                User         = $User.Name
                Type         = $JLType
                FileName     = $_.Name
                SizeBytes    = $_.Length
                LastModified = $_.LastWriteTimeUtc.ToString("o")
                AppID        = $_.BaseName
                Note         = "Use JLECmd.exe (Eric Zimmerman) for full parsing of application activity"
            })
        }
    }
}

Write-Log "PST/OST: $($OutlookFiles.Count) | Profiles: $($OutlookProfiles.Count) | MacroFiles: $($MacroFiles.Count) | JumpLists: $($JumpLists.Count)"

$Evidence = [PSCustomObject]@{
    ChainOfCustody    = [PSCustomObject]@{ CaseNumber=$CaseNum; Hostname=$Hostname; CollectedAt=(Get-Date).ToString("o"); ToolVersion="1.0" }
    ArtifactType      = "Email_Office_Artifacts"
    OutlookPSTOST     = $OutlookFiles
    OutlookProfiles   = $OutlookProfiles
    OfficeRecentFiles = $OfficeData
    OfficeTrustedLocs = $TrustedLocations
    MacroEnabledFiles = $MacroFiles
    JumpLists         = $JumpLists
}

$Evidence | ConvertTo-Json -Depth 7 | Out-File -FilePath $JsonFile -Encoding UTF8
$Hash = Get-FileHash -Path $JsonFile -Algorithm SHA256
[PSCustomObject]@{ FileName=$JsonFile; Hash=$Hash.Hash; Generated=(Get-Date).ToString("o") } |
    ConvertTo-Json | Out-File "$JsonFile.hash.json" -Encoding UTF8

Write-Host "[+] Email/Office artifacts collected | PST/OST: $($OutlookFiles.Count) | Macro Files: $($MacroFiles.Count) | JumpLists: $($JumpLists.Count)" -ForegroundColor Green
Write-Host "[+] JSON: $JsonFile" -ForegroundColor Green
Write-Log "Completed"
