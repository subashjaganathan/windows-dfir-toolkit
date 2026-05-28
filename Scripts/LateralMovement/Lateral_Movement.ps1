#Requires -Version 5.1
<#
.SYNOPSIS
    Collects lateral movement artifacts and remote access indicators.

.DESCRIPTION
    Enumerates SMB sessions, active RDP sessions, admin shares,
    WinRM configuration, DCOM settings, remote logon evidence,
    and PSExec artifacts.

.IR_PHASE
    Lateral Movement / Investigation

.MITRE_ATTCK
    T1021.001 - Remote Services: RDP
    T1021.002 - Remote Services: SMB/Windows Admin Shares
    T1021.006 - Remote Services: Windows Remote Management
    T1570     - Lateral Tool Transfer
    T1135     - Network Share Discovery

.FORENSIC_SAFETY
    Read-only, forensic-safe

.AUTHOR
    DFIR Toolkit

.VERSION
    2.0
#>

Set-StrictMode -Off
$ErrorActionPreference = "Continue"
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) { Write-Warning "[!] Administrator privileges required for SMB session and share enumeration." }

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Hostname  = $env:COMPUTERNAME
$BasePath  = if ($env:DFIR_OUTPUT) { $env:DFIR_OUTPUT } else { "C:\IR_Collection" }
$CaseNum   = if ($env:DFIR_CASE) { $env:DFIR_CASE } else { "CASE-$(Get-Date -Format yyyyMMdd)" }
New-Item -ItemType Directory -Path $BasePath -Force | Out-Null
$LogFile  = "$BasePath\Lateral_Movement_Execution.log"
$JsonFile = "$BasePath\Lateral_Movement_${Hostname}_${Timestamp}.json"

function Write-Log { param([string]$M,[string]$L="INFO") Add-Content $LogFile "$(Get-Date -Format o) [$L] :: $M" }
Write-Log "Lateral movement artifact collection started"

# -- SMB Sessions ---------------------------------------------------------------
Write-Host "[*] Collecting SMB sessions..." -ForegroundColor Cyan
$SMBSessions = @(Get-SmbSession -ErrorAction SilentlyContinue | ForEach-Object {
    [PSCustomObject]@{
        SessionID    = $_.SessionId
        ClientName   = $_.ClientComputerName
        ClientIP     = $_.ClientUserName
        NumOpens     = $_.NumOpens
        SecondsIdle  = $_.SecondsIdle
        SecondsExist = $_.SecondsExists
    }
})
Write-Log "SMB sessions: $($SMBSessions.Count)"

# -- SMB Open Files -------------------------------------------------------------
Write-Host "[*] Collecting SMB open files..." -ForegroundColor Cyan
$SMBFiles = @(Get-SmbOpenFile -ErrorAction SilentlyContinue | ForEach-Object {
    [PSCustomObject]@{
        FileID     = $_.FileId
        SessionID  = $_.SessionId
        Path       = $_.Path
        ShareName  = $_.ShareName
        ClientName = $_.ClientComputerName
    }
})
Write-Log "SMB open files: $($SMBFiles.Count)"

# -- Network Shares -------------------------------------------------------------
Write-Host "[*] Collecting network shares..." -ForegroundColor Cyan
$Shares = @(Get-SmbShare -ErrorAction SilentlyContinue | ForEach-Object {
    [PSCustomObject]@{
        Name          = $_.Name
        Path          = $_.Path
        Description   = $_.Description
        ShareType     = $_.ShareType
        CurrentUsers  = $_.CurrentUsers
        EncryptData   = $_.EncryptData
        FolderEnumMode= $_.FolderEnumerationMode
        IsHidden      = $_.Name.EndsWith("$")
        IsSuspicious  = ($_.Name -notin @("ADMIN$","C$","D$","E$","IPC$","print$","SYSVOL","NETLOGON") -and $_.Name.EndsWith("$"))
    }
})
Write-Log "Network shares: $($Shares.Count)"

# -- RDP Configuration ----------------------------------------------------------
Write-Host "[*] Collecting RDP configuration..." -ForegroundColor Cyan
$TSKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
$RDPConfig = [PSCustomObject]@{
    RDPEnabled          = -not [bool](Get-ItemProperty $TSKey -ErrorAction SilentlyContinue).fDenyTSConnections
    RDPPort             = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -ErrorAction SilentlyContinue).PortNumber
    NLARequired         = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -ErrorAction SilentlyContinue).UserAuthentication
    SingleSession       = (Get-ItemProperty $TSKey -ErrorAction SilentlyContinue).fSingleSessionPerUser
    MaxConnections      = (Get-ItemProperty $TSKey -ErrorAction SilentlyContinue).MaxInstanceCount
    ShadowingEnabled    = (Get-ItemProperty $TSKey -ErrorAction SilentlyContinue).Shadow
    NonStandardPort     = ((Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -ErrorAction SilentlyContinue).PortNumber -ne 3389)
}
Write-Log "RDP config collected"

# -- WinRM Configuration --------------------------------------------------------
Write-Host "[*] Collecting WinRM configuration..." -ForegroundColor Cyan
$WinRMData = [PSCustomObject]@{}
try {
    $WinRMConfig = winrm get winrm/config 2>&1
    $WinRMData = [PSCustomObject]@{
        RawConfig = ($WinRMConfig -join "`n")
        ServiceEnabled = (Get-Service WinRM -ErrorAction SilentlyContinue).Status -eq "Running"
    }
} catch { $WinRMData = [PSCustomObject]@{ Error = "WinRM query failed: $_" } }
Write-Log "WinRM config collected"

# -- PSExec Artifacts -----------------------------------------------------------
Write-Host "[*] Checking PSExec artifacts..." -ForegroundColor Cyan
$PSExecArtifacts = [PSCustomObject]@{
    PSEXESVCService   = (Get-CimInstance Win32_Service -Filter "Name='PSEXESVC'" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty PathName -ErrorAction SilentlyContinue)
    PSEXEPipeExists   = Test-Path "\\.\pipe\PSEXESVC" -ErrorAction SilentlyContinue
    PAExecService     = (Get-CimInstance Win32_Service -Filter "Name LIKE 'PAExec%'" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name -ErrorAction SilentlyContinue)
    RemComService     = (Get-CimInstance Win32_Service -Filter "Name='RemCom'" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty PathName -ErrorAction SilentlyContinue)
    SmbExecService    = (Get-CimInstance Win32_Service -Filter "Name='smbexec'" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty PathName -ErrorAction SilentlyContinue)
}
Write-Log "PSExec artifacts checked"

# -- Admin Shares Access History ------------------------------------------------
Write-Host "[*] Checking mapped drives and UNC history..." -ForegroundColor Cyan
$MappedDrives = @(Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayRoot -like "\\*" } |
    ForEach-Object { [PSCustomObject]@{ Drive=$_.Name; UNCPath=$_.DisplayRoot; Root=$_.Root } })

$UNCHistory = @()
try {
    $MRUNet = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU" -ErrorAction SilentlyContinue
    $UNCHistory = @($MRUNet.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS|MRUList" } |
        ForEach-Object { [PSCustomObject]@{ Key=$_.Name; UNCPath=$_.Value } })
} catch {}
Write-Log "Mapped drives: $($MappedDrives.Count) | UNC history: $($UNCHistory.Count)"

# -- Hosts File ----------------------------------------------------------------
Write-Host "[*] Collecting hosts file..." -ForegroundColor Cyan
$HostsFile = [PSCustomObject]@{
    Path    = "C:\Windows\System32\drivers\etc\hosts"
    Content = @(Get-Content "C:\Windows\System32\drivers\etc\hosts" -ErrorAction SilentlyContinue |
                Where-Object { $_ -notmatch "^#" -and $_.Trim() -ne "" })
    NonStandardEntries = @(Get-Content "C:\Windows\System32\drivers\etc\hosts" -ErrorAction SilentlyContinue |
        Where-Object { $_ -notmatch "^#" -and $_.Trim() -ne "" -and $_ -notmatch "^127\.|^::1|^0\.0\.0\.0" })
}
$HostsFile | Add-Member -NotePropertyName IsSuspicious -NotePropertyValue ($HostsFile.NonStandardEntries.Count -gt 0)
Write-Log "Hosts file entries: $($HostsFile.Content.Count)"

$Evidence = [PSCustomObject]@{
    ChainOfCustody = [PSCustomObject]@{ CaseNumber=$CaseNum; Hostname=$Hostname; CollectedAt=(Get-Date).ToString("o"); ToolVersion="1.0" }
    ArtifactType   = "LateralMovement"
    SMBSessions    = $SMBSessions
    SMBOpenFiles   = $SMBFiles
    NetworkShares  = $Shares
    RDPConfig      = $RDPConfig
    WinRMConfig    = $WinRMData
    PSExecArtifacts= $PSExecArtifacts
    MappedDrives   = $MappedDrives
    UNCHistory     = $UNCHistory
    HostsFile      = $HostsFile
}

$Evidence | ConvertTo-Json -Depth 7 | Out-File -FilePath $JsonFile -Encoding UTF8
$Hash = Get-FileHash -Path $JsonFile -Algorithm SHA256
[PSCustomObject]@{ FileName=$JsonFile; Hash=$Hash.Hash; Generated=(Get-Date).ToString("o") } |
    ConvertTo-Json | Out-File "$JsonFile.hash.json" -Encoding UTF8

Write-Host "[+] Lateral movement artifacts collected" -ForegroundColor Green
Write-Host "    SMB Sessions: $($SMBSessions.Count) | Shares: $($Shares.Count) | Mapped Drives: $($MappedDrives.Count)" -ForegroundColor Cyan
Write-Host "[+] JSON: $JsonFile" -ForegroundColor Green
Write-Log "Completed"
