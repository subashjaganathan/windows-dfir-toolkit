#Requires -Version 5.1
<#
.SYNOPSIS
    Collects full system baseline information as the IR case header.

.DESCRIPTION
    Captures OS details, hardware, domain membership, timezone,
    NTP sync status, logged-on users, uptime, and environment
    variables. Always run FIRST in any IR engagement.

.IR_PHASE
    Identification / Case Initialization

.MITRE_ATTCK
    T1082 - System Information Discovery
    T1614 - System Location Discovery

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

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Hostname  = $env:COMPUTERNAME
$BasePath  = if ($env:DFIR_OUTPUT) { $env:DFIR_OUTPUT } else { "C:\IR_Collection" }
$CaseNum   = if ($env:DFIR_CASE) { $env:DFIR_CASE } else { "CASE-$(Get-Date -Format yyyyMMdd)" }
$Investigator = if ($env:DFIR_INV)   { $env:DFIR_INV }   else { $env:USERNAME }
New-Item -ItemType Directory -Path $BasePath -Force | Out-Null
$LogFile   = "$BasePath\System_Info_Execution.log"
$JsonFile  = "$BasePath\System_Info_${Hostname}_${Timestamp}.json"

function Write-Log { param([string]$M,[string]$L="INFO") Add-Content $LogFile "$(Get-Date -Format o) [$L] :: $M" }

Write-Log "System info collection started | Case: $CaseNum | Investigator: $Investigator"
Write-Host "[*] Collecting system information..." -ForegroundColor Cyan

# OS
$OS  = Get-CimInstance Win32_OperatingSystem  -ErrorAction SilentlyContinue
$CS  = Get-CimInstance Win32_ComputerSystem   -ErrorAction SilentlyContinue
$CPU = Get-CimInstance Win32_Processor        -ErrorAction SilentlyContinue | Select-Object -First 1
$BIOS= Get-CimInstance Win32_BIOS             -ErrorAction SilentlyContinue

# NTP
$W32 = (w32tm /query /status 2>&1) -join "`n"
$NtpSource = if ($W32 -match "Source\s*:\s*(.+)") { $Matches[1].Trim() } else { "Unknown" }
$NtpOffset = if ($W32 -match "Phase Offset\s*:\s*(.+)") { $Matches[1].Trim() } else { "Unknown" }
$NtpStratum= if ($W32 -match "Stratum\s*:\s*(.+)") { $Matches[1].Trim() } else { "Unknown" }

# Logged-on users
$LoggedOn = @(query user 2>$null | Select-Object -Skip 1 | ForEach-Object {
    if ($_ -match '^\s*(.+?)\s+(\S+)\s+(\d+)\s+(\S+)\s+(.+)$') {
        [PSCustomObject]@{ Username=$Matches[1].Trim(); Session=$Matches[2]; ID=$Matches[3]; State=$Matches[4]; IdleTime=$Matches[5].Trim() }
    }
})

# Network adapters
$Adapters = @(Get-NetIPConfiguration -ErrorAction SilentlyContinue | ForEach-Object {
    [PSCustomObject]@{
        Alias       = $_.InterfaceAlias
        IPv4        = ($_.IPv4Address.IPAddress -join ", ")
        IPv6        = ($_.IPv6Address.IPAddress -join ", ")
        Gateway     = $_.IPv4DefaultGateway.NextHop
        DNS         = ($_.DNSServer.ServerAddresses -join ", ")
        MACAddress  = (Get-NetAdapter -Name $_.InterfaceAlias -ErrorAction SilentlyContinue).MacAddress
    }
})

# Drives
$Drives = @(Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue | ForEach-Object {
    [PSCustomObject]@{
        Drive      = $_.Name
        Root       = $_.Root
        UsedGB     = [math]::Round(($_.Used / 1GB), 2)
        FreeGB     = [math]::Round(($_.Free / 1GB), 2)
        TotalGB    = [math]::Round((($_.Used + $_.Free) / 1GB), 2)
    }
})

# Environment variables
$EnvVars = [System.Environment]::GetEnvironmentVariables([System.EnvironmentVariableTarget]::Machine)
$EnvData = @($EnvVars.GetEnumerator() | Sort-Object Name | ForEach-Object {
    [PSCustomObject]@{ Name = $_.Key; Value = $_.Value }
})

# Domain info
$DomainInfo = [PSCustomObject]@{
    Domain        = $CS.Domain
    DomainRole    = switch ($CS.DomainRole) {
        0 {"StandaloneWorkstation"} 1 {"MemberWorkstation"} 2 {"StandaloneServer"}
        3 {"MemberServer"} 4 {"BackupDomainController"} 5 {"PrimaryDomainController"}
    }
    PartOfDomain  = $CS.PartOfDomain
}

$Evidence = [PSCustomObject]@{
    ChainOfCustody = [PSCustomObject]@{
        CaseNumber    = $CaseNum
        Investigator  = $Investigator
        CollectedAt   = (Get-Date).ToString("o")
        CollectedAtUTC= (Get-Date).ToUniversalTime().ToString("o")
        TimeZone      = [System.TimeZoneInfo]::Local.Id
        NTPSource     = $NtpSource
        NTPOffset     = $NtpOffset
        NTPStratum    = $NtpStratum
        ToolVersion="1.0"
        IsAdmin       = $IsAdmin
    }
    ArtifactType = "SystemInformation"
    System = [PSCustomObject]@{
        Hostname        = $Hostname
        FQDN            = [System.Net.Dns]::GetHostEntry("").HostName
        OSCaption       = $OS.Caption
        OSVersion       = $OS.Version
        OSBuildNumber   = $OS.BuildNumber
        OSArchitecture  = $OS.OSArchitecture
        OSInstallDate   = $OS.InstallDate.ToString("o")
        LastBootTime    = $OS.LastBootUpTime.ToString("o")
        UptimeDays      = [math]::Round(((Get-Date) - $OS.LastBootUpTime).TotalDays, 2)
        SerialNumber    = $BIOS.SerialNumber
        Manufacturer    = $CS.Manufacturer
        Model           = $CS.Model
        TotalRAMGB      = [math]::Round($CS.TotalPhysicalMemory / 1GB, 2)
        CPUName         = $CPU.Name
        CPUCores        = $CPU.NumberOfCores
        CPULogical      = $CPU.NumberOfLogicalProcessors
        Timezone        = [System.TimeZoneInfo]::Local.DisplayName
    }
    Domain          = $DomainInfo
    NetworkAdapters = $Adapters
    LoggedOnUsers   = $LoggedOn
    Drives          = $Drives
    EnvironmentVars = $EnvData
}

$Evidence | ConvertTo-Json -Depth 8 | Out-File -FilePath $JsonFile -Encoding UTF8
$Hash = Get-FileHash -Path $JsonFile -Algorithm SHA256
[PSCustomObject]@{ FileName=$JsonFile; Hash=$Hash.Hash; Generated=(Get-Date).ToString("o") } |
    ConvertTo-Json | Out-File "$JsonFile.hash.json" -Encoding UTF8

Write-Log "System info collected successfully"
Write-Host "[+] System Info collected" -ForegroundColor Green
Write-Host "[+] JSON    : $JsonFile"   -ForegroundColor Green
Write-Log "Completed"
