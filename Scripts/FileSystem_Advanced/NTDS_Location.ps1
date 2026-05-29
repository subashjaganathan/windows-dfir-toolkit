#Requires -Version 5.1
Set-StrictMode -Off
$ErrorActionPreference = "Continue"
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Hostname  = $env:COMPUTERNAME
$BasePath  = if ($env:DFIR_OUTPUT) { $env:DFIR_OUTPUT } else { "C:\IR_Collection" }
$CaseNum   = if ($env:DFIR_CASE) { $env:DFIR_CASE } else { "CASE-$(Get-Date -Format yyyyMMdd)" }
New-Item -ItemType Directory -Path $BasePath -Force | Out-Null
$LogFile  = "$BasePath\NTDS_Location_Execution.log"
$JsonFile = "$BasePath\NTDS_Location_${Hostname}_${Timestamp}.json"

function Write-Log { param([string]$M,[string]$L="INFO") Add-Content $LogFile "$(Get-Date -Format o) [$L] :: $M" }
Write-Log "NTDS location collection started | Case: $CaseNum"

# Check if this machine is a Domain Controller
Write-Host "[*] Checking domain controller role..." -ForegroundColor Cyan
$IsDC = $false
$DCRole = [PSCustomObject]@{ IsDomainController = $false }

try {
    $OSInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $IsDC   = $OSInfo.ProductType -eq 2

    $CompSys = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
    $DCRole  = [PSCustomObject]@{
        IsDomainController = $IsDC
        DomainRole         = $CompSys.DomainRole
        DomainRoleName     = switch ($CompSys.DomainRole) {
            0 { "Standalone Workstation" }
            1 { "Member Workstation" }
            2 { "Standalone Server" }
            3 { "Member Server" }
            4 { "Backup Domain Controller" }
            5 { "Primary Domain Controller" }
            default { "Unknown" }
        }
        Domain             = $CompSys.Domain
        PartOfDomain       = $CompSys.PartOfDomain
    }
    Write-Log "Domain role: $($DCRole.DomainRoleName) | IsDC: $IsDC"
} catch { Write-Log "DC role check failed: $_" "WARN" }

# NTDS database location from registry
Write-Host "[*] Locating NTDS database..." -ForegroundColor Cyan
$NTDSInfo = [PSCustomObject]@{ Found = $false }

$NTDSRegKey = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
if (Test-Path $NTDSRegKey) {
    $Props = Get-ItemProperty $NTDSRegKey -ErrorAction SilentlyContinue
    $NTDSPath    = $Props."DSA Database File"
    $NTDSLogPath = $Props."Database log files path"
    $NTDSWorkPath= $Props."DSA Working Directory"
    $SysVolPath  = $Props."System Schema Version"

    $NTDSExists  = if ($NTDSPath)    { Test-Path $NTDSPath    } else { $false }
    $SysHivePath = "$env:SystemRoot\System32\config\SYSTEM"
    $SamHivePath = "$env:SystemRoot\System32\config\SAM"
    $SecHivePath = "$env:SystemRoot\System32\config\SECURITY"

    $NTDSInfo = [PSCustomObject]@{
        Found             = $true
        NTDSPath          = $NTDSPath
        NTDSExists        = $NTDSExists
        NTDSSizeGB        = if ($NTDSExists) { [math]::Round((Get-Item $NTDSPath).Length/1GB,3) } else { $null }
        LogFilesPath      = $NTDSLogPath
        WorkingDirectory  = $NTDSWorkPath
        SYSTEMHive        = $SysHivePath
        SYSTEMHiveExists  = (Test-Path $SysHivePath)
        SAMHive           = $SamHivePath
        SAMHiveExists     = (Test-Path $SamHivePath)
        SECURITYHive      = $SecHivePath
        SECURITYHiveExists= (Test-Path $SecHivePath)
        ExtractionNote    = "For offline extraction: impacket-secretsdump -system SYSTEM -ntds ntds.dit LOCAL"
        ForensicNote      = "NTDS.dit contains all domain password hashes. Requires SYSTEM hive for decryption."
    }
    Write-Log "NTDS: Found=$($NTDSExists) | Path=$NTDSPath | SizeGB=$($NTDSInfo.NTDSSizeGB)"
} else {
    Write-Log "NTDS registry key not found - not a DC or registry inaccessible" "WARN"
    Write-Host "[!] NTDS registry key not found - machine may not be a Domain Controller" -ForegroundColor Yellow
}

# VSS copies containing NTDS
Write-Host "[*] Locating VSS shadow copies with NTDS..." -ForegroundColor Cyan
$NTDSInVSS = [System.Collections.Generic.List[PSCustomObject]]::new()
try {
    $Shadows = @(Get-CimInstance Win32_ShadowCopy -ErrorAction SilentlyContinue)
    foreach ($Shadow in $Shadows) {
        $DevicePath = $Shadow.DeviceObject
        if ($NTDSInfo.Found -and $NTDSInfo.NTDSPath) {
            $NTDSRelPath = $NTDSInfo.NTDSPath -replace "^[A-Za-z]:\\",""
            $VSSNTDSPath = "$DevicePath\$NTDSRelPath"
            $NTDSInVSS.Add([PSCustomObject]@{
                ShadowID      = $Shadow.ID
                CreationDate  = $Shadow.InstallDate.ToString("o")
                DeviceObject  = $DevicePath
                VSSNTDSPath   = $VSSNTDSPath
                VSSSystemHive = "$DevicePath\Windows\System32\config\SYSTEM"
                ExtractionCmd = "impacket-secretsdump -system `"$DevicePath\Windows\System32\config\SYSTEM`" -ntds `"$VSSNTDSPath`" LOCAL"
            })
        }
    }
    Write-Log "VSS copies with NTDS path: $($NTDSInVSS.Count)"
} catch { Write-Log "VSS NTDS search failed: $_" "WARN" }

# ntdsutil snapshot history
Write-Host "[*] Checking ntdsutil snapshot history..." -ForegroundColor Cyan
$NtdsutilHistory = [PSCustomObject]@{ Available = $false }
try {
    $Filter = @{ LogName="Directory Service"; Id=@(2089,1168,1173); StartTime=(Get-Date).AddDays(-30) }
    $DsEvents = @(Get-WinEvent -FilterHashtable $Filter -ErrorAction SilentlyContinue)
    if ($DsEvents) {
        $NtdsutilHistory = [PSCustomObject]@{
            Available   = $true
            EventCount  = $DsEvents.Count
            Events      = @($DsEvents | Select-Object -First 20 | ForEach-Object {
                [PSCustomObject]@{ Time=$_.TimeCreated.ToString("o"); ID=$_.Id; Message=($_.Message -split "`r?`n" -join " ").Substring(0,[Math]::Min(150,$_.Message.Length)) }
            })
        }
    }
    Write-Log "Directory Service events: $($DsEvents.Count)"
} catch { Write-Log "Directory Service log not available: $_" "WARN" }

# SYSVOL location
Write-Host "[*] Locating SYSVOL..." -ForegroundColor Cyan
$SYSVOLInfo = [PSCustomObject]@{ Found = $false }
$SYSVOLKey  = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
if (Test-Path $SYSVOLKey) {
    $Props = Get-ItemProperty $SYSVOLKey -ErrorAction SilentlyContinue
    $SYSVOLPath = $Props.SysVol
    $SYSVOLInfo = [PSCustomObject]@{
        Found    = ($null -ne $SYSVOLPath)
        Path     = $SYSVOLPath
        Exists   = if ($SYSVOLPath) { Test-Path $SYSVOLPath } else { $false }
        SizeMB   = if ($SYSVOLPath -and (Test-Path $SYSVOLPath)) {
            [math]::Round((Get-ChildItem $SYSVOLPath -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum/1MB,1)
        } else { $null }
    }
    Write-Log "SYSVOL: $SYSVOLPath | Exists=$($SYSVOLInfo.Exists)"
}

$Evidence = [PSCustomObject]@{
    ChainOfCustody  = [PSCustomObject]@{ CaseNumber=$CaseNum; Hostname=$Hostname; CollectedAt=(Get-Date).ToString("o"); ToolVersion="1.0" }
    ArtifactType    = "NTDS_Location"
    DCRole          = $DCRole
    NTDSDatabase    = $NTDSInfo
    NTDSInVSS       = $NTDSInVSS
    SYSVOLLocation  = $SYSVOLInfo
    NtdsutilHistory = $NtdsutilHistory
    SecurityNote    = "NTDS.dit and SYSTEM hive locations documented for forensic reference only. Not extracted."
}

$Evidence | ConvertTo-Json -Depth 7 | Out-File $JsonFile -Encoding UTF8
$Hash = Get-FileHash $JsonFile -Algorithm SHA256
[PSCustomObject]@{ FileName=$JsonFile; Hash=$Hash.Hash; Generated=(Get-Date).ToString("o") } |
    ConvertTo-Json | Out-File "$JsonFile.hash.json" -Encoding UTF8

Write-Host "[+] NTDS location collected | IsDC: $IsDC | NTDS Found: $($NTDSInfo.Found) | VSS copies: $($NTDSInVSS.Count) | SYSVOL: $($SYSVOLInfo.Found)" -ForegroundColor Green
Write-Host "[+] JSON: $JsonFile" -ForegroundColor Green
Write-Log "Completed"
