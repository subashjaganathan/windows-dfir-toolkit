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
$LogFile  = "$BasePath\SQL_Server_Execution.log"
$JsonFile = "$BasePath\SQL_Server_${Hostname}_${Timestamp}.json"

function Write-Log { param([string]$M,[string]$L="INFO") Add-Content $LogFile "$(Get-Date -Format o) [$L] :: $M" }
Write-Log "SQL Server artifact collection started | Case: $CaseNum"

$DaysBack  = if ($env:DFIR_DAYS) { [int]$env:DFIR_DAYS } else { 30 }
$SinceDate = (Get-Date).AddDays(-$DaysBack)

# Detect SQL Server instances
Write-Host "[*] Detecting SQL Server instances..." -ForegroundColor Cyan
$SQLInstances = [System.Collections.Generic.List[PSCustomObject]]::new()

# From registry
$SQLRegPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Microsoft SQL Server"
)
foreach ($SQLReg in $SQLRegPaths) {
    if (-not (Test-Path $SQLReg)) { continue }
    $InstalledInstances = Get-ItemProperty "$SQLReg\Instance Names\SQL" -ErrorAction SilentlyContinue
    if ($InstalledInstances) {
        $InstalledInstances.PSObject.Properties |
            Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object {
                $InstName  = $_.Name
                $InstKey   = $_.Value
                $InstProps = Get-ItemProperty "$SQLReg\$InstKey\MSSQLServer" -ErrorAction SilentlyContinue
                $SetupProps= Get-ItemProperty "$SQLReg\$InstKey\Setup" -ErrorAction SilentlyContinue
                $SQLInstances.Add([PSCustomObject]@{
                    InstanceName   = $InstName
                    RegistryKey    = $InstKey
                    Version        = if ($SetupProps) { $SetupProps.Version } else { $null }
                    Edition        = if ($SetupProps) { $SetupProps.Edition } else { $null }
                    SQLDataRoot    = if ($SetupProps) { $SetupProps.SQLDataRoot } else { $null }
                    SQLBinRoot     = if ($SetupProps) { $SetupProps.SQLBinRoot } else { $null }
                    ErrorLogPath   = if ($InstProps) { $InstProps.DefaultLog } else { $null }
                })
            }
    }
}

# From services
$SQLServices = @(Get-Service -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -match "SQL Server" -or $_.ServiceName -match "MSSQL" })
foreach ($Svc in $SQLServices) {
    $AlreadyFound = $SQLInstances | Where-Object { $_.InstanceName -eq $Svc.ServiceName.Replace("MSSQL$","") }
    if (-not $AlreadyFound) {
        $SQLInstances.Add([PSCustomObject]@{
            InstanceName = $Svc.ServiceName.Replace("MSSQL$","")
            ServiceName  = $Svc.ServiceName
            Status       = $Svc.Status.ToString()
            StartType    = $Svc.StartType.ToString()
        })
    }
}
Write-Log "SQL instances found: $($SQLInstances.Count)"

if ($SQLInstances.Count -eq 0) {
    Write-Host "[!] No SQL Server instances detected on this machine" -ForegroundColor Yellow
    Write-Log "No SQL Server instances found"
}

# SQL Server error logs - check for suspicious activity
Write-Host "[*] Scanning SQL Server error logs..." -ForegroundColor Cyan
$SQLLogEntries = [System.Collections.Generic.List[PSCustomObject]]::new()
$SQLLogPaths = [System.Collections.Generic.List[string]]::new()

foreach ($Inst in $SQLInstances) {
    if ($Inst.ErrorLogPath -and (Test-Path $Inst.ErrorLogPath)) {
        $SQLLogPaths.Add($Inst.ErrorLogPath)
    }
    if ($Inst.SQLDataRoot) {
        $LogPath = "$($Inst.SQLDataRoot)\Log"
        if (Test-Path $LogPath) { $SQLLogPaths.Add($LogPath) }
    }
}

# Default paths
@("C:\Program Files\Microsoft SQL Server",
  "C:\Program Files (x86)\Microsoft SQL Server") | ForEach-Object {
    if (Test-Path $_) {
        Get-ChildItem $_ -Recurse -Filter "ERRORLOG" -ErrorAction SilentlyContinue | ForEach-Object {
            $SQLLogPaths.Add($_.FullName)
        }
    }
}

$SuspiciousKeywords = @("xp_cmdshell","EXEC master","OPENROWSET","OPENDATASOURCE",
    "sp_oacreate","sp_oamethod","sp_configure","bulk insert","EXEC.*xp_","Ole Automation")

foreach ($LogPath in ($SQLLogPaths | Sort-Object -Unique)) {
    if (-not (Test-Path $LogPath)) { continue }
    $LogFiles = if ((Get-Item $LogPath).PSIsContainer) {
        @(Get-ChildItem $LogPath -Filter "ERRORLOG*" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 3)
    } else {
        @(Get-Item $LogPath -ErrorAction SilentlyContinue)
    }
    foreach ($LF in $LogFiles) {
        $Lines = @(Get-Content $LF.FullName -ErrorAction SilentlyContinue | Select-Object -Last 2000)
        foreach ($Line in $Lines) {
            foreach ($KW in $SuspiciousKeywords) {
                if ($Line -match $KW) {
                    $SQLLogEntries.Add([PSCustomObject]@{
                        LogFile      = $LF.Name
                        MatchedKeyword = $KW
                        LogEntry     = $Line.Trim()
                    })
                    break
                }
            }
        }
    }
}
Write-Log "Suspicious SQL log entries: $($SQLLogEntries.Count)"

# Windows Event Log - SQL Server events
Write-Host "[*] Collecting SQL Server event log entries..." -ForegroundColor Cyan
$SQLEventLog = [System.Collections.Generic.List[PSCustomObject]]::new()
try {
    $SQLFilter = @{
        LogName   = "Application"
        ProviderName = "MSSQLSERVER","MSSQL`$*"
        StartTime = $SinceDate
    }
    $SQLEvents = @(Get-WinEvent -FilterHashtable $SQLFilter -ErrorAction SilentlyContinue | Select-Object -First 200)
    foreach ($E in $SQLEvents) {
        $IsSusp = ($E.Message -match "xp_cmdshell|sp_configure|EXEC master|bulk insert|OLE Automation|login failed.*sa\b")
        $SQLEventLog.Add([PSCustomObject]@{
            TimeCreated  = $E.TimeCreated.ToString("o")
            EventID      = $E.Id
            Level        = $E.LevelDisplayName
            Message      = ($E.Message -split [System.Environment]::NewLine -join " ").Substring(0,[Math]::Min(250,$E.Message.Length))
            IsSuspicious = $IsSusp
        })
    }
    Write-Log "SQL event log entries: $($SQLEventLog.Count)"
} catch { Write-Log "SQL event log query failed: $_" "WARN" }

# xp_cmdshell state from registry
Write-Host "[*] Checking xp_cmdshell configuration..." -ForegroundColor Cyan
$XPCmdShell = [PSCustomObject]@{ State = "Unknown"; Note = "Check via SQL query: SELECT value FROM sys.configurations WHERE name = 'xp_cmdshell'" }
$XPRegPath  = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\*\MSSQLServer\Parameters"
try {
    $XPKey = Get-ItemProperty $XPRegPath -ErrorAction SilentlyContinue
    if ($XPKey) {
        $XPCmdShell = [PSCustomObject]@{
            State          = "Registry found"
            Parameters     = $XPKey
            SecurityNote   = "xp_cmdshell allows OS command execution from SQL - critical if enabled"
        }
    }
} catch {}

# SQL Server linked servers (lateral movement vector)
Write-Host "[*] Checking SQL Server configuration files for linked servers..." -ForegroundColor Cyan
$LinkedServerInfo = [PSCustomObject]@{
    Note = "Linked servers require SQL query: SELECT * FROM sys.servers WHERE is_linked = 1"
    ConfigFilesFound = @(Get-ChildItem "C:\Program Files\Microsoft SQL Server" -Recurse -Filter "*.ini" -ErrorAction SilentlyContinue | Select-Object -First 10 | Select-Object Name,FullPath)
}

# SQL firewall rules (port 1433/1434)
Write-Host "[*] Checking SQL Server firewall exposure..." -ForegroundColor Cyan
$SQLFirewall = @(Get-NetFirewallRule -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -match "SQL" -and $_.Enabled -eq $true } |
    ForEach-Object {
        $Ports = ($_ | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue)
        [PSCustomObject]@{
            RuleName  = $_.DisplayName
            Direction = $_.Direction.ToString()
            Action    = $_.Action.ToString()
            Protocol  = $Ports.Protocol
            LocalPort = $Ports.LocalPort
        }
    })

# SQL Server service accounts
$SQLServiceAccounts = @($SQLServices | ForEach-Object {
    $SvcObj = Get-CimInstance Win32_Service -Filter "Name='$($_.ServiceName)'" -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        ServiceName  = $_.ServiceName
        DisplayName  = $_.DisplayName
        Status       = $_.Status.ToString()
        StartAccount = if ($SvcObj) { $SvcObj.StartName } else { "Unknown" }
    }
})

$SuspCount = ($SQLLogEntries.Count) + (@($SQLEventLog | Where-Object { $_.IsSuspicious }).Count)
Write-Log "SQL instances: $($SQLInstances.Count) | Suspicious entries: $SuspCount | Firewall rules: $($SQLFirewall.Count)"

$Evidence = [PSCustomObject]@{
    ChainOfCustody      = [PSCustomObject]@{ CaseNumber=$CaseNum; Hostname=$Hostname; CollectedAt=([DateTime]::UtcNow).ToString("o"); ToolVersion=$Global:DFIR_ToolVersion }
    ArtifactType        = "SQL_Server_Artifacts"
    SQLInstanceCount    = $SQLInstances.Count
    SuspiciousEntryCount= $SuspCount
    SQLInstances        = $SQLInstances
    SQLServiceAccounts  = $SQLServiceAccounts
    SuspiciousLogEntries= $SQLLogEntries
    SQLEventLog         = $SQLEventLog
    XPCmdShellConfig    = $XPCmdShell
    LinkedServerInfo    = $LinkedServerInfo
    SQLFirewallRules    = $SQLFirewall
    Note                = "For full SQL forensics connect to instance: sqlcmd -S localhost -Q 'SELECT * FROM sys.fn_get_audit_file(...)'"
}

$Evidence | ConvertTo-Json -Depth 6 | Out-File $JsonFile -Encoding UTF8
$Hash = Get-FileHash $JsonFile -Algorithm SHA256
[PSCustomObject]@{ FileName=$JsonFile; Hash=$Hash.Hash; Generated=([DateTime]::UtcNow).ToString("o") } |
    ConvertTo-Json | Out-File "$JsonFile.hash.json" -Encoding UTF8

Write-Host "[+] SQL Server artifacts collected | Instances: $($SQLInstances.Count) | Suspicious: $SuspCount | Firewall: $($SQLFirewall.Count)" -ForegroundColor Green
Write-Host "[+] JSON: $JsonFile" -ForegroundColor Green
Write-Log "Completed"
