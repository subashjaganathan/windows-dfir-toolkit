<#
.SYNOPSIS
    Module: sql_server_artifacts - Microsoft SQL Server instances, service
    accounts, ERRORLOG references plus a capped recent tail, and SQL-related
    firewall rules. Migrated from windows-dfir-toolkit
    Application\SQL_Server_Artifacts.ps1. RAW collection only (no xp_cmdshell
    verdicts, no suspicious-keyword tagging - the analyzer scores).
#>
param([Parameter(Mandatory)][string]$SessionRoot, $Config)

Write-HawkLog 'sql_server_artifacts: collection started'

$records   = New-Object System.Collections.Generic.List[object]
$TailLines = 1000   # recent lines per ERRORLOG (full files remain on disk)
$errorLogPaths = New-Object System.Collections.Generic.List[string]

function Get-HawkRegProp([string]$path, [string]$name) {
    try {
        $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($path)
        if ($k) { return $k.GetValue($name) }
    } catch {}
    $null
}

function Get-LogTail([string]$path, [int]$n) {
    try {
        $all = [System.IO.File]::ReadAllLines($path)
        if ($all.Count -le $n) { return ,$all }
        return ,($all[($all.Count - $n)..($all.Count - 1)])
    } catch { return ,@() }
}

# (a) Installed instances from registry (native + WOW6432Node)
$sqlRoots = @(
    'SOFTWARE\Microsoft\Microsoft SQL Server',
    'SOFTWARE\WOW6432Node\Microsoft\Microsoft SQL Server'
)
foreach ($root in $sqlRoots) {
    try {
        $instNamesKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("$root\Instance Names\SQL")
        if (-not $instNamesKey) { continue }
        foreach ($instName in $instNamesKey.GetValueNames()) {
            $instKey = "$($instNamesKey.GetValue($instName))"
            if (-not $instKey) { continue }
            $errLog = Get-HawkRegProp "$root\$instKey\MSSQLServer" 'DefaultLog'
            $dataRoot = Get-HawkRegProp "$root\$instKey\Setup" 'SQLDataRoot'
            $records.Add([ordered]@{
                recordType   = 'sqlInstance'
                instanceName = $instName
                registryKey  = $instKey
                hive         = if ($root -match 'WOW6432Node') { 'WOW6432Node' } else { 'native' }
                version      = "$(Get-HawkRegProp "$root\$instKey\Setup" 'Version')"
                edition      = "$(Get-HawkRegProp "$root\$instKey\Setup" 'Edition')"
                sqlDataRoot  = "$dataRoot"
                sqlBinRoot   = "$(Get-HawkRegProp "$root\$instKey\Setup" 'SQLBinRoot')"
                errorLogPath = "$errLog"
            })
            if ($errLog) { $errorLogPaths.Add("$errLog") }
            if ($dataRoot) { $errorLogPaths.Add((Join-Path "$dataRoot" 'Log')) }
        }
    } catch { Write-HawkLog "sql_server_artifacts: registry instance walk failed ($root) - $_" 'WARN' }
}

# (b) SQL Server services + their start accounts (lateral/privesc context)
try {
    $svcList = @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -match 'SQL Server' -or $_.Name -match 'MSSQL' })
    foreach ($svc in $svcList) {
        $records.Add([ordered]@{
            recordType   = 'sqlService'
            serviceName  = $svc.Name
            displayName  = $svc.DisplayName
            state        = "$($svc.State)"
            startMode    = "$($svc.StartMode)"
            startName    = $svc.StartName
            pathName     = $svc.PathName
        })
    }
} catch { Write-HawkLog "sql_server_artifacts: service enumeration failed - $_" 'WARN' }

# Default install locations - find any ERRORLOG files not already mapped
foreach ($base in @('C:\Program Files\Microsoft SQL Server', 'C:\Program Files (x86)\Microsoft SQL Server')) {
    try {
        if (-not (Test-Path -LiteralPath $base -ErrorAction SilentlyContinue)) { continue }
        foreach ($f in (Get-ChildItem -LiteralPath $base -Recurse -Filter 'ERRORLOG' -ErrorAction SilentlyContinue)) {
            $errorLogPaths.Add($f.FullName)
        }
    } catch { Write-HawkLog "sql_server_artifacts: default-path ERRORLOG scan failed ($base) - $_" 'WARN' }
}

# (c) ERRORLOG files: metadata + bounded recent tail (raw, verbatim - no filtering)
$seenLogs = @{}
foreach ($lp in ($errorLogPaths | Sort-Object -Unique)) {
    try {
        if (-not (Test-Path -LiteralPath $lp -ErrorAction SilentlyContinue)) { continue }
        $item = Get-Item -LiteralPath $lp -ErrorAction SilentlyContinue
        $logFiles = if ($item -and $item.PSIsContainer) {
            @(Get-ChildItem -LiteralPath $lp -Filter 'ERRORLOG*' -File -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending | Select-Object -First 3)
        } else {
            @($item)
        }
        foreach ($lf in $logFiles) {
            if (-not $lf -or $seenLogs.ContainsKey($lf.FullName)) { continue }
            $seenLogs[$lf.FullName] = $true
            $records.Add([ordered]@{
                recordType      = 'sqlErrorLog'
                path            = $lf.FullName
                sizeBytes       = $lf.Length
                lastModifiedUtc = ConvertTo-HawkUtc $lf.LastWriteTimeUtc
                sha256          = (Get-HawkFileIdentity -Path $lf.FullName).sha256
                recentLines     = Get-LogTail $lf.FullName $TailLines
            })
        }
    } catch { Write-HawkLog "sql_server_artifacts: ERRORLOG read failed ($lp) - $_" 'WARN' }
}

# (d) SQL-related firewall rules (network exposure context)
try {
    $fwRules = @(Get-NetFirewallRule -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -match 'SQL' -and $_.Enabled -eq $true })
    foreach ($r in $fwRules) {
        $ports = $null
        try { $ports = $r | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue } catch {}
        $records.Add([ordered]@{
            recordType = 'sqlFirewallRule'
            ruleName   = $r.DisplayName
            direction  = "$($r.Direction)"
            action     = "$($r.Action)"
            protocol   = if ($ports) { "$($ports.Protocol)" } else { $null }
            localPort  = if ($ports) { "$($ports.LocalPort)" } else { $null }
        })
    }
} catch { Write-HawkLog "sql_server_artifacts: firewall rule query failed - $_" 'WARN' }

if ($records.Count -eq 0) { Write-HawkLog 'sql_server_artifacts: no SQL Server instances or artifacts present' }

Export-HawkArtifact -SessionRoot $SessionRoot -ArtifactType 'sql_server_artifacts' -Records $records
