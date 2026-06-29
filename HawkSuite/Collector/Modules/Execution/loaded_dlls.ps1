<#
.SYNOPSIS
    Module: loaded_dlls - DLLs/modules loaded in running processes.
    Raw collection only (no injection/hijack analysis). Migrated from
    windows-dfir-toolkit Memory\Loaded_DLLs.ps1 (analysis logic removed).
#>
param([Parameter(Mandatory)][string]$SessionRoot, $Config)

Write-HawkLog 'loaded_dlls: collection started'

# CIM gives an authoritative pid->name map (covers processes Get-Process may miss)
$cimProcs  = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
$nameByPid = @{}
foreach ($p in $cimProcs) { $nameByPid[[int]$p.ProcessId] = $p.Name }

$seen         = @{}   # dedupe key: "<pid>|<modulePath>"
$inaccessible = 0
$records      = [System.Collections.Generic.List[object]]::new()

foreach ($proc in (Get-Process -ErrorAction SilentlyContinue)) {
    $procId   = [int]$proc.Id
    $procName = if ($nameByPid.ContainsKey($procId)) { $nameByPid[$procId] } else { $proc.ProcessName }

    # Module enumeration is frequently access-denied without elevation (and
    # always for protected processes). Expected - skip and count.
    $modules = $null
    try { $modules = $proc.Modules } catch { $inaccessible++; continue }
    if ($null -eq $modules) { continue }

    foreach ($module in $modules) {
        $modulePath = $module.FileName
        if (-not $modulePath) { continue }

        $key = '{0}|{1}' -f $procId, $modulePath
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true

        $identity = Get-HawkFileIdentity -Path $modulePath

        $fileVersion = $null
        try { if ($module.FileVersionInfo) { $fileVersion = $module.FileVersionInfo.FileVersion } } catch {}

        $records.Add([ordered]@{
            pid             = $procId
            processName     = $procName
            moduleName      = $module.ModuleName
            modulePath      = $modulePath          # never truncated (contract section 7)
            fileVersion     = $fileVersion
            sha256          = $identity.sha256
            md5             = $identity.md5
            signatureStatus = $identity.signatureStatus
            signer          = $identity.signer
        })
    }
}

if ($inaccessible -gt 0) {
    Write-HawkLog "loaded_dlls: $inaccessible process(es) had inaccessible module lists (access denied / protected); skipped" 'WARN'
}

Export-HawkArtifact -SessionRoot $SessionRoot -ArtifactType 'loaded_dlls' -Records $records
