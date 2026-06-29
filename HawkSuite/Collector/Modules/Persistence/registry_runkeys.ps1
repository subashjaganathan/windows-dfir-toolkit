<#
.SYNOPSIS
    Module: registry_runkeys â€” autorun registry persistence locations, all users.
    Migrated from windows-dfir-toolkit Registry_RunKeys.ps1 (analysis logic removed).
    HKU enumeration covers every LOADED user hive, not just the collector's user.
#>
param([Parameter(Mandatory)][string]$SessionRoot, $Config)

Write-HawkLog 'registry_runkeys: collection started'

if (-not (Get-PSDrive HKU -ErrorAction SilentlyContinue)) {
    New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
}

$machineKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'    # AppInit_DLLs
)
$userSubKeys = @(
    'SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
)
# Winlogon/Windows keys: only these values are autorun-relevant
$valueFilter = @{
    'Winlogon' = @('Userinit', 'Shell', 'Taskman', 'AppSetup')
    'Windows'  = @('AppInit_DLLs', 'LoadAppInit_DLLs', 'Load', 'Run')
}

$records = New-Object System.Collections.Generic.List[object]

function Add-RunKeyRecords {
    param([string]$KeyPath, [string]$UserSid, [System.Collections.Generic.List[object]]$Out)
    if (-not (Test-Path $KeyPath)) { return }
    $leaf = Split-Path $KeyPath -Leaf
    $props = $null
    try { $props = Get-ItemProperty $KeyPath -ErrorAction Stop } catch { return }
    foreach ($prop in $props.PSObject.Properties) {
        if ($prop.Name -in 'PSPath','PSParentPath','PSChildName','PSDrive','PSProvider') { continue }
        if ($valueFilter.ContainsKey($leaf) -and $prop.Name -notin $valueFilter[$leaf]) { continue }
        $command = "$($prop.Value)"
        if (-not $command) { continue }
        $exePath = Resolve-HawkCommandPath $command
        $identity = if ($exePath) { Get-HawkFileIdentity -Path $exePath }
                    else { @{ sha256 = $null; md5 = $null; signatureStatus = 'Unknown'; signer = $null } }
        $Out.Add([ordered]@{
            keyPath         = ($KeyPath -replace '^HKU:\\[^\\]+', 'HKU:\<sid>')
            userSid         = $UserSid
            valueName       = $prop.Name
            command         = $command            # raw, never truncated
            binaryPath      = $exePath
            sha256          = $identity.sha256
            md5             = $identity.md5
            signatureStatus = $identity.signatureStatus
            signer          = $identity.signer
        })
    }
}

foreach ($k in $machineKeys) { Add-RunKeyRecords -KeyPath $k -UserSid $null -Out $records }

foreach ($hive in (Get-ChildItem HKU:\ -ErrorAction SilentlyContinue)) {
    $sid = $hive.PSChildName
    if ($sid -match '_Classes$' -or $sid -eq '.DEFAULT') { continue }
    foreach ($sub in $userSubKeys) {
        Add-RunKeyRecords -KeyPath "HKU:\$sid\$sub" -UserSid $sid -Out $records
    }
}

Export-HawkArtifact -SessionRoot $SessionRoot -ArtifactType 'registry_runkeys' -Records $records
