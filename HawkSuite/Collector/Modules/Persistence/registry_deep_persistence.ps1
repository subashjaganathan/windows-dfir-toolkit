<#
.SYNOPSIS
    Module: registry_deep_persistence — deep registry persistence locations.
    RAW collection only. One record per value; recordType = location kind.
    Migrated from windows-dfir-toolkit Registry_Deep_Persistence.ps1 (analysis removed).
#>
param([Parameter(Mandatory)][string]$SessionRoot, $Config)

Write-HawkLog 'registry_deep_persistence: collection started'

$records = New-Object System.Collections.Generic.List[object]

function Add-RDPRecord {
    param(
        [string]$RecordType,
        [string]$KeyPath,
        [string]$ValueName,
        $ValueData
    )
    $dataStr = if ($null -ne $ValueData) {
        if ($ValueData -is [array]) { ($ValueData -join '; ') } else { "$ValueData" }
    } else { $null }

    # Path resolution is best-effort: many values (LSA package lists, flags)
    # are not file paths. Never let a non-path value abort the caller.
    $binaryPath = $null
    $identity = @{ sha256 = $null; md5 = $null; signatureStatus = 'Unknown'; signer = $null }
    try {
        if ($dataStr -and -not [string]::IsNullOrWhiteSpace($dataStr)) {
            $binaryPath = Resolve-HawkCommandPath $dataStr
            if ($binaryPath) { $identity = Get-HawkFileIdentity -Path $binaryPath }
        }
    } catch { $binaryPath = $null }

    $records.Add([ordered]@{
        recordType      = $RecordType
        keyPath         = $KeyPath
        valueName       = $ValueName
        valueData       = $dataStr          # raw, never truncated
        binaryPath      = $binaryPath
        sha256          = $identity.sha256
        md5             = $identity.md5
        signatureStatus = $identity.signatureStatus
        signer          = $identity.signer
    })
}

# Read a single value safely
function Get-RDPVal {
    param([string]$Path, [string]$Name)
    try {
        $item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
        return $item.$Name
    } catch { return $null }
}

# -- IFEO Debugger / GlobalFlag ------------------------------------------------
try {
    $ifeoRoot = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    if (Test-Path $ifeoRoot) {
        foreach ($sub in (Get-ChildItem $ifeoRoot -ErrorAction Stop)) {
            $props = $null
            try { $props = Get-ItemProperty -LiteralPath $sub.PSPath -ErrorAction Stop } catch { continue }
            foreach ($vn in 'Debugger','GlobalFlag') {
                $val = $props.PSObject.Properties[$vn]
                if ($val) { Add-RDPRecord -RecordType 'ifeo' -KeyPath $sub.PSPath -ValueName $vn -ValueData $val.Value }
            }
        }
    }
} catch { Write-HawkLog "registry_deep_persistence: IFEO walk failed - $_" 'WARN' }

# -- AppInit_DLLs + LoadAppInit_DLLs (Windows + WOW6432Node) -------------------
try {
    $winKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows'
    )
    foreach ($wk in $winKeys) {
        if (-not (Test-Path $wk)) { continue }
        foreach ($vn in 'AppInit_DLLs','LoadAppInit_DLLs') {
            $v = Get-RDPVal -Path $wk -Name $vn
            if ($null -ne $v -and "$v" -ne '') {
                Add-RDPRecord -RecordType 'appInit' -KeyPath $wk -ValueName $vn -ValueData $v
            }
        }
    }
} catch { Write-HawkLog "registry_deep_persistence: AppInit_DLLs walk failed - $_" 'WARN' }

# -- AppCertDLLs ---------------------------------------------------------------
try {
    $appCertKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls'
    if (Test-Path $appCertKey) {
        $props = Get-ItemProperty -LiteralPath $appCertKey -ErrorAction Stop
        foreach ($prop in $props.PSObject.Properties) {
            if ($prop.Name -in 'PSPath','PSParentPath','PSChildName','PSDrive','PSProvider') { continue }
            Add-RDPRecord -RecordType 'appCertDll' -KeyPath $appCertKey -ValueName $prop.Name -ValueData $prop.Value
        }
    }
} catch { Write-HawkLog "registry_deep_persistence: AppCertDLLs walk failed - $_" 'WARN' }

# -- Winlogon ------------------------------------------------------------------
try {
    $winlogonKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    if (Test-Path $winlogonKey) {
        foreach ($vn in 'Shell','Userinit','Taskman','GpExtensions') {
            $v = Get-RDPVal -Path $winlogonKey -Name $vn
            if ($null -ne $v -and "$v" -ne '') {
                Add-RDPRecord -RecordType 'winlogon' -KeyPath $winlogonKey -ValueName $vn -ValueData $v
            }
        }
    }
    # Notify subkeys (legacy GINA notification packages)
    $notifyKey = "$winlogonKey\Notify"
    if (Test-Path $notifyKey) {
        foreach ($sub in (Get-ChildItem $notifyKey -ErrorAction Stop)) {
            $props = $null
            try { $props = Get-ItemProperty -LiteralPath $sub.PSPath -ErrorAction Stop } catch { continue }
            $dll = $props.PSObject.Properties['DllName']
            if ($dll) { Add-RDPRecord -RecordType 'winlogonNotify' -KeyPath $sub.PSPath -ValueName 'DllName' -ValueData $dll.Value }
        }
    }
} catch { Write-HawkLog "registry_deep_persistence: Winlogon walk failed - $_" 'WARN' }

# -- LSA packages --------------------------------------------------------------
try {
    $lsaKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    if (Test-Path $lsaKey) {
        foreach ($vn in 'Security Packages','Authentication Packages','Notification Packages') {
            $v = Get-RDPVal -Path $lsaKey -Name $vn
            if ($null -ne $v) {
                Add-RDPRecord -RecordType 'lsaPackages' -KeyPath $lsaKey -ValueName $vn -ValueData $v
            }
        }
    }
} catch { Write-HawkLog "registry_deep_persistence: LSA packages walk failed - $_" 'WARN' }

# -- Print Monitors ------------------------------------------------------------
try {
    $printMonKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors'
    if (Test-Path $printMonKey) {
        foreach ($sub in (Get-ChildItem $printMonKey -ErrorAction Stop)) {
            $driver = Get-RDPVal -Path $sub.PSPath -Name 'Driver'
            if ($null -ne $driver -and "$driver" -ne '') {
                Add-RDPRecord -RecordType 'printMonitor' -KeyPath $sub.PSPath -ValueName 'Driver' -ValueData $driver
            }
        }
    }
} catch { Write-HawkLog "registry_deep_persistence: Print Monitors walk failed - $_" 'WARN' }

# -- Netsh helpers -------------------------------------------------------------
try {
    $netshKey = 'HKLM:\SOFTWARE\Microsoft\Netsh'
    if (Test-Path $netshKey) {
        $props = Get-ItemProperty -LiteralPath $netshKey -ErrorAction Stop
        foreach ($prop in $props.PSObject.Properties) {
            if ($prop.Name -in 'PSPath','PSParentPath','PSChildName','PSDrive','PSProvider') { continue }
            Add-RDPRecord -RecordType 'netshHelper' -KeyPath $netshKey -ValueName $prop.Name -ValueData $prop.Value
        }
    }
} catch { Write-HawkLog "registry_deep_persistence: Netsh helpers walk failed - $_" 'WARN' }

# -- COM InprocServer32 in HKCU (per-user CLSID overrides) ---------------------
try {
    $clsidRoot = 'HKCU:\Software\Classes\CLSID'
    if (Test-Path $clsidRoot) {
        foreach ($clsid in (Get-ChildItem $clsidRoot -ErrorAction Stop)) {
            $inproc = Join-Path $clsid.PSPath 'InprocServer32'
            if (Test-Path $inproc) {
                $default = Get-RDPVal -Path $inproc -Name '(default)'
                if ($null -ne $default -and "$default" -ne '') {
                    Add-RDPRecord -RecordType 'comInprocServer' -KeyPath $inproc -ValueName '(default)' -ValueData $default
                }
            }
        }
    }
} catch { Write-HawkLog "registry_deep_persistence: HKCU COM InprocServer32 walk failed - $_" 'WARN' }

Export-HawkArtifact -SessionRoot $SessionRoot -ArtifactType 'registry_deep_persistence' -Records $records
