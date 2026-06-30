<#
.SYNOPSIS
    Module: windows_hello - Windows Hello for Business / NGC enrollment state.
    Per-user NGC key-container counts and item metadata, PassportForWork policy,
    biometric service/devices, credential providers, and AAD/domain join status.
    Migrated from windows-dfir-toolkit WindowsHello\WindowsHello_ModernAuth.ps1.
    RAW collection only - NO key material or credential secrets are read.
#>
param([Parameter(Mandatory)][string]$SessionRoot, $Config)

Write-HawkLog 'windows_hello: collection started'

$records = New-Object System.Collections.Generic.List[object]

# (a) Per-user Windows Hello (NGC) enrollment - folder existence + item counts.
#     Only metadata of container items is recorded; key contents are never read.
try {
    foreach ($u in (Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue)) {
        $ngcPath = Join-Path $u.FullName 'AppData\Local\Microsoft\Ngc'
        $hasNgc = $false
        try { $hasNgc = Test-Path -LiteralPath $ngcPath -ErrorAction Stop } catch {}
        $items = @()
        if ($hasNgc) {
            try { $items = @(Get-ChildItem -LiteralPath $ngcPath -Recurse -Force -ErrorAction SilentlyContinue) } catch {}
        }
        $lastWrite = $null
        if ($hasNgc) { try { $lastWrite = (Get-Item -LiteralPath $ngcPath -ErrorAction SilentlyContinue).LastWriteTimeUtc } catch {} }
        $records.Add([ordered]@{
            recordType      = 'helloEnrollment'
            user            = $u.Name
            profilePath     = $u.FullName
            ngcFolderExists = $hasNgc
            ngcItemCount    = $items.Count
            lastWriteUtc    = ConvertTo-HawkUtc $lastWrite
        })
        foreach ($it in $items) {
            $records.Add([ordered]@{
                recordType   = 'ngcContainerItem'
                user         = $u.Name
                name         = $it.Name
                path         = $it.FullName
                sizeBytes    = if ($it.PSIsContainer) { $null } else { $it.Length }
                isDirectory  = [bool]$it.PSIsContainer
                lastWriteUtc = ConvertTo-HawkUtc $it.LastWriteTimeUtc
                creationUtc  = ConvertTo-HawkUtc $it.CreationTimeUtc
            })
        }
    }
} catch { Write-HawkLog "windows_hello: NGC enrollment enum failed - $_" 'WARN' }

# (b) PassportForWork / Hello policy (both policy hive locations).
$policyKeys = @(
    'SOFTWARE\Policies\Microsoft\PassportForWork',
    'SOFTWARE\Microsoft\Policies\PassportForWork',
    'SOFTWARE\Policies\Microsoft\Biometrics',
    'SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures'
)
foreach ($pk in $policyKeys) {
    try {
        $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($pk)
        if (-not $k) { continue }
        foreach ($vn in $k.GetValueNames()) {
            $records.Add([ordered]@{
                recordType = 'helloPolicy'
                key        = "HKLM\$pk"
                valueName  = $vn
                value      = "$($k.GetValue($vn))"
            })
        }
    } catch { Write-HawkLog "windows_hello: policy read failed ($pk) - $_" 'WARN' }
}

# (c) Biometric service + enrolled biometric devices.
try {
    $wbio = Get-Service WbioSrvc -ErrorAction Stop
    $records.Add([ordered]@{
        recordType    = 'biometricService'
        serviceStatus = "$($wbio.Status)"
        startType     = "$($wbio.StartType)"
    })
    foreach ($dev in (Get-PnpDevice -Class Biometric -ErrorAction SilentlyContinue)) {
        $records.Add([ordered]@{
            recordType   = 'biometricDevice'
            friendlyName = $dev.FriendlyName
            status       = "$($dev.Status)"
            deviceId     = $dev.DeviceID
            manufacturer = $dev.Manufacturer
        })
    }
} catch { Write-HawkLog "windows_hello: biometric service query failed - $_" 'WARN' }

# (d) Registered credential providers (a Hello/modern-auth tampering surface).
try {
    $cpBase = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
        'SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers')
    if ($cpBase) {
        foreach ($clsid in $cpBase.GetSubKeyNames()) {
            $ck = $cpBase.OpenSubKey($clsid)
            if (-not $ck) { continue }
            $records.Add([ordered]@{
                recordType = 'credentialProvider'
                clsid      = $clsid
                name       = "$($ck.GetValue(''))"
                disabled   = $ck.GetValue('Disabled')
            })
        }
    }
} catch { Write-HawkLog "windows_hello: credential provider walk failed - $_" 'WARN' }

# (e) AAD / domain join + Hello-for-Business status (dsregcmd, metadata only).
try {
    $dsreg = (& "$env:SystemRoot\System32\dsregcmd.exe" /status 2>$null) -join "`n"
    if ($dsreg) {
        function Get-DsregField([string]$label) {
            if ($dsreg -match "$label\s*:\s*(.+)") { return $Matches[1].Trim() }
            $null
        }
        $records.Add([ordered]@{
            recordType             = 'joinStatus'
            azureAdJoined          = ($dsreg -match 'AzureAdJoined\s*:\s*YES')
            domainJoined           = ($dsreg -match 'DomainJoined\s*:\s*YES')
            workplaceJoined        = ($dsreg -match 'WorkplaceJoined\s*:\s*YES')
            tenantId               = (Get-DsregField 'TenantId')
            tenantName             = (Get-DsregField 'TenantName')
            deviceId               = (Get-DsregField 'DeviceId')
            ngcPrerequisiteCheck   = (Get-DsregField 'NgcPrerequisiteCheck')
        })
    }
} catch { Write-HawkLog "windows_hello: dsregcmd query failed - $_" 'WARN' }

if ($records.Count -eq 0) { Write-HawkLog 'windows_hello: no Windows Hello artifacts present' }

Export-HawkArtifact -SessionRoot $SessionRoot -ArtifactType 'windows_hello' -Records $records
