<#
.SYNOPSIS
    Module: usb_device_history â€” USBSTOR/USB device enumeration + mounted-device mappings.
    Migrated from windows-dfir-toolkit USB_Device_History.ps1 (analysis/driver/WER logic removed).
    Read-only against HKLM. Raw observations only.
#>
param([Parameter(Mandatory)][string]$SessionRoot, $Config)

Write-HawkLog 'usb_device_history: collection started'

$records = New-Object System.Collections.Generic.List[object]

# Property GUID\index keys under a device hold install/arrival timestamps as
# little-endian FILETIME. Best-effort decode; unknown stays $null.
#   {83da6326-97a6-4088-9453-a1923f573b29}\0064 = first install date
#   {83da6326-97a6-4088-9453-a1923f573b29}\0066 = last arrival date
function Get-HawkDeviceProperty {
    param([string]$DeviceKeyPath, [string]$PropGuid, [string]$Index)
    try {
        $propPath = Join-Path $DeviceKeyPath ("Properties\{0}\{1}" -f $PropGuid, $Index)
        if (-not (Test-Path $propPath)) { return $null }
        $val = (Get-ItemProperty -LiteralPath $propPath -ErrorAction Stop)
        # The default '(Data)' value holds the raw bytes
        $raw = $val.'(default)'
        if (-not $raw) {
            foreach ($p in $val.PSObject.Properties) {
                if ($p.Value -is [byte[]] -and $p.Value.Length -eq 8) { $raw = $p.Value; break }
            }
        }
        if ($raw -is [byte[]] -and $raw.Length -eq 8) {
            $ft = [BitConverter]::ToInt64($raw, 0)
            if ($ft -gt 0) { return [DateTime]::FromFileTimeUtc($ft) }
        }
    } catch {}
    return $null
}

function Add-HawkEnumDevices {
    param([string]$RootKey, [string]$DeviceClass, [System.Collections.Generic.List[object]]$Out)
    try {
        if (-not (Test-Path $RootKey)) { return }
        foreach ($classKey in (Get-ChildItem -LiteralPath $RootKey -ErrorAction Stop)) {
            foreach ($instKey in (Get-ChildItem -LiteralPath $classKey.PSPath -ErrorAction SilentlyContinue)) {
                $props = $null
                try { $props = Get-ItemProperty -LiteralPath $instKey.PSPath -ErrorAction Stop } catch {}
                $devKeyPath = $instKey.PSPath

                $firstInstall = Get-HawkDeviceProperty -DeviceKeyPath $devKeyPath `
                    -PropGuid '{83da6326-97a6-4088-9453-a1923f573b29}' -Index '0064'
                $lastArrival  = Get-HawkDeviceProperty -DeviceKeyPath $devKeyPath `
                    -PropGuid '{83da6326-97a6-4088-9453-a1923f573b29}' -Index '0066'

                $Out.Add([ordered]@{
                    deviceClass     = $DeviceClass
                    deviceId        = "$($classKey.PSChildName)\$($instKey.PSChildName)"
                    instanceId      = $instKey.PSChildName
                    friendlyName    = if ($props) { $props.FriendlyName } else { $null }
                    deviceDesc      = if ($props) { $props.DeviceDesc } else { $null }
                    manufacturer    = if ($props) { $props.Mfg } else { $null }
                    hardwareId      = if ($props -and $props.HardwareID) { @($props.HardwareID) -join '; ' } else { $null }
                    firstInstallUtc = ConvertTo-HawkUtc $firstInstall
                    lastArrivalUtc  = ConvertTo-HawkUtc $lastArrival
                })
            }
        }
    } catch {
        Write-HawkLog "usb_device_history: failed reading $RootKey - $_" 'WARN'
    }
}

Add-HawkEnumDevices -RootKey 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR' -DeviceClass 'USBSTOR' -Out $records
Add-HawkEnumDevices -RootKey 'HKLM:\SYSTEM\CurrentControlSet\Enum\USB'     -DeviceClass 'USB'     -Out $records

# Mounted volume mappings â€” decode binary data to a readable identifier.
try {
    $mdKey = 'HKLM:\SYSTEM\MountedDevices'
    if (Test-Path $mdKey) {
        $md = Get-ItemProperty -LiteralPath $mdKey -ErrorAction Stop
        foreach ($p in $md.PSObject.Properties) {
            if ($p.Name -in 'PSPath','PSParentPath','PSChildName','PSDrive','PSProvider') { continue }
            $decoded = $null
            $bytes   = $p.Value
            if ($bytes -is [byte[]] -and $bytes.Length -gt 0) {
                try {
                    # Unicode device path (\??\USBSTOR#... ) when high bytes are zero,
                    # otherwise the 12-byte MBR disk signature + offset blob (ASCII-ish).
                    $unicode = ([Text.Encoding]::Unicode.GetString($bytes)) -replace '[^\x20-\x7E]', ''
                    $ascii   = ([Text.Encoding]::ASCII.GetString($bytes))   -replace '[^\x20-\x7E]', ''
                    if ($unicode.Length -ge $ascii.Length) { $decoded = $unicode } else { $decoded = $ascii }
                    if (-not $decoded) { $decoded = $null }
                } catch {}
            }
            $records.Add([ordered]@{
                deviceClass     = 'MountedDevice'
                deviceId        = $p.Name
                instanceId      = $null
                friendlyName    = $null
                deviceDesc      = $decoded
                manufacturer    = $null
                hardwareId      = $null
                firstInstallUtc = $null
                lastArrivalUtc  = $null
            })
        }
    }
} catch {
    Write-HawkLog "usb_device_history: failed reading MountedDevices - $_" 'WARN'
}

Export-HawkArtifact -SessionRoot $SessionRoot -ArtifactType 'usb_device_history' -Records $records
