<#
.SYNOPSIS
    Module: office_artifacts - Outlook data files, Office MRU, trusted locations,
    add-ins. RAW collection only (metadata; no message/document contents).
#>
param([Parameter(Mandatory)][string]$SessionRoot, $Config)

Write-HawkLog 'office_artifacts: collection started'

$records = New-Object System.Collections.Generic.List[object]

# (a) Outlook data files (.ost/.pst) - metadata only
try {
    foreach ($u in (Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue)) {
        $roots = @(
            (Join-Path $u.FullName 'AppData\Local\Microsoft\Outlook'),
            (Join-Path $u.FullName 'Documents\Outlook Files')
        )
        foreach ($r in $roots) {
            $exists = $false
            try { $exists = Test-Path -LiteralPath $r -ErrorAction Stop } catch { continue }
            if (-not $exists) { continue }
            try {
                foreach ($f in (Get-ChildItem -LiteralPath $r -File -Include '*.ost','*.pst' -Recurse -ErrorAction SilentlyContinue)) {
                    $records.Add([ordered]@{
                        recordType      = 'outlookDataFile'
                        user            = $u.Name
                        path            = $f.FullName
                        sizeBytes       = $f.Length
                        lastModifiedUtc = ConvertTo-HawkUtc $f.LastWriteTimeUtc
                    })
                }
            } catch {}
        }
    }
} catch { Write-HawkLog "office_artifacts: outlook data file enum failed - $_" 'WARN' }

# Helper: walk HKCU Office subkeys for a given trailing path under each app/version
function Walk-OfficeKey([string]$leaf, [string]$recordType, [scriptblock]$emit) {
    try {
        $office = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\Microsoft\Office')
        if (-not $office) { return }
        foreach ($ver in $office.GetSubKeyNames()) {
            $verKey = $office.OpenSubKey($ver)
            if (-not $verKey) { continue }
            foreach ($app in $verKey.GetSubKeyNames()) {
                $target = $office.OpenSubKey("$ver\$app\$leaf")
                if ($target) { & $emit $ver $app $target }
            }
        }
    } catch { Write-HawkLog "office_artifacts: $recordType walk failed - $_" 'WARN' }
}

# (b) File/Place MRU
Walk-OfficeKey 'File MRU' 'officeMru' {
    param($ver, $app, $key)
    foreach ($vn in $key.GetValueNames()) {
        if ($vn -eq 'Max Display') { continue }
        $records.Add([ordered]@{ recordType = 'officeMru'; office = $ver; app = $app; mruType = 'File'; valueName = $vn; item = "$($key.GetValue($vn))" })
    }
}
Walk-OfficeKey 'Place MRU' 'officeMru' {
    param($ver, $app, $key)
    foreach ($vn in $key.GetValueNames()) {
        if ($vn -eq 'Max Display') { continue }
        $records.Add([ordered]@{ recordType = 'officeMru'; office = $ver; app = $app; mruType = 'Place'; valueName = $vn; item = "$($key.GetValue($vn))" })
    }
}

# (c) Trusted Locations
Walk-OfficeKey 'Security\Trusted Locations' 'trustedLocation' {
    param($ver, $app, $key)
    foreach ($sub in $key.GetSubKeyNames()) {
        $loc = $key.OpenSubKey($sub)
        if ($loc) {
            $records.Add([ordered]@{ recordType = 'trustedLocation'; office = $ver; app = $app
                path = "$($loc.GetValue('Path'))"; description = "$($loc.GetValue('Description'))" })
        }
    }
}

# (d) Add-ins (HKCU and HKLM)
function Walk-Addins($root, $hiveName) {
    try {
        $office = $root.OpenSubKey('Software\Microsoft\Office')
        if (-not $office) { return }
        foreach ($app in $office.GetSubKeyNames()) {
            $addins = $office.OpenSubKey("$app\Addins")
            if (-not $addins) { continue }
            foreach ($a in $addins.GetSubKeyNames()) {
                $ak = $addins.OpenSubKey($a)
                if ($ak) {
                    $records.Add([ordered]@{ recordType = 'officeAddin'; hive = $hiveName; app = $app; addin = $a
                        friendlyName = "$($ak.GetValue('FriendlyName'))"; loadBehavior = $ak.GetValue('LoadBehavior') })
                }
            }
        }
    } catch { Write-HawkLog "office_artifacts: addins ($hiveName) walk failed - $_" 'WARN' }
}
Walk-Addins ([Microsoft.Win32.Registry]::CurrentUser) 'HKCU'
Walk-Addins ([Microsoft.Win32.Registry]::LocalMachine) 'HKLM'

Export-HawkArtifact -SessionRoot $SessionRoot -ArtifactType 'office_artifacts' -Records $records
