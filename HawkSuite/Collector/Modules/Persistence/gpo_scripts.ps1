<#
.SYNOPSIS
    Module: gpo_scripts - Group Policy startup/shutdown/logon/logoff scripts and
    applied-GPO history. Logon scripts are a common persistence/lateral vector.
    RAW collection only.
#>
param([Parameter(Mandatory)][string]$SessionRoot, $Config)

Write-HawkLog 'gpo_scripts: collection started'

$records = New-Object System.Collections.Generic.List[object]

# (a) GPO script files on disk
$scriptDirs = @(
    @{ scope = 'Machine\Startup';  path = (Join-Path $env:SystemRoot 'System32\GroupPolicy\Machine\Scripts\Startup') },
    @{ scope = 'Machine\Shutdown'; path = (Join-Path $env:SystemRoot 'System32\GroupPolicy\Machine\Scripts\Shutdown') },
    @{ scope = 'User\Logon';       path = (Join-Path $env:SystemRoot 'System32\GroupPolicy\User\Scripts\Logon') },
    @{ scope = 'User\Logoff';      path = (Join-Path $env:SystemRoot 'System32\GroupPolicy\User\Scripts\Logoff') }
)
foreach ($sd in $scriptDirs) {
    try {
        if (-not (Test-Path -LiteralPath $sd.path -ErrorAction SilentlyContinue)) { continue }
        foreach ($f in (Get-ChildItem -LiteralPath $sd.path -File -Recurse -ErrorAction SilentlyContinue)) {
            $id = Get-HawkFileIdentity -Path $f.FullName
            $records.Add([ordered]@{
                recordType      = 'gpoScript'
                scope           = $sd.scope
                path            = $f.FullName
                sizeBytes       = $f.Length
                lastModifiedUtc = ConvertTo-HawkUtc $f.LastWriteTimeUtc
                sha256          = $id.sha256
                md5             = $id.md5
                signatureStatus = $id.signatureStatus
                signer          = $id.signer
            })
        }
    } catch { Write-HawkLog "gpo_scripts: $($sd.scope) enum failed - $_" 'WARN' }
}

# (b) registry-registered Startup/Shutdown scripts
foreach ($kind in 'Startup','Shutdown') {
    try {
        $base = "SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\$kind"
        $bk = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($base)
        if (-not $bk) { continue }
        foreach ($gpo in $bk.GetSubKeyNames()) {
            $gk = $bk.OpenSubKey($gpo)
            foreach ($idx in $gk.GetSubKeyNames()) {
                $sk = $gk.OpenSubKey($idx)
                $cmd = "$($sk.GetValue('Script'))"
                if (-not $cmd) { continue }
                $records.Add([ordered]@{
                    recordType = 'gpoRegisteredScript'
                    scope      = $kind
                    command    = $cmd
                    parameters = "$($sk.GetValue('Parameters'))"
                })
            }
        }
    } catch { Write-HawkLog "gpo_scripts: registry $kind walk failed - $_" 'WARN' }
}

# (c) applied-GPO history (machine)
try {
    $hist = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History')
    if ($hist) {
        foreach ($g in $hist.GetSubKeyNames()) {
            $gk = $hist.OpenSubKey($g)
            $dn = $gk.GetValue('DisplayName')
            if ($dn) { $records.Add([ordered]@{ recordType = 'gpoHistory'; guid = $g; displayName = "$dn"; extensionName = "$($gk.GetValue('GPOName'))" }) }
        }
    }
} catch { Write-HawkLog "gpo_scripts: history walk failed - $_" 'WARN' }

Export-HawkArtifact -SessionRoot $SessionRoot -ArtifactType 'gpo_scripts' -Records $records
