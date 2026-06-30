<#
.SYNOPSIS
    Module: drivers - loaded/registered kernel-mode drivers with on-disk binary
    identity (hash + signature). The unsigned / invalid-signature drivers in a
    user-writable or unusual path are the BYOVD (bring-your-own-vulnerable-driver)
    surface. RAW collection only - the analyzer scores signature/path.
#>
param([Parameter(Mandatory)][string]$SessionRoot, $Config)

Write-HawkLog 'drivers: collection started'

$records = New-Object System.Collections.Generic.List[object]

# Normalize the kernel-style ImagePath (\SystemRoot\, \??\, system32\...) to a
# real filesystem path so Get-HawkFileIdentity can hash + check its signature.
function Resolve-DriverPath([string]$p, [string]$name) {
    if ([string]::IsNullOrWhiteSpace($p)) {
        $guess = Join-Path $env:SystemRoot "System32\drivers\$name.sys"
        if (Test-Path -LiteralPath $guess -ErrorAction SilentlyContinue) { return $guess }
        return $null
    }
    $x = $p.Trim('"')
    $x = $x -replace '^\\\?\?\\', ''                    # \??\C:\... -> C:\...
    $x = $x -replace '^\\SystemRoot\\', "$env:SystemRoot\"
    $x = $x -replace '^System32\\', "$env:SystemRoot\System32\"
    $x = $x -replace '^\\Windows\\', "$env:SystemDrive\Windows\"
    $x = [Environment]::ExpandEnvironmentVariables($x)
    if ($x -notmatch '^[a-zA-Z]:\\' -and $x -match 'system32') {
        $x = Join-Path $env:SystemDrive ($x.TrimStart('\'))
    }
    $x
}

try {
    foreach ($d in (Get-CimInstance Win32_SystemDriver -ErrorAction Stop)) {
        $path = Resolve-DriverPath $d.PathName $d.Name
        $id = if ($path) { Get-HawkFileIdentity -Path $path } else { @{ sha256=$null; md5=$null; signatureStatus='Unknown'; signer=$null } }
        $records.Add([ordered]@{
            recordType      = 'kernelDriver'
            name            = $d.Name
            displayName     = $d.DisplayName
            description     = $d.Description
            state           = "$($d.State)"        # Running / Stopped
            startMode       = "$($d.StartMode)"    # Boot / System / Auto / Manual / Disabled
            serviceType     = "$($d.ServiceType)"
            imagePathRaw    = $d.PathName
            resolvedPath    = $path
            sha256          = $id.sha256
            md5             = $id.md5
            signatureStatus = $id.signatureStatus
            signer          = $id.signer
        })
    }
} catch { Write-HawkLog "drivers: Win32_SystemDriver query failed - $_" 'WARN' }

# Minifilter drivers (fltmc) - file-system filters; rootkits/EDR-killers register
# here. Needs elevation; parse the plain-text table, graceful if unavailable.
try {
    $flt = & "$env:SystemRoot\System32\fltmc.exe" filters 2>$null
    if ($LASTEXITCODE -eq 0 -and $flt) {
        foreach ($line in $flt) {
            $t = ($line -replace '\s{2,}', '|').Trim()
            if ($t -match '^(Filter Name|-----)' -or [string]::IsNullOrWhiteSpace($t)) { continue }
            $cols = $t -split '\|'
            if ($cols.Count -ge 1 -and $cols[0] -and $cols[0] -notmatch 'Num Instances') {
                $records.Add([ordered]@{
                    recordType  = 'minifilter'
                    filterName  = $cols[0].Trim()
                    numInstances = if ($cols.Count -ge 2) { $cols[1].Trim() } else { $null }
                    altitude    = if ($cols.Count -ge 3) { $cols[2].Trim() } else { $null }
                    frame       = if ($cols.Count -ge 4) { $cols[3].Trim() } else { $null }
                })
            }
        }
    }
} catch { Write-HawkLog "drivers: fltmc enumeration failed - $_" 'WARN' }

if ($records.Count -eq 0) { Write-HawkLog 'drivers: no drivers enumerated' }

Export-HawkArtifact -SessionRoot $SessionRoot -ArtifactType 'drivers' -Records $records
