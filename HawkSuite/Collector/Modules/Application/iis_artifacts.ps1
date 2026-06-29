<#
.SYNOPSIS
    Module: iis_artifacts - IIS sites, app pools, and web-root script inventory.
    RAW collection only. Inventories server-side script files (hashed) for the
    analyzer to assess; does NOT label anything a "webshell".
#>
param([Parameter(Mandatory)][string]$SessionRoot, $Config)

Write-HawkLog 'iis_artifacts: collection started'

$records = New-Object System.Collections.Generic.List[object]

$inetsrv = Join-Path $env:SystemRoot 'System32\inetsrv'
if (-not (Test-Path -LiteralPath $inetsrv -ErrorAction SilentlyContinue)) {
    Write-HawkLog 'iis_artifacts: IIS not present'
    Export-HawkArtifact -SessionRoot $SessionRoot -ArtifactType 'iis_artifacts' -Records $records
    return
}

$physicalPaths = New-Object System.Collections.Generic.List[string]

# (a) Sites - prefer WebAdministration, fall back to applicationHost.config
$gotSites = $false
try {
    Import-Module WebAdministration -ErrorAction Stop
    foreach ($site in (Get-Website -ErrorAction Stop)) {
        $gotSites = $true
        if ($site.physicalPath) { $physicalPaths.Add([Environment]::ExpandEnvironmentVariables($site.physicalPath)) }
        $records.Add([ordered]@{
            recordType   = 'iisSite'
            siteName     = $site.Name
            state        = "$($site.State)"
            physicalPath = $site.physicalPath
            bindings     = "$($site.bindings.Collection -join '; ')"
        })
    }
    foreach ($pool in (Get-IISAppPool -ErrorAction SilentlyContinue)) {
        $records.Add([ordered]@{
            recordType           = 'iisAppPool'
            name                 = $pool.Name
            state                = "$($pool.State)"
            managedRuntimeVersion= $pool.ManagedRuntimeVersion
            identityType         = "$($pool.ProcessModel.IdentityType)"
        })
    }
} catch { Write-HawkLog "iis_artifacts: WebAdministration unavailable - $_" 'WARN' }

if (-not $gotSites) {
    # Parse applicationHost.config
    try {
        $cfgPath = Join-Path $inetsrv 'config\applicationHost.config'
        if (Test-Path -LiteralPath $cfgPath -ErrorAction SilentlyContinue) {
            [xml]$cfg = Get-Content -LiteralPath $cfgPath -Raw -ErrorAction Stop
            foreach ($site in $cfg.configuration.'system.applicationHost'.sites.site) {
                foreach ($app in $site.application) {
                    foreach ($vd in $app.virtualDirectory) {
                        if ($vd.physicalPath) {
                            $pp = [Environment]::ExpandEnvironmentVariables($vd.physicalPath)
                            $physicalPaths.Add($pp)
                            $records.Add([ordered]@{ recordType = 'iisSite'; siteName = $site.name; state = $null; physicalPath = $pp; bindings = $null })
                        }
                    }
                }
            }
            foreach ($pool in $cfg.configuration.'system.applicationHost'.applicationPools.add) {
                $records.Add([ordered]@{ recordType = 'iisAppPool'; name = $pool.name; state = $null
                    managedRuntimeVersion = $pool.managedRuntimeVersion; identityType = $pool.processModel.identityType })
            }
        }
    } catch { Write-HawkLog "iis_artifacts: applicationHost.config parse failed - $_" 'WARN' }
}

# (c) Web-root server-side script inventory (hashed)
$exts = '.aspx','.asp','.ashx','.asmx','.php','.jsp','.aspx.cs','.config'
$scanned = 0
foreach ($root in ($physicalPaths | Select-Object -Unique)) {
    try {
        if (-not (Test-Path -LiteralPath $root -ErrorAction SilentlyContinue)) { continue }
        foreach ($f in (Get-ChildItem -LiteralPath $root -Recurse -File -ErrorAction SilentlyContinue)) {
            if ($scanned -ge 5000) { break }
            if ($exts -notcontains $f.Extension.ToLower()) { continue }
            $scanned++
            $id = Get-HawkFileIdentity -Path $f.FullName
            $records.Add([ordered]@{
                recordType      = 'webrootFile'
                webRoot         = $root
                path            = $f.FullName
                sizeBytes       = $f.Length
                createdUtc      = ConvertTo-HawkUtc $f.CreationTimeUtc
                lastModifiedUtc = ConvertTo-HawkUtc $f.LastWriteTimeUtc
                sha256          = $id.sha256
                md5             = $id.md5
            })
        }
    } catch { Write-HawkLog "iis_artifacts: webroot scan failed for $root - $_" 'WARN' }
}

Export-HawkArtifact -SessionRoot $SessionRoot -ArtifactType 'iis_artifacts' -Records $records
