<#
.SYNOPSIS
    Module: wer_reports - Windows Error Reporting crash/hang reports.
    Each Report.wer records a crashed/hung process (name, path, fault module),
    useful exploitation/crash evidence. RAW collection only.
#>
param([Parameter(Mandatory)][string]$SessionRoot, $Config)

Write-HawkLog 'wer_reports: collection started'

$records = New-Object System.Collections.Generic.List[object]

# Report.wer is key=value text; pull the high-signal fields.
function Read-WerFields([string]$werPath) {
    $f = @{}
    try {
        foreach ($ln in [System.IO.File]::ReadAllLines($werPath)) {
            $i = $ln.IndexOf('=')
            if ($i -gt 0) { $f[$ln.Substring(0,$i)] = $ln.Substring($i+1) }
        }
    } catch {}
    $f
}

# Machine-wide + per-user WER stores
$roots = New-Object System.Collections.Generic.List[object]
$roots.Add([pscustomobject]@{ scope='machine'; base=(Join-Path $env:ProgramData 'Microsoft\Windows\WER') })
try {
    foreach ($u in (Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue)) {
        $roots.Add([pscustomobject]@{ scope="user:$($u.Name)"; base=(Join-Path $u.FullName 'AppData\Local\Microsoft\Windows\WER') })
    }
} catch {}

foreach ($r in $roots) {
    foreach ($queue in 'ReportArchive','ReportQueue') {
        $dir = Join-Path $r.base $queue
        $ex = $false; try { $ex = Test-Path -LiteralPath $dir -ErrorAction Stop } catch { continue }
        if (-not $ex) { continue }
        try {
            foreach ($rep in (Get-ChildItem -LiteralPath $dir -Directory -ErrorAction SilentlyContinue)) {
                $wer = Join-Path $rep.FullName 'Report.wer'
                $fields = if (Test-Path -LiteralPath $wer -ErrorAction SilentlyContinue) { Read-WerFields $wer } else { @{} }
                $records.Add([ordered]@{
                    recordType   = 'werReport'
                    scope        = $r.scope
                    queue        = $queue
                    reportFolder = $rep.Name
                    eventType    = $fields['EventType']
                    appName      = $fields['AppName']
                    appPath      = $fields['AppPath']
                    faultModule  = $fields['Sig[3].Value']     # APPCRASH fault module name (when present)
                    reportTimeUtc= ConvertTo-HawkUtc $rep.LastWriteTimeUtc
                })
            }
        } catch { Write-HawkLog "wer_reports: enum failed $dir - $_" 'WARN' }
    }
}

Export-HawkArtifact -SessionRoot $SessionRoot -ArtifactType 'wer_reports' -Records $records
