<#
.SYNOPSIS
    Module: userassist_mru - UserAssist (ROT13) + Explorer MRU execution traces.
    RAW collection only. recordType discriminates the source.
#>
param([Parameter(Mandatory)][string]$SessionRoot, $Config)

Write-HawkLog 'userassist_mru: collection started'

$records = New-Object System.Collections.Generic.List[object]

function ConvertFrom-Rot13([string]$s) {
    if (-not $s) { return $s }
    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in $s.ToCharArray()) {
        $c = [int]$ch
        if ($c -ge 65 -and $c -le 90)      { [void]$sb.Append([char](65 + (($c - 65 + 13) % 26))) }
        elseif ($c -ge 97 -and $c -le 122) { [void]$sb.Append([char](97 + (($c - 97 + 13) % 26))) }
        else                               { [void]$sb.Append($ch) }
    }
    $sb.ToString()
}

# (a) UserAssist - binary values under each GUID\Count subkey
try {
    $uaRoot = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey(
        'Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist')
    if ($uaRoot) {
        foreach ($guid in $uaRoot.GetSubKeyNames()) {
            $count = $null
            try { $count = $uaRoot.OpenSubKey("$guid\Count") } catch {}
            if (-not $count) { continue }
            foreach ($vn in $count.GetValueNames()) {
                $decoded = ConvertFrom-Rot13 $vn
                $data = $count.GetValue($vn)
                $runCount = $null; $lastExec = $null
                if ($data -is [byte[]] -and $data.Length -ge 68) {
                    try { $runCount = [BitConverter]::ToInt32($data, 4) } catch {}
                    try {
                        $ft = [BitConverter]::ToInt64($data, 60)
                        if ($ft -gt 0) { $lastExec = ConvertTo-HawkUtc ([DateTime]::FromFileTimeUtc($ft)) }
                    } catch {}
                }
                $records.Add([ordered]@{
                    recordType  = 'userAssist'
                    decodedName = $decoded
                    runCount    = $runCount
                    lastExecUtc = $lastExec
                })
            }
        }
    }
} catch { Write-HawkLog "userassist_mru: UserAssist walk failed - $_" 'WARN' }

# (b/c/d) RunMRU / TypedPaths / RecentDocs (string values)
$stringMru = @(
    @{ rt = 'runMru';     path = 'Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU' },
    @{ rt = 'typedPaths'; path = 'Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths' }
)
foreach ($m in $stringMru) {
    try {
        $k = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($m.path)
        if (-not $k) { continue }
        foreach ($vn in $k.GetValueNames()) {
            $records.Add([ordered]@{
                recordType = $m.rt
                valueName  = $vn
                command    = "$($k.GetValue($vn))"
            })
        }
    } catch { Write-HawkLog "userassist_mru: $($m.rt) walk failed - $_" 'WARN' }
}

# RecentDocs - value names are binary; record the value name index only
try {
    $rd = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey(
        'Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs')
    if ($rd) {
        foreach ($vn in $rd.GetValueNames()) {
            if ($vn -eq 'MRUListEx') { continue }
            $val = $rd.GetValue($vn)
            $name = $null
            if ($val -is [byte[]]) {
                try {
                    # leading UTF-16LE filename up to first double-null
                    $s = [System.Text.Encoding]::Unicode.GetString($val)
                    $nul = $s.IndexOf([char]0)
                    $name = if ($nul -ge 0) { $s.Substring(0, $nul) } else { $s }
                } catch {}
            }
            $records.Add([ordered]@{ recordType = 'recentDocs'; valueName = $vn; docName = $name })
        }
    }
} catch { Write-HawkLog "userassist_mru: RecentDocs walk failed - $_" 'WARN' }

# (e) MuiCache
try {
    $mui = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey(
        'Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache')
    if ($mui) {
        foreach ($vn in $mui.GetValueNames()) {
            $records.Add([ordered]@{
                recordType   = 'muiCache'
                path         = $vn
                friendlyName = "$($mui.GetValue($vn))"
            })
        }
    }
} catch { Write-HawkLog "userassist_mru: MuiCache walk failed - $_" 'WARN' }

Export-HawkArtifact -SessionRoot $SessionRoot -ArtifactType 'userassist_mru' -Records $records
