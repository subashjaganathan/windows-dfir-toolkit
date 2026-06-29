<#
.SYNOPSIS
    Module: recent_files - file/app access + deletion evidence:
      - Recent LNK shortcuts (resolved target = files the user opened)
      - Jump List files (per-app open history; metadata)
      - Recycle Bin $I records (deleted file original path + delete time)
    RAW collection only. recordType discriminates the source.
#>
param([Parameter(Mandatory)][string]$SessionRoot, $Config)

Write-HawkLog 'recent_files: collection started'

$records = New-Object System.Collections.Generic.List[object]
$shell = $null
try { $shell = New-Object -ComObject WScript.Shell } catch { Write-HawkLog "recent_files: WScript.Shell unavailable - $_" 'WARN' }

$users = @()
try { $users = Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue } catch {}

foreach ($u in $users) {
    $recent = Join-Path $u.FullName 'AppData\Roaming\Microsoft\Windows\Recent'
    $ex = $false; try { $ex = Test-Path -LiteralPath $recent -ErrorAction Stop } catch { continue }
    if (-not $ex) { continue }

    # (a) Recent LNK shortcuts -> resolved targets
    try {
        foreach ($f in (Get-ChildItem -LiteralPath $recent -Filter '*.lnk' -File -ErrorAction SilentlyContinue)) {
            $target = $null; $args2 = $null; $work = $null
            if ($shell) {
                try { $s = $shell.CreateShortcut($f.FullName); $target = $s.TargetPath; $args2 = $s.Arguments; $work = $s.WorkingDirectory } catch {}
            }
            $records.Add([ordered]@{
                recordType      = 'recentLnk'
                user            = $u.Name
                lnkName         = $f.Name
                target          = $target
                arguments       = $args2
                workingDir      = $work
                lnkModifiedUtc  = ConvertTo-HawkUtc $f.LastWriteTimeUtc
                lnkCreatedUtc   = ConvertTo-HawkUtc $f.CreationTimeUtc
            })
        }
    } catch { Write-HawkLog "recent_files: LNK enum failed for $($u.Name) - $_" 'WARN' }

    # (b) Jump Lists (metadata only; deep parse is analyst-side)
    foreach ($jl in @(
        @{ sub = 'AutomaticDestinations'; kind = 'automatic' },
        @{ sub = 'CustomDestinations';    kind = 'custom' })) {
        $dir = Join-Path $recent $jl.sub
        try {
            if (Test-Path -LiteralPath $dir -ErrorAction SilentlyContinue) {
                foreach ($f in (Get-ChildItem -LiteralPath $dir -File -ErrorAction SilentlyContinue)) {
                    $records.Add([ordered]@{
                        recordType   = 'jumpList'
                        user         = $u.Name
                        jumpListKind = $jl.kind
                        appIdFile    = $f.Name       # leading hex = AppID
                        sizeBytes    = $f.Length
                        modifiedUtc  = ConvertTo-HawkUtc $f.LastWriteTimeUtc
                    })
                }
            }
        } catch { Write-HawkLog "recent_files: jumplist enum failed for $($u.Name) - $_" 'WARN' }
    }
}

# (c) Recycle Bin $I records (deleted-file metadata, per SID)
try {
    $rb = 'C:\$Recycle.Bin'
    if (Test-Path -LiteralPath $rb -ErrorAction SilentlyContinue) {
        foreach ($sidDir in (Get-ChildItem -LiteralPath $rb -Directory -Force -ErrorAction SilentlyContinue)) {
            try {
                foreach ($iFile in (Get-ChildItem -LiteralPath $sidDir.FullName -Filter '$I*' -File -Force -ErrorAction SilentlyContinue)) {
                    try {
                        $b = [System.IO.File]::ReadAllBytes($iFile.FullName)
                        if ($b.Length -lt 24) { continue }
                        $ver  = [BitConverter]::ToInt64($b, 0)
                        $size = [BitConverter]::ToInt64($b, 8)
                        $ft   = [BitConverter]::ToInt64($b, 16)
                        $deletedUtc = $null
                        if ($ft -gt 0) { try { $deletedUtc = ConvertTo-HawkUtc ([DateTime]::FromFileTimeUtc($ft)) } catch {} }
                        $origPath = $null
                        if ($ver -eq 2 -and $b.Length -ge 28) {
                            $len = [BitConverter]::ToInt32($b, 24)               # chars incl. null
                            if ($len -gt 0 -and (28 + $len*2) -le $b.Length + 2) {
                                $origPath = [System.Text.Encoding]::Unicode.GetString($b, 28, [Math]::Min($len*2, $b.Length-28)).TrimEnd([char]0)
                            }
                        } else {
                            # v1: fixed 260-char UTF-16 path at offset 24
                            $maxlen = [Math]::Min(520, $b.Length - 24)
                            $origPath = [System.Text.Encoding]::Unicode.GetString($b, 24, $maxlen)
                            $nul = $origPath.IndexOf([char]0); if ($nul -ge 0) { $origPath = $origPath.Substring(0, $nul) }
                        }
                        $records.Add([ordered]@{
                            recordType    = 'recycleBin'
                            userSid       = $sidDir.Name
                            recycledName  = $iFile.Name
                            originalPath  = $origPath
                            sizeBytes     = $size
                            deletedUtc    = $deletedUtc
                        })
                    } catch { Write-HawkLog "recent_files: `$I parse failed $($iFile.Name) - $_" 'WARN' }
                }
            } catch {}
        }
    }
} catch { Write-HawkLog "recent_files: recycle bin enum failed - $_" 'WARN' }

Export-HawkArtifact -SessionRoot $SessionRoot -ArtifactType 'recent_files' -Records $records
