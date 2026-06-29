<#
.SYNOPSIS
    Module: bam_dam - Background/Desktop Activity Moderator execution evidence.
    Each value is a full executable path with an 8-byte FILETIME = last time
    that program ran, per user SID. RAW collection only.
#>
param([Parameter(Mandatory)][string]$SessionRoot, $Config)

Write-HawkLog 'bam_dam: collection started'

$records = New-Object System.Collections.Generic.List[object]

# BAM (1809+ uses \State\, older builds omit it); DAM mirrors it on some builds.
$roots = @(
    @{ rt = 'bam'; path = 'SYSTEM\CurrentControlSet\Services\bam\State\UserSettings' },
    @{ rt = 'bam'; path = 'SYSTEM\CurrentControlSet\Services\bam\UserSettings' },
    @{ rt = 'dam'; path = 'SYSTEM\CurrentControlSet\Services\dam\State\UserSettings' }
)

foreach ($r in $roots) {
    try {
        $base = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($r.path)
        if (-not $base) { continue }
        foreach ($sid in $base.GetSubKeyNames()) {
            $sk = $base.OpenSubKey($sid)
            if (-not $sk) { continue }
            foreach ($vn in $sk.GetValueNames()) {
                # value name = executable path; skip housekeeping values (Version, SequenceNumber)
                if ($vn -notmatch '\\') { continue }
                $data = $sk.GetValue($vn)
                if ($data -isnot [byte[]] -or $data.Length -lt 8) { continue }
                $lastExec = $null
                try {
                    $ft = [BitConverter]::ToInt64($data, 0)
                    if ($ft -gt 0) { $lastExec = ConvertTo-HawkUtc ([DateTime]::FromFileTimeUtc($ft)) }
                } catch {}
                # normalize \Device\HarddiskVolumeN\... to a readable path tail
                $clean = $vn -replace '^\\Device\\HarddiskVolume\d+', ''
                $records.Add([ordered]@{
                    recordType        = $r.rt
                    userSid           = $sid
                    path              = $vn          # raw, never truncated
                    normalizedPath    = $clean
                    lastExecutionUtc  = $lastExec
                })
            }
        }
    } catch { Write-HawkLog "bam_dam: $($r.rt) walk failed ($($r.path)) - $_" 'WARN' }
}

Export-HawkArtifact -SessionRoot $SessionRoot -ArtifactType 'bam_dam' -Records $records
