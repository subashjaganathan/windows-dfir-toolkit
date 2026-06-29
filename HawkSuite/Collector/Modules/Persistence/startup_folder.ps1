<#
.SYNOPSIS
    Module: startup_folder â€” Startup-folder items for all users, with .lnk resolution.
    Migrated from windows-dfir-toolkit Startup_Folder.ps1 (analysis logic removed).
#>
param([Parameter(Mandatory)][string]$SessionRoot, $Config)

Write-HawkLog 'startup_folder: collection started'
$records = New-Object System.Collections.Generic.List[object]
$shell = $null
try { $shell = New-Object -ComObject WScript.Shell } catch {}

$folders = @(
    @{ path = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"; user = '<all-users>' }
)
foreach ($u in (Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue)) {
    $folders += @{ path = "$($u.FullName)\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"; user = $u.Name }
}

foreach ($f in $folders) {
    # Test-Path throws UnauthorizedAccessException on other users' Startup dirs
    # when unelevated; treat any access failure as "not present".
    $exists = $false
    try { $exists = Test-Path -LiteralPath $f.path -ErrorAction Stop } catch { continue }
    if (-not $exists) { continue }
    foreach ($item in (Get-ChildItem $f.path -File -Force -ErrorAction SilentlyContinue)) {
        if ($item.Name -eq 'desktop.ini') { continue }
        $target = $null; $targetArgs = $null
        if ($item.Extension -eq '.lnk' -and $shell) {
            try {
                $lnk = $shell.CreateShortcut($item.FullName)
                $target = $lnk.TargetPath
                $targetArgs = $lnk.Arguments
            } catch {}
        }
        $hashSource = $(if ($target -and (Test-Path $target -PathType Leaf -ErrorAction SilentlyContinue)) { $target } else { $item.FullName })
        $identity = Get-HawkFileIdentity -Path $hashSource
        $records.Add([ordered]@{
            user            = $f.user
            itemPath        = $item.FullName
            itemName        = $item.Name
            target          = $target
            targetArguments = $targetArgs
            sha256          = $identity.sha256
            md5             = $identity.md5
            signatureStatus = $identity.signatureStatus
            signer          = $identity.signer
            createdUtc      = ConvertTo-HawkUtc $item.CreationTimeUtc
            modifiedUtc     = ConvertTo-HawkUtc $item.LastWriteTimeUtc
        })
    }
}

Export-HawkArtifact -SessionRoot $SessionRoot -ArtifactType 'startup_folder' -Records $records
