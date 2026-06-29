<#
.SYNOPSIS
    Module: browser_history - browser artifact inventory (metadata) + Chromium
    bookmarks (JSON). RAW collection only. History/Cookies/LoginData SQLite DBs
    are LOCKED by running browsers and not parseable in PS 5.1, so they are
    recorded as file metadata for the analyst to pull; only Bookmarks (JSON,
    unlocked) is parsed.
#>
param([Parameter(Mandatory)][string]$SessionRoot, $Config)

Write-HawkLog 'browser_history: collection started'

$records = New-Object System.Collections.Generic.List[object]

$chromium = @{
    'Chrome' = 'AppData\Local\Google\Chrome\User Data'
    'Edge'   = 'AppData\Local\Microsoft\Edge\User Data'
    'Brave'  = 'AppData\Local\BraveSoftware\Brave-Browser\User Data'
}
$chromiumArtifacts = 'History','Cookies','Login Data','Web Data','Bookmarks'

foreach ($u in (Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue)) {
    foreach ($browser in $chromium.Keys) {
        $udRoot = Join-Path $u.FullName $chromium[$browser]
        $exists = $false
        try { $exists = Test-Path -LiteralPath $udRoot -ErrorAction Stop } catch { continue }
        if (-not $exists) { continue }
        # profile dirs: Default, Profile 1, ...
        try {
            $profiles = Get-ChildItem -LiteralPath $udRoot -Directory -ErrorAction SilentlyContinue |
                        Where-Object { $_.Name -eq 'Default' -or $_.Name -like 'Profile *' }
        } catch { continue }
        foreach ($prof in $profiles) {
            foreach ($art in $chromiumArtifacts) {
                $p = Join-Path $prof.FullName $art
                try {
                    if (-not (Test-Path -LiteralPath $p -ErrorAction SilentlyContinue)) { continue }
                    $item = Get-Item -LiteralPath $p -ErrorAction SilentlyContinue
                    $records.Add([ordered]@{
                        recordType      = 'browserArtifact'
                        browser         = $browser
                        profile         = $prof.Name
                        user            = $u.Name
                        artifact        = $art
                        path            = $p
                        sizeBytes       = if ($item) { $item.Length } else { $null }
                        lastModifiedUtc = if ($item) { ConvertTo-HawkUtc $item.LastWriteTimeUtc } else { $null }
                    })
                    # Bookmarks is JSON (not locked) - parse it
                    if ($art -eq 'Bookmarks') {
                        try {
                            $json = Get-Content -LiteralPath $p -Raw -ErrorAction Stop | ConvertFrom-Json
                            $stack = New-Object System.Collections.Stack
                            foreach ($rootName in 'bookmark_bar','other','synced') {
                                if ($json.roots.$rootName) { $stack.Push($json.roots.$rootName) }
                            }
                            $seen = 0
                            while ($stack.Count -gt 0 -and $seen -lt 5000) {
                                $node = $stack.Pop()
                                if ($node.type -eq 'url') {
                                    $seen++
                                    $added = $null
                                    if ($node.date_added) {
                                        try { $added = ConvertTo-HawkUtc ([DateTime]::FromFileTimeUtc(([int64]$node.date_added) * 10)) } catch {}
                                    }
                                    $records.Add([ordered]@{
                                        recordType = 'bookmark'; browser = $browser; profile = $prof.Name; user = $u.Name
                                        name = $node.name; url = $node.url; addedUtc = $added })
                                } elseif ($node.children) {
                                    foreach ($c in $node.children) { $stack.Push($c) }
                                }
                            }
                        } catch {}
                    }
                } catch {}
            }
        }
    }
    # Firefox
    $ffRoot = Join-Path $u.FullName 'AppData\Roaming\Mozilla\Firefox\Profiles'
    try {
        if (Test-Path -LiteralPath $ffRoot -ErrorAction SilentlyContinue) {
            foreach ($prof in (Get-ChildItem -LiteralPath $ffRoot -Directory -ErrorAction SilentlyContinue)) {
                foreach ($art in 'places.sqlite','cookies.sqlite','formhistory.sqlite') {
                    $p = Join-Path $prof.FullName $art
                    if (-not (Test-Path -LiteralPath $p -ErrorAction SilentlyContinue)) { continue }
                    $item = Get-Item -LiteralPath $p -ErrorAction SilentlyContinue
                    $records.Add([ordered]@{
                        recordType = 'browserArtifact'; browser = 'Firefox'; profile = $prof.Name; user = $u.Name
                        artifact = $art; path = $p
                        sizeBytes = if ($item) { $item.Length } else { $null }
                        lastModifiedUtc = if ($item) { ConvertTo-HawkUtc $item.LastWriteTimeUtc } else { $null } })
                }
            }
        }
    } catch {}
}

Export-HawkArtifact -SessionRoot $SessionRoot -ArtifactType 'browser_history' -Records $records
