<#
.SYNOPSIS
    Module: powershell_history - PSReadLine console history, PS logging config,
    transcript inventory. RAW collection only. recordType discriminates source.
#>
param([Parameter(Mandatory)][string]$SessionRoot, $Config)

Write-HawkLog 'powershell_history: collection started'

$records = New-Object System.Collections.Generic.List[object]

# (a) PSReadLine ConsoleHost_history.txt per user (FULL content, never truncated)
try {
    foreach ($u in (Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue)) {
        $hist = Join-Path $u.FullName 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
        $exists = $false
        try { $exists = Test-Path -LiteralPath $hist -ErrorAction Stop } catch { continue }
        if (-not $exists) { continue }
        try {
            # Read as a plain .NET string[] via ReadAllLines. NOTE: Get-Content
            # decorates each line with ETS note properties (PSProvider etc.);
            # ConvertTo-Json -Depth then recurses into ProviderInfo per line and
            # effectively hangs. ReadAllLines returns clean strings (no ETS),
            # preserving every line with no truncation.
            $lines = [System.IO.File]::ReadAllLines($hist)
            $item = Get-Item -LiteralPath $hist -ErrorAction SilentlyContinue
            $records.Add([ordered]@{
                recordType     = 'psReadlineHistory'
                user           = $u.Name
                path           = $hist
                lineCount      = $lines.Count
                lastModifiedUtc= if ($item) { ConvertTo-HawkUtc $item.LastWriteTimeUtc } else { $null }
                lines          = $lines
            })
        } catch { Write-HawkLog "powershell_history: read failed for $($u.Name) - $_" 'WARN' }
    }
} catch { Write-HawkLog "powershell_history: user enum failed - $_" 'WARN' }

# (b) Logging configuration
function Get-PHReg([string]$hive, [string]$path, [string]$name) {
    try {
        $root = if ($hive -eq 'HKLM') { [Microsoft.Win32.Registry]::LocalMachine } else { [Microsoft.Win32.Registry]::CurrentUser }
        $k = $root.OpenSubKey($path)
        if ($k) { return $k.GetValue($name) }
    } catch {}
    $null
}
$transcriptDir = Get-PHReg 'HKLM' 'SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' 'OutputDirectory'
$records.Add([ordered]@{
    recordType                  = 'loggingConfig'
    enableScriptBlockLogging    = Get-PHReg 'HKLM' 'SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging'
    enableModuleLogging         = Get-PHReg 'HKLM' 'SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' 'EnableModuleLogging'
    enableTranscripting         = Get-PHReg 'HKLM' 'SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' 'EnableTranscripting'
    transcriptOutputDirectory   = $transcriptDir
})

# (c) Transcript files metadata (NOT content) under configured dir
if ($transcriptDir) {
    try {
        $exists = $false
        try { $exists = Test-Path -LiteralPath $transcriptDir -ErrorAction Stop } catch {}
        if ($exists) {
            foreach ($f in (Get-ChildItem -LiteralPath $transcriptDir -Recurse -File -Filter '*.txt' -ErrorAction SilentlyContinue | Select-Object -First 2000)) {
                $records.Add([ordered]@{
                    recordType      = 'transcriptFile'
                    path            = $f.FullName
                    sizeBytes       = $f.Length
                    lastModifiedUtc = ConvertTo-HawkUtc $f.LastWriteTimeUtc
                })
            }
        }
    } catch { Write-HawkLog "powershell_history: transcript enum failed - $_" 'WARN' }
}

Export-HawkArtifact -SessionRoot $SessionRoot -ArtifactType 'powershell_history' -Records $records
