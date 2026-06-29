<#
.SYNOPSIS
    Hawk Collector orchestrator — runs on the TARGET host.
    Executes packaged modules, acquires raw artifacts, produces one .hawk file.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$PackageRoot,
    [string]$OutputDir = $PackageRoot   # session lands next to the package (USB) by default
)

$ErrorActionPreference = 'Continue'
Import-Module (Join-Path $PackageRoot 'Runtime\Hawk.Common.psm1') -Force

if (-not (Test-HawkAdmin)) { Write-Host '[!] Run elevated.' -ForegroundColor Red; exit 1 }

$Config   = Get-Content (Join-Path $PackageRoot 'config.json') -Raw | ConvertFrom-Json
$Hostname = $env:COMPUTERNAME
$StartUtc = (Get-Date).ToUniversalTime()
$Stamp    = $StartUtc.ToString('yyyyMMddTHHmmssZ')
$CaseNum  = if ($Config.caseNumber) { $Config.caseNumber } else { "CASE-$Stamp" }

$WorkRoot = Join-Path $env:TEMP "hawk_$Stamp"
Initialize-HawkSession -WorkRoot $WorkRoot | Out-Null
Write-HawkLog "Hawk Collector started — case $CaseNum, preset $($Config.preset)"

# --- Host role detection (drives analyzer role modifiers) --------------------
$Role = 'workstation'
try {
    $cs = Get-CimInstance Win32_ComputerSystem
    $os = Get-CimInstance Win32_OperatingSystem
    if ($cs.DomainRole -in 4,5)      { $Role = 'domain-controller' }
    elseif ($os.ProductType -eq 3)   { $Role = 'server' }
} catch { Write-HawkLog "role detection failed: $_" 'WARN' }

# --- Run collection modules ---------------------------------------------------
$ModuleResults = @()
$Modules = Get-ChildItem (Join-Path $PackageRoot 'Modules') -Recurse -Filter '*.ps1' | Sort-Object FullName
$i = 0
foreach ($mod in $Modules) {
    $i++
    $name = $mod.BaseName
    Write-Host ("[{0}/{1}] {2}" -f $i, $Modules.Count, $name)
    $mStart = (Get-Date).ToUniversalTime()
    $status = 'success'; $errors = @(); $count = 0
    try {
        # Contract: module receives -SessionRoot and -Config, calls
        # Export-HawkArtifact, and RETURNS the record count.
        $count = & $mod.FullName -SessionRoot $WorkRoot -Config $Config
        if ($null -eq $count) { $count = 0 }
    } catch {
        $status = 'failed'; $errors += "$_"
        Write-HawkLog "module $name failed: $_" 'ERROR'
    }
    $ModuleResults += [ordered]@{
        name = $name; version = '2.0.0'; status = $status
        startedUtc = $mStart.ToString('yyyy-MM-ddTHH:mm:ssZ')
        endedUtc   = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        artifactFile = "artifacts/$name.json"; recordCount = [int]"$count"; errors = $errors
    }
}

# --- Raw EVTX acquisition -------------------------------------------------------
# Full native .evtx export (no truncation). Time-bounded by eventLogDays when set
# (keeps Security logs from bloating the session); per-channel status recorded so
# the analyst can see exactly what was and wasn't captured.
$RawArtifacts  = @()
$EvtxStatus    = @()
if ($Config.rawAcquisition.evtxChannels) {
    $channels = if ($Config.rawAcquisition.evtxChannels -contains '*') {
        (wevtutil el) | Where-Object { $_ }
    } else { $Config.rawAcquisition.evtxChannels }

    # Optional time filter: XPath, no spaces (avoids native-arg quoting issues).
    $timeQuery = $null
    if ($Config.eventLogDays -and [int]$Config.eventLogDays -gt 0) {
        $ms = [int64]$Config.eventLogDays * 86400000
        $timeQuery = "*[System[TimeCreated[timediff(@SystemTime)<=$ms]]]"
    }

    foreach ($ch in $channels) {
        $safe = ($ch -replace '[\\/]', '%4') + '.evtx'
        $dest = Join-Path $WorkRoot "raw\evtx\$safe"
        $exported = $false; $err = $null
        try {
            # Try time-bounded export first, fall back to full export if the
            # channel rejects the query (some classic logs do).
            if ($timeQuery) {
                cmd /c "wevtutil epl `"$ch`" `"$dest`" `"/q:$timeQuery`" /ow:true" 2>$null | Out-Null
                if (-not (Test-Path $dest)) {
                    cmd /c "wevtutil epl `"$ch`" `"$dest`" /ow:true" 2>$null | Out-Null
                }
            } else {
                cmd /c "wevtutil epl `"$ch`" `"$dest`" /ow:true" 2>$null | Out-Null
            }
            if (Test-Path $dest) {
                $exported = $true
                $RawArtifacts += [ordered]@{ path = "raw/evtx/$safe"; source = $ch; method = 'wevtutil'
                    sha256 = (Get-FileHash $dest -Algorithm SHA256).Hash }
            } else { $err = 'no output (access denied or empty channel)' }
        } catch { $err = "$_"; Write-HawkLog "EVTX export failed for ${ch}: $_" 'WARN' }
        $EvtxStatus += [ordered]@{ channel = $ch; exported = $exported; error = $err }
    }
    Write-HawkLog "EVTX channels exported: $(@($RawArtifacts | Where-Object { $_.path -like 'raw/evtx/*' }).Count) of $(@($channels).Count)"

    # The Security channel is the highest-value DFIR source and requires elevation;
    # the orchestrator already enforces admin, but surface it loudly if it slipped.
    $secStatus = $EvtxStatus | Where-Object { $_.channel -eq 'Security' }
    if ($secStatus -and -not $secStatus.exported) {
        Write-HawkLog 'Security channel NOT exported — run elevated for authentication/logon evidence.' 'WARN'
    }
}

# --- Archived / rotated event logs (Archive-*.evtx) ------------------------------
if ($Config.rawAcquisition.archivedLogs) {
    try {
        $winevt = Join-Path $env:SystemRoot 'System32\winevt\Logs'
        $arch = Get-ChildItem -LiteralPath $winevt -Filter 'Archive-*.evtx' -ErrorAction SilentlyContinue
        foreach ($a in $arch) {
            $dst = Join-Path $WorkRoot "raw\evtx\$($a.Name)"
            try {
                Copy-Item -LiteralPath $a.FullName -Destination $dst -ErrorAction Stop
                $RawArtifacts += [ordered]@{ path = "raw/evtx/$($a.Name)"; source = $a.FullName; method = 'archived-copy'
                    sha256 = (Get-FileHash $dst -Algorithm SHA256).Hash }
            } catch { Write-HawkLog "archived log copy failed: $($a.Name) - $_" 'WARN' }
        }
        if ($arch) { Write-HawkLog "archived event logs copied: $(@($arch).Count)" }
    } catch { Write-HawkLog "archived log sweep failed: $_" 'WARN' }
}

# --- Raw hives / MFT / SRUM via VSS (comprehensive preset) -----------------------
if ($Config.rawAcquisition.registryHives -or $Config.rawAcquisition.mft -or $Config.rawAcquisition.srum) {
    try {
        $shadow = (Get-CimInstance -ClassName Win32_ShadowCopy -ErrorAction SilentlyContinue |
                   Sort-Object InstallDate -Descending | Select-Object -First 1)
        if (-not $shadow) {
            $r = (vssadmin create shadow /for=C: 2>&1) -join ' '
            $shadow = Get-CimInstance Win32_ShadowCopy | Sort-Object InstallDate -Descending | Select-Object -First 1
        }
        if ($shadow) {
            $dev = $shadow.DeviceObject   # \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN
            # Standard tooling can't address GLOBALROOT device paths. Mount the
            # shadow as a directory symlink — reliable on Win7 → Server 2025.
            $vssLink = Join-Path $env:TEMP "hawk_vss_$Stamp"
            cmd /c mklink /d "$vssLink" "$dev\" 1>$null 2>$null
            if (-not (Test-Path $vssLink)) { throw "could not link shadow copy device $dev" }
            try {
                $targets = @()   # paths relative to the volume root
                if ($Config.rawAcquisition.registryHives) {
                    $targets += @(
                        @{ rel = 'Windows\System32\config\SYSTEM';   dst = 'raw\registry\SYSTEM' },
                        @{ rel = 'Windows\System32\config\SOFTWARE'; dst = 'raw\registry\SOFTWARE' },
                        @{ rel = 'Windows\System32\config\SAM';      dst = 'raw\registry\SAM' },
                        @{ rel = 'Windows\System32\config\SECURITY'; dst = 'raw\registry\SECURITY' },
                        @{ rel = 'Windows\AppCompat\Programs\Amcache.hve'; dst = 'raw\registry\Amcache.hve' }
                    )
                    foreach ($u in (Get-ChildItem C:\Users -Directory -ErrorAction SilentlyContinue)) {
                        $targets += @{ rel = "Users\$($u.Name)\NTUSER.DAT"; dst = "raw\registry\NTUSER_$($u.Name).DAT" }
                    }
                }
                if ($Config.rawAcquisition.srum) { $targets += @{ rel = 'Windows\System32\sru\SRUDB.dat'; dst = 'raw\srum\SRUDB.dat' } }
                foreach ($t in $targets) {
                    try {
                        $src = Join-Path $vssLink $t.rel
                        if (-not (Test-Path -LiteralPath $src)) { continue }
                        $dst = Join-Path $WorkRoot $t.dst
                        Copy-Item -LiteralPath $src -Destination $dst -Force -ErrorAction Stop
                        $RawArtifacts += [ordered]@{ path = ($t.dst -replace '\\','/'); source = "C:\$($t.rel)"
                            method = 'vss'; sha256 = (Get-FileHash $dst -Algorithm SHA256).Hash }
                    } catch { Write-HawkLog "VSS copy failed: $($t.rel) — $_" 'WARN' }
                }
                Write-HawkLog "VSS acquisition complete via $dev"
            } finally {
                cmd /c rmdir "$vssLink" 1>$null 2>$null   # remove link only, not contents
            }
        } else { Write-HawkLog 'no shadow copy available; raw hive acquisition skipped' 'WARN' }
    } catch { Write-HawkLog "VSS acquisition error: $_" 'ERROR' }
}

# --- Prefetch -------------------------------------------------------------------
if ($Config.rawAcquisition.prefetchFiles) {
    Get-ChildItem 'C:\Windows\Prefetch\*.pf' -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            Copy-Item $_.FullName (Join-Path $WorkRoot "raw\prefetch\$($_.Name)") -ErrorAction Stop
            $RawArtifacts += [ordered]@{ path = "raw/prefetch/$($_.Name)"; source = $_.FullName; method = 'direct'
                sha256 = (Get-FileHash $_.FullName -Algorithm SHA256).Hash }
        } catch {}
    }
}

# --- Manifest ---------------------------------------------------------------------
$os = Get-CimInstance Win32_OperatingSystem
$Manifest = [ordered]@{
    schemaVersion = '1.0'
    tool = @{ name = 'HawkCollector'; version = '2.0.0' }
    case = [ordered]@{
        caseNumber = $CaseNum; investigator = $Config.investigator
        collectionStartUtc = $StartUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')
        collectionEndUtc   = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    }
    host = [ordered]@{
        hostname = $Hostname; domain = $env:USERDNSDOMAIN
        os = @{ caption = $os.Caption; version = $os.Version; build = [int]$os.BuildNumber }
        role = $Role
        timezone = (Get-TimeZone).DisplayName
        arch = $env:PROCESSOR_ARCHITECTURE
    }
    preset = $Config.preset
    eventLogDays = $Config.eventLogDays
    modules = $ModuleResults
    rawArtifacts = $RawArtifacts
    evtxStatus = $EvtxStatus
}
$Manifest | ConvertTo-Json -Depth 8 | Out-File (Join-Path $WorkRoot 'manifest.json') -Encoding utf8

# --- Hash everything, zip to .hawk --------------------------------------------------
$AllHashes = Get-ChildItem $WorkRoot -Recurse -File | ForEach-Object {
    [ordered]@{ path = $_.FullName.Substring($WorkRoot.Length + 1) -replace '\\','/'
                sha256 = (Get-FileHash $_.FullName -Algorithm SHA256).Hash }
}
@{ schemaVersion = '1.0'; files = $AllHashes } | ConvertTo-Json -Depth 4 |
    Out-File (Join-Path $WorkRoot 'hashes.json') -Encoding utf8

$SessionFile = Join-Path $OutputDir ("{0}_{1}_{2}.hawk" -f $CaseNum, $Hostname, $Stamp)
Add-Type -AssemblyName System.IO.Compression.FileSystem
[IO.Compression.ZipFile]::CreateFromDirectory($WorkRoot, $SessionFile,
    [IO.Compression.CompressionLevel]::Optimal, $false)

$SessionHash = (Get-FileHash $SessionFile -Algorithm SHA256).Hash
"$SessionHash  $(Split-Path $SessionFile -Leaf)" | Out-File "$SessionFile.sha256" -Encoding ascii

Write-Host ""
Write-Host "[+] Session: $SessionFile" -ForegroundColor Green
Write-Host "[+] SHA256 : $SessionHash"
Write-Host "    Import this file in Hawk Analyzer."

# Clean working dir (evidence now sealed in the .hawk)
Remove-Item $WorkRoot -Recurse -Force -ErrorAction SilentlyContinue
