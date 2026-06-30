# Hawk.Common.psm1 — shared helpers for Hawk Collector modules (v2.0)
# Successor to DFIR_Common.psm1. COLLECTION ONLY: no scoring, no severity,
# no suspicious flags. Analysis happens in Hawk Analyzer.

Set-StrictMode -Version 2.0

# Script-scoped state, pre-initialized so StrictMode never trips on first read.
# (Set-StrictMode -Version 2.0 throws on referencing an unset variable, which
# would otherwise break the lazy-init in Get-HawkFileIdentity / Write-HawkLog.)
$script:IdentityCache = @{}
$script:HawkLogFile   = $null

function Test-HawkAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Write-HawkLog {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO','WARN','ERROR')][string]$Level = 'INFO',
        [string]$LogFile = $script:HawkLogFile
    )
    $line = "{0} [{1}] {2}" -f (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'), $Level, $Message
    if ($LogFile) { Add-Content -Path $LogFile -Value $line -Encoding UTF8 }
    if ($Level -ne 'INFO') { Write-Host $line -ForegroundColor ($(if ($Level -eq 'WARN') {'Yellow'} else {'Red'})) }
}

function Initialize-HawkSession {
    <# Creates the working session directory tree; returns its root path. #>
    param([Parameter(Mandatory)][string]$WorkRoot)
    foreach ($d in 'artifacts','raw','raw\evtx','raw\registry','raw\prefetch','raw\srum','raw\mft','logs') {
        New-Item -ItemType Directory -Force (Join-Path $WorkRoot $d) | Out-Null
    }
    $script:HawkLogFile = Join-Path $WorkRoot 'logs\collector.log'
    $WorkRoot
}

function ConvertTo-HawkJsonSafe {
    <#
      Recursively normalizes a value into JSON-safe primitives BEFORE
      ConvertTo-Json. This eliminates a whole class of PS 5.1 ConvertTo-Json
      hangs: (1) strings carrying ETS note-properties (e.g. Get-Content lines
      decorated with PSProvider/PSPath) that make the serializer recurse into
      rich provider objects, and (2) accidental object graphs. Every string is
      rebuilt fresh (ETS stripped); dictionaries/arrays are rebuilt with
      sanitized contents; anything exotic is stringified.
    #>
    param($Value, [int]$Depth = 0)
    if ($Depth -gt 24) { return "$Value" }            # hard recursion backstop
    if ($null -eq $Value) { return $null }
    if ($Value -is [string]) { return ('' + $Value) } # fresh plain string, no ETS
    if ($Value -is [ValueType]) { return $Value }     # int/long/bool/double/datetime/enum
    if ($Value -is [System.Collections.IDictionary]) {
        $o = [ordered]@{}
        foreach ($k in @($Value.Keys)) { $o["$k"] = ConvertTo-HawkJsonSafe $Value[$k] ($Depth + 1) }
        return $o
    }
    if ($Value -is [System.Collections.IEnumerable]) {  # arrays, List<> (string handled above)
        $list = New-Object System.Collections.Generic.List[object]
        foreach ($item in $Value) { $list.Add((ConvertTo-HawkJsonSafe $item ($Depth + 1))) }
        return ,($list.ToArray())
    }
    "$Value"                                           # PSCustomObject / unknown -> string
}

function Export-HawkArtifact {
    <#
      Writes a collection module's records to artifacts\<type>.json using the
      v1.0 envelope. Records must be RAW OBSERVATIONS — the analyzer scores.
      Returns the record count.
    #>
    param(
        [Parameter(Mandatory)][string]$SessionRoot,
        [Parameter(Mandatory)][string]$ArtifactType,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Records
    )
    $count = @($Records).Count
    $envelope = [ordered]@{
        schemaVersion  = '1.0'
        artifactType   = $ArtifactType
        host           = $env:COMPUTERNAME
        collectedAtUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        records        = $Records
    }
    # Sanitize to JSON-safe primitives first (see ConvertTo-HawkJsonSafe) so a
    # single ETS-decorated/exotic value can never hang the whole collection.
    $clean = ConvertTo-HawkJsonSafe $envelope
    $path = Join-Path $SessionRoot "artifacts\$ArtifactType.json"
    # -Compress keeps multi-MB artifacts manageable; analyzer pretty-prints on demand
    $clean | ConvertTo-Json -Depth 24 -Compress | Out-File $path -Encoding utf8
    Write-HawkLog "artifact '$ArtifactType' written ($count records)"
    $count
}

function Get-HawkFileIdentity {
    <#
      Hash + signature info for a binary, used by every module that references
      executables. MD5 included intentionally — NSRL whitelist is MD5-keyed.
      Results are cached per path for the life of the run.
    #>
    param([Parameter(Mandatory)][string]$Path)
    if ($script:IdentityCache.ContainsKey($Path)) { return $script:IdentityCache[$Path] }

    $result = [ordered]@{ path = $Path; sha256 = $null; md5 = $null; signatureStatus = 'Unknown'; signer = $null }
    if ($Path -and (Test-Path $Path -PathType Leaf)) {
        try { $result.sha256 = (Get-FileHash $Path -Algorithm SHA256 -ErrorAction Stop).Hash } catch {}
        try { $result.md5    = (Get-FileHash $Path -Algorithm MD5    -ErrorAction Stop).Hash } catch {}
        try {
            $sig = Get-AuthenticodeSignature $Path -ErrorAction Stop
            $result.signatureStatus = switch ($sig.Status) {
                'Valid'     { 'Valid' }
                'NotSigned' { 'NotSigned' }
                default     { 'Invalid' }
            }
            if ($sig.SignerCertificate) { $result.signer = $sig.SignerCertificate.Subject }
        } catch {}
    }
    $script:IdentityCache[$Path] = $result
    $result
}

function Resolve-HawkCommandPath {
    <#
      Extracts the executable path from a raw command string (service PathName,
      run-key value, task action). Handles quotes, arguments, env vars.
      Returns $null when no plausible file path can be resolved.
    #>
    param([string]$Command)
    if (-not $Command) { return $null }
    $cmd = [Environment]::ExpandEnvironmentVariables($Command.Trim())

    if ($cmd.StartsWith('"')) {
        $end = $cmd.IndexOf('"', 1)
        if ($end -gt 1) { $candidate = $cmd.Substring(1, $end - 1) } else { $candidate = $cmd.Trim('"') }
        if (Test-Path -LiteralPath $candidate -PathType Leaf -ErrorAction SilentlyContinue) { return $candidate }
        return $null
    }

    # Unquoted: try progressively longer prefixes (handles "C:\Program Files\x.exe -arg")
    $parts = $cmd -split ' '
    for ($i = 0; $i -lt $parts.Count; $i++) {
        $candidate = ($parts[0..$i] -join ' ')
        if ([string]::IsNullOrWhiteSpace($candidate)) { continue }   # e.g. multi-sz lists like "kerberos; msv1_0"
        if (Test-Path -LiteralPath $candidate -PathType Leaf -ErrorAction SilentlyContinue) { return $candidate }
        # rundll32-style "path,EntryPoint"
        $comma = $candidate -replace ',.*$', ''
        if ($comma -ne $candidate -and (Test-Path -LiteralPath $comma -PathType Leaf -ErrorAction SilentlyContinue)) { return $comma }
    }
    # Bare image name (e.g. service "svchost.exe -k netsvcs") — try System32
    $first = $parts[0]
    if ($first -match '^[\w.-]+\.(exe|dll|sys)$') {
        $sys = Join-Path $env:SystemRoot "System32\$first"
        if (Test-Path -LiteralPath $sys -PathType Leaf -ErrorAction SilentlyContinue) { return $sys }
    }
    $null
}

function ConvertTo-HawkUtc {
    <#
      Normalizes a timestamp to ISO-8601 UTC, or $null. NEVER substitutes
      collection time — unknown stays null (analyzer shows [UNKNOWN]).
    #>
    param($Value)
    if ($null -eq $Value) { return $null }
    try {
        $dt = if ($Value -is [datetime]) { $Value } else { [datetime]::Parse($Value, [Globalization.CultureInfo]::InvariantCulture) }
        if ($dt.Year -lt 1990 -or $dt.Year -gt 2100) { return $null }
        $dt.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    } catch { $null }
}

function Invoke-HawkMemoryAcquisition {
    <#
      Captures a full physical RAM image to raw\memory\ using an acquisition
      tool staged in the package Tools\ folder (winpmem / DumpIt / Magnet RAM
      Capture). Run FIRST (before disk/VSS activity) per order of volatility.
      No tool staged -> logs a clear note and skips (the rest of the collection
      proceeds normally). Integrity is covered by the session-level hashes.json.
    #>
    param(
        [Parameter(Mandatory)][string]$ToolsDir,
        [Parameter(Mandatory)][string]$WorkRoot,
        [ref]$RawArtifacts = $null
    )
    $memDir = Join-Path $WorkRoot 'raw\memory'
    New-Item -ItemType Directory -Force $memDir | Out-Null
    $out = Join-Path $memDir 'physmem.raw'

    $tools = @(Get-ChildItem -LiteralPath $ToolsDir -File -ErrorAction SilentlyContinue)
    $wp     = $tools | Where-Object { $_.Name -match '(?i)winpmem' }          | Select-Object -First 1
    $dumpit = $tools | Where-Object { $_.Name -match '(?i)dumpit' }           | Select-Object -First 1
    $magnet = $tools | Where-Object { $_.Name -match '(?i)magnetramcapture' } | Select-Object -First 1

    if (-not ($wp -or $dumpit -or $magnet)) {
        Write-HawkLog 'memory: no RAM-acquisition tool in Tools\ (drop winpmem.exe / DumpIt.exe to enable full memory capture); skipping' 'WARN'
        return
    }

    try {
        if ($wp) {
            $tool = $wp.FullName
            Write-HawkLog "memory: capturing RAM via $($wp.Name) (minutes; multi-GB)"
            # Rekall/Velocidex winpmem uses -o; the 'mini' build takes a positional path.
            Start-Process -FilePath $tool -ArgumentList @('-o', "`"$out`"") -Wait -NoNewWindow -ErrorAction Stop
            if (-not (Test-Path -LiteralPath $out)) {
                Start-Process -FilePath $tool -ArgumentList @("`"$out`"") -Wait -NoNewWindow -ErrorAction Stop
            }
        }
        elseif ($dumpit) {
            $tool = $dumpit.FullName
            Write-HawkLog "memory: capturing RAM via $($dumpit.Name) (minutes; multi-GB)"
            Start-Process -FilePath $tool -ArgumentList @('/OUTPUT', "`"$out`"", '/QUIET') -Wait -NoNewWindow -ErrorAction Stop
        }
        else {
            $tool = $magnet.FullName
            Write-HawkLog "memory: capturing RAM via $($magnet.Name) (minutes; multi-GB)"
            # Magnet writes its own filename into the output directory
            Start-Process -FilePath $tool -ArgumentList @('/accepteula', '/go', '/silent', $memDir) -Wait -NoNewWindow -ErrorAction Stop
        }
    } catch { Write-HawkLog "memory: acquisition tool failed - $_" 'ERROR'; return }

    $img = Get-ChildItem -LiteralPath $memDir -File -ErrorAction SilentlyContinue | Sort-Object Length -Descending | Select-Object -First 1
    if ($img -and $img.Length -gt 0) {
        Write-HawkLog ("memory: captured {0:N0} bytes -> {1}" -f $img.Length, $img.Name)
        if ($RawArtifacts) {
            $RawArtifacts.Value += [ordered]@{ path = "raw/memory/$($img.Name)"; source = 'physical memory'; method = 'memory-acquisition' }
        }
    } else {
        Write-HawkLog 'memory: acquisition produced no image' 'WARN'
    }
}

function Invoke-HawkNetworkCapture {
    <#
      Passive live packet capture via the built-in `netsh trace` (kernel NDIS
      capture -> .etl), converted to .pcapng with `pktmon etl2pcap` when
      available (both built into Windows 10/Server 2019+). Fixed-duration,
      circular, size-capped. Read-only/passive. Volatile evidence, so it runs
      with the early acquisition phase. No third-party tool required; skips
      gracefully if the capture cannot start. Integrity via session hashes.json.
      (Same approach as windows-dfir-toolkit v1 Network_Packet_Capture.)
    #>
    param(
        [Parameter(Mandatory)][string]$WorkRoot,
        [int]$Seconds = 120,
        [int]$MaxSizeMB = 500,
        [ref]$RawArtifacts = $null
    )
    $ErrorActionPreference = 'Continue'
    $netDir = Join-Path $WorkRoot 'raw\network'
    New-Item -ItemType Directory -Force $netDir | Out-Null
    $etl = Join-Path $netDir 'capture.etl'

    # Clear any trace session left running by a previous/aborted run, otherwise
    # 'netsh trace start' fails with "a tracing session is already in progress".
    try { $null = netsh trace stop 2>&1 } catch {}

    Write-Host ("[*] Packet capture: running netsh trace for {0}s (passive, circular, max {1}MB). Please wait..." -f $Seconds, $MaxSizeMB) -ForegroundColor Cyan
    Write-HawkLog "network: starting netsh packet capture (${Seconds}s, max ${MaxSizeMB}MB, circular)"
    $started = $false
    try {
        $null = netsh trace start capture=yes report=disabled overwrite=yes maxSize=$MaxSizeMB fileMode=circular traceFile="$etl" 2>&1
        $started = ($LASTEXITCODE -eq 0)
    } catch {}
    if (-not $started) {
        Write-Host '[!] Packet capture could not start; skipping (collection continues).' -ForegroundColor Yellow
        Write-HawkLog 'network: netsh trace start failed (needs admin / capture provider); skipping packet capture' 'WARN'
        return
    }

    # Visible countdown so this phase never looks hung from the console.
    $remaining = $Seconds
    while ($remaining -gt 0) {
        $chunk = [Math]::Min(10, $remaining)
        try { Start-Sleep -Seconds $chunk } catch {}
        $remaining -= $chunk
        Write-Host ("    ...capturing ({0}s remaining)" -f $remaining) -ForegroundColor DarkGray
    }

    # 'netsh trace stop' flushes/finalizes the ETL and can take a long time
    # (sometimes minutes). Bound it with a timed job so a slow stop can never
    # hang the entire collection; whatever was captured remains usable.
    Write-Host '[*] Finalizing capture (stopping trace; this can take up to a minute)...' -ForegroundColor Cyan
    Write-HawkLog 'network: stopping netsh trace'
    try {
        $stopJob = Start-Job -ScriptBlock { netsh trace stop 2>&1 | Out-Null }
        if (Wait-Job $stopJob -Timeout 180) {
            Receive-Job $stopJob | Out-Null
        } else {
            Write-Host '[!] Trace stop is taking too long; continuing with what was captured.' -ForegroundColor Yellow
            Write-HawkLog 'network: netsh trace stop exceeded 180s; continuing (ETL may be partially flushed)' 'WARN'
        }
        Remove-Job $stopJob -Force -ErrorAction SilentlyContinue
    } catch {
        Write-HawkLog "network: netsh trace stop error - $_" 'WARN'
    }

    if (-not (Test-Path -LiteralPath $etl)) { Write-HawkLog 'network: capture produced no ETL' 'WARN'; return }

    # Best-effort convert ETL -> pcapng (Wireshark-readable) via built-in pktmon.
    $pcap = Join-Path $netDir 'capture.pcapng'
    try { $null = pktmon etl2pcap "$etl" --out "$pcap" 2>&1 } catch {}
    if (-not (Test-Path -LiteralPath $pcap)) { try { $null = pktmon etl2pcap "$etl" -o "$pcap" 2>&1 } catch {} }

    foreach ($out in @($pcap, $etl)) {
        if (Test-Path -LiteralPath $out) {
            $sz = (Get-Item -LiteralPath $out).Length
            Write-HawkLog ("network: captured {0} ({1:N0} bytes)" -f (Split-Path $out -Leaf), $sz)
            if ($RawArtifacts) {
                $RawArtifacts.Value += [ordered]@{ path = "raw/network/$(Split-Path $out -Leaf)"
                    source = 'live packet capture (netsh trace)'; method = 'packet-capture' }
            }
        }
    }
}

Export-ModuleMember -Function Test-HawkAdmin, Write-HawkLog, Initialize-HawkSession,
    Export-HawkArtifact, Get-HawkFileIdentity, ConvertTo-HawkUtc, Resolve-HawkCommandPath,
    Invoke-HawkMemoryAcquisition, Invoke-HawkNetworkCapture
