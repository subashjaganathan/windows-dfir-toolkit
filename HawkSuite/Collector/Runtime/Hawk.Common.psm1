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
    $envelope = [ordered]@{
        schemaVersion  = '1.0'
        artifactType   = $ArtifactType
        host           = $env:COMPUTERNAME
        collectedAtUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        records        = $Records
    }
    $path = Join-Path $SessionRoot "artifacts\$ArtifactType.json"
    # -Compress keeps multi-MB artifacts manageable; analyzer pretty-prints on demand
    $envelope | ConvertTo-Json -Depth 12 -Compress | Out-File $path -Encoding utf8
    Write-HawkLog "artifact '$ArtifactType' written ($(@($Records).Count) records)"
    @($Records).Count
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

Export-ModuleMember -Function Test-HawkAdmin, Write-HawkLog, Initialize-HawkSession,
    Export-HawkArtifact, Get-HawkFileIdentity, ConvertTo-HawkUtc, Resolve-HawkCommandPath
