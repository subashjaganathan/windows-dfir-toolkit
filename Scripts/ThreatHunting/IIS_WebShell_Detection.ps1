#Requires -Version 5.1
Set-StrictMode -Off
$ErrorActionPreference = "Continue"
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Hostname  = $env:COMPUTERNAME
$BasePath  = if ($env:DFIR_OUTPUT) { $env:DFIR_OUTPUT } else { "C:\IR_Collection" }
$CaseNum   = if ($env:DFIR_CASE) { $env:DFIR_CASE } else { "CASE-$(Get-Date -Format yyyyMMdd)" }
New-Item -ItemType Directory -Path $BasePath -Force | Out-Null
$LogFile  = "$BasePath\IIS_WebShell_Execution.log"
$JsonFile = "$BasePath\IIS_WebShell_${Hostname}_${Timestamp}.json"
$OutDir   = "$BasePath\WebShell_Suspects_${Hostname}_${Timestamp}"
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

function Write-Log { param([string]$M,[string]$L="INFO") Add-Content $LogFile "$(Get-Date -Format o) [$L] :: $M" }
Write-Log "IIS WebShell detection started | Case: $CaseNum"

$DaysBack  = if ($env:DFIR_DAYS) { [int]$env:DFIR_DAYS } else { 30 }
$SinceDate = (Get-Date).AddDays(-$DaysBack)

# Web-shell content signatures, split by confidence. Generic tokens like eval()/Process.Start
# appear in nearly every real ASP.NET/PHP app, so a single generic match must NOT flag a file.
# STRONG signatures tie execution directly to attacker-controlled request input - high confidence.
$StrongShellSig = @(
    'shell_exec\s*\(', 'passthru\s*\(', 'proc_open\s*\(', '\bpopen\s*\(',
    'eval\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13|\$_(GET|POST|REQUEST|COOKIE))',
    'assert\s*\(\s*\$_(GET|POST|REQUEST)',
    'base64_decode\s*\(\s*\$_(GET|POST|REQUEST)',
    'preg_replace\s*\(\s*[''"].*/e',
    '\$_(GET|POST|REQUEST|COOKIE)\s*\[[^\]]*\][^\r\n]{0,40}(eval|exec|system|shell_exec|passthru)',
    '(cmd|command|exec|c99|r57|b374k|weevely|antsword)\s*=\s*\$_(GET|POST|REQUEST)',
    'Request(\.(QueryString|Form|Params))?\s*\[[^\]]*\][^\r\n]{0,60}(eval|Process\.Start|cmd\.exe|WScript\.Shell)',
    'Response\.Write[^\r\n]{0,60}Process\.Start',
    'WScript\.Shell[^\r\n]{0,40}(Request|\.Exec|\.Run)',
    'FromBase64String[^\r\n]{0,60}(Request|Assembly\.Load)',
    '<%@\s*Page[^\r\n]{0,120}(eval|Process\.Start)'
)
# WEAK signatures are common in legitimate frameworks; only meaningful when several co-occur.
$WeakShellSig = @(
    'eval\s*\(', 'exec\s*\(', 'system\s*\(', 'base64_decode\s*\(',
    'Runtime\.getRuntime', 'ProcessBuilder', 'Process\.Start',
    'WScript\.Shell', 'Shell\.Application', 'CreateObject.*(WScript|Shell)',
    'cmd\.exe', 'powershell\.exe', 'cmd /c', 'net user', 'net localgroup', 'whoami',
    'Response\.Write.*Request', '<%.*Request\(', '<\?php.*\$_', 'FSO\.CreateTextFile', 'ADODB\.Stream'
)
# Match with Singleline so obfuscated shells that split tokens across newlines are still caught.
$RxOpt = [Text.RegularExpressions.RegexOptions]::Singleline -bor [Text.RegularExpressions.RegexOptions]::IgnoreCase

# Web executable extensions to scan
$WebExtensions = @("*.asp","*.aspx","*.ashx","*.asmx","*.php","*.jsp","*.jspx","*.cfm","*.shtml","*.phtml","*.php5","*.php7")

# IIS web roots
Write-Host "[*] Locating IIS web roots..." -ForegroundColor Cyan
$WebRoots = [System.Collections.Generic.List[string]]::new()

# Check IIS applicationHost.config
$IISConfig = "$env:SystemRoot\System32\inetsrv\config\applicationHost.config"
if (Test-Path $IISConfig) {
    try {
        [xml]$Config = Get-Content $IISConfig -ErrorAction SilentlyContinue
        $Config.configuration."system.applicationHost".sites.site | ForEach-Object {
            $_.application | ForEach-Object {
                $_.virtualDirectory | ForEach-Object {
                    if ($_.physicalPath -and (Test-Path ($_.physicalPath -replace "%SystemDrive%",$env:SystemDrive))) {
                        $WebRoots.Add($_.physicalPath -replace "%SystemDrive%",$env:SystemDrive)
                    }
                }
            }
        }
    } catch { Write-Log "IIS config parse failed: $_" "WARN" }
}

# Default IIS paths
$DefaultPaths = @(
    "C:\inetpub\wwwroot",
    "C:\inetpub\wwwroot\aspnet_client",
    "D:\inetpub\wwwroot",
    "C:\xampp\htdocs",
    "C:\wamp\www",
    "C:\nginx\html"
)
foreach ($DP in $DefaultPaths) {
    if (Test-Path $DP) { $WebRoots.Add($DP) }
}

$UniqueRoots = @($WebRoots | Sort-Object -Unique)
Write-Host "[*] Scanning $($UniqueRoots.Count) web root(s)..." -ForegroundColor Cyan
Write-Log "Web roots to scan: $($UniqueRoots -join ', ')"

$AllWebFiles    = [System.Collections.Generic.List[PSCustomObject]]::new()
$SuspectedShells= [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($Root in $UniqueRoots) {
    if (-not (Test-Path $Root)) { continue }
    foreach ($Ext in $WebExtensions) {
        $Files = @(Get-ChildItem $Root -Recurse -Filter $Ext -ErrorAction SilentlyContinue)
        foreach ($File in $Files) {
            $IsRecent     = ($File.LastWriteTimeUtc -gt $SinceDate)
            $IsSuspicious = $false
            $MatchedSigs  = @()
            $Content      = $null
            $SHA256       = $null

            try {
                $SHA256  = (Get-FileHash $File.FullName -Algorithm SHA256).Hash
                $Content = Get-Content $File.FullName -Raw -ErrorAction SilentlyContinue
            } catch {}

            $StrongSigs = @(); $WeakSigs = @(); $Confidence = $null
            if ($Content) {
                foreach ($Sig in $StrongShellSig) { if ([regex]::IsMatch($Content,$Sig,$RxOpt)) { $StrongSigs += $Sig } }
                foreach ($Sig in $WeakShellSig)   { if ([regex]::IsMatch($Content,$Sig,$RxOpt)) { $WeakSigs   += $Sig } }
                $MatchedSigs = $StrongSigs + $WeakSigs
                # One strong signature, OR three co-occurring weak ones, marks a suspect.
                if ($StrongSigs.Count -ge 1) { $IsSuspicious = $true; $Confidence = "High" }
                elseif ($WeakSigs.Count -ge 3) { $IsSuspicious = $true; $Confidence = "Medium" }
            }

            # Only preserve a copy for genuinely high-confidence suspects (a strong signature),
            # so we don't clone hundreds of legitimate framework pages on a real web server.
            $CopiedPath = $null
            if ($IsSuspicious -and $StrongSigs.Count -ge 1) {
                $CopiedPath = "$OutDir\$($File.Name)_$($File.LastWriteTimeUtc.ToString('yyyyMMdd')).copy"
                Copy-Item $File.FullName $CopiedPath -Force -ErrorAction SilentlyContinue
                Write-Host "  [!] SUSPECT: $($File.FullName) | Strong: $($StrongSigs.Count) Weak: $($WeakSigs.Count)" -ForegroundColor Red
            }

            $FileObj = [PSCustomObject]@{
                FileName        = $File.Name
                FullPath        = $File.FullName
                Extension       = $File.Extension
                SizeBytes       = $File.Length
                CreationTime    = $File.CreationTimeUtc.ToString("o")
                LastModified    = $File.LastWriteTimeUtc.ToString("o")
                IsRecentlyModified = $IsRecent
                SHA256          = $SHA256
                IsSuspicious    = $IsSuspicious
                Confidence      = $Confidence
                MatchedSignatures = $MatchedSigs
                StrongSignatureCount = $StrongSigs.Count
                SignatureCount  = $MatchedSigs.Count
                CopiedTo        = $CopiedPath
                WebRoot         = $Root
            }
            $AllWebFiles.Add($FileObj)
            if ($IsSuspicious) { $SuspectedShells.Add($FileObj) }
        }
    }
}

# IIS access log - check for web shell access patterns
Write-Host "[*] Scanning IIS access logs for web shell patterns..." -ForegroundColor Cyan
$SuspiciousRequests = [System.Collections.Generic.List[PSCustomObject]]::new()
$IISLogPaths = @(
    "C:\inetpub\logs\LogFiles",
    "D:\inetpub\logs\LogFiles",
    "$env:SystemDrive\inetpub\logs\LogFiles"
)
# W3C field order is declared per-file by the "#Fields:" directive and varies by config,
# so we build a name->index map from it rather than hardcoding column positions. The
# suspicious-request pattern targets known web-shell command/param signatures, not any .asp URL.
$SuspReqPattern = '(?i)(whoami|ipconfig|net(\+|%20)user|cmd\.exe|cmd(\+|%20)?/c|powershell|xp_cmdshell|c99|r57|b374k|weevely|antsword|\beval\b|cmd=|command=|exec=|shell=|\.\./\.\.|%00|certutil.*urlcache)'
foreach ($LogPath in $IISLogPaths) {
    if (-not (Test-Path $LogPath)) { continue }
    Get-ChildItem $LogPath -Recurse -Filter "*.log" -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTimeUtc -gt $SinceDate } | ForEach-Object {
            $LogName = $_.Name
            $FieldMap = @{}
            foreach ($Line in [System.IO.File]::ReadLines($_.FullName)) {
                if ($Line -match '^#Fields:\s*(.+)') {
                    $names = ($Matches[1].Trim() -split '\s+')
                    $FieldMap = @{}
                    for ($i = 0; $i -lt $names.Count; $i++) { $FieldMap[$names[$i]] = $i }
                    continue
                }
                if ($Line.StartsWith('#') -or $Line.Trim() -eq '') { continue }

                $Parts = $Line -split '\s+'
                $get = { param($n) if ($FieldMap.ContainsKey($n) -and $Parts.Count -gt $FieldMap[$n]) { $Parts[$FieldMap[$n]] } else { $null } }
                $uri = & $get 'cs-uri-stem'
                $qry = & $get 'cs-uri-query'
                $cip = & $get 'c-ip'
                $combined = "$uri`?$qry"

                if ($combined -match $SuspReqPattern) {
                    $SuspiciousRequests.Add([PSCustomObject]@{
                        LogFile    = $LogName
                        ClientIP   = $cip
                        RequestURI = $uri
                        Query      = $qry
                        Method     = (& $get 'cs-method')
                        Status     = (& $get 'sc-status')
                        LogEntry   = $Line
                    })
                }
            }
        }
}

Write-Log "Web files scanned: $($AllWebFiles.Count) | Suspected shells: $($SuspectedShells.Count) | Suspicious requests: $($SuspiciousRequests.Count)"

$Evidence = [PSCustomObject]@{
    ChainOfCustody       = [PSCustomObject]@{ CaseNumber=$CaseNum; Hostname=$Hostname; CollectedAt=(Get-Date).ToString("o"); ToolVersion="1.0" }
    ArtifactType         = "IIS_WebShell_Detection"
    WebRootsScanned      = $UniqueRoots
    TotalFilesScanned    = $AllWebFiles.Count
    SuspectedShellCount  = $SuspectedShells.Count
    SuspiciousRequestCount = $SuspiciousRequests.Count
    OutputDirectory      = $OutDir
    SuspectedShells      = $SuspectedShells
    SuspiciousRequests   = $SuspiciousRequests
    RecentlyModifiedFiles= @($AllWebFiles | Where-Object { $_.IsRecentlyModified } | Select-Object FullPath,LastModified,SizeBytes,SHA256)
}

$Evidence | ConvertTo-Json -Depth 7 | Out-File $JsonFile -Encoding UTF8
$Hash = Get-FileHash $JsonFile -Algorithm SHA256
[PSCustomObject]@{ FileName=$JsonFile; Hash=$Hash.Hash; Generated=(Get-Date).ToString("o") } |
    ConvertTo-Json | Out-File "$JsonFile.hash.json" -Encoding UTF8

Write-Host "[+] Web shell detection complete | Scanned: $($AllWebFiles.Count) | Suspected: $($SuspectedShells.Count) | Suspicious Requests: $($SuspiciousRequests.Count)" -ForegroundColor Green
Write-Host "[+] Suspects copied to: $OutDir" -ForegroundColor Green
Write-Host "[+] JSON: $JsonFile" -ForegroundColor Green
Write-Log "Completed"
