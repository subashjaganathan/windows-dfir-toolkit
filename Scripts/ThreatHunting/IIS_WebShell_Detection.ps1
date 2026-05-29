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

# Web shell content signatures
$WebShellSignatures = @(
    "eval\s*\(",
    "exec\s*\(",
    "system\s*\(",
    "shell_exec\s*\(",
    "passthru\s*\(",
    "base64_decode\s*\(",
    "cmd\.exe",
    "powershell\.exe",
    "cmd /c",
    "Runtime\.getRuntime",
    "ProcessBuilder",
    "Process\.Start",
    "net user",
    "net localgroup",
    "whoami",
    "ipconfig",
    "cmd=",
    "command=",
    "execute=",
    "RunCmd\b",
    "WScript\.Shell",
    "Shell\.Application",
    "CreateObject.*WScript",
    "CreateObject.*Shell",
    "Response\.Write.*Request",
    "<%.*Request\(",
    "<\?php.*\$_",
    "FSO\.CreateTextFile",
    "ADODB\.Stream"
)

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

            if ($Content) {
                foreach ($Sig in $WebShellSignatures) {
                    if ($Content -match $Sig) {
                        $IsSuspicious = $true
                        $MatchedSigs += $Sig
                    }
                }
            }

            # Copy suspected shells
            $CopiedPath = $null
            if ($IsSuspicious) {
                $SafeName   = $File.FullName -replace "[:\\/<>|?*]","-"
                $CopiedPath = "$OutDir\$($File.Name)_$($File.LastWriteTimeUtc.ToString('yyyyMMdd')).copy"
                Copy-Item $File.FullName $CopiedPath -Force -ErrorAction SilentlyContinue
                Write-Host "  [!] SUSPECT: $($File.FullName) | Signatures: $($MatchedSigs.Count)" -ForegroundColor Red
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
                MatchedSignatures = $MatchedSigs
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
foreach ($LogPath in $IISLogPaths) {
    if (-not (Test-Path $LogPath)) { continue }
    Get-ChildItem $LogPath -Recurse -Filter "*.log" -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTimeUtc -gt $SinceDate } | ForEach-Object {
            $Lines = @(Get-Content $_.FullName -ErrorAction SilentlyContinue |
                Where-Object { $_ -match "\.asp|\.php|\.jsp|cmd\.exe|powershell|whoami|ipconfig|net\+user" -and $_ -notmatch "^#" })
            foreach ($Line in $Lines) {
                $Parts = $Line -split "\s+"
                $SuspiciousRequests.Add([PSCustomObject]@{
                    LogFile    = $_.Name
                    LogEntry   = $Line
                    ClientIP   = if ($Parts.Count -gt 2) { $Parts[2] } else { $null }
                    RequestURI = if ($Parts.Count -gt 4) { $Parts[4] } else { $null }
                })
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
