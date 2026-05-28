#Requires -Version 5.1
<#
.SYNOPSIS
    Live network packet capture using netsh trace with automatic ETL to PCAP conversion.

.DESCRIPTION
    Captures live network traffic using Windows built-in netsh trace (kernel level).
    Automatically converts ETL output to PCAP format using:
      - Method 1: pktmon etl2pcap (built-in Windows 10 2004+ / Server 2022+)
      - Method 2: etl2pcapng (auto-downloaded from Microsoft GitHub)
    Output is Wireshark-compatible PCAP ready for analysis.

.PARAMETER Duration
    Capture duration in seconds. Default: 300 (5 minutes)

.PARAMETER MaxSizeMB
    Maximum capture file size in MB. Default: 500

.PARAMETER Interface
    Network interface to capture on. Default: All interfaces

.COMPATIBILITY
    Windows 10/11 / Server 2016+ : Full
    pktmon conversion : Windows 10 2004+ / Server 2022+
    etl2pcapng fallback : All versions

.IR_PHASE
    Live Response / Network Forensics

.MITRE_ATTCK
    T1040  - Network Sniffing (detection)
    T1071  - Application Layer Protocol (C2 detection)
    T1048  - Exfiltration Over Alternative Protocol

.FORENSIC_SAFETY
    Read-only passive capture
    Does not modify network traffic
    SHA256 integrity on all output files

.AUTHOR
    DFIR Toolkit

.VERSION
    1.0
#>

param(
    [int]$Duration   = 300,
    [int]$MaxSizeMB  = 500,
    [string]$Interface = ""
)

Set-StrictMode -Off
$ErrorActionPreference = "Continue"

$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) { Write-Error "[!] Network capture requires Administrator privileges."; exit 1 }

$Timestamp    = Get-Date -Format "yyyyMMdd_HHmmss"
$Hostname     = $env:COMPUTERNAME
$BasePath     = if ($env:DFIR_OUTPUT) { $env:DFIR_OUTPUT } else { "C:\IR_Collection" }
$CaseNum      = if ($env:DFIR_CASE) { $env:DFIR_CASE } else { "CASE-$(Get-Date -Format yyyyMMdd)" }
$OutDir       = "$BasePath\NetCapture_${Hostname}_${Timestamp}"
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$LogFile      = "$BasePath\NetCapture_Execution.log"
$JsonFile     = "$BasePath\NetCapture_${Hostname}_${Timestamp}.json"
$ETLFile      = "$OutDir\capture_${Hostname}_${Timestamp}.etl"
$PCAPFile     = "$OutDir\capture_${Hostname}_${Timestamp}.pcap"
$PCAPngFile   = "$OutDir\capture_${Hostname}_${Timestamp}.pcapng"
$ToolsDir     = Split-Path (Split-Path $PSScriptRoot) -Parent
$ToolsDir     = Join-Path $ToolsDir "Tools"
New-Item -ItemType Directory -Path $ToolsDir -Force | Out-Null

function Write-Log { param([string]$M,[string]$L="INFO") Add-Content $LogFile "$(Get-Date -Format o) [$L] :: $M" }
function Write-Banner { param([string]$M,[string]$Color="Cyan") Write-Host "[*] $M" -ForegroundColor $Color }
function Write-OK     { param([string]$M) Write-Host "[+] $M" -ForegroundColor Green }
function Write-Warn   { param([string]$M) Write-Host "[!] $M" -ForegroundColor Yellow }
function Write-Fail   { param([string]$M) Write-Host "[!] $M" -ForegroundColor Red }

Write-Log "Network packet capture started | Case: $CaseNum | Duration: ${Duration}s | MaxSize: ${MaxSizeMB}MB"

#  Pre-flight checks 
Write-Banner "Running pre-flight checks..."

# Disk space check
$Drive      = Split-Path $OutDir -Qualifier
$DiskObj    = Get-PSDrive ($Drive -replace ":","") -ErrorAction SilentlyContinue
$FreeDiskMB = if ($DiskObj) { [math]::Round($DiskObj.Free/1MB) } else { 9999 }
$RequiredMB = $MaxSizeMB + 200

if ($FreeDiskMB -lt $RequiredMB) {
    Write-Fail "Insufficient disk space. Need ${RequiredMB}MB, have ${FreeDiskMB}MB free."
    Write-Log "Insufficient disk space: need ${RequiredMB}MB have ${FreeDiskMB}MB" "ERROR"
    exit 1
}
Write-OK "Disk space OK: ${FreeDiskMB}MB free (need ${RequiredMB}MB)"

# Stop any existing netsh trace
$ExistingTrace = (netsh trace show status 2>&1) -join " "
if ($ExistingTrace -match "Running") {
    Write-Warn "Existing netsh trace running - stopping it first..."
    netsh trace stop | Out-Null
    Start-Sleep -Seconds 2
    Write-Log "Stopped existing netsh trace"
}

# Record network state before capture
Write-Banner "Recording pre-capture network state..."
$PreCaptureConns = @(Get-NetTCPConnection -ErrorAction SilentlyContinue |
    Where-Object { $_.State -eq "Established" } |
    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess)

$PreCaptureTime = Get-Date

#  Start netsh trace 
Write-Banner "Starting netsh trace capture..."
Write-Host ""
Write-Host "  Duration  : $Duration seconds ($([math]::Round($Duration/60,1)) minutes)" -ForegroundColor White
Write-Host "  Max Size  : $MaxSizeMB MB" -ForegroundColor White
Write-Host "  Output    : $ETLFile" -ForegroundColor White
Write-Host "  Interface : $(if($Interface){'$Interface'}else{'All interfaces'})" -ForegroundColor White
Write-Host ""

# Build netsh command
$NetshArgs = @(
    "trace", "start",
    "capture=yes",
    "persistent=no",
    "traceFile=`"$ETLFile`"",
    "maxSize=$MaxSizeMB",
    "fileMode=single",
    "report=yes",
    "overwrite=yes"
)

# Add providers for comprehensive capture
$NetshArgs += "provider=Microsoft-Windows-TCPIP"
$NetshArgs += "provider=Microsoft-Windows-DNS-Client"
$NetshArgs += "provider=Microsoft-Windows-Winsock-AFD"
$NetshArgs += "provider=Microsoft-Windows-NDIS-PacketCapture"
$NetshArgs += "provider=Microsoft-Windows-HttpService"

if ($Interface) {
    $NetshArgs += "interfaceName=`"$Interface`""
}

Write-Log "Starting netsh trace: $($NetshArgs -join ' ')"

$StartResult = & netsh @NetshArgs 2>&1
Write-Log "netsh start result: $($StartResult -join ' ')"

if ($StartResult -match "Trace configuration") {
    Write-OK "netsh trace started successfully"
} else {
    # Fallback - minimal args
    Write-Warn "Full capture args failed - trying minimal configuration..."
    $FallbackResult = netsh trace start capture=yes traceFile="`"$ETLFile`"" maxSize=$MaxSizeMB overwrite=yes 2>&1
    Write-Log "Fallback result: $($FallbackResult -join ' ')"
    if ($FallbackResult -match "error|fail" -and $FallbackResult -notmatch "Trace configuration") {
        Write-Fail "netsh trace failed to start: $FallbackResult"
        Write-Log "netsh trace failed to start" "ERROR"
        exit 1
    }
    Write-OK "netsh trace started (minimal mode)"
}

#  Live countdown 
Write-Host ""
Write-Banner "Capturing network traffic..." "Yellow"
Write-Host "  Press Ctrl+C to stop early (capture will be saved)" -ForegroundColor Gray
Write-Host ""

$CaptureStart = Get-Date
$StoppedEarly = $false

try {
    $Intervals = [math]::Floor($Duration / 10)
    for ($i = 0; $i -lt $Intervals; $i++) {
        $Elapsed   = $i * 10
        $Remaining = $Duration - $Elapsed
        $Percent   = [math]::Round(($Elapsed / $Duration) * 100)
        $Bar       = "#" * [math]::Round($Percent / 5)
        $Empty     = "-" * (20 - [math]::Round($Percent / 5))
        Write-Host "`r  [$Bar$Empty] $Percent% | Elapsed: ${Elapsed}s | Remaining: ${Remaining}s    " -NoNewline -ForegroundColor Cyan
        Start-Sleep -Seconds 10
    }
    # Remaining seconds
    $RemainingFinal = $Duration - ($Intervals * 10)
    if ($RemainingFinal -gt 0) { Start-Sleep -Seconds $RemainingFinal }
    Write-Host "`r  [####################] 100% | Complete                              " -ForegroundColor Green
} catch {
    $StoppedEarly = $true
    Write-Host ""
    Write-Warn "Capture interrupted by user - saving collected data..."
    Write-Log "Capture stopped early by user"
}

$CaptureEnd      = Get-Date
$CaptureDuration = [math]::Round(($CaptureEnd - $CaptureStart).TotalSeconds)

#  Stop capture 
Write-Host ""
Write-Banner "Stopping capture..."
$StopResult = netsh trace stop 2>&1
Write-Log "netsh stop result: $($StopResult -join ' ')"

# Wait for ETL to be written
Start-Sleep -Seconds 5

if (-not (Test-Path $ETLFile)) {
    Write-Fail "ETL file not found after capture: $ETLFile"
    Write-Log "ETL file missing after capture" "ERROR"
    exit 1
}

$ETLSize   = [math]::Round((Get-Item $ETLFile).Length/1MB,2)
$ETLHash   = (Get-FileHash $ETLFile -Algorithm SHA256).Hash
Write-OK "ETL capture saved: ${ETLSize}MB | SHA256: $ETLHash"
Write-Log "ETL file: $ETLFile | Size: ${ETLSize}MB | SHA256: $ETLHash"

#  PCAP Conversion 
Write-Host ""
Write-Banner "Converting ETL to PCAP format..."

$ConversionResult = [PSCustomObject]@{
    Method       = $null
    Success      = $false
    PCAPFile     = $null
    PCAPSizeMB   = $null
    PCAPSHA256   = $null
    Error        = $null
}

# Method 1: pktmon etl2pcap (built-in Windows 10 2004+ / Server 2022+)
Write-Banner "Method 1: Trying pktmon etl2pcap (built-in)..."
$PktmonAvail = $null
try {
    $PktmonVersion = (pktmon --version 2>&1) -join " "
    $PktmonAvail   = $PktmonVersion -notmatch "not recognized|not found"
} catch { $PktmonAvail = $false }

if ($PktmonAvail) {
    try {
        Write-Log "Attempting pktmon etl2pcap conversion"
        $PktmonResult = pktmon etl2pcap $ETLFile --out $PCAPFile 2>&1
        Write-Log "pktmon result: $($PktmonResult -join ' ')"

        if (Test-Path $PCAPFile) {
            $ConversionResult.Method     = "pktmon etl2pcap (built-in)"
            $ConversionResult.Success    = $true
            $ConversionResult.PCAPFile   = $PCAPFile
            $ConversionResult.PCAPSizeMB = [math]::Round((Get-Item $PCAPFile).Length/1MB,2)
            $ConversionResult.PCAPSHA256 = (Get-FileHash $PCAPFile -Algorithm SHA256).Hash
            Write-OK "pktmon conversion successful: $($ConversionResult.PCAPSizeMB)MB"
            Write-Log "pktmon conversion OK: $PCAPFile | SHA256: $($ConversionResult.PCAPSHA256)"
        } else {
            Write-Warn "pktmon ran but no output file created"
            Write-Log "pktmon ran but no output file" "WARN"
        }
    } catch {
        Write-Warn "pktmon conversion failed: $_"
        Write-Log "pktmon failed: $_" "WARN"
    }
} else {
    Write-Warn "pktmon not available on this OS version - trying Method 2"
    Write-Log "pktmon not available"
}

# Method 2: etl2pcapng (auto-download from Microsoft GitHub)
if (-not $ConversionResult.Success) {
    Write-Banner "Method 2: etl2pcapng (Microsoft GitHub)..."

    $Etl2PcapNg = Join-Path $ToolsDir "etl2pcapng.exe"

    if (-not (Test-Path $Etl2PcapNg)) {
        Write-Banner "Downloading etl2pcapng from Microsoft GitHub..."
        Write-Log "etl2pcapng not found - attempting download"

        $DownloadSuccess = $false
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            $APIUrl   = "https://api.github.com/repos/microsoft/etl2pcapng/releases/latest"
            $Headers  = @{ "User-Agent" = "DFIR-Toolkit/4.0" }
            $Release  = Invoke-RestMethod -Uri $APIUrl -Headers $Headers -ErrorAction Stop

            $Asset = $Release.assets | Where-Object { $_.name -match "etl2pcapng.*\.exe$" -or $_.name -match "x64.*\.exe$" } | Select-Object -First 1
            if (-not $Asset) { $Asset = $Release.assets | Where-Object { $_.name -match "\.exe$" } | Select-Object -First 1 }

            if ($Asset) {
                Write-Banner "Downloading $($Asset.name) ($([math]::Round($Asset.size/1KB))KB)..."
                Invoke-WebRequest -Uri $Asset.browser_download_url -OutFile $Etl2PcapNg -Headers $Headers -ErrorAction Stop
                if (Test-Path $Etl2PcapNg) {
                    $DownloadSuccess = $true
                    Write-OK "etl2pcapng downloaded: $Etl2PcapNg"
                    Write-Log "etl2pcapng downloaded: $($Asset.browser_download_url)"
                }
            }
        } catch {
            Write-Warn "GitHub download failed: $_"
            Write-Log "etl2pcapng download failed: $_" "WARN"
        }

        # Fallback direct URL
        if (-not $DownloadSuccess) {
            try {
                Write-Banner "Trying direct download fallback..."
                $FallbackURL = "https://github.com/microsoft/etl2pcapng/releases/download/v1.10.0/etl2pcapng.exe"
                Invoke-WebRequest -Uri $FallbackURL -OutFile $Etl2PcapNg -ErrorAction Stop
                if (Test-Path $Etl2PcapNg) {
                    $DownloadSuccess = $true
                    Write-OK "etl2pcapng downloaded via fallback"
                    Write-Log "etl2pcapng downloaded via fallback URL"
                }
            } catch {
                Write-Warn "Fallback download also failed: $_"
                Write-Log "Fallback download failed: $_" "WARN"
            }
        }
    } else {
        Write-OK "etl2pcapng already in Tools folder"
    }

    # Run conversion
    if (Test-Path $Etl2PcapNg) {
        try {
            Write-Banner "Converting ETL to PCAPNG..."
            Write-Log "Running etl2pcapng: $Etl2PcapNg $ETLFile $PCAPngFile"
            $ConvArgs   = @($ETLFile, $PCAPngFile)
            $ConvResult = & $Etl2PcapNg @ConvArgs 2>&1
            Write-Log "etl2pcapng result: $($ConvResult -join ' ')"

            if (Test-Path $PCAPngFile) {
                $ConversionResult.Method     = "etl2pcapng (Microsoft GitHub)"
                $ConversionResult.Success    = $true
                $ConversionResult.PCAPFile   = $PCAPngFile
                $ConversionResult.PCAPSizeMB = [math]::Round((Get-Item $PCAPngFile).Length/1MB,2)
                $ConversionResult.PCAPSHA256 = (Get-FileHash $PCAPngFile -Algorithm SHA256).Hash
                Write-OK "etl2pcapng conversion successful: $($ConversionResult.PCAPSizeMB)MB"
                Write-Log "etl2pcapng OK: $PCAPngFile | SHA256: $($ConversionResult.PCAPSHA256)"
            } else {
                $ConversionResult.Error = "etl2pcapng ran but produced no output file"
                Write-Warn "etl2pcapng produced no output - ETL file retained for manual conversion"
                Write-Log "etl2pcapng no output" "WARN"
            }
        } catch {
            $ConversionResult.Error = $_.ToString()
            Write-Warn "etl2pcapng conversion failed: $_"
            Write-Log "etl2pcapng failed: $_" "WARN"
        }
    } else {
        $ConversionResult.Error = "etl2pcapng not available and could not be downloaded"
        Write-Warn "ETL conversion tools not available"
        Write-Log "No conversion tool available" "WARN"
    }
}

#  Post-capture network state 
Write-Banner "Recording post-capture network state..."
$PostCaptureConns = @(Get-NetTCPConnection -ErrorAction SilentlyContinue |
    Where-Object { $_.State -eq "Established" } |
    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess)

# New connections that appeared during capture
$NewConnections = @($PostCaptureConns | Where-Object {
    $Pre = $PreCaptureConns | Where-Object {
        $_.RemoteAddress -eq $_.RemoteAddress -and $_.RemotePort -eq $_.RemotePort
    }
    $null -eq $Pre
})

#  Capture summary 
Write-Host ""
Write-Host "========================================================" -ForegroundColor Magenta
Write-Host "  NETWORK CAPTURE COMPLETE" -ForegroundColor Magenta
Write-Host "========================================================" -ForegroundColor Magenta
Write-Host "  Case Number  : $CaseNum" -ForegroundColor Cyan
Write-Host "  Duration     : $CaptureDuration seconds$(if($StoppedEarly){' (stopped early)'})" -ForegroundColor Cyan
Write-Host "  ETL File     : $ETLFile ($ETLSize MB)" -ForegroundColor Cyan
Write-Host "  ETL SHA256   : $ETLHash" -ForegroundColor Cyan

if ($ConversionResult.Success) {
    Write-Host "  PCAP File    : $($ConversionResult.PCAPFile) ($($ConversionResult.PCAPSizeMB) MB)" -ForegroundColor Green
    Write-Host "  PCAP SHA256  : $($ConversionResult.PCAPSHA256)" -ForegroundColor Green
    Write-Host "  Converted By : $($ConversionResult.Method)" -ForegroundColor Green
} else {
    Write-Host "  PCAP Convert : FAILED - ETL file retained" -ForegroundColor Yellow
    Write-Host "  Manual Conv  : pktmon etl2pcap `"$ETLFile`" --out capture.pcap" -ForegroundColor Yellow
    Write-Host "                 OR: etl2pcapng.exe `"$ETLFile`" capture.pcapng" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "  Open in Wireshark:" -ForegroundColor Cyan
if ($ConversionResult.PCAPFile) {
    Write-Host "    wireshark `"$($ConversionResult.PCAPFile)`"" -ForegroundColor White
}
Write-Host "  Useful filters:" -ForegroundColor Cyan
Write-Host "    ip.addr == X.X.X.X          (filter by IP)" -ForegroundColor Gray
Write-Host "    tcp.port == 443              (filter by port)" -ForegroundColor Gray
Write-Host "    dns                          (show DNS queries)" -ForegroundColor Gray
Write-Host "    http or https                (web traffic)" -ForegroundColor Gray
Write-Host "    !(ip.dst == 10.0.0.0/8)     (external traffic only)" -ForegroundColor Gray
Write-Host "========================================================" -ForegroundColor Magenta

$Evidence = [PSCustomObject]@{
    ChainOfCustody      = [PSCustomObject]@{
        CaseNumber   = $CaseNum
        Hostname     = $Hostname
        CollectedAt  = (Get-Date).ToString("o")
        ToolVersion="1.0"
        IsAdmin      = $IsAdmin
    }
    ArtifactType        = "NetworkPacketCapture"
    CaptureMethod       = "netsh trace (Windows built-in kernel capture)"
    CaptureStart        = $CaptureStart.ToString("o")
    CaptureEnd          = $CaptureEnd.ToString("o")
    CaptureDurationSec  = $CaptureDuration
    StoppedEarly        = $StoppedEarly
    ETLFile             = $ETLFile
    ETLSizeMB           = $ETLSize
    ETLSHA256           = $ETLHash
    OutputDirectory     = $OutDir
    Conversion          = $ConversionResult
    PreCaptureConns     = $PreCaptureConns.Count
    PostCaptureConns    = $PostCaptureConns.Count
    NewConnectionsDuring= $NewConnections
    WiresharkFilters    = @{
        AllTraffic      = "Open $($ConversionResult.PCAPFile) in Wireshark"
        ExternalOnly    = "!(ip.dst == 10.0.0.0/8 or ip.dst == 192.168.0.0/16 or ip.dst == 172.16.0.0/12)"
        DNSQueries      = "dns"
        TCPConnections  = "tcp.flags.syn == 1 and tcp.flags.ack == 0"
        LargeTransfers  = "tcp.len > 1000"
        C2Indicators    = "tcp.port == 4444 or tcp.port == 8080 or tcp.port == 1337"
    }
    ManualConversion    = [PSCustomObject]@{
        pktmon      = "pktmon etl2pcap `"$ETLFile`" --out capture.pcap"
        etl2pcapng  = "etl2pcapng.exe `"$ETLFile`" capture.pcapng"
        NetworkMonitor = "Open ETL directly in Microsoft Network Monitor 3.4"
    }
}

$Evidence | ConvertTo-Json -Depth 7 | Out-File $JsonFile -Encoding UTF8
$Hash = Get-FileHash $JsonFile -Algorithm SHA256
[PSCustomObject]@{ FileName=$JsonFile; Hash=$Hash.Hash; Generated=(Get-Date).ToString("o") } |
    ConvertTo-Json | Out-File "$JsonFile.hash.json" -Encoding UTF8

Write-OK "JSON metadata: $JsonFile"
Write-Log "Completed | Duration: ${CaptureDuration}s | ETL: ${ETLSize}MB | Converted: $($ConversionResult.Success) | Method: $($ConversionResult.Method)"
