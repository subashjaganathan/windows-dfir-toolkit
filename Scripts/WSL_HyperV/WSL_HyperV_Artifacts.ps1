#Requires -Version 5.1
Set-StrictMode -Off
$ErrorActionPreference = "Continue"
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Hostname  = $env:COMPUTERNAME
$BasePath  = if ($env:DFIR_OUTPUT) { $env:DFIR_OUTPUT } else { "C:\IR_Collection" }
$CaseNum   = if ($env:DFIR_CASE) { $env:DFIR_CASE } else { "CASE-$(Get-Date -Format yyyyMMdd)" }
New-Item -ItemType Directory -Path $BasePath -Force | Out-Null
$LogFile  = "$BasePath\WSL_HyperV_Execution.log"
$JsonFile = "$BasePath\WSL_HyperV_${Hostname}_${Timestamp}.json"

function Write-Log { param([string]$M,[string]$L="INFO") Add-Content $LogFile "$(Get-Date -Format o) [$L] :: $M" }
Write-Log "WSL/Hyper-V collection started | Case: $CaseNum"

# WSL Installations
Write-Host "[*] Collecting WSL artifacts..." -ForegroundColor Cyan
$WSLData = [PSCustomObject]@{ Installed = $false }
try {
    $WSLOut = (wsl --list --verbose 2>&1) -join "`n"
    $WSLInstalled = $WSLOut -notmatch "not installed|not recognized"
    if ($WSLInstalled) {
        $Distros = [System.Collections.Generic.List[PSCustomObject]]::new()
        $WSLOut -split "`n" | Select-Object -Skip 1 | ForEach-Object {
            if ($_ -match "(\*?)\s+(\S+)\s+(\S+)\s+(\d+)") {
                $Distros.Add([PSCustomObject]@{
                    Default  = $Matches[1] -eq "*"
                    Name     = $Matches[2]
                    State    = $Matches[3]
                    Version  = $Matches[4]
                })
            }
        }
        # WSL filesystem locations
        $WSLPaths = @(Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            "$($_.FullName)\AppData\Local\Packages" } | Where-Object { Test-Path $_ } | ForEach-Object {
            Get-ChildItem $_ -Directory -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match "Ubuntu|Debian|Kali|openSUSE|Alpine|SUSE|Oracle|fedora" } |
                ForEach-Object { [PSCustomObject]@{ User=(Split-Path (Split-Path (Split-Path $_)) -Leaf); Package=$_.Name; Path=$_.FullName } }
        })

        # Check for suspicious files in WSL filesystems
        $SuspiciousWSLFiles = [System.Collections.Generic.List[PSCustomObject]]::new()
        foreach ($WSLPkg in $WSLPaths) {
            $FSRoot = "$($WSLPkg.Path)\LocalState\rootfs"
            if (Test-Path $FSRoot) {
                $SuspPaths = @("$FSRoot\tmp","$FSRoot\var\tmp","$FSRoot\dev\shm","$FSRoot\root")
                foreach ($SP in $SuspPaths) {
                    if (Test-Path $SP) {
                        Get-ChildItem $SP -ErrorAction SilentlyContinue | ForEach-Object {
                            $SuspiciousWSLFiles.Add([PSCustomObject]@{
                                Distro   = $WSLPkg.Package
                                Path     = $_.FullName
                                Name     = $_.Name
                                Size     = $_.Length
                                Modified = $_.LastWriteTimeUtc.ToString("o")
                            })
                        }
                    }
                }
            }
        }

        # WSL bash history
        $WSLHistory = [System.Collections.Generic.List[PSCustomObject]]::new()
        foreach ($WSLPkg in $WSLPaths) {
            $HistPaths = @(
                "$($WSLPkg.Path)\LocalState\rootfs\root\.bash_history",
                "$($WSLPkg.Path)\LocalState\rootfs\home\*\.bash_history"
            )
            foreach ($HP in $HistPaths) {
                $HistFiles = @(Get-Item $HP -ErrorAction SilentlyContinue)
                foreach ($HF in $HistFiles) {
                    if (Test-Path $HF) {
                        $Commands = @(Get-Content $HF -ErrorAction SilentlyContinue)
                        $WSLHistory.Add([PSCustomObject]@{
                            Distro    = $WSLPkg.Package
                            HistFile  = $HF
                            Commands  = $Commands
                            Count     = $Commands.Count
                        })
                    }
                }
            }
        }

        $WSLData = [PSCustomObject]@{
            Installed          = $true
            Distros            = $Distros
            DistroPackages     = $WSLPaths
            SuspiciousFiles    = $SuspiciousWSLFiles
            BashHistory        = $WSLHistory
            WSLVersion         = (wsl --version 2>&1) -join " "
            WSLNetworkAdapter  = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Name -match "WSL|vEthernet" } | Select-Object Name, Status, MacAddress)
        }
        Write-Log "WSL: Installed | Distros=$($Distros.Count) | SuspFiles=$($SuspiciousWSLFiles.Count) | History=$($WSLHistory.Count)"
    }
} catch { Write-Log "WSL collection failed: $_" "WARN" }

# Hyper-V VMs
Write-Host "[*] Collecting Hyper-V virtual machine inventory..." -ForegroundColor Cyan
$HyperVData = [PSCustomObject]@{ Available = $false }
try {
    $HVService = Get-Service vmms -ErrorAction Stop
    $HVRunning = $HVService.Status -eq "Running"

    if ($HVRunning) {
        $VMs = @(Get-VM -ErrorAction SilentlyContinue | ForEach-Object {
            [PSCustomObject]@{
                VMName          = $_.Name
                State           = $_.State.ToString()
                CPUUsage        = $_.CPUUsage
                MemoryMB        = $_.MemoryAssigned / 1MB
                UptimeSeconds   = $_.Uptime.TotalSeconds
                CreationTime    = $_.CreationTime.ToString("o")
                ConfigPath      = $_.ConfigurationLocation
                CheckpointCount = ($_.Checkpoints | Measure-Object).Count
                Generation      = $_.Generation
                SecureBoot      = (Get-VMFirmware $_.Name -ErrorAction SilentlyContinue).SecureBoot
                NetworkAdapters = @($_.NetworkAdapters | Select-Object SwitchName, MacAddress, IPAddresses)
                HDDs            = @(Get-VMHardDiskDrive $_.Name -ErrorAction SilentlyContinue | Select-Object Path, Size)
            }
        })

        # Snapshots/Checkpoints
        $Checkpoints = @(Get-VM -ErrorAction SilentlyContinue | ForEach-Object {
            $VMName = $_.Name
            Get-VMSnapshot $_.Name -ErrorAction SilentlyContinue | ForEach-Object {
                [PSCustomObject]@{ VM=$VMName; Snapshot=$_.Name; Created=$_.CreationTime.ToString("o"); IsCurrent=$_.IsCurrent }
            }
        })

        $HyperVData = [PSCustomObject]@{
            Available       = $true
            ServiceStatus   = $HVService.Status.ToString()
            VMCount         = $VMs.Count
            VMs             = $VMs
            Checkpoints     = $Checkpoints
            HyperVVersion   = (Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -ErrorAction SilentlyContinue).Version
        }
        Write-Log "Hyper-V: VMs=$($VMs.Count) | Checkpoints=$($Checkpoints.Count)"
    } else {
        $HyperVData = [PSCustomObject]@{ Available=$true; ServiceStatus="Stopped"; Note="Hyper-V installed but not running" }
    }
} catch { Write-Log "Hyper-V not available: $_" "WARN" }

# Windows Sandbox - Get-WindowsOptionalFeature requires elevation and THROWS a terminating
# error when not admin, so it must be wrapped (this aborted the whole module non-elevated).
$SandboxInstalled = "Unknown (requires admin)"
try {
    $sb = Get-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM -ErrorAction Stop
    $SandboxInstalled = ($sb.State -eq "Enabled")
} catch { Write-Log "Windows Sandbox feature query needs elevation - skipped: $_" "WARN" }

# Docker Desktop
$DockerData = [PSCustomObject]@{ Installed = $false }
try {
    $DockerService = Get-Service com.docker.service -ErrorAction SilentlyContinue
    if ($DockerService) {
        $DockerOut = (docker ps -a 2>&1) -join "`n"
        $DockerData = [PSCustomObject]@{
            Installed     = $true
            ServiceStatus = $DockerService.Status.ToString()
            Containers    = ($DockerOut -split "`n" | Select-Object -Skip 1 | Where-Object { $_ }).Count
            RawOutput     = $DockerOut
        }
        Write-Log "Docker: Installed | Status=$($DockerService.Status)"
    }
} catch { Write-Log "Docker query failed: $_" "WARN" }

$Evidence = [PSCustomObject]@{
    ChainOfCustody  = [PSCustomObject]@{ CaseNumber=$CaseNum; Hostname=$Hostname; CollectedAt=(Get-Date).ToString("o"); ToolVersion="1.0" }
    ArtifactType    = "WSL_HyperV_Virtualization"
    WSL             = $WSLData
    HyperV          = $HyperVData
    WindowsSandbox  = [PSCustomObject]@{ Installed=$SandboxInstalled }
    Docker          = $DockerData
}

$Evidence | ConvertTo-Json -Depth 8 | Out-File -FilePath $JsonFile -Encoding UTF8
$Hash = Get-FileHash -Path $JsonFile -Algorithm SHA256
[PSCustomObject]@{ FileName=$JsonFile; Hash=$Hash.Hash; Generated=(Get-Date).ToString("o") } |
    ConvertTo-Json | Out-File "$JsonFile.hash.json" -Encoding UTF8

Write-Host "[+] WSL/Hyper-V collected | WSL: $($WSLData.Installed) | Hyper-V: $($HyperVData.Available) | Docker: $($DockerData.Installed)" -ForegroundColor Green
Write-Host "[+] JSON: $JsonFile" -ForegroundColor Green
Write-Log "Completed"
