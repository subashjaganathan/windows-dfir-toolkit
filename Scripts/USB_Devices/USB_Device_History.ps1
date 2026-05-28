#Requires -Version 5.1
Set-StrictMode -Off
$ErrorActionPreference = "Continue"
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Hostname  = $env:COMPUTERNAME
$BasePath  = if ($env:DFIR_OUTPUT) { $env:DFIR_OUTPUT } else { "C:\IR_Collection" }
$CaseNum   = if ($env:DFIR_CASE) { $env:DFIR_CASE } else { "CASE-$(Get-Date -Format yyyyMMdd)" }
New-Item -ItemType Directory -Path $BasePath -Force | Out-Null
$LogFile   = "$BasePath\USB_Devices_Execution.log"
$JsonFile  = "$BasePath\USB_Devices_${Hostname}_${Timestamp}.json"

function Write-Log { param([string]$M,[string]$L="INFO") Add-Content $LogFile "$(Get-Date -Format o) [$L] :: $M" }
Write-Log "USB/Device collection started | Case: $CaseNum"

# USB USBSTOR History
Write-Host "[*] Collecting USB device history..." -ForegroundColor Cyan
$USBHistory = [System.Collections.Generic.List[PSCustomObject]]::new()
$USBStorKey = "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR"
if (Test-Path $USBStorKey) {
    Get-ChildItem $USBStorKey -ErrorAction SilentlyContinue | ForEach-Object {
        $DevType = $_.PSChildName
        Get-ChildItem $_.PSPath -ErrorAction SilentlyContinue | ForEach-Object {
            $DevInst = $_.PSChildName
            $Props   = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
            $SerialNum = $DevInst -replace "&.$",""
            $USBHistory.Add([PSCustomObject]@{
                DeviceType   = $DevType
                InstanceID   = $DevInst
                SerialNumber = $SerialNum
                FriendlyName = $Props.FriendlyName
                Manufacturer = $Props.Mfg
                DeviceDesc   = $Props.DeviceDesc
                HardwareID   = if ($Props.HardwareID) { $Props.HardwareID[0] } else { $null }
            })
        }
    }
}

# USB Raw devices
$USBRaw = [System.Collections.Generic.List[PSCustomObject]]::new()
$USBKey = "HKLM:\SYSTEM\CurrentControlSet\Enum\USB"
if (Test-Path $USBKey) {
    Get-ChildItem $USBKey -ErrorAction SilentlyContinue | ForEach-Object {
        $VIDPID = $_.PSChildName
        Get-ChildItem $_.PSPath -ErrorAction SilentlyContinue | ForEach-Object {
            $Props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
            $USBRaw.Add([PSCustomObject]@{
                VIDPID       = $VIDPID
                InstanceID   = $_.PSChildName
                FriendlyName = $Props.FriendlyName
                DeviceDesc   = $Props.DeviceDesc
                Class        = $Props.Class
            })
        }
    }
}

# Mounted Devices history
Write-Host "[*] Collecting drive assignment history..." -ForegroundColor Cyan
$MountedDevices = [System.Collections.Generic.List[PSCustomObject]]::new()
$MDKey = "HKLM:\SYSTEM\MountedDevices"
if (Test-Path $MDKey) {
    Get-ItemProperty $MDKey -ErrorAction SilentlyContinue | ForEach-Object {
        $_.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object {
            $MountedDevices.Add([PSCustomObject]@{
                MountPoint = $_.Name
                DataLength = if ($_.Value -is [byte[]]) { $_.Value.Length } else { 0 }
            })
        }
    }
}

# SetupAPI log
Write-Host "[*] Collecting device installation log..." -ForegroundColor Cyan
$SetupApiLog  = "$env:SystemRoot\INF\setupapi.dev.log"
$SetupApiData = [PSCustomObject]@{ Exists = $false }
if (Test-Path $SetupApiLog) {
    $LogContent   = Get-Content $SetupApiLog -ErrorAction SilentlyContinue
    $USBInstalls  = @($LogContent | Where-Object { $_ -match "USBSTOR|USB\\VID" } | Select-Object -First 200)
    $SetupApiData = [PSCustomObject]@{
        Exists     = $true
        Path       = $SetupApiLog
        SizeBytes  = (Get-Item $SetupApiLog).Length
        USBEntries = $USBInstalls.Count
        USBLines   = $USBInstalls
    }
}

# Kernel Drivers
Write-Host "[*] Collecting kernel driver inventory..." -ForegroundColor Cyan
$Drivers = [System.Collections.Generic.List[PSCustomObject]]::new()
Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue | ForEach-Object {
    $DrvPath = $_.PathName
    if ($DrvPath) { $DrvPath = $DrvPath -replace '"','' }
    if ($DrvPath) { $DrvPath = $DrvPath.Replace("\SystemRoot\",$env:SystemRoot+"\") }
    $CleanPath = ($DrvPath -split " ")[0]
    if ($CleanPath) { $CleanPath = $CleanPath -replace "^\\[?]\\","" }
    if ($CleanPath -and $CleanPath -notmatch "^[A-Za-z]:") { $CleanPath = $null }
    $SigStatus = "Unknown"
    $FileHash  = $null
    if ($CleanPath -and (Test-Path $CleanPath -ErrorAction SilentlyContinue)) {
        try {
            $Sig       = Get-AuthenticodeSignature $CleanPath -ErrorAction SilentlyContinue
            $SigStatus = if ($Sig) { $Sig.Status.ToString() } else { "Unknown" }
            $FileHash  = (Get-FileHash $CleanPath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
        } catch {}
    }
    $Drivers.Add([PSCustomObject]@{
        Name            = $_.Name
        DisplayName     = $_.DisplayName
        State           = $_.State
        StartMode       = $_.StartMode
        PathName        = $_.PathName
        SHA256          = $FileHash
        SignatureStatus = $SigStatus
        IsSuspicious    = ($SigStatus -ne "Valid" -and $_.State -eq "Running")
    })
}
$UnsignedRunning = ($Drivers | Where-Object { $_.IsSuspicious }).Count

# WER Crash Reports
Write-Host "[*] Collecting WER crash report metadata..." -ForegroundColor Cyan
$WERData  = [System.Collections.Generic.List[PSCustomObject]]::new()
$WERPaths = @(
    "C:\ProgramData\Microsoft\Windows\WER\ReportArchive",
    "C:\ProgramData\Microsoft\Windows\WER\ReportQueue",
    "$env:LOCALAPPDATA\Microsoft\Windows\WER\ReportArchive"
)
foreach ($WERPath in $WERPaths) {
    if (-not (Test-Path $WERPath)) { continue }
    Get-ChildItem $WERPath -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $WERFiles = @(Get-ChildItem $_.FullName -ErrorAction SilentlyContinue)
        $WERMeta  = $WERFiles | Where-Object { $_.Extension -eq ".wer" } | Select-Object -First 1
        $AppName  = $null
        if ($WERMeta) {
            $Lines   = Get-Content $WERMeta.FullName -ErrorAction SilentlyContinue | Select-Object -First 30
            $AppName = ($Lines | Where-Object { $_ -match "^AppName=" }) -replace "AppName=",""
        }
        $WERData.Add([PSCustomObject]@{
            ReportName   = $_.Name
            ReportPath   = $_.FullName
            CreationTime = $_.CreationTimeUtc.ToString("o")
            AppName      = $AppName
            FileCount    = $WERFiles.Count
            HasDump      = ($WERFiles | Where-Object { $_.Extension -eq ".dmp" }).Count -gt 0
        })
    }
}

# Currently connected devices
$ConnectedDevices = @(Get-PnpDevice -ErrorAction SilentlyContinue |
    Where-Object { $_.Status -eq "OK" -and $_.Class -in @("USB","DiskDrive","CDROM","Image","Biometric","Bluetooth","Net") } |
    Select-Object FriendlyName, Class, Status, DeviceID, Manufacturer)

Write-Log "USB History: $($USBHistory.Count) | Drivers: $($Drivers.Count) | Unsigned+Running: $UnsignedRunning | WER: $($WERData.Count)"

$Evidence = [PSCustomObject]@{
    ChainOfCustody         = [PSCustomObject]@{ CaseNumber=$CaseNum; Hostname=$Hostname; CollectedAt=(Get-Date).ToString("o"); ToolVersion="1.0" }
    ArtifactType           = "USB_Device_Driver_WER"
    USBStorHistory         = $USBHistory
    USBRawDevices          = $USBRaw
    MountedDevices         = $MountedDevices
    SetupAPILog            = $SetupApiData
    KernelDrivers          = $Drivers
    UnsignedRunningDrivers = $UnsignedRunning
    WERCrashReports        = $WERData
    CurrentDevices         = $ConnectedDevices
}

$Evidence | ConvertTo-Json -Depth 6 | Out-File -FilePath $JsonFile -Encoding UTF8
$Hash = Get-FileHash -Path $JsonFile -Algorithm SHA256
[PSCustomObject]@{ FileName=$JsonFile; Hash=$Hash.Hash; Generated=(Get-Date).ToString("o") } |
    ConvertTo-Json | Out-File "$JsonFile.hash.json" -Encoding UTF8

Write-Host "[+] USB/Device collection complete | USB: $($USBHistory.Count) | Drivers: $($Drivers.Count) | Unsigned+Running: $UnsignedRunning | WER: $($WERData.Count)" -ForegroundColor Green
Write-Host "[+] JSON: $JsonFile" -ForegroundColor Green
Write-Log "Completed"
