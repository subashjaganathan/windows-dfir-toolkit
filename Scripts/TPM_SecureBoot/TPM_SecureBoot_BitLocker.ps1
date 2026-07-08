#Requires -Version 5.1
<#
.SYNOPSIS
    Collects TPM, Secure Boot, BitLocker, and UEFI security artifacts.

.DESCRIPTION
    Enumerates Trusted Platform Module (TPM) status, Secure Boot
    configuration, BitLocker encryption state per volume, UEFI
    firmware settings, Device Guard, Credential Guard, and
    Virtualization Based Security (VBS) status.
    Critical for Windows 11 security posture assessment.

.COMPATIBILITY
    Windows 10 1607+  : Full
    Windows 11        : Full
    Server 2016+      : Full (TPM may not be present)

.IR_PHASE
    System Integrity / Security Posture

.MITRE_ATTCK
    T1542.001 - System Firmware
    T1553.002 - Code Signing
    T1486     - Data Encrypted (BitLocker abuse)

.FORENSIC_SAFETY
    Read-only, forensic-safe

.AUTHOR
    DFIR Toolkit

.VERSION
    2.0
#>

Set-StrictMode -Off
$ErrorActionPreference = "Continue"


# --- Shared toolkit module: single source of truth for version + base paths ---
$__DFIRMod = Join-Path $PSScriptRoot '..\Infrastructure\DFIR_Common.psm1'
if (Test-Path $__DFIRMod) { Import-Module $__DFIRMod -Force -ErrorAction SilentlyContinue }
if (-not $Global:DFIR_ToolVersion) { $Global:DFIR_ToolVersion = '1.0' }
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# -- OS Detection --------------------------------------------------------------
$OSInfo    = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
$OSCaption = $OSInfo.Caption
$IsServer  = $OSCaption -match "Server"
$OSBuild   = [int]$OSInfo.BuildNumber

$Timestamp    = Get-Date -Format "yyyyMMdd_HHmmss"
$Hostname     = $env:COMPUTERNAME
$BasePath     = if ($env:DFIR_OUTPUT) { $env:DFIR_OUTPUT } else { "C:\IR_Collection" }
$CaseNum      = if ($env:DFIR_CASE) { $env:DFIR_CASE } else { "CASE-$(Get-Date -Format yyyyMMdd)" }
New-Item -ItemType Directory -Path $BasePath -Force | Out-Null
$LogFile      = "$BasePath\TPM_SecureBoot_Execution.log"
$JsonFile     = "$BasePath\TPM_SecureBoot_${Hostname}_${Timestamp}.json"

function Write-Log { param([string]$M,[string]$L="INFO") Add-Content $LogFile "$(Get-Date -Format o) [$L] :: $M" }
Write-Log "TPM/SecureBoot collection started | Case: $CaseNum"

# -- TPM Status ----------------------------------------------------------------
Write-Host "[*] Collecting TPM information..." -ForegroundColor Cyan
$TPMData = [PSCustomObject]@{}
try {
    $TPM = Get-Tpm -ErrorAction Stop
    $TPMData = [PSCustomObject]@{
        TpmPresent           = $TPM.TpmPresent
        TpmReady             = $TPM.TpmReady
        TpmEnabled           = $TPM.TpmEnabled
        TpmActivated         = $TPM.TpmActivated
        TpmOwned             = $TPM.TpmOwned
        RestartPending       = $TPM.RestartPending
        ManufacturerId       = $TPM.ManufacturerId
        ManufacturerVersion  = $TPM.ManufacturerVersion
        ManagedAuthLevel     = $TPM.ManagedAuthLevel
        SpecVersion          = (Get-CimInstance -Namespace root\cimv2\security\microsofttpm -ClassName Win32_Tpm -ErrorAction SilentlyContinue).SpecVersion
    }
    Write-Log "TPM: Present=$($TPM.TpmPresent) Ready=$($TPM.TpmReady)"
} catch {
    $TPMData = [PSCustomObject]@{
        Error      = "TPM query failed: $_"
        Note       = if ($IsServer) { "Server OS - TPM may not be physically present in VM or rack server. Check BIOS/UEFI settings." } else { "TPM may not be present or accessible" }
        IsServer   = $IsServer
    }
    Write-Log "TPM query failed: $_" "WARN"
}

# -- Secure Boot ----------------------------------------------------------------
Write-Host "[*] Collecting Secure Boot status..." -ForegroundColor Cyan
$SecureBootData = [PSCustomObject]@{}
try {
    $SBState  = Confirm-SecureBootUEFI -ErrorAction Stop
    $SBPolicy = Get-SecureBootPolicy -ErrorAction SilentlyContinue
    $SecureBootData = [PSCustomObject]@{
        SecureBootEnabled    = $SBState
        PolicyPublisher      = $SBPolicy.Publisher
        PolicyVersion        = $SBPolicy.PolicyVersion
        UEFISecureBootDBX    = "Run 'Get-SecureBootUEFI -Name dbx' for revocation list"
    }
    Write-Log "Secure Boot: Enabled=$SBState"
} catch {
    $SecureBootData = [PSCustomObject]@{
        SecureBootEnabled = $false
        Note              = if ($IsServer) { "Secure Boot query failed on Server OS. Servers running as VMs may not support Secure Boot query via PS. Check hypervisor settings." } else { "Secure Boot not supported or BIOS/legacy boot mode." }
        IsServer          = $IsServer
    }
    Write-Log "Secure Boot query failed: $_" "WARN"
}

# -- BitLocker ------------------------------------------------------------------
Write-Host "[*] Collecting BitLocker status per volume..." -ForegroundColor Cyan
$BitLockerData = [System.Collections.Generic.List[PSCustomObject]]::new()
try {
    $BLVolumes = Get-BitLockerVolume -ErrorAction Stop
    foreach ($Vol in $BLVolumes) {
        $BitLockerData.Add([PSCustomObject]@{
            MountPoint           = $Vol.MountPoint
            VolumeType           = $Vol.VolumeType
            ProtectionStatus     = $Vol.ProtectionStatus
            EncryptionMethod     = $Vol.EncryptionMethod
            EncryptionPercentage = $Vol.EncryptionPercentage
            LockStatus           = $Vol.LockStatus
            AutoUnlockEnabled    = $Vol.AutoUnlockEnabled
            AutoUnlockKeyStored  = $Vol.AutoUnlockKeyStored
            KeyProtectors        = ($Vol.KeyProtector | ForEach-Object { $_.KeyProtectorType }) -join ", "
            VolumeStatus         = $Vol.VolumeStatus
        })
    }
    Write-Log "BitLocker volumes: $($BitLockerData.Count)"
} catch {
    $BitLockerData.Add([PSCustomObject]@{ Error = "BitLocker query failed: $_" })
    Write-Log "BitLocker query failed: $_" "WARN"
}

# -- Device Guard / Credential Guard / VBS -------------------------------------
Write-Host "[*] Collecting Device Guard and VBS status..." -ForegroundColor Cyan
$DeviceGuardData = [PSCustomObject]@{}
try {
    $DG = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop
    $DeviceGuardData = [PSCustomObject]@{
        VirtualizationBasedSecurityStatus     = switch ($DG.VirtualizationBasedSecurityStatus) {
            0 {"Not Enabled"} 1 {"Enabled but not running"} 2 {"Running"} default {"Unknown"}
        }
        RequiredSecurityProperties           = $DG.RequiredSecurityProperties
        AvailableSecurityProperties          = $DG.AvailableSecurityProperties
        SecurityServicesConfigured           = $DG.SecurityServicesConfigured
        SecurityServicesRunning              = $DG.SecurityServicesRunning
        CodeIntegrityPolicyEnforcementStatus = switch ($DG.CodeIntegrityPolicyEnforcementStatus) {
            0 {"Off"} 1 {"Audit"} 2 {"Enforced"} default {"Unknown"}
        }
        UsermodeCodeIntegrityPolicyStatus    = switch ($DG.UsermodeCodeIntegrityPolicyEnforcementStatus) {
            0 {"Off"} 1 {"Audit"} 2 {"Enforced"} default {"Unknown"}
        }
    }
    Write-Log "Device Guard VBS Status: $($DeviceGuardData.VirtualizationBasedSecurityStatus)"
} catch {
    $DeviceGuardData = [PSCustomObject]@{ Error = "Device Guard query failed: $_" }
    Write-Log "Device Guard query failed: $_" "WARN"
}

# -- UEFI / Boot Configuration --------------------------------------------------
Write-Host "[*] Collecting boot configuration..." -ForegroundColor Cyan
$BootConfig = [PSCustomObject]@{}
try {
    $BCDOut = (bcdedit /enum all 2>&1) -join "`n"
    $FirmwareType = if ($env:firmware_type) { $env:firmware_type } else {
        if (Test-Path "HKLM:\System\CurrentControlSet\Control\SecureBoot\State") { "UEFI" } else { "BIOS/Legacy" }
    }
    $BootConfig = [PSCustomObject]@{
        FirmwareType      = $FirmwareType
        BCDSummary        = ($BCDOut -split "`n" | Select-Object -First 50) -join "`n"
        SystemBCDPath     = "C:\Windows\Boot\BCD"
        BootStatusPolicy  = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -ErrorAction SilentlyContinue).AutoReboot
    }
    Write-Log "Boot config collected. Firmware: $FirmwareType"
} catch {
    $BootConfig = [PSCustomObject]@{ Error = "Boot config query failed: $_" }
    Write-Log "Boot config failed: $_" "WARN"
}

# -- Code Integrity / WDAC Policy ----------------------------------------------
Write-Host "[*] Checking Code Integrity policy..." -ForegroundColor Cyan
$CodeIntegrity = [PSCustomObject]@{
    CIPolicyPath         = "C:\Windows\System32\CodeIntegrity\SIPolicy.p7b"
    CIPolicyExists       = (Test-Path "C:\Windows\System32\CodeIntegrity\SIPolicy.p7b")
    CIAuditPolicyExists  = (Test-Path "C:\Windows\System32\CodeIntegrity\SIPolicy.p7b.bak")
    HVCIEnabled          = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -ErrorAction SilentlyContinue).Enabled
    WDACPolicies         = @(Get-ChildItem "C:\Windows\System32\CodeIntegrity\CiPolicies\Active" -ErrorAction SilentlyContinue | Select-Object Name, LastWriteTime)
}
Write-Log "Code Integrity: HVCI=$($CodeIntegrity.HVCIEnabled)"

$Evidence = [PSCustomObject]@{
    ChainOfCustody  = [PSCustomObject]@{ CaseNumber=$CaseNum; Hostname=$Hostname; CollectedAt=([DateTime]::UtcNow).ToString("o"); ToolVersion=$Global:DFIR_ToolVersion; IsAdmin=$IsAdmin }
    ArtifactType    = "TPM_SecureBoot_BitLocker"
    OSMode          = if ($IsServer) { "Server OS - TPM/SecureBoot may be limited in VM environments. BitLocker and DeviceGuard should still be present." } else { "Workstation OS - Full TPM/SecureBoot collection" }
    Compatibility   = "Windows 10 1607+ / Windows 11 / Server 2016+"
    TPM             = $TPMData
    SecureBoot      = $SecureBootData
    BitLocker       = $BitLockerData
    DeviceGuard_VBS = $DeviceGuardData
    BootConfig      = $BootConfig
    CodeIntegrity   = $CodeIntegrity
}

$Evidence | ConvertTo-Json -Depth 7 | Out-File -FilePath $JsonFile -Encoding UTF8
$Hash = Get-FileHash -Path $JsonFile -Algorithm SHA256
[PSCustomObject]@{ FileName=$JsonFile; Hash=$Hash.Hash; Generated=([DateTime]::UtcNow).ToString("o") } |
    ConvertTo-Json | Out-File "$JsonFile.hash.json" -Encoding UTF8

Write-Host "[+] TPM/SecureBoot/BitLocker collected" -ForegroundColor Green
Write-Host "[+] JSON: $JsonFile" -ForegroundColor Green
Write-Log "Completed"
