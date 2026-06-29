<#
.SYNOPSIS
    Module: bitlocker_tpm - BitLocker volume, TPM, and Secure Boot status.
    RAW collection only. recordType discriminates source. Degrades on VMs/legacy.
#>
param([Parameter(Mandatory)][string]$SessionRoot, $Config)

Write-HawkLog 'bitlocker_tpm: collection started'

$records = New-Object System.Collections.Generic.List[object]

# (a) BitLocker volumes
$gotBitlocker = $false
try {
    foreach ($v in (Get-BitLockerVolume -ErrorAction Stop)) {
        $gotBitlocker = $true
        $kp = $null
        try { $kp = (($v.KeyProtector | ForEach-Object { "$($_.KeyProtectorType)" }) -join ', ') } catch {}
        $records.Add([ordered]@{
            recordType           = 'bitlockerVolume'
            mountPoint           = $v.MountPoint
            volumeStatus         = "$($v.VolumeStatus)"
            protectionStatus     = "$($v.ProtectionStatus)"
            encryptionPercentage = $v.EncryptionPercentage
            encryptionMethod     = "$($v.EncryptionMethod)"
            keyProtectorTypes    = $kp
        })
    }
} catch { Write-HawkLog "bitlocker_tpm: Get-BitLockerVolume unavailable - $_" 'WARN' }

if (-not $gotBitlocker) {
    # Fallback: manage-bde -status text parse
    try {
        $raw = (manage-bde -status 2>$null) -join "`n"
        if ($raw) {
            $records.Add([ordered]@{ recordType = 'bitlockerVolume'; mountPoint = 'see-rawText'
                volumeStatus = $null; protectionStatus = $null; encryptionPercentage = $null
                encryptionMethod = $null; keyProtectorTypes = $null; rawText = $raw })
        }
    } catch {}
}

# (b) TPM
try {
    $tpm = Get-Tpm -ErrorAction Stop
    $records.Add([ordered]@{
        recordType       = 'tpm'
        tpmPresent       = $tpm.TpmPresent
        tpmReady         = $tpm.TpmReady
        tpmEnabled       = $tpm.TpmEnabled
        manufacturerId   = "$($tpm.ManufacturerIdTxt)"
        managedAuthLevel = "$($tpm.ManagedAuthLevel)"
    })
} catch { Write-HawkLog "bitlocker_tpm: Get-Tpm unavailable - $_" 'WARN' }

# (c) Secure Boot
$sb = 'unsupported'
try { $sb = [bool](Confirm-SecureBootUEFI -ErrorAction Stop) } catch { $sb = 'unsupported' }
$records.Add([ordered]@{ recordType = 'secureBoot'; secureBootEnabled = $sb })

Export-HawkArtifact -SessionRoot $SessionRoot -ArtifactType 'bitlocker_tpm' -Records $records
