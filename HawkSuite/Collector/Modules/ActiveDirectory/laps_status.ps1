<#
.SYNOPSIS
    Module: laps_status - LAPS deployment/config status (legacy MS LAPS and
    Windows LAPS). RAW collection only - configuration metadata, never the
    managed password value. Graceful on hosts without LAPS.
#>
param([Parameter(Mandatory)][string]$SessionRoot, $Config)

Write-HawkLog 'laps_status: collection started'

$records = New-Object System.Collections.Generic.List[object]

function Get-LapsReg([string]$path, [string]$name) {
    try {
        $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($path)
        if ($k) { return $k.GetValue($name) }
    } catch {}
    $null
}

# (a) Legacy Microsoft LAPS (AdmPwd GPO CSE) config
$records.Add([ordered]@{
    recordType            = 'lapsConfig'
    lapsFlavor            = 'LegacyMsLaps'
    admPwdEnabled         = Get-LapsReg 'SOFTWARE\Policies\Microsoft Services\AdmPwd' 'AdmPwdEnabled'
    passwordComplexity    = Get-LapsReg 'SOFTWARE\Policies\Microsoft Services\AdmPwd' 'PasswordComplexity'
    passwordLength        = Get-LapsReg 'SOFTWARE\Policies\Microsoft Services\AdmPwd' 'PasswordLength'
    adminAccountName      = "$(Get-LapsReg 'SOFTWARE\Policies\Microsoft Services\AdmPwd' 'AdminAccountName')"
})

# (b) Windows LAPS (built into modern Windows)
$records.Add([ordered]@{
    recordType        = 'lapsConfig'
    lapsFlavor        = 'WindowsLaps'
    backupDirectory   = Get-LapsReg 'SOFTWARE\Microsoft\Policies\LAPS' 'BackupDirectory'
    passwordAgeDays   = Get-LapsReg 'SOFTWARE\Microsoft\Policies\LAPS' 'PasswordAgeDays'
    adminAccountName  = "$(Get-LapsReg 'SOFTWARE\Microsoft\Policies\LAPS' 'AdministratorAccountName')"
    lapsCseInstalled  = (Test-Path -LiteralPath (Join-Path $env:SystemRoot 'System32\laps.dll') -ErrorAction SilentlyContinue)
})

# (c) Whether this computer object exposes a LAPS password attribute (presence only, off-domain safe)
$partOfDomain = $false
try { $partOfDomain = (Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).PartOfDomain } catch {}
if ($partOfDomain) {
    try {
        $searcher = New-Object DirectoryServices.DirectorySearcher
        $searcher.Filter = "(&(objectCategory=computer)(cn=$env:COMPUTERNAME))"
        [void]$searcher.PropertiesToLoad.AddRange(@('ms-Mcs-AdmPwdExpirationTime','msLAPS-PasswordExpirationTime'))
        $res = $searcher.FindOne()
        if ($res) {
            $records.Add([ordered]@{
                recordType                 = 'lapsDirectoryState'
                legacyExpirationPresent    = [bool]$res.Properties['ms-mcs-admpwdexpirationtime'].Count
                windowsLapsExpirationPresent = [bool]$res.Properties['mslaps-passwordexpirationtime'].Count
            })
        }
    } catch { Write-HawkLog "laps_status: directory attribute check failed - $_" 'WARN' }
}

Export-HawkArtifact -SessionRoot $SessionRoot -ArtifactType 'laps_status' -Records $records
