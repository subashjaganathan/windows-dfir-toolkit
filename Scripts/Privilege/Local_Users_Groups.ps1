<#
.SYNOPSIS
    Collects local users and group memberships for DFIR investigations.

.DESCRIPTION
    Enumerates local user accounts and local group memberships to
    identify unauthorized accounts, privilege escalation, and
    persistence via valid accounts.

.IR_PHASE
    Privilege Escalation / Persistence / Investigation

.MITRE_ATTCK
    T1136.001 - Create Account: Local Account
    T1078    - Valid Accounts
    T1068    - Privilege Escalation
    T1021.001 - Remote Services: RDP

.FORENSIC_SAFETY
    Read-only, forensic-safe

.OUTPUT
    JSON evidence file + SHA256 hash
    Execution log

.AUTHOR
    DFIR Toolkit

.VERSION
    1.1
#>

Set-StrictMode -Off
$ErrorActionPreference = "Continue"

# =========================
# Privilege Awareness
# =========================
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# =========================
# Environment / Paths
# =========================
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Hostname  = $env:COMPUTERNAME
$CaseNum   = if ($env:DFIR_CASE) { $env:DFIR_CASE } else { "CASE-$(Get-Date -Format yyyyMMdd)" }
$BasePath  = if ($env:DFIR_OUTPUT) { $env:DFIR_OUTPUT } else { "C:\IR_Collection" }
$LogFile   = "$BasePath\Local_Users_Groups_Execution.log"

New-Item -ItemType Directory -Path $BasePath -Force | Out-Null

function Write-Log {
    param([string]$Message)
    Add-Content -Path $LogFile -Value "$(Get-Date -Format o) :: $Message"
}

Write-Log "Local users and groups collection started"
Write-Log "Administrator privileges: $IsAdmin"

if (-not $IsAdmin) {
    Write-Warning "[!] Administrator privileges recommended for full user and group visibility."
}

# =========================
# Local User Collection
# FIX: Added AccountExpires, PasswordLastSet, UserMayChangePassword, AccountSource
# =========================
Write-Host "[*] Collecting local users..." -ForegroundColor Cyan
Write-Log "Enumerating local users"

$Users = Get-LocalUser -ErrorAction SilentlyContinue

$UserData = foreach ($User in $Users) {
    [PSCustomObject]@{
        Hostname             = $Hostname
        CollectionTime       = (Get-Date).ToString("o")
        UserName             = $User.Name
        FullName             = $User.FullName
        Description          = $User.Description
        Enabled              = $User.Enabled
        PasswordRequired     = $User.PasswordRequired
        PasswordChangeable   = $User.UserMayChangePassword      # FIX: added
        PasswordLastSet      = if ($User.PasswordLastSet) { $User.PasswordLastSet.ToString("o") } else { $null }
        PasswordExpires      = if ($User.PasswordExpires) { $User.PasswordExpires.ToString("o") } else { $null }
        AccountExpires       = if ($User.AccountExpires) { $User.AccountExpires.ToString("o") } else { $null }  # FIX
        LastLogon            = if ($User.LastLogon) { $User.LastLogon.ToString("o") } else { $null }
        SID                  = $User.SID.Value
        PrincipalSource      = $User.PrincipalSource.ToString()  # FIX: Local vs AzureAD vs MicrosoftAccount
    }
}

Write-Log "Local users collected: $($UserData.Count)"

# =========================
# Local Group Collection
# FIX: v1.0 stored Members as an array mixed with an error string - inconsistent type.
#      Now consistently stored as array; errors recorded in MemberEnumError field.
# =========================
Write-Host "[*] Collecting local groups..." -ForegroundColor Cyan
Write-Log "Enumerating local groups"

$Groups = Get-LocalGroup -ErrorAction SilentlyContinue

$GroupData = foreach ($Group in $Groups) {

    $MemberList  = @()
    $MemberError = $null

    try {
        $MemberList = @(Get-LocalGroupMember -Group $Group.Name -ErrorAction Stop |
            Select-Object -Property Name, ObjectClass, PrincipalSource, SID)
    } catch {
        $MemberError = $_.Exception.Message
        Write-Log "WARNING: Could not enumerate members of '$($Group.Name)': $_"
    }

    [PSCustomObject]@{
        Hostname         = $Hostname
        CollectionTime   = (Get-Date).ToString("o")
        GroupName        = $Group.Name
        Description      = $Group.Description
        SID              = $Group.SID.Value                       # FIX: added group SID
        PrincipalSource  = $Group.PrincipalSource.ToString()
        MemberCount      = $MemberList.Count
        Members          = $MemberList
        MemberEnumError  = $MemberError
    }
}

Write-Log "Local groups collected: $($GroupData.Count)"

# =========================
# Unified Evidence Schema
# =========================
$JsonFile = "$BasePath\Local_Users_Groups_${Hostname}_${Timestamp}.json"
$HashFile = "$JsonFile.hash.json"

$Evidence = [PSCustomObject]@{
    ChainOfCustody = [PSCustomObject]@{ CaseNumber=$CaseNum; Hostname=$Hostname; CollectedAt=(Get-Date).ToString("o"); ToolVersion="1.0" }
    ArtifactType = "LocalUsersAndGroups"
    Hostname     = $Hostname
    CollectedAt  = (Get-Date).ToString("o")
    ToolVersion="1.0"
    UserCount    = $UserData.Count
    GroupCount   = $GroupData.Count
    Users        = $UserData
    Groups       = $GroupData
}

$Evidence | ConvertTo-Json -Depth 6 |
    Out-File -FilePath $JsonFile -Encoding UTF8

Write-Log "Local users and groups exported to JSON"

# =========================
# Evidence Integrity
# =========================
$Hash = Get-FileHash -Path $JsonFile -Algorithm SHA256

[PSCustomObject]@{
    FileName  = $JsonFile
    Algorithm = $Hash.Algorithm
    Hash      = $Hash.Hash
    Generated = (Get-Date).ToString("o")
} | ConvertTo-Json | Out-File -FilePath $HashFile -Encoding UTF8

Write-Log "SHA256 hash generated"

Write-Host "[+] Local users and groups collection completed" -ForegroundColor Green
Write-Host "    Users : $($UserData.Count) | Groups: $($GroupData.Count)"  -ForegroundColor Cyan
Write-Host "[+] JSON Output  : $JsonFile"  -ForegroundColor Green
Write-Host "[+] Hash Output  : $HashFile"  -ForegroundColor Green
Write-Host "[+] Execution Log: $LogFile"   -ForegroundColor Green

Write-Log "Script execution completed"
