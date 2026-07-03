#Requires -Version 5.1
Set-StrictMode -Off
$ErrorActionPreference = "Continue"
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Hostname  = $env:COMPUTERNAME
$BasePath  = if ($env:DFIR_OUTPUT) { $env:DFIR_OUTPUT } else { "C:\IR_Collection" }
$CaseNum   = if ($env:DFIR_CASE) { $env:DFIR_CASE } else { "CASE-$(Get-Date -Format yyyyMMdd)" }
New-Item -ItemType Directory -Path $BasePath -Force | Out-Null
$LogFile  = "$BasePath\Registry_Deep_Execution.log"
$JsonFile = "$BasePath\Registry_Deep_Persistence_${Hostname}_${Timestamp}.json"

function Write-Log { param([string]$M,[string]$L="INFO") Add-Content $LogFile "$(Get-Date -Format o) [$L] :: $M" }
function Get-RegVal { param([string]$Path,[string]$Name) try { (Get-ItemProperty $Path -ErrorAction Stop).$Name } catch { $null } }
function Get-RegChildren { param([string]$Path) if (Test-Path $Path) { Get-ChildItem $Path -ErrorAction SilentlyContinue } }

# Resolve a DLL name/path to a full path under System32 when it is bare.
function Resolve-SystemDll { param([string]$Name)
    if (-not $Name) { return $null }
    $n = [Environment]::ExpandEnvironmentVariables([string]$Name).Trim().Trim('"')
    if ($n -notmatch '\.(dll|exe)$') { $n = "$n.dll" }
    if ([System.IO.Path]::IsPathRooted($n)) { return $n }
    $cand = Join-Path $env:SystemRoot "System32\$n"
    if (Test-Path $cand -ErrorAction SilentlyContinue) { return $cand }
    return $n
}
# A DLL is trusted (benign) when it lives under System32/SysWOW64 AND carries a valid
# Authenticode signature. This is the core false-positive filter: signed system DLLs
# referenced by time providers, netsh, KnownDLLs, port monitors are legitimate OS/OEM/VM
# components, not persistence, even when their names are not in a hardcoded baseline.
function Test-TrustedDll { param([string]$Name)
    try {
        $p = Resolve-SystemDll $Name
        if (-not $p -or -not (Test-Path $p -ErrorAction SilentlyContinue)) { return $false }
        if ($p -notmatch '(?i)\\Windows\\(System32|SysWOW64)\\') { return $false }
        $sig = Get-AuthenticodeSignature $p -ErrorAction SilentlyContinue
        return ($sig -and $sig.Status -eq 'Valid')
    } catch { return $false }
}

Write-Log "Deep registry persistence collection started | Case: $CaseNum"

$Findings = [System.Collections.Generic.List[PSCustomObject]]::new()
function Add-Finding { param($Category,$Key,$Value,$Risk)
    $Findings.Add([PSCustomObject]@{ Category=$Category; RegistryKey=$Key; Value=$Value; RiskLevel=$Risk; CollectionTime=(Get-Date).ToString("o") })
}

# Image File Execution Options (debugger hijacking)
Write-Host "[*] Checking Image File Execution Options..." -ForegroundColor Cyan
$IFEOKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
Get-RegChildren $IFEOKey | ForEach-Object {
    $Props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
    if ($Props.Debugger) {
        Add-Finding "IFEO_Debugger" $_.PSPath $Props.Debugger "CRITICAL"
    }
    if ($Props.GlobalFlag) {
        # GlobalFlag alone is legitimately set for app-compat / silent-exit on many
        # Microsoft apps; only the paired Debugger/SilentProcessExit is the real backdoor.
        Add-Finding "IFEO_GlobalFlag" $_.PSPath $Props.GlobalFlag "INFO"
    }
}

# Silent Process Exit
Write-Host "[*] Checking SilentProcessExit monitoring..." -ForegroundColor Cyan
$SPEKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit"
Get-RegChildren $SPEKey | ForEach-Object {
    $Props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
    if ($Props.MonitorProcess -or $Props.ReportingMode) {
        Add-Finding "SilentProcessExit" $_.PSPath "$($Props.MonitorProcess)" "HIGH"
    }
}

# AppCert DLLs
Write-Host "[*] Checking AppCert DLLs..." -ForegroundColor Cyan
$AppCertKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls"
if (Test-Path $AppCertKey) {
    $Props = Get-ItemProperty $AppCertKey -ErrorAction SilentlyContinue
    $Props.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object {
        Add-Finding "AppCertDLL" $AppCertKey "$($_.Name) = $($_.Value)" "CRITICAL"
    }
}

# AppInit DLLs (already in v2 but deeper check here)
Write-Host "[*] Checking AppInit DLLs..." -ForegroundColor Cyan
@("HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
  "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows") | ForEach-Object {
    $AppInit = Get-RegVal $_ "AppInit_DLLs"
    $Loaded  = Get-RegVal $_ "LoadAppInit_DLLs"
    if ($AppInit) { Add-Finding "AppInitDLL" $_ "$AppInit (LoadEnabled=$Loaded)" "CRITICAL" }
}

# Security Support Providers (SSP)
Write-Host "[*] Checking Security Support Providers..." -ForegroundColor Cyan
$LSAKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$SSPs   = Get-RegVal $LSAKey "Security Packages"
$AuthPkgs = Get-RegVal $LSAKey "Authentication Packages"
$NotifPkgs = Get-RegVal $LSAKey "Notification Packages"
# Baselines cover modern Win10/11 defaults plus common signed third parties (Citrix ctxauth).
$DefaultSSPs = @("kerberos","msv1_0","schannel","wdigest","tspkg","pku2u","cloudap","negoexts","ctxauth")
$DefaultAuth = @("msv1_0")
$DefaultNotif = @("scecli","rassfm")
if ($SSPs) {
    $SSPs | Where-Object { $_ -and ($_.ToLower() -notin $DefaultSSPs) -and $_ -ne '""' } | ForEach-Object {
        # A non-default SSP that resolves to a signed System32 DLL is far less likely malicious.
        $risk = if (Test-TrustedDll $_) { "MEDIUM" } else { "CRITICAL" }
        Add-Finding "SSP_NonDefault" $LSAKey $_ $risk
    }
}
if ($AuthPkgs) {
    $AuthPkgs | Where-Object { $_ -and ($_.ToLower() -notin $DefaultAuth) } | ForEach-Object {
        $risk = if (Test-TrustedDll $_) { "MEDIUM" } else { "CRITICAL" }
        Add-Finding "AuthPackage_NonDefault" $LSAKey $_ $risk
    }
}
# Notification Packages baseline is now actually compared (was previously collected but unused).
if ($NotifPkgs) {
    $NotifPkgs | Where-Object { $_ -and ($_.ToLower() -notin $DefaultNotif) } | ForEach-Object {
        $risk = if (Test-TrustedDll $_) { "MEDIUM" } else { "HIGH" }
        Add-Finding "NotificationPackage_NonDefault" $LSAKey $_ $risk
    }
}

# Time Provider DLLs
Write-Host "[*] Checking Time Providers..." -ForegroundColor Cyan
$TimeProvKey = "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders"
Get-RegChildren $TimeProvKey | ForEach-Object {
    $Props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
    # Signed System32 time-provider DLLs (Hyper-V, VMware, domain time) are legitimate.
    if ($Props.DllName -and -not (Test-TrustedDll $Props.DllName)) {
        Add-Finding "TimeProviderDLL" $_.PSPath $Props.DllName "HIGH"
    }
}

# Port Monitors
Write-Host "[*] Checking Port Monitors..." -ForegroundColor Cyan
$PortMonKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors"
Get-RegChildren $PortMonKey | ForEach-Object {
    $Props  = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
    $Driver = $Props.Driver
    $Default = @("Local Port","Standard TCP/IP Port","USB Monitor","WSD Port","BJ Language Monitor","PJL Language Monitor")
    # Signed System32 driver DLLs (OEM print monitors) are legitimate.
    if ($Driver -and ($_.PSChildName -notin $Default) -and -not (Test-TrustedDll $Driver)) {
        Add-Finding "PortMonitor" $_.PSPath "$($_.PSChildName) = $Driver" "HIGH"
    }
}

# Netsh Helper DLLs
Write-Host "[*] Checking Netsh Helpers..." -ForegroundColor Cyan
$NetshKey = "HKLM:\SOFTWARE\Microsoft\NetSh"
if (Test-Path $NetshKey) {
    Get-ItemProperty $NetshKey -ErrorAction SilentlyContinue |
        Select-Object -Property * -ExcludeProperty PS* |
        ForEach-Object { $_.PSObject.Properties | ForEach-Object {
            $KnownNetshDLLs = "netsh.dll|ifmon.dll|rasmontr.dll|rpcnsh.dll|whhelper.dll|winhttp.dll|wlstore.dll|p2pnetsh.dll|wcnetsh.dll|wshelper.dll|wshqos.dll|dot3cfg.dll|eapqec.dll|netiohlp.dll|dhcpcmonitor.dll|dnscmd.dll|fwcfg.dll|hnetmon.dll|napmontr.dll|peerdistsh.dll|authfwcfg.dll|wwancfg.dll|mbncfg.dll|wcmnetsh.dll|nettrace.dll|wfpnetsh.dll|bcastdvr.dll"
            # Skip empty values and DLLs that resolve to a signed System32 module.
            if ($_.Value -and ($_.Value -notmatch $KnownNetshDLLs) -and -not (Test-TrustedDll $_.Value)) {
                Add-Finding "NetshHelper" $NetshKey "$($_.Name) = $($_.Value)" "HIGH"
            }
        }}
}

# Accessibility Feature Hijacks (sethc/utilman)
Write-Host "[*] Checking Accessibility Feature backdoors..." -ForegroundColor Cyan
$AccKeys = @(
    @{ Key="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe"; Name="Debugger" }
    @{ Key="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe"; Name="Debugger" }
    @{ Key="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\osk.exe"; Name="Debugger" }
    @{ Key="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\narrator.exe"; Name="Debugger" }
    @{ Key="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\magnify.exe"; Name="Debugger" }
)
foreach ($AK in $AccKeys) {
    $Val = Get-RegVal $AK.Key $AK.Name
    if ($Val) { Add-Finding "Accessibility_Backdoor" $AK.Key $Val "CRITICAL" }
}

# Network Provider Order (credential capture)
Write-Host "[*] Checking Network Provider Order..." -ForegroundColor Cyan
$NetProvKey = "HKLM:\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order"
$NetProviders = Get-RegVal $NetProvKey "ProviderOrder"
$DefaultProviders = @("RDPNP","LanmanWorkstation","webclient")
if ($NetProviders) {
    $Providers = $NetProviders -split ","
    $First = $Providers[0].Trim()
    # VPN/endpoint clients legitimately insert themselves first; report as MEDIUM context.
    if ($First -notin $DefaultProviders) {
        Add-Finding "NetworkProvider_NonDefaultOrder" $NetProvKey $NetProviders "MEDIUM"
    }
}

# Known DLLs (process injection via KnownDLLs override)
Write-Host "[*] Checking KnownDLLs..." -ForegroundColor Cyan
$KnownDLLsKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs"
if (Test-Path $KnownDLLsKey) {
    $ExpectedDLLs = @("advapi32","clbcatq","combase","COMDLG32","coml2","DifxApi","GDI32","gdiplus","IMAGEHLP","IMM32","kernel32","MSCTF","MSVCRT","NORMALIZ","NSI","ole32","OLEAUT32","PSAPI","rpcrt4","sechost","Setupapi","SHELL32","SHLWAPI","USER32","USERENV","USP10","VERSION","WLDAP32","wow64","wow64cpu","wow64win","WS2_32")
    Get-ItemProperty $KnownDLLsKey -ErrorAction SilentlyContinue |
        Select-Object -Property * -ExcludeProperty PS* |
        ForEach-Object { $_.PSObject.Properties | ForEach-Object {
            # DllDirectory/DllDirectory32 are path strings, not DLLs; numeric names are indices.
            if ($_.Name -notin $ExpectedDLLs -and $_.Name -notmatch "^\d+$" -and
                $_.Name -notin @("DllDirectory","DllDirectory32") -and -not (Test-TrustedDll $_.Value)) {
                Add-Finding "KnownDLLs_NonDefault" $KnownDLLsKey "$($_.Name) = $($_.Value)" "HIGH"
            }
        }}
}

# Logon Scripts
Write-Host "[*] Checking Logon Scripts..." -ForegroundColor Cyan
$LogonScriptPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logon",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logon",
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\Scripts"
)
foreach ($LSPath in $LogonScriptPaths) {
    if (Test-Path $LSPath) {
        Get-ChildItem $LSPath -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
            $Props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
            if ($Props.Script) { Add-Finding "LogonScript" $_.PSPath $Props.Script "HIGH" }
        }
    }
}

# Shellbags
Write-Host "[*] Collecting Shellbags metadata..." -ForegroundColor Cyan
$ShellbagPaths = @(
    "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags",
    "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU",
    "HKCU:\SOFTWARE\Microsoft\Windows\Shell\BagMRU",
    "HKCU:\SOFTWARE\Microsoft\Windows\Shell\Bags"
)
$ShellbagCount = 0
foreach ($SBPath in $ShellbagPaths) {
    if (Test-Path $SBPath) {
        $Count = (Get-ChildItem $SBPath -Recurse -ErrorAction SilentlyContinue).Count
        $ShellbagCount += $Count
    }
}
$ShellbagInfo = [PSCustomObject]@{
    TotalEntries = $ShellbagCount
    Note         = "Shellbags record every folder ever browsed. Use ShellBagsExplorer (Eric Zimmerman) for full parsing."
    Paths        = $ShellbagPaths
}

# Recycle Bin metadata
Write-Host "[*] Collecting Recycle Bin metadata..." -ForegroundColor Cyan
$RecycleBinData = [System.Collections.Generic.List[PSCustomObject]]::new()
Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue | ForEach-Object {
    $RBPath = Join-Path $_.Root '$Recycle.Bin'
    if (Test-Path $RBPath -ErrorAction SilentlyContinue) {
        Get-ChildItem $RBPath -Force -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.Name.StartsWith('$I') } | ForEach-Object {
                $RecycleBinData.Add([PSCustomObject]@{
                    Drive        = $_.PSDrive
                    MetaFile     = $_.Name
                    FullPath     = $_.FullName
                    SizeBytes    = $_.Length
                    DeletedTime  = $_.LastWriteTimeUtc.ToString("o")
                    Note         = "Pair with matching `$R file for original content. Use RBCmd.exe (Eric Zimmerman)."
                })
            }
    }
}

$CriticalCount = ($Findings | Where-Object { $_.RiskLevel -eq "CRITICAL" }).Count
$HighCount     = ($Findings | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
Write-Log "Deep persistence findings: CRITICAL=$CriticalCount HIGH=$HighCount | Shellbags=$ShellbagCount | RecycleBin=$($RecycleBinData.Count)"

$Evidence = [PSCustomObject]@{
    ChainOfCustody   = [PSCustomObject]@{ CaseNumber=$CaseNum; Hostname=$Hostname; CollectedAt=(Get-Date).ToString("o"); ToolVersion="1.0" }
    ArtifactType     = "Registry_Deep_Persistence"
    CriticalFindings = $CriticalCount
    HighFindings     = $HighCount
    PersistenceFindings = $Findings
    Shellbags        = $ShellbagInfo
    RecycleBin       = $RecycleBinData
}

$Evidence | ConvertTo-Json -Depth 6 | Out-File -FilePath $JsonFile -Encoding UTF8
$Hash = Get-FileHash -Path $JsonFile -Algorithm SHA256
[PSCustomObject]@{ FileName=$JsonFile; Hash=$Hash.Hash; Generated=(Get-Date).ToString("o") } |
    ConvertTo-Json | Out-File "$JsonFile.hash.json" -Encoding UTF8

Write-Host "[+] Deep registry persistence complete | CRITICAL: $CriticalCount | HIGH: $HighCount | Shellbags: $ShellbagCount | RecycleBin: $($RecycleBinData.Count)" -ForegroundColor Green
Write-Host "[+] JSON: $JsonFile" -ForegroundColor Green
Write-Log "Completed"
