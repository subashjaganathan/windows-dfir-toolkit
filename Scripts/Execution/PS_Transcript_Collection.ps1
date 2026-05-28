#Requires -Version 5.1
Set-StrictMode -Off
$ErrorActionPreference = "Continue"

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Hostname  = $env:COMPUTERNAME
$BasePath  = if ($env:DFIR_OUTPUT) { $env:DFIR_OUTPUT } else { "C:\IR_Collection" }
$CaseNum   = if ($env:DFIR_CASE) { $env:DFIR_CASE } else { "CASE-$(Get-Date -Format yyyyMMdd)" }
New-Item -ItemType Directory -Path $BasePath -Force | Out-Null
$LogFile  = "$BasePath\PS_Transcripts_Execution.log"
$JsonFile = "$BasePath\PS_Transcripts_${Hostname}_${Timestamp}.json"
$OutDir   = "$BasePath\PS_Transcripts_${Hostname}_${Timestamp}"
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

function Write-Log { param([string]$M,[string]$L="INFO") Add-Content $LogFile "$(Get-Date -Format o) [$L] :: $M" }
Write-Log "PS Transcript collection started | Case: $CaseNum"

Write-Host "[*] Checking PowerShell transcription configuration..." -ForegroundColor Cyan

# Check if transcription is enabled
$TranscriptConfig = [PSCustomObject]@{
    MachineEnabled       = $false
    MachineOutputDir     = $null
    UserEnabled          = $false
    UserOutputDir        = $null
}

$PSPolicyKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
if (Test-Path $PSPolicyKey) {
    $Props = Get-ItemProperty $PSPolicyKey -ErrorAction SilentlyContinue
    $TranscriptConfig.MachineEnabled   = ($Props.EnableTranscripting -eq 1)
    $TranscriptConfig.MachineOutputDir = $Props.OutputDirectory
}
$PSPolicyKeyUser = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
if (Test-Path $PSPolicyKeyUser) {
    $Props2 = Get-ItemProperty $PSPolicyKeyUser -ErrorAction SilentlyContinue
    $TranscriptConfig.UserEnabled   = ($Props2.EnableTranscripting -eq 1)
    $TranscriptConfig.UserOutputDir = $Props2.OutputDirectory
}

Write-Log "Transcription: Machine=$($TranscriptConfig.MachineEnabled) | Dir=$($TranscriptConfig.MachineOutputDir)"

# Known transcript locations to search
$SearchPaths = [System.Collections.Generic.List[string]]::new()

# From policy config
if ($TranscriptConfig.MachineOutputDir -and (Test-Path $TranscriptConfig.MachineOutputDir)) {
    $SearchPaths.Add($TranscriptConfig.MachineOutputDir)
}
if ($TranscriptConfig.UserOutputDir -and (Test-Path $TranscriptConfig.UserOutputDir)) {
    $SearchPaths.Add($TranscriptConfig.UserOutputDir)
}

# Default locations
$DefaultPaths = @(
    "$env:SystemDrive\Transcripts",
    "$env:SystemDrive\PSTranscripts",
    "$env:ProgramData\PowerShell\Transcripts",
    "$env:SystemRoot\System32\config\systemprofile\Documents",
    "$env:SystemRoot\SysWOW64\config\systemprofile\Documents"
)
foreach ($P in $DefaultPaths) { if (Test-Path $P) { $SearchPaths.Add($P) } }

# Per-user documents
Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    $UserDocs = "$($_.FullName)\Documents"
    if (Test-Path $UserDocs) { $SearchPaths.Add($UserDocs) }
    $UserTrans = "$($_.FullName)\AppData\Local\Temp"
    if (Test-Path $UserTrans) { $SearchPaths.Add($UserTrans) }
}

Write-Host "[*] Searching $($SearchPaths.Count) locations for transcript files..." -ForegroundColor Cyan

$Transcripts = [System.Collections.Generic.List[PSCustomObject]]::new()
$SuspiciousTranscripts = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($SearchPath in ($SearchPaths | Sort-Object -Unique)) {
    $TxtFiles = @(Get-ChildItem $SearchPath -Filter "PowerShell_transcript*.txt" -Recurse -ErrorAction SilentlyContinue)
    foreach ($TF in $TxtFiles) {
        $Content = $null
        $Preview = $null
        try {
            $Content = Get-Content $TF.FullName -ErrorAction SilentlyContinue
            $Preview = @($Content | Select-Object -First 20)
        } catch {}

        # Extract metadata from transcript header
        $MachineName = if ($Content) { ($Content | Where-Object { $_ -match "^Machine\s*:" }) -replace "Machine\s*:\s*","" | Select-Object -First 1 } else { $null }
        $UserName    = if ($Content) { ($Content | Where-Object { $_ -match "^Username\s*:" }) -replace "Username\s*:\s*","" | Select-Object -First 1 } else { $null }
        $StartTime   = if ($Content) { ($Content | Where-Object { $_ -match "^Start time\s*:" }) -replace "Start time\s*:\s*","" | Select-Object -First 1 } else { $null }

        # Suspicious command detection
        $IsSuspicious = $false
        $SuspReasons  = @()
        if ($Content) {
            $FullText = $Content -join " "
            if ($FullText -match "-EncodedCommand|-enc\s+[A-Za-z0-9+/]{20}") { $IsSuspicious=$true; $SuspReasons+="Encoded command" }
            if ($FullText -match "DownloadString|DownloadFile|WebClient|Invoke-WebRequest") { $IsSuspicious=$true; $SuspReasons+="Download activity" }
            if ($FullText -match "Invoke-Expression|IEX\s*\(|IEX\s*`"") { $IsSuspicious=$true; $SuspReasons+="IEX execution" }
            if ($FullText -match "Mimikatz|sekurlsa|lsadump|dcsync") { $IsSuspicious=$true; $SuspReasons+="Credential tool" }
            if ($FullText -match "Add-MpPreference|Set-MpPreference.*Disable|DisableRealtimeMonitoring") { $IsSuspicious=$true; $SuspReasons+="AV tampering" }
            if ($FullText -match "New-LocalUser|Add-LocalGroupMember|net user|net localgroup") { $IsSuspicious=$true; $SuspReasons+="Account manipulation" }
        }

        # Copy suspicious transcripts
        $CopiedPath = $null
        if ($IsSuspicious) {
            $CopiedPath = "$OutDir\SUSPICIOUS_$($TF.Name)"
            Copy-Item $TF.FullName $CopiedPath -Force -ErrorAction SilentlyContinue
        }

        $TObj = [PSCustomObject]@{
            FileName         = $TF.Name
            FullPath         = $TF.FullName
            SizeBytes        = $TF.Length
            CreationTime     = $TF.CreationTimeUtc.ToString("o")
            LastModified     = $TF.LastWriteTimeUtc.ToString("o")
            MachineName      = $MachineName
            UserName         = $UserName
            StartTime        = $StartTime
            LineCount        = if ($Content) { $Content.Count } else { 0 }
            IsSuspicious     = $IsSuspicious
            SuspiciousReasons= ($SuspReasons -join "; ")
            CopiedTo         = $CopiedPath
            Preview          = $Preview
        }
        $Transcripts.Add($TObj)
        if ($IsSuspicious) { $SuspiciousTranscripts.Add($TObj) }
    }
}

Write-Log "Transcripts found: $($Transcripts.Count) | Suspicious: $($SuspiciousTranscripts.Count)"

$Evidence = [PSCustomObject]@{
    ChainOfCustody       = [PSCustomObject]@{ CaseNumber=$CaseNum; Hostname=$Hostname; CollectedAt=(Get-Date).ToString("o"); ToolVersion="1.0" }
    ArtifactType         = "PSTranscriptCollection"
    TranscriptionConfig  = $TranscriptConfig
    SearchPathsChecked   = @($SearchPaths | Sort-Object -Unique)
    TranscriptCount      = $Transcripts.Count
    SuspiciousCount      = $SuspiciousTranscripts.Count
    OutputDirectory      = $OutDir
    SuspiciousTranscripts= $SuspiciousTranscripts
    AllTranscripts       = $Transcripts
}

$Evidence | ConvertTo-Json -Depth 7 | Out-File $JsonFile -Encoding UTF8
$Hash = Get-FileHash $JsonFile -Algorithm SHA256
[PSCustomObject]@{ FileName=$JsonFile; Hash=$Hash.Hash; Generated=(Get-Date).ToString("o") } |
    ConvertTo-Json | Out-File "$JsonFile.hash.json" -Encoding UTF8

Write-Host "[+] PS Transcript collection complete | Found: $($Transcripts.Count) | Suspicious: $($SuspiciousTranscripts.Count)" -ForegroundColor Green
Write-Host "[+] Output: $OutDir" -ForegroundColor Green
Write-Host "[+] JSON  : $JsonFile" -ForegroundColor Green
Write-Log "Completed"
