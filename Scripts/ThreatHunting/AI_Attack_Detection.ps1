#Requires -Version 5.1
<#
.SYNOPSIS
    Detects AI-assisted attacks, LLM tool usage, and AI-generated malware indicators.
.DESCRIPTION
    Hunts for evidence of:
    - Local LLM tools (Ollama, LM Studio, GPT4All, etc.)
    - AI-generated PowerShell (high entropy, GPT patterns, obfuscation)
    - AI-assisted credential attacks (unusual velocity, pattern-based)
    - Polymorphic/AI-generated malware behavioral indicators
    - Prompt injection attempts in web/app logs
    - AI model files and suspicious Python environments
    - Unusual script entropy suggesting AI generation
.VERSION
    1.0
#>
Set-StrictMode -Off
$ErrorActionPreference = "Continue"

$Timestamp    = Get-Date -Format "yyyyMMdd_HHmmss"
$Hostname     = $env:COMPUTERNAME
$BasePath     = if ($env:DFIR_OUTPUT) { $env:DFIR_OUTPUT } else { "C:\IR_Collection" }
$CaseNum      = if ($env:DFIR_CASE)   { $env:DFIR_CASE   } else { "CASE-$(Get-Date -Format yyyyMMdd)" }
$Investigator = if ($env:DFIR_INV)    { $env:DFIR_INV    } else { $env:USERNAME }
$JsonFile     = "$BasePath\AI_Attack_Detection_${Hostname}_${Timestamp}.json"
$LogFile      = "$BasePath\AI_Attack_Detection_Execution.log"

function Write-Log { param([string]$M,[string]$L="INFO") Add-Content $LogFile "$(Get-Date -Format o) [$L] :: $M" }
function Write-OK   { param([string]$M) Write-Host "[+] $M" -ForegroundColor Green }
function Write-Warn { param([string]$M) Write-Host "[!] $M" -ForegroundColor Yellow }
function Write-Info { param([string]$M) Write-Host "[*] $M" -ForegroundColor Cyan }
function Write-Hit  { param([string]$M) Write-Host "[DETECTION] $M" -ForegroundColor Red }

# Safe-evaluate a scriptblock, return default on any error (PS5.1 inline try/catch is invalid)
function Get-Safe {
    param([scriptblock]$Code, $Default = "")
    try { $v = & $Code; if ($null -ne $v) { return $v } else { return $Default } }
    catch { return $Default }
}

Write-Log "AI Attack Detection started | Case: $CaseNum"

# Context: is this a server or workstation?
$IsServer     = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).ProductType -gt 1
$IsDC         = (Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue).DomainRole -in @(4,5)
$IsDevMachine = Test-Path "$env:LOCALAPPDATA\Programs\Microsoft VS Code" -ErrorAction SilentlyContinue

# Context affects severity:
# LLM on developer workstation = LOW (expected)
# LLM on server/DC             = HIGH (unexpected)
# High entropy PS anywhere     = HIGH (always suspicious)
# Prompt injection patterns    = HIGH (always suspicious)
# AI-assisted brute force      = CRITICAL (always malicious)

function Get-ContextSeverity {
    param([string]$BaseSeverity, [string]$Type)
    # Malicious patterns are always high severity regardless of context
    if ($Type -in @("AI_PS_Script","Prompt_Injection","AI_CredAttack","AI_DGA")) { return $BaseSeverity }
    # LLM tools on servers/DCs = elevated severity
    if ($Type -in @("LLM_Tool","AI_Model","AI_Environment") -and ($IsServer -or $IsDC)) { return "HIGH" }
    # LLM tools on dev machines = lower severity
    if ($Type -in @("LLM_Tool","AI_Model","AI_Environment") -and $IsDevMachine) { return "LOW" }
    return $BaseSeverity
}

$Findings    = [System.Collections.Generic.List[PSCustomObject]]::new()
$LLMTools    = [System.Collections.Generic.List[PSCustomObject]]::new()
$SuspScripts = [System.Collections.Generic.List[PSCustomObject]]::new()
$AIModels    = [System.Collections.Generic.List[PSCustomObject]]::new()
$PromptInj   = [System.Collections.Generic.List[PSCustomObject]]::new()
$AIProcesses = [System.Collections.Generic.List[PSCustomObject]]::new()

function Add-Finding {
    param([string]$Category,[string]$Severity,[string]$Title,[string]$Detail,[string]$MITRE="",[string]$Context="")
    # Add context note for analyst
    $ContextNote = switch ($Category) {
        "LLM_Tool"        { if ($IsServer -or $IsDC) { "SUSPICIOUS: LLM tool on server/DC is unusual" } elseif ($IsDevMachine) { "INFO: May be legitimate developer tool - verify with user" } else { "REVIEW: Verify if this tool is authorized" } }
        "AI_Model"        { if ($IsServer -or $IsDC) { "SUSPICIOUS: AI model files on server/DC" } else { "INFO: May be legitimate - check if authorized" } }
        "AI_PS_Script"    { "MALICIOUS INDICATOR: High-entropy/pattern-matched script - investigate immediately" }
        "Prompt_Injection"{ "MALICIOUS INDICATOR: Prompt injection text found - possible AI application attack" }
        "AI_CredAttack"   { "MALICIOUS INDICATOR: Automated credential attack pattern detected" }
        "AI_DGA"          { "SUSPICIOUS: Possible AI-generated domain name - verify legitimacy" }
        "AI_API_Access"   { "INFO: AI API access detected - may be legitimate developer activity" }
        default           { "REVIEW: Determine if this activity is authorized" }
    }
    $script:Findings.Add([PSCustomObject]@{
        Category=$Category; Severity=$Severity; Title=$Title
        Detail=$Detail; MITRE=$MITRE; DetectedAt=(Get-Date).ToString("o")
        ContextNote=$ContextNote; IsMalicious=($Category -in @("AI_PS_Script","Prompt_Injection","AI_CredAttack"))
        IsAmbiguous=($Category -in @("LLM_Tool","AI_Model","AI_Environment","AI_API_Access"))
    })
    Write-Hit "$Severity | $Category | $Title"
    if ($ContextNote) { Write-Host "    Context: $ContextNote" -ForegroundColor DarkYellow }
    Write-Log "FINDING: [$Severity] ${Category}: $Title | $Detail | Context: $ContextNote" "WARN"
}

# Entropy calculation for detecting AI-generated/obfuscated content
function Get-StringEntropy {
    param([string]$Text)
    if (-not $Text -or $Text.Length -lt 10) { return 0.0 }
    $Freq = @{}
    foreach ($Char in $Text.ToCharArray()) {
        $Key = [string]$Char
        if ($Freq.ContainsKey($Key)) { $Freq[$Key]++ } else { $Freq[$Key] = 1 }
    }
    $Entropy = 0.0
    $Len = $Text.Length
    foreach ($Count in $Freq.Values) {
        $P = $Count / $Len
        if ($P -gt 0) { $Entropy -= $P * [Math]::Log($P, 2) }
    }
    return [Math]::Round($Entropy, 3)
}

#  1. LOCAL LLM TOOL DETECTION 
Write-Info "Checking for local LLM tools..."

$LLMProcessNames = @(
    "ollama","ollama_llama_server","lm-studio","lmstudio",
    "gpt4all","localai","jan","llamafile","llama.cpp",
    "koboldcpp","textgen","oobaboogai","mistral",
    "whisper","stable-diffusion","automatic1111","comfyui",
    "langchain","autogpt","babyagi","crewai","privateGPT"
)

$RunningProcs = @(Get-Process -ErrorAction SilentlyContinue)
foreach ($Proc in $RunningProcs) {
    foreach ($LLMName in $LLMProcessNames) {
        if ($Proc.ProcessName -like "*$LLMName*") {
            $AIProcesses.Add([PSCustomObject]@{
                ProcessName = $Proc.ProcessName
                PID         = $Proc.Id
                Path        = Get-Safe { $Proc.MainModule.FileName } "Access Denied"
                StartTime   = Get-Safe { $Proc.StartTime.ToString("o") } ""
                Type        = "Local LLM Runtime"
            })
            $LLMSev = Get-ContextSeverity "HIGH" "LLM_Tool"
            Add-Finding "LLM_Tool" $LLMSev "Local LLM tool running: $($Proc.ProcessName)" "PID: $($Proc.Id)" "T1059"
        }
    }
}

#  2. LLM INSTALLATION ARTIFACTS 
Write-Info "Scanning for LLM installation artifacts..."

$LLMPaths = @(
    "$env:LOCALAPPDATA\Ollama",
    "$env:APPDATA\Ollama",
    "$env:LOCALAPPDATA\LM-Studio",
    "$env:LOCALAPPDATA\Programs\LM-Studio",
    "$env:USERPROFILE\.ollama",
    "$env:USERPROFILE\.lmstudio",
    "$env:USERPROFILE\AppData\Local\nomic.ai",
    "$env:LOCALAPPDATA\GPT4All",
    "$env:USERPROFILE\.local\share\ollama",
    "C:\Program Files\Ollama",
    "C:\Program Files\LM Studio",
    "$env:USERPROFILE\.cache\lm-studio",
    "$env:USERPROFILE\.jan",
    "$env:USERPROFILE\jan"
)

foreach ($LLMPath in $LLMPaths) {
    if (Test-Path $LLMPath -ErrorAction SilentlyContinue) {
        $Size = try {
            $Items = @(Get-ChildItem $LLMPath -Recurse -ErrorAction SilentlyContinue)
            "$($Items.Count) files"
        } catch { "unknown" }
        $LLMTools.Add([PSCustomObject]@{
            Path      = $LLMPath
            Exists    = $true
            FileCount = $Size
            Modified  = Get-Safe { (Get-Item $LLMPath).LastWriteTime.ToString("o") } ""
        })
        $InstSev = Get-ContextSeverity "MEDIUM" "LLM_Tool"
        Add-Finding "LLM_Tool" $InstSev "LLM tool installation found: $LLMPath" "Size: $Size" "T1588"
    }
}

#  3. AI MODEL FILES (.gguf, .ggml, .bin, .pt) 
Write-Info "Scanning for AI model files..."

$ModelExtensions = @("*.gguf","*.ggml","*.safetensors")
$SearchPaths = @(
    $env:USERPROFILE,
    "$env:USERPROFILE\.ollama\models",
    "$env:LOCALAPPDATA\LM-Studio\models",
    "C:\Users"
)

foreach ($SearchPath in $SearchPaths) {
    if (-not (Test-Path $SearchPath -ErrorAction SilentlyContinue)) { continue }
    foreach ($Ext in $ModelExtensions) {
        $Models = @(Get-ChildItem $SearchPath -Filter $Ext -Recurse -ErrorAction SilentlyContinue |
                    Select-Object -First 10)
        foreach ($M in $Models) {
            $SizeGB = [Math]::Round($M.Length/1GB, 2)
            $AIModels.Add([PSCustomObject]@{
                ModelFile = $M.FullName
                SizeGB    = $SizeGB
                Extension = $M.Extension
                Modified  = $M.LastWriteTime.ToString("o")
                SHA256    = Get-Safe { (Get-FileHash $M.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash } ""
            })
            if ($SizeGB -gt 0.5) {
                Add-Finding "AI_Model" "MEDIUM" "Large AI model file found: $($M.Name) ($SizeGB GB)" $M.FullName "T1588"
            }
        }
    }
}

#  4. HIGH-ENTROPY / AI-GENERATED POWERSHELL DETECTION 
Write-Info "Analyzing PowerShell script blocks for AI-generated content..."

# AI-generation indicators in PS scripts
$AIPatterns = @(
    # GPT/LLM comment style
    @{ Pattern = "# This (script|function|code) (will|should|is designed to)"; Desc = "GPT-style comment pattern" }
    @{ Pattern = "# (Note|Please note|Important):"; Desc = "LLM explanation comment" }
    @{ Pattern = "# Step \d+:"; Desc = "LLM step-by-step pattern" }
    # AI-generated obfuscation patterns
    @{ Pattern = "\[char\]\d+\+\[char\]\d+\+\[char\]\d+"; Desc = "Character-code obfuscation (AI-generated)" }
    @{ Pattern = "-join.*\[char\]"; Desc = "Char-join obfuscation" }
    @{ Pattern = "\$\w{1,3}=\[char\]"; Desc = "Single-char variable obfuscation" }
    # AI malware download patterns
    @{ Pattern = "DownloadString|DownloadFile|WebClient|Invoke-WebRequest|IWR|IEX|Invoke-Expression"; Desc = "Download and execute pattern" }
    @{ Pattern = "FromBase64String.*IEX|IEX.*FromBase64"; Desc = "Base64 decode and execute" }
    # Credential harvesting
    @{ Pattern = "ConvertTo-SecureString|NetworkCredential|PSCredential"; Desc = "Credential manipulation" }
    # Lateral movement
    @{ Pattern = "Enter-PSSession|Invoke-Command.*ComputerName|New-PSSession"; Desc = "Remote execution" }
    # AI-assisted evasion
    @{ Pattern = "amsiInitFailed|AmsiScanBuffer|AMSI"; Desc = "AMSI bypass attempt" }
    @{ Pattern = "Set-MpPreference.*DisableRealtimeMonitoring"; Desc = "Defender disable attempt" }
    @{ Pattern = "bypass.*execution|ExecutionPolicy.*bypass"; Desc = "Execution policy bypass" }
)

# Read PowerShell event log for suspicious script blocks
try {
    $PSEvents = @(Get-WinEvent -FilterHashtable @{
        LogName   = "Microsoft-Windows-PowerShell/Operational"
        Id        = 4104
        StartTime = (Get-Date).AddDays(-30)
    } -ErrorAction SilentlyContinue | Select-Object -First 500)

    $PSAnalyzed = 0
    foreach ($Event in $PSEvents) {
        $ScriptText = $Event.Message
        if (-not $ScriptText -or $ScriptText.Length -lt 50) { continue }
        $PSAnalyzed++

        # Entropy check
        $Entropy = Get-StringEntropy ($ScriptText.Substring(0, [Math]::Min(1000, $ScriptText.Length)))

        $MatchedPatterns = @()
        foreach ($P in $AIPatterns) {
            if ($ScriptText -match $P.Pattern) {
                $MatchedPatterns += $P.Desc
            }
        }

        # High entropy + multiple AI patterns = likely AI-generated malware
        $IsHighEntropy = $Entropy -gt 5.5
        $HasManyPatterns = $MatchedPatterns.Count -ge 2

        if ($IsHighEntropy -or $HasManyPatterns) {
            $Severity = if ($HasManyPatterns -and $IsHighEntropy) { "CRITICAL" } elseif ($HasManyPatterns) { "HIGH" } else { "MEDIUM" }
            $Snippet  = $ScriptText.Substring(0, [Math]::Min(300, $ScriptText.Length))

            $SuspScripts.Add([PSCustomObject]@{
                TimeCreated  = $Event.TimeCreated.ToString("o")
                Entropy      = $Entropy
                Patterns     = $MatchedPatterns
                PatternCount = $MatchedPatterns.Count
                Severity     = $Severity
                Snippet      = $Snippet
            })

            if ($HasManyPatterns) {
                Add-Finding "AI_PS_Script" $Severity "AI-generated PS script detected ($($MatchedPatterns.Count) indicators)" ($MatchedPatterns -join ", ") "T1059.001"
            }
        }
    }
    Write-OK "Analyzed $PSAnalyzed PowerShell script blocks"
    Write-Log "PS analysis: $PSAnalyzed blocks, $($SuspScripts.Count) suspicious"
} catch {
    Write-Log "PS event log analysis failed: $_" "WARN"
}

#  5. PYTHON AI ENVIRONMENT DETECTION 
Write-Info "Checking for Python AI/ML environments..."

$PythonAIPackages = @(
    "transformers","langchain","openai","anthropic","torch","tensorflow",
    "llama-cpp-python","ctransformers","gpt4all","llmware","autogen",
    "chromadb","faiss","sentence-transformers","huggingface-hub"
)

$PythonPaths = @(
    "$env:APPDATA\Python",
    "$env:LOCALAPPDATA\Programs\Python",
    "C:\Python*",
    "$env:USERPROFILE\AppData\Local\Programs\Python",
    "$env:USERPROFILE\.conda",
    "$env:USERPROFILE\anaconda3",
    "$env:USERPROFILE\miniconda3"
)

$PythonFound = @()
foreach ($PyPath in $PythonPaths) {
    $Matches2 = @(Get-Item $PyPath -ErrorAction SilentlyContinue)
    foreach ($P in $Matches2) {
        if (Test-Path $P.FullName) {
            $PythonFound += $P.FullName
            # Check for AI packages in site-packages
            $SitePkg = @(Get-ChildItem "$($P.FullName)" -Recurse -Filter "site-packages" -ErrorAction SilentlyContinue |
                         Select-Object -First 1)
            if ($SitePkg) {
                foreach ($Pkg in $PythonAIPackages) {
                    if (Test-Path "$($SitePkg.FullName)\$Pkg" -ErrorAction SilentlyContinue) {
                        Add-Finding "AI_Environment" "MEDIUM" "AI/ML Python package installed: $Pkg" "$($SitePkg.FullName)\$Pkg" "T1588"
                        $LLMTools.Add([PSCustomObject]@{
                            Path      = "$($SitePkg.FullName)\$Pkg"
                            Exists    = $true
                            FileCount = "Python package"
                            Modified  = ""
                        })
                    }
                }
            }
        }
    }
}

#  6. PROMPT INJECTION INDICATORS 
Write-Info "Checking for prompt injection artifacts..."

$PromptInjPatterns = @(
    "ignore previous instructions",
    "ignore all previous",
    "disregard your instructions",
    "you are now",
    "act as",
    "jailbreak",
    "DAN mode",
    "developer mode",
    "ignore your training",
    "pretend you are",
    "simulate a",
    "roleplay as"
)

# Check recent files for prompt injection text
$RecentFiles = @(Get-ChildItem "$env:TEMP","$env:USERPROFILE\Documents","$env:USERPROFILE\Downloads" `
    -Include "*.txt","*.log","*.json","*.md","*.ps1","*.bat","*.cmd" `
    -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) -and $_.Length -lt 1MB } |
    Select-Object -First 100)

foreach ($File in $RecentFiles) {
    try {
        $Content = Get-Content $File.FullName -Raw -ErrorAction SilentlyContinue
        if (-not $Content) { continue }
        $ContentLower = $Content.ToLower()
        $MatchedInj = @()
        foreach ($Pattern in $PromptInjPatterns) {
            if ($ContentLower -contains $Pattern -or $ContentLower -match [regex]::Escape($Pattern)) {
                $MatchedInj += $Pattern
            }
        }
        if ($MatchedInj.Count -ge 2) {
            $PromptInj.Add([PSCustomObject]@{
                FilePath    = $File.FullName
                FileName    = $File.Name
                Modified    = $File.LastWriteTime.ToString("o")
                Patterns    = $MatchedInj
                Snippet     = $Content.Substring(0, [Math]::Min(200, $Content.Length))
            })
            Add-Finding "Prompt_Injection" "HIGH" "Prompt injection patterns in file: $($File.Name)" ($MatchedInj -join ", ") "T1566"
        }
    } catch {}
}

#  7. AI-ASSISTED CREDENTIAL ATTACK PATTERNS 
Write-Info "Checking for AI-assisted credential attack patterns..."

try {
    # Unusually high velocity logon failures (AI-assisted brute force)
    $FailedLogons = @(Get-WinEvent -FilterHashtable @{
        LogName   = "Security"
        Id        = 4625
        StartTime = (Get-Date).AddHours(-1)
    } -ErrorAction SilentlyContinue)

    if ($FailedLogons.Count -gt 50) {
        Add-Finding "AI_CredAttack" "CRITICAL" "High-velocity failed logons in last hour: $($FailedLogons.Count)" "Possible AI-assisted credential stuffing or spray attack" "T1110.003"
    }

    # Password spray pattern (many accounts, few attempts each)
    $TargetedAccounts = @($FailedLogons | ForEach-Object {
        try { $_.Properties[5].Value } catch { "" }
    } | Where-Object { $_ } | Sort-Object -Unique)

    if ($TargetedAccounts.Count -gt 10 -and $FailedLogons.Count -gt 20) {
        Add-Finding "AI_CredAttack" "HIGH" "Password spray pattern: $($TargetedAccounts.Count) accounts targeted" "Possible AI-generated username list attack" "T1110.003"
    }
} catch {
    Write-Log "Credential attack analysis failed: $_" "WARN"
}

#  8. UNUSUAL NETWORK PATTERNS (AI C2) 
Write-Info "Checking for AI-generated C2 traffic patterns..."

try {
    $NetConns = @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue)

    # Check for connections to known AI API endpoints being misused
    $AIAPIDomains = @("openai.com","api.openai.com","anthropic.com","api.anthropic.com",
                      "huggingface.co","replicate.com","together.ai","groq.com",
                      "cohere.com","mistral.ai","perplexity.ai")

    # Check DNS cache for AI API connections
    $DNSCache = @(Get-DnsClientCache -ErrorAction SilentlyContinue)
    foreach ($Entry in $DNSCache) {
        foreach ($AIDomain in $AIAPIDomains) {
            if ($Entry.Entry -like "*$AIDomain*") {
                Add-Finding "AI_API_Access" "MEDIUM" "AI API endpoint in DNS cache: $($Entry.Entry)" "Possible AI-assisted attack or unauthorized AI usage" "T1071"
            }
        }
    }

    # DGA-like domain patterns (AI-generated domain names)
    $SuspiciousDNS = @($DNSCache | Where-Object {
        $Entry = $_.Entry
        # High consonant ratio = DGA indicator (AI often generates these)
        $Consonants = ($Entry -replace "[aeiou\.\-_0-9]","").Length
        $Total      = ($Entry -replace "[\.\-_]","").Length
        $Ratio      = if ($Total -gt 0) { $Consonants / $Total } else { 0 }
        $Ratio -gt 0.75 -and $Entry.Length -gt 10 -and $Entry -notmatch "windows|microsoft|office|adobe"
    })

    foreach ($D in $SuspiciousDNS | Select-Object -First 5) {
        Add-Finding "AI_DGA" "MEDIUM" "Possible AI/DGA-generated domain: $($D.Entry)" "High consonant ratio - possible AI-generated C2 domain" "T1568.002"
    }
} catch {
    Write-Log "Network analysis failed: $_" "WARN"
}

#  9. AI TOOL REGISTRY ARTIFACTS 
Write-Info "Checking registry for AI tool artifacts..."

$AIRegPaths = @(
    "HKCU:\Software\Ollama",
    "HKLM:\SOFTWARE\Ollama",
    "HKCU:\Software\LM Studio",
    "HKLM:\SOFTWARE\LM Studio",
    "HKCU:\Software\GPT4All",
    "HKCU:\Software\OpenAI",
    "HKCU:\Software\Anthropic"
)

foreach ($RegPath in $AIRegPaths) {
    if (Test-Path $RegPath -ErrorAction SilentlyContinue) {
        Add-Finding "AI_Tool_Registry" "LOW" "AI tool registry key found: $RegPath" "Evidence of AI tool installation" "T1112"
    }
}

#  10. SUMMARIZE 
$CriticalCount = @($Findings | Where-Object { $_.Severity -eq "CRITICAL" }).Count
$HighCount     = @($Findings | Where-Object { $_.Severity -eq "HIGH" }).Count
$MedCount      = @($Findings | Where-Object { $_.Severity -eq "MEDIUM" }).Count

# Separate definite malicious from ambiguous
$DefinitelyMalicious = @($Findings | Where-Object { $_.IsMalicious })
$NeedsReview         = @($Findings | Where-Object { $_.IsAmbiguous })

Write-OK "AI attack detection complete"
Write-Host ""
Write-Host "CLASSIFICATION:" -ForegroundColor White
Write-Host "  Definitely Malicious : $($DefinitelyMalicious.Count)" -ForegroundColor Red
Write-Host "  Needs Human Review   : $($NeedsReview.Count)" -ForegroundColor Yellow
Write-Host "  Context: $(if($IsServer){'SERVER'}elseif($IsDC){'DOMAIN CONTROLLER'}elseif($IsDevMachine){'DEVELOPER MACHINE'}else{'WORKSTATION'})" -ForegroundColor Cyan
Write-OK "Findings: $($Findings.Count) total | CRITICAL: $CriticalCount | HIGH: $HighCount | MEDIUM: $MedCount"
Write-OK "LLM tools found: $($LLMTools.Count)"
Write-OK "AI model files: $($AIModels.Count)"
Write-OK "Suspicious PS scripts: $($SuspScripts.Count)"
Write-OK "Prompt injection files: $($PromptInj.Count)"

# Save JSON
$Evidence = [PSCustomObject]@{
    ChainOfCustody   = [PSCustomObject]@{
        CaseNumber=$CaseNum; Hostname=$Hostname
        CollectedAt=(Get-Date).ToString("o"); ToolVersion="1.0"
        Investigator=$Investigator
    }
    ArtifactType     = "AI_Attack_Detection"
    TotalFindings    = $Findings.Count
    CriticalFindings = $CriticalCount
    HighFindings     = $HighCount
    MediumFindings   = $MedCount
    LLMToolsFound    = $LLMTools.Count
    AIModelsFound    = $AIModels.Count
    SuspiciousScripts= $SuspScripts.Count
    PromptInjFiles   = $PromptInj.Count
    Findings         = $Findings
    LLMTools         = $LLMTools
    AIModels         = $AIModels
    SuspiciousPS     = $SuspScripts
    PromptInjection  = $PromptInj
    AIProcesses      = $AIProcesses
}

$Evidence | ConvertTo-Json -Depth 6 | Out-File $JsonFile -Encoding UTF8
$Hash = Get-FileHash $JsonFile -Algorithm SHA256
[PSCustomObject]@{ FileName=$JsonFile; Hash=$Hash.Hash; Generated=(Get-Date).ToString("o") } |
    ConvertTo-Json | Out-File "$JsonFile.hash.json" -Encoding UTF8

Write-OK "JSON: $JsonFile"
Write-Log "AI detection complete | Findings=$($Findings.Count) LLMTools=$($LLMTools.Count) Models=$($AIModels.Count)"
