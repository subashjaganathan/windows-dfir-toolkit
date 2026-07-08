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


# --- Shared toolkit module: single source of truth for version + base paths ---
$__DFIRMod = Join-Path $PSScriptRoot '..\Infrastructure\DFIR_Common.psm1'
if (Test-Path $__DFIRMod) { Import-Module $__DFIRMod -Force -ErrorAction SilentlyContinue }
if (-not $Global:DFIR_ToolVersion) { $Global:DFIR_ToolVersion = '1.0' }

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
        Detail=$Detail; MITRE=$MITRE; DetectedAt=([DateTime]::UtcNow).ToString("o")
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
# Scan only the known model-store locations under each user profile (depth-limited), rather
# than recursing all of C:\Users - a blanket recursive scan took minutes and timed out.
$SearchPaths = [System.Collections.Generic.List[string]]::new()
foreach ($UserDir in (Get-ChildItem "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue)) {
    foreach ($sub in @(".ollama\models",".cache\huggingface",".cache\lm-studio\models",".lmstudio\models",
                       "AppData\Local\LM-Studio\models","AppData\Local\nomic.ai\GPT4All","AppData\Roaming\GPT4All")) {
        $SearchPaths.Add((Join-Path $UserDir.FullName $sub))
    }
}
$SearchPaths.Add("$env:LOCALAPPDATA\LM-Studio\models")

foreach ($SearchPath in ($SearchPaths | Select-Object -Unique)) {
    if (-not (Test-Path $SearchPath -ErrorAction SilentlyContinue)) { continue }
    foreach ($Ext in $ModelExtensions) {
        $Models = @(Get-ChildItem $SearchPath -Filter $Ext -Recurse -Depth 4 -ErrorAction SilentlyContinue |
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

# Strong-malice indicators: specific, high-confidence attack techniques. Any one of these
# is meaningful on its own. These are the ONLY patterns that mark a script as malicious.
$StrongMalice = @(
    @{ Pattern = "FromBase64String[^\r\n]{0,60}(IEX|Invoke-Expression)|(IEX|Invoke-Expression)[^\r\n]{0,60}FromBase64String"; Desc = "Base64 decode piped to execution" }
    @{ Pattern = "AmsiScanBuffer|amsiInitFailed|Amsi.*(Bypass|Patch)|\[Ref\]\.Assembly.*Amsi"; Desc = "AMSI bypass" }
    @{ Pattern = "Set-MpPreference[^\r\n]*Disable(RealtimeMonitoring|IOAVProtection|BehaviorMonitoring|ScriptScanning)"; Desc = "Defender disable" }
    @{ Pattern = "(DownloadString|DownloadFile)\s*\([^)]*https?://[^)]*\)[^\r\n]{0,60}(IEX|Invoke-Expression|\|\s*iex)"; Desc = "Download-and-execute" }
    @{ Pattern = "-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/]{80,}={0,2}"; Desc = "Long encoded-command payload" }
    @{ Pattern = "\[char\]\d+\+\[char\]\d+\+\[char\]\d+"; Desc = "Character-code obfuscation" }
    @{ Pattern = "VirtualAlloc|WriteProcessMemory|CreateRemoteThread|NtCreateThreadEx"; Desc = "Process-injection primitive" }
)
# Weak-context indicators: common in legitimate admin/DFIR scripts. Recorded as CONTEXT only;
# never escalate a finding on these alone and never count them toward the malicious total.
$WeakContext = @(
    @{ Pattern = "# This (script|function|code) (will|should|is designed to)"; Desc = "GPT-style comment" }
    @{ Pattern = "# (Note|Please note|Important):"; Desc = "explanation comment" }
    @{ Pattern = "# Step \d+:"; Desc = "step-by-step comment" }
    @{ Pattern = "ConvertTo-SecureString|NetworkCredential|PSCredential"; Desc = "credential object use" }
    @{ Pattern = "Enter-PSSession|New-PSSession|Invoke-Command"; Desc = "remoting" }
    @{ Pattern = "Invoke-WebRequest|IWR|DownloadString|WebClient"; Desc = "web request" }
)

# Read PowerShell 4104 script-block logging. A single script is often split across many
# 4104 records (MessageNumber/MessageTotal of the same ScriptBlockId), so we reassemble by
# ScriptBlockId and analyze the FULL script once - analyzing per-record truncates the logic
# and misses payloads that straddle records. We read the raw ScriptBlockText event-data
# field (Properties[2]) rather than the rendered .Message.
try {
    $PSCap = if ($env:DFIR_PS4104_MAX) { [int]$env:DFIR_PS4104_MAX } else { 20000 }
    $DaysBack = if ($env:DFIR_DAYS) { [int]$env:DFIR_DAYS } else { 30 }
    $PSEvents = @(Get-WinEvent -FilterHashtable @{
        LogName   = "Microsoft-Windows-PowerShell/Operational"
        Id        = 4104
        StartTime = (Get-Date).AddDays(-$DaysBack)
    } -ErrorAction SilentlyContinue | Select-Object -First $PSCap)
    if ($PSEvents.Count -ge $PSCap) {
        Write-Log "4104 records hit cap of $PSCap (raise `$env:DFIR_PS4104_MAX to read more)" "WARN"
    }

    # Group records into complete scripts keyed by ScriptBlockId.
    $Blocks = @{}
    foreach ($Event in $PSEvents) {
        $num=1; $text=$null; $id=$null; $path=$null
        try { $p=$Event.Properties; $num=[int]$p[0].Value; $text=[string]$p[2].Value; $id=[string]$p[3].Value; $path=[string]$p[4].Value } catch {}
        if (-not $text) { $text = $Event.Message }
        if (-not $id)   { $id = "msg-" + $Event.RecordId }
        if (-not $Blocks.ContainsKey($id)) { $Blocks[$id] = [System.Collections.Generic.List[object]]::new() }
        $Blocks[$id].Add([PSCustomObject]@{ Num=$num; Text=$text; Time=$Event.TimeCreated; Path=$path })
    }

    $PSAnalyzed = 0
    foreach ($id in $Blocks.Keys) {
        $ordered    = $Blocks[$id] | Sort-Object Num
        $ScriptText = ($ordered | ForEach-Object { $_.Text }) -join ""
        $BlockTime  = $ordered[0].Time
        $BlockPath  = ($ordered | ForEach-Object { $_.Path } | Where-Object { $_ } | Select-Object -First 1)
        if (-not $ScriptText -or $ScriptText.Length -lt 50) { continue }

        # Do NOT flag security/detection tooling on its own signature definitions. Such source
        # contains malware pattern strings as literals (not executed techniques); scanning it
        # would self-detect this toolkit and any AV/EDR/DFIR script. Recognisable by detection
        # scaffolding or a path under a DFIR toolkit - real malware carries none of these.
        if ($ScriptText -match '(?i)(Add-Finding|\$StrongMalice|\$WeakContext|\$LOLBASAbuse|\$AIPatterns|Get-StringEntropy|Export-HawkArtifact|ArtifactType\s*=\s*["'']?(AI_Attack|ThreatHunting|Registry_Deep))') { continue }
        if ($BlockPath -and $BlockPath -match '(?i)(windows-dfir-toolkit|\\DFIR|\\Scripts\\(ThreatHunting|Reporting|Registry_Advanced|Persistence|Credentials|DefenseEvasion)\\)') { continue }
        # A log/event-hunting script carries these technique names as -match/-like patterns, not
        # as executed code. Don't let a log hunter flag other log hunters (or itself).
        if ($ScriptText -match '(?i)Get-WinEvent' -and $ScriptText -match '(?i)-i?match|-i?like|\[regex\]') { continue }
        $PSAnalyzed++

        # Entropy is only meaningful on the longest unbroken base64/obfuscation-like run,
        # not the whole script (normal mixed-case code with symbols exceeds 5.5 easily).
        $LongRun = ([regex]::Matches($ScriptText,'[A-Za-z0-9+/=]{40,}') |
                    Sort-Object { $_.Length } -Descending | Select-Object -First 1).Value
        $Entropy = if ($LongRun) { Get-StringEntropy $LongRun } else { 0 }
        $IsHighEntropy = $Entropy -gt 5.9   # packed/base64 content only; ~4.5 is normal text

        $StrongHits = @(); foreach ($P in $StrongMalice) { if ($ScriptText -match $P.Pattern) { $StrongHits += $P.Desc } }
        $WeakHits   = @(); foreach ($P in $WeakContext)  { if ($ScriptText -match $P.Pattern) { $WeakHits   += $P.Desc } }

        # Only strong-malice indicators constitute a finding. CRITICAL requires an actual
        # obfuscated payload (high-entropy blob) present alongside the technique - this is what
        # separates a delivered malicious payload from a script that merely names the techniques.
        # Weak-context matches are retained for the analyst but never raise severity on their own.
        if ($StrongHits.Count -ge 1) {
            $Severity = if ($IsHighEntropy) { "CRITICAL" } elseif ($StrongHits.Count -ge 2) { "HIGH" } else { "MEDIUM" }
            $Snippet  = $ScriptText.Substring(0, [Math]::Min(300, $ScriptText.Length))

            $SuspScripts.Add([PSCustomObject]@{
                TimeCreated      = $BlockTime.ToString("o")
                ScriptBlockId    = $id
                ScriptPath       = $BlockPath
                Entropy          = $Entropy
                StrongIndicators = $StrongHits
                ContextIndicators= $WeakHits
                Severity         = $Severity
                Snippet          = $Snippet
            })
            Add-Finding "Malicious_PS_Script" $Severity "Malicious PowerShell script block ($($StrongHits.Count) strong indicator(s))" "$($StrongHits -join ', ')$(if($BlockPath){" [path: $BlockPath]"})" "T1059.001"
        }
    }
    Write-OK "Analyzed $PSAnalyzed reassembled PowerShell scripts from $($PSEvents.Count) records"
    Write-Log "PS analysis: $($PSEvents.Count) records, $PSAnalyzed scripts, $($SuspScripts.Count) suspicious"
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
            $SitePkg = @(Get-ChildItem "$($P.FullName)" -Recurse -Depth 4 -Filter "site-packages" -ErrorAction SilentlyContinue |
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

# Strong phrases are specific jailbreak/override attempts; weak phrases are common English
# (a security note or prompt-engineering doc trips them). Only a strong phrase raises HIGH.
$StrongInjPatterns = @(
    "ignore (previous|all previous|the above|prior) instructions",
    "disregard (your|all|previous) instructions",
    "ignore your training",
    "\bDAN mode\b",
    "do anything now",
    "you are (now )?(in )?developer mode",
    "enable developer mode"
)
$WeakInjPatterns = @(
    "you are now",
    "\bact as\b",
    "pretend (you are|to be)",
    "simulate a",
    "roleplay as",
    "\bjailbreak\b"
)

# Check recent files for prompt injection text (depth-limited to keep the scan fast).
$RecentFiles = @(Get-ChildItem "$env:TEMP","$env:USERPROFILE\Documents","$env:USERPROFILE\Downloads" `
    -Include "*.txt","*.log","*.json","*.md","*.ps1","*.bat","*.cmd" `
    -Recurse -Depth 4 -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) -and $_.Length -lt 1MB } |
    Select-Object -First 100)

foreach ($File in $RecentFiles) {
    try {
        $Content = Get-Content $File.FullName -Raw -ErrorAction SilentlyContinue
        if (-not $Content) { continue }
        $ContentLower = $Content.ToLower()
        # -match (regex) only; -contains on a string is a value-equality test (always false here).
        $StrongInj = @(); foreach ($p in $StrongInjPatterns) { if ($ContentLower -match $p) { $StrongInj += $p } }
        $WeakInj   = @(); foreach ($p in $WeakInjPatterns)   { if ($ContentLower -match $p) { $WeakInj   += $p } }

        # A single strong override phrase is meaningful; weak phrases need several to matter.
        $sev = if ($StrongInj.Count -ge 1) { "HIGH" } elseif ($WeakInj.Count -ge 3) { "MEDIUM" } else { $null }
        if ($sev) {
            $PromptInj.Add([PSCustomObject]@{
                FilePath    = $File.FullName
                FileName    = $File.Name
                Modified    = $File.LastWriteTime.ToString("o")
                StrongPatterns = $StrongInj
                WeakPatterns   = $WeakInj
                Snippet     = $Content.Substring(0, [Math]::Min(200, $Content.Length))
            })
            Add-Finding "Prompt_Injection" $sev "Prompt-injection phrasing in file: $($File.Name)" (($StrongInj + $WeakInj) -join ", ") "T1566"
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

    # Nothing here distinguishes "AI" from any script, so we do not claim it. On busy
    # servers/DCs dozens of failed logons/hour are routine (expired/service creds), so the
    # volume threshold is raised and severity is MEDIUM pending analyst review.
    if ($FailedLogons.Count -gt 100) {
        Add-Finding "CredAttack_Velocity" "MEDIUM" "High volume of failed logons in last hour: $($FailedLogons.Count)" "Review source IPs and targeted accounts; may be brute force or misconfigured service credentials" "T1110"
    }

    # Password spray pattern (many distinct accounts, few attempts each) - the distinct-account
    # fan-out is the real signal, so require a high account count before flagging.
    $TargetedAccounts = @($FailedLogons | ForEach-Object {
        try { $_.Properties[5].Value } catch { "" }
    } | Where-Object { $_ } | Sort-Object -Unique)

    if ($TargetedAccounts.Count -gt 20 -and $FailedLogons.Count -gt 40) {
        Add-Finding "CredAttack_Spray" "MEDIUM" "Password-spray pattern: $($TargetedAccounts.Count) distinct accounts with failed logons" "High distinct-account fan-out; correlate source IPs before escalating" "T1110.003"
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

    # Check DNS cache for AI API connections. Reaching an AI API is normal (developer tools,
    # assistants, this toolkit's own use) - it is INFORMATIONAL context, not an attack. Record
    # each domain once so legitimate usage does not inflate the report with duplicate findings.
    $DNSCache = @(Get-DnsClientCache -ErrorAction SilentlyContinue)
    $SeenAIDomain = @{}
    foreach ($Entry in $DNSCache) {
        foreach ($AIDomain in $AIAPIDomains) {
            if ($Entry.Entry -like "*$AIDomain*" -and -not $SeenAIDomain.ContainsKey($AIDomain)) {
                $SeenAIDomain[$AIDomain] = $true
                Add-Finding "AI_API_Access" "INFO" "AI API endpoint seen in DNS cache: $AIDomain" "Informational: confirm this AI usage is expected/authorized" "T1071"
            }
        }
    }

    # Consonant-ratio is a weak DGA proxy that also flags CDNs and hashed hostnames, so this
    # is INFO-only context. Broad allow-list covers the common consonant-heavy benign infra.
    $DgaAllow = "windows|microsoft|msft|azure|windowsupdate|msedge|office|office365|live\.com|bing|adobe|akadns|akamai|akamaiedge|edgekey|edgesuite|cloudfront|amazonaws|awsstatic|google|gstatic|googleapis|gvt1|ggpht|fbcdn|facebook|instagram|apple|icloud|mzstatic|digicert|verisign|globalsign|trafficmanager|cloudflare|fastly|sentry|mozilla|nvidia|intel|dropbox|spotify|cdn"
    $SuspiciousDNS = @($DNSCache | Where-Object {
        $Entry = $_.Entry
        $Consonants = ($Entry -replace "[aeiou\.\-_0-9]","").Length
        $Total      = ($Entry -replace "[\.\-_]","").Length
        $Ratio      = if ($Total -gt 0) { $Consonants / $Total } else { 0 }
        $Ratio -gt 0.80 -and $Entry.Length -gt 12 -and $Entry -notmatch $DgaAllow
    })

    foreach ($D in $SuspiciousDNS | Select-Object -First 10) {
        Add-Finding "DGA_Candidate" "INFO" "High-consonant domain in DNS cache: $($D.Entry)" "Weak DGA heuristic; verify against threat intel before acting" "T1568.002"
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
        CollectedAt=([DateTime]::UtcNow).ToString("o"); ToolVersion=$Global:DFIR_ToolVersion
        Investigator=$Investigator
    }
    ArtifactType     = "AI_Attack_Detection"
    TotalFindings    = $Findings.Count
    CriticalFindings = $CriticalCount
    HighFindings     = $HighCount
    MediumFindings   = $MedCount
    LLMToolsFound    = $LLMTools.Count
    AIModelsFound    = $AIModels.Count
    SuspiciousScriptCount = $SuspScripts.Count
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
[PSCustomObject]@{ FileName=$JsonFile; Hash=$Hash.Hash; Generated=([DateTime]::UtcNow).ToString("o") } |
    ConvertTo-Json | Out-File "$JsonFile.hash.json" -Encoding UTF8

Write-OK "JSON: $JsonFile"
Write-Log "AI detection complete | Findings=$($Findings.Count) LLMTools=$($LLMTools.Count) Models=$($AIModels.Count)"
