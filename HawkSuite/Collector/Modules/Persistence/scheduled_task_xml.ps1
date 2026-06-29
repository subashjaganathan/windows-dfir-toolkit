<#
.SYNOPSIS
    Module: scheduled_task_xml - raw scheduled-task definitions from
    C:\Windows\System32\Tasks. Catches tasks HIDDEN from the Schedule API
    (e.g. by deleting the task's SD registry value) that scheduled_tasks (CIM)
    misses. RAW collection only.
#>
param([Parameter(Mandatory)][string]$SessionRoot, $Config)

Write-HawkLog 'scheduled_task_xml: collection started'

$records = New-Object System.Collections.Generic.List[object]
$tasksRoot = Join-Path $env:SystemRoot 'System32\Tasks'

try {
    if (-not (Test-Path -LiteralPath $tasksRoot -ErrorAction SilentlyContinue)) {
        Write-HawkLog 'scheduled_task_xml: Tasks folder not found' 'WARN'
        Export-HawkArtifact -SessionRoot $SessionRoot -ArtifactType 'scheduled_task_xml' -Records $records
        return
    }
    $files = Get-ChildItem -LiteralPath $tasksRoot -Recurse -File -Force -ErrorAction SilentlyContinue
    $prefix = (Resolve-Path -LiteralPath $tasksRoot).Path
    foreach ($f in $files) {
        $taskName = $f.FullName.Substring($prefix.Length).Replace('\','/')
        $exec=$null; $args2=$null; $workDir=$null; $userId=$null; $runLevel=$null
        $author=$null; $enabled=$null; $triggers=$null; $regDate=$null
        try {
            [xml]$x = [System.IO.File]::ReadAllText($f.FullName)
            $t = $x.Task
            if ($t) {
                $author   = "$($t.RegistrationInfo.Author)"
                $regDate  = ConvertTo-HawkUtc "$($t.RegistrationInfo.Date)"
                $enabled  = "$($t.Settings.Enabled)"
                $userId   = "$($t.Principals.Principal.UserId)"; if (-not $userId) { $userId = "$($t.Principals.Principal.GroupId)" }
                $runLevel = "$($t.Principals.Principal.RunLevel)"
                $a = $t.Actions.Exec
                if ($a) {
                    if ($a -is [array]) { $a = $a[0] }
                    $exec = "$($a.Command)"; $args2 = "$($a.Arguments)"; $workDir = "$($a.WorkingDirectory)"
                }
                if ($t.Triggers) { $triggers = (($t.Triggers.ChildNodes | ForEach-Object { $_.Name }) -join ', ') }
            }
        } catch { Write-HawkLog "scheduled_task_xml: parse failed $taskName - $_" 'WARN' }

        $binPath = if ($exec) { Resolve-HawkCommandPath $exec } else { $null }
        $id = if ($binPath) { Get-HawkFileIdentity -Path $binPath } else { @{ sha256=$null; md5=$null; signatureStatus='Unknown'; signer=$null } }

        $records.Add([ordered]@{
            taskName        = $taskName
            author          = $author
            registeredUtc   = $regDate
            enabled         = $enabled
            runAs           = $userId
            runLevel        = $runLevel
            execute         = $exec
            arguments       = $args2
            workingDirectory= $workDir
            triggers        = $triggers
            binaryPath      = $binPath
            sha256          = $id.sha256
            md5             = $id.md5
            signatureStatus = $id.signatureStatus
            signer          = $id.signer
            xmlModifiedUtc  = ConvertTo-HawkUtc $f.LastWriteTimeUtc
        })
    }
} catch { Write-HawkLog "scheduled_task_xml: enumeration failed - $_" 'WARN' }

Export-HawkArtifact -SessionRoot $SessionRoot -ArtifactType 'scheduled_task_xml' -Records $records
