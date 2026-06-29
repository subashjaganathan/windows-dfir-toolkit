<#
.SYNOPSIS
    Module: wsl_hyperv_artifacts - WSL distributions + Hyper-V VMs/disks.
    RAW collection only. recordType per source. Empty/graceful when absent.
#>
param([Parameter(Mandatory)][string]$SessionRoot, $Config)

Write-HawkLog 'wsl_hyperv_artifacts: collection started'

$records = New-Object System.Collections.Generic.List[object]

# (a) WSL distributions (current user Lxss)
try {
    $lxss = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\Microsoft\Windows\CurrentVersion\Lxss')
    if ($lxss) {
        foreach ($name in $lxss.GetSubKeyNames()) {
            $k = $lxss.OpenSubKey($name)
            if (-not $k) { continue }
            $basePath = "$($k.GetValue('BasePath'))"
            $vhdx = $null; $vhdxSize = $null; $vhdxMtime = $null
            if ($basePath) {
                $vhdx = Join-Path $basePath 'ext4.vhdx'
                try {
                    if (Test-Path -LiteralPath $vhdx -ErrorAction SilentlyContinue) {
                        $vi = Get-Item -LiteralPath $vhdx -ErrorAction SilentlyContinue
                        if ($vi) { $vhdxSize = $vi.Length; $vhdxMtime = ConvertTo-HawkUtc $vi.LastWriteTimeUtc }
                    }
                } catch {}
            }
            $records.Add([ordered]@{
                recordType         = 'wslDistro'
                distributionName   = "$($k.GetValue('DistributionName'))"
                basePath           = $basePath
                version            = $k.GetValue('Version')
                defaultUid         = $k.GetValue('DefaultUid')
                state              = $k.GetValue('State')
                packageFamilyName  = "$($k.GetValue('PackageFamilyName'))"
                vhdxPath           = $vhdx
                vhdxSizeBytes      = $vhdxSize
                vhdxModifiedUtc    = $vhdxMtime
            })
        }
    }
} catch { Write-HawkLog "wsl_hyperv_artifacts: WSL enum failed - $_" 'WARN' }

# (b) Hyper-V VMs (module often absent -> graceful)
try {
    foreach ($vm in (Get-VM -ErrorAction Stop)) {
        $records.Add([ordered]@{
            recordType            = 'hyperVVm'
            name                  = $vm.Name
            state                 = "$($vm.State)"
            generation            = $vm.Generation
            version               = "$($vm.Version)"
            path                  = $vm.Path
            configurationLocation = $vm.ConfigurationLocation
            creationTimeUtc       = ConvertTo-HawkUtc $vm.CreationTime
        })
        # (c) attached disks
        try {
            foreach ($d in ($vm | Get-VMHardDiskDrive -ErrorAction Stop)) {
                $sz = $null; $mt = $null
                try {
                    if ($d.Path -and (Test-Path -LiteralPath $d.Path -ErrorAction SilentlyContinue)) {
                        $di = Get-Item -LiteralPath $d.Path -ErrorAction SilentlyContinue
                        if ($di) { $sz = $di.Length; $mt = ConvertTo-HawkUtc $di.LastWriteTimeUtc }
                    }
                } catch {}
                $records.Add([ordered]@{ recordType = 'hyperVDisk'; vmName = $vm.Name; path = $d.Path; sizeBytes = $sz; modifiedUtc = $mt })
            }
        } catch {}
    }
} catch { Write-HawkLog 'wsl_hyperv_artifacts: Hyper-V not present or inaccessible' 'WARN' }

Export-HawkArtifact -SessionRoot $SessionRoot -ArtifactType 'wsl_hyperv_artifacts' -Records $records
