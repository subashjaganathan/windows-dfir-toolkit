<#
.SYNOPSIS
    Raw-parser verification session builder.
    Assembles a .hawk session containing REAL evtx exports from this machine,
    a synthetic SCCA v30 prefetch file, and synthetic-but-real-format registry
    hives (built via reg.exe save), then imports it and prints parser results.

    Run unelevated: skips Security.evtx + real prefetch (ACL'd), still
    exercises every parser code path.
#>
[CmdletBinding()]
param([string]$OutDir = $PSScriptRoot)

$ErrorActionPreference = 'Stop'
$Work = Join-Path $env:TEMP "hawk_rawtest_$(Get-Date -Format yyyyMMddHHmmss)"
New-Item -ItemType Directory -Force "$Work\raw\evtx", "$Work\raw\prefetch", "$Work\raw\registry", "$Work\artifacts" | Out-Null

# --- 1. real EVTX exports ----------------------------------------------------
Write-Host '[*] Exporting real event logs (System, PowerShell/Operational)...'
cmd /c "wevtutil epl System `"$Work\raw\evtx\System.evtx`" 2>nul"
cmd /c "wevtutil epl `"Microsoft-Windows-PowerShell/Operational`" `"$Work\raw\evtx\Microsoft-Windows-PowerShell%4Operational.evtx`" 2>nul"
cmd /c "wevtutil epl Security `"$Work\raw\evtx\Security.evtx`" 2>nul"   # works only elevated
if (-not (Test-Path "$Work\raw\evtx\Security.evtx")) { Write-Host '    (Security.evtx skipped — not elevated)' }

# --- 2. synthetic SCCA v30 prefetch -------------------------------------------
Write-Host '[*] Building synthetic prefetch (SCCA v30, uncompressed)...'
$pf = New-Object byte[] 0x400
[BitConverter]::GetBytes(30).CopyTo($pf, 0)                        # version
[Text.Encoding]::ASCII.GetBytes('SCCA').CopyTo($pf, 4)
[BitConverter]::GetBytes(3).CopyTo($pf, 8)
[BitConverter]::GetBytes($pf.Length).CopyTo($pf, 0xC)              # file size
[Text.Encoding]::Unicode.GetBytes('EVIL.EXE').CopyTo($pf, 0x10)    # exe name
[BitConverter]::GetBytes([uint32]0x12345678).CopyTo($pf, 0x4C)     # pf hash
[BitConverter]::GetBytes(0x130).CopyTo($pf, 0x54)                  # metrics offset → run count @0xD0
[BitConverter]::GetBytes(0x200).CopyTo($pf, 0x64)                  # strings offset
[BitConverter]::GetBytes(0x80).CopyTo($pf, 0x68)                   # strings size
[BitConverter]::GetBytes(0x300).CopyTo($pf, 0x6C)                  # volume info offset
[BitConverter]::GetBytes(1).CopyTo($pf, 0x70)                      # volume count
$run1 = [DateTime]::new(2026, 6, 1, 10, 0, 0, [DateTimeKind]::Utc).ToFileTimeUtc()
$run2 = [DateTime]::new(2026, 5, 30, 8, 30, 0, [DateTimeKind]::Utc).ToFileTimeUtc()
[BitConverter]::GetBytes($run1).CopyTo($pf, 0x80)                  # last run [0]
[BitConverter]::GetBytes($run2).CopyTo($pf, 0x88)                  # last run [1]
[BitConverter]::GetBytes(5).CopyTo($pf, 0xD0)                      # run count
$strings = "\VOLUME{x}\WINDOWS\SYSTEM32\NTDLL.DLL`0\USERS\VICTIM\APPDATA\EVIL.EXE`0"
[Text.Encoding]::Unicode.GetBytes($strings).CopyTo($pf, 0x200)
$volCreated = [DateTime]::new(2024, 1, 15, 0, 0, 0, [DateTimeKind]::Utc).ToFileTimeUtc()
[BitConverter]::GetBytes($volCreated).CopyTo($pf, 0x308)           # volume created
[BitConverter]::GetBytes([uint32]3405691582).CopyTo($pf, 0x310)    # volume serial 0xCAFEBABE
[IO.File]::WriteAllBytes("$Work\raw\prefetch\EVIL.EXE-12345678.pf", $pf)

# --- 3. synthetic SYSTEM + Amcache hives (regf binary, built directly) ---------
# reg.exe save needs SeBackupPrivilege (admin) — instead we emit the regf
# structures the parser consumes: base block, nk/vk cells, lf subkey lists.
Write-Host '[*] Building synthetic SYSTEM + Amcache hives (regf format)...'

$script:HiveCells = $null; $script:HiveSize = 0
function Reset-Hive { $script:HiveCells = New-Object System.Collections.ArrayList; $script:HiveSize = 0 }
function Add-Cell([byte[]]$payload) {
    # 4-byte size prefix (negative = allocated), 8-byte aligned
    $total = 4 + $payload.Length
    $pad = (8 - ($total % 8)) % 8
    $cell = New-Object byte[] ($total + $pad)
    [BitConverter]::GetBytes(-($total + $pad)).CopyTo($cell, 0)
    $payload.CopyTo($cell, 4)
    $off = $script:HiveSize
    [void]$script:HiveCells.Add($cell)
    $script:HiveSize += $cell.Length
    return $off
}
function Add-Vk([string]$name, [int]$type, [byte[]]$data) {
    $nameB = [Text.Encoding]::ASCII.GetBytes($name)
    if ($type -eq 4 -and $data.Length -le 4) {        # inline dword
        $dataOff = 0; $dataSize = [uint32]$data.Length -bor [uint32]2147483648   # 0x80000000 inline flag
    } else {
        $dataOff = Add-Cell $data; $dataSize = [uint32]$data.Length
    }
    $vk = New-Object byte[] (0x14 + $nameB.Length)
    [Text.Encoding]::ASCII.GetBytes('vk').CopyTo($vk, 0)
    [BitConverter]::GetBytes([uint16]$nameB.Length).CopyTo($vk, 2)
    [BitConverter]::GetBytes($dataSize).CopyTo($vk, 4)
    if ($type -eq 4 -and $data.Length -le 4) { $data.CopyTo($vk, 8) }
    else { [BitConverter]::GetBytes($dataOff).CopyTo($vk, 8) }
    [BitConverter]::GetBytes($type).CopyTo($vk, 0xC)
    [BitConverter]::GetBytes([uint16]1).CopyTo($vk, 0x10)   # ascii name flag
    $nameB.CopyTo($vk, 0x14)
    return Add-Cell $vk
}
function Add-Key([string]$name, [hashtable[]]$values, [int[]]$subkeyOffsets) {
    $valListOff = -1
    if ($values.Count -gt 0) {
        $vkOffs = foreach ($v in $values) { Add-Vk $v.name $v.type $v.data }
        $list = New-Object byte[] (4 * $vkOffs.Count)
        for ($i = 0; $i -lt $vkOffs.Count; $i++) { [BitConverter]::GetBytes([int]$vkOffs[$i]).CopyTo($list, $i * 4) }
        $valListOff = Add-Cell $list
    }
    $subListOff = -1
    if ($subkeyOffsets.Count -gt 0) {
        $lf = New-Object byte[] (4 + 8 * $subkeyOffsets.Count)
        [Text.Encoding]::ASCII.GetBytes('lf').CopyTo($lf, 0)
        [BitConverter]::GetBytes([uint16]$subkeyOffsets.Count).CopyTo($lf, 2)
        for ($i = 0; $i -lt $subkeyOffsets.Count; $i++) { [BitConverter]::GetBytes($subkeyOffsets[$i]).CopyTo($lf, 4 + $i * 8) }
        $subListOff = Add-Cell $lf
    }
    $nameB = [Text.Encoding]::ASCII.GetBytes($name)
    $nk = New-Object byte[] (0x4C + $nameB.Length)
    [Text.Encoding]::ASCII.GetBytes('nk').CopyTo($nk, 0)
    [BitConverter]::GetBytes([uint16]0x20).CopyTo($nk, 2)    # KEY_COMP_NAME
    [BitConverter]::GetBytes([DateTime]::new(2026,5,29,12,0,0,[DateTimeKind]::Utc).ToFileTimeUtc()).CopyTo($nk, 4)
    [BitConverter]::GetBytes([int]$subkeyOffsets.Count).CopyTo($nk, 0x14)
    [BitConverter]::GetBytes([int]$subListOff).CopyTo($nk, 0x1C)
    [BitConverter]::GetBytes([int]$values.Count).CopyTo($nk, 0x24)
    [BitConverter]::GetBytes([int]$valListOff).CopyTo($nk, 0x28)
    [BitConverter]::GetBytes([uint16]$nameB.Length).CopyTo($nk, 0x48)
    $nameB.CopyTo($nk, 0x4C)
    return Add-Cell $nk
}
function Save-Hive([int]$rootOffset, [string]$path) {
    $base = New-Object byte[] 0x1000
    [Text.Encoding]::ASCII.GetBytes('regf').CopyTo($base, 0)
    [BitConverter]::GetBytes($rootOffset).CopyTo($base, 0x24)
    $ms = New-Object IO.MemoryStream
    $ms.Write($base, 0, $base.Length)
    foreach ($c in $script:HiveCells) { $ms.Write($c, 0, $c.Length) }
    [IO.File]::WriteAllBytes($path, $ms.ToArray())
}
function Sz([string]$s)  { ,([Text.Encoding]::Unicode.GetBytes($s + "`0")) }
function Dw([uint32]$v)  { ,([BitConverter]::GetBytes($v)) }

# shimcache blob: Win10 layout — 0x30 header, then 10ts entries
function New-ShimEntry([string]$path, [DateTime]$mtime) {
    $p = [Text.Encoding]::Unicode.GetBytes($path)
    $entrySize = 2 + $p.Length + 8 + 4
    $e = New-Object byte[] (12 + $entrySize)
    [Text.Encoding]::ASCII.GetBytes('10ts').CopyTo($e, 0)
    [BitConverter]::GetBytes($entrySize).CopyTo($e, 8)
    [BitConverter]::GetBytes([uint16]$p.Length).CopyTo($e, 12)
    $p.CopyTo($e, 14)
    [BitConverter]::GetBytes($mtime.ToFileTimeUtc()).CopyTo($e, 14 + $p.Length)
    return $e
}
$blob = New-Object byte[] 0x30
[BitConverter]::GetBytes(0x30).CopyTo($blob, 0)
$blob += New-ShimEntry 'C:\Users\victim\AppData\Local\Temp\dropper.exe' ([DateTime]::new(2026,5,28,14,0,0,[DateTimeKind]::Utc))
$blob += New-ShimEntry 'C:\Windows\System32\calc.exe' ([DateTime]::new(2025,11,2,3,0,0,[DateTimeKind]::Utc))

# SYSTEM hive: ROOT { Select(Current=1), ControlSet001\Control\Session Manager\AppCompatCache }
Reset-Hive
$selectOff  = Add-Key 'Select' @(@{name='Current'; type=4; data=(Dw 1)}) @()
$accOff     = Add-Key 'AppCompatCache' @(@{name='AppCompatCache'; type=3; data=$blob}) @()
$smOff      = Add-Key 'Session Manager' @() @($accOff)
$controlOff = Add-Key 'Control' @() @($smOff)
$cs1Off     = Add-Key 'ControlSet001' @() @($controlOff)
$rootOff    = Add-Key 'ROOT' @() @($selectOff, $cs1Off)
Save-Hive $rootOff "$Work\raw\registry\SYSTEM"

# Amcache hive: ROOT { Root { InventoryApplicationFile{...}, InventoryDriverBinary{...} } }
Reset-Hive
$appOff = Add-Key 'evil.exe|abc123' @(
    @{name='LowerCaseLongPath'; type=1; data=(Sz 'c:\users\victim\appdata\evil.exe')},
    @{name='Name';              type=1; data=(Sz 'evil.exe')},
    @{name='Publisher';         type=1; data=(Sz 'totally legit ltd')},
    @{name='FileId';            type=1; data=(Sz '0000aabbccddeeff00112233445566778899aabb')},
    @{name='Size';              type=1; data=(Sz '482304')},
    @{name='LinkDate';          type=1; data=(Sz '05/20/2026 11:22:33')}
) @()
$iafOff = Add-Key 'InventoryApplicationFile' @() @($appOff)
$drvOff = Add-Key 'rootkit.sys' @(
    @{name='DriverSigned';  type=4; data=(Dw 0)},
    @{name='DriverCompany'; type=1; data=(Sz 'unknown')},
    @{name='Service';       type=1; data=(Sz 'rk0')}
) @()
$idbOff  = Add-Key 'InventoryDriverBinary' @() @($drvOff)
$amRoot  = Add-Key 'Root' @() @($iafOff, $idbOff)
$rootOff = Add-Key 'ROOT' @() @($amRoot)
Save-Hive $rootOff "$Work\raw\registry\Amcache.hve"

# --- 4. manifest + zip ----------------------------------------------------------
@{
    schemaVersion = '1.0'
    tool = @{ name = 'HawkCollector'; version = '2.0.0-test' }
    case = @{ caseNumber = 'RAWTEST-001'; investigator = 'parser-test'
              collectionStartUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
              collectionEndUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
    host = @{ hostname = $env:COMPUTERNAME; os = @{ caption = 'test'; version = '10.0'; build = 26200 }
              role = 'workstation' }
    preset = 'rawtest'
    modules = @()
    rawArtifacts = @()
} | ConvertTo-Json -Depth 6 | Out-File "$Work\manifest.json" -Encoding utf8

$Session = Join-Path $OutDir 'RAWTEST-001.hawk'
if (Test-Path $Session) { Remove-Item $Session -Force }
Add-Type -AssemblyName System.IO.Compression.FileSystem
[IO.Compression.ZipFile]::CreateFromDirectory($Work, $Session, 'Optimal', $false)
Remove-Item $Work -Recurse -Force
Write-Host "[+] Test session: $Session"
