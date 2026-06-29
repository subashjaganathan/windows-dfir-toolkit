<#
.SYNOPSIS
    Module: injected_memory - per-process private executable memory regions.

    RAW COLLECTION ONLY. Records committed memory that is BOTH private
    (MEM_PRIVATE, i.e. not backed by an image/file on disk) AND executable
    (PAGE_EXECUTE*). That combination is the classic code-injection / process-
    hollowing / shellcode footprint Redline surfaced via Memoryze. Legitimate
    JIT engines (.NET, browsers, Java) also produce it, so this module ONLY
    records the facts (region addresses/sizes/protections + the host process
    identity/signature); the analyzer's MRI rule decides significance by
    requiring convergence (e.g. unsigned host + RWX region).

    Read-only. Inaccessible/protected processes are counted and skipped.
#>
param([Parameter(Mandatory)][string]$SessionRoot, $Config)

Write-HawkLog 'injected_memory: collection started'

Add-Type -ErrorAction SilentlyContinue -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

public static class HawkMem
{
    [StructLayout(LayoutKind.Sequential)]
    struct MEMORY_BASIC_INFORMATION {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint   AllocationProtect;
        public IntPtr RegionSize;
        public uint   State;
        public uint   Protect;
        public uint   Type;
    }

    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr VirtualQueryEx(IntPtr h, IntPtr addr, out MEMORY_BASIC_INFORMATION mbi, IntPtr len);

    const uint PROCESS_QUERY_INFORMATION = 0x0400;
    const uint PROCESS_VM_READ           = 0x0010;
    const uint MEM_COMMIT  = 0x1000;
    const uint MEM_PRIVATE = 0x20000;
    const uint EXEC_MASK   = 0x10 | 0x20 | 0x40 | 0x80; // EXECUTE | _READ | _READWRITE | _WRITECOPY
    const uint PAGE_RWX    = 0x40;                       // EXECUTE_READWRITE

    // Returns: null = could not open (access denied / protected);
    // "" = accessible, no private-exec regions;
    // else newline-joined "hexBase|size|protectHex|rwx(0/1)" (capped).
    public static string Scan(int pid)
    {
        IntPtr h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
        if (h == IntPtr.Zero) return null;
        try {
            var sb = new StringBuilder();
            IntPtr addr = IntPtr.Zero;
            IntPtr mbiLen = (IntPtr)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION));
            int kept = 0, scanned = 0;
            while (scanned++ < 200000) {
                MEMORY_BASIC_INFORMATION mbi;
                if (VirtualQueryEx(h, addr, out mbi, mbiLen) == IntPtr.Zero) break;
                bool exec = (mbi.Protect & EXEC_MASK) != 0;
                if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE && exec) {
                    if (kept < 64) {
                        int rwx = (mbi.Protect == PAGE_RWX) ? 1 : 0;
                        sb.Append(((long)mbi.BaseAddress).ToString("X")).Append('|')
                          .Append((long)mbi.RegionSize).Append('|')
                          .Append(mbi.Protect.ToString("X")).Append('|')
                          .Append(rwx).Append('\n');
                    }
                    kept++;
                }
                long next = (long)mbi.BaseAddress + (long)mbi.RegionSize;
                if (next <= (long)addr) break;             // guard against stall
                addr = (IntPtr)next;
            }
            return sb.ToString();
        }
        finally { CloseHandle(h); }
    }
}
'@

$records      = New-Object System.Collections.Generic.List[object]
$inaccessible = 0

# pid -> CIM process (path + name) in one pass
$byPid = @{}
foreach ($p in (Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)) { $byPid[[int]$p.ProcessId] = $p }

foreach ($procId in $byPid.Keys) {
    if ($procId -le 4) { continue }   # System/Idle have no user-mode private memory
    $scan = $null
    try { $scan = [HawkMem]::Scan($procId) } catch { $inaccessible++; continue }
    if ($null -eq $scan) { $inaccessible++; continue }     # could not open
    if ($scan.Length -eq 0) { continue }                   # accessible, nothing private-exec

    $cim  = $byPid[$procId]
    $path = $cim.ExecutablePath
    $identity = if ($path) { Get-HawkFileIdentity -Path $path }
                else { @{ sha256 = $null; md5 = $null; signatureStatus = 'Unknown'; signer = $null } }

    $regions = New-Object System.Collections.Generic.List[object]
    $rwx = 0
    foreach ($line in ($scan -split "`n")) {
        if (-not $line) { continue }
        $f = $line -split '\|'
        if ($f.Count -lt 4) { continue }
        if ($f[3] -eq '1') { $rwx++ }
        $regions.Add([ordered]@{
            baseAddress = '0x' + $f[0]
            regionSize  = [int64]$f[1]
            protect     = '0x' + $f[2]
            isRwx       = ($f[3] -eq '1')
        })
    }

    $records.Add([ordered]@{
        pid                    = $procId
        name                   = $cim.Name
        path                   = $path
        commandLine            = $cim.CommandLine
        privateExecRegionCount = $regions.Count
        rwxRegionCount         = $rwx
        sha256                 = $identity.sha256
        md5                    = $identity.md5
        signatureStatus        = $identity.signatureStatus
        signer                 = $identity.signer
        regions                = $regions
    })
}

if ($inaccessible -gt 0) {
    Write-HawkLog "injected_memory: $inaccessible process(es) inaccessible (access denied / protected); skipped" 'WARN'
}

Export-HawkArtifact -SessionRoot $SessionRoot -ArtifactType 'injected_memory' -Records $records
