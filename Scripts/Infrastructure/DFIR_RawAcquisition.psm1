#Requires -Version 5.1
<#
.SYNOPSIS
    DFIR Toolkit - raw acquisition helpers (VSS shadow copies + raw NTFS metadata).

.DESCRIPTION
    Shared by Registry_Hive_Export and MFT_USN_Collection.

    Shadow copies
      Get-DfirShadow creates ONE fresh shadow copy of a volume per collection run
      (Win32_ShadowCopy.Create - works on client AND server Windows, unlike
      `vssadmin create shadow`) and mounts it as a directory link so ordinary file
      APIs can read locked files (registry hives + their .LOG1/.LOG2, Amcache).
      Under the orchestrator the shadow is reused by every script and removed by
      Remove-DfirShadows at the end of the run; standalone scripts remove their own.
      Creating a shadow writes copy-on-write data to the volume - one per run keeps
      that footprint minimal, and the shadow ID is recorded for the analyst.

      The old approach read the FIRST shadow listed by `vssadmin list shadows` - the
      OLDEST one - so a "fallback" hive could be weeks stale yet labelled current.

    Raw NTFS metadata
      $MFT, $LogFile and $UsnJrnl:$J are NTFS metafiles: Copy-Item, robocopy /B and
      esentutl cannot open them. They are extracted with raw cluster reads from the
      shadow DEVICE by following each file's own $DATA run list (ported from the DFIR
      Hawk collector, same author, MIT). Admin required.
#>

Set-StrictMode -Version 2.0

Add-Type -ErrorAction SilentlyContinue -TypeDefinition @'
using System;
using System.IO;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public static class DfirRawNtfs
{
    const uint GENERIC_READ = 0x80000000;
    const uint FILE_SHARE_RW = 0x3;
    const uint OPEN_EXISTING = 3;

    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr sec, uint disp, uint flags, IntPtr tmpl);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool ReadFile(IntPtr h, byte[] buf, int len, out int read, IntPtr ov);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool SetFilePointerEx(IntPtr h, long dist, out long np, uint method);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool CloseHandle(IntPtr h);

    static void Seek(IntPtr h, long off) {
        long np; if (!SetFilePointerEx(h, off, out np, 0)) throw new IOException("seek err " + Marshal.GetLastWin32Error());
    }

    // Reads len bytes at offset (sector-aligned; whole-cluster reads satisfy this).
    static byte[] ReadAt(IntPtr h, long offset, int len) {
        Seek(h, offset);
        byte[] outBuf = new byte[len];
        int done = 0;
        while (done < len) {
            int want = Math.Min(len - done, 8 * 1024 * 1024);
            byte[] tmp = new byte[want];
            int got;
            if (!ReadFile(h, tmp, want, out got, IntPtr.Zero)) throw new IOException("read err " + Marshal.GetLastWin32Error());
            if (got <= 0) break;
            Array.Copy(tmp, 0, outBuf, done, got);
            done += got;
        }
        return outBuf;
    }

    static void ApplyFixup(byte[] rec, int bps) {
        ushort usaOff = BitConverter.ToUInt16(rec, 4);
        ushort usaCnt = BitConverter.ToUInt16(rec, 6);
        for (int i = 1; i < usaCnt; i++) {
            int sectorEnd = i * bps - 2;
            if (sectorEnd + 2 > rec.Length || usaOff + i * 2 + 1 >= rec.Length) break;
            rec[sectorEnd]     = rec[usaOff + i * 2];
            rec[sectorEnd + 1] = rec[usaOff + i * 2 + 1];
        }
    }

    // Non-resident data runs -> {lcn (-1 if sparse), clusterCount, sparseFlag}.
    static List<long[]> ParseRuns(byte[] rec, int attrOff) {
        var runs = new List<long[]>();
        int p = attrOff + BitConverter.ToUInt16(rec, attrOff + 0x20);
        long lcn = 0;
        while (p < rec.Length && rec[p] != 0) {
            int lenBytes = rec[p] & 0x0F, offBytes = (rec[p] >> 4) & 0x0F;
            p++;
            if (lenBytes == 0 || p + lenBytes + offBytes > rec.Length) break;
            long runLen = 0;
            for (int i = 0; i < lenBytes; i++) runLen |= ((long)rec[p + i]) << (8 * i);
            p += lenBytes;
            bool sparse = (offBytes == 0);
            if (!sparse) {
                long ro = 0;
                for (int i = 0; i < offBytes; i++) ro |= ((long)rec[p + i]) << (8 * i);
                if ((rec[p + offBytes - 1] & 0x80) != 0) for (int i = offBytes; i < 8; i++) ro |= ((long)0xFF) << (8 * i);
                lcn += ro;
            }
            p += offBytes;
            runs.Add(new long[] { sparse ? -1 : lcn, runLen, sparse ? 1 : 0 });
        }
        return runs;
    }

    // First NON-RESIDENT attribute of a type (+ optional stream name); -1 if none.
    // Throws if the record holds an $ATTRIBUTE_LIST and the attribute is not inline -
    // that file is too fragmented for this reader, and saying so beats a silent miss.
    static int FindAttr(byte[] rec, uint type, string name) {
        int off = BitConverter.ToUInt16(rec, 0x14);
        bool hasList = false;
        while (off + 8 <= rec.Length) {
            uint t = BitConverter.ToUInt32(rec, off);
            if (t == 0xFFFFFFFF) break;
            int len = (int)BitConverter.ToUInt32(rec, off + 4);
            if (len <= 0 || off + len > rec.Length) break;
            if (t == 0x20) hasList = true;
            if (t == type && rec[off + 8] != 0) {
                byte nameLen = rec[off + 9];
                string an = nameLen > 0 ? System.Text.Encoding.Unicode.GetString(rec, off + BitConverter.ToUInt16(rec, off + 10), nameLen * 2) : null;
                if ((name == null && an == null) || (name != null && name == an)) return off;
            }
            off += len;
        }
        if (hasList) throw new IOException("attribute is in an $ATTRIBUTE_LIST extension record (heavily fragmented file) - acquire from a full disk image");
        return -1;
    }

    static bool HasFileName(byte[] w, string target) {
        int off = BitConverter.ToUInt16(w, 0x14);
        while (off + 8 <= w.Length) {
            uint t = BitConverter.ToUInt32(w, off);
            if (t == 0xFFFFFFFF) break;
            int len = (int)BitConverter.ToUInt32(w, off + 4);
            if (len <= 0 || off + len > w.Length) break;
            if (t == 0x30 && w[off + 8] == 0) {
                int co = BitConverter.ToUInt16(w, off + 0x14);
                int nl = off + co + 0x40, ns = off + co + 0x42;
                if (nl < w.Length && ns + w[nl] * 2 <= w.Length &&
                    System.Text.Encoding.Unicode.GetString(w, ns, w[nl] * 2) == target) return true;
            }
            off += len;
        }
        return false;
    }

    class Vol { public IntPtr H; public int Bps; public int Cluster; public long MftLcn; public int RecSize; }

    static Vol OpenVol(string device) {
        IntPtr h = CreateFileW(device, GENERIC_READ, FILE_SHARE_RW, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
        if (h == new IntPtr(-1)) throw new IOException("open failed " + device + " err " + Marshal.GetLastWin32Error());
        byte[] boot = ReadAt(h, 0, 512);
        var v = new Vol { H = h };
        if (System.Text.Encoding.ASCII.GetString(boot, 3, 4) != "NTFS") { CloseHandle(h); throw new IOException("not an NTFS volume"); }
        v.Bps = BitConverter.ToUInt16(boot, 0x0B);
        v.Cluster = v.Bps * boot[0x0D];
        v.MftLcn = BitConverter.ToInt64(boot, 0x30);
        sbyte cpr = (sbyte)boot[0x40];
        v.RecSize = cpr > 0 ? cpr * v.Cluster : (1 << (-cpr));
        if (v.Bps == 0 || v.Cluster == 0 || v.RecSize == 0) { CloseHandle(h); throw new IOException("bad NTFS boot sector"); }
        return v;
    }

    // Writes the run data; trims the final cluster slack to the attribute's real size.
    static long StreamRuns(IntPtr h, List<long[]> runs, int cluster, long realSize, FileStream fs, bool keepSparseAsZeros) {
        long written = 0;
        foreach (var run in runs) {
            long remaining = run[1] * (long)cluster;
            if (run[2] == 1) {
                if (keepSparseAsZeros) { fs.SetLength(fs.Length + remaining); fs.Seek(0, SeekOrigin.End); written += remaining; }
                continue;
            }
            long pos = run[0] * (long)cluster;
            while (remaining > 0) {
                int chunk = (int)Math.Min(remaining, 8L * 1024 * 1024);
                byte[] data = ReadAt(h, pos, chunk);
                fs.Write(data, 0, chunk);
                pos += chunk; remaining -= chunk; written += chunk;
            }
        }
        if (realSize > 0 && fs.Length > realSize) { fs.SetLength(realSize); written = realSize; }
        return written;
    }

    static long RealSize(byte[] rec, int attrOff) { return BitConverter.ToInt64(rec, attrOff + 0x30); }

    static byte[] ReadRecord(Vol v, long recordNo) {
        // Records 0-15 always live in the first $MFT extent (contiguous at MftLcn).
        byte[] rec = ReadAt(v.H, v.MftLcn * (long)v.Cluster + recordNo * v.RecSize, v.RecSize);
        if (!(rec[0] == 'F' && rec[1] == 'I' && rec[2] == 'L' && rec[3] == 'E')) throw new IOException("MFT record " + recordNo + " has no FILE signature");
        ApplyFixup(rec, v.Bps);
        return rec;
    }

    // Unnamed $DATA of a system file record: 0 = $MFT, 2 = $LogFile.
    public static long ExtractSystemFile(string device, long recordNo, string outPath) {
        Vol v = OpenVol(device);
        try {
            byte[] rec = ReadRecord(v, recordNo);
            int a = FindAttr(rec, 0x80, null);
            if (a < 0) throw new IOException("$DATA not found in record " + recordNo);
            using (var fs = new FileStream(outPath, FileMode.Create, FileAccess.Write))
                return StreamRuns(v.H, ParseRuns(rec, a), v.Cluster, RealSize(rec, a), fs, false);
        } finally { CloseHandle(v.H); }
    }

    // Scans an extracted $MFT for $UsnJrnl and streams its $J stream. Sparse runs
    // (the purged front of the journal) are SKIPPED: records are self-describing,
    // and the sparse prefix can be gigabytes of zeros. -1 if not found.
    public static long ExtractUsnJournal(string device, string mftPath, string outPath) {
        Vol v = OpenVol(device);
        try {
            using (var mft = new FileStream(mftPath, FileMode.Open, FileAccess.Read)) {
                byte[] rec = new byte[v.RecSize];
                long count = mft.Length / v.RecSize;
                for (long i = 0; i < count; i++) {
                    if (mft.Read(rec, 0, v.RecSize) < v.RecSize) break;
                    if (!(rec[0] == 'F' && rec[1] == 'I' && rec[2] == 'L' && rec[3] == 'E')) continue;
                    if ((BitConverter.ToUInt16(rec, 0x16) & 0x01) == 0) continue;
                    byte[] w = (byte[])rec.Clone();
                    ApplyFixup(w, v.Bps);
                    if (!HasFileName(w, "$UsnJrnl")) continue;
                    int a = FindAttr(w, 0x80, "$J");
                    if (a < 0) continue;
                    using (var fs = new FileStream(outPath, FileMode.Create, FileAccess.Write))
                        return StreamRuns(v.H, ParseRuns(w, a), v.Cluster, 0, fs, false);
                }
            }
            return -1;
        } finally { CloseHandle(v.H); }
    }
}
'@

function Get-DfirShadow {
    <#
      Returns @{ Id; Device; Link; Created; CreatedUtc } for a fresh shadow of Volume
      (e.g. 'C:'). Reuses a shadow created earlier in the same run (orchestrator) -
      shared via environment variables because each script imports this module anew.
      $null if a shadow cannot be created (caller falls back and records why).
    #>
    param([Parameter(Mandatory)][string]$Volume, [string]$LogFile)
    $letter = $Volume.TrimEnd(':', '\').ToUpperInvariant()
    $envId = "DFIR_SHADOW_${letter}_ID"; $envLink = "DFIR_SHADOW_${letter}_LINK"; $envDev = "DFIR_SHADOW_${letter}_DEVICE"
    $existingLink = [Environment]::GetEnvironmentVariable($envLink)
    if ($existingLink -and (Test-Path -LiteralPath $existingLink)) {
        return @{ Id = [Environment]::GetEnvironmentVariable($envId); Device = [Environment]::GetEnvironmentVariable($envDev)
                  Link = $existingLink; Created = $false; CreatedUtc = $null }
    }
    function Log($m) { if ($LogFile) { Add-Content $LogFile "$(Get-Date -Format o) [INFO] :: $m" } }
    try {
        $res = ([wmiclass]'root\cimv2:Win32_ShadowCopy').Create("$letter`:\", 'ClientAccessible')
        if ($res.ReturnValue -ne 0 -or -not $res.ShadowID) { Log "VSS create for ${letter}: returned $($res.ReturnValue)"; return $null }
        $sc = Get-CimInstance Win32_ShadowCopy -Filter "ID='$($res.ShadowID)'" -ErrorAction Stop
        $link = Join-Path $env:TEMP ("dfir_vss_{0}_{1}" -f $letter, ([guid]::NewGuid().ToString('N').Substring(0, 8)))
        cmd /c mklink /d "$link" "$($sc.DeviceObject)\" 1>$null 2>$null
        if (-not (Test-Path -LiteralPath $link)) {
            Remove-CimInstance -InputObject $sc -ErrorAction SilentlyContinue
            Log "VSS ${letter}: could not link $($sc.DeviceObject)"; return $null
        }
        [Environment]::SetEnvironmentVariable($envId, $res.ShadowID)
        [Environment]::SetEnvironmentVariable($envLink, $link)
        [Environment]::SetEnvironmentVariable($envDev, $sc.DeviceObject)
        $env:DFIR_SHADOWS_CREATED = ((@("$env:DFIR_SHADOWS_CREATED" -split ';') + $letter) | Where-Object { $_ } | Sort-Object -Unique) -join ';'
        Log "VSS ${letter}: created $($res.ShadowID) at $($sc.DeviceObject), linked $link"
        return @{ Id = $res.ShadowID; Device = $sc.DeviceObject; Link = $link; Created = $true; CreatedUtc = ([DateTime]::UtcNow).ToString('o') }
    } catch { Log "VSS ${letter}: $_"; return $null }
}

function Remove-DfirShadows {
    <# Removes every shadow (and its link) created through Get-DfirShadow in this run. #>
    param([string]$LogFile)
    foreach ($letter in @($env:DFIR_SHADOWS_CREATED -split ';' | Where-Object { $_ } | Sort-Object -Unique)) {
        $id = [Environment]::GetEnvironmentVariable("DFIR_SHADOW_${letter}_ID")
        $link = [Environment]::GetEnvironmentVariable("DFIR_SHADOW_${letter}_LINK")
        if ($link) { cmd /c rmdir "$link" 1>$null 2>$null }   # removes the link only, never the contents
        if ($id) {
            Get-CimInstance Win32_ShadowCopy -Filter "ID='$id'" -ErrorAction SilentlyContinue | Remove-CimInstance -ErrorAction SilentlyContinue
            if ($LogFile) { Add-Content $LogFile "$(Get-Date -Format o) [INFO] :: VSS ${letter}: removed $id" }
        }
        foreach ($n in 'ID', 'LINK', 'DEVICE') { [Environment]::SetEnvironmentVariable("DFIR_SHADOW_${letter}_$n", $null) }
    }
    $env:DFIR_SHADOWS_CREATED = $null
}

function Copy-DfirFromShadow {
    <#
      Copies a file (volume-relative path, e.g. 'Windows\System32\config\SYSTEM') out of
      a mounted shadow, plus its registry transaction logs (.LOG1/.LOG2) when present -
      tools need them to replay a dirty hive. Returns the list of files written.
    #>
    param([Parameter(Mandatory)]$Shadow, [Parameter(Mandatory)][string]$RelPath,
          [Parameter(Mandatory)][string]$Destination, [switch]$WithTransactionLogs)
    $written = @()
    $src = Join-Path $Shadow.Link $RelPath
    if (-not (Test-Path -LiteralPath $src)) { return $written }
    Copy-Item -LiteralPath $src -Destination $Destination -Force -ErrorAction Stop
    $written += $Destination
    if ($WithTransactionLogs) {
        foreach ($ext in '.LOG1', '.LOG2') {
            $l = $src + $ext
            if (Test-Path -LiteralPath $l) {
                Copy-Item -LiteralPath $l -Destination ($Destination + $ext) -Force -ErrorAction SilentlyContinue
                if (Test-Path -LiteralPath ($Destination + $ext)) { $written += ($Destination + $ext) }
            }
        }
    }
    $written
}

function Get-DfirUserProfiles {
    <#
      User profiles from the registry ProfileList (authoritative: catches profiles
      redirected off C:\Users, renamed folders, domain / Entra ID accounts), plus
      anything else under %SystemDrive%\Users. Objects: Sid ($null if disk-only), Name, Path.
    #>
    $seen = @{}; $out = @()
    try {
        foreach ($k in (Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -ErrorAction Stop)) {
            $sid = $k.PSChildName
            if ($sid -notmatch '^S-1-5-21-|^S-1-12-1-') { continue }
            $img = (Get-ItemProperty -LiteralPath $k.PSPath -Name ProfileImagePath -ErrorAction SilentlyContinue).ProfileImagePath
            if (-not $img) { continue }
            $img = [Environment]::ExpandEnvironmentVariables($img)
            if ($seen.ContainsKey($img.ToLowerInvariant())) { continue }
            $seen[$img.ToLowerInvariant()] = $true
            $out += [pscustomobject]@{ Sid = $sid; Name = (Split-Path $img -Leaf); Path = $img }
        }
    } catch {}
    foreach ($u in (Get-ChildItem (Join-Path $env:SystemDrive 'Users') -Directory -ErrorAction SilentlyContinue)) {
        if ($seen.ContainsKey($u.FullName.ToLowerInvariant()) -or $u.Name -in 'Public', 'Default', 'Default User', 'All Users') { continue }
        $seen[$u.FullName.ToLowerInvariant()] = $true
        $out += [pscustomobject]@{ Sid = $null; Name = $u.Name; Path = $u.FullName }
    }
    ,$out
}

Export-ModuleMember -Function Get-DfirShadow, Remove-DfirShadows, Copy-DfirFromShadow, Get-DfirUserProfiles
