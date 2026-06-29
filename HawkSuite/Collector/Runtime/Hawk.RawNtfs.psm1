# Hawk.RawNtfs.psm1 - raw NTFS acquisition of $MFT and $UsnJrnl:$J from a
# volume/shadow-copy device. These are NTFS metadata files that cannot be
# copied with Copy-Item; they require raw cluster reads. Admin required.
#
# Invoke-HawkMftAcquisition opens the shadow DEVICE (e.g.
# \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN), parses the boot sector to
# locate $MFT, follows $MFT's own $DATA run list to stream the full $MFT to
# disk, then scans the extracted $MFT for the $UsnJrnl record and streams its
# $J data-stream runs.

Set-StrictMode -Version 2.0

Add-Type -ErrorAction SilentlyContinue -TypeDefinition @'
using System;
using System.IO;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public static class HawkRawNtfs
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

    // Reads exactly len bytes at offset. Offset/len must be sector-aligned;
    // whole-cluster reads (and the 512-aligned boot read) satisfy this.
    static byte[] ReadAt(IntPtr h, long offset, int len) {
        Seek(h, offset);
        byte[] outBuf = new byte[len];
        int done = 0;
        while (done < len) {
            int want = len - done; if (want > 8 * 1024 * 1024) want = 8 * 1024 * 1024;
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

    // Non-resident attribute data-run list -> list of {lcnOrMinus1IfSparse, clusterCount, sparseFlag}.
    static List<long[]> ParseRuns(byte[] rec, int attrOff) {
        var runs = new List<long[]>();
        int runOff = BitConverter.ToUInt16(rec, attrOff + 0x20);
        int p = attrOff + runOff;
        long lcn = 0;
        while (p < rec.Length && rec[p] != 0) {
            int lenBytes = rec[p] & 0x0F;
            int offBytes = (rec[p] >> 4) & 0x0F;
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

    // First non-resident attribute of given type (+ optional unicode stream name); -1 if none.
    static int FindAttr(byte[] rec, uint type, string name) {
        int off = BitConverter.ToUInt16(rec, 0x14);
        while (off + 8 <= rec.Length) {
            uint t = BitConverter.ToUInt32(rec, off);
            if (t == 0xFFFFFFFF) break;
            int len = (int)BitConverter.ToUInt32(rec, off + 4);
            if (len <= 0 || off + len > rec.Length) break;
            if (t == type && rec[off + 8] != 0) {
                byte nameLen = rec[off + 9];
                bool ok;
                if (name == null) ok = (nameLen == 0);
                else {
                    ushort nameOff = BitConverter.ToUInt16(rec, off + 10);
                    string an = (nameLen > 0) ? System.Text.Encoding.Unicode.GetString(rec, off + nameOff, nameLen * 2) : "";
                    ok = string.Equals(an, name, StringComparison.Ordinal);
                }
                if (ok) return off;
            }
            off += len;
        }
        return -1;
    }

    static bool HasFileName(byte[] rec, int bps, string target) {
        byte[] w = (byte[])rec.Clone();
        ApplyFixup(w, bps);
        int off = BitConverter.ToUInt16(w, 0x14);
        while (off + 8 <= w.Length) {
            uint t = BitConverter.ToUInt32(w, off);
            if (t == 0xFFFFFFFF) break;
            int len = (int)BitConverter.ToUInt32(w, off + 4);
            if (len <= 0 || off + len > w.Length) break;
            if (t == 0x30 && w[off + 8] == 0) {                 // resident $FILE_NAME
                int co = BitConverter.ToUInt16(w, off + 0x14);
                int nlPos = off + co + 0x40;
                if (nlPos < w.Length) {
                    int nameLen = w[nlPos];
                    int ns = off + co + 0x42;
                    if (ns + nameLen * 2 <= w.Length) {
                        string nm = System.Text.Encoding.Unicode.GetString(w, ns, nameLen * 2);
                        if (nm == target) return true;
                    }
                }
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
        var v = new Vol();
        v.H = h;
        v.Bps = BitConverter.ToUInt16(boot, 0x0B);
        int spc = boot[0x0D];
        v.Cluster = v.Bps * spc;
        v.MftLcn = BitConverter.ToInt64(boot, 0x30);
        sbyte cpr = (sbyte)boot[0x40];
        v.RecSize = cpr > 0 ? cpr * v.Cluster : (1 << (-cpr));
        if (v.Bps == 0 || v.Cluster == 0 || v.RecSize == 0) { CloseHandle(h); throw new IOException("not an NTFS volume"); }
        return v;
    }

    static long StreamRuns(IntPtr h, List<long[]> runs, int cluster, FileStream fs) {
        long written = 0;
        foreach (var run in runs) {
            if (run[2] == 1) continue;                          // sparse -> skip
            long pos = run[0] * (long)cluster;
            long remaining = run[1] * (long)cluster;
            while (remaining > 0) {
                int chunk = (int)Math.Min(remaining, 8L * 1024 * 1024);
                byte[] data = ReadAt(h, pos, chunk);
                fs.Write(data, 0, chunk);
                pos += chunk; remaining -= chunk; written += chunk;
            }
        }
        return written;
    }

    public static long ExtractMft(string device, string outPath) {
        Vol v = OpenVol(device);
        try {
            byte[] rec0 = ReadAt(v.H, v.MftLcn * (long)v.Cluster, v.RecSize);
            ApplyFixup(rec0, v.Bps);
            int dataAttr = FindAttr(rec0, 0x80, null);
            if (dataAttr < 0) throw new IOException("$MFT $DATA attribute not found");
            var runs = ParseRuns(rec0, dataAttr);
            using (var fs = new FileStream(outPath, FileMode.Create, FileAccess.Write))
                return StreamRuns(v.H, runs, v.Cluster, fs);
        } finally { CloseHandle(v.H); }
    }

    // Scans an already-extracted $MFT for the $UsnJrnl record and streams its $J runs. -1 if not found.
    public static long ExtractUsnJournal(string device, string mftPath, string outPath) {
        Vol v = OpenVol(device);
        try {
            using (var mft = new FileStream(mftPath, FileMode.Open, FileAccess.Read)) {
                byte[] rec = new byte[v.RecSize];
                long count = mft.Length / v.RecSize;
                for (long i = 0; i < count; i++) {
                    if (mft.Read(rec, 0, v.RecSize) < v.RecSize) break;
                    if (!(rec[0] == (byte)'F' && rec[1] == (byte)'I' && rec[2] == (byte)'L' && rec[3] == (byte)'E')) continue;
                    ushort flags = BitConverter.ToUInt16(rec, 0x16);
                    if ((flags & 0x01) == 0) continue;          // not in use
                    if (!HasFileName(rec, v.Bps, "$UsnJrnl")) continue;
                    byte[] work = (byte[])rec.Clone();
                    ApplyFixup(work, v.Bps);
                    int jAttr = FindAttr(work, 0x80, "$J");
                    if (jAttr < 0) continue;
                    var runs = ParseRuns(work, jAttr);
                    using (var fs = new FileStream(outPath, FileMode.Create, FileAccess.Write))
                        return StreamRuns(v.H, runs, v.Cluster, fs);
                }
            }
            return -1;
        } finally { CloseHandle(v.H); }
    }
}
'@

function Invoke-HawkMftAcquisition {
    <#
      Acquires $MFT (always) and optionally $UsnJrnl:$J from the given shadow
      DEVICE into the session raw\mft tree. Returns nothing; logs via Write-HawkLog.
    #>
    param(
        [Parameter(Mandatory)][string]$Device,
        [Parameter(Mandatory)][string]$WorkRoot,
        [bool]$IncludeUsn = $false,
        [ref]$RawArtifacts = $null
    )
    $mftOut = Join-Path $WorkRoot 'raw\mft\$MFT'
    try {
        $bytes = [HawkRawNtfs]::ExtractMft($Device, $mftOut)
        Write-HawkLog ("MFT acquired: {0:N0} bytes via {1}" -f $bytes, $Device)
        if ($RawArtifacts -and (Test-Path -LiteralPath $mftOut)) {
            $RawArtifacts.Value += [ordered]@{ path = 'raw/mft/$MFT'; source = "$Device\`$MFT"; method = 'raw-ntfs'
                sha256 = (Get-FileHash -LiteralPath $mftOut -Algorithm SHA256).Hash }
        }
    } catch { Write-HawkLog "MFT acquisition failed: $_" 'ERROR'; return }

    if ($IncludeUsn) {
        $usnOut = Join-Path $WorkRoot 'raw\mft\$UsnJrnl_J'
        try {
            $w = [HawkRawNtfs]::ExtractUsnJournal($Device, $mftOut, $usnOut)
            if ($w -ge 0) {
                Write-HawkLog ("USN journal (`$J) acquired: {0:N0} bytes" -f $w)
                if ($RawArtifacts -and (Test-Path -LiteralPath $usnOut)) {
                    $RawArtifacts.Value += [ordered]@{ path = 'raw/mft/$UsnJrnl_J'; source = "$Device\`$Extend\`$UsnJrnl:`$J"; method = 'raw-ntfs'
                        sha256 = (Get-FileHash -LiteralPath $usnOut -Algorithm SHA256).Hash }
                }
            } else { Write-HawkLog 'USN journal record not found' 'WARN' }
        } catch { Write-HawkLog "USN journal acquisition failed: $_" 'WARN' }
    }
}

Export-ModuleMember -Function Invoke-HawkMftAcquisition
