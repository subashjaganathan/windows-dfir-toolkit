# Hawk Windows Collector - single-file executable

The toolkit can be packaged into one self-extracting, signed `.exe` (**Hawk Windows Collector**)
for drop-and-run field use.

## Build

```powershell
# from the repo root
.\Build\Build-Exe.ps1                      # builds + self-signs dist\HawkWindowsCollector.exe
.\Build\Build-Exe.ps1 -SignThumbprint <t>  # sign with your CA-issued code-signing cert
.\Build\Build-Exe.ps1 -NoSign              # build without signing
```

Output: `dist\HawkWindowsCollector.exe` (+ a `.sha256` sidecar). Requires only Windows itself -
it compiles with the built-in .NET Framework C# compiler (`csc.exe`); no external toolchain.

## What the exe does

1. **Self-elevates** (UAC prompt) if not already Administrator.
2. **Extracts** the embedded toolkit to a fresh `%TEMP%\DFIR_Toolkit_<timestamp>` folder,
   preserving the full `Scripts\` structure.
3. **Runs** `Run_IR_Collection.ps1` with **`-ExecutionPolicy Bypass -NoProfile`** so the
   collection never fails on machine execution policy. Arguments and `DFIR_*` environment
   variables are honored.

The launcher only unpacks and invokes - it makes no collection decisions - so collection stays
deterministic and forensically sound. File metadata (Details tab) identifies it as
"Hawk Windows Collector". Source: [`Launcher.cs`](Launcher.cs).

## Signing

- By default the build **self-signs** the exe (Authenticode SHA-256). A self-signed signature
  proves integrity and stamps a publisher, but is **not trusted** on other machines until the
  certificate is added to Trusted Publishers - so SmartScreen/AV will still warn on download.
- For real distribution, sign with a **CA-issued code-signing certificate**:
  `-SignThumbprint <thumbprint>` (cert in `Cert:\CurrentUser\My`).

## Distribution

- The `.exe` is a build artifact (git-ignored) - it is published on the repo's **Releases**
  page, not committed to the tree.
- Always verify the published `SHA256` before running a downloaded copy.
