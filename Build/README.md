# Building a single-file executable

The toolkit can be packaged into one self-extracting `.exe` for drop-and-run field use.

## Build

```powershell
# from the repo root
.\Build\Build-Exe.ps1
# optionally sign it (recommended for distribution)
.\Build\Build-Exe.ps1 -SignThumbprint <your-cert-thumbprint>
```

Output: `dist\WindowsDFIRToolkit.exe` (+ a `.sha256` sidecar). Requires only Windows itself -
it compiles with the built-in .NET Framework C# compiler (`csc.exe`); no external toolchain.

## What the exe does

1. Self-elevates (UAC prompt) if not already running as Administrator.
2. Extracts the embedded toolkit to a fresh `%TEMP%\DFIR_Toolkit_<timestamp>` working folder,
   preserving the full `Scripts\` structure.
3. Runs `Run_IR_Collection.ps1` (arguments and `DFIR_*` environment variables are honored).

The launcher only unpacks and invokes - it makes no collection decisions, so collection remains
deterministic and forensically sound. Source: [`Launcher.cs`](Launcher.cs).

## Notes

- **Signing:** an unsigned executable draws more AV/EDR attention than the signed scripts. Sign
  the output (`-SignThumbprint`, or `signtool` manually) before distributing.
- **Distribution:** the `.exe` is a build artifact (git-ignored). Attach it to a GitHub
  **Release** rather than committing it to the repo tree.
- **Environment variables** still apply, e.g. `WindowsDFIRToolkit.exe` after setting
  `$env:DFIR_CASE`, `$env:DFIR_INV`, `$env:DFIR_DAYS`, `$env:DFIR_IOC_FILE`, etc.
