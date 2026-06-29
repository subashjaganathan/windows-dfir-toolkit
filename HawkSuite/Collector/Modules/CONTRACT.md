# Collection Module Contract (v2)

Every module under `Modules\<Category>\<Name>.ps1` must:

1. Accept exactly these parameters:
   ```powershell
   param([Parameter(Mandatory)][string]$SessionRoot, $Config)
   ```
2. Import nothing globally — `Hawk.Common.psm1` is already loaded by the orchestrator.
3. Collect **raw observations only**. Forbidden in output:
   `IsSuspicious`, `Severity`, `RiskScore`, verdicts, detection flags of any kind.
4. Call `Export-HawkArtifact -SessionRoot $SessionRoot -ArtifactType <name> -Records $records`
   exactly once per artifact type and **return the record count**.
5. Use `Get-HawkFileIdentity` for every binary reference (gives sha256+md5+signature).
6. Use `ConvertTo-HawkUtc` for every timestamp. Unknown timestamps stay `$null`.
7. Never truncate command lines, script blocks, or paths.
8. Read-only against the target system. No network calls.

## Migrating a v1 script (windows-dfir-toolkit)

| v1 (DFIR_Common)            | v2 (Hawk.Common)                      |
|-----------------------------|----------------------------------------|
| `Test-AdminRights`          | (orchestrator handles it — remove)     |
| `New-EvidenceEnvelope` + COC| `Export-HawkArtifact` (envelope built in) |
| `Export-EvidenceJson` + hash| `Export-HawkArtifact` (hashing done once at session level) |
| per-script log file         | `Write-HawkLog` (single collector.log) |
| `IsSuspicious` tagging      | DELETE — analyzer's MRI engine does this |
| HTML/report generation      | DELETE — analyzer does this            |

See `Execution\processes.ps1` for the reference implementation.
