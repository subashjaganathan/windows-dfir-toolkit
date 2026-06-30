# Security Policy

## Scope

HawkSuite is incident-response software that runs with administrator rights on
target hosts and parses untrusted, attacker-influenced input (event logs,
registry hives, `$MFT`, memory, packet captures). The most serious issues are:

- A crafted artifact that lets a parser execute code or escape the analyzer.
- A collector flaw that damages the target system or contaminates evidence.
- A flaw that causes evidence to be silently dropped or misattributed.

## Reporting a vulnerability

Please report security issues **privately** via GitHub Security Advisories
("Report a vulnerability" on the repository's Security tab) rather than opening
a public issue. Include repro steps and a sample artifact if safe to share.

We aim to acknowledge within a few days and to coordinate disclosure once a fix
is available.

## Handling evidence safely

- Treat `.hawk` packages and memory images as sensitive: they contain hashes,
  paths, account names, and potentially secrets from the target host.
- The collector is read-only and makes no network calls; it does create a VSS
  shadow copy and loads a memory-acquisition driver if one is staged. These are
  recorded in the session manifest (`collectorFootprint`).
- Run the collector only on systems you are authorized to investigate.
