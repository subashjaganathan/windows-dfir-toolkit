# IOC Matching

Drop indicator files in this folder. On every `hawk import`, Hawk matches them
against the session and writes `ioc-*` rows into the **Findings** view
(severity: critical). Matching is layered on top of MRI scoring — it never
suppresses or replaces it.

## Supported file formats (auto-detected)

| Format | Shape |
|--------|-------|
| `*.json` | `{ "ips":[...], "domains":[...], "sha256":[...], "md5":[...], "sha1":[...] }` |
| `*.csv`  | `type,value[,note]` per line — `type` ∈ `ip` \| `domain` \| `sha256` \| `md5` \| `sha1` |
| `*.txt`  | one indicator per line; type auto-detected by shape |

See `indicators.example.csv` for a template.

## What gets matched

| Indicator | Matched against |
|-----------|-----------------|
| IP        | `network_connections.remote_address` (exact) |
| Domain    | DNS cache + browser history (host and any subdomain) |
| Hash      | process / service / amcache file hashes (sha256, md5, sha1) |

## Rules / safeguards

- **Private/loopback IPs are ignored** in indicator lists — they would match
  half the session and are almost always a mistake, not a lead.
- **Domains match parent suffixes**: an indicator `evil.com` matches
  `evil.com` and `cdn.evil.com`.
- `known-bad-handles.json` in this folder is **MRI content** (mutex/pipe
  signatures), not an IOC list — it is skipped by the IOC matcher.
- A malformed indicator file is skipped with a warning; it never aborts import.

## Known-bad hashes

For file-hash blocklists you want applied as part of the **trust ladder**
(so a match forces MALICIOUS verdict, not just a finding), use
`Configuration/Whitelist/known-bad-md5.txt` instead — that layer wins over
every whitelist/signer trust.
