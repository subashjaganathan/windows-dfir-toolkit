# User-Supplied IOCs

Drop indicator files here (`.txt` or `.csv`) and the toolkit will sweep every collected
evidence artifact for them during reporting (`Scripts/Reporting/IOC_Match.ps1`), surfacing any
hits in the HTML report as a CRITICAL "Indicator Match" finding.

## How to provide indicators

Any of these (first that exists wins):

1. `$env:DFIR_IOC_FILE` - explicit path to one indicator file
2. This `IOCs\` folder - any `.txt` / `.csv` files you place here
3. `<output>\IOCs\` - an `IOCs\` folder inside the evidence output directory

## File format

One indicator per line. Lines starting with `#` are comments. Two accepted forms:

```
# type,value  (type = sha256 | sha1 | md5 | ip | domain | filename)
sha256,e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
ip,203.0.113.10
domain,evil-c2.example
filename,beacon.exe

# or a bare value - the type is auto-detected
8.8.8.8
44d88612fea8a8f36de82e1278abb02f
malicious-domain.test
```

Matching is boundary-aware to keep false positives low (hashes match as whole hex tokens, IPs
and domains match on token boundaries). Note: files named `*.md` (like this one) are NOT
ingested - only `.txt` and `.csv`.
