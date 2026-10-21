# integrity-check

Detects tampering with log files. It stores a SHA-256 hash of each file, then tells you if any file was changed, deleted or added since. The hash store is signed with HMAC-SHA256, so an attacker can't cover their tracks by rewriting the stored hashes too.

Python standard library only, about 120 lines. Based on the [roadmap.sh File Integrity Checker](https://roadmap.sh/projects/file-integrity-checker) project, with HMAC signing added.

## Use

```bash
export INTEGRITY_KEY='a-long-random-secret'   # Windows: set INTEGRITY_KEY=...

./integrity-check init   /var/log      # store hashes
./integrity-check check  /var/log      # compare; exit code 1 if anything changed
./integrity-check update /var/log/syslog   # accept a legitimate change
```

```
/var/log/auth.log: Unmodified
/var/log/syslog: Modified (Hash mismatch)
WARNING: 1 file(s) failed integrity check - possible tampering.
```

Hashes are saved to `~/.integrity-check/hashes.json`. Set `INTEGRITY_DB` to use another path.

## Threat model

**Detects**
- Edited, deleted or new files under a checked directory
- Edits to `hashes.json` made without the key: `check` prints `ALERT` and refuses to continue

**Does not detect**
- An attacker who has `INTEGRITY_KEY`. Keep the key off the machine you're checking and supply it only when you run `check`.
- Changes made before `init` ran. The baseline is only as trustworthy as the files were at that moment.
- Rollback: an attacker could restore an older, validly signed `hashes.json` together with the matching older files. A remote copy of the store, or a timestamp signed into it, would close this.

## Test

```bash
python test_integrity_check.py
```

It covers unchanged, modified, deleted and re-initialized files, a forged hash store, a wrong key and a missing key.
