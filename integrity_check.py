#!/usr/bin/env python3
"""Log file integrity checker: SHA-256 baseline + tamper detection.

  integrity-check init   <file|dir>   store hashes (re-run to re-initialize)
  integrity-check check  <file|dir>   compare against stored hashes
  integrity-check update <file|dir>   accept current contents as the new baseline

The hash store is signed with HMAC-SHA256 using the INTEGRITY_KEY environment variable,
so editing hashes.json without the key is detected.
"""
import argparse
import hashlib
import hmac
import json
import os
import sys
from pathlib import Path

DB = Path(os.environ.get("INTEGRITY_DB", Path.home() / ".integrity-check" / "hashes.json"))


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def files_in(target):
    p = Path(target).resolve()
    if p.is_file():
        return [p]
    if p.is_dir():
        return sorted(f for f in p.rglob("*") if f.is_file())
    sys.exit(f"Error: {target} not found")


def key():
    k = os.environ.get("INTEGRITY_KEY", "")
    if len(k) < 16:
        sys.exit("Error: set INTEGRITY_KEY to a secret of at least 16 characters "
                 "(keep it off the machine whose files you are checking).")
    return k.encode()


def sign(hashes):
    body = json.dumps(hashes, sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(key(), body, hashlib.sha256).hexdigest()


def load():
    if not DB.exists():
        return {}
    try:
        data = json.loads(DB.read_text())
        hashes, mac = data["hashes"], data["mac"]
    except (ValueError, KeyError, TypeError):
        hashes, mac = None, ""
    if hashes is None or not hmac.compare_digest(sign(hashes), mac):
        sys.exit(f"ALERT: {DB} failed its signature check - the hash store was tampered with "
                 "or INTEGRITY_KEY is wrong. If you trust the current files, delete it and run init.")
    return hashes


def save(db):
    DB.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(DB.parent, 0o700)  # ponytail: POSIX perms only; on Windows rely on the user-profile ACL
    tmp = DB.with_suffix(".tmp")
    tmp.write_text(json.dumps({"hashes": db, "mac": sign(db)}, indent=2, sort_keys=True))
    os.chmod(tmp, 0o600)
    os.replace(tmp, DB)  # atomic: a crash mid-write never corrupts the baseline


def store(target, msg, reset=False):
    db = load()
    if reset:  # re-init drops stale entries for files that no longer exist under target
        root = Path(target).resolve()
        db = {k: v for k, v in db.items() if not (Path(k) == root or Path(k).is_relative_to(root))}
    for f in files_in(target):
        try:
            db[str(f)] = sha256(f)
        except OSError as e:
            print(f"Skipped {f}: {e}", file=sys.stderr)
    save(db)
    print(msg)


def check(target):
    db = load()
    root = Path(target).resolve()
    present = files_in(target)
    tampered = 0
    for f in present:
        old = db.get(str(f))
        if old is None:
            status = "New (no stored hash)"
        elif sha256(f) == old:
            status = "Unmodified"
        else:
            status, tampered = "Modified (Hash mismatch)", tampered + 1
        print(f"{f}: {status}" if len(present) > 1 or root.is_dir() else f"Status: {status}")
    if root.is_dir():
        for k in db:
            if Path(k).is_relative_to(root) and not Path(k).exists():
                print(f"{k}: Deleted (file missing)")
                tampered += 1
    if tampered:
        print(f"WARNING: {tampered} file(s) failed integrity check - possible tampering.")
    return 1 if tampered else 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="integrity-check", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["init", "check", "update"])
    ap.add_argument("path")
    a = ap.parse_args(argv)
    if a.command == "check":
        return check(a.path)
    init = a.command == "init"
    store(a.path, "Hashes stored successfully." if init else "Hash updated successfully.", reset=init)
    return 0


if __name__ == "__main__":
    sys.exit(main())
