import hashlib, json, os, subprocess, sys, tempfile
from pathlib import Path

HERE = Path(__file__).parent

with tempfile.TemporaryDirectory() as d:
    d = Path(d)
    logs = d / "logs"; logs.mkdir()
    (logs / "syslog").write_text("boot ok\n")
    (logs / "auth.log").write_text("login root\n")
    db = d / "db" / "hashes.json"
    env = {**os.environ, "INTEGRITY_DB": str(db), "INTEGRITY_KEY": "test-key-0123456789"}

    def run(*args, **extra):
        r = subprocess.run([sys.executable, str(HERE / "integrity_check.py"), *args],
                           capture_output=True, text=True, env={**env, **extra})
        return r.returncode, r.stdout + r.stderr

    assert run("init", str(logs)) == (0, "Hashes stored successfully.\n")
    assert run("check", str(logs / "auth.log")) == (0, "Status: Unmodified\n")

    (logs / "syslog").write_text("boot ok\nattacker was here\n")
    code, out = run("check", str(logs / "syslog"))
    assert code == 1 and "Status: Modified (Hash mismatch)" in out, out

    code, out = run("check", str(logs))  # directory check reports which file mismatched
    assert code == 1 and "syslog: Modified" in out and "auth.log: Unmodified" in out, out

    assert run("update", str(logs / "syslog")) == (0, "Hash updated successfully.\n")
    assert run("check", str(logs / "syslog"))[0] == 0

    (logs / "auth.log").unlink()
    code, out = run("check", str(logs))
    assert code == 1 and "Deleted" in out, out

    assert run("init", str(logs))[0] == 0  # manual re-initialization
    assert run("check", str(logs))[0] == 0  # stale auth.log entry is gone

    # An attacker edits a log, then rewrites its stored hash without the key.
    (logs / "syslog").write_text("covered tracks\n")
    store = json.loads(db.read_text())
    store["hashes"][str((logs / "syslog").resolve())] = hashlib.sha256(b"covered tracks\n").hexdigest()
    db.write_text(json.dumps(store))
    code, out = run("check", str(logs))
    assert code == 1 and "ALERT" in out, out

    assert run("init", str(logs))[0] == 1  # can't launder a forged store by re-initializing
    db.unlink()
    assert run("init", str(logs))[0] == 0
    code, out = run("check", str(logs), INTEGRITY_KEY="wrong-key-0123456789")
    assert code == 1 and "ALERT" in out, out
    code, out = run("check", str(logs), INTEGRITY_KEY="")
    assert code == 1 and "INTEGRITY_KEY" in out, out
    print("all checks passed")
