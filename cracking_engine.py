# cracking_engine.py
import sqlite3
import subprocess
import time
import os
from database import get_conn, update_crack_result, list_users, fetch_recent_logs

DB_FILE = "security.db"
JOHN_INPUT = "john_input.txt"

def export_hashes_to_john():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("SELECT username, password_hash FROM users")
    rows = cur.fetchall()
    conn.close()

    if not rows:
        return 0

    with open(JOHN_INPUT, "w") as f:
        for username, pwd_hash in rows:
            # John can accept user:hash format for many formats
            f.write(f"{username}:{pwd_hash}\n")

    return len(rows)

def john_available():
    try:
        subprocess.run(["john", "--version"], capture_output=True)
        return True
    except Exception:
        return False

def run_john_once(format_hint=None, max_runtime_seconds=30):
    if not john_available():
        return False, "John the Ripper not found on PATH."

    args = ["john", JOHN_INPUT] if False else ["john", JOHN_INPUT]  # placeholder
    # build command: basic run with default formats
    cmd = ["john", JOHN_INPUT]
    # optional: pass --format if you know the hash type, or pass --wordlist
    # run John for a limited time by running it and killing after timeout (simple way)
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        proc.wait(timeout=max_runtime_seconds)
    except subprocess.TimeoutExpired:
        proc.kill()
        return True, f"John run killed after {max_runtime_seconds}s (time-limited)."
    return True, "John completed."

def parse_john_show_and_update():
    if not os.path.exists(JOHN_INPUT):
        return "john_input.txt not found."

    try:
        output = subprocess.check_output(["john", "--show", JOHN_INPUT], text=True, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError as e:
        output = e.output or ""
    except Exception:
        output = ""

    # parse lines like: username:password
    cracked = {}
    for line in output.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        # john --show prints lines with cracked entries; sometimes includes colons for other info. Use first two fields.
        parts = line.split(":")
        if len(parts) >= 2:
            user = parts[0].strip()
            pwd = parts[1].strip()
            # avoid "password hash" header lines
            if user and pwd and user.lower() != "password hash":
                cracked[user] = pwd

    # update DB with cracked_password and set guesses to -1 (approx)
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    for user, pwd in cracked.items():
        # we don't have exact guesses from John easily; store -1 as placeholder
        cur.execute("UPDATE users SET cracked_password=?, crack_guesses=?, crack_time=? WHERE username=?",
                    (pwd, -1, str(int(time.time())) , user))
    conn.commit()
    conn.close()
    return f"Updated {len(cracked)} cracked entries."

def run_full_audit(max_runtime_seconds=30):
    count = export_hashes_to_john()
    if count == 0:
        return False, "No users to audit."

    ok, msg = run_john_once(max_runtime_seconds=max_runtime_seconds)
    if not ok:
        return False, msg

    parsed = parse_john_show_and_update()
    return True, parsed
