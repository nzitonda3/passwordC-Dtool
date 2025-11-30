# database.py
import sqlite3
from datetime import datetime
from utils import hash_password, verify_password, fingerprint_password

DB_FILE = "security.db"

def get_conn():
    return sqlite3.connect(DB_FILE, check_same_thread=False)

def init_db():
    conn = get_conn()
    cur = conn.cursor()

    # Users table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password_hash TEXT,
            risk_score INTEGER DEFAULT 0,
            crack_time TEXT,
            crack_guesses INTEGER,
            cracked_password TEXT
        );
    """)

    # Login logs table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS login_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            ip TEXT,
            status TEXT,
            fingerprint TEXT,
            timestamp TEXT
        );
    """)

    # Alerts table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_type TEXT,
            details TEXT,
            timestamp TEXT
        );
    """)

    conn.commit()
    conn.close()

# -------------------------
# USERS
# -------------------------
def create_user(username, password):
    try:
        conn = get_conn()
        cur = conn.cursor()
        pwd_hash = hash_password(password)
        cur.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, pwd_hash))
        conn.commit()
        conn.close()
        return True, "ok"
    except sqlite3.IntegrityError:
        return False, "Username already exists."

def get_user_row(username):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id, username, password_hash, risk_score, crack_time, crack_guesses, cracked_password FROM users WHERE username=?", (username,))
    row = cur.fetchone()
    conn.close()
    return row

def verify_user(username, password):
    row = get_user_row(username)
    if not row:
        return False, "User does not exist."
    stored_hash = row[2]
    if verify_password(password, stored_hash):
        return True, "ok"
    return False, "Incorrect password."

def list_users():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT username, risk_score, crack_guesses, cracked_password, crack_time FROM users")
    rows = cur.fetchall()
    conn.close()
    return rows

# -------------------------
# LOGS
# -------------------------
def log_login_attempt(username, ip, status, password):
    conn = get_conn()
    cur = conn.cursor()
    fp = fingerprint_password(password)
    cur.execute("INSERT INTO login_logs (username, ip, status, fingerprint, timestamp) VALUES (?, ?, ?, ?, ?)",
                (username, ip, status, fp, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()

def fetch_recent_logs(limit=200):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT username, ip, status, fingerprint, timestamp FROM login_logs ORDER BY id DESC LIMIT ?", (limit,))
    rows = cur.fetchall()
    conn.close()
    return rows

# -------------------------
# ALERTS
# -------------------------
def store_alert(alert_type, details):
    conn = get_conn()
    cur = conn.cursor()
    ts = datetime.utcnow().isoformat()
    cur.execute("INSERT INTO alerts (alert_type, details, timestamp) VALUES (?, ?, ?)", (alert_type, details, ts))
    conn.commit()
    conn.close()

def fetch_recent_alerts(limit=50):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT alert_type, details, timestamp FROM alerts ORDER BY id DESC LIMIT ?", (limit,))
    rows = cur.fetchall()
    conn.close()
    return rows

# -------------------------
# Cracking updates & risk
# -------------------------
def update_crack_result(username, cracked_password, guesses, duration_seconds):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("UPDATE users SET cracked_password=?, crack_guesses=?, crack_time=? WHERE username=?",
                (cracked_password, guesses, str(duration_seconds), username))
    conn.commit()
    conn.close()

def set_user_risk(username, score):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("UPDATE users SET risk_score=? WHERE username=?", (score, username))
    conn.commit()
    conn.close()

def calculate_and_update_risk(username):
    """
    Simple risk logic:
      - cracked quickly -> high risk
      - many related alerts -> raise risk
    """
    conn = get_conn()
    cur = conn.cursor()

    # alerts that mention the username
    cur.execute("SELECT COUNT(*) FROM alerts WHERE details LIKE ?", (f"%{username}%",))
    alert_count = cur.fetchone()[0]

    cur.execute("SELECT crack_guesses FROM users WHERE username=?", (username,))
    row = cur.fetchone()
    guesses = row[0] if row else None

    score = 0
    if guesses is None:
        score += 20
    else:
        try:
            g = int(guesses)
            if g <= 0:
                score += 80
            elif g < 1000:
                score += 70
            elif g < 10000:
                score += 50
            elif g < 100000:
                score += 30
            else:
                score += 10
        except Exception:
            score += 20

    score += alert_count * 10
    if score > 100:
        score = 100

    cur.execute("UPDATE users SET risk_score=? WHERE username=?", (score, username))
    conn.commit()
    conn.close()
