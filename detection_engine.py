# detection_engine.py
import time
from datetime import datetime, timedelta
from database import fetch_recent_logs, store_alert

# thresholds (tune as needed)
BRUTE_FORCE_THRESHOLD = 5      # failed attempts from one IP
BRUTE_FORCE_WINDOW_SEC = 120   # lookback window
BRUTE_FORCE_COOLDOWN = 300     # do not repeat same IP alert within this many seconds

STUFFING_THRESHOLD = 3         # distinct users using same password fingerprint
STUFFING_WINDOW_SEC = 120
STUFFING_COOLDOWN = 300

# in-memory cooldown trackers to prevent flooding
last_bruteforce_alert = {}  # ip -> timestamp
last_stuffing_alert = {}    # fingerprint -> timestamp

def run_detection_engine_loop(poll_interval=5):
    while True:
        try:
            logs = fetch_recent_logs(500)  # recent logs
            now = datetime.utcnow()

            # ========== BRUTE FORCE DETECTION ==========
            # Build map: ip -> list of (timestamp, status)
            ip_map = {}
            for username, ip, status, fp, ts in logs:
                try:
                    t = datetime.fromisoformat(ts)
                except Exception:
                    t = now
                # only consider within window
                if (now - t).total_seconds() <= BRUTE_FORCE_WINDOW_SEC:
                    ip_map.setdefault(ip, []).append((t, status))

            for ip, events in ip_map.items():
                fail_count = sum(1 for (t, status) in events if status.startswith("fail"))
                if fail_count >= BRUTE_FORCE_THRESHOLD:
                    last = last_bruteforce_alert.get(ip)
                    if not last or (now - last).total_seconds() > BRUTE_FORCE_COOLDOWN:
                        details = f"Detected {fail_count} failed attempts from IP {ip}"
                        store_alert("BRUTE_FORCE", details)
                        last_bruteforce_alert[ip] = now
                        # after alert, we do not need to keep the old count growing uncontrolled

            # ========== CREDENTIAL STUFFING DETECTION ==========
            # Map fingerprint -> set of usernames seen in window
            fp_map = {}
            for username, ip, status, fp, ts in logs:
                try:
                    t = datetime.fromisoformat(ts)
                except Exception:
                    t = now
                if (now - t).total_seconds() <= STUFFING_WINDOW_SEC:
                    # track distinct usernames only
                    fp_map.setdefault(fp, set()).add(username)

            for fp, users in fp_map.items():
                if len(users) >= STUFFING_THRESHOLD:
                    last = last_stuffing_alert.get(fp)
                    if not last or (now - last).total_seconds() > STUFFING_COOLDOWN:
                        details = f"Same password used on accounts: {', '.join(list(users)[:10])}"
                        store_alert("CREDENTIAL_STUFFING", details)
                        last_stuffing_alert[fp] = now

        except Exception as e:
            # don't crash; log to console
            print("Detection engine error:", e)

        time.sleep(poll_interval)
