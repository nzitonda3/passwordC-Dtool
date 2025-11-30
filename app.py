# app.py
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
import threading
import time

from database import init_db, create_user, verify_user, log_login_attempt, fetch_recent_logs, store_alert, fetch_recent_alerts, list_users, calculate_and_update_risk, update_crack_result
from simulate_engine import simulate
from detection_engine import run_detection_engine_loop
from cracking_engine import run_full_audit

app = Flask(__name__)
app.secret_key = "super_secret_key_change_me"

# start DB
init_db()

# --------- Utilities ----------
def get_client_ip(req):
    xff = req.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    return req.remote_addr

# --------- Pages ----------
@app.route("/")
def home():
    return redirect(url_for("login_page"))

@app.route("/signup", methods=["GET", "POST"])
def signup_page():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        ok, msg = create_user(username, password)
        if not ok:
            flash(msg, "error")
            return redirect(url_for("signup_page"))
        flash("Account created. You may login.", "success")
        return redirect(url_for("login_page"))
    return render_template("signup.html")

@app.route("/login", methods=["GET", "POST"])
def login_page():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        ip = get_client_ip(request)

        valid, msg = verify_user(username, password)
        # log attempt with explicit status
        status = "success" if valid else "fail"
        # if user does not exist, verify_user returns False and message "User does not exist."
        log_login_attempt(username, ip, status, password)

        if valid:
            session["username"] = username
            flash("Login successful", "success")
            return redirect(url_for("admin_dashboard"))
        else:
            flash(msg, "error")
            return redirect(url_for("login_page"))

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out", "info")
    return redirect(url_for("login_page"))

@app.route("/admin")
def admin_dashboard():
    # require admin in session (for demo we allow any logged-in user)
    if "username" not in session:
        flash("Please log in as admin to view dashboard", "error")
        return redirect(url_for("login_page"))
    return render_template("admin_dashboard.html")

# --------- Dashboard data endpoints ----------
@app.route("/admin/logs/data")
def admin_logs_data():
    rows = fetch_recent_logs(200)
    result = []
    for r in rows:
        result.append({
            "username": r[0],
            "ip": r[1],
            "status": r[2],
            "fingerprint": r[3][:10],
            "timestamp": r[4]
        })
    return jsonify(result)

@app.route("/admin/alerts/data")
def admin_alerts_data():
    rows = fetch_recent_alerts(50)
    result = []
    for r in rows:
        result.append({
            "alert_type": r[0],
            "details": r[1],
            "timestamp": r[2]
        })
    return jsonify(result)

@app.route("/admin/risk/data")
def admin_risk_data():
    users = list_users()
    result = []
    for u in users:
        result.append({
            "username": u[0],
            "risk": u[1] or 0,
            "guesses": u[2],
            "cracked": u[3],
            "crack_time": u[4]
        })
    return jsonify(result)

# --------- Simulation page ----------
@app.route("/simulate", methods=["GET", "POST"])
def simulate_page():
    if "username" not in session:
        flash("Please log in as admin to simulate attacks", "error")
        return redirect(url_for("login_page"))

    if request.method == "POST":
        attack_type = request.form.get("attack_type")
        usernames = [s.strip() for s in request.form.get("usernames", "").split(",") if s.strip()]
        passwords = [s.strip() for s in request.form.get("passwords", "").split(",") if s.strip()]
        ip = request.form.get("ip", "1.2.3.4")
        count = int(request.form.get("count", "3"))

        # simulate (runs inline; for long runs move to background)
        simulate(attack_type, usernames, passwords, ip, count)
        flash("Attack simulation executed (check dashboard)", "success")
        return redirect(url_for("admin_dashboard"))

    return render_template("simulate_attack.html")

# --------- Run audit (JTR) ----------
@app.route("/run_audit", methods=["POST"])
def run_audit_route():
    # simple protection: require logged-in
    if "username" not in session:
        flash("Please log in to run audit", "error")
        return redirect(url_for("login_page"))

    ok, msg = run_full_audit(max_runtime_seconds=20)
    flash(f"Audit result: {msg}", "info")

    # after audit, update risk for all users
    users = list_users()
    for u in users:
        username = u[0]
        try:
            calculate_and_update_risk(username)
        except Exception:
            pass

    return redirect(url_for("admin_dashboard"))

# --------- Start detection thread ----------
def start_detection_background():
    t = threading.Thread(target=run_detection_engine_loop, daemon=True)
    t.start()

if __name__ == "__main__":
    # ensure DB exists
    init_db()
    # start background detection
    start_detection_background()
    # run app
    app.run(host="0.0.0.0", port=5000, debug=True)
