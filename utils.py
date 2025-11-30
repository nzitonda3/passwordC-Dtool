# utils.py
import bcrypt
import hashlib
import os

# pepper for fingerprinting - in lab an env var would be better
PEPPER = os.environ.get("PWD_PEPPER", "super_secret_pepper_for_lab")

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), hashed.encode())
    except Exception:
        return False

def fingerprint_password(password: str) -> str:
    m = hashlib.sha256()
    m.update((PEPPER + password).encode())
    return m.hexdigest()
