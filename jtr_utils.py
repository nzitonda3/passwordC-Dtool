# jtr_utils.py - ENHANCED VERSION
"""
Enhanced Password Audit System with:
1. Strength scoring integration
2. Risk level classification
3. Detailed recommendations
4. Better performance tracking
"""

import subprocess
import time
import hashlib
import os
import shutil
from database import insert_jtr_result, get_conn, get_config, clear_jtr_results

# Import the enhanced password analyzer
from pcfg_utils import analyze_password_comprehensive

# Configuration
WORDLIST_PATH = os.environ.get("JTR_WORDLIST", "/usr/share/wordlists/rockyou.txt")
MAX_SECONDS_PER_USER = int(os.environ.get("JTR_MAX_SECONDS_PER_USER", "30"))
MAX_GUESSES = int(os.environ.get("JTR_MAX_GUESSES", "200000"))


def get_risk_level(strength_score, cracked, guesses):
    """
    Determine risk level based on multiple factors.
    
    Risk Levels:
    - CRITICAL: Password cracked OR score < 20
    - HIGH: Score 20-39 OR very few guesses needed
    - MEDIUM: Score 40-59
    - LOW: Score 60+
    """
    if cracked:
        return "CRITICAL", "🔴", "Password was cracked!"
    
    if strength_score < 20:
        return "CRITICAL", "🔴", "Extremely weak password"
    elif strength_score < 40:
        return "HIGH", "🟠", "Weak password - easily guessable"
    elif strength_score < 60:
        return "MEDIUM", "🟡", "Fair password - could be stronger"
    else:
        return "LOW", "🟢", "Strong password"


def get_recommendations_for_user(cracked, cracked_password, strength_analysis):
    """
    Generate specific recommendations for a user based on audit results.
    """
    recommendations = []
    
    if cracked:
        recommendations.append("🚨 URGENT: Your password was cracked! Change it immediately!")
        recommendations.append(f"⚠️ The cracked password was: '{cracked_password}'")
        recommendations.append("💡 Use a password manager to generate strong passwords")
    
    if strength_analysis:
        # Add recommendations from strength analysis
        if 'recommendations' in strength_analysis:
            for rec in strength_analysis['recommendations']:
                if rec not in recommendations:  # Avoid duplicates
                    recommendations.append(rec)
    
    if not recommendations:
        recommendations.append("✅ Password passed basic audit")
        recommendations.append("💡 Consider using 15+ characters with mixed types")
    
    return recommendations


def run_jtr_on_hash(user_id, stored_hexdigest, get_plaintext_callback=None):
    """
    Enhanced audit that includes strength analysis.
    
    Args:
        user_id: User ID to audit
        stored_hexdigest: SHA512 hash of password
        get_plaintext_callback: Optional function to get plaintext for analysis
                                (e.g., during signup when we still have it)
    
    Returns:
        Tuple: (guesses, cracked, cracked_password, audit_time, strength_analysis, risk_level)
    """
    start = time.time()
    guesses = 0
    cracked = False
    cracked_password = None
    strength_analysis = None

    # Common passwords to try first (expanded list)
    common_passwords = [
        'password', '123456', '12345678', 'qwerty', 'abc123', 'monkey', '1234567',
        'letmein', 'trustno1', 'dragon', 'baseball', 'iloveyou', 'master', 'sunshine',
        'ashley', 'bailey', 'passw0rd', 'shadow', '123123', '654321', 'password1',
        'admin', 'welcome', 'login', 'admin123', 'root', 'toor', 'pass', 'test',
        'guest', 'password123', '12345', '123456789', 'qwerty123', 'Password1',
        '1234567890', 'abc', 'password!', 'P@ssw0rd', 'Welcome1', 'Admin123'
    ]
    
    # Phase 1: Try common passwords (fast path)
    for guess in common_passwords:
        guesses += 1
        ghex = hashlib.sha512(guess.encode()).hexdigest()
        if ghex == stored_hexdigest:
            cracked = True
            cracked_password = guess
            
            # Analyze the cracked password
            strength_analysis = analyze_password_comprehensive(guess)
            
            audit_time_ms = int((time.time() - start) * 1000)
            
            # Determine risk level
            risk_level, risk_icon, risk_desc = get_risk_level(
                strength_analysis['strength_score'], 
                cracked, 
                guesses
            )
            
            # Get recommendations
            recommendations = get_recommendations_for_user(
                cracked, 
                cracked_password, 
                strength_analysis
            )
            
            # Store enhanced results
            insert_jtr_result_enhanced(
                user_id, guesses, 1, cracked_password, audit_time_ms,
                strength_analysis, risk_level, recommendations
            )
            
            return (guesses, cracked, cracked_password, str(audit_time_ms), 
                    strength_analysis, risk_level)
        
        if (time.time() - start) > MAX_SECONDS_PER_USER:
            break

    # Phase 2: Wordlist attack (if available)
    wordlist = None
    db_wordlist = get_config('JTR_WORDLIST')
    if db_wordlist and os.path.exists(db_wordlist):
        wordlist = db_wordlist
    elif WORDLIST_PATH and os.path.exists(WORDLIST_PATH):
        wordlist = WORDLIST_PATH
    else:
        preferred_wordlists = [
            '/usr/share/wordlists/rockyou.txt',
            '/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt',
            '/usr/share/wordlists/fasttrack.txt'
        ]
        for p in preferred_wordlists:
            if os.path.exists(p):
                wordlist = p
                break

    if wordlist:
        db_timeout = get_config('JTR_MAX_SECONDS_PER_USER')
        try:
            timeout = int(db_timeout) if db_timeout is not None else MAX_SECONDS_PER_USER
        except Exception:
            timeout = MAX_SECONDS_PER_USER

        try:
            with open(wordlist, 'r', errors='ignore') as wf:
                for line in wf:
                    guess = line.rstrip('\n').rstrip('\r')
                    if not guess:
                        continue
                    guesses += 1
                    if hashlib.sha512(guess.encode()).hexdigest() == stored_hexdigest:
                        cracked = True
                        cracked_password = guess
                        
                        # Analyze the cracked password
                        strength_analysis = analyze_password_comprehensive(guess)
                        break
                    
                    if (time.time() - start) > timeout:
                        break
        except Exception as e:
            print(f"Wordlist error: {e}")

    # Phase 3: Try John the Ripper (fallback)
    # Allow forcing JtR run via env var or DB config (JTR_FORCE_RUN = 1/true)
    force_jtr_env = os.environ.get('JTR_FORCE_RUN')
    force_jtr_db = get_config('JTR_FORCE_RUN')
    force_jtr = False
    for v in (force_jtr_env, force_jtr_db):
        if v and str(v).lower() in ('1', 'true', 'yes', 'on'):
            force_jtr = True
            break

    if not cracked or force_jtr:
        import tempfile
        tf = None
        try:
            fd, tf = tempfile.mkstemp(prefix=f"jtrhash_{user_id}_", text=True)
            with os.fdopen(fd, 'w') as f:
                f.write(f"user{user_id}:{stored_hexdigest}\n")

            john_cmd = ["john", "--format=Raw-SHA512", "--incremental=All", tf]
            # Check that `john` exists in PATH
            john_path = shutil.which('john')
            proc = None
            if not john_path:
                print("[!] John the Ripper not found in PATH; skipping JtR phase.")
            else:
                try:
                    proc = subprocess.Popen([john_path] + john_cmd[1:], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                except Exception as e:
                    print(f"[!] Failed to start John the Ripper: {e}")
                    proc = None

            # If process started, wait up to the configured timeout
            if proc:
                db_timeout = get_config('JTR_MAX_SECONDS_PER_USER')
                try:
                    timeout = int(db_timeout) if db_timeout is not None else MAX_SECONDS_PER_USER
                except Exception:
                    timeout = MAX_SECONDS_PER_USER

                try:
                    proc.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    try:
                        proc.kill()
                    except Exception:
                        pass

                # Check if John cracked it
                try:
                    john_path = shutil.which('john')
                    if john_path:
                        show = subprocess.run([john_path, "--show", "--format=Raw-SHA512", tf], 
                                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
                    else:
                        show = None
                    out = show.stdout or ''
                    for line in out.splitlines():
                        if ':' in line and not line.lower().startswith('loaded'):
                            parts = line.split(':')
                            if len(parts) >= 2 and parts[1].strip():
                                cracked_password = parts[1].strip()
                                cracked = True
                                strength_analysis = analyze_password_comprehensive(cracked_password)
                                break
                except Exception:
                    pass
        finally:
            try:
                if tf and os.path.exists(tf):
                    os.remove(tf)
            except Exception:
                pass

    # Final results
    audit_time_ms = int((time.time() - start) * 1000)
    
    # If we have the plaintext (from signup callback), analyze it even if not cracked
    if not cracked and get_plaintext_callback:
        try:
            plaintext = get_plaintext_callback(user_id)
            if plaintext:
                strength_analysis = analyze_password_comprehensive(plaintext)
        except Exception:
            pass
    
    # If we still don't have strength analysis, estimate based on hash
    if not strength_analysis and not cracked:
        # Can't analyze hash directly, but we can estimate risk
        strength_analysis = {
            'strength_score': 70,  # Assume decent if not cracked
            'strength_label': 'Unknown (not cracked)',
            'estimated_guesses': 'N/A',
            'crack_time_human': 'Not cracked in audit',
            'recommendations': [
                '✓ Password survived basic audit',
                '⚠️ Cannot verify strength without plaintext',
                '💡 Consider checking manually at /check_password'
            ]
        }
    
    # Determine risk level
    risk_level, risk_icon, risk_desc = get_risk_level(
        strength_analysis.get('strength_score', 50) if strength_analysis else 50,
        cracked,
        guesses
    )
    
    # Get recommendations
    recommendations = get_recommendations_for_user(
        cracked,
        cracked_password,
        strength_analysis
    )
    
    # Store enhanced results
    insert_jtr_result_enhanced(
        user_id, guesses, 1 if cracked else 0, cracked_password, audit_time_ms,
        strength_analysis, risk_level, recommendations
    )
    
    return (guesses, cracked, cracked_password, str(audit_time_ms), 
            strength_analysis, risk_level)


def insert_jtr_result_enhanced(user_id, guesses, cracked_int, cracked_password, 
                                audit_time, strength_analysis, risk_level, recommendations):
    """
    Store enhanced audit results including strength analysis.
    Falls back to basic insert if enhanced columns don't exist.
    """
    conn = get_conn()
    c = conn.cursor()
    
    # Try enhanced insert first
    try:
        # Check if enhanced columns exist
        c.execute("PRAGMA table_info(jtr_results)")
        columns = [row[1] for row in c.fetchall()]
        
        if 'strength_score' in columns and 'risk_level' in columns:
            # Enhanced insert
            strength_score = strength_analysis.get('strength_score', 0) if strength_analysis else 0
            entropy_bits = strength_analysis.get('entropy_bits', 0) if strength_analysis else 0
            crack_time = strength_analysis.get('crack_time_human', 'N/A') if strength_analysis else 'N/A'
            recommendations_text = '\n'.join(recommendations) if recommendations else ''
            
            c.execute("""
                INSERT INTO jtr_results 
                (user_id, guesses, cracked, cracked_password, audit_time, 
                 strength_score, entropy_bits, crack_time_estimate, risk_level, recommendations)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (user_id, guesses, cracked_int, cracked_password, audit_time,
                  strength_score, entropy_bits, crack_time, risk_level, recommendations_text))
        else:
            # Basic insert (backward compatible)
            insert_jtr_result(user_id, guesses, cracked_int, cracked_password, audit_time)
    except Exception as e:
        # Fallback to basic insert
        print(f"Enhanced insert failed, using basic: {e}")
        insert_jtr_result(user_id, guesses, cracked_int, cracked_password, audit_time)
    finally:
        conn.commit()
        conn.close()


def run_full_audit_all_users():
    """
    Enhanced full audit with strength analysis for all users.
    """
    # Clear previous audit results
    try:
        clear_jtr_results()
    except Exception:
        pass

    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT id, password_hash FROM users")
    rows = c.fetchall()
    conn.close()
    
    results = []
    for user_id, stored_hash in rows:
        print(f"[*] Auditing user {user_id}...")
        r = run_jtr_on_hash(user_id, stored_hash)
        results.append((user_id,) + r)
    
    print(f"[+] Audit complete: {len(results)} users audited")
    return results


def get_audit_summary():
    """
    Get summary statistics of latest audit.
    Returns dict with counts and risk breakdown.
    """
    conn = get_conn()
    c = conn.cursor()
    
    # Try enhanced query first
    try:
        c.execute("""
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN cracked = 1 THEN 1 ELSE 0 END) as cracked_count,
                SUM(CASE WHEN risk_level = 'CRITICAL' THEN 1 ELSE 0 END) as critical_count,
                SUM(CASE WHEN risk_level = 'HIGH' THEN 1 ELSE 0 END) as high_count,
                SUM(CASE WHEN risk_level = 'MEDIUM' THEN 1 ELSE 0 END) as medium_count,
                SUM(CASE WHEN risk_level = 'LOW' THEN 1 ELSE 0 END) as low_count,
                AVG(strength_score) as avg_strength
            FROM jtr_results
        """)
        row = c.fetchone()
        conn.close()
        
        if row:
            return {
                'total': row[0] or 0,
                'cracked': row[1] or 0,
                'critical': row[2] or 0,
                'high': row[3] or 0,
                'medium': row[4] or 0,
                'low': row[5] or 0,
                'avg_strength': round(row[6], 1) if row[6] else 0
            }
    except Exception:
        # Fallback to basic query
        c.execute("SELECT COUNT(*), SUM(cracked) FROM jtr_results")
        row = c.fetchone()
        conn.close()
        
        return {
            'total': row[0] or 0,
            'cracked': row[1] or 0,
            'critical': row[1] or 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'avg_strength': 0
        }
    
    return {'total': 0, 'cracked': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'avg_strength': 0}


# For testing
if __name__ == "__main__":
    print("="*70)
    print("ENHANCED PASSWORD AUDIT SYSTEM")
    print("="*70)
    
    # Test with a weak password hash
    weak_hash = hashlib.sha512(b"password").hexdigest()
    print(f"\nTesting with weak password hash...")
    result = run_jtr_on_hash(999, weak_hash)
    
    guesses, cracked, pwd, time, analysis, risk = result
    print(f"\nResults:")
    print(f"  Cracked: {cracked}")
    print(f"  Password: {pwd}")
    print(f"  Guesses: {guesses}")
    print(f"  Risk Level: {risk}")
    if analysis:
        print(f"  Strength Score: {analysis.get('strength_score', 'N/A')}/100")
        print(f"  Entropy: {analysis.get('entropy_bits', 'N/A')} bits")