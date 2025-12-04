# simulate_engine.py - ENHANCED VERSION
"""
Attack simulation engine with:
- Real-time password testing
- PCFG integration
- Multiple attack types
- Live progress tracking
"""

import time
from database import insert_login_log
from utils import hash_password_sha512, verify_password_sha512, fingerprint_password

# Try to import PCFG integration
try:
    from pcfg_integration import generate_attack_passwords
    PCFG_AVAILABLE = True
except ImportError:
    PCFG_AVAILABLE = False
    print("[!] PCFG integration not available - using fallback passwords")


def simulate(attack_type, usernames, passwords, ip, count, wordlist_file=None):
    """
    Simulate various types of password attacks.
    
    Args:
        attack_type: Type of attack (brute_force, credential_stuffing, dictionary, etc.)
        usernames: List of usernames to target
        passwords: List of passwords to try
        ip: Source IP address for simulation
        count: Number of attempts per username
        wordlist_file: Optional wordlist file path
    """
    print(f"\n{'='*70}")
    print(f"ATTACK SIMULATION: {attack_type.upper()}")
    print(f"{'='*70}")
    print(f"Source IP: {ip}")
    print(f"Target Usernames: {', '.join(usernames)}")
    print(f"Attempts per user: {count}")
    print(f"{'='*70}\n")
    
    # Get password list based on attack type
    password_list = get_password_list(attack_type, passwords, count, wordlist_file)
    
    print(f"[+] Loaded {len(password_list)} passwords")
    print(f"[*] Starting simulation...\n")
    
    # Execute attack based on type
    if attack_type == "brute_force":
        simulate_brute_force(usernames, password_list, ip, count)
    
    elif attack_type == "credential_stuffing":
        simulate_credential_stuffing(usernames, password_list, ip, count)
    
    elif attack_type == "dictionary":
        simulate_dictionary(usernames, password_list, ip, count)
    
    elif attack_type == "spray":
        simulate_password_spray(usernames, password_list, ip, count)
    
    else:
        # Generic simulation
        simulate_generic(usernames, password_list, ip, count)
    
    print(f"\n{'='*70}")
    print(f"SIMULATION COMPLETE")
    print(f"{'='*70}\n")


def get_password_list(attack_type, passwords, count, wordlist_file=None):
    """
    Get password list based on attack type and available sources.
    
    Priority:
    1. Wordlist file (if provided)
    2. User-provided passwords
    3. PCFG-generated passwords
    4. Fallback common passwords
    """
    password_list = []
    
    # 1. Try wordlist file first
    if wordlist_file:
        try:
            with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
                password_list = [line.strip() for line in f if line.strip()]
                print(f"[+] Loaded {len(password_list)} passwords from wordlist")
                return password_list[:count * 10]  # Limit size
        except Exception as e:
            print(f"[!] Could not read wordlist: {e}")
    
    # 2. Use user-provided passwords
    if passwords and len(passwords) > 0:
        password_list = passwords
        print(f"[+] Using {len(password_list)} user-provided passwords")
    
    # 3. Try PCFG generation
    elif PCFG_AVAILABLE:
        try:
            password_list = generate_attack_passwords(count * 10)
            print(f"[+] Generated {len(password_list)} PCFG passwords")
        except Exception as e:
            print(f"[!] PCFG generation failed: {e}")
            password_list = []
    
    # 4. Fallback to common passwords
    if not password_list:
        password_list = get_fallback_passwords()
        print(f"[+] Using {len(password_list)} fallback passwords")
    
    return password_list


def get_fallback_passwords():
    """
    Fallback password list when no other source available.
    """
    return [
        'password', '123456', '12345678', 'qwerty', 'abc123',
        'monkey', '1234567', 'letmein', 'trustno1', 'dragon',
        'baseball', 'iloveyou', 'master', 'sunshine', 'ashley',
        'bailey', 'passw0rd', 'shadow', '123123', '654321',
        'superman', 'password1', 'Welcome1', 'admin', 'login',
        'welcome', 'solo', 'starwars', 'summer', 'flower',
        'Password1', 'Admin123', 'password123', 'qwerty123'
    ]


def simulate_brute_force(usernames, password_list, ip, count):
    """
    Simulate brute-force attack: Many passwords against few users.
    High failure rate, same IP, rapid attempts.
    """
    print("[*] Simulating BRUTE-FORCE attack")
    print("    Pattern: Many passwords → Few users")
    print("    Speed: Very fast (0.1s between attempts)\n")
    
    for username in usernames:
        print(f"[*] Attacking user: {username}")
        attempts = 0
        
        for password in password_list:
            if attempts >= count:
                break
            
            # Simulate login attempt
            fingerprint = fingerprint_password(password)
            status = "fail_wrong_password"
            
            insert_login_log(username, ip, status, fingerprint, "BruteForceBot/1.0")
            
            attempts += 1
            
            # Show progress every 10 attempts
            if attempts % 10 == 0:
                print(f"    [{attempts}/{count}] Attempted...")
            
            # Simulate rapid attack speed
            time.sleep(0.1)
        
        print(f"    [✓] Completed {attempts} attempts on {username}\n")


def simulate_credential_stuffing(usernames, password_list, ip, count):
    """
    Simulate credential stuffing: Same password across many users.
    Pattern: Reused credentials from leaked databases.
    """
    print("[*] Simulating CREDENTIAL STUFFING attack")
    print("    Pattern: Same passwords → Many users")
    print("    Speed: Medium (0.3s between attempts)\n")
    
    # Use same passwords across all users
    for i, password in enumerate(password_list[:count]):
        print(f"[*] Testing password {i+1}/{count}: {password}")
        
        for username in usernames:
            fingerprint = fingerprint_password(password)
            status = "fail_wrong_password"
            
            insert_login_log(username, ip, status, fingerprint, "StuffingBot/1.0")
            
            time.sleep(0.3)
        
        print(f"    [✓] Tested against {len(usernames)} users\n")


def simulate_dictionary(usernames, password_list, ip, count):
    """
    Simulate dictionary attack: Common passwords in order.
    Pattern: Most likely passwords first.
    """
    print("[*] Simulating DICTIONARY attack")
    print("    Pattern: Common passwords by probability")
    print("    Speed: Fast (0.2s between attempts)\n")
    
    for username in usernames:
        print(f"[*] Attacking user: {username}")
        attempts = 0
        
        for password in password_list:
            if attempts >= count:
                break
            
            fingerprint = fingerprint_password(password)
            status = "fail_wrong_password"
            
            insert_login_log(username, ip, status, fingerprint, "DictionaryBot/1.0")
            
            attempts += 1
            
            if attempts % 10 == 0:
                print(f"    [{attempts}/{count}] Attempted...")
            
            time.sleep(0.2)
        
        print(f"    [✓] Completed {attempts} attempts on {username}\n")


def simulate_password_spray(usernames, password_list, ip, count):
    """
    Simulate password spray: Few common passwords against many users.
    Pattern: Low and slow to avoid detection.
    """
    print("[*] Simulating PASSWORD SPRAY attack")
    print("    Pattern: Common passwords → All users (slow)")
    print("    Speed: Very slow (2s between attempts)\n")
    
    # Use only most common passwords
    common_passwords = password_list[:min(5, count)]
    
    for i, password in enumerate(common_passwords):
        print(f"[*] Spraying password {i+1}/{len(common_passwords)}: {password}")
        
        for username in usernames:
            fingerprint = fingerprint_password(password)
            status = "fail_wrong_password"
            
            insert_login_log(username, ip, status, fingerprint, "SprayBot/1.0")
            
            print(f"    → Testing {username}...")
            time.sleep(2)  # Slow to avoid detection
        
        print(f"    [✓] Sprayed to all users\n")


def simulate_generic(usernames, password_list, ip, count):
    """
    Generic simulation for custom attack patterns.
    """
    print("[*] Simulating GENERIC attack\n")
    
    for username in usernames:
        print(f"[*] Attacking user: {username}")
        attempts = 0
        
        for password in password_list:
            if attempts >= count:
                break
            
            fingerprint = fingerprint_password(password)
            status = "fail_wrong_password"
            
            insert_login_log(username, ip, status, fingerprint, "GenericBot/1.0")
            
            attempts += 1
            time.sleep(0.5)
        
        print(f"    [✓] Completed {attempts} attempts\n")


# For testing
if __name__ == "__main__":
    print("="*70)
    print("SIMULATE ENGINE TEST")
    print("="*70 + "\n")
    
    # Test simulation
    simulate(
        attack_type="brute_force",
        usernames=["testuser"],
        passwords=["password", "123456", "qwerty"],
        ip="10.0.0.99",
        count=5,
        wordlist_file=None
    )
    
    print("\n[✓] Test complete!")