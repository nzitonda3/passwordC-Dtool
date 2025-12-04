# pcfg_utils.py - FIXED VERSION
"""
Real Password Strength Analyzer
Fixes critical issues:
1. Proper entropy calculation (bits)
2. Realistic guess estimation
3. Crack time estimates
4. Character set analysis
5. Pattern detection
"""

import math
import re
from database import insert_pcfg
from datetime import datetime


# Common passwords database (top 100 most common)
COMMON_PASSWORDS = {
    'password': 1, '123456': 2, '12345678': 3, 'qwerty': 4, 'abc123': 5,
    'monkey': 6, '1234567': 7, 'letmein': 8, 'trustno1': 9, 'dragon': 10,
    'baseball': 11, 'iloveyou': 12, 'master': 13, 'sunshine': 14, 'ashley': 15,
    'bailey': 16, 'passw0rd': 17, 'shadow': 18, 'superman': 19, 'qazwsx': 20,
    'michael': 21, 'football': 22, 'welcome': 23, 'jesus': 24, 'ninja': 25,
    'mustang': 26, 'password1': 27, '123123': 28, 'admin': 29, 'solo': 30,
    'love': 31, 'hello': 32, 'freedom': 33, 'whatever': 34, 'princess': 35,
    'starwars': 36, 'summer': 37, 'cheese': 38, 'computer': 39, 'access': 40,
    '111111': 41, 'flower': 42, 'cookie': 43, 'batman': 44, 'thunder': 45,
    'ginger': 46, 'daniel': 47, 'bandit': 48, 'pepper': 49, 'jordan': 50,
    'test': 51, 'test123': 52, 'admin123': 53, 'root': 54, 'user': 55,
    'guest': 56, 'default': 57, 'sample': 58, 'demo': 59, 'login': 60,
}

# Common patterns that reduce strength
COMMON_PATTERNS = [
    (r'password', 'Contains "password"'),
    (r'123', 'Sequential numbers'),
    (r'abc', 'Sequential letters'),
    (r'qwerty', 'Keyboard pattern'),
    (r'^[a-z]+$', 'Only lowercase letters'),
    (r'^\d+$', 'Only numbers'),
]

# Common substitutions (leet speak)
SUBSTITUTIONS = {
    '@': 'a', '4': 'a', '3': 'e', '1': 'i', '!': 'i',
    '0': 'o', '$': 's', '7': 't', '+': 't', '5': 's'
}


def identify_pattern_and_groups(password):
    """
    Identify character type groups in password.
    Returns pattern like "L3D2S1" and groups.
    """
    groups = []
    cur = None
    cnt = 0
    
    for ch in password:
        if ch.islower():
            cls = 'L'
        elif ch.isupper():
            cls = 'U'
        elif ch.isdigit():
            cls = 'D'
        else:
            cls = 'S'
        
        if cls == cur:
            cnt += 1
        else:
            if cur is not None:
                groups.append((cur, cnt))
            cur = cls
            cnt = 1
    
    if cur is not None:
        groups.append((cur, cnt))
    
    pattern = ''.join([f"{g[0]}{g[1]}" for g in groups])
    return pattern, groups


def calculate_charset_size(password):
    """
    Calculate the character set size used in password.
    This is critical for entropy calculation.
    """
    charset_size = 0
    
    if any(c.islower() for c in password):
        charset_size += 26  # a-z
    
    if any(c.isupper() for c in password):
        charset_size += 26  # A-Z
    
    if any(c.isdigit() for c in password):
        charset_size += 10  # 0-9
    
    # Count unique special characters
    special_chars = set(c for c in password if not c.isalnum())
    if special_chars:
        charset_size += len(special_chars) + 20  # Common symbols
    
    return max(charset_size, 10)  # Minimum 10


def calculate_entropy(password):
    """
    Calculate password entropy in bits.
    Formula: entropy = log2(charset_size ^ length)
    """
    length = len(password)
    charset_size = calculate_charset_size(password)
    
    # Entropy = log2(possible_combinations)
    # possible_combinations = charset_size ^ length
    # So: entropy = length * log2(charset_size)
    
    entropy = length * math.log2(charset_size)
    
    return entropy, charset_size


def estimate_guesses_realistic(password):
    """
    REALISTIC guess estimation using proper entropy calculation.
    
    This is the FIX for the broken estimate_guesses() function!
    """
    pwd_lower = password.lower()
    
    # Check if it's in common passwords (instant crack)
    if pwd_lower in COMMON_PASSWORDS:
        rank = COMMON_PASSWORDS[pwd_lower]
        return rank, "COMMON_PASSWORD", 0.0001  # Cracked in 0.1ms
    
    # Check for common patterns
    for pattern_regex, description in COMMON_PATTERNS:
        if re.search(pattern_regex, pwd_lower):
            # Pattern found - significantly reduces strength
            entropy, charset = calculate_entropy(password)
            # Reduce entropy by pattern penalty
            entropy = max(entropy - 10, 10)  # -10 bits for pattern
            guesses = 2 ** entropy
            return int(guesses), f"PATTERN_{description}", entropy
    
    # Check for leet speak (reduces entropy)
    clean_pwd = pwd_lower
    for leet, normal in SUBSTITUTIONS.items():
        clean_pwd = clean_pwd.replace(leet, normal)
    
    if clean_pwd in COMMON_PASSWORDS:
        # It's a common password with substitutions
        rank = COMMON_PASSWORDS[clean_pwd]
        guesses = rank * 1000  # Leet speak adds 3-4 bits (~1000x)
        entropy = math.log2(guesses)
        return int(guesses), "LEET_SPEAK", entropy
    
    # Calculate full entropy for strong passwords
    entropy, charset = calculate_entropy(password)
    
    # Guesses = 2^entropy
    guesses = 2 ** entropy
    
    return int(guesses), f"CHARSET_{charset}", entropy


def estimate_crack_time(guesses, guesses_per_second=10_000_000_000):
    """
    Estimate time to crack password.
    
    Assumptions:
    - Modern GPU: 10 billion MD5 hashes/second
    - Average case: guesses/2 (we find it halfway)
    
    Args:
        guesses: Number of possible guesses
        guesses_per_second: Hash rate (default 10B/s)
    
    Returns:
        (seconds, human_readable_time)
    """
    # Average case: we find the password halfway through search space
    avg_guesses = guesses / 2
    
    seconds = avg_guesses / guesses_per_second
    
    # Convert to human-readable
    if seconds < 1:
        time_str = f"{seconds*1000:.2f} milliseconds"
    elif seconds < 60:
        time_str = f"{seconds:.2f} seconds"
    elif seconds < 3600:
        time_str = f"{seconds/60:.2f} minutes"
    elif seconds < 86400:
        time_str = f"{seconds/3600:.2f} hours"
    elif seconds < 31536000:
        time_str = f"{seconds/86400:.2f} days"
    elif seconds < 31536000 * 100:
        time_str = f"{seconds/31536000:.2f} years"
    elif seconds < 31536000 * 1000:
        time_str = f"{seconds/(31536000*100):.2f} centuries"
    else:
        time_str = f"{seconds/(31536000*1000000):.2e} million years"
    
    return seconds, time_str


def calculate_strength_score(entropy):
    """
    Calculate password strength score (0-100).
    
    Based on entropy:
    - 0-28 bits: Very Weak (0-20)
    - 28-36 bits: Weak (20-40)
    - 36-60 bits: Fair (40-60)
    - 60-80 bits: Strong (60-80)
    - 80+ bits: Very Strong (80-100)
    """
    if entropy < 28:
        score = (entropy / 28) * 20
    elif entropy < 36:
        score = 20 + ((entropy - 28) / 8) * 20
    elif entropy < 60:
        score = 40 + ((entropy - 36) / 24) * 20
    elif entropy < 80:
        score = 60 + ((entropy - 60) / 20) * 20
    else:
        score = 80 + min((entropy - 80) / 20 * 20, 20)
    
    return min(int(score), 100)


def get_strength_label(score):
    """Get strength label from score."""
    if score < 20:
        return "Very Weak 🔴", "red"
    elif score < 40:
        return "Weak 🟠", "orange"
    elif score < 60:
        return "Fair 🟡", "yellow"
    elif score < 80:
        return "Strong 🟢", "green"
    else:
        return "Very Strong ✅", "darkgreen"


def get_recommendations(password, entropy, score):
    """
    Provide actionable recommendations to improve password.
    """
    recommendations = []
    
    # Length check
    if len(password) < 8:
        recommendations.append(" Too short! Use at least 12 characters.")
    elif len(password) < 12:
        recommendations.append(" Consider using 12+ characters for better security.")
    
    # Character diversity
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    
    if not has_lower:
        recommendations.append(" Add lowercase letters (a-z)")
    if not has_upper:
        recommendations.append(" Add uppercase letters (A-Z)")
    if not has_digit:
        recommendations.append(" Add numbers (0-9)")
    if not has_special:
        recommendations.append(" Add special characters (!@#$%)")
    
    # Common password check
    if password.lower() in COMMON_PASSWORDS:
        recommendations.append("🚨 CRITICAL: This is a very common password! Change immediately!")
    
    # Pattern check
    for pattern_regex, description in COMMON_PATTERNS:
        if re.search(pattern_regex, password.lower()):
            recommendations.append(f"⚠️ Avoid pattern: {description}")
    
    # Good practices
    if score >= 60:
        recommendations.append("✅ Good password strength!")
        if score < 80:
            recommendations.append("💡 Tip: Add more length or special characters for even better security.")
    
    return recommendations


def estimate_guesses(password):
    """
    MAIN FUNCTION - Backward compatible wrapper.
    
    This replaces the broken estimate_guesses() but keeps same function signature.
    """
    guesses, pattern_type, entropy = estimate_guesses_realistic(password)
    pattern, groups = identify_pattern_and_groups(password)
    
    return guesses, pattern


def analyze_password_comprehensive(password):
    """
    Comprehensive password analysis.
    Returns detailed strength information.
    
    This is what we'll use for the enhanced check_password page.
    """
    # Calculate all metrics
    guesses, pattern_type, entropy = estimate_guesses_realistic(password)
    pattern, groups = identify_pattern_and_groups(password)
    charset_size = calculate_charset_size(password)
    crack_time_sec, crack_time_human = estimate_crack_time(guesses)
    score = calculate_strength_score(entropy)
    strength_label, color = get_strength_label(score)
    recommendations = get_recommendations(password, entropy, score)
    
    return {
        'password_length': len(password),
        'pattern': pattern,
        'charset_size': charset_size,
        'entropy_bits': round(entropy, 2),
        'estimated_guesses': guesses,
        'guesses_formatted': format_large_number(guesses),
        'crack_time_seconds': crack_time_sec,
        'crack_time_human': crack_time_human,
        'strength_score': score,
        'strength_label': strength_label,
        'strength_color': color,
        'recommendations': recommendations,
        'pattern_type': pattern_type,
    }


def format_large_number(num):
    """Format large numbers in scientific notation."""
    if num < 1000:
        return str(int(num))
    elif num < 1_000_000:
        return f"{num/1000:.1f}K"
    elif num < 1_000_000_000:
        return f"{num/1_000_000:.1f}M"
    elif num < 1_000_000_000_000:
        return f"{num/1_000_000_000:.1f}B"
    else:
        # Use scientific notation
        exponent = int(math.log10(num))
        mantissa = num / (10 ** exponent)
        return f"{mantissa:.2f}×10^{exponent}"


def analyze_and_store(user_id, password):
    """
    Analyze password and store in database.
    Backward compatible with existing code.
    """
    guesses, pattern = estimate_guesses(password)
    insert_pcfg(user_id, guesses, pattern)
    return guesses, pattern


# ============================================
# TESTING / DEMONSTRATION
# ============================================

if __name__ == "__main__":
    print("="*70)
    print("PASSWORD STRENGTH ANALYZER - TESTING")
    print("="*70 + "\n")
    
    test_passwords = [
        "abc",                      # Very weak
        "password",                 # Common
        "Password123",              # Weak pattern
        "MyStr0ng!Pass2024",        # Strong
        "Tr0ub4dor&3",             # Famous XKCD
        "correcthorsebatterystaple",  # Passphrase
    ]
    
    for pwd in test_passwords:
        print(f"\nPassword: '{pwd}'")
        print("-" * 70)
        
        analysis = analyze_password_comprehensive(pwd)
        
        print(f"Length: {analysis['password_length']} characters")
        print(f"Pattern: {analysis['pattern']}")
        print(f"Charset Size: {analysis['charset_size']} possible characters")
        print(f"Entropy: {analysis['entropy_bits']} bits")
        print(f"Estimated Guesses: {analysis['guesses_formatted']} ({analysis['estimated_guesses']:,})")
        print(f"Crack Time: {analysis['crack_time_human']}")
        print(f"Strength Score: {analysis['strength_score']}/100")
        print(f"Strength: {analysis['strength_label']}")
        
        if analysis['recommendations']:
            print("\nRecommendations:")
            for rec in analysis['recommendations']:
                print(f"  {rec}")
        
        print("=" * 70)