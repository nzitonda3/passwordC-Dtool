# ml/feature_engineering.py
"""
Feature Engineering for ML-based Attack Detection

Extracts features from login logs for ML classification:
- IP-based features
- Time-based patterns
- User targeting patterns
- Request frequency
- User-Agent patterns
"""

import sqlite3
from datetime import datetime, timedelta
from collections import defaultdict
import math


def extract_features_from_logs(db_path='pcdt.db', time_window_minutes=10):
    """
    Extract ML features from login logs.
    
    Features:
    1. failed_attempt_rate: % of failed logins from IP
    2. unique_users_targeted: Number of different users tried
    3. attempts_per_minute: Speed of attempts
    4. time_variance: Consistency of timing (bot indicator)
    5. geographic_anomaly: IP location changes (requires GeoIP)
    6. user_agent_diversity: Different UAs from same IP
    7. password_pattern_score: Repetition of same password hash
    
    Returns:
        List of feature dictionaries with labels
    """
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    # Get recent logs
    cutoff = (datetime.utcnow() - timedelta(hours=24)).isoformat()
    c.execute("""
        SELECT username, ip, status, timestamp, fingerprint, user_agent
        FROM login_logs 
        WHERE timestamp > ?
        ORDER BY timestamp DESC
    """, (cutoff,))
    
    logs = c.fetchall()
    conn.close()
    
    if not logs:
        return []
    
    # Group by IP for feature extraction
    ip_data = defaultdict(lambda: {
        'attempts': [],
        'users': set(),
        'fingerprints': defaultdict(int),
        'user_agents': set(),
        'timestamps': [],
        'failures': 0,
        'successes': 0
    })
    
    for username, ip, status, timestamp, fingerprint, user_agent in logs:
        data = ip_data[ip]
        data['attempts'].append((username, status, timestamp, fingerprint))
        data['users'].add(username)
        data['fingerprints'][fingerprint] += 1
        if user_agent:
            data['user_agents'].add(user_agent)
        
        try:
            ts = datetime.fromisoformat(timestamp)
            data['timestamps'].append(ts)
        except:
            pass
        
        if status.startswith('fail'):
            data['failures'] += 1
        else:
            data['successes'] += 1
    
    # Extract features per IP
    features = []
    
    for ip, data in ip_data.items():
        total_attempts = len(data['attempts'])
        
        if total_attempts == 0:
            continue
        
        # Feature 1: Failed attempt rate
        failed_rate = data['failures'] / total_attempts
        
        # Feature 2: Unique users targeted
        unique_users = len(data['users'])
        
        # Feature 3: Attempts per minute
        if len(data['timestamps']) >= 2:
            time_span = (max(data['timestamps']) - min(data['timestamps'])).total_seconds()
            attempts_per_minute = (total_attempts / max(time_span / 60, 0.1))
        else:
            attempts_per_minute = 0
        
        # Feature 4: Time variance (consistency - bot indicator)
        time_variance = 0
        if len(data['timestamps']) >= 3:
            intervals = []
            sorted_times = sorted(data['timestamps'])
            for i in range(1, len(sorted_times)):
                interval = (sorted_times[i] - sorted_times[i-1]).total_seconds()
                intervals.append(interval)
            
            if intervals:
                mean_interval = sum(intervals) / len(intervals)
                variance = sum((x - mean_interval)**2 for x in intervals) / len(intervals)
                time_variance = math.sqrt(variance)
        
        # Feature 5: User-Agent diversity
        ua_diversity = len(data['user_agents'])
        
        # Feature 6: Password pattern score (same password on multiple accounts)
        max_fingerprint_reuse = max(data['fingerprints'].values()) if data['fingerprints'] else 0
        password_pattern_score = max_fingerprint_reuse / unique_users if unique_users > 0 else 0
        
        # Feature 7: Success rate (inverted - high success in attacks is suspicious)
        success_rate = data['successes'] / total_attempts
        
        # Determine label based on patterns
        label = determine_label(
            failed_rate, unique_users, attempts_per_minute,
            time_variance, password_pattern_score, total_attempts
        )
        
        feature_dict = {
            'ip': ip,
            'failed_attempt_rate': round(failed_rate, 3),
            'unique_users_targeted': unique_users,
            'attempts_per_minute': round(attempts_per_minute, 2),
            'time_variance': round(time_variance, 2),
            'ua_diversity': ua_diversity,
            'password_pattern_score': round(password_pattern_score, 3),
            'success_rate': round(success_rate, 3),
            'total_attempts': total_attempts,
            'label': label
        }
        
        features.append(feature_dict)
    
    return features


def determine_label(failed_rate, unique_users, attempts_per_minute, 
                   time_variance, password_pattern_score, total_attempts):
    """
    Determine attack label based on feature patterns.
    
    Labels:
    - normal: Low failure rate, reasonable speed
    - brute_force: High failure rate, single user, high speed
    - credential_stuffing: Multiple users, same password pattern
    - suspicious: Unusual but not clearly malicious
    """
    
    # Brute-force indicators
    if (failed_rate > 0.8 and 
        unique_users <= 2 and 
        attempts_per_minute > 5):
        return 'brute_force'
    
    # Credential stuffing indicators
    if (unique_users >= 5 and 
        password_pattern_score > 0.5 and
        failed_rate > 0.7):
        return 'credential_stuffing'
    
    # Suspicious patterns
    if (attempts_per_minute > 10 or 
        (time_variance < 1 and total_attempts > 10) or  # Bot-like consistency
        failed_rate > 0.9):
        return 'suspicious'
    
    # Normal traffic
    return 'normal'


def generate_synthetic_training_data():
    """
    Generate synthetic training data for initial model training.
    Use this if not enough real data exists.
    """
    import random
    
    synthetic_data = []
    
    # Normal traffic (40%)
    for _ in range(100):
        synthetic_data.append({
            'failed_attempt_rate': random.uniform(0, 0.3),
            'unique_users_targeted': random.randint(1, 2),
            'attempts_per_minute': random.uniform(0.1, 2),
            'time_variance': random.uniform(5, 60),
            'ua_diversity': random.randint(1, 2),
            'password_pattern_score': random.uniform(0, 0.2),
            'success_rate': random.uniform(0.7, 1.0),
            'total_attempts': random.randint(1, 10),
            'label': 'normal'
        })
    
    # Brute-force attacks (30%)
    for _ in range(75):
        synthetic_data.append({
            'failed_attempt_rate': random.uniform(0.85, 1.0),
            'unique_users_targeted': 1,
            'attempts_per_minute': random.uniform(10, 50),
            'time_variance': random.uniform(0.1, 2),  # Very consistent
            'ua_diversity': 1,
            'password_pattern_score': random.uniform(0, 0.1),
            'success_rate': random.uniform(0, 0.15),
            'total_attempts': random.randint(45, 200),
            'label': 'brute_force'
        })
    
    # Credential stuffing (20%)
    for _ in range(50):
        synthetic_data.append({
            'failed_attempt_rate': random.uniform(0.75, 0.95),
            'unique_users_targeted': random.randint(5, 30),
            'attempts_per_minute': random.uniform(3, 15),
            'time_variance': random.uniform(0.5, 3),
            'ua_diversity': random.randint(1, 3),
            'password_pattern_score': random.uniform(0.5, 1.0),  # Same password
            'success_rate': random.uniform(0, 0.25),
            'total_attempts': random.randint(10, 100),
            'label': 'credential_stuffing'
        })
    
    # Suspicious activity (10%)
    for _ in range(25):
        synthetic_data.append({
            'failed_attempt_rate': random.uniform(0.6, 0.85),
            'unique_users_targeted': random.randint(1, 5),
            'attempts_per_minute': random.uniform(5, 20),
            'time_variance': random.uniform(0.1, 5),
            'ua_diversity': random.randint(1, 4),
            'password_pattern_score': random.uniform(0.1, 0.6),
            'success_rate': random.uniform(0.1, 0.4),
            'total_attempts': random.randint(10, 50),
            'label': 'suspicious'
        })
    
    return synthetic_data


def features_to_array(features):
    """
    Convert feature dictionaries to numpy arrays for ML training.
    
    Returns:
        X (features), y (labels)
    """
    feature_names = [
        'failed_attempt_rate',
        'unique_users_targeted', 
        'attempts_per_minute',
        'time_variance',
        'ua_diversity',
        'password_pattern_score',
        'success_rate',
        'total_attempts'
    ]
    
    X = []
    y = []
    
    for f in features:
        X.append([f[name] for name in feature_names])
        y.append(f['label'])
    
    return X, y


if __name__ == "__main__":
    print("="*70)
    print("FEATURE ENGINEERING TEST")
    print("="*70 + "\n")
    
    # Try extracting from real data
    print("[*] Attempting to extract features from database...")
    try:
        real_features = extract_features_from_logs()
        print(f"[+] Extracted {len(real_features)} feature sets from real data")
        
        if real_features:
            print("\nSample features:")
            for i, f in enumerate(real_features[:3], 1):
                print(f"\n{i}. IP: {f['ip']}")
                print(f"   Label: {f['label']}")
                print(f"   Failed Rate: {f['failed_attempt_rate']}")
                print(f"   Users Targeted: {f['unique_users_targeted']}")
                print(f"   Attempts/min: {f['attempts_per_minute']}")
    except Exception as e:
        print(f"[!] Could not extract from database: {e}")
        real_features = []
    
    # Generate synthetic data
    print("\n[*] Generating synthetic training data...")
    synthetic_features = generate_synthetic_training_data()
    print(f"[+] Generated {len(synthetic_features)} synthetic feature sets")
    
    # Combine
    all_features = real_features + synthetic_features
    print(f"\n[+] Total features for training: {len(all_features)}")
    
    # Show distribution
    from collections import Counter
    label_dist = Counter([f['label'] for f in all_features])
    print("\nLabel distribution:")
    for label, count in label_dist.items():
        print(f"  {label}: {count} ({count/len(all_features)*100:.1f}%)")