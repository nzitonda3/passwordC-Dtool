# ml/risk_scorer.py - FIXED VERSION
"""
Real-Time ML Risk Scoring

Integrates ML model with detection system to provide:
- Risk scores (0-100) for each login attempt
- Attack type classification
- Confidence scores
- Real-time predictions
"""

import joblib
import numpy as np
from datetime import datetime, timedelta
from collections import defaultdict
import os


class RiskScorer:
    """
    Real-time risk scoring using trained ML model.
    """
    
    def __init__(self, model_path='ml/models/risk_model.pkl'):  # FIXED PATH
        """Initialize risk scorer with trained model."""
        self.model = None
        self.metadata = None
        self.model_path = model_path
        self.load_model()
        
        # Cache for feature extraction
        self.ip_cache = defaultdict(lambda: {
            'attempts': [],
            'users': set(),
            'fingerprints': defaultdict(int),
            'user_agents': set(),
            'timestamps': [],
            'failures': 0,
            'successes': 0
        })
    
    def load_model(self):
        """Load the trained ML model."""
        try:
            self.model = joblib.load(self.model_path)
            metadata_path = self.model_path.replace('.pkl', '_metadata.pkl')
            self.metadata = joblib.load(metadata_path)
            print(f"[+] ML Risk Scorer loaded (accuracy: {self.metadata['accuracy']*100:.1f}%)")
            return True
        except FileNotFoundError:
            print(f"[!] Model not found at {self.model_path}")
            print("[!] Run train_model.py first to train the model")
            return False
        except Exception as e:
            print(f"[!] Error loading model: {e}")
            return False
    
    def update_cache(self, ip, username, status, fingerprint, user_agent=None):
        """
        Update IP cache with new login attempt.
        Call this for each login attempt.
        """
        data = self.ip_cache[ip]
        
        timestamp = datetime.utcnow()
        
        data['attempts'].append((username, status, timestamp, fingerprint))
        data['users'].add(username)
        data['fingerprints'][fingerprint] += 1
        data['timestamps'].append(timestamp)
        
        if user_agent:
            data['user_agents'].add(user_agent)
        
        if status.startswith('fail'):
            data['failures'] += 1
        else:
            data['successes'] += 1
        
        # Clean old data (keep last 1 hour)
        cutoff = datetime.utcnow() - timedelta(hours=1)
        data['timestamps'] = [t for t in data['timestamps'] if t > cutoff]
        data['attempts'] = [a for a in data['attempts'] if a[2] > cutoff]
    
    def extract_features(self, ip):
        """
        Extract ML features for an IP address.
        Returns feature array ready for prediction.
        """
        data = self.ip_cache[ip]
        
        total_attempts = len(data['attempts'])
        
        if total_attempts == 0:
            # Return default safe features
            return np.array([[0.0, 1, 0.1, 30, 1, 0.0, 1.0, 1]])
        
        # Calculate features
        failed_rate = data['failures'] / total_attempts
        unique_users = len(data['users'])
        
        # Attempts per minute
        if len(data['timestamps']) >= 2:
            time_span = (max(data['timestamps']) - min(data['timestamps'])).total_seconds()
            attempts_per_minute = total_attempts / max(time_span / 60, 0.1)
        else:
            attempts_per_minute = 0
        
        # Time variance
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
                time_variance = variance ** 0.5
        
        # User-Agent diversity
        ua_diversity = len(data['user_agents'])
        
        # Password pattern score
        max_fingerprint_reuse = max(data['fingerprints'].values()) if data['fingerprints'] else 0
        password_pattern_score = max_fingerprint_reuse / unique_users if unique_users > 0 else 0
        
        # Success rate
        success_rate = data['successes'] / total_attempts
        
        # Return feature array
        features = [
            failed_rate,
            unique_users,
            attempts_per_minute,
            time_variance,
            ua_diversity,
            password_pattern_score,
            success_rate,
            total_attempts
        ]
        
        return np.array([features])
    
    def score_ip(self, ip):
        """
        Calculate risk score for an IP address.
        
        Returns:
            dict with keys:
            - risk_score: 0-100 (higher = more risky)
            - classification: normal/brute_force/credential_stuffing/suspicious
            - confidence: 0-100 (model confidence)
            - probabilities: dict of class probabilities
        """
        if not self.model:
            return {
                'risk_score': 50,
                'classification': 'unknown',
                'confidence': 0,
                'probabilities': {},
                'error': 'Model not loaded'
            }
        
        # Extract features
        features = self.extract_features(ip)
        
        # Predict
        try:
            prediction = self.model.predict(features)[0]
            probabilities = self.model.predict_proba(features)[0]
            
            # Calculate risk score (0-100)
            # Normal = low risk, attacks = high risk
            risk_map = {
                'normal': 0,
                'suspicious': 60,
                'credential_stuffing': 85,
                'brute_force': 95
            }
            
            base_risk = risk_map.get(prediction, 50)
            
            # Adjust by confidence
            max_prob = max(probabilities)
            confidence = max_prob * 100
            
            # Final risk score
            risk_score = int(base_risk * max_prob)
            
            # Build probability dict
            prob_dict = {}
            for i, class_name in enumerate(self.metadata['classes']):
                prob_dict[class_name] = round(probabilities[i] * 100, 1)
            
            return {
                'risk_score': risk_score,
                'classification': prediction,
                'confidence': round(confidence, 1),
                'probabilities': prob_dict
            }
            
        except Exception as e:
            return {
                'risk_score': 50,
                'classification': 'error',
                'confidence': 0,
                'probabilities': {},
                'error': str(e)
            }
    
    def should_block(self, ip, threshold=80):
        """
        Determine if an IP should be blocked based on risk score.
        
        Args:
            ip: IP address
            threshold: Risk score threshold (default 80)
        
        Returns:
            bool: True if should block
        """
        score_data = self.score_ip(ip)
        return score_data['risk_score'] >= threshold
    
    def get_risk_level(self, risk_score):
        """Get risk level from score."""
        if risk_score >= 80:
            return "CRITICAL", "🔴"
        elif risk_score >= 60:
            return "HIGH", "🟠"
        elif risk_score >= 40:
            return "MEDIUM", "🟡"
        else:
            return "LOW", "🟢"
    
    def clear_cache(self, ip=None):
        """Clear cache for IP or all IPs."""
        if ip:
            if ip in self.ip_cache:
                del self.ip_cache[ip]
        else:
            self.ip_cache.clear()


# Global risk scorer instance
_risk_scorer = None

def get_risk_scorer():
    """Get or create global risk scorer instance."""
    global _risk_scorer
    if _risk_scorer is None:
        _risk_scorer = RiskScorer()
    return _risk_scorer


def score_login_attempt(ip, username, status, fingerprint, user_agent=None):
    """
    Score a single login attempt in real-time.
    
    Call this from your login route or detection system.
    
    Returns:
        dict with risk score and classification
    """
    scorer = get_risk_scorer()
    
    if not scorer.model:
        # Model not available, return safe defaults
        return {
            'risk_score': 0,
            'classification': 'unknown',
            'confidence': 0
        }
    
    # Update cache
    scorer.update_cache(ip, username, status, fingerprint, user_agent)
    
    # Score
    return scorer.score_ip(ip)


# For testing
if __name__ == "__main__":
    print("="*70)
    print("RISK SCORER TEST")
    print("="*70 + "\n")
    
    scorer = RiskScorer()
    
    if not scorer.model:
        print("[!] Model not loaded. Train model first:")
        print("    python ml_train_model.py")
    else:
        print("[+] Risk scorer initialized\n")
        
        # Simulate normal login
        print("Test 1: Normal Login")
        print("-" * 70)
        scorer.update_cache("192.168.1.100", "john", "success", "hash1", "Chrome")
        scorer.update_cache("192.168.1.100", "john", "success", "hash1", "Chrome")
        result = scorer.score_ip("192.168.1.100")
        print(f"Risk Score: {result['risk_score']}/100")
        print(f"Classification: {result['classification']}")
        print(f"Confidence: {result['confidence']}%")
        print(f"Probabilities: {result['probabilities']}\n")
        
        # Simulate brute-force
        print("Test 2: Brute-Force Attack")
        print("-" * 70)
        for i in range(50):
            scorer.update_cache("10.0.0.1", "admin", "fail_wrong_password", f"hash{i}", "bot")
        result = scorer.score_ip("10.0.0.1")
        print(f"Risk Score: {result['risk_score']}/100")
        print(f"Classification: {result['classification']}")
        print(f"Confidence: {result['confidence']}%")
        print(f"Probabilities: {result['probabilities']}\n")
        
        # Simulate credential stuffing
        print("Test 3: Credential Stuffing")
        print("-" * 70)
        for i in range(20):
            scorer.update_cache("10.0.0.2", f"user{i}", "fail_wrong_password", "common_hash", "bot")
        result = scorer.score_ip("10.0.0.2")
        print(f"Risk Score: {result['risk_score']}/100")
        print(f"Classification: {result['classification']}")
        print(f"Confidence: {result['confidence']}%")
        print(f"Probabilities: {result['probabilities']}\n")
        
        print("="*70)
        print("✅ Risk Scorer Tests Complete!")
        print("="*70)