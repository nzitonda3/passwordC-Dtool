# ml/train_model.py
"""
ML Model Training for Attack Detection

Trains a Random Forest classifier to detect:
- Normal traffic
- Brute-force attacks
- Credential stuffing
- Suspicious activity

Model saved to: models/risk_model.pkl
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import joblib
import numpy as np


def train_risk_model():
    """
    Train the ML risk scoring model.
    """
    print("="*70)
    print("ML RISK MODEL TRAINING")
    print("="*70 + "\n")
    
    # Import feature engineering
    try:
        from ml_feature_engineering import (
            extract_features_from_logs,
            generate_synthetic_training_data,
            features_to_array
        )
    except ImportError:
        print("[!] Could not import feature engineering module")
        print("[*] Make sure ml_feature_engineering.py is in the same directory")
        return False
    
    # Step 1: Collect training data
    print("[*] Step 1: Collecting training data...")
    
    # Try real data first
    try:
        real_features = extract_features_from_logs()
        print(f"[+] Extracted {len(real_features)} real feature sets")
    except Exception as e:
        print(f"[!] Could not extract real features: {e}")
        real_features = []
    
    # Generate synthetic data
    print("[*] Generating synthetic training data...")
    synthetic_features = generate_synthetic_training_data()
    print(f"[+] Generated {len(synthetic_features)} synthetic feature sets")
    
    # Combine
    all_features = real_features + synthetic_features
    
    if len(all_features) < 50:
        print("[!] Not enough training data!")
        return False
    
    print(f"[+] Total training samples: {len(all_features)}")
    
    # Step 2: Convert to arrays
    print("\n[*] Step 2: Converting features to arrays...")
    X, y = features_to_array(all_features)
    X = np.array(X)
    y = np.array(y)
    
    print(f"[+] Feature matrix shape: {X.shape}")
    print(f"[+] Label array shape: {y.shape}")
    
    # Show class distribution
    unique, counts = np.unique(y, return_counts=True)
    print("\n[*] Class distribution:")
    for label, count in zip(unique, counts):
        print(f"    {label}: {count} ({count/len(y)*100:.1f}%)")
    
    # Step 3: Split data
    print("\n[*] Step 3: Splitting data (80% train, 20% test)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"[+] Training set: {len(X_train)} samples")
    print(f"[+] Test set: {len(X_test)} samples")
    
    # Step 4: Train model
    print("\n[*] Step 4: Training Random Forest classifier...")
    model = RandomForestClassifier(
        n_estimators=100,      # Number of trees
        max_depth=10,          # Maximum tree depth
        min_samples_split=5,   # Minimum samples to split
        min_samples_leaf=2,    # Minimum samples in leaf
        random_state=42,
        n_jobs=-1              # Use all CPU cores
    )
    
    model.fit(X_train, y_train)
    print("[+] Model trained successfully!")
    
    # Step 5: Evaluate model
    print("\n[*] Step 5: Evaluating model...")
    
    # Training accuracy
    train_score = model.score(X_train, y_train)
    print(f"[+] Training accuracy: {train_score*100:.2f}%")
    
    # Test accuracy
    test_score = model.score(X_test, y_test)
    print(f"[+] Test accuracy: {test_score*100:.2f}%")
    
    # Cross-validation
    cv_scores = cross_val_score(model, X, y, cv=5)
    print(f"[+] Cross-validation accuracy: {cv_scores.mean()*100:.2f}% (+/- {cv_scores.std()*2*100:.2f}%)")
    
    # Predictions
    y_pred = model.predict(X_test)
    
    # Classification report
    print("\n" + "="*70)
    print("CLASSIFICATION REPORT")
    print("="*70 + "\n")
    print(classification_report(y_test, y_pred))
    
    # Confusion matrix
    print("="*70)
    print("CONFUSION MATRIX")
    print("="*70 + "\n")
    cm = confusion_matrix(y_test, y_pred)
    print("Labels:", unique)
    print(cm)
    
    # Feature importance
    print("\n" + "="*70)
    print("FEATURE IMPORTANCE")
    print("="*70 + "\n")
    
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
    
    importances = model.feature_importances_
    indices = np.argsort(importances)[::-1]
    
    for i, idx in enumerate(indices, 1):
        print(f"{i}. {feature_names[idx]}: {importances[idx]*100:.2f}%")
    
    # Step 6: Save model
    print("\n[*] Step 6: Saving model...")
    
    # Create models directory
    os.makedirs('models', exist_ok=True)
    
    model_path = 'models/risk_model.pkl'
    joblib.dump(model, model_path)
    print(f"[+] Model saved to: {model_path}")
    
    # Save feature names for later use
    metadata = {
        'feature_names': feature_names,
        'classes': list(unique),
        'accuracy': test_score,
        'cv_accuracy': cv_scores.mean()
    }
    
    metadata_path = 'models/risk_model_metadata.pkl'
    joblib.dump(metadata, metadata_path)
    print(f"[+] Metadata saved to: {metadata_path}")
    
    print("\n" + "="*70)
    print("✅ MODEL TRAINING COMPLETE!")
    print("="*70)
    print(f"\nModel Performance:")
    print(f"  • Test Accuracy: {test_score*100:.2f}%")
    print(f"  • CV Accuracy: {cv_scores.mean()*100:.2f}%")
    print(f"  • Ready for real-time risk scoring!")
    print("="*70 + "\n")
    
    return True


def test_model():
    """
    Test the trained model with sample data.
    """
    print("\n" + "="*70)
    print("MODEL TESTING")
    print("="*70 + "\n")
    
    # Load model
    try:
        model = joblib.load('models/risk_model.pkl')
        metadata = joblib.load('models/risk_model_metadata.pkl')
        print("[+] Model loaded successfully")
    except Exception as e:
        print(f"[!] Could not load model: {e}")
        return
    
    # Test cases
    test_cases = [
        {
            'name': 'Normal Login',
            'features': [0.1, 1, 0.5, 30, 1, 0.0, 0.9, 3],
            'expected': 'normal'
        },
        {
            'name': 'Brute-Force Attack',
            'features': [0.95, 1, 30, 0.5, 1, 0.0, 0.05, 50],
            'expected': 'brute_force'
        },
        {
            'name': 'Credential Stuffing',
            'features': [0.85, 20, 10, 2, 2, 0.9, 0.15, 30],
            'expected': 'credential_stuffing'
        },
        {
            'name': 'Suspicious Activity',
            'features': [0.75, 3, 15, 1, 3, 0.4, 0.25, 25],
            'expected': 'suspicious'
        }
    ]
    
    print("Testing model with sample data:\n")
    
    for test in test_cases:
        features = np.array([test['features']])
        prediction = model.predict(features)[0]
        probabilities = model.predict_proba(features)[0]
        
        print(f"Test: {test['name']}")
        print(f"  Expected: {test['expected']}")
        print(f"  Predicted: {prediction}")
        
        # Show probabilities
        print(f"  Probabilities:")
        for i, class_name in enumerate(metadata['classes']):
            print(f"    {class_name}: {probabilities[i]*100:.1f}%")
        
        # Verdict
        if prediction == test['expected']:
            print(f"  ✅ CORRECT\n")
        else:
            print(f"  ❌ INCORRECT\n")


if __name__ == "__main__":
    # Train model
    success = train_risk_model()
    
    if success:
        # Test model
        test_model()
    else:
        print("[!] Training failed")
        sys.exit(1)