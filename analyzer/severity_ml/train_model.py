"""
Training Script for Severity Classification Model

Usage:
    # Train with the comprehensive labeled dataset
    python train_model.py
    
    # Train with custom data
    python train_model.py --data path/to/labeled_data.json
"""

import os
import sys
import json
import argparse
import numpy as np
from typing import List, Dict, Any

# Add the current directory to path for imports when run as script
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False

from severity_classifier import SeverityClassifier
from feature_extractor import FeatureExtractor


def load_labeled_data(filepath: str) -> List[Dict]:
    """Load labeled vulnerability data from JSON file."""
    with open(filepath, 'r', encoding='utf-8') as f:
        data = json.load(f)
    return data


def prepare_training_data(data: List[Dict]) -> tuple:
    """
    Prepare feature matrix X and labels y from labeled data.
    
    Expected data format:
    [
        {
            "scan_result": { ... },  # Your scan result format
            "severity": "High"       # One of: Critical/High/Medium/Low
        },
        ...
    ]
    """
    extractor = FeatureExtractor()
    classifier = SeverityClassifier()
    
    X = []
    y = []
    
    print(f"Processing {len(data)} samples...")
    
    for idx, item in enumerate(data):
        scan_result = item.get('scan_result', item)
        severity = item.get('severity', 'Medium')
        
        # Extract features
        features = extractor.extract_features(scan_result)
        feature_vector = list(features.values())
        
        X.append(feature_vector)
        y.append(classifier.SEVERITY_MAPPING.get(severity, 1))
        
        if (idx + 1) % 10 == 0 or idx == len(data) - 1:
            print(f"  Processed {idx + 1}/{len(data)} samples")
    
    return np.array(X), np.array(y)


def train_from_json(json_path: str, output_dir: str = None):
    """Train model from labeled JSON data."""
    print(f"🔄 Loading data from {json_path}")
    data = load_labeled_data(json_path)
    
    print(f"📊 Preparing features from {len(data)} samples...")
    X, y = prepare_training_data(data)
    
    print(f"✅ Feature matrix shape: {X.shape}")
    print(f"📈 Class distribution:")
    classifier = SeverityClassifier()
    for label, count in zip(*np.unique(y, return_counts=True)):
        severity_name = classifier.REVERSE_MAPPING[label]
        print(f"  {severity_name}: {count}")
    
    # Train model
    print("\n🚀 Training Random Forest classifier...")
    print("   Parameters:")
    print("   - n_estimators: 200")
    print("   - max_depth: 15")
    print("   - class_weight: balanced")
    print("   - min_samples_split: 3")
    print("   - min_samples_leaf: 2")
    
    classifier = SeverityClassifier(model_dir=output_dir)
    results = classifier.train(X, y, save=True)
    
    # Print results
    print(f"\n✅ Training complete!")
    print(f"\n📊 Performance Metrics:")
    print(f"  Training Accuracy: {results['train_accuracy']:.2%}")
    print(f"  Test Accuracy: {results['test_accuracy']:.2%}")
    print(f"  CV Mean Accuracy: {results['cv_mean_accuracy']:.2%} (+/- {results['cv_std_accuracy']:.2%})")
    print(f"  OOB Score: {results['oob_score']:.2%}")
    print(f"\n📊 Dataset Info:")
    print(f"  Training samples: {results['n_train_samples']}")
    print(f"  Test samples: {results['n_test_samples']}")
    
    # Feature importance
    print("\n🔍 Top 10 Most Important Features:")
    importance = results['feature_importance']
    sorted_features = sorted(importance.items(), key=lambda x: x[1], reverse=True)
    for feature, imp in sorted_features[:10]:
        print(f"  {feature:30}: {imp:.4f}")
    
    # Classification report summary
    print("\n📊 Per-Class Performance:")
    report = results['classification_report']
    for class_name in ['Low', 'Medium', 'High', 'Critical']:
        if class_name in report:
            precision = report[class_name]['precision']
            recall = report[class_name]['recall']
            f1 = report[class_name]['f1-score']
            support = report[class_name]['support']
            print(f"  {class_name:8}: Precision={precision:.2f}, Recall={recall:.2f}, F1={f1:.2f}, Support={support}")
    
    return classifier, results


def test_model():
    """Test the trained model with example predictions."""
    print("\n" + "="*60)
    print("🧪 Testing Model Predictions")
    print("="*60)
    
    classifier = SeverityClassifier()
    
    if not classifier.is_trained():
        print("⚠️  No trained model found. Please train the model first.")
        return
    
    # Test cases
    test_cases = [
        {
            "name": "Critical - Auth Bypass",
            "scan": {
                "attack_details": {"payload": "' OR '1'='1", "parameter": "username", "category": "boolean"},
                "rule_analysis": {"score": 5, "evidence": ["authentication_bypass_detected"]},
                "ai_analysis": {"verdict": "yes", "confidence": 0.95},
                "response": {"body": "Welcome admin. Dashboard loaded.", "status_code": 200, "response_time": 0.5},
                "baseline": {"body": "Invalid login", "status_code": 200, "response_time": 0.3}
            }
        },
        {
            "name": "High - SQL Error",
            "scan": {
                "attack_details": {"payload": "'", "parameter": "id", "category": "error"},
                "rule_analysis": {"score": 3.5, "evidence": ["error_pattern_matched"]},
                "ai_analysis": {"verdict": "yes", "confidence": 0.85},
                "response": {"body": "SQL syntax error near '", "status_code": 500, "response_time": 0.4},
                "baseline": {"body": "Product details", "status_code": 200, "response_time": 0.3}
            }
        },
        {
            "name": "Medium - Content Change",
            "scan": {
                "attack_details": {"payload": "1' AND 1=1--", "parameter": "id", "category": "boolean"},
                "rule_analysis": {"score": 2, "evidence": ["normalized_hash_changed"]},
                "ai_analysis": {"verdict": "yes", "confidence": 0.6},
                "response": {"body": "Product ABC-123", "status_code": 200, "response_time": 0.4},
                "baseline": {"body": "Product XYZ-789", "status_code": 200, "response_time": 0.3}
            }
        },
        {
            "name": "Low - Weak Signal",
            "scan": {
                "attack_details": {"payload": "test", "parameter": "query", "category": "boolean"},
                "rule_analysis": {"score": 0.5, "evidence": []},
                "ai_analysis": {"verdict": "no", "confidence": 0.3},
                "response": {"body": "Results", "status_code": 200, "response_time": 0.3},
                "baseline": {"body": "Results", "status_code": 200, "response_time": 0.3}
            }
        }
    ]
    
    for test in test_cases:
        print(f"\n📝 Test: {test['name']}")
        result = classifier.predict_severity(test['scan'])
        print(f"   Predicted Severity: {result['severity']}")
        print(f"   Confidence: {result['confidence']:.2%}")
        print(f"   Risk Factors: {', '.join(result['risk_factors'])}")
        print(f"   Method: {'ML Model' if result['model_used'] else 'Rule-based'}")


def main():
    parser = argparse.ArgumentParser(description='Train severity classification model')
    parser.add_argument('--data', type=str, default='training_data.json',
                        help='Path to labeled training data JSON file')
    parser.add_argument('--output-dir', type=str, default=None,
                        help='Directory to save the trained model')
    parser.add_argument('--test', action='store_true',
                        help='Test the trained model after training')
    
    args = parser.parse_args()
    
    # Check if data file exists
    if not os.path.exists(args.data):
        print(f"❌ Data file not found: {args.data}")
        print("Looking for training_data.json...")
        
        # Try to find training_data.json in current directory
        script_dir = os.path.dirname(os.path.abspath(__file__))
        alternative_path = os.path.join(script_dir, 'training_data.json')
        
        if os.path.exists(alternative_path):
            print(f"✅ Found: {alternative_path}")
            args.data = alternative_path
        else:
            print("❌ Could not find training_data.json")
            print("Please provide a valid data file path using --data")
            return
    
    # Train the model
    try:
        classifier, results = train_from_json(args.data, args.output_dir)
        
        # Test if requested
        if args.test:
            test_model()
        
        print("\n" + "="*60)
        print("✅ Training completed successfully!")
        print("="*60)
        print("\nNext steps:")
        print("1. The model is saved in analyzer/severity_ml/model/")
        print("2. Run your scanner - it will automatically use the trained model")
        print("3. Open 'Severity_Classification_Analysis.ipynb' for full statistics")
        
    except Exception as e:
        print(f"\n❌ Error during training: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
