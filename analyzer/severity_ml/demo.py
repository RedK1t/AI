"""
Quick Demo: Severity Classification Model

This script demonstrates the ML severity classifier with examples.
Run this to verify the model is working correctly.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from severity_classifier import SeverityClassifier
from feature_extractor import FeatureExtractor
import json


def demo_severity_classification():
    """Demonstrate severity classification with various test cases."""
    
    print("=" * 70)
    print("🔒 SQL INJECTION SEVERITY CLASSIFICATION - DEMO")
    print("=" * 70)
    
    # Initialize classifier
    classifier = SeverityClassifier()
    
    if classifier.is_trained():
        print("✅ Using trained ML model")
    else:
        print("⚠️  Using rule-based classification (train model for ML)")
    
    # Test cases representing different severity levels
    test_cases = [
        {
            "name": "🔴 CRITICAL - Authentication Bypass",
            "description": "SQL injection successfully bypassed authentication and gained admin access",
            "scan": {
                "attack_details": {
                    "payload": "' OR '1'='1",
                    "parameter": "username",
                    "category": "boolean"
                },
                "rule_analysis": {
                    "score": 5.0,
                    "evidence": ["authentication_bypass_detected", "content_changed"]
                },
                "ai_analysis": {
                    "verdict": "yes",
                    "confidence": 0.95
                },
                "response": {
                    "body": "Welcome Administrator! Dashboard loaded. Admin panel accessible.",
                    "status_code": 200,
                    "response_time": 0.5
                },
                "baseline": {
                    "body": "Invalid username or password",
                    "status_code": 200,
                    "response_time": 0.3
                }
            }
        },
        {
            "name": "🔴 CRITICAL - Data Extraction",
            "description": "UNION-based injection extracted sensitive user data including passwords",
            "scan": {
                "attack_details": {
                    "payload": "' UNION SELECT username, password, email FROM users--",
                    "parameter": "id",
                    "category": "union"
                },
                "rule_analysis": {
                    "score": 4.5,
                    "evidence": ["content_changed", "sensitive_data_detected"]
                },
                "ai_analysis": {
                    "verdict": "yes",
                    "confidence": 0.92
                },
                "response": {
                    "body": "admin:password123:admin@test.com\nuser1:qwerty:user1@test.com",
                    "status_code": 200,
                    "response_time": 0.6
                },
                "baseline": {
                    "body": "Product: Laptop - Price: $999",
                    "status_code": 200,
                    "response_time": 0.3
                }
            }
        },
        {
            "name": "🟠 HIGH - SQL Error Exposure",
            "description": "Error-based injection exposed database error messages",
            "scan": {
                "attack_details": {
                    "payload": "'",
                    "parameter": "search",
                    "category": "error"
                },
                "rule_analysis": {
                    "score": 3.5,
                    "evidence": ["error_pattern_matched"]
                },
                "ai_analysis": {
                    "verdict": "yes",
                    "confidence": 0.85
                },
                "response": {
                    "body": "You have an error in your SQL syntax near '\" at line 1. SELECT * FROM products WHERE name LIKE '%'%'",
                    "status_code": 500,
                    "response_time": 0.4
                },
                "baseline": {
                    "body": "Search results",
                    "status_code": 200,
                    "response_time": 0.3
                }
            }
        },
        {
            "name": "🟠 HIGH - Time-Based Blind Injection",
            "description": "Time delay confirms blind SQL injection vulnerability",
            "scan": {
                "attack_details": {
                    "payload": "' AND SLEEP(5)--",
                    "parameter": "id",
                    "category": "time"
                },
                "rule_analysis": {
                    "score": 4.0,
                    "evidence": ["time_delay_5.2s_vs_0.3s"]
                },
                "ai_analysis": {
                    "verdict": "yes",
                    "confidence": 0.88
                },
                "response": {
                    "body": "Loading...",
                    "status_code": 200,
                    "response_time": 5.2
                },
                "baseline": {
                    "body": "Loading...",
                    "status_code": 200,
                    "response_time": 0.3
                }
            }
        },
        {
            "name": "🟡 MEDIUM - Content Change",
            "description": "Boolean-based injection caused content differences but no sensitive data exposed",
            "scan": {
                "attack_details": {
                    "payload": "1' AND 1=1--",
                    "parameter": "id",
                    "category": "boolean"
                },
                "rule_analysis": {
                    "score": 2.0,
                    "evidence": ["normalized_hash_changed"]
                },
                "ai_analysis": {
                    "verdict": "yes",
                    "confidence": 0.65
                },
                "response": {
                    "body": "Product: ABC-123 - Sample product description here",
                    "status_code": 200,
                    "response_time": 0.4
                },
                "baseline": {
                    "body": "Product: XYZ-789 - Another product description",
                    "status_code": 200,
                    "response_time": 0.3
                }
            }
        },
        {
            "name": "🟢 LOW - Weak Signal",
            "description": "Minor differences detected, likely false positive",
            "scan": {
                "attack_details": {
                    "payload": "test",
                    "parameter": "query",
                    "category": "boolean"
                },
                "rule_analysis": {
                    "score": 0.5,
                    "evidence": []
                },
                "ai_analysis": {
                    "verdict": "no",
                    "confidence": 0.3
                },
                "response": {
                    "body": "Results for test query",
                    "status_code": 200,
                    "response_time": 0.3
                },
                "baseline": {
                    "body": "Results for test query",
                    "status_code": 200,
                    "response_time": 0.3
                }
            }
        }
    ]
    
    # Run predictions
    correct_predictions = 0
    
    for test in test_cases:
        print(f"\n{'='*70}")
        print(f"{test['name']}")
        print(f"{'='*70}")
        print(f"Description: {test['description']}")
        print(f"\nPayload: {test['scan']['attack_details']['payload']}")
        print(f"Category: {test['scan']['attack_details']['category']}")
        print(f"Rule Score: {test['scan']['rule_analysis']['score']}")
        
        # Get prediction
        result = classifier.predict_severity(test['scan'])
        
        print(f"\n📊 PREDICTION RESULT:")
        print(f"   Severity: {result['severity'].upper()}")
        print(f"   Confidence: {result['confidence']:.1%}")
        print(f"   Risk Factors: {', '.join(result['risk_factors']) if result['risk_factors'] else 'None'}")
        print(f"   Method: {'🤖 ML Model' if result['model_used'] else '📝 Rule-based'}")
        
        if 'all_probabilities' in result:
            print(f"\n   All Probabilities:")
            for sev, prob in result['all_probabilities'].items():
                bar = '█' * int(prob * 20)
                print(f"      {sev:8}: {prob:.1%} {bar}")
        
        # Check if prediction matches expected severity
        expected_severity = test['name'].split(' - ')[0].strip().replace('🔴 ', '').replace('🟠 ', '').replace('🟡 ', '').replace('🟢 ', '')
        if result['severity'] == expected_severity:
            correct_predictions += 1
            print(f"\n   ✅ CORRECT - Matches expected {expected_severity}")
        else:
            print(f"\n   ⚠️  Expected {expected_severity}, got {result['severity']}")
    
    # Summary
    print(f"\n{'='*70}")
    print("📊 DEMO SUMMARY")
    print(f"{'='*70}")
    print(f"Total test cases: {len(test_cases)}")
    print(f"Correct predictions: {correct_predictions}")
    print(f"Accuracy: {correct_predictions/len(test_cases):.1%}")
    
    if classifier.is_trained():
        print(f"\n✅ Model is trained and working!")
    else:
        print(f"\n⚠️  Using rule-based classification.")
        print(f"   Train the model for better accuracy:")
        print(f"   python train_model.py")
    
    print(f"\n{'='*70}")


def show_feature_importance():
    """Display feature importance if model is trained."""
    classifier = SeverityClassifier()
    
    if not classifier.is_trained():
        print("\n⚠️  Train the model first to see feature importance")
        return
    
    print("\n" + "="*70)
    print("🔍 FEATURE IMPORTANCE")
    print("="*70)
    
    importance = classifier.get_feature_importance()
    
    print("\nTop 15 Most Important Features:")
    for i, (feature, imp) in enumerate(list(importance.items())[:15], 1):
        bar = '█' * int(imp * 50)
        print(f"{i:2d}. {feature:30} {imp:.4f} {bar}")


def main():
    """Main demo function."""
    try:
        demo_severity_classification()
        show_feature_importance()
        
        print("\n" + "="*70)
        print("✅ DEMO COMPLETED SUCCESSFULLY!")
        print("="*70)
        print("\nNext steps:")
        print("1. Train the model: python train_model.py")
        print("2. View full analysis: Open Severity_Classification_Analysis.ipynb")
        print("3. Use in scanner: Run your vulnerability scanner")
        
    except Exception as e:
        print(f"\n❌ Error during demo: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
