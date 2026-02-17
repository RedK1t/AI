"""
Quick test to verify imports are working correctly
"""
import sys
import os

# Add the severity_ml directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

print("Testing imports...")

try:
    from feature_extractor import FeatureExtractor
    print("✅ FeatureExtractor imported successfully")
except Exception as e:
    print(f"❌ Error importing FeatureExtractor: {e}")

try:
    from severity_classifier import SeverityClassifier
    print("✅ SeverityClassifier imported successfully")
except Exception as e:
    print(f"❌ Error importing SeverityClassifier: {e}")

# Test basic functionality
print("\nTesting basic functionality...")
try:
    extractor = FeatureExtractor()
    print("✅ FeatureExtractor instantiated")
    
    classifier = SeverityClassifier()
    print("✅ SeverityClassifier instantiated")
    
    # Test if model is loaded
    if classifier.is_trained():
        print("✅ Model is trained and loaded")
    else:
        print("⚠️  Model not trained yet (run train_model.py)")
    
    # Test feature extraction
    test_scan = {
        "attack_details": {
            "payload": "' OR '1'='1",
            "parameter": "username",
            "category": "boolean"
        },
        "rule_analysis": {
            "score": 5.0,
            "evidence": ["authentication_bypass_detected"]
        },
        "ai_analysis": {
            "verdict": "yes",
            "confidence": 0.95
        },
        "response": {
            "body": "Welcome admin",
            "status_code": 200,
            "response_time": 0.5
        },
        "baseline": {
            "body": "Invalid login",
            "status_code": 200,
            "response_time": 0.3
        }
    }
    
    features = extractor.extract_features(test_scan)
    print(f"✅ Feature extraction works - extracted {len(features)} features")
    
    # Test prediction
    result = classifier.predict_severity(test_scan)
    print(f"✅ Prediction works - Severity: {result['severity']}, Confidence: {result['confidence']:.1%}")
    
    print("\n" + "="*60)
    print("✅ ALL TESTS PASSED!")
    print("="*60)
    print("\nYou can now run:")
    print("  python train_model.py  - to train the model")
    print("  python demo.py         - to see demo predictions")
    
except Exception as e:
    print(f"\n❌ Error: {e}")
    import traceback
    traceback.print_exc()
