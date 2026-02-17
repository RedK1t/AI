"""
ML-Based Severity Classification Module for SQL Injection Vulnerabilities

This module provides machine learning-based severity classification for SQL injection
detections, categorizing vulnerabilities into Critical/High/Medium/Low severity levels.

Usage:
    from analyzer.severity_ml.severity_classifier import SeverityClassifier
    
    classifier = SeverityClassifier()
    result = classifier.predict_severity(scan_data)
    # Returns: {'severity': 'High', 'confidence': 0.85, 'factors': [...]}
"""

__version__ = "1.0.0"
__author__ = "Vulnerability Scanner Project"

try:
    from .feature_extractor import FeatureExtractor
    from .severity_classifier import SeverityClassifier
    __all__ = ['FeatureExtractor', 'SeverityClassifier']
except ImportError:
    # Allow importing even if dependencies are missing
    __all__ = []
