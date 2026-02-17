# ML Severity Classification Module

This module provides machine learning-based severity classification for SQL injection vulnerabilities detected by the scanner.

## Overview

The severity classifier analyzes vulnerability scan results and assigns one of four severity levels:

- **Critical**: Authentication bypass, data exfiltration, immediate threat
- **High**: SQL errors, time-based blind injection, database structure exposure
- **Medium**: Content changes, minor information leaks
- **Low**: Weak signals, possible false positives

## Quick Start

### 1. Install Dependencies

```bash
pip install scikit-learn numpy
```

### 2. Label Your Data

First, collect vulnerability scan results and label them. See `example_labeled_data.json` for the format.

Severity levels:
- `Critical`: Score 5+, authentication bypass
- `High`: Score 3-4, SQL errors or time-based injection
- `Medium`: Score 1-2, content changes
- `Low`: Score 0-1, weak signals

### 3. Train the Model

```bash
cd analyzer/severity_ml
python train_model.py --data your_labeled_data.json
```

This will:
- Extract features from your data
- Train a Random Forest classifier
- Save the model to `model/severity_model.pkl`
- Display accuracy and feature importance

### 4. Use in Scanner

The scanner automatically uses the trained model. When a vulnerability is detected, it will output:

```json
{
  "ai_analysis": {
    "verdict": "yes",
    "confidence": 0.9,
    "explanation": "SQL error exposed database structure",
    "ml_label": 1,
    "severity": "High",
    "severity_confidence": 0.85,
    "risk_factors": ["sql_errors", "sensitive_data"],
    "severity_method": "ml_model"
  }
}
```

## Features Used (20 features)

### Payload Features
- `payload_category_*`: One-hot encoded category (boolean/error/time/union)
- `payload_length`: Length of payload string
- `payload_complexity`: Complexity score based on special chars and keywords
- `is_time_based`: Contains SLEEP/WAITFOR
- `is_union_based`: Contains UNION
- `is_error_based`: Contains quotes/OR/AND

### Rule Analysis Features
- `rule_score`: Score from rule-based analyzer (0-10)
- `has_sql_errors`: SQL error pattern detected
- `has_time_delay`: Time delay detected
- `auth_bypass_detected`: Authentication bypass indicator
- `content_changed`: Response content changed

### LLM Analysis Features
- `llm_confidence`: LLM confidence score (0.0-1.0)
- `llm_verdict`: LLM verdict (0=no, 1=yes)

### Response Features
- `response_length`: Length of response body
- `response_has_db_errors`: Database errors in response
- `response_has_sensitive_data`: Sensitive keywords in response
- `response_has_admin_access`: Admin panel keywords in response
- `status_code`: HTTP status code

### Comparison Features
- `length_ratio`: Ratio of response/baseline length change
- `time_difference`: Response time difference from baseline
- `status_code_change`: Status code changed from baseline

## Model Details

- **Algorithm**: Random Forest Classifier
- **Classes**: 4 (Low, Medium, High, Critical)
- **Features**: 20 engineered features
- **Training**: Stratified train/test split (80/20)
- **Metrics**: Accuracy, precision, recall per class

## Training Data Format

```json
[
  {
    "scan_result": {
      "attack_details": {
        "payload": "' OR 1=1--",
        "parameter": "username",
        "category": "boolean"
      },
      "rule_analysis": {
        "score": 5,
        "evidence": ["authentication_bypass_detected"]
      },
      "ai_analysis": {
        "verdict": "yes",
        "confidence": 0.9
      },
      "response": {
        "body": "Welcome admin...",
        "status_code": 200,
        "response_time": 0.5
      },
      "baseline": {
        "body": "Invalid login",
        "status_code": 200,
        "response_time": 0.3
      }
    },
    "severity": "Critical",
    "notes": "Optional notes"
  }
]
```

## Fallback Behavior

If no trained model is available, the system falls back to rule-based classification using the same features. This ensures the scanner always provides severity predictions.

## API Usage

```python
from analyzer.severity_ml.severity_classifier import SeverityClassifier

# Initialize classifier (loads trained model if available)
classifier = SeverityClassifier()

# Predict severity
result = classifier.predict_severity(scan_result)
print(result)
# {
#   'severity': 'High',
#   'severity_label': 2,
#   'confidence': 0.85,
#   'risk_factors': ['sql_errors', 'sensitive_data'],
#   'all_probabilities': {...},
#   'model_used': True
# }
```

## Graduation Project Context

This module fulfills Phase 2 of the vulnerability scanner project:
- **Phase 1**: LLM-based vulnerability detection (✅ Complete)
- **Phase 2**: ML-based severity classification (✅ This module)

The combination provides:
1. LLM interprets linguistic signs in HTTP responses
2. ML model classifies severity based on technical features
3. Results provide actionable prioritization for security teams

## Troubleshooting

**Import Error**: Install scikit-learn:
```bash
pip install scikit-learn numpy
```

**Model Not Found**: Train the model first:
```bash
python analyzer/severity_ml/train_model.py --data your_data.json
```

**Low Accuracy**: Collect more labeled samples (minimum 100 recommended)

## Citation

For academic use, cite this as:
```
Vulnerability Scanner with LLM+ML Pipeline (2026)
Phase 2: Machine Learning Severity Classification
Random Forest classifier with 20 engineered features
```
