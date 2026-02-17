# Quick Start: ML Severity Classification

## What You Just Got

A complete Machine Learning module that automatically classifies SQL injection vulnerabilities by severity:
- **Critical**: Auth bypass, data theft
- **High**: SQL errors, time-based blind injection  
- **Medium**: Content changes, minor leaks
- **Low**: Weak signals, possible false positives

## Files Created

```
analyzer/severity_ml/
├── __init__.py                 # Module initialization
├── feature_extractor.py        # Extract 20 features from scan data
├── severity_classifier.py      # RandomForest ML model
├── train_model.py              # Training script
├── example_labeled_data.json   # 8 example samples
└── README.md                   # Full documentation
```

## Step-by-Step Setup (10 minutes)

### 1. Install Dependencies (1 min)

```bash
pip install scikit-learn numpy
```

### 2. Collect & Label Your Data (5-10 mins)

Run your scanner on vulnerable test sites (DVWA, WebGoat, etc.):

```bash
python test.py
```

Look at `core/scan_results.json` and manually label 50-100 confirmed vulnerabilities:

1. Open the JSON file
2. For each vulnerable entry (is_vulnerable: true), add a "severity" field
3. Choose severity based on:
   - **Critical**: Got admin access, saw passwords/credit cards
   - **High**: SQL error messages, time delays (5+ seconds)
   - **Medium**: Page content changed, different response
   - **Low**: Minor differences, not sure

Example labeled entry:
```json
{
  "scan_result": { ... original data ... },
  "severity": "High",
  "notes": "SQL error exposed table structure"
}
```

See `analyzer/severity_ml/example_labeled_data.json` for the full format.

### 3. Train the Model (2 mins)

```bash
cd analyzer/severity_ml
python train_model.py --data your_labeled_data.json
```

You'll see output like:
```
✅ Feature matrix shape: (80, 20)
📈 Class distribution:
  High: 35
  Critical: 20
  Medium: 15
  Low: 10
🚀 Training Random Forest classifier...
✅ Training complete!
📊 Accuracy: 87.5%
```

### 4. Run Scanner with Severity (Instant!)

No code changes needed! Just run your scanner:

```bash
python test.py
```

Results now include severity:
```json
{
  "ai_analysis": {
    "verdict": "yes",
    "confidence": 0.9,
    "explanation": "SQL error exposed database structure",
    "severity": "High",
    "severity_confidence": 0.85,
    "risk_factors": ["sql_errors", "sensitive_data"]
  }
}
```

## How It Works

```
┌─────────────────────────────────────────────────────┐
│  Your Scanner                                       │
│  └─> Detects vulnerability (LLM + Rules)           │
│      └─> [NEW] ML Severity Classifier activates    │
│          └─> Extracts 20 features                  │
│              └─> RandomForest predicts severity    │
│                  └─> Output: Critical/High/Med/Low │
└─────────────────────────────────────────────────────┘
```

### Features Used (20 total)

**Payload Features (8):**
- Category (boolean/error/time/union)
- Length, complexity
- Contains SLEEP/UNION/OR/AND

**Detection Features (5):**
- Rule-based score
- SQL errors detected
- Time delays
- Auth bypass
- Content changed

**LLM Features (2):**
- LLM confidence
- LLM verdict

**Response Features (5):**
- Response length
- Database errors
- Sensitive data exposure
- Admin panel access
- Status code

## No Model? No Problem!

If you don't train a model, the system automatically uses **rule-based severity** with the same features. It works immediately without any training!

## For Your Graduation

### What to Present:

1. **Phase 1**: LLM detects vulnerabilities (done ✓)
2. **Phase 2**: ML classifies severity (done ✓)
3. **Innovation**: Hybrid approach combining linguistic analysis + technical features

### Key Points:

- ✅ LLM interprets HTTP responses linguistically
- ✅ ML model classifies severity using 20 engineered features
- ✅ Rule-based fallback ensures it always works
- ✅ 4-class severity categorization (Critical/High/Medium/Low)
- ✅ Risk factors explain WHY severity was assigned

### Technical Achievements:

- RandomForest classifier with balanced class weights
- 20 carefully engineered security-focused features
- Automatic fallback to rule-based if ML unavailable
- Feature importance analysis
- Confidence scores for predictions

## Troubleshooting

**"Module not found" error?**
```bash
pip install scikit-learn numpy
```

**"No model found" warning?**
- This is normal! It uses rule-based classification
- Train a model when you have labeled data

**Low accuracy after training?**
- Need more samples (aim for 100+ labeled vulnerabilities)
- Make sure you have all 4 severity classes
- Check class distribution (don't have 90% High)

**Want to see feature importance?**
```python
from analyzer.severity_ml.severity_classifier import SeverityClassifier

clf = SeverityClassifier()
print(clf.get_feature_importance())
```

## Next Steps for Graduation

1. ✅ Collect 100-200 labeled samples from your tests
2. ✅ Train the model
3. ✅ Run full scan on 3-5 vulnerable apps
4. ✅ Document results (severity distribution, accuracy)
5. ✅ Prepare presentation showing:
   - Before: Just "vulnerable=yes"
   - After: "vulnerable=yes, severity=High, risk_factors=[...]"

## Questions?

Check `analyzer/severity_ml/README.md` for full technical documentation.

---

**Good luck with your graduation! 🎓**
