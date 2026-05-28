"""Augment training data and retrain model with better hyperparams."""
import json
import copy
import random

random.seed(42)

# Load merged data
with open("analyzer/severity_ml/merged_training_data.json") as f:
    data = json.load(f)

augmented = list(data)

# ---- Data Augmentation ----
# For each entry, create variants with slightly modified features

for entry in data:
    sr = entry["scan_result"]
    payload = sr["attack_details"]["payload"]
    category = sr["attack_details"]["category"]
    severity = entry["severity"]
    vuln_type = sr.get("vuln_type", "sql_injection")

    # 1. Score variations: nearby scores should map to same severity
    base_score = sr["rule_analysis"]["score"]
    for delta in [-0.5, 0.5, 1.0, -1.0]:
        new_score = round(base_score + delta, 1)
        if new_score < 0 or new_score > 6:
            continue
        new_entry = copy.deepcopy(entry)
        new_entry["scan_result"]["rule_analysis"]["score"] = new_score
        # Add a marker so we know it's synthetic
        new_entry["notes"] = f"synthetic: score_variant base={base_score}"
        if new_score != base_score:
            augmented.append(new_entry)

    # 2. Confidence variations
    base_conf = sr["ai_analysis"]["confidence"]
    for delta in [-0.15, 0.15]:
        new_conf = round(base_conf + delta, 2)
        if new_conf < 0.1 or new_conf > 1.0:
            continue
        new_entry = copy.deepcopy(entry)
        new_entry["scan_result"]["ai_analysis"]["confidence"] = new_conf
        new_entry["notes"] = f"synthetic: conf_variant base={base_conf}"
        augmented.append(new_entry)

    # 3. Parameter name variations (doesn't affect severity but adds diversity)
    if category in ("boolean", "error"):
        modified_sr = copy.deepcopy(sr)
        modified_sr["attack_details"]["parameter"] = sr["attack_details"]["parameter"] + "_alt"
        new_entry = copy.deepcopy(entry)
        new_entry["scan_result"] = modified_sr
        new_entry["notes"] = "synthetic: param_variant"
        augmented.append(new_entry)

    # 4. For XSS, payload variant with same category
    if vuln_type == "reflected_xss" and category == "basic":
        alt_payloads = {
            "<script>alert(1)</script>": ["<script>alert('xss')</script>", "<script>alert(document.cookie)</script>"],
            "<script>confirm('xss')</script>": ["<script>confirm('test')</script>"],
            '\"><script>alert(1)</script>': ["\"><script>alert('x')</script>"],
            "'><script>alert(1)</script>": ["'><script>alert('xss')</script>"],
        }
        if payload in alt_payloads:
            for alt_p in alt_payloads[payload]:
                new_entry = copy.deepcopy(entry)
                new_entry["scan_result"]["attack_details"]["payload"] = alt_p
                new_entry["notes"] = "synthetic: payload_variant"
                augmented.append(new_entry)

    # 5. Evidence variations
    evidence = sr["rule_analysis"].get("evidence", [])
    for extra_ev in ["content_changed", "parameter_reflected"]:
        if extra_ev not in evidence:
            new_entry = copy.deepcopy(entry)
            new_entry["scan_result"]["rule_analysis"]["evidence"] = evidence + [extra_ev]
            new_entry["notes"] = f"synthetic: extra_evidence {extra_ev}"
            augmented.append(new_entry)

# Remove exact duplicates
seen = set()
final = []
for item in augmented:
    payload = item["scan_result"]["attack_details"]["payload"]
    score = item["scan_result"]["rule_analysis"]["score"]
    conf = item["scan_result"]["ai_analysis"]["confidence"]
    key = (payload, score, conf)
    if key not in seen:
        seen.add(key)
        final.append(item)

# Shuffle
random.shuffle(final)

# Count
sev_dist = {}
vt_dist = {}
for item in final:
    s = item["severity"]
    v = item["scan_result"].get("vuln_type", "sql_injection")
    sev_dist[s] = sev_dist.get(s, 0) + 1
    vt_dist[v] = vt_dist.get(v, 0) + 1

print(f"Original: {len(data)} entries")
print(f"Augmented + deduped: {len(final)} entries")
print(f"Severity: {sev_dist}")
print(f"Vuln type: {vt_dist}")

# Save augmented data
with open("analyzer/severity_ml/augmented_training_data.json", "w") as f:
    json.dump(final, f, indent=2)

print("\nNow retraining with better hyperparams...")

# ---- Retrain with tuned hyperparams ----
import sys
import os
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix

sys.path.insert(0, "analyzer/severity_ml")
from feature_extractor import FeatureExtractor
from severity_classifier import SeverityClassifier

SEVERITY_MAPPING = {'Low': 0, 'Medium': 1, 'High': 2, 'Critical': 3}
REVERSE_MAPPING = {v: k for k, v in SEVERITY_MAPPING.items()}

extractor = FeatureExtractor()
X = []
y = []

for item in final:
    sr = item["scan_result"]
    features = extractor.extract_features(sr)
    X.append(list(features.values()))
    y.append(SEVERITY_MAPPING.get(item["severity"], 1))

X = np.array(X)
y = np.array(y)

print(f"Feature matrix: {X.shape}")
print(f"Class distribution: {dict(zip(*np.unique(y, return_counts=True)))}")

# Stratified split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

scaler = StandardScaler()
X_train_s = scaler.fit_transform(X_train)
X_test_s = scaler.transform(X_test)

# Tuned for small dataset: fewer trees, shallower, more regularization
model = RandomForestClassifier(
    n_estimators=50,            # Fewer trees (was 200)
    max_depth=8,                # Shallower (was 15)
    min_samples_split=5,        # Require more samples (was 3)
    min_samples_leaf=3,         # Larger leaves (was 2)
    max_features='log2',        # More conservative (was sqrt)
    random_state=42,
    class_weight='balanced',
    bootstrap=True,
    oob_score=True
)

model.fit(X_train_s, y_train)
y_pred = model.predict(X_test_s)
y_train_pred = model.predict(X_train_s)

train_acc = accuracy_score(y_train, y_train_pred)
test_acc = accuracy_score(y_test, y_pred)

cv_scores = cross_val_score(model, X_train_s, y_train, cv=StratifiedKFold(n_splits=3))

print(f"\n--- New Model Performance ---")
print(f"Train Accuracy: {train_acc:.2%}")
print(f"Test Accuracy: {test_acc:.2%}")
print(f"CV Mean Accuracy: {cv_scores.mean():.2%} (+/- {cv_scores.std():.2%})")
print(f"OOB Score: {model.oob_score_:.2%}")
print(f"Train vs Test gap: {train_acc - test_acc:.2%} (was ~43%)")

# Save model
import pickle
model_dir = "analyzer/severity_ml/model"
os.makedirs(model_dir, exist_ok=True)
with open(os.path.join(model_dir, "severity_model.pkl"), "wb") as f:
    pickle.dump(model, f)
with open(os.path.join(model_dir, "scaler.pkl"), "wb") as f:
    pickle.dump(scaler, f)

# Save metadata
feature_names = extractor.get_feature_names()
importance = dict(zip(feature_names, model.feature_importances_.tolist()))
sorted_imp = dict(sorted(importance.items(), key=lambda x: x[1], reverse=True))

report = classification_report(y_test, y_pred, target_names=['Low','Medium','High','Critical'], output_dict=True)
metadata = {
    "train_accuracy": train_acc,
    "test_accuracy": test_acc,
    "cv_mean_accuracy": cv_scores.mean(),
    "cv_std_accuracy": cv_scores.std(),
    "oob_score": model.oob_score_,
    "n_train_samples": len(X_train),
    "n_test_samples": len(X_test),
    "n_total_samples": len(X),
    "augmented_from": len(data),
    "feature_importance": sorted_imp,
    "classification_report": report,
}
with open(os.path.join(model_dir, "model_metadata.json"), "w") as f:
    json.dump(metadata, f, indent=2, default=str)

print(f"\nModel saved to {model_dir}")
print(f"Top 10 features:")
for name, val in list(sorted_imp.items())[:10]:
    print(f"  {name:30}: {val:.4f}")
