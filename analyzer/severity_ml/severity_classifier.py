"""
Severity Classifier - RandomForest-based ML Model

Trains on labeled vulnerability data and predicts severity levels:
- Critical: Immediate threat, auth bypass, data exfiltration
- High: SQL errors, time-based blind injection
- Medium: Content changes, minor info leaks
- Low: Weak signals, possible false positives
"""

import os
import json
import pickle
import numpy as np
from typing import Dict, List, Any, Optional, Tuple

# Try importing sklearn, provide fallback if not available
try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
    from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
    from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
    from sklearn.inspection import permutation_importance
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    print("⚠️  scikit-learn not installed. Using rule-based classification only.")

# Handle imports for both module and direct script execution
try:
    # Try relative import first (when used as module)
    from .feature_extractor import FeatureExtractor
except ImportError:
    # Fall back to absolute import (when run as script)
    from feature_extractor import FeatureExtractor


class SeverityClassifier:
    """Machine Learning classifier for vulnerability severity prediction."""
    
    SEVERITY_LABELS = ['Low', 'Medium', 'High', 'Critical']
    SEVERITY_MAPPING = {'Low': 0, 'Medium': 1, 'High': 2, 'Critical': 3}
    REVERSE_MAPPING = {v: k for k, v in SEVERITY_MAPPING.items()}
    
    def __init__(self, model_dir: str = None):
        """Initialize the severity classifier."""
        if model_dir is None:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            self.model_dir = os.path.join(current_dir, 'model')
        else:
            self.model_dir = model_dir
        
        self.model_path = os.path.join(self.model_dir, 'severity_model.pkl')
        self.scaler_path = os.path.join(self.model_dir, 'scaler.pkl')
        self.metadata_path = os.path.join(self.model_dir, 'model_metadata.json')
        
        self.model = None
        self.scaler = None
        self.feature_extractor = FeatureExtractor()
        self.model_metadata = {}
        
        self._load_model()
    
    def _load_model(self) -> bool:
        """Load pre-trained model if available."""
        if not SKLEARN_AVAILABLE:
            return False
            
        try:
            if os.path.exists(self.model_path) and os.path.exists(self.scaler_path):
                with open(self.model_path, 'rb') as f:
                    self.model = pickle.load(f)
                with open(self.scaler_path, 'rb') as f:
                    self.scaler = pickle.load(f)
                
                # Load metadata if available
                if os.path.exists(self.metadata_path):
                    with open(self.metadata_path, 'r') as f:
                        self.model_metadata = json.load(f)
                
                print(f"✅ Loaded severity model from {self.model_dir}")
                return True
        except Exception as e:
            print(f"⚠️  Could not load model: {e}")
        
        return False
    
    def is_trained(self) -> bool:
        """Check if model has been trained/loaded."""
        return self.model is not None and self.scaler is not None
    
    def predict_severity(self, scan_result: Dict[str, Any]) -> Dict[str, Any]:
        """Predict severity for a vulnerability scan result."""
        features = self.feature_extractor.extract_features(scan_result)
        
        if not self.is_trained():
            return self._rule_based_prediction(features)
        
        feature_vector = np.array(list(features.values())).reshape(1, -1)
        feature_vector_scaled = self.scaler.transform(feature_vector)
        
        severity_label = self.model.predict(feature_vector_scaled)[0]
        probabilities = self.model.predict_proba(feature_vector_scaled)[0]
        
        severity_name = self.REVERSE_MAPPING.get(severity_label, 'Medium')
        confidence = float(max(probabilities))
        
        all_probs = {self.REVERSE_MAPPING[i]: prob for i, prob in enumerate(probabilities)}
        risk_factors = self._identify_risk_factors(features)
        
        return {
            'severity': severity_name,
            'severity_label': int(severity_label),
            'confidence': confidence,
            'risk_factors': risk_factors,
            'all_probabilities': all_probs,
            'model_used': True,
            'features_used': list(features.keys()),
            'feature_values': features
        }
    
    def _rule_based_prediction(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """Fallback rule-based prediction when ML model is not available.
        Handles both SQL Injection and XSS vulnerability types.
        """
        score = 0
        risk_factors = []
        is_xss = features.get('is_xss', 0)
        
        # ===== XSS-Specific Indicators =====
        if is_xss:
            # Payload reflection is the strongest XSS indicator
            if features.get('has_payload_reflection', 0):
                score += 5
                risk_factors.append('payload_reflected')
            
            if features.get('payload_reflected_decoded', 0):
                score += 4
                risk_factors.append('payload_reflected_decoded')
            
            if features.get('has_xss_markers', 0):
                score += 3
                risk_factors.append('xss_markers_detected')
            
            if features.get('response_has_xss_markers', 0):
                score += 2
                risk_factors.append('xss_indicators_in_response')
            
            if features.get('has_html_tags', 0):
                score += 1
                risk_factors.append('html_tag_injection')
            
            if features.get('is_script_tag', 0):
                score += 2
                risk_factors.append('script_tag_injection')
            
            if features.get('is_event_handler', 0):
                score += 2
                risk_factors.append('event_handler_injection')
            
            # Only use XSS-relevant evidence from response
            if features.get('response_has_sensitive_data', 0):
                score += 3
                risk_factors.append('sensitive_data_exposure')
            
            if features.get('response_has_admin_access', 0):
                score += 3
                risk_factors.append('admin_panel_access')
        
        # ===== SQLi-Specific Indicators =====
        else:
            # Critical indicators (highest weight)
            if features.get('auth_bypass_detected', 0):
                score += 5
                risk_factors.append('authentication_bypass')
            
            if features.get('response_has_admin_access', 0) and features.get('response_has_sensitive_data', 0):
                score += 4
                risk_factors.append('admin_with_sensitive_data')
            
            if features.get('is_union_based', 0) and features.get('response_has_sensitive_data', 0):
                score += 4
                risk_factors.append('union_data_extraction')
            
            # High severity indicators
            if features.get('has_sql_errors', 0):
                score += 3
                risk_factors.append('sql_error_exposure')
            
            if features.get('response_has_db_errors', 0):
                score += 3
                risk_factors.append('database_errors')
            
            if features.get('has_time_delay', 0):
                score += 3
                risk_factors.append('time_based_injection')
            
            if features.get('response_has_sensitive_data', 0):
                score += 3
                risk_factors.append('sensitive_data_exposure')
            
            if features.get('response_has_admin_access', 0):
                score += 3
                risk_factors.append('admin_panel_access')
        
        # ===== Shared Indicators (both XSS and SQLi) =====
        if features.get('is_time_based', 0):
            score += 2
            risk_factors.append('time_payload')
        
        if features.get('is_union_based', 0):
            score += 2
            risk_factors.append('union_payload')
        
        if features.get('content_changed', 0):
            score += 1
            risk_factors.append('content_changed')
        
        # Rule-based score factor
        rule_score = features.get('rule_score', 0)
        if rule_score >= 4:
            score += 2
            risk_factors.append('high_rule_score')
        elif rule_score >= 2:
            score += 1
            risk_factors.append('medium_rule_score')
        
        # LLM confidence factor
        llm_confidence = features.get('llm_confidence', 0)
        if llm_confidence >= 0.8:
            score += 1
            risk_factors.append('high_llm_confidence')
        
        # Determine severity based on cumulative score
        if score >= 6:
            severity = 'Critical'
            severity_label = 3
            confidence = 0.9
        elif score >= 4:
            severity = 'High'
            severity_label = 2
            confidence = 0.8
        elif score >= 2:
            severity = 'Medium'
            severity_label = 1
            confidence = 0.7
        else:
            severity = 'Low'
            severity_label = 0
            confidence = 0.5
        
        return {
            'severity': severity,
            'severity_label': severity_label,
            'confidence': confidence,
            'risk_factors': risk_factors,
            'all_probabilities': {
                'Critical': 0.9 if severity == 'Critical' else 0.03,
                'High': 0.9 if severity == 'High' else 0.03,
                'Medium': 0.9 if severity == 'Medium' else 0.03,
                'Low': 0.9 if severity == 'Low' else 0.01
            },
            'model_used': False,
            'rule_score': score
        }
    
    def _identify_risk_factors(self, features: Dict[str, Any]) -> List[str]:
        """Identify which risk factors contributed to the severity."""
        factors = []
        is_xss = features.get('is_xss', 0)
        
        if is_xss:
            if features.get('has_payload_reflection', 0):
                factors.append('payload_reflection')
            if features.get('payload_reflected_decoded', 0):
                factors.append('decoded_payload_reflection')
            if features.get('has_xss_markers', 0):
                factors.append('xss_markers')
            if features.get('response_has_xss_markers', 0):
                factors.append('xss_indicators')
            if features.get('is_script_tag', 0):
                factors.append('script_injection')
            if features.get('is_event_handler', 0):
                factors.append('event_handler_injection')
        else:
            if features.get('auth_bypass_detected', 0):
                factors.append('authentication_bypass')
            if features.get('has_sql_errors', 0) or features.get('response_has_db_errors', 0):
                factors.append('sql_errors')
            if features.get('has_time_delay', 0):
                factors.append('time_based_injection')
            if features.get('is_union_based', 0):
                factors.append('union_based_injection')
        
        # Shared factors
        if features.get('response_has_sensitive_data', 0):
            factors.append('sensitive_data')
        if features.get('response_has_admin_access', 0):
            factors.append('admin_access')
        if features.get('rule_score', 0) >= 4:
            factors.append('high_rule_score')
        if features.get('llm_confidence', 0) >= 0.8:
            factors.append('high_llm_confidence')
        
        return factors
    
    def train(self, X: np.ndarray, y: np.ndarray, save: bool = True) -> Dict[str, Any]:
        """Train the severity classification model."""
        if not SKLEARN_AVAILABLE:
            return {'error': 'scikit-learn not installed'}
        
        # Split data with stratification to maintain class balance
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Scale features
        self.scaler = StandardScaler()
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Initialize Random Forest with optimized hyperparameters
        self.model = RandomForestClassifier(
            n_estimators=200,           # More trees for better stability
            max_depth=15,               # Allow deeper trees
            min_samples_split=3,        # Allow smaller splits
            min_samples_leaf=2,         # Minimum samples in leaf
            random_state=42,
            class_weight='balanced',    # Handle class imbalance
            max_features='sqrt',        # Use sqrt(n_features) for splits
            bootstrap=True,
            oob_score=True              # Out-of-bag score for validation
        )
        
        # Train the model
        self.model.fit(X_train_scaled, y_train)
        
        # Make predictions
        y_pred = self.model.predict(X_test_scaled)
        y_train_pred = self.model.predict(X_train_scaled)
        
        # Calculate metrics
        train_accuracy = accuracy_score(y_train, y_train_pred)
        test_accuracy = accuracy_score(y_test, y_pred)
        
        # Cross-validation for more robust evaluation
        cv_scores = cross_val_score(self.model, X_train_scaled, y_train, cv=StratifiedKFold(n_splits=5))
        
        # Detailed classification report
        report = classification_report(
            y_test, y_pred, 
            target_names=self.SEVERITY_LABELS,
            output_dict=True
        )
        
        # Confusion matrix
        conf_matrix = confusion_matrix(y_test, y_pred)
        
        # Feature importance
        feature_names = self.feature_extractor.get_feature_names()
        importance = dict(zip(feature_names, self.model.feature_importances_.tolist()))
        
        # Sort by importance
        sorted_importance = dict(sorted(importance.items(), key=lambda x: x[1], reverse=True))
        
        # Store metadata
        self.model_metadata = {
            'train_accuracy': train_accuracy,
            'test_accuracy': test_accuracy,
            'cv_mean_accuracy': cv_scores.mean(),
            'cv_std_accuracy': cv_scores.std(),
            'oob_score': self.model.oob_score_,
            'n_train_samples': len(X_train),
            'n_test_samples': len(X_test),
            'class_distribution': {
                'train': {self.REVERSE_MAPPING[int(k)]: int(v) for k, v in zip(*np.unique(y_train, return_counts=True))},
                'test': {self.REVERSE_MAPPING[int(k)]: int(v) for k, v in zip(*np.unique(y_test, return_counts=True))}
            },
            'feature_importance': sorted_importance,
            'classification_report': report,
            'confusion_matrix': conf_matrix.tolist(),
            'model_params': self.model.get_params()
        }
        
        if save:
            self._save_model()
        
        return self.model_metadata
    
    def _save_model(self) -> bool:
        """Save the trained model and scaler."""
        try:
            os.makedirs(self.model_dir, exist_ok=True)
            
            with open(self.model_path, 'wb') as f:
                pickle.dump(self.model, f)
            
            with open(self.scaler_path, 'wb') as f:
                pickle.dump(self.scaler, f)
            
            with open(self.metadata_path, 'w') as f:
                json.dump(self.model_metadata, f, indent=2)
            
            print(f"✅ Model saved to {self.model_dir}")
            return True
        except Exception as e:
            print(f"⚠️  Could not save model: {e}")
            return False
    
    def get_feature_importance(self) -> Dict[str, float]:
        """Get feature importance from the trained model."""
        if not self.is_trained():
            return {}
        
        feature_names = self.feature_extractor.get_feature_names()
        importance = dict(zip(feature_names, self.model.feature_importances_))
        return dict(sorted(importance.items(), key=lambda x: x[1], reverse=True))
    
    def get_model_stats(self) -> Dict[str, Any]:
        """Get comprehensive model statistics."""
        if not self.is_trained():
            return {'error': 'Model not trained'}
        
        return {
            'is_trained': True,
            'model_type': 'RandomForestClassifier',
            'n_estimators': self.model.n_estimators,
            'max_depth': self.model.max_depth,
            'feature_count': len(self.feature_extractor.get_feature_names()),
            'feature_names': self.feature_extractor.get_feature_names(),
            'training_metadata': self.model_metadata
        }
    
    def explain_prediction(self, scan_result: Dict[str, Any]) -> Dict[str, Any]:
        """Explain why a particular severity was predicted."""
        features = self.feature_extractor.extract_features(scan_result)
        prediction = self.predict_severity(scan_result)
        
        # Get top contributing features
        feature_importance = self.get_feature_importance()
        
        explanation = {
            'predicted_severity': prediction['severity'],
            'confidence': prediction['confidence'],
            'risk_factors': prediction['risk_factors'],
            'top_features': {},
            'all_features': features
        }
        
        # Identify which features had high values
        for feature_name, importance in list(feature_importance.items())[:10]:
            value = features.get(feature_name, 0)
            if value > 0:
                explanation['top_features'][feature_name] = {
                    'value': value,
                    'importance': importance
                }
        
        return explanation


# For backward compatibility and easy imports
__all__ = ['SeverityClassifier']
