"""
Feature Extractor for Severity Classification

Extracts 20 features from scan results to feed into the ML model.
"""

import re
import json
from typing import Dict, List, Any, Union


class FeatureExtractor:
    """Extract features from vulnerability scan results for severity classification."""
    
    # SQL error patterns that indicate severity
    SEVERE_ERROR_PATTERNS = [
        r"mysql_fetch",
        r"ORA-\d+",
        r"SQLSTATE",
        r"pg_query",
        r"supplied argument is not a valid",
        r"unclosed quotation mark",
        r"you have an error in your sql syntax",
    ]
    
    # Keywords indicating sensitive data exposure
    SENSITIVE_KEYWORDS = [
        'password', 'passwd', 'pwd', 'credential', 'secret',
        'credit_card', 'ssn', 'social_security', 'bank',
        'admin', 'root', 'user_id', 'email', 'phone'
    ]
    
    # Admin panel indicators
    ADMIN_INDICATORS = [
        'admin', 'administrator', 'dashboard', 'control panel',
        'management', 'settings', 'configuration'
    ]
    
    def __init__(self):
        self.error_regex = re.compile("|".join(self.SEVERE_ERROR_PATTERNS), re.IGNORECASE)
    
    def extract_features(self, scan_result: Dict[str, Any]) -> Dict[str, Union[int, float, bool]]:
        """Extract 20 features from a scan result dictionary."""
        features = {}
        
        # Extract nested data
        attack_details = scan_result.get('attack_details', {})
        rule_analysis = scan_result.get('rule_analysis', {})
        ai_analysis = scan_result.get('ai_analysis', {})
        response_data = scan_result.get('response', {})
        baseline_data = scan_result.get('baseline', {})
        
        # 1. Payload Features
        features.update(self._extract_payload_features(attack_details))
        
        # 2. Rule Analysis Features
        features.update(self._extract_rule_features(rule_analysis))
        
        # 3. LLM Analysis Features
        features.update(self._extract_llm_features(ai_analysis))
        
        # 4. Response Features
        features.update(self._extract_response_features(response_data))
        
        # 5. Comparison Features
        features.update(self._extract_comparison_features(response_data, baseline_data))
        
        return features
    
    def _extract_payload_features(self, attack_details: Dict) -> Dict[str, Any]:
        """Extract features related to the attack payload."""
        payload = attack_details.get('payload', '')
        category = attack_details.get('category', '').lower()
        
        return {
            'payload_category_boolean': 1 if category == 'boolean' else 0,
            'payload_category_error': 1 if category == 'error' else 0,
            'payload_category_time': 1 if category == 'time' else 0,
            'payload_category_union': 1 if category == 'union' else 0,
            'payload_length': len(payload),
            'payload_complexity': self._calculate_payload_complexity(payload),
            'is_time_based': 1 if any(kw in payload.lower() for kw in ['sleep', 'waitfor']) else 0,
            'is_union_based': 1 if 'union' in payload.lower() else 0,
            'is_error_based': 1 if any(kw in payload.lower() for kw in ["'", '"', 'or']) else 0,
        }
    
    def _extract_rule_features(self, rule_analysis: Dict) -> Dict[str, Any]:
        """Extract features from rule-based analysis."""
        score = rule_analysis.get('score', 0)
        evidence = rule_analysis.get('evidence', [])
        evidence_str = ' '.join(str(e) for e in evidence).lower()
        
        return {
            'rule_score': score,
            'has_sql_errors': 1 if 'error_pattern_matched' in evidence_str else 0,
            'has_time_delay': 1 if 'time_delay' in evidence_str else 0,
            'auth_bypass_detected': 1 if 'authentication_bypass' in evidence_str else 0,
            'content_changed': 1 if 'normalized_hash_changed' in evidence_str else 0,
        }
    
    def _extract_llm_features(self, ai_analysis: Dict) -> Dict[str, Any]:
        """Extract features from LLM analysis."""
        return {
            'llm_confidence': ai_analysis.get('confidence', 0.0),
            'llm_verdict': 1 if ai_analysis.get('verdict') == 'yes' else 0,
        }
    
    def _extract_response_features(self, response: Dict) -> Dict[str, Any]:
        """Extract features from HTTP response."""
        body = response.get('body', '')
        body_lower = body.lower()
        
        has_severe_errors = 1 if self.error_regex.search(body) else 0
        has_sensitive_data = 1 if any(kw in body_lower for kw in self.SENSITIVE_KEYWORDS) else 0
        has_admin_access = 1 if any(ind in body_lower for ind in self.ADMIN_INDICATORS) else 0
        
        return {
            'response_length': len(body),
            'response_has_db_errors': has_severe_errors,
            'response_has_sensitive_data': has_sensitive_data,
            'response_has_admin_access': has_admin_access,
            'status_code': response.get('status_code', 200),
        }
    
    def _extract_comparison_features(self, response: Dict, baseline: Dict) -> Dict[str, Any]:
        """Extract features comparing response to baseline."""
        response_len = len(response.get('body', ''))
        baseline_len = len(baseline.get('body', ''))
        
        if baseline_len > 0:
            length_ratio = abs(response_len - baseline_len) / baseline_len
        else:
            length_ratio = 0.0
        
        response_time = response.get('response_time', 0)
        baseline_time = baseline.get('response_time', 0)
        time_diff = response_time - baseline_time
        
        status_changed = 1 if response.get('status_code') != baseline.get('status_code') else 0
        
        return {
            'length_ratio': min(length_ratio, 10.0),
            'time_difference': time_diff,
            'status_code_change': status_changed,
        }
    
    def _calculate_payload_complexity(self, payload: str) -> float:
        """Calculate payload complexity score."""
        if not payload:
            return 0.0
        
        length_factor = min(len(payload) / 50.0, 1.0)
        special_chars = sum(1 for c in payload if c in "'\";--#/*=")
        special_factor = min(special_chars / 5.0, 1.0)
        
        keywords = ['union', 'select', 'from', 'where', 'and', 'or', 'sleep']
        keyword_count = sum(1 for kw in keywords if kw in payload.lower())
        keyword_factor = min(keyword_count / 3.0, 1.0)
        
        return (length_factor + special_factor + keyword_factor) / 3.0
    
    def get_feature_names(self) -> List[str]:
        """Return list of feature names for model training."""
        dummy_scan = {
            'attack_details': {'payload': "' OR 1=1--", 'category': 'boolean'},
            'rule_analysis': {'score': 3.0, 'evidence': []},
            'ai_analysis': {'verdict': 'yes', 'confidence': 0.8},
            'response': {'body': '', 'status_code': 200, 'response_time': 1.0},
            'baseline': {'body': '', 'status_code': 200, 'response_time': 0.5}
        }
        features = self.extract_features(dummy_scan)
        return list(features.keys())
