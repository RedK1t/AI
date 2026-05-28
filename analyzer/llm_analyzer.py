import json
import cohere
import re
from core.config import COHERE_API_KEY

# Import severity classifier (optional - will use rule-based if not available)
try:
    from analyzer.severity_ml.severity_classifier import SeverityClassifier

    SEVERITY_CLASSIFIER_AVAILABLE = True
except ImportError:
    SEVERITY_CLASSIFIER_AVAILABLE = False


class LLMAnalyzer:
    def __init__(self):
        # agent or Cohere
        self.client = cohere.Client(COHERE_API_KEY)
        self.model = "command-xlarge-nightly"

        # Initialize severity classifier
        self.severity_classifier = None
        if SEVERITY_CLASSIFIER_AVAILABLE:
            try:
                self.severity_classifier = SeverityClassifier()
                print("✅ Severity classifier loaded")
            except Exception as e:
                print(f"⚠️ Could not load severity classifier: {e}")

    def analyze_vulnerability(self, attack_data, response_body, rule_result=None, baseline=None, response=None, vuln_type="sql_injection"):
        """
        Analyze vulnerability using LLM and predict severity if vulnerable.

        Args:
            attack_data: Attack mutation data
            response_body: HTTP response body
            rule_result: Rule analysis result (optional, for severity)
            baseline: Baseline response data (optional, for severity)
            response: Full response data (optional, for severity)
            vuln_type: Type of vulnerability ("sql_injection" or "reflected_xss")

        Returns:
            Dictionary with LLM analysis and severity prediction
        """
        # We take only the first 1500 characters to ensure that the API and analysis speed limits are not exceeded
        snippet = str(response_body)[:1500].replace('\n', ' ')

        vuln_name = "SQL Injection" if vuln_type == "sql_injection" else "Reflected XSS (Cross-Site Scripting)"

        # the prompet to force AI to JSON-only format
        prompt = f"""
        Analyze the following for {vuln_name} vulnerability.
        Payload used: {attack_data.get('payload')}
        Server Response: {snippet}
        Return ONLY a JSON object with this exact structure:
        {{
          "verdict": "yes" or "no",
          "confidence": 0.0 to 1.0,
          "explanation": "one short sentence",
          "ml_label": 1 or 0
        }}
        Do not include any other text or explanations.
        """
        try:
            llm_response = self.client.chat(
                model=self.model,
                message=prompt,
                temperature=0.0
            )
            text = llm_response.text.strip()
            # استخدام Regex لاستخراج الـ JSON من وسط أي كلام
            json_match = re.search(r'\{.*\}', text, re.DOTALL)
            if json_match:
                result = json.loads(json_match.group())
            else:
                result = json.loads(text)
            # If vulnerability detected, predict severity
            if result.get('verdict') == 'yes':
                severity_result = self._predict_severity(attack_data, result, rule_result, baseline, response)

                # Add severity to result
                result['severity'] = severity_result['severity']
                result['severity_confidence'] = severity_result['confidence']
                result['risk_factors'] = severity_result['risk_factors']
                result['severity_method'] = 'ml_model' if severity_result.get('model_used') else 'rule_based'
            return result
        except Exception as e:
            print(f"DEBUG: AI Error (Cohere) - {str(e)}")
            return {
                "verdict": "no",
                "confidence": 0.0,
                "explanation": f"Error: {str(e)}",
                "ml_label": 0
            }

    def _predict_severity(self, attack_data, llm_result, rule_result, baseline, response):
        """Predict severity using the severity classifier."""
        if self.severity_classifier:
            # Build scan result for severity classification
            scan_result = self._build_scan_result(attack_data, llm_result, rule_result, baseline, response)
            return self.severity_classifier.predict_severity(scan_result)
        else:
            # Fallback to simple rule-based
            return self._simple_severity_prediction(attack_data, rule_result)

    def _build_scan_result(self, attack_data, llm_result, rule_result, baseline, response):
        """Build scan result dictionary for severity classification."""
        # Get evidence from rule_result if available
        evidence = []
        if rule_result:
            evidence = rule_result.get('reasons', []) or rule_result.get('evidence', [])

        # Get rule score
        rule_score = rule_result.get('score', 0) if rule_result else 0

        # Build the scan result structure
        scan_result = {
            'attack_details': {
                'payload': attack_data.get('raw_payload', attack_data.get('payload', '')),
                'parameter': attack_data.get('target_param', ''),
                'category': attack_data.get('category', 'error')
            },
            'rule_analysis': {
                'score': rule_score,
                'evidence': evidence
            },
            'ai_analysis': {
                'verdict': llm_result.get('verdict', 'yes'),
                'confidence': llm_result.get('confidence', 0.8)
            },
            'response': response or {
                'body': '',
                'status_code': 200,
                'response_time': 0.5
            },
            'baseline': baseline or {
                'body': '',
                'status_code': 200,
                'response_time': 0.3
            }
        }

        return scan_result

    def _simple_severity_prediction(self, attack_data, rule_result):
        """Simple rule-based severity prediction when classifier not available."""
        score = rule_result.get('score', 0) if rule_result else 0
        category = attack_data.get('category', '').lower()

        # Determine severity based on score and category
        if score >= 5 or category == 'union':
            severity = 'Critical'
        elif score >= 3 or category == 'time':
            severity = 'High'
        elif score >= 1 or category == 'error':
            severity = 'Medium'
        else:
            severity = 'Low'

        return {
            'severity': severity,
            'confidence': 0.6,
            'risk_factors': [f'score_{score}', f'category_{category}'],
            'model_used': False
        }