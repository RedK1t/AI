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
        #
        self.model = "command-xlarge-nightly"
        
        # Initialize severity classifier
        self.severity_classifier = None
        if SEVERITY_CLASSIFIER_AVAILABLE:
            try:
                self.severity_classifier = SeverityClassifier()
            except Exception as e:
                print(f"⚠️  Could not initialize severity classifier: {e}")

    def analyze_vulnerability(self, attack_data, response_body, baseline=None, response=None):
        """
        Analyze vulnerability using LLM and predict severity if vulnerable.
        
        Args:
            attack_data: Attack mutation data
            response_body: HTTP response body
            baseline: Baseline response data (for severity classification)
            response: Full response data (for severity classification)
            
        Returns:
            Dictionary with LLM analysis and severity prediction
        """
        # We take only the first 1500 characters to ensure that the API and analysis speed limits are not exceeded
        snippet = str(response_body)[:1500].replace('\n', ' ')

        # the prompet to force AI to JSON-only format
        prompt = f"""
        Analyze the following for SQL Injection vulnerability.
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
                temperature=0.0  # constancy
            )

            text = llm_response.text.strip()

            # استخدام Regex لاستخراج الـ JSON من وسط أي كلام
            json_match = re.search(r'\{.*\}', text, re.DOTALL)
            if json_match:
                result = json.loads(json_match.group())
            else:
                result = json.loads(text)

            # If vulnerability detected, predict severity
            if result.get('verdict') == 'yes' and self.severity_classifier:
                # Build scan result for severity classification
                scan_result = self._build_scan_result(
                    attack_data, result, baseline, response
                )
                severity_result = self.severity_classifier.predict_severity(scan_result)
                
                # Add severity to result
                result['severity'] = severity_result['severity']
                result['severity_confidence'] = severity_result['confidence']
                result['risk_factors'] = severity_result['risk_factors']
                result['severity_method'] = 'ml_model' if severity_result['model_used'] else 'rule_based'

            return result

        except Exception as e:
            print(f"DEBUG: AI Error (Cohere) - {str(e)}")
            return {
                "verdict": "no",
                "confidence": 0.0,
                "explanation": f"Error: {str(e)}",
                "ml_label": 0
            }

    def _build_scan_result(self, attack_data, llm_result, baseline, response):
        """Build scan result dictionary for severity classification."""
        # Extract evidence from attack_data if available
        evidence = attack_data.get('evidence', [])
        
        # Build the scan result structure expected by feature extractor
        scan_result = {
            'attack_details': {
                'payload': attack_data.get('raw_payload', attack_data.get('payload', '')),
                'parameter': attack_data.get('target_param', ''),
                'category': attack_data.get('category', 'error')
            },
            'rule_analysis': {
                'score': attack_data.get('rule_score', 3.0),  # Default if not provided
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
    
    def analyze_with_severity(self, attack_data, response_body, rule_result=None, baseline=None, response=None):
        """
        Extended analyze method with full context for severity classification.
        
        This is the preferred method when you have all the context available.
        """
        # Add rule score to attack_data if provided
        if rule_result and 'rule_score' not in attack_data:
            attack_data['rule_score'] = rule_result.get('score', 0)
            attack_data['evidence'] = rule_result.get('evidence', [])
        
        return self.analyze_vulnerability(attack_data, response_body, baseline, response)
