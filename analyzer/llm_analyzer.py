import json
import cohere
import re
from core.config import COHERE_API_KEY


class LLMAnalyzer:
    def __init__(self):
        # agent or Cohere
        self.client = cohere.Client(COHERE_API_KEY)
        #
        self.model = "command-xlarge-nightly"

    def analyze_vulnerability(self, attack_data, response_body):
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
            response = self.client.chat(
                model=self.model,
                message=prompt,
                temperature=0.0  # constancy
            )

            text = response.text.strip()

            # استخدام Regex لاستخراج الـ JSON من وسط أي كلام
            json_match = re.search(r'\{.*\}', text, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())

            return json.loads(text)

        except Exception as e:
            print(f"DEBUG: AI Error (Cohere) - {str(e)}")
            return {
                "verdict": "no",
                "confidence": 0.0,
                "explanation": f"Error: {str(e)}",
                "ml_label": 0
            }