"""Test the full pipeline with mock data: ML severity + report generation."""
import json
import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

mock_results = [
    # SQLi - Critical: Auth Bypass
    {
        "timestamp": "2026-05-28T10:00:00",
        "vuln_type": "sql_injection",
        "attack_details": {
            "payload": "' OR '1'='1",
            "parameter": "username",
            "category": "boolean"
        },
        "rule_analysis": {
            "score": 5.0,
            "evidence": ["authentication_bypass_detected", "content_changed"]
        },
        "ai_analysis": {
            "verdict": "yes",
            "confidence": 0.95,
            "explanation": "Authentication bypass detected with tautology injection",
            "ml_label": 1
        },
        "severity_analysis": None,
        "is_vulnerable": True
    },
    # SQLi - High: Error-based
    {
        "timestamp": "2026-05-28T10:00:05",
        "vuln_type": "sql_injection",
        "attack_details": {
            "payload": "'",
            "parameter": "id",
            "category": "error"
        },
        "rule_analysis": {
            "score": 3.5,
            "evidence": ["error_pattern_matched", "sql_syntax_error"]
        },
        "ai_analysis": {
            "verdict": "yes",
            "confidence": 0.85,
            "explanation": "SQL error messages exposed in response",
            "ml_label": 1
        },
        "severity_analysis": None,
        "is_vulnerable": True
    },
    # SQLi - Medium: Boolean-based
    {
        "timestamp": "2026-05-28T10:00:10",
        "vuln_type": "sql_injection",
        "attack_details": {
            "payload": "1' AND 1=1--",
            "parameter": "search",
            "category": "boolean"
        },
        "rule_analysis": {
            "score": 2.0,
            "evidence": ["normalized_hash_changed"]
        },
        "ai_analysis": {
            "verdict": "yes",
            "confidence": 0.60,
            "explanation": "Content change detected with boolean injection",
            "ml_label": 1
        },
        "severity_analysis": None,
        "is_vulnerable": True
    },
    # XSS - Critical: script reflected
    {
        "timestamp": "2026-05-28T10:00:15",
        "vuln_type": "reflected_xss",
        "attack_details": {
            "payload": "<script>alert(1)</script>",
            "parameter": "search",
            "category": "basic"
        },
        "rule_analysis": {
            "score": 5.5,
            "evidence": ["payload_reflected_in_response", "xss_markers_detected", "normalized_hash_changed"]
        },
        "ai_analysis": {
            "verdict": "yes",
            "confidence": 0.90,
            "explanation": "Script payload directly reflected in response",
            "ml_label": 1
        },
        "severity_analysis": None,
        "is_vulnerable": True
    },
    # XSS - High: event handler
    {
        "timestamp": "2026-05-28T10:00:20",
        "vuln_type": "reflected_xss",
        "attack_details": {
            "payload": "<img src=x onerror=alert(1)>",
            "parameter": "q",
            "category": "event"
        },
        "rule_analysis": {
            "score": 4.5,
            "evidence": ["payload_reflected_in_response", "xss_markers_detected"]
        },
        "ai_analysis": {
            "verdict": "yes",
            "confidence": 0.85,
            "explanation": "Event handler payload reflected in response",
            "ml_label": 1
        },
        "severity_analysis": None,
        "is_vulnerable": True
    },
    # XSS - Medium: polyglot
    {
        "timestamp": "2026-05-28T10:00:25",
        "vuln_type": "reflected_xss",
        "attack_details": {
            "payload": "'><script>prompt(1)</script>",
            "parameter": "comment",
            "category": "polyglot"
        },
        "rule_analysis": {
            "score": 2.5,
            "evidence": ["xss_markers_detected", "normalized_hash_changed"]
        },
        "ai_analysis": {
            "verdict": "yes",
            "confidence": 0.65,
            "explanation": "Polyglot XSS payload reflected partially",
            "ml_label": 1
        },
        "severity_analysis": None,
        "is_vulnerable": True
    }
]

output_file = os.path.join(SCRIPT_DIR, "core", "scan_results.json")
os.makedirs(os.path.dirname(output_file), exist_ok=True)
with open(output_file, "w", encoding="utf-8") as f:
    json.dump(mock_results, f, indent=2)

print(f"Mock scan results written to {output_file}")
print(f"Entries: {len(mock_results)} (3 SQLi + 3 XSS)")
print("\nVerifying ML severity predictions...")

from analyzer.severity_ml.severity_classifier import SeverityClassifier

classifier = SeverityClassifier()
for r in mock_results:
    print(f"\n--- {r['vuln_type']} | param={r['attack_details']['parameter']} ---")
    result = classifier.predict_severity(r)
    print(f"  Severity: {result['severity']} (confidence: {result['confidence']:.2%})")
    print(f"  Method: {'ML Model' if result.get('model_used') else 'Rule-based'}")
    print(f"  Risk factors: {', '.join(result.get('risk_factors', []))}")
    if result.get('model_used'):
        print(f"  All probs: {result.get('all_probabilities', {})}")

print("\n\nGenerating reports...")
from reports.report_generator import SingleVulnReportGenerator

target = "http://testphp.vulnweb.com"
report_gen = SingleVulnReportGenerator(output_file, target, "Test Client")

print(report_gen.generate_summary())

reports_dir = os.path.join(SCRIPT_DIR, "reports")
os.makedirs(reports_dir, exist_ok=True)

docx_path = report_gen.generate_docx()
print(f"\nDOCX report: {docx_path}")

md_path = report_gen.generate_markdown(output_dir=reports_dir)
print(f"Markdown report: {md_path}")

print("\n✅ Full pipeline verification complete!")
