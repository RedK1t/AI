import json
import os
import copy
from datetime import datetime
from docx import Document
from docx.shared import Inches, Pt, RGBColor, Twips
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.section import WD_ORIENT

class SingleVulnReportGenerator:
    def __init__(self, scan_results_path, target_url="Unknown", client_name="Client"):
        self.scan_results_path = scan_results_path
        self.target_url = target_url
        self.client_name = client_name
        self.results = []
        self.highest_vuln = None
        self.severity_label = "N/A"
        self.vuln_type_label = "N/A"
        self.severity_ml_available = False
        self.load_results()
        self.find_highest_severity()
        self._init_severity_ml()

    def _init_severity_ml(self):
        try:
            from analyzer.severity_ml.severity_classifier import SeverityClassifier
            clf = SeverityClassifier()
            self.severity_ml_available = clf.is_trained()
        except Exception:
            self.severity_ml_available = False

    def load_results(self):
        try:
            with open(self.scan_results_path, 'r') as f:
                data = json.load(f)
                self.results = [x for x in data if isinstance(x, dict)]
        except Exception as e:
            print(f"Error loading results: {e}")

    def find_highest_severity(self):
        if not self.results:
            return

        max_score = 0
        for vuln in self.results:
            score = vuln.get('rule_analysis', {}).get('score', 0)
            if score > max_score:
                max_score = score
                self.highest_vuln = vuln

        if max_score >= 3.0:
            self.severity_label = "CRITICAL"
        elif max_score >= 2.0:
            self.severity_label = "HIGH"
        elif max_score >= 1.0:
            self.severity_label = "MEDIUM"
        else:
            self.severity_label = "LOW"

        if self.highest_vuln:
            vt = self.highest_vuln.get('vuln_type', '')
            if vt == 'reflected_xss':
                self.vuln_type_label = "Reflected XSS (Cross-Site Scripting)"
            elif vt == 'sql_injection':
                self.vuln_type_label = "SQL Injection"
            else:
                self.vuln_type_label = "Security Vulnerability"

    def count_by_type(self):
        sqli = sum(1 for r in self.results if r.get('vuln_type') == 'sql_injection' and r.get('is_vulnerable'))
        xss = sum(1 for r in self.results if r.get('vuln_type') == 'reflected_xss' and r.get('is_vulnerable'))
        return sqli, xss

    def get_severity_label(self, score):
        if score >= 3.0:
            return "CRITICAL"
        elif score >= 2.0:
            return "HIGH"
        elif score >= 1.0:
            return "MEDIUM"
        return "LOW"

    def get_vuln_type_for_score(self, vuln_entry):
        vt = vuln_entry.get('vuln_type', '')
        if vt == 'reflected_xss':
            return "Reflected XSS (Cross-Site Scripting)"
        elif vt == 'sql_injection':
            return "SQL Injection"
        return "Security Vulnerability"

    def get_vuln_detection_method(self, vuln_entry):
        vt = vuln_entry.get('vuln_type', '')
        if vt == 'reflected_xss':
            return "Reflected XSS Detection"
        category = vuln_entry.get('attack_details', {}).get('category', '')
        if 'time' in str(category).lower():
            return "Time-based Blind SQL Injection"
        elif 'error' in str(category).lower():
            return "Error-based SQL Injection"
        elif 'boolean' in str(category).lower():
            return "Boolean-based Blind SQL Injection"
        return category.title() + " SQL Injection" if category else "SQL Injection"

    def generate_docx(self, output_path=None):
        doc = Document()

        title = doc.add_heading("Security Assessment Report", 0)
        title.alignment = WD_ALIGN_PARAGRAPH.CENTER

        p = doc.add_paragraph()
        p.add_run("Prepared For: ").bold = True
        p.add_run(self.client_name)

        p = doc.add_paragraph()
        p.add_run("Prepared By: ").bold = True
        p.add_run("V_Scanner Security Team")

        p = doc.add_paragraph()
        p.add_run("Report Issued: ").bold = True
        p.add_run(datetime.now().strftime("%B %d, %Y"))

        doc.add_heading("Executive Summary", level=1)

        severity_desc = {
            "CRITICAL": "critical and immediately exploitable",
            "HIGH": "high and potentially exploitable",
            "MEDIUM": "medium severity",
            "LOW": "low severity"
        }

        sqli_count, xss_count = self.count_by_type()
        has_sqli = sqli_count > 0
        has_xss = xss_count > 0

        summary_text = f"V_Scanner performed a security assessment on {self.target_url}. "
        summary_text += f"The assessment identified security vulnerabilities including: "

        vuln_parts = []
        if has_sqli:
            vuln_parts.append(f"{sqli_count} SQL Injection issue(s)")
        if has_xss:
            vuln_parts.append(f"{xss_count} Reflected XSS issue(s)")

        if vuln_parts:
            summary_text += ", ".join(vuln_parts) + ". "
        else:
            summary_text += "no significant vulnerabilities. "

        if self.highest_vuln:
            top_type = self.get_vuln_type_for_score(self.highest_vuln)
            top_param = self.highest_vuln.get('attack_details', {}).get('parameter', 'Unknown')
            summary_text += f"The highest severity finding is a {self.severity_label} severity {top_type} "
            summary_text += f"affecting the {top_param} parameter."

        doc.add_paragraph(summary_text)

        p = doc.add_paragraph()
        p.add_run("The identified vulnerabilities give potential attackers the opportunity to: ").bold = False

        risk_items = []
        if has_sqli:
            risk_items.append("execute arbitrary SQL commands on the database, potentially exposing sensitive data, bypassing authentication, or compromising the entire system")
        if has_xss:
            risk_items.append("inject malicious scripts into web pages viewed by other users, potentially stealing session cookies, credentials, or performing actions on behalf of victims")

        if risk_items:
            p.add_run("; ".join(risk_items) + ".")
        else:
            p.add_run("No exploitable vulnerabilities were identified at this time.")

        doc.add_paragraph()
        p = doc.add_paragraph()
        run = p.add_run("Note that this assessment may not disclose all vulnerabilities present in the system. ")
        run.italic = True
        p.add_run("A comprehensive security assessment should include additional testing such as network scanning, configuration review, and manual penetration testing.")

        doc.add_heading("High Level Assessment Overview", level=1)

        doc.add_heading("Areas for Improvement", level=2)

        doc.add_heading("Short Term Recommendations", level=3)
        short_term = [
            "Implement parameterized queries (prepared statements) for all database interactions",
            "Apply proper output encoding and escaping for all user-supplied data rendered in HTML",
            "Deploy input validation and sanitization at all application entry points",
            "Implement Content Security Policy (CSP) headers to mitigate XSS risks",
            "Apply principle of least privilege to database accounts",
            "Implement Web Application Firewall (WAF) rules as temporary mitigation"
        ]
        for rec in short_term:
            doc.add_paragraph(rec, style='List Bullet')

        doc.add_heading("Long Term Recommendations", level=3)
        long_term = [
            "Conduct comprehensive code review focusing on database queries and output rendering",
            "Implement Security Development Lifecycle (SDL) practices including security testing",
            "Schedule regular security assessments and penetration testing",
            "Train development team on secure coding practices (SQLi and XSS prevention)",
            "Adopt a Content Security Policy (CSP) framework across the application"
        ]
        for rec in long_term:
            doc.add_paragraph(rec, style='List Bullet')

        doc.add_heading("Scope", level=1)
        doc.add_paragraph(f"Target: {self.target_url}")
        doc.add_paragraph(f"Test Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        vuln_types_scanned = []
        if has_sqli or True:
            vuln_types_scanned.append("SQL Injection Vulnerability Assessment")
        if has_xss or True:
            vuln_types_scanned.append("Reflected XSS (Cross-Site Scripting) Vulnerability Assessment")
        doc.add_paragraph(f"Assessment Type: {' and '.join(vuln_types_scanned)}")

        doc.add_heading("Testing Methodology", level=1)
        doc.add_paragraph("The V_Scanner Vulnerability Testing Framework employs multiple attack vectors:")

        methodology = [
            "Boolean-based blind SQL injection testing",
            "Error-based SQL injection testing",
            "Time-based blind SQL injection testing",
            "Multi-parameter simultaneous injection for login forms",
            "Reflected XSS testing with various HTML/JS injection vectors",
            "XSS polyglot and encoded payload testing",
            "AI-powered severity analysis and validation (Cohere API)"
        ]
        for m in methodology:
            doc.add_paragraph(m, style='List Bullet')

        doc.add_heading("Risk Classifications", level=1)

        severity_table = doc.add_table(rows=5, cols=2)
        severity_table.style = 'Table Grid'

        headers = severity_table.rows[0].cells
        headers[0].text = 'Severity'
        headers[1].text = 'Description'
        for cell in headers:
            cell.paragraphs[0].runs[0].bold = True

        severity_defs = [
            ("CRITICAL", "Vulnerability allows complete system compromise with no user interaction required"),
            ("HIGH", "Vulnerability allows significant unauthorized access with minimal effort"),
            ("MEDIUM", "Vulnerability requires specific conditions to exploit"),
            ("LOW", "Vulnerability has limited impact or requires significant user interaction")
        ]

        for i, (sev, desc) in enumerate(severity_defs):
            row = severity_table.rows[i + 1].cells
            row[0].text = sev
            row[1].text = desc

        doc.add_heading("Assessment Findings", level=1)
        doc.add_paragraph("The following vulnerabilities were identified during the assessment (sorted by descending risk score):")
        doc.add_paragraph()

        vuln_count = 0
        for idx, vuln_entry in enumerate(self.results):
            if not vuln_entry.get('is_vulnerable'):
                continue
            vuln_count += 1
            vt = self.get_vuln_type_for_score(vuln_entry)

            doc.add_heading(f"{vuln_count}. {vt} Vulnerability", level=2)

            p = doc.add_paragraph()
            p.add_run("Severity: ").bold = True
            sev = self.get_severity_label(vuln_entry.get('rule_analysis', {}).get('score', 0))
            p.add_run(sev)

            p = doc.add_paragraph()
            p.add_run("Risk Score: ").bold = True
            score = vuln_entry.get('rule_analysis', {}).get('score', 0)
            p.add_run(f"{score}/10")

            doc.add_heading("Security Implications", level=3)

            if vuln_entry.get('vuln_type') == 'reflected_xss':
                implications = {
                    "CRITICAL": "This Reflected XSS vulnerability allows attackers to inject malicious scripts into web pages. An attacker could potentially: steal session cookies and authentication tokens, capture keystrokes and form inputs, redirect users to phishing pages, perform actions on behalf of the victim, and deliver malware.",
                    "HIGH": "This Reflected XSS vulnerability allows attackers to execute arbitrary JavaScript in the victim's browser. Attackers could steal sensitive information, deface web content, or perform unauthorized actions through the victim's session.",
                    "MEDIUM": "This Reflected XSS vulnerability could allow attackers to inject scripts under specific conditions. While exploitation may require user interaction, it still represents a security risk for sensitive applications.",
                    "LOW": "This XSS vulnerability has limited practical impact but should still be addressed to maintain good security posture."
                }
            else:
                implications = {
                    "CRITICAL": "This SQL Injection vulnerability allows attackers to execute arbitrary SQL commands on the database server. An attacker could potentially: read sensitive data (usernames, passwords, credit cards), modify or delete database records, bypass authentication mechanisms, and in some cases, execute operating system commands on the underlying server.",
                    "HIGH": "This SQL Injection vulnerability allows attackers to manipulate SQL queries, potentially leading to unauthorized data access. Attackers could extract sensitive information from the database or bypass authentication controls.",
                    "MEDIUM": "This SQL Injection vulnerability could allow attackers to influence database queries under specific conditions. While direct exploitation may be difficult, it represents a potential security risk.",
                    "LOW": "This vulnerability has limited practical impact but should still be addressed to maintain good security practices."
                }
            doc.add_paragraph(implications.get(sev, "Vulnerability identified."))

            doc.add_heading("Vulnerability Details", level=3)

            vuln_table = doc.add_table(rows=7, cols=2)
            vuln_table.style = 'Table Grid'

            attack = vuln_entry.get('attack_details', {})
            rule = vuln_entry.get('rule_analysis', {})
            ai = vuln_entry.get('ai_analysis', {})

            details = [
                ("Vulnerability Type", vt),
                ("Affected Parameter", str(attack.get('parameter', 'Unknown'))),
                ("Payload Used", str(attack.get('payload', 'N/A'))),
                ("Category", str(attack.get('category', 'Unknown')).upper()),
                ("Confidence", f"{ai.get('confidence', 0) * 100:.0f}%" if ai.get('confidence') else 'N/A'),
                ("Detection Method", self.get_vuln_detection_method(vuln_entry))
            ]

            for i, (key, value) in enumerate(details):
                row = vuln_table.rows[i].cells
                row[0].text = key
                row[1].text = str(value)
                row[0].paragraphs[0].runs[0].bold = True

            doc.add_paragraph()

            doc.add_heading("Evidence", level=3)

            evidence_items = rule.get('evidence', [])
            if evidence_items:
                for e in evidence_items:
                    doc.add_paragraph(e, style='List Bullet')
            else:
                doc.add_paragraph("No additional evidence indicators collected.")

            doc.add_heading("AI Analysis", level=3)
            ai_explanation = ai.get('explanation', 'Analysis not available.')
            doc.add_paragraph(ai_explanation)

            doc.add_heading("Recommendations", level=3)
            if vuln_entry.get('vuln_type') == 'reflected_xss':
                recommendations = [
                    "Implement proper output encoding and escaping for all user-controlled data in HTML/JS contexts",
                    "Apply Content Security Policy (CSP) headers to restrict script execution",
                    "Use context-aware escaping libraries (e.g., OWASP Java Encoder, ESAPI)",
                    "Implement input validation to reject or sanitize script-containing inputs",
                    "Set HttpOnly and Secure flags on session cookies to limit XSS impact",
                    "Conduct regular security code reviews focusing on template rendering"
                ]
            else:
                recommendations = [
                    "Immediately implement parameterized queries (prepared statements) for all database operations",
                    "Deploy input validation and sanitization on all user-supplied data",
                    "Apply least privilege principle - database accounts should only have necessary permissions",
                    "Implement a Web Application Firewall (WAF) as an immediate mitigation measure",
                    "Conduct regular security code reviews focusing on database query construction"
                ]
            for rec in recommendations:
                doc.add_paragraph(rec, style='List Bullet')

            doc.add_heading("References", level=3)
            refs = [
                "OWASP Top 10 - Injection: https://owasp.org/www-project-top-ten/",
                "SQL Injection Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                "XSS (Cross Site Scripting) Prevention: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                "DOM based XSS Prevention: https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html"
            ]
            for ref in refs:
                doc.add_paragraph(ref, style='List Bullet')

        if vuln_count == 0:
            doc.add_paragraph("No exploitable vulnerabilities were found during the assessment.")

        doc.add_heading("Appendix A - Tools Used", level=1)
        tools_table = doc.add_table(rows=6, cols=2)
        tools_table.style = 'Table Grid'
        tools_headers = tools_table.rows[0].cells
        tools_headers[0].text = 'Tool'
        tools_headers[1].text = 'Purpose'
        for cell in tools_headers:
            cell.paragraphs[0].runs[0].bold = True

        tools = [
            ("V_Scanner", "SQL Injection and XSS Testing Framework"),
            ("Python", "Core Testing Engine"),
            ("Requests Library", "HTTP Request Handling"),
            ("Cohere AI", "LLM-based Vulnerability Confirmation"),
            ("AI Analyzer (ML)", "Severity Classification and Validation")
        ]
        for i, (tool, purpose) in enumerate(tools):
            row = tools_table.rows[i + 1].cells
            row[0].text = tool
            row[1].text = purpose

        doc.add_heading("Appendix B - Engagement Information", level=1)
        doc.add_heading("Version Information", level=2)
        ver_table = doc.add_table(rows=4, cols=2)
        ver_table.style = 'Table Grid'
        ver_info = [
            ("Report Version", "1.0"),
            ("Assessment Date", datetime.now().strftime("%Y-%m-%d")),
            ("Report Generated", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            ("Framework Version", "V_Scanner v1.1 (SQLi + XSS)")
        ]
        for i, (key, value) in enumerate(ver_info):
            row = ver_table.rows[i].cells
            row[0].text = key
            row[1].text = value
            row[0].paragraphs[0].runs[0].bold = True

        if output_path is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_path = f"reports/security_report_{timestamp}.docx"

        doc.save(output_path)
        print(f"Report saved: {output_path}")
        return output_path

    def generate_markdown(self, output_dir=None):
        """Generate a professional Markdown vulnerability report with severity breakdown."""
        if output_dir is None:
            output_dir = "reports"
        os.makedirs(output_dir, exist_ok=True)

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_path = os.path.join(output_dir, f"vuln_report_{timestamp}.md")

        sqli_count, xss_count = self.count_by_type()
        total_tests = len(self.results)
        vulnerable_entries = [r for r in self.results if r.get('is_vulnerable')]

        # Severity breakdown
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for r in vulnerable_entries:
            sev = self.get_severity_label(r.get('rule_analysis', {}).get('score', 0))
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        lines = []
        lines.append("# Vulnerability Assessment Report")
        lines.append("")
        lines.append("## Executive Summary")
        lines.append("")
        lines.append(f"V_Scanner performed a comprehensive security assessment on **{self.target_url}**. ")
        lines.append(f"The scan tested **{total_tests} payload variations** across all discovered endpoints ")
        lines.append(f"and identified **{len(vulnerable_entries)} security vulnerabilities** ")
        lines.append(f"({sqli_count} SQL Injection, {xss_count} Reflected XSS).")
        lines.append("")

        sev_desc = {
            "CRITICAL": "Immediate action required",
            "HIGH": "Action required soon",
            "MEDIUM": "Plan remediation",
            "LOW": "Monitor"
        }
        lines.append("| Severity | Count | Risk Level |")
        lines.append("|----------|-------|------------|")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            lines.append(f"| **{sev}** | {severity_counts.get(sev, 0)} | {sev_desc[sev]} |")
        lines.append("")

        # Summary table
        lines.append("## Scan Summary")
        lines.append("")
        lines.append("| Field | Value |")
        lines.append("|-------|-------|")
        lines.append(f"| **Target** | {self.target_url} |")
        lines.append(f"| **Scan Date** | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} |")
        lines.append(f"| **Total Tests** | {total_tests} |")
        lines.append(f"| **Vulnerabilities Found** | {len(vulnerable_entries)} |")
        lines.append(f"| **SQL Injection** | {sqli_count} |")
        lines.append(f"| **Reflected XSS** | {xss_count} |")
        lines.append("")

        # Vulnerability Breakdown by Severity
        lines.append("---")
        lines.append("## Vulnerability Breakdown by Severity")
        lines.append("")

        crit = [r for r in vulnerable_entries if self.get_severity_label(r.get('rule_analysis', {}).get('score', 0)) == "CRITICAL"]
        high = [r for r in vulnerable_entries if self.get_severity_label(r.get('rule_analysis', {}).get('score', 0)) == "HIGH"]

        def write_vuln_entry(entry, idx):
            vt = self.get_vuln_type_for_score(entry)
            attack = entry.get('attack_details', {})
            rule = entry.get('rule_analysis', {})
            ai = entry.get('ai_analysis', {})
            sev = self.get_severity_label(rule.get('score', 0))
            severity_obj = entry.get('severity_analysis', {})

            lines.append(f"### {idx}. {vt} - {sev}")
            lines.append("")
            lines.append(f"**Parameter:** {attack.get('parameter', 'Unknown')}  ")
            lines.append(f"**Payload:** `{attack.get('payload', 'N/A')}`  ")
            lines.append(f"**Category:** {attack.get('category', 'Unknown')}  ")
            lines.append(f"**Risk Score:** {rule.get('score', 0)}/10  ")
            conf = ai.get('confidence', 0)
            conf_pct = f"{conf * 100:.0f}%" if conf else "N/A"
            lines.append(f"**AI Confidence:** {conf_pct}  ")

            # ML Severity
            if severity_obj:
                ml_sev = severity_obj.get('severity', 'N/A')
                ml_conf = severity_obj.get('confidence', 0)
                ml_method = "ML Model" if severity_obj.get('model_used') else "Rule-Based"
                lines.append(f"**ML Severity:** {ml_sev} ({ml_conf:.0%} confidence, {ml_method})  ")
                risk_factors = severity_obj.get('risk_factors', [])
                if risk_factors:
                    lines.append(f"**Risk Factors:** {', '.join(risk_factors)}  ")

            lines.append("")
            lines.append(f"**AI Analysis:** {ai.get('explanation', 'Analysis not available.')}")
            lines.append("")
            evidence = rule.get('evidence', [])
            if evidence:
                lines.append(f"**Evidence:** {', '.join(evidence)}")
            lines.append("")
            lines.append("---")
            lines.append("")

        if crit:
            lines.append("### Critical Vulnerabilities")
            lines.append("")
            for i, v in enumerate(crit, 1):
                write_vuln_entry(v, i)

        if high:
            lines.append("### High Vulnerabilities")
            lines.append("")
            for i, v in enumerate(high, 1):
                write_vuln_entry(v, i)

        medium = [r for r in vulnerable_entries if self.get_severity_label(r.get('rule_analysis', {}).get('score', 0)) == "MEDIUM"]
        low = [r for r in vulnerable_entries if self.get_severity_label(r.get('rule_analysis', {}).get('score', 0)) == "LOW"]

        if medium:
            lines.append("### Medium Risk Findings")
            lines.append("")
            for i, v in enumerate(medium, 1):
                write_vuln_entry(v, i)

        if low:
            lines.append("### Low Risk Findings")
            lines.append("")
            for i, v in enumerate(low, 1):
                write_vuln_entry(v, i)

        # Recommendations
        lines.append("## Recommendations")
        lines.append("")
        lines.append("### Critical Actions")
        lines.append("- Immediate isolation of affected systems")
        lines.append("- Apply emergency patches")
        lines.append("- Review and sanitize all database inputs and output rendering")
        lines.append("")
        lines.append("### Short-term Actions (1-4 weeks)")
        lines.append("- Implement parameterized queries (prepared statements)")
        lines.append("- Apply output encoding for all user-supplied data rendered in HTML")
        lines.append("- Implement Content Security Policy (CSP) headers")
        lines.append("- Deploy input validation at all application layers")
        lines.append("")
        lines.append("### Long-term Actions (1-3 months)")
        lines.append("- Conduct comprehensive security code review (SQLi + XSS focus)")
        lines.append("- Implement Security Development Lifecycle (SDL)")
        lines.append("- Schedule regular penetration testing")
        lines.append("- Train development team on secure coding practices")

        # ML Severity Model Info
        lines.append("")
        lines.append("---")
        lines.append("## Appendix A - ML Severity Classification Model")
        lines.append("")
        lines.append("The V_Scanner uses a **RandomForest classifier** with **20+ features** to predict vulnerability severity.")
        lines.append("")
        lines.append("| Feature | Description |")
        lines.append("|---------|-------------|")
        lines.append("| `rule_score` | Rule-based analysis score (0-10) |")
        lines.append("| `llm_confidence` | AI/LLM confidence in vulnerability (0-1) |")
        lines.append("| `payload_reflection` | Payload reflected in response (XSS) |")
        lines.append("| `has_sql_errors` | SQL error patterns detected |")
        lines.append("| `auth_bypass` | Authentication bypass detected |")
        lines.append("| `has_time_delay` | Time-based injection detected |")
        lines.append("| `response_has_sensitive_data` | Sensitive data in response |")
        lines.append("| `payload_length` | Attack payload length |")
        lines.append("| `length_ratio` | Response length change ratio |")
        lines.append("| `time_difference` | Response time difference |")

        if hasattr(self, 'severity_ml_available') and self.severity_ml_available:
            lines.append("")
            lines.append("**Model Status:** Active (pre-trained model loaded)")
        else:
            lines.append("")
            lines.append("**Model Status:** Rule-based fallback (pre-trained model not available)")

        # Tools
        lines.append("")
        lines.append("## Appendix B - Tools Used")
        lines.append("")
        lines.append("| Tool | Purpose |")
        lines.append("|------|---------|")
        lines.append("| V_Scanner Framework | SQLi + XSS Testing Engine |")
        lines.append("| Python + Requests | HTTP Scanning Engine |")
        lines.append("| Cohere AI (LLM) | Vulnerability Confirmation |")
        lines.append("| RandomForest (ML) | Severity Classification |")
        lines.append("| python-docx | DOCX Report Generation |")

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))

        print(f"Markdown report saved: {output_path}")
        return output_path

    def generate_summary(self):
        if not self.results:
            return "No vulnerabilities found in scan results."

        sqli_count, xss_count = self.count_by_type()
        vuln_entries = [r for r in self.results if r.get('is_vulnerable')]

        if not vuln_entries:
            return "No vulnerable entries found in scan results."

        summary = "=== VULNERABILITY SUMMARY ===\n"
        summary += f"SQL Injection: {sqli_count} issue(s)\n"
        summary += f"Reflected XSS: {xss_count} issue(s)\n"
        summary += f"Total: {len(vuln_entries)} issue(s)\n"

        if self.highest_vuln:
            attack = self.highest_vuln.get('attack_details', {})
            rule = self.highest_vuln.get('rule_analysis', {})
            vt = self.get_vuln_type_for_score(self.highest_vuln)
            summary += f"\n=== HIGHEST SEVERITY VULNERABILITY ===\n"
            summary += f"Type: {vt}\n"
            summary += f"Severity: {self.severity_label}\n"
            summary += f"Parameter: {attack.get('parameter', 'Unknown')}\n"
            summary += f"Payload: {attack.get('payload', 'N/A')}\n"
            summary += f"Score: {rule.get('score', 0)}\n"
            evidence = rule.get('evidence', [])[:3]
            if evidence:
                summary += f"Evidence: {', '.join(evidence)}\n"

        return summary


def main():
    scan_files = [
        'all_scan_results.json',
        'core/scan_results.json'
    ]

    scan_path = None
    for f in scan_files:
        if os.path.exists(f):
            scan_path = f
            break

    if not scan_path:
        print("No scan results found!")
        return

    target = "http://altoro.testfire.net"
    client = "Altoro Mutual"

    generator = SingleVulnReportGenerator(scan_path, target, client)

    print(generator.generate_summary())
    print("\nGenerating report...")
    output = generator.generate_docx()
    print(f"\nDone! Report: {output}")


if __name__ == "__main__":
    main()
