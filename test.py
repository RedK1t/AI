import logging
import json
import time
import os
from datetime import datetime
from core.parser import parse_endpoint, parse_raw_request
from core.request_builder import RequestBuilder
from core.http_client import HttpClient
from payloads.mutator import Mutator
from analyzer.rules import analyze_with_rules, analyze_with_rules_xss
from analyzer.verdict import decide_verdict
from analyzer.llm_analyzer import LLMAnalyzer
from reports.report_generator import SingleVulnReportGenerator

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

try:
    from analyzer.severity_ml.severity_classifier import SeverityClassifier
    severity_classifier = SeverityClassifier()
    SEVERITY_AVAILABLE = True
except ImportError:
    severity_classifier = None
    SEVERITY_AVAILABLE = False

logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')


SQLI_QUICK_PROBE_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR '1'='1'--",
    "1' AND 1=1--",
    "' OR 1=1#"
]

XSS_QUICK_PROBE_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "\"><script>alert(1)</script>",
    "'><script>alert(1)</script>",
    "<svg onload=alert(1)>"
]


def _run_vuln_scan_for_endpoint(
    endpoint_data, baseline, scan_client, llm,
    vuln_type, payload_file, quick_probe_payloads,
    progress_callback, result_callback,
    endpoint_idx, endpoints_len, final_results_log,
    counters=None
):
    """
    Run a single vulnerability type scan (SQLi or XSS) on one endpoint.
    Returns number of vulnerabilities found.

    counters: optional dict with a 'tested' key, incremented for every payload sent
    (quick probe + deep test) so the API can report an accurate total.
    """
    if counters is None:
        counters = {'tested': 0}

    method = endpoint_data.get('method', 'GET')
    endpoint_url = endpoint_data.get('url', 'unknown')
    params = endpoint_data.get('params', {})
    param_names = list(params.keys())

    # Captured request headers (cookies/auth) and JSON-vs-form body, if this came from a raw request
    request_headers = endpoint_data.get('request_headers')
    is_json_body = endpoint_data.get('body_type') == 'json'

    if not param_names:
        return 0

    vuln_label = "SQL Injection" if vuln_type == "sql_injection" else "Reflected XSS"
    logging.info(f"\n--- [{vuln_label}] Scan for {endpoint_url} ---")

    found_vulnerabilities = 0
    vulnerable_params = set()
    potentially_vulnerable = {}

    logging.info(f"   Phase 1: Quick probing {len(param_names)} parameter(s) with {vuln_label} payloads...")

    for param_name in param_names:
        if param_name in vulnerable_params:
            continue

        logging.info(f"   Probing parameter: {param_name}")

        for probe_payload in quick_probe_payloads:
            test_params = {}
            for k, v in params.items():
                original_val = v['value'] if isinstance(v, dict) else v
                if k == param_name:
                    test_params[k] = f"{original_val}{probe_payload}"
                else:
                    test_params[k] = original_val

            body_methods = {'POST', 'PUT', 'PATCH'}
            if method in body_methods:
                response = scan_client.send(
                    url=endpoint_url,
                    method=method,
                    data=None if is_json_body else test_params,
                    json_data=test_params if is_json_body else None,
                    headers=request_headers
                )
            else:
                response = scan_client.send(
                    url=endpoint_url,
                    method=method,
                    params=test_params,
                    headers=request_headers
                )

            counters['tested'] += 1

            if vuln_type == "sql_injection":
                rule_result = analyze_with_rules(baseline, response, hint="check_content_change")
            else:
                rule_result = analyze_with_rules_xss(baseline, response, probe_payload, hint="xss_detection")

            score = rule_result.get('score', 0)

            if score > 0:
                logging.info(f"      Potential {vuln_label} in '{param_name}' with score {score}")
                if param_name not in potentially_vulnerable:
                    potentially_vulnerable[param_name] = []
                potentially_vulnerable[param_name].append((probe_payload, score))
                # Strong potential -> stop probing THIS param and move on to deep testing.
                # (Do NOT add to vulnerable_params here: that set means "already confirmed,
                #  skip in deep testing", and marking a merely-potential param would cause the
                #  real vulnerable param to never be deep-tested or reported.)
                if score >= 2.0:
                    break

    # Phase 2: Deep testing.
    # Always build the plan from the FULL endpoint (every param + the all-params injection).
    # This is essential for things like login forms, where injecting only the one param the
    # quick probe happened to flag (e.g. passw) never triggers the SQLi, but injecting all
    # params (uid + passw) does (auth bypass). Quick-probe just decides whether to go deep.
    mutator = Mutator(payload_filename=payload_file, max_per_param=3)
    if potentially_vulnerable:
        logging.info(f"   Phase 2: Deep testing all params (flagged: {list(potentially_vulnerable.keys())})...")
        attack_plan = mutator.create_attack_plan([endpoint_data])
        logging.info(f"   Created {len(attack_plan)} mutations.")
    else:
        logging.info(f"   Phase 2: No individual params flagged, trying multi-parameter injection...")
        attack_plan = mutator.create_attack_plan([endpoint_data])
        attack_plan = [a for a in attack_plan if
                       a.get('injection_type') == 'multi' or a.get('target_param') == 'ALL_PARAMS']
        logging.info(f"   Created {len(attack_plan)} multi-parameter mutations.")

    endpoint_total = len(attack_plan)
    endpoint_current = 0

    for idx, attack in enumerate(attack_plan):
        target_param = attack['target_param']
        if target_param in vulnerable_params:
            continue

        response = scan_client.send(
            url=attack['target_url'],
            method=attack['method'],
            params=attack.get('params_to_send'),
            data=None if is_json_body else attack.get('body_data'),
            json_data=attack.get('body_data') if is_json_body else None,
            headers=request_headers
        )

        endpoint_current += 1
        counters['tested'] += 1

        progress_msg = f"[{vuln_label}] [{attack['method']}] {attack['target_param']} = {attack['raw_payload'][:50]}..."
        if progress_callback:
            progress_callback(progress_msg, url=endpoint_url, current=endpoint_current,
                              total=endpoint_total, tested=counters['tested'])
        logging.info(progress_msg)

        if vuln_type == "sql_injection":
            rule_result = analyze_with_rules(baseline, response, hint=attack['analyzer_hint'])
        else:
            rule_result = analyze_with_rules_xss(baseline, response, attack.get('raw_payload'), hint="xss_detection")

        # Consult the LLM for any payload with medium+ rule evidence (>= 2.0). Medium findings
        # require the LLM's agreement to be confirmed (see decide_verdict), which is what
        # eliminates false positives from weak/ambiguous signals.
        llm_result = None
        if rule_result['score'] >= 2.0:
            logging.info(f"Score {rule_result['score']} warrants AI review for {vuln_label}...")
            llm_result = llm.analyze_vulnerability(
                attack, response['body'],
                rule_result=rule_result, baseline=baseline, response=response,
                vuln_type=vuln_type
            )
            # Rate-limit guard between Cohere calls. Was a flat 6s; now configurable and
            # lower by default. Raise LLM_RATE_LIMIT_DELAY if you hit Cohere 429s.
            time.sleep(float(os.getenv("LLM_RATE_LIMIT_DELAY", "2")))
        else:
            llm_result = {
                "verdict": "no",
                "confidence": 0.0,
                "explanation": "No strong indicators (rule analysis)",
                "ml_label": 0
            }

        final_decision = decide_verdict(rule_result, llm_result)

        severity_result = None
        if final_decision.get('is_vulnerable', False) and SEVERITY_AVAILABLE:
            try:
                scan_result = {
                    'attack_details': {
                        'payload': attack.get('raw_payload', ''),
                        'parameter': attack.get('target_param', ''),
                        'category': attack.get('category', 'boolean')
                    },
                    'rule_analysis': {
                        'score': rule_result.get('score', 0),
                        'evidence': rule_result.get('reasons') or rule_result.get('matches') or []
                    },
                    'ai_analysis': {
                        'verdict': 'yes' if final_decision.get('is_vulnerable') else 'no',
                        'confidence': llm_result.get('confidence', 0.5) if llm_result else 0.5
                    },
                    'response': {
                        'body': response.get('body', ''),
                        'status_code': response.get('status_code', 200),
                        'response_time': response.get('response_time', 0.5)
                    },
                    'baseline': {
                        'body': baseline.get('body', ''),
                        'status_code': baseline.get('status_code', 200),
                        'response_time': baseline.get('response_time', 0.3)
                    }
                }
                severity_result = severity_classifier.predict_severity(scan_result)
            except Exception as e:
                logging.warning(f"Could not predict severity: {e}")

        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "vuln_type": vuln_type,
            "attack_details": {
                "payload": attack.get('raw_payload'),
                "parameter": attack.get('target_param'),
                "category": attack.get('category')
            },
            "rule_analysis": {
                "score": rule_result.get('score', 0),
                "evidence": rule_result.get('reasons') or rule_result.get('matches') or []
            },
            "ai_analysis": llm_result,
            "severity_analysis": severity_result,
            "is_vulnerable": final_decision.get('is_vulnerable', False)
        }
        final_results_log.append(log_entry)

        if final_decision['is_vulnerable']:
            found_vulnerabilities += 1
            vulnerable_params.add(target_param)
            logging.info(f"  [{vuln_label}] [VULNERABLE] Confirmed at: {attack['target_param']}")
            if llm_result:
                logging.info(f"  AI Confidence: {llm_result.get('confidence')} | Label: {llm_result.get('ml_label')}")

            attack_method = attack['method']
            attack_url = attack['target_url']
            params_to_send = attack.get('params_to_send')
            body_data = attack.get('body_data')

            raw_request_lines = [f"{attack_method} {attack_url} HTTP/1.1"]
            raw_request_lines.append("Host: " + attack_url.split('/')[2])
            raw_request_lines.append("User-Agent: V-Scanner/1.0")
            raw_request_lines.append("Accept: */*")
            raw_request_lines.append("Connection: close")

            if attack_method in ['POST', 'PUT', 'PATCH'] and body_data:
                body_str = '&'.join([f"{k}={v}" for k, v in body_data.items()])
                raw_request_lines.append("Content-Type: application/x-www-form-urlencoded")
                raw_request_lines.append(f"Content-Length: {len(body_str)}")
                raw_request_lines.append("")
                raw_request_lines.append(body_str)
            elif params_to_send:
                query_str = '&'.join([f"{k}={v}" for k, v in params_to_send.items()])
                raw_request_lines.append("")
                raw_request_lines.append(f"Query: {query_str}")
            else:
                raw_request_lines.append("")

            raw_request = '\n'.join(raw_request_lines)

            status_code = response.get('status_code', 0)
            if status_code == 0:
                # No HTTP response came back (connection error, or the payload made the
                # server hang past our timeout). Show that explicitly instead of a blank
                # "HTTP/1.1 0" panel — for time-based blind SQLi the delay IS the signal.
                err = response.get('error', 'no response received')
                rt = response.get('response_time', 0.0)
                raw_response = (
                    "HTTP/1.1 000 No Response\n"
                    f"X-Scanner-Note: request did not complete after {rt:.2f}s\n"
                    f"X-Scanner-Error: {err}\n"
                    "\n"
                    "[No response body — the server returned no HTTP response. For a "
                    "time-based blind SQL injection, this delay/timeout is itself the "
                    "evidence that the injected SLEEP/WAITFOR executed.]"
                )
            else:
                raw_response_lines = [f"HTTP/1.1 {status_code}"]
                for header, value in response.get('headers', {}).items():
                    raw_response_lines.append(f"{header}: {value}")
                raw_response_lines.append("")
                raw_response_lines.append(response.get('body', '')[:5000])
                raw_response = '\n'.join(raw_response_lines)

            resolved_param = target_param
            if target_param == "ALL_PARAMS":
                if body_data:
                    resolved_param = list(body_data.keys())
                elif params_to_send:
                    resolved_param = list(params_to_send.keys())
                else:
                    resolved_param = []

            # Confidence + explanation come from the FINAL decision, not the (possibly
            # unused) LLM placeholder, so a confirmed finding never shows "Safe by rules".
            reasons = final_decision.get('why') or rule_result.get('reasons', [])
            if final_decision.get('llm_used') and llm_result and llm_result.get('verdict') == 'yes' \
                    and llm_result.get('explanation'):
                explanation = llm_result['explanation']
            else:
                explanation = "Confirmed by rule analysis"
                if reasons:
                    explanation += ": " + ", ".join(str(r) for r in reasons)
            severity_label = severity_result.get('severity') if severity_result else None

            vulnerability_details = {
                "vuln_type": vuln_type,
                "severity": severity_label,
                "parameter": resolved_param,
                "payload": attack.get('raw_payload'),
                "url": attack['target_url'],
                "method": attack['method'],
                "confidence": final_decision.get('confidence', 0),
                "explanation": explanation,
                "raw_request": raw_request,
                "raw_response": raw_response
            }

            if result_callback:
                result_callback(vulnerability_details)

            logging.info(f"  Stopping tests for {vuln_label} on parameter: {target_param} (vulnerability found)")
            logging.info(f"  Progress: {endpoint_current}/{endpoint_total} payloads tested")
            logging.info("-" * 30)
            break

    return found_vulnerabilities


# Metadata of the most recent scan, consumed by the report REST API
LAST_SCAN = {
    "target_url": None,
    "results_file": None,
    "timestamp": None,
}


def run_scan(target_url, progress_callback=None, result_callback=None,
             endpoint_transition_callback=None, raw_request=None, absolute_url=None):
    """
    Run SQL Injection + Reflected XSS scan with smart parameter detection.

    Two input modes:
    - raw_request provided: scan EXACTLY that captured HTTP request (method, headers,
      query + body params). This is how POST/PUT/PATCH body parameters get tested.
    - raw_request omitted: parse target_url and discover forms (recon / URL-only flow).

    Uses a two-phase approach for each vulnerability type:
    1. Quick probe each parameter with 1-2 payloads to detect potential vulnerabilities
    2. Full testing only on parameters that show potential, or multi-param if none do
    """
    final_results_log = []
    total_vulnerabilities = 0
    previous_endpoint_url = None

    def send_progress(msg, url=None, current=None, total=None):
        if progress_callback and url is not None:
            progress_callback(msg, url, current, total)
        logging.info(msg)

    def send_endpoint_transition(completed_url, next_url):
        if endpoint_transition_callback and completed_url:
            endpoint_transition_callback(completed_url, next_url)

    try:
        if raw_request:
            send_progress("Scanning a captured raw HTTP request (GET/POST/any method, body params included)")
            parsed_data = parse_raw_request(raw_request, absolute_url=absolute_url or target_url)
            if not parsed_data:
                send_progress("Could not parse the raw HTTP request")
                return {"error": "Could not parse the raw HTTP request"}
            # Use the resolved absolute URL as the reporting target when available
            target_url = parsed_data.get('full_url') or parsed_data.get('url') or target_url
        else:
            parsed_data = parse_endpoint(target_url)
        if not parsed_data:
            send_progress("No data parsed from target")
            return {"error": "No data parsed from target"}

        if isinstance(parsed_data, list):
            endpoints = parsed_data
            send_progress(f"Parser OK: Found {len(endpoints)} endpoint(s) from {target_url}")
            for i, ep in enumerate(endpoints):
                method = ep.get('method', 'GET')
                url = ep.get('url', 'unknown')
                params = list(ep.get('params', {}).keys())
                send_progress(f"   [{i + 1}] {method} {url} - Params: {params}")
        else:
            endpoints = [parsed_data]
            method = parsed_data.get('method', 'GET')
            url = parsed_data.get('url', 'unknown')
            params = list(parsed_data.get('params', {}).keys())
            send_progress(f"Parser OK: Target {target_url}")
            send_progress(f"   Method: {method}, Params: {params}")

        scan_client = HttpClient()
        llm = LLMAnalyzer()
        builder = RequestBuilder()
        counters = {'tested': 0}

        # Establish a baseline for each endpoint once; reused by both scan passes.
        prepared = []  # list of (endpoint_data, baseline)
        for endpoint_idx, endpoint_data in enumerate(endpoints):
            endpoint_url = endpoint_data.get('url', target_url)
            param_names = list(endpoint_data.get('params', {}).keys())
            send_progress(f"\n{'=' * 60}")
            send_progress(f"Endpoint {endpoint_idx + 1}/{len(endpoints)}: "
                          f"{endpoint_data.get('method', 'GET')} {endpoint_url}")
            send_progress(f"   Params: {param_names}")

            baseline = builder.get_baseline(endpoint_data)
            if not baseline.get('success'):
                send_progress(f"Baseline Error for endpoint {endpoint_idx + 1}: {baseline.get('error')}")
                continue
            send_progress(f"Baseline Captured (Length: {baseline['length']})")
            prepared.append((endpoint_data, baseline))

        # ===== PASS 1/2: SQL Injection across ALL endpoints first =====
        send_progress(f"\n{'=' * 60}\nPASS 1/2 — SQL Injection\n{'=' * 60}")
        for endpoint_idx, (endpoint_data, baseline) in enumerate(prepared):
            send_progress(f"--- [SQLi] {endpoint_data.get('url')} ---")
            sqli_found = _run_vuln_scan_for_endpoint(
                endpoint_data, baseline, scan_client, llm,
                "sql_injection", "sql_payloads.json", SQLI_QUICK_PROBE_PAYLOADS,
                progress_callback, result_callback,
                endpoint_idx, len(prepared), final_results_log, counters
            )
            total_vulnerabilities += sqli_found

        # ===== PASS 2/2: Reflected XSS across ALL endpoints =====
        send_progress(f"\n{'=' * 60}\nPASS 2/2 — Reflected XSS\n{'=' * 60}")
        for endpoint_idx, (endpoint_data, baseline) in enumerate(prepared):
            send_progress(f"--- [XSS] {endpoint_data.get('url')} ---")
            xss_found = _run_vuln_scan_for_endpoint(
                endpoint_data, baseline, scan_client, llm,
                "reflected_xss", "xss_payloads.json", XSS_QUICK_PROBE_PAYLOADS,
                progress_callback, result_callback,
                endpoint_idx, len(prepared), final_results_log, counters
            )
            total_vulnerabilities += xss_found

            # Endpoint is fully scanned (both passes) -> emit exactly one transition for it
            completed_url = endpoint_data.get('url')
            next_url = prepared[endpoint_idx + 1][0].get('url') if endpoint_idx + 1 < len(prepared) else None
            send_endpoint_transition(completed_url, next_url)

        output_file = os.path.join(SCRIPT_DIR, "core", "scan_results.json")
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(final_results_log, f, indent=4, ensure_ascii=False)

        # Record metadata so the report REST API can build a report from this scan
        LAST_SCAN["target_url"] = target_url
        LAST_SCAN["results_file"] = output_file
        LAST_SCAN["timestamp"] = datetime.now().isoformat()

        sqli_count = sum(1 for r in final_results_log if r.get('vuln_type') == 'sql_injection' and r.get('is_vulnerable'))
        xss_count = sum(1 for r in final_results_log if r.get('vuln_type') == 'reflected_xss' and r.get('is_vulnerable'))

        send_progress(f"\n{'=' * 60}")
        send_progress(f"ALL SCANS COMPLETE!")
        send_progress(f"Total Endpoints Tested: {len(prepared)}")
        send_progress(f"Total Payloads Tested: {counters['tested']}")
        send_progress(f"SQL Injection Vulnerabilities: {sqli_count}")
        send_progress(f"Reflected XSS Vulnerabilities: {xss_count}")
        send_progress(f"Total Vulnerabilities Found: {total_vulnerabilities}")
        send_progress(f"Results saved to: {output_file}")

        try:
            reports_dir = os.path.join(SCRIPT_DIR, "reports")
            os.makedirs(reports_dir, exist_ok=True)
            report_gen = SingleVulnReportGenerator(output_file, target_url)
            docx_path = report_gen.generate_docx()
            send_progress(f"DOCX report generated: {docx_path}")
            md_path = report_gen.generate_markdown(output_dir=reports_dir)
            send_progress(f"Markdown report generated: {md_path}")
        except Exception as report_err:
            send_progress(f"Report generation failed: {str(report_err)}")

        send_progress(f"{'=' * 60}")

        return {
            "success": True,
            "total_endpoints": len(prepared),
            "total_payloads_tested": counters['tested'],
            "total_vulnerabilities": total_vulnerabilities,
            "sqli_vulnerabilities": sqli_count,
            "xss_vulnerabilities": xss_count,
            "results_file": output_file
        }

    except Exception as e:
        send_progress(f"Critical Crash: {str(e)}")
        return {"error": str(e)}


def verify_core_integration():
    print("Starting Full System Attack Test with AI & JSON Export...\n")
    target_url = "http://altoro.testfire.net/login.jsp"
    return run_scan(target_url)


if __name__ == "__main__":
    verify_core_integration()
