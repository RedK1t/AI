import logging
import json
import time
from datetime import datetime
from core.parser import parse_endpoint
from core.request_builder import RequestBuilder
from core.http_client import HttpClient
from payloads.mutator import Mutator
from analyzer.rules import analyze_with_rules
from analyzer.verdict import decide_verdict
from analyzer.llm_analyzer import LLMAnalyzer

# إعداد الـ Logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')


def run_scan(target_url, progress_callback=None, result_callback=None):
    """
    Run SQL injection scan on target URL with smart parameter detection.
    
    Uses a two-phase approach:
    1. Quick probe each parameter with 1-2 payloads to detect potential vulnerabilities
    2. Full testing only on parameters that show potential, or multi-param if none do
    
    Args:
        target_url: The URL to scan
        progress_callback: Optional callback for progress updates (callback(message))
        result_callback: Optional callback for vulnerability found (callback(vulnerability_details))
    
    Returns:
        Dictionary with scan results
    """
    final_results_log = []
    total_vulnerabilities = 0
    total_payloads_tested = 0
    
    # Quick probe payloads - test these first on each parameter
    QUICK_PROBE_PAYLOADS = [
        "' OR '1'='1",
        "' OR 1=1--",
        "' OR '1'='1'--",
        "1' AND 1=1--",
        "' OR 1=1#"
    ]

    def send_progress(msg, current=None, total=None):
        if progress_callback:
            progress_callback(msg, current, total)
        logging.info(msg)

    try:
        parsed_data = parse_endpoint(target_url)
        if not parsed_data:
            send_progress("❌ No data parsed from target")
            return {"error": "No data parsed from target"}
        
        if isinstance(parsed_data, list):
            endpoints = parsed_data
            send_progress(f"✅ Parser OK: Found {len(endpoints)} endpoint(s) from {target_url}")
            for i, ep in enumerate(endpoints):
                method = ep.get('method', 'GET')
                url = ep.get('url', 'unknown')
                params = list(ep.get('params', {}).keys())
                send_progress(f"   [{i+1}] {method} {url} - Params: {params}")
        else:
            endpoints = [parsed_data]
            method = parsed_data.get('method', 'GET')
            url = parsed_data.get('url', 'unknown')
            params = list(parsed_data.get('params', {}).keys())
            send_progress(f"✅ Parser OK: Target {target_url}")
            send_progress(f"   Method: {method}, Params: {params}")

        for endpoint_idx, endpoint_data in enumerate(endpoints):
            method = endpoint_data.get('method', 'GET')
            endpoint_url = endpoint_data.get('url', target_url)
            params = endpoint_data.get('params', {})
            param_names = list(params.keys())
            
            send_progress(f"\n{'='*60}")
            send_progress(f"🔍 Testing Endpoint {endpoint_idx+1}/{len(endpoints)}")
            send_progress(f"   Method: {method}")
            send_progress(f"   URL: {endpoint_url}")
            send_progress(f"   Params: {param_names}")
            send_progress(f"{'='*60}")
            
            builder = RequestBuilder()
            baseline = builder.get_baseline(endpoint_data)

            if not baseline.get('success'):
                send_progress(f"❌ Baseline Error for endpoint {endpoint_idx+1}: {baseline.get('error')}")
                continue
                
            send_progress(f"✅ Baseline Captured (Length: {baseline['length']})")

            scan_client = HttpClient()
            llm = LLMAnalyzer()
            found_vulnerabilities = 0
            vulnerable_params = set()
            potentially_vulnerable = {}  # param -> list of (payload, score) tuples
            
            send_progress(f"\n🧪 Phase 1: Quick probing {len(param_names)} parameter(s)...")
            
            # Phase 1: Quick probe each parameter with simple payloads
            for param_name in param_names:
                if param_name in vulnerable_params:
                    continue
                    
                send_progress(f"   Probing parameter: {param_name}")
                
                for probe_payload in QUICK_PROBE_PAYLOADS:
                    # Inject payload into this parameter
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
                            data=test_params
                        )
                    else:
                        response = scan_client.send(
                            url=endpoint_url,
                            method=method,
                            params=test_params
                        )
                    
                    total_payloads_tested += 1
                    
                    rule_result = analyze_with_rules(baseline, response, hint="check_content_change")
                    score = rule_result.get('score', 0)
                    
                    if score > 0:
                        send_progress(f"      ⚡ Potential vuln detected in '{param_name}' with score {score}")
                        if param_name not in potentially_vulnerable:
                            potentially_vulnerable[param_name] = []
                        potentially_vulnerable[param_name].append((probe_payload, score))
                        
                        # If high score, mark as vulnerable immediately
                        if score >= 2.0:
                            vulnerable_params.add(param_name)
                            break
            
            # Decide testing strategy based on probe results
            if potentially_vulnerable:
                send_progress(f"\n🔬 Phase 2: Deep testing on {len(potentially_vulnerable)} potentially vulnerable parameter(s)...")
                
                # Create focused attack plan for only potentially vulnerable params
                mutator = Mutator(max_per_param=3)
                
                # Create custom endpoint data with only potentially vulnerable params
                filtered_params = {k: v for k, v in params.items() if k in potentially_vulnerable}
                filtered_endpoint = endpoint_data.copy()
                filtered_endpoint['params'] = filtered_params
                
                attack_plan = mutator.create_attack_plan([filtered_endpoint])
                send_progress(f"📦 Created {len(attack_plan)} focused mutations.")
                
            else:
                send_progress(f"\n🔄 Phase 2: No individual params vulnerable, trying multi-parameter injection...")
                
                # Create attack plan with multi-param injection only
                mutator = Mutator(max_per_param=3)
                attack_plan = mutator.create_attack_plan([endpoint_data])
                # Filter to only multi-param attacks
                attack_plan = [a for a in attack_plan if a.get('injection_type') == 'multi' or a.get('target_param') == 'ALL_PARAMS']
                send_progress(f"📦 Created {len(attack_plan)} multi-parameter mutations.")
            
            # Phase 2: Execute full attack plan
            total_payloads_planned = len(attack_plan)
            
            for idx, attack in enumerate(attack_plan):
                target_param = attack['target_param']
                
                if target_param in vulnerable_params:
                    continue

                response = scan_client.send(
                    url=attack['target_url'],
                    method=attack['method'],
                    params=attack.get('params_to_send'),
                    data=attack.get('body_data')
                )

                total_payloads_tested += 1
                
                send_progress(
                    f"   [{attack['method']}] {attack['target_param']} = {attack['raw_payload'][:50]}...",
                    current=total_payloads_tested,
                    total=total_payloads_planned
                )

                rule_result = analyze_with_rules(baseline, response, hint=attack['analyzer_hint'])

                llm_result = None
                if rule_result['score'] >= 3.0:
                    send_progress(f"🔍 Score {rule_result['score']} is high. Consulting AI...")
                    llm_result = llm.analyze_vulnerability(attack, response['body'])
                    time.sleep(6)
                else:
                    llm_result = {
                        "verdict": "no",
                        "confidence": 0.0,
                        "explanation": "Safe by rules",
                        "ml_label": 0
                    }

                final_decision = decide_verdict(rule_result, llm_result)

                log_entry = {
                    "timestamp": datetime.now().isoformat(),
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
                    "is_vulnerable": final_decision.get('is_vulnerable', False)
                }
                final_results_log.append(log_entry)

                if final_decision['is_vulnerable']:
                    found_vulnerabilities += 1
                    vulnerable_params.add(target_param)
                    send_progress(f"⚠️  [VULNERABLE] Confirmed at: {attack['target_param']}")
                    if llm_result:
                        send_progress(f"🤖 AI Confidence: {llm_result.get('confidence')} | Label: {llm_result.get('ml_label')}")
                    
                    vulnerability_details = {
                        "parameter": attack['target_param'],
                        "payload": attack.get('raw_payload'),
                        "url": attack['target_url'],
                        "method": attack['method'],
                        "confidence": llm_result.get('confidence') if llm_result else 0,
                        "explanation": llm_result.get('explanation') if llm_result else ""
                    }
                    
                    if result_callback:
                        result_callback(vulnerability_details)
                    
                    send_progress(f"🛑 Stopping tests for parameter: {target_param} (vulnerability found)")
                    send_progress(f"📊 Progress: {total_payloads_tested}/{total_payloads_planned} payloads tested")
                    send_progress("-" * 30)

            total_vulnerabilities += found_vulnerabilities
            send_progress(f"\n✅ Endpoint {endpoint_idx+1} Complete. Found {found_vulnerabilities} vulnerabilities.")
            send_progress("-" * 60)
        
        output_file = "core/scan_results.json"
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(final_results_log, f, indent=4, ensure_ascii=False)

        send_progress(f"\n{'='*60}")
        send_progress(f"🏁 ALL SCANS COMPLETE!")
        send_progress(f"📊 Total Endpoints Tested: {len(endpoints)}")
        send_progress(f"🐛 Total Vulnerabilities Found: {total_vulnerabilities}")
        send_progress(f"📂 Results saved to: {output_file}")
        send_progress(f"{'='*60}")

        return {
            "success": True,
            "total_endpoints": len(endpoints),
            "total_vulnerabilities": total_vulnerabilities,
            "results_file": output_file
        }

    except Exception as e:
        send_progress(f"💥 Critical Crash: {str(e)}")
        return {"error": str(e)}


def verify_core_integration():
    print("🚀 Starting Full System Attack Test with AI & JSON Export...\n")
    target_url = "http://altoro.testfire.net/login.jsp"
    return run_scan(target_url)


if __name__ == "__main__":
    verify_core_integration()