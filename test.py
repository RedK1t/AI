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


def verify_core_integration():
    print("🚀 Starting Full System Attack Test with AI & JSON Export...\n")
    target_url = "http://altoro.testfire.net/login.jsp"

    # قائمة لتخزين النتائج النهائية لتصديرها كـ JSON
    final_results_log = []

    try:
        # [Step 1] Parser
        parsed_data = parse_endpoint(target_url)
        if not parsed_data: 
            print("❌ No data parsed from target")
            return
        
        # Handle both single endpoint and list of endpoints (from forms)
        if isinstance(parsed_data, list):
            endpoints = parsed_data
            print(f"✅ Parser OK: Found {len(endpoints)} endpoint(s) from {target_url}")
            for i, ep in enumerate(endpoints):
                method = ep.get('method', 'GET')
                url = ep.get('url', 'unknown')
                params = list(ep.get('params', {}).keys())
                print(f"   [{i+1}] {method} {url} - Params: {params}")
        else:
            endpoints = [parsed_data]
            method = parsed_data.get('method', 'GET')
            url = parsed_data.get('url', 'unknown')
            params = list(parsed_data.get('params', {}).keys())
            print(f"✅ Parser OK: Target {target_url}")
            print(f"   Method: {method}, Params: {params}")

        # Process each endpoint (URL + forms)
        total_vulnerabilities = 0
        
        for endpoint_idx, endpoint_data in enumerate(endpoints):
            method = endpoint_data.get('method', 'GET')
            endpoint_url = endpoint_data.get('url', target_url)
            
            print(f"\n{'='*60}")
            print(f"🔍 Testing Endpoint {endpoint_idx+1}/{len(endpoints)}")
            print(f"   Method: {method}")
            print(f"   URL: {endpoint_url}")
            print(f"   Params: {list(endpoint_data.get('params', {}).keys())}")
            print(f"{'='*60}")
            
            # [Step 2] Baseline
            builder = RequestBuilder()
            baseline = builder.get_baseline(endpoint_data)

            if not baseline.get('success'):
                print(f"❌ Baseline Error for endpoint {endpoint_idx+1}: {baseline.get('error')}")
                continue
                
            print(f"✅ Baseline Captured (Length: {baseline['length']})")

            # [Step 3] Mutator
            print("\n[Step 3] Generating Attack Plan...")
            mutator = Mutator(max_per_param=3)
            attack_plan = mutator.create_attack_plan([endpoint_data])
            print(f"📦 Created {len(attack_plan)} mutations to test.")

            # [Step 4] Execution & AI Analysis
            print("\n[Step 4] Launching Attacks...")
            scan_client = HttpClient()
            llm = LLMAnalyzer()
            found_vulnerabilities = 0

            for attack in attack_plan:
                # For POST requests, send data in body; for GET, send in query params
                response = scan_client.send(
                    url=attack['target_url'],
                    method=attack['method'],
                    params=attack.get('params_to_send'),
                    data=attack.get('body_data')
                )

                # Debug: Show first few attacks to verify payload injection
                if len(final_results_log) < 3 or attack.get('injection_type') == 'multi':
                    print(f"   [{attack['method']}] {attack['target_param']} = {attack['raw_payload'][:50]}...")
                    if attack.get('body_data'):
                        print(f"      Body: {attack['body_data']}")
                    elif attack.get('params_to_send'):
                        print(f"      Params: {attack['params_to_send']}")

                rule_result = analyze_with_rules(baseline, response, hint=attack['analyzer_hint'])

                llm_result = None
                # تعديل: الفحص فقط للسكور العالي 3.0 فأكثر لتوفير الـ API
                if rule_result['score'] >= 3.0:
                    print(f"🔍 Score {rule_result['score']} is high. Consulting AI...")
                    llm_result = llm.analyze_vulnerability(attack, response['body'])

                    # --- أهم سطر لتجنب الـ 429 ---
                    time.sleep(6)  # انتظار 6 ثوانٍ بين كل طلب AI
                else:
                    # نتائج افتراضية للحالات غير المشبوهة
                    llm_result = {
                        "verdict": "no",
                        "confidence": 0.0,
                        "explanation": "Safe by rules",
                        "ml_label": 0
                    }

                final_decision = decide_verdict(rule_result, llm_result)

                # 4. تجهيز سجل البيانات لملف الـ JSON (هذا هو كنز الـ ML الخاص بك)
                log_entry = {
                    "timestamp": datetime.now().isoformat(),
                    "attack_details": {
                        "payload": attack.get('raw_payload'),
                        "parameter": attack.get('target_param'),
                        "category": attack.get('category')
                    },
                    "rule_analysis": {
                        "score": rule_result.get('score', 0),
                        # هنا بنشوف لو فيه reasons أو matches أو نخليه فاضي
                        "evidence": rule_result.get('reasons') or rule_result.get('matches') or []
                    },
                    "ai_analysis": llm_result,
                    "is_vulnerable": final_decision.get('is_vulnerable', False)
                }
                final_results_log.append(log_entry)

                if final_decision['is_vulnerable']:
                    found_vulnerabilities += 1
                    print(f"⚠️  [VULNERABLE] Confirmed at: {attack['target_param']}")
                    if llm_result:
                        print(f"🤖 AI Confidence: {llm_result.get('confidence')} | Label: {llm_result.get('ml_label')}")
                    print("-" * 30)

            total_vulnerabilities += found_vulnerabilities
            print(f"\n✅ Endpoint {endpoint_idx+1} Complete. Found {found_vulnerabilities} vulnerabilities.")
            print("-" * 60)
        
        # --- [Final Step] Save all results to JSON ---
        output_file = "core/scan_results.json"
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(final_results_log, f, indent=4, ensure_ascii=False)

        print(f"\n{'='*60}")
        print(f"🏁 ALL SCANS COMPLETE!")
        print(f"📊 Total Endpoints Tested: {len(endpoints)}")
        print(f"🐛 Total Vulnerabilities Found: {total_vulnerabilities}")
        print(f"📂 Results saved to: {output_file}")
        print(f"{'='*60}")

    except Exception as e:
        print(f"💥 Critical Crash: {str(e)}")


if __name__ == "__main__":
    verify_core_integration()