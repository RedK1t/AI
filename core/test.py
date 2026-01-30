import logging
import json
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
    target_url = "http://testphp.vulnweb.com/listproducts.php?artist=1"

    # قائمة لتخزين النتائج النهائية لتصديرها كـ JSON
    final_results_log = []

    try:
        # [Step 1] Parser
        parsed_data = parse_endpoint(target_url)
        if not parsed_data: return
        print(f"✅ Parser OK: Target {target_url}")

        # [Step 2] Baseline
        builder = RequestBuilder()
        baseline = builder.get_baseline(parsed_data)

        if baseline['success']:
            print(f"✅ Baseline Captured (Length: {baseline['length']})")

            # [Step 3] Mutator
            print("\n[Step 3] Generating Attack Plan...")
            mutator = Mutator(max_per_param=3)
            attack_plan = mutator.create_attack_plan([parsed_data])
            print(f"📦 Created {len(attack_plan)} mutations to test.")

            # [Step 4] Execution & AI Analysis
            print("\n[Step 4] Launching Attacks...")
            scan_client = HttpClient()
            llm = LLMAnalyzer()
            found_vulnerabilities = 0
            import time  # تأكد من وجود هذا السطر في أعلى الملف

            for attack in attack_plan:
                response = scan_client.send(
                    url=attack['target_url'],
                    method=attack['method'],
                    params=attack['params_to_send'],
                    data=attack.get('json_to_send')
                )

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

            # --- [Step 5] حفظ النتائج في ملف JSON ---
            output_file = "scan_results.json"
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(final_results_log, f, indent=4, ensure_ascii=False)

            print(f"\n🏁 Scan Finished. Found {found_vulnerabilities} potential issues.")
            print(f"📂 All results (including safe ones) saved to: {output_file}")

        else:
            print(f"❌ Baseline Error: {baseline.get('error')}")

    except Exception as e:
        print(f"💥 Critical Crash: {str(e)}")


if __name__ == "__main__":
    verify_core_integration()