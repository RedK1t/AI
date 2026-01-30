import json
import os
import urllib.parse
import uuid
from copy import deepcopy
from datetime import datetime

class Mutator:
    def __init__(self, payload_filename="sql_payloads.json", max_per_param=None):
        self.current_dir = os.path.dirname(os.path.abspath(__file__))
        self.payload_file = os.path.join(self.current_dir, payload_filename)
        self.payloads = self._load_payloads()
        self.encodings = ["raw", "url", "url_plus"]   # url_plus => quote_plus
        self.inject_modes = ["append", "prefix", "replace"]  # common modes
        self.max_per_param = max_per_param  # None => use all

    def _load_payloads(self):
        try:
            if os.path.exists(self.payload_file):
                with open(self.payload_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            else:
                print(f"[!] Warning: Payload file NOT found at: {self.payload_file}")
                return {}
        except Exception as e:
            print(f"[-] Error loading payloads: {e}")
            return {}

    def _apply_encoding(self, payload, encoding_type="url"):
        if encoding_type == "url":
            return urllib.parse.quote(payload, safe='')
        if encoding_type == "url_plus":
            return urllib.parse.quote_plus(payload)
        return payload

    def _get_hint(self, category):
        hints = {
            "boolean": "check_content_change",
            "error": "look_for_sql_errors",
            "time": "measure_response_time"
        }
        return hints.get(category, "generic")

    def _should_use_payload_for_type(self, param_type, category):
        # بسيط: لو int و category string-only فلا
        if param_type == "int" and category in ("boolean", "time", "error"):
            return True
        return True

    def _inject_payload(self, original_params, target_param, payload, mode="append"):
        new_params = {}
        for k, v in original_params.items():
            original_val = v['value'] if isinstance(v, dict) else v
            if k == target_param:
                if mode == "replace":
                    new_params[k] = payload
                elif mode == "prefix":
                    new_params[k] = f"{payload}{original_val}"
                else:  # append
                    new_params[k] = f"{original_val}{payload}"
            else:
                new_params[k] = original_val
        return new_params

    def _inject_json_body(self, body_obj, target_path, payload, mode="append"):
        """
        إذا كان body JSON و target_param يشير لمسار داخل JSON مثل "user.name"
        هذا يلزمك تعديل بسيط لتعريف مكان الحقن.
        """
        obj = deepcopy(body_obj)
        parts = target_path.split('.')
        cur = obj
        for p in parts[:-1]:
            cur = cur.get(p, {})
        key = parts[-1]
        orig = cur.get(key)
        if orig is None:
            cur[key] = payload
        else:
            if mode == "replace":
                cur[key] = payload
            elif mode == "prefix":
                cur[key] = f"{payload}{orig}"
            else:
                cur[key] = f"{orig}{payload}"
        return obj

    def create_attack_plan(self, parsed_endpoints_list):
        attack_plan = []
        if not isinstance(parsed_endpoints_list, list):
            parsed_endpoints_list = [parsed_endpoints_list]

        for endpoint in parsed_endpoints_list:
            # بدلاً من السطر القديم، استخدم ده لضمان وجود قيمة دايماً
            url = endpoint.get('url') or endpoint.get('full_url') or "http://unknown-url"
            method = endpoint.get('method', 'GET').upper()
            params = endpoint.get('params', {})

            if not params:
                continue

            for param_name, param_info in params.items():
                param_type = param_info.get('type', 'string') if isinstance(param_info, dict) else 'string'

                # sampling limit: لو ملف payload ضخم، قلل
                for category, payload_list in self.payloads.items():
                    if not self._should_use_payload_for_type(param_type, category):
                        continue

                    # apply optional limit per param (random sample for speed)
                    payloads_to_use = payload_list
                    if self.max_per_param and len(payload_list) > self.max_per_param:
                        import random
                        payloads_to_use = random.sample(payload_list, self.max_per_param)

                    for payload in payloads_to_use:
                        for enc in self.encodings:
                            final_payload = self._apply_encoding(payload, enc)
                            for mode in self.inject_modes:
                                mutation = {
                                    "id": str(uuid.uuid4()),
                                    "timestamp": datetime.utcnow().isoformat(),
                                    "target_url": url,
                                    "method": method,
                                    "target_param": param_name,
                                    "param_type": param_type,
                                    "category": category,
                                    "payload": final_payload,
                                    "raw_payload": payload,
                                    "encoding": enc,
                                    "inject_mode": mode,
                                    "params_to_send": self._inject_payload(params, param_name, final_payload, mode=mode),
                                    "analyzer_hint": self._get_hint(category)
                                }
                                attack_plan.append(mutation)
        return attack_plan
