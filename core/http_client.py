import requests
import urllib3
import time
from core.config import get_config # ربطه بالإعدادات كما في Scanner

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
config = get_config()

def build_response_object(resp, elapsed):
    body = resp.text if resp else ""
    return {
        "status_code": resp.status_code if resp else None,
        "headers": dict(resp.headers) if resp else {},
        "body": body,
        "length": len(body),
        "response_time": elapsed
    }


class HttpClient:
    def __init__(self):
        self.session = requests.Session()
        # نأخذ التايم أوت من الإعدادات المركزية التي يستخدمها الـ Scanner
        self.timeout = getattr(config, 'TIMEOUT', 10)

    def send(self, url, method="GET", params=None, data=None, headers=None):
        """
        هذه الدالة هي التي ستستدعيها كل وحدات الحقن (SQLi, XSS)
        التي يوزعها الـ Scanner.
        """
        try:
            start = time.time()
            resp = self.session.request(
                method=method,
                url=url,
                params=params,
                data=data,
                headers=headers,
                timeout=self.timeout,
                verify=False
            )
            elapsed = time.time() - start
            return build_response_object(resp, elapsed)
        except (requests.exceptions.RequestException,Exception) as e:
            return {
                "status_code": 0,  # بدل None عشان الحسابات
                "headers": {},
                "body": "",
                "length": 0,
                "response_time": 0.0
            }