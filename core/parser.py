import os
import random
from urllib.parse import urlparse, parse_qs

# ==========================================

# ==========================================

IGNORED_EXTENSIONS = (
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg',
    '.css', '.js', '.ico', '.pdf', '.woff', '.woff2',
    '.mp3', '.mp4'
)

# ==========================================
#A simple list of different browsers to deceive the server
# ==========================================

## --->  Thats "not enough" user_agenst BUT ITS JUST FOR NOW!##
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36"
]


def get_random_headers():
    """Generate random headers for each request"""
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Connection": "keep-alive",
        #the idea from  X-Forwarded-For "IP Spoofing"
        "X-Forwarded-For": f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
    }


def detect_type(value):
    """(AI Feature) Define the data type to help the model later """
    try:
        int(value)
        return "int"
    except ValueError:
        try:
            float(value)
            return "float"
        except ValueError:
            if str(value).lower() in ['true', 'false']:
                return "boolean"
            return "string"


def parse_endpoint(url):
    """
Main function: receives the link and returns a data structure ready for checking
    """
    # 1. التحقق من صحة الرابط (Sanity Check)
    if not url or url.lower().endswith(IGNORED_EXTENSIONS):
        print(f"[-] Skipping static file: {url}")
        return None

    # 2.Parses the url
    parsed = urlparse(url)

    # 3. (Query Params)
    query_params = parse_qs(parsed.query)

    # لو مفيش باراميترات، غالباً الصفحة دي مش هدف للـ SQLi (مبدئياً)
    if not query_params:
        print(f"[*] Note: No parameters found in {url}")

    # 4. إعادة هيكلة الباراميترات
    structured_params = {}
    for key, values in query_params.items():
        # parse_qs بترجع لستة ['1']، إحنا عايزين القيمة بس
        val = values[0]
        structured_params[key] = {
            "value": val,
            "type": detect_type(val)  # this is for AI
        }

    # 5. بناء النتيجة النهائية (The Blueprint)
    result = {
        "method": "GET",
        "url": f"{parsed.scheme}://{parsed.netloc}{parsed.path}",  # ⭐ المهم
        "full_url": url,
        "params": structured_params,
        "headers": get_random_headers()
    }

    print(f"[+] Successfully Parsed: {parsed.path}")
    print(f"    └── Found {len(structured_params)} parameters: {list(structured_params.keys())}")

    return result


# ==========================================
# Try the code (to make sure it's working)
# ==========================================
if __name__ == "__test__":
    test_url = "http://testphp.vulnweb.com/listproducts.php?cat=1&type=test"
    data = parse_endpoint(test_url)

    import json

    if data:
        print("\n--- Final Output Structure ---")
        print(json.dumps(data, indent=4))

#