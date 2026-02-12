import os
import random
import requests
import re
import urllib3
from urllib.parse import urlparse, parse_qs, urljoin

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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


def _extract_forms_from_html(html_content, base_url):
    """Extract forms from HTML content using regex and return list of form data"""
    forms = []
    try:
        # Find all form tags - support both <form>...</form> and self-closing
        form_pattern = r'<form\b([^>]*)>(.*?)</form>'
        form_matches = re.findall(form_pattern, html_content, re.DOTALL | re.IGNORECASE)
        
        for form_attrs, form_content in form_matches:
            # Get form method (default to GET) - supports ANY method
            method_match = re.search(r'method=["\']?([^"\'\s>]+)["\']?', form_attrs, re.IGNORECASE)
            method = method_match.group(1).upper() if method_match else 'GET'
            
            # Get form action
            action_match = re.search(r'action=["\']?([^"\'\s>]*|[^"\']+)["\']?', form_attrs, re.IGNORECASE)
            action = action_match.group(1) if action_match else ''
            form_url = urljoin(base_url, action)
            
            # Extract all input fields from form content
            inputs = {}
            
            # Match input tags - handle various attribute orders
            input_pattern = r'<input\b([^>]*?)>'
            for input_attrs in re.findall(input_pattern, form_content, re.IGNORECASE):
                name_match = re.search(r'name=["\']?([^"\'\s>]+)["\']?', input_attrs, re.IGNORECASE)
                if name_match:
                    name = name_match.group(1)
                    value_match = re.search(r'value=["\']?([^"\']*?)["\']?(?:\s|$|>)', input_attrs, re.IGNORECASE)
                    value = value_match.group(1) if value_match else ''
                    inputs[name] = {
                        "value": value,
                        "type": detect_type(value)
                    }
            
            # Match textarea tags
            textarea_pattern = r'<textarea\b([^>]*?)>(.*?)</textarea>'
            for textarea_attrs, textarea_content in re.findall(textarea_pattern, form_content, re.DOTALL | re.IGNORECASE):
                name_match = re.search(r'name=["\']?([^"\'\s>]+)["\']?', textarea_attrs, re.IGNORECASE)
                if name_match:
                    name = name_match.group(1)
                    inputs[name] = {
                        "value": textarea_content.strip(),
                        "type": detect_type(textarea_content)
                    }
            
            # Match select tags
            select_pattern = r'<select\b([^>]*?)>(.*?)</select>'
            for select_attrs, select_content in re.findall(select_pattern, form_content, re.DOTALL | re.IGNORECASE):
                name_match = re.search(r'name=["\']?([^"\'\s>]+)["\']?', select_attrs, re.IGNORECASE)
                if name_match:
                    name = name_match.group(1)
                    # Get first selected option or first option
                    option_match = re.search(r'<option[^>]*selected[^>]*value=["\']?([^"\'\s>]*)["\']?', select_content, re.IGNORECASE)
                    if not option_match:
                        option_match = re.search(r'<option[^>]*value=["\']?([^"\'\s>]*)["\']?', select_content, re.IGNORECASE)
                    value = option_match.group(1) if option_match else ''
                    inputs[name] = {
                        "value": value,
                        "type": detect_type(value)
                    }
            
            if inputs:  # Only add forms with input fields
                forms.append({
                    "method": method,
                    "url": form_url,
                    "params": inputs,
                    "headers": get_random_headers()
                })
                print(f"    [DEBUG] Added form with method={method}, url={form_url}, fields={list(inputs.keys())}")
    except Exception as e:
        print(f"[-] Error parsing forms: {e}")
        import traceback
        traceback.print_exc()
    
    return forms


def parse_endpoint(url, fetch_forms=True):
    """
Main function: receives the link and returns a data structure ready for checking
Optionally fetches the page to discover forms
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

    results = []

    # 5. بناء النتيجة الأولى للـ URL (The Blueprint)
    url_result = {
        "method": "GET",
        "url": f"{parsed.scheme}://{parsed.netloc}{parsed.path}",  # ⭐ المهم
        "full_url": url,
        "params": structured_params,
        "headers": get_random_headers()
    }

    print(f"[+] Successfully Parsed URL: {parsed.path}")
    print(f"    └── Found {len(structured_params)} parameters: {list(structured_params.keys())}")
    
    # Add URL params result if there are query parameters
    if structured_params:
        results.append(url_result)

    # 6. Fetch page and extract forms if requested
    if fetch_forms:
        try:
            headers = get_random_headers()
            print(f"[*] Fetching page to discover forms: {url}")
            response = requests.get(url, headers=headers, timeout=10, verify=False)
            print(f"[*] Page fetched successfully (Status: {response.status_code})")
            if response.status_code == 200:
                # Debug: Check if HTML contains form tags
                form_count = len(re.findall(r'<form', response.text, re.IGNORECASE))
                print(f"[*] Found {form_count} form tag(s) in HTML")
                forms = _extract_forms_from_html(response.text, url)
                print(f"[*] Extracted {len(forms)} form(s) with input fields")
                for i, form in enumerate(forms):
                    print(f"[+] Form #{i+1}: {form['method']} {form['url']}")
                    print(f"    └── Fields: {list(form['params'].keys())}")
                    results.append(form)
        except Exception as e:
            print(f"[-] Error fetching forms from {url}: {e}")
            import traceback
            traceback.print_exc()

    # Return single result if only one, else return list
    if len(results) == 1:
        return results[0]
    elif len(results) > 1:
        return results
    else:
        return url_result if structured_params else None


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