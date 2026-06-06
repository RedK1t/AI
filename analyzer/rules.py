# analyzer/rules.py
import re
import hashlib
import difflib
import urllib.parse




DYNAMIC_PATTERNS = [
    r"\d{2}:\d{2}:\d{2}",        # time
    r"\d{4}-\d{2}-\d{2}",        # date
    r"csrf_token=[a-zA-Z0-9]+",
    r"token\":\"[a-zA-Z0-9\-_]+\"",
    r"[0-9a-f]{32}",             # md5-like
]

def normalize_body(body: str) -> str:
    if not body:
        return ""
    clean = body
    for pattern in DYNAMIC_PATTERNS:
        clean = re.sub(pattern, "", clean, flags=re.IGNORECASE)
    return clean


ERROR_PATTERNS = [
    r"sql syntax", r"mysql_fetch", r"ORA-\d+", r"SQLSTATE", r"syntax error",
    r"unclosed quotation mark", r"you have an error in your sql syntax",
    r"warning: mysql", r"pg_query\(", r"supplied argument is not a valid"
]
ERROR_RE = re.compile("|".join(ERROR_PATTERNS), re.IGNORECASE)

# Authentication bypass indicators (for login forms)
AUTH_SUCCESS_INDICATORS = [
    'welcome', 'hello', 'logout', 'dashboard', 'account', 'profile',
    'admin', 'administrator', 'member', 'logged in', 'sign out',
    'my account', 'user profile', 'control panel', 'cpanel'
]
AUTH_FAIL_INDICATORS = [
    'invalid', 'incorrect', 'failed', 'error', 'wrong', 'denied',
    'authentication failed', 'login failed', 'not found'
]

def _md5(text):
    return hashlib.md5(text.encode('utf-8', errors='ignore')).hexdigest()

def length_diff_ratio(baseline_len, new_len):
    if baseline_len == 0:
        return 1.0 if new_len > 0 else 0.0
    return abs(new_len - baseline_len) / float(max(baseline_len, 1))

def snippet_diff(baseline_body, new_body, max_lines=5):
    # return small human-friendly diff snippets
    base_lines = baseline_body.splitlines()
    new_lines = new_body.splitlines()
    diff = list(difflib.unified_diff(base_lines[:200], new_lines[:200], n=1))
    # limit the size
    return "\n".join(diff[:max_lines])

def analyze_with_rules(baseline, response, hint=None, thresholds=None):
    """
    baseline and response are dicts with keys:
      - status_code, length, response_time, body, hash (optional)
    hint: string hint from mutator like 'time' / 'error' / 'check_content_change'
    returns: dict with flags, score, reasons, snippets
    """
    if thresholds is None:
        thresholds = {"length_ratio": 0.20, "time_delta": 4.0}

    score = 0
    reasons = []

    # 1) Error regex
    if response.get("body") and ERROR_RE.search(response["body"]):
        reasons.append("error_pattern_matched")
        score += 2

    # 2) Status code change (e.g., 200 -> 500)
    if baseline.get("status_code") is not None and response.get("status_code") is not None:
        if baseline["status_code"] != response["status_code"] and response["status_code"] >= 500:
            reasons.append(f"status_changed_{baseline['status_code']}_to_{response['status_code']}")
            score += 2

    # 3) Length diff - also detect when response is SHORTER (login success often redirects)
    lr = length_diff_ratio(baseline.get("length", 0), response.get("length", 0))
    if lr >= thresholds["length_ratio"]:
        reasons.append(f"length_diff_ratio_{lr:.2f}")
        score += 1
    
    # 3b) Large absolute length change (for auth bypass detection)
    abs_diff = abs(baseline.get("length", 0) - response.get("length", 0))
    if abs_diff > 1000:  # Significant content change
        reasons.append(f"large_content_change_{abs_diff}_bytes")
        score += 1

    # 4) Time-based
    if baseline.get("response_time") is not None and response.get("response_time") is not None:
        if response["response_time"] >= baseline["response_time"] + thresholds["time_delta"]:
            reasons.append(f"time_delay_{response['response_time']:.2f}s_vs_{baseline['response_time']:.2f}s")
            score += 2

    # 5) Hash difference
    baseline_clean = normalize_body(baseline.get("body", ""))
    response_clean = normalize_body(response.get("body", ""))

    baseline_hash = _md5(baseline_clean[:10000])
    new_hash = _md5(response_clean[:10000])

    if baseline_hash != new_hash:
        reasons.append("normalized_hash_changed")
        score += 0.5  # مهم جدًا: مؤشر ضعيف فقط

    # 6) Authentication Bypass Detection (for login forms)
    baseline_body_lower = baseline.get("body", "").lower()
    response_body_lower = response.get("body", "").lower()
    
    # Check for auth success indicators appearing after injection
    baseline_success = any(ind in baseline_body_lower for ind in AUTH_SUCCESS_INDICATORS)
    response_success = any(ind in response_body_lower for ind in AUTH_SUCCESS_INDICATORS)
    
    if not baseline_success and response_success:
        # Auth bypass successful - we weren't logged in before but now we are
        reasons.append("authentication_bypass_detected")
        score += 3  # High score for auth bypass
    
    # Check for auth failure indicators disappearing
    baseline_fail = any(ind in baseline_body_lower for ind in AUTH_FAIL_INDICATORS)
    response_fail = any(ind in response_body_lower for ind in AUTH_FAIL_INDICATORS)
    
    if baseline_fail and not response_fail:
        # Error message disappeared - possible bypass
        reasons.append("login_error_disappeared")
        score += 2

    # 7) Snippet diff (for LLM)
    snippet = snippet_diff(baseline.get("body",""), response.get("body",""))

    result = {
        "score": score,
        "reasons": reasons,
        "length_ratio": lr,
        "snippet": snippet,
        "hint": hint
    }
    return result


XSS_REFLECTION_MARKERS = [
    "<script>", "</script>", "onerror=", "onload=", "onfocus=",
    "onmouseover=", "onclick=", "onkeypress=", "onchange=",
    "javascript:", "prompt(", "confirm(", "alert(",
    "<img ", "<svg ", "<body ", "<input ", "<details ",
]

def analyze_with_rules_xss(baseline, response, payload_used, hint=None, thresholds=None):
    """
    XSS-specific rule analysis:
    1. Payload reflection in response (primary)
    2. HTML/JS injection markers
    3. Status code change
    4. Length/content change
    """
    if thresholds is None:
        thresholds = {"length_ratio": 0.15, "reflection_required": True}

    score = 0
    reasons = []

    response_body = response.get("body", "") if response else ""
    payload_str = str(payload_used) if payload_used else ""

    # 1) Payload reflection check — the PRIMARY (and required) reflected-XSS indicator.
    # Reflected XSS only exists if our injected payload appears, unescaped, in the response.
    # A distinctive fragment of the payload (e.g. confirm('xss') / the <script> we sent) must
    # be present; otherwise pre-existing page markers must NOT count (testfire etc. ship
    # <script> tags of their own, which previously caused false positives).
    reflected = False
    if response_body and payload_str:
        if payload_str in response_body:
            reasons.append("payload_reflected_in_response")
            score += 3
            reflected = True
        decoded_payload = urllib.parse.unquote(payload_str)
        if decoded_payload != payload_str and decoded_payload in response_body:
            reasons.append("payload_reflected_decoded")
            if not reflected:
                score += 3
            reflected = True

    # 2) Injection markers — only meaningful when OUR payload actually reflected.
    # Confirms the reflection landed as live HTML/JS rather than HTML-encoded text.
    if reflected and response_body:
        body_lower = response_body.lower()
        found_markers = [m for m in XSS_REFLECTION_MARKERS if m in body_lower]
        if found_markers:
            reasons.append(f"xss_markers_detected:{','.join(found_markers[:3])}")
            score += 1

    # NOTE: status/length/hash differences are recorded for context but do NOT add score
    # for XSS — they are noise without reflection and were a major false-positive source.
    if baseline and baseline.get("status_code") is not None and response.get("status_code") is not None:
        if baseline["status_code"] != response["status_code"]:
            reasons.append(f"status_changed_{baseline['status_code']}_to_{response['status_code']}")

    lr = length_diff_ratio(baseline.get("length", 0) if baseline else 0, response.get("length", 0))
    if lr >= thresholds["length_ratio"]:
        reasons.append(f"length_diff_ratio_{lr:.2f}")

    snippet = snippet_diff(
        baseline.get("body", "") if baseline else "",
        response.get("body", "") if response else ""
    )

    result = {
        "score": score,
        "reasons": reasons,
        "length_ratio": lr,
        "snippet": snippet,
        "hint": hint
    }
    return result
