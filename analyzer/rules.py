# analyzer/rules.py
import re
import hashlib
import difflib
import re
import hashlib




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

    # 3) Length diff
    lr = length_diff_ratio(baseline.get("length", 0), response.get("length", 0))
    if lr >= thresholds["length_ratio"]:
        reasons.append(f"length_diff_ratio_{lr:.2f}")
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

    # 6) Snippet diff (for LLM)
    snippet = snippet_diff(baseline.get("body",""), response.get("body",""))

    result = {
        "score": score,
        "reasons": reasons,
        "length_ratio": lr,
        "snippet": snippet,
        "hint": hint
    }
    return result
