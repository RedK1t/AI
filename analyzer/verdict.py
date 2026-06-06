# analyzer/verdict.py

# Reasons that are strong, low-false-positive evidence of a real vulnerability.
# If any of these is present, we confirm on rules alone (the LLM only corroborates).
STRONG_REASON_KEYS = (
    "error_pattern_matched",            # SQL error surfaced in the response
    "authentication_bypass_detected",   # login succeeded after injection
    "time_delay",                       # time-based blind SQLi
    "payload_reflected_in_response",    # reflected XSS (payload echoed live)
    "payload_reflected_decoded",        # reflected XSS (decoded form echoed)
)


def _has_strong_reason(reasons):
    for r in reasons:
        rs = str(r)
        if any(key in rs for key in STRONG_REASON_KEYS):
            return True
        # status code escalating to a 5xx is also strong (e.g. 200 -> 500)
        if rs.startswith("status_changed_") and "_to_5" in rs:
            return True
    return False


def decide_verdict(rule_result, llm_result=None, thresholds=None):
    """
    Combine rule analysis with the LLM verdict.

    - STRONG rule evidence (a high-signal reason, or score >= strong) -> confirm.
      The LLM only corroborates; a confident LLM "no" can still veto.
    - MEDIUM evidence (weak signals summing to >= medium, no strong reason) -> confirm
      ONLY if the LLM agrees. This is what filters out length/hash/marker noise.
    - WEAK evidence (score < medium) -> not vulnerable.
    """
    if thresholds is None:
        thresholds = {"strong": 3.0, "medium": 2.0}

    score = rule_result.get("score", 0)
    reasons = rule_result.get("reasons", [])

    llm_verdict = (llm_result or {}).get("verdict")
    llm_yes = llm_verdict == "yes"
    llm_no = llm_verdict == "no"
    llm_conf = (llm_result or {}).get("confidence", 0)

    final = {
        "is_vulnerable": False,
        "why": [],
        "confidence": 0.0,
        "llm_used": llm_verdict in ("yes", "no"),
        "llm": llm_result,
    }

    strong = _has_strong_reason(reasons) or score >= thresholds["strong"]

    if strong:
        # Strong evidence. Honour only a confident LLM "no" as a veto.
        if llm_no and llm_conf >= 0.7:
            final["why"] = reasons + ["llm_rejected"]
            final["confidence"] = 0.2
            return final
        final["is_vulnerable"] = True
        final["why"] = reasons + (["llm_confirmed"] if llm_yes else [])
        final["confidence"] = llm_conf if llm_yes else min(0.95, 0.5 + 0.12 * score)
        return final

    if score >= thresholds["medium"]:
        # Medium evidence from weak signals needs LLM agreement to be reported.
        if llm_yes:
            final["is_vulnerable"] = True
            final["why"] = reasons + ["llm_confirmed"]
            final["confidence"] = llm_conf or 0.6
        else:
            final["confidence"] = max(0.1, 0.2 * score)
        return final

    # Weak evidence -> not vulnerable
    final["confidence"] = max(0.05, 0.1 * score)
    return final
