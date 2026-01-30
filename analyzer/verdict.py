# analyzer/verdict.py

def decide_verdict(rule_result, llm_result=None, thresholds=None):
    """
    rule_result: output from analyze_with_rules
    llm_result: dict from LLM analyzer like {'verdict': 'yes'/'no', 'explanation':..., 'confidence': 0.8}
    returns final dict
    """
    if thresholds is None:
        thresholds = {"rule_confirm": 2}  # score >=2 means confirm

    final = {
        "is_vulnerable": False,
        "why": [],
        "confidence": 0.0,
        "llm_used": False,
        "llm": llm_result
    }

    score = rule_result.get("score", 0)

    if score >= thresholds["rule_confirm"]:
        final["is_vulnerable"] = True
        final["why"].extend(rule_result.get("reasons", []))
        final["confidence"] = min(0.9, 0.4 + 0.3 * score)  # heuristic
        return final

    # weak signal -> consult LLM if provided
    if llm_result:
        final["llm_used"] = True
        if llm_result.get("verdict") == "yes":
            final["is_vulnerable"] = True
            final["why"].extend(rule_result.get("reasons", []))
            final["why"].append("llm_confirmed")
            final["confidence"] = llm_result.get("confidence", 0.6)
        else:
            final["confidence"] = max(0.1, 0.3 * score)
    else:
        final["confidence"] = max(0.05, 0.2 * score)

    return final
