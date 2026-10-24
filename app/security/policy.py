from typing import List, Literal
from app.schemas import SecurityDecision


def choose_action(score: int, signals: List[str]) -> Literal["allow", "review", "block"]:
    """Applies independent, conservative policy thresholds based on risk score and rule signals.
    
    Rules:
    - If possible data exfiltration signal detected -> "block"
    - If score >= 70 -> "block"
    - If score >= 35 or any rule signals -> "review"
    - Otherwise -> "allow"
    """
    if "possible_data_exfiltration" in signals:
        return "block"
    if score >= 70:
        return "block"
    if score >= 35 or bool(signals):
        return "review"
    return "allow"


def build_security_decision(
    score: int,
    signals: List[str],
    category: str,
    reasons: List[str],
    model_used: str,
) -> SecurityDecision:
    """Builds and validates a final SecurityDecision instance."""
    action = choose_action(score, signals)
    
    # Consolidate signals into reasons list if not already present
    all_reasons = list(reasons)
    for sig in signals:
        formatted_sig = f"Rule trigger: {sig.replace('_', ' ')}"
        if formatted_sig not in all_reasons:
            all_reasons.append(formatted_sig)
            
    return SecurityDecision(
        risk_score=score,
        category=category,
        action=action,
        reasons=all_reasons,
        model_used=model_used,
    )
