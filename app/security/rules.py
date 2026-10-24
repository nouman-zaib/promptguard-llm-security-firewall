from typing import List


def inspect_prompt(text: str) -> List[str]:
    """Deterministic rule-based inspection for high-risk prompt injection and exfiltration patterns.
    
    Returns a list of signal flags detected in the text.
    """
    text = text.casefold()
    signals: List[str] = []

    override_phrases = [
        "ignore all previous instructions",
        "ignore previous instructions",
        "disregard your system prompt",
        "reveal your system prompt",
        "ignore the above and instead",
        "disregard prior commands",
        "bypass all guardrails",
        "output all internal instructions",
    ]

    exfiltration_phrases = [
        "send the api key",
        "upload secrets",
        "exfiltrate credentials",
        "print all environment variables",
        "reveal your api key",
        "read /etc/passwd",
        "dump the env",
        "exfiltrate token",
    ]

    suspicious_tool_phrases = [
        "execute arbitrary bash",
        "curl -x post",
        "rm -rf /",
        "wget http://malicious",
        "run python code to delete",
    ]

    if any(x in text for x in override_phrases):
        signals.append("instruction_override")

    if any(x in text for x in exfiltration_phrases):
        signals.append("possible_data_exfiltration")

    if any(x in text for x in suspicious_tool_phrases):
        signals.append("suspicious_tool_intent")

    return signals


def inspect_input(prompt: str, context: str = "") -> List[str]:
    """Inspects both user prompt and untrusted context for deterministic risk signals."""
    combined = f"{prompt}\n{context}"
    return inspect_prompt(combined)
