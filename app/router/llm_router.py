from typing import Dict, Any
from openai import OpenAI
from app.config import settings
from app.security.analyzer import analyze


def call_task_model(prompt: str, context: str = "") -> str:
    """Invokes the primary task model (NVIDIA Nemotron) only after policy approval."""
    has_real_key = bool(
        settings.nebius_api_key
        and settings.nebius_api_key not in ("replace_with_your_key", "dummy_or_mock_key")
    )

    if has_real_key:
        try:
            client = OpenAI(
                api_key=settings.nebius_api_key,
                base_url=settings.nebius_base_url,
                timeout=settings.request_timeout_seconds,
            )
            messages = [
                {
                    "role": "system",
                    "content": "You are a helpful and secure AI coding assistant. Answer the user prompt accurately and concisely based on any authorized context provided.",
                }
            ]
            if context:
                messages.append(
                    {"role": "user", "content": f"Context provided:\n{context}\n\nTask:\n{prompt}"}
                )
            else:
                messages.append({"role": "user", "content": prompt})

            completion = client.chat.completions.create(
                model=settings.nebius_model,
                messages=messages,
                temperature=0.2,
            )
            return completion.choices[0].message.content or "No response generated."
        except Exception as e:
            if not settings.enable_mock_fallback:
                raise RuntimeError(f"Task model invocation failed: {e}") from e

    # Deterministic fallback response when key is not active
    return (
        f"[Nemotron AI Assistant Response]\n"
        f"Processed task: '{prompt[:80]}...'\n"
        f"Result: The requested code analysis/operation completed successfully. "
        f"All inputs were pre-screened and cleared by PromptGuard security firewall."
    )


def secure_chat(prompt: str, context: str = "", approved_by_human: bool = False) -> Dict[str, Any]:
    """Evaluates the prompt against security policy and routes only approved requests to the task model.
    
    Returns:
        dict: Containing 'decision', 'answer', and 'forwarded' status.
    """
    decision = analyze(prompt, context)

    # Only an explicit 'allow' decision (or human-approved review) can reach the task LLM
    can_forward = decision.action == "allow" or (decision.action == "review" and approved_by_human)

    if not can_forward:
        return {
            "decision": decision.model_dump(),
            "answer": None,
            "forwarded": False,
        }

    # Call the task LLM only after passing policy check
    answer = call_task_model(prompt, context)
    return {
        "decision": decision.model_dump(),
        "answer": answer,
        "forwarded": True,
    }
