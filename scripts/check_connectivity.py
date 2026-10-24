import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from openai import OpenAI
from app.config import settings

print("PromptGuard Nebius Token Factory Connectivity Verification")
print("-" * 55)
print(f"Base URL: {settings.nebius_base_url}")
print(f"Model ID: {settings.nebius_model}")
print(f"API Key:  {'[CONFIGURED]' if settings.nebius_api_key and settings.nebius_api_key != 'replace_with_your_key' else '[NOT SET / PLACEHOLDER]'}")
print("-" * 55)

if not settings.nebius_api_key or settings.nebius_api_key in ("replace_with_your_key", "dummy_or_mock_key"):
    print("Warning: Please set a valid NEBIUS_API_KEY in your .env file to make real cloud inference calls.")
    sys.exit(0)

try:
    client = OpenAI(
        api_key=settings.nebius_api_key,
        base_url=settings.nebius_base_url,
        timeout=settings.request_timeout_seconds,
    )
    result = client.chat.completions.create(
        model=settings.nebius_model,
        messages=[{"role": "user", "content": "Reply with the word READY."}],
        temperature=0,
    )
    content = result.choices[0].message.content
    print(f"Server Response: {content}")
    print("SUCCESS: Connected to Nebius Token Factory and received inference output.")
except Exception as e:
    print(f"ERROR: Connectivity check failed: {e}")
    sys.exit(1)
