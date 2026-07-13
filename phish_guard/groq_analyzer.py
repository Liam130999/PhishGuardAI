"""Groq-backed semantic analysis used by the Streamlit web UI (app.py).

Kept separate from app.py so the parsing / API logic is unit-testable without
importing Streamlit. Returns the strict two-key contract required by the UI:
``{"Risk_Score": int(1-100), "XAI_Explanation": str}``.
"""

from __future__ import annotations

import json
import re
from typing import Any, Optional

from groq import (
    APIConnectionError,
    APITimeoutError,
    AuthenticationError,
    Groq,
    GroqError,
    RateLimitError,
)

# Groq's fastest Llama-3.3 70B model balances speed and reasoning quality.
DEFAULT_MODEL = "llama-3.3-70b-versatile"

# Instructs the model to act as a security analyst judging INTENT (urgency, authority,
# manipulation) rather than matching keywords. Returns a strict two-key JSON contract.
SYSTEM_PROMPT = """You are Phish-Guard, an elite cybersecurity analyst specialised in
detecting phishing, Business Email Compromise (BEC) and social-engineering attacks.

Analyse the email for INTENT and manipulation, not just keywords:
- Urgency / fear (account suspension, deadlines, threats).
- Authority / impersonation (CEO, IT, bank; abuse of hierarchy).
- Contextual anomalies (wire/gift-card/credential requests, secrecy, look-alike
  domains, unexpected attachments, too-good-to-be-true offers).

Scoring (Risk_Score, integer 1-100):
  1-20 benign, 21-50 mildly suspicious, 51-75 likely phishing, 76-100 high-confidence attack.

Respond with ONLY a single valid JSON object and nothing else, using EXACTLY these two keys:
{
  "Risk_Score": <integer 1-100>,
  "XAI_Explanation": "<explain WHY this score was given: name the specific psychological
                       triggers and red flags, quoting short snippets from the email>"
}
"""


class GroqAnalysisError(RuntimeError):
    """Raised when Groq cannot be reached or its output cannot be parsed."""


def analyze_email(
    api_key: str,
    model: str,
    subject: str,
    body: str,
    client: Optional[Any] = None,
) -> dict:
    """Send one email to Groq and return the parsed two-key verdict.

    ``client`` may be injected for testing; otherwise a real Groq client is built.
    Raises GroqAnalysisError on any API or parsing failure.
    """
    client = client or Groq(api_key=api_key)
    user_prompt = (
        "Analyse the following email and return the JSON verdict.\n\n"
        f"Subject: {subject}\n"
        f"Body:\n{body}"
    )
    try:
        # Groq call: json_object mode + temperature=0 push the model toward a
        # single deterministic JSON object. GroqError is the base class for API
        # timeouts, connection errors and rate limits, so one except covers them.
        completion = client.chat.completions.create(
            model=model,
            temperature=0,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
        )
    except AuthenticationError as exc:
        # Wrong/expired key: the most common setup mistake, so name it clearly.
        raise GroqAnalysisError(
            "Invalid Groq API key. Check the key in the sidebar — get a free "
            "one at https://console.groq.com/keys."
        ) from exc
    except RateLimitError as exc:
        raise GroqAnalysisError(
            "Groq rate limit reached. Wait a few seconds and try again."
        ) from exc
    except (APIConnectionError, APITimeoutError) as exc:
        raise GroqAnalysisError(
            "Could not reach Groq (network error or timeout). Check your "
            "internet connection and try again."
        ) from exc
    except GroqError as exc:
        raise GroqAnalysisError(f"Groq API error: {exc}") from exc

    try:
        raw = completion.choices[0].message.content or ""
    except (AttributeError, IndexError) as exc:
        raise GroqAnalysisError(f"Unexpected Groq response shape: {completion!r}") from exc

    return parse_verdict(raw)


def parse_verdict(raw: str) -> dict:
    """Parse a model response into ``{"Risk_Score": int, "XAI_Explanation": str}``.

    Defensive: recovers JSON wrapped in prose, coerces a numeric-string score,
    clamps to 1-100, and validates that both keys are present.
    """
    data = None
    # Try the raw text first (json_object mode usually returns clean JSON), then
    # fall back to extracting the JSON object even if the model wrapped it in
    # ```json ... ``` fences or surrounded it with prose.
    for candidate in (_strip_code_fences(raw), _first_json_object(raw)):
        if not candidate:
            continue
        try:
            parsed = json.loads(candidate)
        except (json.JSONDecodeError, TypeError):
            continue
        if isinstance(parsed, dict):
            data = parsed
            break
    if data is None:
        raise GroqAnalysisError(f"Model did not return valid JSON: {raw!r}")

    try:
        score = int(round(float(data["Risk_Score"])))
    except (KeyError, TypeError, ValueError) as exc:
        raise GroqAnalysisError(f"Missing or invalid 'Risk_Score' in output: {raw!r}") from exc

    explanation = str(data.get("XAI_Explanation", "")).strip()
    if not explanation:
        raise GroqAnalysisError(f"Missing 'XAI_Explanation' in output: {raw!r}")

    score = max(1, min(100, score))
    return {"Risk_Score": score, "XAI_Explanation": explanation}


def _first_json_object(text: str) -> Optional[str]:
    match = re.search(r"\{.*\}", text, re.DOTALL)
    return match.group(0) if match else None


def _strip_code_fences(text: str) -> str:
    """Remove surrounding markdown code fences (```json ... ``` or ``` ... ```)."""
    stripped = text.strip()
    fence = re.match(r"^```[a-zA-Z0-9]*\s*(.*?)\s*```$", stripped, re.DOTALL)
    return fence.group(1).strip() if fence else stripped
