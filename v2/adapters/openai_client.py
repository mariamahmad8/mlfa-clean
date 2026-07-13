import os
import json
from openai import OpenAI

from models.ClassificationResult import ClassificationResult


_client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))


def classify_email(prompt: str) -> ClassificationResult:
    """Send a prompt to GPT and parse the response into a ClassificationResult."""
    try:
        response = _client.chat.completions.create(
            model="gpt-5.4",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
        )

        raw = (response.choices[0].message.content or "").strip()

        if raw.startswith("```json"):
            raw = raw[len("```json"):].strip()
        if raw.endswith("```"):
            raw = raw[:-3].strip()

        parsed = _safe_json_parse(raw)

        return ClassificationResult(
            categories=parsed.get("categories", []),
            recipients=parsed.get("all_recipients", []),
            needs_personal_reply=parsed.get("needs_personal_reply", False),
            escalation_reason=parsed.get("escalation_reason", ""),
            name_sender=parsed.get("name_sender"),
            amount_money_detected=parsed.get("amount_detected"),
        )

    except Exception as e:
        print(f"Classification error: {e}")
        return ClassificationResult(
            categories=[],
            recipients=[],
            needs_personal_reply=False,
            escalation_reason="",
            name_sender=None,
            amount_money_detected=None,
        )

#to be safe incase GPT returns a message like "Sure!"
def _safe_json_parse(raw: str) -> dict:
    """Try strict JSON parse, fall back to extracting the JSON object from within text."""
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            return parsed
        if isinstance(parsed, list) and parsed and isinstance(parsed[0], dict):
            return parsed[0]
    except Exception:
        pass

    try:
        start = raw.find("{")
        end = raw.rfind("}")
        if start != -1 and end != -1 and end > start:
            return json.loads(raw[start:end + 1])
    except Exception:
        pass

    return {}
