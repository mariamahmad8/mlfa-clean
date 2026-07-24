import os
import json
from openai import OpenAI

from models.ClassificationResult import ClassificationResult
from security_logging import log_event


def _get_client() -> OpenAI:
    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY is required for classification.")
    return OpenAI(api_key=api_key, timeout=30.0, max_retries=2)


def classify_email(system_prompt: str, email_prompt: str) -> ClassificationResult:
    """Send a prompt to GPT and parse the response into a ClassificationResult."""
    try:
        response = _get_client().chat.completions.create(
            model="gpt-5.4",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": email_prompt},
            ],
            temperature=0.2,
            response_format={"type": "json_object"},
            store=False,
        )

        raw = (response.choices[0].message.content or "").strip()

        if raw.startswith("```json"):
            raw = raw[len("```json"):].strip()
        if raw.endswith("```"):
            raw = raw[:-3].strip()

        parsed = _safe_json_parse(raw)

        return _validated_result(parsed)

    except Exception as e:
        log_event("classifier.request_failed", level="ERROR", error=e)
        return ClassificationResult(
            categories=[],
            recipients=[],
            needs_personal_reply=False,
            escalation_reason="",
            name_sender=None,
            amount_money_detected=None,
            reason={},
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


def _validated_result(parsed: dict) -> ClassificationResult:
    """Constrain model output to the primitive types the router expects."""
    raw_categories = parsed.get("categories", [])
    categories = []
    if isinstance(raw_categories, list):
        for category in raw_categories[:20]:
            if isinstance(category, str) and category.strip():
                categories.append(category.strip())

    raw_recipients = parsed.get("all_recipients", [])
    recipients = []
    if isinstance(raw_recipients, list):
        for recipient in raw_recipients[:50]:
            if isinstance(recipient, str) and len(recipient) <= 320:
                recipients.append(recipient.strip())

    amount = parsed.get("amount_detected")
    if not isinstance(amount, (int, float)) or isinstance(amount, bool) or amount < 0:
        amount = None

    sender_name = parsed.get("name_sender")
    if not isinstance(sender_name, str) or not sender_name.strip():
        sender_name = None
    elif len(sender_name) > 200:
        sender_name = sender_name[:200]

    escalation = parsed.get("escalation_reason", "")
    if not isinstance(escalation, str):
        escalation = ""

    # Per-category justification dict from GPT: {"donor": "mentions $500 donation", ...}
    raw_reason = parsed.get("reason", {})
    reason = {}
    if isinstance(raw_reason, dict):
        for key, value in list(raw_reason.items())[:20]:
            if isinstance(key, str) and isinstance(value, str) and value.strip():
                reason[key.strip()] = value.strip()[:500]

    return ClassificationResult(
        categories=categories,
        recipients=recipients,
        needs_personal_reply=parsed.get("needs_personal_reply") is True,
        escalation_reason=escalation[:2000],
        name_sender=sender_name,
        amount_money_detected=amount,
        reason=reason,
    )
