"""Privacy-safe application logging helpers.

Production logs must never contain email subjects, bodies, sender addresses,
message identifiers, tokens, or credentials. Callers provide only operational
metadata such as an inbox database ID or message count.
"""

import json
import os
from datetime import datetime, timezone
from typing import Any, Optional


_FORBIDDEN_FIELD_FRAGMENTS = {
    "body",
    "credential",
    "email",
    "message_id",
    "secret",
    "sender",
    "subject",
    "token",
}


def _is_production() -> bool:
    return bool(os.getenv("RAILWAY_ENVIRONMENT_NAME")) or (
        os.getenv("APP_ENV", "").strip().lower() == "production"
    )


def _safe_fields(fields: dict[str, Any]) -> dict[str, Any]:
    safe: dict[str, Any] = {}
    for key, value in fields.items():
        normalized_key = key.lower()
        if any(fragment in normalized_key for fragment in _FORBIDDEN_FIELD_FRAGMENTS):
            raise ValueError(f"Sensitive log field is not allowed: {key}")
        if value is None or isinstance(value, (str, int, float, bool)):
            safe[key] = value
        else:
            safe[key] = str(value)
    return safe


def log_event(
    event: str,
    *,
    level: str = "INFO",
    error: Optional[BaseException] = None,
    **fields: Any,
) -> None:
    """Write one structured event while suppressing exception details in production."""
    record: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "level": level.upper(),
        "event": event,
        **_safe_fields(fields),
    }
    if error is not None:
        record["error_type"] = type(error).__name__
        if not _is_production():
            record["error_detail"] = str(error)
    print(json.dumps(record, sort_keys=True), flush=True)
