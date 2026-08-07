"""Versioned authenticated encryption for temporary queue payloads."""

import json
import os
from typing import Any

from cryptography.fernet import Fernet, InvalidToken


VALID_QUEUE_SECURITY_MODES = {
    "legacy",
    "encrypted_fallback",
    "microsoft_primary",
    "microsoft_only",
}


def queue_security_mode() -> str:
    mode = os.getenv("QUEUE_SECURITY_MODE", "legacy").strip().lower()
    if mode not in VALID_QUEUE_SECURITY_MODES:
        raise RuntimeError(
            "QUEUE_SECURITY_MODE must be legacy, encrypted_fallback, "
            "microsoft_primary, or microsoft_only."
        )
    return mode


def current_key_version() -> int:
    try:
        version = int(os.getenv("QUEUE_ENCRYPTION_CURRENT_VERSION", "1"))
    except ValueError as exc:
        raise RuntimeError("QUEUE_ENCRYPTION_CURRENT_VERSION must be an integer.") from exc
    if version < 1:
        raise RuntimeError("QUEUE_ENCRYPTION_CURRENT_VERSION must be positive.")
    return version


def _fernet(version: int) -> Fernet:
    raw_key = os.getenv(f"QUEUE_ENCRYPTION_KEY_V{version}", "").strip()
    if not raw_key:
        raise RuntimeError(f"QUEUE_ENCRYPTION_KEY_V{version} is required.")
    try:
        return Fernet(raw_key.encode("ascii"))
    except (TypeError, ValueError) as exc:
        raise RuntimeError(f"QUEUE_ENCRYPTION_KEY_V{version} is invalid.") from exc


def encrypt_payload(payload: dict[str, Any]) -> tuple[str, int]:
    version = current_key_version()
    plaintext = json.dumps(
        payload,
        separators=(",", ":"),
        sort_keys=True,
        default=str,
    ).encode("utf-8")
    return _fernet(version).encrypt(plaintext).decode("ascii"), version


def decrypt_payload(ciphertext: str, version: int) -> dict[str, Any]:
    try:
        plaintext = _fernet(int(version)).decrypt(ciphertext.encode("ascii"))
        payload = json.loads(plaintext.decode("utf-8"))
    except (InvalidToken, UnicodeError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise RuntimeError("Queue payload could not be decrypted.") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("Queue payload has an invalid structure.")
    return payload
