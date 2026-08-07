import json
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from sqlalchemy import text

from adapters.db import get_db_session
from models.InboxConfig import InboxConfig
from models.NormalizedMessage import NormalizedMessage
from security_encryption import decrypt_payload, encrypt_payload, queue_security_mode


def _utc_naive(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value
    return value.astimezone(timezone.utc).replace(tzinfo=None)


def _expires_at(inbox: InboxConfig) -> datetime:
    days = int(inbox.retention_days)
    if days < 1 or days > 365:
        raise RuntimeError("Inbox retention_days must be between 1 and 365.")
    return _utc_naive(datetime.now(timezone.utc) + timedelta(days=days))


def add_to_queue(
    msg: NormalizedMessage,
    inbox: InboxConfig,
    classification: dict,
) -> None:
    """Add a pending email using the configured migration/security mode."""
    session = get_db_session()
    try:
        existing = session.execute(
            text(
                "SELECT id FROM pending_queue "
                "WHERE inbox_id = :inbox_id AND message_id = :mid"
            ),
            {"inbox_id": inbox.id, "mid": msg.message_id},
        ).first()
        if existing is not None:
            return

        mode = queue_security_mode()
        encrypted_payload: Optional[str] = None
        key_version: Optional[int] = None

        if mode == "legacy":
            subject = msg.subject
            body = msg.body
            sender = msg.sender
            classification_column = classification
        else:
            payload = {
                "classification": classification,
                "subject": msg.subject,
                "sender": msg.sender,
            }
            if mode != "microsoft_only":
                payload["body"] = msg.body
            encrypted_payload, key_version = encrypt_payload(payload)
            subject = ""
            body = ""
            sender = ""
            classification_column = {}

        session.execute(
            text(
                """
                INSERT INTO pending_queue (
                    inbox_id, message_id, subject_email, body_email,
                    sender, received_at, classification, expires_at,
                    sensitive_payload_ciphertext, encryption_key_version
                ) VALUES (
                    :inbox_id, :message_id, :subject, :body,
                    :sender, :received_at, :classification, :expires_at,
                    :ciphertext, :key_version
                )
                """
            ),
            {
                "inbox_id": inbox.id,
                "message_id": msg.message_id,
                "subject": subject,
                "body": body,
                "sender": sender,
                "received_at": _utc_naive(msg.received_at),
                "classification": json.dumps(classification_column),
                "expires_at": _expires_at(inbox),
                "ciphertext": encrypted_payload,
                "key_version": key_version,
            },
        )
        session.commit()
    finally:
        session.close()


def get_pending(inbox_id: int) -> List[dict]:
    """Return all unexpired pending emails for one inbox, oldest first."""
    session = get_db_session()
    try:
        result = session.execute(
            text(
                """
                SELECT * FROM pending_queue
                WHERE inbox_id = :inbox_id
                  AND (expires_at IS NULL OR expires_at > NOW())
                ORDER BY created_at
                """
            ),
            {"inbox_id": inbox_id},
        )
        return [dict(row) for row in result.mappings().all()]
    finally:
        session.close()


def get_pending_message(inbox_id: int, message_id: str):
    """Return one unexpired queue row belonging to the specified inbox."""
    session = get_db_session()
    try:
        result = session.execute(
            text(
                """
                SELECT * FROM pending_queue
                WHERE inbox_id = :inbox_id
                  AND message_id = :message_id
                  AND (expires_at IS NULL OR expires_at > NOW())
                """
            ),
            {"inbox_id": inbox_id, "message_id": message_id},
        ).mappings().first()
        return dict(result) if result else None
    finally:
        session.close()


def get_expired(inbox_id: int) -> List[dict]:
    """Return expired rows so the worker can preserve an Outlook audit tag."""
    session = get_db_session()
    try:
        result = session.execute(
            text(
                """
                SELECT * FROM pending_queue
                WHERE inbox_id = :inbox_id
                  AND expires_at IS NOT NULL
                  AND expires_at <= NOW()
                ORDER BY created_at
                """
            ),
            {"inbox_id": inbox_id},
        )
        return [dict(row) for row in result.mappings().all()]
    finally:
        session.close()


def decode_payload(row: dict) -> dict:
    """Read encrypted rows and legacy rows during the zero-downtime migration."""
    ciphertext = row.get("sensitive_payload_ciphertext")
    key_version = row.get("encryption_key_version")
    if ciphertext:
        if not key_version:
            raise RuntimeError("Encrypted queue row is missing its key version.")
        return decrypt_payload(ciphertext, int(key_version))
    return {
        "subject": row.get("subject_email") or "",
        "body": row.get("body_email") or "",
        "sender": row.get("sender") or "",
        "classification": row.get("classification") or {},
    }


def update_classification(inbox_id: int, message_id: str, classification: dict) -> bool:
    """Update a pending decision while preserving encrypted storage semantics."""
    session = get_db_session()
    try:
        row = session.execute(
            text(
                """
                SELECT * FROM pending_queue
                WHERE inbox_id = :inbox_id AND message_id = :message_id
                FOR UPDATE
                """
            ),
            {"inbox_id": inbox_id, "message_id": message_id},
        ).mappings().first()
        if row is None:
            return False

        row_dict = dict(row)
        if row_dict.get("sensitive_payload_ciphertext"):
            payload = decode_payload(row_dict)
            payload["classification"] = classification
            ciphertext, version = encrypt_payload(payload)
            session.execute(
                text(
                    """
                    UPDATE pending_queue
                    SET sensitive_payload_ciphertext = :ciphertext,
                        encryption_key_version = :version,
                        classification = '{}'::jsonb
                    WHERE id = :id
                    """
                ),
                {"ciphertext": ciphertext, "version": version, "id": row_dict["id"]},
            )
        else:
            session.execute(
                text("UPDATE pending_queue SET classification = :classification WHERE id = :id"),
                {"classification": json.dumps(classification), "id": row_dict["id"]},
            )
        session.commit()
        return True
    finally:
        session.close()


def remove_from_queue(message_id: str) -> None:
    """Remove an email after approval, rejection, dismissal, or expiration."""
    session = get_db_session()
    try:
        session.execute(
            text("DELETE FROM pending_queue WHERE message_id = :message_id"),
            {"message_id": message_id},
        )
        session.commit()
    finally:
        session.close()
