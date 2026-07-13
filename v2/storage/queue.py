import json
from typing import List
from sqlalchemy import text

from adapters.db import get_db_session
from models.NormalizedMessage import NormalizedMessage


def add_to_queue(msg: NormalizedMessage, inbox_id: int, classification: dict) -> None:
    """Add a pending email to the queue if it's not already there."""
    session = get_db_session()
    try:
        # Check if this message is already queued
        existing = session.execute(
            text("SELECT id FROM pending_queue WHERE message_id = :mid"),
            {"mid": msg.message_id},
        ).first()
        if existing is not None:
            return

        session.execute(
            text(
                """
                INSERT INTO pending_queue (
                    inbox_id, message_id, subject_email, body_email,
                    sender, received_at, classification
                ) VALUES (
                    :inbox_id, :message_id, :subject, :body,
                    :sender, :received_at, :classification
                )
                """
            ),
            {
                "inbox_id": inbox_id,
                "message_id": msg.message_id,
                "subject": msg.subject,
                "body": msg.body,
                "sender": msg.sender,
                "received_at": msg.received_at,
                "classification": json.dumps(classification),
            },
        )
        session.commit()
    finally:
        session.close()


def get_pending(inbox_id: int) -> List[dict]:
    """Return all pending emails for one inbox, oldest first."""
    session = get_db_session()
    try:
        result = session.execute(
            text("SELECT * FROM pending_queue WHERE inbox_id = :inbox_id ORDER BY created_at"),
            {"inbox_id": inbox_id},
        )
        return [dict(row) for row in result.mappings().all()]
    finally:
        session.close()


def remove_from_queue(message_id: str) -> None:
    """Remove an email from the queue after it's been approved/rejected/dismissed."""
    session = get_db_session()
    try:
        session.execute(
            text("DELETE FROM pending_queue WHERE message_id = :message_id"),
            {"message_id": message_id},
        )
        session.commit()
    finally:
        session.close()
