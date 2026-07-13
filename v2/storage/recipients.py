"""
Storage functions for the recipients directory.
Each inbox has its own list of staff email recipients.
"""

from typing import List, Optional
from sqlalchemy import text

from adapters.db import get_db_session
from models.Recipient import Recipient


def get_recipients_for_inbox(inbox_id: int) -> List[Recipient]:
    """Return all recipients belonging to one inbox."""
    session = get_db_session()
    try:
        result = session.execute(
            text("SELECT * FROM recipients WHERE inbox_id = :inbox_id ORDER BY label_recipient"),
            {"inbox_id": inbox_id},
        )
        rows = result.mappings().all()
        return [
            Recipient(
                id=row["id"],
                inbox_id=row["inbox_id"],
                label_recipient=row["label_recipient"],
                email=row["email"],
                notes=row["notes"],
                active=row["active"],
                created_at=row["created_at"],
            )
            for row in rows
        ]
    finally:
        session.close()


def save_recipient(recipient: Recipient) -> None:
    """Insert a new recipient. id and created_at are auto-generated."""
    session = get_db_session()
    try:
        session.execute(
            text("""
                INSERT INTO recipients (inbox_id, label_recipient, email, notes, active)
                VALUES (:inbox_id, :label_recipient, :email, :notes, :active)
            """),
            {
                "inbox_id": recipient.inbox_id,
                "label_recipient": recipient.label_recipient,
                "email": recipient.email,
                "notes": recipient.notes,
                "active": recipient.active,
            },
        )
        session.commit()
    finally:
        session.close()


def update_recipient(recipient: Recipient) -> None:
    """Update an existing recipient's fields."""
    session = get_db_session()
    try:
        session.execute(
            text("""
                UPDATE recipients
                SET label_recipient = :label_recipient,
                    email = :email,
                    notes = :notes,
                    active = :active
                WHERE id = :id
            """),
            {
                "id": recipient.id,
                "label_recipient": recipient.label_recipient,
                "email": recipient.email,
                "notes": recipient.notes,
                "active": recipient.active,
            },
        )
        session.commit()
    finally:
        session.close()


def delete_recipient(recipient_id: int) -> None:
    """Delete a recipient by id."""
    session = get_db_session()
    try:
        session.execute(
            text("DELETE FROM recipients WHERE id = :id"),
            {"id": recipient_id},
        )
        session.commit()
    finally:
        session.close()
