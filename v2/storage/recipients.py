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


def get_recipient(recipient_id: int) -> Optional[Recipient]:
    """Return one directory recipient by id."""
    session = get_db_session()
    try:
        row = session.execute(
            text("SELECT * FROM recipients WHERE id = :id"),
            {"id": recipient_id},
        ).mappings().first()
        if row is None:
            return None
        return Recipient(
            id=row["id"],
            inbox_id=row["inbox_id"],
            label_recipient=row["label_recipient"],
            email=row["email"],
            notes=row["notes"],
            active=row["active"],
            created_at=row["created_at"],
        )
    finally:
        session.close()


def save_recipient(recipient: Recipient) -> int:
    """Insert a new recipient. id and created_at are auto-generated."""
    session = get_db_session()
    try:
        new_id = session.execute(
            text("""
                INSERT INTO recipients (inbox_id, label_recipient, email, notes, active)
                VALUES (:inbox_id, :label_recipient, :email, :notes, :active)
                RETURNING id
            """),
            {
                "inbox_id": recipient.inbox_id,
                "label_recipient": recipient.label_recipient,
                "email": recipient.email,
                "notes": recipient.notes,
                "active": recipient.active,
            },
        ).scalar_one()
        session.commit()
        return new_id
    finally:
        session.close()


def update_recipient(recipient: Recipient) -> None:
    """
    Update an existing recipient. When the email address changes, cascade the
    new address to every category rule that forwards to the old one. Category
    rules store forward addresses as raw email strings in a JSONB array (not
    a foreign-key reference), so without this cascade an email rename would
    silently leave stale addresses on the rules that used to point to it.
    """
    session = get_db_session()
    try:
        # Fetch the pre-update email + inbox scope so we know what to rewrite
        prior = session.execute(
            text("SELECT email, inbox_id FROM recipients WHERE id = :id"),
            {"id": recipient.id},
        ).mappings().first()
        prior_email = prior["email"] if prior else None
        inbox_scope = prior["inbox_id"] if prior else recipient.inbox_id

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

        if prior_email is not None and prior_email != recipient.email:
            session.execute(
                text("""
                    UPDATE category_rules
                    SET emails_to_forward = COALESCE(
                        (SELECT jsonb_agg(
                            CASE WHEN value = :old_email THEN :new_email ELSE value END
                        )
                        FROM jsonb_array_elements_text(emails_to_forward) AS value),
                        '[]'::jsonb
                    )
                    WHERE inbox_id = :inbox_id
                      AND emails_to_forward ? :old_email
                """),
                {
                    "old_email": prior_email,
                    "new_email": recipient.email,
                    "inbox_id": inbox_scope,
                },
            )

        session.commit()
    finally:
        session.close()


def delete_recipient(recipient_id: int) -> None:
    """
    Delete a recipient. Also strip the deleted email address from any
    category rule's forward list on the same inbox so stale addresses
    don't linger.
    """
    session = get_db_session()
    try:
        prior = session.execute(
            text("SELECT email, inbox_id FROM recipients WHERE id = :id"),
            {"id": recipient_id},
        ).mappings().first()

        session.execute(
            text("DELETE FROM recipients WHERE id = :id"),
            {"id": recipient_id},
        )

        if prior:
            session.execute(
                text("""
                    UPDATE category_rules
                    SET emails_to_forward = COALESCE(
                        (SELECT jsonb_agg(value)
                         FROM jsonb_array_elements_text(emails_to_forward) AS value
                         WHERE value <> :deleted_email),
                        '[]'::jsonb
                    )
                    WHERE inbox_id = :inbox_id
                      AND emails_to_forward ? :deleted_email
                """),
                {
                    "deleted_email": prior["email"],
                    "inbox_id": prior["inbox_id"],
                },
            )

        session.commit()
    finally:
        session.close()


def count_recipient_references(recipient_id: int) -> int:
    """Return the number of category rules linked to this recipient."""
    session = get_db_session()
    try:
        return session.execute(
            text("""
                SELECT COUNT(*)
                FROM category_rule_recipients
                WHERE recipient_id = :id
            """),
            {"id": recipient_id},
        ).scalar_one()
    finally:
        session.close()
