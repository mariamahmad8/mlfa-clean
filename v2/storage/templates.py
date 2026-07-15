"""
Storage functions for the reply templates library.
Each inbox has its own reusable reply templates.
"""

from typing import List, Optional
from sqlalchemy import text

from adapters.db import get_db_session
from models.ReplyTemplate import ReplyTemplate


def get_templates_for_inbox(inbox_id: int) -> List[ReplyTemplate]:
    """Return all reply templates belonging to one inbox."""
    session = get_db_session()
    try:
        result = session.execute(
            text("SELECT * FROM reply_templates WHERE inbox_id = :inbox_id ORDER BY name_template"),
            {"inbox_id": inbox_id},
        )
        rows = result.mappings().all()
        return [
            ReplyTemplate(
                id=row["id"],
                inbox_id=row["inbox_id"],
                name_template=row["name_template"],
                body_html=row["body_html"],
                active=row["active"],
                created_at=row["created_at"],
            )
            for row in rows
        ]
    finally:
        session.close()


def save_template(template: ReplyTemplate) -> None:
    """Insert a new template. id and created_at are auto-generated."""
    session = get_db_session()
    try:
        session.execute(
            text("""
                INSERT INTO reply_templates (inbox_id, name_template, body_html, active)
                VALUES (:inbox_id, :name_template, :body_html, :active)
            """),
            {
                "inbox_id": template.inbox_id,
                "name_template": template.name_template,
                "body_html": template.body_html,
                "active": template.active,
            },
        )
        session.commit()
    finally:
        session.close()


def update_template(template: ReplyTemplate) -> None:
    """
    Update an existing template. When the body changes, cascade the new body
    to any category rules that stored a snapshot of the old body. Without
    this cascade, editing a template would not propagate to rules using it,
    because rules store the body text directly (not a foreign-key reference).
    """
    session = get_db_session()
    try:
        # Grab the pre-update body so we know what snapshot to look for on rules
        prior = session.execute(
            text("SELECT body_html FROM reply_templates WHERE id = :id"),
            {"id": template.id},
        ).mappings().first()
        prior_body = prior["body_html"] if prior else None

        session.execute(
            text("""
                UPDATE reply_templates
                SET name_template = :name_template,
                    body_html = :body_html,
                    active = :active
                WHERE id = :id
            """),
            {
                "id": template.id,
                "name_template": template.name_template,
                "body_html": template.body_html,
                "active": template.active,
            },
        )

        # Cascade the new body to rules whose stored body matches the old snapshot,
        # scoped to the same inbox to avoid cross-inbox collisions.
        if prior_body is not None and prior_body != template.body_html:
            session.execute(
                text("""
                    UPDATE category_rules
                    SET reply_template = :new_body
                    WHERE inbox_id = :inbox_id AND reply_template = :old_body
                """),
                {
                    "new_body": template.body_html,
                    "inbox_id": template.inbox_id,
                    "old_body": prior_body,
                },
            )
            session.execute(
                text("""
                    UPDATE category_rules
                    SET reply_template_personal = :new_body
                    WHERE inbox_id = :inbox_id AND reply_template_personal = :old_body
                """),
                {
                    "new_body": template.body_html,
                    "inbox_id": template.inbox_id,
                    "old_body": prior_body,
                },
            )

        session.commit()
    finally:
        session.close()


def delete_template(template_id: int) -> None:
    """Delete a template by id."""
    session = get_db_session()
    try:
        session.execute(
            text("DELETE FROM reply_templates WHERE id = :id"),
            {"id": template_id},
        )
        session.commit()
    finally:
        session.close()
