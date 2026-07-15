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


def get_template(template_id: int) -> Optional[ReplyTemplate]:
    """Return one reply template by id."""
    session = get_db_session()
    try:
        row = session.execute(
            text("SELECT * FROM reply_templates WHERE id = :id"),
            {"id": template_id},
        ).mappings().first()
        if row is None:
            return None
        return ReplyTemplate(
            id=row["id"],
            inbox_id=row["inbox_id"],
            name_template=row["name_template"],
            body_html=row["body_html"],
            active=row["active"],
            created_at=row["created_at"],
        )
    finally:
        session.close()


def save_template(template: ReplyTemplate) -> int:
    """Insert a new template. id and created_at are auto-generated."""
    session = get_db_session()
    try:
        new_id = session.execute(
            text("""
                INSERT INTO reply_templates (inbox_id, name_template, body_html, active)
                VALUES (:inbox_id, :name_template, :body_html, :active)
                RETURNING id
            """),
            {
                "inbox_id": template.inbox_id,
                "name_template": template.name_template,
                "body_html": template.body_html,
                "active": template.active,
            },
        ).scalar_one()
        session.commit()
        return new_id
    finally:
        session.close()


def update_template(template: ReplyTemplate) -> None:
    """
    Update an existing template and refresh the legacy fallback snapshots.

    Linked rules resolve the live template body by id at send time. The text
    columns remain synchronized for safe rollback and for pre-migration rules.
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

        # Keep linked rules' fallback snapshots current regardless of whether
        # an older snapshot had already drifted from this template.
        session.execute(
            text("""
                UPDATE category_rules
                SET reply_template = :new_body
                WHERE inbox_id = :inbox_id AND reply_template_id = :template_id
            """),
            {
                "new_body": template.body_html,
                "inbox_id": template.inbox_id,
                "template_id": template.id,
            },
        )
        session.execute(
            text("""
                UPDATE category_rules
                SET reply_template_personal = :new_body
                WHERE inbox_id = :inbox_id
                  AND reply_template_personal_id = :template_id
            """),
            {
                "new_body": template.body_html,
                "inbox_id": template.inbox_id,
                "template_id": template.id,
            },
        )

        # Preserve Claude's exact-body cascade only for unlinked legacy rules.
        if prior_body is not None and prior_body != template.body_html:
            session.execute(
                text("""
                    UPDATE category_rules
                    SET reply_template = :new_body
                    WHERE inbox_id = :inbox_id
                      AND reply_template_id IS NULL
                      AND reply_template = :old_body
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
                    WHERE inbox_id = :inbox_id
                      AND reply_template_personal_id IS NULL
                      AND reply_template_personal = :old_body
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


def count_template_references(template_id: int) -> int:
    """Return how many category fields currently reference a template id."""
    session = get_db_session()
    try:
        return session.execute(
            text("""
                SELECT
                    COUNT(*) FILTER (WHERE reply_template_id = :id) +
                    COUNT(*) FILTER (WHERE reply_template_personal_id = :id)
                FROM category_rules
            """),
            {"id": template_id},
        ).scalar_one()
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
