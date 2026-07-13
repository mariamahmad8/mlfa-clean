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
    """Update an existing template's fields."""
    session = get_db_session()
    try:
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
