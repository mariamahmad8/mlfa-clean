from typing import List, Optional
from sqlalchemy import text

from adapters.db import get_db_session


def log_event(
    inbox_id: Optional[int],
    email_id: str,
    action: str,
    actor: str,
    comment: Optional[str] = None,
) -> None:
    """Log an action taken on an email (approve, reject, dismiss, auto_processed)."""
    session = get_db_session()
    try:
        session.execute(
            text(
                """
                INSERT INTO audit_log (inbox_id, email, action_taken, actor, comment)
                VALUES (:inbox_id, :email, :action, :actor, :comment)
                """
            ),
            {
                "inbox_id": inbox_id,
                "email": email_id,
                "action": action,
                "actor": actor,
                "comment": comment,
            },
        )
        session.commit()
    finally:
        session.close()


def get_events(inbox_id: int, limit: int = 200) -> List[dict]:
    """Return recent audit log entries for an inbox plus global (no-inbox) actions."""
    session = get_db_session()
    try:
        result = session.execute(
            text("""
                SELECT * FROM audit_log
                WHERE inbox_id = :inbox_id OR inbox_id IS NULL
                ORDER BY created_at DESC
                LIMIT :limit
            """),
            {"inbox_id": inbox_id, "limit": limit},
        )
        return [dict(row) for row in result.mappings().all()]
    finally:
        session.close()
