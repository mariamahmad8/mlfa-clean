from datetime import datetime
from typing import List, Optional
from sqlalchemy import text

from adapters.db import get_db_session


def log_event(
    inbox_id: Optional[int],
    email_id: str,
    action: str,
    actor: str,
    comment: Optional[str] = None,
    duration_ms: Optional[int] = None,
) -> None:
    """Log an action taken on an email (approve, reject, dismiss, auto_processed)."""
    session = get_db_session()
    try:
        session.execute(
            text(
                """
                INSERT INTO audit_log (inbox_id, email, action_taken, actor, comment, duration_ms)
                VALUES (:inbox_id, :email, :action, :actor, :comment, :duration_ms)
                """
            ),
            {
                "inbox_id": inbox_id,
                "email": email_id,
                "action": action,
                "actor": actor,
                "comment": comment,
                "duration_ms": duration_ms,
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


def get_stats(inbox_id: int, today_start_utc: datetime) -> dict:
    """
    Efficiency stats for one inbox.
    - total_processed: all successful actions ever
    - processed_today: those since today's midnight Central Time
    - total_duration_ms: cumulative pipeline time
    - avg_duration_ms: mean duration per processed message
    """
    processed_actions = ('auto_processed', 'approved', 'approved_bulk', 'auto_processed_on_toggle')
    session = get_db_session()
    try:
        result = session.execute(
            text("""
                SELECT
                    COUNT(*) FILTER (WHERE action_taken = ANY(:actions)) AS total_processed,
                    COUNT(*) FILTER (WHERE action_taken = ANY(:actions) AND created_at >= :today_start) AS processed_today,
                    COALESCE(SUM(duration_ms) FILTER (WHERE action_taken = ANY(:actions)), 0) AS total_duration_ms,
                    COALESCE(AVG(duration_ms) FILTER (WHERE action_taken = ANY(:actions) AND duration_ms IS NOT NULL), 0) AS avg_duration_ms,
                    COUNT(*) FILTER (WHERE action_taken = 'queued_for_review') AS total_queued,
                    COUNT(*) FILTER (WHERE action_taken = 'rejected') AS total_rejected,
                    COUNT(*) FILTER (WHERE action_taken = 'dismissed') AS total_dismissed
                FROM audit_log
                WHERE inbox_id = :inbox_id
            """),
            {
                "inbox_id": inbox_id,
                "actions": list(processed_actions),
                "today_start": today_start_utc,
            },
        )
        row = result.mappings().first()
        return dict(row) if row else {}
    finally:
        session.close()
