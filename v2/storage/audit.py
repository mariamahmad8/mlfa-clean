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
    Efficiency stats for one inbox — today-scoped AND all-time.
    Central-Time midnight boundary. Past entries without duration_ms still
    count in processed totals; time sums only include rows with recorded duration.
    """
    processed_actions = ('auto_processed', 'approved', 'approved_bulk', 'auto_processed_on_toggle')
    session = get_db_session()
    try:
        result = session.execute(
            text("""
                SELECT
                    -- Today
                    COUNT(*) FILTER (WHERE action_taken = ANY(:actions) AND created_at >= :today_start) AS processed_today,
                    COALESCE(SUM(duration_ms) FILTER (WHERE action_taken = ANY(:actions) AND created_at >= :today_start), 0) AS duration_ms_today,
                    COALESCE(AVG(duration_ms) FILTER (WHERE action_taken = ANY(:actions) AND duration_ms IS NOT NULL AND created_at >= :today_start), 0) AS avg_duration_ms_today,
                    COUNT(*) FILTER (WHERE action_taken = 'rejected' AND created_at >= :today_start) AS rejected_today,
                    COUNT(*) FILTER (WHERE action_taken = 'dismissed' AND created_at >= :today_start) AS dismissed_today,
                    -- All-time
                    COUNT(*) FILTER (WHERE action_taken = ANY(:actions)) AS processed_all,
                    COALESCE(SUM(duration_ms) FILTER (WHERE action_taken = ANY(:actions)), 0) AS duration_ms_all,
                    COALESCE(AVG(duration_ms) FILTER (WHERE action_taken = ANY(:actions) AND duration_ms IS NOT NULL), 0) AS avg_duration_ms_all,
                    COUNT(*) FILTER (WHERE action_taken = 'rejected') AS rejected_all,
                    COUNT(*) FILTER (WHERE action_taken = 'dismissed') AS dismissed_all
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
