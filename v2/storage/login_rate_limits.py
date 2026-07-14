"""Database-backed throttling for magic-link requests."""

from datetime import datetime, timedelta

from sqlalchemy import text

from adapters.db import get_db_session


def record_attempt(key_hash: str, window_seconds: int) -> int:
    """Increment one rate-limit bucket and return its current attempt count."""
    now = datetime.utcnow()
    cutoff = now - timedelta(seconds=window_seconds)
    session = get_db_session()
    try:
        result = session.execute(
            text("""
                INSERT INTO login_rate_limits (
                    key_hash, attempts, window_started_at, updated_at
                ) VALUES (
                    :key_hash, 1, :now, :now
                )
                ON CONFLICT (key_hash) DO UPDATE SET
                    attempts = CASE
                        WHEN login_rate_limits.window_started_at < :cutoff THEN 1
                        ELSE login_rate_limits.attempts + 1
                    END,
                    window_started_at = CASE
                        WHEN login_rate_limits.window_started_at < :cutoff THEN :now
                        ELSE login_rate_limits.window_started_at
                    END,
                    updated_at = :now
                RETURNING attempts
            """),
            {"key_hash": key_hash, "now": now, "cutoff": cutoff},
        )
        attempts = int(result.scalar_one())
        session.commit()
        return attempts
    finally:
        session.close()
