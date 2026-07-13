"""
Storage for magic-link login tokens.
Tokens are hashed before storage; the plaintext is only sent in the login email.
"""

from datetime import datetime, timedelta
from typing import Optional
from sqlalchemy import text

from adapters.db import get_db_session


def create_token(email: str, token_hash: str, expires_in_minutes: int = 15) -> None:
    """Insert a new magic-link token for an email address."""
    session = get_db_session()
    try:
        expires_at = datetime.utcnow() + timedelta(minutes=expires_in_minutes)
        session.execute(
            text("""
                INSERT INTO login_tokens (email, token_hash, expires_at)
                VALUES (:email, :token_hash, :expires_at)
            """),
            {"email": email, "token_hash": token_hash, "expires_at": expires_at},
        )
        session.commit()
    finally:
        session.close()


def get_valid_token(token_hash: str) -> Optional[dict]:
    """Return the token row if it exists, hasn't been used, and hasn't expired."""
    session = get_db_session()
    try:
        result = session.execute(
            text("""
                SELECT * FROM login_tokens
                WHERE token_hash = :token_hash
                  AND used = false
                  AND expires_at > NOW()
            """),
            {"token_hash": token_hash},
        )
        row = result.mappings().first()
        return dict(row) if row else None
    finally:
        session.close()


def mark_used(token_hash: str) -> None:
    """Mark a token as used so it can't be reused."""
    session = get_db_session()
    try:
        session.execute(
            text("UPDATE login_tokens SET used = true WHERE token_hash = :token_hash"),
            {"token_hash": token_hash},
        )
        session.commit()
    finally:
        session.close()
