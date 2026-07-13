import json
from typing import List, Optional
from sqlalchemy import text

from adapters.db import get_db_session
from models.User import User


def _row_to_user(row) -> User:
    return User(
        id=row["id"],
        email=row["email"],
        display_name=row["display_name"],
        microsoft_oid=row["microsoft_oid"],
        role_user=row["role_user"],
        last_login_at=row["last_login_at"],
        created_at=row["created_at"],
        active=row["active"],
        assigned_inbox_ids=row.get("assigned_inbox_ids") or [],
    )


def get_user_by_email(email) -> Optional[User]:
    session = get_db_session()
    try:
        result = session.execute(text("SELECT * FROM users WHERE email = :email"), {"email": email})
        row = result.mappings().first()
        if row is None:
            return None
        return _row_to_user(row)
    finally:
        session.close()


def save_user(user):
    """Insert a new user."""
    session = get_db_session()
    try:
        session.execute(
            text("""INSERT INTO users (email, role_user, active, assigned_inbox_ids)
                    VALUES (:email, :role_user, :active, :assigned_inbox_ids)"""),
            {
                "email": user.email,
                "role_user": user.role_user,
                "active": user.active,
                "assigned_inbox_ids": json.dumps(user.assigned_inbox_ids or []),
            },
        )
        session.commit()
    finally:
        session.close()


def update_last_login(user_id, oid, display_name):
    session = get_db_session()
    try:
        session.execute(
            text("""UPDATE users SET microsoft_oid = :oid, display_name = :display_name, last_login_at = NOW() WHERE id = :user_id"""),
            {"user_id": user_id, "display_name": display_name, "oid": oid},
        )
        session.commit()
    finally:
        session.close()


def update_user(user_id: int, role_user: str, active: bool, assigned_inbox_ids: Optional[List[int]] = None) -> None:
    """Update a user's role, active status, and inbox assignments."""
    session = get_db_session()
    try:
        session.execute(
            text("""UPDATE users
                    SET role_user = :role,
                        active = :active,
                        assigned_inbox_ids = :assigned_inbox_ids
                    WHERE id = :id"""),
            {
                "id": user_id,
                "role": role_user,
                "active": active,
                "assigned_inbox_ids": json.dumps(assigned_inbox_ids or []),
            },
        )
        session.commit()
    finally:
        session.close()


def delete_user(user_id: int) -> None:
    session = get_db_session()
    try:
        session.execute(text("DELETE FROM users WHERE id = :id"), {"id": user_id})
        session.commit()
    finally:
        session.close()


def get_all_users():
    session = get_db_session()
    try:
        result = session.execute(text("SELECT * FROM users"))
        rows = result.mappings().all()
        return [_row_to_user(row) for row in rows]
    finally:
        session.close()
