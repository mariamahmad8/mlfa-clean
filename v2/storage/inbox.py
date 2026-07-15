import json
from typing import List, Optional
from sqlalchemy import text

from adapters.db import get_db_session
from models.InboxConfig import InboxConfig

"""Return all inboxes from the database as InboxConfig objects."""
def get_active_inboxes() -> List[InboxConfig]:
    session = get_db_session()
    try:
        result = session.execute(text("SELECT * FROM inboxes"))
        rows = result.mappings().all()
        return [
            InboxConfig(
                id=row["id"],
                email_to_watch=row["email_to_watch"],
                display_name=row["display_name"],
                automation_mode=row["automation_mode"],
                blocked_senders=row["blocked_senders"],
                skip_sender_pairs=row["skip_sender_pairs"],
                system_preamble=row["system_preamble"],
                global_guidelines=row["global_guidelines"],
                internal_domains=row.get("internal_domains", []) or [],
                backfill_days=row.get("backfill_days", 2),
                use_thread_context=row.get("use_thread_context", True),
                internal_reply_bridge_enabled=row.get("internal_reply_bridge_enabled", False),
                internal_reply_external_prefix=row.get("internal_reply_external_prefix", "[EXTERNAL]"),
                internal_reply_internal_prefix=row.get("internal_reply_internal_prefix", "[INTERNAL]"),
                delta_token_inbox=row.get("delta_token_inbox"),
                delta_token_junk=row.get("delta_token_junk"),
            )
            for row in rows
        ]
    finally:
        session.close()

"""Return one inbox by id, or None if not found."""
def get_inbox(inbox_id: int) -> Optional[InboxConfig]:
    session = get_db_session()
    try:
        result = session.execute(
            text("SELECT * FROM inboxes WHERE id = :inbox_id"),
            {"inbox_id": inbox_id},
        )
        row = result.mappings().first()

        if row is None:
            return None

        return InboxConfig(
            id=row["id"],
            email_to_watch=row["email_to_watch"],
            display_name=row["display_name"],
            automation_mode=row["automation_mode"],
            blocked_senders=row["blocked_senders"],
            skip_sender_pairs=row["skip_sender_pairs"],
            system_preamble=row["system_preamble"],
            global_guidelines=row["global_guidelines"],
            internal_domains=row.get("internal_domains", []) or [],
            backfill_days=row.get("backfill_days", 2),
            use_thread_context=row.get("use_thread_context", True),
            internal_reply_bridge_enabled=row.get("internal_reply_bridge_enabled", False),
            internal_reply_external_prefix=row.get("internal_reply_external_prefix", "[EXTERNAL]"),
            internal_reply_internal_prefix=row.get("internal_reply_internal_prefix", "[INTERNAL]"),
            delta_token_inbox=row.get("delta_token_inbox"),
            delta_token_junk=row.get("delta_token_junk"),
        )
    finally:
        session.close()

"""insert a new inbox into the database"""
def save_inbox(inbox: InboxConfig) -> None:
    session = get_db_session()
    try:
        session.execute(
            text(
                """
                INSERT INTO inboxes (email_to_watch, display_name, automation_mode, blocked_senders, skip_sender_pairs)
                VALUES (:email_to_watch, :display_name, :automation_mode, :blocked_senders, :skip_sender_pairs)
                """
            ),
            {
                "email_to_watch": inbox.email_to_watch,
                "display_name": inbox.display_name,
                "automation_mode": inbox.automation_mode,
                "blocked_senders": json.dumps(inbox.blocked_senders),
                "skip_sender_pairs": json.dumps(inbox.skip_sender_pairs),
            },
        )
        session.commit()
    finally:
        session.close()

def update_inbox(inbox: InboxConfig) -> None:
    """Update an existing inbox's editable fields."""
    session = get_db_session()
    try:
        session.execute(
            text("""
                UPDATE inboxes
                SET email_to_watch = :email_to_watch,
                    display_name = :display_name,
                    automation_mode = :automation_mode,
                    blocked_senders = :blocked_senders,
                    skip_sender_pairs = :skip_sender_pairs,
                    system_preamble = :system_preamble,
                    global_guidelines = :global_guidelines,
                    internal_domains = :internal_domains,
                    backfill_days = :backfill_days,
                    use_thread_context = :use_thread_context,
                    internal_reply_bridge_enabled = :internal_reply_bridge_enabled,
                    internal_reply_external_prefix = :internal_reply_external_prefix,
                    internal_reply_internal_prefix = :internal_reply_internal_prefix
                WHERE id = :id
            """),
            {
                "id": inbox.id,
                "email_to_watch": inbox.email_to_watch,
                "display_name": inbox.display_name,
                "automation_mode": inbox.automation_mode,
                "blocked_senders": json.dumps(inbox.blocked_senders),
                "skip_sender_pairs": json.dumps(inbox.skip_sender_pairs),
                "system_preamble": inbox.system_preamble,
                "global_guidelines": inbox.global_guidelines,
                "internal_domains": json.dumps(inbox.internal_domains),
                "backfill_days": inbox.backfill_days,
                "use_thread_context": inbox.use_thread_context,
                "internal_reply_bridge_enabled": inbox.internal_reply_bridge_enabled,
                "internal_reply_external_prefix": inbox.internal_reply_external_prefix,
                "internal_reply_internal_prefix": inbox.internal_reply_internal_prefix,
            },
        )
        session.commit()
    finally:
        session.close()


def delete_inbox(inbox_id: int) -> None:
    """
    Delete an inbox row by id. Also strip this inbox_id from every user's
    assigned_inbox_ids array so users don't hold stale references.
    Note: category_rules with this inbox_id must be deleted first because
    of the foreign-key constraint.
    """
    session = get_db_session()
    try:
        # Strip stale inbox_id references from every user assignment list
        session.execute(
            text("""
                UPDATE users
                SET assigned_inbox_ids = COALESCE(
                    (SELECT jsonb_agg(value)
                     FROM jsonb_array_elements(assigned_inbox_ids) AS value
                     WHERE value <> to_jsonb(:inbox_id::int)),
                    '[]'::jsonb
                )
                WHERE assigned_inbox_ids @> to_jsonb(ARRAY[:inbox_id::int])
            """),
            {"inbox_id": inbox_id},
        )
        session.execute(
            text("DELETE FROM inboxes WHERE id = :inbox_id"),
            {"inbox_id": inbox_id},
        )
        session.commit()
    finally:
        session.close()

"""Toggle automation_mode for an inbox (used by the reviewer UI)."""
def update_automation_mode(inbox_id: int, enabled: bool) -> None:

    session = get_db_session()
    try:
        session.execute(
            text("UPDATE inboxes SET automation_mode = :enabled WHERE id = :inbox_id"),
            {"inbox_id": inbox_id, "enabled": enabled},
        )
        session.commit()
    finally:
        session.close()

"""Save delta sync tokens for an inbox after polling completes."""
def update_delta_tokens(inbox_id: int, delta_token_inbox: Optional[str], delta_token_junk: Optional[str]) -> None:
    session = get_db_session()
    try:
        session.execute(
            text(
                """
                UPDATE inboxes
                SET delta_token_inbox = :delta_token_inbox,
                    delta_token_junk = :delta_token_junk
                WHERE id = :inbox_id
                """
            ),
            {
                "inbox_id": inbox_id,
                "delta_token_inbox": delta_token_inbox,
                "delta_token_junk": delta_token_junk,
            },
        )
        session.commit()
    finally:
        session.close()
