import json
from typing import List, Optional
from sqlalchemy import text

from adapters.db import get_db_session
from models.CategoryRule import CategoryRule


_RULE_SELECT = """
    SELECT cr.*,
           default_template.body_html AS current_reply_template,
           personal_template.body_html AS current_reply_template_personal,
           linked_recipients.recipient_ids AS recipient_ids,
           linked_recipients.active_recipient_emails AS active_recipient_emails
    FROM category_rules cr
    LEFT JOIN reply_templates default_template
      ON default_template.id = cr.reply_template_id
     AND default_template.inbox_id = cr.inbox_id
    LEFT JOIN reply_templates personal_template
      ON personal_template.id = cr.reply_template_personal_id
     AND personal_template.inbox_id = cr.inbox_id
    LEFT JOIN LATERAL (
        SELECT
            COALESCE(jsonb_agg(r.id ORDER BY r.id), '[]'::jsonb) AS recipient_ids,
            COALESCE(
                jsonb_agg(r.email ORDER BY r.id) FILTER (WHERE r.active),
                '[]'::jsonb
            ) AS active_recipient_emails
        FROM category_rule_recipients links
        JOIN recipients r ON r.id = links.recipient_id
        WHERE links.category_rule_id = cr.id
          AND r.inbox_id = cr.inbox_id
    ) linked_recipients ON true
"""


def _row_to_rule(row) -> CategoryRule:
    default_id = row.get("reply_template_id")
    personal_id = row.get("reply_template_personal_id")
    return CategoryRule(
        id=row["id"],
        inbox_id=row["inbox_id"],
        key=row["key_for_category"],
        label=row["label"],
        rule_text=row["rule_text"],
        mark_read=row["mark_read"],
        skip=row["skip_email"],
        auto_reply_safeguard=row["auto_reply_safeguard"],
        auto_reply_enabled=row["auto_reply_enabled"],
        emails_to_forward=(
            row.get("active_recipient_emails") or []
            if row.get("recipient_links_migrated", False)
            else row["emails_to_forward"]
        ),
        folder_path=row["folder_path"],
        reply_template=(
            row.get("current_reply_template")
            if default_id is not None and row.get("current_reply_template") is not None
            else row["reply_template"]
        ) or "",
        amount_threshold=float(row["amount_threshold"]) if row["amount_threshold"] is not None else None,
        priority=row["priority"],
        active=row["active"],
        skip_if_internal=row.get("skip_if_internal", False),
        delete_immediately=row.get("delete_immediately", False),
        reply_template_personal=(
            row.get("current_reply_template_personal")
            if personal_id is not None and row.get("current_reply_template_personal") is not None
            else row.get("reply_template_personal")
        ) or "",
        reply_template_id=default_id,
        reply_template_personal_id=personal_id,
        recipient_ids=row.get("recipient_ids") or [],
        recipient_links_migrated=row.get("recipient_links_migrated", False),
    )


def get_rules_for_inbox(inbox_id: int) -> List[CategoryRule]:
    """Return all category rules belonging to one inbox, ordered by priority."""
    session = get_db_session()
    try:
        result = session.execute(
            text(_RULE_SELECT + " WHERE cr.inbox_id = :inbox_id ORDER BY cr.priority"),
            {"inbox_id": inbox_id},
        )
        rows = result.mappings().all()

        return [_row_to_rule(row) for row in rows]
    finally:
        session.close()

def _sync_rule_recipients(
    session, rule_id: int, inbox_id: int, recipient_ids: List[int], migrated: bool
) -> None:
    session.execute(
        text("DELETE FROM category_rule_recipients WHERE category_rule_id = :rule_id"),
        {"rule_id": rule_id},
    )
    if not migrated:
        return
    for recipient_id in dict.fromkeys(recipient_ids or []):
        session.execute(
            text("""
                INSERT INTO category_rule_recipients
                    (category_rule_id, recipient_id, inbox_id)
                VALUES (:rule_id, :recipient_id, :inbox_id)
            """),
            {
                "rule_id": rule_id,
                "recipient_id": recipient_id,
                "inbox_id": inbox_id,
            },
        )


def save_rule(rule: CategoryRule) -> int:
    """Insert a new category rule into the database. The id is auto-generated."""
    session = get_db_session()
    try:
        rule_id = session.execute(
            text(
                """
                INSERT INTO category_rules (
                    inbox_id, key_for_category, label, rule_text,
                    mark_read, skip_email, auto_reply_safeguard, auto_reply_enabled,
                    emails_to_forward, folder_path, reply_template,
                    amount_threshold, priority, active,
                    skip_if_internal, delete_immediately, reply_template_personal,
                    reply_template_id, reply_template_personal_id,
                    recipient_links_migrated
                ) VALUES (
                    :inbox_id, :key, :label, :rule_text,
                    :mark_read, :skip, :auto_reply_safeguard, :auto_reply_enabled,
                    :emails_to_forward, :folder_path, :reply_template,
                    :amount_threshold, :priority, :active,
                    :skip_if_internal, :delete_immediately, :reply_template_personal,
                    :reply_template_id, :reply_template_personal_id,
                    :recipient_links_migrated
                )
                RETURNING id
                """
            ),
            {
                "inbox_id": rule.inbox_id,
                "key": rule.key,
                "label": rule.label,
                "rule_text": rule.rule_text,
                "mark_read": rule.mark_read,
                "skip": rule.skip,
                "auto_reply_safeguard": rule.auto_reply_safeguard,
                "auto_reply_enabled": rule.auto_reply_enabled,
                "emails_to_forward": json.dumps(rule.emails_to_forward),
                "folder_path": rule.folder_path,
                "reply_template": rule.reply_template,
                "amount_threshold": rule.amount_threshold,
                "priority": rule.priority,
                "active": rule.active,
                "skip_if_internal": rule.skip_if_internal,
                "delete_immediately": rule.delete_immediately,
                "reply_template_personal": rule.reply_template_personal,
                "reply_template_id": rule.reply_template_id,
                "reply_template_personal_id": rule.reply_template_personal_id,
                "recipient_links_migrated": rule.recipient_links_migrated,
            },
        ).scalar_one()
        _sync_rule_recipients(
            session, rule_id, rule.inbox_id,
            rule.recipient_ids, rule.recipient_links_migrated
        )
        session.commit()
        return rule_id
    finally:
        session.close()

def update_rule(rule: CategoryRule) -> None:
    """Update an existing category rule's fields by id."""
    session = get_db_session()
    try:
        session.execute(
            text("""
                UPDATE category_rules
                SET key_for_category = :key,
                    label = :label,
                    rule_text = :rule_text,
                    mark_read = :mark_read,
                    skip_email = :skip,
                    auto_reply_safeguard = :auto_reply_safeguard,
                    auto_reply_enabled = :auto_reply_enabled,
                    emails_to_forward = :emails_to_forward,
                    folder_path = :folder_path,
                    reply_template = :reply_template,
                    amount_threshold = :amount_threshold,
                    priority = :priority,
                    active = :active,
                    skip_if_internal = :skip_if_internal,
                    delete_immediately = :delete_immediately,
                    reply_template_personal = :reply_template_personal,
                    reply_template_id = :reply_template_id,
                    reply_template_personal_id = :reply_template_personal_id,
                    recipient_links_migrated = :recipient_links_migrated
                WHERE id = :id
            """),
            {
                "id": rule.id,
                "key": rule.key,
                "label": rule.label,
                "rule_text": rule.rule_text,
                "mark_read": rule.mark_read,
                "skip": rule.skip,
                "auto_reply_safeguard": rule.auto_reply_safeguard,
                "auto_reply_enabled": rule.auto_reply_enabled,
                "emails_to_forward": json.dumps(rule.emails_to_forward),
                "folder_path": rule.folder_path,
                "reply_template": rule.reply_template,
                "amount_threshold": rule.amount_threshold,
                "priority": rule.priority,
                "active": rule.active,
                "skip_if_internal": rule.skip_if_internal,
                "delete_immediately": rule.delete_immediately,
                "reply_template_personal": rule.reply_template_personal,
                "reply_template_id": rule.reply_template_id,
                "reply_template_personal_id": rule.reply_template_personal_id,
                "recipient_links_migrated": rule.recipient_links_migrated,
            },
        )
        _sync_rule_recipients(
            session, rule.id, rule.inbox_id,
            rule.recipient_ids, rule.recipient_links_migrated
        )
        session.commit()
    finally:
        session.close()


def delete_rule(rule_id: int) -> None:
    """Delete a category rule by id."""
    session = get_db_session()
    try:
        session.execute(
            text("DELETE FROM category_rules WHERE id = :id"),
            {"id": rule_id},
        )
        session.commit()
    finally:
        session.close()


def get_rule(rule_id: int) -> Optional[CategoryRule]:
    """Return one category rule by id (for the admin edit form)."""
    session = get_db_session()
    try:
        result = session.execute(
            text(_RULE_SELECT + " WHERE cr.id = :id"),
            {"id": rule_id},
        )
        row = result.mappings().first()
        if row is None:
            return None
        return _row_to_rule(row)
    finally:
        session.close()
