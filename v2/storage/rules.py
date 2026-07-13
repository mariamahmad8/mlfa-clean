import json
from typing import List, Optional
from sqlalchemy import text

from adapters.db import get_db_session
from models.CategoryRule import CategoryRule


def get_rules_for_inbox(inbox_id: int) -> List[CategoryRule]:
    """Return all category rules belonging to one inbox, ordered by priority."""
    session = get_db_session()
    try:
        result = session.execute(
            text("SELECT * FROM category_rules WHERE inbox_id = :inbox_id ORDER BY priority"),
            {"inbox_id": inbox_id},
        )
        rows = result.mappings().all()

        return [
            CategoryRule(
                id=row["id"],
                inbox_id=row["inbox_id"],
                key=row["key_for_category"],
                label=row["label"],
                rule_text=row["rule_text"],
                mark_read=row["mark_read"],
                skip=row["skip_email"],
                auto_reply_safeguard=row["auto_reply_safeguard"],
                auto_reply_enabled=row["auto_reply_enabled"],
                emails_to_forward=row["emails_to_forward"],
                folder_path=row["folder_path"],
                reply_template=row["reply_template"],
                amount_threshold=float(row["amount_threshold"]) if row["amount_threshold"] is not None else None,
                priority=row["priority"],
                active=row["active"],
                skip_if_internal=row.get("skip_if_internal", False),
                delete_immediately=row.get("delete_immediately", False),
                reply_template_personal=row.get("reply_template_personal") or "",
            )
            for row in rows
        ]
    finally:
        session.close()

def save_rule(rule: CategoryRule) -> None:
    """Insert a new category rule into the database. The id is auto-generated."""
    session = get_db_session()
    try:
        session.execute(
            text(
                """
                INSERT INTO category_rules (
                    inbox_id, key_for_category, label, rule_text,
                    mark_read, skip_email, auto_reply_safeguard, auto_reply_enabled,
                    emails_to_forward, folder_path, reply_template,
                    amount_threshold, priority, active,
                    skip_if_internal, delete_immediately, reply_template_personal
                ) VALUES (
                    :inbox_id, :key, :label, :rule_text,
                    :mark_read, :skip, :auto_reply_safeguard, :auto_reply_enabled,
                    :emails_to_forward, :folder_path, :reply_template,
                    :amount_threshold, :priority, :active,
                    :skip_if_internal, :delete_immediately, :reply_template_personal
                )
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
            },
        )
        session.commit()
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
                    reply_template_personal = :reply_template_personal
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
            },
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
            text("SELECT * FROM category_rules WHERE id = :id"),
            {"id": rule_id},
        )
        row = result.mappings().first()
        if row is None:
            return None
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
            emails_to_forward=row["emails_to_forward"],
            folder_path=row["folder_path"],
            reply_template=row["reply_template"],
            amount_threshold=float(row["amount_threshold"]) if row["amount_threshold"] is not None else None,
            priority=row["priority"],
            active=row["active"],
            skip_if_internal=row.get("skip_if_internal", False),
            delete_immediately=row.get("delete_immediately", False),
            reply_template_personal=row.get("reply_template_personal") or "",
        )
    finally:
        session.close()
