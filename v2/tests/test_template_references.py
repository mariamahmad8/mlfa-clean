import os
import unittest

# storage.rules initializes SQLAlchemy at import time; no database calls are
# made in these mapper-only tests.
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
from storage.rules import _row_to_rule


def _rule_row(**overrides):
    row = {
        "id": 7,
        "inbox_id": 3,
        "key_for_category": "legal",
        "label": "Legal",
        "rule_text": "Legal request",
        "mark_read": False,
        "skip_email": False,
        "auto_reply_safeguard": True,
        "auto_reply_enabled": True,
        "emails_to_forward": ["legal@example.org"],
        "folder_path": "Apply for help",
        "reply_template": "old default snapshot",
        "reply_template_personal": "old personal snapshot",
        "reply_template_id": None,
        "reply_template_personal_id": None,
        "current_reply_template": None,
        "current_reply_template_personal": None,
        "recipient_ids": [],
        "active_recipient_emails": [],
        "recipient_links_migrated": False,
        "amount_threshold": None,
        "priority": 1,
        "active": True,
        "skip_if_internal": False,
        "delete_immediately": False,
    }
    row.update(overrides)
    return row


class TemplateReferenceTests(unittest.TestCase):
    def test_linked_rule_uses_current_template_body(self):
        rule = _row_to_rule(_rule_row(
            reply_template_id=11,
            current_reply_template="new default body",
        ))

        self.assertEqual(rule.reply_template_id, 11)
        self.assertEqual(rule.reply_template, "new default body")

    def test_linked_personal_rule_uses_current_template_body(self):
        rule = _row_to_rule(_rule_row(
            reply_template_personal_id=12,
            current_reply_template_personal="new personal body",
        ))

        self.assertEqual(rule.reply_template_personal_id, 12)
        self.assertEqual(rule.reply_template_personal, "new personal body")

    def test_unlinked_legacy_rule_keeps_snapshot(self):
        rule = _row_to_rule(_rule_row())

        self.assertIsNone(rule.reply_template_id)
        self.assertEqual(rule.reply_template, "old default snapshot")
        self.assertEqual(rule.reply_template_personal, "old personal snapshot")

    def test_missing_joined_template_falls_back_to_snapshot(self):
        rule = _row_to_rule(_rule_row(
            reply_template_id=99,
            current_reply_template=None,
        ))

        self.assertEqual(rule.reply_template, "old default snapshot")

    def test_linked_recipients_use_current_directory_addresses(self):
        rule = _row_to_rule(_rule_row(
            emails_to_forward=["old@example.org"],
            recipient_ids=[21],
            active_recipient_emails=["new@example.org"],
            recipient_links_migrated=True,
        ))

        self.assertEqual(rule.recipient_ids, [21])
        self.assertEqual(rule.emails_to_forward, ["new@example.org"])

    def test_unlinked_recipients_keep_legacy_addresses(self):
        rule = _row_to_rule(_rule_row(
            emails_to_forward=["custom@example.org"],
            recipient_ids=[],
            active_recipient_emails=[],
            recipient_links_migrated=False,
        ))

        self.assertEqual(rule.emails_to_forward, ["custom@example.org"])


if __name__ == "__main__":
    unittest.main()
