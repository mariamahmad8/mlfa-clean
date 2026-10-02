import os
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from flask import Flask, session

os.environ.setdefault("O365_CLIENT_ID", "00000000-0000-0000-0000-000000000001")
os.environ.setdefault("O365_CLIENT_SECRET", "test-secret")
os.environ.setdefault("O365_TENANT_ID", "00000000-0000-0000-0000-000000000002")

from web import admin, reviewer


def _inbox(inbox_id, protected=False):
    return SimpleNamespace(id=inbox_id, protected=protected)


def _user(assignments=()):
    return SimpleNamespace(assigned_inbox_ids=list(assignments))


class RestrictedAdminAccessTests(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.app.secret_key = "test"

    def test_restricted_admin_sees_normal_and_assigned_protected_only(self):
        inboxes = [_inbox(1), _inbox(2, protected=True), _inbox(3, protected=True)]
        with patch.object(reviewer.inbox_storage, "get_active_inboxes", return_value=inboxes), \
             patch.object(reviewer.users_storage, "get_user_by_email", return_value=_user([3])), \
             self.app.test_request_context("/"):
            session.update(role="restricted_admin", user_email="rachel@mlfa.org")
            self.assertEqual([inbox.id for inbox in reviewer._accessible_inboxes()], [1, 3])

    def test_full_admin_still_sees_every_protected_inbox(self):
        inboxes = [_inbox(1), _inbox(2, protected=True)]
        with patch.object(reviewer.inbox_storage, "get_active_inboxes", return_value=inboxes), \
             self.app.test_request_context("/"):
            session.update(role="admin", user_email="maria@mlfa.org")
            self.assertEqual(reviewer._accessible_inboxes(), inboxes)

    def test_restricted_admin_can_configure_every_inbox(self):
        inboxes = [_inbox(1), _inbox(2, protected=True), _inbox(3, protected=True)]
        with patch.object(admin.inbox_storage, "get_active_inboxes", return_value=inboxes), \
             patch.object(admin.users_storage, "get_user_by_email", return_value=_user([3])), \
             self.app.test_request_context("/"):
            session.update(role="restricted_admin", user_email="staff@mlfa.org")
            self.assertEqual(admin._accessible_inbox_ids(), {1, 2, 3})
            self.assertTrue(admin._current_user_can_access(2))
            self.assertTrue(admin._current_user_can_access(3))


if __name__ == "__main__":
    unittest.main()
