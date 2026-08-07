"""Tests for the queue claim that keeps an approval from running twice.

Reproduces the reported bug: clicking Approve twice sent two auto-replies,
because each request read the pending row, did the Microsoft work, and only
then deleted the row.
"""

import os
import unittest
from unittest.mock import patch

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

from storage import queue as queue_storage


class _Boom(Exception):
    pass


class ClaimPendingTests(unittest.TestCase):
    def setUp(self):
        # One shared in-memory connection so separate sessions see one database.
        self.engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        with self.engine.begin() as conn:
            conn.execute(text(
                "CREATE TABLE pending_queue ("
                "id INTEGER PRIMARY KEY, inbox_id INTEGER, message_id TEXT)"
            ))
            conn.execute(text(
                "INSERT INTO pending_queue (inbox_id, message_id) VALUES (1, 'msg-1')"
            ))
        self._patch = patch.object(
            queue_storage, "get_db_session", sessionmaker(bind=self.engine)
        )
        self._patch.start()
        self.addCleanup(self._patch.stop)

    def _rows(self):
        with self.engine.begin() as conn:
            return conn.execute(text("SELECT COUNT(*) FROM pending_queue")).scalar()

    def test_first_claim_wins_and_second_gets_nothing(self):
        """The double-clicked Approve case: only one caller may act."""
        with queue_storage.claim_pending(1, "msg-1") as claimed:
            self.assertIsNotNone(claimed)
            self.assertEqual(claimed["message_id"], "msg-1")

        with queue_storage.claim_pending(1, "msg-1") as second:
            self.assertIsNone(second)

        self.assertEqual(self._rows(), 0)

    def test_failed_action_leaves_the_email_queued(self):
        """A failed approval must stay retryable, not vanish from the queue."""
        with self.assertRaises(_Boom):
            with queue_storage.claim_pending(1, "msg-1") as claimed:
                self.assertIsNotNone(claimed)
                raise _Boom

        self.assertEqual(self._rows(), 1)

        # Still claimable afterwards.
        with queue_storage.claim_pending(1, "msg-1") as retry:
            self.assertIsNotNone(retry)

    def test_unknown_message_yields_none(self):
        with queue_storage.claim_pending(1, "does-not-exist") as claimed:
            self.assertIsNone(claimed)
        self.assertEqual(self._rows(), 1)

    def test_other_inbox_cannot_claim(self):
        with queue_storage.claim_pending(2, "msg-1") as claimed:
            self.assertIsNone(claimed)
        self.assertEqual(self._rows(), 1)


if __name__ == "__main__":
    unittest.main()
