import io
import json
import os
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from security_logging import log_event


class SecurityLoggingTests(unittest.TestCase):
    def test_sensitive_field_names_are_rejected(self):
        for field in ("subject", "email_address", "message_id", "access_token"):
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    log_event("test", **{field: "sensitive"})

    def test_production_exception_detail_is_suppressed(self):
        output = io.StringIO()
        with patch.dict(os.environ, {"APP_ENV": "production"}, clear=True):
            with redirect_stdout(output):
                log_event(
                    "worker.failed",
                    level="ERROR",
                    error=RuntimeError("private email content"),
                    inbox_db_id=1,
                )

        record = json.loads(output.getvalue())
        self.assertEqual(record["error_type"], "RuntimeError")
        self.assertNotIn("error_detail", record)
        self.assertNotIn("private email content", output.getvalue())

    def test_local_exception_detail_is_available_for_debugging(self):
        output = io.StringIO()
        with patch.dict(os.environ, {}, clear=True):
            with redirect_stdout(output):
                log_event("worker.failed", error=ValueError("local detail"))

        record = json.loads(output.getvalue())
        self.assertEqual(record["error_detail"], "local detail")


if __name__ == "__main__":
    unittest.main()
