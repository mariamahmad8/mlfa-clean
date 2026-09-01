import os
import unittest
from datetime import datetime
from unittest.mock import MagicMock, patch

from cryptography.fernet import Fernet

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("O365_CLIENT_ID", "00000000-0000-0000-0000-000000000001")
os.environ.setdefault("O365_CLIENT_SECRET", "test-secret")
os.environ.setdefault("O365_TENANT_ID", "00000000-0000-0000-0000-000000000002")

from adapters import openai_client
with patch("O365.Account", return_value=MagicMock()):
    from engine import pipeline
from models.InboxConfig import InboxConfig
from models.NormalizedMessage import NormalizedMessage
from security_encryption import decrypt_payload, encrypt_payload, queue_security_mode


def _inbox(send_to_openai=True):
    return InboxConfig(
        id=1,
        email_to_watch="info@mlfa.org",
        blocked_senders=[],
        automation_mode=False,
        skip_sender_pairs=[],
        display_name="MLFA",
        system_preamble="Policy",
        global_guidelines="Return JSON",
        send_to_openai=send_to_openai,
        retention_days=30,
    )


def _message():
    return NormalizedMessage(
        message_id="message-1",
        sender="person@example.com",
        subject="Confidential subject",
        body="Confidential body",
        received_at=datetime.utcnow(),
        conversation_id="conversation-1",
        thread_messages=[],
        existing_tags=[],
    )


class QueueEncryptionTests(unittest.TestCase):
    def test_versioned_payload_round_trip(self):
        key = Fernet.generate_key().decode("ascii")
        env = {
            "QUEUE_ENCRYPTION_CURRENT_VERSION": "2",
            "QUEUE_ENCRYPTION_KEY_V2": key,
        }
        with patch.dict(os.environ, env, clear=True):
            ciphertext, version = encrypt_payload({"body": "private"})
            self.assertEqual(version, 2)
            self.assertNotIn("private", ciphertext)
            self.assertEqual(decrypt_payload(ciphertext, version), {"body": "private"})

    def test_invalid_security_mode_fails_closed(self):
        with patch.dict(os.environ, {"QUEUE_SECURITY_MODE": "unknown"}, clear=True):
            with self.assertRaises(RuntimeError):
                queue_security_mode()

    @patch("engine.pipeline.audit.log_event")
    @patch("engine.pipeline.o365.tag_email")
    @patch("engine.pipeline.queue.add_to_queue")
    @patch("engine.pipeline.classifier.classify")
    def test_ai_disabled_never_calls_classifier(
        self,
        classify,
        add_to_queue,
        tag_email,
        audit_event,
    ):
        raw_msg = object()
        pipeline.process_message(_message(), raw_msg, _inbox(send_to_openai=False), [])

        classify.assert_not_called()
        add_to_queue.assert_called_once()
        classification = add_to_queue.call_args.args[2]
        self.assertTrue(classification["ai_disabled"])
        self.assertEqual(classification["categories"], [])
        tag_email.assert_called_once_with(raw_msg, ["queued"])
        audit_event.assert_called_once()

    def test_openai_request_explicitly_disables_storage(self):
        response = MagicMock()
        response.choices[0].message.content = "{}"
        client = MagicMock()
        client.chat.completions.create.return_value = response

        with patch("adapters.openai_client._get_client", return_value=client):
            openai_client.classify_email("system", "email")

        self.assertIs(client.chat.completions.create.call_args.kwargs["store"], False)

    def test_guide_answer_explicitly_disables_storage(self):
        response = MagicMock()
        response.choices[0].message.content = "Open Settings, then Categories."
        client = MagicMock()
        client.chat.completions.create.return_value = response

        with patch("adapters.openai_client._get_client", return_value=client):
            answer = openai_client.answer_guide_question(
                "How do I add a category?",
                ["Open Settings.", "Choose Categories."],
            )

        request = client.chat.completions.create.call_args.kwargs
        self.assertIs(request["store"], False)
        self.assertIn("nontechnical MLFA staff member", request["messages"][0]["content"])
        self.assertIn("database columns", request["messages"][0]["content"])
        self.assertIn("Choose Categories", request["messages"][1]["content"])
        self.assertEqual(answer, "Open Settings, then Categories.")

if __name__ == "__main__":
    unittest.main()
