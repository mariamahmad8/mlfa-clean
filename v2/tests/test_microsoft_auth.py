import os
import unittest
from unittest.mock import Mock, patch

from auth.microsoft import (
    MicrosoftAuthConfig,
    claim_email_candidates,
    complete_flow,
    load_config,
)


TENANT_ID = "11111111-1111-4111-8111-111111111111"
CLIENT_ID = "22222222-2222-4222-8222-222222222222"
USER_OID = "33333333-3333-4333-8333-333333333333"


def _config():
    return MicrosoftAuthConfig(
        auth_mode="microsoft",
        tenant_id=TENANT_ID,
        client_id=CLIENT_ID,
        redirect_uri="https://hub.example.com/auth/microsoft/callback",
        client_credential="not-a-real-secret",
        max_auth_age_seconds=3600,
    )


class MicrosoftAuthenticationTests(unittest.TestCase):
    def test_single_tenant_configuration_is_required(self):
        env = {
            "AUTH_MODE": "microsoft",
            "ENTRA_TENANT_ID": "organizations",
            "ENTRA_CLIENT_ID": CLIENT_ID,
            "ENTRA_CLIENT_SECRET": "secret",
        }
        with patch.dict(os.environ, env, clear=True):
            with self.assertRaises(RuntimeError):
                load_config("https://hub.example.com", production=True)

    def test_production_redirect_must_use_https(self):
        env = {
            "AUTH_MODE": "microsoft",
            "ENTRA_TENANT_ID": TENANT_ID,
            "ENTRA_CLIENT_ID": CLIENT_ID,
            "ENTRA_CLIENT_SECRET": "secret",
            "ENTRA_REDIRECT_URI": "http://hub.example.com/auth/microsoft/callback",
        }
        with patch.dict(os.environ, env, clear=True):
            with self.assertRaises(RuntimeError):
                load_config("", production=True)

    @patch("auth.microsoft.build_client")
    def test_callback_rejects_tokens_from_another_tenant(self, build_client):
        client = Mock()
        client.acquire_token_by_auth_code_flow.return_value = {
            "id_token_claims": {"tid": CLIENT_ID, "oid": USER_OID}
        }
        build_client.return_value = client

        with self.assertRaises(ValueError):
            complete_flow(_config(), {"state": "state"}, {"code": "code"})

    @patch("auth.microsoft.build_client")
    def test_callback_requires_immutable_user_object_id(self, build_client):
        client = Mock()
        client.acquire_token_by_auth_code_flow.return_value = {
            "id_token_claims": {"tid": TENANT_ID}
        }
        build_client.return_value = client

        with self.assertRaises(ValueError):
            complete_flow(_config(), {"state": "state"}, {"code": "code"})

    def test_guest_email_claim_can_bind_but_ext_upn_cannot(self):
        claims = {
            "email": "Mariam.Ahmad@pairsys.ai",
            "preferred_username": "mariam.ahmad_pairsys.ai#EXT#@mlfa.onmicrosoft.com",
        }
        self.assertEqual(
            list(claim_email_candidates(claims)),
            ["mariam.ahmad@pairsys.ai"],
        )


if __name__ == "__main__":
    unittest.main()
