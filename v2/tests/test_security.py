import os
import unittest
from unittest.mock import patch

from flask import Flask, session

from security import configure_security


class SecurityConfigurationTests(unittest.TestCase):
    def _production_env(self):
        return {
            "RAILWAY_ENVIRONMENT_NAME": "production",
            "RAILWAY_PUBLIC_DOMAIN": "hub.example.com",
            "APP_BASE_URL": "https://hub.example.com",
            "TRUSTED_HOSTS": "hub.example.com",
            "SECRET_KEY": "s" * 64,
        }

    def test_production_rejects_weak_secret(self):
        env = self._production_env()
        env["SECRET_KEY"] = "short"
        with patch.dict(os.environ, env, clear=True):
            with self.assertRaises(RuntimeError):
                configure_security(Flask(__name__))

    def test_production_cookie_is_hardened(self):
        with patch.dict(os.environ, self._production_env(), clear=True):
            app = Flask(__name__)
            configure_security(app)

            @app.route("/")
            def index():
                session["test"] = True
                return "ok"

            response = app.test_client().get("/", base_url="https://hub.example.com")
            cookie = response.headers.get("Set-Cookie", "")
            self.assertIn("__Host-mlfa_session=", cookie)
            self.assertIn("Secure", cookie)
            self.assertIn("HttpOnly", cookie)
            self.assertIn("SameSite=Lax", cookie)

    def test_csrf_is_required_for_state_changes(self):
        with patch.dict(os.environ, {}, clear=True):
            app = Flask(__name__)
            configure_security(app)

            @app.route("/login", methods=["GET", "POST"])
            def login():
                return "ok"

            client = app.test_client()
            client.get("/login")
            self.assertEqual(client.post("/login").status_code, 400)

            with client.session_transaction() as active_session:
                csrf_token = active_session["csrf_token"]
            response = client.post("/login", data={"csrf_token": csrf_token})
            self.assertEqual(response.status_code, 200)

    def test_untrusted_production_host_is_rejected(self):
        with patch.dict(os.environ, self._production_env(), clear=True):
            app = Flask(__name__)
            configure_security(app)

            @app.route("/")
            def index():
                return "ok"

            response = app.test_client().get("/", base_url="https://attacker.example")
            self.assertEqual(response.status_code, 400)

    def test_sensitive_responses_receive_security_headers(self):
        with patch.dict(os.environ, {}, clear=True):
            app = Flask(__name__)
            configure_security(app)

            @app.route("/")
            def index():
                return "ok"

            response = app.test_client().get("/")
            self.assertEqual(response.headers["X-Frame-Options"], "DENY")
            self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
            self.assertIn("frame-ancestors 'none'", response.headers["Content-Security-Policy"])
            self.assertEqual(response.headers["Cache-Control"], "no-store, max-age=0")


if __name__ == "__main__":
    unittest.main()
