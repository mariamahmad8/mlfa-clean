"""Central security configuration for the v2 Flask application."""

import os
import hmac
import secrets
import time
from datetime import timedelta
from urllib.parse import urlparse

from flask import abort, jsonify, redirect, request, session, url_for
from werkzeug.middleware.proxy_fix import ProxyFix


_INSECURE_SECRET_KEYS = {
    "mlfa-email-hub-2024",
    "change-me",
    "changeme",
}


def _is_production() -> bool:
    app_env = os.getenv("APP_ENV", "").strip().lower()
    return bool(os.getenv("RAILWAY_ENVIRONMENT_NAME")) or app_env == "production"


def _public_base_url(production: bool) -> str:
    configured = os.getenv("APP_BASE_URL", "").strip().rstrip("/")
    railway_domain = os.getenv("RAILWAY_PUBLIC_DOMAIN", "").strip()
    base_url = configured or (f"https://{railway_domain}" if railway_domain else "")

    if production and not base_url:
        raise RuntimeError("APP_BASE_URL or RAILWAY_PUBLIC_DOMAIN must be set in production.")

    if base_url:
        parsed = urlparse(base_url)
        if parsed.scheme not in ({"https"} if production else {"http", "https"}) or not parsed.hostname:
            raise RuntimeError("APP_BASE_URL must be a valid HTTPS URL in production.")

    return base_url


def _trusted_hosts(base_url: str, production: bool) -> set[str]:
    hosts = {
        host.strip().lower()
        for host in os.getenv("TRUSTED_HOSTS", "").split(",")
        if host.strip()
    }
    if base_url:
        hostname = urlparse(base_url).hostname
        if hostname:
            hosts.add(hostname.lower())

    railway_domain = os.getenv("RAILWAY_PUBLIC_DOMAIN", "").strip().lower()
    if railway_domain:
        hosts.add(railway_domain)

    if production and not hosts:
        raise RuntimeError("At least one trusted production hostname is required.")

    return hosts


def configure_security(app) -> dict:
    """Apply fail-safe production defaults and return derived settings."""
    production = _is_production()
    secret_key = os.getenv("SECRET_KEY", "").strip()

    if production:
        if len(secret_key) < 32 or secret_key.lower() in _INSECURE_SECRET_KEYS:
            raise RuntimeError("SECRET_KEY must be a unique random value of at least 32 characters.")
    elif not secret_key:
        # Local-only ephemeral key; production is never allowed to use this path.
        secret_key = secrets.token_urlsafe(48)

    base_url = _public_base_url(production)
    trusted_hosts = _trusted_hosts(base_url, production)

    app.config.update(
        SECRET_KEY=secret_key,
        SESSION_COOKIE_NAME="__Host-mlfa_session" if production else "mlfa_session",
        SESSION_COOKIE_SECURE=production,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_PATH="/",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
        SESSION_REFRESH_EACH_REQUEST=False,
        PREFERRED_URL_SCHEME="https" if production else "http",
        MAX_CONTENT_LENGTH=1024 * 1024,
        MAX_FORM_MEMORY_SIZE=64 * 1024,
        MAX_FORM_PARTS=50,
    )

    if production:
        # Railway terminates TLS at one trusted reverse proxy hop.
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    @app.before_request
    def validate_host_header():
        if not production:
            return None
        request_host = (request.host or "").split(":", 1)[0].lower()
        if request_host not in trusted_hosts:
            abort(400)
        return None

    @app.before_request
    def protect_against_csrf():
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_urlsafe(32)

        if request.method in {"GET", "HEAD", "OPTIONS"}:
            return None

        if request.path != "/login" and not session.get("logged_in"):
            return None

        supplied = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token", "")
        expected = session.get("csrf_token", "")
        if not supplied or not expected or not hmac.compare_digest(supplied, expected):
            if request.path.startswith("/api/"):
                return jsonify({"error": "Invalid or missing CSRF token"}), 400
            abort(400)
        return None

    @app.before_request
    def revalidate_authenticated_user():
        if not session.get("logged_in"):
            return None
        if request.endpoint in {
            "reviewer.logout",
            "reviewer.shared_css",
            "reviewer.favicon",
            "reviewer.mlfa_logo",
            "reviewer.mlfa_biglogo",
            "reviewer.info_icon",
            "static",
        }:
            return None

        now = int(time.time())
        authenticated_at = int(session.get("authenticated_at", 0) or 0)
        last_activity_at = int(session.get("last_activity_at", 0) or 0)
        session_expired = (
            not authenticated_at
            or not last_activity_at
            or now - authenticated_at > 8 * 60 * 60
            or now - last_activity_at > 30 * 60
        )
        if session_expired:
            session.clear()
            if request.path.startswith("/api/"):
                return jsonify({"error": "Session expired"}), 401
            return redirect(url_for("reviewer.login"))

        from storage import users as users_storage

        user = users_storage.get_user_by_email(session.get("user_email", ""))
        if (
            not user
            or not user.active
            or user.id != session.get("user_id")
            or user.role_user not in {"admin", "owner", "reviewer"}
        ):
            session.clear()
            if request.path.startswith("/api/"):
                return jsonify({"error": "Session is no longer authorized"}), 401
            return redirect(url_for("reviewer.login"))

        # Role changes and inbox assignments take effect on the next request.
        session["role"] = user.role_user
        session["last_activity_at"] = now
        return None

    @app.after_request
    def add_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
        )
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "base-uri 'self'; "
            "frame-ancestors 'none'; "
            "form-action 'self'; "
            "object-src 'none'; "
            "img-src 'self' data:; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "script-src 'self' 'unsafe-inline'; "
            "connect-src 'self'"
        )
        if production:
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )

        # Only allow browsers to cache immutable image assets. CSS/JS + all HTML
        # get no-store so template edits show up immediately after a deploy,
        # without needing cache-buster query strings in every template.
        cacheable_prefixes = ("/mlfa-logo", "/mlfa-favicon", "/mlfa-biglogo", "/info-icon")
        if not request.path.startswith(cacheable_prefixes):
            response.headers["Cache-Control"] = "no-store, max-age=0"
            response.headers["Pragma"] = "no-cache"

        return response

    return {
        "production": production,
        "public_base_url": base_url,
        "trusted_hosts": trusted_hosts,
    }
