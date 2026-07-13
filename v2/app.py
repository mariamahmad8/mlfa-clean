"""
Entry point — creates the Flask app, registers blueprints, starts the worker.

The worker runs in a background thread (polls inboxes forever) and Flask
runs in the main thread (serves the reviewer + admin hub).

Run with: python v2/app.py
"""

import os
import threading

# Load .env before importing any modules that read env vars
from dotenv import load_dotenv
load_dotenv()
load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'src', '.env'), override=False)

from flask import Flask
from flask_cors import CORS

from worker import loop as worker_loop
from web.reviewer import reviewer_bp
from web.admin import admin_bp


def create_app() -> Flask:
    """Build the Flask app and register both blueprints."""
    app = Flask(__name__, template_folder='templates')
    app.secret_key = os.getenv('SECRET_KEY', 'mlfa-email-hub-2024')
    app.config['SESSION_COOKIE_SECURE'] = os.getenv('SESSION_COOKIE_SECURE', 'false').strip().lower() == 'true'
    app.config['SESSION_COOKIE_SAMESITE'] = os.getenv('SESSION_COOKIE_SAMESITE', 'Lax')

    allowed_origins = os.getenv('ALLOWED_ORIGINS', '').strip()
    if allowed_origins:
        origins = [o.strip() for o in allowed_origins.split(',') if o.strip()]
        CORS(app, supports_credentials=True, origins=origins)
    else:
        CORS(app, supports_credentials=True)

    app.register_blueprint(reviewer_bp)
    app.register_blueprint(admin_bp)

    # Expose the current session user email and role to ALL templates
    from flask import session
    @app.context_processor
    def inject_user():
        return {
            "current_email": session.get("user_email", ""),
            "current_role": session.get("role", ""),
        }

    return app


def main():
    # Start the polling worker in a background thread
    worker_thread = threading.Thread(target=worker_loop.run, daemon=True)
    worker_thread.start()
    print("Worker thread started")

    # Start Flask on the main thread
    print("Starting web server")
    app = create_app()
    port = int(os.getenv('PORT', '5050'))
    app.run(host='0.0.0.0', port=port, debug=False)


if __name__ == "__main__":
    main()
