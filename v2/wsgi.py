"""Production WSGI entry point for the v2 web app and polling worker."""

import os
import threading

from app import create_app
from worker import loop as worker_loop


app = create_app()


def _start_email_worker() -> None:
    if os.getenv("RUN_EMAIL_WORKER", "true").strip().lower() != "true":
        return
    worker_thread = threading.Thread(
        target=worker_loop.run,
        name="mlfa-email-worker",
        daemon=True,
    )
    worker_thread.start()


_start_email_worker()
