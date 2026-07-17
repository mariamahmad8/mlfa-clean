#!/usr/bin/env bash
set -euo pipefail

if [[ "${SERVICE_ROLE:-combined}" == "worker" ]]; then
  exec python3 v2/worker_main.py
fi

# The existing deployment remains combined by default. A separate web service
# sets SERVICE_ROLE=web and RUN_EMAIL_WORKER=false; the worker service sets
# SERVICE_ROLE=worker and does not expose a public domain.
exec gunicorn \
  --chdir v2 \
  --bind "0.0.0.0:${PORT:-5050}" \
  --workers 1 \
  --threads 4 \
  --timeout 120 \
  --graceful-timeout 30 \
  --max-requests 1000 \
  --max-requests-jitter 100 \
  --access-logfile - \
  --access-logformat '%(m)s %(U)s %(H)s %(s)s %(L)s' \
  --error-logfile - \
  wsgi:app
