#!/usr/bin/env bash
set -euo pipefail

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
