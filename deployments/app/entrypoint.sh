#!/bin/sh

set -eu

if [ "${DEEPHONEY_RUN_MIGRATIONS:-0}" = "1" ]; then
    echo "Applying database migrations..."
    python -m alembic -c /app/alembic.ini upgrade head
fi

exec "$@"
