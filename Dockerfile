FROM python:3.12.5-slim-bookworm@sha256:c24c34b502635f1f7c4e99dc09a2cbd85d480b7dcfd077198c6b5af138906390

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONPATH=/app/src \
    DEEPHONEY_PROJECT_ROOT=/app

RUN groupadd --gid 10001 deephoney \
    && useradd --uid 10001 --gid deephoney --create-home --shell /usr/sbin/nologin deephoney

WORKDIR /app

COPY requirements.lock ./
RUN python -m pip install --no-cache-dir --require-hashes -r requirements.lock

COPY alembic.ini ./
COPY migrations ./migrations
COPY configs ./configs
COPY src ./src
COPY data/samples ./data/samples
COPY deployments/app/entrypoint.sh /usr/local/bin/deephoney-entrypoint

RUN chmod 0755 /usr/local/bin/deephoney-entrypoint \
    && mkdir -p /app/data/raw /app/data/processed /app/data/artifacts /app/models \
    && chown -R deephoney:deephoney /app/data /app/models

USER deephoney

EXPOSE 8501

ENTRYPOINT ["/usr/local/bin/deephoney-entrypoint"]
CMD ["python", "-m", "deephoney", "healthcheck", "--json"]
