FROM python:3.11.9-slim-bookworm@sha256:8fb099199b9f2d70342674bd9dbccd3ed03a258f26bbd1d556822c6dfc60c317 AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

COPY deployments/cowrie/requirements.lock /tmp/requirements.lock
RUN python -m venv /opt/cowrie \
    && /opt/cowrie/bin/pip install --no-cache-dir --require-hashes -r /tmp/requirements.lock

RUN python - <<'PY'
import hashlib
import pathlib
import tarfile
import urllib.request

url = "https://github.com/cowrie/cowrie/archive/refs/tags/v2.5.0.tar.gz"
expected = "9db15102675729783a4d65617fb4355e366a7fdcd8f5705f6d41541eb1f5919b"
archive = pathlib.Path("/tmp/cowrie.tar.gz")
with urllib.request.urlopen(url, timeout=120) as response:
    data = response.read()
actual = hashlib.sha256(data).hexdigest()
if actual != expected:
    raise SystemExit(f"Cowrie tarball digest mismatch: {actual} != {expected}")
archive.write_bytes(data)
with tarfile.open(archive) as handle:
    handle.extractall("/opt", filter="data")
PY

RUN mv /opt/cowrie-2.5.0 /opt/cowrie-src

FROM python:3.11.9-slim-bookworm@sha256:8fb099199b9f2d70342674bd9dbccd3ed03a258f26bbd1d556822c6dfc60c317

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    COWRIE_STDOUT=yes \
    COWRIE_VIRTUAL_ENV=/opt/cowrie \
    PATH=/opt/cowrie/bin:/usr/local/bin:/usr/local/sbin:/usr/bin:/sbin:/bin

RUN groupadd --gid 10002 cowrie \
    && useradd --uid 10002 --gid cowrie --home-dir /opt/cowrie-src --shell /usr/sbin/nologin cowrie

COPY --from=builder /opt/cowrie /opt/cowrie
COPY --from=builder /opt/cowrie-src /opt/cowrie-src
COPY deployments/cowrie/cowrie.cfg /opt/cowrie-src/etc/cowrie.cfg
COPY deployments/cowrie/userdb.txt /opt/cowrie-src/etc/userdb.txt
COPY deployments/cowrie/entrypoint.sh /usr/local/bin/cowrie-entrypoint

RUN chmod 0755 /usr/local/bin/cowrie-entrypoint \
    && mkdir -p /opt/cowrie-src/var/log/cowrie \
        /opt/cowrie-src/var/lib/cowrie/downloads \
        /opt/cowrie-src/var/lib/cowrie/tty \
    && chown -R cowrie:cowrie /opt/cowrie-src/var

WORKDIR /opt/cowrie-src
USER cowrie

EXPOSE 2222 2223

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import socket; s=socket.create_connection(('127.0.0.1', 2222), 3); s.close()"]

ENTRYPOINT ["/usr/local/bin/cowrie-entrypoint"]
