ARG PYTHON_IMAGE=python:3.12-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df
FROM ${PYTHON_IMAGE}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    GATEWAY_HOST=0.0.0.0 \
    GATEWAY_PORT=8000

WORKDIR /app
COPY requirements.lock /app/requirements.lock
RUN python -m pip install --no-cache-dir --require-hashes -r /app/requirements.lock \
    && useradd --uid 10001 --create-home --shell /usr/sbin/nologin gateway \
    && mkdir -p /data \
    && chown 10001:10001 /data

COPY --chown=10001:10001 app/ /app/app/
COPY --chown=10001:10001 config/ /app/config/

USER 10001:10001

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import os, urllib.request, sys; port = os.environ.get('GATEWAY_PORT', '8000'); sys.exit(0 if urllib.request.urlopen(f'http://127.0.0.1:{port}/healthz', timeout=3).getcode() == 200 else 1)"

CMD ["sh", "-c", "umask 077 && exec uvicorn app.main:create_app --factory --host \"${GATEWAY_HOST:-0.0.0.0}\" --port \"${GATEWAY_PORT:-8000}\" --timeout-graceful-shutdown 15 --no-access-log"]
