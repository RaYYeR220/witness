# syntax=docker/dockerfile:1
# The Python services of Witness, one target each, on one shared python:3.12-slim base:
#
#   docker build -f deploy/docker/python.Dockerfile --target indexer -t witness-indexer .
#   docker build -f deploy/docker/python.Dockerfile --target api     -t witness-api .
#   docker build -f deploy/docker/python.Dockerfile --target relay   -t witness-relay .
#
# Build from the repository root. Each target gets a virtualenv with only its own package and
# dependencies, installed from uv.lock (frozen, no dev tools), and runs as an unprivileged user
# on a read-only root filesystem. Nothing secret is copied in: keys, policy and credentials are
# mounted at run time.

ARG PYTHON_IMAGE=python:3.12-slim

FROM ghcr.io/astral-sh/uv:0.11.23 AS uv

# ------------------------------------------------------------------------------ build base
FROM ${PYTHON_IMAGE} AS build
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_FROZEN=1 \
    UV_NO_CACHE=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/opt/venv
WORKDIR /src
# Every workspace member's metadata, so uv can read the workspace; sources come later so a
# source change does not reinstall the dependencies.
COPY pyproject.toml uv.lock .python-version ./
COPY core/pyproject.toml core/
COPY indexer/pyproject.toml indexer/
COPY api/pyproject.toml api/
COPY relay/pyproject.toml relay/
COPY sdk/pyproject.toml sdk/
COPY cli/pyproject.toml cli/
COPY mcp/pyproject.toml mcp/
COPY chaos/pyproject.toml chaos/

FROM build AS deps-indexer
RUN uv sync --no-dev --no-install-workspace --package witness-indexer

FROM build AS deps-api
RUN uv sync --no-dev --no-install-workspace --package witness-api

FROM build AS deps-relay
RUN uv sync --no-dev --no-install-workspace --package witness-relay

FROM build AS sources
COPY core/src core/src
COPY indexer/src indexer/src
COPY api/src api/src
COPY api/templates api/templates
COPY relay/src relay/src

FROM deps-indexer AS venv-indexer
COPY --from=sources /src /src
RUN uv sync --no-dev --no-editable --package witness-indexer

FROM deps-api AS venv-api
COPY --from=sources /src /src
RUN uv sync --no-dev --no-editable --package witness-api

FROM deps-relay AS venv-relay
COPY --from=sources /src /src
RUN uv sync --no-dev --no-editable --package witness-relay

# ------------------------------------------------------------------------------ runtime base
FROM ${PYTHON_IMAGE} AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/opt/venv/bin:$PATH
RUN groupadd --system --gid 10001 witness \
 && useradd --system --uid 10001 --gid witness --no-create-home --home-dir /nonexistent \
    --shell /usr/sbin/nologin witness
WORKDIR /tmp
LABEL org.opencontainers.image.source="https://github.com/RaYYeR220/witness" \
      org.opencontainers.image.licenses="Apache-2.0"

# ------------------------------------------------------------------------------ indexer
FROM runtime AS indexer
COPY --from=venv-indexer /opt/venv /opt/venv
COPY deploy/docker/indexer_health.py /usr/local/lib/witness/indexer_health.py
USER 10001:10001
LABEL org.opencontainers.image.title="witness-indexer" \
      org.opencontainers.image.description="Witness indexer: HORNET milestones over INX, verdicts, rules, incidents"
# No HTTP port: healthy while the database answers and the newest indexed milestone is recent.
HEALTHCHECK --interval=30s --timeout=10s --start-period=180s --retries=3 \
    CMD ["python", "/usr/local/lib/witness/indexer_health.py"]
ENTRYPOINT ["python", "-m", "witness_indexer"]

# ------------------------------------------------------------------------------ api
FROM runtime AS api
COPY --from=venv-api /opt/venv /opt/venv
USER 10001:10001
ENV WITNESS_HOST=0.0.0.0 \
    WITNESS_PORT=7200
EXPOSE 7200
LABEL org.opencontainers.image.title="witness-api" \
      org.opencontainers.image.description="Witness Advanced Explorer REST API"
HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=3 \
    CMD ["python", "-c", "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/healthz' % os.environ.get('WITNESS_PORT', '7200'), timeout=4)"]
ENTRYPOINT ["python", "-m", "witness_api"]

# ------------------------------------------------------------------------------ relay
FROM runtime AS relay
COPY --from=venv-relay /opt/venv /opt/venv
USER 10001:10001
ENV RELAY_HOST=0.0.0.0 \
    RELAY_PORT=5555
EXPOSE 5555
LABEL org.opencontainers.image.title="witness-relay" \
      org.opencontainers.image.description="Witness relay: the aeriOS Messages API with signing, writer policy and forwarding"
HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=3 \
    CMD ["python", "-c", "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/healthz' % os.environ.get('RELAY_PORT', '5555'), timeout=4)"]
ENTRYPOINT ["python", "-m", "witness_relay"]
