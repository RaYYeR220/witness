# syntax=docker/dockerfile:1
# The organisers' Trust Manager, with producer-signed trust.score uploads.
# Build from the repository root:
#   docker build -f deploy/compose/trust-manager-witness/Dockerfile -t trust-manager-witness .
#
# The base image runs Python 3.9; witness_core/witness_sdk need 3.11+, so they get their
# own interpreter in /opt/witness and the patched Trust Manager calls it as a subprocess.
# The signing key is mounted at run time (WITNESS_KEY_PATH); nothing secret is in the image.
ARG TRUST_MANAGER_IMAGE=eclipseaerios/trust-manager:latest@sha256:f55442e2c0ed582c027f10b63fe9c47599787326bf9e591a22749711f27ebf54

FROM ghcr.io/astral-sh/uv:0.11.23 AS uv

FROM ${TRUST_MANAGER_IMAGE}
COPY --from=uv /uv /usr/local/bin/uv
COPY core /tmp/witness/core
COPY sdk /tmp/witness/sdk
RUN UV_PYTHON_INSTALL_DIR=/opt/python UV_NO_CACHE=1 uv venv --python 3.12 /opt/witness \
 && UV_NO_CACHE=1 uv pip install --compile-bytecode --python /opt/witness/bin/python \
    /tmp/witness/core /tmp/witness/sdk \
 && apt-get update && apt-get install -y --no-install-recommends git \
 && cd /manager && git init -q . && git apply -v /tmp/witness/sdk/patches/trust-manager-witness.patch \
 && rm -rf .git /tmp/witness /var/lib/apt/lists/* /usr/local/bin/uv \
 && apt-get purge -y git && apt-get autoremove -y \
 && groupadd --system --gid 10001 witness \
 && useradd --system --uid 10001 --gid witness --no-create-home --home-dir /nonexistent \
    --shell /usr/sbin/nologin witness \
 && mkdir -p /data && chown witness:witness /data

# Signer state (seq/prev chain), the salts log and the score store must outlive the container:
# mount /data. The score store path comes from manager.ini (storageName = /data/scores).
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    WITNESS_PYTHON=/opt/witness/bin/python \
    WITNESS_STATE_PATH=/data/witness-state.json \
    WITNESS_DISCLOSURES_PATH=/data/disclosures.jsonl
VOLUME /data
USER witness:witness
LABEL org.opencontainers.image.title="trust-manager-witness" \
      org.opencontainers.image.description="Eclipse aeriOS Trust Manager with producer-signed trust.score uploads" \
      org.opencontainers.image.licenses="Apache-2.0"
# The stock image sleeps 15 s before starting and scores every IE once on start.
HEALTHCHECK --interval=30s --timeout=5s --start-period=90s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:3000/weights', timeout=4)"]
