# The organisers' Trust Manager, with producer-signed trust.score uploads.
# Build from the repository root:
#   docker build -f deploy/compose/trust-manager-witness/Dockerfile -t trust-manager-witness .
#
# The base image runs Python 3.9; witness_core/witness_sdk need 3.11+, so they get their
# own interpreter in /opt/witness and the patched Trust Manager calls it as a subprocess.
FROM eclipseaerios/trust-manager:latest

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv
COPY core /tmp/witness/core
COPY sdk /tmp/witness/sdk
RUN UV_PYTHON_INSTALL_DIR=/opt/python uv venv --python 3.12 /opt/witness \
 && uv pip install --python /opt/witness/bin/python /tmp/witness/core /tmp/witness/sdk \
 && apt-get update && apt-get install -y --no-install-recommends git \
 && cd /manager && git init -q . && git apply -v /tmp/witness/sdk/patches/trust-manager-witness.patch \
 && rm -rf .git /tmp/witness /var/lib/apt/lists/* \
 && apt-get purge -y git && apt-get autoremove -y

# Signer state (seq/prev chain) and the salts log must outlive the container: mount /data.
ENV WITNESS_PYTHON=/opt/witness/bin/python \
    WITNESS_STATE_PATH=/data/witness-state.json \
    WITNESS_DISCLOSURES_PATH=/data/disclosures.jsonl
VOLUME /data
