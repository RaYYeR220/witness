# Build from the repository root:
#   docker build -f relay/Dockerfile -t witness-relay .
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app
COPY core ./core
COPY relay ./relay
RUN pip install ./core ./relay \
    && useradd --system --uid 10001 relay

USER relay
ENV RELAY_HOST=0.0.0.0 \
    RELAY_PORT=5555
EXPOSE 5555
HEALTHCHECK --interval=15s --timeout=3s --retries=3 \
    CMD python -c "import os,urllib.request;urllib.request.urlopen('http://127.0.0.1:%s/healthz' % os.environ.get('RELAY_PORT','5555'), timeout=2)"
CMD ["python", "-m", "witness_relay"]
