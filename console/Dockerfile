# syntax=docker/dockerfile:1
# Witness console: the Vue app built in live mode, served by an unprivileged nginx that also
# proxies /api/ to the witness-api. Build from the repository root:
#   docker build -f console/Dockerfile --build-arg ANCHOR_TRAIL_ID=0x… -t witness-console .
#
# Proofs are verified in the browser against the pins built into the app
# (console/src/config/verifier.json); ANCHOR_TRAIL_ID pins the Audit Trail the anchors are on.

ARG NODE_IMAGE=node:22-slim
ARG NGINX_IMAGE=nginxinc/nginx-unprivileged:1.29-alpine

FROM ${NODE_IMAGE} AS build
ENV CI=1
RUN npm install --global --no-fund --no-audit pnpm@9.15.0
WORKDIR /src
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY packages/verify/package.json packages/verify/
COPY anchor/package.json anchor/
COPY console/package.json console/
RUN pnpm install --frozen-lockfile --filter "console..."
COPY packages/verify packages/verify
COPY console console
COPY deploy/docker/console/pin-trail.mjs /tmp/pin-trail.mjs
ARG ANCHOR_TRAIL_ID=""
ARG VITE_API_URL=/api
RUN ANCHOR_TRAIL_ID="${ANCHOR_TRAIL_ID}" node /tmp/pin-trail.mjs console/src/config/verifier.json \
 && pnpm --filter @witness/verify build \
 && VITE_MODE=live VITE_API_URL="${VITE_API_URL}" pnpm --filter console build

FROM ${NGINX_IMAGE} AS runtime
COPY --from=build /src/console/dist /usr/share/nginx/html
COPY deploy/docker/console/default.conf.template deploy/docker/console/security-headers.inc.template \
     /etc/nginx/templates/
# The templates are rendered into /etc/nginx/conf.d at start (a tmpfs when the root filesystem
# is read-only); /tmp holds nginx's pid and temp files.
ENV NGINX_ENTRYPOINT_LOCAL_RESOLVERS=1 \
    NGINX_ENTRYPOINT_QUIET_LOGS=1 \
    NGINX_ENVSUBST_FILTER="^(WITNESS_|NGINX_LOCAL_RESOLVERS$)" \
    WITNESS_API_UPSTREAM=witness-api:7200 \
    WITNESS_REBASED_RPC_ORIGIN=https://api.testnet.iota.cafe
EXPOSE 8080
LABEL org.opencontainers.image.title="witness-console" \
      org.opencontainers.image.description="Witness console (live mode) behind nginx" \
      org.opencontainers.image.source="https://github.com/RaYYeR220/witness" \
      org.opencontainers.image.licenses="Apache-2.0"
HEALTHCHECK --interval=15s --timeout=5s --start-period=15s --retries=3 \
    CMD ["wget", "-q", "-O", "/dev/null", "http://127.0.0.1:8080/healthz"]
