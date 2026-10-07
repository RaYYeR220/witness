# syntax=docker/dockerfile:1
# Witness anchor service (did:iota resolver, checkpoint reads, anchoring loop on IOTA Rebased).
# Build from the repository root:
#   docker build -f anchor/Dockerfile -t witness-anchor .
#
# The image holds no key material. The IOTA keystore (ANCHOR_KEYSTORE_PATH), the component
# keys (SECRETS_DIR/<component>/) and the writer policy are mounted at run time, read-only;
# the trail and loop state go to a writable volume.

ARG NODE_IMAGE=node:22-slim

FROM ${NODE_IMAGE} AS build
ENV CI=1
RUN npm install --global --no-fund --no-audit pnpm@9.15.0
WORKDIR /src
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY packages/verify/package.json packages/verify/
COPY anchor/package.json anchor/
COPY console/package.json console/
RUN pnpm install --frozen-lockfile --filter "@witness/anchor..."
COPY packages/verify packages/verify
COPY anchor anchor
RUN pnpm --filter @witness/verify build \
 && pnpm --filter @witness/anchor build \
 && pnpm --filter @witness/anchor deploy --prod /out \
 && rm -rf /out/src /out/test /out/scripts /out/tsconfig*.json /out/.env.example /out/Dockerfile*

FROM ${NODE_IMAGE} AS runtime
# State lives in /var/lib/witness-anchor (mount a volume there): the trail record
# (SECRETS_DIR/trail-<network>.json) and the loop state. Component keys are mounted read-only
# at SECRETS_DIR/<component>/sig-1.jwk.json.
ENV NODE_ENV=production \
    ANCHOR_HOST=0.0.0.0 \
    ANCHOR_PORT=7300 \
    SECRETS_DIR=/var/lib/witness-anchor/secrets \
    ANCHOR_STATE_PATH=/var/lib/witness-anchor/anchor-state.json
WORKDIR /app/anchor
COPY --from=build /out /app/anchor
# The public identity file (DIDs and keys of the domain's components): dist/ looks for it at
# ../../deploy/identity/<network>.json.
COPY deploy/identity /app/deploy/identity
RUN mkdir -p /var/lib/witness-anchor/secrets \
 && chown -R node:node /var/lib/witness-anchor \
 && chmod 0700 /var/lib/witness-anchor /var/lib/witness-anchor/secrets
VOLUME /var/lib/witness-anchor
USER node:node
EXPOSE 7300
LABEL org.opencontainers.image.title="witness-anchor" \
      org.opencontainers.image.description="Witness anchor: DID resolver and checkpoint anchoring on IOTA Rebased" \
      org.opencontainers.image.source="https://github.com/RaYYeR220/witness" \
      org.opencontainers.image.licenses="Apache-2.0"
# /healthz answers 503 while the anchoring loop is degraded (5 failed ticks, a window the node
# disagrees with, or a stall); the start period covers the first windows.
HEALTHCHECK --interval=30s --timeout=5s --start-period=120s --retries=3 \
    CMD ["node", "-e", "fetch('http://127.0.0.1:' + (process.env.ANCHOR_PORT || 7300) + '/healthz').then((r) => process.exit(r.ok ? 0 : 1), () => process.exit(1))"]
CMD ["node", "dist/main.js"]
