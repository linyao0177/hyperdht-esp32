# Image for the long-running public nodes: relay-node.js and anchor-node.js
# (docs/relay-node.md, docs/anchor-node.md). Build from the repository root:
#   docker build -f deploy/Dockerfile -t hdht-nodes .
FROM node:20-bookworm-slim

WORKDIR /app
COPY tools/host/package.json tools/host/package-lock.json ./
# the nodes need neither BLE (noble) nor the HashAnchor client (anchor-verify.js)
RUN npm pkg delete "dependencies.@abandonware/noble" "dependencies.@tlay/hashanchor-client" \
 && npm install --omit=dev --no-audit --no-fund \
 && npm cache clean --force
COPY tools/host/*.js ./

# keys and logs live in volumes, owned by the unprivileged user
RUN mkdir -p /home/node/.hdht-relay /home/node/.open-anchor \
 && chown node:node /home/node/.hdht-relay /home/node/.open-anchor
USER node
ENV HOME=/home/node
ENTRYPOINT ["node"]
