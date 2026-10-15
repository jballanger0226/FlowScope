# FlowScope container image. Multi-arch friendly: no native modules, only Node.js 22.
# Runs under Docker, Podman, and as an OCI application container on Proxmox VE 9.1 or newer (see docs/deployment.md).
FROM node:22-slim AS build
WORKDIR /src
# package-lock.json is optional here so the image still builds without one, but commit it: with a lockfile the build installs exactly the
# versions that were reviewed (npm ci). Dependency install scripts are never run; FlowScope's dependencies need none.
COPY package.json package-lock.json* ./
RUN if [ -f package-lock.json ]; then npm ci --ignore-scripts --no-audit --no-fund; else npm install --ignore-scripts --no-audit --no-fund; fi
COPY tsconfig.*.json ./
COPY tools ./tools
COPY src ./src
COPY web ./web
# The commit this image is built from (CI passes the commit; a local build can pass --build-arg GIT_SHA=$(git rev-parse HEAD)).
# tools/build.mjs records it in the build, so `flowscope version` and Admin > System show it.
ARG GIT_SHA=unknown
RUN FLOWSCOPE_REVISION="$GIT_SHA" node tools/build.mjs && npm prune --omit=dev

FROM node:22-slim
ARG GIT_SHA=unknown
LABEL org.opencontainers.image.revision="$GIT_SHA" \
      org.opencontainers.image.title="FlowScope" \
      org.opencontainers.image.description="NetFlow / IPFIX collector with SNMP link and QoS monitoring" \
      org.opencontainers.image.source="https://github.com/jballanger0226/flowscope" \
      org.opencontainers.image.licenses="MIT"
ENV NODE_ENV=production \
    FLOWSCOPE_CONTAINER=1 \
    FLOWSCOPE_DATA_DIR=/data \
    FLOWSCOPE_HTTPS_PORT=8443 \
    FLOWSCOPE_FLOW_PORTS=2055,4739
WORKDIR /app
COPY --from=build /src/package.json ./
COPY --from=build /src/node_modules ./node_modules
COPY --from=build /src/dist/src ./dist/src
COPY --from=build /src/dist/web ./dist/web
COPY packaging/docker-entrypoint.sh /usr/local/bin/flowscope-entrypoint
RUN mkdir -p /data && chown node:node /data && chmod 0755 /usr/local/bin/flowscope-entrypoint
# The entrypoint starts as root only to make /data writable (Proxmox mount points and new bind mounts are owned by root),
# then drops to the "node" user. Use `docker run --user 1000:1000` to skip that and never run as root.
VOLUME /data
# Web console (HTTPS, self-signed until you install your own certificate) and flow export ports.
EXPOSE 8443/tcp 2055/udp 4739/udp
HEALTHCHECK --interval=30s --timeout=6s --start-period=20s --retries=3 CMD ["node", "dist/src/cli.js", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/flowscope-entrypoint"]
CMD ["start"]
