# syntax=docker/dockerfile:1
# FlowScope container image. Multi-arch friendly: no native modules, only Node.js 22.
FROM node:22-slim AS build
WORKDIR /src
COPY package.json ./
RUN npm install --no-audit --no-fund
COPY tsconfig.*.json ./
COPY tools ./tools
COPY src ./src
COPY web ./web
RUN node tools/build.mjs && npm prune --omit=dev

FROM node:22-slim
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
RUN mkdir -p /data && chown node:node /data
USER node
VOLUME /data
# Web console (HTTPS, self-signed until you install your own certificate) and flow export ports.
EXPOSE 8443/tcp 2055/udp 4739/udp
HEALTHCHECK --interval=30s --timeout=6s --start-period=20s --retries=3 CMD ["node", "dist/src/cli.js", "healthcheck"]
ENTRYPOINT ["node", "--disable-warning=ExperimentalWarning", "dist/src/cli.js"]
CMD ["start"]
