FROM node:22-alpine
LABEL org.opencontainers.image.title="BLCKSNAKE Command" \
      org.opencontainers.image.description="ARK: Survival Ascended server and cluster administration" \
      org.opencontainers.image.version="1.1.1" \
      org.opencontainers.image.source="https://github.com/blcksnake/BLCKSNAKE-Command" \
      org.opencontainers.image.licenses="MIT"
WORKDIR /app
ENV NODE_ENV=production \
    CROSSCHAT_RUNTIME_PROFILE=container-v1 \
    CROSSCHAT_DATA_DIRECTORY=/app/data \
    CROSSCHAT_LOG_DIRECTORY=/app/logs/current \
    CROSSCHAT_KEYSTORE_DIRECTORY=/app/keystore \
    CROSSCHAT_HTTP_HOST=0.0.0.0 \
    CROSSCHAT_HTTP_PORT=8787 \
    CROSSCHAT_ALLOW_REMOTE_HTTPS=true
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund \
    && mkdir -p /app/data /app/logs /app/keystore \
    && chown -R root:root /app \
    && chown -R node:node /app/data /app/logs /app/keystore
COPY --chown=root:root src ./src
COPY --chown=root:root THIRD_PARTY_NOTICES.md ./THIRD_PARTY_NOTICES.md
USER node
EXPOSE 8787
VOLUME ["/app/data", "/app/logs", "/app/keystore"]
CMD ["node", "src/app.js"]
