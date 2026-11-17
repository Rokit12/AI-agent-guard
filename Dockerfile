# Agent Shield container, for Amazon ECS on Fargate (or any container host).
# Runs as an unprivileged user, so the System scan's "running as root" finding goes away.
#
#   docker build -t agent-shield .
#   docker run -p 4600:4600 -e HOST=0.0.0.0 -e SHIELD_TOKEN=... \
#     -v /path/to/agent:/target:ro -e TARGET_DIR=/target agent-shield
FROM node:22-slim
ENV NODE_ENV=production
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm install --no-save tsx@4 && npm cache clean --force
COPY src ./src
COPY ui ./ui
COPY rules ./rules
COPY redteam ./redteam
COPY integrations ./integrations
COPY scripts ./scripts
RUN mkdir -p state outbox logs sandbox && chown -R node:node /app
USER node
EXPOSE 4600
HEALTHCHECK --interval=30s --timeout=5s CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||4600)+'/api/state',{headers:process.env.SHIELD_TOKEN?{authorization:'Bearer '+process.env.SHIELD_TOKEN}:{}}).then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["npx", "tsx", "src/server.ts"]
