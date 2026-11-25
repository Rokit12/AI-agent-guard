# Agent Shield container, for Amazon ECS on Fargate (or any container host).
# Runs as an unprivileged user, so the System scan's "running as root" finding goes away.
#
#   docker build -t agent-shield .
#   docker run -p 4600:4600 -e SHIELD_TOKEN=... -e TARGET_REPO=https://github.com/Rokit12/airwallex.git agent-shield
#   (or mount the agent instead: -v /path/to/agent:/app/target:ro)
# infra/ deploys it to AWS: npm run aws:deploy
FROM public.ecr.aws/docker/library/node:22-slim
ENV NODE_ENV=production HOST=0.0.0.0 TARGET_DIR=/app/target
# git: secrets-in-history and leak scans read the repository's history
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm install --no-save tsx@4 && npm cache clean --force
COPY src ./src
COPY ui ./ui
COPY rules ./rules
COPY redteam ./redteam
COPY integrations ./integrations
COPY scripts ./scripts
RUN mkdir -p state outbox logs sandbox target && chown -R node:node /app
USER node
EXPOSE 4600
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||4600)+'/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["sh", "scripts/container-start.sh"]
