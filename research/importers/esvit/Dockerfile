FROM node@sha256:fc3e945f920b7e3000cd1af86c4ae406ec70c72f328b667baf0f3a8910d69eed
WORKDIR /adapter
COPY package.json package-lock.json adapter.mjs ./
RUN npm ci --ignore-scripts --omit=dev && chmod -R a-w /adapter
ENTRYPOINT ["node", "/adapter/adapter.mjs"]
