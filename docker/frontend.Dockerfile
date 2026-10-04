FROM node:24.21.0-bookworm-slim@sha256:0e0ff40c39bc087845bfb27465a0df4ea419520094bc35842ff83dd8cbe6f9b6 AS build
WORKDIR /app
ARG VITE_API_BASE_URL=http://localhost:4000/api/v1
ARG VITE_CSRF_COOKIE_NAME=phishguard_csrf
ENV VITE_API_BASE_URL=$VITE_API_BASE_URL
ENV VITE_CSRF_COOKIE_NAME=$VITE_CSRF_COOKIE_NAME
COPY package*.json ./
RUN npm install --no-audit --no-fund
COPY . .
RUN npm run build
RUN node -e "const fs=require('node:fs'); const u=new URL(process.env.VITE_API_BASE_URL); if(!['http:','https:'].includes(u.protocol)) process.exit(2); fs.writeFileSync('/tmp/phishguard-nginx.conf', fs.readFileSync('nginx.conf.template','utf8').replace('__PHISHGUARD_API_ORIGIN__',u.origin));"

FROM nginxinc/nginx-unprivileged:stable-alpine3.24@sha256:daa17b944bac2b578e962da4c61ad72a59233b3c63abea17113acaf4e6b9aea4
COPY --from=build /app/dist /usr/share/nginx/html
COPY --from=build /tmp/phishguard-nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD wget -q -O /dev/null http://127.0.0.1:8080/ || exit 1
