FROM node:20-alpine AS build

WORKDIR /app

ARG VITE_API_BASE_URL=http://localhost:8000
ENV VITE_API_BASE_URL=${VITE_API_BASE_URL}

# This repository uses npm workspaces (root package-lock.json is authoritative).
COPY package.json package-lock.json ./
COPY frontend/package.json frontend/package.json
RUN npm ci -w reconx-elite-frontend

COPY frontend ./frontend
RUN npm run build -w reconx-elite-frontend

FROM nginx:1.27-alpine

RUN addgroup -S appuser && adduser -S appuser -G appuser

# Fix Nginx permissions for non-root user
RUN touch /var/run/nginx.pid && \
    chown -R appuser:appuser /var/run/nginx.pid /var/cache/nginx /var/log/nginx /etc/nginx/conf.d

COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/frontend/dist /usr/share/nginx/html

RUN chown -R appuser:appuser /usr/share/nginx/html

USER appuser

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=3 \
    CMD wget -qO- http://localhost:8080/ || exit 1

CMD ["nginx", "-g", "daemon off;"]
