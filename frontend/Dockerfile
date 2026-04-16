FROM node:20-alpine AS build

WORKDIR /app

ARG VITE_API_BASE_URL=http://localhost:8000
ENV VITE_API_BASE_URL=${VITE_API_BASE_URL}

# Copy and install dependencies
COPY package*.json ./
COPY frontend/package.json ./frontend/

RUN npm ci -w reconx-elite-frontend

# Copy source
COPY frontend ./frontend

# Build
RUN npm run build -w reconx-elite-frontend && \
    test -d /app/frontend/dist || (echo "Build failed"; exit 1)

# Runtime stage
FROM nginx:1.27-alpine

# Security: create non-root user
RUN addgroup -S appuser && adduser -S appuser -G appuser && \
    mkdir -p /var/cache/nginx /var/log/nginx && \
    chown -R appuser:appuser /var/cache/nginx /var/log/nginx /etc/nginx/conf.d

# Copy nginx config
COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf

# Copy built app
COPY --from=build --chown=appuser:appuser /app/frontend/dist /usr/share/nginx/html

# Optimize nginx
RUN sed -i 's/worker_processes auto;/worker_processes auto;/' /etc/nginx/nginx.conf && \
    sed -i 's/# gzip/gzip/' /etc/nginx/nginx.conf

USER appuser

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=3 \
    CMD wget -qO- http://localhost:8080/ || exit 1

CMD ["nginx", "-g", "daemon off;"]
