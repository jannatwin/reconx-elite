FROM node:20-alpine AS build

WORKDIR /app

ARG VITE_API_BASE_URL=http://localhost:8000
ENV VITE_API_BASE_URL=${VITE_API_BASE_URL}

# Copy package files first for better layer caching
COPY frontend/package*.json ./

RUN npm ci && npm run build && \
    test -d dist || (echo "Build failed: dist directory not found"; exit 1)

# Runtime stage
FROM nginx:1.27-alpine

# Security: create non-root user with writable directories
RUN addgroup -S appuser && adduser -S appuser -G appuser && \
    mkdir -p /var/cache/nginx /var/log/nginx /var/run/nginx && \
    chown -R appuser:appuser /var/cache/nginx /var/log/nginx /var/run/nginx /etc/nginx/conf.d

# Remove the default nginx user directive and set pid to writable location
RUN sed -i '/^user nginx;/d' /etc/nginx/nginx.conf && \
    sed -i 's|^pid /var/run/nginx\.pid;|pid /var/run/nginx/nginx.pid;|' /etc/nginx/nginx.conf

# Copy nginx config first, before validation
COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf

# Validate nginx configuration syntax
RUN nginx -t

# Copy built app
COPY --from=build --chown=appuser:appuser /app/dist /usr/share/nginx/html

USER appuser

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=3 \
    CMD wget -qO- http://localhost:8080/ || exit 1

CMD ["nginx", "-g", "daemon off;"]
