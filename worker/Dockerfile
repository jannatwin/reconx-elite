# Stage 1: download and verify all CLI tool binaries
FROM python:3.12-slim AS tools-builder

ARG SUBFINDER_VERSION=2.6.8
ARG HTTPX_VERSION=1.6.10
ARG NUCLEI_VERSION=3.3.8
ARG GAU_VERSION=2.2.4

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    unzip \
    && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in amd64) goarch=amd64 ;; arm64) goarch=arm64 ;; *) exit 1 ;; esac; \
    curl -fL --retry 6 --retry-delay 5 --retry-all-errors \
        "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_${goarch}.zip" \
        -o /tmp/subfinder.zip; \
    unzip -oj /tmp/subfinder.zip subfinder -d /usr/local/bin; \
    curl -fL --retry 6 --retry-delay 5 --retry-all-errors \
        "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/httpx_${HTTPX_VERSION}_linux_${goarch}.zip" \
        -o /tmp/httpx.zip; \
    unzip -oj /tmp/httpx.zip httpx -d /usr/local/bin; \
    curl -fL --retry 6 --retry-delay 5 --retry-all-errors \
        "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${goarch}.zip" \
        -o /tmp/nuclei.zip; \
    unzip -oj /tmp/nuclei.zip nuclei -d /usr/local/bin; \
    curl -fL --retry 6 --retry-delay 5 --retry-all-errors \
        "https://github.com/lc/gau/releases/download/v${GAU_VERSION}/gau_${GAU_VERSION}_linux_${goarch}.tar.gz" \
        -o /tmp/gau.tar.gz; \
    tar -xzf /tmp/gau.tar.gz -C /usr/local/bin gau; \
    chmod +x /usr/local/bin/subfinder /usr/local/bin/httpx /usr/local/bin/nuclei /usr/local/bin/gau

# Stage 2: lean runtime image — no build tools
FROM python:3.12-slim AS runtime

WORKDIR /app

# Copy verified binaries from tools-builder stage
COPY --from=tools-builder /usr/local/bin/subfinder /usr/local/bin/subfinder
COPY --from=tools-builder /usr/local/bin/httpx /usr/local/bin/httpx
COPY --from=tools-builder /usr/local/bin/nuclei /usr/local/bin/nuclei
COPY --from=tools-builder /usr/local/bin/gau /usr/local/bin/gau

# Install Python dependencies
COPY backend/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --default-timeout=180 --retries=10 -r /tmp/requirements.txt

# Add non-root user
RUN groupadd -r appuser && useradd -r -g appuser -u 1001 appuser

COPY --chown=appuser:appuser backend/app /app/app
COPY --chown=appuser:appuser backend/alembic /app/alembic
COPY --chown=appuser:appuser backend/alembic.ini /app/alembic.ini

USER appuser

HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD sh -c "celery -A app.celery_app inspect ping -d celery@$$HOSTNAME || exit 1"

CMD ["sh", "-c", "celery -A app.celery_app worker --loglevel=info"]
