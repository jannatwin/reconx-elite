# Extended worker: optional modular pipeline tools. Use with docker compose profile `full`.
# Mount Seclists at /usr/share/seclists or set SECLISTS_BASE_PATH in .env.

FROM golang:1.23-bookworm AS gobin
RUN go install github.com/tomnomnom/waybackurls@latest \
    && go install github.com/ffuf/ffuf/v2@latest \
    && go install github.com/projectdiscovery/katana/cmd/katana@latest \
    && go install github.com/hahwul/dalfox/v2@latest \
    && go install github.com/sensepost/gowitness@latest

FROM python:3.12-bookworm

ARG SUBFINDER_VERSION=2.6.8
ARG HTTPX_VERSION=1.6.10
ARG NUCLEI_VERSION=3.3.8
ARG GAU_VERSION=2.2.4

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    unzip \
    nmap \
    masscan \
    sqlmap \
    chromium \
    && rm -rf /var/lib/apt/lists/*

COPY --from=gobin /go/bin/waybackurls /go/bin/ffuf /go/bin/katana /go/bin/dalfox /go/bin/gowitness /usr/local/bin/
RUN chmod +x /usr/local/bin/waybackurls /usr/local/bin/ffuf /usr/local/bin/katana /usr/local/bin/dalfox /usr/local/bin/gowitness

RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in amd64) goarch=amd64 ;; arm64) goarch=arm64 ;; *) exit 1 ;; esac; \
    curl -fsSL "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_${goarch}.zip" -o /tmp/subfinder.zip; \
    unzip -oj /tmp/subfinder.zip subfinder -d /usr/local/bin; \
    curl -fsSL "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/httpx_${HTTPX_VERSION}_linux_${goarch}.zip" -o /tmp/httpx.zip; \
    unzip -oj /tmp/httpx.zip httpx -d /usr/local/bin; \
    curl -fsSL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${goarch}.zip" -o /tmp/nuclei.zip; \
    unzip -oj /tmp/nuclei.zip nuclei -d /usr/local/bin; \
    curl -fsSL "https://github.com/lc/gau/releases/download/v${GAU_VERSION}/gau_${GAU_VERSION}_linux_${goarch}.tar.gz" -o /tmp/gau.tar.gz; \
    tar -xzf /tmp/gau.tar.gz -C /usr/local/bin gau; \
    chmod +x /usr/local/bin/subfinder /usr/local/bin/httpx /usr/local/bin/nuclei /usr/local/bin/gau

RUN pip install --no-cache-dir --default-timeout=180 wafw00f==2.2.0

COPY backend/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --default-timeout=180 --retries=10 -r /tmp/requirements.txt

COPY backend/app /app/app
COPY backend/alembic /app/alembic
COPY backend/alembic.ini /app/alembic.ini

ENV SECLISTS_BASE_PATH=/usr/share/seclists

CMD ["sh", "-c", "celery -A app.tasks.celery_app.celery_app worker --loglevel=info"]
