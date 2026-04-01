FROM python:3.12-slim

ARG SUBFINDER_VERSION=2.6.8
ARG HTTPX_VERSION=1.6.10
ARG NUCLEI_VERSION=3.3.8
ARG GAU_VERSION=2.2.4

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    unzip \
    && rm -rf /var/lib/apt/lists/*

RUN bash -lc "set -eux; \
    arch=$(dpkg --print-architecture); \
    case \"$arch\" in amd64) goarch=amd64;; arm64) goarch=arm64;; *) exit 1;; esac; \
    curl -fsSL \"https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_${goarch}.zip\" -o /tmp/subfinder.zip; \
    unzip /tmp/subfinder.zip -d /usr/local/bin; \
    curl -fsSL \"https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/httpx_${HTTPX_VERSION}_linux_${goarch}.zip\" -o /tmp/httpx.zip; \
    unzip /tmp/httpx.zip -d /usr/local/bin; \
    curl -fsSL \"https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${goarch}.zip\" -o /tmp/nuclei.zip; \
    unzip /tmp/nuclei.zip -d /usr/local/bin; \
    curl -fsSL \"https://github.com/lc/gau/releases/download/v${GAU_VERSION}/gau_${GAU_VERSION}_linux_${goarch}.tar.gz\" -o /tmp/gau.tar.gz; \
    tar -xzf /tmp/gau.tar.gz -C /usr/local/bin gau; \
    chmod +x /usr/local/bin/subfinder /usr/local/bin/httpx /usr/local/bin/nuclei /usr/local/bin/gau"

COPY backend/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

COPY backend/app /app/app
COPY backend/alembic /app/alembic
COPY backend/alembic.ini /app/alembic.ini

CMD ["sh", "-c", "alembic upgrade head && celery -A app.tasks.celery_app.celery_app worker --loglevel=info"]
