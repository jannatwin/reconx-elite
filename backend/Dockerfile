<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Install ProjectDiscovery and related recon tools.
RUN bash -lc "set -eux; \
    arch=$(dpkg --print-architecture); \
    case \"$arch\" in amd64) goarch=amd64;; arm64) goarch=arm64;; *) exit 1;; esac; \
    curl -fsSL \"https://github.com/projectdiscovery/subfinder/releases/latest/download/subfinder_linux_${goarch}.zip\" -o /tmp/subfinder.zip; \
    unzip /tmp/subfinder.zip -d /usr/local/bin; \
    curl -fsSL \"https://github.com/projectdiscovery/httpx/releases/latest/download/httpx_linux_${goarch}.zip\" -o /tmp/httpx.zip; \
    unzip /tmp/httpx.zip -d /usr/local/bin; \
    curl -fsSL \"https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_${goarch}.zip\" -o /tmp/nuclei.zip; \
    unzip /tmp/nuclei.zip -d /usr/local/bin; \
    curl -fsSL \"https://github.com/lc/gau/releases/latest/download/gau_${goarch}.tar.gz\" -o /tmp/gau.tar.gz; \
    tar -xzf /tmp/gau.tar.gz -C /usr/local/bin gau; \
    chmod +x /usr/local/bin/subfinder /usr/local/bin/httpx /usr/local/bin/nuclei /usr/local/bin/gau"

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

COPY . /app

=======
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates unzip && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt email-validator

COPY app ./app

EXPOSE 8000
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
