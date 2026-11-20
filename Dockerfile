# Multi-stage build: frontend + Python backend + security toolchain.
# Tool binaries are pinned; nmap via apt. Non-root runtime user.

FROM node:22-alpine AS web
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM python:3.12-slim-bookworm AS tools
ARG NUCLEI_VERSION=3.4.10
ARG HTTPX_VERSION=1.12.0
ARG SUBFINDER_VERSION=2.10.0
ARG FFUF_VERSION=2.1.0
ARG TRIVY_VERSION=0.69.3
ARG GITLEAKS_VERSION=8.24.3
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap curl unzip ca-certificates git \
    && rm -rf /var/lib/apt/lists/*
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in amd64) a=amd64;; arm64) a=arm64;; *) echo "unsupported $arch"; exit 1;; esac; \
    curl -fsSL -o /tmp/nuclei.zip "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${a}.zip"; \
    unzip -o /tmp/nuclei.zip nuclei -d /usr/local/bin/; \
    curl -fsSL -o /tmp/httpx.zip "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/httpx_${HTTPX_VERSION}_linux_${a}.zip"; \
    unzip -o /tmp/httpx.zip httpx -d /usr/local/bin/; \
    curl -fsSL -o /tmp/subfinder.zip "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_${a}.zip"; \
    unzip -o /tmp/subfinder.zip subfinder -d /usr/local/bin/; \
    curl -fsSL -o /tmp/ffuf.tar.gz "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VERSION}/ffuf_${FFUF_VERSION}_linux_${a}.tar.gz"; \
    tar -xzf /tmp/ffuf.tar.gz -C /usr/local/bin/ ffuf; \
    chmod +x /usr/local/bin/nuclei /usr/local/bin/httpx /usr/local/bin/subfinder /usr/local/bin/ffuf; \
    curl -fsSL -o /tmp/trivy.tar.gz "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"; \
    tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin/ trivy; \
    curl -fsSL -o /tmp/gitleaks.tar.gz "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"; \
    tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin/ gitleaks; \
    chmod +x /usr/local/bin/trivy /usr/local/bin/gitleaks; \
    rm -f /tmp/*.zip /tmp/*.tar.gz; \
    nuclei -update-templates -silent || true

FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap dirb ca-certificates libatomic1 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -u 10001 libella
COPY --from=tools /usr/local/bin/nuclei /usr/local/bin/httpx \
     /usr/local/bin/subfinder /usr/local/bin/ffuf \
     /usr/local/bin/trivy /usr/local/bin/gitleaks /usr/local/bin/
COPY --from=tools /root/nuclei-templates /opt/nuclei-templates
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src/ src/
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright
RUN pip install --no-cache-dir . semgrep playwright \
    && playwright install --with-deps chromium \
    && chmod -R a+rX /opt/ms-playwright
COPY --from=web /web/dist /app/web/dist
ENV LIBELLA_DATA=/data \
    LIBELLA_HOST=0.0.0.0 \
    LIBELLA_PORT=8787 \
    LIBELLA_TEMPLATE_DIR=/opt/nuclei-templates \
    LIBELLA_WORDLIST_DIR=/usr/share/wordlists \
    HOME=/home/libella
RUN mkdir -p /data && chown -R libella:libella /data /app
USER libella
# nuclei templates live at /opt; point HOME-based lookup there via symlink
RUN ln -s /opt/nuclei-templates /home/libella/nuclei-templates
EXPOSE 8787
VOLUME /data
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8787/api/health')" || exit 1
ENTRYPOINT ["python", "-m", "libella.main"]