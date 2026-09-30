# Auth Your Agent browser vault.
# Build from the repository root:  docker build -f vault/Dockerfile -t authyouragent/vault .
FROM debian:trixie-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        chromium xvfb fonts-noto-core fonts-noto-cjk ca-certificates \
        python3 python3-venv xdotool \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1

COPY sdk /src/sdk
RUN pip install --no-cache-dir --retries 10 --timeout 60 "/src/sdk[takeover]" "playwright>=1.40" "aiohttp>=3.9" \
        "python-xlib>=0.33" "pillow>=10"

COPY vault/broker.py vault/screen.py vault/egress.py vault/entrypoint.sh /app/
# Browser policy: no internal pages, dev tools, downloads, extensions or saved passwords.
COPY vault/chromium-policy.json /etc/chromium/policies/managed/vault.json
RUN chmod +x /app/entrypoint.sh && useradd -m -u 10001 vault
USER vault

EXPOSE 7801
ENTRYPOINT ["/app/entrypoint.sh"]
