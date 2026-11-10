FROM python:3.11-slim

LABEL org.opencontainers.image.title="WebSSH Studio"
LABEL org.opencontainers.image.description="Agentless Browser SSH2 Terminal, Auto-Syncing SFTP File Manager, Remote Code Editor, Telemetry HUD, Playbooks & Port Tunnels"
LABEL org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    WEBSSH_HOST=0.0.0.0 \
    WEBSSH_PORT=8090 \
    WEBSSH_DATA_DIR=/data

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 1000 webssh \
    && useradd -u 1000 -g 1000 -m -s /usr/sbin/nologin webssh

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py .
COPY static ./static

RUN mkdir -p /data && chown -R webssh:webssh /app /data

VOLUME ["/data"]

EXPOSE 8090

USER webssh

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://127.0.0.1:8090/api/info || exit 1

CMD ["python", "server.py"]
