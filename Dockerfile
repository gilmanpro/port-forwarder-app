# Port Forwarding Manager - imagen Linux
# Uso: docker build -t port-forwarder . && docker compose up -d
# El contenedor corre el panel web + supervisor (tuneles SSH hacia VPS).
FROM python:3.11-slim

# ssh para tuneles + socat/iptables para reenvio en Linux
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        openssh-client \
        socat \
        iproute2 \
        procps \
        net-tools \
        iptables \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir .

# Datos persistentes: config.json, secrets.json, metrics.db, pidfiles
ENV XDG_CONFIG_HOME=/data \
    XDG_DATA_HOME=/data

VOLUME ["/data"]

# 8794 panel web | 8795 API REST | 8796 MCP (http)
EXPOSE 8794 8795 8796

ENTRYPOINT ["/app/docker/entrypoint.sh"]
CMD ["web", "start"]
