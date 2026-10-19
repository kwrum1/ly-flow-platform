ARG RUNTIME_IMAGE=ubuntu:24.04
FROM ${RUNTIME_IMAGE}

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       ca-certificates wget \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY security-engine/ly-security-engine /app/ly-security-engine
RUN chmod 0755 /app/ly-security-engine \
    && mkdir -p /var/lib/lyflow/audit \
    && chmod 0700 /var/lib/lyflow/audit

EXPOSE 8080
ENTRYPOINT ["/app/ly-security-engine"]
