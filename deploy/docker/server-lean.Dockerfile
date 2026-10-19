ARG RUNTIME_IMAGE=ubuntu:24.04
FROM ${RUNTIME_IMAGE}

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       ca-certificates tzdata wget \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY server/ly-server /app/ly-server
COPY server/ly-agent-center /app/ly-agent-center
COPY rules/ /etc/ly/rules/
COPY agent/rasp/python/ /app/agent/rasp/python/
RUN chmod 0755 /app/ly-server /app/ly-agent-center

EXPOSE 8080 8081
CMD ["/app/ly-server"]
