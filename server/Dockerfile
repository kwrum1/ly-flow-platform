ARG RUNTIME_IMAGE=ly-flow/server@sha256:6304f51cfa58d502e03255aeace1af8f02c3b53c3d8caae23ad34a77a3935eeb

FROM ${RUNTIME_IMAGE}

USER root

WORKDIR /app

RUN rm -f /app/ly-agent-linux-amd64 /app/ly-agent-linux-arm64 /app/ly-agent-windows-amd64.exe \
    && rm -rf /app/probe/rasp /app/agent/rasp

COPY server/ly-server /app/ly-server
COPY server/ly-agent-center /app/ly-agent-center
COPY agent/ly-agent /app/ly-agent
COPY agent/dist/ /app/agents/
COPY rules/ /etc/ly/rules/
COPY agent/rasp/python/ /app/agent/rasp/python/

RUN chmod +x /app/ly-server /app/ly-agent-center /app/ly-agent \
    && find /app/agents -type f -exec chmod +x {} \; \
    && find /app/agent/rasp/python -type d -name __pycache__ -prune -exec rm -rf {} + \
    && find /app/agent/rasp/python -type f \( -name '*.pyc' -o -name '*.pyo' \) -delete

EXPOSE 8080 8081

CMD ["/app/ly-server"]
