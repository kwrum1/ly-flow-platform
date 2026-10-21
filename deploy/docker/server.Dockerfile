ARG RUNTIME_IMAGE=redis:7-alpine
FROM ${RUNTIME_IMAGE}

ARG TARGETARCH
USER root
WORKDIR /app

COPY server/dist/linux/${TARGETARCH}/ly-server /app/ly-server
COPY server/dist/linux/${TARGETARCH}/ly-agent-center /app/ly-agent-center
COPY agent/dist/linux/${TARGETARCH}/ly-agent /app/ly-agent
COPY agent/dist/ /app/agents/
COPY rules/ /etc/ly/rules/
COPY probe/rasp/ /app/probe/rasp/
COPY agent/rasp/python/ /app/agent/rasp/python/

RUN chmod +x /app/ly-server /app/ly-agent-center /app/ly-agent \
    && find /app/agents -type f -exec chmod +x {} \; \
    && find /app/agent/rasp/python -type d -name __pycache__ -prune -exec rm -rf {} + \
    && find /app/agent/rasp/python -type f \( -name '*.pyc' -o -name '*.pyo' \) -delete

EXPOSE 8080 8081
CMD ["/app/ly-server"]
