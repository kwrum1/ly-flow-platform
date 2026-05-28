ARG RUNTIME_IMAGE=ly-flow/dpi-engine:latest

FROM ${RUNTIME_IMAGE}

USER root
WORKDIR /app

COPY security-engine/ly-security-engine .
RUN chmod +x /app/ly-security-engine

USER redis

EXPOSE 8080

ENTRYPOINT ["/app/ly-security-engine"]
