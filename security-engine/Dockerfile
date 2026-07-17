ARG RUNTIME_IMAGE=ly-flow/dpi-engine@sha256:480680c4d2ab620aeb5852a52c472d6b7439777a52bcd27b4ccc32e02f5f5260

FROM ${RUNTIME_IMAGE}

USER root
WORKDIR /app

COPY security-engine/ly-security-engine .
RUN chmod +x /app/ly-security-engine

USER redis

EXPOSE 8080

ENTRYPOINT ["/app/ly-security-engine"]
