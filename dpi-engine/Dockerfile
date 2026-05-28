ARG RUNTIME_IMAGE=redis:7-alpine

FROM ${RUNTIME_IMAGE}

RUN apk add --no-cache ca-certificates tzdata \
    && true

WORKDIR /app

COPY dpi-engine/ly-dpi-engine .
RUN chmod +x /app/ly-dpi-engine

USER redis

EXPOSE 8080

ENTRYPOINT ["/app/ly-dpi-engine"]
