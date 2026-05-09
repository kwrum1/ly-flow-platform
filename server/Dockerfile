# ly-server Dockerfile - using pre-built binary
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates tzdata && rm -rf /var/lib/apt/lists/* \
    && useradd -m -u 1000 appuser

WORKDIR /app

COPY server/ly-server /app/ly-server
COPY rules/ /etc/ly/rules/

RUN chown appuser:appuser /app/ly-server /etc/ly/rules -R

USER appuser

EXPOSE 8080 8081

ENTRYPOINT ["/app/ly-server"]