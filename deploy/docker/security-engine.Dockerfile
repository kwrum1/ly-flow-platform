ARG RUNTIME_IMAGE=redis:7-alpine
FROM ${RUNTIME_IMAGE}

ARG TARGETARCH
USER root
WORKDIR /app

COPY security-engine/dist/linux/${TARGETARCH}/ly-security-engine /app/ly-security-engine
RUN chmod +x /app/ly-security-engine \
    && mkdir -p /var/lib/lyflow/audit \
    && chown redis:redis /var/lib/lyflow/audit \
    && chmod 0700 /var/lib/lyflow/audit

USER redis
EXPOSE 8080
ENTRYPOINT ["/app/ly-security-engine"]
