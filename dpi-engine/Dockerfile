ARG RUNTIME_IMAGE=redis@sha256:9de71018be8413f419688ac34e19dbac432d1c6d9593d2ded99a82eebefeb18f

FROM ${RUNTIME_IMAGE}

WORKDIR /app

COPY dpi-engine/ly-dpi-engine .
RUN chmod +x /app/ly-dpi-engine

USER redis

EXPOSE 8080

ENTRYPOINT ["/app/ly-dpi-engine"]
