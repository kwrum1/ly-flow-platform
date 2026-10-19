ARG BUILDER_IMAGE=docker.1ms.run/library/rust:1.85-bookworm
ARG RUNTIME_IMAGE=ubuntu:24.04
FROM ${BUILDER_IMAGE} AS builder

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       libssl-dev pkg-config ca-certificates cmake \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY frontend/pingora/Cargo.toml frontend/pingora/Cargo.lock ./
COPY frontend/pingora/src ./src
RUN cargo build --release --locked

FROM ${RUNTIME_IMAGE}

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       libssl3 ca-certificates openssl wget \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /usr/share/lyflow/web /etc/lyflow/ssl

COPY --from=builder /build/target/release/lyflow-frontend /usr/local/bin/lyflow-frontend
COPY frontend/dist/ /usr/share/lyflow/web/
RUN openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
      -keyout /etc/lyflow/ssl/lyflow.key -out /etc/lyflow/ssl/lyflow.crt \
      -subj "/CN=lyflow.local/O=LyFlow Security Console" \
      -addext "subjectAltName=DNS:localhost,DNS:lyflow.local,IP:127.0.0.1" \
    && chmod 0600 /etc/lyflow/ssl/lyflow.key \
    && chmod 0644 /etc/lyflow/ssl/lyflow.crt

ENV LYFLOW_WEB_ROOT=/usr/share/lyflow/web \
    LYFLOW_TLS_CERT=/etc/lyflow/ssl/lyflow.crt \
    LYFLOW_TLS_KEY=/etc/lyflow/ssl/lyflow.key \
    LY_SERVER_HOST=ly-server \
    LY_SERVER_PORT=8080

EXPOSE 80 443
ENTRYPOINT ["/usr/local/bin/lyflow-frontend"]



