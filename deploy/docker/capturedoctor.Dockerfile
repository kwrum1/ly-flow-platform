ARG RUNTIME_IMAGE=ubuntu:24.04
FROM ${RUNTIME_IMAGE}

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       ethtool procps iproute2 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/lyflow
COPY deploy/build-context/lyflow-capturedoctor /opt/lyflow/bin/lyflow-capturedoctor
RUN chmod 0755 /opt/lyflow/bin/lyflow-capturedoctor \
    && mkdir -p /var/lib/lyflow

ENTRYPOINT ["/opt/lyflow/bin/lyflow-capturedoctor"]
