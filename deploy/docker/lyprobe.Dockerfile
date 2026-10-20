ARG RUNTIME_IMAGE=ubuntu:24.04
FROM ${RUNTIME_IMAGE}

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       libpcap0.8 libpcre3 procps ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/lyflow
COPY deploy/build-context/lyprobe /opt/lyflow/bin/lyprobe
COPY deploy/build-context/liblyprobe-1.0.0.so /opt/lyflow/bin/liblyprobe-1.0.0.so
COPY deploy/build-context/servicePlugin.so /opt/lyflow/plugins/servicePlugin.so
RUN chmod 0755 /opt/lyflow/bin/lyprobe /opt/lyflow/plugins/servicePlugin.so

ENTRYPOINT ["/opt/lyflow/bin/lyprobe"]
