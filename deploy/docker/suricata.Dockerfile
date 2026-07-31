FROM debian:bookworm-slim

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates procps suricata \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /var/lib/suricata/rules /var/log/suricata

COPY deploy/suricata/lyflow-suricata-profile.yaml /etc/suricata/lyflow-suricata-profile.yaml
COPY deploy/suricata/lyflow-suricata.rules /var/lib/suricata/rules/lyflow-suricata.rules

ENTRYPOINT ["suricata"]
