ARG RUNTIME_IMAGE=docker.io/jasonish/suricata:latest
FROM ${RUNTIME_IMAGE}

USER root
RUN mkdir -p /var/lib/suricata/rules /var/log/suricata

COPY deploy/suricata/lyflow-suricata-profile.yaml /etc/suricata/lyflow-suricata-profile.yaml
COPY deploy/suricata/lyflow-suricata.rules /var/lib/suricata/rules/lyflow-suricata.rules

ENTRYPOINT ["suricata"]
