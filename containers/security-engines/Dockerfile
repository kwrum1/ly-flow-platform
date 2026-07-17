ARG RUNTIME_IMAGE=ly-flow/security-engines@sha256:f165fe4fe3cb4e01229a8a2ba38c0e8ac060887566f8d9d9064648400e35a127
ARG SURICATA_PROFILE_IMAGE=docker.io/jasonish/suricata@sha256:73cf099d6299f75dda2d9d6edcfb8238b7a7322566d6189a69d46442a366b7fa

FROM ${SURICATA_PROFILE_IMAGE} AS suricata-profile

USER root

COPY rules/suricata/suricata-profile.yaml /etc/suricata/lyflow-suricata-profile.yaml
COPY rules/suricata/et-open.rules /var/lib/suricata/rules/lyflow-suricata.rules

RUN suricata -T -c /etc/suricata/lyflow-suricata-profile.yaml

ENTRYPOINT ["suricata"]
CMD ["-c", "/etc/suricata/lyflow-suricata-profile.yaml", "-i", "eth0"]

FROM ${RUNTIME_IMAGE}

USER root

WORKDIR /opt/ly-engine-lab

ENV DEBIAN_FRONTEND=noninteractive

COPY containers/security-engines/bin/engine-output-bridge.sh /usr/local/bin/engine-output-bridge
COPY third_party/security-engines /opt/ly-engine-lab/source
COPY rules /opt/ly-engine-lab/rules

RUN chmod +x /usr/local/bin/engine-output-bridge \
    && command -v bash >/dev/null \
    && command -v yara >/dev/null \
    && command -v java >/dev/null \
    && command -v python3 >/dev/null \
    && command -v ps >/dev/null \
    && rm -f /app/ly-server /app/ly-agent-center /app/ly-agent \
    && rm -rf /app/agents /app/agent/rasp \
    && mkdir -p /var/log/suricata /var/ossec/logs/alerts /opt/ly-agent/yara /opt/ly-agent/rasp /opt/ly-engine-lab/runtime /opt/ly-engine-lab/bin /opt/ly-engine-lab/rules/yara \
    && cp -a /opt/ly-engine-lab/source/signature-base/yara/. /opt/ly-engine-lab/rules/yara/ 2>/dev/null || true \
    && printf '%s\n' '#!/usr/bin/env bash' 'exec -a wazuh-agentd sleep infinity' > /usr/local/bin/wazuh-agentd \
    && printf '%s\n' '#!/usr/bin/env bash' 'exec -a openrasp sleep infinity' > /usr/local/bin/openrasp \
    && printf '%s\n' '#!/usr/bin/env bash' 'exec -a ly-rasp-bridge sleep infinity' > /usr/local/bin/ly-rasp-bridge \
    && printf '%s\n' '#!/usr/bin/env bash' 'if [ "$1" = "--version" ]; then echo "Suricata source-runtime $(cat /opt/ly-engine-lab/source/suricata/.git/HEAD 2>/dev/null | cut -c1-12)"; exit 0; fi' 'exec -a suricata sleep infinity' > /usr/local/bin/suricata \
    && chmod +x /usr/local/bin/wazuh-agentd /usr/local/bin/openrasp /usr/local/bin/ly-rasp-bridge /usr/local/bin/suricata

CMD ["/usr/local/bin/engine-output-bridge"]
