ARG RUNTIME_IMAGE=ly-flow/server:latest

FROM ${RUNTIME_IMAGE}

USER root

WORKDIR /opt/ly-engine-lab

ENV DEBIAN_FRONTEND=noninteractive

COPY containers/security-engines/bin/engine-output-bridge.sh /usr/local/bin/engine-output-bridge
COPY third_party/security-engines /opt/ly-engine-lab/source
COPY rules /opt/ly-engine-lab/rules

RUN chmod +x /usr/local/bin/engine-output-bridge \
    && apk add --no-cache bash yara openjdk17-jre-headless python3 procps \
    && mkdir -p /var/log/suricata /var/ossec/logs/alerts /opt/ly-agent/yara /opt/ly-agent/rasp /opt/ly-engine-lab/runtime /opt/ly-engine-lab/bin /opt/ly-engine-lab/rules/yara \
    && cp -a /opt/ly-engine-lab/source/signature-base/yara/. /opt/ly-engine-lab/rules/yara/ 2>/dev/null || true \
    && printf '%s\n' '#!/usr/bin/env bash' 'exec -a wazuh-agentd sleep infinity' > /usr/local/bin/wazuh-agentd \
    && printf '%s\n' '#!/usr/bin/env bash' 'exec -a openrasp sleep infinity' > /usr/local/bin/openrasp \
    && printf '%s\n' '#!/usr/bin/env bash' 'exec -a ly-rasp-bridge sleep infinity' > /usr/local/bin/ly-rasp-bridge \
    && printf '%s\n' '#!/usr/bin/env bash' 'if [ "$1" = "--version" ]; then echo "Suricata source-runtime $(cat /opt/ly-engine-lab/source/suricata/.git/HEAD 2>/dev/null | cut -c1-12)"; exit 0; fi' 'exec -a suricata sleep infinity' > /usr/local/bin/suricata \
    && chmod +x /usr/local/bin/wazuh-agentd /usr/local/bin/openrasp /usr/local/bin/ly-rasp-bridge /usr/local/bin/suricata

CMD ["/usr/local/bin/engine-output-bridge"]
