ARG RUNTIME_IMAGE=ly-flow/server:latest

FROM ${RUNTIME_IMAGE}

USER root

WORKDIR /app

COPY agent/ly-agent /app/ly-agent
COPY containers/runtime-libs/ /opt/ly-runtime-libs/
COPY containers/security-engines/bin/suricata containers/security-engines/bin/wazuh-agentd containers/security-engines/bin/yara containers/security-engines/bin/ly-rasp-bridge /usr/local/bin/

RUN ln -sf /opt/ly-runtime-libs/libpcap.so.1.10.5 /opt/ly-runtime-libs/libpcap.so.0.8 \
    && chmod +x /usr/local/bin/suricata /usr/local/bin/wazuh-agentd /usr/local/bin/yara /usr/local/bin/ly-rasp-bridge \
    && chmod +x /app/ly-agent

ENV LD_LIBRARY_PATH=/opt/ly-runtime-libs

EXPOSE 8080

ENTRYPOINT ["/opt/ly-runtime-libs/ld-linux-x86-64.so.2", "--library-path", "/opt/ly-runtime-libs", "/app/ly-agent"]
