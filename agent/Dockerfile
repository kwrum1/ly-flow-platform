ARG RUNTIME_IMAGE=ly-flow/server@sha256:6304f51cfa58d502e03255aeace1af8f02c3b53c3d8caae23ad34a77a3935eeb

FROM ${RUNTIME_IMAGE}

ARG AGENT_RELEASE_DIR=agent/dist/release

USER root

WORKDIR /app

RUN rm -f /app/ly-server /app/ly-agent-center /app/ly-agent \
    && rm -rf /app/agents /app/agent/rasp

COPY ${AGENT_RELEASE_DIR}/ly-agent /app/ly-agent
COPY ${AGENT_RELEASE_DIR}/agent.yaml /opt/ly-agent/etc/agent.yaml
COPY ${AGENT_RELEASE_DIR}/agent-binary.digest.json ${AGENT_RELEASE_DIR}/agent-config.digest.json ${AGENT_RELEASE_DIR}/agent-integrity-root.pem /etc/lyflow/trust/
COPY containers/runtime-libs/ /opt/ly-runtime-libs/
COPY containers/security-engines/bin/suricata containers/security-engines/bin/wazuh-agentd containers/security-engines/bin/yara containers/security-engines/bin/ly-rasp-bridge /usr/local/bin/

RUN ln -sf /opt/ly-runtime-libs/libpcap.so.1.10.5 /opt/ly-runtime-libs/libpcap.so.0.8 \
    && chmod +x /usr/local/bin/suricata /usr/local/bin/wazuh-agentd /usr/local/bin/yara /usr/local/bin/ly-rasp-bridge \
    && chmod +x /app/ly-agent \
    && ln -s agent-integrity-root.pem /etc/lyflow/trust/agent-binary-root.pem \
    && ln -s agent-integrity-root.pem /etc/lyflow/trust/agent-config-root.pem

ENV LD_LIBRARY_PATH=/opt/ly-runtime-libs \
    AGENT_BINARY_PATH=/app/ly-agent

EXPOSE 8080

ENTRYPOINT ["/app/ly-agent"]
