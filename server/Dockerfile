ARG RUNTIME_IMAGE=ly-flow/server:latest

FROM ${RUNTIME_IMAGE}

USER root

WORKDIR /app

COPY server/ly-server /app/ly-server
COPY server/ly-agent-center /app/ly-agent-center
COPY agent/ly-agent /app/ly-agent
COPY rules/ /etc/ly/rules/
COPY probe/rasp/ /app/probe/rasp/

RUN chmod +x /app/ly-server /app/ly-agent-center /app/ly-agent \
    && find /app/probe/rasp -name '*.sh' -exec chmod +x {} \;

EXPOSE 8080 8081

CMD ["/app/ly-server"]
