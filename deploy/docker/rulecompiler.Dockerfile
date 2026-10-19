ARG RUNTIME_IMAGE=alpine:3.20
FROM ${RUNTIME_IMAGE}

RUN apk add --no-cache ca-certificates
WORKDIR /opt/lyflow
COPY deploy/build-context/lyflow-rulecompiler /opt/lyflow/bin/lyflow-rulecompiler
RUN chmod 0755 /opt/lyflow/bin/lyflow-rulecompiler

ENTRYPOINT ["/opt/lyflow/bin/lyflow-rulecompiler"]
