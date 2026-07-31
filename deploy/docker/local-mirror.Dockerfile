FROM alpine:3.20

ARG TARGETARCH
WORKDIR /app
COPY agent/dist/linux/${TARGETARCH}/ly-agent /app/ly-agent
RUN chmod +x /app/ly-agent
ENTRYPOINT ["/app/ly-agent"]
