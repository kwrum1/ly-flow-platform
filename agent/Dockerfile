FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

COPY agent/ly-agent /app/ly-agent

RUN chmod +x /app/ly-agent

EXPOSE 8080

ENTRYPOINT ["/app/ly-agent"]
