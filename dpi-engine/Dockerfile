FROM golang:1.21-bookworm AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libc6-dev && rm -rf /var/lib/apt/lists/*

ENV HTTP_PROXY=http://10.18.5.227:10808
ENV HTTPS_PROXY=http://10.18.5.227:10808
ENV http_proxy=http://10.18.5.227:10808
ENV https_proxy=http://10.18.5.227:10808
ENV GOPROXY=https://proxy.golang.org,https://goproxy.cn,direct

COPY pkg/ ./pkg/
COPY dpi-engine/ ./dpi-engine/

WORKDIR /build/dpi-engine

RUN go mod download && go mod verify && go mod tidy

RUN CGO_ENABLED=0 go build -ldflags '-w -s' -o ly-dpi-engine ./cmd/main.go

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates tzdata && rm -rf /var/lib/apt/lists/* \
    && useradd -m -u 1000 appuser

WORKDIR /app

COPY --from=builder /build/dpi-engine/ly-dpi-engine .
RUN chown appuser:appuser /app/ly-dpi-engine

USER appuser

EXPOSE 8080

ENTRYPOINT ["/app/ly-dpi-engine"]
