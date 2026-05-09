FROM golang:1.21-bookworm AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libc6-dev libpcap-dev linux-headers-amd64 make clang llvm && rm -rf /var/lib/apt/lists/*

ENV HTTP_PROXY=http://10.18.5.227:10808
ENV HTTPS_PROXY=http://10.18.5.227:10808
ENV http_proxy=http://10.18.5.227:10808
ENV https_proxy=http://10.18.5.227:10808
ENV GOPROXY=https://proxy.golang.org,direct

COPY pkg/ ./pkg/
COPY probe/ ./probe/

WORKDIR /build/probe

RUN go mod download && go mod verify

RUN CGO_ENABLED=1 go build -ldflags '-w -s' -o ly-probe ./cmd/main.go

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates tzdata libpcap0.8 && rm -rf /var/lib/apt/lists/* \
    && useradd -m -u 1000 appuser

WORKDIR /app

COPY --from=builder /build/probe/ly-probe .
COPY rules/ /etc/ly/rules/

RUN chown appuser:appuser /app/ly-probe /etc/ly/rules -R

EXPOSE 8080

ENTRYPOINT ["/app/ly-probe"]
