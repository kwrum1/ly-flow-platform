FROM gitea/act_runner@sha256:b5c35d6bdbb9bb25e531230bfc7cc663cb751406cbec90a2a891b85fea54de86 AS act-runner

FROM docker.gitea.com/runner-images@sha256:58ea92624c7c09582e05594d95488331045053d3a3f34cf09649f2a32313a614

ARG GO_VERSION=1.26.5
ARG GO_SHA256=5c2c3b16caefa1d968a94c1daca04a7ca301a496d9b086e17ad77bb81393f053
ARG NODE_VERSION=22.22.2

USER root

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl libpcap-dev python3-yaml tini xz-utils \
    && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    architecture="$(dpkg --print-architecture)"; \
    case "$architecture" in \
      amd64) go_arch=amd64; node_arch=x64 ;; \
      arm64) go_arch=arm64; node_arch=arm64 ;; \
      *) echo "unsupported architecture: $architecture" >&2; exit 1 ;; \
    esac; \
    go_archive="go${GO_VERSION}.linux-${go_arch}.tar.gz"; \
    curl -fsSLO "https://go.dev/dl/${go_archive}"; \
    printf '%s  %s\n' "$GO_SHA256" "$go_archive" | sha256sum -c -; \
    rm -rf /usr/local/go; \
    tar -C /usr/local -xzf "$go_archive"; \
    rm -f "$go_archive"; \
    node_archive="node-v${NODE_VERSION}-linux-${node_arch}.tar.xz"; \
    curl -fsSLO "https://nodejs.org/dist/v${NODE_VERSION}/${node_archive}"; \
    curl -fsSLO "https://nodejs.org/dist/v${NODE_VERSION}/SHASUMS256.txt"; \
    grep " ${node_archive}$" SHASUMS256.txt | sha256sum -c -; \
    tar -C /opt -xJf "$node_archive"; \
    ln -s "/opt/node-v${NODE_VERSION}-linux-${node_arch}" /opt/node; \
    rm -f "$node_archive" SHASUMS256.txt

COPY --from=act-runner /usr/local/bin/act_runner /usr/local/bin/act_runner
COPY --from=act-runner /usr/local/bin/run.sh /usr/local/bin/run.sh

ENV PATH="/usr/local/go/bin:/opt/node/bin:${PATH}"

WORKDIR /data
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/run.sh"]
