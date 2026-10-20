ARG RUNTIME_IMAGE=ubuntu:24.04
FROM ${RUNTIME_IMAGE}

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       redis-server ca-certificates \
    && rm -rf /var/lib/apt/lists/*

EXPOSE 6379
CMD ["redis-server", "/etc/redis/redis.conf"]
