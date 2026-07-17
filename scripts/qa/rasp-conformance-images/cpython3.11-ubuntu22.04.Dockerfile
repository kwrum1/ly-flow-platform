FROM ubuntu@sha256:0e0a0fc6d18feda9db1590da249ac93e8d5abfea8f4c3c0c849ce512b5ef8982

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential ca-certificates curl libbz2-dev libffi-dev liblzma-dev libncursesw5-dev libreadline-dev libsqlite3-dev libssl-dev tk-dev uuid-dev zlib1g-dev \
    && curl --fail --show-error --location --retry 5 --output /tmp/Python-3.11.13.tgz https://www.python.org/ftp/python/3.11.13/Python-3.11.13.tgz \
    && printf '%s  %s\n' '0f1a22f4dfd34595a29cf69ee7ea73b9eff8b1cc89d7ab29b3ab0ec04179dad8' /tmp/Python-3.11.13.tgz | sha256sum --check --strict \
    && tar -xzf /tmp/Python-3.11.13.tgz -C /tmp \
    && cd /tmp/Python-3.11.13 \
    && ./configure --prefix=/usr/local --with-ensurepip=no \
    && make -j"$(nproc)" \
    && make install \
    && ln -sf /usr/local/bin/python3.11 /usr/local/bin/python \
    && cd / \
    && rm -rf /tmp/Python-3.11.13 /tmp/Python-3.11.13.tgz /var/lib/apt/lists/* \
    && apt-get purge -y --auto-remove build-essential curl libbz2-dev libffi-dev liblzma-dev libncursesw5-dev libreadline-dev libsqlite3-dev libssl-dev tk-dev uuid-dev zlib1g-dev

CMD ["python", "--version"]
