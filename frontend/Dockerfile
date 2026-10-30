ARG RUNTIME_IMAGE=ly-flow/frontend@sha256:98767ee96d258cdd023b6a620a4b1b44a2239a8f2742f51dc91d240615740707

FROM ${RUNTIME_IMAGE}

USER root

COPY frontend/dist /usr/share/nginx/html
COPY frontend/docker-entrypoint.d/40-lyflow-tls.sh /docker-entrypoint.d/40-lyflow-tls.sh

ENV LY_SERVER_UPSTREAM=http://ly-server:8080
RUN if ! command -v openssl >/dev/null 2>&1; then \
        if command -v apk >/dev/null 2>&1; then \
            apk add --no-cache openssl; \
        elif command -v apt-get >/dev/null 2>&1; then \
            apt-get update \
            && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssl \
            && rm -rf /var/lib/apt/lists/*; \
        else \
            echo 'unable to install openssl in frontend runtime image' >&2; exit 1; \
        fi; \
    fi \
    && mkdir -p /etc/nginx/templates /etc/nginx/ssl \
    && chmod 0755 /docker-entrypoint.d/40-lyflow-tls.sh \
    && echo 'server { \
    listen 80; \
    listen [::]:80; \
    server_name _; \
    return 308 https://$host$request_uri; \
} \
\
server { \
    listen 443 ssl; \
    server_name _; \
    ssl_certificate /etc/nginx/ssl/lyflow.crt; \
    ssl_certificate_key /etc/nginx/ssl/lyflow.key; \
    ssl_protocols TLSv1.2 TLSv1.3; \
    ssl_prefer_server_ciphers off; \
    root /usr/share/nginx/html; \
    index index.html; \
    resolver 127.0.0.11 valid=10s ipv6=off; \
    set $ly_server_upstream ${LY_SERVER_UPSTREAM}; \
    add_header X-Content-Type-Options nosniff always; \
    add_header X-Frame-Options DENY always; \
    add_header Referrer-Policy no-referrer always; \
    add_header X-Permitted-Cross-Domain-Policies none always; \
    \
    location /assets/ { \
        try_files $uri =404; \
        expires 1y; \
    } \
    \
    location / { \
        try_files $uri /index.html; \
    } \
    \
    location /api/ { \
        proxy_pass $ly_server_upstream; \
        proxy_set_header Host $host; \
        proxy_set_header X-Forwarded-Host $host; \
        proxy_set_header X-Forwarded-Proto https; \
    } \
    \
    location /ws/ { \
        proxy_pass $ly_server_upstream; \
        proxy_http_version 1.1; \
        proxy_set_header Upgrade $http_upgrade; \
        proxy_set_header Connection "upgrade"; \
        proxy_set_header Host $host; \
        proxy_set_header X-Forwarded-Host $host; \
        proxy_set_header X-Forwarded-Proto https; \
    } \
}' > /etc/nginx/templates/default.conf.template

EXPOSE 443

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD wget --no-check-certificate -q -O /dev/null https://127.0.0.1/ || exit 1

CMD ["nginx", "-g", "daemon off;"]
