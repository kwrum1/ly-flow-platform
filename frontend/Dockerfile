ARG RUNTIME_IMAGE=nginx:1.27-alpine

FROM ${RUNTIME_IMAGE}

USER root

COPY frontend/dist /usr/share/nginx/html

ENV LY_SERVER_UPSTREAM=http://ly-server:8080
RUN apk add --no-cache openssl \
    && mkdir -p /etc/nginx/templates /etc/nginx/ssl \
    && openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
        -keyout /etc/nginx/ssl/lyflow.key \
        -out /etc/nginx/ssl/lyflow.crt \
        -subj "/CN=lyflow.local/O=LyFlow Security Console" \
        -addext "subjectAltName=DNS:localhost,DNS:lyflow.local,IP:127.0.0.1" \
    && echo 'server { \
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
