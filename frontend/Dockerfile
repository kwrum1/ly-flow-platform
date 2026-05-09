# Vue3 Frontend Dockerfile
# Node.js based

FROM node:20 AS builder

WORKDIR /build

COPY frontend/package*.json ./

RUN npm install

COPY frontend/ ./

RUN npm run build

# Nginx serving
FROM nginx:alpine

COPY --from=builder /build/dist /usr/share/nginx/html

# Nginx 配置
RUN echo 'server { \
    listen 3000; \
    server_name _; \
    root /usr/share/nginx/html; \
    index index.html; \
    \
    location / { \
        try_files $uri $uri/ /index.html; \
    } \
    \
    location /api/ { \
        proxy_pass http://ly-server:8080/; \
        proxy_set_header Host $host; \
    } \
    \
    location /ws { \
        proxy_pass http://ly-server:8080/ws; \
        proxy_http_version 1.1; \
        proxy_set_header Upgrade $http_upgrade; \
        proxy_set_header Connection "upgrade"; \
    } \
}' > /etc/nginx/conf.d/default.conf

EXPOSE 3000

CMD ["nginx", "-g", "daemon off;"]