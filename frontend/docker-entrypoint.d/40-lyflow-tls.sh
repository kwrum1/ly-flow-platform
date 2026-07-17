#!/bin/sh
set -eu

certificate=/etc/nginx/ssl/lyflow.crt
private_key=/etc/nginx/ssl/lyflow.key

if [ ! -s "$certificate" ] || [ ! -s "$private_key" ]; then
    openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
        -keyout "$private_key" \
        -out "$certificate" \
        -subj "/CN=lyflow.local/O=LyFlow Security Console" \
        -addext "subjectAltName=DNS:localhost,DNS:lyflow.local,IP:127.0.0.1"
    chmod 0600 "$private_key"
    chmod 0644 "$certificate"
fi
