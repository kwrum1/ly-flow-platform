#!/bin/sh
set -eu

while IFS= read -r line; do
  line=$(printf '%s' "$line" | tr -d '\r')
  [ -z "$line" ] && break
done

body=$(printf '{"status":"ok","role":"%s","hostname":"%s"}\n' "$LAB_ROLE" "$HOSTNAME")
length=$(printf '%s\n' "$body" | wc -c | tr -d ' ')
printf 'HTTP/1.1 200 OK\r\n'
printf 'Content-Type: application/json\r\n'
printf 'Content-Length: %s\r\n' "$length"
printf 'Connection: close\r\n\r\n'
printf '%s\n' "$body"
