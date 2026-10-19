#!/usr/bin/env bash
set -euo pipefail
ssh -o BatchMode=yes root@10.1.18.100 'bash -s' <<'REMOTE'
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@10.1.18.126 'bash -s' <<'INNER'
set +e
KEY=$(python3 - <<'PY'
import json
print(json.load(open('/var/lib/lyflow/evidence/artifacts/art-f3c092b248a686fb0cc15aa434ea842eb785c49ed88c258147fcb7a8c8498d90.json'))['object_key'].replace('/', '-'))
PY
)
echo "key=$KEY"
curl -s -o /tmp/evidence-object -w 'filer_object=%{http_code} size=%{size_download}\n' "http://127.0.0.1:18888/lyflow/evidence/$KEY"
cat /tmp/evidence-object
echo
curl -sk -o /dev/null -w 'legacy_events=%{http_code}\n' https://127.0.0.1/api/v1/events
curl -sk -o /dev/null -w 'legacy_security_events=%{http_code}\n' https://127.0.0.1/api/v1/security-events
curl -sk -o /dev/null -w 'legacy_response=%{http_code}\n' https://127.0.0.1/api/v1/response/candidates
INNER
REMOTE
