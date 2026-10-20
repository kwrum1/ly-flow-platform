# Native components

Wazuh manager and the OpenRASP Java engine are native services on the test /
single-node host. They are deliberately not linked into the LyFlow Go binary.

## Wazuh manager

The manager runs as `wazuh-manager` systemd and writes alerts to
`/var/ossec/logs/alerts/alerts.json`. The LyFlow agent adapter maps those alerts
into component alerts and XDR.

```bash
sudo WAZUH_PACKAGE=/opt/lyflow/artifacts/wazuh/wazuh-manager_4.9.2-1_amd64.deb \
  bash deploy/native/install-wazuh-manager.sh
```

## OpenRASP Java engine

Place the official `rasp-java.tar.gz` at `/opt/lyflow/artifacts/openrasp/` and
run:

```bash
sudo OPENRASP_ARCHIVE=/opt/lyflow/artifacts/openrasp/rasp-java.tar.gz \
  bash deploy/native/install-openrasp-java.sh
```

The alarm bridge tails `/opt/openrasp/logs/alarm/alarm.log` and forwards
normalized events to the local RASP bridge. It is installed by:

```bash
sudo bash scripts/native/install-openrasp-bridge.sh
```

## SeaweedFS evidence filer

The Compose profiles start SeaweedFS with the `evidence` profile:

```bash
docker compose -f deploy/compose/lean.yml --profile core --profile evidence up -d
```

Set `EVIDENCE_OBJECT_STORE=filer` and
`EVIDENCE_FILER_URL=http://seaweedfs:18888` for `ly-server`.
