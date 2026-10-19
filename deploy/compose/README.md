# LyFlow Compose profiles

Two deployment modes:

- **lean** (default): core services + ClickHouse/PostgreSQL/Redis/Web.
- **full-private**: lean + Elkeid HUB/Console/MongoDB/Kafka. This overlay is
  private and must not be published with public builds.

## Prerequisites

- Linux host with Docker Engine + Compose v2.
- Same architecture for all images.
- Core images from the existing LyFlow image pipeline:
  `ly-flow/server`, `ly-flow/security-engine`, `ly-flow/frontend`.
- Sensor images can be built from the current artifacts:

```bash
cd /path/to/lyflow
LYFLOW_ARTIFACTS=/opt/lyflow/artifacts \
  bash deploy/compose/build-sensor-images.sh
```

This builds `ly-flow/lyprobe`, `ly-flow/capturedoctor` and
`ly-flow/rulecompiler`. Set `LYFLOW_BUILD_SURICATA=1` to also build the
Suricata image (requires the upstream `jasonish/suricata` base image).

## Lean quick start

```bash
cd deploy/compose
cp lean.env.example lean.env
# edit lean.env: passwords, management interface, capture interface,
# LYPROBE_TEMPLATE, image tags
./lyflowctl bootstrap
./lyflowctl config
./lyflowctl up
```

`bootstrap` creates `lean.env` with random secrets if missing, prepares
`runtime/fp-patterns`, `runtime/rules/source` and `runtime/status`, and seeds
the generated LyFlow sample rules. For real ET/CRS rules, put source files in
`runtime/rules/source`; the rule compiler watches them and updates
`runtime/fp-patterns/threat.json` atomically.

Open `https://<host>/` for the UI. The default admin password is generated into
`lean.env`; change it before exposing the host.

## Capture profile

The capture services run with `network_mode: host` and require root/Docker
capabilities:

- `lyprobe-sensor`: `NET_RAW`, `NET_ADMIN`
- `suricata-sensor`: `NET_RAW`, `NET_ADMIN`, `SYS_NICE`
- `lyflow-capturedoctor`: `NET_ADMIN` + host PID namespace
- `lyflow-rulecompiler`: writes the shared `runtime/fp-patterns` directory

Set in `lean.env`:

```text
LYPROBE_INTERFACE=ens160
SURICATA_INTERFACE=ens160
LYPROBE_COLLECTOR=127.0.0.1:9995
LYPROBE_TEMPLATE=%PROTOCOL %IPV4_SRC_ADDR %IPV4_DST_ADDR %L4_SRC_PORT %L4_DST_PORT %THREAT_TYPE %THREAT_NAME %THREAT_VERS
```

The `%PROTOCOL` field is mandatory; without it ly_probe disables protocol
filtering and `"protocol":"tcp"`/`"udp"` threat rules cannot match.

The sensor images expect `/opt/lyflow/fp-patterns` to contain the upstream
`service.json`, `device.json`, `os.json`, `midware.json` plus the generated
`threat.json`. `bootstrap` copies them from `LYPROBE_SOURCE_DIR` when available.

## Full-private overlay

```bash
LYFLOW_PROFILE=full-private ./lyflowctl config
LYFLOW_PROFILE=full-private ./lyflowctl up
```

Set `ELKEID_HUB_IMAGE`, `ELKEID_CONSOLE_IMAGE` and `ELKEID_PRIVATE_DIR` in
`lean.env`. The private overlay is not included by `lean.yml`; do not copy
`private/elkeid` into public artifacts.

## Upgrade, rollback and backup

```bash
./lyflowctl upgrade   # back up env, pull images, restart
./lyflowctl rollback  # restore latest env backup, restart
./lyflowctl backup    # PostgreSQL dump under deploy/compose/backups/
```

`upgrade`/`rollback` retain named volumes. Destructive volume removal requires
an explicit snapshot/confirmation and is intentionally not automated.

## Validation

```bash
./lyflowctl config
docker compose -f lean.yml --profile core --profile capture config
docker compose -f lean.yml -f full-private.yml \
  --profile core --profile capture --profile full-private \
  --env-file lean.env config
```

## Current limitations

- Core server/frontend image builds remain in the existing CI/build pipeline;
  this directory packages deployment and the new sensor images.
- Vector/SeaweedFS are not added until their configs and ingestion paths are
  validated end to end.
- 6 vCPU / 8 GiB is a lean test baseline; T4.6 measured a combined 20k EPS +
  1Gbps ingest at ~18.5k EPS. Use 8+ vCPU / 16+ GiB for formal capacity
  acceptance.
