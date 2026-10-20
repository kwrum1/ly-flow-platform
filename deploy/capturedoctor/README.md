# Capture doctor

Runtime companion to `scripts/agent/lyprobe-preflight.sh`. It watches an
interface and the ly_probe process while capture is running.

## Metrics

- interface exists/up, MTU
- RX packets, drops, errors
- PPS and drop percentage from counter deltas
- `/proc/net/softnet_stat` drops/squeezed
- `ethtool -g` RX ring
- `ethtool -k` GRO/GSO
- `ethtool -S` RX missed/FIFO/over/no-buffer deltas
- PF_RING availability
- ly_probe process, PID and RSS

## Status file

Default path: `/var/lib/lyflow/capture-doctor.json`

```json
{
  "timestamp": "2026-10-19T11:20:00Z",
  "interface": "ens160",
  "status": "warn",
  "issues": [
    {"code": "ring_small", "severity": "warn", "message": "RX ring 1024 is below 2048"}
  ],
  "metrics": {"pps": 12000.5, "drop_pct": 0.02, "ring_rx": 1024},
  "process": {"running": true, "pid": 1234, "name": "lyprobe", "rss_kb": 20480},
  "restarted": false
}
```

Status is `ok`, `warn` or `critical`. One-shot exit codes: `0` ok, `1` warn,
`2` critical.

## Run once

```bash
/opt/lyflow/bin/lyflow-capturedoctor \
  -once -interface ens160 -process lyprobe \
  -output /tmp/capture-doctor.json
```

## Service

```bash
sudo install -d /etc/lyflow /var/lib/lyflow
sudo install -m 0755 /opt/lyflow/bin/lyflow-capturedoctor /opt/lyflow/bin/
sudo install -m 0644 deploy/capturedoctor/lyflow-capturedoctor.service /etc/systemd/system/
sudo install -m 0644 deploy/capturedoctor/capturedoctor.env.example /etc/lyflow/capturedoctor.env
sudo systemctl daemon-reload
sudo systemctl enable --now lyflow-capturedoctor
```

## Restart and alert safety

- Default: **no restart**, only status/issue reporting.
- `LYFLOW_CAPTURE_RESTART_COMMAND` is opt-in. When set, a restart happens only
  after `LYFLOW_CAPTURE_RESTART_AFTER` consecutive critical checks and never
  more often than `LYFLOW_CAPTURE_RESTART_COOLDOWN`.
- Before executing, the doctor logs `CRITICAL: executing configured restart` and
  records an `issues[].code = "restart"` entry. Restart is never silent.
- Set an alert command in `LYFLOW_CAPTURE_ALERT_COMMAND`; the JSON snapshot is
  written to its stdin on status transitions, critical states and restarts.
- A failed restart is recorded as `restart_failed` and does not loop within the
  cooldown.

## Threshold guidance

- `DROP_WARN=1.0`, `DROP_CRIT=5.0` are conservative starting points.
- `RING_MIN=2048` avoids the common 1024-entry default.
- GRO/GSO warnings are advisory; changing offloads is a host-level operation and
  must be recorded/rolled back.
- PF_RING is optional; AF_PACKET fallback is reported as a warning, not critical.

## Tests

```bash
cd agent
go test ./capturedoctor -count=1
```

The package tests use a fake probe for healthy/warn/critical, drop deltas,
missing process, offload/ring warnings, restart threshold/cooldown and atomic
status writes. Run the real probe on the test VM with `-once` against `ens160`
and a nonexistent interface to verify diagnostics.
