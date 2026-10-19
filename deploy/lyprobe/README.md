# ly_probe sensor integration

LyFlow keeps upstream `ly_probe` as an **external process**. The agent supervisor
owns its lifecycle; this directory contains packaging and configuration.

## Files

- `lyprobe.service` — systemd unit for a host sensor.
- `lyprobe.env.example` — interface, collector, NetFlow template and extra args.
- `scripts/agent/lyprobe-preflight.sh` — capture preflight (root, interface,
  runtime libraries, libpcap, offloads, RX ring, PF_RING availability).
- `scripts/dev/lyprobe-build.sh` — build upstream `ly_probe` in an Ubuntu 24.04
  container and publish the sensor bundle to `/opt/lyflow/artifacts/lyprobe`.
- `scripts/dev/lyprobe-netflow-smoke.sh` — live capture + NetFlow export smoke
  test with a local UDP collector.
- `patches/lyprobe/0001-hot-reload.patch` — thin servicePlugin reload patch.
- `server/cmd/rulecompiler` + `deploy/rulecompiler` — automatic rule conversion
  and refresh.
- `agent/supervisor/providers/lyprobe` — Go supervisor provider.

## Build

Run on the build host. The script does not install packages on the host; it uses
a CPU/IO-throttled Ubuntu 24.04 container and removes its temporary source tree.

```bash
sudo bash scripts/dev/lyprobe-build.sh
cat /opt/lyflow/artifacts/lyprobe/BUILD-INFO
cat /opt/lyflow/artifacts/lyprobe/SHA256SUMS
```

The build installs `libpcre3-dev`, compiles the service plugin, and applies
`patches/lyprobe/0001-hot-reload.patch`. The binary uses an `$ORIGIN` rpath for
`liblyprobe-1.0.0.so`.

If GitHub is unreachable, point the build at an existing clean clone:

```bash
LYPROBE_SOURCE_DIR=/opt/lyflow/build/lyprobe-src \
  bash scripts/dev/lyprobe-build.sh
```

## Install

```bash
sudo install -d /opt/lyflow/bin /opt/lyflow/plugins /opt/lyflow/fp-patterns /etc/lyflow
sudo install -m 0755 /opt/lyflow/artifacts/lyprobe/lyprobe /opt/lyflow/bin/
sudo install -m 0644 /opt/lyflow/artifacts/lyprobe/liblyprobe-1.0.0.so /opt/lyflow/bin/
sudo install -m 0755 /opt/lyflow/artifacts/lyprobe/plugins/servicePlugin.so /opt/lyflow/plugins/
# Install service.json/device.json/os.json/midware.json from upstream fp-patterns.
sudo bash scripts/agent/lyprobe-preflight.sh ens160 /opt/lyflow/bin/lyprobe
sudo install -m 0644 deploy/lyprobe/lyprobe.env.example /etc/lyflow/lyprobe.env
sudo install -m 0644 deploy/lyprobe/lyprobe.service /etc/systemd/system/lyprobe.service
sudo systemctl daemon-reload
sudo systemctl enable --now lyprobe
```

Runtime dependency: `libpcre3` (PCRE1) for `servicePlugin.so`.

The unit uses `WorkingDirectory=/opt/lyflow` so the plugin searches `./plugins`
and `./fp-patterns`. The `-T` template must contain `%PROTOCOL` and at least one
`%THREAT_*` field; otherwise protocol filtering is disabled or the plugin is not
enabled.

## Rule refresh

Use the rule compiler service:

```bash
sudo install -m 0755 /opt/lyflow/bin/lyflow-rulecompiler /opt/lyflow/bin/
sudo install -m 0644 deploy/rulecompiler/lyflow-rulecompiler.service /etc/systemd/system/
sudo install -m 0644 deploy/rulecompiler/rulecompiler.env.example /etc/lyflow/rulecompiler.env
sudo systemctl enable --now lyflow-rulecompiler
```

The compiler writes `fp-patterns/threat.json` atomically. The patched ly_probe
watcher reloads it every 2 seconds without restarting capture. Unpatched builds
can set `LYFLOW_RULE_RELOAD=systemctl restart lyprobe` as a fallback, with a
brief capture interruption.

## Validate

```bash
sudo bash scripts/agent/lyprobe-preflight.sh ens160 /opt/lyflow/bin/lyprobe
sudo bash scripts/dev/lyprobe-netflow-smoke.sh ens160
```

The smoke test starts a local UDP collector, runs `lyprobe` for 14 seconds,
generates IPv4 traffic, and requires at least one NetFlow v5 datagram. This
validates capture, flow expiry and export end to end.

## Known upstream issue

`lyprobe -P <dir> -D t` (text flow dump) aborts with
`*** buffer overflow detected ***` on ly_probe revision `06c097d` after
capturing traffic. Binary dump (`-D b`) does not crash but only writes IPv4
NetFlow v5 records, so an IPv6-only traffic window produces a 0-byte dump.
LyFlow uses the NetFlow collector path; do not enable text dumps in production.

## Safety and cleanup

- Capture requires `CAP_NET_RAW`/`CAP_NET_ADMIN`; the unit grants only those.
- Do not run `ly_probe` and a full-packet capture tool on the same mirror
  without sizing the RX ring and CPU affinity.
- Feature-offload changes are host-level; record the previous state before
  applying and restore it during rollback.
- The upstream C/C++ source is not vendored or edited in-tree; the hot-reload
  change is a patch file applied only during the container build.
- Build sources are temporary; artifacts and checksums are retained. Remove
  `/opt/lyflow/build/lyprobe-build` and any `lyprobe-*` temp dirs after a failed
  run to reclaim disk space.
