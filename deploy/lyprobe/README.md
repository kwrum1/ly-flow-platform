# ly_probe sensor integration

LyFlow keeps upstream `ly_probe` as an **external process**. The agent supervisor
owns its lifecycle; this directory contains packaging and configuration.

## Files

- `lyprobe.service` — systemd unit for a host sensor.
- `lyprobe.env.example` — interface, collector and extra nProbe arguments.
- `scripts/agent/lyprobe-preflight.sh` — capture preflight (root, interface,
  runtime library, libpcap, offloads, RX ring, PF_RING availability).
- `scripts/dev/lyprobe-build.sh` — build upstream `ly_probe` in an Ubuntu 24.04
  container and publish `lyprobe` + `liblyprobe-1.0.0.so` to
  `/opt/lyflow/artifacts/lyprobe`.
- `scripts/dev/lyprobe-netflow-smoke.sh` — live capture + NetFlow export smoke
  test with a local UDP collector.
- `agent/supervisor/providers/lyprobe` — Go supervisor provider.

## Build

Run on the build host. The script does not install packages on the host; it uses
a CPU/IO-throttled Ubuntu 24.04 container and removes its temporary source tree.

```bash
sudo bash scripts/dev/lyprobe-build.sh
cat /opt/lyflow/artifacts/lyprobe/BUILD-INFO
cat /opt/lyflow/artifacts/lyprobe/SHA256SUMS
```

The binary is linked against `liblyprobe-1.0.0.so`; the shared library is placed
next to the binary and the binary uses an `$ORIGIN` rpath.

## Install

```bash
sudo install -d /opt/lyflow/bin /etc/lyflow
sudo install -m 0755 /opt/lyflow/artifacts/lyprobe/lyprobe /opt/lyflow/bin/
sudo install -m 0644 /opt/lyflow/artifacts/lyprobe/liblyprobe-1.0.0.so /opt/lyflow/bin/
sudo bash scripts/agent/lyprobe-preflight.sh ens160 /opt/lyflow/bin/lyprobe
sudo install -m 0644 deploy/lyprobe/lyprobe.env.example /etc/lyflow/lyprobe.env
sudo install -m 0644 deploy/lyprobe/lyprobe.service /etc/systemd/system/lyprobe.service
sudo systemctl daemon-reload
sudo systemctl enable --now lyprobe
```

Edit `/etc/lyflow/lyprobe.env` before starting. `LYPROBE_COLLECTOR=none` keeps
the probe running without a collector, but upstream then requires `-P`: use the
smoke test below instead of enabling `-P` in production.

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
- The upstream C/C++ source is not modified; productization lives in the
  wrapper, unit, preflight and supervisor.
- Build sources are temporary; artifacts and checksums are retained. Remove
  `/opt/lyflow/build/lyprobe-build` and any `lyprobe-*` temp dirs after a failed
  run to reclaim disk space.
