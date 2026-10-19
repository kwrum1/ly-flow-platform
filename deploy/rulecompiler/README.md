# LyFlow rule compiler service

Compiles a conservative subset of Suricata rules into ly_probe's
`fp-patterns/threat.json`, polls for source changes, and keeps the sensor rules
fresh.

## Pipeline

```text
source rules
  -> parse + conservative conversion
  -> validate bundle + Go/RE2 regex
  -> write threat.json + manifest.json atomically
  -> patched ly_probe watcher detects inode/size/mtime change
  -> atomic in-memory rule swap (no capture restart)
```

A failed parse or validation leaves the old `threat.json` in place and does not
trigger a reload.

## Build

```bash
cd /opt/lyflow/src/server
CGO_ENABLED=0 go build -trimpath -o /opt/lyflow/bin/lyflow-rulecompiler ./cmd/rulecompiler
```

## Install

```bash
sudo install -d /etc/lyflow /var/lib/lyflow/rules/source /opt/lyflow/fp-patterns
sudo install -m 0755 /opt/lyflow/bin/lyflow-rulecompiler /opt/lyflow/bin/
sudo install -m 0644 deploy/rulecompiler/lyflow-rulecompiler.service /etc/systemd/system/
sudo install -m 0644 deploy/rulecompiler/rulecompiler.env.example /etc/lyflow/rulecompiler.env
sudo systemctl daemon-reload
sudo systemctl enable --now lyflow-rulecompiler
```

Put source `.rules` files in `/var/lib/lyflow/rules/source`. The service writes
`/opt/lyflow/fp-patterns/threat.json` and `manifest.json`.

## ly_probe requirements

- Use the patched build from `scripts/dev/lyprobe-build.sh` (includes
  `patches/lyprobe/0001-hot-reload.patch`).
- Run ly_probe with `WorkingDirectory=/opt/lyflow` so `./plugins` and
  `./fp-patterns` are found.
- Include `%PROTOCOL` and `%THREAT_TYPE`/`%THREAT_NAME` in the `-T` template.
  Without `%PROTOCOL`, ly_probe disables protocol filtering and rules with
  `"protocol":"tcp"`/`"udp"` never match.
- Install the service plugin at `/opt/lyflow/plugins/servicePlugin.so`. The
  build script produces it and links PCRE (`libpcre3` runtime).

## Unpatched fallback

Set `LYFLOW_RULE_RELOAD=systemctl restart lyprobe` in
`/etc/lyflow/rulecompiler.env` only if running an unpatched ly_probe. This
briefly interrupts capture; the patched watcher does not.

## Scope

Converted rules are intentionally conservative: one content or one simple
`pcre`, HTTP URI/header/body, TLS SNI, exact DNS names, `nocase`, and PCRE `i`.
Rules requiring multiple contents, flowbits, byte tests, thresholds, datasets,
or unsupported PCRE constructs are recorded in `manifest.json` and left to
Suricata.
