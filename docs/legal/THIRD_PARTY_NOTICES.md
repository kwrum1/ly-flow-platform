# Third-party notices

LyFlow is distributed as a single-node appliance. GPL and other copyleft
components are kept in separate processes/containers and are not linked into
LyFlow's proprietary Go binaries.

| Component | Version / revision | License | Distribution | Source / notice |
|---|---|---|---|---|
| ly_probe | `06c097dd5c69e391efd3c8b3776d672e03386e49` + LyFlow patch | GPL-3.0 | separate binary/container | https://github.com/Abyssal-Fish-Technology/ly_probe; patch `patches/lyprobe/0001-hot-reload.patch`; build `scripts/dev/lyprobe-build.sh` |
| Suricata | 7.0.3 | GPL-2.0 | separate container | https://github.com/OISF/suricata |
| Emerging Threats Open | daily ET Open | BSD-3-Clause | rules | https://rules.emergingthreats.net/ |
| Wazuh Agent | distribution version | GPL-2.0 | separate host agent | https://github.com/wazuh/wazuh |
| OpenRASP | upstream release | Apache-2.0 | separate runtime agent | https://github.com/baidu/openrasp |
| Elkeid RASP / HUB / Console | private module | Elkeid License | **not distributed publicly** | private/elkeid only |
| ClickHouse | 24.8 / 26.9 test | Apache-2.0 | separate container | https://github.com/ClickHouse/ClickHouse |
| PostgreSQL | 16 | PostgreSQL License | separate container | https://www.postgresql.org/about/licence/ |
| Redis | 7.2.x | BSD-3-Clause | separate container | https://github.com/redis/redis/tree/7.2 |
| Valkey | optional replacement | BSD-3-Clause | separate container | https://github.com/valkey-io/valkey |
| nginx | frontend runtime | BSD-2-Clause | separate container | https://nginx.org/ |
| libpcap | runtime | BSD-3-Clause | linked by ly_probe/Suricata | https://www.tcpdump.org/ |
| PCRE | 8.39 | BSD-3-Clause | linked by ly_probe | https://www.pcre.org/ |
| gopacket | upstream/fork | BSD-3-Clause | Go dependency | https://github.com/gopacket/gopacket |
| pgx, viper, go-redis, gRPC, protobuf, websocket, YAML | module versions in `go.mod` | MIT / Apache-2.0 / BSD | Go dependencies | see `docs/dev/SBOM` / module manifests |
| Pingora | 0.9.0 | Apache-2.0 | separate frontend container | https://github.com/cloudflare/pingora |
| Vue, Element Plus, ECharts, Axios, Pinia, G6 | `frontend/package-lock.json` | MIT / Apache-2.0 | frontend bundle | see `frontend-licenses.json` SBOM |

## License boundaries

- No GPL component is linked into `ly-server`, `ly-agent`, or other LyFlow
  proprietary binaries. `ly_probe` and Suricata run as separate processes and
  communicate through NetFlow/EVE/JSON.
- Elkeid HUB/Console, Elkeid HIDS/RASP rules, and `private/elkeid/` must not be
  placed in public images, release bundles, or SBOMs.
- MongoDB (SSPL) is only referenced by the **private** `full-private.yml`
  overlay and is not part of the lean public stack.
- Redis 7.2 is the public lean pin. Post-7.2 Redis releases use non-OSI terms;
  use Valkey or an explicitly reviewed commercial license instead.
- ET Open rules are redistributed under their upstream BSD terms; preserve the
  upstream notices in the rules bundle.

## SBOM

Generate the dependency inventory on the build host:

```bash
bash scripts/dev/generate-sbom.sh /opt/lyflow/artifacts/sbom
```

The output includes Go module manifests, frontend production dependency and
license inventories, Docker image tags, and the git revision.
