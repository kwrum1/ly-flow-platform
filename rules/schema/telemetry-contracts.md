# LyFlow HIDS/DPI Telemetry Contracts

This document defines the stable telemetry contract that external rule converters may target in the HIDS + DPI rule engineering system.

## Scope

In scope:

- HIDS runtime events emitted by `ly-agent` process/auth/file collectors.
- DPI raw flow, semantic flow, and semantic session fields emitted through `flows:raw`, `flows:semantic`, and `sessions:semantic`.
- Field support mapping for ECS, Falco, Suricata, and Wazuh auditd.

Out of scope:

- RASP telemetry contracts.
- Full syscall/eBPF parity with Falco.
- Automatic enforcement or host/network blocking.

## HIDS runtime event envelope

Source: `agent/cmd/main.go` `RuntimeEvent` and `buildRuntimeMonitorEvent`.

Required envelope fields:

| LyFlow field | Type | Required | Notes |
| --- | --- | --- | --- |
| `agent_id` | string | yes | Agent identifier. |
| `hostname` | string | yes | Hostname from agent host. |
| `ip` | string | yes | Agent local IP. |
| `type` | string | yes | Event type such as `runtime.process.new`. |
| `severity` | string | yes | `low`, `medium`, `high`, `critical`. |
| `strategy` | string | yes | Configured runtime strategy. |
| `backend` | string | yes | Active or fallback backend label. |
| `capability_status` | string | yes | `active`, `fallback`, or `unsupported_fallback`. |
| `source_evidence` | string | yes | Collector/path evidence. |
| `mode` | string | yes | Current value is `monitor`. |
| `message` | string | yes | Human-readable event message. |
| `occurred_at` | RFC3339 string | yes | Event occurrence time. |
| `metadata` | object | yes | Collector-specific fields. |

## HIDS process event metadata

Event type: `runtime.process.new`.

Required fields for rule matching:

| LyFlow field | Support | Notes |
| --- | --- | --- |
| `metadata.collector` | full_supported | `process-delta-fallback`. |
| `metadata.user` | full_supported | Process user if available from `ps`. |
| `metadata.process_name` | full_supported | Process executable/name from process snapshot. |
| `metadata.command_line` | full_supported | Command line snapshot. |
| `metadata.signal` | full_supported | Derived signal such as `reverse-shell` or `persistence`. |

## HIDS auth event metadata

Event types include `runtime.auth.root_login`, `runtime.auth.sudo_failure`, `runtime.auth.failure`, `runtime.auth.account_change`, `runtime.auth.privilege`, and `runtime.auth.persistence`.

Required fields for rule matching:

| LyFlow field | Support | Notes |
| --- | --- | --- |
| `metadata.collector` | full_supported | `auth-log-fallback`. |
| `metadata.path` | full_supported | Source log path. |
| `metadata.line` | full_supported | Raw auth log line. |
| `metadata.signal` | full_supported | Derived auth signal. |

## HIDS file event metadata

Event type: `runtime.file.changed`.

Required fields for rule matching:

| LyFlow field | Support | Notes |
| --- | --- | --- |
| `metadata.collector` | full_supported | `file-metadata-fallback`. |
| `metadata.path` | full_supported | Watched file or directory path. |
| `metadata.size` | full_supported | File size from stat. |
| `metadata.mod_unix_nano` | full_supported | Modification timestamp. |

## DPI raw flow contract

Source: historical `flows:raw` schema (legacy DPI producer removed); new traffic events use the unified engine and LyFlow probe.

Required fields:

| LyFlow field | Support | Notes |
| --- | --- | --- |
| `id` | full_supported | Flow ID. |
| `timestamp` | full_supported | Unix timestamp seconds. |
| `sensor_id` | full_supported | Agent/sensor identifier. |
| `src_ip`, `dst_ip` | full_supported | Network tuple. |
| `src_port`, `dst_port` | full_supported | Network tuple. |
| `protocol` | full_supported | Transport protocol. |
| `app_protocol` | full_supported | Application protocol if known. |
| `dns_query`, `dns_answer`, `dns_domain` | partial_supported | Present for DNS-observable flows. |
| `http_host`, `http_method`, `http_path`, `http_status` | partial_supported | Present for HTTP-observable flows. |
| `tls_sni`, `ja3` | partial_supported | Present for TLS-observable flows. |
| `bytes_in`, `bytes_out`, `packets`, `duration_ms`, `direction` | full_supported | Flow metrics. |

## DPI semantic flow/session contract

Source: `SemanticFlow` and `SemanticSession`, streams `flows:semantic` and `sessions:semantic`.

Additional semantic fields:

| LyFlow field | Support | Notes |
| --- | --- | --- |
| `schema_version` | full_supported | Current value `v1`. |
| `source_stream` | full_supported | Upstream stream name. |
| `flow_id`, `session_id` | full_supported | Correlation IDs. |
| `domain` | full_supported | Derived from SNI, HTTP host, or DNS query. |
| `risk_score`, `risk_level`, `threat_type`, `context` | partial_supported | Semantic enrichment fields. |
| `behavior_summary`, `suspected_bot`, `repeated_domain_hits` | partial_supported | Session-level enrichment. |

## Explicit unsupported fields

Current LyFlow HIDS is a lightweight monitor/fallback implementation. These fields must be marked `unsupported` until a real backend provides them:

- Falco syscall/event fields: `evt.type`, `evt.dir`, `evt.rawres`, `syscall.type`.
- Falco kernel file descriptor fields not present in LyFlow metadata: `fd.num`, `fd.typechar`, `fd.name`.
- Full auditd key/value fields that are not present in current auth log lines.
- Packet payload offsets and Suricata engine-only state that cannot be represented by current DPI flow/session fields.
