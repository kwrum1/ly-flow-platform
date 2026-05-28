# LyFlow HIDS/DPI Rule IR

This directory defines the first stable LyFlow rule intermediate representation used by the HIDS + DPI rule engineering plan.

## Scope

In scope:

- HIDS single-event rules from LyFlow, rebuilt Elkeid, Wazuh auditd, Elastic Linux, and the supported Falco subset.
- DPI single-event rules from LyFlow internal DPI rules and Suricata/ET Open style signatures.
- Behavior correlation rules and scoring rules as first-class rule kinds.
- Subscription manifests and support reports used by the conversion pipeline.

Out of scope for this phase:

- RASP rule execution or RASP refactoring.
- Automatic response enforcement. The first response version may emit candidates only.

## Required source metadata

Every active or quarantined rule must preserve:

- `source.origin`: `internal`, `rebuilt_internal`, `external_subscription`, or `external_import`
- `source.vendor`
- `source.license`
- `source.url`
- `source.version`
- optional upstream identifiers such as `upstream_id`, `revision`, and `conversion_version`

## Support levels

- `full_supported`: all fields and operators can be evaluated by the current LyFlow telemetry/runtime.
- `partial_supported`: rule can be represented but loses part of the upstream semantics.
- `unsupported`: rule is retained for reporting/quarantine but must not be enabled.

## Attack stages

Active rules must map to one of the seven user-approved stages:

1. `recon`
2. `initial_access`
3. `execution`
4. `persistence`
5. `privilege_escalation`
6. `lateral_movement`
7. `c2_exfiltration`

`uncategorized` is allowed only for disabled/quarantined rules or incomplete draft reports.

## Validation

The lightweight validator intentionally uses only Python standard library so it can run in the appliance development environment without installing dependencies:

```bash
python3 scripts/validate-rule-ir.py rules/schema/examples/internal-hids-rule.json rules/schema/examples/suricata-dpi-rule.json
```

Negative example:

```bash
python3 scripts/validate-rule-ir.py rules/schema/examples/invalid-missing-source.json
```

The negative fixture must fail because source metadata is incomplete.
