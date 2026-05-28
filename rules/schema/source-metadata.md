# LyFlow Rule Source Metadata Model

Every rule and every source manifest must preserve enough origin metadata for audit, deduplication, conflict resolution, and later UI display.

## Required manifest metadata

Each `manifest.json` must include:

- `source_id`
- `name`
- `category`
- `source_type`
- `update_mode`
- `vendor`
- `license`
- `source_url`
- `raw_path`
- `converted_path`
- `compiled_path`
- `enabled_by_default`
- `conversion.converter`
- `conversion.target_ir`

## Required rule metadata

Each Rule IR file must include `source` metadata:

- `source.origin`
- `source.vendor`
- `source.license`
- `source.url`
- `source.version`

Recommended upstream fields:

- `source.upstream_id`
- `source.revision`
- `source.conversion_version`
- `source.raw_path`
- `source.converted_path`

## Origin values

- `internal`: LyFlow self-developed rules.
- `rebuilt_internal`: one-time imported rules that become internal after review, such as rebuilt Elkeid HIDS rules.
- `external_subscription`: externally maintained rules that are fetched, converted, validated, and reviewed.
- `external_import`: one-time external import that is not maintained as an ongoing subscription.

## NOTICE reporting

The NOTICE generator reads manifests and Rule IR fixtures, groups by vendor/license/source URL, and emits a Markdown report. It does not download, activate, or compile rules.

```bash
python3 scripts/generate-rule-notice.py --output .sisyphus/evidence/task-5-license-report.md <manifest-or-rule-json>...
```
