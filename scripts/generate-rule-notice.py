#!/usr/bin/env python3
"""Generate a NOTICE-like report for LyFlow rule sources."""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Any


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def metadata_from_document(path: Path, data: dict[str, Any]) -> dict[str, str]:
    if "source" in data and isinstance(data["source"], dict):
        source = data["source"]
        return {
            "path": str(path),
            "name": str(data.get("name", data.get("id", path.name))),
            "vendor": str(source.get("vendor", "")),
            "license": str(source.get("license", "")),
            "source_url": str(source.get("url", "")),
            "origin": str(source.get("origin", "")),
            "version": str(source.get("version", "")),
            "upstream_id": str(source.get("upstream_id", "")),
            "revision": str(source.get("revision", "")),
            "conversion_version": str(source.get("conversion_version", "")),
        }
    return {
        "path": str(path),
        "name": str(data.get("name", data.get("source_id", path.name))),
        "vendor": str(data.get("vendor", "")),
        "license": str(data.get("license", "")),
        "source_url": str(data.get("source_url", "")),
        "origin": str(data.get("source_type", "")),
        "version": str(data.get("schema_version", "")),
        "upstream_id": str(data.get("source_id", "")),
        "revision": "",
        "conversion_version": str(data.get("conversion", {}).get("target_ir", "")) if isinstance(data.get("conversion"), dict) else "",
    }


def validate_metadata(item: dict[str, str]) -> list[str]:
    errors: list[str] = []
    for field in ["vendor", "license", "source_url"]:
        if not item.get(field):
            errors.append(f"{item['path']}: missing {field}")
    return errors


def render_notice(items: list[dict[str, str]]) -> str:
    grouped: dict[tuple[str, str, str], list[dict[str, str]]] = defaultdict(list)
    for item in items:
        grouped[(item["vendor"], item["license"], item["source_url"])].append(item)

    lines = [
        "# LyFlow Rule Source NOTICE",
        "",
        "This report is generated from rule manifests and Rule IR metadata. It is for audit and conversion tracking only; it does not activate rules.",
        "",
    ]
    for (vendor, license_name, source_url), entries in sorted(grouped.items()):
        lines.extend([
            f"## {vendor}",
            "",
            f"- License: `{license_name}`",
            f"- Source URL: `{source_url}`",
            "- Entries:",
        ])
        for entry in sorted(entries, key=lambda value: value["path"]):
            suffix = []
            if entry.get("upstream_id"):
                suffix.append(f"upstream={entry['upstream_id']}")
            if entry.get("revision"):
                suffix.append(f"rev={entry['revision']}")
            if entry.get("conversion_version"):
                suffix.append(f"conversion={entry['conversion_version']}")
            details = f" ({', '.join(suffix)})" if suffix else ""
            lines.append(f"  - `{entry['path']}` — {entry['name']}{details}")
        lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("documents", nargs="+", type=Path)
    args = parser.parse_args()

    items = [metadata_from_document(path, load_json(path)) for path in args.documents]
    errors: list[str] = []
    for item in items:
        errors.extend(validate_metadata(item))
    if errors:
        for error in errors:
            print(error)
        return 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(render_notice(items) + "\n", encoding="utf-8")
    print(f"ok: wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
