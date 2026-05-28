#!/usr/bin/env python3
"""Validate LyFlow telemetry contract fixtures with only stdlib JSON."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


def get_path(data: dict[str, Any], dotted: str) -> Any:
    current: Any = data
    for part in dotted.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def validate_fixture(mapping: dict[str, Any], contract_name: str, fixture_path: Path) -> list[str]:
    contracts = mapping.get("contracts", {})
    contract = contracts.get(contract_name)
    if not isinstance(contract, dict):
        return [f"unknown contract: {contract_name}"]

    try:
        data = json.loads(fixture_path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        return [f"{fixture_path}: failed to parse JSON: {exc}"]

    errors: list[str] = []
    for field in contract.get("required_fields", []):
        value = get_path(data, field)
        if value is None or value == "":
            errors.append(f"{fixture_path}: missing required field {field}")
    return errors


def validate_mapping(mapping_path: Path) -> list[str]:
    mapping = json.loads(mapping_path.read_text(encoding="utf-8"))
    errors: list[str] = []
    falco = mapping.get("external_mappings", {}).get("falco", {})
    evt_type = falco.get("evt.type", {})
    if evt_type.get("support") != "unsupported":
        errors.append("falco evt.type must remain unsupported until real syscall telemetry exists")
    if evt_type.get("lyflow") is not None:
        errors.append("falco evt.type must not map to a LyFlow field in current contract")
    return errors


def main(argv: list[str]) -> int:
    if len(argv) != 12:
        print(
            "usage: validate-telemetry-contract.py <mapping.json> "
            "hids_process <fixture> hids_auth <fixture> hids_file <fixture> "
            "dpi_flow <fixture> dpi_semantic_session <fixture>",
            file=sys.stderr,
        )
        return 2

    mapping_path = Path(argv[1])
    mapping = json.loads(mapping_path.read_text(encoding="utf-8"))
    errors = validate_mapping(mapping_path)

    pairs = list(zip(argv[2::2], argv[3::2]))
    for contract_name, fixture_name in pairs:
        errors.extend(validate_fixture(mapping, contract_name, Path(fixture_name)))

    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1

    print("ok: telemetry contracts and fixtures are valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
