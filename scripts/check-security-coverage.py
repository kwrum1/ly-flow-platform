#!/usr/bin/env python3
from pathlib import Path
import sys

REQUIRED = ["dpi", "semantic_flow", "runtime", "rasp", "logs", "xdr", "asset_context"]
CONFIG = Path("security-coverage.yaml")


def main() -> int:
    text = CONFIG.read_text(encoding="utf-8")
    missing = []
    for signal in REQUIRED:
        if f"  {signal}:" not in text:
            missing.append(signal)
    for token in ["fixture:", "analyzer:", "output_stream:", "xdr_correlation: true"]:
        if token not in text:
            missing.append(token)
    if missing:
        print("coverage_missing=" + ",".join(missing), file=sys.stderr)
        return 1
    print("coverage=pass signals=" + ",".join(REQUIRED))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
