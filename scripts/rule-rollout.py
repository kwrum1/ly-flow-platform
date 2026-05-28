#!/usr/bin/env python3
"""Safe dry-run, activate, and rollback helper for compiled rule artifacts."""

from __future__ import annotations

import argparse
import shutil
import time
from pathlib import Path


def count_rules(path: Path) -> int:
    return len(list(path.glob("*.json"))) if path.exists() else 0


def copytree_clean(src: Path, dst: Path) -> None:
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst)


def newest_backup(root: Path) -> Path | None:
    backups = sorted([p for p in root.iterdir() if p.is_dir()]) if root.exists() else []
    return backups[-1] if backups else None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--dry-run", action="store_true")
    group.add_argument("--activate", action="store_true")
    group.add_argument("--rollback", action="store_true")
    parser.add_argument("--source", type=Path, default=Path("rules/compiled/scored-preview"))
    parser.add_argument("--live", type=Path, required=True)
    parser.add_argument("--backup", type=Path, required=True)
    args = parser.parse_args()

    if args.dry_run:
        if not args.source.exists():
            print(f"source missing: {args.source}")
            return 1
        print(f"ok: dry-run source={args.source} rules={count_rules(args.source)} live_unchanged={args.live}")
        return 0

    args.backup.mkdir(parents=True, exist_ok=True)
    if args.activate:
        if not args.source.exists():
            print(f"source missing: {args.source}")
            return 1
        if args.live.exists():
            target = args.backup / time.strftime("%Y%m%d%H%M%S")
            shutil.copytree(args.live, target)
            print(f"backup: {target}")
        copytree_clean(args.source, args.live)
        print(f"ok: activated {count_rules(args.live)} rules into {args.live}")
        return 0

    backup = newest_backup(args.backup)
    if backup is None:
        print(f"no backup available in {args.backup}")
        return 1
    copytree_clean(backup, args.live)
    print(f"ok: rolled back {args.live} from {backup}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
