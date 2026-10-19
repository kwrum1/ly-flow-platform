#!/usr/bin/env sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$ROOT"
dotnet build -c Release -o publish
cp publish/LyRaspProfiler.dll "$ROOT/LyRaspProfiler.dll"
printf '%s\n' "$ROOT/LyRaspProfiler.dll"
