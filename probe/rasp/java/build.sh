#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
BUILD_DIR="$ROOT/build"
CLASS_DIR="$BUILD_DIR/classes"
JAR_PATH="$ROOT/ly-rasp-agent.jar"
rm -rf "$BUILD_DIR"
mkdir -p "$CLASS_DIR"
javac -source 8 -target 8 -d "$CLASS_DIR" $(find "$ROOT/src/main/java" -name '*.java' | sort)
jar cfm "$JAR_PATH" "$ROOT/MANIFEST.MF" -C "$CLASS_DIR" .
printf '%s\n' "$JAR_PATH"
