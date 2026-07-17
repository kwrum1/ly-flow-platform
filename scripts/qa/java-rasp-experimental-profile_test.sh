#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
module="$root/agent/rasp/java"

grep -Fq '<id>experimental-runtime</id>' "$module/pom.xml"
output=$(bash "$root/scripts/qa/run-java-rasp-conformance.sh" --iterations 1)
[[ $output == java-rasp\ experimental-profile\ conformance* ]]
[[ -f $module/target/ly-rasp-java-1.0.0-experimental.jar ]]
