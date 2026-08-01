#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
manifest=${T12_MANIFEST:-$root/fixtures/real-detections/v1/manifest.json}
lock=${T12_SURICATA_LOCK:-$root/third_party/security-engines/suricata-profile.lock.json}
profile=${T12_SURICATA_PROFILE:-$root/rules/suricata/suricata-profile.yaml}
evidence_root=${T12_EVIDENCE_DIR:-$root/acceptance-evidence/T12}
replay_root=$evidence_root/replay
required_sources=(suricata-et-open oisf-trafficid snort-community ptresearch-attackdetection stamus-lateral)

fail() {
  printf 'T12 real-detection gate failed: %s\n' "$*" >&2
  exit 1
}

require_tool() {
  command -v "$1" >/dev/null 2>&1 || fail "required tool unavailable: $1"
}

require_file() {
  [[ -s $1 ]] || fail "required file missing or empty: $1"
}

file_sha256() {
  sha256sum "$1" | cut -d' ' -f1
}

validate_manifest() {
  local source_id
  jq -e '
    .schema_version == "lyflow.real-detection-fixture/v1" and
    .qualification == "real_packet_offline_sensor" and
    .raw_hash_semantics == "canonical_eve_without_ephemeral_flow_id_sha256" and
    (.sources | length) == 5 and
    (.packet_fixtures | length) == 2 and
    all(.sources[];
      (.sid | type) == "number" and (.revision | type) == "number" and
      (.emitted_sid | type) == "number" and (.emitted_revision | type) == "number" and
      (.expected_alert_count | type) == "number" and .expected_alert_count > 0) and
    all(.packet_fixtures[];
      (.path | type) == "string" and (.sha256 | test("^[0-9a-f]{64}$")) and
      (.rules_path | type) == "string" and (.rules_sha256 | test("^[0-9a-f]{64}$")))
  ' "$manifest" >/dev/null || fail "manifest schema or count contract is invalid"
  for source_id in "${required_sources[@]}"; do
    jq -e --arg source_id "$source_id" '.sources | any(.source_id == $source_id)' "$manifest" >/dev/null ||
      fail "manifest source missing: $source_id"
  done
}

validate_inputs() {
  local fixture_path expected actual
  while IFS=$'\t' read -r fixture_path expected; do
    [[ $fixture_path != /* && $fixture_path != *'..'* ]] || fail "unsafe fixture path: $fixture_path"
    require_file "$root/$fixture_path"
    actual=$(file_sha256 "$root/$fixture_path")
    [[ $actual == "$expected" ]] || fail "fixture digest mismatch: $fixture_path expected=$expected actual=$actual"
  done < <(jq -r '.packet_fixtures[] | [.path, .sha256] | @tsv' "$manifest")

  while IFS=$'\t' read -r fixture_path expected; do
    [[ $fixture_path != /* && $fixture_path != *'..'* ]] || fail "unsafe rule fixture path: $fixture_path"
    require_file "$root/$fixture_path"
    actual=$(file_sha256 "$root/$fixture_path")
    [[ $actual == "$expected" ]] || fail "rule fixture digest mismatch: $fixture_path expected=$expected actual=$actual"
  done < <(jq -r '.packet_fixtures[] | [.rules_path, .rules_sha256] | @tsv' "$manifest")

  local expected_profile actual_profile
  expected_profile=$(jq -r '.config_sha256' "$lock")
  actual_profile=$(file_sha256 "$profile")
  [[ $actual_profile == "$expected_profile" ]] ||
    fail "Suricata profile digest mismatch: expected=$expected_profile actual=$actual_profile"
}

materialize_packet_fixtures() {
	local fixture_id fixture_path expected embedded url temp actual
	while IFS=$'\t' read -r fixture_id fixture_path expected embedded; do
		[[ $fixture_path != /* && $fixture_path != *'..'* ]] || fail "unsafe fixture path: $fixture_path"
		fixture_path=$root/$fixture_path
		if [[ -s $fixture_path ]] && [[ $(file_sha256 "$fixture_path") == "$expected" ]]; then
			continue
		fi
		mkdir -p "$(dirname "$fixture_path")"
		temp=$fixture_path.tmp.$$
		rm -f "$temp"
		if [[ -n $embedded ]]; then
			[[ $embedded != /* && $embedded != *'..'* ]] || fail "unsafe embedded fixture path: $embedded"
			require_file "$root/$embedded"
			base64 --decode "$root/$embedded" >"$temp"
		else
			url=$(jq -er --arg source_id "$(jq -r --arg fixture_id "$fixture_id" '.packet_fixtures[] | select(.fixture_id == $fixture_id) | .source_ids[0]' "$manifest")" '.external_packet_fixture | select(.source_id == $source_id) | .url' "$manifest")
			curl --proto '=https' --tlsv1.2 --http1.1 --location --fail --silent --show-error \
				--retry 3 --retry-all-errors --retry-delay 1 --connect-timeout 15 --max-time 120 "$url" --output "$temp"
		fi
		actual=$(file_sha256 "$temp")
		if [[ $actual != "$expected" ]]; then
			rm -f "$temp"
			fail "materialized fixture digest mismatch: $fixture_id expected=$expected actual=$actual"
		fi
		mv "$temp" "$fixture_path"
	done < <(jq -r '.packet_fixtures[] | [.fixture_id, .path, .sha256, (.embedded_base64_path // "")] | @tsv' "$manifest")
}

prepare_rule_bundle() {
	local bundle=$evidence_root/t12-five-source-bundle.json
	jq -n --arg version t12-five-source-baseline \
		--rawfile four "$root/fixtures/real-detections/v1/four-source.rules" \
		--rawfile stamus "$root/fixtures/real-detections/v1/stamus.rules" '
		def rules($contents; $group):
			$contents | split("\n") | map(select(length > 0) |
				. as $rule | capture("sid:(?<sid>[0-9]+)") as $identity |
				{id: ("suricata-" + $identity.sid), name: ("T12 Suricata SID " + $identity.sid),
				 category: "traffic", severity: "info", field: ("suricata." + $group + ".rule"),
				 value: $rule, candidate: false});
		{version: $version, rules: (rules($four; "four-source") + rules($stamus; "stamus"))}
	' >"$bundle"
	require_file "$bundle"
	printf '%s\n' "$bundle"
}

materialize_replay_rules() {
	local bundle=$1 active_rules=$evidence_root/active-rules
	rm -rf "$active_rules"
	mkdir -p "$active_rules"
	jq -r '.rules[] | select(.field == "suricata.four-source.rule") | .value' "$bundle" >"$active_rules/four-source.rules"
	jq -r '.rules[] | select(.field == "suricata.stamus.rule") | .value' "$bundle" >"$active_rules/stamus.rules"
	require_file "$active_rules/four-source.rules"
	require_file "$active_rules/stamus.rules"
}

run_replays() {
	local rule_bundle=$1 image four_pcap stamus_pcap
	materialize_replay_rules "$rule_bundle"
	image=${SURICATA_REPLAY_IMAGE:-$(jq -er '.image' "$lock")}
  docker image inspect "$image" >/dev/null 2>&1 || fail "pinned Suricata image is not cached: $image"
  four_pcap=$root/$(jq -r '.packet_fixtures[] | select(.fixture_id == "four-source") | .path' "$manifest")
  stamus_pcap=$root/$(jq -r '.packet_fixtures[] | select(.fixture_id == "stamus-svcctl") | .path' "$manifest")
  [[ $replay_root != / ]] || fail "refusing unsafe replay root"
  rm -rf "$replay_root/four-source" "$replay_root/stamus"
  mkdir -p "$replay_root/four-source" "$replay_root/stamus"

  docker run --rm --pull never --network none --user 0:0 --entrypoint suricata \
    -v "$profile:/input/profile.yaml:ro" \
		-v "$evidence_root/active-rules/four-source.rules:/input/rules.rules:ro" \
    -v "$four_pcap:/input/input.pcap:ro" \
    -v "$replay_root/four-source:/output" \
    "$image" -c /input/profile.yaml -S /input/rules.rules -r /input/input.pcap \
    -l /output -k none --runmode single

  docker run --rm --pull never --network none --user 0:0 --entrypoint suricata \
    -v "$profile:/input/profile.yaml:ro" \
		-v "$evidence_root/active-rules/stamus.rules:/input/rules.rules:ro" \
    -v "$stamus_pcap:/input/input.pcap:ro" \
    -v "$replay_root/stamus:/output" \
    "$image" -c /input/profile.yaml --set app-layer.protocols.smb.enabled=yes \
    -S /input/rules.rules -r /input/input.pcap -l /output -k none --runmode single
}

verify_alerts() {
  local checked_manifest=$1 four_eve=$2 stamus_eve=$3 source_id emitted_sid expected actual eve total_expected total_actual
  require_file "$four_eve"
  require_file "$stamus_eve"
  total_expected=0
  while IFS=$'\t' read -r source_id emitted_sid expected; do
    if [[ $source_id == stamus-lateral ]]; then
      eve=$stamus_eve
    else
      eve=$four_eve
    fi
    actual=$(jq -s --argjson sid "$emitted_sid" '[.[] | select(.event_type == "alert" and .alert.signature_id == $sid)] | length' "$eve")
    [[ $actual -eq $expected ]] || fail "alert count drift: source=$source_id sid=$emitted_sid expected=$expected actual=$actual"
    total_expected=$((total_expected + expected))
  done < <(jq -r '.sources[] | [.source_id, (.witness_sid // .sid), .expected_alert_count] | @tsv' "$checked_manifest")
  total_actual=$(jq -s '[.[] | select(.event_type == "alert")] | length' "$four_eve" "$stamus_eve")
  [[ $total_actual -eq $total_expected ]] || fail "unexpected alert SID or total count drift: expected=$total_expected actual=$total_actual"
  jq -s -e '
    [.[] | select(.event_type == "alert" and .alert.signature_id == 990000000)] as $alerts |
    ($alerts | length) > 0 and
    all($alerts[];
      ((.alert.metadata.contributing_source // []) | index("oisf-trafficid")) != null and
      ((.alert.metadata.emitting_source // []) | index("lyflow")) != null)
  ' "$four_eve" >/dev/null || fail "OISF witness attribution is missing"
  jq -s -e '[.[] | select(.event_type == "alert" and .alert.signature_id == 300000000)] | length == 0' "$four_eve" >/dev/null ||
    fail "OISF noalert source SID emitted an alert"
}

write_result() {
  local four_eve=$1 stamus_eve=$2
  jq -n --slurpfile manifest "$manifest" --slurpfile four "$four_eve" --slurpfile stamus "$stamus_eve" \
    --slurpfile pipeline "$evidence_root/pipeline-result.json" \
    --arg image "$(jq -r '.image' "$lock")" --arg profile_sha256 "$(file_sha256 "$profile")" '
      $manifest[0] as $contract |
      {
        schema_version: "lyflow.t12.real_detection_result/v1",
        status: "PASS",
        suricata_image: $image,
        profile_sha256: $profile_sha256,
        pipeline: $pipeline[0],
        sources: [$contract.sources[] | . as $source |
          (if .source_id == "stamus-lateral" then $stamus else $four end) as $events |
          {
            source_id: .source_id,
            source_sid: .sid,
            emitted_sid: (.witness_sid // .sid),
            expected_alert_count: .expected_alert_count,
            actual_alert_count: ([$events[] | select(.event_type == "alert" and .alert.signature_id == ($source.witness_sid // $source.sid))] | length)
          }
        ]
      }
    ' >"$evidence_root/result.json"
}

run_negative_checks() {
  local four_eve=$1 stamus_eve=$2 temp
  temp=$(mktemp -d /tmp/lyflow-t12-negative.XXXXXX)
  trap 'rm -rf "$temp"' RETURN
  jq 'del(.sources[] | select(.source_id == "stamus-lateral"))' "$manifest" >"$temp/missing-source.json"
  if (manifest="$temp/missing-source.json"; validate_manifest) >/dev/null 2>&1; then
    fail "missing-source negative control passed unexpectedly"
  fi
  jq -c 'if .event_type == "alert" and .alert.signature_id == 990000000 then .alert.metadata = {} else . end' "$four_eve" >"$temp/missing-witness.json"
  if (verify_alerts "$manifest" "$temp/missing-witness.json" "$stamus_eve") >/dev/null 2>&1; then
    fail "missing-witness negative control passed unexpectedly"
  fi
  jq '(.sources[] | select(.source_id == "suricata-et-open") | .expected_alert_count) += 1' "$manifest" >"$temp/count-drift.json"
  if (verify_alerts "$temp/count-drift.json" "$four_eve" "$stamus_eve") >/dev/null 2>&1; then
    fail "count-drift negative control passed unexpectedly"
  fi
}

run_pipeline() {
	local pipeline_result=$evidence_root/pipeline-result.json
	rm -f "$pipeline_result"
	T12_REAL_DETECTION_EVE_DIR="$replay_root" \
		T12_REAL_DETECTION_PIPELINE=1 \
		T12_REAL_DETECTION_MANIFEST="$manifest" \
		T12_PIPELINE_EVIDENCE_OUTPUT="$pipeline_result" \
    "$root/scripts/qa/with-disposable-redis.sh" \
    "$root/scripts/qa/with-disposable-event-stores.sh" \
    bash -c 'env GOWORK=off GOTOOLCHAIN=auto GOSUMDB=sum.golang.org go -C "$1/agent" test -race -count=1 ./cmd -run "^TestRealDetectionEVE_publishesFiveNativeSourcesToRedis$" && env GOWORK=off GOTOOLCHAIN=auto GOSUMDB=sum.golang.org go -C "$1/server" test -race -count=1 ./cmd -run "^TestRealDetectionPipeline_persistsAgentAlertsInBothStoresAndAPI$"' _ "$root"
	require_file "$pipeline_result"
	jq -e '
    .status == "PASS" and
    .agent_stream_count == 9 and
    .threat_event_count == 9 and
    .canonical_postgres_count == 9 and
    .canonical_clickhouse_count == 9 and
    .server_dispatch_receipt_count == 9 and
    .security_events_api_count == 9 and
    .roleless_request_status == 403 and
    (.native_source_counts | length) == 5
	' "$pipeline_result" >/dev/null || fail "Agent/server/store/API pipeline evidence is incomplete"
}

run_reload_restore() {
	local baseline_bundle=$1 reload_root=$evidence_root/reload
  rm -rf "$reload_root"
  mkdir -p "$reload_root"
	RELOAD_AUDIT_EVIDENCE_DIR="$reload_root" \
		LYFLOW_RELOAD_BASELINE_BUNDLE="$baseline_bundle" \
		LYFLOW_RELOAD_BASELINE_VERSION=t12-five-source-baseline \
		"$root/scripts/qa/with-disposable-event-stores.sh" \
    bash "$root/scripts/qa/reload-audit_test.sh"
  jq -e '
    .status == "PASS" and .failed_events == 1 and .successful_events == 1 and .rollback_events == 1 and
		.baseline_version == "t12-five-source-baseline" and
		.baseline_version == .final_version and .baseline_digest == .final_digest and
		(.final_bundle_path | type) == "string" and (.final_bundle_path | length) > 0
	' "$reload_root/reload-events.json" >/dev/null || fail "reload/restore audit evidence is incomplete"
	local restored_bundle
	restored_bundle=$(jq -er '.final_bundle_path' "$reload_root/reload-events.json")
	require_file "$restored_bundle"
	[[ $(file_sha256 "$restored_bundle") == $(file_sha256 "$baseline_bundle") ]] || fail "restored active bundle content differs from T12 baseline"
}

write_continuity_result() {
  jq -s -e '
    .[0].sources == .[1].sources and
    .[0].pipeline.native_source_counts == .[1].pipeline.native_source_counts and
    .[0].pipeline.event_uids == .[1].pipeline.event_uids
  ' "$evidence_root/baseline-result.json" "$evidence_root/result.json" >/dev/null ||
    fail "real-detection identity changed after exact bundle restore"
  jq -n --slurpfile baseline "$evidence_root/baseline-result.json" \
    --slurpfile restored "$evidence_root/result.json" \
    --slurpfile reload "$evidence_root/reload/reload-events.json" '
      {
        schema_version: "lyflow.t12.restore_continuity/v1",
        status: "PASS",
        baseline_version: $reload[0].baseline_version,
        candidate_version: $reload[0].candidate_version,
        final_version: $reload[0].final_version,
        baseline_digest: $reload[0].baseline_digest,
        final_digest: $reload[0].final_digest,
        baseline_sources: $baseline[0].sources,
        restored_sources: $restored[0].sources,
        stable_event_uids: $restored[0].pipeline.event_uids
      }
    ' >"$evidence_root/restore-continuity.json"
}

run_live_ui() {
  "$root/scripts/qa/t12-live-ui_test.sh"
  jq -e '.status == "PASS" and .persisted_event_count == 9 and .persisted_source_count == 5 and (.browser_sources | length) == 5' \
    "$evidence_root/ui/result.json" >/dev/null || fail "live UI evidence is incomplete"
  jq --slurpfile ui "$evidence_root/ui/result.json" '. + {ui: $ui[0]}' \
    "$evidence_root/result.json" >"$evidence_root/result.json.tmp"
  mv "$evidence_root/result.json.tmp" "$evidence_root/result.json"
}

write_evidence_index() {
	local commit dirty
	commit=$(git -C "$root" rev-parse HEAD)
	dirty=false
	if [[ -n $(git -C "$root" status --short) ]]; then
		dirty=true
	fi
	jq -n --arg commit "$commit" --argjson dirty "$dirty" \
		--arg manifest_sha256 "$(file_sha256 "$manifest")" \
		--arg result_sha256 "$(file_sha256 "$evidence_root/result.json")" \
		--arg pipeline_sha256 "$(file_sha256 "$evidence_root/pipeline-result.json")" \
		--arg restore_sha256 "$(file_sha256 "$evidence_root/restore-continuity.json")" \
		--arg ui_sha256 "$(file_sha256 "$evidence_root/ui/result.json")" '
		{
			schema_version: "lyflow.t12.evidence_index/v1",
			commit: $commit,
			worktree_dirty: $dirty,
			artifacts: {
				manifest: {path: "fixtures/real-detections/v1/manifest.json", sha256: $manifest_sha256},
				result: {path: "acceptance-evidence/T12/result.json", sha256: $result_sha256},
				pipeline: {path: "acceptance-evidence/T12/pipeline-result.json", sha256: $pipeline_sha256},
				restore_continuity: {path: "acceptance-evidence/T12/restore-continuity.json", sha256: $restore_sha256},
				ui: {path: "acceptance-evidence/T12/ui/result.json", sha256: $ui_sha256}
			}
		}
	' >"$evidence_root/evidence-index.json"
	jq -e '.schema_version == "lyflow.t12.evidence_index/v1" and (.artifacts | length) == 5 and all(.artifacts[]; .sha256 | test("^[0-9a-f]{64}$"))' \
		"$evidence_root/evidence-index.json" >/dev/null || fail "T12 evidence index is incomplete"
}

for tool in base64 curl docker jq sha256sum; do
  require_tool "$tool"
done
require_file "$manifest"
require_file "$lock"
require_file "$profile"
validate_manifest
materialize_packet_fixtures
validate_inputs
baseline_bundle=$(prepare_rule_bundle)
run_replays "$baseline_bundle"
four_eve=$replay_root/four-source/eve.json
stamus_eve=$replay_root/stamus/eve.json
verify_alerts "$manifest" "$four_eve" "$stamus_eve"
run_negative_checks "$four_eve" "$stamus_eve"
run_pipeline
write_result "$four_eve" "$stamus_eve"
cp "$evidence_root/result.json" "$evidence_root/baseline-result.json"
run_reload_restore "$baseline_bundle"
restored_bundle=$(jq -er '.final_bundle_path' "$evidence_root/reload/reload-events.json")
run_replays "$restored_bundle"
verify_alerts "$manifest" "$four_eve" "$stamus_eve"
run_pipeline
write_result "$four_eve" "$stamus_eve"
write_continuity_result
run_live_ui
jq -e '.status == "PASS" and .pipeline.status == "PASS" and .ui.status == "PASS" and (.sources | length) == 5 and all(.sources[]; .actual_alert_count == .expected_alert_count)' "$evidence_root/result.json" >/dev/null
write_evidence_index
printf 'T12 real-detection release gate PASS: %s\n' "$evidence_root/result.json"
