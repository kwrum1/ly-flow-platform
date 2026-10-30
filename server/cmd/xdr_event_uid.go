package main

import (
	"crypto/sha256"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
)

const (
	eventUIDVersionV1 = "v1"
	eventUIDVersionV2 = "v2"
)

// eventUIDVersion selects the idempotency key algorithm. v1 stays the default
// until the shadow comparison shows v2 does not split or merge real incidents.
func eventUIDVersion() string {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("LYFLOW_EVENT_UID_VERSION"))) {
	case "v2", "2":
		return eventUIDVersionV2
	default:
		return eventUIDVersionV1
	}
}

// xdrNativeEventID returns the most stable source identifier available.
func xdrNativeEventID(event map[string]interface{}) string {
	raw := asMap(event["raw"])
	return firstNonEmpty(
		xdrPickString(event, "message_id"),
		xdrPickString(event, "native_event_id"),
		xdrPickString(event, "raw_event_id"),
		xdrPickString(raw, "message_id"),
		xdrPickString(raw, "id"),
	)
}

// xdrPayloadHash returns a content hash when the producer provided one.
func xdrPayloadHash(event map[string]interface{}) string {
	return firstNonEmpty(
		xdrPickString(event, "raw_sha256"),
		xdrPickString(event, "payload_sha256"),
		xdrPickString(asMap(event["raw_reference"]), "hash"),
		xdrPickString(asMap(event["raw"]), "payload_sha256"),
	)
}

// deterministicEventUIDV2 is the versioned idempotency key.
//
//   - A native source ID wins: tenant + native ID is the identity.
//   - Otherwise the key mixes tenant, source, rule, entities, payload hash and
//     the full nanosecond timestamp. The v1 key truncated to seconds, which let
//     distinct events collide and redeliveries with a different second split.
func deterministicEventUIDV2(tenant, category, ruleID, srcIP, victim, agentID string, at time.Time, nativeID, payloadHash string) string {
	tenant = strings.ToLower(strings.TrimSpace(tenant))
	if native := strings.TrimSpace(nativeID); native != "" {
		sum := sha256.Sum256([]byte(tenant + "|native|" + native))
		return fmt.Sprintf("xdr2n-%x", sum[:16])
	}
	canonical := strings.Join([]string{
		tenant,
		strings.ToLower(strings.TrimSpace(category)),
		strings.ToLower(strings.TrimSpace(ruleID)),
		strings.ToLower(strings.TrimSpace(srcIP)),
		strings.ToLower(strings.TrimSpace(victim)),
		strings.ToLower(strings.TrimSpace(agentID)),
		strings.ToLower(strings.TrimSpace(payloadHash)),
		at.UTC().Format(time.RFC3339Nano),
	}, "|")
	sum := sha256.Sum256([]byte(canonical))
	return fmt.Sprintf("xdr2p-%x", sum[:16])
}

// resolveEventUID returns the configured UID and, while running v1, the v2
// value for shadow comparison.
func resolveEventUID(event map[string]interface{}, tenant, category, ruleID, srcIP, victim, agentID string, observedAt time.Time) (uid, shadowUID string) {
	legacy := deterministicEventUID(tenant, category, ruleID, srcIP, victim, agentID, observedAt)
	v2 := deterministicEventUIDV2(tenant, category, ruleID, srcIP, victim, agentID, observedAt,
		xdrNativeEventID(event), xdrPayloadHash(event))
	if eventUIDVersion() == eventUIDVersionV2 {
		return v2, ""
	}
	return legacy, v2
}

// logEventUIDShadow emits a bounded shadow comparison when explicitly enabled.
func logEventUIDShadow(legacy, v2 string) {
	if v2 == "" || v2 == legacy {
		return
	}
	if strings.TrimSpace(os.Getenv("LYFLOW_EVENT_UID_SHADOW_LOG")) != "1" {
		return
	}
	log.Printf("event uid shadow: legacy=%s v2=%s", legacy, v2)
}
