package contracts

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
)

type ReconcileRecord struct {
	EventUID string
	Payload  []byte
}

type ReconciliationReport struct {
	LegacyCount       int    `json:"legacy_count"`
	CanonicalCount    int    `json:"canonical_count"`
	LegacyChecksum    string `json:"legacy_checksum"`
	CanonicalChecksum string `json:"canonical_checksum"`
	Match             bool   `json:"match"`
}

func Reconcile(legacy, canonical []ReconcileRecord) ReconciliationReport {
	legacyChecksum := reconcileChecksum(legacy)
	canonicalChecksum := reconcileChecksum(canonical)
	return ReconciliationReport{
		LegacyCount: len(legacy), CanonicalCount: len(canonical),
		LegacyChecksum: legacyChecksum, CanonicalChecksum: canonicalChecksum,
		Match: len(legacy) == len(canonical) && legacyChecksum == canonicalChecksum,
	}
}

func reconcileChecksum(records []ReconcileRecord) string {
	ordered := append([]ReconcileRecord(nil), records...)
	sort.Slice(ordered, func(left, right int) bool { return ordered[left].EventUID < ordered[right].EventUID })
	digest := sha256.New()
	for _, record := range ordered {
		digest.Write([]byte(record.EventUID))
		digest.Write([]byte{0})
		digest.Write(record.Payload)
		digest.Write([]byte{0})
	}
	return hex.EncodeToString(digest.Sum(nil))
}
